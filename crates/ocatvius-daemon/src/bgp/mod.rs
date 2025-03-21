use log::{debug, error, info, trace};
use mio::net::{TcpListener, TcpStream};
use std::net::{SocketAddr, TcpStream as StdTcpStream};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::sync::Arc;
use std::time::Duration;
use mio::{Events, Interest, Poll, Token};
use socket2::{Domain, Socket, Type};
use tokio::io;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::sleep;

const SERVER: Token = Token(0);

#[rustfmt::skip]
async fn create_tcp_server(socket_address: SocketAddr, poll: Option<(&Poll, Token)>) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(socket_address), Type::STREAM, None)?;
    if socket_address.is_ipv6() {
        socket.set_only_v6(true)?;
    }

    // Configure listener
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket_address.into())?;
    socket.listen(4096)?;

    // Create listener out of it and register into polling (this is safe!)
    let mut tcp_listener = unsafe { TcpListener::from_raw_fd(socket.into_raw_fd()) };
    debug!("TCP listener is listening on {}", socket_address);
    if let Some((poll, token)) = poll {
        trace!("Registered listener into event polling system");
        poll.registry().register(&mut tcp_listener, token, Interest::READABLE)?;
    }
    Ok(tcp_listener)
}

/// This enum contains all connection states defined by the BGP base RFC for the BGP FSM (Finite State Machine). These states are per-peer
/// and are stored in the BGP session.
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Debug, Default)]
pub enum SessionState {
    /// This is the initial state of a BGP session. In this state, the BGP session is waiting for a connection request from a peer or tries
    /// to establish one.
    #[default]
    Idle,

    /// In this state, the BGP router sent a TCP connection request to the remote peer. The router is waiting for a TCP connection to be
    /// established.
    Connect,

    /// In this state, the TCP connection is established, the BGP router has sent an open message to the peer and the BGP router is waiting
    /// for an incoming open message from the peer.
    OpenSent,

    /// In this state, the BGP session wait for an incoming keep-alive or notification message by the BGP peer.
    OpenConfirm,

    /// In this state, the BGP session can exchange updates, notifications and keep-alive messages with the peer.
    Established,
}

/// This struct contains the BGP session information which is only stored as long as the connection to/from the server exists. When this
/// application receives a close, we drop this connection.
pub struct BGPConnection {
    incoming_stream: Option<TcpStream>,
    outgoing_stream: Option<TcpStream>
}

impl BGPConnection {
    fn stream(&self) -> Option<&TcpStream> {
        self.incoming_stream
            .as_ref()
            .or(self.outgoing_stream.as_ref())
    }
}

pub struct BGPSessionInter {
    active_connection: Mutex<Option<BGPConnection>>,
    connection_drop_notifier: Arc<Notify>,
    state: SessionState,
    hostname: String,
    port: u16,
}

/// This struct contains the persistent information about the BGP session established with the peer router. After closing the connection, we
/// only drop the connection.
pub struct BGPSession {
    internal: Arc<Mutex<BGPSessionInter>>,
    _reconnect_thread: JoinHandle<()>,
}

impl BGPSession {
    pub async fn close(&mut self) {
        let session = self.internal.lock().await;
        info!(
            "Closing TCP connection to {}:{}",
            session.hostname, session.port
        );
        *session.active_connection.lock().await = None;
        session.connection_drop_notifier.notify_waiters();
    }
}

struct BGPServerInter {
    sessions: Mutex<Vec<BGPSession>>,
    pending_connections: Vec<TcpStream>,
    listener: TcpListener,
    poll: Arc<Poll>
}

pub struct BGPServer {
    internal: Arc<BGPServerInter>,
    event_loop: JoinHandle<()>
}

impl BGPServer {
    pub async fn new(server_addr: SocketAddr) -> io::Result<Self> {
        let mut poll = Arc::new(Poll::new()?);
        let mut listener = create_tcp_server(server_addr, Some((&poll, SERVER))).await?;
        if let Err(error) = Arc::get_mut(&mut poll).unwrap().registry().register(&mut listener, SERVER, Interest::READABLE) {
            error!("Unable to register server into polling => {error}");
        }

        let server = Arc::new(BGPServerInter {
            pending_connections: Vec::new(),
            sessions: Mutex::new(Vec::new()),
            poll: poll.clone(),
            listener
        });

        let internal = server.clone();
        Ok(BGPServer {
            event_loop: tokio::spawn(async move {
                let mut events = Events::with_capacity(1024);

                loop {
                    if let Err(error) = Arc::get_mut(&mut poll).unwrap().poll(&mut events, Some(Duration::from_millis(100))) {
                        error!("Unable to polling events => {}", error);
                    } else {
                        // Processing events received by event poll (e.g. Kqueue, Epoll). If the server received the event, accepting the
                        // new connections until that operation fails.
                        for event in events.iter() {
                            match event.token() {
                                SERVER => {
                                    // We accept all incoming sockets and put them into the staging streams list. Staging streams are
                                    // streams without the open message being sent.
                                    while let Ok((stream, address)) = internal.listener.accept() {

                                    }
                                },
                                token => {
                                    // TODO: Handle close and read
                                }
                            }
                        }
                    }
                }
            }),
            internal: server
        })
    }

    /// This function creates a new session from the specified parameters. When creating a session, the created session spawns a fiber to
    /// permanently connect to the peer if no connection is established. After the creation, the session is stored in the internal list.
    pub async fn new_session(&mut self, hostname: String, port: u16, reconnect_time: Duration) {
        let connection_drop_notifier = Arc::new(Notify::new());
        let internal = Arc::new(Mutex::new(BGPSessionInter {
            active_connection: Mutex::new(None),
            connection_drop_notifier: connection_drop_notifier.clone(),
            state: SessionState::Idle,
            hostname: hostname.clone(),
            port,
        }));

        // Initialize reconnect fiber (user thread) which allows to establish connection to the BGP server. This is used to re-establish
        // the connection to the peer immediately after the connection was closed.
        let session = internal.clone();
        let poll = self.internal.poll.clone();
        let reconnect_thread = tokio::spawn(async move {
            loop {
                #[rustfmt::skip]
                match StdTcpStream::connect(format!("{}:{}", hostname, port)) {
                    Ok(stream) => {
                        {
                            // Lock internal BGP session object and set state and active connection. This active connection should be none
                            // so we can simply set the BGP connection.
                            info!("Successfully established connection to {hostname}:{port}");
                            let mut session = session.lock().await;
                            session.state = SessionState::Connect;
                            let mut connection = session.active_connection.lock().await;
                            *connection = Some(BGPConnection {
                                outgoing_stream: Some(TcpStream::from_std(stream)),
                                incoming_stream: None
                            });

                            // Register into polling TODO: Use next_token
                            let stream = connection.as_mut().map(|value| value.outgoing_stream.as_mut().unwrap()).unwrap();
                            if let Err(error) = poll.registry().register(stream, Token(0), Interest::WRITABLE | Interest::READABLE) {
                                error!("Unable to register connection from {hostname}:{port} into polling => {error}");
                                continue
                            }
                        }

                        // Pause thread until the other thread etc. notifies this thread about the close of the BGP connection. If the
                        // connection was closed we retry to open the connection.
                        connection_drop_notifier.notified().await;
                        debug!("Retry to establish connection to {}:{}", hostname, port);
                    }
                    Err(_) => {
                        error!("Failed to establish connection to {hostname}:{port} => Retry in {} seconds", reconnect_time.as_secs());
                        sleep(reconnect_time).await;
                    }
                }
            }
        });

        self.internal.sessions.lock().await.push(BGPSession {
            _reconnect_thread: reconnect_thread,
            internal
        });
    }
}