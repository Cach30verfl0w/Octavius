use crate::{
    Route,
    RouteError,
    RouteProtocol,
    RouteTable,
};
use futures_util::TryStreamExt;
use netlink_packet_route::{
    route::{
        RouteAddress,
        RouteAttribute,
    },
    AddressFamily,
};
use octavius_common::{
    next_enum_of,
    Prefix,
};
use rtnetlink::{
    new_connection,
    Handle,
    IpVersion,
};
use std::{
    future::Future,
    net::IpAddr,
};
use netlink_packet_route::route::RouteMessage;
use tokio::task::JoinHandle;

pub type NetlinkRouteProtocol = netlink_packet_route::route::RouteProtocol;

impl From<NetlinkRouteProtocol> for RouteProtocol {
    fn from(value: NetlinkRouteProtocol) -> Self {
        match value {
            NetlinkRouteProtocol::Bgp => Self::BGP,
            NetlinkRouteProtocol::Ospf => Self::OSPF,
            NetlinkRouteProtocol::Static => Self::Static,
            NetlinkRouteProtocol::Dhcp => Self::DHCP,
            NetlinkRouteProtocol::Kernel => Self::Kernel,
            NetlinkRouteProtocol::Ra => Self::RouterAdvertisement,
            _ => Self::Other,
        }
    }
}

pub struct LinuxRouteTable {
    netlink_handle: Handle,
    _connection_thread: JoinHandle<()>,
}

impl RouteTable for LinuxRouteTable {
    fn new() -> Result<Self, RouteError> {
        let (connection, netlink_handle, _) = new_connection()?;
        let connection_thread = tokio::spawn(connection);
        Ok(Self {
            netlink_handle,
            _connection_thread: connection_thread,
        })
    }

    fn all(&self) -> impl Future<Output = Result<Vec<Route>, RouteError>> + Send {
        fn netlink_route_message_to_route(route: RouteMessage) -> Route {
            Route {
                // The protocol origin of this route
                protocol: RouteProtocol::from(route.header.protocol),

                // The next hop in the pathway to the destination prefix
                next_hop: next_enum_of!(route.attributes, RouteAttribute::Gateway(val) => val).map_or(None, |addr| {
                    match addr {
                        RouteAddress::Inet(addr) => Some(IpAddr::V4(addr.clone())),
                        RouteAddress::Inet6(addr) => Some(IpAddr::V6(addr.clone())),
                        _ => None,
                    }
                }),

                // The priority of the route
                priority: next_enum_of!(route.attributes, RouteAttribute::Priority(value) => *value),

                // The destination of the route (if not present, alternate to 0.0.0.0/0 or equivalent)
                destination: next_enum_of!(route.attributes, RouteAttribute::Destination(value) => value).map_or(
                    None,
                    |addr| {
                        match addr {
                            RouteAddress::Inet(addr) => {
                                Some(Prefix {
                                    address: IpAddr::V4(addr.clone()),
                                    mask: route.header.destination_prefix_length,
                                })
                            }
                            RouteAddress::Inet6(addr) => {
                                Some(Prefix {
                                    address: IpAddr::V6(addr.clone()),
                                    mask: route.header.destination_prefix_length,
                                })
                            }
                            _ => None
                        }
                    },
                ),
            }
        }

        async {
            let mut routes = Vec::new();

            // Collect IPv4 routing table entries
            let mut netlink_v4_routes = self.netlink_handle.route().get(IpVersion::V4).execute();
            while let Some(route) = netlink_v4_routes.try_next().await? {
                routes.push(netlink_route_message_to_route(route));
            }

            // Collect IPv6 routing table entries
            let mut netlink_v6_routes = self.netlink_handle.route().get(IpVersion::V6).execute();
            while let Some(route) = netlink_v6_routes.try_next().await? {
                routes.push(netlink_route_message_to_route(route));
            }

            // Return
            Ok(routes)
        }
    }
}
