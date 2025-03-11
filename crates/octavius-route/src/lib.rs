use octavius_common::Prefix;
use std::{
    future::Future,
    io,
    net::IpAddr,
};
use thiserror::Error;

#[cfg(target_os = "linux")] pub mod linux;
#[cfg(target_os = "windows")] pub mod windows_sys;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("IO Error => {0}")]
    Io(#[from] io::Error),

    #[error("Invalid address type")]
    InvalidAddressType,

    // Platform-specific errors
    #[cfg(target_os = "linux")]
    #[error("Netlink error => {0}")]
    Netlink(#[from] rtnetlink::Error),
    #[cfg(target_os = "windows")]
    #[error("Win32 API error => {0}")]
    Win32(u32)
}

/// This enum describes the routing protocol that was used to learn this route.
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone, Copy)]
pub enum RouteProtocol {
    /// The source of the route is unknown to this library.
    ///
    /// ## References
    /// - [Page 8, RFC 1354](https://www.rfc-editor.org/rfc/rfc1354.html)
    Other,

    /// This route was manually added by the system administrator.
    ///
    /// ## References
    /// - [Page 8, RFC 1354](https://www.rfc-editor.org/rfc/rfc1354.html) as Netmgmt
    Static,

    /// This route was learned via the Border Gateway Protocol (BGP).
    ///
    /// ## References
    /// - [Page 8, RFC 1354](https://www.rfc-editor.org/rfc/rfc1354.html)
    BGP,

    /// This route was learned via the Dynamic Host Configuration Protocol (DHCP).
    DHCP,

    /// This route was learned via the Open Shortest Path First (OSPF) Protocol.
    ///
    /// ## References
    /// - [Page 8, RFC 1354](https://www.rfc-editor.org/rfc/rfc1354.html)
    OSPF,

    /// This route was added by the operating system.
    Kernel,

    /// This route was learned via the Neighbor Discovery Protocol (NDP).
    RouterAdvertisement
}

/// This struct represents a single route in the routing table of the current environment in a platform-agnostic way. It allows the
/// developer to read and modify routes in the table and is the central wrapping object around the routing table's entries.
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone, Copy)]
pub struct Route {
    pub protocol: RouteProtocol,
    pub next_hop: Option<IpAddr>,
    pub destination: Option<Prefix>,
    pub priority: Option<u32>,
}

/// This trait is used to implement a platform-agnostic routing table in Rust. It provides methods to modify, read, write and delete routes
/// in the table.
pub trait RouteTable: Sized {
    fn new() -> Result<Self, RouteError>;
    fn all(&self) -> impl Future<Output = Result<Vec<Route>, RouteError>> + Send;
}
