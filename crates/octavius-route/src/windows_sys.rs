use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::slice;
use windows::Win32::Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, MIB_IPPROTO_NETMGMT, MIB_IPPROTO_NT_AUTOSTATIC, NL_ROUTE_PROTOCOL, PROTO_IP_BGP, PROTO_IP_DHCP, PROTO_IP_NT_STATIC, PROTO_IP_OSPF, SOCKADDR_INET};
use crate::{Route, RouteError, RouteProtocol, RouteTable};
use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIpForwardTable2, IP_ADDRESS_PREFIX};
use octavius_common::Prefix;

#[inline(always)]
unsafe fn convert_ip_address(address: SOCKADDR_INET) -> Option<IpAddr> {
    match address.si_family {
        AF_INET => Some(IpAddr::V4(Ipv4Addr::from(address.Ipv4.sin_addr.S_un.S_addr))),
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte))),
        _ => return None
    }
}

#[inline(always)]
fn convert_windows_prefix(prefix: IP_ADDRESS_PREFIX) -> Option<Prefix> {
    return unsafe { convert_ip_address(prefix.Prefix) }.map(|value| Prefix { address: value, mask: prefix.PrefixLength })
}

impl From<NL_ROUTE_PROTOCOL> for RouteProtocol {
    fn from(value: NL_ROUTE_PROTOCOL) -> Self {
        match value {
            PROTO_IP_NT_STATIC | MIB_IPPROTO_NT_AUTOSTATIC | MIB_IPPROTO_NETMGMT => Self::Static,
            PROTO_IP_BGP => Self::BGP,
            PROTO_IP_DHCP => Self::DHCP,
            PROTO_IP_OSPF => Self::OSPF,
            _ => Self::Other
        }
    }
}

pub struct WindowsRouteTable;

impl RouteTable for WindowsRouteTable {
    fn new() -> Result<Self, RouteError> {
        Ok(WindowsRouteTable)
    }

    fn all(&self) -> impl Future<Output = Result<Vec<Route>, RouteError>> + Send {
        fn enumerate_table(routes: &mut Vec<Route>, family: ADDRESS_FAMILY) -> Result<(), RouteError> {
            let mut table_ptr = std::ptr::null_mut();
            let result = unsafe { GetIpForwardTable2(family, &mut table_ptr) };
            if result.is_err() {
                return Err(RouteError::Win32(result.0));
            }

            // Enumerate table
            if !table_ptr.is_null() {
                let table = &unsafe { *table_ptr };
                for entry in unsafe { slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as _) } {
                    routes.push(Route {
                        protocol: RouteProtocol::from(entry.Protocol),
                        priority: Some(entry.Metric),
                        next_hop: unsafe { convert_ip_address(entry.NextHop) },
                        destination: convert_windows_prefix(entry.DestinationPrefix)
                    });
                }
            }
            unsafe { FreeMibTable(table_ptr as *mut _) };
            Ok(())
        }

        async {
            let mut routes = Vec::new();
            enumerate_table(&mut routes, AF_INET)?;
            enumerate_table(&mut routes, AF_INET6)?;
            Ok(routes)
        }
    }
}
