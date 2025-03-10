#![no_std]
extern crate alloc;

pub mod macros;

use alloc::string::{
    String,
    ToString,
};
use core::{
    fmt::{
        Debug,
        Display,
        Formatter,
    },
    net::{
        AddrParseError,
        IpAddr,
        Ipv4Addr,
        Ipv6Addr,
    },
    num::ParseIntError,
    str::FromStr,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommonError {
    #[error("Expected format <address>/<mask> (a.e. 192.168.2.0/24), but got '{0}'")]
    InvalidPrefixFormat(String),
    #[error("Unable to parse address => '{0}'")]
    IpAddrParse(#[from] AddrParseError),
    #[error("Unable to parse int => '{0}'")]
    IntParse(#[from] ParseIntError),
}

/// This value represents a IPv6/IPv4 network prefix. This prefix represents a sub-share of the network like the local network at home or
/// a subnetwork in a bigger network.
#[derive(Ord, PartialOrd, Eq, PartialEq, Hash, Clone, Copy)]
pub struct Prefix {
    pub address: IpAddr,
    pub mask: u8,
}

impl FromStr for Prefix {
    type Err = CommonError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let (addr, mask) = string.split_once("/").ok_or(CommonError::InvalidPrefixFormat(string.to_string()))?;
        Ok(Self {
            address: IpAddr::from_str(addr)?,
            mask: mask.parse()?,
        })
    }
}

impl Debug for Prefix {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}/{}", self.address, self.mask)
    }
}

impl Display for Prefix {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}/{}", self.address, self.mask)
    }
}

impl Prefix {
    pub const ANY_IPV4: Prefix = Prefix {
        address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        mask: 0,
    };
    pub const ANY_IPV6: Prefix = Prefix {
        address: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        mask: 0,
    };
}
