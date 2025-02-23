use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use nom::bytes::complete::take;
use nom::IResult;
use nom::number::complete::be_u8;
use crate::protocols::bgp::rfc4760::AddressFamily;

fn slice_to_array<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut array = [0u8; N];
    if slice.len() <= N {
        array[0..slice.len()].copy_from_slice(slice);
    }

    array
}

/// This enum implements support for serializing IPv4 and IPv6 prefixes from binary or text data. Prefixes are used to address a part of a
/// network like the Internet.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Prefix {
    IPv4 { addr: Ipv4Addr, mask: u8 },
    IPv6 { addr: Ipv6Addr, mask: u8 }
}

impl Display for Prefix {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IPv4 { addr, mask } => write!(formatter, "{}/{}", addr, mask),
            Self::IPv6 { addr, mask } => write!(formatter, "{}/{}", addr, mask),
        }
    }
}

impl FromStr for Prefix {
    type Err = anyhow::Error;
    
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        let (address, mask) = str.split_once("/").ok_or(anyhow::anyhow!("Invalid prefix syntax"))?;
        let (address, mask) = (IpAddr::from_str(address)?, u8::from_str(mask)?);
        Ok(match address {
            IpAddr::V4(addr) => Self::IPv4 { addr, mask },
            IpAddr::V6(addr) => Self::IPv6 { addr, mask }
        })
    }
}

impl Prefix {
    pub(crate) fn unpack(input: &[u8], address_family: AddressFamily) -> IResult<&[u8], Self> {
        let (input, mask) = be_u8(input)?;
        let (input, prefix) = take((mask + 7) / 8)(input)?;
        match address_family {
            AddressFamily::IPv4 => Ok((input, Self::IPv4 { addr: Ipv4Addr::from(slice_to_array::<4>(prefix)), mask })),
            AddressFamily::IPv6 => Ok((input, Self::IPv6 { addr: Ipv6Addr::from(slice_to_array::<16>(prefix)), mask })),
            AddressFamily::Unknown(_) => Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Complete))),
        }
    }
}
