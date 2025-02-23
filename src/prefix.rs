use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;
use nom::bytes::complete::take;
use nom::IResult;
use nom::number::complete::be_u8;
use crate::protocols::bgp::rfc4760::AddressFamily;
use crate::protocols::bgp::unpack_address;

/// This enum implements support for serializing IPv4 and IPv6 prefixes from binary or text data. Prefixes are used to address a part of a
/// network like the Internet.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Prefix {
    address: IpAddr,
    mask: u8
}

impl Display for Prefix {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.address, self.mask)
    }
}

impl FromStr for Prefix {
    type Err = anyhow::Error;
    
    fn from_str(str: &str) -> Result<Self, Self::Err> {
        let (address, mask) = str.split_once("/").ok_or(anyhow::anyhow!("Invalid prefix syntax"))?;
        let (address, mask) = (IpAddr::from_str(address)?, u8::from_str(mask)?);
        Ok(Self { address, mask })
    }
}

impl Prefix {
    pub(crate) fn unpack(input: &[u8], address_family: AddressFamily) -> IResult<&[u8], Self> {
        let (input, mask) = be_u8(input)?;
        let (input, prefix) = take((mask + 7) / 8)(input)?;
        Ok((input, Prefix { address: unpack_address(prefix, address_family)?.1, mask }))
    }
}
