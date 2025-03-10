use crate::ParameterizedBGPElement;
use alloc::vec::Vec;
use core::{
    cmp::min,
    net::{
        IpAddr,
        Ipv4Addr,
        Ipv6Addr,
    },
};
use nom::{
    bytes::streaming::take,
    error::{
        Error,
        ErrorKind,
    },
    number::complete::be_u8,
    IResult,
};
use octavius_common::{
    type_enum,
    Prefix,
};

type_enum! {
    /// This value represents the address family specified in the Multiprotocol Extensions associated attributes. Currently we only support
    /// IPv4 and IPv6.
    ///
    /// ## References
    /// - [Address Family Numbers, IANA](https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml)
    #[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone, Copy)]
    pub enum AddressFamily: be_u16(u16) {
        IPv4 = 1,
        IPv6 = 2
    }
}

type_enum! {
    /// This enum represents all SAFI (Subsequent address family identifier) supported by this BGP implementation, currently we only support
    /// Unicast or Multicast.
    ///
    /// ## References
    /// [Subsequent Address Family Identifier, Section 6 RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760#section-6)
    #[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone, Copy)]
    pub enum SubsequentAddressFamily: be_u8(u8) {
        Unicast = 1,
        Multicast = 2
    }
}

impl ParameterizedBGPElement for Prefix {
    type Parameter = AddressFamily;

    fn unpack(input: &[u8], parameter: AddressFamily) -> IResult<&[u8], Prefix> {
        let (input, mask) = be_u8(input)?;
        let (input, prefix) = take((mask + 7) / 8)(input)?;
        Ok((
            input,
            Prefix {
                address: unpack_ip_address(prefix, parameter)?.1,
                mask,
            },
        ))
    }

    fn pack(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.mask.to_be_bytes());
        match self.address {
            IpAddr::V4(addr) => buffer.extend_from_slice(&addr.octets()[0..(((self.mask + 7) / 8) as usize)]),
            IpAddr::V6(addr) => buffer.extend_from_slice(&addr.octets()[0..(((self.mask + 7) / 8) as usize)]),
        }
        buffer
    }
}

pub fn unpack_ip_address(input: &[u8], address_family: AddressFamily) -> IResult<&[u8], IpAddr> {
    fn slice_to_array<const N: usize>(input: &[u8]) -> IResult<&[u8], [u8; N]> {
        let mut array = [0u8; N];
        let read = min(input.len(), N);
        let (input, bytes) = take(read)(input)?;
        array[0..read].copy_from_slice(bytes);
        Ok((input, array))
    }

    match address_family {
        AddressFamily::IPv4 => {
            let (input, bytes) = slice_to_array::<4>(input)?;
            Ok((input, IpAddr::V4(Ipv4Addr::from(bytes))))
        }
        AddressFamily::IPv6 => {
            let (input, bytes) = slice_to_array::<16>(input)?;
            Ok((input, IpAddr::V6(Ipv6Addr::from(bytes))))
        }
        _ => Err(nom::Err::Error(Error::new(input, ErrorKind::Complete))),
    }
}
