//! This module of the BGP serialization and deserialization library implements the serialization of the Multiprotocol extensions in the BGP
//! update message (and the capability) as specified in [RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760). It allows to tell the
//! peer about IPv4 prefixes etc.

use crate::{
    prefix::{
        AddressFamily,
        Prefix,
    },
    type_enum,
    BGPElement,
    NextHop,
};
use alloc::vec::Vec;
use nom::{
    multi::many0,
    number::complete::be_u8,
    IResult,
    Parser,
};

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

#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone, Copy)]
pub struct MultiprotocolExtensionsCapability {
    pub address_family: AddressFamily,
    pub subsequent_address_family: SubsequentAddressFamily,
}

impl BGPElement for MultiprotocolExtensionsCapability {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, address_family) = AddressFamily::unpack(input)?;
        let (input, _) = be_u8(input)?;
        let (input, subsequent_address_family) = SubsequentAddressFamily::unpack(input)?;
        Ok((
            input,
            Self {
                address_family,
                subsequent_address_family,
            },
        ))
    }

    fn pack(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&u16::from(self.address_family).to_be_bytes());
        buffer.extend_from_slice(&0_u8.to_be_bytes());
        buffer.extend_from_slice(&u8::from(self.subsequent_address_family).to_be_bytes());
        buffer
    }
}

/// This struct represents the multiprotocol reachable path attribute defined by the Multiprotocol Extensions for BGP as an optional and
/// non-transitive attribute. It's used to advertise a route to a peer or to permit a router to advertise the network layer address of the
/// router.
///
/// ## References
/// - [Multiprotocol Reachable NLRI - MP_REACH_NLRI, Section 3 RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760#section-3)
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone)]
pub struct MultiprotocolReachNLRI {
    pub address_family: AddressFamily,
    pub subsequent_address_family: SubsequentAddressFamily,
    pub next_hop: NextHop,
    pub nlri: Vec<Prefix>,
}

impl BGPElement for MultiprotocolReachNLRI {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, address_family) = AddressFamily::unpack(input)?;
        let (input, subsequent_address_family) = SubsequentAddressFamily::unpack(input)?;
        let (input, next_hop) = NextHop::unpack(input, address_family, true)?;
        let (nlri, _) = be_u8(input)?;
        let (_, nlri) = many0(|input| Prefix::unpack(input, address_family)).parse(nlri)?;
        Ok((
            &[],
            Self {
                address_family,
                subsequent_address_family,
                next_hop,
                nlri,
            },
        ))
    }

    fn pack(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&u16::from(self.address_family).to_be_bytes());
        buffer.extend_from_slice(&u8::from(self.subsequent_address_family).to_be_bytes());
        buffer.extend(self.next_hop.pack());
        buffer.extend_from_slice(&0_u8.to_be_bytes());
        self.nlri.iter().for_each(|prefix| buffer.extend(prefix.pack()));
        buffer
    }
}

/// This struct represents the multiprotocol unreachable NLRI path attribute defined by the Multiprotocol Extensions for BGP as an optional
/// and non-transitive attribute for withdrawing multiple routes from the service.
///
/// ## References
/// - [Multiprotocol Unreachable NLRI - MP_UNREACH_NLRI, Section 4 RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760#section-4)
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone)]
pub struct MultiprotocolUnreachNLRI {
    pub address_family: AddressFamily,
    pub subsequent_address_family: SubsequentAddressFamily,
    pub withdrawn_routes: Vec<Prefix>,
}

impl BGPElement for MultiprotocolUnreachNLRI {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, address_family) = AddressFamily::unpack(input)?;
        let (withdrawn_routes, subsequent_address_family) = SubsequentAddressFamily::unpack(input)?;
        let withdrawn_routes = many0(|input| Prefix::unpack(input, address_family)).parse(withdrawn_routes)?.1;

        Ok((
            &[],
            Self {
                withdrawn_routes,
                address_family,
                subsequent_address_family,
            },
        ))
    }

    fn pack(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&u16::from(self.address_family).to_be_bytes());
        buffer.extend_from_slice(&u8::from(self.subsequent_address_family).to_be_bytes());
        let mut withdrawn_routes_buffer = Vec::new();
        self.withdrawn_routes
            .iter()
            .for_each(|prefix| withdrawn_routes_buffer.extend(prefix.pack()));
        buffer.extend(withdrawn_routes_buffer);
        buffer
    }
}
