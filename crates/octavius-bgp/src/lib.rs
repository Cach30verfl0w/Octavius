//! This crate (Octavius project module) implements serialization and deserialization APIs for the Border Gateway Protocol (BGP), that is
//! **the** EGP (Exterior Gateway Protocol) used in the Internet for the exchange of routes between two networks. BGP itself is an unsafe
//! and limited protocol but there are many RFCs used as extensions for that protocol.
//!
//! ## RFCs currently implemented or planned to be implemented
//! | RFC                                                       | Title                                       | Status      |
//! |-----------------------------------------------------------|---------------------------------------------|-------------|
//! | [RFC 1997](https://datatracker.ietf.org/doc/html/rfc1997) | BGP Communities Attribute                   | Planned     |
//! | [RFC 2918](https://datatracker.ietf.org/doc/html/rfc2918) | Route Refresh Capability for BGP-4          | Planned     |
//! | [RFC 3392](https://datatracker.ietf.org/doc/html/rfc3392) | Capabilities Advertisement with BGP-4       | Implemented |
//! | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271) | A Border Gateway Protocol 4 (BGP-4)         | Implemented |
//! | [RFC 4370](https://datatracker.ietf.org/doc/html/rfc4360) | BGP Extended Communities Attribute          | Planned     |
//! | [RFC 4724](https://datatracker.ietf.org/doc/html/rfc4724) | Graceful Restart Mechanism for BGP          | Planned     |
//! | [RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760) | Multiprotocol Extensions for BGP-4          | Planned     |
//! | [RFC 5549](https://datatracker.ietf.org/doc/html/rfc5549) | Advertising IPv4 NLRI with an IPv6 Next Hop | Planned     |
//! | [RFC 5668](https://datatracker.ietf.org/doc/html/rfc5668) | 4-Octet AS-specific BGP Extended Community  | Planned     |
//! | [RFC 6793](https://datatracker.ietf.org/doc/html/rfc6793) | BGP Support for Four-Octet AS Numbers       | Planned     |
//! | [RFC 7313](https://datatracker.ietf.org/doc/html/rfc7313) | Enhanced Route Refresh Capability           | Planned     |
//! | [RFC 7606](https://datatracker.ietf.org/doc/html/rfc7606) | Revised Error Handling for BGP UPDATE       | Planned     |
//! | [RFC 8205](https://datatracker.ietf.org/doc/html/rfc8205) | BGPsec Protocol Specification               | Planned     |
//! | [RFC 8955](https://datatracker.ietf.org/doc/html/rfc8955) | Dissemination of FlowSpec rules             | Planned     |
//!
//! ## Examples
//!
//! TODO: Add examples for the API usage
//!
//! ## References
//! - [Standards documents, Wikipedia "Border Gateway Protocol"](https://en.wikipedia.org/wiki/Border_Gateway_Protocol#Standards_documents)
//! - [Supported Standards for BGP, Juniper](https://www.juniper.net/documentation/us/en/software/junos/standards/bgp/topics/concept/bgp.html)
//! - [Wikipedia "Exterior Gateway Protocol"](https://en.wikipedia.org/wiki/Exterior_gateway_protocol)
//! - [RFC 4271 - A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271)

#![no_std]
extern crate alloc;

pub(crate) mod macros;

pub mod prefix;
#[cfg(feature = "rfc3392")] pub mod rfc3392;
pub mod rfc4271;
#[cfg(feature = "rfc4760")] pub mod rfc4760;

use crate::{
    prefix::{
        unpack_ip_address,
        AddressFamily,
    },
    rfc4271::{
        BGPMessageHeader,
        NotificationMessage,
        OpenMessage,
        UpdateMessage,
    },
};
use alloc::vec::Vec;
use core::net::IpAddr;
use nom::{
    bytes::complete::take,
    IResult,
};

pub trait BGPElement<P = ()> {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized;
    fn pack(&self) -> Vec<u8>;
}

/// This enum is a wrapper around the BGP messages provided by the BGP serialization library. It allows the serialization and
/// deserialization of every BGP message received/being sent.
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone)]
pub enum BGPMessage {
    Open(OpenMessage),
    Update(UpdateMessage),
    Notification(NotificationMessage),
    KeepAlive,
    Unknown { kind: u8, data: Vec<u8> },
}

impl BGPElement for BGPMessage {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header) = BGPMessageHeader::unpack(input)?;
        let (input, message) = take(header.length as usize)(input)?;
        Ok((
            input,
            match header.kind {
                1 => Self::Open(OpenMessage::unpack(message)?.1),
                2 => Self::Update(UpdateMessage::unpack(message)?.1),
                3 => Self::Notification(NotificationMessage::unpack(message)?.1),
                4 => Self::KeepAlive,
                _ => {
                    Self::Unknown {
                        kind: header.kind,
                        data: message.to_vec(),
                    }
                }
            },
        ))
    }

    fn pack(&self) -> Vec<u8> {
        let message = match self {
            Self::Open(message) => message.pack(),
            Self::Update(message) => message.pack(),
            Self::Notification(message) => message.pack(),
            Self::Unknown { data, .. } => data.clone(),
            Self::KeepAlive => Vec::new(),
        };

        let mut buffer = BGPMessageHeader {
            marker: [0xF; 16],
            kind: self.kind(),
            length: message.len() as u16,
        }
        .pack();
        buffer.extend_from_slice(&message);
        buffer
    }
}

impl BGPMessage {
    fn kind(&self) -> u8 {
        match self {
            Self::Open(_) => 1,
            Self::Update(_) => 2,
            Self::Notification(_) => 3,
            Self::KeepAlive => 4,
            Self::Unknown { kind, .. } => kind.clone(),
        }
    }
}

/// This struct implements the next hop attribute/parameter for the basic BGP implementation and the Multiprotocol extension form of the
/// next hop.
pub struct NextHop {
    pub next_hop: IpAddr,
    #[cfg(feature = "rfc4760")]
    pub link_local_address: Option<IpAddr>,
}

impl NextHop {
    pub fn unpack(input: &[u8], addr_family: AddressFamily, extended: bool) -> IResult<&[u8], Self> {
        let (input, next_hop) = unpack_ip_address(input, addr_family)?;
        Ok((
            &[],
            Self {
                next_hop,
                #[cfg(feature = "rfc4760")]
                link_local_address: if extended && addr_family == AddressFamily::IPv6 {
                    Some(unpack_ip_address(input, addr_family)?.1)
                } else {
                    None
                },
            },
        ))
    }

    fn pack(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        match self.next_hop {
            IpAddr::V4(addr) => buffer.extend_from_slice(&addr.octets()),
            IpAddr::V6(addr) => buffer.extend_from_slice(&addr.octets()),
        }

        #[cfg(feature = "rfc4760")]
        if let Some(link_local_address) = self.link_local_address.as_ref() {
            match link_local_address {
                IpAddr::V4(addr) => buffer.extend_from_slice(&addr.octets()),
                IpAddr::V6(addr) => buffer.extend_from_slice(&addr.octets()),
            }
        }

        buffer
    }
}
