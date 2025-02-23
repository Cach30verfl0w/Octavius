// Copyright 2025 Cedric Hammes
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module is the implementation of the BGP protocol, and it's security and functionality extensions provides through the RFCs. Please
//! be aware that not every RFCs is currently implemented into this codebase. Below this text you can see a list with the standards already
//! implemented, not implemented or planned to be implemented.
//!
//! | RFC                                                       | Title                                 | Status            | File      |
//! |-----------------------------------------------------------|---------------------------------------|-------------------|-----------|
//! | [RFC 1997](https://datatracker.ietf.org/doc/html/rfc1997) | BGP Communities Attribute             | Planned           | -/-       |
//! | [RFC 2918](https://datatracker.ietf.org/doc/html/rfc2918) | Route Refresh Capability for BGP-4    | Planned           | -/-       |
//! | [RFC 3392](https://datatracker.ietf.org/doc/html/rfc3392) | Capabilities Advertisement with BGP-4 | Fully implemented | [rfc3392] |
//! | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271) | A Border Gateway Protocol 4 (BGP-4)   | Fully implemented | [self]    |
//! | [RFC 4370](https://datatracker.ietf.org/doc/html/rfc4360) | BGP Extended Communities Attribute    | Planned           | -/-       |
//! | [RFC 4724](https://datatracker.ietf.org/doc/html/rfc4724) | Graceful Restart Mechanism for BGP    | Planned           | -/-       |
//! | [RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760) | Multiprotocol Extensions for BGP-4    | Fully implemented | [rfc4760] |
//! | [RFC 6793](https://datatracker.ietf.org/doc/html/rfc6793) | BGP Support for Four-Octet AS Numbers | Fully implemented | [rfc6793] |
//! | [RFC 7313](https://datatracker.ietf.org/doc/html/rfc7313) | Enhanced Route Refresh Capability     | Planned           | -/-       |
//! | [RFC 7606](https://datatracker.ietf.org/doc/html/rfc7606) | Revised Error Handling for BGP UPDATE | Planned           | -/-       |
//! | [RFC 8955](https://datatracker.ietf.org/doc/html/rfc8955) | Dissemination of FlowSpec rules       | Potentially       | -/-       |
//!
//! The BGP (Border Gateway Protocol) is the EGP (Exterior Gateway Protocol) protocol used for the exchange of routes between two autonomous
//! systems, but can also be used as an IGP (Interior Gateway Protocol) and is used for big networks. This module implements the processing
//! and serialization of BGP packets itself.

pub mod params;
pub mod rfc3392;
pub mod rfc4760;
pub mod rfc6793;
pub mod path_attr;

#[cfg(test)]
pub mod tests;

use std::fmt::{Display, Formatter};
use bitflags::bitflags;
use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::{IResult, Parser};
use nom::multi::{many0, many1};
use nom::number::complete::{be_u16, be_u32, be_u8};
use crate::prefix::Prefix;
use crate::protocols::bgp::params::OptionalParameter;
use crate::protocols::bgp::path_attr::Origin;
use crate::protocols::bgp::rfc4760::{AddressFamily, MultiprotocolReachablePathAttribute, MultiprotocolUnreachablePathAttribute};

/// This enum is the implementation for processing all supported BGP messages transferred in a BGP session. This should be used when
/// implementing a BGP receiver/sender.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BGPMessage {
    Open(OpenMessage),
    Update(UpdateMessage),
    KeepAlive,
    Notification(NotificationMessage),
    Unknown { kind: u8 }
}

impl BGPMessage {
    pub fn unpack(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _marker) = take(16usize)(input)?;
        let (input, length) = be_u16(input)?;
        let (input, kind) = be_u8(input)?;
        let (input, data) = take((length as usize) - 19)(input)?;
        Ok((input, match kind {
            1 => Self::Open(OpenMessage::unpack(data)?.1),
            2 => Self::Update(UpdateMessage::unpack(data)?.1),
            3 => Self::Notification(NotificationMessage::unpack(data)?.1),
            4 => Self::KeepAlive,
            _ => Self::Unknown { kind }
        }))
    }

    #[inline(always)]
    pub fn unpack_many(input: &[u8]) -> IResult<&[u8], Vec<Self>> {
        many1(Self::unpack).parse(input)
    }
}

/// This struct is the type-safe implementation for handling the incoming/outgoing open message. The open message is the BGP equivalent of
/// a handshake between two pair routers.
///
/// ## Reference
/// - [OPEN Message Format, Section 4.2 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.2)
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct OpenMessage {
    pub version: u8,
    pub autonomous_system: u16,
    pub hold_time: u16,
    pub bgp_identifier: u32,
    pub optional_parameters: Vec<OptionalParameter>
}

impl OpenMessage {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, version) = be_u8(input)?;
        let (input, autonomous_system) = be_u16(input)?;
        let (input, hold_time) = be_u16(input)?;
        let (input, bgp_identifier) = be_u32(input)?;

        let (input, optional_parameters_length) = be_u8(input)?;
        let (input, optional_parameters_bytes) = take(optional_parameters_length as usize)(input)?;
        let (_, optional_parameters) = many0(OptionalParameter::unpack).parse(optional_parameters_bytes)?;
        Ok((input, Self { version, autonomous_system, hold_time, bgp_identifier, optional_parameters }))
    }
}

bitflags! {
    /// ## References
    /// - [UPDATE Message Format, Section 4.2 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.3)
    #[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
    pub struct PathAttributeFlags: u8 {
        const OPTIONAL        = 0b1000_0000;
        const TRANSITIVE      = 0b0100_0000;
        const PARTIAL         = 0b0010_0000;
        const EXTENDED_LENGTH = 0b0001_0000;
    }
}

impl Display for PathAttributeFlags {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let flags = [
            (PathAttributeFlags::OPTIONAL, "Optional"),
            (PathAttributeFlags::TRANSITIVE, "Transitive"),
            (PathAttributeFlags::PARTIAL, "Partial"),
            (PathAttributeFlags::EXTENDED_LENGTH, "Extended length")
        ];

        let flags: Vec<&str> = flags.iter().filter_map(|&(flag, name)| if self.contains(flag) { Some(name) } else { None }).collect();
        if flags.is_empty() {
            write!(formatter, "None")
        } else {
            write!(formatter, "{}", flags.join(", "))
        }
    }
}

/// Path attributes are used in BGP to describe and influence the propagation etc. of routes sent in this update message to the peer's
/// router.
///
/// ## References
/// - [UPDATE Message Format, Section 4.2 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.3)
/// - [Path Attributes, Section 5 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-5)
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathAttribute {
    Origin(Origin),
    MpReachableNLRI(MultiprotocolReachablePathAttribute),
    MpUnreachableNLRI(MultiprotocolUnreachablePathAttribute),
    Unknown { flags: PathAttributeFlags, kind: u8, data: Vec<u8> }
}

impl PathAttribute {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        let flags = PathAttributeFlags::from_bits(flags).ok_or(nom::Err::Error(Error::new(input, ErrorKind::Tag)))?;
        let (input, kind) = be_u8(input)?;

        // Following to the parser rules for path attributes in section 4.3 of RFC 4271, the length is an u16 when the extended length flag
        // is applied. Otherwise, the length is just one byte.
        let (input, length) = if !flags.contains(PathAttributeFlags::EXTENDED_LENGTH) {
            let (input, length) = be_u8(input)?;
            (input, length as u16)
        } else { be_u16(input)? };

        let (input, data) = take(length)(input)?;
        Ok((input, match kind {
            1 => Self::Origin(Origin::from(be_u8(data)?.1)),
            14 => Self::MpReachableNLRI(MultiprotocolReachablePathAttribute::unpack(data)?.1),
            15 => Self::MpUnreachableNLRI(MultiprotocolUnreachablePathAttribute::unpack(data)?.1),
            _ => Self::Unknown {
                flags,
                kind,
                data: data.to_vec()
            }
        }))
    }
}

impl Display for PathAttribute {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Origin(origin) => write!(formatter, "{:?}", origin),
            Self::MpUnreachableNLRI(reachable) => write!(
                formatter,
                "{} newly unreachable {} addresses ({})",
                reachable.network_layer_reachability_information.len(),
                reachable.address_family,
                reachable.subsequent_address_family
            ),
            Self::MpReachableNLRI(reachable) => write!(
                formatter,
                "{} newly reachable {} addresses ({})",
                reachable.network_layer_reachability_information.len(),
                reachable.address_family,
                reachable.subsequent_address_family
            ),
            Self::Unknown { flags, kind, data } => write!(formatter, "Unknown {} bytes (Flags: {}, kind: {})", data.len(), flags, kind)
        }
    }
}

/// This struct is the type-safe implementation for handling the incoming/outgoing update message. The update messages tell the router about
/// routes newly announced, routes withdrawn and network layer reachability information.
///
/// ## Reference
/// - [UPDATE Message Format, Section 4.3 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.3)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateMessage {
    pub withdrawn_routes: Vec<Prefix>,
    pub path_attributes: Vec<PathAttribute>,
    pub network_layer_reachability_information: Vec<Prefix>
}

impl UpdateMessage {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, withdrawn_routes_length) = be_u16(input)?;
        let (input, withdrawn_routes) = take(withdrawn_routes_length)(input)?;
        let (input, path_attributes_length) = be_u16(input)?;
        let (nlri, path_attributes_bytes) = take(path_attributes_length)(input)?;
        let (_, path_attributes) = many0(PathAttribute::unpack).parse(path_attributes_bytes)?;
        Ok((&[], Self {
            path_attributes,
            withdrawn_routes: many0(|b| Prefix::unpack(b, AddressFamily::IPv4)).parse(withdrawn_routes)?.1,
            network_layer_reachability_information: many0(|b| Prefix::unpack(b, AddressFamily::IPv4)).parse(nlri)?.1
        }))
    }
}

/// This struct is the type-safe implementation for handling the incoming/outgoing notification message. The notification message informs
/// the peer router about errors or state information like shutdown etc.
///
/// ## Reference
/// - [NOTIFICATION Message Format, Section 4.5 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.5)
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct NotificationMessage {
    pub error_code: u8,
    pub error_subcode: u8,
    pub data: Vec<u8>
}

impl NotificationMessage {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, error_code) = be_u8(input)?;
        let (data, error_subcode) = be_u8(input)?;
        Ok((&[], Self { error_code, error_subcode, data: data.to_vec() }))
    }
}
