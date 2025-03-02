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

//! This module provides the implementation defines for the BGP communities attribute as specified in RFC 1997. BGP communities are used to
//! add extra information to routes announced over BGP. There are some well-known attributes standardized in the RFC whatever this feature
//! is allowing custom communities. The syntax for communities is `<AS number>:<Community>` with the AS number as a "namespace". Below this
//! text you can see the well-known communities (A standalone ASN not part of a confederation should be considered as a confederation
//! itself):
//! - `65535:65281` (`NO_EXPORT`) - All routes received with this community **MUST NOT** be advertised outside a BGP confederation
//! - `65535:65282` (`NO_ADVERTISE`) - All routes received with this community **MUST NOT** be advertised to other BGP peers
//! - `65535:65283` (`NO_EXPORT_SUBCONFED`) - ALl routes received with this community **MUST NOT** be advertised to eBGP peers
//!
//! ## References
//! - [RFC 1997 "BGP Communities Attribute"](https://datatracker.ietf.org/doc/html/rfc1997)
//! - [RFC 4360 "BGP Extended Communities Attribute"](https://datatracker.ietf.org/doc/html/rfc4360)
//! - [RFC 5668 "4-Octet AS-specific BGP Extended Community"](https://datatracker.ietf.org/doc/html/rfc5668)

use std::net::Ipv4Addr;
use bitflags::bitflags;
use nom::{IResult, bytes::complete::take, number::complete::{be_u16, be_u32, be_u8}};

bitflags! {
    #[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
    pub struct CommunityFlags: u8 {
        /// IANA-assignable type using the "First Come First Serve" policy
        const IANA_AUTHORITY = 0b1000_0000;

        /// Determines whether the community is transitive across ASes
        const TRANSITIVE = 0b0100_0000;
    }
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
pub enum Assignment {
    RouteTarget,
    RouteOrigin,
    Unknown { value: u8 }
}

impl From<u8> for Assignment {
    fn from(value: u8) -> Self {
        match value {
            0x02 => Assignment::RouteTarget,
            0x03 => Assignment::RouteOrigin,
            _ => Assignment::Unknown { value }
        }
    }
}

impl From<Assignment> for u8 {
    fn from(value: Assignment) -> Self {
        match value {
            Assignment::RouteTarget => 0x02,
            Assignment::RouteOrigin => 0x03,
            Assignment::Unknown { value } => value
        }
    }
}

/// This struct is representing a BGP community. A community is used to add metainformation to the route like advertisement information for
/// the route. This struct support serializing basic RFC 1997 communities and extended communities as specified in RFC 4360 with support for
/// 4-byte ASNs (RFC 5668).
///
/// ## References
/// - [RFC 1997 "BGP Communities Attribute"](https://datatracker.ietf.org/doc/html/rfc1997)
/// - [RFC 4360 "BGP Extended Communities Attribute"](https://datatracker.ietf.org/doc/html/rfc4360)
/// - [RFC 5668 "4-Octet AS-specific BGP Extended Community"](https://datatracker.ietf.org/doc/html/rfc5668)
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
pub enum Community {
    /// This value indicates a community value as specified in [RFC 1997](https://datatracker.ietf.org/doc/html/rfc1997) for 2-octet
    /// autonomous systems.
    ///
    /// ## References
    /// - [RFC 1997 "BGP Communities Attribute"](https://datatracker.ietf.org/doc/html/rfc1997)
    RFC1997 { global_administrator: u16, local_administrator: u16 },

    /// This value indicates an extended community value (4-byte local administrator value) for an 2-byte ASN (as assigned by one of the
    /// registries) as specified in RFC 4360.
    ///
    /// ## References
    /// - [Two-octet AS Specific Extended Community, Section 3.1 RFC 4360](https://datatracker.ietf.org/doc/html/rfc4360#section-3.1)
    RFC4360ASN { subkind: Assignment, flags: CommunityFlags, global_administrator: u16, local_administrator: u32 },

    /// This value indicates an extended community value (2-byte local administrator value) for an IPv4 unicast address assigned by one
    /// of the Registries.
    ///
    /// ## References
    /// - [IPv4 Address Specific Extended Community, Section 3.2 RFC 4360](https://datatracker.ietf.org/doc/html/rfc4360#section-3.2)
    RFC4360Address { subkind: Assignment, flags: CommunityFlags, global_administrator: Ipv4Addr, local_administrator: u16 },

    /// This value indicates an opaque extended community as specified by RFC 4360.
    ///
    /// ## References
    /// - [Opaque Extended Community, Section 3.3 RFC 4360](https://datatracker.ietf.org/doc/html/rfc4360#section-3.3)
    RFC4360Opaque { subkind: Assignment, flags: CommunityFlags, value: [u8; 6] },

    /// This value indicates an RFC5668-specified community value for 4-byte ASN values.
    ///
    /// ## References
    /// - [4-Octet AS Specific Extended Community, Section 2 RFC 5668](https://datatracker.ietf.org/doc/html/rfc5668#section-2)
    RFC5668ASN { subkind: Assignment, flags: CommunityFlags, global_administrator: u32, local_administrator: u16 },

    Unknown { kind: u8, subkind: Assignment, flags: CommunityFlags }
}

impl Community {
    /// This function takes the input bytes and serializes them into a community. The `extended_attribute` parameter is set true, if this
    /// element is being parsed in an extended communities path attribute, otherwise that should be set false. If successful, this function
    /// returns the remaining bytes as a slice and the community itself.
    pub(crate) fn unpack(input: &[u8], extended_community: bool) -> IResult<&[u8], Self> {
        if !extended_community {
            let (input, global_administrator) = be_u16(input)?;
            let (input, local_administrator) = be_u16(input)?;
            Ok((input, Self::RFC1997 { global_administrator, local_administrator }))
        } else {
            let (input, kind) = be_u8(input)?;
            let (input, subkind) = be_u8(input)?;
            let subkind = Assignment::from(subkind);
            let flags = CommunityFlags::from_bits(kind).unwrap_or(CommunityFlags::empty());

            match kind {
                0x00 | 0x40 => {
                    let (input, global_administrator) = be_u16(input)?;
                    let (input, local_administrator) = be_u32(input)?;
                    Ok((input, Self::RFC4360ASN { subkind, flags, global_administrator, local_administrator }))
                },
                0x01 | 0x41 => {
                    let (input, global_administrator) = be_u32(input)?;
                    let (input, local_administrator) = be_u16(input)?;
                    Ok((input, Self::RFC4360Address {
                        subkind,
                        flags,
                        global_administrator: Ipv4Addr::from_bits(global_administrator),
                        local_administrator
                    }))
                },
                0x02 | 0x42 => {
                    let (input, global_administrator) = be_u32(input)?;
                    let (input, local_administrator) = be_u16(input)?;
                    Ok((input, Self::RFC5668ASN { subkind, flags, global_administrator, local_administrator }))
                }
                0x03 | 0x43 => {
                    let (input, value) = take(6usize)(input)?;
                    Ok((input, Self::RFC4360Opaque { subkind, flags, value: value.try_into().unwrap() }))
                },
                _ => Ok((input, Self::Unknown { kind, subkind, flags }))
            }
        }
    }
}
