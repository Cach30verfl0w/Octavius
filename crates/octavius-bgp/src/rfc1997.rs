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

use crate::type_enum;
use bitflags::bitflags;
use nom::{
    bytes::complete::take,
    number::complete::{
        be_u16,
        be_u32,
        be_u8,
    },
    IResult,
};
use std::{
    net::Ipv4Addr,
    prelude::v1::Vec,
};

bitflags! {
    #[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
    pub struct CommunityFlags: u8 {
        /// IANA-assignable type using the "First Come First Serve" policy
        const IANA_AUTHORITY = 0b1000_0000;

        /// Determines whether the community is transitive across ASes
        const TRANSITIVE = 0b0100_0000;
    }
}

type_enum! {
    #[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone, Copy)]
    pub enum Assignment: be_u8(u8) {
        RouteTarget = 0x02,
        RouteOrigin = 0x03
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
    RFC1997 {
        global_administrator: u16,
        local_administrator: u16,
    },

    /// This value indicates an extended community value (4-byte local administrator value) for an 2-byte ASN (as assigned by one of the
    /// registries) as specified in RFC 4360.
    ///
    /// ## References
    /// - [Two-octet AS Specific Extended Community, Section 3.1 RFC 4360](https://datatracker.ietf.org/doc/html/rfc4360#section-3.1)
    #[cfg(feature = "rfc4360")]
    RFC4360ASN {
        subkind: Assignment,
        flags: CommunityFlags,
        global_administrator: u16,
        local_administrator: u32,
    },

    /// This value indicates an extended community value (2-byte local administrator value) for an IPv4 unicast address assigned by one
    /// of the Registries.
    ///
    /// ## References
    /// - [IPv4 Address Specific Extended Community, Section 3.2 RFC 4360](https://datatracker.ietf.org/doc/html/rfc4360#section-3.2)
    #[cfg(feature = "rfc4360")]
    RFC4360Address {
        subkind: Assignment,
        flags: CommunityFlags,
        global_administrator: Ipv4Addr,
        local_administrator: u16,
    },

    /// This value indicates an opaque extended community as specified by RFC 4360.
    ///
    /// ## References
    /// - [Opaque Extended Community, Section 3.3 RFC 4360](https://datatracker.ietf.org/doc/html/rfc4360#section-3.3)
    #[cfg(feature = "rfc4360")]
    RFC4360Opaque {
        subkind: Assignment,
        flags: CommunityFlags,
        value: [u8; 6],
    },

    /// This value indicates an RFC5668-specified community value for 4-byte ASN values.
    ///
    /// ## References
    /// - [4-Octet AS Specific Extended Community, Section 2 RFC 5668](https://datatracker.ietf.org/doc/html/rfc5668#section-2)
    #[cfg(feature = "rfc5668")]
    RFC5668ASN {
        subkind: Assignment,
        flags: CommunityFlags,
        global_administrator: u32,
        local_administrator: u16,
    },

    Unknown {
        kind: u8,
        subkind: Assignment,
        flags: CommunityFlags,
    },
}

impl Community {
    pub fn unpack(input: &[u8], extended_community: bool) -> IResult<&[u8], Self> {
        if !extended_community {
            let (input, global_administrator) = be_u16(input)?;
            let (input, local_administrator) = be_u16(input)?;
            Ok((
                input,
                Self::RFC1997 {
                    global_administrator,
                    local_administrator,
                },
            ))
        } else {
            let (input, kind) = be_u8(input)?;
            let (input, subkind) = be_u8(input)?;
            let subkind = Assignment::from(subkind);
            let flags = CommunityFlags::from_bits(kind).unwrap_or(CommunityFlags::empty());

            match kind {
                0x00 | 0x40 => {
                    let (input, global_administrator) = be_u16(input)?;
                    let (input, local_administrator) = be_u32(input)?;
                    Ok((
                        input,
                        Self::RFC4360ASN {
                            subkind,
                            flags,
                            global_administrator,
                            local_administrator,
                        },
                    ))
                }
                0x01 | 0x41 => {
                    let (input, global_administrator) = be_u32(input)?;
                    let (input, local_administrator) = be_u16(input)?;
                    Ok((
                        input,
                        Self::RFC4360Address {
                            subkind,
                            flags,
                            global_administrator: Ipv4Addr::from_bits(global_administrator),
                            local_administrator,
                        },
                    ))
                }
                0x02 | 0x42 => {
                    let (input, global_administrator) = be_u32(input)?;
                    let (input, local_administrator) = be_u16(input)?;
                    Ok((
                        input,
                        Self::RFC5668ASN {
                            subkind,
                            flags,
                            global_administrator,
                            local_administrator,
                        },
                    ))
                }
                0x03 | 0x43 => {
                    let (input, value) = take(6usize)(input)?;
                    Ok((
                        input,
                        Self::RFC4360Opaque {
                            subkind,
                            flags,
                            value: value.try_into().unwrap(),
                        },
                    ))
                }
                _ => Ok((input, Self::Unknown { kind, subkind, flags })),
            }
        }
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        match self {
            Community::RFC1997 {
                global_administrator,
                local_administrator,
            } => {
                buffer.extend_from_slice(&global_administrator.to_be_bytes());
                buffer.extend_from_slice(&local_administrator.to_be_bytes());
            }
            Community::RFC4360ASN {
                subkind,
                flags,
                global_administrator,
                local_administrator,
            } => {
                buffer.extend_from_slice(&(0x00 | flags.bits()).to_be_bytes());
                buffer.extend_from_slice(&u8::from(*subkind).to_be_bytes());
                buffer.extend_from_slice(&global_administrator.to_be_bytes());
                buffer.extend_from_slice(&local_administrator.to_be_bytes());
            }
            Community::RFC4360Address {
                subkind,
                flags,
                global_administrator,
                local_administrator,
            } => {
                buffer.extend_from_slice(&(0x01 | flags.bits()).to_be_bytes());
                buffer.extend_from_slice(&u8::from(*subkind).to_be_bytes());
                buffer.extend_from_slice(&global_administrator.octets());
                buffer.extend_from_slice(&local_administrator.to_be_bytes());
            }
            Community::RFC5668ASN {
                subkind,
                flags,
                global_administrator,
                local_administrator,
            } => {
                buffer.extend_from_slice(&(0x02 | flags.bits()).to_be_bytes());
                buffer.extend_from_slice(&u8::from(*subkind).to_be_bytes());
                buffer.extend_from_slice(&global_administrator.to_be_bytes());
                buffer.extend_from_slice(&local_administrator.to_be_bytes());
            }
            Community::RFC4360Opaque { subkind, flags, value } => {
                buffer.extend_from_slice(&(0x03 | flags.bits()).to_be_bytes());
                buffer.extend_from_slice(&u8::from(*subkind).to_be_bytes());
                buffer.extend_from_slice(value.as_slice());
            }
            Community::Unknown { .. } => {}
        }
        buffer
    }
}
