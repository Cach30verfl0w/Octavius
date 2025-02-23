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

//! This module implements the [RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760) that implements the multiprotocol extensions for
//! BGP. This extension allows the support for IPv6 addresses to the BGP router.

use std::fmt::{Display, Formatter};
use nom::IResult;
use nom::number::complete::{be_u8, be_u16};

/// This enum represents all AFI (Address family identifier) supported by this BGP implementation, currently we only support IPv4 and IPv6.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
pub enum AddressFamilyIdentifier {
    /// This value indicates IPv4 (Internet protocol version 4, 32 bits)
    IPv4,

    /// This value indicates IPv6 (Internet protocol version 6, 128 bits)
    IPv6,

    /// This value indicates an unknown AFI identifier
    Unknown(u16)
}

impl From<u16> for AddressFamilyIdentifier {
    fn from(value: u16) -> Self {
        match value {
            0x01 => Self::IPv4,
            0x02 => Self::IPv6,
            _ => Self::Unknown(value)
        }
    }
}

impl From<AddressFamilyIdentifier> for u16 {
    fn from(value: AddressFamilyIdentifier) -> Self {
        match value {
            AddressFamilyIdentifier::IPv4 => 0x01,
            AddressFamilyIdentifier::IPv6 => 0x02,
            AddressFamilyIdentifier::Unknown(value) => value
        }
    }
}

impl Display for AddressFamilyIdentifier {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IPv4 => write!(formatter, "IPv4"),
            Self::IPv6 => write!(formatter, "IPv6"),
            Self::Unknown(value) => write!(formatter, "Unknown ({})", value)
        }
    }
}

/// This enum represents all SAFI (Subsequent address family identifier) supported by this BGP implementation, currently we only support
/// Unicast or Multicast.
///
/// ## References
/// [Subsequent Address Family Identifier, Section 6 RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760#section-6)
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
pub enum SubsequentAddrFamilyIdentifier {
    /// This value indicates Unicast forwarding
    ///
    /// ## References
    /// [Subsequent Address Family Identifier, Section 6 RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760#section-6)
    Unicast,

    /// This value indicates Multicast forwarding
    ///
    /// ## References
    /// [Subsequent Address Family Identifier, Section 6 RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760#section-6)
    Multicast,

    /// This value indicates an unknown SAFI identifier
    Unknown(u8)
}

impl From<u8> for SubsequentAddrFamilyIdentifier {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Unicast,
            2 => Self::Multicast,
            _ => Self::Unknown(value)
        }
    }
}

impl From<SubsequentAddrFamilyIdentifier> for u8 {
    fn from(value: SubsequentAddrFamilyIdentifier) -> Self {
        match value {
            SubsequentAddrFamilyIdentifier::Unicast => 1,
            SubsequentAddrFamilyIdentifier::Multicast => 2,
            SubsequentAddrFamilyIdentifier::Unknown(value) => value
        }
    }
}

impl Display for SubsequentAddrFamilyIdentifier {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unicast => write!(formatter, "Unicast"),
            Self::Multicast => write!(formatter, "Multicast"),
            Self::Unknown(value) => write!(formatter, "Unknown ({})", value)
        }
    }
}

/// This struct represents the capability parameter for the open message that indicates that this router supports the multiprotocol
/// extensions for the following address and subsequent address family.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
pub struct MultiprotocolExtensionsCapability {
    pub address_family: AddressFamilyIdentifier,
    pub subsequent_address_family: SubsequentAddrFamilyIdentifier,
}

impl Display for MultiprotocolExtensionsCapability {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Multiprotocol support for {} ({})", self.address_family, self.subsequent_address_family)
    }
}

impl MultiprotocolExtensionsCapability {
    pub(crate) fn unpack(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, address_family) = be_u16(input)?;
        let (input, _) = be_u8(input)?;
        let (input, subsequent_address_family) = be_u8(input)?;
        Ok((input, Self {
            address_family: AddressFamilyIdentifier::from(address_family),
            subsequent_address_family: SubsequentAddrFamilyIdentifier::from(subsequent_address_family)
        }))
    }
}
