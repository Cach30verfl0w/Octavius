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
use std::net::IpAddr;
use nom::bytes::complete::take;
use nom::IResult;
use nom::multi::many0;
use nom::number::complete::{be_u8, be_u16};
use nom::Parser;
use crate::prefix::Prefix;
use crate::protocols::bgp::unpack_address;

/// This enum represents all AFI (Address family identifier) supported by this BGP implementation, currently we only support IPv4 and IPv6.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
pub enum AddressFamily {
    /// This value indicates IPv4 (Internet protocol version 4, 32 bits)
    IPv4,

    /// This value indicates IPv6 (Internet protocol version 6, 128 bits)
    IPv6,

    /// This value indicates an unknown AFI identifier
    Unknown(u16)
}

impl From<u16> for AddressFamily {
    fn from(value: u16) -> Self {
        match value {
            0x01 => Self::IPv4,
            0x02 => Self::IPv6,
            _ => Self::Unknown(value)
        }
    }
}

impl From<AddressFamily> for u16 {
    fn from(value: AddressFamily) -> Self {
        match value {
            AddressFamily::IPv4 => 0x01,
            AddressFamily::IPv6 => 0x02,
            AddressFamily::Unknown(value) => value
        }
    }
}

impl Display for AddressFamily {
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
pub enum SubsequentAddressFamily {
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

impl From<u8> for SubsequentAddressFamily {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Unicast,
            2 => Self::Multicast,
            _ => Self::Unknown(value)
        }
    }
}

impl From<SubsequentAddressFamily> for u8 {
    fn from(value: SubsequentAddressFamily) -> Self {
        match value {
            SubsequentAddressFamily::Unicast => 1,
            SubsequentAddressFamily::Multicast => 2,
            SubsequentAddressFamily::Unknown(value) => value
        }
    }
}

impl Display for SubsequentAddressFamily {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unicast => write!(formatter, "Unicast"),
            Self::Multicast => write!(formatter, "Multicast"),
            Self::Unknown(value) => write!(formatter, "Unknown ({})", value)
        }
    }
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
pub struct MultiprotocolNextHop {
    address: IpAddr,
    link_local_address: IpAddr
}

impl MultiprotocolNextHop {
    fn unpack(input: &[u8], address_family: AddressFamily) -> IResult<&[u8], Self> {
        let (input, length) = be_u8(input)?;
        let (input, data) = take(length)(input)?;
        let (data, address) = unpack_address(data, address_family)?;
        let (_, link_local_address) = unpack_address(data, address_family)?;
        Ok((input, Self { address, link_local_address }))
    }
}

/// This struct represents the capability parameter for the open message that indicates that this router supports the multiprotocol
/// extensions for the following address and subsequent address family.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
pub struct MultiprotocolExtensionsCapability {
    pub address_family: AddressFamily,
    pub subsequent_address_family: SubsequentAddressFamily,
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
            address_family: AddressFamily::from(address_family),
            subsequent_address_family: SubsequentAddressFamily::from(subsequent_address_family)
        }))
    }
}

/// This struct represents the multiprotocol reachable path attribute defined by the Multiprotocol Extensions for BGP as an optional and
/// non-transitive attribute. It's used to advertise a route to a peer or to permit a router to advertise the network layer address of the
/// router.
///
/// ## References
/// - [Multiprotocol Reachable NLRI - MP_REACH_NLRI, Section 3 RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760#section-3)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiprotocolReachablePathAttribute {
    pub address_family: AddressFamily,
    pub subsequent_address_family: SubsequentAddressFamily,
    pub next_hop_address: MultiprotocolNextHop,
    pub network_layer_reachability_information: Vec<Prefix>
}

impl MultiprotocolReachablePathAttribute {
    pub(crate) fn unpack(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, address_family) = be_u16(input)?;
        let address_family = AddressFamily::from(address_family);

        let (input, subsequent_address_family) = be_u8(input)?;
        let subsequent_address_family = SubsequentAddressFamily::from(subsequent_address_family);

        let (input, next_hop_address) = MultiprotocolNextHop::unpack(input, address_family)?;
        let (nlri, _) = be_u8(input)?;

        let (_, network_layer_reachability_information) = many0(|b| Prefix::unpack(b, address_family)).parse(nlri)?;
        Ok((&[], Self {
            address_family,
            subsequent_address_family,
            next_hop_address,
            network_layer_reachability_information
        }))
    }
}

/// This struct represents the multiprotocol unreachable NLRI path attribute defined by the Multiprotocol Extensions for BGP as an optional
/// and non-transitive attribute for withdrawing multiple routes from the service.
///
/// ## References
/// - [Multiprotocol Unreachable NLRI - MP_UNREACH_NLRI, Section 4 RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760#section-4)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiprotocolUnreachablePathAttribute {
    pub address_family: AddressFamily,
    pub subsequent_address_family: SubsequentAddressFamily,
    pub network_layer_reachability_information: Vec<Prefix>
}

impl MultiprotocolUnreachablePathAttribute {
    pub(crate) fn unpack(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, address_family) = be_u16(input)?;
        let (nlri, subsequent_address_family) = be_u8(input)?;
        let address_family = AddressFamily::from(address_family);
        let subsequent_address_family = SubsequentAddressFamily::from(subsequent_address_family);
        let (_, network_layer_reachability_information) = many0(|b| Prefix::unpack(b, address_family)).parse(nlri)?;
        Ok((&[], Self {
            address_family,
            subsequent_address_family,
            network_layer_reachability_information
        }))
    }
}
