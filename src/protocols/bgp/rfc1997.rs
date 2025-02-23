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

use std::str::FromStr;
use nom::{IResult, Parser, number::complete::be_u16};

/// This struct is representing a BGP community. A community is used to add metainformation to the route like advertisement information for
/// the route.
///
/// ## References
/// - [RFC 1997 "BGP Communities Attribute"](https://datatracker.ietf.org/doc/html/rfc1997)
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Community {
    /// The ASN (Autonomous System Number) is used as a namespace parameter for the community value. It identifies the network operating
    /// with the community value and establishes a relationship between the community and the ASN itself.
    pub namespace: u16,

    /// The local tag of the community. This value represents the value of the community within the autonomous system (AS) and is used to
    /// identify rules/policies for the routes.
    pub local_tag: u16
}

impl From<u32> for Community {
    #[inline(always)]
    fn from(value: u32) -> Self {
        Self { namespace: ((value >> 16) & 0xFFFF) as _, local_tag: (value & 0xFFFF) as _ }
    }
}

impl From<Community> for u32 {
    #[inline(always)]
    fn from(value: Community) -> Self {
        (value.namespace as u32) << 16 | value.local_tag as u32
    }
}

impl FromStr for Community {
    type Err = anyhow::Error;
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let (namespace, local_tag) = string.split_once(":").ok_or(anyhow::anyhow!("String is not matching format namespace:local_tag"))?;
        Ok(Self { namespace: namespace.parse()?, local_tag: local_tag.parse()? })
    }
}

impl Community {
    pub const NO_EXPORT: Community = Community { namespace: 0xFFFF, local_tag: 0xFF01 };
    pub const NO_ADVERTISE: Community = Community { namespace: 0xFFFF, local_tag: 0xFF01 };
    pub const NO_EXPORT_SUBCONFED: Community = Community { namespace: 0xFFFF, local_tag: 0xFF01 };

    pub fn unpack(input: &[u8]) -> IResult<&[u8], Community> {
        let (input, namespace) = be_u16(input)?;
        let (input, local_tag) = be_u16(input)?;
        Ok((input, Self { namespace, local_tag }))
    }
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct CommunitiesPathAttribute {
    pub communities: Vec<Community>
}

impl CommunitiesPathAttribute {
    #[inline]
    pub fn unpack(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, communities) = nom::multi::many0(Community::unpack).parse(input)?;
        Ok((input, Self { communities }))
    }
}
