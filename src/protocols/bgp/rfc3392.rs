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

use std::fmt::{Display, Formatter};
use nom::bytes::complete::take;
use nom::IResult;
use nom::number::complete::{be_u8, be_u32};
use crate::protocols::bgp::rfc4760::MultiprotocolExtensionsCapability;
use crate::protocols::bgp::rfc6793::FourOctetASNumberSupportCapability;

/// This enum implements a wrapper around [RFC 3392](https://datatracker.ietf.org/doc/html/rfc3392) that defines the capability
/// advertisement with BGP-4.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Capability {
    MultiprotocolExtensions(MultiprotocolExtensionsCapability),
    FourOctetASNumberSupport(FourOctetASNumberSupportCapability),
    Unknown { kind: u8, data: Vec<u8> }
}

impl Capability {
    pub(crate) fn unpack(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, kind) = be_u8(input)?;
        let (input, length) = be_u8(input)?;
        let (input, data) = take(length)(input)?;
        println!("{}", kind);
        Ok((input, match kind {
            1 => Self::MultiprotocolExtensions(MultiprotocolExtensionsCapability::unpack(data)?.1),
            65 => Self::FourOctetASNumberSupport(FourOctetASNumberSupportCapability { as_number: be_u32(data)?.1 }),
            _ => Self::Unknown { kind, data: data.to_vec() }
        }))
    }
}

impl Display for Capability {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MultiprotocolExtensions(extensions) => write!(formatter, "{}", extensions),
            Self::FourOctetASNumberSupport(support) => write!(formatter, "AS{}", support.as_number),
            Self::Unknown { kind, data } => write!(formatter, "Unknown {} bytes (Kind: {})", data.len(), kind)
        }
    }
}
