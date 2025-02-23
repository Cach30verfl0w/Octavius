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

use nom::bytes::complete::take;
use nom::IResult;
use nom::multi::many0;
use nom::number::complete::be_u8;
use crate::protocols::bgp::rfc3392::Capability;
use nom::Parser;

/// This enum implements all optional parameters which are sent with the BGP open message. These parameters contains some information about
/// the router and it's capabilities ([RFC 3392](https://datatracker.ietf.org/doc/html/rfc3392)).<
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum OptionalParameter {
    Capabilities(Vec<Capability>),
    Unknown { kind: u8, data: Vec<u8> }
}

impl OptionalParameter {
    pub(crate) fn unpack(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, kind) = be_u8(input)?;
        let (input, length) = be_u8(input)?;
        let (input, data) = take(length)(input)?;
        Ok((input, match kind {
            2 => Self::Capabilities(many0(Capability::unpack).parse(data)?.1),
            _ => Self::Unknown { kind, data: data.to_vec() }
        }))
    }
}
