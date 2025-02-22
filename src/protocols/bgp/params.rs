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

use std::io::{Cursor, Read};
use tokio::io::AsyncReadExt;
use crate::protocols::bgp::rfc3392::Capability;

/// This enum implements all optional parameters which are sent with the BGP open message. These parameters contains some information about
/// the router and it's capabilities ([RFC 3392](https://datatracker.ietf.org/doc/html/rfc3392)).
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum OptionalParameter {
    Capabilities(Vec<Capability>),
    Unknown { kind: u8, data: Vec<u8> }
}

impl OptionalParameter {
    pub(crate) async fn unpack(reader: &mut Cursor<&[u8]>) -> anyhow::Result<Self> {
        let kind = reader.read_u8().await?;
        let length = reader.read_u8().await?;
        let mut reader = Read::take(reader, length as _).into_inner();
        Ok(match kind {
            2 => Self::Capabilities(Capability::unpack_list(reader).await?),
            _ => {
                let mut data = Vec::with_capacity(length as _);
                Read::read(&mut reader, &mut data)?;
                Self::Unknown { kind, data }
            }
        })
    }
}
