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
use std::io::{Cursor, Write};
use rocket::form::validate::Len;
use rocket::http::hyper::body::Buf;
use tokio::io::AsyncReadExt;
use crate::protocols::bgp::rfc4760::{AddressFamilyIdentifier, MultiprotocolExtensionsCapability, SubsequentAddrFamilyIdentifier};

/// This enum implements a wrapper around [RFC 3392](https://datatracker.ietf.org/doc/html/rfc3392) that defines the capability
/// advertisement with BGP-4.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Capability {
    MultiprotocolExtensions(MultiprotocolExtensionsCapability),
    Unknown { kind: u8, data: Vec<u8> }
}

impl Capability {
    pub(crate) async fn unpack_list(reader: &mut Cursor<&[u8]>) -> anyhow::Result<Vec<Self>> {
        let mut capabilities = Vec::new();
        while reader.remaining() >= 2 {
            let kind = reader.read_u8().await?;
            let length = reader.read_u8().await?;
            capabilities.push(match kind {
                1 => {
                    let address_family = AddressFamilyIdentifier::from(reader.read_u16().await?);
                    let _ = reader.read_u8().await?; // Reserved
                    let subsequent_address_family = SubsequentAddrFamilyIdentifier::from(reader.read_u8().await?);
                    Self::MultiprotocolExtensions(MultiprotocolExtensionsCapability { address_family, subsequent_address_family })
                }
                _ => {
                    let mut data = Vec::with_capacity(length as _);
                    reader.read(&mut data).await?;
                    Self::Unknown { kind, data }
                }
            })
        }
        Ok(capabilities)
    }

    async fn pack<W: Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        match self {
            Self::MultiprotocolExtensions(extensions) => {
                writer.write_all(&1.to_be_bytes())?;
                writer.write_all(&4.to_be_bytes())?;
                writer.write_all(&u8::from(extensions.address_family).to_be_bytes())?;
                writer.write_all(&[0u8; 1])?;
                writer.write_all(&u8::from(extensions.subsequent_address_family).to_be_bytes())?;
            },
            Self::Unknown { kind, data } => {
                writer.write_all(&kind.to_be_bytes())?;
                writer.write_all(&(data.len() as u8).to_be_bytes())?;
                writer.write_all(&data)?;
            }
        }
        Ok(())
    }
}

impl Display for Capability {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MultiprotocolExtensions(extensions) => write!(formatter, "{}", extensions),
            Self::Unknown { kind, data } => write!(formatter, "Unknown {} bytes (Kind: {})", data.len(), kind)
        }
    }
}
