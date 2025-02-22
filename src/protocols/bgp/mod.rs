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
//! | [RFC 2918](https://datatracker.ietf.org/doc/html/rfc2918) | Route Refresh Capability for BGP-4    | Planned           | -/-       |
//! | [RFC 3392](https://datatracker.ietf.org/doc/html/rfc3392) | Capabilities Advertisement with BGP-4 | Fully implemented | [rfc3392] |
//! | [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271) | A Border Gateway Protocol 4 (BGP-4)   | Fully implemented | [self]    |
//! | [RFC 4370](https://datatracker.ietf.org/doc/html/rfc4360) | BGP Extended Communities Attribute    | Planned           | -/-       |
//! | [RFC 4724](https://datatracker.ietf.org/doc/html/rfc4724) | Graceful Restart Mechanism for BGP    | Planned           | -/-       |
//! | [RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760) | Multiprotocol Extensions for BGP-4    | Fully implemented | [rfc4760] |
//! | [RFC 6793](https://datatracker.ietf.org/doc/html/rfc6793) | BGP Support for Four-Octet AS Numbers | Planned           | -/-       |
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
pub mod path_attr;

#[cfg(test)]
pub mod tests;

use std::fmt::{Display, Formatter};
use std::io::{Cursor, Read};
use bitflags::bitflags;
use rocket::http::hyper::body::Buf;
use tokio::io::AsyncReadExt;
use crate::protocols::bgp::params::OptionalParameter;
use crate::protocols::bgp::path_attr::OriginAttribute;

const HEADER_SIZE: u16 = 19; // Marker (16 bytes) + length (2 bytes) + kind (1 bytes) = Header Size in bytes

/// This enum provides all BGP message kinds/types available through this BGP (de-)serialization library. It allows a type-safe handling of
/// the incoming packets.
///
/// ## References
/// - [Message Header Format, Section 4.1 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.1)
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
pub enum MessageKind {
    Open,
    Update,
    Notification,
    KeepAlive,
    Unknown(u8)
}

impl From<u8> for MessageKind {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Open,
            2 => Self::Update,
            3 => Self::Notification,
            4 => Self::KeepAlive,
            _ => Self::Unknown(value),
        }
    }
}

impl From<MessageKind> for u8 {
    fn from(kind: MessageKind) -> Self {
        match kind {
            MessageKind::Open => 1,
            MessageKind::Update => 2,
            MessageKind::Notification => 3,
            MessageKind::KeepAlive => 4,
            MessageKind::Unknown(value) => value
        }
    }
}

/// This struct is the type-safe implementation for handling the header of incoming or outgoing BGP messages. These headers are applied at
/// the start of any BGP packet. It contains the length of the message (inclusive the header itself) and the kind/type of the message.
///
/// ## Reference
/// - [Message Header Format, Section 4.1 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.1)
struct MessageHeader {
    pub length: u16,
    pub kind: MessageKind
}

/// This enum is the implementation for processing all supported BGP messages transferred in a BGP session. This should be used when
/// implementing a BGP receiver/sender.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum BGPMessage {
    Open(OpenMessage),
    Update(UpdateMessage),
    KeepAlive,
    Notification(NotificationMessage),
    Unknown { kind: MessageKind }
}

impl BGPMessage {
    pub(crate) async fn unpack(reader: &mut Cursor<&[u8]>) -> anyhow::Result<Self> {
        let mut marker = [0u8; 16];
        Read::read(&mut *reader, &mut marker)?;
        let length = reader.read_u16().await?;
        let kind = MessageKind::from(reader.read_u8().await?);
        let header = MessageHeader { length, kind };

        Ok(match header.kind {
            MessageKind::Open => Self::Open(OpenMessage::unpack(reader).await?),
            MessageKind::Update => Self::Update(UpdateMessage::unpack(&header, reader).await?),
            MessageKind::Notification => Self::Notification(NotificationMessage::unpack(&header, reader).await?),
            MessageKind::KeepAlive => Self::KeepAlive,
            _ => Self::Unknown { kind: header.kind }
        })
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
    async fn unpack(reader: &mut Cursor<&[u8]>) -> anyhow::Result<Self> {
        let version = reader.read_u8().await?;
        let autonomous_system = reader.read_u16().await?;
        let hold_time = reader.read_u16().await?;
        let bgp_identifier = reader.read_u32().await?;

        // Read optional parameters
        let opt_param_length = reader.read_u8().await?;
        let opt_param_cursor = Read::take(reader, opt_param_length as _).into_inner();
        let mut optional_parameters = Vec::new();
        while opt_param_cursor.remaining() >= 2 {
            optional_parameters.push(OptionalParameter::unpack(opt_param_cursor).await?);
        }

        // Return
        Ok(Self { version, autonomous_system, hold_time, bgp_identifier, optional_parameters })
    }
}

bitflags! {
    /// ## References
    /// - [UPDATE Message Format, Section 4.2 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.3)
    #[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
    pub struct PathAttributeFlags: u8 {
        const OPTIONAL        = 0b0001_0000;
        const TRANSITIVE      = 0b0010_0000;
        const PARTIAL         = 0b0100_0000;
        const EXTENDED_LENGTH = 0b1000_0000;
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
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum PathAttribute {
    Origin(OriginAttribute),
    Unknown { flags: PathAttributeFlags, kind: u8, data: Vec<u8> }
}

impl PathAttribute {
    async fn unpack(reader: &mut Cursor<&[u8]>) -> anyhow::Result<Self> {
        let flags = PathAttributeFlags::from_bits(reader.read_u8().await?).ok_or(anyhow::anyhow!("Unable to get flags of path attribute"))?;
        let kind = reader.read_u8().await?;
        let length = reader.read_u8().await?;
        let reader = Read::take(&mut *reader, length as _).into_inner();

        Ok(match kind {
            1 => Self::Origin(OriginAttribute::from(reader.read_u8().await?)),
            _ => {
                let mut data = Vec::with_capacity(reader.remaining());
                Read::read(reader, &mut data)?;
                Self::Unknown { flags, kind, data }
            }
        })
    }
}

impl Display for PathAttribute {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Origin(origin) => write!(formatter, "{:?}", origin),
            Self::Unknown { flags, kind, data } => write!(formatter, "Unknown {} bytes (Flags: {}, kind: {})", data.len(), flags, kind)
        }
    }
}

/// This struct is the type-safe implementation for handling the incoming/outgoing update message. The update messages tell the router about
/// routes newly announced, routes withdrawn and network layer reachability information.
///
/// ## Reference
/// - [UPDATE Message Format, Section 4.3 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.3)
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct UpdateMessage {
    pub withdrawn_routes: Vec<u8>, // TODO: struct
    pub path_attributes: Vec<PathAttribute>,
    pub network_layer_reachability_information: Vec<u8> // TODO: Prefix struct
}

impl UpdateMessage {
    async fn unpack(header: &MessageHeader, reader: &mut Cursor<&[u8]>) -> anyhow::Result<Self> {
        let mut withdrawn_routes = Vec::with_capacity(reader.read_u8().await? as _);
        Read::read(&mut *reader, &mut withdrawn_routes)?;

        let path_attributes_length = reader.read_u8().await?;
        let mut path_attributes = Vec::new();
        let mut path_attr_cursor = Read::take(&mut *reader, path_attributes_length as _);
        while path_attr_cursor.get_ref().has_remaining() {
            path_attributes.push(PathAttribute::unpack(path_attr_cursor.get_mut()).await?);
        }

        let remaining = header.length - HEADER_SIZE - (withdrawn_routes.len() as u16) - (path_attributes_length as u16);
        let mut network_layer_reachability_information = Vec::with_capacity(remaining as _);
        Read::read(&mut *reader, &mut network_layer_reachability_information)?;

        Ok(Self { withdrawn_routes, path_attributes, network_layer_reachability_information })
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
    async fn unpack(header: &MessageHeader, reader: &mut Cursor<&[u8]>) -> anyhow::Result<Self> {
        let error_code = reader.read_u8().await?;
        let error_subcode = reader.read_u8().await?;
        let data_size = header.length - HEADER_SIZE - 2;
        let mut data = Vec::with_capacity(data_size as _);
        Read::read(&mut *reader, &mut data)?;
        Ok(Self { error_code, error_subcode, data })
    }
}
