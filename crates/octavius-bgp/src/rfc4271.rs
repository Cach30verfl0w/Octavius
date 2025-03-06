//! This file implemented the [RFC 4271 - A Border Gateway Protocol 4 (BGP-4)](https://datatracker.ietf.org/doc/html/rfc4271), the base RFC
//! of the BGP protocol which is specifying the base of the protocol.

use crate::BGPElement;
use alloc::vec::Vec;
use bitflags::bitflags;
use nom::{
    bytes::complete::take,
    error::{
        Error,
        ErrorKind,
    },
    multi::many0,
    number::complete::{
        be_u16,
        be_u32,
        be_u8,
    },
    IResult,
    Parser,
};

#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Copy, Hash)]
pub struct BGPMessageHeader {
    pub marker: [u8; 16],
    pub length: u16,
    pub kind: u8,
}

impl BGPElement for BGPMessageHeader {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, marker) = take(16usize)(input)?;
        let (input, length) = be_u16(input)?;
        let (input, kind) = be_u8(input)?;
        Ok((
            input,
            Self {
                marker: marker.try_into().unwrap(),
                length,
                kind,
            },
        ))
    }

    fn pack(&self) -> Vec<u8> {
        let mut buffer = self.marker.to_vec();
        buffer.extend_from_slice(&self.length.to_be_bytes());
        buffer.extend_from_slice(&self.kind.to_be_bytes());
        buffer
    }
}

/// This struct represents the BGP open message. The open message is sent between two BGP peers to initialize the connection and exchange
/// information about the router (supported extensions/capabilities etc.) to the other peer. It contains the BGP protocol version, this
/// library only supports BGP-4.
///
/// ## References
/// - [OPEN Message Format, Section 4.2 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.2)
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone)]
pub struct OpenMessage {
    pub version: u8,
    pub autonomous_system: u16,
    pub hold_time: u16,
    pub bgp_identifier: u32,
    pub optional_parameters: Vec<u8>,
}

impl BGPElement for OpenMessage {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, version) = be_u8(input)?;
        let (input, autonomous_system) = be_u16(input)?;
        let (input, hold_time) = be_u16(input)?;
        let (input, bgp_identifier) = be_u32(input)?;
        let (input, optional_parameters_length) = be_u8(input)?;
        let (input, optional_parameters) = take(optional_parameters_length as usize)(input)?;
        Ok((
            input,
            Self {
                version,
                autonomous_system,
                hold_time,
                bgp_identifier,
                optional_parameters: optional_parameters.to_vec(),
            },
        ))
    }

    fn pack(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.version.to_be_bytes());
        buffer.extend_from_slice(&self.autonomous_system.to_be_bytes());
        buffer.extend_from_slice(&self.hold_time.to_be_bytes());
        buffer.extend_from_slice(&self.bgp_identifier.to_be_bytes());
        buffer.extend_from_slice(&(self.optional_parameters.len() as u8).to_be_bytes());
        buffer.extend_from_slice(&self.optional_parameters);
        buffer
    }
}

bitflags! {
    /// This structure contains the flags of a path attribute.
    ///
    /// ## References
    /// - [UPDATE Message Format, Section 4.2 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.3)
    #[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
    pub struct PathAttributeFlags: u8 {
        /// This attribute flag indicates whether the path attribute is optional (1) or well-known (0).
        const OPTIONAL = 0b1000_0000;

        /// This attribute flag indicates whether the path attribute is transitive (1) or non-transitive (0). Well-known attributes require
        /// that the transitive bit is being set.
        const TRANSITIVE  = 0b0100_0000;

        /// This attribute flag indicates whether the information in the path attribute is partial (1) or complete (0). For well-known
        /// attributes and for optional non-transitive, the partial bit MUST be set to 0.
        const PARTIAL = 0b0010_0000;

        /// This attribute flags indicates whether the path attribute's length should be encoded as 2-byte value (1) or as 1-byte value (0).
        const EXTENDED_LENGTH = 0b0001_0000;

    }
}

/// Origin is a well-known mandatory attribute that defines the origin of the path information.
///
/// ## References
/// - [ORIGIN Path Attribute Usage, Section 5.1.1 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-5.1.1)
/// - [UPDATE Message Format, Section 4.2 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.3)
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone, Copy)]
#[repr(u8)]
pub enum Origin {
    IGP = 0,
    EGP = 1,
    Incomplete = 2,
}

impl From<u8> for Origin {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::IGP,
            1 => Self::EGP,
            _ => Self::Incomplete
        }
    }
}

impl From<&Origin> for u8 {
    fn from(value: &Origin) -> Self {
        match value {
            Origin::IGP => 0,
            Origin::EGP => 1,
            Origin::Incomplete => 2
        }
    }
}

/// This enum represents the path attributes sent in a BGP update message. Path attributes are providing information about the prefixes
/// being sent to the peer like communities, origin etc.
///
/// ## References
/// - [UPDATE Message Format, Section 4.2 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.3)
/// - [Path Attributes, Section 5 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-5)
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone)]
pub enum PathAttribute {
    Origin(Origin),
    // TODO: AS_PATH
    // TODO: NEXT_HOP
    MultiExitDisc(u32),
    LocalPref(u32),
    AtomicAggregate,
    // TODO: AGGREGATOR
    Unknown {
        kind: u8,
        flags: PathAttributeFlags,
        data: Vec<u8>,
    },
}

impl BGPElement for PathAttribute {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, flags) = be_u8(input)?;
        let flags = PathAttributeFlags::from_bits(flags).ok_or(nom::Err::Error(Error::new(input, ErrorKind::Tag)))?;
        let (input, kind) = be_u8(input)?;

        // Following to the parser rules for path attributes in section 4.3 of RFC 4271, the length is an u16 when the extended length flag
        // is applied. Otherwise, the length is just one byte.
        let (input, length) = if !flags.contains(PathAttributeFlags::EXTENDED_LENGTH) {
            let (input, length) = be_u8(input)?;
            (input, length as u16)
        } else {
            be_u16(input)?
        };

        let (input, data) = take(length)(input)?;
        Ok((
            input,
            match kind {
                1 => Self::Origin(Origin::from(be_u8(data)?.1)),
                4 => Self::MultiExitDisc(be_u32(data)?.1),
                5 => Self::LocalPref(be_u32(data)?.1),
                6 => Self::AtomicAggregate,
                _ => {
                    Self::Unknown {
                        kind,
                        flags,
                        data: data.to_vec(),
                    }
                }
            },
        ))
    }

    fn pack(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        match self {
            Self::Origin(origin) => {
                buffer.extend_from_slice(&PathAttributeFlags::TRANSITIVE.bits().to_be_bytes());
                buffer.extend_from_slice(&4_u8.to_be_bytes());
                buffer.extend_from_slice(&1_u8.to_be_bytes());
                buffer.extend_from_slice(&u8::from(origin).to_be_bytes());
            }
            Self::MultiExitDisc(multi_exit_disc) => {
                buffer.extend_from_slice(&PathAttributeFlags::OPTIONAL.bits().to_be_bytes());
                buffer.extend_from_slice(&4_u8.to_be_bytes());
                buffer.extend_from_slice(&4_u8.to_be_bytes());
                buffer.extend_from_slice(&multi_exit_disc.to_be_bytes());
            }
            Self::LocalPref(local_pref) => {
                buffer.extend_from_slice(&PathAttributeFlags::TRANSITIVE.bits().to_be_bytes());
                buffer.extend_from_slice(&5_u8.to_be_bytes());
                buffer.extend_from_slice(&4_u8.to_be_bytes());
                buffer.extend_from_slice(&local_pref.to_be_bytes());
            }
            Self::AtomicAggregate => {
                buffer.extend_from_slice(&PathAttributeFlags::TRANSITIVE.bits().to_be_bytes());
                buffer.extend_from_slice(&6_u8.to_be_bytes());
                buffer.extend_from_slice(&0_u8.to_be_bytes());
            }
            Self::Unknown { kind, flags, data } => {
                let use_extended_length = data.len() > u8::MAX as _;
                let flags = if use_extended_length {
                    flags.union(PathAttributeFlags::EXTENDED_LENGTH)
                } else {
                    flags.clone()
                };
                buffer.extend_from_slice(&flags.bits().to_be_bytes());
                buffer.extend_from_slice(&kind.to_be_bytes());
                if flags.contains(PathAttributeFlags::EXTENDED_LENGTH) {
                    buffer.extend_from_slice(&(data.len() as u16).to_be_bytes());
                } else {
                    buffer.extend_from_slice(&(data.len() as u8).to_be_bytes());
                }
                buffer.extend_from_slice(&data);
            }
        }
        buffer
    }
}

/// This struct represents the BGP update message. The update message is sent after the establishment of the connection to exchange route
/// information to the BGP peer like Network Layer Reachability Information (NLRI, new reachable routes) with some information about the
/// prefixes itself (path attributes).
///
/// ## References
/// - [UPDATE Message Format, Section 4.3 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.3)
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone)]
pub struct UpdateMessage {
    pub withdrawn_routes: Vec<u8>,
    pub path_attributes: Vec<PathAttribute>,
    pub nlri: Vec<u8>,
}

impl BGPElement for UpdateMessage {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, withdrawn_routes_length) = be_u16(input)?;
        let (input, withdrawn_routes) = take(withdrawn_routes_length as usize)(input)?;
        let (input, path_attributes_length) = be_u16(input)?;
        let (nlri, path_attributes) = take(path_attributes_length as usize)(input)?;
        let (_, path_attributes) = many0(PathAttribute::unpack).parse(path_attributes)?;

        Ok((
            &[],
            Self {
                withdrawn_routes: withdrawn_routes.to_vec(),
                path_attributes,
                nlri: nlri.to_vec(),
            },
        ))
    }

    fn pack(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&(self.withdrawn_routes.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&self.withdrawn_routes);

        // Write path attributes
        let mut path_attr_buffer = Vec::new();
        for path_attribute in &self.path_attributes {
            path_attr_buffer.extend_from_slice(&path_attribute.pack());
        }

        buffer.extend_from_slice(&(path_attr_buffer.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&path_attr_buffer);

        // Write NLRI and return
        buffer.extend_from_slice(&self.nlri);
        buffer
    }
}

/// This struct represents the BGP notification message. The notification message is sent to inform a peer about an error while processing
/// the peer's routes or generally something related to that peer.
///
/// ## References
/// - [NOTIFICATION Message Format, Section 4.5 RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271#section-4.5)
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone)]
pub struct NotificationMessage {
    pub error_code: u8,
    pub error_subcode: u8,
    pub data: Vec<u8>,
}

impl BGPElement for NotificationMessage {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, error_code) = be_u8(input)?;
        let (data, error_subcode) = be_u8(input)?;
        Ok((
            &[],
            Self {
                error_code,
                error_subcode,
                data: data.to_vec(),
            },
        ))
    }

    fn pack(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.error_code.to_be_bytes());
        buffer.extend_from_slice(&self.error_subcode.to_be_bytes());
        buffer.extend_from_slice(&self.data);
        buffer
    }
}
