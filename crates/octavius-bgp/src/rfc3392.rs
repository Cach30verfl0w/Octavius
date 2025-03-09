//! This module of the BGP serialization and deserialization library implements the serialization of capabilities in the BGP open message as
//! specified in [RFC 3392](https://datatracker.ietf.org/doc/html/rfc3392). It allows to tell the peer's router about the supported features
//! and extensions of this router.

#[cfg(feature = "rfc4760")]
use crate::rfc4760::MultiprotocolExtensionsCapability;
use crate::BGPElement;
use alloc::vec::Vec;
use nom::{
    bytes::complete::take,
    number::complete::be_u8,
    IResult,
};

/// This enum represents a capability. Capabilities are sent in the open message of the BGP router to tell the other peer about the features
/// and supported extensions of this BGP router.
///
/// ## References
/// - [Capabilities Optional Parameter, Section. 4 RFC 3392](https://datatracker.ietf.org/doc/html/rfc3392#section-4)
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone)]
pub enum Capability {
    #[cfg(feature = "rfc4760")]
    MultiprotocolExtensions(MultiprotocolExtensionsCapability),
    Unknown {
        code: u8,
        data: Vec<u8>,
    },
}

impl BGPElement for Capability {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, code) = be_u8(input)?;
        let (input, length) = be_u8(input)?;
        let (input, data) = take(length as usize)(input)?;
        Ok((
            input,
            match code {
                1 => Self::MultiprotocolExtensions(MultiprotocolExtensionsCapability::unpack(data)?.1),
                _ => Self::Unknown { code, data: data.to_vec() },
            },
        ))
    }

    fn pack(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        match self {
            Self::MultiprotocolExtensions(capability) => {
                buffer.extend_from_slice(&1_u8.to_be_bytes());
                buffer.extend_from_slice(&4_u8.to_be_bytes());
                buffer.extend(capability.pack());
            }
            Self::Unknown { code, data } => {
                buffer.extend_from_slice(&code.to_be_bytes());
                buffer.extend_from_slice(&(data.len() as u8).to_be_bytes());
                buffer.extend(data);
            }
        }
        buffer
    }
}
