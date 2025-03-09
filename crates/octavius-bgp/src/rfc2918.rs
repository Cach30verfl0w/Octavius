use crate::{
    prefix::{
        AddressFamily,
        SubsequentAddressFamily,
    },
    BGPElement,
};
use nom::{
    number::complete::be_u8,
    IResult,
};
use std::prelude::rust_2015::Vec;

/// This message tells the BGP peer to resend all routes matching the specified address family context. It is used to update filters and
/// policies without establishing a new BGP connection.
#[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone, Copy)]
pub struct RouteRefreshMessage {
    address_family: AddressFamily,
    subsequent_address_family: SubsequentAddressFamily,
}

impl BGPElement for RouteRefreshMessage {
    fn unpack(input: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        let (input, address_family) = AddressFamily::unpack(input)?;
        let (input, _) = be_u8(input)?;
        let (input, subsequent_address_family) = SubsequentAddressFamily::unpack(input)?;
        Ok((
            input,
            Self {
                address_family,
                subsequent_address_family,
            },
        ))
    }

    fn pack(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&u16::from(self.address_family).to_be_bytes());
        buffer.extend_from_slice(&0_u8.to_be_bytes());
        buffer.extend_from_slice(&u8::from(self.subsequent_address_family).to_be_bytes());
    }
}
