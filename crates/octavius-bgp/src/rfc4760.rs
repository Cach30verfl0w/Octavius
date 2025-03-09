//! This module of the BGP serialization and deserialization library implements the serialization of the Multiprotocol extensions in the BGP
//! update message (and the capability) as specified in [RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760). It allows to tell the
//! peer about IPv4 prefixes etc.

use alloc::vec::Vec;
use crate::type_enum;

type_enum! {
    /// This value represents the address family specified in the Multiprotocol Extensions associated attributes. Currently we only support
    /// IPv4 and IPv6.
    ///
    /// ## References
    /// - [Address Family Numbers, IANA](https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml)
    #[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone, Copy)]
    pub enum AddressFamily: be_u8(u8) {
        IPv4 = 1,
        IPv6 = 2
    }
}

type_enum! {
    /// This enum represents all SAFI (Subsequent address family identifier) supported by this BGP implementation, currently we only support
    /// Unicast or Multicast.
    ///
    /// ## References
    /// [Subsequent Address Family Identifier, Section 6 RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760#section-6)
    #[derive(Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Clone, Copy)]
    pub enum SubsequentAddressFamily: be_u8(u8) {
        Unicast = 1,
        Multicast = 2
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
    pub network_layer_reachability_information: Vec<u8>
}
