//! This module is implementing RFC 6793 which adds support for 4-byte AS numbers to the BGP implementation. This is done by sending a
//! capability in the handshake.

/// This struct represents the 4-byte AS number support of the router. It indicates the support for 4-byte ASN numbers of the router and
/// contains the uncut AS number announced by this implementation.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
pub struct FourOctetASNumberSupportCapability {
    pub as_number: u32
}


