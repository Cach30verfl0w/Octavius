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

//! This module is implementing RFC 6793 which adds support for 4-byte AS numbers to the BGP implementation. This is done by sending a
//! capability in the handshake.

/// This struct represents the 4-byte AS number support of the router. It indicates the support for 4-byte ASN numbers of the router and
/// contains the uncut AS number announced by this implementation.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
pub struct FourOctetASNumberSupportCapability {
    pub as_number: u32
}
