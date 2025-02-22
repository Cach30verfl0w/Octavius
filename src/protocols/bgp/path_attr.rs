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

/// The origin attribute is one of the mandatory attributes when sending update messages and is informing about the origin of the
/// NLRI/prefixes sent in the message.
#[repr(u8)]
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Copy)]
pub enum OriginAttribute {
    /// NLRI is interior to the originating AS
    IGP = 0,

    /// NLRI was learned via the EGP protocol
    EGP = 1,

    /// NLRI learned by some other means
    Incomplete = 2
}

impl From<u8> for OriginAttribute {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::IGP,
            1 => Self::EGP,
            _ => Self::Incomplete
        }
    }
}

// TODO: Add AS_PATH, NEXT_HOP and other specified by https://datatracker.ietf.org/doc/html/rfc4271#section-5
