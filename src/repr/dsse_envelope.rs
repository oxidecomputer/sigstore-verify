// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::repr::Parsed;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::fmt::Debug;

#[derive(Debug, Deserialize)]
#[serde(
    rename_all = "camelCase",
    bound = "T: DeserializeOwned + Debug, M: DeserializeOwned + Debug"
)]
pub struct DsseEnvelope<T, M> {
    pub payload: Parsed<T>,
    pub payload_type: M,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseSignature {
    #[serde(deserialize_with = "crate::utils::deserialize_base64")]
    pub sig: Vec<u8>,
}
