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
