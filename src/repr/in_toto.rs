use crate::utils::media_type;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub type_: InTotoStatementType,
    pub subject: Vec<InTotoSubject>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTotoSubject {
    pub digest: InTotoDigest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTotoDigest {
    #[serde(default, deserialize_with = "crate::utils::deserialize_option_hex")]
    pub sha1: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "crate::utils::deserialize_option_hex")]
    pub sha256: Option<Vec<u8>>,
}

media_type! {
    #[derive(Debug)]
    pub struct InTotoStatementType = "https://in-toto.io/Statement/v1";
}
