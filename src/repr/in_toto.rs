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
    #[serde(with = "hex::serde")]
    pub sha256: Vec<u8>,
}

media_type! {
    #[derive(Debug)]
    pub struct InTotoStatementType = "https://in-toto.io/Statement/v1";
}
