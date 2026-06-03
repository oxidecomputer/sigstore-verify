// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::utils::media_type;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub type_: InTotoStatementType,
    pub subject: Vec<InTotoSubject>,
    #[serde(flatten)]
    pub predicate: InTotoPredicate,
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

#[derive(Debug, Deserialize)]
#[serde(tag = "predicateType", rename_all = "camelCase")]
pub enum InTotoPredicate {
    #[serde(rename = "https://slsa.dev/provenance/v1")]
    Provenance1(InTotoPredicateWrapper<InTotoProvenance1>),
    #[serde(rename = "https://in-toto.io/attestation/release/v0.1")]
    Release01(InTotoPredicateWrapper<InTotoRelease01>),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTotoPredicateWrapper<T> {
    pub predicate: T,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTotoProvenance1 {}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTotoRelease01 {
    pub repository: String,
    pub tag: String,
}

media_type! {
    #[derive(Debug)]
    pub struct InTotoStatementType = "https://in-toto.io/Statement/v1";
}
