// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::repr::Parsed;
use crate::repr::dsse_envelope::DsseEnvelope;
use crate::repr::in_toto::InTotoStatement;
use crate::utils::media_type;
use serde::Deserialize;
use std::fmt::Debug;
use x509_cert::Certificate;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bundle {
    pub media_type: BundleMediaType,
    pub verification_material: BundleVerificationMaterial,
    #[serde(flatten)]
    pub content: BundleContent,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleVerificationMaterial {
    #[serde(deserialize_with = "crate::utils::deserialize_cert")]
    pub certificate: Certificate,
    #[serde(default)]
    pub tlog_entries: Vec<BundleTlogEntry>,
    #[serde(default)]
    pub timestamp_verification_data: BundleTimestamps,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleTlogEntry {
    #[serde(deserialize_with = "crate::utils::deserialize_fromstr")]
    pub log_index: i64,
    pub log_id: BundleTlogLogId,
    #[serde(deserialize_with = "crate::utils::deserialize_option_fromstr")]
    pub integrated_time: Option<i64>,
    pub canonicalized_body: Parsed<BundleTlogBody>,
    pub inclusion_promise: Option<BundleTlogInclusionPromise>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleTlogLogId {
    #[serde(deserialize_with = "crate::utils::deserialize_base64")]
    pub key_id: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleTlogInclusionPromise {
    #[serde(deserialize_with = "crate::utils::deserialize_base64")]
    pub signed_entry_timestamp: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum BundleTlogBody {
    #[serde(rename = "hashedrekord")]
    HashedRekord(BundleTlogBodySpec<BundleTlogHashedRekord>),
    Dsse(BundleTlogBodySpec<BundleTlogDsse>),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleTlogBodySpec<T> {
    pub spec: T,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleTlogHashedRekord {
    pub data: BundleTlogHashedRekordData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleTlogHashedRekordData {
    pub hash: BundleTlogBodyHash,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleTlogDsse {
    pub payload_hash: BundleTlogBodyHash,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleTlogBodyHash {
    pub algorithm: BundleTlogBodyHashAlgorithm,
    #[serde(with = "hex::serde")]
    pub value: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BundleTlogBodyHashAlgorithm {
    Sha256,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BundleTimestamps {
    #[serde(default)]
    pub rfc3161_timestamps: Vec<BundleRfc3161>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleRfc3161 {
    #[serde(deserialize_with = "crate::utils::deserialize_base64")]
    pub signed_timestamp: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BundleContent {
    MessageSignature(BundleMessageSignature),
    DsseEnvelope(DsseEnvelope<InTotoStatement, BundleInTotoMediaType>),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleMessageSignature {
    pub message_digest: BundleMessageDigest,
    #[serde(deserialize_with = "crate::utils::deserialize_base64")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleMessageDigest {
    pub algorithm: BundleDigestAlgorithm,
    #[serde(deserialize_with = "crate::utils::deserialize_base64")]
    pub digest: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub enum BundleDigestAlgorithm {
    #[serde(rename = "SHA2_256")]
    Sha256,
}

media_type! {
    #[derive(Debug)]
    pub struct BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json", "application/vnd.dev.sigstore.bundle+json;version=0.3";
}

media_type! {
    #[derive(Debug)]
    pub struct BundleInTotoMediaType = "application/vnd.in-toto+json";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_json;

    #[test]
    fn test_parse_dsse() {
        let _: Bundle = test_json!(
            "sigstore-conformance/test/assets/bundle-verify/happy-path-intoto-in-dsse-v3/bundle.sigstore.json"
        );
    }

    #[test]
    fn test_parse_message_signature() {
        let _: Bundle = test_json!(
            "sigstore-conformance/test/assets/bundle-verify/happy-path-v0.3/bundle.sigstore.json"
        );
    }
}
