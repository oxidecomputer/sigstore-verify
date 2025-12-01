use crate::utils::media_type;
use jiff::Timestamp;
use serde::Deserialize;
use x509_cert::Certificate;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedRoot {
    pub media_type: TrustedRootMediaType,
    #[serde(default)]
    pub certificate_authorities: Vec<TrustedRootCa>,
    #[serde(default)]
    pub timestamp_authorities: Vec<TrustedRootCa>,
    #[serde(default)]
    pub tlogs: Vec<TrustedRootTlog>,
}

impl TrustedRoot {
    pub fn empty() -> Self {
        Self {
            media_type: TrustedRootMediaType,
            certificate_authorities: Vec::new(),
            timestamp_authorities: Vec::new(),
            tlogs: Vec::new(),
        }
    }

    pub fn merge(&mut self, other: TrustedRoot) {
        let TrustedRoot {
            media_type: _,
            certificate_authorities: other_cas,
            timestamp_authorities: other_tas,
            tlogs: other_tlogs,
        } = other;

        for ca in other_cas {
            self.certificate_authorities.push(ca);
        }
        for ta in other_tas {
            self.timestamp_authorities.push(ta);
        }
        for tlog in other_tlogs {
            self.tlogs.push(tlog);
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedRootCa {
    pub cert_chain: TrustedRootCertChain,
    pub valid_for: TrustedRootValidFor,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedRootCertChain {
    #[serde(deserialize_with = "crate::utils::deserialize_vec_cert")]
    pub certificates: Vec<Certificate>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedRootTlog {
    pub public_key: TrustedRootTlogPublicKey,
    pub log_id: TrustedRootTlogLogId,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedRootTlogPublicKey {
    #[serde(deserialize_with = "crate::utils::deserialize_base64")]
    pub raw_bytes: Vec<u8>,
    pub key_details: TrustedRootTlogKeyDetails,
    pub valid_for: TrustedRootValidFor,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedRootTlogLogId {
    #[serde(deserialize_with = "crate::utils::deserialize_base64")]
    pub key_id: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub enum TrustedRootTlogKeyDetails {
    #[serde(rename = "PKIX_ECDSA_P256_SHA_256")]
    PkixEcdsaP256Sha256,
    #[serde(rename = "PKIX_ED25519")]
    PkixEd25519,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedRootValidFor {
    pub start: Timestamp,
    pub end: Option<Timestamp>,
}

impl TrustedRootValidFor {
    pub(crate) fn is_valid(&self, time: Timestamp) -> bool {
        time >= self.start && self.end.map(|end| time <= end).unwrap_or(true)
    }
}

media_type! {
    #[derive(Debug)]
    pub struct TrustedRootMediaType = "application/vnd.dev.sigstore.trustedroot+json;version=0.1";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_json;

    #[test]
    fn test_parse() {
        let _: TrustedRoot = test_json!("trusted-roots/sigstore.json");
    }
}
