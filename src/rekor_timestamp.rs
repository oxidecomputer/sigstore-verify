//! One of the sources of trusted timestamps is the Rekor v1 transparency log inclusion proofs.
//! These proofs are signed by Rekor and contain the timestamp at which point the signature was
//! added to the transparency log.
//!
//! This module verifies that the inclusion proof is correctly signed by a Rekor certificate and
//! extracts the timestamp out of it. It **does not** verify whether the certificate was actually
//! included in the transparency log, as we don't check transparency logs in this crate.

use crate::digest::Digest;
use crate::repr::bundle::{BundleTlogBody, BundleTlogBodyHashAlgorithm, BundleTlogEntry};
use crate::repr::trusted_root::{TrustedRoot, TrustedRootTlogKeyDetails};
use crate::verify::{DigestOf, VerifiedTimestamp};
use base64::prelude::{BASE64_STANDARD, Engine as _};
use ecdsa::signature::hazmat::PrehashVerifier as _;
use jiff::Timestamp;
use p256::pkcs8::DecodePublicKey as _;
use sha2::{Digest as _, Sha256};

pub(crate) fn validate_rekor_timestamp(
    root: &TrustedRoot,
    entry: &BundleTlogEntry,
) -> Result<Option<VerifiedTimestamp>, RekorTimestampError> {
    // Rekor v2 transparency log entries don't include a signed timestamp and inclusion promise, so
    // we return `None`. The signed timestamp will have to come from somewhere else.
    let (Some(inclusion_promise), Some(integrated_time)) =
        (&entry.inclusion_promise, entry.integrated_time)
    else {
        return Ok(None);
    };

    let key = root
        .tlogs
        .iter()
        .find(|log| log.log_id.key_id == entry.log_id.key_id)
        .ok_or_else(|| {
            RekorTimestampError::LogKeyNotInTrustedRoot(
                BASE64_STANDARD.encode(&entry.log_id.key_id),
            )
        })?;

    // Rekor transparency log inclusion proofs sign RFC8785-canonicalized JSON bodies of parts of
    // a subset of the metadata present in the bundle. We reconstruct it here.
    let payload = serde_json_canonicalizer::to_vec(&CanonicalizedPayload {
        body: BASE64_STANDARD.encode(&entry.canonicalized_body.raw),
        integrated_time,
        log_index: entry.log_index,
        log_id: hex::encode(&entry.log_id.key_id),
    })
    .map_err(RekorTimestampError::VerificationPayloadSer)?;

    // Unfortunately we cannot share the verification logic with the x509 module, as Rekor keys are
    // DER-encoded instead of SEC1 encoded.
    match key.public_key.key_details {
        TrustedRootTlogKeyDetails::PkixEcdsaP256Sha256 => {
            let public_key =
                p256::ecdsa::VerifyingKey::from_public_key_der(&key.public_key.raw_bytes)
                    .map_err(RekorTimestampError::InvalidP256VerifyingKey)?;
            let signature =
                p256::ecdsa::Signature::from_der(&inclusion_promise.signed_entry_timestamp)
                    .map_err(RekorTimestampError::InvalidP256Signature)?;

            let hash = Sha256::digest(&payload);
            public_key
                .verify_prehash(&hash, &signature)
                .map_err(|_| RekorTimestampError::VerificationFailed)?;
        }
        TrustedRootTlogKeyDetails::PkixEd25519 => {
            let public_key = ed25519_dalek::VerifyingKey::from_bytes(
                &key.public_key
                    .raw_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| RekorTimestampError::InvalidEd25519VerifyingKeySize)?,
            )
            .map_err(RekorTimestampError::InvalidEd25519VerifyingKey)?;
            let signature = ed25519_dalek::Signature::from_bytes(
                &key.public_key
                    .raw_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| RekorTimestampError::InvalidEd25519SignatureSize)?,
            );
            public_key
                .verify_strict(&payload, &signature)
                .map_err(|_| RekorTimestampError::VerificationFailed)?;
        }
    }

    // The type of inclusion proof can be hashedrekord if the bundle contains the signed file
    // digest, or dsse if the bundle contains a DSSE envelope instead. This *of course* results in
    // different things being hashed.
    let (digest, digest_of) = match &entry.canonicalized_body.parsed {
        BundleTlogBody::HashedRekord(body) => (&body.spec.data.hash, DigestOf::FileDigest),
        BundleTlogBody::Dsse(body) => (&body.spec.payload_hash, DigestOf::DsseEnvelope),
    };

    Ok(Some(VerifiedTimestamp {
        timestamp: Timestamp::from_second(integrated_time)
            .map_err(|_| RekorTimestampError::OutOfRangeTimestamp)?,
        digest: match digest.algorithm {
            BundleTlogBodyHashAlgorithm::Sha256 => Digest::Sha256(digest.value.clone()),
        },
        digest_of,
    }))
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalizedPayload {
    body: String,
    integrated_time: i64,
    log_index: i64,
    #[serde(rename = "logID")]
    log_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RekorTimestampError {
    #[error("rekor key with ID {0} is not present in the trusted root")]
    LogKeyNotInTrustedRoot(String),
    #[error("serializing the verification payload to JSON failed")]
    VerificationPayloadSer(#[source] serde_json::Error),
    #[error("failed to verify the signature of the rekor entry")]
    VerificationFailed,
    #[error("timestamp out of range")]
    OutOfRangeTimestamp,

    #[error("invalid signing key")]
    InvalidP256VerifyingKey(#[source] x509_cert::spki::Error),
    #[error("invalid signature representation")]
    InvalidP256Signature(#[source] p384::ecdsa::signature::Error),

    #[error("the verifying key is of the wrong size")]
    InvalidEd25519VerifyingKeySize,
    #[error("the signature is of the wrong size")]
    InvalidEd25519SignatureSize,
    #[error("invalid signing key")]
    InvalidEd25519VerifyingKey(#[source] ed25519_dalek::SignatureError),
}
