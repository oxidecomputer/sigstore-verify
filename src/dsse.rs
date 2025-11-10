//! [DSSE] is an encoding format to sign arbitrary data and store those signatures. It's used to
//! store signed in-toto statements in the bundle. This module implements verifying signatures of
//! DSSE envelopes.
//!
//! [DSSE]: https://github.com/secure-systems-lab/dsse

use crate::repr::dsse_envelope::DsseEnvelope;
use crate::x509::{CertError, verify_signature};
use jiff::Timestamp;
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use std::fmt::{Debug, Display};
use x509_cert::Certificate;

pub(crate) fn verify_dsse<'a, T, M>(
    time: Timestamp,
    certificate: &Certificate,
    envelope: &'a DsseEnvelope<T, M>,
) -> Result<&'a T, DsseError>
where
    T: DeserializeOwned + Debug,
    M: DeserializeOwned + Debug + Display,
{
    let payload_type = envelope.payload_type.to_string();

    // PAE = Pre-Authenticated Encoding
    // https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md
    let mut pae = Vec::new();
    pae.extend_from_slice(b"DSSEv1 ");
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(envelope.payload.raw.len().to_string().as_bytes());
    pae.push(b' ');
    pae.extend_from_slice(&envelope.payload.raw);

    // I cannot find the documentation of this being sha256-encoded anywhere, but sigstore-python
    // hashes it with sha256 and verification fails if I don't hash it.
    // https://github.com/sigstore/sigstore-python/blob/31386bb131487e72f5589741b8ac1e6fb9793935/sigstore/dsse/__init__.py#L298
    let hashed = Sha256::digest(&pae);

    verify_signature(time, certificate, &hashed, dsse_signature(envelope)?)
        .map_err(DsseError::InvalidSignature)?;

    Ok(&envelope.payload.parsed)
}

pub(crate) fn dsse_signature<T, M>(envelope: &DsseEnvelope<T, M>) -> Result<&[u8], DsseError> {
    match envelope.signatures.as_slice() {
        [signature] => Ok(&signature.sig),
        _ => Err(DsseError::WrongSignatureCount(envelope.signatures.len())),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DsseError {
    #[error("expected one signature in the DSSE envelope, found {0}")]
    WrongSignatureCount(usize),
    #[error("invalid signature of the DSSE envelope")]
    InvalidSignature(#[source] CertError),
}
