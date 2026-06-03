// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! X.509 certificates are used everywhere in Sigstore bundles. This module wraps the RustCrypto
//! family of crates to provide an higher level API for the rest of the crate.

use crate::repr::trusted_root::{TrustedRoot, TrustedRootCa};
use der::oid::ObjectIdentifier;
use der::oid::db::rfc5912::{ECDSA_WITH_SHA_256, ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1};
use der::referenced::OwnedToRef;
use ecdsa::signature::hazmat::PrehashVerifier;
use jiff::Timestamp;
use sha2::{Digest, Sha256, Sha384};
use x509_cert::Certificate;
use x509_cert::der::Encode as _;
use x509_cert::der::oid::db::rfc5912::ECDSA_WITH_SHA_384;
use x509_cert::name::RdnSequence;
use x509_cert::time::Time;

pub(crate) fn ensure_trusted_cert(
    time: Timestamp,
    root: &TrustedRoot,
    subject: &Certificate,
) -> Result<(), CertError> {
    ensure_valid_cert(time, subject)?;

    let payload = subject
        .tbs_certificate
        .to_der()
        .map_err(CertError::SubjectDerFailed)?;
    let hashed_payload = hash_for_signature(subject.signature_algorithm.oid, &payload)?;

    // GitHub's private Fulcio instance has multiple CAs with the same subject name with
    // overlapping validity time. Check the signature against all matching issuers rather than just
    // the first matching issuer.
    let issuers = find_issuers(
        time,
        &root.certificate_authorities,
        &subject.tbs_certificate.issuer,
    );
    if issuers.is_empty() {
        return Err(CertError::NoMatchingIssuer);
    }
    for issuer in issuers {
        match verify_signature(time, issuer, &hashed_payload, subject.signature.raw_bytes()) {
            Ok(()) => return Ok(()),
            Err(CertError::VerificationFailed) => {}
            Err(err) => return Err(err),
        }
    }
    Err(CertError::VerificationFailed)
}

fn find_issuers<'a>(
    time: Timestamp,
    authorities: &'a [TrustedRootCa],
    subject_name: &RdnSequence,
) -> Vec<&'a Certificate> {
    let mut issuers = Vec::new();
    for ca in authorities {
        // Only consider CAs valid at the time the certificate was signed.
        if !ca.valid_for.is_valid(time) {
            continue;
        }
        for issuer in &ca.cert_chain.certificates {
            if *subject_name == issuer.tbs_certificate.subject {
                issuers.push(issuer);
            }
        }
    }
    issuers
}

pub(crate) fn hash_for_signature(
    algorithm: ObjectIdentifier,
    payload: &[u8],
) -> Result<Vec<u8>, CertError> {
    match algorithm {
        ECDSA_WITH_SHA_256 => Ok(Sha256::digest(&payload).to_vec()),
        ECDSA_WITH_SHA_384 => Ok(Sha384::digest(&payload).to_vec()),
        oid => return Err(CertError::UnsupportedSignatureAlgorithm(oid)),
    }
}

pub(crate) fn verify_signature(
    time: Timestamp,
    issuer: &Certificate,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), CertError> {
    ensure_valid_cert(time, issuer).map_err(|e| {
        CertError::InvalidIssuer(issuer.tbs_certificate.subject.to_string(), Box::new(e))
    })?;

    let spki = &issuer.tbs_certificate.subject_public_key_info;
    let public_key_bytes = spki.subject_public_key.raw_bytes();
    let issuer_oids = spki
        .algorithm
        .owned_to_ref()
        .oids()
        .map_err(CertError::InvalidOidInCertificate)?;

    match issuer_oids {
        (ID_EC_PUBLIC_KEY, Some(SECP_384_R_1)) => {
            let public_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&public_key_bytes)
                .map_err(CertError::InvalidP384VerifyingKey)?;
            let signature = p384::ecdsa::Signature::from_der(signature)
                .map_err(CertError::InvalidP384Signature)?;
            match public_key.verify_prehash(payload, &signature) {
                Ok(()) => Ok(()),
                Err(_) => Err(CertError::VerificationFailed),
            }
        }
        (ID_EC_PUBLIC_KEY, Some(SECP_256_R_1)) => {
            let public_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key_bytes)
                .map_err(CertError::InvalidP256VerifyingKey)?;
            let signature = p256::ecdsa::Signature::from_der(signature)
                .map_err(CertError::InvalidP256Signature)?;
            match public_key.verify_prehash(payload, &signature) {
                Ok(()) => Ok(()),
                Err(_) => Err(CertError::VerificationFailed),
            }
        }
        (oid1, oid2) => Err(CertError::UnsupportedPublicKeyAlgorithm(oid1, oid2)),
    }
}

fn ensure_valid_cert(time: Timestamp, cert: &Certificate) -> Result<(), CertError> {
    let not_before = cert_timestamp(cert.tbs_certificate.validity.not_before)?;
    let not_after = cert_timestamp(cert.tbs_certificate.validity.not_after)?;
    if time > not_after {
        return Err(CertError::Expired { not_after, time });
    }
    if time < not_before {
        return Err(CertError::BeforeValidity { not_before, time });
    }
    Ok(())
}

fn cert_timestamp(cert_time: Time) -> Result<Timestamp, CertError> {
    Timestamp::from_second(cert_time.to_unix_duration().as_secs() as _)
        .map_err(|_| CertError::TimeOutsideRange)
}

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("the subject certificate is not valid")]
    InvalidSubject(#[source] Box<CertError>),
    #[error("the issuer certificate {0} is not valid")]
    InvalidIssuer(String, #[source] Box<CertError>),

    #[error("the certificate expired at {not_after}, but verification time is {time}")]
    Expired {
        not_after: Timestamp,
        time: Timestamp,
    },
    #[error("the certificate is valid from {not_before}, but verification time is {time}")]
    BeforeValidity {
        not_before: Timestamp,
        time: Timestamp,
    },
    #[error("certificate time is outside of range")]
    TimeOutsideRange,

    #[error("verifying the signature failed")]
    VerificationFailed,
    #[error("couldn't find any trusted issuer for the given cert")]
    NoMatchingIssuer,
    #[error("failed to decode the subject certificate")]
    SubjectDerFailed(#[source] der::Error),
    #[error("the certificate contains invalid OIDs")]
    InvalidOidInCertificate(#[source] der::Error),

    #[error("invalid signing key")]
    InvalidP384VerifyingKey(#[source] p384::ecdsa::signature::Error),
    #[error("invalid signature representation")]
    InvalidP384Signature(#[source] p384::ecdsa::signature::Error),

    #[error("invalid signing key")]
    InvalidP256VerifyingKey(#[source] p384::ecdsa::signature::Error),
    #[error("invalid signature representation")]
    InvalidP256Signature(#[source] p384::ecdsa::signature::Error),

    #[error("unsupported x509 signature algorithm with OID {0}")]
    UnsupportedSignatureAlgorithm(ObjectIdentifier),
    #[error("unsupported x509 public key algorithm with OIDs {0} and {1:?}")]
    UnsupportedPublicKeyAlgorithm(ObjectIdentifier, Option<ObjectIdentifier>),
}
