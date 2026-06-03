// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! [RFC 3161] ("Internet X.509 Public Key Infrastructre Time-Stamp Protocol") defines a standard
//! to request a timestamping server to attest that a piece of data existed at a point in time.
//! This is achieved by sending the hash of the data to the server, and the server replying with
//! its signature over the current time and that piece of data.
//!
//! The server reply is actually an [RFC 5652] ("Cryptographic Message Syntax") `SignedData`, and
//! so it must be verified according to RFC 5652 rules. In practice, RFC 3161 only specifies the
//! protocol a client needs to use to request a signature from a timestamping authority, leaving
//! any cryptographic bits to RFC 5652.
//!
//! The Sigstore bundle format can contain such responses to prove that a signature was made within
//! the certificate's validity window. This module thus validates the signed timestamp repsonse and
//! returns the digest of the piece of data it proves existed at that time.
//!
//! [RFC 3161]: https://www.rfc-editor.org/rfc/rfc3161
//! [RFC 5652]: https://www.rfc-editor.org/rfc/rfc5652

use crate::digest::Digest;
use crate::repr::bundle::BundleRfc3161;
use crate::repr::trusted_root::TrustedRoot;
use crate::verify::{DigestOf, VerifiedTimestamp};
use crate::x509::{CertError, hash_for_signature, verify_signature};
use cms::signed_data::{SignedData, SignerIdentifier};
use der::asn1::{OctetString, SetOfVec};
use der::oid::ObjectIdentifier;
use der::oid::db::rfc5911::{ID_CONTENT_TYPE, ID_MESSAGE_DIGEST};
use der::oid::db::rfc5912::{ID_SHA_256, ID_SHA_384};
use der::{Decode, Encode as _};
use jiff::Timestamp;
use sha2::{Digest as _, Sha256, Sha384};
use x509_cert::attr::Attribute;
use x509_tsp::{TimeStampResp, TstInfo};

pub(crate) fn validate_rfc3161(
    root: &TrustedRoot,
    item: &BundleRfc3161,
) -> Result<VerifiedTimestamp, Rfc3161Error> {
    // Remove a few ~~onion~~ ASN.1 layers.
    let signed: SignedData = TimeStampResp::from_der(&item.signed_timestamp)?
        .time_stamp_token
        .ok_or(Rfc3161Error::NoToken)?
        .content
        .decode_as()?;
    let econtent = signed
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(Rfc3161Error::NoContent)?
        .value();
    let tst_info = TstInfo::from_der(econtent)?;

    // We need a timestamp to validate whether the timestamp authority's certificate is valid, but
    // in the current phase of the verification process we have not determined a trusted timestamp
    // yet. Since just later in the function we verify the authenticity of this timestamp, we'll
    // use it to check the validity of the certificate too.
    //
    // In theory doing so would also allow a malicious timestamp authority to use an expired
    // certificate, but if that certificate falls into the wrong hands the whole Sigstore model
    // breaks down. The Sigstore client specification also recommends this:
    //
    // https://github.com/sigstore/architecture-docs/blob/main/client-spec.md#421-timestamping-service
    //
    let timestamp = Timestamp::from_second(tst_info.gen_time.to_unix_duration().as_secs() as _)
        .map_err(|_| Rfc3161Error::OutOfRange)?;

    // All signatures must be valid, if by any chance more than one is present.
    for signature in signed.signer_infos.0.iter() {
        let issuer_serial = match &signature.sid {
            SignerIdentifier::IssuerAndSerialNumber(sid) => &sid.serial_number,
            SignerIdentifier::SubjectKeyIdentifier(_) => return Err(Rfc3161Error::SkiUnsupported),
        };
        let issuer = root
            .timestamp_authorities
            .iter()
            .filter(|ca| ca.valid_for.is_valid(timestamp))
            .flat_map(|ca| ca.cert_chain.certificates.iter())
            .find(|cert| cert.tbs_certificate.serial_number == *issuer_serial)
            .ok_or_else(|| Rfc3161Error::NoTrustedCa(hex::encode(issuer_serial.as_bytes())))?;

        // According to RFC 5652, there are two ways to sign a `SignedData`. If there are signed
        // attributes, the DER encoding of all signed attributes is signed, otherwise the hash of
        // the content is signed. In practice the two are equivalent, since one of the required
        // signed attributes (if any attribute is present) is the content hash.
        let payload = if let Some(attrs) = signature.signed_attrs.as_ref()
            && !attrs.is_empty()
        {
            let content_type: ObjectIdentifier = get_attr(attrs, ID_CONTENT_TYPE)?;
            if content_type != signed.encap_content_info.econtent_type {
                return Err(Rfc3161Error::MismatchedContentTypeAttr);
            }

            let message_digest: OctetString = get_attr(attrs, ID_MESSAGE_DIGEST)?;
            let econtent_digest = match signature.digest_alg.oid {
                ID_SHA_256 => Sha256::digest(econtent).to_vec(),
                ID_SHA_384 => Sha384::digest(econtent).to_vec(),
                oid => return Err(Rfc3161Error::UnsupportedHash(oid)),
            };
            if econtent_digest != message_digest.as_bytes() {
                return Err(Rfc3161Error::MismatchedDigestAttr);
            }

            hash_for_signature(signature.signature_algorithm.oid, &attrs.to_der()?)?
        } else {
            hash_for_signature(signature.signature_algorithm.oid, econtent)?
        };

        verify_signature(timestamp, issuer, &payload, &signature.signature.as_bytes())?;
    }

    let digest = match tst_info.message_imprint.hash_algorithm.oid {
        ID_SHA_256 => {
            Digest::sha256_prehashed(tst_info.message_imprint.hashed_message.as_bytes().to_vec())
        }
        oid => return Err(Rfc3161Error::UnsupportedHash(oid)),
    };

    Ok(VerifiedTimestamp {
        timestamp,
        digest,
        digest_of: DigestOf::Signature,
    })
}

fn get_attr<'a, T: der::DecodeValue<'a> + der::Choice<'a>>(
    attrs: &'a SetOfVec<Attribute>,
    oid: ObjectIdentifier,
) -> Result<T, Rfc3161Error> {
    let mut iter = attrs
        .iter()
        .filter(|attr| attr.oid == oid)
        .flat_map(|attr| attr.values.iter());
    let attr = iter.next().ok_or(Rfc3161Error::MissingAttr(oid))?;
    if iter.next().is_some() {
        return Err(Rfc3161Error::DuplicateAttr(oid));
    }

    Ok(attr.decode_as()?)
}

#[derive(Debug, thiserror::Error)]
pub enum Rfc3161Error {
    #[error("failed to parse the timestamp request")]
    Parse(#[from] der::Error),
    #[error("no timestamp token in the timestamp response")]
    NoToken,
    #[error("no content in the signed timestamp")]
    NoContent,
    #[error("signatures with a subject key identifier as sid are unsupported")]
    SkiUnsupported,
    #[error("no trusted timestamp authority certificate with serial number {0}")]
    NoTrustedCa(String),
    #[error("unsupported hash algorithm with OID {0}")]
    UnsupportedHash(ObjectIdentifier),
    #[error("timestamp out of range")]
    OutOfRange,
    #[error("the signed attribute with OID {0} is missing")]
    MissingAttr(ObjectIdentifier),
    #[error("the signed attribute with OID {0} is present more than once")]
    DuplicateAttr(ObjectIdentifier),
    #[error("the signed content type attribute doesn't match the content type")]
    MismatchedContentTypeAttr,
    #[error("the signed digest attribute doesn't match the econtent attribute")]
    MismatchedDigestAttr,
    #[error(transparent)]
    Cert(#[from] CertError),
}
