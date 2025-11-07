use crate::claims::{Claims, ClaimsError};
use crate::digest::{Digest, DigestCollection, DigestError};
use crate::dsse::{DsseError, dsse_signature, verify_dsse};
use crate::rekor_timestamp::{RekorTimestampError, validate_rekor_timestamp};
use crate::repr::bundle::{Bundle, BundleContent, BundleDigestAlgorithm};
use crate::repr::in_toto::{InTotoDigest, InTotoSubject};
use crate::repr::trusted_root::TrustedRoot;
use crate::rfc3161::{Rfc3161Error, validate_rfc3161};
use crate::x509::{CertError, ensure_trusted_cert, verify_signature};
use jiff::Timestamp;
use std::io::Read;

/// Verify that the provided Sigstore bundle matches the provided content.
///
/// **Transparency log inclusion is not verified by this function!**
///
/// If the attestation is valid (according to the provided trusted root), this function returns the
/// list of claims included within the attestation. It is **imperative** that the caller verifies
/// whether the claims match what they expect, as this function only verifies the attestation was
/// correctly produced by any trusted identity provider.
///
/// ```rust
/// # use sigstore_verify::repr::trusted_root::TrustedRoot;
/// # use sigstore_verify::repr::bundle::Bundle;
/// # use sigstore_verify::verify_no_tlog;
/// # let root_content = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-data/trusted-roots/sigstore.json"));
/// # let bundle_content = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-data/sigstore-conformance/test/assets/bundle-verify/happy-path-v0.3/bundle.sigstore.json"));
/// # let signed_content = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/test-data/sigstore-conformance/test/assets/a.txt"));
///
/// let root: TrustedRoot = serde_json::from_slice(root_content)?;
/// let bundle: Bundle = serde_json::from_slice(bundle_content)?;
/// let mut content = std::io::Cursor::new(signed_content);
///
/// let claims = verify_no_tlog(&root, &bundle, &mut content)?;
/// assert_eq!(
///     claims.issuer_v2.as_deref(),
///     Some("https://token.actions.githubusercontent.com"),
/// );
/// assert_eq!(
///     claims.source_repository_uri.as_deref(),
///     Some("https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon"),
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn verify_no_tlog(
    root: &TrustedRoot,
    bundle: &Bundle,
    content: &mut dyn Read,
) -> Result<Claims, VerifyError> {
    let verification = &bundle.verification_material;

    let content_digest = DigestCollection::calculate_from_reader(content)
        .map_err(VerifyError::CalculateContentDigest)?;

    // Sigstore certificates are intentionally short-lived (the Fulcio CA returns certificates with
    // a 10 minute lifespan), so they are almost certainly expired by the time this function is
    // called. We thus need to determine whether they were used within their validity window.
    //
    // To determine the time of use, we cannot trust any metadata signed with the certificate.
    // The issued certificate is in the hands of a potentially compromised client, which could
    // backdate or postdate any signature made with it.
    //
    // Instead, Sigstore requires that at least one (or more) sources of trusted timestamps are
    // present in the bundle. Currently they can come from either RFC 3161 timestamp authorities or
    // as part of the Rekor transparency log's proof of inclusion.
    let mut timestamps = Vec::new();
    for timestamp in &verification.timestamp_verification_data.rfc3161_timestamps {
        timestamps.push(validate_rfc3161(root, timestamp)?);
    }
    for entry in &verification.tlog_entries {
        // Rekor v2 inclusion proofs don't have an embedded timestamp, so some transparency log
        // entries might lack a trusted timestamp :(
        if let Some(timestamp) = validate_rekor_timestamp(root, entry)? {
            timestamps.push(timestamp);
        }
    }

    // Check that the attestation is valid during *all* timestamps we know of.
    if timestamps.is_empty() {
        return Err(VerifyError::NoTimestamps);
    }
    for timestamp in &timestamps {
        verify_with_timestamp(root, bundle, timestamp, &content_digest)?;
    }

    Ok(Claims::from_certificate(&verification.certificate)?)
}

fn verify_with_timestamp(
    root: &TrustedRoot,
    bundle: &Bundle,
    timestamp: &VerifiedTimestamp,
    content_digest: &DigestCollection,
) -> Result<(), VerifyError> {
    let certificate = &bundle.verification_material.certificate;
    ensure_trusted_cert(timestamp.timestamp, root, &certificate)
        .map_err(VerifyError::UntrustedSubject)?;

    // Sigstore bundles contain the hash of the signed content in one of two ways: either directly
    // signed by the certificate and stored in the bundle, or within an in-toto statement encoded
    // into a DSSE envelope which is then signed by the certificate. Handle either case.
    let digests = match &bundle.content {
        BundleContent::MessageSignature(ms) => {
            let message_digest = &ms.message_digest.digest;
            verify_signature(
                timestamp.timestamp,
                &certificate,
                &message_digest,
                &ms.signature,
            )
            .map_err(VerifyError::InvalidSignature)?;
            match ms.message_digest.algorithm {
                BundleDigestAlgorithm::Sha256 => {
                    vec![Digest::sha256_prehashed(message_digest.clone())]
                }
            }
        }
        BundleContent::DsseEnvelope(dsse) => {
            let in_toto = verify_dsse(timestamp.timestamp, &certificate, dsse)?;
            dsse_digests(&in_toto.subject)?
        }
    };

    // There can be multiple digests included in the bundle (if there is a DSSE envelope). One
    // example of such a bundle is GitHub's release attestations, whose in-toto statement inside
    // the DSSE envelope contains a subject for every file included in the release.
    let mut matched = false;
    for digest in digests {
        match content_digest.verify(&digest) {
            Ok(()) => {
                matched = true;
                break;
            }
            Err(DigestError::HashMismatch) => {}
            Err(err) => return Err(VerifyError::VerifyContentDigest(err)),
        }
    }
    if !matched {
        return Err(VerifyError::VerifyContentDigest(DigestError::HashMismatch));
    }

    ensure_timestamp_hash(bundle, timestamp, content_digest)?;

    Ok(())
}

fn dsse_digests(subjects: &[InTotoSubject]) -> Result<Vec<Digest>, VerifyError> {
    let mut digests = Vec::new();
    for subject in subjects {
        // Deconstruct the struct to ensure we get an error when a new algorithm is added.
        let InTotoDigest { sha1, sha256 } = &subject.digest;

        if let Some(sha1) = sha1 {
            digests.push(Digest::sha1_prehashed(sha1.clone()));
        }
        if let Some(sha256) = sha256 {
            digests.push(Digest::sha256_prehashed(sha256.clone()));
        }
    }
    Ok(digests)
}

/// It's crucial the signed timestamp was generated specifically for this bundle, and wasn't
/// requested for other purposes. We thus check whether the digest embedded in the signature
/// matches the contents of the bundle.
fn ensure_timestamp_hash<'a>(
    bundle: &'a Bundle,
    timestamp: &VerifiedTimestamp,
    content_digest: &DigestCollection,
) -> Result<(), VerifyError> {
    let mut extend_lifetime;

    // Different sources of trusted timestamps hash different parts of the bundle. Hash the correct
    // thing depending on what the trusted timestamp tells us.
    let collection = match timestamp.digest_of {
        DigestOf::Signature => match &bundle.content {
            BundleContent::MessageSignature(ms) => {
                extend_lifetime = DigestCollection::calculate(&ms.signature);
                &extend_lifetime
            }
            BundleContent::DsseEnvelope(dsse) => {
                extend_lifetime = DigestCollection::calculate(dsse_signature(dsse)?);
                &extend_lifetime
            }
        },
        DigestOf::FileDigest => content_digest,
        DigestOf::DsseEnvelope => match &bundle.content {
            BundleContent::MessageSignature(_) => return Err(VerifyError::DigestOfDsseWithoutDsse),
            BundleContent::DsseEnvelope(dsse) => {
                extend_lifetime = DigestCollection::calculate(&dsse.payload.raw);
                &mut extend_lifetime
            }
        },
    };

    collection
        .verify(&timestamp.digest)
        .map_err(VerifyError::VerifyTimestampDigest)
}

#[derive(Debug)]
pub(crate) struct VerifiedTimestamp {
    pub(crate) timestamp: Timestamp,
    pub(crate) digest: Digest,
    pub(crate) digest_of: DigestOf,
}

#[derive(Debug)]
pub(crate) enum DigestOf {
    Signature,
    FileDigest,
    DsseEnvelope,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    #[error("the subject certificate is not trusted by any CA in the trusted root")]
    UntrustedSubject(#[source] CertError),
    #[error("failed to extract the claims from the certificate")]
    Claims(#[from] ClaimsError),
    #[error("failed to validate timestamp in the Rekor entry")]
    RekorTimestamp(#[from] RekorTimestampError),
    #[error("failed to parse an RFC3161 timestamp")]
    Rfc3161(#[from] Rfc3161Error),
    #[error("invalid signature")]
    InvalidSignature(#[source] CertError),
    #[error("invalid DSSE signature")]
    InvalidDsseSignature(#[from] DsseError),
    #[error("the bundle doesn't contain any trusted timestamp")]
    NoTimestamps,
    #[error("digest of the DSSE envelope is requested when the bundle doesn't have it")]
    DigestOfDsseWithoutDsse,
    #[error("failed to calculate the digest of the content")]
    CalculateContentDigest(#[source] DigestError),
    #[error("failed to verify the digest of the content")]
    VerifyContentDigest(#[source] DigestError),
    #[error("failed to verify the digest of the timestamp")]
    VerifyTimestampDigest(#[source] DigestError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_json;
    use expect_test::expect;
    use std::fs::File;
    use std::io::BufReader;

    #[test]
    fn test_verify_dsse() {
        let root: TrustedRoot = test_json!("trusted-roots/sigstore.json");
        let bundle: Bundle = test_json!(
            "sigstore-conformance/test/assets/bundle-verify/happy-path-intoto-in-dsse-v3/bundle.sigstore.json"
        );

        let mut file = BufReader::new(
            File::open(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-data/sigstore-conformance/test/assets/a.txt",
            ))
            .unwrap(),
        );

        let claims = verify_no_tlog(&root, &bundle, &mut file).unwrap();

        expect![[r#"
            Claims {
                build_config_digest: Some(
                    "82a3bfe6dd50fe9c71d6315eae66da15307856cf",
                ),
                build_config_uri: Some(
                    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main",
                ),
                build_signer_digest: Some(
                    "82a3bfe6dd50fe9c71d6315eae66da15307856cf",
                ),
                build_signer_uri: Some(
                    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main",
                ),
                build_trigger: Some(
                    "workflow_dispatch",
                ),
                issuer_v2: Some(
                    "https://token.actions.githubusercontent.com",
                ),
                run_invocation_uri: Some(
                    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/actions/runs/12359147651/attempts/1",
                ),
                runner_environment: Some(
                    "github-hosted",
                ),
                source_repository_digest: Some(
                    "82a3bfe6dd50fe9c71d6315eae66da15307856cf",
                ),
                source_repository_identifier: Some(
                    "632596897",
                ),
                source_repository_owner_identifier: Some(
                    "131804563",
                ),
                source_repository_owner_uri: Some(
                    "https://github.com/sigstore-conformance",
                ),
                source_repository_ref: Some(
                    "refs/heads/main",
                ),
                source_repository_uri: Some(
                    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon",
                ),
                source_repository_visibility_at_signing: Some(
                    "public",
                ),
                subject_alternative_names_emails: [],
                subject_alternative_names_domains: [],
                subject_alternative_names_uris: [
                    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main",
                ],
            }
        "#]]
        .assert_debug_eq(&claims);
    }

    #[test]
    fn test_verify_digest() {
        let root: TrustedRoot = test_json!("trusted-roots/sigstore.json");
        let bundle: Bundle = test_json!(
            "sigstore-conformance/test/assets/bundle-verify/happy-path-v0.3/bundle.sigstore.json"
        );

        let mut file = BufReader::new(
            File::open(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-data/sigstore-conformance/test/assets/a.txt",
            ))
            .unwrap(),
        );

        let claims = verify_no_tlog(&root, &bundle, &mut file).unwrap();

        expect![[r#"
            Claims {
                build_config_digest: Some(
                    "c7b3dfb335f051e1c86bda4c716fac97df62ad81",
                ),
                build_config_uri: Some(
                    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main",
                ),
                build_signer_digest: Some(
                    "c7b3dfb335f051e1c86bda4c716fac97df62ad81",
                ),
                build_signer_uri: Some(
                    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main",
                ),
                build_trigger: Some(
                    "workflow_dispatch",
                ),
                issuer_v2: Some(
                    "https://token.actions.githubusercontent.com",
                ),
                run_invocation_uri: Some(
                    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/actions/runs/8347481628/attempts/1",
                ),
                runner_environment: Some(
                    "github-hosted",
                ),
                source_repository_digest: Some(
                    "c7b3dfb335f051e1c86bda4c716fac97df62ad81",
                ),
                source_repository_identifier: Some(
                    "632596897",
                ),
                source_repository_owner_identifier: Some(
                    "131804563",
                ),
                source_repository_owner_uri: Some(
                    "https://github.com/sigstore-conformance",
                ),
                source_repository_ref: Some(
                    "refs/heads/main",
                ),
                source_repository_uri: Some(
                    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon",
                ),
                source_repository_visibility_at_signing: Some(
                    "public",
                ),
                subject_alternative_names_emails: [],
                subject_alternative_names_domains: [],
                subject_alternative_names_uris: [
                    "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main",
                ],
            }
        "#]]
        .assert_debug_eq(&claims);
    }
}
