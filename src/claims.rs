//! Representation of claims in the Sigstore certificate.

use der::oid::ObjectIdentifier;
use der::{Decode as _, Tagged as _};
use x509_cert::Certificate;
use x509_cert::ext::pkix::ID_CE_SUBJECT_ALT_NAME;
use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};

macro_rules! oids {
    ($($vis:vis const $name:ident = $value:expr;)*) => {
        $($vis const $name: ObjectIdentifier = ObjectIdentifier::new_unwrap($value);)*
    }
}

oids! {
    // OIDs of the certificate extensions Fulcio uses to record build metadata.
    // https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#directory
    const OID_BUILD_CONFIG_DIGEST = "1.3.6.1.4.1.57264.1.19";
    const OID_BUILD_CONFIG_URI = "1.3.6.1.4.1.57264.1.18";
    const OID_BUILD_SIGNER_DIGEST = "1.3.6.1.4.1.57264.1.10";
    const OID_BUILD_SIGNER_URI = "1.3.6.1.4.1.57264.1.9";
    const OID_BUILD_TRIGGER = "1.3.6.1.4.1.57264.1.20";
    const OID_DEPLOYMENT_ENVIRONMENT = "1.3.6.1.4.1.57264.1.23";
    const OID_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8";
    const OID_RUNNER_ENVIRONMENT = "1.3.6.1.4.1.57264.1.11";
    const OID_RUN_INVOCATION_URI = "1.3.6.1.4.1.57264.1.21";
    const OID_SOURCE_REPOSITORY_DIGEST = "1.3.6.1.4.1.57264.1.13";
    const OID_SOURCE_REPOSITORY_IDENTIFIER = "1.3.6.1.4.1.57264.1.15";
    const OID_SOURCE_REPOSITORY_OWNER_IDENTIFIER = "1.3.6.1.4.1.57264.1.17";
    const OID_SOURCE_REPOSITORY_OWNER_URI = "1.3.6.1.4.1.57264.1.16";
    const OID_SOURCE_REPOSITORY_REF = "1.3.6.1.4.1.57264.1.14";
    const OID_SOURCE_REPOSITORY_URI = "1.3.6.1.4.1.57264.1.12";
    const OID_SOURCE_REPOSITORY_VISIBILITY_AT_SIGNING = "1.3.6.1.4.1.57264.1.22";
}

#[derive(Debug, Default)]
pub struct Claims {
    pub build_config_digest: Option<String>,
    pub build_config_uri: Option<String>,
    pub build_signer_digest: Option<String>,
    pub build_signer_uri: Option<String>,
    pub build_trigger: Option<String>,
    pub deployment_environment: Option<String>,
    pub issuer_v2: Option<String>,
    pub run_invocation_uri: Option<String>,
    pub runner_environment: Option<String>,
    pub source_repository_digest: Option<String>,
    pub source_repository_identifier: Option<String>,
    pub source_repository_owner_identifier: Option<String>,
    pub source_repository_owner_uri: Option<String>,
    pub source_repository_ref: Option<String>,
    pub source_repository_uri: Option<String>,
    pub source_repository_visibility_at_signing: Option<String>,
    pub subject_alternative_names_emails: Vec<String>,
    pub subject_alternative_names_domains: Vec<String>,
    pub subject_alternative_names_uris: Vec<String>,
}

impl Claims {
    /// Extract all relevant claims from the certificate. The certificate is assumed to be trusted.
    pub(crate) fn from_certificate(certificate: &Certificate) -> Result<Self, ClaimsError> {
        let mut claims = Claims::default();

        for extension in certificate.tbs_certificate.extensions.iter().flatten() {
            let dest = match extension.extn_id {
                // The subject alternate name is encoded as the `GeneralNames` ASN.1 sequence
                // defined in https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
                ID_CE_SUBJECT_ALT_NAME => {
                    match GeneralNames::from_der(&extension.extn_value.as_bytes()) {
                        Ok(names) => {
                            for name in names {
                                match name {
                                    GeneralName::Rfc822Name(value) => claims
                                        .subject_alternative_names_emails
                                        .push(value.to_string()),
                                    GeneralName::DnsName(value) => claims
                                        .subject_alternative_names_domains
                                        .push(value.to_string()),
                                    GeneralName::UniformResourceIdentifier(value) => claims
                                        .subject_alternative_names_uris
                                        .push(value.to_string()),
                                    _ => return Err(ClaimsError::UnsupportedSanTag(name.tag())),
                                }
                            }
                        }
                        Err(err) => return Err(ClaimsError::ParseSan(err)),
                    }
                    continue;
                }

                // All Fulcio claims we care about are defined as string: we can determine the
                // destination of the claim, and parse them outside of the match.
                OID_BUILD_CONFIG_DIGEST => &mut claims.build_config_digest,
                OID_BUILD_CONFIG_URI => &mut claims.build_config_uri,
                OID_BUILD_SIGNER_DIGEST => &mut claims.build_signer_digest,
                OID_BUILD_SIGNER_URI => &mut claims.build_signer_uri,
                OID_BUILD_TRIGGER => &mut claims.build_trigger,
                OID_DEPLOYMENT_ENVIRONMENT => &mut claims.deployment_environment,
                OID_ISSUER_V2 => &mut claims.issuer_v2,
                OID_RUNNER_ENVIRONMENT => &mut claims.runner_environment,
                OID_RUN_INVOCATION_URI => &mut claims.run_invocation_uri,
                OID_SOURCE_REPOSITORY_DIGEST => &mut claims.source_repository_digest,
                OID_SOURCE_REPOSITORY_IDENTIFIER => &mut claims.source_repository_identifier,
                OID_SOURCE_REPOSITORY_OWNER_URI => &mut claims.source_repository_owner_uri,
                OID_SOURCE_REPOSITORY_OWNER_IDENTIFIER => {
                    &mut claims.source_repository_owner_identifier
                }
                OID_SOURCE_REPOSITORY_REF => &mut claims.source_repository_ref,
                OID_SOURCE_REPOSITORY_URI => &mut claims.source_repository_uri,
                OID_SOURCE_REPOSITORY_VISIBILITY_AT_SIGNING => {
                    &mut claims.source_repository_visibility_at_signing
                }

                // Unknown extensions should be ignored.
                _ => continue,
            };

            match String::from_der(&extension.extn_value.as_bytes()) {
                Ok(string) => *dest = Some(string),
                Err(err) => return Err(ClaimsError::ParseFulcioClaim(extension.extn_id, err)),
            }
        }

        Ok(claims)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClaimsError {
    #[error("failed to parse fulcio claim with OID {0}")]
    ParseFulcioClaim(ObjectIdentifier, #[source] der::Error),
    #[error("failed to parse the SAN")]
    ParseSan(#[source] der::Error),
    #[error("unsupported SAN tag: {0}")]
    UnsupportedSanTag(der::Tag),
}
