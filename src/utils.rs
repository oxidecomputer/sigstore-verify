use base64::prelude::{BASE64_STANDARD, Engine};
use serde::{Deserialize, Deserializer, de::Error as _};
use std::error::Error;
use std::str::FromStr;
use x509_cert::Certificate;
use x509_cert::der::Decode;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigstoreCertificate {
    raw_bytes: String,
}

impl SigstoreCertificate {
    fn to_certificate(self) -> Result<Certificate, Box<dyn Error>> {
        let decoded = BASE64_STANDARD.decode(&self.raw_bytes).map_err(Box::new)?;
        Ok(Certificate::from_der(&decoded).map_err(Box::new)?)
    }
}

/// Annotate a field with `#[serde(deserialize_with = "crate::utils::deserialize_cert")]` to
/// deserialize sigstore's certificate representation into a `Certificate`.
pub(crate) fn deserialize_cert<'de, D>(de: D) -> Result<Certificate, D::Error>
where
    D: Deserializer<'de>,
{
    SigstoreCertificate::deserialize(de)?
        .to_certificate()
        .map_err(D::Error::custom)
}

/// Annotate a field with `#[serde(deserialize_with = "crate::utils::deserialize_vec_cert")]` to
/// deserialize sigstore's certificate representation into a `Vec<Certificate>`.
pub(crate) fn deserialize_vec_cert<'de, D>(de: D) -> Result<Vec<Certificate>, D::Error>
where
    D: Deserializer<'de>,
{
    <Vec<SigstoreCertificate>>::deserialize(de)?
        .into_iter()
        .map(|cert| cert.to_certificate().map_err(D::Error::custom))
        .collect()
}

/// Annotate a field with `#[serde(deserialize_with = "crate::utils::deserialize_base64")]` to
/// deserialize a string field containing base64-encoded data representation into a `Vec<u8>`.
pub(crate) fn deserialize_base64<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    BASE64_STANDARD
        .decode(&String::deserialize(de)?)
        .map_err(D::Error::custom)
}

/// Annotate a field with `#[serde(deserialize_with = "crate::utils::deserialize_fromstr")]` to
/// deserialize a string field into a T using the FromStr implementation.
pub(crate) fn deserialize_fromstr<'de, T, D>(de: D) -> Result<T, D::Error>
where
    T: FromStr,
    T::Err: std::fmt::Display,
    D: Deserializer<'de>,
{
    T::from_str(&String::deserialize(de)?).map_err(D::Error::custom)
}

/// Annotate a field with `#[serde(deserialize_with = "crate::utils::deserialize_option_fromstr")]`
/// to deserialize a string field into an Option<T> using T's FromStr implementation.
pub(crate) fn deserialize_option_fromstr<'de, T, D>(de: D) -> Result<Option<T>, D::Error>
where
    T: FromStr,
    T::Err: std::fmt::Display,
    D: Deserializer<'de>,
{
    match <Option<String>>::deserialize(de)? {
        Some(val) => Ok(Some(T::from_str(&val).map_err(D::Error::custom)?)),
        None => Ok(None),
    }
}

/// Annotate a field with `#[serde(deserialize_with = "crate::utils::deserialize_option_hex")]` to
/// deserialize an Option<String> field into an Option<Vec<u8>> when the string is hex-encoded.
pub(crate) fn deserialize_option_hex<'de, D>(de: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    match <Option<String>>::deserialize(de)? {
        Some(val) => Ok(Some(hex::decode(&val).map_err(D::Error::custom)?)),
        None => Ok(None),
    }
}

/// Define an unit type deserializing only to the requested media type.
macro_rules! media_type {
    ($(#[$attr:meta])* $vis:vis struct $name:ident = $media:expr $(, $fallback:expr)*;) => {
        $(#[$attr])*
        $vis struct $name;

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                use serde::de::Error as _;
                let value: String = serde::Deserialize::deserialize(deserializer)?;
                if value == $media $(|| value == $fallback)* {
                    Ok($name)
                } else {
                    Err(D::Error::custom(format!("expected media type {}, found {value}", $media)))
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str($media)
            }
        }
    }
}
pub(crate) use media_type;

#[cfg(test)]
macro_rules! test_json {
    ($file:expr) => {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/",
            $file
        )))
        .unwrap()
    };
}
#[cfg(test)]
pub(crate) use test_json;
