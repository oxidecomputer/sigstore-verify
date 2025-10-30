use base64::prelude::{BASE64_STANDARD, Engine as _};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::fmt::Debug;

pub mod bundle;
pub mod dsse_envelope;
pub mod in_toto;
pub mod trusted_root;

#[derive(Deserialize)]
#[serde(try_from = "String", bound = "T: DeserializeOwned + Debug")]
pub struct Parsed<T> {
    pub parsed: T,
    pub raw: Vec<u8>,
}

impl<T: Debug> Debug for Parsed<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Parsed")
            .field("parsed", &self.parsed)
            .finish_non_exhaustive()
    }
}

impl<T: DeserializeOwned> TryFrom<String> for Parsed<T> {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let ty = std::any::type_name::<T>();
        let raw = BASE64_STANDARD
            .decode(value)
            .map_err(|e| format!("failed to base64-decode {ty}: {e}"))?;
        let parsed =
            serde_json::from_slice(&raw).map_err(|e| format!("failed to parse {ty}: {e}"))?;
        Ok(Parsed { parsed, raw })
    }
}
