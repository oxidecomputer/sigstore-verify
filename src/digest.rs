use sha2::{Digest as _, Sha256};
use std::io::{Read, Seek, SeekFrom};

/// Representation of a digest.
///
/// We wrap them in this enum because different parts of the Sigstore bundle can hash things with
/// different algorithms, and we need an unified interface to let the verifier check those hashes.
/// The idea is that the verifier receives the expected hash, and calls a method to check whether
/// the actual content matches the hash, without having to care about the algorithm.
#[derive(PartialEq, Eq)]
pub(crate) enum Digest {
    Sha256(Vec<u8>),
}

impl Digest {
    pub(crate) fn matches(&self, other: &[u8]) -> bool {
        match self {
            Digest::Sha256(expected) => &*Sha256::digest(other) == expected,
        }
    }

    pub(crate) fn matches_stream<T: Read + Seek>(
        &self,
        mut other: T,
    ) -> Result<bool, std::io::Error> {
        other.seek(SeekFrom::Start(0))?;
        Ok(match self {
            Digest::Sha256(expected) => {
                let mut hasher = Sha256::new();
                std::io::copy(&mut other, &mut hasher)?;
                &*hasher.finalize() == expected
            }
        })
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha256(hash) => write!(f, "sha256:{}", hex::encode(&hash)),
        }
    }
}
