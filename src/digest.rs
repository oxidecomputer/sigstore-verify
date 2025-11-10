use sha2::{Digest as _, Sha256};
use std::io::Read;

#[derive(PartialEq, Eq, Clone)]
pub(crate) struct Digest {
    raw: Vec<u8>,
    kind: DigestKind,
}

impl Digest {
    pub(crate) fn sha256_prehashed(raw: Vec<u8>) -> Self {
        Self {
            raw,
            kind: DigestKind::Sha256,
        }
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.kind, hex::encode(&self.raw))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
enum DigestKind {
    Sha256,
}

impl std::fmt::Display for DigestKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DigestKind::Sha256 => f.write_str("sha256"),
        }
    }
}

/// The Sigstore bundle format is fairly flexible in regards to the hashing algorithms allowed to
/// be used. This struct prepares hashes for all digest algorithms we expect to be used, so that
/// later we can just check the actual hash without having to re-hash things.
pub(crate) struct DigestCollection {
    sha256: Option<Digest>,
}

impl DigestCollection {
    pub(crate) fn calculate(content: &[u8]) -> Self {
        DigestCollection {
            sha256: Some(Digest::sha256_prehashed(Sha256::digest(content).to_vec())),
        }
    }

    pub(crate) fn calculate_from_reader(reader: &mut dyn Read) -> Result<Self, DigestError> {
        let mut buffer = [0; 1024];
        let mut sha256 = Sha256::new();
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(len) => {
                    let read = &buffer[..len];
                    sha256.update(read);
                }
                Err(err) => return Err(DigestError::Io(err)),
            }
        }
        Ok(DigestCollection {
            sha256: Some(Digest::sha256_prehashed(sha256.finalize().to_vec())),
        })
    }

    pub(crate) fn verify(&self, digest: &Digest) -> Result<(), DigestError> {
        let expected = match (digest.kind, self) {
            (
                DigestKind::Sha256,
                Self {
                    sha256: Some(expected),
                    ..
                },
            ) => expected,
            _ => return Err(DigestError::DigestNotCalculated(digest.kind.to_string())),
        };
        if expected == digest {
            Ok(())
        } else {
            Err(DigestError::HashMismatch(
                format!("{expected:?}"),
                format!("{digest:?}"),
            ))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("hash mismatch: {0} != {1}")]
    HashMismatch(String, String),
    #[error("digest for algorithm {0} was not calculated ahead of time")]
    DigestNotCalculated(String),
}
