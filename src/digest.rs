// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use tokio::io::{AsyncRead, AsyncReadExt as _};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use std::io::Read;

#[derive(PartialEq, Eq, Clone)]
pub(crate) struct Digest {
    raw: Vec<u8>,
    kind: DigestKind,
}

impl Digest {
    pub(crate) fn sha1_prehashed(raw: Vec<u8>) -> Self {
        Self {
            raw,
            kind: DigestKind::Sha1,
        }
    }

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
    Sha1,
    Sha256,
}

impl std::fmt::Display for DigestKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DigestKind::Sha1 => f.write_str("sha1"),
            DigestKind::Sha256 => f.write_str("sha256"),
        }
    }
}

/// The Sigstore bundle format is fairly flexible in regards to the hashing algorithms allowed to
/// be used. This struct prepares hashes for all digest algorithms we expect to be used, so that
/// later we can just check the actual hash without having to re-hash things.
pub(crate) struct DigestCollection {
    pub(crate) sha1: Option<Digest>,
    pub(crate) sha256: Option<Digest>,
}

impl DigestCollection {
    pub(crate) fn calculate(content: &[u8]) -> Self {
        DigestCollection {
            sha1: Some(Digest::sha1_prehashed(Sha1::digest(content).to_vec())),
            sha256: Some(Digest::sha256_prehashed(Sha256::digest(content).to_vec())),
        }
    }

    pub(crate) fn calculate_from_reader(reader: &mut dyn Read) -> Result<Self, DigestError> {
        let mut buffer = [0; 1024];
        let mut builder = DigestCollectionBuilder::new();
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(len) => builder.update(&buffer[..len]),
                Err(err) => return Err(DigestError::Io(err)),
            }
        }
        Ok(builder.finalize())
    }

    pub(crate) async fn calculate_from_async_reader(
        reader: &mut (dyn AsyncRead + Unpin + Send),
    ) -> Result<Self, DigestError> {
        let mut buffer = [0; 1024];
        let mut builder = DigestCollectionBuilder::new();
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(len) => builder.update(&buffer[..len]),
                Err(err) => return Err(DigestError::Io(err)),
            }
        }
        Ok(builder.finalize())
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
            (
                DigestKind::Sha1,
                Self {
                    sha1: Some(expected),
                    ..
                },
            ) => expected,
            _ => return Err(DigestError::DigestNotCalculated(digest.kind.to_string())),
        };
        if expected == digest {
            Ok(())
        } else {
            Err(DigestError::HashMismatch)
        }
    }
}

struct DigestCollectionBuilder {
    sha1: Sha1,
    sha256: Sha256,
}

impl DigestCollectionBuilder {
    fn new() -> Self {
        Self {
            sha1: Sha1::new(),
            sha256: Sha256::new(),
        }
    }

    fn update(&mut self, buffer: &[u8]) {
        self.sha1.update(buffer);
        self.sha256.update(buffer);
    }

    fn finalize(self) -> DigestCollection {
        DigestCollection {
            sha1: Some(Digest::sha1_prehashed(self.sha1.finalize().to_vec())),
            sha256: Some(Digest::sha256_prehashed(self.sha256.finalize().to_vec())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("hash mismatch")]
    HashMismatch,
    #[error("digest for algorithm {0} was not calculated ahead of time")]
    DigestNotCalculated(String),
}
