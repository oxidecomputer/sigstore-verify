use crate::repr::trusted_root::TrustedRoot;
use futures::StreamExt as _;
use std::path::{Path, PathBuf};
use tough::{KeyIdFormat, RepositoryLoader, TargetName};

/// The Sigstore Public Good instance. To be used with [`fetch_trusted_root`].
pub static SIGSTORE_PUBLIC_GOOD: FetchableTrustedRoot = FetchableTrustedRoot {
    name: "sigstore",
    pinned_root: include_bytes!("../trusted-roots/sigstore.15.root.json"),
    metadata_base_url: "https://tuf-repo-cdn.sigstore.dev",
    targets_base_url: "https://tuf-repo-cdn.sigstore.dev/targets",
};

/// GitHub's Sigstore instance. To be used with [`fetch_trusted_root`].
pub static GITHUB_DOT_COM: FetchableTrustedRoot = FetchableTrustedRoot {
    name: "github",
    pinned_root: include_bytes!("../trusted-roots/github.8.root.json"),
    metadata_base_url: "https://tuf-repo.github.com",
    targets_base_url: "https://tuf-repo.github.com/targets",
};

/// Fetch the trusted root configuration for a Sigstore instance.
///
/// The function will use The Update Framework to securely retrieve the latest copy of the trusted
/// root configuration file. You need to provide the path to a directory that will contain a cache
/// of the TUF metadata, which should ideally be reused across invocations.
pub async fn fetch_trusted_root(
    cache_dir: &Path,
    config: &FetchableTrustedRoot,
) -> Result<TrustedRoot, FetchTrustedRootError> {
    let cache = cache_dir.join(config.name);
    std::fs::create_dir_all(&cache)
        .map_err(|e| FetchTrustedRootError::CreateCacheDir(cache.clone(), e))?;

    let repo = RepositoryLoader::new(
        &config.pinned_root,
        config
            .metadata_base_url
            .parse()
            .map_err(|_| FetchTrustedRootError::InvalidUrl(config.metadata_base_url.into()))?,
        config
            .targets_base_url
            .parse()
            .map_err(|_| FetchTrustedRootError::InvalidUrl(config.targets_base_url.into()))?,
    )
    .datastore(&cache)
    // The key IDs in GitHub's TUF repo don't conform to the TUF 1.0.0 specification, so we
    // have to enable TAP 12 support (allowing arbitrary key IDs).
    .key_id_format(KeyIdFormat::Any)
    .load()
    .await
    .map_err(FetchTrustedRootError::LoadTuf)?;

    let mut stream = repo
        .read_target(&TargetName::new("trusted_root.json").unwrap())
        .await
        .map_err(FetchTrustedRootError::ReadTarget)?
        .ok_or(FetchTrustedRootError::MissingTarget)?;

    let mut content = Vec::new();
    while let Some(bytes) = stream.next().await {
        content.extend_from_slice(bytes.map_err(FetchTrustedRootError::ReadTarget)?.as_ref());
    }

    Ok(serde_json::from_slice(&content).map_err(FetchTrustedRootError::ParseTarget)?)
}

#[derive(Debug, thiserror::Error)]
pub enum FetchTrustedRootError {
    #[error("faield to create cache dir {}", .0.display())]
    CreateCacheDir(PathBuf, #[source] std::io::Error),
    #[error("invalid URL {0:?}")]
    InvalidUrl(String),
    #[error("failed to load TUF repository")]
    LoadTuf(#[source] tough::error::Error),
    #[error("failed to load trusted_root.json from the repo")]
    ReadTarget(#[source] tough::error::Error),
    #[error("trusted_root.json is not present in the repo")]
    MissingTarget,
    #[error("failed to parse trusted_root.json")]
    ParseTarget(serde_json::Error),
}

pub struct FetchableTrustedRoot {
    pinned_root: &'static [u8],
    metadata_base_url: &'static str,
    targets_base_url: &'static str,
    name: &'static str,
}
