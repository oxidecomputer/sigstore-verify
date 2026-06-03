# sigstore-verify

The `sigstore-verify` crate provides a Rust API to verify attestations and
signatures encoded with the [Sigstore bundle format v0.3][bundle-format], used
among others by GitHub's attestation features.

The crate **does not verify whether the attestation was uploaded to a
transparency log**. It verifies whether it was produced by a trusted certificate
and whether it happened within the certificate's validity period.

Example usage:

```rust
use sigstore_verify::repr::{bundle::Bundle, trusted_root::TrustedRoot};

// Load the Sigstore trusted root, the attestation bundle, and the file to verify.
let root: TrustedRoot = serde_json::from_slice(&std::fs::read("trusted_root.json")?)?;
let bundle: Bundle = serde_json::from_slice(&std::fs::read("file.txt.sigstore.json")?)?;
let mut file = File::open("file.txt")?;

// Verify the attestation is valid, returning the claims within it.
let claims = sigstore_verify::verify_no_tlog(&root, &bundle, &mut file)?;

// Assert that the claims are the expected ones.
assert_eq!(
  claims.issuer_v2,
  Some("https://token.actions.githubusercontent.com"),
);
assert_eq!(
  claims.source_repository_uri,
  Some("https://github.com/oxidecomputer/sigstore-verify"),
);
```

[bundle-format]: https://docs.sigstore.dev/about/bundle/
