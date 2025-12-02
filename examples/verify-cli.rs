use clap::Parser;
use sigstore_verify::repr::bundle::Bundle;
use sigstore_verify::repr::trusted_root::TrustedRoot;
use sigstore_verify::verify_no_tlog;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

static BUNDLED_TRUSTED_ROOT: &str = include_str!("../test-data/trusted-roots/sigstore.json");

#[derive(Debug, Parser)]
struct Cli {
    /// File to verify.
    file: PathBuf,

    /// Bundle to verify (usually ends with .sigstore.json).
    bundle: PathBuf,

    /// Trusted root to use (defaults to the Sigstore public good instance).
    #[clap(long)]
    trusted_root: Option<PathBuf>,
}

fn app() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    let mut file = BufReader::new(File::open(&cli.file)?);
    let bundle: Bundle = serde_json::from_slice(&std::fs::read(&cli.bundle)?)?;
    let root = load_trusted_root(&match &cli.trusted_root {
        Some(file) => std::fs::read_to_string(&file)?,
        None => BUNDLED_TRUSTED_ROOT.into(),
    })?;

    let claims = verify_no_tlog(&root, &bundle, &mut file)?;
    dbg!(claims);

    Ok(())
}

fn load_trusted_root(content: &str) -> Result<TrustedRoot, Box<dyn Error>> {
    let mut merged = TrustedRoot::empty();
    for line in content.trim().split('\n') {
        merged.merge(serde_json::from_str(line)?);
    }
    Ok(merged)
}

fn main() {
    if let Err(err) = app() {
        eprintln!("error: {err}");
        let mut source = err.source();
        while let Some(err) = source {
            eprintln!("  caused by: {err}");
            source = err.source();
        }
        std::process::exit(1);
    }
}
