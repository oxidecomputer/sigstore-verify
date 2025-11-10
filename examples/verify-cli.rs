use clap::Parser;
use sigstore_verify::repr::bundle::Bundle;
use sigstore_verify::repr::trusted_root::TrustedRoot;
use sigstore_verify::verify_no_tlog;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

static BUNDLED_TRUSTED_ROOT: &[u8] = include_bytes!("../test-data/trusted-roots/sigstore.json");

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
    let root: TrustedRoot = serde_json::from_slice(&match &cli.trusted_root {
        Some(file) => std::fs::read(&file)?,
        None => BUNDLED_TRUSTED_ROOT.to_vec(),
    })?;

    let claims = verify_no_tlog(&root, &bundle, &mut file)?;
    dbg!(claims);

    Ok(())
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
