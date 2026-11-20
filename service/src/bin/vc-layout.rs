//! The vc-layout migration tool: translate the vc-stack verifier's
//! `config.yaml` into this service's proxy.toml.
//!
//! A MIGRATION AID, not a pipeline step: the operator runs it once
//! against the deployment's existing vc configuration, reads the
//! report (what maps, what this service does not support, what the
//! operator must decide), and then adapts the emitted configuration
//! into the deployment's own templating. The report IS the migration
//! checklist; the emitted proxy.toml is the starting point.
//!
//! ```sh
//! vc-layout <config.yaml> [-o proxy.toml] [options]
//! ```
//!
//! The report goes to stderr; the proxy.toml to stdout (or `-o`).
//! Any refusal — an unknown member (a typo, or a NEW vc-stack feature
//! that would otherwise silently vanish), an unfulfillable subject
//! claim, an HTTP PDP without the opt-in — exits non-zero naming the
//! path.

use std::io::Write;

use siros_verifier_service::vc_layout::{translate, TranslateOptions};

fn main() {
    let mut source: Option<String> = None;
    let mut output: Option<String> = None;
    let mut options = TranslateOptions::default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].clone();
        match arg.as_str() {
            "-o" | "--output" => {
                i += 1;
                output = args.get(i).cloned();
            }
            "--allow-insecure-pdp" => options.allow_insecure_pdp = true,
            "--subject-pointer" => {
                i += 1;
                options.subject_pointer = args.get(i).cloned();
            }
            "--subject-scope" => {
                i += 1;
                options.subject_scope = args.get(i).cloned();
            }
            "-h" | "--help" => {
                print!("{}", HELP);
                return;
            }
            _ if source.is_none() => source = Some(arg),
            _ => {
                eprintln!("unexpected argument {arg}\n\n{HELP}");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    let Some(source) = source else {
        eprint!("{HELP}");
        std::process::exit(2);
    };
    let yaml = match std::fs::read_to_string(&source) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("reading {source}: {e}");
            std::process::exit(1);
        }
    };
    let source_dir = std::path::Path::new(&source)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let translation = match translate(&yaml, &source_dir, &options) {
        Ok(translation) => translation,
        Err(e) => {
            eprintln!("{source}: {e:#}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "{source} translated ({} mapped, {} known-unsupported, {} notes):",
        translation.report.mapped.len(),
        translation.report.warned.len(),
        translation.report.notes.len()
    );
    eprintln!("{}", translation.report);
    eprintln!(
        "the migration checklist: the notes above are the decisions the deployment's own \
         templating must state when it is rewritten natively; the known-unsupported list is \
         the capability the deployment runs without"
    );
    match output {
        Some(path) => {
            // The emitted config can carry credentials (the mongo URI
            // embeds them) — owner-only.
            if let Err(e) = std::fs::write(&path, &translation.toml) {
                eprintln!("writing {path}: {e}");
                std::process::exit(1);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) =
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                {
                    eprintln!("restricting {path} to owner-only: {e}");
                    std::process::exit(1);
                }
            }
            eprintln!("the translated proxy.toml is at {path}");
        }
        None => {
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            if let Err(e) = out.write_all(translation.toml.as_bytes()) {
                eprintln!("writing the translation to stdout: {e}");
                std::process::exit(1);
            }
        }
    }
}

const HELP: &str = "\
vc-layout — translate the vc-stack verifier's config.yaml into this service's proxy.toml

USAGE:
    vc-layout <config.yaml> [-o <proxy.toml>] [options]

    The report (mapped / known-unsupported / unknown / notes) goes to
    stderr; the proxy.toml to stdout, or to -o (owner-only mode).

OPTIONS:
    -o, --output <file>        write the translated proxy.toml here
        --allow-insecure-pdp   permit a plain-HTTP PDP on a non-loopback
                               address (the vc layouts' private-network
                               posture; the emitted config states
                               allow_insecure_http = true)
        --subject-pointer <claim-path>
                               the OP's subject identifier — a UNIQUE
                               claim, required when the layout enables
                               the OP (a holder's name is not one)
        --subject-scope <credential-scope>
                               the supported credential whose fallback
                               query carries the subject claim (required
                               when the layout supports more than one
                               credential)
    -h, --help                 this help
";
