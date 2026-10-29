//! CLI: `aws-codegen <service-2.json> [-o <out.zap>]`.
//!
//! Reads a botocore model, generates the Zap client, and writes it to `-o`
//! (or stdout). A coverage summary is printed to stderr.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aws-codegen: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let mut model_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            "-o" | "--out" => {
                i += 1;
                out_path = Some(args.get(i).ok_or("-o requires a path")?.clone());
            }
            s if s.starts_with('-') => return Err(format!("unknown flag `{s}`")),
            s => {
                if model_path.is_some() {
                    return Err(format!("unexpected extra argument `{s}`"));
                }
                model_path = Some(s.to_string());
            }
        }
        i += 1;
    }

    let model_path = model_path.ok_or_else(|| {
        print_usage();
        "missing <service-2.json> path".to_string()
    })?;
    let json =
        std::fs::read_to_string(&model_path).map_err(|e| format!("reading {model_path}: {e}"))?;
    let (src, cov) = aws_codegen::generate_from_json(&json)?;

    match &out_path {
        Some(p) => std::fs::write(p, &src).map_err(|e| format!("writing {p}: {e}"))?,
        None => print!("{src}"),
    }

    eprintln!(
        "aws-codegen: {} operations ({} methods, {} skipped), {} structs ({} derived), {} enums, {} error variants{}",
        cov.operations_total,
        cov.operations_methods,
        cov.operations_skipped,
        cov.structs_total,
        cov.structs_derivable,
        cov.enums,
        cov.error_variants,
        out_path.map(|p| format!(" -> {p}")).unwrap_or_default(),
    );
    Ok(())
}

fn print_usage() {
    eprintln!("usage: aws-codegen <service-2.json> [-o <out.zap>]");
    eprintln!("  Generate a Zap awsJson client from a botocore model.");
    eprintln!("  With no -o, the client is written to stdout.");
}
