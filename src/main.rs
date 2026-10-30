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
    let mut package_dir: Option<String> = None;
    let mut package_name: Option<String> = None;
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
            "--package" => {
                i += 1;
                package_dir = Some(args.get(i).ok_or("--package requires a directory")?.clone());
            }
            "--name" => {
                i += 1;
                package_name = Some(args.get(i).ok_or("--name requires a package name")?.clone());
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

    // Botocore ships pagination metadata in a `paginators-1.json` sidecar next to
    // the model; pick it up automatically when present.
    let paginators_path = std::path::Path::new(&model_path).with_file_name("paginators-1.json");
    let paginators_json = match std::fs::read_to_string(&paginators_path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("reading {}: {e}", paginators_path.display())),
    };
    let (src, cov) =
        aws_codegen::generate_from_json_with_paginators(&json, paginators_json.as_deref())?;

    // --package writes the full zenv package (zap.toml + src/<name>.zap); -o
    // writes the raw client source; with neither, the client goes to stdout.
    match (&package_dir, &out_path) {
        (Some(_), Some(_)) => return Err("--package and -o are mutually exclusive".to_string()),
        (Some(dir), None) => {
            let name = package_name
                .as_deref()
                .ok_or("--package requires --name <package>")?;
            let dir = std::path::Path::new(dir);
            let src_dir = dir.join("src");
            std::fs::create_dir_all(&src_dir)
                .map_err(|e| format!("creating {}: {e}", src_dir.display()))?;
            let manifest_path = dir.join("zap.toml");
            std::fs::write(&manifest_path, aws_codegen::package_manifest(name))
                .map_err(|e| format!("writing {}: {e}", manifest_path.display()))?;
            let client_path = src_dir.join(format!("{name}.zap"));
            std::fs::write(&client_path, &src)
                .map_err(|e| format!("writing {}: {e}", client_path.display()))?;
        }
        (None, Some(p)) => std::fs::write(p, &src).map_err(|e| format!("writing {p}: {e}"))?,
        (None, None) => {
            if package_name.is_some() {
                return Err("--name requires --package <dir>".to_string());
            }
            print!("{src}");
        }
    }

    eprintln!(
        "aws-codegen: {} operations ({} methods, {} skipped), {} structs ({} derived), {} enums, {} error variants, {} paginators ({} skipped){}",
        cov.operations_total,
        cov.operations_methods,
        cov.operations_skipped,
        cov.structs_total,
        cov.structs_derivable,
        cov.enums,
        cov.error_variants,
        cov.paginators,
        cov.paginators_skipped,
        package_dir
            .map(|d| format!(" -> {d}/ (package)"))
            .or_else(|| out_path.map(|p| format!(" -> {p}")))
            .unwrap_or_default(),
    );
    Ok(())
}

fn print_usage() {
    eprintln!("usage: aws-codegen <service-2.json> [--package <dir> --name <pkg> | -o <out.zap>]");
    eprintln!("  Generate a Zap AWS SDK client from a botocore model.");
    eprintln!("  --package <dir> --name <pkg>  write a zenv package: <dir>/zap.toml +");
    eprintln!("                                <dir>/src/<pkg>.zap (depends on aws_core).");
    eprintln!("  -o <out.zap>                  write just the client source to a file.");
    eprintln!("  With neither, the client source is written to stdout.");
}
