//! Shared host-only test support for the per-service fidelity gates added in
//! #350 (SQS, and later JSON-protocol services).
//!
//! Same toolchain-free philosophy as the DynamoDB #348/#349 gates: an
//! independent SigV4 signer (a re-implementation distinct from both `aws.core`
//! and the Python oracle `tools/verify_goldens.py`) plus small parsers that pull
//! the generator-OWNED pieces out of freshly generated source, so any drift in
//! what the generator emits changes the reconstructed request or paginator
//! behavior. The DynamoDB tests keep their own inline copies (that gate predates
//! this module and is left byte-for-byte untouched); new services share this one.

#![allow(dead_code)] // each test binary uses a subset.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

// AWS's published SigV4 example credentials + timestamp — the same fixed inputs
// the hand-written SDK pins, so signatures are deterministic and reproducible
// with botocore / any oracle.
pub const ACCESS: &str = "AKIDEXAMPLE";
pub const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
pub const REGION: &str = "us-east-1";
pub const AMZ_DATE: &str = "20150830T123600Z";
pub const DATE_STAMP: &str = "20150830";

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn read(path: &str) -> String {
    let p = repo_root().join(path);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

// --- an independent SigV4 signer, mirroring aws.core -------------------------

pub fn hex_sha256(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex(&h.finalize())
}

fn hmac_raw(key: &[u8], msg: &str) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac key of any length");
    m.update(msg.as_bytes());
    m.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Percent-encode a path with "/" as a safe separator (RFC-3986 unreserved pass
/// through), matching url.quote_path / aws.core.wire_path.
fn quote_path(path: &str) -> String {
    let mut out = String::new();
    for b in path.bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/');
        if unreserved {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// CanonicalURI: non-S3 services double-encode the path (aws.core.canonical_uri).
fn canonical_uri(path: &str, service: &str) -> String {
    let once = quote_path(path);
    if service == "s3" {
        once
    } else {
        quote_path(&once)
    }
}

fn signing_key(secret: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_raw(format!("AWS4{secret}").as_bytes(), date_stamp);
    let k_region = hmac_raw(&k_date, region);
    let k_service = hmac_raw(&k_region, service);
    hmac_raw(&k_service, "aws4_request")
}

/// Build the full HTTP/1.1 request text exactly as aws.core.sign_request:
/// generic canonicalization (lowercase / trim / sort the header dict), the
/// double-encoded canonical URI, SHA-256 payload hash, and the SigV4 signature.
/// Byte-identical in shape to the inline signer in `tests/byte_diff.rs`.
pub fn sign_request(
    service: &str,
    method: &str,
    path: &str,
    body: &str,
    headers: &[(&str, String)],
) -> String {
    let mut sorted: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| (n.to_lowercase(), v.clone()))
        .collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let canon_headers: String = sorted
        .iter()
        .map(|(n, v)| format!("{n}:{}\n", v.trim()))
        .collect();
    let signed_headers: Vec<String> = sorted.iter().map(|(n, _)| n.clone()).collect();
    let signed_headers = signed_headers.join(";");

    let canon_uri = canonical_uri(path, service);
    let payload_sha = hex_sha256(body);
    let canon_req =
        format!("{method}\n{canon_uri}\n\n{canon_headers}\n{signed_headers}\n{payload_sha}");
    let scope = format!("{DATE_STAMP}/{REGION}/{service}/aws4_request");
    let sts = format!(
        "AWS4-HMAC-SHA256\n{AMZ_DATE}\n{scope}\n{}",
        hex_sha256(&canon_req)
    );
    let key = signing_key(SECRET, DATE_STAMP, REGION, service);
    let signature = hex(&hmac_raw(&key, &sts));
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut headers_block = String::new();
    for (n, v) in &sorted {
        headers_block.push_str(&format!("{n}: {v}\r\n"));
    }
    headers_block.push_str(&format!("content-length: {}\r\n", body.len()));
    headers_block.push_str(&format!("authorization: {auth}\r\n"));

    let target = quote_path(path);
    format!("{method} {target} HTTP/1.1\r\n{headers_block}Connection: close\r\n\r\n{body}")
}

// --- generator-owned pieces, parsed out of the generated source --------------

/// The substring between `open` and the next `close` after it, if both occur.
pub fn between(s: &str, open: &str, close: &str) -> Option<String> {
    let a = s.find(open)? + open.len();
    let rest = &s[a..];
    let b = rest.find(close)?;
    Some(rest[..b].to_string())
}

/// The awsJson protocol config threaded into every call: the X-Amz-Target prefix,
/// the SigV4 service name, and the content type pinned by the codec constructor.
/// Read from `def <svc>_protocol() -> AwsJson: return awsjson_1_<v>("<prefix>", "<svc>")`.
pub fn parse_protocol(src: &str) -> (String, String, String) {
    let (call, ctype) = if src.contains("awsjson_1_1(") {
        ("awsjson_1_1(", "application/x-amz-json-1.1")
    } else {
        ("awsjson_1_0(", "application/x-amz-json-1.0")
    };
    let start = src.find(call).expect("protocol fn uses awsjson_1_x(...)");
    let args = &src[start + call.len()..];
    let end = args.find(')').expect("awsjson_1_x(...) is closed");
    let strings: Vec<String> = args[..end]
        .split(',')
        .map(|a| a.trim().trim_matches('"').to_string())
        .collect();
    assert_eq!(
        strings.len(),
        2,
        "awsjson_1_x takes (target_prefix, service)"
    );
    (strings[0].clone(), strings[1].clone(), ctype.to_string())
}

/// The operation name a generated method dispatches, read from its
/// `awsjson_request_now(..., "<Op>", body)` call. `method_sig` is the exact
/// `def ...:` header line to anchor on.
pub fn parse_dispatch_op(src: &str, method_sig: &str) -> String {
    let m = src
        .find(method_sig)
        .unwrap_or_else(|| panic!("generated client defines `{method_sig}`"));
    let body = &src[m..];
    between(body, "self.region, \"", "\", body)").expect("dispatches a named operation")
}

/// Struct member declarations (type, name), in declaration order, for
/// `struct <name>:`. Stops at the first non-indented line.
pub fn parse_struct_fields(src: &str, struct_name: &str) -> Vec<(String, String)> {
    let anchor = format!("struct {struct_name}:");
    let m = src
        .find(&anchor)
        .unwrap_or_else(|| panic!("generated source defines `{anchor}`"));
    let after = &src[m + anchor.len()..];
    let mut fields = Vec::new();
    for line in after.lines().skip(1) {
        if !line.starts_with("    ") {
            break;
        }
        let decl = line.trim();
        if decl.starts_with('#') || decl.starts_with('@') {
            continue; // comments / per-field decorators
        }
        let mut it = decl.split_whitespace();
        let ty = it.next().unwrap_or("").to_string();
        let name = it.next().unwrap_or("").to_string();
        fields.push((ty, name));
    }
    fields
}

// --- paginator parsing + a faithful re-implementation of the emitted loop ----

/// The pagination wiring a generated `paginate_*` method encodes.
pub struct ParsedPaginator {
    pub op: String,
    pub output_token: String,
    pub input_token: String,
}

/// Parse a `paginate_*` method body. `method_sig` is its exact `def ...:` header.
pub fn parse_paginator(src: &str, method_sig: &str) -> ParsedPaginator {
    let m = src
        .find(method_sig)
        .unwrap_or_else(|| panic!("generated client defines `{method_sig}`"));
    let body = &src[m..];
    let after = &body[method_sig.len()..];
    let end = ["\n    def ", "\n    #", "\n# ", "\ndef "]
        .iter()
        .filter_map(|marker| after.find(marker))
        .min()
        .map(|i| method_sig.len() + i)
        .unwrap_or(body.len());
    let body = &body[..end];

    assert!(
        body.contains("yield page"),
        "paginator yields pages:\n{body}"
    );
    assert!(
        body.contains("auto page = send(host, raw)"),
        "paginator sends each page:\n{body}"
    );
    assert!(
        body.contains("if not np.has_more:"),
        "paginator stops on an absent token:\n{body}"
    );

    let op = between(body, "self.region, \"", "\", body)").expect("dispatches a named operation");
    let output_token = between(body, "next_page_json(page.body, \"", "\")")
        .expect("reads the next token via next_page_json");
    // Anchor on the assignment itself, between the last `input.` before the
    // `= ...(np.token)` suffix (so `input.to_json()` is not matched).
    let close = body
        .find("np.token")
        .expect("assigns the token from np.token");
    let head = &body[..close];
    let open = "input.";
    let start = head
        .rfind(open)
        .expect("token assignment targets input.<field>")
        + open.len();
    let input_token = head[start..]
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .next()
        .unwrap_or("")
        .to_string();

    ParsedPaginator {
        op,
        output_token,
        input_token,
    }
}

/// Mirror of aws.core `json_string_field`: the quoted value of `"field":"..."`.
pub fn json_string_field(body: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let k = body.find(&needle)?;
    let rest = &body[k + needle.len()..];
    let c = rest.find(':')?;
    let after = &rest[c + 1..];
    let q1 = after.find('"')?;
    let tail = &after[q1 + 1..];
    let q2 = tail.find('"')?;
    Some(tail[..q2].to_string())
}

/// One run of a generated paginator loop against a fixed page sequence.
pub struct Run {
    pub pages: Vec<String>,
    pub request_tokens: Vec<String>,
}

/// Execute the loop exactly as a `paginate_*` method emits it, using the parsed
/// field names, over a stubbed response sequence. Guarded against runaway loops.
pub fn drive(p: &ParsedPaginator, responses: &[&str]) -> Run {
    let mut pages = Vec::new();
    let mut request_tokens = Vec::new();
    let mut token = String::new();
    let mut i = 0;
    loop {
        assert!(
            i < responses.len(),
            "paginator requested more pages than the stub provides — it failed to stop (op {}, token {})",
            p.op,
            p.output_token
        );
        request_tokens.push(token.clone());
        let page = responses[i].to_string();
        pages.push(page.clone());
        let next = json_string_field(&page, &p.output_token).unwrap_or_default();
        if next.is_empty() {
            break;
        }
        token = next;
        i += 1;
    }
    Run {
        pages,
        request_tokens,
    }
}
