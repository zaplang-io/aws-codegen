//! Byte-diff fidelity gate for the generated DynamoDB client (#348).
//!
//! Proves the v0 generator is faithful: a DynamoDB `DescribeTable` call,
//! serialized on the wire by the GENERATED client, is byte-identical to the
//! request the HAND-WRITTEN reference (zaplang-io/aws `aws.dynamodb` +
//! `aws.awsjson`) produces for the same input.
//!
//! WHY THIS IS A HOST-ONLY RUST TEST. The true end-to-end check runs the
//! generated Zap client under the Zap toolchain
//! (`tests/describe_table_byte_diff.main.zap`); but the published compiler image
//! still lags the derive(Json) AWS hooks (zaplang-io/zap#346), so the full
//! generated file does not yet compile there and that step is CI-only and
//! best-effort. To fail CI on a generator regression *now*, with no toolchain,
//! this test reconstructs the exact on-the-wire request from two sources:
//!
//!   * everything the generator OWNS — the request body, the X-Amz-Target
//!     operation + prefix, the content type, the method and path — is parsed
//!     out of the freshly generated client source, so any drift in what the
//!     generator emits changes the reconstructed request; and
//!   * the SigV4 signature over those bytes, computed here by an independent
//!     signer (a third implementation besides aws.core and
//!     tools/verify_describe_table.py), with AWS's published example
//!     credentials + timestamp.
//!
//! The result is compared byte-for-byte against the checked-in golden
//! `tests/expected/dynamodb_describe_table.http` — the hand-written reference's
//! request, which `tools/verify_describe_table.py` reproduces from scratch. The
//! full request is compared: request line (method + path), every header, and the
//! body. Nothing on the wire is normalized away.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

// AWS's published SigV4 example credentials + timestamp — the same fixed inputs
// the hand-written SDK pins in zaplang-io/aws tests/service_signing.main.zap, so
// the signature is deterministic and reproducible with botocore / any oracle.
const ACCESS: &str = "AKIDEXAMPLE";
const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const REGION: &str = "us-east-1";
const AMZ_DATE: &str = "20150830T123600Z";
const DATE_STAMP: &str = "20150830";
const HOST: &str = "dynamodb.us-east-1.amazonaws.com";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    let p = repo_root().join(path);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

// --- what the generator owns, parsed out of the generated source -------------

/// The awsJson protocol config the generated client threads into every call:
/// the X-Amz-Target prefix and the SigV4 service name, read from
/// `def dynamodb_protocol() -> AwsJson: return awsjson_1_0("<prefix>", "<svc>")`.
fn parse_protocol(src: &str) -> (String, String, String) {
    let call = "awsjson_1_0(";
    let start = src
        .find(call)
        .expect("generated source defines dynamodb_protocol via awsjson_1_0(...)");
    let args = &src[start + call.len()..];
    let end = args.find(')').expect("awsjson_1_0(...) is closed");
    let args = &args[..end];
    let strings: Vec<String> = args
        .split(',')
        .map(|a| a.trim().trim_matches('"').to_string())
        .collect();
    assert_eq!(
        strings.len(),
        2,
        "awsjson_1_0 takes (target_prefix, service); got {args:?}"
    );
    // awsjson_1_0 pins Content-Type application/x-amz-json-1.0 (aws.awsjson).
    (
        strings[0].clone(),
        strings[1].clone(),
        "application/x-amz-json-1.0".to_string(),
    )
}

/// The operation name the generated `describe_table` method selects, read from
/// its `awsjson_request_now(..., "<Op>", body)` call.
fn parse_describe_table_op(src: &str) -> String {
    let anchor = "def describe_table(self, DescribeTableInput input) -> str:";
    let m = src
        .find(anchor)
        .expect("generated client defines describe_table(DescribeTableInput)");
    let body = &src[m..];
    // The method body serializes the input then dispatches through the codec.
    assert!(
        body[..200].contains("auto body = input.to_json()"),
        "describe_table serializes its input with derive(Json) to_json()"
    );
    let needle = "awsjson_request_now(dynamodb_protocol(), self.creds, self.region, \"";
    let n = body
        .find(needle)
        .expect("describe_table dispatches through awsjson_request_now");
    let rest = &body[n + needle.len()..];
    let end = rest.find('"').expect("operation name is quoted");
    rest[..end].to_string()
}

/// The JSON body `DescribeTableInput(TableName="Users").to_json()` produces,
/// built from the generated struct definition so a change to the struct's fields
/// (name, order, type, optionality) changes the body. v0 DescribeTableInput is a
/// single required `str TableName`; derive(Json) encodes it as compact,
/// declaration-order JSON (zaplang-io/zap#346).
fn parse_describe_table_body(src: &str, table_name: &str) -> String {
    let anchor = "struct DescribeTableInput:";
    let m = src
        .find(anchor)
        .expect("generated source defines struct DescribeTableInput");
    // The struct must carry @derive(Json) for to_json() to exist at all: the
    // decorator is the line immediately preceding the struct header.
    assert!(
        src[..m].trim_end().ends_with("@derive(Json)"),
        "DescribeTableInput is @derive(Json)"
    );
    let after = &src[m + anchor.len()..];
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in after.lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }
        // Struct body lines are indented; the first unindented line ends it.
        if !line.starts_with("    ") {
            break;
        }
        let decl = line.trim();
        let mut it = decl.split_whitespace();
        let ty = it.next().unwrap_or("").to_string();
        let name = it.next().unwrap_or("").to_string();
        fields.push((ty, name));
    }
    assert_eq!(
        fields,
        vec![("str".to_string(), "TableName".to_string())],
        "v0 DescribeTableInput is a single required `str TableName`; the byte-diff \
         fixture must be updated if the generated shape changes"
    );
    // Single required string field -> {"TableName":"<escaped value>"}.
    format!("{{\"{}\":\"{}\"}}", fields[0].1, json_escape(table_name))
}

/// Minimal JSON string escaping — enough for the fixture's table name. derive's
/// own escaper (zap_json_escape) covers the full set; "Users" needs none.
fn json_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

// --- an independent SigV4 signer, mirroring aws.core -------------------------

fn hex_sha256(s: &str) -> String {
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
fn sign_request(
    service: &str,
    method: &str,
    path: &str,
    body: &str,
    headers: &[(&str, String)],
) -> String {
    let payload_sha = hex_sha256(body);

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

#[test]
fn generated_describe_table_request_matches_handwritten_golden() {
    // Regenerate the client from the pinned model (not the checked-in file), so
    // this fails the moment the generator's output drifts.
    let model = read("models/dynamodb/2012-08-10/service-2.json");
    let (src, _cov) = aws_codegen::generate_from_json(&model).expect("DynamoDB model generates");

    // Pull every wire-determining piece out of the generated source.
    let (prefix, service, content_type) = parse_protocol(&src);
    let op = parse_describe_table_op(&src);
    let body = parse_describe_table_body(&src, "Users");

    // Reconstruct the on-the-wire request the generated client would sign.
    let target = format!("{prefix}.{op}");
    let headers = vec![
        ("content-type", content_type),
        ("host", HOST.to_string()),
        ("x-amz-content-sha256", hex_sha256(&body)),
        ("x-amz-date", AMZ_DATE.to_string()),
        ("x-amz-target", target),
    ];
    let generated = sign_request(&service, "POST", "/", &body, &headers);

    // The hand-written reference's request, pinned and independently reproduced
    // by tools/verify_describe_table.py.
    let golden = read("tests/expected/dynamodb_describe_table.http");

    assert_eq!(
        generated, golden,
        "generated DynamoDB DescribeTable request is NOT byte-identical to the \
         hand-written reference golden (tests/expected/dynamodb_describe_table.http).\n\
         If this is an intended change, re-pin the golden with \
         `python3 tools/verify_describe_table.py --emit` and confirm the oracle agrees."
    );

    // Guard the generator-owned pieces explicitly, so a failure points at the
    // drift rather than an opaque signature mismatch.
    assert_eq!(prefix, "DynamoDB_20120810", "X-Amz-Target prefix drifted");
    assert_eq!(service, "dynamodb", "SigV4 service name drifted");
    assert_eq!(op, "DescribeTable", "operation name drifted");
    assert_eq!(body, "{\"TableName\":\"Users\"}", "request body drifted");
}
