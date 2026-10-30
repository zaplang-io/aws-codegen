//! Byte-diff fidelity gate for the generated rest-json Lambda client (#4).
//!
//! Proves the rest-json generator is faithful: four Lambda calls spanning the
//! binding kinds — `GetFunction` (httpLabel + httpQuery, GET, no body),
//! `ListFunctions` (pure httpQuery incl. an int, GET, paginated), `Invoke`
//! (httpLabel + httpQuery + httpHeader + a raw httpPayload blob, POST) and
//! `PutFunctionConcurrency` (httpLabel + a JSON document body, PUT) — each
//! serialize, on the wire, byte-identically to a request the hand-written
//! `aws.binding` + `aws.restjson` codec would produce.
//!
//! WHY THIS IS A HOST-ONLY RUST TEST (same rationale as tests/byte_diff.rs). The
//! end-to-end check runs the generated Zap client under the toolchain, but the
//! published compiler image lags the derive(Json) AWS hooks (zaplang-io/zap#346),
//! so that step is CI-only and best-effort. To fail CI on a generator regression
//! *now*, with no toolchain, this test reconstructs each on-the-wire request from:
//!
//!   * everything the generator OWNS — the HTTP method, the URI path template,
//!     the SigV4 service name, and (for a document body) the body JSON — parsed
//!     out of the freshly generated source, so drift in what the emitter writes
//!     changes the reconstructed request; the member->slot wiring is asserted
//!     against the generated method body too; and
//!   * the binding + SigV4 signature over those bytes, computed here by an
//!     independent signer mirroring aws.binding.binding_sign (a non-greedy label
//!     encodes "/", the canonical URI is a single quote_path pass over the
//!     already-encoded wire path, the wire target is that path verbatim).
//!
//! The result is compared byte-for-byte against the checked-in goldens
//! `tests/expected/lambda_*.http`, which `tools/verify_lambda_requests.py`
//! reproduces from scratch and which were cross-checked against real botocore
//! 1.38.27 (zaplang-io/aws #345). The pinned inputs here match that oracle.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

// AWS's published SigV4 example credentials + timestamp (same fixed inputs as
// the awsJson byte-diff and zaplang-io/aws tests/service_signing.main.zap).
const ACCESS: &str = "AKIDEXAMPLE";
const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const REGION: &str = "us-east-1";
const AMZ_DATE: &str = "20150830T123600Z";
const DATE_STAMP: &str = "20150830";
const HOST: &str = "lambda.us-east-1.amazonaws.com";
const SERVICE: &str = "lambda";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    let p = repo_root().join(path);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

fn generated() -> String {
    let model = read("models/lambda/2015-03-31/service-2.json");
    let (src, _cov) = aws_codegen::generate_from_json(&model).expect("Lambda model generates");
    src
}

// --- what the generator owns, parsed out of the generated source -------------

/// The SigV4 service the client threads into every call, read from
/// `def lambda__service() -> str: return "<svc>"`.
fn parse_service(src: &str) -> String {
    let anchor = "_service() -> str:";
    let a = src
        .find(anchor)
        .expect("generated source defines a *_service()");
    let rest = &src[a + anchor.len()..];
    let r = rest
        .find("return \"")
        .expect("service returns a string literal")
        + "return \"".len();
    let s = &rest[r..];
    s[..s.find('"').expect("closed")].to_string()
}

/// The HTTP method + URI path template of an operation, read from the single
/// `HttpBinding(method="..", path_template="..", ..)` constructor in its method.
fn parse_binding(src: &str, def_sig: &str) -> (String, String) {
    let m = src
        .find(def_sig)
        .unwrap_or_else(|| panic!("generated client defines `{def_sig}`"));
    let body = &src[m..];
    let hb = body
        .find("HttpBinding(")
        .expect("method builds an HttpBinding");
    let seg = &body[m_line_bounds(body, hb)..];
    (field(seg, "method"), field(seg, "path_template"))
}

/// The value of `key="..."` in `s` (the first occurrence).
fn field(s: &str, key: &str) -> String {
    let needle = format!("{key}=\"");
    let i = s
        .find(&needle)
        .unwrap_or_else(|| panic!("HttpBinding has {key}=\"...\""))
        + needle.len();
    let rest = &s[i..];
    rest[..rest.find('"').expect("closed string")].to_string()
}

/// The slice of `body` from the line containing byte offset `at` to its end —
/// just enough to read the whole `HttpBinding(...)` call on one line.
fn m_line_bounds(body: &str, at: usize) -> usize {
    body[..at].rfind('\n').map(|n| n + 1).unwrap_or(0)
}

/// The body of a method, from its `def` to the next top-level `def ` or struct
/// boundary — used for substring wiring assertions.
fn method_body<'a>(src: &'a str, def_sig: &'a str) -> &'a str {
    let m = src
        .find(def_sig)
        .unwrap_or_else(|| panic!("generated client defines `{def_sig}`"));
    let rest = &src[m..];
    let end = rest[1..]
        .find("\n    def ")
        .map(|e| e + 1)
        .unwrap_or(rest.len());
    &rest[..end]
}

/// The compact JSON body `PutFunctionConcurrencyDocument(...).to_json()` would
/// produce, built from the generated doc struct so a change to its fields
/// changes the body. v0 pins it to a single required `int64` member.
fn concurrency_body(src: &str, value: i64) -> String {
    let anchor = "struct PutFunctionConcurrencyDocument:";
    let m = src.find(anchor).expect("doc struct is generated");
    assert!(
        src[..m].trim_end().ends_with("@derive(Json)"),
        "the document struct is @derive(Json)"
    );
    let after = &src[m + anchor.len()..];
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in after.lines().skip(1) {
        if !line.starts_with("    ") {
            break;
        }
        let decl = line.trim();
        if decl.starts_with('#') {
            continue;
        }
        let mut it = decl.split_whitespace();
        let ty = it.next().unwrap_or("").to_string();
        let name = it.next().unwrap_or("").to_string();
        fields.push((ty, name));
    }
    assert_eq!(
        fields,
        vec![(
            "int64".to_string(),
            "ReservedConcurrentExecutions".to_string()
        )],
        "v0 PutFunctionConcurrency document is a single required int64; update the \
         fixture if the generated shape changes"
    );
    format!("{{\"{}\":{}}}", fields[0].1, value)
}

// --- an independent binding + SigV4 signer, mirroring aws.binding ------------

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

/// RFC-3986 percent-encode (url.quote / url.quote_path). `keep_slash` keeps "/".
fn quote(s: &str, keep_slash: bool) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// SigV4 CanonicalQueryString: each key/value encoded, pairs sorted by encoded
/// key then value, joined with "&" (url.canonical_query).
fn canonical_query(params: &[(&str, String)]) -> String {
    let mut enc: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (quote(k, false), quote(v, false)))
        .collect();
    enc.sort();
    enc.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Expand a URI path template, percent-encoding each label value (non-greedy
/// encodes "/", greedy keeps it) — aws.binding.expand_path.
fn expand_path(template: &str, labels: &[(&str, String, bool)]) -> String {
    let mut out = String::new();
    let bytes: Vec<char> = template.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '{' {
            let close = template[i..].find('}').map(|c| i + c);
            match close {
                None => {
                    out.push_str(&template[i..]);
                    break;
                }
                Some(c) => {
                    let mut token = &template[i + 1..c];
                    let greedy = token.ends_with('+');
                    if greedy {
                        token = &token[..token.len() - 1];
                    }
                    let val = labels
                        .iter()
                        .find(|(name, _, _)| *name == token)
                        .map(|(_, v, _)| v.clone())
                        .unwrap_or_default();
                    out.push_str(&quote(&val, greedy));
                    i = c + 1;
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// Sign a binding request whose path is already wire-encoded and return the full
/// HTTP/1.1 text — aws.binding.binding_sign (non-S3).
#[allow(clippy::too_many_arguments)]
fn binding_sign(
    method: &str,
    path_template: &str,
    labels: &[(&str, String, bool)],
    query: &[(&str, String)],
    member_headers: &[(&str, String)],
    body: &str,
    content_type: &str,
) -> String {
    let wire_path = expand_path(path_template, labels);

    // binding_headers: transport headers + member headers (+ content-type).
    let mut signed: Vec<(String, String)> = vec![
        ("host".to_string(), HOST.to_string()),
        ("x-amz-date".to_string(), AMZ_DATE.to_string()),
        ("x-amz-content-sha256".to_string(), hex_sha256(body)),
    ];
    for (n, v) in member_headers {
        signed.push((n.to_lowercase(), v.clone()));
    }
    if !content_type.is_empty() {
        signed.push(("content-type".to_string(), content_type.to_string()));
    }
    signed.sort_by(|a, b| a.0.cmp(&b.0));

    let canon_uri = quote(&wire_path, true); // one more quote_path pass (non-S3)
    let canon_q = canonical_query(query);
    let canon_headers: String = signed
        .iter()
        .map(|(n, v)| format!("{n}:{}\n", v.trim()))
        .collect();
    let signed_names: Vec<String> = signed.iter().map(|(n, _)| n.clone()).collect();
    let signed_names = signed_names.join(";");

    let canon_req = format!(
        "{method}\n{canon_uri}\n{canon_q}\n{canon_headers}\n{signed_names}\n{}",
        hex_sha256(body)
    );
    let scope = format!("{DATE_STAMP}/{REGION}/{SERVICE}/aws4_request");
    let sts = format!(
        "AWS4-HMAC-SHA256\n{AMZ_DATE}\n{scope}\n{}",
        hex_sha256(&canon_req)
    );
    let key = {
        let k = hmac_raw(format!("AWS4{SECRET}").as_bytes(), DATE_STAMP);
        let k = hmac_raw(&k, REGION);
        let k = hmac_raw(&k, SERVICE);
        hmac_raw(&k, "aws4_request")
    };
    let signature = hex(&hmac_raw(&key, &sts));
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, \
         SignedHeaders={signed_names}, Signature={signature}"
    );

    let mut headers_block = String::new();
    for (n, v) in &signed {
        headers_block.push_str(&format!("{n}: {v}\r\n"));
    }
    headers_block.push_str(&format!("content-length: {}\r\n", body.len()));
    headers_block.push_str(&format!("authorization: {auth}\r\n"));

    let mut target = wire_path;
    if !canon_q.is_empty() {
        target.push('?');
        target.push_str(&canon_q);
    }
    format!("{method} {target} HTTP/1.1\r\n{headers_block}Connection: close\r\n\r\n{body}")
}

// --- the four fixtures -------------------------------------------------------

#[test]
fn generated_get_function_request_matches_golden() {
    let src = generated();
    assert_eq!(parse_service(&src), SERVICE, "SigV4 service drifted");
    let sig = "def get_function(self, GetFunctionRequest input) -> str:";
    let (method, path) = parse_binding(&src, sig);
    assert_eq!(method, "GET");
    assert_eq!(path, "/2015-03-31/functions/{FunctionName}");

    let mb = method_body(&src, sig);
    assert!(
        mb.contains("labels[\"FunctionName\"] = input.FunctionName"),
        "FunctionName must bind to the {{FunctionName}} path label"
    );
    assert!(
        mb.contains("query[\"Qualifier\"] = input.Qualifier.unwrap_or(\"\")"),
        "Qualifier must bind to the query string"
    );
    assert!(
        mb.contains("restjson.rest_json_request(self.creds, b,"),
        "GET sends no body (binding b, not a payload/document variant)"
    );

    let got = binding_sign(
        &method,
        &path,
        &[("FunctionName", "my-func".to_string(), false)],
        &[("Qualifier", "5".to_string())],
        &[],
        "",
        "",
    );
    assert_eq!(got, read("tests/expected/lambda_get_function.http"));
}

#[test]
fn generated_list_functions_request_matches_golden() {
    let src = generated();
    let sig = "def list_functions(self, ListFunctionsRequest input) -> str:";
    let (method, path) = parse_binding(&src, sig);
    assert_eq!(method, "GET");
    assert_eq!(path, "/2015-03-31/functions");

    let mb = method_body(&src, sig);
    assert!(mb.contains("query[\"Marker\"] = input.Marker.unwrap_or(\"\")"));
    assert!(
        mb.contains("query[\"MaxItems\"] = str(input.MaxItems.unwrap_or(0))"),
        "an int query member must be str()-coerced"
    );
    assert!(mb.contains("query[\"FunctionVersion\"] = input.FunctionVersion.unwrap_or(\"\")"));

    // Only the parameters the caller set are sent (absent optionals send nothing).
    let got = binding_sign(
        &method,
        &path,
        &[],
        &[
            ("FunctionVersion", "ALL".to_string()),
            ("Marker", "bWFyaw==".to_string()),
            ("MaxItems", "50".to_string()),
        ],
        &[],
        "",
        "",
    );
    assert_eq!(got, read("tests/expected/lambda_list_functions.http"));
}

#[test]
fn generated_put_function_concurrency_request_matches_golden() {
    let src = generated();
    let sig = "def put_function_concurrency(self, PutFunctionConcurrencyRequest input) -> str:";
    let (method, path) = parse_binding(&src, sig);
    assert_eq!(method, "PUT");
    assert_eq!(path, "/2017-10-31/functions/{FunctionName}/concurrency");

    let mb = method_body(&src, sig);
    assert!(mb.contains("labels[\"FunctionName\"] = input.FunctionName"));
    assert!(
        mb.contains(
            "auto doc = PutFunctionConcurrencyDocument(ReservedConcurrentExecutions=input.ReservedConcurrentExecutions)"
        ),
        "the document body is built from the document members"
    );
    assert!(mb.contains("restjson.rest_json_document(b, doc.to_json())"));

    let body = concurrency_body(&src, 100);
    let got = binding_sign(
        &method,
        &path,
        &[("FunctionName", "my-func".to_string(), false)],
        &[],
        &[],
        &body,
        "application/json",
    );
    assert_eq!(
        got,
        read("tests/expected/lambda_put_function_concurrency.http")
    );
}

#[test]
fn generated_invoke_request_matches_golden() {
    let src = generated();
    let sig = "def invoke(self, InvocationRequest input) -> str:";
    let (method, path) = parse_binding(&src, sig);
    assert_eq!(method, "POST");
    assert_eq!(path, "/2015-03-31/functions/{FunctionName}/invocations");

    let mb = method_body(&src, sig);
    assert!(mb.contains("labels[\"FunctionName\"] = input.FunctionName"));
    assert!(mb.contains("query[\"Qualifier\"] = input.Qualifier.unwrap_or(\"\")"));
    assert!(
        mb.contains("headers[\"X-Amz-Invocation-Type\"] = input.InvocationType.unwrap_or(\"\")"),
        "the enum header member binds as its plain wire string"
    );
    assert!(
        mb.contains(
            "restjson.rest_json_raw_payload(b, str(input.Payload.unwrap_or(bytes())), \"application/octet-stream\")"
        ),
        "the blob httpPayload is carried as the raw body"
    );

    // A partial ARN function name: the ':' separators percent-encode to %3A.
    let got = binding_sign(
        &method,
        &path,
        &[(
            "FunctionName",
            "123456789012:function:my-func".to_string(),
            false,
        )],
        &[("Qualifier", "PROD".to_string())],
        &[("X-Amz-Invocation-Type", "Event".to_string())],
        r#"{"k":"v"}"#,
        "application/octet-stream",
    );
    assert_eq!(got, read("tests/expected/lambda_invoke.http"));
}

// --- zaplang-io/zap#424: collection / nested JSON document bodies -------------

#[test]
fn generated_tag_resource_request_matches_golden() {
    // A document **map** body: `Tags: map<str,str>` serializes as a JSON object
    // with keys emitted sorted (deterministic; AWS maps are order-insensitive).
    let src = generated();
    let sig = "def tag_resource(self, TagResourceRequest input) -> str:";
    let (method, path) = parse_binding(&src, sig);
    assert_eq!(method, "POST");
    assert_eq!(path, "/2017-03-31/tags/{Resource}");

    let mb = method_body(&src, sig);
    assert!(mb.contains("labels[\"Resource\"] = input.Resource"));
    // The map is serialized inline: sorted keys, each `"k":"v"` via _json_str.
    assert!(mb.contains("for k0 in sorted(input.Tags.keys()):"));
    assert!(
        mb.contains("m0.append(lambda__json_str(k0) + \":\" + lambda__json_str(input.Tags[k0]))"),
        "map members serialize each entry with the escaping helper"
    );
    assert!(mb.contains("parts.append(\"\\\"Tags\\\":\" + lambda__json_obj(m0))"));
    assert!(mb.contains("restjson.rest_json_document(b, lambda__json_obj(parts))"));

    let body = r#"{"Tags":{"Dept":"Eng","Env":"Prod"}}"#;
    let got = binding_sign(
        &method,
        &path,
        &[(
            "Resource",
            "arn:aws:lambda:us-east-1:123456789012:function:my-func".to_string(),
            false,
        )],
        &[],
        &[],
        body,
        "application/json",
    );
    assert_eq!(got, read("tests/expected/lambda_tag_resource.http"));
}

#[test]
fn generated_create_function_request_matches_golden() {
    // A document body with a **nested struct** (Code, derivable -> `.to_json()`),
    // a nested struct carrying a **list** (VpcConfig, non-derivable -> explicit
    // `vpc_config_to_json`), and a base64 **blob** inside Code. Members emit in
    // model declaration order; absent optionals are omitted.
    let src = generated();
    let sig = "def create_function(self, CreateFunctionRequest input) -> str:";
    let (method, path) = parse_binding(&src, sig);
    assert_eq!(method, "POST");
    assert_eq!(path, "/2015-03-31/functions");

    let mb = method_body(&src, sig);
    assert!(mb.contains(
        "parts.append(\"\\\"FunctionName\\\":\" + lambda__json_str(input.FunctionName))"
    ));
    assert!(mb.contains("parts.append(\"\\\"Role\\\":\" + lambda__json_str(input.Role))"));
    // Code is a derivable nested struct -> its own derived encoder.
    assert!(mb.contains("parts.append(\"\\\"Code\\\":\" + input.Code.to_json())"));
    // VpcConfig is non-derivable (holds lists) -> an explicit serializer.
    assert!(mb.contains("parts.append(\"\\\"VpcConfig\\\":\" + vpc_config_to_json(u"));

    // The VpcConfig serializer: SubnetIds list -> JSON array of escaped strings.
    assert!(src.contains("def vpc_config_to_json(VpcConfig v) -> str:"));
    assert!(src.contains("auto u0 = v.SubnetIds.unwrap()"));
    assert!(src.contains("e1.append(lambda__json_str(x1))"));
    assert!(src.contains("parts.append(\"\\\"SubnetIds\\\":\" + lambda__json_arr(e1))"));

    let body = concat!(
        r#"{"FunctionName":"my-func","#,
        r#""Role":"arn:aws:iam::123456789012:role/svc","#,
        r#""Code":{"ZipFile":"emlwYnl0ZXM="},"#,
        r#""VpcConfig":{"SubnetIds":["subnet-1","subnet-2"]}}"#,
    );
    let got = binding_sign(&method, &path, &[], &[], &[], body, "application/json");
    assert_eq!(got, read("tests/expected/lambda_create_function.http"));
}
