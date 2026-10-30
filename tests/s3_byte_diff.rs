//! Byte-diff fidelity gate for the generated rest-xml S3 client (#356).
//!
//! S3 is the second generated-is-product service (after STS #355) and the first
//! to exercise the S3 variant of the binding signer: S3 disables path
//! normalization, so the SigV4 canonical URI is the already-wire-encoded path
//! VERBATIM (no second `quote_path` pass the other services get), and object keys
//! bind to a greedy `{Key+}` label that keeps "/". The host is the path-style
//! regional endpoint `s3.<region>.amazonaws.com` (the generated client calls
//! `endpoints.regional_host("s3", region)`), not a virtual-hosted bucket host.
//!
//! Same toolchain-free design as the sibling gates (tests/rest_byte_diff.rs,
//! tests/xml_byte_diff.rs): the generator-OWNED pieces — the HTTP method, the URI
//! path template, the SigV4 service name, and the member->slot wiring — are
//! asserted out of the freshly generated source, and the binding + SigV4
//! signature over fixed inputs is computed by an independent signer here. The
//! result is compared byte-for-byte to the checked-in goldens
//! `tests/expected/s3_*.http`, which `tools/verify_xml_requests.py` reproduces
//! from scratch. The pinned inputs here match that oracle.
//!
//! Four operations the v0 rest-xml emitter emits *correctly* end to end — a
//! bucket op (`HeadBucket`), a service listing (`ListBuckets`), an object GET
//! (`ListParts`) and an object PUT with a raw body (`UploadPart`) — stand in for
//! the ticket's named ops (GetObject / PutObject / ListObjectsV2 / CreateBucket),
//! which the v0 emitter skips (DateTime / bool header + query bindings, optional
//! httpPayload structs; see the generated file's skip block). The greedy `{Key+}`
//! object key carries a space and "/"s, the S3-key case the hand-written aws.s3
//! reference calls out (zaplang-io/zap#335).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

// AWS's published SigV4 example credentials + timestamp (same fixed inputs as the
// other byte-diff gates and zaplang-io/aws tests/service_signing.main.zap).
const ACCESS: &str = "AKIDEXAMPLE";
const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const REGION: &str = "us-east-1";
const AMZ_DATE: &str = "20150830T123600Z";
const DATE_STAMP: &str = "20150830";
const HOST: &str = "s3.us-east-1.amazonaws.com";
const SERVICE: &str = "s3";

// The pinned inputs, matching tools/verify_xml_requests.py.
const BUCKET: &str = "my-bucket";
const KEY: &str = "photos/2024/my object.jpg";
const UPLOAD_ID: &str = "abc123XYZ";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    let p = repo_root().join(path);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

fn generated() -> String {
    let model = read("models/s3/2006-03-01/service-2.json");
    let (src, _cov) = aws_codegen::generate_from_json(&model).expect("S3 model generates");
    src
}

// --- what the generator owns, parsed out of the generated source -------------

/// The SigV4 service the client threads into every call, read from
/// `def s3_service() -> str: return "<svc>"`.
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
    let line_start = body[..hb].rfind('\n').map(|n| n + 1).unwrap_or(0);
    let seg = &body[line_start..];
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

/// The body of a method, from its `def` to the next top-level `def ` boundary —
/// used for substring wiring assertions.
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

// --- an independent binding + SigV4 signer, mirroring aws.binding (S3) --------

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

/// Expand a URI path template — a non-greedy `{Name}` label encodes "/", a greedy
/// `{Name+}` label keeps it (aws.binding.expand_path). Labels carry a `greedy`
/// flag.
fn expand_path(template: &str, labels: &[(&str, String, bool)]) -> String {
    let mut out = String::new();
    let chars: Vec<char> = template.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '{' {
            match template[i..].find('}').map(|c| i + c) {
                None => {
                    out.push_str(&template[i..]);
                    break;
                }
                Some(c) => {
                    let mut token = &template[i + 1..c];
                    if token.ends_with('+') {
                        token = &token[..token.len() - 1];
                    }
                    let (val, greedy) = labels
                        .iter()
                        .find(|(name, _, _)| *name == token)
                        .map(|(_, v, g)| (v.clone(), *g))
                        .unwrap_or_default();
                    out.push_str(&quote(&val, greedy));
                    i = c + 1;
                }
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Sign a binding request for the S3 service and return the full HTTP/1.1 text —
/// aws.binding.binding_sign with `canonical_uri_encoded` for service "s3": the
/// canonical URI is the wire path VERBATIM (no second quote_path pass).
#[allow(clippy::too_many_arguments)]
fn s3_binding_sign(
    method: &str,
    path_template: &str,
    labels: &[(&str, String, bool)],
    query: &[(&str, String)],
    member_headers: &[(&str, String)],
    body: &str,
    content_type: &str,
) -> String {
    let wire_path = expand_path(path_template, labels);

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

    let canon_uri = wire_path.clone(); // S3: verbatim, no extra quote_path pass.
    let canon_q = canonical_query(query);
    let canon_headers: String = signed
        .iter()
        .map(|(n, v)| format!("{n}:{}\n", v.trim()))
        .collect();
    let signed_names = signed
        .iter()
        .map(|(n, _)| n.clone())
        .collect::<Vec<_>>()
        .join(";");

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
fn generated_s3_head_bucket_matches_golden() {
    let src = generated();
    assert_eq!(parse_service(&src), SERVICE, "SigV4 service drifted");
    let sig = "def head_bucket(self, HeadBucketRequest input) -> str:";
    let (method, path) = parse_binding(&src, sig);
    assert_eq!(method, "HEAD");
    assert_eq!(path, "/{Bucket}");
    let mb = method_body(&src, sig);
    assert!(
        mb.contains("labels[\"Bucket\"] = input.Bucket"),
        "Bucket must bind to the {{Bucket}} path label"
    );

    let got = s3_binding_sign(
        "HEAD",
        "/{Bucket}",
        &[("Bucket", BUCKET.to_string(), false)],
        &[],
        &[],
        "",
        "",
    );
    assert_eq!(got, read("tests/expected/s3_head_bucket.http"));
}

#[test]
fn generated_s3_list_buckets_matches_golden() {
    let src = generated();
    let sig = "def list_buckets(self, ListBucketsRequest input) -> str:";
    let (method, path) = parse_binding(&src, sig);
    assert_eq!(method, "GET");
    assert_eq!(path, "/");
    let mb = method_body(&src, sig);
    assert!(mb.contains("query[\"max-buckets\"] = str(input.MaxBuckets.unwrap_or(0))"));
    assert!(mb.contains("query[\"prefix\"] = input.Prefix.unwrap_or(\"\")"));

    let got = s3_binding_sign(
        "GET",
        "/",
        &[],
        &[
            ("max-buckets", "100".to_string()),
            ("prefix", "team-".to_string()),
        ],
        &[],
        "",
        "",
    );
    assert_eq!(got, read("tests/expected/s3_list_buckets.http"));
}

#[test]
fn generated_s3_list_parts_matches_golden() {
    let src = generated();
    let sig = "def list_parts(self, ListPartsRequest input) -> str:";
    let (method, path) = parse_binding(&src, sig);
    assert_eq!(method, "GET");
    assert_eq!(path, "/{Bucket}/{Key+}");
    let mb = method_body(&src, sig);
    assert!(mb.contains("labels[\"Bucket\"] = input.Bucket"));
    assert!(
        mb.contains("greedy_labels[\"Key\"] = input.Key"),
        "Key must bind to the greedy {{Key+}} label"
    );
    assert!(mb.contains("query[\"uploadId\"] = input.UploadId"));
    assert!(mb.contains("query[\"max-parts\"] = str(input.MaxParts.unwrap_or(0))"));

    let got = s3_binding_sign(
        "GET",
        "/{Bucket}/{Key+}",
        &[
            ("Bucket", BUCKET.to_string(), false),
            ("Key", KEY.to_string(), true),
        ],
        &[
            ("max-parts", "50".to_string()),
            ("uploadId", UPLOAD_ID.to_string()),
        ],
        &[],
        "",
        "",
    );
    assert_eq!(got, read("tests/expected/s3_list_parts.http"));
}

#[test]
fn generated_s3_upload_part_matches_golden() {
    let src = generated();
    let sig = "def upload_part(self, UploadPartRequest input) -> str:";
    let (method, path) = parse_binding(&src, sig);
    assert_eq!(method, "PUT");
    assert_eq!(path, "/{Bucket}/{Key+}");
    let mb = method_body(&src, sig);
    assert!(mb.contains("greedy_labels[\"Key\"] = input.Key"));
    assert!(mb.contains("query[\"partNumber\"] = str(input.PartNumber)"));
    assert!(mb.contains("query[\"uploadId\"] = input.UploadId"));
    // The body is the raw httpPayload blob carried as application/octet-stream.
    assert!(mb.contains(
        "restxml.rest_xml_raw_payload(b, str(input.Body.unwrap_or(bytes())), \"application/octet-stream\")"
    ));

    let got = s3_binding_sign(
        "PUT",
        "/{Bucket}/{Key+}",
        &[
            ("Bucket", BUCKET.to_string(), false),
            ("Key", KEY.to_string(), true),
        ],
        &[
            ("partNumber", "1".to_string()),
            ("uploadId", UPLOAD_ID.to_string()),
        ],
        &[],
        "hello part contents",
        "application/octet-stream",
    );
    assert_eq!(got, read("tests/expected/s3_upload_part.http"));
}
