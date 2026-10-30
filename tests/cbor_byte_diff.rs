//! Byte-diff fidelity gate for the generated smithy-rpc-v2-cbor clients
//! (zaplang-io/zap#428 part 2).
//!
//! Proves the cbor emitter is faithful to botocore's `RpcV2CBORSerializer`:
//! CloudWatch `PutMetricData` and Translate `TranslateText`, serialized on the
//! wire by the GENERATED client, are byte-identical to botocore's output.
//!
//! Like the other byte-diff gates this is a HOST-ONLY Rust test that needs no
//! Zap toolchain. It reconstructs the request from two sources:
//!
//!   * everything the generator OWNS for the pinned operations — the SigV4
//!     service, the rpc-v2 service shape (URI `targetPrefix`), the operation
//!     name, and the per-member CBOR encoding of the body serializer (member
//!     order + the `cbor_text`/`cbor_double`/`cbor_int`/`cbor_list` choice) — is
//!     asserted against the freshly generated client source, so any drift in
//!     what the generator emits fails the test; and
//!   * the CBOR body bytes + the SigV4 signature over them, computed here by an
//!     independent encoder/signer (a third implementation besides aws_core.cbor
//!     and tools/verify_cbor_requests.py), with AWS's published example
//!     credentials + timestamp.
//!
//! The CBOR body is cross-checked against the botocore-verified vectors pinned in
//! zaplang-io/aws `tests/expected/cbor_codec.expected` (aws #428 part 1, driven
//! through botocore itself), and the full signed CloudWatch request against the
//! checked-in golden `tests/expected/cbor_cloudwatch_put_metric_data.http`, which
//! `tools/verify_cbor_requests.py` reproduces from scratch.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

const ACCESS: &str = "AKIDEXAMPLE";
const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const REGION: &str = "us-east-1";
const AMZ_DATE: &str = "20150830T123600Z";
const DATE_STAMP: &str = "20150830";

// The botocore-verified CBOR bodies (hex) for the two pinned operations, copied
// from zaplang-io/aws tests/expected/cbor_codec.expected (driven through
// botocore's RpcV2CBORSerializer). The generated client, driven with the same
// inputs, must reproduce these exactly.
const CLOUDWATCH_BODY_HEX: &str = "a2694e616d6573706163656a4d794170702f50726f646a4d65747269634461746182a46a4d65747269634e616d65674c6174656e63796556616c7565fb405900000000000064556e69746c4d696c6c697365636f6e64737153746f726167655265736f6c7574696f6e01a36a4d65747269634e616d65664572726f72736556616c7565fb3fe000000000000064556e697465436f756e74";
const TRANSLATE_BODY_HEX: &str = "a364546578746c48656c6c6f2c20776f726c6472536f757263654c616e6775616765436f646562656e725461726765744c616e6775616765436f6465626573";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

// --- an independent canonical CBOR encoder (mirrors aws_core.cbor) -----------

enum Cbor {
    Int(i64),
    Text(String),
    Double(f64),
    List(Vec<Cbor>),
    /// A structure/map: text keys in order (botocore does not sort struct keys).
    Map(Vec<(String, Cbor)>),
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let base = major << 5;
    if n < 24 {
        out.push(base + n as u8);
    } else if n < 256 {
        out.push(base + 24);
        out.push(n as u8);
    } else if n < 65536 {
        out.push(base + 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n < 4294967296 {
        out.push(base + 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(base + 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn encode_into(out: &mut Vec<u8>, v: &Cbor) {
    match v {
        Cbor::Int(n) => {
            if *n >= 0 {
                head(out, 0, *n as u64);
            } else {
                head(out, 1, (-1 - *n) as u64);
            }
        }
        Cbor::Text(s) => {
            let b = s.as_bytes();
            head(out, 3, b.len() as u64);
            out.extend_from_slice(b);
        }
        Cbor::Double(f) => {
            out.push((7 << 5) + 27);
            out.extend_from_slice(&f.to_be_bytes());
        }
        Cbor::List(items) => {
            head(out, 4, items.len() as u64);
            for it in items {
                encode_into(out, it);
            }
        }
        Cbor::Map(entries) => {
            head(out, 5, entries.len() as u64);
            for (k, val) in entries {
                let kb = k.as_bytes();
                head(out, 3, kb.len() as u64);
                out.extend_from_slice(kb);
                encode_into(out, val);
            }
        }
    }
}

fn cbor_encode(v: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(&mut out, v);
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// --- independent SigV4 over a bytes body (mirrors aws_core.cbor.cbor_sign) ----

fn hmac_raw(key: &[u8], msg: &str) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac key of any length");
    m.update(msg.as_bytes());
    m.finalize().into_bytes().to_vec()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

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

/// Build the full HTTP/1.1 request bytes exactly as aws_core.cbor.cbor_sign:
/// the rpc-v2 header set, SigV4 over the CBOR body, then the binary body.
fn sign_cbor_request(service: &str, host: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let body_sha = sha256_hex(body);
    let mut headers: Vec<(String, String)> = vec![
        ("accept".into(), "application/cbor".into()),
        ("host".into(), host.into()),
        ("smithy-protocol".into(), "rpc-v2-cbor".into()),
        ("x-amz-content-sha256".into(), body_sha.clone()),
        ("x-amz-date".into(), AMZ_DATE.into()),
    ];
    if !body.is_empty() {
        headers.push(("content-type".into(), "application/cbor".into()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let canon_headers: String = headers
        .iter()
        .map(|(n, v)| format!("{n}:{}\n", v.trim()))
        .collect();
    let signed_headers = headers
        .iter()
        .map(|(n, _)| n.clone())
        .collect::<Vec<_>>()
        .join(";");

    let canon_uri = canonical_uri(path, service);
    let canon_req = format!("POST\n{canon_uri}\n\n{canon_headers}\n{signed_headers}\n{body_sha}");
    let scope = format!("{DATE_STAMP}/{REGION}/{service}/aws4_request");
    let sts = format!(
        "AWS4-HMAC-SHA256\n{AMZ_DATE}\n{scope}\n{}",
        sha256_hex(canon_req.as_bytes())
    );
    let signature = hex(&hmac_raw(
        &signing_key(SECRET, DATE_STAMP, REGION, service),
        &sts,
    ));
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut block = String::new();
    for (n, v) in &headers {
        block.push_str(&format!("{n}: {v}\r\n"));
    }
    block.push_str(&format!("content-length: {}\r\n", body.len()));
    block.push_str(&format!("authorization: {auth}\r\n"));
    let head = format!(
        "POST {} HTTP/1.1\r\n{block}Connection: close\r\n\r\n",
        quote_path(path)
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

// --- the pinned operation bodies, built independently ------------------------

fn cloudwatch_put_metric_data_body() -> Vec<u8> {
    let datum1 = Cbor::Map(vec![
        ("MetricName".into(), Cbor::Text("Latency".into())),
        ("Value".into(), Cbor::Double(100.0)),
        ("Unit".into(), Cbor::Text("Milliseconds".into())),
        ("StorageResolution".into(), Cbor::Int(1)),
    ]);
    let datum2 = Cbor::Map(vec![
        ("MetricName".into(), Cbor::Text("Errors".into())),
        ("Value".into(), Cbor::Double(0.5)),
        ("Unit".into(), Cbor::Text("Count".into())),
    ]);
    let body = Cbor::Map(vec![
        ("Namespace".into(), Cbor::Text("MyApp/Prod".into())),
        ("MetricData".into(), Cbor::List(vec![datum1, datum2])),
    ]);
    cbor_encode(&body)
}

fn translate_translate_text_body() -> Vec<u8> {
    let body = Cbor::Map(vec![
        ("Text".into(), Cbor::Text("Hello, world".into())),
        ("SourceLanguageCode".into(), Cbor::Text("en".into())),
        ("TargetLanguageCode".into(), Cbor::Text("es".into())),
    ]);
    cbor_encode(&body)
}

fn read(path: &str) -> String {
    let p = repo_root().join(path);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

/// The substring of `src` from the first `anchor` to the next blank line — a
/// single generated `def` block, for member-level drift assertions.
fn block<'a>(src: &'a str, anchor: &str) -> &'a str {
    let start = src
        .find(anchor)
        .unwrap_or_else(|| panic!("generated source contains `{anchor}`"));
    let rest = &src[start..];
    let end = rest.find("\n\n").unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn generated_cloudwatch_put_metric_data_matches_botocore() {
    // Regenerate from the pinned model so generator drift fails the test.
    let model = read("models/cloudwatch/2010-08-01/service-2.json");
    let (src, _cov) = aws_codegen::generate_from_json(&model).expect("CloudWatch model generates");

    // 1. The pieces the generator owns, asserted against the source.
    assert!(
        src.contains("def monitoring_service() -> str:") && src.contains("return \"monitoring\""),
        "SigV4 service name drifted (expected `monitoring`)"
    );
    let method = block(
        &src,
        "def put_metric_data(self, PutMetricDataInput input) -> bytes:",
    );
    assert!(
        method.contains("auto body = cbor.cbor_encode(put_metric_data_input_to_cbor(input))"),
        "put_metric_data body construction drifted:\n{method}"
    );
    assert!(
        method.contains(
            "cbor.cbor_build_request(monitoring_service(), self.region, host, \"GraniteServiceVersion20100801\", \"PutMetricData\", body, t.amz_date)"
        ),
        "rpc-v2 framing (service shape / op) drifted:\n{method}"
    );
    assert!(
        method.contains("return cbor.cbor_sign(self.creds, req, body, t.amz_date, t.date_stamp)"),
        "signing call drifted:\n{method}"
    );

    // The top serializer: Namespace (text) then MetricData (list of MetricDatum).
    let top = block(
        &src,
        "def put_metric_data_input_to_cbor(PutMetricDataInput v) -> cbor.CborValue:",
    );
    let ns = top
        .find("keys.append(\"Namespace\")")
        .expect("Namespace member");
    let md = top
        .find("keys.append(\"MetricData\")")
        .expect("MetricData member");
    assert!(ns < md, "Namespace must precede MetricData (model order)");
    assert!(
        top.contains("vals.append(cbor.cbor_text(v.Namespace))"),
        "Namespace must encode as cbor_text:\n{top}"
    );
    assert!(
        top.contains("e1.append(metric_datum_to_cbor(x1))"),
        "MetricData must be a list of MetricDatum serialized recursively:\n{top}"
    );

    // MetricDatum: Value is a `double` (cbor_double, ai 27) and StorageResolution
    // an integer (cbor_int) — the fidelity-critical choices.
    let datum = block(
        &src,
        "def metric_datum_to_cbor(MetricDatum v) -> cbor.CborValue:",
    );
    assert!(
        datum.contains("vals.append(cbor.cbor_double(u")
            && datum.contains("keys.append(\"Value\")"),
        "MetricDatum.Value must encode as cbor_double:\n{datum}"
    );
    assert!(
        datum.contains("vals.append(cbor.cbor_int(u")
            && datum.contains("keys.append(\"StorageResolution\")"),
        "MetricDatum.StorageResolution must encode as cbor_int:\n{datum}"
    );
    assert!(
        datum.contains("cbor.cbor_timestamp(datetime.to_timestamp(u"),
        "MetricDatum.Timestamp must encode as a tag-1 epoch timestamp:\n{datum}"
    );

    // 2. The body bytes must equal botocore's output (aws #428 vector).
    let body = cloudwatch_put_metric_data_body();
    assert_eq!(
        hex(&body),
        CLOUDWATCH_BODY_HEX,
        "reconstructed CloudWatch PutMetricData CBOR body is not botocore-identical"
    );

    // 3. The full signed request must match the golden (reproduced by
    //    tools/verify_cbor_requests.py).
    let request = sign_cbor_request(
        "monitoring",
        "monitoring.us-east-1.amazonaws.com",
        "/service/GraniteServiceVersion20100801/operation/PutMetricData",
        &body,
    );
    let golden =
        std::fs::read(repo_root().join("tests/expected/cbor_cloudwatch_put_metric_data.http"))
            .expect("golden exists");
    assert!(
        request == golden,
        "generated CloudWatch PutMetricData request is NOT byte-identical to the golden \
         (tests/expected/cbor_cloudwatch_put_metric_data.http). If intended, re-pin with \
         `python3 tools/verify_cbor_requests.py --emit`."
    );
}

#[test]
fn generated_translate_text_body_matches_botocore() {
    let model = read("models/translate/2017-07-01/service-2.json");
    let (src, _cov) = aws_codegen::generate_from_json(&model).expect("Translate model generates");

    assert!(src.contains("def translate_text(self, TranslateTextRequest input) -> bytes:"));
    let top = block(
        &src,
        "def translate_text_request_to_cbor(TranslateTextRequest v) -> cbor.CborValue:",
    );
    // Text, SourceLanguageCode, TargetLanguageCode in model order, all text.
    let t = top.find("keys.append(\"Text\")").expect("Text member");
    let s = top
        .find("keys.append(\"SourceLanguageCode\")")
        .expect("SourceLanguageCode member");
    let g = top
        .find("keys.append(\"TargetLanguageCode\")")
        .expect("TargetLanguageCode member");
    assert!(t < s && s < g, "Translate member order drifted");

    let body = translate_translate_text_body();
    assert_eq!(
        hex(&body),
        TRANSLATE_BODY_HEX,
        "reconstructed Translate TranslateText CBOR body is not botocore-identical"
    );
}
