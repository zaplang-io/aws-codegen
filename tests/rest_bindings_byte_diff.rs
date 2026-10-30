//! Byte-diff fidelity gate for the rest-json HTTP-binding types added in
//! zaplang-io/zap#425: a bool / timestamp / list[str] bound to a URI query or a
//! header. A synthetic rest-json service exercises, in one `GET`:
//!
//!   * a non-greedy `httpLabel` (`{Id}`, so "/" -> %2F),
//!   * a **bool** `httpQuery` (required) and an optional bool `httpQuery`,
//!   * a **timestamp** `httpQuery` (ISO-8601, the query default),
//!   * a **timestamp** `httpHeader` (RFC-822 / HTTP-date, the header default),
//!   * a **list[str]** `httpQuery` emitted as REPEATED params (`tag=a&tag=b`).
//!
//! Like `tests/rest_byte_diff.rs`, this reconstructs the on-the-wire request from
//! the generator-OWNED pieces (method / path / the member->slot wiring asserted
//! against the generated method body) plus an independent SigV4 + binding signer,
//! and compares byte-for-byte to the checked-in golden
//! `tests/expected/restjson_synth_bindings.http`, which
//! `tools/verify_lambda_requests.py` reproduces from scratch. The timestamp
//! *values* are the strings `datetime.strftime` produces (proven in
//! zaplang-io/zap#338); this test asserts the emitter calls strftime with the
//! right format and binds each member to the right slot.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

const ACCESS: &str = "AKIDEXAMPLE";
const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const REGION: &str = "us-east-1";
const AMZ_DATE: &str = "20150830T123600Z";
const DATE_STAMP: &str = "20150830";
const SERVICE: &str = "svc";
const HOST: &str = "svc.us-east-1.amazonaws.com";

// A synthetic rest-json model exercising every binding type #425 adds. Member
// order is declaration order, so the emitted query dict fills Enabled, Verbose,
// After; the multi_query holds Tags; the header holds Since.
const SYNTH: &str = r#"{
  "metadata":{"protocol":"rest-json","endpointPrefix":"svc","serviceId":"Synth","apiVersion":"2021-01-01"},
  "operations":{"DoThing":{"name":"DoThing","http":{"method":"GET","requestUri":"/t/{Id}"},
    "input":{"shape":"DoThingRequest"}}},
  "shapes":{
    "S":{"type":"string"},
    "B":{"type":"boolean"},
    "T":{"type":"timestamp"},
    "Tags":{"type":"list","member":{"shape":"S"}},
    "DoThingRequest":{"type":"structure","required":["Id","Enabled"],
      "members":{
        "Id":{"shape":"S","location":"uri","locationName":"Id"},
        "Enabled":{"shape":"B","location":"querystring","locationName":"enabled"},
        "Verbose":{"shape":"B","location":"querystring","locationName":"verbose"},
        "After":{"shape":"T","location":"querystring","locationName":"after"},
        "Since":{"shape":"T","location":"header","locationName":"x-since"},
        "Tags":{"shape":"Tags","location":"querystring","locationName":"tag"}}}}}"#;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    let p = repo_root().join(path);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

fn generated() -> String {
    let (src, _cov) = aws_codegen::generate_from_json(SYNTH).expect("synth model generates");
    src
}

/// The body of the generated `do_thing` method (up to the next `def`/comment).
fn method_body(src: &str) -> String {
    let sig = "def do_thing(self, DoThingRequest input) -> str:";
    let m = src.find(sig).expect("generated client defines do_thing");
    let after = &src[m + sig.len()..];
    let end = ["\n    def ", "\n    #", "\n# ", "\ndef "]
        .iter()
        .filter_map(|mk| after.find(mk))
        .min()
        .unwrap_or(after.len());
    after[..end].to_string()
}

// --- independent SigV4 + binding signer --------------------------------------

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

/// CanonicalQueryString over (key, value) pairs — repeated keys allowed (a list
/// bound to httpQuery) — sorted by encoded key then value, joined with "&".
fn canonical_query(params: &[(&str, &str)]) -> String {
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

fn expand_label(template: &str, name: &str, value: &str) -> String {
    template.replace(&format!("{{{name}}}"), &quote(value, false))
}

#[allow(clippy::too_many_arguments)]
fn binding_sign(
    method: &str,
    wire_path: &str,
    query: &[(&str, &str)],
    member_headers: &[(&str, &str)],
    body: &str,
) -> String {
    let mut signed: Vec<(String, String)> = vec![
        ("host".to_string(), HOST.to_string()),
        ("x-amz-date".to_string(), AMZ_DATE.to_string()),
        ("x-amz-content-sha256".to_string(), hex_sha256(body)),
    ];
    for (n, v) in member_headers {
        signed.push((n.to_lowercase(), v.to_string()));
    }
    signed.sort_by(|a, b| a.0.cmp(&b.0));

    let canon_uri = quote(wire_path, true);
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
    let mut target = wire_path.to_string();
    if !canon_q.is_empty() {
        target.push('?');
        target.push_str(&canon_q);
    }
    format!("{method} {target} HTTP/1.1\r\n{headers_block}Connection: close\r\n\r\n{body}")
}

#[test]
fn generated_binding_types_wire_correctly() {
    let src = generated();
    let mb = method_body(&src);

    // Required bool -> the per-file helper, unconditional.
    assert!(src.contains("def svc_bind_bool(bool b) -> str:"), "{src}");
    assert!(
        mb.contains("query[\"enabled\"] = svc_bind_bool(input.Enabled)"),
        "{mb}"
    );
    // Optional bool -> guarded, unwrapped with a False default.
    assert!(
        mb.contains("if input.Verbose.is_some():")
            && mb.contains("svc_bind_bool(input.Verbose.unwrap_or(False))"),
        "{mb}"
    );
    // Timestamp query -> ISO-8601 (the query default), guarded.
    assert!(
        mb.contains("datetime.strftime(input.After.unwrap(), \"%Y-%m-%dT%H:%M:%SZ\")"),
        "{mb}"
    );
    // Timestamp header -> RFC-822 / HTTP-date (the header default), guarded.
    assert!(
        mb.contains("datetime.strftime(input.Since.unwrap(), \"%a, %d %b %Y %H:%M:%S GMT\")"),
        "{mb}"
    );
    // list[str] query -> repeated params via multi_query.
    assert!(
        mb.contains("dict[str, list[str]] multi_query = {}")
            && mb.contains("multi_query[\"tag\"] = input.Tags.unwrap()"),
        "{mb}"
    );
    // The binding threads multi_query through to the codec.
    assert!(mb.contains("multi_query=multi_query"), "{mb}");
    // datetime is imported for the timestamp binds.
    assert!(src.contains("\nimport datetime\n"), "{src}");

    // Reconstruct the on-the-wire request for a chosen input and diff the golden.
    let wire_path = expand_label("/t/{Id}", "Id", "a/b");
    let query = [
        ("enabled", "true"),
        ("verbose", "true"),
        ("after", "2015-08-30T12:36:00Z"),
        ("tag", "b"),
        ("tag", "a"),
    ];
    let headers = [("x-since", "Sun, 30 Aug 2015 12:36:00 GMT")];
    let got = binding_sign("GET", &wire_path, &query, &headers, "");
    assert_eq!(got, read("tests/expected/restjson_synth_bindings.http"));
}
