//! Byte-diff fidelity gate for the generated query + ec2 clients (#354).
//!
//! Proves the query/ec2 emitter is faithful: a SimpleDB `GetAttributes`
//! (awsQuery — scalars + a flattened list + a boolean) and an EC2
//! `MonitorInstances` (the ec2 variant — Capitalized keys + an always-flattened
//! list), serialized on the wire by the GENERATED client, are byte-identical to
//! the requests the hand-written `aws.query` codec (zaplang-io/aws#353) produces.
//!
//! Same toolchain-free design as the awsJson/rest-json gates (tests/byte_diff.rs,
//! tests/rest_byte_diff.rs): the generator-OWNED pieces — the `Action`, the
//! `Version`, and each member's form key, order and list flattening — are parsed
//! / asserted out of the freshly generated source, and the SigV4 signature over
//! the reconstructed form body is computed by the independent signer in
//! `tests/common`. The result is compared to the checked-in goldens, which
//! `tools/verify_xml_requests.py` reproduces from scratch.

mod common;

use common::{hex_sha256, read, sign_request, uri_quote, REGION};

fn generate(model_rel: &str) -> String {
    let model = read(model_rel);
    aws_codegen::generate_from_json(&model)
        .unwrap_or_else(|e| panic!("{model_rel} generates: {e}"))
        .0
}

/// The body of a generated method, from its `def` line to the next method/EOF —
/// enough for substring wiring assertions.
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

/// The form body the query codec builds: `Action`, `Version`, then the members
/// in order, each key and value url.quote'd and joined by '&'.
fn form_body(action: &str, version: &str, members: &[(&str, &str)]) -> String {
    let mut pairs = vec![("Action", action), ("Version", version)];
    pairs.extend_from_slice(members);
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", uri_quote(k, false), uri_quote(v, false)))
        .collect::<Vec<_>>()
        .join("&")
}

fn query_headers(service: &str, body: &str) -> Vec<(&'static str, String)> {
    let host = format!("{service}.{REGION}.amazonaws.com");
    vec![
        (
            "content-type",
            "application/x-www-form-urlencoded; charset=utf-8".to_string(),
        ),
        ("host", host),
        ("x-amz-content-sha256", hex_sha256(body)),
        ("x-amz-date", common::AMZ_DATE.to_string()),
    ]
}

#[test]
fn generated_sdb_get_attributes_matches_golden() {
    let src = generate("models/sdb/2009-04-15/service-2.json");
    assert!(src.contains("def sdb_service() -> str:"));
    assert!(src.contains("    return \"sdb\""));

    let sig = "def get_attributes(self, GetAttributesRequest input) -> str:";
    let mb = method_body(&src, sig);
    assert!(mb.contains("auto p = query_params(\"GetAttributes\", \"2009-04-15\")"));
    assert!(mb.contains("p = query_scalar(p, \"DomainName\", input.DomainName)"));
    assert!(mb.contains("p = query_scalar(p, \"ItemName\", input.ItemName)"));
    assert!(
        mb.contains(
            "p = query_flat_list(p, \"AttributeNames\", input.AttributeNames.unwrap_or([]))"
        ),
        "a flattened string list threads through query_flat_list:\n{mb}"
    );
    assert!(
        mb.contains("query_bool(input.ConsistentRead.unwrap())"),
        "the boolean member uses the codec's query_bool:\n{mb}"
    );
    assert!(mb.contains("return query_request(self.creds, sdb_service(), self.region, p)"));

    // Reconstruct the body for a representative input and sign it.
    let body = form_body(
        "GetAttributes",
        "2009-04-15",
        &[
            ("DomainName", "My Domain"),
            ("ItemName", "Item42"),
            ("AttributeNames.1", "Color"),
            ("AttributeNames.2", "Size"),
            ("ConsistentRead", "true"),
        ],
    );
    let got = sign_request("sdb", "POST", "/", &body, &query_headers("sdb", &body));
    assert_eq!(got, read("tests/expected/sdb_get_attributes.http"));
}

#[test]
fn generated_ec2_monitor_instances_matches_golden() {
    let src = generate("models/ec2/2014-09-01/service-2.json");
    assert!(src.contains("def ec2_service() -> str:"));
    assert!(src.contains("    return \"ec2\""));

    let sig = "def monitor_instances(self, MonitorInstancesRequest input) -> str:";
    let mb = method_body(&src, sig);
    assert!(mb.contains("auto p = query_params(\"MonitorInstances\", \"2014-09-01\")"));
    assert!(
        mb.contains("query_bool(input.DryRun.unwrap())"),
        "the dryRun member is capitalized to DryRun and encoded as a bool:\n{mb}"
    );
    assert!(
        mb.contains("p = query_scalar(p, \"DryRun\","),
        "ec2 capitalizes the locationName key:\n{mb}"
    );
    assert!(
        mb.contains("p = query_flat_list(p, \"InstanceId\", input.InstanceIds)"),
        "the ec2 list is always flattened under the capitalized member key:\n{mb}"
    );
    assert!(mb.contains("return query_request(self.creds, ec2_service(), self.region, p)"));

    // DryRun first (model order), then the flattened InstanceId.N list.
    let body = form_body(
        "MonitorInstances",
        "2014-09-01",
        &[
            ("DryRun", "true"),
            ("InstanceId.1", "i-1111"),
            ("InstanceId.2", "i-2222"),
        ],
    );
    let got = sign_request("ec2", "POST", "/", &body, &query_headers("ec2", &body));
    assert_eq!(got, read("tests/expected/ec2_monitor_instances.http"));
}

// STS (query) — the first service under the generated-is-product policy (#355).
// GetCallerIdentity proves the empty-input body (just `Action` + `Version`);
// GetSessionToken proves optional scalar members, including an integer rendered
// via `str(...)` and a value that url-encodes (the MFA serial's `:` and `/`).
// STS's assume-role family (AssumeRole, …) is v0-skipped — those inputs carry
// list-of-struct members (PolicyArns/Tags/…) the `aws.query` oracle does not yet
// serialize — so there is no oracle request to diff them against here.

#[test]
fn generated_sts_get_caller_identity_matches_golden() {
    let src = generate("models/sts/2011-06-15/service-2.json");
    assert!(src.contains("def sts_service() -> str:"));
    assert!(src.contains("    return \"sts\""));

    // Empty input: the generated method takes no `input` and emits only the
    // Action/Version pair.
    let sig = "def get_caller_identity(self) -> str:";
    let mb = method_body(&src, sig);
    assert!(mb.contains("auto p = query_params(\"GetCallerIdentity\", \"2011-06-15\")"));
    assert!(
        !mb.contains("query_scalar"),
        "GetCallerIdentity has no input members, so no form parameters:\n{mb}"
    );
    assert!(mb.contains("return query_request(self.creds, sts_service(), self.region, p)"));

    let body = form_body("GetCallerIdentity", "2011-06-15", &[]);
    let got = sign_request("sts", "POST", "/", &body, &query_headers("sts", &body));
    assert_eq!(got, read("tests/expected/sts_get_caller_identity.http"));
}

#[test]
fn generated_sts_get_session_token_matches_golden() {
    let src = generate("models/sts/2011-06-15/service-2.json");

    let sig = "def get_session_token(self, GetSessionTokenRequest input) -> str:";
    let mb = method_body(&src, sig);
    assert!(mb.contains("auto p = query_params(\"GetSessionToken\", \"2011-06-15\")"));
    assert!(
        mb.contains(
            "p = query_scalar(p, \"DurationSeconds\", str(input.DurationSeconds.unwrap()))"
        ),
        "an integer member is rendered through str(...):\n{mb}"
    );
    assert!(mb.contains("p = query_scalar(p, \"SerialNumber\", input.SerialNumber.unwrap())"));
    assert!(mb.contains("p = query_scalar(p, \"TokenCode\", input.TokenCode.unwrap())"));
    assert!(mb.contains("return query_request(self.creds, sts_service(), self.region, p)"));

    // All optional members set, in model order; the MFA serial exercises
    // url-encoding of `:` and `/` in a value.
    let body = form_body(
        "GetSessionToken",
        "2011-06-15",
        &[
            ("DurationSeconds", "3600"),
            ("SerialNumber", "arn:aws:iam::123456789012:mfa/user"),
            ("TokenCode", "123456"),
            ("MinimumSessionTokenSize", "1024"),
        ],
    );
    let got = sign_request("sts", "POST", "/", &body, &query_headers("sts", &body));
    assert_eq!(got, read("tests/expected/sts_get_session_token.http"));
}
