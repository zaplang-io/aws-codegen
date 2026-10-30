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
    assert!(mb.contains("auto p = query.query_params(\"GetAttributes\", \"2009-04-15\")"));
    assert!(mb.contains("p = query.query_scalar(p, \"DomainName\", input.DomainName)"));
    assert!(mb.contains("p = query.query_scalar(p, \"ItemName\", input.ItemName)"));
    // The qualified codec prefix pushes this call past 88 cols, so the value is
    // hoisted into a fresh local first (emit_hoisted) — still the same flat list.
    assert!(
        mb.contains("auto t0 = input.AttributeNames.unwrap_or([])"),
        "the flattened list value is hoisted:\n{mb}"
    );
    assert!(
        mb.contains("p = query.query_flat_list(p, \"AttributeNames\", t0)"),
        "a flattened string list threads through query_flat_list:\n{mb}"
    );
    assert!(
        mb.contains("query.query_bool(input.ConsistentRead.unwrap())"),
        "the boolean member uses the codec's query_bool:\n{mb}"
    );
    assert!(mb.contains("return query.query_request(self.creds, sdb_service(), self.region, p)"));

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

// EC2 (ec2 variant) — productionized to the full current model (2016-11-15, 811
// ops) under the generated-is-product policy (#357); the 2014-09-01 pin was the
// #354 sample. MonitorInstances proves the always-flattened list + capitalized
// bool key; GetConsoleOutput a plain scalar op with two bools (true and false).
// DescribeInstances / DescribeRegions are v0-skipped (Filters list-of-struct),
// so there is no `aws.query` oracle request to diff them against.

#[test]
fn generated_ec2_monitor_instances_matches_golden() {
    let src = generate("models/ec2/2016-11-15/service-2.json");
    assert!(src.contains("def ec2_service() -> str:"));
    assert!(src.contains("    return \"ec2\""));

    let sig = "def monitor_instances(self, MonitorInstancesRequest input) -> str:";
    let mb = method_body(&src, sig);
    assert!(mb.contains("auto p = query.query_params(\"MonitorInstances\", \"2016-11-15\")"));
    assert!(
        mb.contains("query.query_bool(input.DryRun.unwrap())"),
        "the dryRun member is capitalized to DryRun and encoded as a bool:\n{mb}"
    );
    assert!(
        mb.contains("p = query.query_scalar(p, \"DryRun\","),
        "ec2 capitalizes the locationName key:\n{mb}"
    );
    assert!(
        mb.contains("p = query.query_flat_list(p, \"InstanceId\", input.InstanceIds)"),
        "the ec2 list is always flattened under the capitalized member key:\n{mb}"
    );
    assert!(mb.contains("return query.query_request(self.creds, ec2_service(), self.region, p)"));

    // The flattened InstanceId.N list first (model member order), then DryRun.
    let body = form_body(
        "MonitorInstances",
        "2016-11-15",
        &[
            ("InstanceId.1", "i-1111"),
            ("InstanceId.2", "i-2222"),
            ("DryRun", "true"),
        ],
    );
    let got = sign_request("ec2", "POST", "/", &body, &query_headers("ec2", &body));
    assert_eq!(got, read("tests/expected/ec2_monitor_instances.http"));
}

#[test]
fn generated_ec2_get_console_output_matches_golden() {
    let src = generate("models/ec2/2016-11-15/service-2.json");

    let sig = "def get_console_output(self, GetConsoleOutputRequest input) -> str:";
    let mb = method_body(&src, sig);
    assert!(mb.contains("auto p = query.query_params(\"GetConsoleOutput\", \"2016-11-15\")"));
    assert!(mb.contains("p = query.query_scalar(p, \"InstanceId\", input.InstanceId)"));
    assert!(
        mb.contains(
            "p = query.query_scalar(p, \"Latest\", query.query_bool(input.Latest.unwrap()))"
        ),
        "an optional bool threads through query_bool under the capitalized key:\n{mb}"
    );
    assert!(mb.contains(
        "p = query.query_scalar(p, \"DryRun\", query.query_bool(input.DryRun.unwrap()))"
    ));
    assert!(mb.contains("return query.query_request(self.creds, ec2_service(), self.region, p)"));

    // InstanceId, then the two bools in model order; DryRun is false here, so the
    // codec renders the "false" branch of query_bool.
    let body = form_body(
        "GetConsoleOutput",
        "2016-11-15",
        &[
            ("InstanceId", "i-1234567890abcdef0"),
            ("Latest", "true"),
            ("DryRun", "false"),
        ],
    );
    let got = sign_request("ec2", "POST", "/", &body, &query_headers("ec2", &body));
    assert_eq!(got, read("tests/expected/ec2_get_console_output.http"));
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
    assert!(mb.contains("auto p = query.query_params(\"GetCallerIdentity\", \"2011-06-15\")"));
    assert!(
        !mb.contains("query_scalar"),
        "GetCallerIdentity has no input members, so no form parameters:\n{mb}"
    );
    assert!(mb.contains("return query.query_request(self.creds, sts_service(), self.region, p)"));

    let body = form_body("GetCallerIdentity", "2011-06-15", &[]);
    let got = sign_request("sts", "POST", "/", &body, &query_headers("sts", &body));
    assert_eq!(got, read("tests/expected/sts_get_caller_identity.http"));
}

#[test]
fn generated_sts_get_session_token_matches_golden() {
    let src = generate("models/sts/2011-06-15/service-2.json");

    let sig = "def get_session_token(self, GetSessionTokenRequest input) -> str:";
    let mb = method_body(&src, sig);
    assert!(mb.contains("auto p = query.query_params(\"GetSessionToken\", \"2011-06-15\")"));
    // The qualified codec prefix pushes this call past 88 cols, so the
    // `str(...)` value is hoisted into a fresh local first (emit_hoisted).
    assert!(
        mb.contains("auto t0 = str(input.DurationSeconds.unwrap())"),
        "an integer member is rendered through str(...):\n{mb}"
    );
    assert!(
        mb.contains("p = query.query_scalar(p, \"DurationSeconds\", t0)"),
        "the hoisted integer threads through query_scalar:\n{mb}"
    );
    assert!(mb.contains("p = query.query_scalar(p, \"SerialNumber\", input.SerialNumber.unwrap())"));
    assert!(mb.contains("p = query.query_scalar(p, \"TokenCode\", input.TokenCode.unwrap())"));
    assert!(mb.contains("return query.query_request(self.creds, sts_service(), self.region, p)"));

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

// SNS + IAM (query) — the query-family household services (#357). The ticket's
// SNS Publish / CreateTopic and IAM CreateUser are v0-skipped (map /
// list-of-struct members the `aws.query` oracle does not serialize), so clean
// scalar ops stand in: SNS GetTopicAttributes (one required scalar) and
// SetTopicAttributes (two required + one optional), IAM GetUser (optional
// scalar) and ListUsers (optional scalars incl. an integer via str()).

#[test]
fn generated_sns_get_topic_attributes_matches_golden() {
    let src = generate("models/sns/2010-03-31/service-2.json");
    assert!(src.contains("def sns_service() -> str:"));
    assert!(src.contains("    return \"sns\""));

    let sig = "def get_topic_attributes(self, GetTopicAttributesInput input) -> str:";
    let mb = method_body(&src, sig);
    assert!(mb.contains("auto p = query.query_params(\"GetTopicAttributes\", \"2010-03-31\")"));
    assert!(mb.contains("p = query.query_scalar(p, \"TopicArn\", input.TopicArn)"));
    assert!(mb.contains("return query.query_request(self.creds, sns_service(), self.region, p)"));

    // One required scalar; the ARN's `:` chars url-encode to %3A.
    let body = form_body(
        "GetTopicAttributes",
        "2010-03-31",
        &[("TopicArn", "arn:aws:sns:us-east-1:123456789012:MyTopic")],
    );
    let got = sign_request("sns", "POST", "/", &body, &query_headers("sns", &body));
    assert_eq!(got, read("tests/expected/sns_get_topic_attributes.http"));
}

#[test]
fn generated_sns_set_topic_attributes_matches_golden() {
    let src = generate("models/sns/2010-03-31/service-2.json");

    let sig = "def set_topic_attributes(self, SetTopicAttributesInput input) -> str:";
    let mb = method_body(&src, sig);
    assert!(mb.contains("auto p = query.query_params(\"SetTopicAttributes\", \"2010-03-31\")"));
    assert!(mb.contains("p = query.query_scalar(p, \"TopicArn\", input.TopicArn)"));
    assert!(mb.contains("p = query.query_scalar(p, \"AttributeName\", input.AttributeName)"));
    assert!(
        mb.contains("p = query.query_scalar(p, \"AttributeValue\", input.AttributeValue.unwrap())"),
        "the optional AttributeValue threads through query_scalar when set:\n{mb}"
    );
    assert!(mb.contains("return query.query_request(self.creds, sns_service(), self.region, p)"));

    // Two required scalars + the optional AttributeValue (a space -> %20).
    let body = form_body(
        "SetTopicAttributes",
        "2010-03-31",
        &[
            ("TopicArn", "arn:aws:sns:us-east-1:123456789012:MyTopic"),
            ("AttributeName", "DisplayName"),
            ("AttributeValue", "My Topic"),
        ],
    );
    let got = sign_request("sns", "POST", "/", &body, &query_headers("sns", &body));
    assert_eq!(got, read("tests/expected/sns_set_topic_attributes.http"));
}

#[test]
fn generated_iam_get_user_matches_golden() {
    let src = generate("models/iam/2010-05-08/service-2.json");
    assert!(src.contains("def iam_service() -> str:"));
    assert!(src.contains("    return \"iam\""));

    let sig = "def get_user(self, GetUserRequest input) -> str:";
    let mb = method_body(&src, sig);
    assert!(mb.contains("auto p = query.query_params(\"GetUser\", \"2010-05-08\")"));
    assert!(
        mb.contains("p = query.query_scalar(p, \"UserName\", input.UserName.unwrap())"),
        "the optional UserName threads through query_scalar when set:\n{mb}"
    );
    assert!(mb.contains("return query.query_request(self.creds, iam_service(), self.region, p)"));

    let body = form_body("GetUser", "2010-05-08", &[("UserName", "Bob")]);
    let got = sign_request("iam", "POST", "/", &body, &query_headers("iam", &body));
    assert_eq!(got, read("tests/expected/iam_get_user.http"));
}

#[test]
fn generated_iam_list_users_matches_golden() {
    let src = generate("models/iam/2010-05-08/service-2.json");

    let sig = "def list_users(self, ListUsersRequest input) -> str:";
    let mb = method_body(&src, sig);
    assert!(mb.contains("auto p = query.query_params(\"ListUsers\", \"2010-05-08\")"));
    assert!(mb.contains("p = query.query_scalar(p, \"PathPrefix\", input.PathPrefix.unwrap())"));
    assert!(mb.contains("p = query.query_scalar(p, \"Marker\", input.Marker.unwrap())"));
    assert!(
        mb.contains("p = query.query_scalar(p, \"MaxItems\", str(input.MaxItems.unwrap()))"),
        "the integer MaxItems renders through str(...):\n{mb}"
    );
    assert!(mb.contains("return query.query_request(self.creds, iam_service(), self.region, p)"));

    // Optional scalars in model order; PathPrefix's `/` url-encodes to %2F.
    let body = form_body(
        "ListUsers",
        "2010-05-08",
        &[
            ("PathPrefix", "/division_abc/"),
            ("Marker", "abc"),
            ("MaxItems", "10"),
        ],
    );
    let got = sign_request("iam", "POST", "/", &body, &query_headers("iam", &body));
    assert_eq!(got, read("tests/expected/iam_list_users.http"));
}
