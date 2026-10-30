//! Per-service fidelity gate for the generated Amazon Kinesis client (#350).
//!
//! Kinesis is the THIRD service through the v0 generator and the first on
//! **awsJson 1.1** (targetPrefix `Kinesis_20131202`, jsonVersion 1.1) — DynamoDB
//! and SQS are both 1.0, so Kinesis is what exercises the generator's 1.1 path
//! (the `awsjson_1_1` constructor and the `application/x-amz-json-1.1` content
//! type). Same toolchain-free gates as the other services (no Zap compiler /
//! Docker): coverage + contract, a `DescribeStreamSummary` byte-diff against a
//! pinned golden (cross-checked by `tools/verify_goldens.py`), and the
//! `ListStreams` paginator. It also pins the behavior of the paginator
//! flat-token guard: Kinesis `DescribeStream`'s nested JMESPath output_token must
//! be document-skipped, not emitted as a broken paginator.

mod common;
use common::*;

fn kinesis_model() -> String {
    read("models/kinesis/2013-12-02/service-2.json")
}

fn kinesis_paginators() -> String {
    read("models/kinesis/2013-12-02/paginators-1.json")
}

fn generate_kinesis() -> (String, aws_codegen::Coverage) {
    aws_codegen::generate_from_json_with_paginators(&kinesis_model(), Some(&kinesis_paginators()))
        .expect("Kinesis model generates")
}

#[test]
fn kinesis_model_is_awsjson_1_1() {
    let m: serde_json::Value = serde_json::from_str(&kinesis_model()).unwrap();
    assert_eq!(m["metadata"]["protocol"], "json");
    assert_eq!(
        m["metadata"]["jsonVersion"], "1.1",
        "Kinesis is awsJson 1.1"
    );
    assert_eq!(m["metadata"]["targetPrefix"], "Kinesis_20131202");
}

#[test]
fn checked_in_kinesis_output_is_current() {
    let (src, _cov) = generate_kinesis();
    let on_disk = read("generated/kinesis/src/kinesis.zap");
    assert_eq!(
        src, on_disk,
        "generated/kinesis/src/kinesis.zap is stale — re-run: \
         cargo run -- models/kinesis/2013-12-02/service-2.json -o generated/kinesis/src/kinesis.zap"
    );
}

#[test]
fn kinesis_coverage() {
    let (_src, cov) = generate_kinesis();
    assert_eq!(cov.operations_total, 45, "ops: {}", cov.operations_total);
    assert_eq!(
        cov.operations_methods, 34,
        "methods: {}",
        cov.operations_methods
    );
    assert_eq!(
        cov.operations_skipped, 11,
        "skipped: {}",
        cov.operations_skipped
    );
    assert_eq!(cov.structs_total, 132, "structs: {}", cov.structs_total);
    assert_eq!(
        cov.structs_derivable, 94,
        "derivable: {}",
        cov.structs_derivable
    );
    assert_eq!(cov.enums, 16, "enums: {}", cov.enums);
    assert_eq!(cov.error_variants, 17, "errors: {}", cov.error_variants);
    // 4 paginated ops have simple NextToken input; DescribeStream's output_token
    // is a nested path (skipped by the flat-token guard) and ListChannels' input
    // is non-derivable, so 3 generate and 2 are skipped.
    assert_eq!(cov.paginators, 3, "paginators: {}", cov.paginators);
    assert_eq!(
        cov.paginators_skipped, 2,
        "skipped: {}",
        cov.paginators_skipped
    );
}

#[test]
fn kinesis_awsjson_1_1_contract_shape() {
    let (src, _cov) = generate_kinesis();
    assert!(src.contains("def kinesis_protocol() -> awsjson.AwsJson:"));
    // The 1.1 constructor — the whole reason Kinesis is in the suite.
    assert!(src.contains("awsjson.awsjson_1_1(\"Kinesis_20131202\", \"kinesis\")"));
    assert!(src.contains("struct KinesisClient:"));
    assert!(
        src.contains("def kinesis_client(core.Credentials creds, str region) -> KinesisClient:")
    );
    assert!(
        src.contains("def describe_stream_summary(self, DescribeStreamSummaryInput input) -> str:")
    );
    assert!(src.contains(
        "return awsjson.awsjson_request_now(kinesis_protocol(), self.creds, self.region, \"DescribeStreamSummary\", body)"
    ));
    assert!(src.contains("enum KinesisError:"));
    assert!(src.contains("def kinesis_error_from_code(str code) -> KinesisError:"));
    assert!(src.contains("ResourceNotFoundException"));
}

#[test]
fn generated_describe_stream_summary_request_matches_golden() {
    let src = aws_codegen::generate_from_json(&kinesis_model())
        .expect("Kinesis model generates")
        .0;

    let (prefix, service, content_type) = parse_protocol(&src);
    // awsJson 1.1 => content type 1.1, the distinguishing feature from 1.0.
    assert_eq!(
        content_type, "application/x-amz-json-1.1",
        "Kinesis must sign with the 1.1 content type"
    );
    let op = parse_dispatch_op(
        &src,
        "def describe_stream_summary(self, DescribeStreamSummaryInput input) -> str:",
    );

    // DescribeStreamSummaryInput's first member is StreamName; derive encodes the
    // single set field as compact, declaration-order JSON.
    let fields = parse_struct_fields(&src, "DescribeStreamSummaryInput");
    assert_eq!(
        fields.first().map(|(_, n)| n.as_str()),
        Some("StreamName"),
        "DescribeStreamSummaryInput's first field is StreamName; the byte-diff \
         fixture must be updated if the generated shape changes"
    );
    let body = "{\"StreamName\":\"exampleStreamName\"}".to_string();

    let host = "kinesis.us-east-1.amazonaws.com";
    let target = format!("{prefix}.{op}");
    let headers = vec![
        ("content-type", content_type),
        ("host", host.to_string()),
        ("x-amz-content-sha256", hex_sha256(&body)),
        ("x-amz-date", AMZ_DATE.to_string()),
        ("x-amz-target", target),
    ];
    let generated = sign_request(&service, "POST", "/", &body, &headers);

    let golden = read("tests/expected/kinesis_describe_stream_summary.http");
    assert_eq!(
        generated, golden,
        "generated Kinesis DescribeStreamSummary request is NOT byte-identical to \
         the pinned golden (tests/expected/kinesis_describe_stream_summary.http).\n\
         If intended, re-pin with `python3 tools/verify_goldens.py --emit`."
    );
    assert_eq!(prefix, "Kinesis_20131202", "X-Amz-Target prefix drifted");
    assert_eq!(service, "kinesis", "SigV4 service name drifted");
    assert_eq!(op, "DescribeStreamSummary", "operation name drifted");
}

#[test]
fn generated_list_streams_paginator_threads_tokens_and_stops() {
    let (src, _cov) = generate_kinesis();
    let p = parse_paginator(
        &src,
        "def paginate_list_streams(self, ListStreamsInput input):",
    );
    assert_eq!(p.op, "ListStreams", "paginated operation drifted");
    assert_eq!(p.output_token, "NextToken", "output_token drifted");
    assert_eq!(p.input_token, "NextToken", "input_token drifted");

    let responses = [
        r#"{"StreamNames":["a"],"NextToken":"n1"}"#,
        r#"{"StreamNames":["b"],"NextToken":"n2"}"#,
        r#"{"StreamNames":["c"]}"#,
    ];
    let run = drive(&p, &responses);
    assert_eq!(run.pages.len(), 3, "should yield exactly three pages");
    assert_eq!(
        run.request_tokens,
        vec!["".to_string(), "n1".to_string(), "n2".to_string()],
        "continuation token was not threaded correctly across requests"
    );
}

#[test]
fn kinesis_nested_output_token_paginator_is_skipped() {
    // DescribeStream's paginators-1.json output_token is the nested JMESPath
    // `StreamDescription.Shards[-1].ShardId`, which the flat `next_page_json`
    // lookup cannot resolve. It must be document-skipped (with the reason), never
    // emitted as a paginator that would silently stop after one page.
    let (src, _cov) = generate_kinesis();
    assert!(
        !src.contains("def paginate_describe_stream("),
        "DescribeStream must not get a paginator (nested output_token)"
    );
    assert!(
        src.contains("DescribeStream (output_token StreamDescription.Shards[-1].ShardId is a nested path, not a flat field)"),
        "the nested-path skip must be documented with its reason"
    );
}
