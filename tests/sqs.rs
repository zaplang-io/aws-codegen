//! Per-service fidelity gate for the generated Amazon SQS client (#350).
//!
//! SQS proves a SECOND awsJson service runs through the same v0 generator as
//! DynamoDB: SQS's modern JSON protocol is `protocol: "json"` (awsJson 1.0,
//! targetPrefix `AmazonSQS`), so it generates with no new protocol machinery.
//! The tests mirror the DynamoDB #348/#349 gates and are equally toolchain-free
//! (no Zap compiler / Docker):
//!   * coverage + awsJson contract shape of the generated source;
//!   * a byte-diff of the generated `GetQueueUrl` request against a pinned golden
//!     (`tests/expected/sqs_get_queue_url.http`), reconstructed from the generated
//!     source + an independent SigV4 signer and cross-checked by the Python oracle
//!     `tools/verify_goldens.py`; and
//!   * a behavioral check of the generated `ListQueues` paginator.

mod common;
use common::*;

fn sqs_model() -> String {
    read("models/sqs/2012-11-05/service-2.json")
}

fn sqs_paginators() -> String {
    read("models/sqs/2012-11-05/paginators-1.json")
}

fn generate_sqs() -> (String, aws_codegen::Coverage) {
    aws_codegen::generate_from_json_with_paginators(&sqs_model(), Some(&sqs_paginators()))
        .expect("SQS model generates")
}

#[test]
fn sqs_model_is_awsjson() {
    // Guard the premise: SQS's pinned model is the modern JSON protocol, not the
    // legacy query protocol (that would be Phase 3, #352).
    let m: serde_json::Value = serde_json::from_str(&sqs_model()).unwrap();
    assert_eq!(
        m["metadata"]["protocol"], "json",
        "SQS model is not awsJson"
    );
    assert_eq!(m["metadata"]["targetPrefix"], "AmazonSQS");
    assert_eq!(m["metadata"]["jsonVersion"], "1.0");
}

#[test]
fn checked_in_sqs_output_is_current() {
    let (src, _cov) = generate_sqs();
    let on_disk = read("generated/sqs/src/sqs.zap");
    assert_eq!(
        src, on_disk,
        "generated/sqs/src/sqs.zap is stale — re-run: \
         cargo run -- models/sqs/2012-11-05/service-2.json -o generated/sqs/src/sqs.zap"
    );
}

#[test]
fn sqs_coverage() {
    let (_src, cov) = generate_sqs();
    // The pinned 2012-11-05 model: 23 operations, 76 structures.
    assert_eq!(cov.operations_total, 23, "ops: {}", cov.operations_total);
    assert_eq!(
        cov.operations_methods, 12,
        "methods: {}",
        cov.operations_methods
    );
    assert_eq!(
        cov.operations_skipped, 11,
        "skipped: {}",
        cov.operations_skipped
    );
    assert_eq!(cov.structs_total, 76, "structs: {}", cov.structs_total);
    assert_eq!(
        cov.structs_derivable, 52,
        "derivable: {}",
        cov.structs_derivable
    );
    assert_eq!(cov.enums, 2, "enums: {}", cov.enums);
    assert_eq!(cov.error_variants, 28, "errors: {}", cov.error_variants);
    // paginators-1.json lists ListQueues + ListDeadLetterSourceQueues; both have
    // derivable input and a single string NextToken, so both are surfaced.
    assert_eq!(cov.paginators, 2, "paginators: {}", cov.paginators);
    assert_eq!(
        cov.paginators_skipped, 0,
        "skipped: {}",
        cov.paginators_skipped
    );
}

#[test]
fn sqs_awsjson_contract_shape() {
    let (src, _cov) = generate_sqs();
    assert!(src.contains("def sqs_protocol() -> awsjson.AwsJson:"));
    assert!(src.contains("awsjson.awsjson_1_0(\"AmazonSQS\", \"sqs\")"));
    assert!(src.contains("struct SQSClient:"));
    assert!(src.contains("def sqs_client(core.Credentials creds, str region) -> SQSClient:"));
    // A derivable op dispatches through the codec with a derived body.
    assert!(src.contains("def get_queue_url(self, GetQueueUrlRequest input) -> str:"));
    assert!(src.contains(
        "return awsjson.awsjson_request_now(sqs_protocol(), self.creds, self.region, \"GetQueueUrl\", body)"
    ));
    // Error dispatch.
    assert!(src.contains("enum SQSError:"));
    assert!(src.contains("def sqs_error_from_code(str code) -> SQSError:"));
    assert!(src.contains("QueueDoesNotExist"));
    // Collection-input ops (ReceiveMessage, SendMessage, ...) are documented as
    // skipped, not silently emitted wrong — same derive gap as DynamoDB item ops.
    assert!(src.contains("Operations skipped in v0"));
    assert!(src.contains("ReceiveMessage (input ReceiveMessageRequest)"));
    assert!(src.contains("SendMessage (input SendMessageRequest)"));
}

#[test]
fn generated_get_queue_url_request_matches_golden() {
    // Regenerate from the pinned model so this fails the moment the generator's
    // output drifts.
    let src = aws_codegen::generate_from_json(&sqs_model())
        .expect("SQS model generates")
        .0;

    let (prefix, service, content_type) = parse_protocol(&src);
    let op = parse_dispatch_op(
        &src,
        "def get_queue_url(self, GetQueueUrlRequest input) -> str:",
    );

    // Body: GetQueueUrlRequest is a required `str QueueName` first, then an
    // optional account id. derive(Json) encodes the single set field as compact,
    // declaration-order JSON; the None optional is omitted.
    let fields = parse_struct_fields(&src, "GetQueueUrlRequest");
    assert_eq!(
        fields.first(),
        Some(&("str".to_string(), "QueueName".to_string())),
        "GetQueueUrlRequest's first field is a required `str QueueName`; the \
         byte-diff fixture must be updated if the generated shape changes"
    );
    let body = "{\"QueueName\":\"MyQueue\"}".to_string();

    // Reconstruct the on-the-wire request the generated client would sign.
    let host = "sqs.us-east-1.amazonaws.com";
    let target = format!("{prefix}.{op}");
    let headers = vec![
        ("content-type", content_type),
        ("host", host.to_string()),
        ("x-amz-content-sha256", hex_sha256(&body)),
        ("x-amz-date", AMZ_DATE.to_string()),
        ("x-amz-target", target),
    ];
    let generated = sign_request(&service, "POST", "/", &body, &headers);

    let golden = read("tests/expected/sqs_get_queue_url.http");
    assert_eq!(
        generated, golden,
        "generated SQS GetQueueUrl request is NOT byte-identical to the pinned \
         golden (tests/expected/sqs_get_queue_url.http).\n\
         If this is an intended change, re-pin with \
         `python3 tools/verify_goldens.py --emit` and confirm the oracle agrees."
    );

    // Point at the drift explicitly on failure.
    assert_eq!(prefix, "AmazonSQS", "X-Amz-Target prefix drifted");
    assert_eq!(service, "sqs", "SigV4 service name drifted");
    assert_eq!(op, "GetQueueUrl", "operation name drifted");
}

#[test]
fn generated_list_queues_paginator_threads_tokens_and_stops() {
    let (src, _cov) = generate_sqs();
    let p = parse_paginator(
        &src,
        "def paginate_list_queues(self, ListQueuesRequest input):",
    );

    // Drift guards: the wiring must match the pinned SQS paginators-1.json, where
    // ListQueues threads a single NextToken in and out.
    assert_eq!(p.op, "ListQueues", "paginated operation drifted");
    assert_eq!(p.output_token, "NextToken", "output_token drifted");
    assert_eq!(p.input_token, "NextToken", "input_token drifted");

    // A three-page listing: pages 1 and 2 carry a NextToken, page 3 does not.
    let responses = [
        r#"{"QueueUrls":["https://sqs/q/A"],"NextToken":"t1"}"#,
        r#"{"QueueUrls":["https://sqs/q/B"],"NextToken":"t2"}"#,
        r#"{"QueueUrls":["https://sqs/q/C"]}"#,
    ];
    let run = drive(&p, &responses);

    assert_eq!(run.pages.len(), 3, "should yield exactly three pages");
    assert_eq!(run.pages[0], responses[0]);
    assert_eq!(run.pages[2], responses[2]);
    // request 1 carries no cursor; request 2 carries page 1's NextToken; etc.
    assert_eq!(
        run.request_tokens,
        vec!["".to_string(), "t1".to_string(), "t2".to_string()],
        "continuation token was not threaded correctly across requests"
    );
}

#[test]
fn generated_list_queues_paginator_handles_single_page() {
    let (src, _cov) = generate_sqs();
    let p = parse_paginator(
        &src,
        "def paginate_list_queues(self, ListQueuesRequest input):",
    );
    let responses = [r#"{"QueueUrls":["only"]}"#];
    let run = drive(&p, &responses);
    assert_eq!(run.pages.len(), 1);
    assert_eq!(run.request_tokens, vec!["".to_string()]);
}
