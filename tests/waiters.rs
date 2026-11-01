//! Behavioral oracle for the generated waiters (zaplang-io/aws-codegen#22).
//!
//! Proves the generator emits, for a service with a `waiters-2.json` sidecar,
//! the per-waiter acceptor table + `wait_<name>` method (boto3's
//! `wait_table_exists`) and the shared per-operation poll helper, delegating to
//! the hand-written `aws_core.waiters` engine (D-0004 / D-0012).
//!
//! WHY THIS IS A HOST-ONLY RUST TEST (same rationale as the #349 paginator
//! oracle and the #348 byte-diff): the published compiler image still lags the
//! derive(Json) AWS hooks (zaplang-io/zap#346), so the full generated client does
//! not yet compile there. To fail CI on a waiter-emission regression *now*, with
//! no toolchain, this asserts the generator-owned text: the acceptor-table
//! constructors, the method signatures, the dedup of the poll helper, and the
//! `waiter(cfg, poll).wait_or_raise()` delegation.
//!
//! No model vendored under `models/` ships a `waiters-2.json` yet (botocore ships
//! them, but `tools/sync-models.py` snapshots only `service-2.json` +
//! `paginators-1.json`), so these tests drive a fixture sidecar over the pinned
//! DynamoDB / S3 models — exactly as the paginator fixtures stand in for a
//! generated `paginators-1.json` on the aws-core side (D-0012).

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    let p = repo_root().join(path);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

/// A DynamoDB-shaped fixture: two waiters on DescribeTable (path + error
/// acceptors) and a third carrying a status acceptor, to exercise every acceptor
/// constructor the emitter renders.
const DDB_WAITERS: &str = r#"{"version":2,"waiters":{
  "TableExists":{"delay":20,"operation":"DescribeTable","maxAttempts":25,
    "acceptors":[
      {"expected":"ACTIVE","matcher":"path","state":"success","argument":"Table.TableStatus"},
      {"expected":"ResourceNotFoundException","matcher":"error","state":"retry"}]},
  "TableNotExists":{"delay":20,"operation":"DescribeTable","maxAttempts":25,
    "acceptors":[
      {"expected":"ResourceNotFoundException","matcher":"error","state":"success"}]},
  "TableReady":{"delay":5,"operation":"DescribeTable","maxAttempts":10,
    "acceptors":[
      {"expected":200,"matcher":"status","state":"success"}]}
}}"#;

fn ddb_client() -> String {
    let model = read("models/dynamodb/2012-08-10/service-2.json");
    aws_codegen::generate_from_json_with_waiters(&model, Some(DDB_WAITERS))
        .expect("DynamoDB model generates with waiters")
        .0
}

#[test]
fn awsjson_waiters_emit_table_method_and_delegation() {
    let src = ddb_client();

    // The waiter engine is imported only when a waiter is surfaced.
    assert!(
        src.contains("import aws_core.waiters"),
        "generated client imports the waiter engine"
    );

    // Each waiter gets a typed `wait_<snake(name)>(self, <Input> input)` method.
    assert!(
        src.contains("def wait_table_exists(self, DescribeTableInput input):"),
        "emits wait_table_exists over the operation's input shape"
    );
    assert!(
        src.contains("def wait_table_not_exists(self, DescribeTableInput input):"),
        "emits wait_table_not_exists"
    );
    assert!(
        src.contains("def wait_table_ready(self, DescribeTableInput input):"),
        "emits wait_table_ready"
    );

    // The acceptor table is built from the acceptor_* constructors, with the
    // matcher kind, the mapped state, and the (string-normalized) expected value.
    assert!(
        src.contains(
            "waiters.acceptor_path(waiters.state_success(), \"Table.TableStatus\", \"ACTIVE\")"
        ),
        "path acceptor renders argument + expected with the success state"
    );
    assert!(
        src.contains(
            "waiters.acceptor_error(waiters.state_retry(), \"ResourceNotFoundException\")"
        ),
        "error acceptor renders with the retry state and no argument"
    );
    assert!(
        src.contains("waiters.acceptor_status(waiters.state_success(), \"200\")"),
        "status acceptor renders the integer expected as its string form"
    );

    // The config carries the model's name / delay / maxAttempts.
    assert!(
        src.contains("name=\"TableExists\""),
        "config names the waiter"
    );
    assert!(src.contains("delay=20"), "config carries the delay");
    assert!(
        src.contains("max_attempts=25"),
        "config carries maxAttempts"
    );

    // Each method binds a single-expression poll closure and delegates to the
    // raising engine entry point.
    assert!(
        src.contains("fn() -> waiters.Poll poll = lambda: self._waiter_poll_describe_table(input)"),
        "waiter binds the poll closure to the shared helper"
    );
    assert!(
        src.contains("waiters.waiter(cfg, poll).wait_or_raise()"),
        "waiter delegates to waiter(cfg, poll).wait_or_raise()"
    );

    // The poll helper is shared across every waiter on DescribeTable — emitted
    // exactly once — and sends the signed op request + parses the body.
    assert_eq!(
        src.matches(
            "def _waiter_poll_describe_table(self, DescribeTableInput input) -> waiters.Poll:"
        )
        .count(),
        1,
        "the per-operation poll helper is deduplicated across waiters"
    );
    assert!(
        src.contains("auto resp = core.send(host, self.describe_table(input))"),
        "the poll helper sends the signed operation request"
    );
    assert!(
        src.contains("return waiters.Poll(response=resp, parsed=waiters.parse_body(resp))"),
        "the poll helper parses the response into the matcher DOM"
    );

    // The header coverage line reflects the count.
    assert!(
        src.contains("3 waiters generated (0 skipped) from waiters-2.json."),
        "header reports the waiter coverage"
    );
}

#[test]
fn no_waiters_sidecar_emits_no_waiter_surface() {
    let model = read("models/dynamodb/2012-08-10/service-2.json");
    let src = aws_codegen::generate_from_json(&model)
        .expect("DynamoDB model generates")
        .0;

    assert!(
        !src.contains("import aws_core.waiters"),
        "no waiter engine import without a waiters-2.json"
    );
    assert!(
        !src.contains("def wait_"),
        "no wait_<name> methods without a waiters-2.json"
    );
    assert!(
        src.contains("0 waiters generated (0 skipped) from waiters-2.json."),
        "header still reports a zero waiter count"
    );
}

#[test]
fn non_json_protocol_notes_waiters_not_surfaced() {
    // S3 is rest-xml: waiters are noted-but-skipped (the XML matcher DOM needs a
    // parse adapter, a follow-up), exactly like XML paginators.
    let model = read("models/s3/2006-03-01/service-2.json");
    let waiters = r#"{"version":2,"waiters":{
      "BucketExists":{"delay":5,"operation":"HeadBucket","maxAttempts":20,
        "acceptors":[
          {"expected":200,"matcher":"status","state":"success"},
          {"expected":404,"matcher":"status","state":"retry"}]}
    }}"#;
    let src = aws_codegen::generate_from_json_with_waiters(&model, Some(waiters))
        .expect("S3 model generates with waiters")
        .0;

    assert!(
        !src.contains("def wait_bucket_exists"),
        "rest-xml does not surface a waiter method yet"
    );
    assert!(
        !src.contains("import aws_core.waiters"),
        "no waiter engine import when no waiter is surfaced"
    );
    assert!(
        src.contains("Waiters (waiters-2.json) are not surfaced for this protocol yet"),
        "the skipped waiter is noted"
    );
    assert!(
        src.contains("0 waiters generated (1 skipped) from waiters-2.json."),
        "header records the waiter as skipped, not generated"
    );
}
