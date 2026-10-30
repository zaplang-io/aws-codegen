//! Behavioral oracle for the generated DynamoDB paginators (#349).
//!
//! Proves the generated `paginate_list_tables` iterator walks pages correctly:
//! it threads the model's continuation token (`LastEvaluatedTableName` out ->
//! `ExclusiveStartTableName` in) and stops the moment the output token is absent.
//!
//! WHY THIS IS A HOST-ONLY RUST TEST (same rationale as the #348 byte-diff).
//! The real end-to-end check runs the generated Zap paginator under the Zap
//! toolchain against a replayed response sequence, but the published compiler
//! image still lags the derive(Json) AWS hooks (zaplang-io/zap#346), so the full
//! generated file does not yet compile there. To fail CI on a pagination-logic
//! regression *now*, with no toolchain, this test:
//!
//!   * parses the generator-OWNED pieces out of the freshly generated
//!     `paginate_list_tables` source — the operation name, the output-token field
//!     read by `next_page_json`, and the input-token field the loop assigns — so
//!     any drift in what the generator emits changes the simulated behavior; and
//!   * drives those exact field names through a faithful re-implementation of the
//!     emitted loop (mirroring aws.core `next_page_json` / `json_string_field`)
//!     against a stubbed 3-page response sequence, asserting the page count, the
//!     per-request token threading, and clean termination.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> String {
    let p = repo_root().join(path);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

fn generated_client() -> String {
    let model = read("models/dynamodb/2012-08-10/service-2.json");
    let paginators = read("models/dynamodb/2012-08-10/paginators-1.json");
    aws_codegen::generate_from_json_with_paginators(&model, Some(&paginators))
        .expect("DynamoDB model generates")
        .0
}

// --- what the generator owns, parsed out of the generated paginator ----------

/// The pagination wiring the generated `paginate_list_tables` method encodes:
/// the operation name it dispatches, the response-body field it reads the next
/// token from (`core.next_page_json(page.body, "<output>")`), and the input field it
/// assigns that token to on the next request (`input.<input> = ...`).
struct ParsedPaginator {
    op: String,
    output_token: String,
    input_token: String,
}

fn parse_list_tables_paginator(src: &str) -> ParsedPaginator {
    let anchor = "def paginate_list_tables(self, ListTablesInput input):";
    let m = src
        .find(anchor)
        .expect("generated client defines paginate_list_tables(ListTablesInput)");
    // The method body runs until the next method (`\n    def `) or the next
    // top-level line (`\n# ` / `\ndef `), whichever comes first.
    let body = &src[m..];
    let after = &body[anchor.len()..];
    let end = ["\n    def ", "\n# ", "\ndef "]
        .iter()
        .filter_map(|marker| after.find(marker))
        .min()
        .map(|i| anchor.len() + i)
        .unwrap_or(body.len());
    let body = &body[..end];

    // It must be a yield-based generator that sends and loops.
    assert!(
        body.contains("yield page"),
        "paginator yields pages:\n{body}"
    );
    assert!(
        body.contains("auto page = core.send(host, raw)"),
        "paginator sends each page:\n{body}"
    );
    assert!(
        body.contains("if not np.has_more:"),
        "paginator stops on an absent token:\n{body}"
    );

    let op = between(body, "self.region, \"", "\", body)").expect("dispatches a named operation");
    let output_token = between(body, "core.next_page_json(page.body, \"", "\")")
        .expect("reads the next token via next_page_json");
    // Anchor on the assignment itself: the field sits between the last `input.`
    // before ` = Optional.Some(np.token)` and that suffix (avoids matching the
    // earlier `input.to_json()`).
    let assign = " = Optional.Some(np.token)";
    let close = body
        .find(assign)
        .expect("assigns the token to an input field");
    let open = "input.";
    let head = &body[..close];
    let start = head
        .rfind(open)
        .expect("token assignment targets input.<field>")
        + open.len();
    let input_token = head[start..].to_string();

    ParsedPaginator {
        op,
        output_token,
        input_token,
    }
}

/// The substring between `open` and the next `close` after it, if both occur.
fn between(s: &str, open: &str, close: &str) -> Option<String> {
    let a = s.find(open)? + open.len();
    let rest = &s[a..];
    let b = rest.find(close)?;
    Some(rest[..b].to_string())
}

// --- a faithful re-implementation of the emitted loop ------------------------

/// Mirror of aws.core `json_string_field`: the quoted value of `"field":"..."`,
/// or None. Enough for the stubbed string-token bodies.
fn json_string_field(body: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let k = body.find(&needle)?;
    let rest = &body[k + needle.len()..];
    let c = rest.find(':')?;
    let after = &rest[c + 1..];
    let q1 = after.find('"')?;
    let tail = &after[q1 + 1..];
    let q2 = tail.find('"')?;
    Some(tail[..q2].to_string())
}

/// One run of the generated paginator loop against a fixed page sequence.
struct Run {
    /// Pages the consumer saw (their bodies), in order.
    pages: Vec<String>,
    /// The continuation token carried on each request (empty on the first).
    request_tokens: Vec<String>,
}

/// Execute the loop exactly as `paginate_list_tables` emits it, using the parsed
/// field names, over a stubbed response sequence (`responses[i]` is the body the
/// i-th `send` returns). Guarded against runaway loops.
fn drive(p: &ParsedPaginator, responses: &[&str]) -> Run {
    let mut pages = Vec::new();
    let mut request_tokens = Vec::new();
    let mut token = String::new(); // input.<input_token> starts unset
    let mut i = 0;
    loop {
        assert!(i < responses.len(), "paginator requested more pages than the stub provides — it failed to stop (op {}, token field {})", p.op, p.output_token);
        // body = input.to_json(): the request carries the current token.
        request_tokens.push(token.clone());
        let page = responses[i].to_string();
        // yield page
        pages.push(page.clone());
        // np = core.next_page_json(page.body, "<output_token>")
        let next = json_string_field(&page, &p.output_token).unwrap_or_default();
        if next.is_empty() {
            break; // if not np.has_more: break
        }
        // input.<input_token> = Optional.Some(np.token)
        token = next;
        i += 1;
    }
    Run {
        pages,
        request_tokens,
    }
}

#[test]
fn generated_list_tables_paginator_threads_tokens_and_stops() {
    let src = generated_client();
    let p = parse_list_tables_paginator(&src);

    // Drift guards: the wiring must match the pinned DynamoDB paginators-1.json.
    assert_eq!(p.op, "ListTables", "paginated operation drifted");
    assert_eq!(
        p.output_token, "LastEvaluatedTableName",
        "output_token drifted"
    );
    assert_eq!(
        p.input_token, "ExclusiveStartTableName",
        "input_token drifted"
    );

    // A three-page listing: pages 1 and 2 carry a next-table cursor, page 3 does
    // not, which ends the walk.
    let responses = [
        r#"{"TableNames":["A","B"],"LastEvaluatedTableName":"B"}"#,
        r#"{"TableNames":["C","D"],"LastEvaluatedTableName":"D"}"#,
        r#"{"TableNames":["E"]}"#,
    ];
    let run = drive(&p, &responses);

    // Every page was yielded, in order, and the loop stopped after the last.
    assert_eq!(run.pages.len(), 3, "should yield exactly three pages");
    assert_eq!(run.pages[0], responses[0]);
    assert_eq!(run.pages[2], responses[2]);

    // Token threading: request 1 carries no cursor; request 2 carries page 1's
    // LastEvaluatedTableName ("B"); request 3 carries page 2's ("D").
    assert_eq!(
        run.request_tokens,
        vec!["".to_string(), "B".to_string(), "D".to_string()],
        "continuation token was not threaded correctly across requests"
    );
}

#[test]
fn generated_list_tables_paginator_handles_single_page() {
    let src = generated_client();
    let p = parse_list_tables_paginator(&src);

    // A lone page with no continuation token: exactly one request, one page, stop.
    let responses = [r#"{"TableNames":["only"]}"#];
    let run = drive(&p, &responses);
    assert_eq!(run.pages.len(), 1);
    assert_eq!(run.request_tokens, vec!["".to_string()]);
}
