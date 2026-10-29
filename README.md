# aws-codegen

Model-driven code generator: botocore `service-2.json` → Zap AWS SDK clients.

`aws-codegen` is the engine behind the Zap AWS broad-coverage program
([zaplang-io/zap#366](https://github.com/zaplang-io/zap/issues/366)). It reads
AWS's own service models and emits a Zap client that rides on the hand-written
`aws.core` runtime and protocol codecs (`zaplang-io/aws`).

**Protocols**: the **awsJson** protocol
([zaplang-io/zap#347](https://github.com/zaplang-io/zap/issues/347)), proven across
multiple services, and the **rest-json** (restJson1) protocol
([#4](https://github.com/zaplang-io/aws-codegen/issues/4), **Lambda** the proof).
rest-xml / query protocols (#352/#353) and wiring the output into the `aws`
package are later tickets.

## Services

The generator is the single source of truth for every checked-in client; CI
regenerates each from its pinned model and fails on any drift.

| Service | Protocol | Model | Generated | Notes |
|---|---|---|---|---|
| **DynamoDB** | awsJson **1.0** | `models/dynamodb/2012-08-10/` | `generated/dynamodb/dynamodb.zap` | The original proof (#347); byte-diffed against the hand-written reference (#348); 3 paginators (#349). |
| **SQS** | awsJson **1.0** | `models/sqs/2012-11-05/` | `generated/sqs/sqs.zap` | SQS's **modern JSON** protocol (`AmazonSQS` target); 2 `List*` paginators; `GetQueueUrl` byte-diffed against a pinned golden (#350). |
| **Kinesis** | awsJson **1.1** | `models/kinesis/2013-12-02/` | `generated/kinesis/kinesis.zap` | Covers the **1.1** wire variant (content type `…-json-1.1`, `awsjson_1_1`) that the 1.0 services don't; 3 `NextToken` paginators; `DescribeStreamSummary` byte-diffed; `DescribeStream`'s nested JMESPath paginator token is document-skipped (#350). |
| **Lambda** | **rest-json** | `models/lambda/2015-03-31/` | `generated/lambda/lambda.zap` | The **rest-json** proof (#4): HTTP path/query/header bindings + raw httpPayload + JSON document bodies, through the `aws.binding` + `aws.restjson` codec; 14 `Marker` paginators; `GetFunction` / `ListFunctions` / `Invoke` / `PutFunctionConcurrency` byte-diffed (cross-checked vs botocore). |

The awsJson services span both wire versions (1.0 and 1.1) and three protocol
prefixes; Lambda adds the REST binding path — together proving the generator is
model-driven rather than tuned to one service or protocol. Each ships a
toolchain-free fidelity gate (see **Development / CI gate**): regeneration
determinism, a byte-diff of a concrete operation's signed request against a pinned
golden, and a behavioral paginator check — all host-only (no Zap compiler / Docker
required).

## What it generates

Given a `service-2.json`, the generator emits one Zap file. For **awsJson** it
contains:

- **A protocol constructor** — `def <svc>_protocol() -> AwsJson` returning
  `awsjson_1_0/1_1(targetPrefix, endpointPrefix)` per the model's `jsonVersion`.
- **A struct per structure shape**, with AWS types mapped to Zap types and the
  `@derive(Json)` AWS hooks attached where the shape supports them
  ([zaplang-io/zap#346](https://github.com/zaplang-io/zap/issues/346)):
  - timestamps → `DateTime` with `@json(timestamp="iso8601")` when the model
    says so (epoch by default, matching awsJson);
  - blobs → `bytes` (type-driven base64, no annotation);
  - string enums → `@json(open)` enums with an `Unknown(str value)` fallback.
- **A service error enum** (`enum <Svc>Error`) over every operation's errors plus
  service-level errors, with an `Unknown(str code)` fallback and a
  `<svc>_error_from_code(str)` classifier driven by the codec's `__type` /
  `X-Amzn-ErrorType` handling.
- **A client struct** (`struct <Svc>Client`) holding `Credentials` + region, with
  one method per operation that builds the input shape and dispatches through the
  `aws.awsjson` codec — the same shape as the hand-written `aws.dynamodb` client.
  Each method returns ready-to-send, SigV4-signed HTTP/1.1 request text.
- **Paginators** ([zaplang-io/zap#349](https://github.com/zaplang-io/zap/issues/349)),
  driven by the botocore `paginators-1.json` sidecar. For each paginated operation
  whose input is derivable and whose `input_token`/`output_token` are simple string
  fields, the generator emits a `paginate_<op>(self, <Input>)` **yield-based
  iterator** method: it signs + `send`s each page, `yield`s the `Response`, reads
  the next token with `next_page_json(page.body, "<output_token>")`, threads it
  back into the input's `<input_token>`, and stops when the token is absent.
  Consume it with `for page in client.paginate_list_tables(input):`. Paginated ops
  with a non-derivable input or a non-string token (DynamoDB `Query`/`Scan`, whose
  `ExclusiveStartKey` is an `AttributeValue` map) are documented as skipped.

### rest-json (restJson1)

For a `rest-json` model (e.g. Lambda) the generator drives the hand-written
**`aws.binding`** HTTP binding layer + **`aws.restjson`** codec instead. The
protocol seam is a `def <svc>_service() -> str` (the SigV4 / endpoint name), and
each operation method places its input members at the HTTP locations the model's
Smithy traits name, then SigV4-signs via `rest_json_request`:

- **`httpLabel`** → a `{Name}` / greedy `{Name+}` URI path segment, percent-encoded
  per AWS rules (a non-greedy label encodes `/` as `%2F`, a greedy one keeps it);
- **`httpQuery`** → a query-string parameter (an `int` is `str(...)`-coerced; a
  string enum is carried as its plain wire string);
- **`httpHeader`** / **`httpPrefixHeaders`** → a request header / a header group
  sharing a name prefix;
- **payload** → the `httpPayload` member carried as the raw body (a `blob` as
  `application/octet-stream`, a `string` as `text/plain`, a derivable structure as
  `application/json`), otherwise the remaining "document" members serialized into
  a per-operation `@derive(Json)` `<Op>Document` struct and sent as the JSON body.

The input shape is emitted as a plain parameter-carrier struct (it is never
serialized whole). Operations with a non-bindable URI/query/header member
(timestamp, collection), a non-derivable document member, or an unsupported
payload are **skipped** with a documented reason — the same honest posture as the
awsJson derive gap. rest-json paginators thread the model's string token (e.g.
Lambda's `Marker` ← `NextMarker`) the same way, reusing the operation's own method
to build each signed request.

### The derive-collection gap

`@derive(Json)` does not serialize `list`/`map` fields yet (collections in derive
are a #346 follow-up). The generator handles this honestly rather than emitting
code that cannot compile:

- a structure whose members are **all** derive-serializable (scalars, `str`,
  `bytes`, `DateTime`, open enums, nested derivable structs) gets `@derive(Json)`;
- a structure that transitively contains a `list`/`map` member is emitted as a
  **plain struct** (full type fidelity, so the model is complete for #350) with a
  comment naming the blocking member(s);
- an operation whose **input** is non-derivable is **skipped** in the client with
  a documented note; derivable-input operations get a full method.

This mirrors the hand-written client, where flat shapes (e.g. `DescribeTable`)
ride `@derive(Json)` end to end and item/map operations were written by hand.

### Identifier escaping

Member / shape / operation / enum-value names that collide with Zap keywords or
are not valid identifiers are escaped deterministically (trailing `_`, leading
`_` for a leading digit, non-ident chars → `_`). When an escaped field name no
longer matches its wire name, the field carries a comment — the derive rename
hook (`@json(name=)`) is a #346 follow-up, so wire-name overrides are not yet
available.

## Usage

```bash
cargo run --release -- path/to/service-2.json -o out/client.zap
# or to stdout:
cargo run --release -- path/to/service-2.json
```

## Repo layout

```
src/            the generator (model parse, type resolution, emission)
models/         pinned botocore service-2.json + paginators-1.json fixtures (per service)
generated/      checked-in generated Zap, one dir per service (regenerated + diffed in CI)
vendor/         pinned aws-core runtime + per-service smoke mains for the compile gate
scripts/        compile_check.sh — best-effort bundle + run under the Zap image
tools/          verify_*.py — independent SigV4 oracles for the byte-diff goldens
tests/          regeneration / determinism / contract / byte-diff / paginator tests
tests/common/   shared host-only SigV4 signer + generated-source parsers (per-service gates)
tests/expected/ pinned golden request bytes for the byte-diff gates
```

Each service's client is regenerated from its pinned model and diffed in CI; the
build fails if any checked-in output drifts from the generator.

## Development / CI gate

A single required **CI gate** job runs:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --locked
cargo test --locked   # includes the byte-diff gates (tests/byte_diff.rs, tests/rest_byte_diff.rs, ...)
# regeneration determinism: every service's generated output must match what's checked in
cargo run -- models/dynamodb/2012-08-10/service-2.json -o /tmp/ddb.zap && diff /tmp/ddb.zap generated/dynamodb/dynamodb.zap
cargo run -- models/sqs/2012-11-05/service-2.json       -o /tmp/sqs.zap && diff /tmp/sqs.zap generated/sqs/sqs.zap
cargo run -- models/kinesis/2013-12-02/service-2.json   -o /tmp/kin.zap && diff /tmp/kin.zap generated/kinesis/kinesis.zap
cargo run -- models/lambda/2015-03-31/service-2.json    -o /tmp/lam.zap && diff /tmp/lam.zap generated/lambda/lambda.zap
# independent-oracle byte-diff: pinned goldens are genuine SigV4
python3 tools/verify_describe_table.py   # DynamoDB (#348)
python3 tools/verify_goldens.py          # SQS + Kinesis JSON services (#350)
python3 tools/verify_lambda_requests.py  # Lambda rest-json (#4; cross-checked vs botocore)
```

These are all **host-only** (no Zap toolchain / Docker). The byte-diff is proven
twice over, independently: `tests/byte_diff.rs` / `tests/sqs.rs` reconstruct the
signed request from the *generated source* with a Rust SigV4 signer, while the
`tools/verify_*.py` oracles recompute the same golden from scratch in Python — a
regression shows up in both.

A separate **non-blocking** job compiles each generated client under
`ghcr.io/zaplang-io/zap:latest` via `scripts/compile_check.sh`. It is non-blocking
because the published image lags the derive(Json) AWS hooks (#346); it turns green
once those land upstream. The generated client has been verified to compile and
run against a #346-enabled compiler.

## Provenance / license

The generator is Apache-2.0. The pinned `service-2.json` models are AWS's
botocore service models (Apache-2.0), with `documentation` fields stripped to keep
the fixtures small and structural. The `vendor/` runtime is pinned from
`zaplang-io/aws` (see `vendor/README.md`).
