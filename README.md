# aws-codegen

Model-driven code generator: botocore `service-2.json` → Zap AWS SDK clients.

`aws-codegen` is the engine behind the Zap AWS broad-coverage program
([zaplang-io/zap#366](https://github.com/zaplang-io/zap/issues/366)). It reads
AWS's own service models and emits a Zap client that rides on the hand-written
`aws.core` runtime and protocol codecs (`zaplang-io/aws`).

**v0 scope** ([zaplang-io/zap#347](https://github.com/zaplang-io/zap/issues/347)):
the **awsJson** protocol, with **DynamoDB** as the proof. rest-json / rest-xml /
query protocols and wiring the output into the `aws` package are later tickets
(#345/#350 and friends).

## What it generates

Given a `service-2.json`, the generator emits one Zap file containing:

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
models/         pinned botocore service-2.json fixtures (docs stripped)
generated/      checked-in generated Zap (regenerated + diffed in CI)
vendor/         pinned aws-core runtime for the compile gate (see vendor/README)
scripts/        compile_check.sh — best-effort bundle + run under the Zap image
tests/          regeneration / determinism / contract tests
```

The checked-in DynamoDB client lives at
[`generated/dynamodb/dynamodb.zap`](generated/dynamodb/dynamodb.zap); its model
is [`models/dynamodb/2012-08-10/service-2.json`](models/dynamodb/2012-08-10/service-2.json).
CI fails if the checked-in output drifts from the generator.

## Development / CI gate

A single required **CI gate** job runs:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --locked
cargo test --locked
# regeneration determinism: generated output must match what's checked in
cargo run -- models/dynamodb/2012-08-10/service-2.json -o /tmp/ddb.zap && diff /tmp/ddb.zap generated/dynamodb/dynamodb.zap
```

A separate **non-blocking** job compiles the generated Zap under
`ghcr.io/zaplang-io/zap:latest` via `scripts/compile_check.sh`. It is non-blocking
because the published image lags the derive(Json) AWS hooks (#346); it turns green
once those land upstream. The generated client has been verified to compile and
run against a #346-enabled compiler.

## Provenance / license

The generator is Apache-2.0. The pinned `service-2.json` models are AWS's
botocore service models (Apache-2.0), with `documentation` fields stripped to keep
the fixtures small and structural. The `vendor/` runtime is pinned from
`zaplang-io/aws` (see `vendor/README.md`).
