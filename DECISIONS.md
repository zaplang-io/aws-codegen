# Decisions

Durable architectural decisions for `aws-codegen`. Each entry is append-only:
once recorded it stays, superseded rather than edited, so the history of why the
repo looks the way it does is legible from here alone.

## D-0001 — Generated clients are the product (2026-10-29)

**Status:** accepted.

**Context.** The Zap AWS SDK began as hand-written service clients on top of the
hand-written `aws.core` runtime and protocol codecs (`zaplang-io/aws`). In
parallel, `aws-codegen` grew into a model-driven generator that emits clients
from AWS's own botocore `service-2.json` models across every major protocol —
awsJson 1.0/1.1 (#347), rest-json (#4), and the XML family: rest-xml + query +
ec2 (#354). Once the generator covers a protocol, maintaining a second,
hand-written client for a service in that protocol is duplicated effort that can
only drift from the models.

**Decision.** The **generated** clients are the shipping SDK — the product.

- The generator (this repo) is the single source of truth for every client. CI
  regenerates each checked-in client from its pinned model and fails on any
  drift; no client is hand-edited.
- The hand-written code in `zaplang-io/aws` — `aws.core` (SigV4, transport,
  `Request`/`Response`) and the protocol **codecs** (`awsjson`, `restjson`,
  `restxml`, `query`) — remains, but only in two roles: (1) the runtime the
  generated clients ride on, and (2) the **byte-diff oracle**. Every generated
  request is diffed, byte-for-byte, against what the hand-written codec produces
  for the same input (reproduced a third time by an independent Python SigV4
  oracle), so the codecs pin wire fidelity without being shipped as clients.
- Hand-written **service** clients retire as generated equivalents land. A
  hand-written `s3.zap`, `sts.zap`, etc. is removed once the generator emits a
  byte-diff-verified client for that service; there is no hand-written client to
  retire where none existed.

**First application.** STS (#355) is the first service to land under this
policy: there is no hand-written STS client — the generated
`generated/sts/sts.zap` is the client, byte-diffed against the `aws.query` codec
oracle. S3 (#356) follows and additionally retires the existing hand-written
`s3.zap`.

**Consequences.** New AWS service coverage is added by listing the service in
`models/manifest.json`, syncing its pinned model, and letting the generator emit
and byte-diff it — not by writing a client. The codecs are maintained for wire
correctness and as the oracle, not as a client surface.

## D-0002 — Generated clients are per-service zenv packages (2026-10-30)

**Status:** accepted. Implements #339 step 2 on top of step 1 (zaplang-io/aws#11,
`aws_core` as a zenv package).

**Context.** Until now a generated client was a single `generated/<svc>/<svc>.zap`
that assumed the `aws.core`/codec runtime was concatenated ahead of it (the
`tools/bundle.py` crutch; `scripts/compile_check.sh` did the `cat`). Step 1 made
the hand-written runtime ship as the `aws_core` zenv package, importable via real
Zap-to-Zap module imports (zaplang-io/zap#283). The generated clients — the
shipping SDK (D-0001) — should consume it the same way, not by bundling.

**Decision.** The generator emits each service as its own **zenv package**:

- Layout `generated/<svc>/{zap.toml, src/<svc>.zap}` (mirrors step 1's
  `aws-core/`). The CLI mode is `aws-codegen <model> --package <dir> --name <pkg>`;
  `zap.toml` is `emit::package_manifest(name)`, deterministic and CI-diffed like
  the client source. The package root module is `src/<pkg>.zap` (D-0081).
- The client `import aws_core.<module>`s its runtime/codecs and calls them via
  the bound leaf name — `core.Credentials`, `endpoints.regional_host`,
  `query.query_params`, `restxml.rest_xml_scalar`, `awsjson.awsjson_request_now`,
  etc. A dotted dependency import binds the leaf, so the call form matches how the
  codecs reference each other internally. #283 has no `from x import y`, so every
  reference is module-qualified. The import set per client is precise (only the
  modules it references; `endpoints` joins the awsJson set only when a paginator
  is generated).
- Host resolution lives under `endpoints.*` and the `Endpoint` type under
  `endpoints` (the step-1 core↔endpoints cycle break). A service that itself
  models a shape named `Credentials` (STS) or `Endpoint` (SNS, DynamoDB) keeps
  that shape as a local, bare type; the aws_core type is reached only through its
  module qualifier, so the two never collide (this also retires a latent
  duplicate-definition from the old concat).
- `aws_core` is referenced as an in-repo **path dependency**,
  `{ path = "../../vendor/aws_core" }`. `vendor/` is reshaped from loose pinned
  codec copies into a pinned copy of the whole `aws_core` package
  (`vendor/aws_core/{zap.toml,src/*.zap}`), so aws-codegen CI stays hermetic and
  the best-effort compile/byte-diff gates can `zap zenv create` + run a consumer.
  The `tools/bundle.py`-style concatenation is retired.

**No serialization change.** This is a packaging/import restructure only. The
byte-diff oracle (the Rust reconstructions + the independent Python SigV4 oracles)
is untouched and still passes for every service; the only generated-output change
is module-qualified call sites (and the `emit_hoisted` 88-column rule now hoisting
a few calls whose qualified prefix crosses the width — still canonical by
construction).
