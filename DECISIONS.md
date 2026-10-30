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
