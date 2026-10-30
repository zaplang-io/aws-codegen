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

## D-0003 — Model bumps are automated into a review-only PR (2026-10-30)

**Status:** accepted. Implements #363 on top of #6 (the pinned-botocore source of
truth + the `model-sync` drift check).

**Context.** botocore moves constantly; the "Bump all models" procedure
(README > Model sourcing) is mechanical — bump the pin in three files, re-run
`tools/sync-models.py`, `make generate`, review the diff — but doing it by hand
means it lags, and a stale pin silently ages the whole generated SDK. #6 already
made the pin a single declarative source of truth and added the drift guard; what
was missing was something to *propose* the bump on a schedule.

**Decision.** A scheduled GitHub Actions workflow
(`.github/workflows/model-bump.yml`, weekly cron + `workflow_dispatch`) prepares
the bump and opens a pull request for human review. It **never merges and never
auto-approves**; the maintainer merges aws-codegen PRs by hand (consistent with
D-0001 — the generated clients are the product, so a model bump is a product
change that gets reviewed).

- **The PR's own CI is the validator, not the bump workflow.** The workflow only
  produces the PR (bump the pin → `sync-models.py` → `make generate` → commit). The
  existing *CI gate* (determinism regen + byte-diff oracles) and the *model-sync
  drift check* run on the PR exactly as for a hand-made bump, so the automation
  needs no fidelity logic of its own and cannot wave a bad bump through.
- **Host-tooling only; no Docker.** Python (stdlib) + `cargo` (preinstalled on the
  runner) + `git`/`gh`. Raw `git`+`gh` rather than a third-party PR action, to keep
  the trust surface at zero new dependencies and the logic fully auditable in-repo.
  (Local Docker is off-limits on the maintainer's host, and the CI gate is
  deliberately hermetic — the bump workflow is the one extra place, alongside
  `model-sync`, that fetches botocore from the network.)
- **Idempotent and non-spammy.** A fixed branch `automation/botocore-bump`: a run
  with no new release, or one that yields no diff, opens nothing; a run whose bump
  already matches the open PR's branch leaves it untouched; otherwise the single PR
  is updated in place rather than a second being opened.
- **Conservative, advisory semver label.** `semver:{patch,minor,major}` inferred
  from the botocore version delta and whether any generated client changed (major =
  botocore MAJOR bumped; minor = a generated client's source moved; patch = only the
  models/pin moved). It errs toward "review carefully" and does not auto-distinguish
  additive from breaking API changes — the maintainer sets the real release semver.

**Pin mechanics.** `tools/bump-botocore.py` is the pin-mover: it resolves the latest
(or a named) botocore from PyPI, re-verifies the `py3-none-any` wheel SHA-256, and
rewrites `models/manifest.json` + `models/BOTOCORE_VERSION` + `tools/requirements.txt`
in lockstep (the same three files `sync-models.py` asserts agree). It touches neither
`models/<svc>/` nor `generated/`; the workflow runs `sync-models.py` and
`make generate` for those.

**CI-trigger caveat.** A PR created by the default `GITHUB_TOKEN` does not trigger
`pull_request` workflows. The workflow therefore uses an optional `MODEL_BUMP_TOKEN`
secret (PAT) when present so the bump PR's CI runs automatically, falling back to
`GITHUB_TOKEN` (maintainer re-runs CI once by hand) when it is not configured.

## D-0004 — Broad rollout to every supported-protocol service (2026-10-30)

**Status:** accepted. Implements #364 on top of the full protocol matrix
(awsJson/rest-json/rest-xml/query/ec2) and D-0001 (generated clients are the
product).

**Context.** With all five wire protocols supported and the byte-diff oracle in
place, the manifest still listed only 11 curated services. The generator is
mechanical per-service once a protocol is covered, so the remaining long tail was
unshipped only because it was not listed.

**Decision.** `models/manifest.json` lists **every botocore service on a protocol
the generator supports**, and the whole SDK is manifest-driven end to end.

- **Scope.** Every service in the pinned botocore snapshot whose
  `metadata.protocol` is `json`, `rest-json`, `rest-xml`, `query`, or `ec2` is
  manifested and generated — 410 services as of botocore 1.43.121. Services on an
  unsupported protocol (`smithy-rpc-v2-cbor`, 25 of them) are omitted entirely
  (#428). The pin is unchanged; existing services keep their originally pinned
  `api_version` (so e.g. CloudFront stays `2015-09-17`, not the latest), new
  services take the snapshot's latest.
- **Single source of truth.** `tools/manifest_services.py` prints the work list
  from the manifest; the Makefile `generate` target, the CI "generated output is
  current" step, and the `all_checked_in_packages_are_current` Rust test all
  consume it. Adding/removing a service is a one-line manifest edit — nothing else
  drifts. The package name/dir is the service name with `-`→`_` (a valid Zap
  identifier/module name); for pre-rollout services (no hyphen) this is a no-op, so
  their output is byte-identical.

**Skip policy (what lands vs. what is deferred).**

- **Per-operation skips are kept, not blockers.** The generator emits every
  operation it can serialize byte-faithfully and skips the rest with a documented
  reason in the client footer. A service that generates with *some* (or even zero)
  methods still ships its package — it is valid Zap (structs, enums, error set) and
  gains methods as the gaps close. 12,233 of 18,536 operations get a method;
  6,303 are skipped. The categorized long tail is tracked in #424–#427 (+ #428 for
  the excluded protocol); see `docs/coverage.md`.
- **A whole service is skipped only if it cannot generate at all** — an unsupported
  protocol, or a model the generator errors/panics on. In this rollout only the
  25 cbor services hit this (all 410 supported-protocol models generate cleanly);
  no broken package is committed.
- **Byte-diff goldens stay representative per protocol, not per service.** Each
  golden is an independently-validated SigV4 vector; the protocol codec + binding
  path is shared across every service of that protocol, so one clean golden per
  protocol already exercises the code every service of that protocol runs. Adding
  one per service would multiply fragile hand-authored vectors for no additional
  codec coverage and endanger the green gate, so the broad-rollout gate is:
  models-match-pin + byte-identical determinism of all generated output + the
  existing per-protocol oracles + (CI, best-effort) toolchain compile.

**Validation (host-only; Docker not run — it kernel-panics the maintainer's
host).** `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` (incl. the
byte-diff reconstructions and the all-packages determinism test), the Python SigV4
oracles, and the model-drift check all pass host-side. A current `zap` front-end
(`zap ir`) was run on a five-protocol sample and a parse-level sweep over all 410
clients: the only diagnostic is the tracked generators-as-methods limitation
(#429, paginator methods), which affects the pre-rollout clients equally and is
why the toolchain *compile* CI step is best-effort. The authoritative full
compile/byte-diff under the toolchain image is CI's job.

## D-0005 — smithy-rpc-v2-cbor is the sixth protocol; its codec is vendored, not pinned (2026-10-30)

**Status:** accepted. Implements #428 part 2 on top of D-0004 (broad rollout) and
D-0002 (generated clients are per-service zenv packages depending on `aws_core`).

**Context.** #364/D-0004 shipped every botocore service on the five supported
protocols and excluded the 25 `smithy-rpc-v2-cbor` services entirely (no manifest
entry, no package). #428 part 1 landed the hand-written `aws_core.cbor` codec (the
canonical CBOR wire format + rpc-v2 framing + SigV4-over-bytes + the byte-diff
oracle) in zaplang-io/aws (PR #18, merged to aws `main`). This decision wires the
generator to that codec and brings the 25 services online.

**Decision.** The generator emits a `smithy-rpc-v2-cbor` client like the awsJson
RPC path, but builds the body as a canonical CBOR data item and returns `bytes`.

- **Emitter.** `src/cborbody.rs` emits, per request-body shape, an explicit
  `def <shape>_to_cbor(<Shape> v) -> cbor.CborValue` that builds the value tree in
  model order and hands it to `cbor.cbor_encode`. There is no `@derive(Cbor)`, so
  *every* reachable body struct gets an explicit serializer (unlike the JSON
  derive fast path). Each operation method resolves the regional host + SigV4
  timestamp, calls `cbor.cbor_build_request` (POST to
  `/service/{targetPrefix}/operation/{Op}`) and signs over the CBOR bytes with
  `cbor.cbor_sign`. Fidelity is byte-matched to botocore's `RpcV2CBORSerializer`:
  structure = text-keyed map in model order with absent optional members omitted;
  `float`→single (ai 26) / `double`→double (ai 27) distinguished from the raw
  shape kind; tag-1 integer epoch timestamps; blobs as raw bytes. The URI service
  name is the model's `metadata.targetPrefix` (what botocore uses), not the
  serviceId. The generator reuses the codec and never reimplements the wire
  format. All 25 services generate with **810 operations, 0 skipped**.

- **The codec is VENDORED, not pinned as a dependency.** `aws_core.cbor` is copied
  into `vendor/aws_core/src/cbor.zap` (byte-identical to aws `main`), exactly like
  the other `aws_core` modules already here. aws-codegen does **not** take a
  versioned/commit-pinned dependency on zaplang-io/aws; D-0002 established that it
  keeps a *pinned in-repo snapshot* of the whole `aws_core` package under
  `vendor/`, so the repo stays hermetic (no sibling checkout, no network) for the
  byte-diff gate and the best-effort compile. Adding the CBOR codec therefore means
  refreshing that snapshot with the new module — the same mechanism used when any
  `aws_core` module changes. "Bumping the aws_core pin" is not an option today
  because there is no external pin: the vendored copy *is* the pin.

  - **Sync.** `vendor/README.md` already documents refreshing `vendor/aws_core`
    from zaplang-io/aws when the runtime changes; `cbor.zap` follows that rule. The
    vendored blob here matches aws `main` commit's `aws-core/src/cbor.zap`
    (verified by `git hash-object`). If the upstream codec changes, re-vendor.
  - **Follow-up (open question for the maintainer).** If/when aws-codegen moves to
    a real published/version-pinned `aws_core` dependency (a registry or git pin)
    instead of a vendored snapshot, that is a repo-wide change affecting *all*
    vendored modules, not cbor specifically — out of scope for #428. Flagged here
    so it is a deliberate choice, not an oversight.

**Validation (host-only; Docker not run — it kernel-panics the maintainer's
host, so the local LLVM-18 compile gate is skipped and CI is the sole
authoritative gate).** `cargo fmt --check`, `cargo clippy -D warnings`,
`cargo test` (incl. the new `tests/cbor_byte_diff.rs` reconstructions and the
all-packages determinism test over all 435 packages), the Python SigV4 oracles
(incl. the new `tools/verify_cbor_requests.py`, whose CBOR bodies are cross-checked
against the botocore-verified vectors from aws #428 part 1), and the model-drift
check all pass. A current `zap` front-end (`zap ir`, built from zaplang-io/zap
`main` which has the merged #429 generator-methods) type-checks the generated
Translate client cleanly; CloudWatch's only diagnostic is the pre-existing
`for … in sorted(dict.keys())` codegen limitation (`ZAP6001`) shared byte-for-byte
with every map-bearing generated client (e.g. Lambda), not a cbor regression.
Generated clients are not `zap fmt`-clean (none ever have been — CI does not gate
on it); the vendored hand-written `cbor.zap` *is* fmt-clean.
