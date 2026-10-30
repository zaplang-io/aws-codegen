# vendor/ — pinned aws_core package for the compile gate

`vendor/aws_core/` is a **pinned copy** of the hand-written `aws_core` zenv
package from [`zaplang-io/aws`](https://github.com/zaplang-io/aws)
(`aws-core/`, shipped by #339 step 1): its `zap.toml` + `src/*.zap` runtime and
protocol codecs. aws-codegen does not host aws_core; it keeps this snapshot so
the repo stays hermetic (no sibling checkout) and the best-effort compile gate
can resolve the dependency.

Since #339 step 2 the generated clients are per-service **zenv packages** that
`import aws_core.<module>` their codecs via real module imports
(zaplang-io/zap#283) — the `tools/bundle.py`-style concatenation of loose
`vendor/*.zap` ahead of the client is **retired**. `scripts/compile_check.sh`
and `scripts/byte_diff_check.sh` now materialize a throwaway consumer project
with path dependencies on a generated `generated/<svc>/` package and this
`vendor/aws_core`, run `zap zenv create`, and execute a smoke entry.

| path                      | role                                                              |
| ------------------------- | ----------------------------------------------------------------- |
| `aws_core/zap.toml`       | the pinned package manifest (`[package] name = "aws_core"`)        |
| `aws_core/src/core.zap`   | protocol-agnostic runtime: SigV4 signer, Request/Response, transport |
| `aws_core/src/endpoints.zap` | regional endpoint / host resolution (`regional_host`, `Endpoint`) |
| `aws_core/src/awsjson.zap`| the awsJson 1.0/1.1 codec                                          |
| `aws_core/src/binding.zap`| the protocol-agnostic HTTP binding layer (httpLabel/Query/Header/…) |
| `aws_core/src/restjson.zap` | the rest-json (restJson1) codec, a JSON body atop `binding.zap`   |
| `aws_core/src/restxml.zap`| the rest-xml codec, an XML body atop `binding.zap`                 |
| `aws_core/src/query.zap`  | the query + ec2 codec: a form body + XML response                 |
| `aws_core/src/{credentials,retry,s3,dynamodb,aws_core}.zap` | the rest of the pinned package (not all imported by every client) |
| `smoke_main.zap` / `smoke_sqs_main.zap` / `smoke_kinesis_main.zap` | consumer smoke entries (import the service package + aws_core) |

The generated client ships the per-service `generated/<svc>/` packages; this
pinned copy is **not** a dependency of the Rust generator and is **not** how the
SDK ships. Refresh it from `zaplang-io/aws` (`aws-core/`) when that runtime
changes.
