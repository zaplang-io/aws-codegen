# vendor/ — pinned aws-core runtime for the compile gate

These are **pinned copies** of the hand-written AWS SDK runtime from
[`zaplang-io/aws`](https://github.com/zaplang-io/aws) (`src/aws/`), used only so
`scripts/compile_check.sh` can bundle and run a generated client end to end:

| file           | role                                                                 |
| -------------- | -------------------------------------------------------------------- |
| `core.zap`     | protocol-agnostic runtime: SigV4 signer, Request/Response, transport |
| `endpoints.zap`| regional endpoint / host resolution (used by `core.zap`)             |
| `awsjson.zap`  | the awsJson 1.0/1.1 codec the generated client dispatches through    |
| `binding.zap`  | the protocol-agnostic HTTP binding layer (httpLabel/Query/Header/…)  |
| `restjson.zap` | the rest-json (restJson1) codec, a JSON body atop `binding.zap`       |
| `restxml.zap`  | the rest-xml codec, an XML body atop `binding.zap` (zaplang-io/aws#352) |
| `query.zap`    | the query + ec2 codec: a form body + XML response (zaplang-io/aws#353)  |
| `smoke_main.zap` | a tiny entry point exercising the generated derive-path surface    |

`binding.zap` + `restjson.zap` are the rest-json half (zaplang-io/aws #345, merged
on `aws` main); the generated rest-json client (e.g. `generated/lambda`) builds an
`HttpBinding` and dispatches through `rest_json_request` / `rest_json_sign`.
`restxml.zap` (#352) is the same binding layer with an XML document body from the
`rest_xml_*` helpers (`generated/cloudfront`); `query.zap` (#353) is the query/ec2
half — a flat form body with no URI binding (`generated/sdb`, `generated/ec2`).
Both are merged on `aws` main.

They are **not** a dependency of the Rust generator and are **not** how the
generated client ships. Wiring the generated output into the `aws` package is a
separate ticket (zaplang-io/zap#350); until then these copies let CI prove the
generated Zap compiles. Refresh them from `zaplang-io/aws` when its runtime
changes.
