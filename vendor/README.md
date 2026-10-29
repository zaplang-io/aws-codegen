# vendor/ — pinned aws-core runtime for the compile gate

These are **pinned copies** of the hand-written AWS SDK runtime from
[`zaplang-io/aws`](https://github.com/zaplang-io/aws) (`src/aws/`), used only so
`scripts/compile_check.sh` can bundle and run a generated client end to end:

| file           | role                                                                 |
| -------------- | -------------------------------------------------------------------- |
| `core.zap`     | protocol-agnostic runtime: SigV4 signer, Request/Response, transport |
| `endpoints.zap`| regional endpoint / host resolution (used by `core.zap`)             |
| `awsjson.zap`  | the awsJson 1.0/1.1 codec the generated client dispatches through    |
| `smoke_main.zap` | a tiny entry point exercising the generated derive-path surface    |

They are **not** a dependency of the Rust generator and are **not** how the
generated client ships. Wiring the generated output into the `aws` package is a
separate ticket (zaplang-io/zap#350); until then these copies let CI prove the
generated Zap compiles. Refresh them from `zaplang-io/aws` when its runtime
changes.
