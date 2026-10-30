#!/usr/bin/env bash
# End-to-end byte-diff gate for the GENERATED DynamoDB client (#348).
#
# #339 step 2 retired the vendor/*.zap concatenation. This materializes a
# consumer zenv project depending on the generated `dynamodb` package + the
# pinned in-repo aws_core package (vendor/aws_core), runs
# tests/describe_table_byte_diff.main.zap as src/main.zap under the Zap compiler
# image, and diffs the serialized DescribeTable request against the golden
# tests/expected/dynamodb_describe_table.http.
#
# Usage:  scripts/byte_diff_check.sh [service]
#   service     a dir name under generated/ (default: dynamodb)
#   ZAP_IMAGE   compiler image (default ghcr.io/zaplang-io/zap:latest)
#
# NOTE: like scripts/compile_check.sh, this needs the derive(Json) AWS hooks
# (zaplang-io/zap#346) in the published image to run the full generated file;
# until that lands, CI runs this step non-blocking. The host-only, toolchain-free
# halves of the gate — tests/byte_diff.rs (cargo test) and
# tools/verify_describe_table.py — fail CI on a generator/fixture regression in
# the meantime.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
service="${1:-dynamodb}"
golden="$root/tests/expected/dynamodb_describe_table.http"
image="${ZAP_IMAGE:-ghcr.io/zaplang-io/zap:latest}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/consumer/src"
cp "$root/tests/describe_table_byte_diff.main.zap" "$work/consumer/src/main.zap"
cat > "$work/consumer/zap.toml" <<TOML
[package]
name = "byte_diff_$service"
version = "0.0.0"

[dependencies]
aws_core = { path = "$root/vendor/aws_core" }
$service = { path = "$root/generated/$service" }
TOML

echo "byte_diff_check: consumer byte_diff_$service -> zenv create + run under $image"
got="$(docker run --rm -v "$work/consumer":/w -w /w "$image" \
  bash -lc 'zap zenv create && source zenv/activate && zap run src/main.zap')"

# The Zap program prints the request with a single trailing newline (print());
# the golden is the raw request bytes with none. Accept either framing, exactly
# as the aws repo's tools/run-tests.sh does.
if diff <(printf '%s' "$got") "$golden" >/dev/null 2>&1 \
    || diff <(printf '%s\n' "$got") "$golden" >/dev/null 2>&1; then
    echo "byte_diff_check: generated DescribeTable request is byte-identical to the golden"
else
    echo "::error::generated DescribeTable request differs from tests/expected/dynamodb_describe_table.http" >&2
    diff <(printf '%s\n' "$got") "$golden" >&2 || true
    exit 1
fi
