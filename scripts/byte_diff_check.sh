#!/usr/bin/env bash
# End-to-end byte-diff gate for the GENERATED DynamoDB client (#348).
#
# Bundles the pinned aws.core / aws.endpoints / aws.awsjson runtime (vendor/)
# ahead of the generated client and tests/describe_table_byte_diff.main.zap — the
# same concatenation convention scripts/compile_check.sh and the aws repo's
# tools/bundle.py use (there is no `import` yet) — runs it under the Zap compiler
# image, and diffs the serialized DescribeTable request against the golden
# tests/expected/dynamodb_describe_table.http.
#
# Usage:  scripts/byte_diff_check.sh [generated.zap]
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
generated="${1:-$root/generated/dynamodb/dynamodb.zap}"
golden="$root/tests/expected/dynamodb_describe_table.http"
image="${ZAP_IMAGE:-ghcr.io/zaplang-io/zap:latest}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
bundle="$work/bundle.zap"

# Order matters: runtime first, then the generated client, then the byte-diff.
cat \
  "$root/vendor/core.zap" \
  "$root/vendor/endpoints.zap" \
  "$root/vendor/awsjson.zap" \
  "$generated" \
  "$root/tests/describe_table_byte_diff.main.zap" \
  > "$bundle"

echo "byte_diff_check: bundled $(wc -l < "$bundle") lines -> running under $image"
got="$(docker run --rm -v "$work":/w -w /w "$image" zap run bundle.zap)"

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
