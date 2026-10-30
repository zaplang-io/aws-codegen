#!/usr/bin/env bash
# Best-effort compile/run gate for a GENERATED Zap service PACKAGE.
#
# #339 step 2 retired the tools/bundle.py-style concatenation (vendor/*.zap cat
# ahead of the client). The generated client is now a real zenv package that
# `import aws_core.<module>`s its runtime + codecs (zaplang-io/zap#283). This
# script materializes a throwaway consumer project that depends on BOTH the
# service package and the pinned in-repo aws_core copy (vendor/aws_core), creates
# the zenv, and runs a smoke `main` under the Zap compiler image.
#
# Usage:  scripts/compile_check.sh [service] [smoke_main.zap]
#   service      a dir name under generated/ (default: dynamodb)
#   smoke_main   the entry to run as src/main.zap (default: vendor/smoke_main.zap)
#   ZAP_IMAGE    compiler image (default ghcr.io/zaplang-io/zap:latest)
#
# NOTE: this needs the derive(Json) AWS hooks (zaplang-io/zap#346:
# @json(open) enums, @json(timestamp), bytes-as-base64). Until that lands in the
# published image this step is expected to fail on @json; CI runs it
# non-blocking so the gate stays green in the meantime.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
service="${1:-dynamodb}"
smoke="${2:-$root/vendor/smoke_main.zap}"
image="${ZAP_IMAGE:-ghcr.io/zaplang-io/zap:latest}"

if [ ! -f "$root/generated/$service/zap.toml" ]; then
  echo "compile_check: no generated package at generated/$service" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A consumer project: path deps on the service package + the pinned aws_core.
mkdir -p "$work/consumer/src"
cp "$smoke" "$work/consumer/src/main.zap"
cat > "$work/consumer/zap.toml" <<TOML
[package]
name = "smoke_$service"
version = "0.0.0"

[dependencies]
aws_core = { path = "$root/vendor/aws_core" }
$service = { path = "$root/generated/$service" }
TOML

echo "compile_check: consumer smoke_$service -> zenv create + run under $image"
docker run --rm -v "$work/consumer":/w -w /w "$image" \
  bash -lc 'zap zenv create && source zenv/activate && zap run src/main.zap'
