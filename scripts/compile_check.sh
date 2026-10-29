#!/usr/bin/env bash
# Best-effort compile/run gate for the GENERATED Zap client.
#
# Bundles the pinned aws.core / aws.endpoints / aws.awsjson runtime (vendor/)
# ahead of a generated client and a smoke `main` (vendor/smoke_main.zap), the
# same concatenation convention the aws repo's tools/bundle.py uses (there is no
# `import` yet), then runs it under the Zap compiler image.
#
# Usage:  scripts/compile_check.sh [generated.zap] [smoke_main.zap]
#   ZAP_IMAGE   compiler image (default ghcr.io/zaplang-io/zap:latest)
# Defaults to the DynamoDB client + its smoke entry; pass a service's generated
# file and matching smoke (e.g. generated/sqs/sqs.zap vendor/smoke_sqs_main.zap).
#
# NOTE: this needs the derive(Json) AWS hooks (zaplang-io/zap#346:
# @json(open) enums, @json(timestamp), bytes-as-base64). Until that lands in the
# published image this step is expected to fail on @json; CI runs it
# non-blocking so the gate stays green in the meantime.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
generated="${1:-$root/generated/dynamodb/dynamodb.zap}"
smoke="${2:-$root/vendor/smoke_main.zap}"
image="${ZAP_IMAGE:-ghcr.io/zaplang-io/zap:latest}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
bundle="$work/bundle.zap"

# Order matters: runtime first, then the generated client, then the entry point.
cat \
  "$root/vendor/core.zap" \
  "$root/vendor/endpoints.zap" \
  "$root/vendor/awsjson.zap" \
  "$generated" \
  "$smoke" \
  > "$bundle"

echo "compile_check: bundled $(wc -l < "$bundle") lines -> running under $image"
docker run --rm -v "$work":/w -w /w "$image" zap run bundle.zap
