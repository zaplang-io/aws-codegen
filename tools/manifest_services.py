#!/usr/bin/env python3
"""Print the generator's work list from ``models/manifest.json`` — the single
source of truth for which services are generated (#364 broad rollout).

Each line is three tab-separated fields:

    <service>\t<api_version>\t<package>

where ``service``/``api_version`` locate the pinned model under
``models/<service>/<api_version>/service-2.json`` and ``package`` is the zenv
package name + ``generated/<package>/`` directory. The package is the service
name with ``-`` mapped to ``_`` so it is a valid Zap identifier/module name
(``application-autoscaling`` -> ``application_autoscaling``); for the services
that have no hyphen (every client that predates the broad rollout) the two are
identical, so this is a no-op for them.

The Makefile ``generate`` target, the CI "generated output is current" step, and
the Rust determinism test all consume this list, so adding or removing a service
is a one-line manifest edit and nothing else drifts.

Pure standard library; reads only the checked-in manifest (no network).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

MANIFEST = Path(__file__).resolve().parent.parent / "models" / "manifest.json"


def package_name(service: str) -> str:
    """Map a botocore service name to a valid Zap package/module identifier."""
    return service.replace("-", "_")


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    out = []
    for entry in manifest["services"]:
        svc = entry["service"]
        ver = entry["api_version"]
        out.append(f"{svc}\t{ver}\t{package_name(svc)}")
    sys.stdout.write("\n".join(out) + ("\n" if out else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
