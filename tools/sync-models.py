#!/usr/bin/env python3
"""Snapshot vendored AWS service models from a pinned botocore release.

botocore is the single upstream source of truth, pinned in ``models/manifest.json``.
This script extracts ONLY the services listed in that manifest into
``models/<service>/<api_version>/``, written deterministically so re-runs are
byte-stable. The generator then builds exclusively from the checked-in snapshot,
so ``cargo build`` and running the generator never need pip or the network.

Only this script touches botocore, and only when you run it explicitly:

    tools/sync-models.py               # sync in place (overwrites models/<svc>/)
    tools/sync-models.py --check       # verify models/ matches the pin (no writes)
    tools/sync-models.py --wheel PATH  # use a local botocore wheel (fully offline)

Pure standard library -- no project or third-party dependencies.

Deterministic format (matches the hand-curated snapshot byte-for-byte):
  * service-2.json  -- ``documentation`` keys stripped recursively (the generator
                       ignores them; stripping keeps the snapshot small), then
                       re-serialized with ``json.dumps(indent=1, ensure_ascii=False)``
                       preserving botocore's key order, with a trailing newline.
  * paginators-1.json -- copied verbatim from botocore (byte-identical).
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "models" / "manifest.json"
BOTOCORE_VERSION_PATH = REPO_ROOT / "models" / "BOTOCORE_VERSION"
REQUIREMENTS_PATH = REPO_ROOT / "tools" / "requirements.txt"
MODELS_DIR = REPO_ROOT / "models"

PYPI_JSON = "https://pypi.org/pypi/botocore/{version}/json"


def die(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    sys.stderr.write(f"sync-models: error: {msg}\n")
    raise SystemExit(1)


def load_manifest() -> dict:
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        manifest = json.load(f)
    for key in ("botocore_version", "wheel_sha256", "services"):
        if key not in manifest:
            die(f"models/manifest.json is missing required key {key!r}")
    return manifest


def check_pins_agree(version: str, sha256: str) -> None:
    """The version/hash live in a few files for different tools; keep them honest."""
    if BOTOCORE_VERSION_PATH.exists():
        pinned = BOTOCORE_VERSION_PATH.read_text(encoding="utf-8").strip()
        if pinned != version:
            die(
                f"models/BOTOCORE_VERSION ({pinned}) disagrees with "
                f"models/manifest.json botocore_version ({version})"
            )
    if REQUIREMENTS_PATH.exists():
        req = REQUIREMENTS_PATH.read_text(encoding="utf-8")
        if f"botocore=={version}" not in req:
            die(f"tools/requirements.txt does not pin botocore=={version}")
        if sha256 not in req:
            die("tools/requirements.txt hash disagrees with models/manifest.json wheel_sha256")


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def resolve_wheel_url(version: str) -> str:
    """Resolve the canonical py3-none-any wheel URL from the PyPI JSON API."""
    url = PYPI_JSON.format(version=version)
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 (pinned host)
        meta = json.load(resp)
    for entry in meta.get("urls", []):
        if entry.get("packagetype") == "bdist_wheel" and entry.get(
            "filename", ""
        ).endswith("-py3-none-any.whl"):
            return entry["url"]
    die(f"no py3-none-any wheel found on PyPI for botocore=={version}")


def fetch_wheel_bytes(version: str, expected_sha256: str, wheel_path: str | None) -> bytes:
    if wheel_path:
        data = Path(wheel_path).read_bytes()
        source = wheel_path
    else:
        wheel_url = resolve_wheel_url(version)
        sys.stderr.write(f"sync-models: downloading {wheel_url}\n")
        with urllib.request.urlopen(wheel_url, timeout=120) as resp:  # noqa: S310
            data = resp.read()
        source = wheel_url
    got = sha256_of(data)
    if got != expected_sha256:
        die(
            f"botocore wheel sha256 mismatch from {source}\n"
            f"  expected {expected_sha256}\n"
            f"  got      {got}"
        )
    return data


def strip_documentation(obj):
    """Recursively drop every ``documentation`` key, preserving order elsewhere."""
    if isinstance(obj, dict):
        return {
            k: strip_documentation(v) for k, v in obj.items() if k != "documentation"
        }
    if isinstance(obj, list):
        return [strip_documentation(v) for v in obj]
    return obj


def render_service_2(raw_gz: bytes) -> bytes:
    model = json.loads(gzip.decompress(raw_gz))
    stripped = strip_documentation(model)
    text = json.dumps(stripped, indent=1, ensure_ascii=False) + "\n"
    return text.encode("utf-8")


def extract_service(zf: zipfile.ZipFile, service: str, api_version: str) -> dict[str, bytes]:
    """Return the deterministic {relative_path: bytes} snapshot for one service."""
    base = f"botocore/data/{service}/{api_version}"
    try:
        svc_gz = zf.read(f"{base}/service-2.json.gz")
    except KeyError:
        die(
            f"botocore has no {base}/service-2.json.gz "
            f"(check the service/api_version in models/manifest.json)"
        )
    out = {"service-2.json": render_service_2(svc_gz)}
    try:
        out["paginators-1.json"] = zf.read(f"{base}/paginators-1.json")
    except KeyError:
        sys.stderr.write(
            f"sync-models: note: {service} {api_version} has no paginators-1.json upstream; skipping\n"
        )
    return out


def write_snapshot(service: str, api_version: str, files: dict[str, bytes]) -> None:
    out_dir = MODELS_DIR / service / api_version
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (out_dir / name).write_bytes(data)


def check_snapshot(service: str, api_version: str, files: dict[str, bytes]) -> list[str]:
    out_dir = MODELS_DIR / service / api_version
    problems = []
    for name, data in files.items():
        path = out_dir / name
        if not path.exists():
            problems.append(f"{path.relative_to(REPO_ROOT)} is missing")
        elif path.read_bytes() != data:
            problems.append(f"{path.relative_to(REPO_ROOT)} is stale")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify models/ already matches the pin; make no changes, exit 1 on drift",
    )
    parser.add_argument(
        "--wheel",
        metavar="PATH",
        help="use a local botocore wheel instead of downloading (offline)",
    )
    args = parser.parse_args()

    manifest = load_manifest()
    version = manifest["botocore_version"]
    sha256 = manifest["wheel_sha256"]
    services = manifest["services"]
    check_pins_agree(version, sha256)

    wheel_bytes = fetch_wheel_bytes(version, sha256, args.wheel)
    zf = zipfile.ZipFile(io.BytesIO(wheel_bytes))

    sys.stderr.write(f"sync-models: botocore=={version} (sha256 ok), {len(services)} service(s)\n")

    all_problems: list[str] = []
    for entry in services:
        service = entry["service"]
        api_version = entry["api_version"]
        files = extract_service(zf, service, api_version)
        if args.check:
            problems = check_snapshot(service, api_version, files)
            all_problems.extend(problems)
            status = "DRIFT" if problems else "ok"
            sys.stderr.write(f"sync-models:   [{status}] {service} {api_version}\n")
        else:
            write_snapshot(service, api_version, files)
            sys.stderr.write(f"sync-models:   wrote {service} {api_version}\n")

    if args.check:
        if all_problems:
            sys.stderr.write("\nsync-models: models/ is out of sync with the pin:\n")
            for p in all_problems:
                sys.stderr.write(f"  - {p}\n")
            sys.stderr.write(
                "\nRerun `tools/sync-models.py` and commit the result.\n"
            )
            return 1
        sys.stderr.write("sync-models: models/ matches the pin\n")
    else:
        sys.stderr.write(
            "sync-models: done. Review `git diff -- models/` and regenerate clients.\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
