#!/usr/bin/env python3
"""Bump the pinned botocore release across the three files that carry the pin.

botocore is the single upstream source of truth, pinned in ``models/manifest.json``
and mirrored into ``models/BOTOCORE_VERSION`` and ``tools/requirements.txt`` (which
``tools/sync-models.py`` asserts all agree). This script is the automation half of
the README "Bump all models" procedure: it finds the latest released botocore on
PyPI (or a version you name), resolves that release's canonical ``py3-none-any``
wheel SHA-256, and rewrites all three pin files in lockstep. It does NOT touch
``models/<svc>/`` or ``generated/`` — run ``tools/sync-models.py`` then
``make generate`` after this to refresh those; that is what the CI model-bump
workflow (.github/workflows/model-bump.yml) does.

    tools/bump-botocore.py                 # bump to the latest botocore on PyPI
    tools/bump-botocore.py --version X.Y.Z # bump to a specific release
    tools/bump-botocore.py --check         # report latest vs current; write nothing

Machine-readable results (``key=value`` lines) are written to stdout so a workflow
can append them to ``$GITHUB_OUTPUT``; all human diagnostics go to stderr. Pure
standard library -- no project or third-party dependencies (mirrors sync-models.py).

Emitted keys:
  changed            true if the pin moved (a new version was written), else false
  old_version        the botocore version that was pinned before this run
  new_version        the botocore version now pinned (== old_version when unchanged)
  botocore_major_bump  true if the botocore MAJOR component increased (semver signal)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "models" / "manifest.json"
BOTOCORE_VERSION_PATH = REPO_ROOT / "models" / "BOTOCORE_VERSION"
REQUIREMENTS_PATH = REPO_ROOT / "tools" / "requirements.txt"

# Same pinned-host endpoints sync-models.py uses; botocore is the only upstream.
PYPI_RELEASE = "https://pypi.org/pypi/botocore/json"
PYPI_VERSION = "https://pypi.org/pypi/botocore/{version}/json"


def die(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    sys.stderr.write(f"bump-botocore: error: {msg}\n")
    raise SystemExit(1)


def current_version() -> str:
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        manifest = json.load(f)
    version = manifest.get("botocore_version")
    if not version:
        die("models/manifest.json is missing 'botocore_version'")
    return version


def latest_version() -> str:
    """The newest final botocore release on PyPI (``info.version``)."""
    with urllib.request.urlopen(PYPI_RELEASE, timeout=60) as resp:  # noqa: S310 (pinned host)
        meta = json.load(resp)
    version = meta.get("info", {}).get("version")
    if not version:
        die("could not read info.version from the PyPI release metadata")
    return version


def wheel_sha256(version: str) -> str:
    """SHA-256 of the canonical ``-py3-none-any.whl`` for ``version`` on PyPI.

    Resolved from the PyPI-published digest and re-verified against the bytes, so
    a corrupted or tampered download can never silently set the new pin (the
    manifest hash is the trust anchor the hermetic build relies on).
    """
    url = PYPI_VERSION.format(version=version)
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 (pinned host)
        meta = json.load(resp)
    for entry in meta.get("urls", []):
        if entry.get("packagetype") == "bdist_wheel" and entry.get(
            "filename", ""
        ).endswith("-py3-none-any.whl"):
            published = entry.get("digests", {}).get("sha256", "")
            if not published:
                die(f"PyPI lists no sha256 digest for the botocore=={version} wheel")
            sys.stderr.write(f"bump-botocore: verifying {entry['url']}\n")
            with urllib.request.urlopen(entry["url"], timeout=120) as wresp:  # noqa: S310
                data = wresp.read()
            got = hashlib.sha256(data).hexdigest()
            if got != published:
                die(
                    f"botocore=={version} wheel sha256 mismatch\n"
                    f"  PyPI digest {published}\n"
                    f"  downloaded  {got}"
                )
            return got
    die(f"no py3-none-any wheel found on PyPI for botocore=={version}")


def major_of(version: str) -> int:
    try:
        return int(version.split(".", 1)[0])
    except ValueError:
        die(f"cannot parse a MAJOR component from botocore version {version!r}")


def rewrite_pins(old: str, new: str, old_sha: str, new_sha: str) -> None:
    """Rewrite the version/hash in all three pin files via targeted substitution.

    Deliberately string-substitution rather than json.load/dump so the manifest's
    hand-authored formatting (``_about`` prose, 2-space indent, key order) is left
    byte-for-byte untouched — only the two pinned values move.
    """
    manifest_text = MANIFEST_PATH.read_text(encoding="utf-8")
    old_ver_token = f'"botocore_version": "{old}"'
    old_sha_token = f'"wheel_sha256": "{old_sha}"'
    for token in (old_ver_token, old_sha_token):
        if token not in manifest_text:
            die(f"models/manifest.json does not contain expected token {token!r}")
    manifest_text = manifest_text.replace(
        old_ver_token, f'"botocore_version": "{new}"'
    ).replace(old_sha_token, f'"wheel_sha256": "{new_sha}"')
    MANIFEST_PATH.write_text(manifest_text, encoding="utf-8")

    BOTOCORE_VERSION_PATH.write_text(new + "\n", encoding="utf-8")

    req_text = REQUIREMENTS_PATH.read_text(encoding="utf-8")
    if f"botocore=={old}" not in req_text or old_sha not in req_text:
        die("tools/requirements.txt does not pin the current version/hash as expected")
    req_text = req_text.replace(f"botocore=={old}", f"botocore=={new}").replace(
        old_sha, new_sha
    )
    REQUIREMENTS_PATH.write_text(req_text, encoding="utf-8")


def current_sha() -> str:
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        return json.load(f)["wheel_sha256"]


def emit(changed: bool, old: str, new: str) -> None:
    print(f"changed={'true' if changed else 'false'}")
    print(f"old_version={old}")
    print(f"new_version={new}")
    print(
        "botocore_major_bump="
        f"{'true' if changed and major_of(new) > major_of(old) else 'false'}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--version",
        metavar="X.Y.Z",
        help="bump to this exact botocore release instead of the latest on PyPI",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report latest vs current and write nothing (exit 0 either way)",
    )
    args = parser.parse_args()

    old = current_version()
    target = args.version or latest_version()
    sys.stderr.write(f"bump-botocore: current={old} target={target}\n")

    if target == old:
        sys.stderr.write("bump-botocore: already on the target botocore; no change\n")
        emit(False, old, old)
        return 0

    if args.check:
        sys.stderr.write(
            f"bump-botocore: a bump to botocore=={target} is available "
            "(run without --check to apply)\n"
        )
        emit(True, old, target)
        return 0

    old_sha = current_sha()
    new_sha = wheel_sha256(target)
    rewrite_pins(old, target, old_sha, new_sha)
    sys.stderr.write(
        f"bump-botocore: pinned botocore=={target} (sha256 {new_sha}). "
        "Now run tools/sync-models.py and `make generate`.\n"
    )
    emit(True, old, target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
