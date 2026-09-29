#!/usr/bin/env python3
"""Generate a trusted starter-kit provenance manifest from the monorepo kit.

Source review trusts a submitted file only when its exact path and SHA-256
appear in one of ``ditto_screener/data/starter-kit-provenance-v<N>.json``.
After a ``miners/dittobench-starter-kit`` change is committed, add the next
manifest from the repository root (``regenerate_command`` prints the exact
line) and commit it with the kit change. Never edit or delete a published
manifest: older honest derivatives must keep matching exactly.

``tests/test_starter_provenance_current.py`` fails until the newest manifest
equals the kit's tracked, submittable regular files.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

ORIGIN = "ditto-assistant/ditto-subnet/miners/dittobench-starter-kit"
MANIFEST_VERSION = 1
MANIFEST_GLOB = "starter-kit-provenance-v*.json"
STARTER_DIR = "miners/dittobench-starter-kit"
MANIFEST_DIR = "workers/screener/ditto_screener/data"

_MANIFEST_NAME = re.compile(r"starter-kit-provenance-v([1-9][0-9]*)\.json")
# Git index modes for regular files. Symlinks (120000) and submodules (160000)
# are never trusted: the tracked ``.agents``/``.claude`` skill links point
# outside the kit, and a submission never carries them as regular files.
_REGULAR_FILE_MODES = frozenset({"100644", "100755"})
# Mirror the starter ``submit`` archive excludes (#2395) exactly, so a manifest
# never trusts local state, secrets, build output, or development skills that
# an honest submission does not contain, and never drops a file it does
# contain (``*.tar`` is packaged, so it stays). Like ``tar --exclude``, every
# path component is checked.
_EXCLUDED_COMPONENTS = frozenset({".agents", ".claude", ".git", "target"})
_EXCLUDED_PATTERNS = (".env", ".env.*", "*.db", "*.db-*", "*.tgz")
_COMMITTED_TEMPLATES = frozenset({".env.example"})


def is_submittable(relative: str) -> bool:
    """Return whether a kit-relative path can appear in an honest submission."""
    for part in PurePosixPath(relative).parts:
        if part in _EXCLUDED_COMPONENTS:
            return False
        if part not in _COMMITTED_TEMPLATES and any(
            fnmatch.fnmatchcase(part, pattern) for pattern in _EXCLUDED_PATTERNS
        ):
            return False
    return True


def _git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.run(
            ["git", *args], cwd=root, check=True, capture_output=True
        ).stdout
    except subprocess.CalledProcessError as error:
        detail = error.stderr.decode(errors="replace").strip()
        raise RuntimeError(
            f"starter provenance needs a Git checkout of {root}: {detail}"
        ) from error
    except OSError as error:
        raise RuntimeError(f"starter provenance needs Git: {error}") from error


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def starter_files(root: Path) -> dict[str, str]:
    """Map each tracked, submittable regular kit file to its working-tree sha256.

    Only Git-tracked paths are considered, so untracked build output such as a
    local ``target/`` directory can never enter or break the manifest. A
    tracked path that is missing or no longer a regular file in the working
    tree is left out, which the drift guard reports as removed.
    """
    files: dict[str, str] = {}
    for record in _git(root, "ls-files", "--stage", "-z", "--", ".").split(b"\0"):
        if not record:
            continue
        metadata, _, raw_path = record.partition(b"\t")
        mode, _object, stage = metadata.decode("ascii").split(" ")
        if stage != "0":
            raise RuntimeError("resolve starter-kit merge conflicts first")
        relative = raw_path.decode("utf-8")
        if mode not in _REGULAR_FILE_MODES or not is_submittable(relative):
            continue
        path = root / relative
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                continue
        except FileNotFoundError:
            continue
        files[relative] = _sha256(path)
    return dict(sorted(files.items()))


def starter_revision(root: Path) -> str:
    """Return the last commit that touched the kit, refusing uncommitted edits.

    Pinning the kit's own last commit instead of repository ``HEAD`` keeps a
    rerun byte-identical until the kit itself changes.
    """
    if _git(root, "status", "--porcelain", "--untracked-files=no", "--", "."):
        raise RuntimeError("commit starter-kit changes before generating provenance")
    revision = _git(root, "log", "-1", "--format=%H", "--", ".").decode().strip()
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise RuntimeError("starter revision is not a full Git SHA")
    return revision


def build_manifest(root: Path) -> dict[str, object]:
    return {
        "files": starter_files(root),
        "origin": ORIGIN,
        "revision": starter_revision(root),
        "version": MANIFEST_VERSION,
    }


def render_manifest(payload: dict[str, object]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def manifest_number(path: Path) -> int:
    match = _MANIFEST_NAME.fullmatch(path.name)
    if match is None:
        raise ValueError(f"unexpected starter manifest name: {path.name}")
    return int(match.group(1))


def newest_manifest(directory: Path) -> Path:
    """Return the highest-numbered manifest; numeric, so v10 follows v9."""
    manifests = sorted(directory.glob(MANIFEST_GLOB), key=manifest_number)
    if not manifests:
        raise FileNotFoundError(f"no starter provenance manifest in {directory}")
    return manifests[-1]


def regenerate_command(version: int) -> str:
    return (
        "python workers/screener/scripts/generate_starter_provenance.py "
        f"--starter-dir {STARTER_DIR} "
        f"--output {MANIFEST_DIR}/starter-kit-provenance-v{version}.json"
    )


def manifest_drift(
    expected: dict[str, str], actual: dict[str, str]
) -> dict[str, list[str]]:
    """Exact path+digest delta between a manifest and the kit; empty if equal."""
    drift = {
        "modified": sorted(
            path
            for path in expected.keys() & actual.keys()
            if expected[path] != actual[path]
        ),
        "added": sorted(actual.keys() - expected.keys()),
        "removed": sorted(expected.keys() - actual.keys()),
    }
    return {kind: paths for kind, paths in drift.items() if paths}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a starter-kit provenance manifest."
    )
    parser.add_argument("--starter-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    rendered = render_manifest(build_manifest(args.starter_dir.resolve()))
    if args.output.exists() and args.output.read_text() != rendered:
        # A published manifest is an append-only trust anchor for older
        # derivatives; a kit change always gets the next version number.
        print(
            f"refusing to rewrite {args.output}; write the next manifest version",
            file=sys.stderr,
        )
        return 1
    args.output.write_text(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
