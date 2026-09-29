"""Keep the newest trusted starter manifest equal to the monorepo starter kit.

Source review exempts exact ``path + sha256`` starter matches from scrutiny and
attributes everything else to the miner. A stale manifest therefore makes an
unmodified kit look miner-authored, so every kit change must ship with the next
manifest version.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ditto_screener.source_review import _load_provenance_manifest
from scripts.generate_starter_provenance import (
    ORIGIN,
    manifest_drift,
    manifest_number,
    newest_manifest,
    regenerate_command,
    starter_files,
)

SCREENER_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = SCREENER_ROOT.parents[1]
STARTER_KIT = REPOSITORY_ROOT / "miners" / "dittobench-starter-kit"
MANIFEST_DIR = SCREENER_ROOT / "ditto_screener" / "data"
GENERATOR = SCREENER_ROOT / "scripts" / "generate_starter_provenance.py"


def starter_drift_failure(kit: Path, manifest: Path) -> str | None:
    """Explain how ``manifest`` differs from ``kit``, or return None if exact."""
    expected = json.loads(manifest.read_text())["files"]
    drift = manifest_drift(expected, starter_files(kit))
    if not drift:
        return None
    details = "; ".join(f"{kind}: {', '.join(paths)}" for kind, paths in drift.items())
    return (
        f"{manifest.name} does not match {kit.name} ({details}). Screener "
        "reviewers would attribute these first-party kit files to the miner. "
        "Commit the kit change, then run from the repository root:\n"
        f"  {regenerate_command(manifest_number(manifest) + 1)}"
    )


def test_newest_manifest_covers_current_starter_kit() -> None:
    if not STARTER_KIT.is_dir():
        pytest.skip("the monorepo starter kit is not part of this checkout")
    failure = starter_drift_failure(STARTER_KIT, newest_manifest(MANIFEST_DIR))
    if failure is not None:
        pytest.fail(failure, pytrace=False)


def test_newest_manifest_is_a_loadable_monorepo_manifest() -> None:
    newest = newest_manifest(MANIFEST_DIR)
    manifest = _load_provenance_manifest(newest)
    files = manifest["files"]
    assert isinstance(files, dict) and files
    assert manifest["version"] == 1
    assert manifest["origin"] == ORIGIN
    assert len(str(manifest["revision"])) == 40
    assert not [
        path
        for path in files
        if path.split("/", 1)[0] in {".agents", ".claude", ".git", "target"}
    ]
    numbers = [
        manifest_number(path)
        for path in MANIFEST_DIR.glob("starter-kit-provenance-*.json")
    ]
    assert len(numbers) == len(set(numbers))
    assert manifest_number(newest) == max(numbers)


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git",
            "-c",
            "user.name=provenance-test",
            "-c",
            "user.email=provenance-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=root,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()


def _starter_repository(tmp_path: Path) -> Path:
    """A monorepo-shaped fixture: a kit directory beside unrelated history."""
    repository = tmp_path / "monorepo"
    kit = repository / "kit"
    for relative, content in {
        "src/lib.rs": "pub fn tracked() {}\n",
        "scripts/run.sh": "#!/bin/sh\nexec true\n",
        ".env.example": "OPENROUTER_API_KEY=\n",
        ".env": "OPENROUTER_API_KEY=secret\n",
        ".env.local": "OPENROUTER_API_KEY=secret\n",
        ".agents/skills/mine/SKILL.md": "skill\n",
        "target/release/tracked-artifact": "build output\n",
        "fixtures/local.db": "db\n",
        "fixtures/local.db-wal": "wal\n",
        "submission.tgz": "archive\n",
        "fixtures/sample.tar": "packaged by submit\n",
    }.items():
        path = kit / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    (kit / "scripts/run.sh").chmod(0o755)
    (kit / ".claude").mkdir()
    (kit / ".claude/skills").symlink_to("../.agents/skills")
    (kit / "linked.rs").symlink_to("src/lib.rs")
    (repository / "README.md").write_text("outside the kit\n")
    _git(repository, "init", "-q")
    _git(repository, "add", "-f", ".")
    _git(repository, "commit", "-q", "-m", "kit")
    (kit / "untracked.rs").write_text("pub fn untracked() {}\n")
    (kit / "target/debug").mkdir(parents=True)
    (kit / "target/debug/local-build").write_bytes(os.urandom(64))
    return kit


def _generate(kit: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            "--starter-dir",
            str(kit),
            "--output",
            str(output),
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def test_generator_trusts_only_tracked_submittable_regular_files(
    tmp_path: Path,
) -> None:
    kit = _starter_repository(tmp_path)

    files = starter_files(kit)

    # Symlinks, dev skills, secrets, local DBs, submission tarballs, build
    # output, and untracked files are never trusted. The committed template
    # and a plain .tar, which starter ``submit`` does package, are.
    assert sorted(files) == [
        ".env.example",
        "fixtures/sample.tar",
        "scripts/run.sh",
        "src/lib.rs",
    ]
    assert files["src/lib.rs"] == hashlib.sha256(b"pub fn tracked() {}\n").hexdigest()


def test_drift_guard_fails_on_one_byte_with_the_regenerate_command(
    tmp_path: Path,
) -> None:
    kit = _starter_repository(tmp_path)
    manifest = tmp_path / "starter-kit-provenance-v6.json"
    assert _generate(kit, manifest).returncode == 0
    assert starter_drift_failure(kit, manifest) is None

    source = kit / "src/lib.rs"
    source.write_bytes(source.read_bytes().replace(b"tracked", b"trackee"))
    (kit / "scripts/run.sh").unlink()
    (kit / "src/extra.rs").write_text("pub fn extra() {}\n")
    _git(kit, "add", "src/extra.rs")

    failure = starter_drift_failure(kit, manifest)

    assert failure is not None
    assert "modified: src/lib.rs" in failure
    assert "added: src/extra.rs" in failure
    assert "removed: scripts/run.sh" in failure
    assert regenerate_command(7) in failure
    assert "starter-kit-provenance-v7.json" in failure


def test_generator_is_reproducible_and_pins_the_last_kit_commit(
    tmp_path: Path,
) -> None:
    kit = _starter_repository(tmp_path)
    kit_commit = _git(kit, "rev-parse", "HEAD")
    (kit.parent / "README.md").write_text("an unrelated monorepo change\n")
    _git(kit.parent, "commit", "-q", "-am", "unrelated")
    assert _git(kit, "rev-parse", "HEAD") != kit_commit
    first, second = tmp_path / "first.json", tmp_path / "second.json"

    assert _generate(kit, first).returncode == 0
    assert _generate(kit, second).returncode == 0
    assert _generate(kit, first).returncode == 0

    assert first.read_bytes() == second.read_bytes()
    payload = json.loads(first.read_text())
    assert payload["revision"] == kit_commit
    assert payload["origin"] == ORIGIN
    assert payload["version"] == 1
    assert _load_provenance_manifest(first) == payload


def test_generator_refuses_uncommitted_kit_and_rewriting_a_manifest(
    tmp_path: Path,
) -> None:
    kit = _starter_repository(tmp_path)
    published = tmp_path / "starter-kit-provenance-v6.json"
    assert _generate(kit, published).returncode == 0
    before = published.read_bytes()

    (kit / "src/lib.rs").write_text("pub fn uncommitted() {}\n")
    dirty = _generate(kit, tmp_path / "next.json")
    assert dirty.returncode != 0
    assert "commit starter-kit changes" in dirty.stderr
    assert not (tmp_path / "next.json").exists()

    _git(kit, "commit", "-q", "-am", "kit change")
    rewrite = _generate(kit, published)
    assert rewrite.returncode == 1
    assert "refusing to rewrite" in rewrite.stderr
    assert published.read_bytes() == before
    assert _generate(kit, tmp_path / "starter-kit-provenance-v7.json").returncode == 0


def test_newest_manifest_orders_versions_numerically(tmp_path: Path) -> None:
    for number in (1, 9, 10, 2):
        (tmp_path / f"starter-kit-provenance-v{number}.json").write_text("{}")
    (tmp_path / "bench-categories-v1.json").write_text("{}")

    assert newest_manifest(tmp_path).name == "starter-kit-provenance-v10.json"
