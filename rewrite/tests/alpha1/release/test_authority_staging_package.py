"""The Authority staging artifact stays source-only and diagnostic."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts" / "alpha1"))

from authority_staging_package import (  # noqa: E402
    MANIFEST_PATH, STATUS, build_staging_authority, verify_staging_authority,
)
from authority_staging_probe import isolated_import_probe  # noqa: E402


@pytest.fixture(scope="module")
def staging(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict]:
    package = tmp_path_factory.mktemp("authority-staging") / "authority.zip"
    receipt = build_staging_authority(ROOT, package)
    return package, receipt


def test_staging_artifact_is_bound_source_only_and_imports_in_isolation(
    staging: tuple[Path, dict],
) -> None:
    package, receipt = staging
    result = isolated_import_probe(package, receipt["manifest_sha256"])
    assert result["status"] == STATUS
    assert result["isolated"] is True
    assert result["cold_install_pass"] is False
    assert result["service_bootstrap"] == "absent"
    assert result["dependency_lock_scope"] == "direct_requirements_only"
    assert result["dependency_wheels"] == "absent"
    assert result["source_provenance"] == "unfrozen_worktree"
    with zipfile.ZipFile(package) as archive:
        manifest = json.loads(archive.read(MANIFEST_PATH))
        names = set(archive.namelist())
    assert all(name.endswith(".py") or name in {
        "requirements-authority.txt", MANIFEST_PATH,
    } for name in names)
    assert {
        "scripts/alpha1/verify_d06_algorithm_build.py",
        "rewrite/sylanne3/domains/d06/c04_work_input_v2.py",
        "rewrite/sylanne3/memory_association.py",
        "rewrite/sylanne3/host/installed_package.py",
    } <= names
    assert not any(".sqlite" in name or "credential" in name or "log" in name for name in names)
    assert str(ROOT).replace("\\", "/") not in json.dumps(manifest)
    assert manifest["dependency_lock_sha256"] == hashlib.sha256(
        (ROOT / "requirements-authority.txt").read_bytes(),
    ).hexdigest()


def test_tampered_source_member_is_rejected(staging: tuple[Path, dict], tmp_path: Path) -> None:
    package, receipt = staging
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(package) as source, zipfile.ZipFile(tampered, "w") as target:
        for name in source.namelist():
            data = source.read(name)
            if name == "rewrite/sylanne3/authority_service/daemon.py":
                data += b"# tampered\n"
            target.writestr(name, data)
    with pytest.raises(ValueError, match="digest differs"):
        verify_staging_authority(
            tampered, expected_manifest_sha256=receipt["manifest_sha256"],
        )


def test_manifest_requires_external_pinned_digest(staging: tuple[Path, dict]) -> None:
    package, _ = staging
    with pytest.raises(ValueError, match="manifest digest differs"):
        verify_staging_authority(package, expected_manifest_sha256="0" * 64)
