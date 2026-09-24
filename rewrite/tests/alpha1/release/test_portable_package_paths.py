"""The same archive member names must extract safely on every target OS."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import zipfile

import pytest


BUILDER = Path(__file__).resolve().parents[3] / "tools" / "build_plugin_package.py"


def _builder():
    spec = importlib.util.spec_from_file_location("portable_package_builder", BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "path",
    [
        "resources/catalogue/CON.json",
        "resources/catalogue/lpt1.txt",
        "resources/catalogue/name.",
        "resources/catalogue/name ",
        "resources/catalogue/file:stream",
        "resources/catalogue/file?.json",
        "resources/catalogue/name\n.json",
    ],
)
def test_package_member_rejects_nonportable_windows_paths(path: str) -> None:
    with pytest.raises(ValueError, match="dangerous ZIP member path"):
        _builder()._validate_member_path(path)


@pytest.mark.parametrize(
    "paths",
    [
        ("resources/catalogue/Item.json", "resources/catalogue/item.json"),
        ("resources/catalogue/caf\u00e9.json", "resources/catalogue/cafe\u0301.json"),
    ],
)
def test_verifier_rejects_portable_name_collision_before_extraction(
    tmp_path: Path, paths: tuple[str, str]
) -> None:
    archive_path = tmp_path / "collision.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for path in paths:
            archive.writestr(path, b"distinct")
    with pytest.raises(ValueError, match="collide across platforms"):
        _builder().verify_package(archive_path)
