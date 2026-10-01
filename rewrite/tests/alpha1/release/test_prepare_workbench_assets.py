from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


SCRIPT = Path(__file__).resolve().parents[4] / "scripts" / "alpha1" / "prepare_workbench_assets.py"


def _prepare_module():
    spec = importlib.util.spec_from_file_location("prepare_workbench_assets", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "webui-heritage" / "dist").mkdir(parents=True)
    (root / "resources" / "workbench" / "src").mkdir(parents=True)
    (root / "webui-heritage" / "dist" / "index.html").write_text(
        "<!doctype html><html><body>new build</body></html>\n", encoding="utf-8",
    )
    (root / "resources" / "workbench" / "index.html").write_text("old\n", encoding="utf-8")
    (root / "resources" / "workbench" / "workbench-manifest.json").write_text("{}\n", encoding="utf-8")
    (root / "resources" / "workbench" / "src" / "app.js").write_text(
        "legacy source stays in checkout\n", encoding="utf-8",
    )
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    return root


def test_prepare_syncs_built_html_and_preserves_legacy_source(tmp_path: Path) -> None:
    root = _project(tmp_path)

    _prepare_module().prepare(root)

    workbench = root / "resources" / "workbench"
    assert (workbench / "index.html").read_bytes() == (
        root / "webui-heritage" / "dist" / "index.html"
    ).read_bytes()
    assert (workbench / "src" / "app.js").read_text(encoding="utf-8") == "legacy source stays in checkout\n"
    manifest = json.loads((workbench / "workbench-manifest.json").read_bytes())
    assert manifest["source"] == "webui-heritage"
    assert manifest["build_output"] == "webui-heritage/dist/index.html"
    assert [row["path"] for row in manifest["files"]] == ["index.html"]


def test_prepare_rejects_missing_build_and_untracked_resource(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / "webui-heritage" / "dist" / "index.html").unlink()
    with pytest.raises(FileNotFoundError, match="build output"):
        _prepare_module().prepare(root)

    (root / "webui-heritage" / "dist" / "index.html").write_text("ok", encoding="utf-8")
    (root / "resources" / "workbench" / "unexpected.txt").write_text("untracked", encoding="utf-8")
    with pytest.raises(ValueError, match="untracked file"):
        _prepare_module().prepare(root)
