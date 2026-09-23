from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import warnings
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "build_plugin_package.py"
WORKBENCH_VERIFIER = Path(__file__).resolve().parents[2] / "scripts" / "alpha1" / "verify_delivery_assets.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location("build_plugin_package", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load package builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_workbench_verifier():
    spec = importlib.util.spec_from_file_location("verify_delivery_assets", WORKBENCH_VERIFIER)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load workbench verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WorkbenchAssetTests(unittest.TestCase):
    def test_verifier_rejects_source_drift_after_manifest_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "webui-src"
            destination = root / "resources" / "workbench"
            source.mkdir()
            destination.mkdir(parents=True)
            content = b"<main>current</main>\n"
            for directory in (source, destination):
                (directory / "index.html").write_bytes(content)
            manifest = {
                "schema_version": "sylanne.workbench-assets.v1",
                "source": "webui-src",
                "files": [{"path": "index.html", "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}],
            }
            (destination / "workbench-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            verifier = _load_workbench_verifier()
            verifier.verify_workbench(root)
            (source / "index.html").write_bytes(b"<main>new</main>\n")
            with self.assertRaisesRegex(ValueError, "differs from source"):
                verifier.verify_workbench(root)


def _run_git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


class PluginPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.base = Path(self.tempdir.name)
        self.project = self.base / "project"
        self.project.mkdir()
        files = {
            "__init__.py": b"",
            "main.py": b"VALUE = 1\n",
            "metadata.yaml": b'name: astrbot_plugin_sylanne\nversion: "3.0.0-dev.1"\n',
            "_conf_schema.json": b"{}\n",
            "requirements.txt": b"# none\n",
            "README.md": b"# Sylanne\n",
            "LICENSE": b"license\n",
            "logo.png": b"png-bytes",
            "rewrite/__init__.py": b"",
            "rewrite/sylanne3/__init__.py": b"",
            "rewrite/sylanne3/runtime.py": b"RUNTIME = True\n",
        }
        for relative, content in files.items():
            path = self.project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        _run_git(self.project, "init", "--quiet")
        _run_git(self.project, "config", "user.name", "Package Test")
        _run_git(self.project, "config", "user.email", "package@example.invalid")
        _run_git(self.project, "add", ".")
        _run_git(self.project, "commit", "--quiet", "-m", "fixture")
        self.builder = _load_builder()

    def _native(self, name: str = "sylanne3_kernel.dll") -> Path:
        path = self.base / name
        path.write_bytes(b"native-binary")
        return path

    def _add_formal_assets(self) -> None:
        # Synthetic package-builder fixture only; this is not runtime admission.
        catalogue = {
            "activation_status": "runtime_verified",
            "release_eligibility": "READY",
            "declared_domains": [f"d{number:02d}" for number in range(1, 13)],
            "missing_domain_exports": [],
            "domain_capabilities": {"d04": ["d04.affect.scheme.v1"]},
        }
        affect_scheme = {
            "schema": "d04.affect.scheme.v1",
            "scheme_version": "fixture:scheme:1",
            "operator_version": "fixture:operator:1",
            "parameter_version": "fixture:parameter:1",
            "coupling_version": "fixture:coupling:1",
            "axes": [{
                "axis_id": "fixture:axis:1",
                "unit": "normalized",
                "meaning": "synthetic package-builder test axis",
            }],
            "parameter_bounds": [],
        }
        migrations = {
            "legacy_data_policy": "registered_migrators",
            "release_eligibility": "READY",
            "migrations": [{"id": "fixture-only", "activation": "validated"}],
        }
        files = {
            "resources/workbench/index.html": b"<main>Sylanne</main>\n",
            "resources/catalogue/current.json": json.dumps(catalogue).encode() + b"\n",
            "resources/catalogue/d04-affect-scheme.json": json.dumps(affect_scheme).encode() + b"\n",
            "resources/migrations/v1.json": json.dumps(migrations).encode() + b"\n",
            "THIRD_PARTY_NOTICES": b"No bundled third-party runtime assets.\n",
            "SBOM.spdx.json": b'{"spdxVersion":"SPDX-2.3"}\n',
        }
        for relative, content in files.items():
            path = self.project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        _run_git(self.project, "add", ".")
        _run_git(self.project, "commit", "--quiet", "-m", "formal assets")

    def _set_formal_version(self) -> None:
        (self.project / "metadata.yaml").write_bytes(
            b'name: astrbot_plugin_sylanne\nversion: "3.0.0-alpha1"\n'
        )
        _run_git(self.project, "add", "metadata.yaml")
        _run_git(self.project, "commit", "--quiet", "-m", "formal version")

    def test_build_is_reproducible_and_manifest_matches_allowlisted_payload(self) -> None:
        excluded = {
            "data/runtime.sqlite3": b"private runtime data",
            ".venv/secret.txt": b"credential",
            "rewrite/artifacts/build.log": b"local log",
            "rewrite/native/target/release/sylanne3_kernel.dll": b"stale native",
            "rewrite/sylanne3/__pycache__/runtime.pyc": b"cache",
            "rewrite/sylanne3/debug.log": b"log",
        }
        for relative, content in excluded.items():
            path = self.project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

        first = self.builder.build_package(
            project_root=self.project,
            target_os="windows",
            target_arch="x86_64",
            native_library=self._native(),
            output_dir=self.base / "first",
            allow_dirty_dev_probe=True,
        )
        second = self.builder.build_package(
            project_root=self.project,
            target_os="windows",
            target_arch="x86_64",
            native_library=self._native(),
            output_dir=self.base / "second",
            allow_dirty_dev_probe=True,
        )

        self.assertEqual(first.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(first) as archive:
            names = archive.namelist()
            self.assertEqual(names, sorted(names))
            self.assertEqual(len(names), len(set(names)))
            self.assertIn(
                "rewrite/sylanne3/_native/windows-x86_64/sylanne3_kernel.dll",
                names,
            )
            self.assertNotIn("data/runtime.sqlite3", names)
            self.assertNotIn(".venv/secret.txt", names)
            self.assertNotIn("rewrite/artifacts/build.log", names)
            self.assertNotIn(
                "rewrite/native/target/release/sylanne3_kernel.dll", names
            )
            self.assertNotIn("rewrite/sylanne3/__pycache__/runtime.pyc", names)
            self.assertNotIn("rewrite/sylanne3/debug.log", names)
            manifest = json.loads(archive.read("release-manifest.json"))
            self.assertEqual(manifest["package_version"], "3.0.0-dev.1")
            self.assertEqual(manifest["source"]["dirty"], True)
            self.assertEqual(manifest["build_mode"], "dev-probe")
            self.assertNotIn("affect_scheme", manifest)
            self.assertEqual(manifest["platform"]["os"], "windows")
            self.assertEqual(manifest["platform"]["arch"], "x86_64")
            self.assertEqual(manifest["platform"]["abi_version"], 2)
            listed = {item["path"]: item for item in manifest["files"]}
            self.assertEqual(set(names), set(listed) | {"release-manifest.json"})
            for path, item in listed.items():
                content = archive.read(path)
                self.assertEqual(item["bytes"], len(content))
                self.assertEqual(item["sha256"], hashlib.sha256(content).hexdigest())
        self.builder.verify_package(first)

    def test_formal_build_rejects_dirty_source_but_dev_probe_records_it(self) -> None:
        (self.project / "main.py").write_text("VALUE = 2\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "dirty"):
            self.builder.build_package(
                project_root=self.project,
                target_os="windows",
                target_arch="x86_64",
                native_library=self._native(),
                output_dir=self.base / "formal",
            )

        package = self.builder.build_package(
            project_root=self.project,
            target_os="windows",
            target_arch="x86_64",
            native_library=self._native(),
            output_dir=self.base / "probe",
            allow_dirty_dev_probe=True,
        )
        with zipfile.ZipFile(package) as archive:
            manifest = json.loads(archive.read("release-manifest.json"))
        self.assertTrue(manifest["source"]["dirty"])
        self.assertEqual(manifest["build_mode"], "dev-probe")

    def test_explicit_dev_probe_stays_non_release_on_clean_source(self) -> None:
        package = self.builder.build_package(
            project_root=self.project,
            target_os="windows",
            target_arch="x86_64",
            native_library=self._native(),
            output_dir=self.base / "clean-probe",
            allow_dirty_dev_probe=True,
        )
        with zipfile.ZipFile(package) as archive:
            manifest = json.loads(archive.read("release-manifest.json"))
        self.assertFalse(manifest["source"]["dirty"])
        self.assertEqual(manifest["build_mode"], "dev-probe")

    def test_formal_build_requires_alpha1_version_and_complete_release_assets(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "3.0.0-alpha1"):
            self.builder.build_package(
                project_root=self.project,
                target_os="linux",
                target_arch="aarch64",
                native_library=self._native("libsylanne3_kernel.so"),
                output_dir=self.base / "premature",
                target_libc="glibc",
            )

        self._set_formal_version()
        with self.assertRaisesRegex(RuntimeError, "release resources"):
            self.builder.build_package(
                project_root=self.project,
                target_os="linux",
                target_arch="aarch64",
                native_library=self._native("libsylanne3_kernel.so"),
                output_dir=self.base / "missing-assets",
                target_libc="glibc",
            )

        self._add_formal_assets()
        expected_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.project, text=True
        ).strip()
        package = self.builder.build_package(
            project_root=self.project,
            target_os="linux",
            target_arch="aarch64",
            native_library=self._native("libsylanne3_kernel.so"),
            output_dir=self.base / "formal",
            target_libc="glibc",
            cpu_features=("neon",),
        )
        self.assertEqual(
            package.name,
            "astrbot_plugin_sylanne-3.0.0-alpha1-linux-aarch64-glibc.zip",
        )
        with zipfile.ZipFile(package) as archive:
            manifest = json.loads(archive.read("release-manifest.json"))
        self.assertEqual(manifest["source"]["git_sha"], expected_sha)
        self.assertFalse(manifest["source"]["dirty"])
        self.assertEqual(manifest["build_mode"], "formal-alpha1")
        self.assertEqual(manifest["platform"]["libc"], "glibc")
        self.assertEqual(manifest["platform"]["cpu_features"], ["neon"])
        self.assertEqual(manifest["platform"]["abi_version"], 2)
        binding = manifest["affect_scheme"]
        self.assertEqual(binding["path"], "resources/catalogue/d04-affect-scheme.json")
        self.assertEqual(binding["catalogue_capability"], "d04.affect.scheme.v1")
        self.assertEqual(binding["scheme_version"], "fixture:scheme:1")
        paths = {entry["path"] for entry in manifest["files"]}
        self.assertTrue(
            {
                "resources/workbench/index.html",
                "resources/catalogue/current.json",
                "resources/catalogue/d04-affect-scheme.json",
                "resources/migrations/v1.json",
                "THIRD_PARTY_NOTICES",
                "SBOM.spdx.json",
            }.issubset(paths)
        )
        self.assertIn(
            "rewrite/sylanne3/_native/linux-aarch64/libsylanne3_kernel.so",
            paths,
        )

    def test_verifier_rejects_duplicate_and_dangerous_members(self) -> None:
        duplicate = self.base / "duplicate.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate, "w") as archive:
                archive.writestr("same.txt", b"one")
                archive.writestr("same.txt", b"two")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.builder.verify_package(duplicate)

        dangerous = self.base / "dangerous.zip"
        with zipfile.ZipFile(dangerous, "w") as archive:
            archive.writestr("../escape.txt", b"bad")
        with self.assertRaisesRegex(ValueError, "dangerous"):
            self.builder.verify_package(dangerous)

    def test_verifier_rejects_dev_version_claiming_formal_alpha1(self) -> None:
        package = self.builder.build_package(
            project_root=self.project,
            target_os="windows",
            target_arch="x86_64",
            native_library=self._native(),
            output_dir=self.base / "source-probe",
            allow_dirty_dev_probe=True,
        )
        with zipfile.ZipFile(package) as source:
            members = {name: source.read(name) for name in source.namelist()}
        manifest = json.loads(members["release-manifest.json"])
        manifest["build_mode"] = "formal-alpha1"
        members["release-manifest.json"] = json.dumps(manifest).encode("utf-8")
        forged = self.base / "forged-formal.zip"
        with zipfile.ZipFile(forged, "w") as archive:
            for name, content in members.items():
                archive.writestr(name, content)
        with self.assertRaisesRegex(ValueError, "formal alpha1"):
            self.builder.verify_package(forged)

    def test_formal_build_rejects_candidate_only_catalogue(self) -> None:
        self._set_formal_version()
        self._add_formal_assets()
        path = self.project / "resources/catalogue/current.json"
        catalogue = json.loads(path.read_text(encoding="utf-8"))
        catalogue["activation_status"] = "candidate_only"
        catalogue["release_eligibility"] = "HOLD"
        path.write_text(json.dumps(catalogue) + "\n", encoding="utf-8")
        _run_git(self.project, "add", ".")
        _run_git(self.project, "commit", "--quiet", "-m", "candidate only")
        with self.assertRaisesRegex(RuntimeError, "candidate-only"):
            self.builder.build_package(
                project_root=self.project,
                target_os="windows",
                target_arch="x86_64",
                native_library=self._native(),
                output_dir=self.base / "candidate-formal",
            )

    def test_formal_build_rejects_preview_only_migration(self) -> None:
        self._set_formal_version()
        self._add_formal_assets()
        path = self.project / "resources/migrations/v1.json"
        migration = json.loads(path.read_text(encoding="utf-8"))
        migration["release_eligibility"] = "HOLD: preview only"
        migration["migrations"][0]["activation"] = "prohibited_preview_only"
        path.write_text(json.dumps(migration) + "\n", encoding="utf-8")
        _run_git(self.project, "add", ".")
        _run_git(self.project, "commit", "--quiet", "-m", "preview migration")
        with self.assertRaisesRegex(RuntimeError, "migration placeholders"):
            self.builder.build_package(
                project_root=self.project,
                target_os="windows",
                target_arch="x86_64",
                native_library=self._native(),
                output_dir=self.base / "preview-formal",
            )

    def test_formal_build_requires_strict_d04_asset_and_binding(self) -> None:
        self._set_formal_version()
        self._add_formal_assets()
        asset_path = self.project / "resources/catalogue/d04-affect-scheme.json"
        original = asset_path.read_bytes()
        asset_path.write_bytes(original.replace(b'"schema":', b'"schema":"duplicate", "schema":'))
        _run_git(self.project, "add", ".")
        _run_git(self.project, "commit", "--quiet", "-m", "duplicate D04 field")
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            self.builder.build_package(
                project_root=self.project,
                target_os="windows",
                target_arch="x86_64",
                native_library=self._native(),
                output_dir=self.base / "duplicate-d04",
            )

    def test_formal_build_holds_when_d04_asset_is_absent(self) -> None:
        self._set_formal_version()
        self._add_formal_assets()
        (self.project / "resources/catalogue/d04-affect-scheme.json").unlink()
        _run_git(self.project, "add", "-A")
        _run_git(self.project, "commit", "--quiet", "-m", "without D04 scheme")
        with self.assertRaisesRegex(RuntimeError, "requires a D04 affect scheme asset"):
            self.builder.build_package(
                project_root=self.project,
                target_os="windows",
                target_arch="x86_64",
                native_library=self._native(),
                output_dir=self.base / "missing-d04",
            )

    def test_formal_verifier_rejects_missing_or_mismatched_d04_binding(self) -> None:
        self._set_formal_version()
        self._add_formal_assets()
        package = self.builder.build_package(
            project_root=self.project,
            target_os="windows",
            target_arch="x86_64",
            native_library=self._native(),
            output_dir=self.base / "bound-formal",
        )
        with zipfile.ZipFile(package) as source:
            members = {name: source.read(name) for name in source.namelist()}
        manifest = json.loads(members["release-manifest.json"])
        del manifest["affect_scheme"]
        members["release-manifest.json"] = json.dumps(manifest).encode("utf-8")
        missing = self.base / "missing-d04-binding.zip"
        with zipfile.ZipFile(missing, "w") as archive:
            for name, content in members.items():
                archive.writestr(name, content)
        with self.assertRaisesRegex(ValueError, "D04 manifest binding"):
            self.builder.verify_package(missing)

        manifest["affect_scheme"] = {
            "path": "resources/catalogue/d04-affect-scheme.json",
            "sha256": "0" * 64,
            "bytes": 1,
            "catalogue_capability": "d04.affect.scheme.v1",
            "scheme_version": "fixture:scheme:1",
            "operator_version": "fixture:operator:1",
            "parameter_version": "fixture:parameter:1",
            "coupling_version": "fixture:coupling:1",
        }
        members["release-manifest.json"] = json.dumps(manifest).encode("utf-8")
        mismatched = self.base / "mismatched-d04-binding.zip"
        with zipfile.ZipFile(mismatched, "w") as archive:
            for name, content in members.items():
                archive.writestr(name, content)
        with self.assertRaisesRegex(ValueError, "D04 manifest binding"):
            self.builder.verify_package(mismatched)

    def test_verifier_rejects_formal_archive_with_candidate_resources(self) -> None:
        self._set_formal_version()
        self._add_formal_assets()
        package = self.builder.build_package(
            project_root=self.project,
            target_os="windows",
            target_arch="x86_64",
            native_library=self._native(),
            output_dir=self.base / "fixture-formal",
        )
        with zipfile.ZipFile(package) as source:
            members = {name: source.read(name) for name in source.namelist()}
        catalogue_path = "resources/catalogue/current.json"
        catalogue = json.loads(members[catalogue_path])
        catalogue["activation_status"] = "candidate_only"
        members[catalogue_path] = json.dumps(catalogue).encode("utf-8")
        manifest = json.loads(members["release-manifest.json"])
        entry = next(item for item in manifest["files"] if item["path"] == catalogue_path)
        entry["bytes"] = len(members[catalogue_path])
        entry["sha256"] = hashlib.sha256(members[catalogue_path]).hexdigest()
        members["release-manifest.json"] = json.dumps(manifest).encode("utf-8")
        forged = self.base / "forged-candidate.zip"
        with zipfile.ZipFile(forged, "w") as archive:
            for name, content in members.items():
                archive.writestr(name, content)
        with self.assertRaisesRegex(ValueError, "candidate-only"):
            self.builder.verify_package(forged)

    def test_verifier_rejects_formal_archive_with_preview_migration(self) -> None:
        self._set_formal_version()
        self._add_formal_assets()
        package = self.builder.build_package(
            project_root=self.project,
            target_os="windows",
            target_arch="x86_64",
            native_library=self._native(),
            output_dir=self.base / "fixture-formal",
        )
        with zipfile.ZipFile(package) as source:
            members = {name: source.read(name) for name in source.namelist()}
        migration_path = "resources/migrations/v1.json"
        migration = json.loads(members[migration_path])
        migration["release_eligibility"] = "HOLD: preview only"
        migration["migrations"][0]["activation"] = "prohibited_preview_only"
        members[migration_path] = json.dumps(migration).encode("utf-8")
        manifest = json.loads(members["release-manifest.json"])
        entry = next(item for item in manifest["files"] if item["path"] == migration_path)
        entry["bytes"] = len(members[migration_path])
        entry["sha256"] = hashlib.sha256(members[migration_path]).hexdigest()
        members["release-manifest.json"] = json.dumps(manifest).encode("utf-8")
        forged = self.base / "forged-preview-migration.zip"
        with zipfile.ZipFile(forged, "w") as archive:
            for name, content in members.items():
                archive.writestr(name, content)
        with self.assertRaisesRegex(ValueError, "migration placeholders"):
            self.builder.verify_package(forged)

    def test_rejects_wrong_native_filename_and_unsupported_platform(self) -> None:
        with self.assertRaisesRegex(ValueError, "native library filename"):
            self.builder.build_package(
                project_root=self.project,
                target_os="windows",
                target_arch="x86_64",
                native_library=self._native("wrong.dll"),
                output_dir=self.base / "bad-name",
            )
        with self.assertRaisesRegex(ValueError, "target OS"):
            self.builder.build_package(
                project_root=self.project,
                target_os="android",
                target_arch="aarch64",
                native_library=self._native("libsylanne3_kernel.so"),
                output_dir=self.base / "bad-os",
            )
        with self.assertRaisesRegex(ValueError, "OS/architecture"):
            self.builder.build_package(
                project_root=self.project,
                target_os="windows",
                target_arch="aarch64",
                native_library=self._native(),
                output_dir=self.base / "bad-windows-arch",
                allow_dirty_dev_probe=True,
            )

    def test_dev_probe_covers_each_frozen_os_architecture_target(self) -> None:
        targets = (
            ("windows", "x86_64", "sylanne3_kernel.dll", None),
            ("linux", "x86_64", "libsylanne3_kernel.so", "glibc"),
            ("linux", "aarch64", "libsylanne3_kernel.so", "musl"),
            ("macos", "x86_64", "libsylanne3_kernel.dylib", None),
            ("macos", "aarch64", "libsylanne3_kernel.dylib", None),
        )
        for target_os, target_arch, filename, libc in targets:
            with self.subTest(target=f"{target_os}-{target_arch}-{libc}"):
                package = self.builder.build_package(
                    project_root=self.project,
                    target_os=target_os,
                    target_arch=target_arch,
                    native_library=self._native(filename),
                    output_dir=self.base / f"{target_os}-{target_arch}-{libc}",
                    allow_dirty_dev_probe=True,
                    target_libc=libc,
                )
                with zipfile.ZipFile(package) as archive:
                    manifest = json.loads(archive.read("release-manifest.json"))
                self.assertEqual(manifest["platform"]["os"], target_os)
                self.assertEqual(manifest["platform"]["arch"], target_arch)
                self.assertEqual(manifest["platform"]["libc"], libc)


if __name__ == "__main__":
    unittest.main()
