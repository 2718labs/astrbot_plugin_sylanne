"""Real OS contract for the two fixed ordinary phase children; no business fixture."""
import json
import os
from pathlib import Path
import select
import signal
import tempfile

import pytest

from owned_resource_profile_v1 import (
    FixtureKind, OwnedResourceRunV1, _enter_phase_child_identity_v1, _fixed_child,
)


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="requires real Linux Root fork")
def test_phase_child_actual_ordinary_identity_and_protected_assets_v1():
    with tempfile.TemporaryDirectory(prefix="sylanne-phase-identity-", dir="/var/tmp") as directory:
        root = Path(directory)
        root.chmod(0o755)
        protected = root / "protected"
        protected.mkdir(mode=0o755)
        key = protected / "sentinel.key"
        key.write_bytes(b"permission-test-sentinel")
        os.chown(key, 0, 1000)
        key.chmod(0o640)
        evidence = root / "observer-evidence"
        evidence.mkdir(mode=0o700)
        observation = evidence / "sentinel.json"
        observation.write_bytes(b"root-observation-sentinel")
        observation.chmod(0o600)
        work = root / "ordinary-work"
        work.mkdir(mode=0o700)
        os.chown(work, 1000, 1000)
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                _enter_phase_child_identity_v1()
                result = {"uids": list(os.getresuid()), "gids": list(os.getresgid()),
                    "groups": os.getgroups(), "protected_asset_read": key.read_bytes() == b"permission-test-sentinel"}
                for name, action in (
                    ("root_observation_read_denied", lambda: observation.read_bytes()),
                    ("root_observation_write_denied", lambda: (evidence / "forged.json").write_bytes(b"forged")),
                    ("root_identity_cannot_be_restored", lambda: os.setuid(0)),
                ):
                    try:
                        action()
                    except PermissionError:
                        result[name] = True
                    else:
                        result[name] = False
                output = work / "ordinary.json"
                output.write_bytes(b"ordinary-output")
                result["ordinary_output_uid_gid"] = [output.stat().st_uid, output.stat().st_gid]
                os.write(write_fd, json.dumps(result).encode())
                os._exit(0)
            except BaseException as error:
                os.write(write_fd, json.dumps({"actual_child_error": type(error).__name__, "detail": str(error)}).encode())
                os._exit(1)
        os.close(write_fd)
        if not select.select([read_fd], [], [], 15)[0]:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            os.close(read_fd)
            pytest.fail("actual ordinary child exceeded the bounded identity contract")
        data = os.read(read_fd, 8192)
        os.close(read_fd)
        _, status = os.waitpid(pid, 0)
        result = json.loads(data)
        assert os.waitstatus_to_exitcode(status) == 0, result
        assert result == {"uids": [1000, 1000, 1000], "gids": [1000, 1000, 1000],
            "groups": [1000], "protected_asset_read": True,
            "root_observation_read_denied": True, "root_observation_write_denied": True,
            "root_identity_cannot_be_restored": True, "ordinary_output_uid_gid": [1000, 1000]}
        assert os.getresuid() == (0, 0, 0)
        assert os.getresgid() == (0, 0, 0)
        assert evidence.stat().st_uid == 0 and evidence.stat().st_mode & 0o777 == 0o700
        assert observation.read_bytes() == b"root-observation-sentinel"


def test_phase_fixed_child_refuses_caller_identity_and_arbitrary_command_v1():
    with pytest.raises(ValueError):
        FixtureKind("caller_root_shell")
    with pytest.raises(TypeError, match="unexpected keyword argument.*uid"):
        OwnedResourceRunV1(uid=0)
    with pytest.raises(TypeError, match="unexpected keyword argument.*command"):
        _fixed_child(json.dumps({"command": ["/bin/sh"]}))


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="requires real Linux Root fork")
def test_public_extracted_stage_actual_ordinary_traversal_under_root_umask_v1(monkeypatch):
    """Exercise the actual extractor and OS permissions with synthetic bytes only."""
    import hashlib
    import importlib.util
    import sys
    import zipfile

    source = Path("/mnt/d/codex_handoffs/Sylanne/complete-agent-local-20261006/evidence/alpha2-candidate40-installed-first-driver.py")
    spec = importlib.util.spec_from_file_location("public_stage_driver40_os_contract", source)
    driver = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = driver
    spec.loader.exec_module(driver)
    previous_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="sylanne-public-stage-mode-", dir="/var/tmp") as directory:
            root = Path(directory)
            root.chmod(0o755)
            public_bytes = b"public-stage-permission-sentinel"
            manifest = json.dumps({"scope": "synthetic OS permission test only"}).encode()
            package = root / "synthetic-mode-package.zip"
            with zipfile.ZipFile(package, "x") as archive:
                archive.writestr("release-manifest.json", manifest)
                archive.writestr("rewrite/public-sentinel.py", public_bytes)
            monkeypatch.setattr(driver, "PACKAGE", package)
            stage = root / "public-stage"
            installed = driver.extract_installed(stage, {
                "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                "manifest_sha256": hashlib.sha256(manifest).hexdigest()})
            code = installed / "rewrite/public-sentinel.py"
            private = stage / "protected-initial"
            private.mkdir(mode=0o700)
            secret = private / "synthetic-private-sentinel"
            secret.write_bytes(b"synthetic-private-bytes")
            secret.chmod(0o600)
            assert all(path.stat().st_uid == 0 and path.stat().st_mode & 0o777 == 0o755
                       for path in (stage, installed, installed / "rewrite"))
            assert code.stat().st_uid == 0 and code.stat().st_mode & 0o777 == 0o644
            read_fd, write_fd = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(read_fd)
                try:
                    _enter_phase_child_identity_v1()
                    result = {"uids": list(os.getresuid()), "gids": list(os.getresgid()),
                              "groups": os.getgroups(), "public_read": code.read_bytes() == public_bytes}
                    for key, path in (("private_directory_denied", private), ("private_file_denied", secret)):
                        try:
                            list(path.iterdir()) if path.is_dir() else path.read_bytes()
                        except PermissionError:
                            result[key] = True
                        else:
                            result[key] = False
                    os.write(write_fd, json.dumps(result).encode())
                    os._exit(0)
                except BaseException as error:
                    os.write(write_fd, json.dumps({"actual_child_error": type(error).__name__}).encode())
                    os._exit(1)
            os.close(write_fd)
            if not select.select([read_fd], [], [], 15)[0]:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                os.close(read_fd)
                pytest.fail("actual ordinary permission reader exceeded its bounded OS contract")
            result = json.loads(os.read(read_fd, 8192))
            os.close(read_fd)
            _, status = os.waitpid(pid, 0)
            assert os.waitstatus_to_exitcode(status) == 0, result
            assert result == {"uids": [1000, 1000, 1000], "gids": [1000, 1000, 1000], "groups": [1000],
                              "public_read": True, "private_directory_denied": True, "private_file_denied": True}
            assert private.stat().st_uid == secret.stat().st_uid == 0
            assert private.stat().st_mode & 0o777 == 0o700 and secret.stat().st_mode & 0o777 == 0o600
    finally:
        os.umask(previous_umask)
        sys.modules.pop(spec.name, None)
