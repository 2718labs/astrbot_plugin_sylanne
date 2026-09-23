"""The D11 signing secret is a separate administrator-owned profile object."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import stat
import sys
import types
from types import SimpleNamespace
from unittest.mock import patch

import pytest


_host_package = sys.modules.get("sylanne3.host")
if _host_package is None:
    _host_package = types.ModuleType("sylanne3.host")
    _host_package.__path__ = [str(Path(__file__).resolve().parents[2] /
                                  "sylanne3" / "host")]
    sys.modules["sylanne3.host"] = _host_package
try:
    from sylanne3.host import authority_profile
finally:
    if _host_package is not None and not hasattr(_host_package, "__file__"):
        sys.modules.pop("sylanne3.host", None)


def _profile(root: Path, *, schema: int = 2, key: bytes | None = b"K" * 32) -> Path:
    folder = root / "safe"
    folder.mkdir()
    payload = {
        "schema": schema, "host": "127.0.0.1", "port": 9443,
        "server_name": "authority.example.org",
        "expected_authority_id": "authority:production",
    }
    if schema == 2:
        payload["installation_policy"] = {
            "namespace": {"bot_id": "bot-a", "persona_id": "persona-a"},
            "authority_namespace": "bot-a/persona-a",
            "installation_id": "install-a",
            "manifest_digest": "a" * 64,
            "administrator_holder": "holder-a",
            "expected_authority_id": "authority:production",
            "catalogue_hash": "b" * 64,
            "scheme_version": "scheme:v1",
            "operator_version": "operator:v1",
            "policy_version": "policy:v1",
            "root_lease": {
                "lease_id": "root-lease", "parent_id": None,
                "bot_id": "bot-a", "persona_id": "persona-a",
                "currency": "USD", "limits": {"tokens": 1000},
                "used": {}, "reserved": {}, "unconfirmed": {},
                "version": 1, "state": "active",
            },
            "root_grant": {
                "grant_id": "root-grant", "version": 1,
                "bot_id": "bot-a", "persona_id": "persona-a",
                "lease_id": "root-lease", "currency": "USD",
                "max_ceiling": {"tokens": 100},
                "allowed_work_kinds": ["reply"],
                "valid_until_utc": 4102444800,
                "policy_ref": "budget-policy:v1",
            },
        }
    import json
    (folder / "profile.json").write_text(json.dumps(payload), encoding="utf-8")
    for name in authority_profile._MATERIAL:
        (folder / name).write_bytes(b"test fixture")
    if key is not None:
        (folder / "d11-signing.key").write_bytes(key)
    return folder


def test_signing_key_is_not_a_profile_json_field(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    payload = authority_profile._read_profile_json(profile / "profile.json")
    assert "d11_signing_key" not in payload
    assert "d11-signing.key" not in authority_profile._MATERIAL
    for selection in ("../safe", "safe/other", "safe\\other"):
        with pytest.raises(ValueError, match="profile identifier"):
            authority_profile.load_admin_d11_signing_key(selection)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor traversal")
def test_posix_extra_key_is_opened_under_pinned_dirfd_and_no_follow(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    checked: list[tuple[bool, bool]] = []

    def inspect(fd: int, *, directory: bool, key: bool, system: str) -> None:
        checked.append((directory, key))

    with patch.object(authority_profile, "_check_opened", side_effect=inspect):
        with authority_profile._opened_profile(profile, "Linux", signing_key=True) as files:
            assert authority_profile._read_fd_bounded(files["d11-signing.key"], 32) == b"K" * 32
    assert checked[-1] == (False, True)
    target = profile / "original.key"
    (profile / "d11-signing.key").rename(target)
    (profile / "d11-signing.key").symlink_to(target.name)
    with patch.object(authority_profile, "_check_opened", side_effect=inspect):
        with pytest.raises(OSError):
            with authority_profile._opened_profile(profile, "Linux", signing_key=True):
                pass


@pytest.mark.parametrize("mode,gid,accepted", [
    (0o600, 1001, True),
    (0o640, 1000, True),
    (0o640, 1001, False),
    (0o644, 1000, False),
    (0o660, 1000, False),
])
def test_posix_signing_key_uses_private_key_owner_and_mode_gate(
    mode: int, gid: int, accepted: bool,
) -> None:
    info = SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=0,
                           st_gid=gid, st_nlink=1, st_size=32)
    with patch.object(authority_profile.os, "fstat", return_value=info), \
         patch.object(authority_profile.os, "getegid", return_value=1000, create=True), \
         patch.object(authority_profile, "_check_linux_acl_fd") as acl:
        if accepted:
            authority_profile._check_opened(77, directory=False, key=True,
                                            system="Linux")
            acl.assert_called_once_with(77, directory=False)
        else:
            with pytest.raises(PermissionError):
                authority_profile._check_opened(77, directory=False, key=True,
                                                system="Linux")


def test_posix_signing_key_rejects_acl() -> None:
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0,
                           st_gid=1000, st_nlink=1, st_size=32)
    with patch.object(authority_profile.os, "fstat", return_value=info), \
         patch.object(authority_profile, "_check_linux_acl_fd",
                      side_effect=PermissionError("ACL")):
        with pytest.raises(PermissionError, match="ACL"):
            authority_profile._check_opened(77, directory=False, key=True,
                                            system="Linux")


@pytest.mark.skipif(os.name != "nt", reason="native Windows pinned handles")
def test_windows_signing_key_reads_pinned_handle(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    path = profile / "d11-signing.key"
    with authority_profile._opened_windows_profile(profile, signing_key=True) as handles:
        assert authority_profile._read_windows_signing_key(handles[path]) == b"K" * 32
        with pytest.raises(OSError):
            path.rename(profile / "renamed.key")
        with pytest.raises(OSError):
            path.open("r+b")


@pytest.mark.skipif(os.name != "nt", reason="native Windows profile loader")
@pytest.mark.parametrize("schema,key,error", [
    (2, b"K" * 32, None),
    (2, b"K" * 31, ValueError),
    (2, b"K" * 33, ValueError),
    (2, None, FileNotFoundError),
    (1, b"K" * 32, ValueError),
])
def test_windows_loader_requires_schema2_and_exact_key(
    tmp_path: Path, schema: int, key: bytes | None, error: type[Exception] | None,
    ) -> None:
    _profile(tmp_path, schema=schema, key=key)
    with patch.dict(sys.modules, {"sylanne3.host": _host_package}):
        windows_profile_security = importlib.import_module(
            "sylanne3.host.windows_profile_security")
        with patch.object(windows_profile_security, "programdata_profile_root",
                          return_value=tmp_path), \
             patch.object(authority_profile, "_check_windows_handles") as checked:
            if error is None:
                assert authority_profile.load_admin_d11_signing_key("safe") == b"K" * 32
                checked.assert_called_once()
            else:
                with pytest.raises(error):
                    authority_profile.load_admin_d11_signing_key("safe")


@pytest.mark.skipif(os.name != "nt", reason="native Windows security descriptors")
def test_windows_d11_key_receives_private_key_dacl_check(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    security = types.ModuleType("win32security")
    with patch.dict(sys.modules, {"sylanne3.host": _host_package,
                                  "win32security": security}):
        windows_profile_security = importlib.import_module(
            "sylanne3.host.windows_profile_security")
        with authority_profile._opened_windows_profile(profile, signing_key=True) as handles, \
             patch.object(windows_profile_security, "_runtime_token_sids",
                          return_value=("runtime", {"runtime"})), \
             patch.object(windows_profile_security, "_check_security_descriptor") as check:
            authority_profile._check_windows_handles(profile, handles)
    key_checks = [call for call in check.call_args_list
                  if call.args[0] == profile / "d11-signing.key"]
    assert len(key_checks) == 1 and key_checks[0].kwargs["key"] is True


@pytest.mark.skipif(os.name != "nt", reason="native Windows administrator DACL")
def test_windows_loader_rejects_developer_owned_key(tmp_path: Path) -> None:
    _profile(tmp_path)
    with patch.dict(sys.modules, {"sylanne3.host": _host_package}):
        windows_profile_security = importlib.import_module(
            "sylanne3.host.windows_profile_security")
        with patch.object(windows_profile_security, "programdata_profile_root",
                          return_value=tmp_path):
            with pytest.raises(PermissionError, match="owner|non-admin write|private-key"):
                authority_profile.load_admin_d11_signing_key("safe")


def test_schema1_tls_profile_does_not_require_d11_key(tmp_path: Path) -> None:
    profile = _profile(tmp_path, schema=1, key=None)
    payload = authority_profile._read_profile_json(profile / "profile.json")
    assert authority_profile._profile_from_payload("safe", profile, payload).port == 9443
