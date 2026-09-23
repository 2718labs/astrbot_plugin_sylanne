"""Administrator profile loading never takes trust material from chat settings."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import types
from types import SimpleNamespace
from unittest.mock import patch

import pytest

# Keep this test independent of an installed AstrBot host. Loading the two
# transport modules needs a package path, but not host/__init__.py (which
# imports AstrBot UI classes).
_host_package = sys.modules.get("sylanne3.host")
if _host_package is None:
    _host_package = types.ModuleType("sylanne3.host")
    _host_package.__path__ = [str(Path(__file__).resolve().parents[2] /
                                  "sylanne3" / "host")]
    sys.modules["sylanne3.host"] = _host_package
try:
    from sylanne3.host import authority_profile
    from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
finally:
    if _host_package is not None and not hasattr(_host_package, "__file__"):
        sys.modules.pop("sylanne3.host", None)


def _provision(root: Path, *, payload: dict[str, object] | None = None) -> Path:
    profile = root / "safe"
    profile.mkdir(parents=True)
    (profile / "profile.json").write_text(json.dumps(payload or {
        "schema": 1, "host": "127.0.0.1", "port": 9443,
        "server_name": "authority.example.org",
        "expected_authority_id": "authority:production",
    }), encoding="utf-8")
    for name in ("trust-root.pem", "client-cert.pem", "client-key.pem"):
        (profile / name).write_text("test fixture", encoding="ascii")
    return profile


def test_profile_id_cannot_select_path_or_trust_material(tmp_path: Path) -> None:
    _provision(tmp_path)
    for selection in ("../safe", "safe/other", "safe\\other", "", "."):
        with pytest.raises(ValueError, match="profile identifier"):
            authority_profile._load_profile_from_root(selection, tmp_path)


def test_profile_schema_seam_uses_fixed_material_paths(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path)
    payload = authority_profile._read_profile_json(profile_dir / "profile.json")
    profile = authority_profile._profile_from_payload("safe", profile_dir, payload)
    transport = MtlsAuthorityTransport({"safe": profile})
    assert isinstance(transport, MtlsAuthorityTransport)
    assert transport.profile_for("safe") is profile
    assert profile.server_name == "authority.example.org"
    assert profile.expected_authority_id == "authority:production"
    assert profile.trust_root == profile_dir / "trust-root.pem"
    assert profile.client_certificate == profile_dir / "client-cert.pem"
    assert profile.client_private_key == profile_dir / "client-key.pem"


def test_profile_rejects_extra_fields_and_duplicate_keys(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path)
    profile_file = profile_dir / "profile.json"
    profile_file.write_text(json.dumps({
        "schema": 1, "host": "127.0.0.1", "port": 9443,
        "server_name": "authority.example.org",
        "expected_authority_id": "authority:production",
        "trust_root": "/tmp/chat-ca",
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="profile schema"):
        authority_profile._read_profile_json(profile_file)
    profile_file.write_text(
        '{"schema":1,"host":"127.0.0.1","host":"evil",'
        '"port":9443,"server_name":"authority.example.org",'
        '"expected_authority_id":"authority:production"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        authority_profile._read_profile_json(profile_file)
    profile_file.write_text(json.dumps({
        "schema": 1, "host": "127.0.0.1", "port": 9443,
        "server_name": "authority.example.org",
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="profile schema"):
        authority_profile._read_profile_json(profile_file)


def test_posix_tree_rejects_symlink_and_untrusted_write_bit(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path)
    original_lstat = authority_profile.os.lstat

    def owner_root(path: os.PathLike[str] | str):
        observed = original_lstat(path)
        mode = (0o755 if stat.S_ISDIR(observed.st_mode) else
                0o640 if Path(path).name == "client-key.pem" else 0o644)
        return SimpleNamespace(st_uid=0,
                               st_mode=stat.S_IFMT(observed.st_mode) | mode,
                               st_nlink=1, st_gid=4242)

    with patch.object(authority_profile.os, "lstat", side_effect=owner_root), \
         patch.object(authority_profile.os, "getegid", return_value=4242, create=True):
        authority_profile._check_posix_tree(profile_dir)
        def writable_key(path: os.PathLike[str] | str):
            observed = owner_root(path)
            if Path(path) == profile_dir / "client-key.pem":
                observed.st_mode = stat.S_IFREG | 0o666
            return observed
        with patch.object(authority_profile.os, "lstat", side_effect=writable_key):
            with pytest.raises(PermissionError, match="administrator"):
                authority_profile._check_posix_tree(profile_dir)
    def linked_key(path: os.PathLike[str] | str):
        observed = owner_root(path)
        if Path(path) == profile_dir / "client-key.pem":
            observed.st_mode = stat.S_IFLNK | 0o777
        return observed
    with patch.object(authority_profile.os, "lstat", side_effect=linked_key), \
         patch.object(authority_profile.os, "getegid", return_value=4242, create=True):
        with pytest.raises(PermissionError, match="administrator"):
            authority_profile._check_posix_tree(profile_dir)
    with patch.object(authority_profile.os, "lstat", side_effect=owner_root), \
         patch.object(authority_profile.os, "getegid", return_value=1234, create=True):
        with pytest.raises(PermissionError, match="private key group"):
            authority_profile._check_posix_tree(profile_dir)


def test_windows_production_uses_handle_gate() -> None:
    failure = authority_profile.AuthorityProfileUnavailable("native handle gate unavailable")
    with patch.object(authority_profile.platform, "system", return_value="Windows"), \
         patch.object(authority_profile, "_build_windows_admin_transport",
                      side_effect=failure) as build:
        with pytest.raises(authority_profile.AuthorityProfileUnavailable,
                           match="native handle gate"):
            authority_profile.build_admin_authority_transport("default")
    build.assert_called_once_with("default")


@pytest.mark.skipif(os.name != "nt", reason="native Windows file sharing required")
def test_windows_pinned_objects_cannot_be_replaced_or_written(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path)
    cert = profile_dir / "client-cert.pem"
    key = profile_dir / "client-key.pem"
    with authority_profile._opened_windows_profile(profile_dir) as handles:
        assert cert in handles and key in handles
        with pytest.raises(OSError):
            profile_dir.rename(tmp_path / "replaced-profile")
        with pytest.raises(OSError):
            cert.rename(profile_dir / "replaced-cert.pem")
        with pytest.raises(OSError):
            key.open("r+b")
        assert cert.read_text(encoding="ascii") == "test fixture"


@pytest.mark.skipif(os.name != "nt", reason="native Windows security descriptors required")
def test_windows_dacl_policy_inspects_pinned_handles(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path)
    with authority_profile._opened_windows_profile(profile_dir) as handles:
        # The developer fixture cannot satisfy the administrator DACL policy.
        # This also exercises GetSecurityInfo on pinned Win32 handles.
        with patch.dict(sys.modules, {"sylanne3.host": _host_package}):
            with pytest.raises(PermissionError, match="owner|non-admin write"):
                authority_profile._check_windows_handles(profile_dir, handles)


@pytest.mark.skipif(os.name != "nt" or shutil.which("openssl") is None,
                    reason="native Windows OpenSSL fixture required")
def test_windows_openssl_consumes_cert_and_key_inside_pinned_window(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path)
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(profile_dir / "client-key.pem"),
        "-out", str(profile_dir / "client-cert.pem"),
        "-subj", "/CN=profile-test", "-days", "1", "-config", "NUL",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.copyfile(profile_dir / "client-cert.pem", profile_dir / "trust-root.pem")
    profile = AuthorityTlsProfile(
        "safe", "127.0.0.1", 9443, "authority.example.org",
        "authority:production", profile_dir / "trust-root.pem",
        profile_dir / "client-cert.pem", profile_dir / "client-key.pem",
    )
    with authority_profile._opened_windows_profile(profile_dir):
        context = profile.ssl_context()
    assert context.check_hostname is True


@pytest.mark.skipif(os.name != "nt", reason="Windows-only platform spoof")
def test_macos_cannot_be_claimed_by_platform_string_on_windows() -> None:
    with patch.object(authority_profile.platform, "system", return_value="Darwin"):
        with pytest.raises(authority_profile.AuthorityProfileUnavailable,
                           match="POSIX directory-descriptor"):
            authority_profile.build_admin_authority_transport("default")


def test_tls_descriptor_alias_fails_closed_without_matching_identity() -> None:
    with pytest.raises(authority_profile.AuthorityProfileUnavailable,
                       match="TLS descriptor alias"):
        authority_profile._tls_fd_path(999999, "Darwin")


def test_linux_acl_presence_or_unknown_semantics_fail_closed(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path)
    with patch.object(authority_profile.os, "getxattr", return_value=b"acl", create=True):
        with pytest.raises(PermissionError, match="ACL"):
            authority_profile._check_linux_acl_tree(profile_dir)
    with patch.object(authority_profile.os, "getxattr", side_effect=OSError(95, "unsupported"),
                      create=True):
        with pytest.raises(authority_profile.AuthorityProfileUnavailable,
                           match="ACL verification failed"):
            authority_profile._check_linux_acl_tree(profile_dir)
