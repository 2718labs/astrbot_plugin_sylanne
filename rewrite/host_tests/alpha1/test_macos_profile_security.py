"""The Darwin ACL verifier must fail closed even in platform-mocked tests."""

from __future__ import annotations

import ctypes
import errno
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
from types import SimpleNamespace
from unittest.mock import patch

import pytest


SOURCE = Path(__file__).resolve().parents[2] / "sylanne3" / "host" / "macos_profile_security.py"
SPEC = importlib.util.spec_from_file_location("macos_profile_security", SOURCE)
assert SPEC is not None and SPEC.loader is not None
security = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(security)


class _Function:
    def __init__(self, result):
        self.result = result

    def __call__(self, *args):
        return self.result(*args) if callable(self.result) else self.result


def _libc(entry_result: int, *, acl=123, valid=0, entry_errno=errno.EINVAL):
    def get_entry(*_args):
        ctypes.set_errno(entry_errno if entry_result == -1 else 0)
        return entry_result

    return SimpleNamespace(
        acl_get_fd_np=_Function(acl),
        acl_get_entry=_Function(get_entry),
        acl_valid_fd_np=_Function(valid),
        acl_free=_Function(0),
    )


def test_extended_acl_entry_is_rejected() -> None:
    with patch.object(security.platform, "system", return_value="Darwin"), \
         patch.object(security.ctypes, "CDLL", return_value=_libc(0)):
        with pytest.raises(PermissionError, match="extended ACL"):
            security.reject_extended_acl(4)


def test_acl_query_failure_is_rejected() -> None:
    with patch.object(security.platform, "system", return_value="Darwin"), \
         patch.object(security.ctypes, "CDLL", return_value=_libc(-1, acl=0)):
        with pytest.raises(security.MacOSProfileSecurityUnavailable,
                           match="ACL query failed"):
            security.reject_extended_acl(4)


def test_empty_extended_acl_is_allowed() -> None:
    with patch.object(security.platform, "system", return_value="Darwin"), \
         patch.object(security.ctypes, "CDLL", return_value=_libc(-1)):
        security.reject_extended_acl(4)


def test_invalid_acl_is_rejected_even_when_entry_lookup_reports_einval() -> None:
    with patch.object(security.platform, "system", return_value="Darwin"), \
         patch.object(security.ctypes, "CDLL", return_value=_libc(-1, valid=-1)):
        with pytest.raises(security.MacOSProfileSecurityUnavailable,
                           match="ACL validation failed"):
            security.reject_extended_acl(4)


def test_unexpected_empty_acl_error_is_rejected() -> None:
    with patch.object(security.platform, "system", return_value="Darwin"), \
         patch.object(security.ctypes, "CDLL",
                      return_value=_libc(-1, entry_errno=errno.EIO)):
        with pytest.raises(security.MacOSProfileSecurityUnavailable,
                           match="ACL entry query failed"):
            security.reject_extended_acl(4)


@pytest.mark.skipif(sys.platform != "darwin", reason="native Darwin ACL and /dev/fd required")
def test_native_darwin_acl_and_fd_alias_load_real_tls_material() -> None:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.fail("Darwin TLS smoke requires an openssl fixture generator")
    with tempfile.TemporaryDirectory(prefix="sylanne-macos-profile-") as directory:
        root = Path(directory)
        cert = root / "client-cert.pem"
        key = root / "client-key.pem"
        trust = root / "trust-root.pem"
        result = subprocess.run([
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert),
            "-subj", "/CN=profile-smoke", "-days", "1",
        ], capture_output=True)
        if result.returncode:
            pytest.fail("Darwin TLS smoke could not create its local certificate fixture")
        shutil.copyfile(cert, trust)
        host_package = types.ModuleType("sylanne3.host")
        host_package.__path__ = [str(SOURCE.parent)]
        with patch.dict(sys.modules, {"sylanne3.host": host_package}):
            import importlib
            profile = importlib.import_module("sylanne3.host.authority_profile")
            opened: dict[str, int] = {}
            try:
                for name, path in (
                    ("trust-root.pem", trust), ("client-cert.pem", cert),
                    ("client-key.pem", key),
                ):
                    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                    opened[name] = fd
                    security.reject_extended_acl(fd)
                context = profile._prepared_ssl_context(opened, "Darwin")
                assert context.check_hostname is True
            finally:
                for fd in opened.values():
                    os.close(fd)
