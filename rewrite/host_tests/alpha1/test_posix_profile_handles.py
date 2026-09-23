"""Native Linux checks for pinned Authority profile objects (run on ext4/tmpfs)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


_host_package = types.ModuleType("sylanne3.host")
_host_package.__path__ = [str(Path(__file__).resolve().parents[2] / "sylanne3" / "host")]
sys.modules.setdefault("sylanne3.host", _host_package)
from sylanne3.host import authority_profile  # noqa: E402


@unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0
                     and shutil.which("openssl") and Path("/run").is_dir(),
                     "native Linux root fixture with openssl and /run required")
class PosixProfileHandleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sylanne-profile-", dir="/run")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        self.profile = self.root / "safe"
        self.profile.mkdir(mode=0o755)
        (self.profile / "profile.json").write_text(json.dumps({
            "schema": 1, "host": "127.0.0.1", "port": 9443,
            "server_name": "authority.example.org",
            "expected_authority_id": "authority:production",
        }), encoding="utf-8")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(self.profile / "client-key.pem"),
            "-out", str(self.profile / "client-cert.pem"),
            "-subj", "/CN=profile-test", "-days", "1",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.copyfile(self.profile / "client-cert.pem", self.profile / "trust-root.pem")
        for name in ("profile.json", "trust-root.pem", "client-cert.pem"):
            (self.profile / name).chmod(0o644)
        key = self.profile / "client-key.pem"
        os.chown(key, 0, 65534)
        key.chmod(0o640)

    def test_nonadmin_process_loads_only_pinned_material(self) -> None:
        source = Path(__file__).resolve().parents[2]
        code = (
            "import sys,types; from pathlib import Path; "
            "h=types.ModuleType('sylanne3.host'); "
            f"h.__path__=[{str(source / 'sylanne3' / 'host')!r}]; "
            "sys.modules['sylanne3.host']=h; "
            "from sylanne3.host.authority_profile import _load_profile_from_root; "
            f"p=_load_profile_from_root('safe',Path({str(self.root)!r}),prepare_tls=True); "
            "assert p.prepared_ssl_context is not None"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": str(source)},
            preexec_fn=lambda: (os.setgid(65534), os.setuid(65534)),
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_symlink_and_writable_ancestor_are_rejected(self) -> None:
        self.profile.chmod(0o777)
        with self.assertRaises(PermissionError):
            authority_profile._load_profile_from_root("safe", self.root, prepare_tls=True)
        self.profile.chmod(0o755)
        cert = self.profile / "client-cert.pem"
        cert.rename(self.profile / "original-cert.pem")
        cert.symlink_to("original-cert.pem")
        with self.assertRaises(OSError):
            authority_profile._load_profile_from_root("safe", self.root, prepare_tls=True)

    def test_descriptor_acl_presence_is_rejected(self) -> None:
        with patch.object(authority_profile.os, "getxattr", return_value=b"acl") as read_acl:
            with self.assertRaisesRegex(PermissionError, "ACL"):
                authority_profile._load_profile_from_root("safe", self.root, prepare_tls=True)
        self.assertIsInstance(read_acl.call_args.args[0], int)

    def test_replaced_path_after_open_does_not_change_tls_material(self) -> None:
        alias = authority_profile._tls_fd_path
        cert = self.profile / "client-cert.pem"
        swapped = False

        def replace_after_open(fd: int, system: str) -> str:
            nonlocal swapped
            if not swapped:
                cert.rename(self.profile / "original-cert.pem")
                cert.write_text("replacement is not a certificate", encoding="ascii")
                swapped = True
            return alias(fd, system)

        with patch.object(authority_profile, "_tls_fd_path", side_effect=replace_after_open), \
             patch.object(authority_profile.os, "getegid", return_value=65534):
            loaded = authority_profile._load_profile_from_root(
                "safe", self.root, prepare_tls=True)
        self.assertTrue(swapped)
        self.assertIsNotNone(loaded.prepared_ssl_context)


if __name__ == "__main__":
    unittest.main()
