from __future__ import annotations

import ctypes
import _ctypes
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

from sylanne3.native_runtime import (
    ABI2NativeLibrary,
    ABI2ResultError,
    FixedBlockCSR,
    FixedBlockStep,
    load_production_native,
    run_fixed_block_math,
)


def _block() -> FixedBlockStep:
    offsets = [0, 1, 2]
    diagonal = [0, 1]
    k = FixedBlockCSR(2, 2, offsets, diagonal, [2.0, 2.0])
    r = FixedBlockCSR(2, 2, offsets, diagonal, [1.0, 1.0])
    j = FixedBlockCSR(2, 2, offsets, [1, 0], [0.2, -0.2])
    a = FixedBlockCSR(0, 2, [0], [], [])
    previous = [0.4, -0.2]
    block = FixedBlockStep(k, r, j, a, [], previous, [0.0, 0.0], previous,
                           0.1, 1e-4, 30, 1e-10)
    offsets[1] = 0
    previous[0] = 100.0
    return block


class FixedBlockTranscriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = Path(__file__).resolve().parents[4]
        native_root = root / "rewrite" / "native"
        subprocess.run(["cargo", "build", "--quiet"], cwd=native_root, check=True, timeout=120)
        cls.native_asset = native_root / "target" / "debug" / {
            "Windows": "sylanne3_kernel.dll",
            "Linux": "libsylanne3_kernel.so",
            "Darwin": "libsylanne3_kernel.dylib",
        }[platform.system()]

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        root = Path(self.tempdir.name)
        os_name = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}[platform.system()]
        arch = {"AMD64": "x86_64", "x86_64": "x86_64", "ARM64": "aarch64", "aarch64": "aarch64"}[platform.machine()]
        libc = None
        if os_name == "linux":
            family = platform.libc_ver()[0].strip().lower()
            libc = "glibc" if family in {"glibc", "gnu libc"} else family
        relative = f"rewrite/sylanne3/_native/{os_name}-{arch}/{self.native_asset.name}"
        asset = root / relative
        asset.parent.mkdir(parents=True)
        shutil.copyfile(self.native_asset, asset)
        native_entry = {"path": relative, "bytes": asset.stat().st_size,
                        "sha256": hashlib.sha256(asset.read_bytes()).hexdigest()}
        manifest = {
            "schema_version": 1,
            "native_math": {"contract": "abi2.fixed-block-interval.v1", "capability_flags": 1},
            "platform": {"os": os_name, "arch": arch, "abi_version": 2,
                         "native_filename": asset.name, "libc": libc, "cpu_features": []},
            "native": native_entry,
            "files": [native_entry],
        }
        raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
        (root / "release-manifest.json").write_bytes(raw)
        self.handle = load_production_native(root, trusted_manifest_sha256=hashlib.sha256(raw).hexdigest())
        self.addCleanup(self._unload_package_library)

    def _unload_package_library(self) -> None:
        library = self.handle._library
        if platform.system() == "Windows":
            _ctypes.FreeLibrary(library._handle)
        else:
            _ctypes.dlclose(library._handle)
        library._handle = 0

    def test_real_package_bound_step_retains_actual_values_and_hashes(self) -> None:
        block = _block()
        transcript = run_fixed_block_math(self.handle, block)
        self.assertEqual(transcript.input.previous, (0.4, -0.2))
        self.assertEqual(transcript.input.k.offsets, (0, 1, 2))
        self.assertEqual(len(transcript.output), 2)
        self.assertNotEqual(transcript.output, transcript.input.previous)
        self.assertEqual(transcript.bounds.certificate_flags, 1)
        self.assertEqual(transcript.input_sha256, block.digest())
        self.assertEqual(transcript.production_binding, self.handle.production_binding)
        output_bytes = json.dumps(transcript.output, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        self.assertEqual(transcript.output_sha256, hashlib.sha256(output_bytes).hexdigest())
        self.assertEqual(transcript.production_binding.native_sha256,
                         hashlib.sha256(self.native_asset.read_bytes()).hexdigest())
        self.assertEqual(len(transcript.transcript_sha256), 64)
        self.assertNotEqual(transcript.input_sha256, replace(block, previous_error=2e-4).digest())
        with self.assertRaises(FrozenInstanceError):
            transcript.output = (0.0, 0.0)

    def test_direct_handle_and_incomplete_block_do_not_emit_transcript(self) -> None:
        direct = ABI2NativeLibrary(ctypes.CDLL(str(self.native_asset)), self.native_asset)
        with self.assertRaisesRegex(ABI2ResultError, "package-bound"):
            run_fixed_block_math(direct, _block())
        with self.assertRaisesRegex(ValueError, "zero boundary eta"):
            replace(_block(), boundary_eta=0.01)


if __name__ == "__main__":
    unittest.main()
