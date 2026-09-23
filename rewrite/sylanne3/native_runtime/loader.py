from __future__ import annotations

import ctypes
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import platform
import re
from typing import Callable

from .abi2 import ABI2StepInput, ABI2StepResult, ABI_VERSION


MANIFEST_NAME = "release-manifest.json"
CANONICAL_LIBRARIES = {
    "windows": "sylanne3_kernel.dll",
    "linux": "libsylanne3_kernel.so",
    "macos": "libsylanne3_kernel.dylib",
}
ARCHITECTURES = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}
TARGET_MATRIX = {
    "windows": frozenset({"x86_64"}),
    "linux": frozenset({"x86_64", "aarch64"}),
    "macos": frozenset({"x86_64", "aarch64"}),
}


class NativeLoadError(RuntimeError):
    pass


class NativeIntegrityError(NativeLoadError):
    pass


class NativePlatformError(NativeLoadError):
    pass


@dataclass(frozen=True)
class NativeCapabilities:
    abi_version: int
    max_dimension: int
    numerically_certified: bool = False
    supports_cancellation: bool = False
    diagnostic_only: bool = True


class ABI2NativeLibrary:
    """A validated ABI2 library handle; raw pointer execution is not public."""

    def __init__(self, library: object, path: Path) -> None:
        self.path = path
        version = library.sylanne3_v2_abi_version
        version.argtypes = []
        version.restype = ctypes.c_uint32
        maximum = library.sylanne3_v2_max_dimension
        maximum.argtypes = []
        maximum.restype = ctypes.c_uint32
        step = library.sylanne3_v2_step
        step.argtypes = [
            ctypes.POINTER(ABI2StepInput),
            ctypes.POINTER(ctypes.c_double),
            ctypes.c_uint32,
            ctypes.POINTER(ABI2StepResult),
        ]
        step.restype = ctypes.c_int32
        abi = int(version())
        max_dimension = int(maximum())
        if abi != ABI_VERSION:
            raise NativePlatformError(f"loaded native library reports ABI {abi}, expected ABI 2")
        if not 1 <= max_dimension <= 65_536:
            raise NativeIntegrityError("native maximum dimension is outside the ABI2 contract")
        self._library = library
        self._step = step
        self.capabilities = NativeCapabilities(abi, max_dimension)


def _runtime_target() -> tuple[str, str, str | None]:
    system = platform.system().lower()
    try:
        os_name = {"windows": "windows", "linux": "linux", "darwin": "macos"}[system]
        arch = ARCHITECTURES[platform.machine().lower()]
    except KeyError as exc:
        raise NativePlatformError(
            f"unsupported runtime platform: {platform.system()} {platform.machine()}"
        ) from exc
    if arch not in TARGET_MATRIX[os_name]:
        raise NativePlatformError(
            f"unsupported runtime platform: {platform.system()} {platform.machine()}"
        )
    libc = None
    if os_name == "linux":
        family = platform.libc_ver()[0].strip().lower()
        if not family:
            raise NativePlatformError("unable to identify Linux libc")
        libc = "glibc" if family in {"glibc", "gnu libc"} else family
    return os_name, arch, libc


def _safe_relative(path: str) -> bool:
    if not path or "\\" in path or path.startswith("/") or "\x00" in path:
        return False
    parts = path.split("/")
    return all(part not in {"", ".", ".."} for part in parts) and str(PurePosixPath(path)) == path


def _sha256(path_or_bytes: Path | bytes) -> str:
    content = path_or_bytes if isinstance(path_or_bytes, bytes) else path_or_bytes.read_bytes()
    return hashlib.sha256(content).hexdigest()


def _is_linklike(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(is_junction is not None and is_junction())


def _require_hash(value: str, name: str) -> str:
    normalized = value.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise NativeIntegrityError(f"{name} must be a SHA256 digest")
    return normalized


def load_production_native(
    package_root: Path | str | None = None,
    *,
    trusted_manifest_sha256: str,
    _cdll_factory: Callable[[str], object] = ctypes.CDLL,
) -> ABI2NativeLibrary:
    """Load exactly one package-bound ABI2 asset after external trust verification."""
    root = Path(package_root).resolve() if package_root is not None else Path(__file__).resolve().parents[3]
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file() or _is_linklike(manifest_path):
        raise NativeIntegrityError(f"missing safe {MANIFEST_NAME}")
    raw = manifest_path.read_bytes()
    expected_manifest_hash = _require_hash(trusted_manifest_sha256, "manifest trust root")
    if not hmac.compare_digest(_sha256(raw), expected_manifest_hash):
        raise NativeIntegrityError("manifest trust root mismatch")
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeIntegrityError("release manifest is invalid JSON") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise NativeIntegrityError("unsupported release manifest schema")

    os_name, arch, libc = _runtime_target()
    platform_entry = manifest.get("platform")
    if not isinstance(platform_entry, dict):
        raise NativeIntegrityError("release manifest platform is missing")
    expected_filename = CANONICAL_LIBRARIES[os_name]
    if platform_entry.get("abi_version") != ABI_VERSION:
        raise NativePlatformError("production native package must provide ABI 2")
    if platform_entry.get("os") != os_name or platform_entry.get("arch") != arch:
        raise NativePlatformError("native package OS/architecture does not match this runtime")
    if platform_entry.get("native_filename") != expected_filename:
        raise NativePlatformError("native filename is not canonical for this runtime")
    if platform_entry.get("libc") != libc:
        raise NativePlatformError("native package libc does not match this runtime")
    cpu_features = platform_entry.get("cpu_features")
    if cpu_features != []:
        raise NativePlatformError("this loader cannot prove requested optional CPU features")

    relative = f"rewrite/sylanne3/_native/{os_name}-{arch}/{expected_filename}"
    native_claim = manifest.get("native")
    if not isinstance(native_claim, dict) or native_claim.get("path") != relative:
        raise NativeIntegrityError("release manifest native claim is missing or non-canonical")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise NativeIntegrityError("release manifest files must be a list")
    listed: dict[str, dict[str, object]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise NativeIntegrityError("invalid release manifest file entry")
        member = entry["path"]
        if not _safe_relative(member) or member in listed:
            raise NativeIntegrityError("unsafe or duplicate release manifest path")
        listed[member] = entry
    native_entry = listed.get(relative)
    if native_entry is None:
        raise NativeIntegrityError("canonical native asset is absent from the release manifest")
    if native_claim != native_entry:
        raise NativeIntegrityError("release manifest native claim disagrees with files entry")
    unresolved_library = root / Path(relative)
    if _is_linklike(unresolved_library) or any(
        _is_linklike(path)
        for path in (
            root / Path(*Path(relative).parts[:index])
            for index in range(1, len(Path(relative).parts))
        )
    ):
        raise NativeIntegrityError("canonical native asset path contains a symlink")
    library_path = unresolved_library.resolve()
    expected_parent = (root / Path(relative).parent).resolve()
    if library_path.parent != expected_parent or not library_path.is_file() or library_path.is_symlink():
        raise NativeIntegrityError("canonical native asset is missing, escaped, or a symlink")
    content_size = library_path.stat().st_size
    if native_entry.get("bytes") != content_size:
        raise NativeIntegrityError("native byte count mismatch")
    expected_native_hash = native_entry.get("sha256")
    if not isinstance(expected_native_hash, str) or _sha256(library_path) != _require_hash(expected_native_hash, "native SHA256"):
        raise NativeIntegrityError("native SHA256 mismatch")
    try:
        library = _cdll_factory(str(library_path))
    except OSError as exc:
        raise NativeLoadError(f"canonical native library could not be loaded: {exc}") from exc
    return ABI2NativeLibrary(library, library_path)
