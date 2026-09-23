"""Check installed release bytes against an administrator-pinned manifest."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import re
from typing import Literal


_MANIFEST = "release-manifest.json"
_NATIVE_NAMES = {
    "windows": "sylanne3_kernel.dll",
    "linux": "libsylanne3_kernel.so",
    "macos": "libsylanne3_kernel.dylib",
}
_ARCHES = {
    "windows": {"x86_64"},
    "linux": {"x86_64", "aarch64"},
    "macos": {"x86_64", "aarch64"},
}
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")

VerificationReason = Literal[
    "verified", "invalid_expected_digest", "manifest_missing", "manifest_digest_mismatch",
    "manifest_invalid", "platform_mismatch", "abi_mismatch", "cpu_features_unverified",
    "file_mismatch", "unlisted_executable", "unsafe_package_path", "scan_failed",
]


@dataclass(frozen=True, slots=True)
class InstalledPackageVerification:
    verified: bool
    reason: VerificationReason
    manifest_digest: str | None = None
    package_version: str | None = None
    build_mode: str | None = None
    failed_path: str | None = None


def _host_target() -> tuple[str | None, str | None]:
    os_name = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(platform.system())
    arch = {
        "AMD64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64",
    }.get(platform.machine())
    return os_name, arch


def _is_link(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def _safe_file(root: Path, relative: str) -> Path | None:
    if (not relative or "\\" in relative or "\x00" in relative or relative.startswith("/")):
        return None
    parts = relative.split("/")
    if any(part in {"", ".", ".."} for part in parts) or ":" in parts[0]:
        return None
    path = root
    for part in parts:
        path = path / part
        if _is_link(path):
            return None
    return path if path.is_file() else None


def _is_executable_file(name: str) -> bool:
    lowered = name.casefold()
    return (lowered.endswith((".py", ".pyc", ".pyw", ".pyd", ".dll", ".dylib", ".so", ".exe"))
            or ".so." in lowered)


def _unlisted_executable(root: Path, listed: dict[str, dict]) -> str | None:
    def raise_walk_error(error: OSError) -> None:
        raise error

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=raise_walk_error):
        folder = Path(directory)
        dirs[:] = [name for name in dirs if name != "__pycache__"]
        for name in dirs:
            candidate = folder / name
            if _is_link(candidate):
                return candidate.relative_to(root).as_posix()
        for name in files:
            if not _is_executable_file(name):
                continue
            candidate = folder / name
            relative = candidate.relative_to(root).as_posix()
            if relative not in listed or _is_link(candidate):
                return relative
    return None


def verify_installed_package(
    package_root: Path | str,
    expected_manifest_digest: str,
    *,
    available_cpu_features: frozenset[str] | None = None,
) -> InstalledPackageVerification:
    """Verify an extracted package; never turn this result into admission alone.

    ``available_cpu_features`` must come from a trusted host probe. A package
    requiring features cannot pass if the host has not supplied that evidence.
    """
    if not isinstance(expected_manifest_digest, str) or not _DIGEST.fullmatch(expected_manifest_digest):
        return InstalledPackageVerification(False, "invalid_expected_digest")
    root = Path(package_root).absolute()
    if any(_is_link(candidate) for candidate in (root, *root.parents)):
        return InstalledPackageVerification(False, "unsafe_package_path")
    manifest_path = _safe_file(root, _MANIFEST)
    if manifest_path is None:
        return InstalledPackageVerification(False, "manifest_missing")
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError:
        return InstalledPackageVerification(False, "manifest_missing")
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    if not hmac.compare_digest(digest, expected_manifest_digest):
        return InstalledPackageVerification(False, "manifest_digest_mismatch", digest)
    invalid = InstalledPackageVerification(False, "manifest_invalid", digest)
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return invalid
    if not isinstance(manifest, dict) or type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
        return invalid
    version = manifest.get("package_version")
    mode = manifest.get("build_mode")
    target = manifest.get("platform")
    native = manifest.get("native")
    entries = manifest.get("files")
    if (not isinstance(version, str) or not version or mode not in {"dev-probe", "formal-alpha1"}
            or not isinstance(target, dict) or not isinstance(native, dict)
            or not isinstance(entries, list) or not entries):
        return invalid
    os_name, arch = target.get("os"), target.get("arch")
    if (os_name not in _NATIVE_NAMES or arch not in _ARCHES[os_name]
            or target.get("native_filename") != _NATIVE_NAMES[os_name]):
        return invalid
    host_os, host_arch = _host_target()
    if (os_name, arch) != (host_os, host_arch):
        return InstalledPackageVerification(False, "platform_mismatch", digest)
    if type(target.get("abi_version")) is not int or target["abi_version"] != 2:
        return InstalledPackageVerification(False, "abi_mismatch", digest)
    libc = target.get("libc")
    if os_name == "linux":
        if libc not in {"glibc", "musl"}:
            return invalid
        if platform.libc_ver()[0] != libc:
            return InstalledPackageVerification(False, "platform_mismatch", digest)
    elif libc is not None:
        return invalid
    features = target.get("cpu_features")
    if (not isinstance(features, list) or any(not isinstance(item, str) for item in features)
            or features != sorted(set(features))
            or any(not re.fullmatch(r"[a-z0-9][a-z0-9_.+-]*", item) for item in features)):
        return invalid
    if not set(features).issubset(available_cpu_features or frozenset()):
        return InstalledPackageVerification(False, "cpu_features_unverified", digest)

    listed: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            return invalid
        relative = entry.get("path")
        size = entry.get("bytes")
        sha = entry.get("sha256")
        if (not isinstance(relative, str) or relative == _MANIFEST or relative in listed
                or type(size) is not int or size < 0 or not isinstance(sha, str)
                or not _DIGEST.fullmatch(sha)):
            return invalid
        listed[relative] = entry
    native_path = f"rewrite/sylanne3/_native/{os_name}-{arch}/{_NATIVE_NAMES[os_name]}"
    if native_path not in listed or native != listed[native_path]:
        return invalid
    for relative, entry in listed.items():
        path = _safe_file(root, relative)
        if path is None:
            return InstalledPackageVerification(False, "file_mismatch", digest, failed_path=relative)
        sha = hashlib.sha256()
        size = 0
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    size += len(chunk)
                    sha.update(chunk)
        except OSError:
            return InstalledPackageVerification(False, "file_mismatch", digest, failed_path=relative)
        if size != entry["bytes"] or not hmac.compare_digest(sha.hexdigest(), entry["sha256"]):
            return InstalledPackageVerification(False, "file_mismatch", digest, failed_path=relative)
    try:
        extra = _unlisted_executable(root, listed)
    except OSError:
        return InstalledPackageVerification(False, "scan_failed", digest)
    if extra is not None:
        return InstalledPackageVerification(False, "unlisted_executable", digest, failed_path=extra)
    return InstalledPackageVerification(True, "verified", digest, version, mode)
