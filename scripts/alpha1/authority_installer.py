"""Windows Authority deployment gate and local staging administration.

The diagnostic staging ZIP may include exact locked dependency wheels. This
tool verifies and lays it out under an explicit publisher key; that key is not
a product trust root and this tool does not register a Windows service.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

from authority_staging_package import MANIFEST_PATH, verify_staging_authority


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SID = re.compile(r"S-1-(?:[0-9]+-)+[0-9]+\Z")
_STATE = "authority-deployment.json"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_publisher_bundle(
    package: Path, signature: Path, publisher_key: Path, *,
    trusted_root_sha256: str, expected_package_sha256: str,
    expected_manifest_sha256: str,
) -> dict:
    """Verify an externally pinned Ed25519 publisher root and exact bundle."""
    if any(_SHA.fullmatch(value) is None for value in (
        trusted_root_sha256, expected_package_sha256, expected_manifest_sha256,
    )):
        raise ValueError("trusted root, package and manifest SHA256 pins are required")
    key_bytes = publisher_key.read_bytes()
    package_bytes = package.read_bytes()
    if _digest(key_bytes) != trusted_root_sha256:
        raise ValueError("publisher root differs from externally pinned digest")
    if _digest(package_bytes) != expected_package_sha256:
        raise ValueError("Authority package differs from externally pinned digest")
    if len(key_bytes) != 32:
        raise ValueError("publisher root must be raw Ed25519 public key bytes")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(
            signature.read_bytes(), b"sylanne.authority.bundle.v1\0" + package_bytes,
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Authority publisher signature differs") from exc
    verified = verify_staging_authority(
        package, expected_manifest_sha256=expected_manifest_sha256,
    )
    return {
        **verified,
        "publisher_key_sha256": trusted_root_sha256,
        "publisher_signature": "verified_against_supplied_pinned_key",
        "formal_publisher_root": "unproven",
        "service_installer": "absent",
        "cold_install_pass": False,
    }


def _require_elevated_windows() -> None:
    if os.name != "nt":
        raise RuntimeError("Windows installation requires Windows")
    from ctypes import WinDLL, byref, c_int, c_void_p, c_wchar_p, get_last_error

    advapi = WinDLL("advapi32", use_last_error=True)
    kernel = WinDLL("kernel32", use_last_error=True)
    sid = c_void_p()
    if not advapi.ConvertStringSidToSidW(c_wchar_p("S-1-5-32-544"), byref(sid)):
        raise OSError(get_last_error(), "cannot inspect Windows administrator token")
    try:
        member = c_int()
        if not advapi.CheckTokenMembership(c_void_p(), sid, byref(member)):
            raise OSError(get_last_error(), "cannot inspect effective administrator token")
        if not member.value:
            raise PermissionError("elevated Windows administrator token is required")
    finally:
        kernel.LocalFree(sid)


def _acl(path: Path, service_sid: str, service_right: str) -> None:
    if _SID.fullmatch(service_sid) is None:
        raise ValueError("service account SID is invalid")
    grants = (
        "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F",
        f"*{service_sid}:(OI)(CI){service_right}",
    )
    for args in (("/grant:r", *grants, "/T"), ("/inheritance:r", "/T")):
        subprocess.run(("icacls", str(path), *args), check=True,
                       capture_output=True, text=True)


def _install_bundled_wheels(code: Path, root: Path, digest: str) -> Path | None:
    manifest = json.loads((code / MANIFEST_PATH).read_bytes())
    wheels = manifest["wheels"]
    if not wheels:
        return None
    target = root / "dependencies" / digest
    if target.exists():
        raise FileExistsError("Authority private dependency version already exists")
    target.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="sylanne-authority-pip-") as temporary:
        requirements = Path(temporary) / "requirements.txt"
        by_name = {Path(row["path"]).name.split("-", 1)[0].replace("_", "-").lower(): row
                   for row in wheels}
        lines = []
        for line in manifest["dependencies"]:
            name = line.split("==", 1)[0].replace("_", "-").lower()
            lines.append(f'{line} --hash=sha256:{by_name[name]["sha256"]}')
        requirements.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = subprocess.run(
            (sys.executable, "-I", "-m", "pip", "install", "--no-index",
             "--no-deps", "--require-hashes", "--ignore-installed",
             "--no-cache-dir", "--disable-pip-version-check",
             "--find-links", str(code / "wheels"), "--target", str(target),
             "-r", str(requirements)),
            cwd=temporary, capture_output=True, text=True,
            env={name: value for name, value in os.environ.items()
                 if not name.upper().startswith(("PYTHON", "PIP_"))},
        )
        if result.returncode:
            raise RuntimeError("offline Authority wheel installation failed: "
                               + result.stderr.strip())
    return target


def prepare_install(
    root: Path, package: Path, verification: dict, *, service_sid: str,
    signature: Path, publisher_key: Path,
) -> dict:
    """Stage code separately from empty state and certificate directories.

    Installation stays disabled: no trusted callback registry, service wrapper,
    state initialization or formal publisher root is supplied here.
    """
    _require_elevated_windows()
    root = root.resolve()
    if root.exists() or root == package.resolve() or root.is_relative_to(Path(__file__).resolve().parents[2]):
        raise ValueError("installation root must be new and outside the source checkout")
    if _SID.fullmatch(service_sid) is None:
        raise ValueError("service account SID is invalid")
    code = root / "code" / verification["package_sha256"]
    state = root / "state"
    certificates = root / "certificates"
    trust = root / "trust" / verification["package_sha256"]
    code.mkdir(parents=True)
    state.mkdir()
    certificates.mkdir()
    trust.mkdir(parents=True)
    with zipfile.ZipFile(package) as archive:
        archive.extractall(code)
    dependencies = _install_bundled_wheels(code, root, verification["package_sha256"])
    (trust / "authority.zip").write_bytes(package.read_bytes())
    (trust / "publisher.sig").write_bytes(signature.read_bytes())
    (trust / "publisher.pub").write_bytes(publisher_key.read_bytes())
    marker = {
        "schema": "sylanne.authority.deployment-state.v1",
        "status": "disabled_diagnostic_staging",
        "package_sha256": verification["package_sha256"],
        "manifest_sha256": verification["manifest_sha256"],
        "publisher_key_sha256": verification["publisher_key_sha256"],
        "trust_dir": str(trust.relative_to(root)),
        "service_sid": service_sid,
        "service_registered": False,
        "dependency_dir": str(dependencies.relative_to(root)) if dependencies else None,
    }
    (root / _STATE).write_text(json.dumps(marker, sort_keys=True), encoding="utf-8")
    _acl(root, service_sid, "RX")
    _acl(code, service_sid, "RX")
    if dependencies:
        _acl(dependencies, service_sid, "RX")
    _acl(state, service_sid, "M")
    _acl(certificates, service_sid, "R")
    _acl(trust, service_sid, "R")
    return {**marker, "root": str(root), "cold_install_pass": False}


def _stopped_state(root: Path) -> dict:
    import msvcrt

    marker = json.loads((root / _STATE).read_bytes())
    if marker.get("schema") != "sylanne.authority.deployment-state.v1":
        raise ValueError("Authority deployment state differs")
    lock = root / "state" / "authority.lock"
    if lock.exists():
        with lock.open("r+b") as handle:
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError("Authority daemon is active; stop before maintenance") from exc
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    return marker


def prepare_upgrade(root: Path, package: Path, verification: dict, *,
                    signature: Path, publisher_key: Path) -> dict:
    _require_elevated_windows()
    root = root.resolve(strict=True)
    marker = _stopped_state(root)
    if marker.get("status") != "disabled_diagnostic_staging":
        raise RuntimeError("Authority must be disabled before code upgrade")
    code = root / "code" / verification["package_sha256"]
    trust = root / "trust" / verification["package_sha256"]
    if code.exists() or trust.exists():
        raise FileExistsError("Authority code version already staged")
    code.mkdir(parents=True)
    trust.mkdir(parents=True)
    with zipfile.ZipFile(package) as archive:
        archive.extractall(code)
    dependencies = _install_bundled_wheels(code, root, verification["package_sha256"])
    (trust / "authority.zip").write_bytes(package.read_bytes())
    (trust / "publisher.sig").write_bytes(signature.read_bytes())
    (trust / "publisher.pub").write_bytes(publisher_key.read_bytes())
    _acl(code, marker["service_sid"], "RX")
    if dependencies:
        _acl(dependencies, marker["service_sid"], "RX")
    _acl(trust, marker["service_sid"], "R")
    marker.update(
        package_sha256=verification["package_sha256"],
        manifest_sha256=verification["manifest_sha256"],
        publisher_key_sha256=verification["publisher_key_sha256"],
        trust_dir=str(trust.relative_to(root)),
        dependency_dir=str(dependencies.relative_to(root)) if dependencies else None,
    )
    temporary = root / (_STATE + ".tmp")
    temporary.write_text(json.dumps(marker, sort_keys=True), encoding="utf-8")
    temporary.replace(root / _STATE)
    return {**marker, "root": str(root), "cold_install_pass": False}


def disable(root: Path) -> dict:
    _require_elevated_windows()
    root = root.resolve(strict=True)
    marker = _stopped_state(root)
    marker["status"] = "disabled_diagnostic_staging"
    (root / _STATE).write_text(json.dumps(marker, sort_keys=True), encoding="utf-8")
    return {**marker, "root": str(root), "cold_install_pass": False}


_COLD_PROBE = """
import importlib, importlib.metadata, json, sys
from pathlib import Path
code = Path(sys.argv[1]).resolve(strict=True)
source = Path(sys.argv[2]).resolve(strict=True)
requirements = json.loads(sys.argv[3])
entrypoints = json.loads(sys.argv[4])
dependencies = Path(sys.argv[5]).resolve(strict=True)
assert sys.flags.isolated and sys.dont_write_bytecode
assert all(not Path(part).resolve().is_relative_to(source) for part in sys.path if part)
if dependencies.is_relative_to(source) or dependencies.is_relative_to(code):
    raise RuntimeError('dependency root must be outside source and installed code')
sys.path.insert(0, str(dependencies))
versions = {}
for requirement in requirements:
    name, expected = requirement.split('==', 1)
    distribution = importlib.metadata.distribution(name)
    if not Path(distribution.locate_file('')).resolve().is_relative_to(dependencies):
        raise RuntimeError(f'dependency escaped explicit root: {name}')
    actual = distribution.version
    if actual != expected:
        raise RuntimeError(f'installed dependency differs: {name} {actual} != {expected}')
    loaded = importlib.import_module(name.replace('-', '_'))
    if not Path(loaded.__file__).resolve().is_relative_to(dependencies):
        raise RuntimeError(f'loaded dependency escaped explicit root: {name}')
    versions[name] = actual
sys.path.insert(0, str(code))
for name in entrypoints:
    module = importlib.import_module(name)
    if not Path(module.__file__).resolve().is_relative_to(code):
        raise RuntimeError(f'Authority entrypoint escaped installed code: {name}')
for name, module in sys.modules.items():
    if (name == 'rewrite' or name.startswith('rewrite.')) and getattr(module, '__file__', None):
        if not Path(module.__file__).resolve().is_relative_to(code):
            raise RuntimeError(f'Authority module escaped installed code: {name}')
print(json.dumps({'entrypoints_imported': len(entrypoints), 'installed_dependencies': versions}))
"""


def verify_disabled_install(root: Path, *, trusted_root_sha256: str,
                            expected_package_sha256: str,
                            expected_manifest_sha256: str,
                            dependency_root: Path | None = None) -> dict:
    """Reopen a disabled staging layout with external pins and local Python.

    This is an installed-code diagnostic; the source-only package cannot pass
    the formal release gate or establish a self-contained cold install.
    """
    _require_elevated_windows()
    root = root.resolve(strict=True)
    marker = _stopped_state(root)
    if (marker.get("status") != "disabled_diagnostic_staging"
            or marker.get("service_registered") is not False):
        raise RuntimeError("Authority staging must remain disabled and unregistered")
    if any(marker.get(field) != expected for field, expected in (
        ("publisher_key_sha256", trusted_root_sha256),
        ("package_sha256", expected_package_sha256),
        ("manifest_sha256", expected_manifest_sha256),
    )):
        raise ValueError("installed Authority pins differ from external pins")
    code = root / "code" / expected_package_sha256
    trust = root / "trust" / expected_package_sha256
    if marker.get("trust_dir") != str(trust.relative_to(root)):
        raise ValueError("installed Authority trust directory differs")
    paths = (root, code.parent, code, trust.parent, trust,
             root / "state", root / "certificates")
    if any(not path.is_dir() or path.is_symlink() for path in paths):
        raise ValueError("installed Authority directory is absent or linked")
    if any((trust / name).is_symlink() for name in
           ("authority.zip", "publisher.sig", "publisher.pub")):
        raise ValueError("installed Authority trust file is linked")
    verified = verify_publisher_bundle(
        trust / "authority.zip", trust / "publisher.sig", trust / "publisher.pub",
        trusted_root_sha256=trusted_root_sha256,
        expected_package_sha256=expected_package_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    with zipfile.ZipFile(trust / "authority.zip") as archive:
        manifest = json.loads(archive.read(MANIFEST_PATH))
        expected_files = {MANIFEST_PATH, *(row["path"] for row in manifest["files"])}
        actual_files = {path.relative_to(code).as_posix() for path in code.rglob("*")
                        if path.is_file()}
        if actual_files != expected_files or any(path.is_symlink() for path in code.rglob("*")):
            raise ValueError("installed Authority code file set differs")
        for relative in expected_files:
            if (code / relative).read_bytes() != archive.read(relative):
                raise ValueError(f"installed Authority code differs: {relative}")
    with tempfile.TemporaryDirectory(prefix="sylanne-authority-cold-") as temporary:
        if manifest["wheels"]:
            expected_dependency_dir = str(Path("dependencies") / expected_package_sha256)
            if marker.get("dependency_dir") != expected_dependency_dir:
                raise ValueError("installed Authority private dependency directory differs")
            dependency_root = root / expected_dependency_dir
        elif dependency_root is None:
            raise ValueError("source-only staging requires an explicit dependency root")
        dependency_root = dependency_root.resolve(strict=True)
        if not dependency_root.is_dir():
            raise ValueError("explicit dependency root must be a directory")
        if manifest["wheels"] and (dependency_root.is_symlink()
                                   or (root / "dependencies").is_symlink()):
            raise ValueError("installed Authority dependency directory is linked")
        environment = {name: value for name, value in os.environ.items()
                       if not name.upper().startswith(("PYTHON", "RUST", "CARGO"))}
        result = subprocess.run(
            (sys.executable, "-I", "-B", "-c", _COLD_PROBE, str(code),
             str(Path(__file__).resolve().parents[2]),
             json.dumps(manifest["dependencies"]), json.dumps(manifest["entrypoints"]),
             str(dependency_root)),
            cwd=temporary, env=environment, capture_output=True, text=True,
        )
        if result.returncode:
            raise RuntimeError("installed Authority import/dependency probe failed: "
                               + result.stderr.strip())
    return {**verified, **json.loads(result.stdout),
            "status": "disabled_installed_diagnostic",
            "dependency_runtime": ("bundled_offline_private_root" if manifest["wheels"]
                                   else "explicit_local_dependency_root"),
            "cold_install_pass": False}


def main() -> None:
    parser = argparse.ArgumentParser(description="Windows Authority signed staging gate")
    parser.add_argument("action", choices=("verify", "prepare-install", "prepare-upgrade", "disable", "verify-disabled"))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--publisher-key", type=Path)
    parser.add_argument("--trusted-root-sha256")
    parser.add_argument("--expected-package-sha256")
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--service-sid")
    parser.add_argument("--dependency-root", type=Path)
    args = parser.parse_args()
    if args.action == "verify-disabled":
        if args.root is None or any(value is None for value in (
            args.trusted_root_sha256, args.expected_package_sha256,
            args.expected_manifest_sha256,
        )):
            parser.error("verify-disabled requires root and all three external SHA256 pins")
        result = verify_disabled_install(
            args.root, trusted_root_sha256=args.trusted_root_sha256,
            expected_package_sha256=args.expected_package_sha256,
            expected_manifest_sha256=args.expected_manifest_sha256,
            dependency_root=args.dependency_root,
        )
    elif args.action == "disable":
        if args.root is None:
            parser.error("disable requires --root")
        result = disable(args.root)
    else:
        required = (args.package, args.signature, args.publisher_key,
                    args.trusted_root_sha256, args.expected_package_sha256,
                    args.expected_manifest_sha256)
        if any(value is None for value in required):
            parser.error("verification requires package, signature, publisher key and all three SHA256 pins")
        verified = verify_publisher_bundle(
            args.package, args.signature, args.publisher_key,
            trusted_root_sha256=args.trusted_root_sha256,
            expected_package_sha256=args.expected_package_sha256,
            expected_manifest_sha256=args.expected_manifest_sha256,
        )
        if args.action == "verify":
            result = verified
        else:
            if args.root is None:
                parser.error("installation preparation requires --root")
            if args.action == "prepare-install":
                if args.service_sid is None:
                    parser.error("prepare-install requires --service-sid")
                result = prepare_install(args.root, args.package, verified,
                                         service_sid=args.service_sid,
                                         signature=args.signature,
                                         publisher_key=args.publisher_key)
            else:
                result = prepare_upgrade(args.root, args.package, verified,
                                         signature=args.signature,
                                         publisher_key=args.publisher_key)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
