"""Windows SCM phases for a pinned Authority installation.

Current source-only staging artifacts cannot pass the formal activation gate.
The commands are fail-closed until a release package, trusted publisher root,
installed assets and elevated administrator are available.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time

from authority_installer import _require_elevated_windows, verify_publisher_bundle
from authority_windows_service import SERVICE_NAME


_FORMAL_STATUS = "formal_authority_release"


def _installation(root: Path, trusted_root_sha256: str) -> tuple[dict, Path, Path, Path, dict]:
    root = root.resolve(strict=True)
    marker = json.loads((root / "authority-deployment.json").read_bytes())
    if marker.get("schema") != "sylanne.authority.deployment-state.v1":
        raise ValueError("installed Authority state schema differs")
    if marker.get("publisher_key_sha256") != trusted_root_sha256:
        raise ValueError("installed publisher root differs from externally pinned root")
    digest = marker["package_sha256"]
    code = root / "code" / digest
    trust = root / marker["trust_dir"]
    assets = root / "state" / "installed-assets.json"
    if (not code.is_dir() or not trust.is_dir() or not assets.is_file()
            or any(path.is_symlink() for path in (root, code, trust, assets))):
        raise ValueError("installed Authority code, trust or assets are absent or unsafe")
    verified = verify_publisher_bundle(
        trust / "authority.zip", trust / "publisher.sig", trust / "publisher.pub",
        trusted_root_sha256=trusted_root_sha256,
        expected_package_sha256=digest,
        expected_manifest_sha256=marker["manifest_sha256"],
    )
    return marker, code, trust, assets, verified


def _formal(marker: dict, verified: dict) -> None:
    if (marker.get("status") != _FORMAL_STATUS
            or verified.get("status") != _FORMAL_STATUS
            or verified.get("formal_publisher_root") != "installed"):
        raise RuntimeError("formal Authority publisher/service activation remains HOLD")


def _sc(*args: str) -> str:
    result = subprocess.run(("sc.exe", *args), check=True,
                            capture_output=True, text=True)
    return result.stdout


def _state() -> int:
    output = _sc("query", SERVICE_NAME)
    match = re.search(r"STATE\s*:\s*(\d+)", output)
    if match is None:
        raise RuntimeError("Windows SCM state could not be read")
    return int(match.group(1))


def _wait_state(target: int) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if _state() == target:
            return
        time.sleep(0.2)
    raise RuntimeError("Authority SCM did not reach requested state")


def register(root: Path, trusted_root_sha256: str, service_account: str) -> dict:
    _require_elevated_windows()
    marker, code, trust, assets, verified = _installation(root, trusted_root_sha256)
    _formal(marker, verified)
    if marker.get("service_registered"):
        raise RuntimeError("Authority service is already registered")
    if service_account != "NT SERVICE\\" + SERVICE_NAME:
        raise ValueError("Authority must use its dedicated virtual service account")
    launch = subprocess.list2cmdline([
        sys.executable, str(code / "scripts/alpha1/authority_windows_service.py"),
        "service", "--code", str(code), "--assets", str(assets),
        "--package", str(trust / "authority.zip"),
        "--signature", str(trust / "publisher.sig"),
        "--publisher-key", str(trust / "publisher.pub"),
        "--trusted-root-sha256", trusted_root_sha256,
        "--expected-package-sha256", marker["package_sha256"],
        "--expected-manifest-sha256", marker["manifest_sha256"],
    ])
    _sc("create", SERVICE_NAME, "binPath=", launch,
        "start=", "demand", "obj=", service_account)
    _sc("sidtype", SERVICE_NAME, "unrestricted")
    marker["service_registered"] = True
    (root / "authority-deployment.json").write_text(
        json.dumps(marker, sort_keys=True), encoding="utf-8")
    return {"status": "registered_stopped", "service": SERVICE_NAME,
            "package_sha256": marker["package_sha256"]}


def start(root: Path, trusted_root_sha256: str) -> dict:
    _require_elevated_windows()
    marker, _, _, _, verified = _installation(root, trusted_root_sha256)
    _formal(marker, verified)
    if not marker.get("service_registered"):
        raise RuntimeError("Authority Windows service is not registered")
    _sc("start", SERVICE_NAME)
    _wait_state(4)
    return {"status": "scm_running", "service": SERVICE_NAME}


def stop(root: Path, trusted_root_sha256: str) -> dict:
    _require_elevated_windows()
    marker, _, _, _, verified = _installation(root, trusted_root_sha256)
    _formal(marker, verified)
    if not marker.get("service_registered"):
        raise RuntimeError("Authority Windows service is not registered")
    if _state() != 1:
        _sc("stop", SERVICE_NAME)
    _wait_state(1)
    return {"status": "scm_stopped", "service": SERVICE_NAME}


def upgrade(root: Path, trusted_root_sha256: str) -> dict:
    _require_elevated_windows()
    marker, _, _, _, verified = _installation(root, trusted_root_sha256)
    _formal(marker, verified)
    raise RuntimeError("formal Authority upgrade requires an accepted release artifact; HOLD")


def main() -> None:
    parser = argparse.ArgumentParser(description="Pinned Windows Authority SCM phases")
    parser.add_argument("action", choices=("register", "start", "stop", "upgrade"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--trusted-root-sha256", required=True)
    parser.add_argument("--service-account", default="NT SERVICE\\" + SERVICE_NAME)
    args = parser.parse_args()
    actions = {
        "register": lambda: register(args.root, args.trusted_root_sha256, args.service_account),
        "start": lambda: start(args.root, args.trusted_root_sha256),
        "stop": lambda: stop(args.root, args.trusted_root_sha256),
        "upgrade": lambda: upgrade(args.root, args.trusted_root_sha256),
    }
    print(json.dumps(actions[args.action](), sort_keys=True))


if __name__ == "__main__":
    main()
