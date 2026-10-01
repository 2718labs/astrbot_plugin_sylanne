"""Diagnostic Windows Authority child-process reopen from an installed layout.

Disposable state and mTLS keys are created by the existing cold-open fixture.
The code is extracted from a staging ZIP; no key or trust root is embedded in
that ZIP or this script. This is not a service installer or publisher proof.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import zipfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authority_staging_package import build_staging_authority


ROOT = Path(__file__).resolve().parents[2]


def _asset_document(config) -> dict:
    (certificate, profile), installation = next(iter(config.installations_v2.items()))
    (certificate2, profile2, role), namespace = next(iter(config.namespace_bindings_v2.items()))
    if (certificate, profile) != (certificate2, profile2):
        raise ValueError("diagnostic peer binding differs")
    reverse = config.reverse_handoff_profiles[namespace]
    journal = config.execution_journals[namespace]
    return {
        "schema": "sylanne3.authority.installed-assets.v1",
        "authority_db": str(config.authority_db),
        "deletion_db": str(config.deletion_db),
        "graph_db": str(config.graph_db),
        "instance_lock": str(config.instance_lock),
        "bind_host": config.bind_host,
        "bind_port": config.bind_port,
        "tls": {
            "certificate": config.tls.certificate,
            "private_key": config.tls.private_key,
            "client_trust_root": config.tls.client_trust_root,
            "timeout_seconds": config.tls.timeout_seconds,
            "max_message_bytes": config.tls.max_message_bytes,
        },
        "execution_journals": [{
            "namespace": namespace, "path": str(journal.path),
            "journal_id": journal.journal_id,
        }],
        "installations_v2": [{
            "certificate_sha256": certificate, "profile_id": profile,
            "installation_id": installation.installation_id,
            "administrator_holder": installation.administrator_holder,
            "publisher_policy_ref": installation.publisher_policy_ref,
            "service_capability_version": installation.service_capability_version,
            "manifest_digest": installation.manifest_digest,
            "source_id": installation.source_id,
            "max_utc_error_seconds": installation.max_utc_error_seconds,
        }],
        "namespace_bindings_v2": [{
            "certificate_sha256": certificate, "profile_id": profile,
            "bot_id": role.bot_id, "persona_id": role.persona_id,
            "authority_namespace": namespace,
        }],
        "reverse_handoff": [{
            "namespace": namespace, "profile_id": reverse.profile_id,
            "installation_id": reverse.installation_id,
            "host": reverse.host, "port": reverse.port,
            "server_name": reverse.server_name,
            "expected_host_certificate_sha256": reverse.expected_host_certificate_sha256,
            "trust_root": str(reverse.trust_root),
            "client_certificate": str(reverse.client_certificate),
            "client_private_key": str(reverse.client_private_key),
            "timeout_seconds": reverse.timeout_seconds,
            "max_message_bytes": reverse.max_message_bytes,
            "issuer_id": config.reverse_handoff_issuers[namespace],
        }],
    }


def run_diagnostic(install_dir: Path) -> dict:
    if os.name != "nt":
        raise RuntimeError("Windows Authority process diagnostic requires Windows")
    install_dir = install_dir.resolve()
    if install_dir == ROOT or install_dir.is_relative_to(ROOT) or install_dir.exists():
        raise ValueError("installation directory must be new and outside source checkout")
    install_dir.mkdir(parents=True)
    state = install_dir / "state"
    state.mkdir()
    code = install_dir / "code"
    code.mkdir()
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "rewrite"))
    from rewrite.tests.alpha1.authority.test_authority_daemon_cold_open import _installed_config

    config, files, bootstrap_server = _installed_config(state)
    asyncio.run(bootstrap_server.aclose())
    asset_manifest = state / "installed-assets.json"
    asset_manifest.write_text(json.dumps(_asset_document(config), sort_keys=True), encoding="utf-8")
    package = install_dir / "authority-staging.zip"
    staging = build_staging_authority(ROOT, package)
    with zipfile.ZipFile(package) as archive:
        archive.extractall(code)
    trust = install_dir / "one-time-trust"
    trust.mkdir()
    private = Ed25519PrivateKey.generate()
    publisher_key = trust / "publisher.pub"
    publisher_key.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    ))
    signature = trust / "authority.sig"
    signature.write_bytes(private.sign(
        b"sylanne.authority.bundle.v1\0" + package.read_bytes(),
    ))
    environment = {
        name: value for name, value in os.environ.items()
        if not name.upper().startswith(("PYTHON", "RUST", "CARGO", "DYLD_", "LD_"))
    }
    environment["PATH"] = ""
    child = subprocess.Popen(
        [sys.executable, "-u", "-E",
         str(code / "scripts/alpha1/authority_windows_service.py"), "console",
         "--code", str(code), "--assets", str(asset_manifest),
         "--package", str(package), "--signature", str(signature),
         "--publisher-key", str(publisher_key),
         "--trusted-root-sha256", hashlib.sha256(publisher_key.read_bytes()).hexdigest(),
         "--expected-package-sha256", staging["package_sha256"],
         "--expected-manifest-sha256", staging["manifest_sha256"]],
        cwd=install_dir, env=environment, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    connected = False
    try:
        deadline = time.monotonic() + 15
        context = ssl.create_default_context(cafile=str(files["ca.pem"]))
        context.load_cert_chain(str(files["client.pem"]), str(files["client.key"]))
        while time.monotonic() < deadline:
            if child.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", config.bind_port), timeout=1) as tcp:
                    with context.wrap_socket(tcp, server_hostname="localhost") as tls:
                        assert tls.version() is not None
                        connected = True
                        break
            except (OSError, ssl.SSLError):
                time.sleep(0.1)
        if not connected:
            detail = child.communicate(timeout=5)[1].strip() if child.poll() is not None else "listener timeout"
            raise RuntimeError("Authority child did not accept mTLS: " + detail)
        stdout, stderr = child.communicate("stop\n", timeout=20)
        if child.returncode != 0:
            raise RuntimeError("Authority child failed: " + stderr.strip())
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
    events = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    if [event.get("event") for event in events] != ["ready", "closed"]:
        raise RuntimeError("Authority child readiness or stop receipt differs")
    ready, closed = events
    if ready["pid"] == os.getpid() or child.returncode != 0:
        raise RuntimeError("Authority process identity or closure differs")
    return {
        "status": "diagnostic_only",
        "cold_install_pass": False,
        "publisher_trust_root": "absent",
        "service_installer": "absent",
        "installation_dir": str(install_dir),
        "authority_staging_package_sha256": staging["package_sha256"],
        "authority_staging_manifest_sha256": staging["manifest_sha256"],
        "separate_process": True,
        "mtls_connected": connected,
        "ready": ready,
        "closed": closed,
        "service_wrapper": "console_mode_only",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Windows Authority child-process diagnostic")
    parser.add_argument("--install-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run_diagnostic(args.install_dir), sort_keys=True))


if __name__ == "__main__":
    main()
