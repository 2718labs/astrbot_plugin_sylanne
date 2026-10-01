"""Linux package/core acceptance. No systemd, privileged OS install or live API claim.

Set SYLANNE_ALPHA1_PACKAGE to the actual candidate ZIP. This exercises its
externally pinned policy, fresh schemas, signed C09 genesis and real PID death.
"""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import zipfile

import pytest

from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as cert_donor
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.c09_storage_control_v1 import C09StorageControlV1, InstalledC09InstanceLeaseV1
from sylanne3.authority_service.c09_storage_maintenance_v1 import InstalledC09WriterGateV1
from sylanne3.authority_service.daemon import open_authority_daemon
from sylanne3.authority_service.deployment_config import AuthorityDeploymentConfig, ExecutionJournalInstallation
from sylanne3.authority_service.installed_core_verifiers import installed_core_verifier_factory
from sylanne3.authority_service.installed_policy import InstalledPeerScopeV1
from sylanne3.authority_service.installed_policy_v2 import InstalledAuthorityPolicyV2
from sylanne3.authority_service.linux_bootstrap_v1 import initialize_fresh_authority_v1, build_initial_inventory_v1, bootstrap_current_storage_v1
from sylanne3.authority_service.mtls_server import AdministratorInstallationV2, AuthorityServerTlsConfig
from sylanne3.authority_service.reverse_handoff import AdministratorReverseHandoffProfile
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
from sylanne3.runtime_contracts import NamespaceId


def fixture(tmp_path):
    package = os.environ.get("SYLANNE_ALPHA1_PACKAGE")
    if not package:
        pytest.skip("actual alpha1 package not supplied")
    root = tmp_path / "code"
    root.mkdir()
    with zipfile.ZipFile(package) as archive:
        archive.extractall(root)
    pin = hashlib.sha256((root / "release-manifest.json").read_bytes()).hexdigest()
    registry = load_verified_affect_scheme(root, pin).registry.type_registry
    role = NamespaceId("installed-bot", "installed-persona")
    namespace = namespace_ref(role)
    certs = tmp_path / "certs"
    certs.mkdir()
    files = cert_donor.AuthorityMtlsLoopbackTests._certificates(certs)
    cert = hashlib.sha256(ssl.PEM_cert_to_DER_cert(files["client.pem"].read_text())).hexdigest()
    host_cert = hashlib.sha256(ssl.PEM_cert_to_DER_cert(files["server.pem"].read_text())).hexdigest()
    peer = (cert, "installed")
    policy = InstalledAuthorityPolicyV2(peer_scopes={cert: InstalledPeerScopeV1(namespace, "host")},
        profile_peers={"installed": cert}, package_root=root, trusted_manifest_sha256=pin, authority_uid=os.geteuid())
    state = tmp_path / "state"
    state.mkdir()
    paths = {role: state / (role + ".db") for role in ("core", "deletion", "execution", "graph")}
    lock = tmp_path / "authority.lock"
    lock.write_bytes(b"\0")
    config = AuthorityDeploymentConfig(paths["core"], paths["deletion"], paths["graph"], lock,
        {namespace: ExecutionJournalInstallation(paths["execution"], "execution:installed")},
        AuthorityServerTlsConfig(str(files["server.pem"]), str(files["server.key"]), str(files["ca.pem"])),
        "127.0.0.1", 19783, {peer: AdministratorInstallationV2("installation", "host", "pinned", "2", pin)},
        {(*peer, role): namespace}, {namespace: AdministratorReverseHandoffProfile(namespace, peer[1], "installation",
            "127.0.0.1", 19784, "localhost", host_cert, files["ca.pem"], files["client.pem"], files["client.key"])},
        {namespace: "graph:installed"}, policy.core_authorizer, installed_core_verifier_factory,
        policy.administrator_authorizer, policy.publisher_manifest_verifier, lambda: datetime.now(timezone.utc),
        policy.local_administrator_credential)
    return config, registry, namespace, peer, paths, state


@pytest.mark.asyncio
async def test_fresh_current_schemas_reopen_and_refuse_reinitialize(tmp_path):
    config, registry, namespace, _peer, _paths, _state = fixture(tmp_path)
    # Initializer is synchronous and starts no listener/model/tool subprocess.
    import asyncio
    original = await asyncio.to_thread(initialize_fresh_authority_v1, config, registry)
    assert original["namespace"] == namespace
    daemon = open_authority_daemon(config)
    try:
        assert daemon.core._id(daemon.core._db) == original["authority_id"]
        with daemon.deletion.freeze_writes():
            assert daemon.deletion.schema_version() == 2
        assert namespace in daemon.server._v2_fences
        assert (namespace, "installation") in daemon.server._current_erasure_prepares
    finally:
        await daemon.aclose()
    with pytest.raises(AuthorityUnavailable, match="existing or partial"):
        initialize_fresh_authority_v1(config, registry)


def test_signed_current_storage_real_peer_crash_restart_and_live_peer_denial(tmp_path):
    config, registry, namespace, peer, paths, state = fixture(tmp_path)
    original = initialize_fresh_authority_v1(config, registry)
    directories = {}
    for kind in ("controlled_backup", "export", "rebuild_temp", "cache"):
        directories[kind] = state / kind
        directories[kind].mkdir()
    inventory = build_initial_inventory_v1(authority_id=original["authority_id"], installation_id="installation",
        namespace=namespace, files=paths, directories=directories)
    key = tmp_path / "control.key"
    key.write_bytes(os.urandom(32))
    processes = []
    with InstalledC09InstanceLeaseV1(config.instance_lock) as lease:
        control = C09StorageControlV1(control_path=tmp_path / "control.db", key_path=key, installation_id="installation",
            authority_id=original["authority_id"], control_store_id="control", key_id="key", lease=lease, resource_roots=(state,))
        context = bootstrap_current_storage_v1(control=control, files=paths, inventory=inventory,
            identities={"core": original["authority_id"], "deletion": original["deletion_journal_id"],
                        "execution": original["execution_journal_id"], "graph": "unprovisioned"})
        assert context.stage == "READY" and context.pointer_version == context.storage_generation == 0
        gate = InstalledC09WriterGateV1(control=control)
        try:
            first = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            second = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            processes.extend((first, second))
            def register(process):
                gate.register_peer_process_v1(peer=peer, process_id=process.pid, process_incarnation=str(process.pid),
                    pointer_version=0, storage_generation=0)
            register(first)
            with gate.admit_peer_v1(peer=peer):
                pass
            with pytest.raises(AuthorityUnavailable, match="remains alive"):
                register(second)
            first.terminate(); first.wait(timeout=5)
            register(second)
            with gate.admit_peer_v1(peer=peer):
                pass
            with pytest.raises(AuthorityUnavailable, match="remains alive"):
                gate.revoke_and_drain_v1(operation_id="deletion")
            second.terminate(); second.wait(timeout=5)
            quiescence = gate.revoke_and_drain_v1(operation_id="deletion")
            assert len(quiescence["retired_peer_originals"]) == 2
            with pytest.raises(AuthorityUnavailable):
                register(second)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)
