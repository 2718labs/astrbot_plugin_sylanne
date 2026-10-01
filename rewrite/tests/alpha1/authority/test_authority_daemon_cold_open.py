"""In-process cold-open of already installed Authority assets and mTLS listener.

The test installs disposable state first. It does not qualify a Windows
service installer, administrator OS policy, or a production callback registry.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import socket
import ssl

import pytest

from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as cert_donor
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.contract import JournalHead
from sylanne3.authority_service.internal_work_rpc_wire import (
    from_wire as c04_from_wire, to_wire as c04_to_wire,
)
from sylanne3.authority_service.internal_work_service import InternalWorkJournalInspectionV1
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.daemon import open_authority_daemon
from sylanne3.authority_service.deployment_config import (
    ASSET_MANIFEST_SCHEMA, AuthorityCoreVerifiers, AuthorityDeploymentConfig,
    ExecutionJournalInstallation, InstalledC04AuthorityV2, InstalledC04AuthorityV3,
    load_installed_asset_config_v1,
)
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityServerTlsConfig, MtlsPeerCredential,
)
from sylanne3.authority_service.reverse_handoff import (
    AdministratorReverseHandoffProfile, ReverseGraphClaimClient,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_owner_proof import AuthorityV2OwnerProofStore
from sylanne3.authority_service.v2_owner_session import AuthorityV2OwnerSessionStore
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.host.owner_deployment import OwnerDeploymentVerifier, compose_owner_deployment
from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import NamespaceId


ROLE = NamespaceId("bot", "persona")
NAMESPACE = namespace_ref(ROLE)
JOURNAL_ID = "execution-installed"


def _bind_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _installed_config(tmp_path):
    files = cert_donor.AuthorityMtlsLoopbackTests._certificates(tmp_path)
    cert = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        files["client.pem"].read_text(encoding="ascii"))).hexdigest()
    host_cert = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        files["server.pem"].read_text(encoding="ascii"))).hexdigest()
    peer = MtlsPeerCredential(cert)
    authority_path = tmp_path / "authority.db"
    deletion_path = tmp_path / "deletion.db"
    execution_path = tmp_path / "execution.db"
    graph_path = tmp_path / "graph.db"
    lock_path = tmp_path / "authority.lock"
    lock_path.write_bytes(b"\0")

    def core_authorizer(candidate, action, selected, holder):
        return (candidate == peer and selected == NAMESPACE
                and action in {"install", "seal_v2_only", "current",
                               "owner_pair", "owner_session", "owner_guard_read"})

    def core_verifiers(guard, journals):
        def deletion_check(selected, _before, current, phase):
            if selected != NAMESPACE or phase != "clear":
                return False
            with guard.freeze_writes():
                return (guard.verified_head() == current
                        and not guard.has_deletion_history(selected))

        def execution_check(selected, _before, current, phase):
            return (selected == NAMESPACE and phase is None
                    and journals[selected].verified_head() == current)

        # The v2-only service never calls these legacy Core mutation routes.
        # Their deliberately closed policy is explicit in this lifecycle test.
        def no_legacy_effect(*_args):
            return False

        def no_legacy_dispatch(*_args):
            return False

        return AuthorityCoreVerifiers(
            deletion_check, execution_check, no_legacy_effect,
            no_legacy_dispatch)

    def enrollment_authorizer(candidate, action, selected, holder):
        return (candidate == peer and action == "pair"
                and selected == "authority:enrollment")

    def installed_publisher(profile, plugin, version, digest):
        return (profile == "test" and plugin == "astrbot_plugin_sylanne"
                and version == "4.28.1" and digest == "a" * 64)

    def local_admin_uninstalled(_action, _namespace):
        raise AuthorityUnavailable("test has no installed OS administrator policy")

    graph = GraphStore(graph_path, TypeRegistry())
    graph.close()
    deletion = DeletionJournal(deletion_path, create=True)
    guard = AuthorityV2DeletionGuard(deletion_path)
    execution = AuthorityV2ExecutionJournal(
        execution_path, namespace=NAMESPACE, journal_id=JOURNAL_ID, create=True)
    verifiers = core_verifiers(guard, {NAMESPACE: execution})
    core = AuthorityServiceCore(
        authority_path, create=True, authorizer=core_authorizer,
        deletion_verifier=verifiers.deletion,
        execution_verifier=verifiers.execution,
        effect_verifier=verifiers.effect,
        dispatch_verifier=verifiers.dispatch)
    try:
        with guard.freeze_writes():
            deletion_head = guard.verified_head()
        core.register_namespace(peer, NAMESPACE, "host", deletion_head,
                                execution.verified_head())
        core.seal_v2_only(peer)
        fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
        service = AuthorityV2FenceService(
            core=core, fences=fences, deletion=guard, execution=execution,
            namespace=NAMESPACE)
        pairing = AuthorityOwnerPairingSource(
            core, utc_clock=lambda: datetime.now(timezone.utc), create=True)
        owner_verifier = OwnerDeploymentVerifier(
            pairing, lambda: datetime.now(timezone.utc))
        AuthorityV2OwnerProofStore(
            core, utc_clock=lambda: datetime.now(timezone.utc),
            pairing_verifier=owner_verifier.pair_credential, create=True)
        sessions = AuthorityV2OwnerSessionStore(
            core, utc_clock=lambda: datetime.now(timezone.utc),
            current_pairing_source=pairing, create=True)
        reverse_profile = AdministratorReverseHandoffProfile(
            NAMESPACE, "test", "installation", "127.0.0.1", 1,
            "localhost", host_cert, files["ca.pem"], files["client.pem"],
            files["client.key"])
        installed = AdministratorInstallationV2(
            "installation", "host", "policy", "capabilities-v2", "a" * 64)
        bootstrap_server = compose_owner_deployment(
            core=core, v2_fences={NAMESPACE: service}, graph_db_path=graph_path,
            utc_clock=lambda: datetime.now(timezone.utc), identity=pairing,
            administrator_authorizer=enrollment_authorizer,
            publisher_manifest_verifier=installed_publisher,
            installations_v2={(cert, "test"): installed},
            namespace_bindings_v2={(cert, "test", ROLE): NAMESPACE},
            v2_final_handoff_reverse={NAMESPACE: ReverseGraphClaimClient(reverse_profile)},
            v2_final_handoff_issuers={NAMESPACE: "graph-issuer"},
            owner_sessions=sessions, create_owner_schema=True)
    finally:
        core.close()
        execution.close()
        guard.close()
        deletion.close()

    config = AuthorityDeploymentConfig(
        authority_path, deletion_path, graph_path, lock_path,
        {NAMESPACE: ExecutionJournalInstallation(execution_path, JOURNAL_ID)},
        AuthorityServerTlsConfig(
            str(files["server.pem"]), str(files["server.key"]),
            str(files["ca.pem"])),
        "127.0.0.1", _bind_port(), {(cert, "test"): installed},
        {(cert, "test", ROLE): NAMESPACE},
        {NAMESPACE: reverse_profile}, {NAMESPACE: "graph-issuer"},
        core_authorizer, core_verifiers, enrollment_authorizer,
        installed_publisher, lambda: datetime.now(timezone.utc),
        local_admin_uninstalled)
    return config, files, bootstrap_server


@pytest.mark.asyncio
async def test_reopens_existing_authority_and_stops_mtls(tmp_path):
    config, files, bootstrap_server = _installed_config(tmp_path)
    await bootstrap_server.aclose()
    daemon = open_authority_daemon(config)
    try:
        with pytest.raises(AuthorityUnavailable, match="another Authority instance"):
            open_authority_daemon(config)
        assert daemon.server._core is daemon.core
        assert daemon.server._v2_owner_pairings is daemon.owner_pairings
        assert daemon.installed_peer_certificate_sha256(
            "test", "installation", NAMESPACE) == next(iter(config.installations_v2))[0]
        with pytest.raises(AuthorityUnavailable, match="local OS administrator"):
            daemon.require_local_administrator("owner_identity_pair", NAMESPACE)
        listener = await daemon.start()
        assert listener.is_serving() and daemon.is_listening
        with pytest.raises(AuthorityUnavailable, match="offline"):
            daemon.require_offline_admin_maintenance()
        ssl_context = ssl.create_default_context(cafile=str(files["ca.pem"]))
        ssl_context.load_cert_chain(str(files["client.pem"]), str(files["client.key"]))
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", config.bind_port, ssl=ssl_context,
            server_hostname="localhost")
        assert writer.get_extra_info("ssl_object") is not None
        writer.close()
        await writer.wait_closed()
    finally:
        await daemon.aclose()
    assert not daemon.is_listening
    with pytest.raises(AuthorityUnavailable, match="offline"):
        daemon.require_offline_admin_maintenance()


@pytest.mark.asyncio
async def test_missing_installed_owner_schema_does_not_create_replacement(tmp_path):
    config, _, bootstrap_server = _installed_config(tmp_path)
    await bootstrap_server.aclose()
    import sqlite3
    with sqlite3.connect(config.authority_db) as db:
        db.execute("DROP TABLE authority_owner_actor_bindings_v1")
    before = config.authority_db.stat().st_size
    with pytest.raises(AuthorityUnavailable, match="Core or Owner schema"):
        open_authority_daemon(config)
    assert config.authority_db.stat().st_size == before
    assert config.authority_db.is_file()


@pytest.mark.asyncio
async def test_missing_execution_journal_is_not_recreated(tmp_path):
    config, _, bootstrap_server = _installed_config(tmp_path)
    await bootstrap_server.aclose()
    absent = tmp_path / "absent-execution.db"
    missing = replace(config, execution_journals={
        NAMESPACE: ExecutionJournalInstallation(absent, JOURNAL_ID)})
    with pytest.raises(AuthorityUnavailable, match="execution journal"):
        open_authority_daemon(missing)
    assert not absent.exists()


@pytest.mark.asyncio
async def test_c04_installation_holds_without_key_or_formal_package(tmp_path):
    config, _, bootstrap_server = _installed_config(tmp_path)
    await bootstrap_server.aclose()
    package = tmp_path / "candidate-package"
    package.mkdir()
    key = tmp_path / "c04-component.key"
    installed = InstalledC04AuthorityV2(package, "a" * 64, key)
    selected = replace(config, c04_installations_v2={NAMESPACE: installed},
                       local_administrator_credential=lambda *_: object())
    with pytest.raises(AuthorityUnavailable, match="C04 component key"):
        open_authority_daemon(selected)
    key.write_bytes(b"k" * 32)
    with pytest.raises(AuthorityUnavailable, match="formal D06 package bytes"):
        open_authority_daemon(selected)


@pytest.mark.asyncio
async def test_c04_rpc_requires_installed_executor_and_routes_typed_inspection(tmp_path):
    from tests.alpha1.authority.test_installed_c04_executor_v2 import _binding
    from tests.alpha1.d06.test_c04_work_input_v2 import _input

    config, _, server = _installed_config(tmp_path)
    peer = MtlsPeerCredential(next(iter(config.installations_v2))[0])
    binding = _binding(_input())
    command = {"namespace": NAMESPACE, "binding": c04_to_wire(binding)}
    try:
        with pytest.raises(RuntimeError, match="authority unavailable"):
            server._v2_command("c04_inspect_v2", peer, "test", "a" * 64, command)

        expected = InternalWorkJournalInspectionV1(
            binding, None, None, None, None,
            JournalHead(JOURNAL_ID, 0, "genesis"))

        class ControlledRoute:
            def inspect(self, candidate):
                assert candidate == binding
                return expected

            def execute(self, candidate):
                assert candidate == binding
                return expected

        # Route-only test: formal installation is exercised by the daemon gate.
        server._v2_internal_work_executors[NAMESPACE] = ControlledRoute()
        for method in ("c04_inspect_v2", "c04_execute_v2"):
            response = server._v2_command(method, peer, "test", "a" * 64, command)
            assert c04_from_wire(
                response["inspection"], InternalWorkJournalInspectionV1) == expected
    finally:
        await server.aclose()


@pytest.mark.asyncio
async def test_versioned_assets_parse_without_executable_callback_names(tmp_path):
    config, _, bootstrap_server = _installed_config(tmp_path)
    await bootstrap_server.aclose()
    (certificate, profile_id), installation = next(iter(config.installations_v2.items()))
    reverse = config.reverse_handoff_profiles[NAMESPACE]
    path = tmp_path / "installed-assets.json"
    document = {
        "schema": ASSET_MANIFEST_SCHEMA,
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
            "namespace": NAMESPACE,
            "path": str(config.execution_journals[NAMESPACE].path),
            "journal_id": JOURNAL_ID,
        }],
        "installations_v2": [{
            "certificate_sha256": certificate,
            "profile_id": profile_id,
            "installation_id": installation.installation_id,
            "administrator_holder": installation.administrator_holder,
            "publisher_policy_ref": installation.publisher_policy_ref,
            "service_capability_version": installation.service_capability_version,
            "manifest_digest": installation.manifest_digest,
            "source_id": installation.source_id,
            "max_utc_error_seconds": installation.max_utc_error_seconds,
        }],
        "namespace_bindings_v2": [{
            "certificate_sha256": certificate,
            "profile_id": profile_id,
            "bot_id": ROLE.bot_id,
            "persona_id": ROLE.persona_id,
            "authority_namespace": NAMESPACE,
        }],
        "reverse_handoff": [{
            "namespace": NAMESPACE,
            "profile_id": reverse.profile_id,
            "installation_id": reverse.installation_id,
            "host": reverse.host,
            "port": reverse.port,
            "server_name": reverse.server_name,
            "expected_host_certificate_sha256": reverse.expected_host_certificate_sha256,
            "trust_root": str(reverse.trust_root),
            "client_certificate": str(reverse.client_certificate),
            "client_private_key": str(reverse.client_private_key),
            "timeout_seconds": reverse.timeout_seconds,
            "max_message_bytes": reverse.max_message_bytes,
            "issuer_id": config.reverse_handoff_issuers[NAMESPACE],
        }],
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    loaded = load_installed_asset_config_v1(
        path, core_authorizer=config.core_authorizer,
        core_verifier_factory=config.core_verifier_factory,
        administrator_authorizer=config.administrator_authorizer,
        publisher_manifest_verifier=config.publisher_manifest_verifier,
        utc_clock=config.utc_clock,
        local_administrator_credential=config.local_administrator_credential)
    assert loaded.execution_journals == config.execution_journals
    assert loaded.namespace_bindings_v2 == config.namespace_bindings_v2
    key = tmp_path / "c04-component.key"
    document["c04_installations_v2"] = [{
        "namespace": NAMESPACE,
        "package_root": str(tmp_path),
        "formal_manifest_sha256": "a" * 64,
        "component_key_path": str(key),
    }]
    path.write_text(json.dumps(document), encoding="utf-8")
    c04_loaded = load_installed_asset_config_v1(
        path, core_authorizer=config.core_authorizer,
        core_verifier_factory=config.core_verifier_factory,
        administrator_authorizer=config.administrator_authorizer,
        publisher_manifest_verifier=config.publisher_manifest_verifier,
        utc_clock=config.utc_clock,
        local_administrator_credential=config.local_administrator_credential)
    assert c04_loaded.c04_installations_v2[NAMESPACE] == InstalledC04AuthorityV2(
        tmp_path, "a" * 64, key)
    # V3 is an independent optional pin; parsing it does not turn the product on.
    v3_package = tmp_path / "v3-package"
    v3_package.mkdir()
    v3_key = tmp_path / "c04-v3-component.key"
    document["c04_installations_v3"] = [{
        "namespace": NAMESPACE, "package_root": str(v3_package),
        "formal_manifest_sha256": "b" * 64,
        "component_key_path": str(v3_key),
    }]
    path.write_text(json.dumps(document), encoding="utf-8")
    c04_v3_loaded = load_installed_asset_config_v1(
        path, core_authorizer=config.core_authorizer,
        core_verifier_factory=config.core_verifier_factory,
        administrator_authorizer=config.administrator_authorizer,
        publisher_manifest_verifier=config.publisher_manifest_verifier,
        utc_clock=config.utc_clock,
        local_administrator_credential=config.local_administrator_credential)
    assert c04_v3_loaded.c04_installations_v3[NAMESPACE] == InstalledC04AuthorityV3(
        v3_package, "b" * 64, v3_key)
    assert c04_v3_loaded.c04_installations_v2[NAMESPACE] == c04_loaded.c04_installations_v2[NAMESPACE]

    document["c04_installations_v3"] = [{
        "namespace": NAMESPACE, "package_root": str(v3_package),
        "formal_manifest_sha256": "B" * 64,
        "component_key_path": str(v3_key), "unexpected": True,
    }]
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(AuthorityUnavailable, match="fields differ"):
        load_installed_asset_config_v1(
            path, core_authorizer=config.core_authorizer,
            core_verifier_factory=config.core_verifier_factory,
            administrator_authorizer=config.administrator_authorizer,
            publisher_manifest_verifier=config.publisher_manifest_verifier,
            utc_clock=config.utc_clock,
            local_administrator_credential=config.local_administrator_credential)
    document["schema"] = "sylanne3.authority.installed-assets.v999"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(AuthorityUnavailable, match="version"):
        load_installed_asset_config_v1(
            path, core_authorizer=config.core_authorizer,
            core_verifier_factory=config.core_verifier_factory,
            administrator_authorizer=config.administrator_authorizer,
            publisher_manifest_verifier=config.publisher_manifest_verifier,
            utc_clock=config.utc_clock,
            local_administrator_credential=config.local_administrator_credential)
