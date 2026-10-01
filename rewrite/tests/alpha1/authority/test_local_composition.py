"""Local Authority composition checks the independent durable write fence."""

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import asyncio
import sqlite3
from types import SimpleNamespace

import pytest

from rewrite.tests.alpha1.runtime.test_authority_v2_fence_service import installed
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.local_composition import compose_local_owner_authority
from sylanne3.authority_service.mtls_server import AdministratorInstallationV2, MtlsPeerCredential
from sylanne3.authority_service.reverse_handoff import ReverseGraphClaimClient
from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService
from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
from sylanne3.authority_service.v2_accounting_service import AuthorityV2AccountingMaintenanceService
from sylanne3.authority_service.v2_model_result_read_service import AuthorityV2ModelResultReadService
from sylanne3.authority_service.v2_owner_proof import AuthorityV2OwnerProofStore
from sylanne3.authority_service.v2_owner_session import AuthorityV2OwnerSessionStore
from sylanne3.authority_service.v2_migration_rpc import MigrationRpcHandlerV2
from sylanne3.authority_service.v2_migration_service import AuthorityV2MigrationService
from sylanne3.authority_service.v2_migration_store import AuthorityV2MigrationStore
from sylanne3.authority_service.v2_model_result_read_wire import to_wire as result_to_wire
from rewrite.tests.alpha1.authority.test_v2_model_result_read import _request as result_request
from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
from sylanne3.runtime_contracts import NamespaceId


ROLE = NamespaceId("bot", "persona")


def _compose(tmp_path, service, core, *, graph_path=None, bindings=True,
             reverse=None, issuers=None, migration_factory=None, migration_rpc=None):
    graph_path = Path(graph_path) if graph_path is not None else tmp_path / "graph.db"
    if graph_path.is_absolute() and not graph_path.exists():
        sqlite3.connect(graph_path).close()
    return compose_local_owner_authority(
        core=core, v2_fences={"ns-a": service}, graph_db_path=graph_path,
        utc_clock=lambda: datetime.now(timezone.utc),
        first_claim_verifier=lambda *_: False,
        claimant_verifier=lambda *_: False,
        administrator_authorizer=lambda *_: False,
        publisher_manifest_verifier=lambda *_: False,
        installations_v2={("a" * 64, "profile"): AdministratorInstallationV2(
            "installation", "holder-a", "policy", "capabilities-v2", "b" * 64)},
        namespace_bindings_v2={
            ("a" * 64, "profile", ROLE): "ns-a"} if bindings else {},
        v2_final_handoff_reverse=reverse,
        v2_final_handoff_issuers=issuers,
        v2_migration_rpc_factory=migration_factory,
        v2_migration_rpc=migration_rpc,
        create_owner_schema=True,
    )


def test_migration_handler_uses_exact_installed_owner_store(tmp_path):
    service, core, _, deletion, guard, execution, _ = installed(tmp_path)
    try:
        def migration_factory(owner_tickets):
            migration = AuthorityV2MigrationService(
                fences=service,
                store=AuthorityV2MigrationStore(
                    core._db, lock=core._lock, create=True),
                pairing_verifier=None, source_snapshot_verifier=None,
                target_recovery_verifier=None, owner_tickets=owner_tickets)
            return MigrationRpcHandlerV2(
                {"ns-a": migration},
                resolve_management_binding=lambda *_: None)

        server = _compose(tmp_path, service, core,
                          migration_factory=migration_factory)
        assert server._v2_migration_rpc._services["ns-a"]._owner_tickets is server._v2_owner_tickets

        different_owner = _compose(tmp_path, service, core)
        different_handler = migration_factory(different_owner._v2_owner_tickets)
        with pytest.raises(AuthorityUnavailable, match="migration handler differs"):
            _compose(tmp_path, service, core, migration_rpc=different_handler)
        with pytest.raises(AuthorityUnavailable, match="two installation sources"):
            _compose(tmp_path, service, core, migration_rpc=different_handler,
                     migration_factory=migration_factory)
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()


def test_composition_passes_reverse_handoff_to_server_validation(tmp_path):
    service, core, _, deletion, guard, execution, _ = installed(tmp_path)
    try:
        client = object.__new__(ReverseGraphClaimClient)
        client.profile = SimpleNamespace(
            namespace="ns-a", profile_id="profile", installation_id="installation")
        with pytest.raises(TypeError, match="graph claim issuers"):
            _compose(tmp_path, service, core, reverse={"ns-a": client})
        server = _compose(tmp_path, service, core, reverse={"ns-a": client},
                          issuers={"ns-a": "graph-issuer"})
        bridge = server._v2_execution["ns-a"]
        assert bridge._final_handoff_authorizer.__self__ is client
        assert bridge._final_handoff_issuer_id == "graph-issuer"
        assert bridge._owner_installation_id == "installation"
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()


def test_composition_reads_exact_finished_authority_fence(tmp_path):
    service, core, _, deletion, guard, execution, _ = installed(tmp_path)
    try:
        server = _compose(tmp_path, service, core)
        verifier = server._v2_owner_tickets._graph_commit_verifier
        finished = verifier._finished_fence_verifier
        anchor = service.current_anchor(credential="ok", subject="subject-a")
        permit = service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="write", operation_id="owner-write", expected_anchor=anchor)
        digest = "sha256:" + "c" * 64
        assert finished(permit, "finish-owner-write", digest) is False
        service.finish_fence(
            credential="ok", subject="subject-a", permit=permit,
            request_id="finish-owner-write", request_digest=digest)
        assert finished(permit, "finish-owner-write", digest) is True
        unrelated = service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="write", operation_id="unrelated-write", expected_anchor=anchor)
        assert finished(unrelated, "finish-unrelated-write", digest) is False
        service.finish_fence(
            credential="ok", subject="subject-a", permit=unrelated,
            request_id="finish-unrelated-write", request_digest=digest)
        assert unrelated.fence_epoch > permit.fence_epoch
        assert finished(permit, "finish-owner-write", digest) is True
        assert finished(permit, "other-finish", digest) is False
        assert finished(permit, "finish-owner-write", "sha256:" + "d" * 64) is False
        assert finished(
            replace(permit, operation_id=unrelated.operation_id),
            "finish-owner-write", digest) is False
        assert finished(replace(permit, operation="read"), "finish-owner-write", digest) is False
        different_token = permit.token[:-1] + ("A" if permit.token[-1] != "A" else "B")
        assert finished(replace(permit, token=different_token), "finish-owner-write", digest) is False
        with core._tx() as db:
            db.execute("UPDATE authority_namespaces SET revocation_epoch=1 WHERE namespace='ns-a'")
        assert finished(permit, "finish-owner-write", digest) is False
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()


def test_composition_requires_pinned_graph_and_installed_identity(tmp_path):
    service, core, _, deletion, guard, execution, _ = installed(tmp_path)
    try:
        with pytest.raises(AuthorityUnavailable, match="bindings"):
            _compose(tmp_path, service, core, bindings=False)
        with pytest.raises(ValueError, match="absolute"):
            _compose(tmp_path, service, core, graph_path="relative-graph.db")
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()


def test_composition_pins_result_read_to_original_store_owner_and_installation(tmp_path):
    service, core, _, deletion, guard, execution, _ = installed(tmp_path)
    try:
        graph_path = tmp_path / "graph.db"
        sqlite3.connect(graph_path).close()
        pairing = AuthorityOwnerPairingSource(
            core, utc_clock=lambda: datetime.now(timezone.utc), create=True)
        AuthorityV2OwnerProofStore(
            core, utc_clock=lambda: datetime.now(timezone.utc),
            pairing_verifier=lambda *_: False,
            current_pairing_source=pairing, create=True)
        sessions = AuthorityV2OwnerSessionStore(
            core, utc_clock=lambda: datetime.now(timezone.utc),
            current_pairing_source=pairing, create=True)
        store = AuthorityV2ModelEgressStore(
            core._db, create=True, lock=core._lock)
        model = object.__new__(AuthorityV2ModelEgressService)
        model._store = store
        model._fences = service
        model._graph_verifier = object()
        model._admin_model_policy = object()
        server = compose_local_owner_authority(
            core=core, v2_fences={"ns-a": service}, graph_db_path=graph_path,
            utc_clock=lambda: datetime.now(timezone.utc),
            first_claim_verifier=lambda *_: False, claimant_verifier=None,
            administrator_authorizer=lambda *_: False,
            publisher_manifest_verifier=lambda *_: False,
            installations_v2={("a" * 64, "profile"): AdministratorInstallationV2(
                "installation", "holder-a", "policy", "capabilities-v2", "b" * 64)},
            namespace_bindings_v2={("a" * 64, "profile", ROLE): "ns-a"},
            v2_model_egress={"ns-a": model},
            model_observers_v2={"ns-a": ("a" * 64, "profile")},
            accounting_observers_v2={"ns-a": ("a" * 64, "profile")},
            model_result_source_purposes={"ns-a": "audit"},
            owner_sessions=sessions, creation_pairing_source=pairing,
            create_owner_schema=True)
        result = server._v2_model_result_reads["ns-a"]
        accounting = server._v2_accounting["ns-a"]
        assert type(accounting) is AuthorityV2AccountingMaintenanceService
        assert accounting._store is store and accounting._fences is service
        assert accounting._subject == "mtls:sha256:" + "a" * 64
        assert type(result) is AuthorityV2ModelResultReadService
        assert result._store is store and result._fences is service
        assert result._sessions is sessions
        assert result._tickets is server._v2_owner_tickets
        assert (result._installation_id, result._source_purpose,
                result._read_subject, result._holder) == (
                    "installation", "audit", "mtls:sha256:" + "a" * 64,
                    "holder-a")
        server._administrator_authorizer = lambda *_: True
        server._publisher_manifest_verifier = lambda *_: True
        raw = {"protocol": "sylanne3.authority.v2", "profile_id": "profile",
               "plugin_name": "astrbot_plugin_sylanne", "host_api_version": "4.28.1",
               "manifest_sha256": "b" * 64}
        peer = MtlsPeerCredential("a" * 64)
        binding = server._dispatch_for_test("handshake", raw, peer, b"result-channel")
        request = result_request()
        request = replace(
            request, authority_id=server._authority_id(),
            authority_namespace="ns-a", namespace=ROLE,
            installation_id="installation",
            owner_session_request=replace(
                request.owner_session_request,
                authority_id=server._authority_id(),
                authority_namespace="ns-a", installation_id="installation"))
        command = {"namespace": "ns-a", "read_request": result_to_wire(request),
                   "owner_session_token": "a" * 43}
        reached = []

        def read_completed(**kwargs):
            reached.append(kwargs["request"])
            raise RuntimeError("reached trusted result service")

        result.read_completed = read_completed
        with pytest.raises(RuntimeError, match="reached trusted result service"):
            server._dispatch_for_test(
                "model_result_read_v1", raw, peer, b"result-channel",
                handshake_binding=binding["channel_binding_sha256"], command=command)
        assert reached == [request]
        with pytest.raises(RuntimeError, match="authority unavailable"):
            server._dispatch_for_test(
                "model_result_read_v1", raw, peer, b"result-channel",
                handshake_binding=binding["channel_binding_sha256"],
                command={**command, "graph_current": True})
        assert reached == [request]
        wrong_peer = MtlsPeerCredential("c" * 64)
        wrong_binding = server._dispatch_for_test(
            "handshake", raw, wrong_peer, b"wrong-channel")
        with pytest.raises(RuntimeError, match="authority unavailable"):
            server._dispatch_for_test(
                "model_result_read_v1", raw, wrong_peer, b"wrong-channel",
                handshake_binding=wrong_binding["channel_binding_sha256"],
                command=command)
        assert reached == [request]
        asyncio.run(server.aclose())
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()
