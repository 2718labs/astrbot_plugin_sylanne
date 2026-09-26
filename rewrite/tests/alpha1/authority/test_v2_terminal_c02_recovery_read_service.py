"""Recovery handoff is fenced, identity-bound, and finishes after delivery."""

from dataclasses import asdict, replace
import time
from types import SimpleNamespace

import pytest

from rewrite.tests.alpha1.authority.test_v2_accounting_deletion import _observed_original
from rewrite.tests.alpha1.runtime.test_authority_v2_fence_service import installed
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, MtlsPeerCredential,
)
from sylanne3.authority_service.current_worker_model_result_graph_verifier import (
    PinnedTerminalRecoveryGraphVerifierV1,
)
from sylanne3.authority_service.v2_terminal_c02_recovery_attempts import (
    AuthorityV2TerminalC02RecoveryAttempts,
)
from sylanne3.authority_service.v2_terminal_c02_recovery_contract import (
    OriginalC02ResultKeyV1, TerminalRecoveryReadRequestV1,
    to_wire as terminal_to_wire,
)
from sylanne3.authority_service.v2_terminal_c02_recovery_read_service import (
    AuthorityV2TerminalC02RecoveryReadService,
)
from sylanne3.runtime.first_ingress_c02_identity import (
    first_ingress_c02_consumer_operation_id_v1,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


def _case(tmp_path, monkeypatch):
    fences, core, _, deletion, guard, execution, _ = installed(tmp_path)
    store, intent = _observed_original(fences, core)
    with core._tx() as db:
        record = store._read(db, intent.call_id)
        _, _, receipt = store.read_admission_locked(db, intent)
    attempts = AuthorityV2TerminalC02RecoveryAttempts(
        core._db, create=True, lock=core._lock)
    graph = object.__new__(PinnedTerminalRecoveryGraphVerifierV1)
    monkeypatch.setattr(graph, "current", lambda *_: True)
    service = AuthorityV2TerminalC02RecoveryReadService(
        store=store, fences=fences, attempts=attempts, graph_verifier=graph,
        installation_id="original-install", read_subject="recovery-reader",
        holder="holder-a")
    namespace = NamespaceId("bot-a", "persona-a")
    key = OriginalC02ResultKeyV1(
        intent.authority_id, intent.namespace, namespace, "original-install",
        intent.job_id, intent.budget_reservation_operation_id,
        intent.operation_id, intent.operation_id, intent.call_id, "a" * 64,
        intent.request_digest, canonical_digest(asdict(intent)),
        record.observation_digest, canonical_digest(asdict(receipt)))
    consumer = first_ingress_c02_consumer_operation_id_v1(
        namespace=namespace, authority_id=key.authority_id,
        authority_namespace=key.authority_namespace,
        installation_id=key.installation_id, job_id=key.job_id,
        acquire_operation_id=key.acquire_operation_id,
        original_operation_id=key.original_operation_id, call_id=key.call_id,
        binding_digest=key.binding_digest,
        model_request_digest=key.model_request_digest)
    request = TerminalRecoveryReadRequestV1(key, consumer, "recovery-attempt-1")
    return service, request, graph, core, deletion, guard, execution


def test_recovery_handoff_replay_query_and_conflicts(tmp_path, monkeypatch):
    service, request, _, core, deletion, guard, execution = _case(tmp_path, monkeypatch)
    try:
        assert service.query(credential="ok", request=request) == (None, None)
        delivery = service.prepare(credential="ok", request=request)
        assert delivery.observation.result_json == "{}"
        attempt, fact = service.query(credential="ok", request=request)
        assert attempt.state == "active" and fact is None
        with pytest.raises(AuthorityUnavailable, match="already in progress"):
            service.prepare(credential="ok", request=request)
        service.abandon_delivery(delivery=delivery)
        attempt, fact = service.query(credential="ok", request=request)
        assert attempt.state == "active" and fact is None
        replay = service.prepare(credential="ok", request=request)
        assert replay.observation == delivery.observation
        service.finish_delivery(credential="ok", delivery=replay)
        attempt, fact = service.query(credential="ok", request=request)
        assert attempt.state == "finished"
        assert fact.handoff_digest == replay.handoff_digest
        assert service._fences.fences._row(core._db, request.read_attempt_id)[6] == "finished"
        with pytest.raises(AuthorityUnavailable, match="completed fence"):
            service.prepare(credential="ok", request=request)
        with pytest.raises(AuthorityUnavailable, match="identity conflict"):
            service.query(credential="ok", request=replace(
                request, original_key=replace(request.original_key,
                                              binding_digest="b" * 64)))
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()


def test_revocation_and_missing_concrete_verifier_hold_body(tmp_path, monkeypatch):
    service, request, graph, core, deletion, guard, execution = _case(tmp_path, monkeypatch)
    try:
        with pytest.raises(AuthorityUnavailable, match="composition unavailable"):
            AuthorityV2TerminalC02RecoveryReadService(
                store=service._store, fences=service._fences,
                attempts=service._attempts, graph_verifier=None,
                installation_id="original-install", read_subject="recovery-reader",
                holder="holder-a")
        monkeypatch.setattr(graph, "current", lambda *_: False)
        with pytest.raises(AuthorityUnavailable, match="graph unavailable"):
            service.prepare(credential="ok", request=request)
        assert service.query(credential="ok", request=request) == (None, None)
        monkeypatch.setattr(graph, "current", lambda *_: True)
        with core._tx() as db:
            db.execute("UPDATE authority_namespaces SET revocation_epoch=revocation_epoch+1 "
                       "WHERE namespace='ns-a'")
        with pytest.raises(AuthorityUnavailable):
            service.prepare(credential="ok", request=request)
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()


def test_graph_revoked_before_drain_finish_never_records_read_fact(tmp_path, monkeypatch):
    service, request, graph, core, deletion, guard, execution = _case(tmp_path, monkeypatch)
    try:
        delivery = service.prepare(credential="ok", request=request)
        monkeypatch.setattr(graph, "current", lambda *_: False)
        with pytest.raises(AuthorityUnavailable, match="before handoff fact"):
            service.finish_delivery(credential="ok", delivery=delivery)
        attempt, fact = service.query(credential="ok", request=request)
        assert attempt.state == "active" and fact is None
        assert service._fences.fences._row(core._db, request.read_attempt_id)[6] == "active"
        with pytest.raises(AuthorityUnavailable, match="graph unavailable"):
            service.prepare(credential="ok", request=request)
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()


def test_expired_original_worker_rejected_but_current_recovery_graph_checked(tmp_path):
    from rewrite.tests.alpha1.runtime.test_worker_model_result_graph import _case as graph_case

    db, _, intent, worker_request, worker_permit, worker_graph, access, _ = graph_case(tmp_path)
    try:
        expired_now = time.time() + 360  # after the five-minute lease, before deadline
        worker_graph._clock = lambda: expired_now
        assert worker_graph.current(worker_request, intent, worker_permit) is False
        key = OriginalC02ResultKeyV1(
            intent.authority_id, intent.namespace, worker_request.namespace,
            worker_request.installation_id, intent.job_id,
            intent.budget_reservation_operation_id, intent.operation_id,
            intent.operation_id, intent.call_id, worker_request.binding_digest,
            intent.request_digest, canonical_digest(asdict(intent)),
            "a" * 64, "b" * 64)
        recovery_request = TerminalRecoveryReadRequestV1(
            key, worker_request.consumer_operation_id, "recovery-attempt-graph")
        recovery_permit = replace(
            worker_permit, subject="recovery-reader",
            operation_id=recovery_request.read_attempt_id)
        recovery_graph = PinnedTerminalRecoveryGraphVerifierV1(
            worker_graph._path, trusted_now_utc=lambda: expired_now,
            d11_issuer=worker_graph._issuer)
        assert recovery_graph.current(recovery_request, intent, recovery_permit) is True
        db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (access.token,))
        assert recovery_graph.current(recovery_request, intent, recovery_permit) is False
        db.execute("UPDATE graph_atoms SET valid=1 WHERE token=?", (access.token,))
        assert recovery_graph.current(
            replace(recovery_request, original_key=replace(key,
                original_intent_digest="0" * 64)), intent, recovery_permit) is False
    finally:
        db.close()


def test_recovery_rpc_missing_installation_holds_and_unknown_query_is_content_free():
    peer = MtlsPeerCredential("a" * 64)
    other = MtlsPeerCredential("b" * 64)
    namespace = NamespaceId("bot-a", "persona-a")
    key = OriginalC02ResultKeyV1(
        "authority-1", "ns-a", namespace, "install-1", "job-1",
        "original-1", "acquire-1", "acquire-1", "call-1",
        *(["c" * 64] * 5))
    request = TerminalRecoveryReadRequestV1(key, "consumer-1", "attempt-1")
    server = object.__new__(AuthorityRpcServer)
    server._installations_v2 = {
        (peer.certificate_sha256, "profile-a"): AdministratorInstallationV2(
            "install-1", "holder-a", "policy", "v2", "f" * 64),
        (other.certificate_sha256, "profile-a"): AdministratorInstallationV2(
            "install-2", "holder-a", "policy", "v2", "f" * 64),
    }
    server._namespace_bindings_v2 = {
        (peer.certificate_sha256, "profile-a", namespace): "ns-a"}
    server._authority_id = lambda: "authority-1"
    server._bound_v2_service = lambda *_: None
    server._v2_terminal_c02_recovery_reads = {}
    server._terminal_c02_recovery_readers_v2 = {}
    command = {"namespace": "ns-a", "read_request": terminal_to_wire(request)}
    with pytest.raises(RuntimeError, match="authority unavailable"):
        server._v2_command(
            "terminal_c02_recovery_read_v1", peer,
            "profile-a", "f" * 64, command)
    service = SimpleNamespace(
        _read_subject="mtls:sha256:" + peer.certificate_sha256,
        query=lambda **_: (None, None))
    server._v2_terminal_c02_recovery_reads = {"ns-a": service}
    server._terminal_c02_recovery_readers_v2 = {
        "ns-a": (peer.certificate_sha256, "profile-a")}
    assert server._v2_command(
        "terminal_c02_recovery_query_v1", peer,
        "profile-a", "f" * 64, command) == {
            "attempt": None, "read_fact": None}
    with pytest.raises(RuntimeError, match="authority unavailable"):
        server._v2_command(
            "terminal_c02_recovery_query_v1", other,
            "profile-a", "f" * 64, command)
