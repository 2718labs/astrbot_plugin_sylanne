"""The first-ingress encoding job is acquired once under the v2 graph fence."""

import json
import sqlite3
import time
from types import SimpleNamespace
from dataclasses import replace

import pytest

from sylanne3.graph_coordinator import (
    AuthorityDenied, GraphCoordinator, JobAcquireOutcomeUnknown, UnavailableGuard,
    first_ingress_encoding_acquire_operation_id,
)
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.memory_types import access_key, source_key, validate_access
from sylanne3.model_broker.broker import ModelCallRequest
from sylanne3.model_broker.first_ingress_encoding import build_first_ingress_encoding_payload
from sylanne3.runtime.encoding_call_binding import (
    EncodingCallConflict, EncodingRequestIssueV1,
    _redact_source_binding_content_in_transaction, insert_binding, load_binding,
)
from sylanne3.runtime.d11_types import (
    D11RuntimeProvider, D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH,
)
from sylanne3.runtime.issuers import build_runtime_issuers
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    canonical_digest,
)
from sylanne3.runtime import first_ingress_v2

from test_first_ingress_v2 import ingress_system  # noqa: F401
from test_graph_v2_provisioning import AuthorityPort


def _op(coordinator, job_id, actor="encoding-worker", nonce="a" * 32):
    (original_operation_id,) = coordinator._GraphCoordinator__store._db.execute(
        "SELECT operation_id FROM runtime_jobs WHERE job_id=?", (job_id,)
    ).fetchone()
    return first_ingress_encoding_acquire_operation_id(
        NamespaceId(*coordinator._GraphCoordinator__store._db.execute(
            "SELECT bot_id,persona_id FROM runtime_jobs WHERE job_id=?", (job_id,)
        ).fetchone()), job_id, original_operation_id, actor, 1, nonce,
    )


def _worker(coordinator, bootstrap, namespace, operation_id=None):
    if operation_id is None:
        (job_id,) = coordinator._GraphCoordinator__store._db.execute(
            "SELECT job_id FROM runtime_jobs ORDER BY job_id LIMIT 1"
        ).fetchone()
        operation_id = _op(coordinator, job_id)
    lease, capability = coordinator.grant(
        bootstrap, actor="encoding-worker", issuer_domain="d11",
        namespace=namespace, domains=("d11",), activation_generation=1,
        operation_id=operation_id,
    )
    (source_json,) = coordinator._GraphCoordinator__store._db.execute(
        "SELECT value FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name='memory.source' ORDER BY token LIMIT 1",
        namespace.as_tuple,
    ).fetchone()
    authority = AuthorityContext(
        "encoding-worker", "d11", capability, namespace, ("activity",),
        "consolidation", tuple(json.loads(source_json)["audiences"]), "policy-1", 1,
    )
    return authority, lease


def _narrow_access_grant(store, namespace, source_id, *,
                         audiences=None, purposes=None):
    token, value = store._db.execute(
        "SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name='memory.access' AND subject=?",
        namespace.as_tuple + (source_id,),
    ).fetchone()
    access = json.loads(value)
    if audiences is not None:
        access["audiences"] = audiences
    if purposes is not None:
        access["purposes"] = purposes
    validate_access(access)
    store._db.execute(
        "UPDATE graph_atoms SET value=? WHERE token=?",
        (json.dumps(access, sort_keys=True, separators=(",", ":")), token),
    )


class FixedEncodingRequestIssuer:
    def __init__(self):
        self.config_digest = "c" * 64

    def __call__(self, context):
        job = context.job
        source = context.source
        source_revision = context.source_revision
        access_revision = context.access_revision
        assert context.authority.worker_fence == job.fence
        assert context.authority.issuer_domain == "d11"
        assert context.source_qualification.source_family == "reported"
        assert context.version_guard.access_epoch >= 0
        assert context.now_utc < context.deadline_utc
        namespace = NamespaceId(job.bot_id, job.persona_id)
        source_ref = source_key(*namespace.as_tuple, source.source_id).token
        payload, template_digest = build_first_ingress_encoding_payload(source)
        envelope = CommandEnvelope(
            "sylanne.runtime.v1",
            OperationIdentity(
                job.activity_id, None, "encoding-attempt", "encode",
                "encoding-model-operation", canonical_digest({"input_refs": [source_ref]})),
            context.authority,
            context.version_guard,
            context.source_qualification,
            (source_ref,), job.budget_ref,
            context.deadline_utc,
            1.0, "interval", (),
        )
        return EncodingRequestIssueV1(
            ModelCallRequest(
                envelope, "encoding-call-1", "provider-1", "model-1",
                frozenset({"structured"}), "private", template_digest,
                payload, 20.0, 128),
            "admin-provider-config", self.config_digest,
        )


def test_first_ingress_job_acquire_is_durable_and_exactly_replayed(ingress_system):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    original = json.loads(store._db.execute(
        "SELECT value FROM graph_atoms WHERE type_name='runtime.job'"
    ).fetchone()[0])
    authority, lease = _worker(coordinator, bootstrap, policy.namespace)

    acquired = coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, _op(coordinator, job_id), lease_seconds=30)
    replay = coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, _op(coordinator, job_id), lease_seconds=30)

    assert replay == acquired
    assert acquired.operation_id == original["operation_id"]
    assert acquired.fence == original["fence"] + 1
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_job_acquire_receipts_v2"
    ).fetchone()[0] == 1
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_jobs"
    ).fetchone()[0] == 1
    with pytest.raises((AuthorityDenied, UnavailableGuard)):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, "acquire-encoding-2", lease_seconds=30)


def test_acquired_encoding_inputs_are_read_from_current_source(ingress_system):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    operation_id = _op(coordinator, job_id)
    authority, lease = _worker(coordinator, bootstrap, policy.namespace,
                               operation_id=operation_id)
    acquired = coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, operation_id, lease_seconds=30)
    current_authority = replace(authority, worker_fence=acquired.fence)
    inputs = coordinator.read_first_ingress_encoding_inputs_v2(
        current_authority, lease, job_id, operation_id)
    assert inputs.job == acquired
    assert inputs.source.text == host.text
    assert inputs.source.source_id == host.lineage.source_ref
    assert inputs.source_revision == 1 and inputs.access_revision == 1
    assert inputs.budget_lease_id == acquired.budget_ref
    assert inputs.budget_reservation_operation_id == acquired.operation_id
    with pytest.raises(UnavailableGuard, match="not current"):
        coordinator.read_first_ingress_encoding_inputs_v2(
            authority, lease, job_id, operation_id)


def test_encoding_request_binds_in_the_job_acquire_transaction(ingress_system):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    issuer = FixedEncodingRequestIssuer()
    coordinator._GraphCoordinator__encoding_request_issuer = issuer
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    operation_id = _op(coordinator, job_id)
    authority, lease = _worker(coordinator, bootstrap, policy.namespace,
                               operation_id=operation_id)
    acquired = coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, operation_id, lease_seconds=30)
    binding = load_binding(store._db, policy.namespace, job_id)
    assert binding is not None
    assert binding.request["envelope"]["authority"]["worker_fence"] == acquired.fence
    assert binding.request["provider_config_digest"] == "c" * 64
    assert binding.request["payload"]["prompt"]
    assert store._db.execute(
        "SELECT encoding_binding_json FROM graph_job_acquire_intents_v2 "
        "WHERE acquire_operation_id=?", (operation_id,),
    ).fetchone()[0] is not None
    issuer.config_digest = "d" * 64
    assert coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, operation_id, lease_seconds=30) == acquired
    assert load_binding(store._db, policy.namespace, job_id) == binding


def test_original_d06_qualification_is_durable_and_legacy_gap_holds(ingress_system):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (saved,) = store._db.execute(
        "SELECT source_qualification_json FROM runtime_ingress_issuance"
    ).fetchone()
    original = json.loads(saved)
    assert original["source_family"] == "reported"
    assert original["source_refs"] == [source_key(
        *policy.namespace.as_tuple, host.lineage.source_ref).token]
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    operation_id = _op(coordinator, job_id)
    authority, lease = _worker(coordinator, bootstrap, policy.namespace,
                               operation_id=operation_id)
    # Emulate a pre-migration row that never stored the original D06 decision.
    store._db.execute("DROP TRIGGER runtime_ingress_issuance_no_update_v2")
    store._db.execute(
        "UPDATE runtime_ingress_issuance SET source_qualification_json=NULL")
    with pytest.raises(UnavailableGuard, match="original D06 source qualification absent"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, operation_id, lease_seconds=30)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_job_acquire_intents_v2").fetchone()[0] == 0


@pytest.mark.parametrize("tamper", ["authority", "version", "qualification"])
def test_issuer_cannot_expand_trusted_encoding_context(ingress_system, tamper):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock

    class TamperedIssuer(FixedEncodingRequestIssuer):
        def __call__(self, context):
            issued = super().__call__(context)
            envelope = issued.request.envelope
            if tamper == "authority":
                envelope = replace(envelope, authority=replace(
                    envelope.authority, issuer_domain="d06"))
            elif tamper == "version":
                envelope = replace(envelope, version_guard=replace(
                    envelope.version_guard,
                    access_epoch=envelope.version_guard.access_epoch + 1))
            else:
                envelope = replace(envelope, source_qualification=replace(
                    envelope.source_qualification,
                    learned_at=envelope.source_qualification.learned_at + 1))
            return replace(issued, request=replace(issued.request, envelope=envelope))

    coordinator._GraphCoordinator__encoding_request_issuer = TamperedIssuer()
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    operation_id = _op(coordinator, job_id)
    authority, lease = _worker(coordinator, bootstrap, policy.namespace,
                               operation_id=operation_id)
    with pytest.raises(UnavailableGuard, match="trusted issuance context"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, operation_id, lease_seconds=30)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_job_acquire_intents_v2").fetchone()[0] == 0


def test_bound_request_replay_rechecks_current_policy_version(ingress_system):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator._GraphCoordinator__encoding_request_issuer = FixedEncodingRequestIssuer()
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    operation_id = _op(coordinator, job_id)
    authority, lease = _worker(coordinator, bootstrap, policy.namespace,
                               operation_id=operation_id)
    coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, operation_id, lease_seconds=30)
    store._db.execute(
        "UPDATE graph_guard_versions SET version='policy-2' "
        "WHERE bot=? AND persona=? AND kind='policy' AND ref='current'",
        policy.namespace.as_tuple)
    with pytest.raises(UnavailableGuard, match="trusted issuance context"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, operation_id, lease_seconds=30)


@pytest.mark.parametrize("stage", ["before_issue", "before_commit", "replay"])
def test_encoding_binding_requires_current_access_audience(ingress_system, stage):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator._GraphCoordinator__encoding_request_issuer = FixedEncodingRequestIssuer()
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    operation_id = _op(coordinator, job_id)
    authority, lease = _worker(coordinator, bootstrap, policy.namespace,
                               operation_id=operation_id)
    if stage == "before_commit":
        begin = port.begin_fence

        def narrow_after_begin(**kwargs):
            permit = begin(**kwargs)
            _narrow_access_grant(
                store, policy.namespace, host.lineage.source_ref,
                audiences=[])
            return permit

        port.begin_fence = narrow_after_begin
    elif stage == "replay":
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, operation_id, lease_seconds=30)
        _narrow_access_grant(
            store, policy.namespace, host.lineage.source_ref, audiences=[])
    else:
        _narrow_access_grant(
            store, policy.namespace, host.lineage.source_ref, audiences=[])
    with pytest.raises(UnavailableGuard, match="current access"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, operation_id, lease_seconds=30)
    if stage != "replay":
        assert load_binding(store._db, policy.namespace, job_id) is None
        assert store._db.execute(
            "SELECT phase FROM runtime_jobs WHERE job_id=?", (job_id,)
        ).fetchone()[0] == "queued"


def test_encoding_binding_requires_current_access_purpose(ingress_system):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator._GraphCoordinator__encoding_request_issuer = FixedEncodingRequestIssuer()
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    operation_id = _op(coordinator, job_id)
    authority, lease = _worker(coordinator, bootstrap, policy.namespace,
                               operation_id=operation_id)
    authority = replace(authority, purpose="context")
    _narrow_access_grant(
        store, policy.namespace, host.lineage.source_ref,
        purposes=["consolidation"])
    with pytest.raises(UnavailableGuard, match="current access"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, operation_id, lease_seconds=30)
    assert load_binding(store._db, policy.namespace, job_id) is None


def test_policy_change_after_acquire_intent_blocks_commit(ingress_system):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator._GraphCoordinator__encoding_request_issuer = FixedEncodingRequestIssuer()
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    operation_id = _op(coordinator, job_id)
    authority, lease = _worker(coordinator, bootstrap, policy.namespace,
                               operation_id=operation_id)
    begin = port.begin_fence

    def change_policy_after_begin(**kwargs):
        permit = begin(**kwargs)
        store._db.execute(
            "UPDATE graph_guard_versions SET version='policy-2' "
            "WHERE bot=? AND persona=? AND kind='policy' AND ref='current'",
            policy.namespace.as_tuple)
        return permit

    port.begin_fence = change_policy_after_begin
    with pytest.raises(UnavailableGuard, match="trusted issuance context"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, operation_id, lease_seconds=30)
    assert store._db.execute(
        "SELECT phase FROM runtime_jobs WHERE job_id=?", (job_id,)
    ).fetchone()[0] == "queued"
    assert load_binding(store._db, policy.namespace, job_id) is None


def test_lost_begin_cannot_replace_frozen_encoding_config(ingress_system):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    issuer = FixedEncodingRequestIssuer()
    coordinator._GraphCoordinator__encoding_request_issuer = issuer
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    operation_id = _op(coordinator, job_id)
    authority, lease = _worker(coordinator, bootstrap, policy.namespace,
                               operation_id=operation_id)
    port.lose_begin_after_durable = True
    with pytest.raises(JobAcquireOutcomeUnknown):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, operation_id, lease_seconds=30)
    issuer.config_digest = "d" * 64
    with pytest.raises(UnavailableGuard, match="configuration changed"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, operation_id, lease_seconds=30)
    assert load_binding(store._db, policy.namespace, job_id) is None
    assert store._db.execute(
        "SELECT phase FROM runtime_jobs WHERE job_id=?", (job_id,),
    ).fetchone()[0] == "queued"


def test_lost_finish_replays_the_same_bound_request(ingress_system):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator._GraphCoordinator__encoding_request_issuer = FixedEncodingRequestIssuer()
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    operation_id = _op(coordinator, job_id)
    authority, lease = _worker(coordinator, bootstrap, policy.namespace,
                               operation_id=operation_id)
    port.lose_finish_after_durable = True
    with pytest.raises(JobAcquireOutcomeUnknown):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, operation_id, lease_seconds=30)
    bound = load_binding(store._db, policy.namespace, job_id)
    assert bound is not None
    replayed = coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, operation_id, lease_seconds=30)
    assert replayed.fence == 1
    assert load_binding(store._db, policy.namespace, job_id) == bound
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_encoding_call_bindings_v1"
    ).fetchone()[0] == 1


def test_d12_storage_redaction_removes_both_request_copies_and_blocks_replay(
    ingress_system,
):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator._GraphCoordinator__encoding_request_issuer = FixedEncodingRequestIssuer()
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    operation_id = _op(coordinator, job_id)
    authority, lease = _worker(coordinator, bootstrap, policy.namespace,
                               operation_id=operation_id)
    acquired = coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, operation_id, lease_seconds=30)
    bound = load_binding(store._db, policy.namespace, job_id)
    assert host.text in bound.request_json
    frozen = store._db.execute(
        "SELECT encoding_binding_json FROM graph_job_acquire_intents_v2 "
        "WHERE acquire_operation_id=?", (operation_id,),
    ).fetchone()[0]
    assert host.text in frozen
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        try:
            assert _redact_source_binding_content_in_transaction(
                store._db, policy.namespace, host.lineage.source_ref,
                "d12-delete-1") == 1
            store._db.execute("COMMIT")
        except BaseException:
            store._db.execute("ROLLBACK")
            raise
    assert load_binding(store._db, policy.namespace, job_id) is None
    assert store._db.execute(
        "SELECT encoding_binding_json FROM graph_job_acquire_intents_v2 "
        "WHERE acquire_operation_id=?", (operation_id,),
    ).fetchone()[0] is None
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        store._db.execute(
            "UPDATE graph_job_acquire_intents_v2 SET encoding_binding_json=? "
            "WHERE acquire_operation_id=?", (frozen, operation_id))
    assert store._db.execute(
        "SELECT call_id,binding_digest,model_request_digest FROM "
        "runtime_encoding_call_redactions_v1 WHERE acquire_operation_id=?",
        (operation_id,),
    ).fetchone() == (
        bound.call_id, bound.binding_digest, bound.model_request_digest)
    with pytest.raises(UnavailableGuard, match="erased"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, operation_id, lease_seconds=30)
    next_operation = _op(coordinator, job_id, nonce="b" * 32)
    next_authority, next_lease = _worker(
        coordinator, bootstrap, policy.namespace, operation_id=next_operation)
    with pytest.raises(UnavailableGuard, match="erased"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            next_authority, next_lease, job_id, next_operation, lease_seconds=30)
    with pytest.raises(UnavailableGuard, match="erased"):
        coordinator.read_first_ingress_encoding_inputs_v2(
            replace(authority, worker_fence=acquired.fence),
            lease, job_id, operation_id)
    with pytest.raises(EncodingCallConflict, match="erased source"):
        insert_binding(store._db, bound)
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        try:
            assert _redact_source_binding_content_in_transaction(
                store._db, policy.namespace, host.lineage.source_ref,
                "d12-delete-1") == 0
            store._db.execute("COMMIT")
        except BaseException:
            store._db.execute("ROLLBACK")
            raise


def test_d12_storage_redaction_covers_uncommitted_acquire_intent(ingress_system):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator._GraphCoordinator__encoding_request_issuer = FixedEncodingRequestIssuer()
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    operation_id = _op(coordinator, job_id)
    authority, lease = _worker(coordinator, bootstrap, policy.namespace,
                               operation_id=operation_id)
    port.lose_begin_after_durable = True
    with pytest.raises(JobAcquireOutcomeUnknown):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, operation_id, lease_seconds=30)
    assert load_binding(store._db, policy.namespace, job_id) is None
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        store._db.execute(
            "UPDATE graph_job_acquire_intents_v2 SET encoding_binding_json=NULL "
            "WHERE acquire_operation_id=?", (operation_id,))
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        try:
            assert _redact_source_binding_content_in_transaction(
                store._db, policy.namespace, host.lineage.source_ref,
                "d12-delete-pending") == 1
            store._db.execute("ROLLBACK")
        except BaseException:
            store._db.execute("ROLLBACK")
            raise
    assert host.text in store._db.execute(
        "SELECT encoding_binding_json FROM graph_job_acquire_intents_v2 "
        "WHERE acquire_operation_id=?", (operation_id,),
    ).fetchone()[0]
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        try:
            assert _redact_source_binding_content_in_transaction(
                store._db, policy.namespace, host.lineage.source_ref,
                "d12-delete-pending") == 1
            store._db.execute("COMMIT")
        except BaseException:
            store._db.execute("ROLLBACK")
            raise
    assert store._db.execute(
        "SELECT encoding_binding_json FROM graph_job_acquire_intents_v2 "
        "WHERE acquire_operation_id=?", (operation_id,),
    ).fetchone()[0] is None
    with pytest.raises(UnavailableGuard, match="erased"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, operation_id, lease_seconds=30)


def test_d11_lease_cannot_acquire_a_different_operation(ingress_system):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    authority, lease = _worker(coordinator, bootstrap, policy.namespace,
                               operation_id="acquire-other-job")

    with pytest.raises(AuthorityDenied, match="scoped to this operation"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, _op(coordinator, job_id), lease_seconds=30)
    with pytest.raises(AuthorityDenied, match="scoped to this operation"):
        coordinator.read_first_ingress_encoding_job_v2(
            authority, lease, job_id, _op(coordinator, job_id))
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_job_acquire_intents_v2"
    ).fetchone()[0] == 0


def test_same_acquire_operation_cannot_be_moved_to_another_job(ingress_system):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (first_job,) = store._db.execute(
        "SELECT job_id FROM runtime_jobs ORDER BY job_id LIMIT 1"
    ).fetchone()
    other_host = replace(
        host, message_id="message-2",
        lineage=replace(host.lineage, source_ref="c" * 64),
    )
    coordinator.commit_first_ingress_v2(
        bootstrap, other_host, policy, clock, encoding)
    (other_job,) = store._db.execute(
        "SELECT job_id FROM runtime_jobs WHERE job_id<>?", (first_job,)
    ).fetchone()
    authority, lease = _worker(
        coordinator, bootstrap, policy.namespace,
        operation_id=_op(coordinator, first_job),
    )
    with pytest.raises(AuthorityDenied, match="names another job"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, other_job, _op(coordinator, first_job),
            lease_seconds=30,
        )
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_job_acquire_intents_v2"
    ).fetchone()[0] == 0


def test_begin_delay_past_deadline_cannot_commit_running_job(
    ingress_system, monkeypatch,
):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    authority, lease = _worker(coordinator, bootstrap, policy.namespace)
    begin = port.begin_fence
    monotonic = time.monotonic

    def delayed_begin(**kwargs):
        permit = begin(**kwargs)
        # Simulate 200 seconds elapsing after a verified UTC/monotonic sample.
        monkeypatch.setattr(first_ingress_v2.time, "monotonic",
                            lambda: monotonic() + 200)
        return permit

    port.begin_fence = delayed_begin
    try:
        with pytest.raises(UnavailableGuard, match="HOLD"):
            coordinator.acquire_first_ingress_encoding_job_v2(
                authority, lease, job_id, _op(coordinator, job_id),
                lease_seconds=30,
            )
    finally:
        monkeypatch.undo()
    assert store._db.execute(
        "SELECT phase FROM runtime_jobs WHERE job_id=?", (job_id,)
    ).fetchone()[0] == "queued"
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_job_acquire_receipts_v2"
    ).fetchone()[0] == 0


def test_lost_finish_response_recovers_only_original_acquire(ingress_system):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    authority, lease = _worker(coordinator, bootstrap, policy.namespace)
    port.lose_finish_after_durable = True

    with pytest.raises(JobAcquireOutcomeUnknown):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, _op(coordinator, job_id), lease_seconds=30)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_job_acquire_receipts_v2"
    ).fetchone()[0] == 1
    prior = store._db.execute(
        "SELECT fence FROM runtime_jobs WHERE job_id=?", (job_id,)
    ).fetchone()[0]

    recovered = coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, _op(coordinator, job_id), lease_seconds=30)
    assert recovered.fence == prior
    assert store._db.execute(
        "SELECT fence FROM runtime_jobs WHERE job_id=?", (job_id,)
    ).fetchone()[0] == prior


def test_lost_begin_response_reuses_durable_acquire_intent(ingress_system):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    authority, lease = _worker(coordinator, bootstrap, policy.namespace)
    port.lose_begin_after_durable = True

    with pytest.raises(JobAcquireOutcomeUnknown):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, _op(coordinator, job_id), lease_seconds=30)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_job_acquire_intents_v2"
    ).fetchone()[0] == 1
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_job_acquire_receipts_v2"
    ).fetchone()[0] == 0
    recovered = coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, _op(coordinator, job_id), lease_seconds=30)
    assert recovered.fence == 1
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_job_acquire_intents_v2"
    ).fetchone()[0] == 1


def test_expired_lease_can_be_reacquired_with_new_job_bound_attempt(
    ingress_system, monkeypatch,
):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    sample = SimpleNamespace(
        utc_upper_bound_seconds=time.time() + 0.01,
        monotonic_after_seconds=time.monotonic(),
    )
    port.read_ingress_clock = lambda _: sample
    first_op = _op(coordinator, job_id)
    first_auth, first_lease = _worker(
        coordinator, bootstrap, policy.namespace, operation_id=first_op)
    first = coordinator.acquire_first_ingress_encoding_job_v2(
        first_auth, first_lease, job_id, first_op, lease_seconds=30)
    monotonic = time.monotonic
    monkeypatch.setattr(first_ingress_v2.time, "monotonic",
                        lambda: monotonic() + 31)
    try:
        with pytest.raises(UnavailableGuard, match="HOLD"):
            coordinator.acquire_first_ingress_encoding_job_v2(
                first_auth, first_lease, job_id, first_op, lease_seconds=30)
        second_op = _op(coordinator, job_id, nonce="b" * 32)
        second_auth, second_lease = _worker(
            coordinator, bootstrap, policy.namespace, operation_id=second_op)
        second = coordinator.acquire_first_ingress_encoding_job_v2(
            second_auth, second_lease, job_id, second_op, lease_seconds=30)
    finally:
        monkeypatch.undo()
    assert second.fence == first.fence + 1
    assert second.operation_id == first.operation_id


def test_replay_after_trusted_expiry_is_hold(ingress_system):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    authority, lease = _worker(coordinator, bootstrap, policy.namespace)
    coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, _op(coordinator, job_id), lease_seconds=30)
    port.read_ingress_clock = lambda _: SimpleNamespace(
        utc_upper_bound_seconds=time.time() + 180,
        monotonic_after_seconds=time.monotonic(),
    )
    with pytest.raises(UnavailableGuard, match="HOLD"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, _op(coordinator, job_id), lease_seconds=30)


def test_withdrawn_d06_access_blocks_read_and_acquire(ingress_system):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    authority, lease = _worker(coordinator, bootstrap, policy.namespace)
    token, value = store._db.execute(
        "SELECT token,value FROM graph_atoms WHERE type_name='memory.access' "
        "AND subject=?", (host.lineage.source_ref,)
    ).fetchone()
    access = json.loads(value)
    # Controlled DB fault injection: assert the worker checks current D06 truth.
    access["status"] = "withdrawn"
    validate_access(access)
    store._db.execute(
        "UPDATE graph_atoms SET value=? WHERE token=?",
        (json.dumps(access, sort_keys=True, separators=(",", ":")), token),
    )
    with pytest.raises(UnavailableGuard, match="source|access"):
        coordinator.read_first_ingress_encoding_job_v2(
            authority, lease, job_id, _op(coordinator, job_id))
    with pytest.raises(UnavailableGuard, match="source|access"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, _op(coordinator, job_id), lease_seconds=30)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_job_acquire_intents_v2"
    ).fetchone()[0] == 0


def test_revoked_budget_lease_blocks_historical_replay(ingress_system):
    store, coordinator, bootstrap, _port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    job_id, budget_ref = store._db.execute(
        "SELECT job_id,budget_ref FROM runtime_jobs"
    ).fetchone()
    authority, lease = _worker(coordinator, bootstrap, policy.namespace)
    coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, _op(coordinator, job_id), lease_seconds=30)
    store._db.execute(
        "UPDATE runtime_budget_leases SET state='blocked' WHERE lease_id=?",
        (budget_ref,),
    )
    with pytest.raises(UnavailableGuard, match="signed authority"):
        coordinator.acquire_first_ingress_encoding_job_v2(
            authority, lease, job_id, _op(coordinator, job_id), lease_seconds=30)


def test_committed_acquire_replays_after_graph_and_authority_reopen(
    ingress_system, tmp_path,
):
    store, coordinator, bootstrap, port, policy, clock, encoding, host = ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    (job_id,) = store._db.execute("SELECT job_id FROM runtime_jobs").fetchone()
    authority, lease = _worker(coordinator, bootstrap, policy.namespace)
    original = coordinator.acquire_first_ingress_encoding_job_v2(
        authority, lease, job_id, _op(coordinator, job_id), lease_seconds=30)
    store.close()

    reopened = ProductionGraphStore(
        tmp_path / "owner-business.db", store._registry)
    import sqlite3

    authority_db = sqlite3.connect(
        tmp_path / "owner-authority.db", isolation_level=None)
    reopened_port = AuthorityPort(reopened, authority_db)
    reopened_port.anchors.update(port.anchors)
    reopened_port.read_ingress_clock = lambda _: SimpleNamespace(
        utc_upper_bound_seconds=time.time() + 0.01,
        monotonic_after_seconds=time.monotonic(),
    )
    d02, d11 = build_runtime_issuers(b"issuer-key-" * 4)
    next_bootstrap = object()
    next_coordinator = GraphCoordinator(
        reopened, next_bootstrap, holder="administrator",
        content_fence_v2=reopened_port, d02_issuer=d02, d11_issuer=d11,
        scene_clock_policy=clock,
    )
    next_coordinator.register_provider(
        next_bootstrap, "d11", D11RuntimeProvider(), D11_PROPOSAL_SCHEMA,
        D11_PROPOSAL_SCHEMA_HASH,
    )
    try:
        next_authority, next_lease = _worker(
            next_coordinator, next_bootstrap, policy.namespace)
        assert next_coordinator.acquire_first_ingress_encoding_job_v2(
            next_authority, next_lease, job_id, _op(next_coordinator, job_id),
            lease_seconds=30,
        ) == original
        assert reopened._db.execute(
            "SELECT COUNT(*) FROM graph_job_acquire_receipts_v2"
        ).fetchone()[0] == 1
    finally:
        reopened.close()
        authority_db.close()
