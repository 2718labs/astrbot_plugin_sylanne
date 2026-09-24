"""A worker receives model draft limits from current graph and D11 facts."""

import json
import sqlite3
import time
from types import SimpleNamespace

import pytest

from sylanne3.graph_coordinator import (
    GraphCoordinator, UnavailableGuard, _operation_capability_ref,
)
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.host.authority_profile import AdminIngressClockPolicy
from sylanne3.runtime.budget import (
    BudgetLease, create_budget_lease, install_schema as install_budget_schema,
    reserve_budget,
)
from sylanne3.runtime.d11_types import runtime_job_key, runtime_outbox_key
from sylanne3.runtime.encoding_call_binding import EncodingCallBinding
from sylanne3.runtime.issuers import (
    D02ResourceIssuer, D11BudgetJobIssuer, ResourceQuote,
    install_schema as install_issuer_schema,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId, canonical_serialize


def _case():
    db = sqlite3.connect(":memory:")
    install_budget_schema(db)
    install_issuer_schema(db)
    db.execute("CREATE TABLE graph_authority_epochs("
               "bot TEXT,persona TEXT,access_epoch INTEGER,delete_epoch INTEGER)")
    db.execute("INSERT INTO graph_authority_epochs VALUES('bot','persona',5,6)")
    namespace = NamespaceId("bot", "persona")
    create_budget_lease(db, BudgetLease(
        "lease", None, "bot", "persona", "USD", {"output_tokens": 100},
        {}, {}, {}, 1, "active"), "create", "a" * 64)
    reserve_budget(db, "lease", "original", "b" * 64, {"output_tokens": 80})
    d02 = D02ResourceIssuer(b"k" * 32)
    job_key = runtime_job_key("bot", "persona", "activity", "job")
    outbox_key = runtime_outbox_key("bot", "persona", "activity", "outbox")
    d02.issue_quote(db, ResourceQuote(
        "quote", 1, "bot", "persona", "activity", "original", None,
        "lease", "d06.encode_source", "snapshot", 100.0, "resource",
        job_key.token, (outbox_key.token,), (), {"output_tokens": 80},
        None, 100.0,
    ))
    store = object.__new__(ProductionGraphStore)
    store._db = db
    coordinator = object.__new__(GraphCoordinator)
    coordinator._GraphCoordinator__store = store
    coordinator._GraphCoordinator__d02_issuer = d02
    coordinator._GraphCoordinator__d11_issuer = D11BudgetJobIssuer(d02, b"j" * 32)
    coordinator._GraphCoordinator__scene_clock_policy = (
        AdminIngressClockPolicy("clock", 1.0, 1.0))
    calls = []
    coordinator._GraphCoordinator__content_fence_v2 = SimpleNamespace(
        read_ingress_clock=lambda _policy: (
            calls.append("clock") or SimpleNamespace(
                utc_upper_bound_seconds=1.0,
                monotonic_after_seconds=time.monotonic() - 0.01)))
    acquire = "acquire"
    capability = _operation_capability_ref(
        namespace, "worker", "d11", frozenset({"d11"}), 1, acquire)
    authority = AuthorityContext(
        "worker", "d11", capability, namespace, ("activity",),
        "consolidation", ("conversation",), "policy", 1)
    binding = EncodingCallBinding(
        namespace, "job", "source", 2, 3, "lease", "original",
        "c" * 64, "d" * 64, "call", canonical_serialize({
            "provider_id": "provider", "model_id": "model",
            "provider_config_digest": "e" * 64, "max_output_tokens": 64,
        }))
    job = SimpleNamespace(
        job_id="job", activity_id="activity", operation_id="original",
        budget_ref="lease", work_kind="d06.encode_source",
        snapshot_ref="snapshot", resource_ref="resource", fence=4,
        operator_versions={"resource_quote": "quote:1"})
    anchor = RestoreAnchor(
        "authority", "authority-ns", 1, "deletions", 0, "genesis",
        "executions", 0, "genesis", 0, "proof")
    requirements = SimpleNamespace(
        authority_id="authority", authority_namespace="authority-ns",
        activation_generation=1, revocation_epoch=0, deletion_seq=0,
        execution_seq=0)
    metadata = SimpleNamespace(requirements=requirements, graph_revision=12)
    epoch = SimpleNamespace(revision=19)
    coordinator._authorize = lambda *_args, **_kwargs: None
    coordinator._first_ingress_encoding_binding_locked = (
        lambda *_args: (binding, job, SimpleNamespace(), outbox_key))

    def read(_authority, reader, *, return_recovery_context):
        assert return_recovery_context
        calls.append("graph")
        return reader(), anchor, metadata, epoch

    coordinator._read_v2 = read
    return db, coordinator, authority, binding, anchor, calls


def test_preparation_uses_current_reservation_and_graph_stamp():
    db, coordinator, authority, binding, anchor, calls = _case()
    try:
        returned_binding, draft, expected_anchor = (
            coordinator.read_first_ingress_model_egress_preparation_v2(
                authority, object(), "job", "acquire"))
        assert returned_binding == binding
        assert expected_anchor == anchor
        assert calls == ["clock", "graph"]
        assert (draft.graph_epoch, draft.graph_revision) == (19, 12)
        assert (draft.access_epoch, draft.delete_epoch) == (5, 6)
        assert draft.budget_reservation_digest == "b" * 64
        assert draft.budget_ceiling == (("output_tokens", 80),)
        assert (draft.operation_id, draft.call_id, draft.worker_fence) == (
            "acquire", "call", 4)
    finally:
        db.close()


def test_preparation_holds_on_changed_original_ceiling():
    db, coordinator, authority, _, _, _ = _case()
    try:
        db.execute(
            "UPDATE runtime_budget_reservations SET ceiling_json=? "
            "WHERE lease_id='lease' AND operation_id='original'",
            (json.dumps({"output_tokens": 79}),))
        with pytest.raises(UnavailableGuard, match="budget or quote"):
            coordinator.read_first_ingress_model_egress_preparation_v2(
                authority, object(), "job", "acquire")
    finally:
        db.close()
