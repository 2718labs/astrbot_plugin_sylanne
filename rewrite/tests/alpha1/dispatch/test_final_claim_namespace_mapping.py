"""P0 uses the opaque Authority namespace; committed D11 rows use graph scope."""

from dataclasses import replace
import hashlib
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_contract import (
    ExecutionBindingV1, ExecutionBindingV2, FencePermitV2, MutationReceiptV2,
    PendingMutationV2,
)
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.runtime.dispatch_current_source_budget import (
    CurrentDispatchHold, CurrentSourceBudgetV1,
)
from sylanne3.runtime.dispatch_final_claim import read_final_claim_prerequisite
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.runtime_journal import RecoveryConstraintFootprint


def _chain(namespace, *, authority_namespace=None, graph_namespace=None):
    opaque = authority_namespace or namespace_ref(namespace)
    graph = graph_namespace or "/".join(namespace.as_tuple)
    footprint = RecoveryConstraintFootprint(opaque, "activity:test", "effect:test",
                                           conflict_keys=("conflict:test",))
    anchor = RestoreAnchor(
        "authority:test", opaque, 1, "deletion:test", 0, "genesis",
        "execution:test", 0, "genesis", 0, "proof:test",
    )
    permit = FencePermitV2(
        "authority:test", opaque, "subject:test", "holder:test", 1,
        "dispatch", "operation:test", "A" * 43, 1, 1, anchor, "effect:test",
        "sha256:" + "1" * 64,
        "sha256:" + hashlib.sha256(footprint._json().encode()).hexdigest(),
    )
    origin = ExecutionBindingV1(
        permit, opaque, "activity:test", "effect:test", "attempt:test",
        "operation:test", 1, 1, "admission:test", ("check:test",),
        "sha256:" + "2" * 64, "platform:test", "adapter:test",
        "account:test", "destination:test", 1, "content:test", 0,
        footprint,
    )
    digest = "sha256:" + "3" * 64
    binding = ExecutionBindingV2(
        origin, graph, "graph:test", digest, "version:test", 1, 0, 0,
        digest, "intent:v1", digest, "schema:v1", digest, "checks:v1",
        digest, "2099-01-01T00:00:00Z", "clock:test", digest,
    )
    prepare = PendingMutationV2(
        permit, "prepare:test", digest, "prepared", anchor,
        "append:prepared", "sha256:" + "4" * 64,
    )
    anchor1 = replace(anchor, execution_seq=1,
                      execution_digest="sha256:" + "4" * 64)
    prepared = MutationReceiptV2(prepare, anchor1, 2, "committed")
    p1 = replace(permit, revision=2, pinned_anchor=anchor1)
    claim = PendingMutationV2(
        p1, "claim:test", digest, "claimed", anchor1,
        "append:claimed", "sha256:" + "5" * 64,
        prepared_receipt=prepared, binding=binding,
    )
    anchor2 = replace(anchor1, execution_seq=2,
                      execution_digest="sha256:" + "5" * 64)
    return binding, MutationReceiptV2(claim, anchor2, 3, "committed")


def _committed_row(binding):
    origin = binding.origin
    admission = SimpleNamespace(
        namespace=binding.graph_namespace, graph_incarnation=binding.graph_incarnation,
        access_epoch=0, delete_epoch=0,
        action_intent_digest="3" * 64, action_intent_schema_version="intent:v1",
        action_schema_digest="3" * 64, action_schema_version="schema:v1",
        required_checks_digest="3" * 64,
        required_checks_schema_version="checks:v1",
        initial_check_evidence_digest="3" * 64,
        utc_deadline=binding.utc_deadline, clock_policy_ref="clock:test",
        clock_policy_digest="3" * 64,
        account_ref=origin.account_ref, destination_ref=origin.destination_ref,
        admission_ref=origin.admission_ref, operation_id=origin.operation_id,
        effect_id=origin.effect_id, dispatch_generation=1,
        candidate_digest="candidate:test",
        check_receipts=(), batch_digest="batch:test",
    )
    request = SimpleNamespace(
        namespace=binding.graph_namespace, operation_id=origin.operation_id,
        activity_id=origin.activity_id, effect_id=origin.effect_id,
        attempt_id=origin.attempt_id, payload_digest="2" * 64,
        platform_capability_ref=origin.platform_capability_ref,
        required_check_refs=origin.verified_check_refs,
        dispatch_generation=1, activation_generation=1, worker_fence=1,
        content_fence="content:test", cancel_epoch=0,
        footprint=replace(origin.footprint, namespace=binding.graph_namespace),
        proactive_contact=False, segment_authorization_ref=None,
        segment_manifest_digest=None, segment_index=None, segment_count=None,
        contact_policy_check_ref=None, command_digest="1" * 64,
    )
    receipt = SimpleNamespace(
        admission=admission, receipt_digest="3" * 64,
        graph_version="version:test", graph_epoch=1,
    )
    return receipt, request


def test_final_prerequisite_maps_only_namespace_between_p0_and_graph(monkeypatch):
    namespace = NamespaceId("bot", "persona")
    binding, claimed = _chain(namespace)
    receipt, request = _committed_row(binding)
    monkeypatch.setattr("sylanne3.runtime.dispatch_final_claim.load_request",
                        lambda *_: (receipt, request))
    monkeypatch.setattr("sylanne3.runtime.dispatch_final_claim.read_current_source_budget",
                        lambda *_args, **_kwargs: CurrentSourceBudgetV1(
                            "admission:test", "candidate:test", "source:test",
                            "budget:test", 0, 0))
    db = SimpleNamespace(in_transaction=True)
    result = read_final_claim_prerequisite(
        db, namespace, binding, claimed, "handoff:test", now_utc=1.0)
    assert result.status == "hold"
    assert binding.namespace == namespace_ref(namespace)
    assert binding.graph_namespace == request.namespace == "bot/persona"
    assert binding.footprint.namespace == binding.namespace
    assert request.footprint.namespace == binding.graph_namespace
    assert replace(binding.footprint, namespace=request.namespace) == request.footprint
    with pytest.raises(CurrentDispatchHold, match="binding differs"):
        monkeypatch.setattr(
            "sylanne3.runtime.dispatch_final_claim.load_request",
            lambda *_: (receipt, SimpleNamespace(**{
                **vars(request), "footprint": replace(
                    request.footprint, conflict_keys=("changed:conflict",)),
            })),
        )
        read_final_claim_prerequisite(
            db, namespace, binding, claimed, "handoff:test", now_utc=1.0)


@pytest.mark.parametrize("authority,graph", (
    ("bot/persona", "bot/persona"),
    (None, "other/persona"),
))
def test_final_prerequisite_rejects_wrong_namespace_before_graph_read(
        monkeypatch, authority, graph):
    namespace = NamespaceId("bot", "persona")
    binding, claimed = _chain(
        namespace, authority_namespace=authority, graph_namespace=graph)
    monkeypatch.setattr(
        "sylanne3.runtime.dispatch_final_claim.load_request",
        lambda *_: pytest.fail("wrong namespace reached graph admission read"),
    )
    with pytest.raises(CurrentDispatchHold, match="original dispatch P0"):
        read_final_claim_prerequisite(
            SimpleNamespace(in_transaction=True), namespace, binding, claimed,
            "handoff:test", now_utc=1.0)
