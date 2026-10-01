"""Current D09 policy binds the paid Owner adoption and graph head."""

import json
from dataclasses import replace
from uuid import uuid4

import pytest

from sylanne3.domains.d12.types import (
    active_scheme_head_key, character_draft_key,
)
from sylanne3.runtime.d12_current_d09_policy_v1 import (
    read_current_d09_expression_policy_v1,
)
from sylanne3.runtime.d12_current_d07_policy_v1 import (
    read_current_d07_attention_policy_v1,
)
from sylanne3.workbench_api import WorkbenchService
from sylanne3.workbench_api.issuer import CoordinatorGrant, GraphWorkbenchIssuer
from tests.alpha1.d12.test_owner_graph_lease import NAMESPACE, owner_graph
from tests.alpha1.d12.test_workbench_service import CONTEXT, request, session
from tests.alpha1.runtime.test_d12_current_compile_v1 import _setup


POLICY = {
    "policy_ref": "d09-visible-48", "policy_version": "v1",
    "max_visible_chars": 48, "schema": "d09.expression_policy.v1",
}


def test_current_d09_reader_uses_default_before_adoption(owner_graph):
    graph, coordinator, authority, lease = _setup(
        owner_graph, {"d09.expression_policy": POLICY}, activate=True)
    with graph._lock:
        db = graph._db
        db.execute("BEGIN")
        try:
            initial = read_current_d09_expression_policy_v1(db, NAMESPACE)
            assert initial.policy is None
            assert initial.active_head_ref.revision == 1
        finally:
            db.execute("ROLLBACK")


def test_current_d09_preview_cost_and_owner_adopted_head(owner_graph):
    graph, coordinator, authority, lease = _setup(
        owner_graph, {"d09.expression_policy": POLICY}, activate=True)
    compilation = coordinator.compile_current_scheme_for_operation_v1(
        authority, lease, operation_id=str(uuid4()),
        draft_ref=character_draft_key(NAMESPACE).token, budget_ref="d12-budget",
    )
    operation_id = str(uuid4())
    preview = coordinator.preview_current_scheme_for_operation_v1(
        authority, lease, operation_id=operation_id,
        compiled_digest=compilation.compiled.compiled_digest,
        budget_ref="d12-budget",
    )
    assert preview.certificate.actual_cost_receipt_ref.startswith(
        "d12-preview-cost:")
    assert coordinator.read_preview_original_v1(
        authority, lease, preview_seal=preview.certificate.issuer_seal,
    ) == preview.certificate
    assert coordinator.preview_current_scheme_for_operation_v1(
        authority, lease, operation_id=operation_id,
        compiled_digest=compilation.compiled.compiled_digest,
        budget_ref="d12-budget",
    ) == preview
    with graph._lock:
        assert graph._db.execute(
            "SELECT COUNT(*) FROM graph_d12_d09_preview_originals_v1 "
            "WHERE operation_id=?", (operation_id,),
        ).fetchone() == (1,)

    compiled = compilation.compiled
    head_key = active_scheme_head_key(NAMESPACE)
    receipt = coordinator.adopt_current_scheme_for_operation_v1(
        authority, lease, operation_id=operation_id,
        compiled_digest=compiled.compiled_digest,
        preview_seal=preview.certificate.issuer_seal,
    )
    assert receipt.status == "coordinator_committed_scheme"
    assert receipt.active_head_revision == 2
    assert coordinator.adopt_current_scheme_for_operation_v1(
        authority, lease, operation_id=operation_id,
        compiled_digest=compiled.compiled_digest,
        preview_seal=preview.certificate.issuer_seal,
    ) == receipt
    with graph._lock:
        db = graph._db
        db.execute("BEGIN")
        try:
            adopted = read_current_d09_expression_policy_v1(db, NAMESPACE)
            assert adopted.active_head_ref.revision == 2
            assert adopted.policy is not None
            assert adopted.policy.max_visible_chars == 48
            assert adopted.compiled_digest == compiled.compiled_digest
            d07 = read_current_d07_attention_policy_v1(db, NAMESPACE)
            assert d07.active_head_ref == adopted.active_head_ref
            assert d07.policy == d07.policy.default()
            db.execute("ROLLBACK")
        except BaseException:
            db.execute("ROLLBACK")
            raise

    with graph._lock:
        db = graph._db
        db.execute("BEGIN IMMEDIATE")
        try:
            raw = json.loads(db.execute(
                "SELECT value FROM graph_atoms WHERE token=?", (head_key.token,),
            ).fetchone()[0])
            raw["compiled_digest"] = "f" * 64
            db.execute(
                "UPDATE graph_atoms SET value=? WHERE token=?",
                (json.dumps(raw, sort_keys=True, separators=(",", ":")),
                 head_key.token),
            )
            with pytest.raises(ValueError, match="compilation original"):
                read_current_d09_expression_policy_v1(db, NAMESPACE)
        finally:
            db.execute("ROLLBACK")


def test_workbench_d09_compile_preview_activate_and_stale_preview(owner_graph):
    graph, coordinator, authority, lease = _setup(
        owner_graph, {"d09.expression_policy": POLICY}, activate=True)

    class Grants:
        def resolve(self, *, session, scope, purpose, audience):
            assert (scope, purpose, audience) == (
                "bot/persona", "workbench_user_action", "owner")
            return CoordinatorGrant(
                scope, authority, lease,
                frozenset(("workbench.compile", "workbench.experiment",
                           "workbench.activate")),
            )

    class Views:
        def view_types(self, authority):
            return {}

    service = WorkbenchService(GraphWorkbenchIssuer(
        coordinator, Grants(), Views(), scheme_port=coordinator))
    creator = replace(
        session("workbench.compile", "workbench.experiment",
                "workbench.activate"), actor_id=authority.actor)
    compilation = service.handle(request(
        "compile_scheme", draft_ref=character_draft_key(NAMESPACE).token,
        budget_ref="d12-budget"), session=creator, context=CONTEXT)
    assert compilation.status == "ready", compilation.problem
    preview = service.handle(request(
        "preview_scheme", compiled_digest=compilation.receipt["compiled_digest"],
        budget_ref="d12-budget"), session=creator, context=CONTEXT)
    assert preview.status == "ready", preview.problem
    activation_request = request(
        "activate_scheme", compiled_digest=compilation.receipt["compiled_digest"],
        preview_seal=preview.receipt["preview_seal"])
    adoption = service.handle(
        activation_request, session=creator, context=CONTEXT)
    assert adoption.status == "ready", adoption.problem
    assert adoption.receipt["active_head_revision"] == 2
    assert service.handle(
        activation_request, session=creator, context=CONTEXT).receipt == adoption.receipt
    with graph._lock:
        db = graph._db
        db.execute("BEGIN")
        try:
            current = read_current_d09_expression_policy_v1(db, NAMESPACE)
            assert current.policy.max_visible_chars == 48
        finally:
            db.execute("ROLLBACK")
    # A paid preview bound to the former head cannot be published again.
    stale = service.handle(request(
        "preview_scheme", compiled_digest=compilation.receipt["compiled_digest"],
        budget_ref="d12-budget"), session=creator, context=CONTEXT)
    assert stale.status != "ready"


def test_d09_adoption_recovers_lost_finish_ack_without_second_cas(
        owner_graph, monkeypatch):
    graph, coordinator, authority, lease = _setup(
        owner_graph, {"d09.expression_policy": POLICY}, activate=True)
    compilation = coordinator.compile_current_scheme_for_operation_v1(
        authority, lease, operation_id=str(uuid4()),
        draft_ref=character_draft_key(NAMESPACE).token, budget_ref="d12-budget")
    operation_id = str(uuid4())
    preview = coordinator.preview_current_scheme_for_operation_v1(
        authority, lease, operation_id=operation_id,
        compiled_digest=compilation.compiled.compiled_digest,
        budget_ref="d12-budget")
    adoption_id = str(uuid4())
    port = owner_graph[3]
    original_finish = port.finish_fence

    def lost_ack(scope, *, request_id, request_digest):
        result = original_finish(
            scope, request_id=request_id, request_digest=request_digest)
        if scope.operation_id.startswith("d12-adopt-"):
            raise RuntimeError("adoption finish ACK lost")
        return result

    monkeypatch.setattr(port, "finish_fence", lost_ack)
    with pytest.raises(RuntimeError, match="ACK lost"):
        coordinator.adopt_current_scheme_for_operation_v1(
            authority, lease, operation_id=adoption_id,
            compiled_digest=compilation.compiled.compiled_digest,
            preview_seal=preview.certificate.issuer_seal)
    monkeypatch.setattr(port, "finish_fence", original_finish)
    receipt = coordinator.adopt_current_scheme_for_operation_v1(
        authority, lease, operation_id=adoption_id,
        compiled_digest=compilation.compiled.compiled_digest,
        preview_seal=preview.certificate.issuer_seal)
    assert receipt.active_head_revision == 2
    with graph._lock:
        assert graph._db.execute(
            "SELECT COUNT(*) FROM graph_d12_adoption_operations_v1",
        ).fetchone() == (1,)
