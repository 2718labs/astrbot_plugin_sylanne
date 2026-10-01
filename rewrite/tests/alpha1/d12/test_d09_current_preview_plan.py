"""W01's current D09 draft is the only input to an isolated D09 preview."""

from uuid import uuid4

from sylanne3.domains.d12.d09_current_preview_plan import (
    read_current_d09_preview_plan_v1,
)
from sylanne3.domains.d12.types import character_draft_key
from sylanne3.runtime_contracts import canonical_digest

from tests.alpha1.d12.test_owner_graph_lease import NAMESPACE, owner_graph
from tests.alpha1.runtime.test_d12_current_compile_v1 import _setup


def test_real_compiled_d09_draft_resolves_default_and_persisted_candidate(owner_graph):
    fields = {"d09.expression_policy": {
        "policy_ref": "d09:expression", "policy_version": "v1",
        "max_visible_chars": 19, "schema": "d09.expression_policy.v1",
    }}
    graph, coordinator, authority, lease = _setup(owner_graph, fields)
    original = coordinator.compile_current_scheme_for_operation_v1(
        authority, lease, operation_id=str(uuid4()),
        draft_ref=character_draft_key(NAMESPACE).token,
        budget_ref="d12-budget",
    )
    compiled = original.compiled
    with graph._lock:
        db = graph._db
        db.execute("BEGIN")
        try:
            plan = read_current_d09_preview_plan_v1(
                db, NAMESPACE, operation_id=str(uuid4()),
                compiled_digest=compiled.compiled_digest,
                graph_revision=compiled.graph_revision,
                access_epoch=compiled.access_epoch,
                delete_epoch=compiled.delete_epoch,
            )
        finally:
            db.execute("ROLLBACK")
    assert plan.original == original
    assert plan.baseline is None
    assert plan.candidate.policy.max_visible_chars == 19
    assert plan.spec.candidate_digest == plan.candidate.candidate_digest
    assert len(plan.plan_digest) == 64
    assert plan.plan_digest != canonical_digest(plan.spec)
