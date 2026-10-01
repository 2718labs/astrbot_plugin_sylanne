"""A signed Owner W01 preview is the only runnable W10 experiment flavor."""

from dataclasses import replace
import pytest

from sylanne3.domains.d12.types import character_draft_key
from sylanne3.workbench_api import WorkbenchService
from sylanne3.workbench_api.issuer import CoordinatorGrant, GraphWorkbenchIssuer

from tests.alpha1.d12.test_owner_graph_lease import NAMESPACE, owner_graph
from tests.alpha1.d12.test_workbench_service import CONTEXT, request, session
from tests.alpha1.runtime.test_d12_current_compile_v1 import _setup
from tests.alpha1.runtime.test_d12_domain_scheme_compile_v1 import ATTENTION_POLICY


@pytest.mark.parametrize("fields,report_table", [
    ({"d07.attention_policy": ATTENTION_POLICY},
     "graph_d12_preview_behavior_originals_v1"),
    ({"d09.expression_policy": {
        "policy_ref": "d09:expression", "policy_version": "v1",
        "max_visible_chars": 19, "schema": "d09.expression_policy.v1",
    }}, "graph_d12_d09_preview_originals_v1"),
])
def test_signed_owner_experiment_uses_paid_persisted_report_and_replays(
        owner_graph, fields, report_table):
    graph, coordinator, authority, lease = _setup(owner_graph, fields)

    class Grants:
        def resolve(self, *, session, scope, purpose, audience):
            assert (scope, purpose, audience) == (
                "bot/persona", "workbench_user_action", "owner")
            return CoordinatorGrant(scope, authority, lease,
                                    frozenset({"workbench.compile",
                                               "workbench.experiment"}))

    class Views:
        def view_types(self, authority):
            return {}

    service = WorkbenchService(GraphWorkbenchIssuer(
        coordinator, Grants(), Views(), scheme_port=coordinator))
    owner = replace(session("workbench.compile", "workbench.experiment"),
                    actor_id=authority.actor)
    compiled = service.handle(
        request("compile_scheme", draft_ref=character_draft_key(NAMESPACE).token,
                budget_ref="d12-budget"), session=owner, context=CONTEXT)
    assert compiled.status == "ready", compiled.problem
    experiment = request(
        "run_experiment", experiment="d12.scheme_preview.v1",
        input_refs=[compiled.receipt["compiled_digest"]],
        budget_ref="d12-budget",
        retention_policy_ref="d12.preview_original.v1")
    first = service.handle(experiment, session=owner, context=CONTEXT)
    assert first.status == "ready", first.problem
    assert first.receipt["phase"] == "isolated_experiment_recorded"
    assert first.receipt["coverage"]
    assert first.receipt["production_revision_unchanged"] is True
    assert first.receipt["external_effect_refs"] == []
    assert first.receipt["formal_contribution_refs"] == []
    assert first.receipt["production_write_refs"] == []
    assert service.handle(experiment, session=owner, context=CONTEXT).receipt == first.receipt

    report = coordinator.read_current_preview_report_v1(
        authority, lease, preview_seal=first.receipt["preview_seal"])
    assert report.report_digest == first.receipt["report_digest"]
    assert report.spec.operation_id == experiment["operation_id"]
    with graph._lock:
        assert graph._db.execute(
            f"SELECT COUNT(*) FROM {report_table}"
        ).fetchone() == (1,)
