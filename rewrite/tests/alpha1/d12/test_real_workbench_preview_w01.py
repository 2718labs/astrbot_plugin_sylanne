"""The D12 service must read W01's durable compile and preview originals."""

from dataclasses import replace

from sylanne3.domains.d12.types import character_draft_key
from sylanne3.workbench_api import WorkbenchService
from sylanne3.workbench_api.issuer import CoordinatorGrant, GraphWorkbenchIssuer

from tests.alpha1.d12.test_owner_graph_lease import NAMESPACE, owner_graph
from tests.alpha1.d12.test_workbench_service import CONTEXT, request, session
from tests.alpha1.runtime.test_d12_current_compile_v1 import _setup
from tests.alpha1.runtime.test_d12_domain_scheme_compile_v1 import ATTENTION_POLICY


def test_real_workbench_compiles_and_previews_but_d07_adoption_stays_hold(owner_graph):
    graph, coordinator, authority, lease = _setup(
        owner_graph, {"d07.attention_policy": ATTENTION_POLICY})

    class Grants:
        def resolve(self, *, session, scope, purpose, audience):
            assert (scope, purpose, audience) == (
                "bot/persona", "workbench_user_action", "owner")
            return CoordinatorGrant(
                scope, authority, lease,
                frozenset({"workbench.compile", "workbench.experiment",
                           "workbench.activate"}),
            )

    class Views:
        def view_types(self, authority):
            return {}

    service = WorkbenchService(GraphWorkbenchIssuer(
        coordinator, Grants(), Views(), scheme_port=coordinator))
    creator = replace(
        session("workbench.compile", "workbench.experiment",
                "workbench.activate"),
        actor_id=authority.actor,
    )
    compile_request = request(
        "compile_scheme", draft_ref=character_draft_key(NAMESPACE).token,
        budget_ref="d12-budget")
    compiled = service.handle(compile_request, session=creator, context=CONTEXT)
    assert compiled.status == "ready", compiled.problem
    assert compiled.receipt["phase"] == "compiled_candidate_recorded"
    assert service.handle(
        compile_request, session=creator, context=CONTEXT).receipt == compiled.receipt

    preview_request = request(
        "preview_scheme", compiled_digest=compiled.receipt["compiled_digest"],
        budget_ref="d12-budget")
    preview = service.handle(preview_request, session=creator, context=CONTEXT)
    assert preview.status == "ready", preview.problem
    assert preview.receipt["phase"] == "isolated_preview_recorded"
    assert preview.receipt["actual_cost_receipt_ref"].startswith("d12-preview-cost:")
    assert service.handle(
        preview_request, session=creator, context=CONTEXT).receipt == preview.receipt

    adoption = service.handle(request(
        "activate_scheme", compiled_digest=compiled.receipt["compiled_digest"],
        preview_seal=preview.receipt["preview_seal"]),
        session=creator, context=CONTEXT)
    assert adoption.status == "stale"
    assert adoption.problem["code"] == "scheme_current_basis_changed"
    with graph._lock:
        assert graph._db.execute(
            "SELECT COUNT(*) FROM graph_d12_compilation_operations_v1"
        ).fetchone() == (1,)
        assert graph._db.execute(
            "SELECT COUNT(*) FROM graph_d12_preview_behavior_originals_v1"
        ).fetchone() == (1,)
