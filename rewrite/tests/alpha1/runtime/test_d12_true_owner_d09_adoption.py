"""D09 adoption uses one real Owner, mTLS fence and business graph."""

import asyncio
from uuid import uuid4

import pytest

from sylanne3.domains.d09.expression_policy import D09ExpressionPolicyV1
from sylanne3.domains.d12.d09_preview import D12D09PreviewReportV1
from sylanne3.domains.d12.types import character_draft_key
from sylanne3.workbench_api import AuthenticatedSession, RequestContext, WorkbenchService
from sylanne3.workbench_api.issuer import CoordinatorGrant, GraphWorkbenchIssuer
from tests.alpha1.runtime.test_post_c02_reply_assembly_v2 import (
    test_paired_reply_assembly_uses_real_c02_and_reply_admission as real_owner_case,
)


def _adopt_d09_workbench(case, *, max_visible_chars=19):
    """Run public Workbench commands on the donor's signed Owner and budget."""
    graph = case["graph"]
    namespace = case["namespace"]
    activation = graph._v2_graph_stamp(namespace)[0].requirements.activation_generation
    authority, lease, _ = graph.grant_current_owner(
        case["bootstrap"], actor="owner-actor-reply", namespace=namespace,
        domains=("d12", "d11"), purpose="workbench_user_action",
        audience="owner", activation_generation=activation,
        owner_session_token=case["owner_session_token"],
        owner_session_request=case["owner_session_request"])
    try:
        policy = D09ExpressionPolicyV1(
            f"d09-visible-{max_visible_chars}", "v1", max_visible_chars)
        versions = graph.initialize_current_d09_scheme_draft_v1(
            authority, lease, operation_id=str(uuid4()), policy=policy)
        assert tuple(version.revision for version in versions) == (1, 1)

        class Grants:
            def resolve(self, *, session, scope, purpose, audience):
                assert (scope, purpose, audience) == (
                    "/".join(namespace.as_tuple),
                    "workbench_user_action", "owner")
                return CoordinatorGrant(
                    scope, authority, lease,
                    frozenset(("workbench.compile", "workbench.experiment",
                               "workbench.activate")))

        class Views:
            def view_types(self, authority):
                return {}

        service = WorkbenchService(GraphWorkbenchIssuer(
            graph, Grants(), Views(), scheme_port=graph))
        scope = "/".join(namespace.as_tuple)
        creator = AuthenticatedSession(
            authority.actor, "owner-session",
            {scope: frozenset(("workbench.compile", "workbench.experiment",
                                "workbench.activate"))},
            {scope: frozenset(("owner",))},
            {scope: frozenset(("workbench_user_action",))})
        context = RequestContext(True, True, True)

        def command(action, **input_data):
            return {
                "schema_version": "d12.contract.v1", "action": action,
                "scope": scope, "purpose": "workbench_user_action",
                "audience": "owner", "operation_id": str(uuid4()),
                "input": input_data,
            }

        compiled = service.handle(command(
            "compile_scheme", draft_ref=character_draft_key(namespace).token,
            budget_ref=case["policy"].root_grant.lease_id),
            session=creator, context=context)
        assert compiled.status == "ready", compiled.problem
        preview = service.handle(command(
            "preview_scheme", compiled_digest=compiled.receipt["compiled_digest"],
            budget_ref=case["policy"].root_grant.lease_id),
            session=creator, context=context)
        assert preview.status == "ready", preview.problem
        report = graph.read_current_preview_report_v1(
            authority, lease, preview_seal=preview.receipt["preview_seal"])
        assert type(report) is D12D09PreviewReportV1
        assert report.status == "isolated_behavior_only"
        assert "visible_chars:20" in report.changed_probe_ids
        assert graph.read_current_preview_report_v1(
            authority, lease, preview_seal=preview.receipt["preview_seal"]
        ) == report
        adopted = service.handle(command(
            "activate_scheme", compiled_digest=compiled.receipt["compiled_digest"],
            preview_seal=preview.receipt["preview_seal"]),
            session=creator, context=context)
        assert adopted.status == "ready", adopted.problem
        assert adopted.receipt["active_head_revision"] == 2
        return adopted.receipt
    finally:
        graph.release_current_owner_lease(case["bootstrap"], lease)


@pytest.mark.asyncio
async def test_d09_workbench_adopts_under_true_owner_fence(tmp_path):
    async def after_c02(case):
        return await asyncio.to_thread(_adopt_d09_workbench, case)

    await real_owner_case(
        tmp_path, "owned", after_c02=after_c02,
        enable_d09_workbench=True)
