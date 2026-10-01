"""Two separate paid C02 originals compete for one current D07 focus."""

import asyncio
from dataclasses import replace
from pathlib import Path
import sqlite3
import sys

import pytest

from sylanne3.host.post_c02_attention_driver import (
    post_c02_attention_operation_id, prepare_post_c02_attention_v1,
)
from sylanne3.runtime.first_ingress_v2 import trusted_upper
from sylanne3.runtime_contracts import AuthorityContext
from sylanne3.model_broker.natural_reply import TEMPLATE_VERSION
from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION
from test_post_c02_reply_assembly_v2 import (
    test_paired_reply_assembly_uses_real_c02_and_reply_admission as real_owner_case,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "authority"))
from test_natural_p2_true_owner_handoff import (  # noqa: E402
    _pay_generation, _complete_generation, _prepare_review, _pay_review,
    _complete_review_and_final, _commit_final, _host_one_shot,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["accepted", "unknown"])
async def test_second_real_c02_defers_until_old_terminal(
        tmp_path, monkeypatch, outcome):
    await _real_two_ticket_case(tmp_path, monkeypatch, outcome)


async def _real_two_ticket_case(
        tmp_path, monkeypatch, outcome, *, after_release=None):
    def workflows(base, _model_shared):
        return replace(
            base,
            natural_generation=replace(
                base.reply, work_kind="natural_generation",
                template_version=TEMPLATE_VERSION),
            natural_review=replace(
                base.reply, work_kind="natural_review",
                template_version=REVIEW_TEMPLATE_VERSION),
        )

    async def after_c02(case):
        graph, namespace, bootstrap = (
            case["graph"], case["namespace"], case["bootstrap"])
        second_ingress, second_c02 = await case["commit_second_c02"](
            "message:reply-second", "second message")
        assert second_ingress.operation_id != case["c02"].operation_id
        assert second_c02.operation_id != case["c02"].operation_id
        assert second_c02.status == "committed"
        (current_c02, snapshot, qualification, audience, guard, anchor,
         clock, policy, competitor) = await asyncio.to_thread(
            graph.read_post_c02_attention_inputs_v1,
            bootstrap, namespace, second_c02.operation_id, None,
            case["installed_bundle"])
        assert competitor is not None
        assert competitor.c02_operation_id == case["c02"].operation_id
        source_ref = qualification.source_refs[0]
        operation_id = post_c02_attention_operation_id(
            second_c02.operation_id, source_ref)
        lease, capability = graph.grant(
            bootstrap, actor=case["client_grant"].subject,
            issuer_domain="d11", namespace=namespace, domains=("d07",),
            activation_generation=anchor.activation_generation,
            operation_id=operation_id)
        try:
            authority = AuthorityContext(
                case["client_grant"].subject, "d11", capability, namespace,
                ("persona",), "expression", (audience,),
                case["policy"].root_grant.policy_ref,
                anchor.activation_generation)
            now = trusted_upper(clock)
            lifetime = 27.0
            candidate = prepare_post_c02_attention_v1(
                c02_receipt=current_c02, source_ref=source_ref,
                snapshot=snapshot, qualification=qualification,
                authority=authority, guard=guard,
                parent_budget_lease_ref=case["policy"].root_grant.lease_id,
                conversation_ref=audience, now_utc=now,
                monotonic_deadline=clock.monotonic_after_seconds + lifetime,
                ticket_lifetime_seconds=lifetime,
                current_policy=policy.policy,
                active_head_ref=policy.active_head_ref,
                current_competitor=competitor)
            assert candidate.inbound_deferred
            assert candidate.selected_ticket_id == competitor.ticket.ticket_id
            receipt = await asyncio.to_thread(
                graph.commit_post_c02_attention_v1,
                candidate.bundle, lease, case["installed_bundle"])
            assert receipt.status == "committed"
        finally:
            graph.release_authority_lease(bootstrap, lease)
        decision = await asyncio.to_thread(
            graph.read_post_c02_attention_decision_v2,
            bootstrap, namespace, second_c02.operation_id,
            case["installed_bundle"])
        assert decision is not None
        assert decision.attention_operation_id == receipt.operation_id
        assert decision.inbound_ticket_ref != decision.selected_ticket_ref
        assert decision.inbound_deferred
        assert decision.wake_at == candidate.wake_at
        assert case["store"]._db.execute(
            "SELECT COUNT(*) FROM runtime_jobs WHERE work_kind='natural_generation'"
        ).fetchone() == (0,)

        port = case["port"]
        with monkeypatch.context() as paid_consumers:
            paid_consumers.setattr(
                port, "natural_paid_consumer_ready_v2",
                lambda *, namespace, template_version:
                    namespace == case["namespace"]
                    and template_version == TEMPLATE_VERSION,
                raising=False)
            paid_consumers.setattr(
                port, "natural_review_paid_consumer_ready_v2",
                lambda *, namespace, template_version:
                    namespace == case["namespace"]
                    and template_version == REVIEW_TEMPLATE_VERSION,
                raising=False)
            held = []
            try:
                saved = await asyncio.to_thread(
                    graph.prepare_post_c02_natural_generation_v2,
                    bootstrap, namespace, case["c02"].operation_id,
                    case["source_ref"], case["installed_bundle"])
                paid = await asyncio.to_thread(_pay_generation, case, saved)
                held.append(paid[1])
                completed = await asyncio.to_thread(
                    _complete_generation, case, saved, paid)
                held.append(completed[2])
                _content, review = await asyncio.to_thread(
                    _prepare_review, case, saved, completed)
                review_paid = await asyncio.to_thread(_pay_review, case, review)
                held.append(review_paid[1])
                final_candidate = await asyncio.to_thread(
                    _complete_review_and_final, case, completed[0], review,
                    review_paid)
                final = await asyncio.to_thread(
                    _commit_final, case, final_candidate)
                held.append(final[1])
                db_path = case["store"]._db.execute(
                    "PRAGMA database_list").fetchone()[2]
                await _host_one_shot(
                    case, final, paid[7], outcome,
                    expected_promoted_c02=(
                        second_c02.operation_id if outcome == "accepted"
                        else None))
                with sqlite3.connect(db_path) as readback:
                    release_table = readback.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' "
                        "AND name='graph_d07_deferred_release_v2'"
                    ).fetchone()
                    if outcome == "accepted":
                        assert release_table == (1,)
                        assert readback.execute(
                            "SELECT deferred_c02_operation_id FROM "
                            "graph_d07_deferred_release_v2 "
                            "WHERE bot=? AND persona=?",
                            namespace.as_tuple,
                        ).fetchall() == [(second_c02.operation_id,)]
                    else:
                        assert release_table is None
                if after_release is not None:
                    await after_release(case, second_c02, decision, outcome)
            finally:
                for paid_lease in reversed(held):
                    await asyncio.to_thread(
                        graph.release_authority_lease, bootstrap, paid_lease)

    await real_owner_case(
        tmp_path, "owned", natural_workflow_builder=workflows,
        after_c02=after_c02)
