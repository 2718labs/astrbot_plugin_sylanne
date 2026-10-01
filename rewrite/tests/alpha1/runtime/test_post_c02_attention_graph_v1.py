"""A settled private C02 can durably select D07 attention under V2 fence."""

from sylanne3.host.authority_profile import (
    AdminD07AttentionPolicy, AdminInstallationBundle,
)
from sylanne3.host.post_c02_attention_driver import (
    post_c02_attention_operation_id, prepare_post_c02_attention_v1,
)
from sylanne3.runtime.first_ingress_v2 import trusted_upper
from sylanne3.runtime.d07_current_competitor_v2 import (
    read_current_primary_competitor_in_transaction,
)
from sylanne3.runtime_contracts import AuthorityContext

from test_first_ingress_c02_terminal_cost_v2 import _committed_case
from test_first_ingress_c02_commit import c02_case
from test_post_c02_reply_model_job_v1 import private_reply_c02_case


def test_settled_private_c02_commits_one_ticket_and_focus(
        private_reply_c02_case, monkeypatch):
    case = private_reply_c02_case
    store, graph, namespace, intent, seal, pinned, _ = _committed_case(
        case, monkeypatch)
    graph._GraphCoordinator__original_c02_cost_intent_port = lambda request: intent
    graph.recover_committed_first_ingress_c02_unknown_cost_v2_pinned(
        case[2], namespace, seal.consumer_operation_id, pinned)
    attention_policy = AdminD07AttentionPolicy(
        30.0, {"cpu_ms": 1}, "attention-snapshot", "attention-resource")
    installed = AdminInstallationBundle(
        object(), case[4], b"d11", b"d02", ingress_clock=case[5],
        d07_attention=attention_policy)
    c02, snapshot, qualification, conversation, guard, anchor, clock, policy, competitor = (
        graph.read_post_c02_attention_inputs_v1(
            case[2], namespace, seal.consumer_operation_id, None, installed))
    assert competitor is None
    source_ref = qualification.source_refs[0]
    operation_id = post_c02_attention_operation_id(c02.operation_id, source_ref)
    actor = graph._GraphCoordinator__content_fence_v2.installation_grant.subject
    lease, capability = graph.grant(
        case[2], actor=actor, issuer_domain="d11", namespace=namespace,
        domains=("d07",), activation_generation=anchor.activation_generation,
        operation_id=operation_id)
    try:
        authority = AuthorityContext(
            actor, "d11", capability, namespace, ("persona",),
            "expression", (conversation,), case[4].root_grant.policy_ref,
            anchor.activation_generation)
        candidate = prepare_post_c02_attention_v1(
            c02_receipt=c02, source_ref=source_ref, snapshot=snapshot,
            qualification=qualification, authority=authority, guard=guard,
            parent_budget_lease_ref=case[4].root_grant.lease_id,
            conversation_ref=conversation, now_utc=trusted_upper(clock),
            monotonic_deadline=clock.monotonic_after_seconds + 30.0,
            ticket_lifetime_seconds=27.0,
            current_policy=policy.policy,
            active_head_ref=policy.active_head_ref)
        first = graph.commit_post_c02_attention_v1(candidate.bundle, lease, installed)
        second = graph.commit_post_c02_attention_v1(candidate.bundle, lease, installed)
    finally:
        graph.release_authority_lease(case[2], lease)
    assert first.status == "committed"
    assert second.operation_id == first.operation_id
    decision = graph.read_post_c02_attention_decision_v2(
        case[2], namespace, c02.operation_id, installed)
    assert decision is not None
    assert decision.attention_operation_id == first.operation_id
    assert decision.inbound_ticket_ref == decision.selected_ticket_ref
    assert decision.inbound_deferred is False
    assert decision.wake_at is None
    assert {version.key.type_name for version in first.write_versions} == {
        "d07.attention_ticket.v1", "d07.focus.v1"}
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_bundle_operations WHERE bot=? AND persona=? "
        "AND operation_id=?", namespace.as_tuple + (operation_id,),
    ).fetchone() == (1,)
    focus_ref = next(version.key for version in first.write_versions
                     if version.key.type_name == "d07.focus.v1")
    focus_value = store._db.execute(
        "SELECT value FROM graph_atoms WHERE token=?", (focus_ref.token,),
    ).fetchone()[0]
    import json
    store._db.execute("BEGIN")
    try:
        competing = read_current_primary_competitor_in_transaction(
            store._db, namespace,
            json.loads(focus_value)["primary_ticket_ref"],
            now_utc=trusted_upper(clock),
        )
    finally:
        store._db.execute("ROLLBACK")
    assert competing.ticket.ticket_id == candidate.ticket.ticket_id
    assert competing.c02_operation_id == c02.operation_id
    assert competing.audience == conversation
    assert {item.key.type_name for item in competing.read_versions} >= {
        "d07.attention_ticket.v1", "memory.source", "memory.access",
        "d06.source_correction_head.v1",
    }
    _, current_snapshot, _, _, current_guard, _, _, _, current_competitor = (
        graph.read_post_c02_attention_inputs_v1(
            case[2], namespace, seal.consumer_operation_id, None, installed))
    assert current_competitor == competing
    assert set(current_competitor.read_versions) <= set(current_snapshot.versions)
    assert set(current_competitor.read_versions) <= set(current_guard.read_versions)
