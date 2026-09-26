"""A settled terminal C02 is the only source for reply preparation."""

from dataclasses import replace
import json

import pytest

from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_types import GraphAtom, GraphSnapshot
from sylanne3.domains.d07 import D07DomainProvider
from sylanne3.host.authority_profile import (
    AdminD06PrivateReplySourcePolicy, AdminD07AttentionPolicy,
    AdminInstallationBundle, AdminModelWorkflowV2, AdminModelWorkflowsV2,
    installed_model_config_ref,
)
from sylanne3.host.post_c02_attention_driver import (
    post_c02_attention_operation_id, prepare_post_c02_attention_v1,
)
from sylanne3.host.installed_reply_model_driver import reply_model_operation_id_v1
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.c02_bundle_codec import c02_bundle_from_wire
from sylanne3.runtime.reply_model_job import (
    ReplyModelJobHold, read_settled_c02_reply_source_v1,
    source_key_from_ref,
)
from sylanne3.runtime.first_ingress_v2 import trusted_upper
from sylanne3.runtime_contracts import AuthorityContext
from sylanne3.model_broker.reply_language import REPLY_TEMPLATE_VERSION

from test_first_ingress_c02_commit import c02_case
from test_first_ingress_c02_terminal_cost_v2 import _committed_case
import test_first_ingress_c02_commit


@pytest.fixture
def private_reply_c02_case(monkeypatch, request):
    """Use the real C02 fixture with explicit private reply ingress policy."""
    private_policy = AdminD06PrivateReplySourcePolicy(
        1, "private_conversation", True)
    original_scene = test_first_ingress_c02_commit._scene_case
    original_commit = GraphCoordinator.commit_first_ingress_v2

    def reply_scene(*args, **kwargs):
        kwargs["extra_work_kinds"] = tuple(
            kwargs.get("extra_work_kinds", ())) + ("reply", "d07.attention")
        kwargs["extra_specs"] = tuple(
            kwargs.get("extra_specs", ())) + D07DomainProvider().type_specs()
        return original_scene(*args, **kwargs)

    def reply_ingress(self, bootstrap, host, policy, clock, encoding,
                      reply_source_policy=None):
        return original_commit(
            self, bootstrap, host, policy, clock, encoding,
            private_policy if reply_source_policy is None else reply_source_policy)

    monkeypatch.setattr(test_first_ingress_c02_commit, "_scene_case", reply_scene)
    monkeypatch.setattr(GraphCoordinator, "commit_first_ingress_v2", reply_ingress)
    case = request.getfixturevalue("c02_case")
    d07 = D07DomainProvider()
    case[1].register_provider(
        case[2], "d07", d07, "d07.proposal.v1",
        d07.descriptor.request_schema_hash)
    return case


def _current_source_snapshot(store, coordinator, namespace, source_id):
    _, epoch = coordinator._v2_graph_stamp(namespace)
    atoms = []
    for key in (source_key(*namespace.as_tuple, source_id),
                access_key(*namespace.as_tuple, source_id)):
        row = store._db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (key.token,),
        ).fetchone()
        atoms.append(GraphAtom(key, row[0], json.loads(row[1]), bool(row[2])))
    return GraphSnapshot(tuple(atoms), (epoch,))


def test_settled_c02_current_source_read_requires_actual_cost(c02_case, monkeypatch):
    store, coordinator, namespace, original_intent, seal, pinned, duplicate = (
        _committed_case(c02_case, monkeypatch))
    bootstrap = c02_case[2]
    operation_id = seal.consumer_operation_id
    row = store._db.execute(
        "SELECT bundle_json FROM graph_first_ingress_c02_committed_seals_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    source_ref = c02_bundle_from_wire(row[0]).envelope.source_qualification.source_refs[0]
    source_id = source_key_from_ref(source_ref, namespace)
    snapshot = _current_source_snapshot(store, coordinator, namespace, source_id)
    receipt = replace(duplicate, status="committed")
    issuer = coordinator._GraphCoordinator__d02_issuer
    store._db.execute("BEGIN")
    try:
        with pytest.raises(ReplyModelJobHold, match="cost"):
            read_settled_c02_reply_source_v1(
                store._db, issuer, namespace, receipt, source_ref, snapshot)
    finally:
        store._db.rollback()
    coordinator._GraphCoordinator__original_c02_cost_intent_port = (
        lambda request: original_intent)
    coordinator.recover_committed_first_ingress_c02_unknown_cost_v2_pinned(
        bootstrap, namespace, operation_id, pinned)
    store._db.execute("BEGIN")
    try:
        with pytest.raises(ReplyModelJobHold, match="source, access"):
            read_settled_c02_reply_source_v1(
                store._db, issuer, namespace, receipt, source_ref, snapshot)
    finally:
        store._db.rollback()
    installed = AdminInstallationBundle(
        object(), c02_case[4], b"d11", b"d02", ingress_clock=c02_case[5])
    with pytest.raises(UnavailableGuard, match="differs from seal"):
        coordinator.read_post_c02_attention_inputs_v1(
            bootstrap, namespace, operation_id, "other-source", installed)
    with pytest.raises(ReplyModelJobHold, match="source, access"):
        coordinator.read_post_c02_attention_inputs_v1(
            bootstrap, namespace, operation_id, None, installed)
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_jobs WHERE work_kind='reply'"
    ).fetchone() == (0,)


def test_explicit_private_reply_source_can_be_read_after_settlement(
        private_reply_c02_case, monkeypatch):
    case = private_reply_c02_case
    store, coordinator, namespace, intent, seal, pinned, duplicate = (
        _committed_case(case, monkeypatch))
    coordinator._GraphCoordinator__original_c02_cost_intent_port = (
        lambda request: intent)
    coordinator.recover_committed_first_ingress_c02_unknown_cost_v2_pinned(
        case[2], namespace, seal.consumer_operation_id, pinned)
    installed = AdminInstallationBundle(
        object(), case[4], b"d11", b"d02", ingress_clock=case[5],
        d07_attention=AdminD07AttentionPolicy(
            300.0, {"cpu_ms": 1}, "attention-snapshot", "attention-resource"))
    receipt, snapshot, qualification, conversation_ref, guard, _, _ = (
        coordinator.read_post_c02_attention_inputs_v1(
            case[2], namespace, seal.consumer_operation_id, None, installed))
    assert receipt.operation_id == seal.consumer_operation_id
    assert qualification.source_refs and len(qualification.source_refs) == 1
    assert conversation_ref == "conversation"
    assert guard.read_versions == snapshot.versions


def test_private_reply_source_can_commit_durable_attention(
        private_reply_c02_case, monkeypatch):
    case = private_reply_c02_case
    store, graph, namespace, intent, seal, pinned, _ = (
        _committed_case(case, monkeypatch))
    graph._GraphCoordinator__original_c02_cost_intent_port = lambda request: intent
    graph.recover_committed_first_ingress_c02_unknown_cost_v2_pinned(
        case[2], namespace, seal.consumer_operation_id, pinned)
    installed = AdminInstallationBundle(
        object(), case[4], b"d11", b"d02", ingress_clock=case[5],
        d07_attention=AdminD07AttentionPolicy(
            300.0, {"cpu_ms": 1}, "attention-snapshot", "attention-resource"))
    c02, snapshot, qualification, audience, guard, anchor, clock = (
        graph.read_post_c02_attention_inputs_v1(
            case[2], namespace, seal.consumer_operation_id, None, installed))
    source_ref = qualification.source_refs[0]
    operation_id = post_c02_attention_operation_id(c02.operation_id, source_ref)
    lease, capability = graph.grant(
        case[2], actor=case[4].administrator_holder,
        issuer_domain="d11", namespace=namespace, domains=("d07",),
        activation_generation=anchor.activation_generation,
        operation_id=operation_id)
    try:
        authority = AuthorityContext(
            case[4].administrator_holder, "d11", capability, namespace,
            ("persona",), "expression", (audience,),
            case[4].root_grant.policy_ref, anchor.activation_generation)
        candidate = prepare_post_c02_attention_v1(
            c02_receipt=c02, source_ref=source_ref, snapshot=snapshot,
            qualification=qualification, authority=authority, guard=guard,
            parent_budget_lease_ref=case[4].root_grant.lease_id,
            conversation_ref=audience, now_utc=trusted_upper(clock),
            monotonic_deadline=clock.monotonic_after_seconds + 299.0,
            ticket_lifetime_seconds=299.0)
        receipt = graph.commit_post_c02_attention_v1(
            candidate.bundle, lease, installed)
        assert receipt.status == "committed"
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_atoms WHERE type_name='d07.attention_ticket.v1' "
            "AND valid=1"
        ).fetchone() == (1,)
    finally:
        graph.release_authority_lease(case[2], lease)


def _reply_workflows():
    config_digest = "a" * 64
    config_ref = installed_model_config_ref("provider", "model", config_digest)
    common = dict(
        provider_id="provider", model_id="model",
        provider_config_ref=config_ref,
        provider_config_digest=config_digest,
        audiences=("conversation",), privacy_tier="private",
        required_capabilities=("text",), timeout_seconds=10.0,
        max_output_tokens=8, quote_ceiling={"output_tokens": 16},
    )
    return AdminModelWorkflowsV2(
        2,
        AdminModelWorkflowV2(
            work_kind="d06.encode_source", purpose="consolidation",
            template_version="encode-fixture", **common),
        AdminModelWorkflowV2(
            work_kind="reply", purpose="proposal",
            template_version=REPLY_TEMPLATE_VERSION, **common),
    )


def test_settled_private_c02_attention_prepares_one_signed_reply_job(
        private_reply_c02_case, monkeypatch):
    case = private_reply_c02_case
    store, graph, namespace, intent, seal, pinned, _ = (
        _committed_case(case, monkeypatch))
    graph._GraphCoordinator__original_c02_cost_intent_port = lambda request: intent
    graph.recover_committed_first_ingress_c02_unknown_cost_v2_pinned(
        case[2], namespace, seal.consumer_operation_id, pinned)
    installed = AdminInstallationBundle(
        object(), case[4], b"d11", b"d02", ingress_clock=case[5],
        d07_attention=AdminD07AttentionPolicy(
            300.0, {"cpu_ms": 1}, "attention-snapshot", "attention-resource"),
        model_workflows=_reply_workflows())
    c02, snapshot, qualification, audience, guard, anchor, clock = (
        graph.read_post_c02_attention_inputs_v1(
            case[2], namespace, seal.consumer_operation_id, None, installed))
    source_ref = qualification.source_refs[0]
    operation_id = post_c02_attention_operation_id(c02.operation_id, source_ref)
    lease, capability = graph.grant(
        case[2], actor=case[4].administrator_holder,
        issuer_domain="d11", namespace=namespace, domains=("d07",),
        activation_generation=anchor.activation_generation,
        operation_id=operation_id)
    try:
        authority = AuthorityContext(
            case[4].administrator_holder, "d11", capability, namespace,
            ("persona",), "expression", (audience,),
            case[4].root_grant.policy_ref, anchor.activation_generation)
        candidate = prepare_post_c02_attention_v1(
            c02_receipt=c02, source_ref=source_ref, snapshot=snapshot,
            qualification=qualification, authority=authority, guard=guard,
            parent_budget_lease_ref=case[4].root_grant.lease_id,
            conversation_ref=audience, now_utc=trusted_upper(clock),
            monotonic_deadline=clock.monotonic_after_seconds + 299.0,
            ticket_lifetime_seconds=299.0)
        graph.commit_post_c02_attention_v1(candidate.bundle, lease, installed)
    finally:
        graph.release_authority_lease(case[2], lease)
    fence_port = graph._GraphCoordinator__content_fence_v2
    begin_fence = fence_port.begin_fence
    def interrupted_reply_begin(**kwargs):
        if kwargs["operation_id"].startswith("reply-job-write-"):
            raise RuntimeError("crash before Authority begin")
        return begin_fence(**kwargs)
    monkeypatch.setattr(fence_port, "begin_fence", interrupted_reply_begin)
    with pytest.raises(RuntimeError, match="crash before Authority begin"):
        graph.prepare_post_c02_reply_model_job_v1(
            case[2], namespace, seal.consumer_operation_id, source_ref,
            installed)
    original_attempt = store._db.execute(
        "SELECT attempt_id FROM graph_post_c02_reply_model_attempts_v1 "
        "WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()[0]
    monkeypatch.setattr(fence_port, "begin_fence", begin_fence)
    prepared = graph.prepare_post_c02_reply_model_job_v1(
        case[2], namespace, seal.consumer_operation_id, source_ref, installed)
    assert store._db.execute(
        "SELECT attempt_id FROM graph_post_c02_reply_model_attempts_v1 "
        "WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()[0] == original_attempt
    assert prepared.job.phase == "queued"
    assert prepared.quote.work_kind == "reply"
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_budget_reservations WHERE operation_id=?",
        (prepared.original_operation_id,),
    ).fetchone() == (1,)
    replay = graph.prepare_post_c02_reply_model_job_v1(
        case[2], namespace, seal.consumer_operation_id, source_ref, installed)
    assert replay == prepared
    acquire_operation_id = reply_model_operation_id_v1(
        seal.consumer_operation_id, source_ref)
    worker_lease, worker_capability = graph.grant(
        case[2], actor=case[4].administrator_holder,
        issuer_domain="d11", namespace=namespace, domains=("d11",),
        activation_generation=anchor.activation_generation,
        operation_id=acquire_operation_id)
    try:
        worker = AuthorityContext(
            case[4].administrator_holder, "d11", worker_capability,
            namespace, ("activity",), "proposal", (audience,),
            case[4].root_grant.policy_ref, anchor.activation_generation)
        acquired = graph.acquire_post_c02_reply_model_job_v1(
            worker, worker_lease, seal.consumer_operation_id, source_ref,
            installed, lease_seconds=30)
        assert acquired.phase == "running"
        assert acquired.fence > 0
        assert graph.acquire_post_c02_reply_model_job_v1(
            worker, worker_lease, seal.consumer_operation_id, source_ref,
            installed, lease_seconds=30) == acquired
        frozen = graph.read_post_c02_reply_model_egress_preparation_v1(
            replace(worker, worker_fence=acquired.fence), worker_lease,
            seal.consumer_operation_id, source_ref, installed)
        assert frozen[0].operation_id == seal.consumer_operation_id
        assert frozen[5].job_id == acquired.job_id
    finally:
        graph.release_authority_lease(case[2], worker_lease)
