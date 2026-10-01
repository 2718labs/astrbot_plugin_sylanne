"""The pre-model D07 proposal is source-bound and writes a durable ticket."""

from dataclasses import asdict, replace

import pytest

from sylanne3.domains.d07 import AttentionPolicy, D07DomainProvider, attention_ticket_key
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.domains.d12.types import active_scheme_head_key
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner,
)
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.host.post_c02_attention_driver import (
    post_c02_attention_operation_id, prepare_post_c02_attention_v1,
)
from sylanne3.runtime.reply_model_job import d07_attention_quote_id_v1
from sylanne3.runtime.d07_current_competitor_v2 import D07CurrentCompetingTicketV2
from sylanne3.runtime_contracts import (
    AuthorityContext, CommitReceipt, NamespaceId, QueryEpoch,
    SourceQualification, VersionGuard, canonical_digest,
)


def _case():
    namespace = NamespaceId("bot", "persona")
    source = source_key(*namespace.as_tuple, "source-1")
    access = access_key(*namespace.as_tuple, "source-1")
    focus = AtomKey(Owner("persona", *namespace.as_tuple),
                    "d07.focus.v1", namespace.persona_id)
    episode = AtomKey(Owner("activity", *namespace.as_tuple, "activity-1"),
                      "memory.episode.v1", "episode-1")
    trace = AtomKey(Owner("activity", *namespace.as_tuple, "activity-1"),
                    "memory.subjective_trace.v2", "trace-1")
    c02 = CommitReceipt(
        "committed", "c02-1", canonical_digest({"c02": 1}), "activity-1",
        None, 3, (), (GraphVersion(episode, 1), GraphVersion(trace, 1)),
        (NamespaceEpoch(*namespace.as_tuple, 2),), (), (),
    )
    snapshot = GraphSnapshot((
        GraphAtom(source, 1, {"source_id": "source-1"}),
        GraphAtom(access, 1, {"status": "active", "purposes": ["expression"],
                              "audiences": ["private-conversation"]}),
        GraphAtom(focus, 0, {}, False),
    ), (NamespaceEpoch(*namespace.as_tuple, 3),))
    guard = VersionGuard(
        snapshot.versions, (QueryEpoch(namespace, "all", 3),), 0, 0,
        "catalogue:1", "scheme:1", "operator:1", "policy:1", (), (), (),
    )
    qualification = SourceQualification(
        (source.token,), "reported", 1.0, 2.0, "external_report",
        "qualified", 0.6, "not_applicable")
    authority = AuthorityContext(
        "host", "d11", "cap:d07", namespace, ("event", "persona"),
        "expression", ("private-conversation",), "policy:1", 1)
    return dict(c02_receipt=c02, source_ref=source.token, snapshot=snapshot,
                qualification=qualification, authority=authority, guard=guard,
                parent_budget_lease_ref="budget-1",
                conversation_ref="private-conversation", now_utc=10.0,
                monotonic_deadline=100.0)


def test_pre_model_attention_writes_source_bound_ticket_and_focus():
    case = _case()
    result = prepare_post_c02_attention_v1(**case)
    namespace = case["authority"].namespace
    key = attention_ticket_key(namespace, result.ticket.ticket_id)
    writes = {write.key: write for write in result.bundle.proposals[0].typed_writes}
    assert set(writes) == {key, AtomKey(Owner("persona", *namespace.as_tuple),
                                         "d07.focus.v1", namespace.persona_id)}
    assert result.ticket.source_refs == (case["source_ref"],)
    assert result.focus.primary_ticket_ref == key.token
    assert result.bundle.envelope.identity.operation_id == post_c02_attention_operation_id(
        "c02-1", case["source_ref"])
    assert GraphVersion(key, 0) in result.bundle.envelope.version_guard.read_versions
    assert result.bundle.envelope.version_guard.resource_lease_versions[0].ref == (
        d07_attention_quote_id_v1(namespace, result.bundle.envelope.identity.operation_id))


def test_pre_model_attention_rejects_revoked_current_access():
    case = _case()
    snapshot = case["snapshot"]
    case["snapshot"] = replace(snapshot, atoms=tuple(
        replace(atom, value={**atom.value, "status": "revoked"})
        if atom.key.type_name == "memory.access" else atom
        for atom in snapshot.atoms))
    with pytest.raises(ValueError, match="current source"):
        prepare_post_c02_attention_v1(**case)


def test_pre_model_attention_defers_inbound_behind_current_ticket():
    case = _case()
    baseline = prepare_post_c02_attention_v1(**case)
    namespace = case["authority"].namespace
    old = replace(baseline.ticket, ticket_id="old-ticket", urgency=1.0,
                  information_value=1.0, persona_salience=1.0,
                  enqueued_seq=1)
    old_key = attention_ticket_key(namespace, old.ticket_id)
    old_value = asdict(old)
    old_value["cancel_refs"] = list(old.cancel_refs)
    old_value["source_refs"] = list(old.source_refs)
    old_value["schema"] = "d07.attention_ticket.v1"
    old_atom = GraphAtom(old_key, 1, old_value)
    source = source_key(*namespace.as_tuple, "source-1")
    record = SourceRecord(
        "source-1", "prior private report", "speaker", "reported", "reported",
        1.0, 2.0, "family:one", ("private-conversation",), ("expression",), (),
    )
    qualified_source = GraphAtom(source, 1, record.to_dict())
    access = access_key(*namespace.as_tuple, "source-1")
    qualified_access = GraphAtom(access, 1, {
        "source_id": "source-1", "audiences": ["private-conversation"],
        "purposes": ["expression"], "status": "active", "recorded_at": 2.0,
    })
    correction = GraphAtom(
        source_correction_head_key(namespace, "source-1"), 0, {}, False)
    focus = next(atom for atom in case["snapshot"].atoms
                 if atom.key.type_name == "d07.focus.v1")
    current_focus = GraphAtom(focus.key, 1, {
        "schema": "d07.focus.v1",
        "persona_id": namespace.persona_id, "focus_epoch": 1,
        "primary_ticket_ref": old_key.token,
        "auxiliary_ticket_refs": [], "switch_reason": "selected_by_bounded_attention",
    })
    snapshot = replace(case["snapshot"], atoms=tuple(
        current_focus if atom.key == focus.key else
        qualified_source if atom.key == source else
        qualified_access if atom.key == access else atom
        for atom in case["snapshot"].atoms) + (old_atom, correction))
    case["snapshot"] = snapshot
    case["guard"] = replace(case["guard"], read_versions=snapshot.versions)
    competitor = D07CurrentCompetingTicketV2(
        old, GraphVersion(old_key, 1), "old-c02", "private-conversation",
        (old_atom,))
    result = prepare_post_c02_attention_v1(
        **case, current_competitor=competitor)
    assert result.inbound_deferred
    assert result.selected_ticket_id == old.ticket_id
    assert result.focus.primary_ticket_ref == old_key.token
    assert result.focus.auxiliary_ticket_refs == (
        attention_ticket_key(namespace, result.ticket.ticket_id).token,)
    assert result.wake_at == old.valid_until


def test_pre_model_attention_consumes_current_adopted_policy(monkeypatch):
    case = _case()
    namespace = case["authority"].namespace
    head = active_scheme_head_key(namespace)
    snapshot = case["snapshot"]
    case["snapshot"] = replace(snapshot, atoms=(
        *snapshot.atoms, GraphAtom(head, 2, {"generation": 2})))
    case["guard"] = replace(case["guard"],
                            read_versions=case["snapshot"].versions)
    baseline = AttentionPolicy.default()
    adopted = replace(baseline, relevance_weight=baseline.relevance_weight + 0.03,
                      urgency_weight=baseline.urgency_weight - 0.03)
    seen = []
    original = D07DomainProvider.rank_attention

    def capture(tickets, policy, *, now):
        seen.append(policy)
        return original(tickets, policy, now=now)

    monkeypatch.setattr(D07DomainProvider, "rank_attention", staticmethod(capture))
    prepare_post_c02_attention_v1(
        **case, current_policy=adopted, active_head_ref=GraphVersion(head, 2))
    assert seen == [adopted]
    with pytest.raises(ValueError, match="graph read version"):
        prepare_post_c02_attention_v1(
            **case, current_policy=adopted, active_head_ref=GraphVersion(head, 1))
