"""The pre-model D07 proposal is source-bound and writes a durable ticket."""

from dataclasses import replace

import pytest

from sylanne3.domains.d07 import attention_ticket_key
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner,
)
from sylanne3.memory_types import access_key, source_key
from sylanne3.host.post_c02_attention_driver import (
    post_c02_attention_operation_id, prepare_post_c02_attention_v1,
)
from sylanne3.runtime.reply_model_job import d07_attention_quote_id_v1
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
