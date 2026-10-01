"""A current focus is usable only with the whole authorized source closure."""

from dataclasses import asdict, replace

import pytest

from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.domains.d07 import (
    AttentionTicket, D07DomainProvider, FocusState, attention_ticket_key,
)
from sylanne3.domains.d07.qualified_attention_read import (
    read_qualified_focus_attention_ticket,
)
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner,
)
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    SourceQualification, VersionGuard, canonical_digest,
)


NAMESPACE = NamespaceId("bot", "persona")


def _source_atoms(source_id: str, *, parents=()):
    record = SourceRecord(
        source_id, "remembered account", "speaker", "reported", "reported",
        1.0, 2.0, "family:one", ("persona",), ("context",), parents,
    )
    source = source_key(*NAMESPACE.as_tuple, source_id)
    access = access_key(*NAMESPACE.as_tuple, source_id)
    head = source_correction_head_key(NAMESPACE, source_id)
    return (
        GraphAtom(source, 1, record.to_dict()),
        GraphAtom(access, 1, {
            "source_id": source_id, "audiences": ["persona"],
            "purposes": ["context"], "status": "active", "recorded_at": 2.0,
        }),
        GraphAtom(head, 0, {}, False),
    )


def _snapshot(*, parents=()):
    source = source_key(*NAMESPACE.as_tuple, "selected")
    ticket = AttentionTicket(
        "ticket-1", "question:one", None, source.token, "interaction",
        0.8, 0.7, 0.4, 0.3, 0.2, 0.0, 0.1, 0.1, 0.0,
        1, 100.0, True, True, (), (source.token,),
    )
    ticket_key = attention_ticket_key(NAMESPACE, ticket.ticket_id)
    focus = FocusState("persona", 1, ticket_key.token, (), "chosen")
    focus_key = AtomKey(Owner("persona", *NAMESPACE.as_tuple),
                        "d07.focus.v1", NAMESPACE.persona_id)
    ticket_value = asdict(ticket)
    ticket_value.update(schema="d07.attention_ticket.v1", cancel_refs=[],
                        source_refs=[source.token])
    focus_value = asdict(focus)
    focus_value.update(schema="d07.focus.v1", auxiliary_ticket_refs=[])
    atoms = [GraphAtom(focus_key, 1, focus_value),
             GraphAtom(ticket_key, 1, ticket_value)]
    atoms.extend(_source_atoms("selected", parents=parents))
    for parent in parents:
        atoms.extend(_source_atoms(parent))
    return GraphSnapshot(tuple(atoms), (NamespaceEpoch(*NAMESPACE.as_tuple, 1),))


def _read(snapshot):
    return read_qualified_focus_attention_ticket(
        snapshot, NAMESPACE, now=10.0, audience="persona", purpose="context",
    )


def _change(snapshot, key, **changes):
    return replace(snapshot, atoms=tuple(
        replace(atom, **changes) if atom.key == key else atom
        for atom in snapshot.atoms
    ))


def test_selected_source_and_ancestors_have_complete_guarded_access():
    snapshot = _snapshot(parents=("ancestor",))
    result = _read(snapshot)
    assert result is not None
    assert result.status == "candidate_requires_current_fence_and_final_admission"
    assert {record.source_id for record in result.source_records} == {"selected", "ancestor"}
    assert len(result.read_versions) == 8  # focus, ticket and three keys per source
    assert {version.key.type_name for version in result.read_versions} == {
        "d07.focus.v1", "d07.attention_ticket.v1", "memory.source",
        "memory.access", "d06.source_correction_head.v1",
    }


def test_missing_revoked_corrected_or_disputed_ancestor_fails_closed():
    snapshot = _snapshot(parents=("ancestor",))
    access = access_key(*NAMESPACE.as_tuple, "ancestor")
    head = source_correction_head_key(NAMESPACE, "ancestor")
    source = source_key(*NAMESPACE.as_tuple, "ancestor")
    assert _read(replace(snapshot, atoms=tuple(
        atom for atom in snapshot.atoms if atom.key != access))) is None
    old = snapshot.get(access)
    assert _read(_change(snapshot, access, value={**old.value, "status": "withdrawn"})) is None
    assert _read(_change(snapshot, head, revision=1, valid=True)) is None
    old = snapshot.get(source)
    assert _read(_change(snapshot, source, value={
        **old.value, "assertion_status": "disputed",
    })) is None
    selected = source_key(*NAMESPACE.as_tuple, "selected")
    old_selected = snapshot.get(selected)
    assert _read(_change(snapshot, selected, value={
        **old_selected.value, "parent_source_ids": ["selected"],
    })) is None
    assert _read(replace(snapshot, epochs=(NamespaceEpoch("bot", "other", 1),))) is None
    assert read_qualified_focus_attention_ticket(
        snapshot, NAMESPACE, now=10.0, audience="other", purpose="context",
    ) is None


def test_old_primary_can_win_only_with_its_guarded_source_closure():
    old = _snapshot(parents=("ancestor",))
    new_source = source_key(*NAMESPACE.as_tuple, "inbound")
    new_ticket = AttentionTicket(
        "ticket-2", "question:two", None, new_source.token,
        "interaction", 0.4, 0.4, 0.4, 0.3, 0.0, 0.0, 0.0, 0.0, 0.0,
        2, 100.0, True, True, (), (new_source.token,),
    )
    new_key = attention_ticket_key(NAMESPACE, new_ticket.ticket_id)
    old_key = attention_ticket_key(NAMESPACE, "ticket-1")
    snapshot = replace(old, atoms=old.atoms + _source_atoms("inbound") + (
        GraphAtom(new_key, 0, {}, False),
    ))
    inputs = (new_source.token,)
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity-2", None, "attempt-2", "focus",
                          "operation-2", canonical_digest({"input_refs": list(inputs)})),
        AuthorityContext("host:user", "d07", "cap:d07", NAMESPACE,
                         ("persona", "event"), "context", ("persona",),
                         "policy:1", 1),
        VersionGuard(snapshot.versions, (), 1, 0, "catalogue:1", "scheme:1",
                     "operator:1", "policy:1", (), (), ()),
        SourceQualification(inputs, "reported", 1.0, 2.0,
                            "external_report", "qualified", 0.6,
                            "not_applicable"),
        inputs, "budget:1", 100.0, 50.0, "clock:1", (),
    )
    focus = FocusState("persona", 2, old_key.token, (new_key.token,),
                       "deferred_for_current_primary")
    provider = D07DomainProvider()
    proposal = provider.attention_focus_proposal(
        envelope, snapshot, new_ticket, focus, now=10.0)
    assert len(proposal.typed_writes) == 2

    old_access = access_key(*NAMESPACE.as_tuple, "ancestor")
    with pytest.raises(ValueError, match="qualified current graph closure"):
        provider.attention_focus_proposal(
            envelope, _change(snapshot, old_access,
                              value={**snapshot.get(old_access).value,
                                     "status": "withdrawn"}),
            new_ticket, focus, now=10.0)
    without_old_guard = replace(envelope, version_guard=replace(
        envelope.version_guard,
        read_versions=tuple(ref for ref in envelope.version_guard.read_versions
                            if ref != GraphVersion(old_access, 1))))
    with pytest.raises(ValueError, match="qualified current graph closure"):
        provider.attention_focus_proposal(
            without_old_guard, snapshot, new_ticket, focus, now=10.0)
