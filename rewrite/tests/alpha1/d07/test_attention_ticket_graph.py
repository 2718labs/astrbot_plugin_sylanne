"""D07 focus resolves a durable current ticket and source graph head."""

from dataclasses import replace
import time

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d07 import (
    AttentionTicket, D07DomainProvider, FocusState, attention_ticket_key,
    read_current_focus_attention_ticket,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (
    AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry,
)
from sylanne3.memory_types import SourceRecord, register_memory_types, source_key
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    SourceQualification, VersionGuard, canonical_digest,
)


def test_attention_ticket_and_focus_commit_and_current_read(tmp_path):
    namespace = NamespaceId("bot", "persona")
    source = source_key(*namespace.as_tuple, "source-1")
    focus_key = AtomKey(Owner("persona", *namespace.as_tuple),
                        "d07.focus.v1", namespace.persona_id)
    registry = TypeRegistry()
    register_memory_types(registry)
    provider = D07DomainProvider()
    for spec in provider.type_specs():
        if spec.name in {"d07.attention_ticket.v1", "d07.focus.v1"}:
            registry.register(spec)
    store = GraphStore(tmp_path / "d07-ticket.db", registry)
    try:
        record = SourceRecord(
            "source-1", "Hello", "user", "reported", "reported",
            1.0, 2.0, "root:message-1", ("user",), ("context",))
        empty = store.graph_snapshot((source,))
        seeded = store.graph_commit(GraphCandidate(
            Event(Scope(*namespace.as_tuple, "session"), "ingress", 2.0,
                  "source-operation", {}),
            (GraphVersion(source, 0),), (GraphWrite(source, record.to_dict()),),
            empty.epochs))
        assert seeded.status == "committed"
        snapshot = store.graph_snapshot((source, focus_key))
        ticket = AttentionTicket(
            "ticket-1", "question:source-1", None, source.token,
            "interaction", 0.8, 0.7, 0.4, 0.3, 0.2, 0.0, 0.1, 0.1, 0.0,
            1, 100.0, True, True, (), (source.token,))
        key = attention_ticket_key(namespace, ticket.ticket_id)
        focus = FocusState("persona", 1, key.token, (), "selected_by_bounded_attention")
        inputs = (source.token,)
        envelope = CommandEnvelope(
            "sylanne.runtime.v1",
            OperationIdentity("activity-1", None, "attempt-1", "focus",
                              "operation-1", canonical_digest({"input_refs": list(inputs)})),
            AuthorityContext("host:user", "d07", "cap:d07", namespace,
                             ("persona", "event"), "context", ("user",),
                             "policy:1", 1),
            VersionGuard((GraphVersion(source, 1), GraphVersion(focus_key, 0)),
                         (), 1, 0, "catalogue:1", "scheme:1", "operator:1",
                         "policy:1", (), (), ()),
            SourceQualification((source.token,), "reported", 1.0, 2.0,
                                "external_report", "qualified", 0.6,
                                "not_applicable"),
            inputs, "budget:1", 100.0, 50.0, "clock:1", ())
        proposal = provider.attention_focus_proposal(
            envelope, snapshot, ticket, focus, now=10.0)
        assert {write.key for write in proposal.typed_writes} == {key, focus_key}
        receipt = store.graph_commit(GraphCandidate(
            Event(Scope(*namespace.as_tuple, "session"), "focus", 10.0,
                  "focus-operation", {}),
            proposal.envelope.version_guard.read_versions,
            proposal.typed_writes, snapshot.epochs))
        assert receipt.status == "committed"
        current = store.graph_snapshot((source, focus_key, key))
        read = read_current_focus_attention_ticket(current, namespace, now=11.0)
        assert read is not None
        assert read.ticket == ticket
        assert read.focus.primary_ticket_ref == key.token
        assert read.ticket_version == GraphVersion(key, 1)
        assert read.source_versions == (GraphVersion(source, 1),)
        assert read_current_focus_attention_ticket(current, namespace, now=100.0) is None
        assert read_current_focus_attention_ticket(
            replace(current, atoms=tuple(atom for atom in current.atoms
                                         if atom.key != source)), namespace, now=11.0) is None
        tampered = replace(current, atoms=tuple(
            replace(atom, value={**atom.value, "causal_root": "other"})
            if atom.key == key else atom for atom in current.atoms))
        assert read_current_focus_attention_ticket(tampered, namespace, now=11.0) is None
        with pytest.raises(ValueError, match="identity differs"):
            provider.validate(replace(
                proposal, typed_writes=(
                    proposal.typed_writes[0],
                    GraphWrite(focus_key, {
                        **proposal.typed_writes[1].value,
                        "primary_ticket_ref": "caller-ticket-id",
                    }),
                )), snapshot)
    finally:
        store.close()
