from dataclasses import asdict, replace

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d03.context import ContextProvider, EntityAnchor
from sylanne3.domains.d07 import (
    CurrentInterpretationCandidate, D07DomainProvider, EvidenceStatus, Stance,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (
    GraphAtom, GraphCandidate, GraphSnapshot, GraphVersion, GraphWrite, TypeRegistry,
)
from sylanne3.memory_types import SourceRecord, access_key, register_memory_types, source_key
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    SourceQualification, VersionGuard, canonical_digest,
)
from sylanne3.graph_types import AtomKey, Owner


def _committed_source(tmp_path):
    source = source_key("bot", "persona", "source-1")
    access = access_key("bot", "persona", "source-1")
    perspective = AtomKey(Owner("persona", "bot", "persona"), "d03.entity_anchor", "entity:1")
    record = SourceRecord(
        "source-1", "The user said the appointment moved.", "user", "reported",
        "reported", 1.0, 2.0, "root:message-1", ("user",), ("context",),
    )
    anchor = EntityAnchor("entity:1", "person", "persona", (source.token,), "active")
    registry = TypeRegistry()
    register_memory_types(registry)
    registry.register(next(spec for spec in ContextProvider().type_specs()
                           if spec.name == "d03.entity_anchor"))
    registry.register(next(spec for spec in D07DomainProvider().type_specs()
                           if spec.name == "d07.current_interpretation.v1"))
    store = GraphStore(tmp_path / "source.db", registry)
    keys = (source, access, perspective)
    empty = store.graph_snapshot(keys)
    receipt = store.graph_commit(GraphCandidate(
        Event(Scope("bot", "persona", "session"), "seed", 1.0, "seed-source", {}),
        tuple(GraphVersion(key, 0) for key in keys),
        (
            GraphWrite(source, record.to_dict()),
            GraphWrite(access, {
                "source_id": record.source_id, "audiences": ["user"],
                "purposes": ["context"], "status": "active", "recorded_at": 2.0,
            }),
            GraphWrite(perspective, {
                **asdict(anchor), "creation_evidence_refs": list(anchor.creation_evidence_refs),
            }),
        ), empty.epochs,
    ))
    assert receipt.status == "committed"
    snapshot = store.graph_snapshot(keys)
    refs = (source.token, perspective.token)
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity-1", None, "attempt-1", "interpret", "operation-1",
                          canonical_digest({"input_refs": list(refs)})),
        AuthorityContext("host:user", "d07", "cap:d07", NamespaceId("bot", "persona"),
                         ("activity", "event", "persona"), "respond", ("user",), "policy:1", 1),
        VersionGuard(snapshot.versions, (), 1, 0, "catalogue:1", "scheme:1",
                     "operator:1", "policy:1", (), (), ()),
        SourceQualification((source.token,), "reported", 1.0, 2.0,
                            "external_report", "qualified", 0.6, "not_applicable"),
        refs, "budget:1", 10.0, 10.0, "clock:1", (),
    )
    interpretation = CurrentInterpretationCandidate(
        "caller-id-is-replaced", "activity-1", "question:appointment",
        "The appointment may have moved.", Stance.SUSPEND, 0.4,
        EvidenceStatus.INSUFFICIENT, (source.token,), (record.provenance_root,),
        ("appointment_time",),
    )
    return store, snapshot, envelope, interpretation, perspective


def test_first_source_interpretation_uses_committed_d06_and_d03_versions(tmp_path):
    store, snapshot, envelope, interpretation, perspective = _committed_source(tmp_path)
    try:
        provider = D07DomainProvider()
        proposal = provider.first_source_interpretation_proposal(
            envelope, snapshot, interpretation, perspective_ref=perspective.token,
        )
        replay = provider.first_source_interpretation_proposal(
            envelope, snapshot, interpretation, perspective_ref=perspective.token,
        )
        assert proposal == replay
        assert provider.validate(proposal, snapshot) == proposal
        assert proposal.dependencies.historical_provenance == (
            snapshot.versions[0], snapshot.versions[2],
        )
        write = proposal.typed_writes[0]
        assert write.value["source_refs"] == [snapshot.atoms[0].key.token]
        assert write.value["evidence_status"] == "insufficient"
        assert write.dependencies == ()
        assert GraphVersion(write.key, 0) in proposal.envelope.version_guard.read_versions
        receipt = store.graph_commit(GraphCandidate(
            Event(Scope("bot", "persona", "session"), "interpret", 2.0, "commit-interpret", {}),
            proposal.envelope.version_guard.read_versions,
            proposal.typed_writes, snapshot.epochs,
        ))
        assert receipt.status == "committed"
        assert store.graph_snapshot((write.key,)).get(write.key).value == write.value
    finally:
        store.close()


def test_first_source_interpretation_rejects_missing_or_changed_authority_reads(tmp_path):
    store, snapshot, envelope, interpretation, perspective = _committed_source(tmp_path)
    try:
        provider = D07DomainProvider()
        kwargs = {"perspective_ref": perspective.token}
        with pytest.raises(ValueError, match="matching committed guarded reads"):
            provider.first_source_interpretation_proposal(
                envelope, GraphSnapshot(snapshot.atoms[:2], snapshot.epochs),
                interpretation, **kwargs,
            )
        stale = GraphSnapshot((replace(snapshot.atoms[0], revision=2), *snapshot.atoms[1:]),
                              snapshot.epochs)
        with pytest.raises(ValueError, match="matching committed guarded reads"):
            provider.first_source_interpretation_proposal(envelope, stale, interpretation, **kwargs)
        withdrawn = GraphSnapshot((snapshot.atoms[0], replace(
            snapshot.atoms[1], value={**snapshot.atoms[1].value, "status": "withdrawn"},
        ), snapshot.atoms[2]), snapshot.epochs)
        with pytest.raises(ValueError, match="source access is not active"):
            provider.first_source_interpretation_proposal(
                envelope, withdrawn, interpretation, **kwargs,
            )
        wrong_family = replace(interpretation, source_families=("unrelated-root",))
        with pytest.raises(ValueError, match="qualification differs"):
            provider.first_source_interpretation_proposal(
                envelope, snapshot, wrong_family, **kwargs,
            )
        forged = provider.first_source_interpretation_proposal(
            envelope, snapshot, interpretation, **kwargs,
        )
        changed = replace(forged, typed_writes=(GraphWrite(
            forged.typed_writes[0].key,
            {**forged.typed_writes[0].value, "proposition": "This definitely happened."},
        ),))
        with pytest.raises(ValueError, match="key differs from committed evidence identity"):
            provider.validate(changed, snapshot)
    finally:
        store.close()
