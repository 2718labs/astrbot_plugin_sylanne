from dataclasses import replace

import pytest

from sylanne3.domains.d07 import D07DomainProvider
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, Owner
from sylanne3.memory_types import (
    InterpretationRecord, SourceRecord, access_key, interpretation_key, source_key,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    SourceQualification, VersionGuard, canonical_digest,
)


def _case():
    source = source_key("bot", "persona", "source-1")
    access = access_key("bot", "persona", "source-1")
    target = interpretation_key("bot", "persona", "interpretation-1")
    belief = AtomKey(Owner("persona", "bot", "persona"),
                     "d07.belief_revision.v1", "belief-1")
    correction = source_key("bot", "persona", "correction-1")
    record = SourceRecord("source-1", "Original claim", "user", "reported",
                          "reported", 1.0, 2.0, "root-1", ("user",), ("context",))
    interpretation = InterpretationRecord("interpretation-1", ("source-1",),
                                           "subject-1", "Original claim", "reported", 1.0, 2.0)
    belief_value = {
        "schema": "d07.belief_revision.v1", "belief_id": "belief-1",
        "question_key": "question-1", "hypothesis_ref": "hypothesis-1",
        "proposition": "Original claim", "stance": "support",
        "subjective_conviction": 0.6, "evidence_status": "insufficient",
        "eligibility": ["subjective_reaction"],
        "source_refs": [source.token, target.token], "source_families": ["root-1"],
        "current": True, "historical": True, "replaced_by": None,
        "invalidation_refs": [], "invalidation_kind": None,
    }
    atoms = (
        GraphAtom(source, 1, record.to_dict()),
        GraphAtom(access, 1, {
            "source_id": "source-1", "audiences": ["user"],
            "purposes": ["context"], "status": "active", "recorded_at": 2.0,
        }),
        GraphAtom(target, 1, interpretation.to_dict()),
        GraphAtom(belief, 1, belief_value),
    )
    snapshot = GraphSnapshot(atoms, ())
    inputs = (correction.token, source.token, target.token, belief.token)
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity-1", None, "attempt-1", "correction", "operation-1",
                          canonical_digest({"input_refs": list(inputs)})),
        AuthorityContext("host:user", "d11", "cap:correction", NamespaceId("bot", "persona"),
                         ("event", "persona"), "context", ("user",), "policy:1", 1),
        VersionGuard((*snapshot.versions, GraphVersion(correction, 0)), (), 1, 0,
                     "catalogue:1", "scheme:1", "operator:1", "policy:1", (), (), ()),
        SourceQualification((source.token,), "reported", 1.0, 2.0,
                            "external_report", "qualified", 0.6, "not_applicable"),
        inputs, "budget:1", 10.0, 10.0, "clock:1", (),
    )
    kwargs = dict(belief_refs=(belief.token,), correction_source_ref=correction.token,
                  source_refs=(source.token,), target_refs=(target.token,))
    return snapshot, envelope, kwargs, (source, access, target, belief, correction)


def test_correction_retracts_belief_with_exact_current_edges():
    snapshot, envelope, kwargs, (source, access, target, belief, correction) = _case()
    provider = D07DomainProvider()
    proposal = provider.source_correction_belief_proposal(envelope, snapshot, **kwargs)
    assert provider.source_correction_belief_proposal(envelope, snapshot, **kwargs) == proposal
    write, = proposal.typed_writes
    assert write.key == belief
    assert write.value["current"] is False
    assert write.value["historical"] is True
    assert write.value["invalidation_refs"] == [correction.token, target.token]
    assert write.dependencies == (target, correction)
    assert proposal.dependencies.current_invalidation == (
        GraphVersion(target, 1), GraphVersion(correction, 0),
    )
    assert proposal.dependencies.historical_provenance == (
        GraphVersion(source, 1), GraphVersion(access, 1),
    )


@pytest.mark.parametrize("changed, expected", [
    ("stale_belief", "current guarded graph reads"),
    ("stale_access", "current guarded graph reads"),
    ("withdrawn_access", "current source access"),
    ("unrelated_target", "current dependent interpretation"),
    ("replayed_correction", "absent, guarded new source"),
    ("missing_qualification", "source qualification"),
])
def test_correction_rejects_unbound_or_stale_reads(changed, expected):
    snapshot, envelope, kwargs, (source, access, target, belief, correction) = _case()
    atoms = list(snapshot.atoms)
    if changed == "stale_belief":
        atoms[3] = replace(atoms[3], revision=2)
    elif changed == "stale_access":
        atoms[1] = replace(atoms[1], revision=2)
    elif changed == "withdrawn_access":
        atoms[1] = replace(atoms[1], value={**atoms[1].value, "status": "withdrawn"})
    elif changed == "unrelated_target":
        atoms[2] = replace(atoms[2], value={**atoms[2].value, "source_ids": ["other"]})
    elif changed == "replayed_correction":
        atoms.append(GraphAtom(correction, 1, atoms[0].value))
    elif changed == "missing_qualification":
        envelope = replace(envelope, source_qualification=replace(
            envelope.source_qualification, source_refs=("another-source",),
        ))
    with pytest.raises(ValueError, match=expected):
        D07DomainProvider().source_correction_belief_proposal(
            envelope, GraphSnapshot(tuple(atoms), ()), **kwargs,
        )


def test_correction_rejects_cross_namespace_reference():
    snapshot, envelope, kwargs, _ = _case()
    kwargs["belief_refs"] = (AtomKey(
        Owner("persona", "other-bot", "persona"), "d07.belief_revision.v1", "belief-1",
    ).token,)
    with pytest.raises(ValueError, match="namespace"):
        D07DomainProvider().source_correction_belief_proposal(envelope, snapshot, **kwargs)
