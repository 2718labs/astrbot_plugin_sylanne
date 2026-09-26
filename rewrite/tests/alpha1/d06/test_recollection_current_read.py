"""A D06 sidecar can only be read against current C04 and source heads."""

from dataclasses import asdict, fields, replace

import pytest

from sylanne3.domains.d04 import AffectAxis, AffectScheme, MoodField
from sylanne3.domains.d04.affect import RecollectionExperience
from sylanne3.domains.d06 import (
    CandidateItem, CandidateSet, D06DomainAdapter, RecollectionContext,
    RecollectionProjectionUnavailable, SelectionTicket,
    inspect_recollection_projection_snapshot,
)
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import CommitReceipt, NamespaceId


NAMESPACE = NamespaceId("bot", "persona")
SOURCE = source_key("bot", "persona", "source-1")
ACCESS = access_key("bot", "persona", "source-1")
MOOD = AtomKey(Owner("persona", "bot", "persona"), "d04.mood_field.v1", "current")
EXPERIENCE = AtomKey(Owner("activity", "bot", "persona", "activity-1"),
                     "d04.recollection_experience.v1", "experience-1")
PROJECTION = AtomKey(Owner("activity", "bot", "persona", "activity-1"),
                     "d06.recollection_projection.v1", "projection-1")
SCHEME = AffectScheme("d04.affect.scheme.v1", "scheme-1", "operator-1",
                      "parameter-1", "coupling-1",
                      (AffectAxis("care", "normalized", "care"),), ())


def json_value(value):
    if isinstance(value, tuple):
        return [json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: json_value(item) for key, item in value.items()}
    return value


def fixture(*, tone=(-0.2, 0.1), mood_revision=1):
    source = SourceRecord("source-1", "private source literal", "alice",
                          "observed", "confirmed", 1.0, 2.0, "family-1",
                          ("owner",), ("context",))
    access = {"source_id": "source-1", "audiences": ["owner"],
              "purposes": ["context"], "status": "active", "recorded_at": 2.0}
    mood = MoodField("mood-1", "scheme-1", (("care", 0.6),),
                     (SOURCE.token,), "parameter-1", "coupling-1", 2.0)
    adapter = D06DomainAdapter(NAMESPACE)
    candidates = CandidateSet("set-1", (
        CandidateItem("candidate-1", "source-1", "family-1", "association",
                      ("context",), 0.8, "observed"),
    ), "complete")
    ticket = SelectionTicket("ticket-1", "activity-1", "set-1", ("candidate-1",), 1)
    recollection = adapter.prepare_recollection(
        ticket, candidates, RecollectionContext(("interpretation-1",),
                                                (EXPERIENCE.token,), ()),
    )
    recollection_write = adapter.recollection_write(
        recollection, candidate_set_id="set-1", focus_epoch=1,
        access_epoch=0, delete_epoch=0,
    )
    experience = RecollectionExperience(
        "experience-1", "activity-1", recollection_write.key.token,
        SOURCE.token, (SOURCE.token,), "mood-1", (SOURCE.token,),
        (0.2, 0.4), tone, "coupling-1", "coupling-1",
    )
    projection = {
        "projection_id": "projection-1", "activity_id": "activity-1",
        "recollection_ref": recollection_write.key.token,
        "experience_ref": EXPERIENCE.token, "source_ref": SOURCE.token,
        "source_revision": 1, "mood_ref": MOOD.token,
        "mood_revision": mood_revision, "coupling_version": "coupling-1",
        "projection_version": "d06.affective_projection.v1",
        "state": "committed_subjective_projection",
        "evidence_eligibility": "subjective_only", "details": [],
        "subjective_weight": [0.2, 0.4], "subjective_tone": list(tone),
        "duration_interval": None, "encoding_trace_ref": None,
        "baseline_status": "not_read",
    }
    atoms = (
        GraphAtom(SOURCE, 1, source.to_dict()),
        GraphAtom(ACCESS, 1, access),
        GraphAtom(MOOD, mood_revision, {**asdict(mood),
                                        "coordinates": [["care", 0.6]],
                                        "source_refs": [SOURCE.token]}),
        GraphAtom(recollection_write.key, 1, recollection_write.value),
        GraphAtom(EXPERIENCE, 1, json_value(asdict(experience))),
        GraphAtom(PROJECTION, 1, projection),
    )
    epoch = NamespaceEpoch("bot", "persona", 4)
    snapshot = GraphSnapshot(atoms, (epoch,))
    receipt = CommitReceipt(
        "committed", "operation-1", "0" * 64, "activity-1", None, 1,
        (), (GraphVersion(recollection_write.key, 1),
             GraphVersion(EXPERIENCE, 1), GraphVersion(PROJECTION, 1)),
        (epoch,), (recollection_write.key.token,), ("outbox-1",),
    )
    return snapshot, receipt


def inspect(snapshot, receipt):
    return inspect_recollection_projection_snapshot(
        snapshot, namespace=NAMESPACE, audience=("owner",), purpose="context",
        projection_ref=PROJECTION.token, receipt=receipt, scheme=SCHEME,
    )


def changed(snapshot, key, **changes):
    return replace(snapshot, atoms=tuple(
        replace(atom, value={**atom.value, **changes}) if atom.key == key else atom
        for atom in snapshot.atoms
    ))


def test_current_projection_exposes_subjective_feeling_without_source_literal():
    snapshot, receipt = fixture()
    current = inspect(snapshot, receipt)
    assert current.subjective_tone == current.experience.tone_interval == (-0.2, 0.1)
    assert current.source_kind == "observed"
    assert current.read_status == "hold_uncertified_c02_baseline"
    assert current.encoding_baseline_certified is False
    assert set(current.read_versions) == set(snapshot.versions)
    assert "source_text" not in {field.name for field in fields(current)}
    assert "private source literal" not in repr(current)


def test_old_receipt_and_revoked_access_cannot_read_projection():
    snapshot, receipt = fixture()
    old = replace(receipt, write_versions=receipt.write_versions[:-1])
    with pytest.raises(RecollectionProjectionUnavailable, match="receipt does not own"):
        inspect(snapshot, old)
    with pytest.raises(RecollectionProjectionUnavailable, match="access_denied"):
        inspect(changed(snapshot, ACCESS, status="withdrawn"), receipt)


def test_changed_mood_requires_new_sidecar_and_distinguishes_current_feeling():
    warm, receipt = fixture()
    changed_mood = replace(warm, atoms=tuple(
        replace(atom, revision=2) if atom.key == MOOD else atom
        for atom in warm.atoms
    ))
    with pytest.raises(RecollectionProjectionUnavailable, match="mood version is stale"):
        inspect(changed_mood, receipt)
    new_snapshot, new_receipt = fixture(tone=(0.3, 0.6), mood_revision=2)
    assert inspect(new_snapshot, new_receipt).subjective_tone != inspect(warm, receipt).subjective_tone


def test_source_or_mood_claim_mismatch_is_held():
    snapshot, receipt = fixture()
    with pytest.raises(RecollectionProjectionUnavailable, match="source or mood version is stale"):
        inspect(changed(snapshot, PROJECTION, source_ref=source_key(
            "bot", "persona", "different").token), receipt)
    with pytest.raises(RecollectionProjectionUnavailable, match="mood identity"):
        inspect(changed(snapshot, MOOD, source_refs=["missing-source"]), receipt)


def test_missing_or_revoked_source_ancestor_is_unavailable():
    snapshot, receipt = fixture()
    child = changed(snapshot, SOURCE, parent_source_ids=["parent-1"])
    with pytest.raises(RecollectionProjectionUnavailable, match="ancestor_unknown"):
        inspect(child, receipt)
    parent_key = source_key("bot", "persona", "parent-1")
    parent_access_key = access_key("bot", "persona", "parent-1")
    parent = SourceRecord("parent-1", "private ancestor literal", "alice",
                          "observed", "confirmed", 0.5, 1.0, "family-1",
                          ("owner",), ("context",))
    parent_access = {"source_id": "parent-1", "audiences": ["owner"],
                     "purposes": ["context"], "status": "withdrawn", "recorded_at": 3.0}
    revoked = replace(child, atoms=(*child.atoms,
                                    GraphAtom(parent_key, 1, parent.to_dict()),
                                    GraphAtom(parent_access_key, 1, parent_access)))
    with pytest.raises(RecollectionProjectionUnavailable, match="access_denied"):
        inspect(revoked, receipt)
