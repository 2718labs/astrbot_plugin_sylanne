"""D04 source correction impact is a held decision over versioned reads."""

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.domains.d04 import (
    AffectProvider, AppraisalBundle, FeelingState, MeaningFacet, MoodField,
    compile_d04_source_reevaluation,
)
from sylanne3.domains.d04.affect import RecollectionExperience
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.memory_types import SourceRecord, interpretation_key, source_key
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "alice")
OLD = source_key(*NS.as_tuple, "old")
NEW = source_key(*NS.as_tuple, "correction")
HEAD = source_correction_head_key(NS, "old")
TARGET = interpretation_key(*NS.as_tuple, "interpretation")


def _wire(value):
    return json.loads(json.dumps(asdict(value)))


def _source(source_id, *, parent=(), provenance="original"):
    return SourceRecord(
        source_id, "reported words", "user", "reported", "reported",
        None, 10.0 if source_id == "old" else 20.0, provenance,
        ("owner",), ("context",), parent,
    ).to_dict()


def _snapshot():
    facet = MeaningFacet(
        "facet", "target", TARGET.token, "value", "unknown", 0.5, 0.5,
        None, None, 0.5, (), (OLD.token,),
    )
    appraisal = AppraisalBundle(
        "appraisal", OLD.token, "target", (facet,), (TARGET.token,),
        (OLD.token,), "reported", "external_report", "contribution:old", 10.0,
    )
    feeling = FeelingState(
        "feeling", "target", "scheme", "operator", (("axis", 0.4),),
        ("facet",), (TARGET.token,), ("contribution:old",), (OLD.token,),
        "parameters", "coupling", 15.0,
    )
    mood = MoodField(
        "mood", "scheme", (("axis", 0.2),), (OLD.token,),
        "parameters", "coupling", 15.0,
    )
    experience = RecollectionExperience(
        "experience", "activity", "recollection", "memory", (OLD.token,),
        "mood", (OLD.token,), (0.2, 0.4), (-0.2, 0.2), "coupling", "coupling",
    )
    rows = [
        GraphAtom(OLD, 2, _source("old")),
        GraphAtom(NEW, 1, _source("correction", parent=("old",),
                                  provenance="owner.correction.v1")),
        GraphAtom(HEAD, 1, {
            "source_ref": OLD.token, "source_revision": 2,
            "correction_source_ref": NEW.token, "target_refs": [TARGET.token],
            "operation_id": "operation", "state": "pending_reevaluation",
            "access_epoch": 0, "deletion_epoch": 0,
        }),
        GraphAtom(AtomKey(Owner("event", "bot", "alice", "event"),
                          "d04.appraisal_bundle.v1", "appraisal"), 1, _wire(appraisal)),
        GraphAtom(AtomKey(Owner("persona", "bot", "alice"),
                          "d04.feeling_state.v1", "feeling"), 3, _wire(feeling)),
        GraphAtom(AtomKey(Owner("persona", "bot", "alice"),
                          "d04.mood_field.v1", "mood"), 2, _wire(mood)),
        GraphAtom(AtomKey(Owner("activity", "bot", "alice", "activity"),
                          "d04.recollection_experience.v1", "experience"), 1,
                  _wire(experience)),
    ]
    return GraphSnapshot(tuple(rows), (NamespaceEpoch("bot", "alice", 4),))


def test_correction_blocks_current_contributions_and_preserves_history():
    snapshot = _snapshot()
    decision = compile_d04_source_reevaluation(snapshot, correction_head_ref=HEAD.token)
    assert decision.old_source.revision == 2
    assert decision.correction_source.revision == 1
    assert decision.learned_at == 20.0
    assert decision.suppressed_contribution_keys == ("contribution:old",)
    assert len(decision.affected_appraisal_refs) == 1
    assert len(decision.blocked_current_feeling_refs) == 1
    assert len(decision.blocked_current_mood_refs) == 1
    assert len(decision.blocked_current_recollection_refs) == 1
    assert decision.preserved_historical_feeling_refs == decision.blocked_current_feeling_refs
    assert decision.status == "proposal_requires_w01_current_snapshot_and_atomic_fence"
    assert snapshot.get(OLD).value["text"] == "reported words"
    assert len(decision.read_versions) == len(snapshot.atoms)


def test_stale_head_and_missing_correction_source_fail_closed():
    snapshot = _snapshot()
    atoms = list(snapshot.atoms)
    atoms[2] = replace(atoms[2], value={**atoms[2].value, "source_revision": 1})
    with pytest.raises(ValueError, match="versions"):
        compile_d04_source_reevaluation(
            replace(snapshot, atoms=tuple(atoms)), correction_head_ref=HEAD.token)
    with pytest.raises(ValueError, match="versions"):
        compile_d04_source_reevaluation(
            replace(snapshot, atoms=tuple(atom for atom in snapshot.atoms if atom.key != NEW)),
            correction_head_ref=HEAD.token)


def test_cross_namespace_and_unproven_provenance_rejected():
    snapshot = _snapshot()
    atoms = list(snapshot.atoms)
    atoms[1] = replace(atoms[1], value=_source("correction", parent=("old",)))
    with pytest.raises(ValueError, match="provenance"):
        compile_d04_source_reevaluation(
            replace(snapshot, atoms=tuple(atoms)), correction_head_ref=HEAD.token)
    foreign = GraphAtom(source_key("bot", "bob", "foreign"), 1, _source("foreign"))
    with pytest.raises(ValueError, match="cross-namespace"):
        compile_d04_source_reevaluation(
            replace(snapshot, atoms=(*snapshot.atoms, foreign)), correction_head_ref=HEAD.token)


def test_missing_appraisal_cannot_silently_clear_old_current_feeling():
    snapshot = _snapshot()
    without_appraisal = replace(snapshot, atoms=tuple(
        atom for atom in snapshot.atoms if atom.key.type_name != "d04.appraisal_bundle.v1"
    ))
    decision = compile_d04_source_reevaluation(
        without_appraisal, correction_head_ref=HEAD.token)
    assert decision.suppressed_contribution_keys == ()
    assert len(decision.blocked_current_feeling_refs) == 1
    assert decision.status == "proposal_requires_w01_current_snapshot_and_atomic_fence"


def test_old_invalidate_hook_fails_closed_without_a_snapshot():
    with pytest.raises(ValueError, match="current correction snapshot"):
        AffectProvider().invalidate((OLD.token,))


def test_public_graph_restart_preserves_old_feeling_but_blocks_corrected_belief(tmp_path):
    from sylanne3.contracts import Event, Scope
    from sylanne3.domains.d06 import D06DomainProvider
    from sylanne3.domains.d07 import D07DomainProvider, compile_d07_source_reevaluation
    from sylanne3.graph_store import GraphStore
    from sylanne3.graph_types import GraphCandidate, GraphVersion, GraphWrite, TypeRegistry
    from rewrite.tests.alpha1.d07.test_source_reevaluation import (
        BELIEF, TARGET, _snapshot as d07_snapshot,
    )

    base = _snapshot()
    d07 = d07_snapshot()
    rows = list(base.atoms)
    rows.extend(atom for atom in d07.atoms if atom.key in {TARGET, BELIEF})
    rows[0] = replace(rows[0], revision=1)
    rows[2] = replace(rows[2], value={**rows[2].value, "source_revision": 1})
    registry = TypeRegistry()
    for provider in (AffectProvider(), D07DomainProvider(), D06DomainProvider()):
        for spec in provider.type_specs():
            registry.register(spec)
    path = tmp_path / "correction.db"
    store = GraphStore(path, registry)
    keys = tuple(atom.key for atom in rows)
    try:
        empty = store.graph_snapshot(keys)
        receipt = store.graph_commit(GraphCandidate(
            Event(Scope("bot", "alice", "session"), "fixture-corrected", 20.0,
                  "fixture-corrected", {}),
            tuple(GraphVersion(key, 0) for key in keys),
            tuple(GraphWrite(atom.key, atom.value) for atom in rows), empty.epochs,
        ))
        assert receipt.status == "committed"
    finally:
        store.close()

    store = GraphStore(path, registry)
    try:
        committed = store.graph_snapshot(keys)
        d04 = compile_d04_source_reevaluation(committed, correction_head_ref=HEAD.token)
        d07_decision = compile_d07_source_reevaluation(
            committed, correction_head_ref=HEAD.token,
        )
        feeling_ref = next(atom.key.token for atom in committed.atoms
                           if atom.key.type_name == "d04.feeling_state.v1")
        assert d04.preserved_historical_feeling_refs == (feeling_ref,)
        assert d04.blocked_current_feeling_refs == (feeling_ref,)
        assert committed.get(AtomKey.from_token(feeling_ref)).valid
        assert d07_decision.historical_belief_refs == (BELIEF.token,)
        assert d07_decision.question_keys_requiring_reevaluation == ("question",)
        assert committed.get(BELIEF).value["current"] is False
        assert len([atom for atom in committed.atoms if atom.key == OLD]) == 1
        assert d04.status.endswith("atomic_fence")
        assert d07_decision.status.endswith("w01_adoption")
    finally:
        store.close()
