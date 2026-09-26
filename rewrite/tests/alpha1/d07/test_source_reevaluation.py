"""D07 correction reevaluation requires new evidence before belief adoption."""

from dataclasses import replace

import pytest

from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.domains.d07 import compile_d07_source_reevaluation
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.memory_types import InterpretationRecord, SourceRecord, interpretation_key, source_key
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "alice")
OLD = source_key(*NS.as_tuple, "old")
NEW = source_key(*NS.as_tuple, "correction")
HEAD = source_correction_head_key(NS, "old")
TARGET = interpretation_key(*NS.as_tuple, "interpretation")
BELIEF = AtomKey(Owner("persona", "bot", "alice"), "d07.belief_revision.v1", "belief")


def _snapshot():
    old = SourceRecord("old", "original claim", "user", "reported", "reported",
                       1.0, 2.0, "original", ("owner",), ("context",))
    new = SourceRecord("correction", "revised claim", "user", "reported", "reported",
                       None, 20.0, "owner.correction.v1", ("owner",), ("context",),
                       ("old",))
    interpretation = InterpretationRecord(
        "interpretation", ("old",), "subject", "original claim", "retracted",
        1.0, 2.0, 20.0,
    )
    belief = {
        "schema": "d07.belief_revision.v1", "belief_id": "belief",
        "question_key": "question", "hypothesis_ref": "hypothesis",
        "proposition": "original claim", "stance": "support",
        "subjective_conviction": 0.6, "evidence_status": "insufficient",
        "eligibility": ["subjective_reaction"],
        "source_refs": [OLD.token, TARGET.token], "source_families": ["original"],
        "current": False, "historical": True, "replaced_by": None,
        "invalidation_refs": [NEW.token, TARGET.token], "invalidation_kind": "correction",
    }
    rows = [
        GraphAtom(OLD, 2, old.to_dict()), GraphAtom(NEW, 1, new.to_dict()),
        GraphAtom(HEAD, 1, {
            "source_ref": OLD.token, "source_revision": 2,
            "correction_source_ref": NEW.token, "target_refs": [TARGET.token],
            "operation_id": "operation", "state": "pending_reevaluation",
            "access_epoch": 0, "deletion_epoch": 0,
        }),
        GraphAtom(TARGET, 2, interpretation.to_dict()),
        GraphAtom(BELIEF, 2, belief),
    ]
    return GraphSnapshot(tuple(rows), (NamespaceEpoch("bot", "alice", 5),))


def test_retracted_belief_yields_held_question_without_copying_old_stance():
    snapshot = _snapshot()
    decision = compile_d07_source_reevaluation(snapshot, correction_head_ref=HEAD.token)
    assert decision.retracted_interpretation_refs == (TARGET.token,)
    assert decision.historical_belief_refs == (BELIEF.token,)
    assert decision.question_keys_requiring_reevaluation == ("question",)
    assert decision.correction_evidence_status == "reported_claim_only"
    assert decision.status == "proposal_requires_new_interpretation_evidence_and_w01_adoption"
    assert len(decision.read_versions) == len(snapshot.atoms)
    assert snapshot.get(BELIEF).value["current"] is False


@pytest.mark.parametrize("field,value,expected", [
    ("source_revision", 1, "versions"),
    ("state", "complete", "pending reevaluation"),
])
def test_stale_or_completed_head_is_not_reused(field, value, expected):
    snapshot = _snapshot()
    atoms = list(snapshot.atoms)
    atoms[2] = replace(atoms[2], value={**atoms[2].value, field: value})
    with pytest.raises(ValueError, match=expected):
        compile_d07_source_reevaluation(
            replace(snapshot, atoms=tuple(atoms)), correction_head_ref=HEAD.token)


def test_old_belief_still_current_or_new_source_claims_observation_rejected():
    snapshot = _snapshot()
    atoms = list(snapshot.atoms)
    atoms[4] = replace(atoms[4], value={**atoms[4].value, "current": True,
                                        "invalidation_refs": [], "invalidation_kind": None})
    with pytest.raises(ValueError, match="invalidation"):
        compile_d07_source_reevaluation(
            replace(snapshot, atoms=tuple(atoms)), correction_head_ref=HEAD.token)
    atoms = list(snapshot.atoms)
    atoms[1] = replace(atoms[1], value={**atoms[1].value, "source_kind": "observed"})
    with pytest.raises(ValueError, match="independent observation"):
        compile_d07_source_reevaluation(
            replace(snapshot, atoms=tuple(atoms)), correction_head_ref=HEAD.token)
