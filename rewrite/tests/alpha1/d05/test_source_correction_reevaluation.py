"""D05 correction leaves boundary and relationship adoption on HOLD."""

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.domains.d05 import (
    BoundaryRule, RelationshipContribution, compile_d05_source_reevaluation,
)
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.memory_types import SourceRecord, interpretation_key, source_key
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "alice")
OLD = source_key(*NS.as_tuple, "old")
NEW = source_key(*NS.as_tuple, "correction")
HEAD = source_correction_head_key(NS, "old")
TARGET = interpretation_key(*NS.as_tuple, "interpretation")


def _source(source_id, *, parent=(), provenance="original"):
    return SourceRecord(
        source_id, "reported words", "user", "reported", "reported",
        None, 10.0 if source_id == "old" else 20.0, provenance,
        ("owner",), ("context",), parent,
    ).to_dict()


def _wire(value):
    return json.loads(json.dumps(asdict(value)))


def _snapshot(effect="deny"):
    rule = BoundaryRule(
        "boundary:contact", "persona:alice", "entity:bob", "contact", "direct",
        None, effect, "counterparty_explicit", (OLD.token,), (), (), 1.0,
        None, 1, "entity:bob", (), "active",
    )
    item = RelationshipContribution(
        "persona:alice", "event:one", "entity:bob", "trust", "external_observation",
        1, (OLD.token,),
    )
    relation = Owner("relation", "bot", "alice", "entity:bob")
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
        GraphAtom(AtomKey(relation, "d05.boundary_rule", rule.rule_id), 2, _wire(rule)),
        GraphAtom(AtomKey(relation, "d05.contribution", item.key), 3, _wire(item)),
        GraphAtom(AtomKey(relation, "d05.relationship_projection", "current"), 1,
                  {"subject_entity_ref": "entity:bob", "dimension": "trust", "status": "positive"}),
    ]
    return GraphSnapshot(tuple(rows), (NamespaceEpoch("bot", "alice", 4),))


@pytest.mark.parametrize("effect", ["deny", "allow"])
def test_old_source_rule_and_social_projection_are_held_without_new_pass(effect):
    decision = compile_d05_source_reevaluation(_snapshot(effect), correction_head_ref=HEAD.token)
    assert decision.old_source.revision == 2
    assert len(decision.affected_current_rule_refs) == 1
    assert len(decision.affected_contribution_refs) == 1
    assert len(decision.blocked_projection_refs) == 1
    assert decision.boundary_scopes_requiring_recheck == (
        ("persona:alice", "entity:bob", "contact", "direct", None),
    )
    assert decision.preserved_historical_rule_refs == decision.affected_current_rule_refs
    assert decision.status == "proposal_requires_w01_current_snapshot_and_boundary_hold"
    assert len(decision.read_versions) == len(_snapshot(effect).atoms)


def test_stale_source_and_foreign_namespace_fail_closed():
    snapshot = _snapshot()
    atoms = list(snapshot.atoms)
    atoms[2] = replace(atoms[2], value={**atoms[2].value, "source_revision": 1})
    with pytest.raises(ValueError, match="versions"):
        compile_d05_source_reevaluation(
            replace(snapshot, atoms=tuple(atoms)), correction_head_ref=HEAD.token)
    foreign = GraphAtom(source_key("bot", "bob", "foreign"), 1, _source("foreign"))
    with pytest.raises(ValueError, match="cross-namespace"):
        compile_d05_source_reevaluation(
            replace(snapshot, atoms=(*snapshot.atoms, foreign)), correction_head_ref=HEAD.token)


def test_missing_rule_in_supplied_snapshot_does_not_claim_coverage():
    snapshot = _snapshot()
    without_rule = replace(snapshot, atoms=tuple(
        atom for atom in snapshot.atoms if atom.key.type_name != "d05.boundary_rule"
    ))
    decision = compile_d05_source_reevaluation(without_rule, correction_head_ref=HEAD.token)
    assert decision.affected_current_rule_refs == ()
    assert decision.status == "proposal_requires_w01_current_snapshot_and_boundary_hold"
