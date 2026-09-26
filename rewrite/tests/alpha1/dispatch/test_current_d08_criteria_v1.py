"""Fixed D08 criteria v1 permits only a narrow, completely observed case."""

from dataclasses import asdict, replace
import json
import sqlite3

import pytest

from rewrite.tests.alpha1.d08.test_goal_execution_domain import _intent, _schema
from rewrite.tests.alpha1.dispatch.test_authority_budget_snapshot import _case
from rewrite.tests.alpha1.dispatch.test_final_claim_namespace_mapping import _chain
from sylanne3.domains.d08.execution import ActionSchemaRecord, Commitment, Goal
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.runtime.dispatch_current_commitment_check import (
    CRITERIA_REF, CRITERIA_VERSION, _current_atom,
    _require_prepared_claimed_delta,
    evaluate_commitment_conflict_criteria_v1,
)
from sylanne3.runtime.dispatch_current_commitments import CurrentD08ConflictFactsV1
from sylanne3.runtime_contracts import QueryEpoch


def _facts():
    namespace, context, _, authority_snapshot, _ = _case()
    intent = _intent(effect_id=context.permit.effect_id)
    goal = Goal(intent.goal_ref, 1, "active", intent.success_predicate,
                (), (), None, (), ())
    commitment = Commitment(
        intent.commitment_refs[0], 1, "persona:persona", intent.target_ref,
        "known-scope", "unilateral", "communicated", "pending", None,
        ("receipt:prior",), (), None, ("source:prior",))
    facts = CurrentD08ConflictFactsV1(
        namespace, QueryEpoch(namespace, "d08.conflict_graph", 4),
        (commitment,), (intent,), (), (), missing_sources=())
    return intent, goal, facts, authority_snapshot


def test_fixed_criteria_v1_has_narrow_clear_case_and_stable_identity():
    intent, goal, facts, authority_snapshot = _facts()
    assert (CRITERIA_REF, CRITERIA_VERSION) == (
        "d08.commitment_conflict.criteria.v1", 1)
    assert evaluate_commitment_conflict_criteria_v1(
        intent, goal, facts, authority_snapshot) == ()


def test_other_unfinished_commitment_and_same_target_action_hold():
    intent, goal, facts, authority_snapshot = _facts()
    other = replace(facts.commitments[0], commitment_id="commitment:other")
    competing = _intent(
        action_id="action:other", effect_id="effect:other",
        attempt_id="attempt:other")
    facts = replace(facts, commitments=facts.commitments + (other,),
                    action_intents=facts.action_intents + (competing,))
    assert evaluate_commitment_conflict_criteria_v1(
        intent, goal, facts, authority_snapshot) == (
            "other_unfinished_commitment", "other_same_target_action_unfinished")


def test_inactive_goal_or_foreign_unresolved_effect_holds():
    intent, goal, facts, authority_snapshot = _facts()
    assert "current_goal_not_active" in evaluate_commitment_conflict_criteria_v1(
        intent, replace(goal, state="waiting"), facts, authority_snapshot)
    other = replace(authority_snapshot.unresolved_effects[0],
                    effect_id="effect:other", operation_id="operation:other",
                    footprint=replace(
                        authority_snapshot.unresolved_effects[0].footprint,
                        effect_id="effect:other"))
    authority_snapshot = replace(
        authority_snapshot, unresolved_effects=tuple(sorted((
            authority_snapshot.unresolved_effects[0], other),
            key=lambda item: item.effect_id)))
    assert "other_authority_effect_unresolved" in (
        evaluate_commitment_conflict_criteria_v1(
            intent, goal, facts, authority_snapshot))


def test_prepared_claimed_chain_identifies_only_own_two_seq_delta():
    namespace, context, _, snapshot, _ = _case()
    _, claimed = _chain(namespace)
    assert _require_prepared_claimed_delta(claimed, context, snapshot) == 0
    moved = replace(context.permit.pinned_anchor, execution_seq=3,
                    execution_digest="sha256:" + "f" * 64)
    with pytest.raises(ValueError, match="unproven intermediate change"):
        _require_prepared_claimed_delta(
            claimed, replace(context, permit=replace(context.permit,
                                                     pinned_anchor=moved)),
            replace(snapshot, anchor=moved))


def test_current_action_schema_atom_must_match_exact_graph_row():
    namespace, _, _, _, _ = _case()
    intent = _intent(effect_id="effect:test")
    schema = ActionSchemaRecord.bind(intent, _schema())
    key = AtomKey(
        Owner("activity", *namespace.as_tuple, intent.identity.activity_id),
        "d08.action_schema.v1", schema.schema_ref)
    atom = GraphAtom(key, 1, json.loads(json.dumps(asdict(schema))))
    graph = GraphSnapshot((atom,), (NamespaceEpoch(*namespace.as_tuple, 1),))
    db = sqlite3.connect(":memory:")
    try:
        db.execute("CREATE TABLE graph_atoms(token TEXT,bot TEXT,persona TEXT,"
                   "type_name TEXT,name TEXT,revision INT,value TEXT,valid INT)")
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?)", (
            key.token, *namespace.as_tuple, key.type_name, key.name, 1,
            json.dumps(atom.value), 1))
        current_atom, current_schema = _current_atom(
            db, namespace, graph, "d08.action_schema.v1", schema.schema_ref)
        assert current_atom == atom and current_schema == schema
        db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (key.token,))
        with pytest.raises(ValueError, match="graph atom changed"):
            _current_atom(db, namespace, graph, "d08.action_schema.v1",
                          schema.schema_ref)
    finally:
        db.close()
