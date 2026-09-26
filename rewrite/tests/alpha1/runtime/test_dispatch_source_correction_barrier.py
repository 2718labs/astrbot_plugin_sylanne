"""Correction heads block stale graph rows even without dependency edges."""

from dataclasses import replace

from sylanne3.contracts import canonical_json
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_types import GraphAtom, GraphSnapshot
from sylanne3.memory_types import interpretation_key, source_key
from sylanne3.runtime.dispatch_current_commitments import read_current_d08_conflict_facts
from sylanne3.runtime.dispatch_current_projection import (
    derive_current_domain_reads, read_current_dispatch_projection,
)
from sylanne3.runtime.dispatch_source_correction_barrier import read_source_correction_barrier
from sylanne3.runtime_contracts import NamespaceId

from test_dispatch_current_d08_execution_evidence import _evidence_case
from test_dispatch_current_projection import _typed_case


def _insert_head(db, namespace, source_id="source-1"):
    head = source_correction_head_key(namespace, source_id)
    old = source_key(*namespace.as_tuple, source_id)
    value = {
        "source_ref": old.token, "source_revision": 1,
        "correction_source_ref": source_key(*namespace.as_tuple, "correction-1").token,
        "target_refs": [interpretation_key(*namespace.as_tuple, "interpretation-1").token],
        "operation_id": "operation-correction-1", "state": "pending_reevaluation",
        "access_epoch": 0, "deletion_epoch": 0,
    }
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
        head.token, *namespace.as_tuple, head.type_name, 1, canonical_json(value), 1,
    ))
    return head


def test_unlinked_d05_deny_remains_visible_but_correction_makes_coverage_partial():
    db, namespace, snapshot, query, context, request = _typed_case()
    try:
        rule = snapshot.atoms[1]
        denied = replace(rule, value={**rule.value, "effect": "deny"})
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?", (
            canonical_json(denied.value), rule.key.token,
        ))
        snapshot = GraphSnapshot((snapshot.atoms[0], denied), snapshot.epochs)
        db.execute("BEGIN IMMEDIATE")
        _insert_head(db, namespace)
        projection = read_current_dispatch_projection(db, namespace, snapshot, query)
        assert projection.boundary_rules == (denied,)
        assert projection.coverage == "partial"
        assert any(item.startswith("source_pending_reevaluation:")
                   for item in projection.missing_sources)
        _, boundary = derive_current_domain_reads(db, projection, request, context)
        assert boundary.coverage == "partial"
        assert boundary.rules[0].effect == "deny"
        assert boundary.missing_items == projection.missing_sources
    finally:
        db.close()


def test_legacy_d05_ref_and_d08_action_are_explicit_hold():
    db, namespace, snapshot, query, _, _ = _typed_case()
    try:
        rule = snapshot.atoms[1]
        legacy = replace(rule, value={**rule.value, "source_refs": ["source:legacy"]})
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?", (
            canonical_json(legacy.value), rule.key.token,
        ))
        snapshot = GraphSnapshot((snapshot.atoms[0], legacy), snapshot.epochs)
        db.execute("BEGIN IMMEDIATE")
        projection = read_current_dispatch_projection(db, namespace, snapshot, query)
        assert projection.boundary_rules == (legacy,)
        assert projection.coverage == "partial"
        assert any(item.startswith("legacy_source_ref_unqualified:")
                   for item in projection.missing_sources)
    finally:
        db.close()

    db, namespace, snapshot, query, _, _ = _evidence_case()
    try:
        db.execute("BEGIN IMMEDIATE")
        facts = read_current_d08_conflict_facts(db, namespace, snapshot, query)
        assert facts.status == "hold"
        assert any(item.startswith("legacy_source_ref_unqualified:")
                   for item in facts.missing_sources)
    finally:
        db.close()


def test_unlinked_d08_action_with_corrected_canonical_source_is_hold():
    db, namespace, snapshot, query, _, _ = _evidence_case()
    try:
        source = source_key(*namespace.as_tuple, "source-1")
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
            source.token, *namespace.as_tuple, source.type_name, 1,
            canonical_json({"source_id": "source-1"}), 1,
        ))
        action = snapshot.atoms[-1]
        corrected = replace(action, value={**action.value, "source_refs": [source.token]})
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?", (
            canonical_json(corrected.value), action.key.token,
        ))
        snapshot = GraphSnapshot((*snapshot.atoms[:-1], corrected), snapshot.epochs)
        db.execute("BEGIN IMMEDIATE")
        _insert_head(db, namespace)
        facts = read_current_d08_conflict_facts(db, namespace, snapshot, query)
        assert facts.action_intents[0].action_id == "action:one"
        assert any(item.startswith("source_pending_reevaluation:")
                   for item in facts.missing_sources)
    finally:
        db.close()


def test_foreign_namespace_head_does_not_block_local_canonical_source():
    db, namespace, snapshot, query, _, _ = _typed_case()
    try:
        db.execute("BEGIN IMMEDIATE")
        _insert_head(db, NamespaceId("another-bot", "persona"))
        source = source_key(*namespace.as_tuple, "source-1")
        barrier = read_source_correction_barrier(
            db, namespace, query, (source.token,), dependent_ref=snapshot.atoms[1].key.token,
        )
        assert barrier.clear
        assert read_current_dispatch_projection(db, namespace, snapshot, query).coverage == "full"
    finally:
        db.close()
