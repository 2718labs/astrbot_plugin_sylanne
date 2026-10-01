"""MEM-10 D06 evidence grouping never publishes a stale or restricted source."""

from dataclasses import replace

import pytest

from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.domains.d06.consolidation import (
    ConsolidationInput, prepare_consolidation_candidate,
)
from sylanne3.graph_types import GraphAtom, GraphSnapshot, NamespaceEpoch
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import NamespaceId


NAMESPACE = NamespaceId("bot", "persona")


def fixture():
    atoms = []
    specs = (
        ("parent", "family-a", "independent", ()),
        ("echo", "family-a", "same_root", ("parent",)),
        ("other", "family-b", "independent", ()),
        ("against", "family-c", "unknown", ()),
    )
    for source_id, root, independence, parents in specs:
        record = SourceRecord(
            source_id, f"private {source_id}", "alice", "reported", "reported",
            1.0, 2.0, root, ("owner",), ("consolidation",), parents,
            independence,
        )
        source = source_key(*NAMESPACE.as_tuple, source_id)
        access = access_key(*NAMESPACE.as_tuple, source_id)
        head = source_correction_head_key(NAMESPACE, source_id)
        atoms.extend((
            GraphAtom(source, 1, record.to_dict()),
            GraphAtom(access, 1, {"source_id": source_id, "audiences": ["owner"],
                                  "purposes": ["consolidation"], "status": "active",
                                  "recorded_at": 2.0}),
            GraphAtom(head, 0, {}, False),
        ))
    return GraphSnapshot(tuple(atoms), (NamespaceEpoch(*NAMESPACE.as_tuple, 4),))


def prepare(snapshot):
    refs = {name: source_key(*NAMESPACE.as_tuple, name).token
            for name in ("parent", "echo", "other", "against")}
    return prepare_consolidation_candidate(
        snapshot, namespace=NAMESPACE, hypothesis_ref="d07:hypothesis-1",
        inputs=(
            ConsolidationInput(refs["parent"], "support"),
            ConsolidationInput(refs["echo"], "support"),
            ConsolidationInput(refs["other"], "support"),
            ConsolidationInput(refs["against"], "counterexample"),
        ), audience="owner", access_epoch=2, deletion_epoch=0,
    )


def changed(snapshot, key, *, revision=None, valid=None, **value):
    return replace(snapshot, atoms=tuple(
        replace(atom,
                revision=atom.revision if revision is None else revision,
                valid=atom.valid if valid is None else valid,
                value={**atom.value, **value})
        if atom.key == key else atom for atom in snapshot.atoms
    ))


def test_groups_declared_independent_families_and_counterexample_without_double_count():
    snapshot = fixture()
    candidate = prepare(snapshot)
    assert candidate.status == "candidate_hold"
    assert len(candidate.families) == 3
    family_a = next(group for group in candidate.families
                    if group.provenance_root == "family-a")
    assert len(family_a.support_refs) == 2
    assert family_a.counterexample_refs == ()
    assert len(candidate.declared_independent_refs) == 2
    assert candidate.independence_unverified_refs == (
        source_key(*NAMESPACE.as_tuple, "against").token,
    )
    assert next(group for group in candidate.families
                if group.provenance_root == "family-c").counterexample_refs
    candidate.assert_current_for_adoption(snapshot, access_epoch=2, deletion_epoch=0)


def test_revocation_correction_or_snapshot_change_rejects_consolidation():
    snapshot = fixture()
    candidate = prepare(snapshot)
    parent_access = access_key(*NAMESPACE.as_tuple, "parent")
    revoked = changed(snapshot, parent_access, revision=2, status="withdrawn")
    with pytest.raises(ValueError, match="stale"):
        candidate.assert_current_for_adoption(revoked, access_epoch=2, deletion_epoch=0)
    with pytest.raises(PermissionError, match="unavailable"):
        prepare(revoked)

    corrected = changed(snapshot, source_correction_head_key(NAMESPACE, "parent"),
                        revision=1, valid=True, state="pending_reevaluation")
    with pytest.raises(ValueError, match="stale"):
        candidate.assert_current_for_adoption(corrected, access_epoch=2, deletion_epoch=0)
    with pytest.raises(ValueError, match="corrected"):
        prepare(corrected)
    with pytest.raises(ValueError, match="corrected"):
        prepare_consolidation_candidate(
            corrected, namespace=NAMESPACE, hypothesis_ref="d07:hypothesis-1",
            inputs=(ConsolidationInput(
                source_key(*NAMESPACE.as_tuple, "echo").token, "support"),),
            audience="owner", access_epoch=2, deletion_epoch=0,
        )
    with pytest.raises(ValueError, match="stale"):
        candidate.assert_current_for_adoption(
            replace(snapshot, epochs=(NamespaceEpoch(*NAMESPACE.as_tuple, 5),)),
            access_epoch=2, deletion_epoch=0,
        )
    with pytest.raises(ValueError, match="stale"):
        candidate.assert_current_for_adoption(snapshot, access_epoch=3, deletion_epoch=0)
