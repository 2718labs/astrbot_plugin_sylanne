"""A fenced W01 page is filtered by D06 without inventing coverage."""

from dataclasses import replace

import pytest

from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.domains.d06.current_memory_evidence import (
    CurrentMemoryQueryCoverageV1,
    project_current_memory_evidence_page_v1,
)
from sylanne3.graph_types import GraphAtom, GraphPage, GraphSnapshot, NamespaceEpoch
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import NamespaceId, QueryEpoch


NS = NamespaceId("bot", "persona")
EPOCH = NamespaceEpoch(*NS.as_tuple, 4)
ROOT = source_key(*NS.as_tuple, "root")
PARENT = source_key(*NS.as_tuple, "parent")


def fixture(*, next_after=None):
    atoms = []
    for key, parents in ((ROOT, ("parent",)), (PARENT, ())):
        source_id = key.owner.subject
        record = SourceRecord(
            source_id, f"private {source_id}", "alice", "reported", "reported",
            1.0, 2.0, "family-1", ("owner",), ("context",), parents,
        )
        atoms.extend((
            GraphAtom(key, 1, record.to_dict()),
            GraphAtom(access_key(*NS.as_tuple, source_id), 1,
                      {"source_id": source_id, "audiences": ["owner"],
                       "purposes": ["context"], "status": "active",
                       "recorded_at": 2.0}),
            GraphAtom(source_correction_head_key(NS, source_id), 0, {}, False),
        ))
    page = GraphPage(GraphSnapshot((atoms[0],), (EPOCH,)), next_after)
    closure = GraphSnapshot(tuple(atoms), (EPOCH,))
    return page, closure


def project(page, closure, *, coverage="verified_complete"):
    return project_current_memory_evidence_page_v1(
        page, closure, namespace=NS, graph_epoch=EPOCH,
        access_epoch=2, deletion_epoch=0, audience="owner", purpose="context",
        query_coverage=CurrentMemoryQueryCoverageV1(
            coverage, QueryEpoch(NS, "memory.source", EPOCH.revision),
            page.next_after.token if page.next_after is not None else None),
    )


def changed(snapshot, key, *, revision=None, valid=None, **value):
    return replace(snapshot, atoms=tuple(
        replace(atom, revision=atom.revision if revision is None else revision,
                valid=atom.valid if valid is None else valid,
                value={**atom.value, **value})
        if atom.key == key else atom for atom in snapshot.atoms
    ))


def test_complete_page_has_authorized_lineage_and_version_closure():
    page, closure = fixture()
    result = project(page, closure)
    assert result.status == "candidate_page_complete" and result.page_complete
    assert result.missing_refs == result.excluded_refs == ()
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.source_ref == ROOT.token
    assert candidate.lineage_source_refs == (ROOT.token, PARENT.token)
    assert len(candidate.read_versions) == len(result.read_versions) == 6
    assert candidate.text == "private root"
    assert candidate.source_kind == candidate.assertion_status == "reported"


def test_revoked_or_corrected_ancestor_excludes_without_resurrection():
    page, closure = fixture()
    access = access_key(*NS.as_tuple, "parent")
    withdrawn = changed(closure, access, revision=2, status="withdrawn")
    result = project(page, withdrawn)
    assert result.candidates == () and result.excluded_refs == (ROOT.token,)
    head = source_correction_head_key(NS, "parent")
    corrected = changed(closure, head, revision=1, valid=True,
                        correction_source_ref="new")
    result = project(page, corrected)
    assert result.candidates == () and result.excluded_refs == (ROOT.token,)


def test_missing_closure_and_pagination_never_claim_complete():
    page, closure = fixture()
    head = source_correction_head_key(NS, "parent")
    missing = replace(closure, atoms=tuple(
        atom for atom in closure.atoms if atom.key != head))
    result = project(page, missing)
    assert result.status == "candidate_page_partial"
    assert result.missing_refs == (head.token,)
    assert result.candidates == () and not result.page_complete
    result = project(page, closure, coverage="partial")
    assert not result.page_complete
    page_with_more = replace(page, next_after=ROOT)
    result = project(page_with_more, closure, coverage="partial")
    assert result.next_after == ROOT.token and not result.page_complete
    with pytest.raises(ValueError, match="continuation"):
        project(replace(page, next_after=PARENT), closure, coverage="partial")
