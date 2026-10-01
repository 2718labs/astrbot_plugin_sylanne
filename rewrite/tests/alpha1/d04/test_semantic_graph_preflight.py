"""A 24D semantic drive must replay from actual graph values before W01 adoption."""

from dataclasses import asdict, replace

import pytest

from sylanne3.domains.d04.numeric_drive import sourced_numeric_drive_write
from sylanne3.domains.d04.semantic_graph_preflight import preflight_d04_semantic_drive_graph
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch
from sylanne3.memory_types import access_key
from sylanne3.native_runtime.d04_semantic_drive_candidate import D04SemanticDriveHold
from sylanne3.runtime_contracts import NamespaceId

from rewrite.tests.alpha1.numerics.test_d04_semantic_drive_candidate import (
    CHECKPOINT, _compile, _drive, _share,
)


NAMESPACE = NamespaceId("bot", "persona")


def _qualified_share(*args, **kwargs):
    share = _share(*args, **kwargs)
    return replace(share, source=replace(share.source, source_kind="reported"))


def _read(*shares):
    candidate = _compile(*shares)
    drives = tuple(_drive(candidate, row) for row in candidate.source_vectors)
    atoms = [GraphAtom(AtomKey.from_token(CHECKPOINT), 1, {"root": "pinned"})]
    for share in shares:
        appraisal = asdict(share.appraisal)
        appraisal["meaning_facets"] = [asdict(facet) for facet in share.appraisal.meaning_facets]
        appraisal["competing_interpretation_refs"] = list(
            share.appraisal.competing_interpretation_refs)
        appraisal["source_refs"] = list(share.appraisal.source_refs)
        for facet in appraisal["meaning_facets"]:
            facet["unknown_fields"] = list(facet["unknown_fields"])
            facet["source_refs"] = list(facet["source_refs"])
        atoms.extend((
            GraphAtom(AtomKey.from_token(share.appraisal_ref), share.appraisal_revision,
                      appraisal),
            GraphAtom(AtomKey.from_token(share.source_ref), share.source_revision,
                      share.source.to_dict()),
            GraphAtom(access_key(*NAMESPACE.as_tuple, share.source.source_id),
                      share.access_revision, {
                          "source_id": share.source.source_id,
                          "audiences": ["owner"], "purposes": ["context"],
                          "status": "active", "recorded_at": 0.0,
                      }),
            GraphAtom(source_correction_head_key(NAMESPACE, share.source.source_id),
                      0, {}, False),
        ))
    for drive in drives:
        write = sourced_numeric_drive_write(drive)
        atoms.append(GraphAtom(write.key, 1, write.value))
    return GraphSnapshot(tuple(atoms), (NamespaceEpoch("bot", "persona", 7),)), drives


def _preflight(snapshot, drives, shares):
    return preflight_d04_semantic_drive_graph(
        snapshot=snapshot, namespace=NAMESPACE,
        checkpoint_ref=CHECKPOINT, checkpoint_revision=1,
        role_start=1.0, role_end=2.0, shares=shares, drives=drives,
        audience=("owner",), purpose="context",
    )


def _mutate(snapshot, key, **changes):
    return replace(snapshot, atoms=tuple(
        replace(atom, **changes) if atom.key == key else atom
        for atom in snapshot.atoms
    ))


def test_graph_bound_24d_drive_intervention_changes_only_its_axis():
    first = _qualified_share()
    second = _qualified_share("source-2", root="family-2", contribution="event-2",
                    mechanism="gain_engagement", fraction=0.25)
    snapshot, drives = _read(first, second)
    result = _preflight(snapshot, drives, (first, second))
    assert result.status == "candidate_hold_for_w01_current_adoption"
    assert len(result.candidate.drive) == 24
    assert len(result.read_versions) == 11  # checkpoint, two appraisal/drive/three source heads
    changed = replace(first, layer_doses=(0.9, 0.4, 0.2))
    changed_snapshot, changed_drives = _read(changed, second)
    changed_result = _preflight(changed_snapshot, changed_drives, (changed, second))
    changed_axes = {index for index, (old, new) in enumerate(zip(
        result.candidate.drive, changed_result.candidate.drive)) if old != new}
    assert changed_axes == {3}
    assert result.source_closure_digest == changed_result.source_closure_digest
    assert result.candidate.transcript_sha256 != changed_result.candidate.transcript_sha256


def test_graph_source_and_drive_counterexamples_hold():
    share = _qualified_share()
    snapshot, drives = _read(share)
    assert _preflight(snapshot, drives, (share,)).candidate.drive[3] == 0.4
    source = AtomKey.from_token(share.source_ref)
    access = access_key(*NAMESPACE.as_tuple, share.source.source_id)
    head = source_correction_head_key(NAMESPACE, share.source.source_id)
    with pytest.raises(D04SemanticDriveHold, match="head differs"):
        _preflight(_mutate(snapshot, source, revision=2), drives, (share,))
    with pytest.raises(D04SemanticDriveHold, match="not authorized"):
        _preflight(_mutate(snapshot, access, value={
            **snapshot.get(access).value, "status": "withdrawn",
        }), drives, (share,))
    with pytest.raises(D04SemanticDriveHold, match="correction head"):
        _preflight(_mutate(snapshot, head, revision=1, valid=True), drives, (share,))
    drive_key = sourced_numeric_drive_write(drives[0]).key
    with pytest.raises(D04SemanticDriveHold, match="graph row differs"):
        _preflight(_mutate(snapshot, drive_key, value={
            **snapshot.get(drive_key).value, "drive": [0.0] * 24,
        }), drives, (share,))


def test_authored_source_cannot_be_promoted_to_external_report():
    forged = _share()  # authored source, but appraisal claims an external report
    snapshot, drives = _read(forged)
    with pytest.raises(D04SemanticDriveHold, match="reality differs"):
        _preflight(snapshot, drives, (forged,))
