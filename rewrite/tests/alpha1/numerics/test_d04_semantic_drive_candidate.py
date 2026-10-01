"""Counterexamples for conditional D04 semantic drive compilation."""

from dataclasses import replace

import pytest

from sylanne3.domains.d04.affect import AppraisalBundle, MeaningFacet
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, SCHEME_VERSION
from sylanne3.domains.d04.numeric_drive import SourcedNumericDrive, numeric_drive_id
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.native_runtime.d04_semantic_drive_candidate import (
    D04SemanticDriveHold, D04SemanticMechanismShare,
    compile_d04_semantic_drive_candidate, verify_d04_semantic_drive_rows,
)


OWNER = Owner("persona", "bot", "persona")
CHECKPOINT = AtomKey(OWNER, "d04.numeric_checkpoint.v1", "root").token


def _share(source_id="source-1", *, root="family-1", contribution="event-1",
           facet_id="facet-1", mechanism="loss_response", fraction=0.5):
    source_ref = source_key("bot", "persona", source_id).token
    source = SourceRecord(source_id, "reported occurrence", "owner", "authored",
                          "reported", 0.0, 0.0, root, ("owner",), ("context",))
    facet = MeaningFacet(facet_id, "target-1", "interpretation-1", "value-1",
                         "uncertain", 0.5, 0.5, None, None, 0.5, (), (source_ref,))
    appraisal = AppraisalBundle(
        "appraisal-" + source_id + "-" + facet_id, "event-1", "target-1",
        (facet,), ("interpretation-1",), (source_ref,), "reported",
        "external_report", contribution, 0.0,
    )
    appraisal_ref = AtomKey(Owner("event", "bot", "persona", "event-1"),
                            "d04.appraisal_bundle.v1", appraisal.appraisal_id).token
    return D04SemanticMechanismShare(
        appraisal_ref, 1, appraisal, facet_id, source_ref, 1, 1, source,
        mechanism, (0.8, 0.4, 0.2), fraction,
    )


def _compile(*shares):
    return compile_d04_semantic_drive_candidate(
        checkpoint_ref=CHECKPOINT, checkpoint_revision=1,
        role_start=1.0, role_end=2.0, shares=shares,
    )


def _drive(candidate, row):
    source = AtomKey.from_token(row.source_ref)
    return SourcedNumericDrive(
        numeric_drive_id(CHECKPOINT, row.source_ref, 1.0, 2.0), 1,
        CHECKPOINT, 1, row.source_ref, row.source_revision,
        access_key("bot", "persona", source.owner.subject).token,
        row.access_revision, candidate.mapping_version, candidate.transcript_sha256,
        SCHEME_VERSION, 1.0, 2.0, REGISTERED_AXIS_IDS, row.drive,
    )


def test_distinct_source_families_map_to_named_axes_and_bind_rows():
    first = _share()
    second = _share("source-2", root="family-2", contribution="event-2",
                    mechanism="gain_engagement", fraction=0.25)
    candidate = _compile(first, second, first)
    assert candidate.status == "candidate_hold"
    assert candidate.collapsed_retries == 1
    assert candidate.drive[:3] == (0.2, 0.1, 0.05)
    assert candidate.drive[3:6] == (0.4, 0.2, 0.1)
    assert sum(value != 0 for value in candidate.drive) == 6
    assert "w01_fenced_current_appraisal_source_access_and_dedup_inventory" in candidate.missing_authorities
    drives = tuple(_drive(candidate, row) for row in candidate.source_vectors)
    verify_d04_semantic_drive_rows(candidate, drives)
    with pytest.raises(D04SemanticDriveHold, match="differs"):
        verify_d04_semantic_drive_rows(candidate, (
            replace(drives[0], drive=(0.0,) * 24), drives[1],
        ))


def test_same_contribution_alias_across_roots_cannot_multiply_dose():
    with pytest.raises(D04SemanticDriveHold, match="aliases distinct source roots"):
        _compile(_share(), _share("source-2", root="family-2"))


def test_same_family_facet_allocation_cannot_exceed_one():
    with pytest.raises(D04SemanticDriveHold, match="share exceeds one"):
        _compile(_share(fraction=0.6),
                 _share(facet_id="facet-2", fraction=0.6))
    with pytest.raises(D04SemanticDriveHold, match="share exceeds one"):
        _compile(_share(fraction=0.6),
                 _share(facet_id="facet-2", contribution="rephrased-event-1",
                        fraction=0.6))


def test_retry_with_changed_dose_is_conflict_and_missing_row_is_rejected():
    first = _share()
    with pytest.raises(D04SemanticDriveHold, match="conflicting doses"):
        _compile(first, replace(first, layer_doses=(0.9, 0.4, 0.2)))
    candidate = _compile(first)
    with pytest.raises(D04SemanticDriveHold, match="incomplete"):
        verify_d04_semantic_drive_rows(candidate, ())
