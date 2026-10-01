"""A real ABI2 box may seed blank authored facets, never event provenance."""

from dataclasses import replace

import pytest

from sylanne3.domains.d04.authored_lineage_v3 import (
    AuthoredRootBlockInputV3, AuthoredRootInputV3, AuthoredRootCandidateV3,
    RootAuthoredFacetV3, authored_root_write_rows_v3,
    compile_authored_root_candidate_v3, decode_authored_feeling_state_v1,
    decode_authored_mood_state_v1, decode_authored_numeric_checkpoint_v2,
    decode_authored_root_candidate_v3, decode_authored_root_input_v3,
    encode_authored_root_candidate_v3, encode_authored_root_input_v3,
    issue_authored_root_writes_v3, run_authored_initial_box_math_v3,
    verify_authored_initial_box_math_v3,
)
from sylanne3.native_runtime.initial_box_trajectory import _box_digest
from sylanne3.runtime_contracts import canonical_digest

from rewrite.tests.alpha1.d04.test_root_projection_v2 import _inputs
from rewrite.tests.alpha1.numerics.test_authored_root_initial_box import handles, native_asset


def _candidate(box_width: float = 0.01):
    old, _, readout, policy = _inputs()
    feelings = (
        RootAuthoredFacetV3("feeling:one", "feeling:base", "feeling", "facet:one"),
        RootAuthoredFacetV3("feeling:two", "feeling:base", "feeling", "facet:two"),
    )
    mood = RootAuthoredFacetV3("mood:one", "mood:base", "mood", "facet:mood")
    blocks = tuple(AuthoredRootBlockInputV3(
        facet, policy.axis_ids, (2.0,) * 24,
        ((2.0 - box_width, 2.0 + box_width),) * 24, f"box:{facet.block_id}",
    ) for facet in (*feelings, mood))
    selection = AuthoredRootInputV3(
        "candidate:blank", old.namespace, old.author_id, old.draft_id,
        old.cursor, old.preset.digest, old.preset.assets.digest, blocks,
    )
    assert decode_authored_root_input_v3(encode_authored_root_input_v3(selection)) == selection
    return compile_authored_root_candidate_v3(old.preset, selection), readout, policy


def test_real_abi2_blank_root_writes_and_provenance_are_exact(handles):
    handle, _ = handles
    candidate, readout, policy = _candidate()
    assert decode_authored_root_candidate_v3(encode_authored_root_candidate_v3(candidate)) == candidate
    proof = run_authored_initial_box_math_v3(handle, candidate)
    verify_authored_initial_box_math_v3(handle, candidate, proof)
    issued = issue_authored_root_writes_v3(candidate, proof, readout, policy, "root:one")
    assert issued.status == "candidate_pending_w01_v3_atomic_adoption"
    assert len(issued.members) == 3
    rows = authored_root_write_rows_v3(issued.members)
    assert issued.write_set_digest == canonical_digest(rows)
    for member in issued.members:
        assert member.checkpoint.latent_state[0] == 2.0
        assert member.state.coordinates[0][1] != 2.0
        assert member.checkpoint.root_candidate_digest == candidate.digest
        assert decode_authored_numeric_checkpoint_v2(next(row[2] for row in rows
            if row[0] == member.checkpoint_ref)) == member.checkpoint
        state = next(row[2] for row in rows if row[0] == member.state_ref)
        decoder = (decode_authored_feeling_state_v1 if member.checkpoint.block.kind == "feeling"
                   else decode_authored_mood_state_v1)
        assert decoder(state) == member.state
        assert state.get("interpretation_refs", ()) == () or state.get("interpretation_refs") == []
        assert state.get("historical_source_refs", ()) == () or state.get("historical_source_refs") == []
        assert state.get("source_refs", ()) == () or state.get("source_refs") == []
    with pytest.raises(ValueError, match="box"):
        checkpoint = candidate.checkpoints[0]
        forged = replace(proof.blocks[0], verified_initial_error=0.0,
                         initial_box_digest=_box_digest(
                             checkpoint.latent_state,
                             tuple(pair[0] for pair in checkpoint.ordered_box),
                             tuple(pair[1] for pair in checkpoint.ordered_box),
                             0.0, proof.production_binding))
        altered = replace(proof, blocks=(forged, *proof.blocks[1:]))
        altered = replace(altered, proof_digest=canonical_digest(dict(
            candidate_digest=altered.candidate_digest,
            production_binding=altered.production_binding,
            binding_digest=altered.binding_digest,
            blocks=altered.blocks, status=altered.status)))
        issue_authored_root_writes_v3(candidate, altered,
                                     readout, policy, "root:one")


def test_blank_facet_rejects_external_or_interpretation_identity():
    with pytest.raises(ValueError, match="cannot claim"):
        RootAuthoredFacetV3("one", "feeling:base", "feeling", "facet:one",
                            "event:invented", None)
    candidate, _, _ = _candidate()
    with pytest.raises(ValueError, match="historical source"):
        replace(candidate, historical_source_refs=("source:invented",))
