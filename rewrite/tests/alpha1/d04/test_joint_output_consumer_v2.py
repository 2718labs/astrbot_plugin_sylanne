"""A V2 output consistency check keeps latent and normalized state distinct."""

from dataclasses import asdict, replace
import json
import struct

import pytest

from sylanne3.domains.d04.affect import _decode_feeling
from sylanne3.domains.d04.encoding_baseline import CommittedRef
from sylanne3.domains.d04.joint_state_output_v1 import (
    JointStateAxisOutputV1, JointStateOutputMemberV1, JointStateOutputOriginalV1,
    SCHEMA,
)
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS
from sylanne3.domains.d04.product_readout import (
    D04ReadoutHold, check_joint_output_against_snapshot_v2,
)
from sylanne3.domains.d04.root import encode_numeric_checkpoint
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot
from sylanne3.runtime_contracts import NamespaceId, canonical_digest

from .test_product_readout_candidate import _case


HASH = "a" * 64


def _case_with_output():
    prior, checkpoint_ref, _, _, _, _, read = _case()
    state_atom = read.snapshot.get(AtomKey.from_token(prior.graph_state.ref))
    previous_state = _decode_feeling(state_atom.value)
    representative = 0.9640275800758169
    axes = tuple(JointStateAxisOutputV1(
        axis, f"output:{axis}", representative, representative,
        representative, 0.0,
    ) for axis in REGISTERED_AXIS_IDS)
    state = replace(previous_state,
                    coordinates=tuple((axis, representative)
                                      for axis in REGISTERED_AXIS_IDS),
                    cursor=11.0, revision=previous_state.revision + 1)
    checkpoint = replace(
        prior, latent_state=(2.0,) * 24, certified_box=((2.0, 2.0),) * 24,
        numeric_error_bound=0.0, certificate_source="trusted_abi2",
        certificate_digest=HASH, cursor=11.0,
        graph_state=CommittedRef(prior.graph_state.ref, state.revision),
        readout_proof_digest=canonical_digest(axes),
        commit_operation_id="joint:operation", predecessor_kind="root",
        predecessor_receipt_digest=HASH,
    )
    member = JointStateOutputMemberV1(
        checkpoint_ref, 3, HASH, prior.graph_state.ref, previous_state.revision,
        HASH, "feeling", checkpoint, state, axes, 0.0,
    )
    checkpoint_value = encode_numeric_checkpoint(checkpoint)
    state_value = json.loads(json.dumps(asdict(state)))
    write_set = tuple(sorted((
        (checkpoint_ref, 4, checkpoint_value),
        (prior.graph_state.ref, state.revision, state_value),
    ), key=lambda row: row[0]))
    bits = [struct.pack("!d", value).hex() for value in checkpoint.latent_state]
    bits.extend(struct.pack("!d", bound).hex()
                for box in checkpoint.certified_box for bound in box)
    bits.extend((struct.pack("!d", checkpoint.numeric_error_bound).hex(),
                 struct.pack("!d", member.native_trajectory_error_2norm).hex()))
    for axis in axes:
        bits.extend(struct.pack("!d", value).hex() for value in (
            axis.certified_lower, axis.certified_upper,
            axis.representative, axis.representative_error,
        ))
    fields = dict(
        schema=SCHEMA, namespace=NamespaceId(*prior.namespace),
        operation_id=checkpoint.commit_operation_id, component_digest=HASH,
        graph_incarnation="incarnation:1", graph_revision=1, graph_epoch=1,
        access_epoch=1, delete_epoch=1, role_start=10.0, role_end=11.0,
        member_refs=(checkpoint_ref,), axis_ids=REGISTERED_AXIS_IDS,
        full_transcript_sha256=HASH, family_transcripts=(("family:one", HASH),),
        math_transcript_sha256=HASH, full_output_sha256=HASH,
        native_manifest_sha256=HASH, native_sha256=HASH, native_abi_version=2,
        policy_id="policy:1", policy_version="d04.joint-state-output.v1",
        policy_digest=HASH, policy_sha256=HASH,
        readout_id="readout:one", readout_version="readout:one",
        readout_sha256=HASH, native_trajectory_error_2norm=0.0,
        members=(member,), write_set_digest=canonical_digest(write_set),
        binary64_bits_digest=canonical_digest(tuple(bits)),
    )
    original = JointStateOutputOriginalV1(
        **fields, original_digest=canonical_digest(fields),
    )
    snapshot = GraphSnapshot((
        GraphAtom(AtomKey.from_token(checkpoint_ref), 4, checkpoint_value),
        GraphAtom(AtomKey.from_token(prior.graph_state.ref),
                  state.revision, state_value),
    ), ())
    return original, snapshot


def test_joint_output_consumer_accepts_distinct_latent_and_normalized_state():
    original, snapshot = _case_with_output()
    assert original.members[0].next_checkpoint.latent_state[0] == 2.0
    assert original.members[0].next_state.coordinates[0][1] < 1.0
    check_joint_output_against_snapshot_v2(original, snapshot)


def test_joint_output_consumer_rejects_missing_or_changed_original_state():
    original, snapshot = _case_with_output()
    with pytest.raises(TypeError):
        check_joint_output_against_snapshot_v2(None, snapshot)
    changed = replace(snapshot.atoms[1], value={
        **snapshot.atoms[1].value,
        "coordinates": [[REGISTERED_AXIS_IDS[0], 0.9]]
        + snapshot.atoms[1].value["coordinates"][1:],
    })
    with pytest.raises(D04ReadoutHold, match="differs"):
        check_joint_output_against_snapshot_v2(
            original, replace(snapshot, atoms=(snapshot.atoms[0], changed)),
        )
