"""C04 V3 wire identity and source-specific evidence linkage."""

from dataclasses import replace
import json

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.memory_association import ActivationPolicy
from sylanne3.memory_types import source_key
from sylanne3.runtime.c04_v3_contracts import (
    ALGORITHM_ID_V3, AssociationBudgetV3, AssociationPageV3,
    AssociationScoreV3, AssociationTargetV3, AssociationWorkInputV3,
    AssociationWorkResultV3, C04AdoptionPlanV3, C04AdoptionReceiptV3,
    D04CurrentConditionedSalienceOriginalV3, D04EncodingBaselineOriginalV3,
    ExactRefV3, GraphHeadV3, ProjectionMemberV3, ProjectionNumericErrorV3,
    PlannedWriteV3, canonical_v3_digest, decode_v3, encode_v3,
)
from sylanne3.runtime_contracts import NamespaceId
from tests.alpha1.d06.test_c04_work_input_v2 import _input as valid_v2_graph_fixture


NS = NamespaceId("bot", "persona")
D = "sha256:" + "a" * 64
S = "a" * 64
ERROR = ProjectionNumericErrorV3(0.001, 0.002, 0.003, 0.004, D)
PERSONA = Owner("persona", *NS.as_tuple)


def key(kind: str, name: str) -> str:
    return AtomKey(PERSONA, kind, name).token


def baseline(source: str) -> D04EncodingBaselineOriginalV3:
    members = (ProjectionMemberV3(
        ExactRefV3(key("d04.feeling_state.v1", "member"), 4),
        ExactRefV3(key("d04.numeric_checkpoint.v1", "member"), 4)),)
    return D04EncodingBaselineOriginalV3(
        namespace=NS, encoding_operation_id="encoding", source=ExactRefV3(source, 1),
        perspective=ExactRefV3(key("d03.self_perspective.v1", "self"), 2),
        interpretations=(ExactRefV3(key("d07.current_interpretation.v1", "i"), 3),),
        members=members, member_set_digest=canonical_v3_digest(members),
        joint_adoption_receipt_digest=D, joint_numeric_original_digest=D,
        joint_output_original_digest=D, policy_digest=D, readout_sha256=S,
        native_manifest_sha256=S, native_sha256=S, owner_epoch=3,
        access_epoch=2, delete_epoch=1, salience_interval=(0.2, 0.4),
        tone_interval=(-0.2, 0.1), numeric_error=ERROR, proof_digest=D,
    )


def target(source: str) -> AssociationTargetV3:
    base = baseline(source)
    condition = D04CurrentConditionedSalienceOriginalV3(
        namespace=NS, operation_id="op", source_ref=source,
        baseline_digest=base.digest,
        current_mood=ExactRefV3(key("d04.mood_field.v1", "primary"), 4),
        current_checkpoint=ExactRefV3(key("d04.numeric_checkpoint.v1", "mood"), 5),
        current_joint_adoption_receipt_digest=D,
        current_joint_numeric_original_digest=D,
        current_joint_output_original_digest=D, source_closure_digest=D,
        audience="self", purpose="context", owner_epoch=3, access_epoch=2,
        delete_epoch=1, policy_digest=D, readout_sha256=S, native_sha256=S,
        base_salience_interval=base.salience_interval,
        conditioned_salience_interval=(0.4, 0.6),
        base_tone_interval=base.tone_interval,
        conditioned_tone_interval=(-0.1, 0.2), numeric_error=ERROR,
        baseline_proof_digest=D, conditioning_proof_digest=D,
    )
    return AssociationTargetV3(source, base, condition)


def work() -> AssociationWorkInputV3:
    graph = valid_v2_graph_fixture()
    cue = graph.cue_source_ref
    other = source_key(*NS.as_tuple, "target").token
    reads = tuple(sorted((GraphHeadV3(row.key.token, row.revision,
                                     row.valid, row.value_json) for row in graph.reads),
                         key=lambda row: row.ref))
    return AssociationWorkInputV3(
        namespace=NS, activity_id="activity", operation_id="op",
        cue_source_ref=cue, focus_ref=graph.focus_ref,
        attention_ticket_ref=graph.attention_ticket_ref, mood_ref=graph.mood_ref,
        selection_ticket=graph.selection_ticket,
        selection_ticket_digest=canonical_v3_digest(graph.selection_ticket),
        audience="self", purpose="context", context_tags=("now",), reads=reads,
        edge_pages=tuple(sorted((AssociationPageV3(page.source_ref, page.hop,
                                                   page.edge_refs, page.next_after)
                                 for page in graph.edge_queries),
                                key=lambda page: page.source_ref)),
        budget=AssociationBudgetV3(2, 128, 128, 32, 32),
        policy=ActivationPolicy(0.5, 0.25, 32, 128, 1e-6),
        graph_epoch=9, owner_epoch=3, access_epoch=2, delete_epoch=1,
        truncated=False, algorithm_id=ALGORITHM_ID_V3, algorithm_build_digest=D,
        targets=tuple(sorted((target(cue), target(other)),
                             key=lambda item: item.source_ref)),
    )


def test_v3_round_trip_and_cross_stage_digests() -> None:
    frozen = work()
    assert AssociationWorkInputV3.from_json(frozen.to_json()) == frozen
    other = next(item for item in frozen.targets if item.source_ref != frozen.cue_source_ref)
    result = AssociationWorkResultV3(
        NS, "op", frozen.input_digest, ALGORITHM_ID_V3, D,
        (AssociationScoreV3(other.source_ref, 0.5, 0.5, 0.25,
                            other.condition.digest),),
        2, 0, 1, False, "converged",
    )
    assert AssociationWorkResultV3.from_json(result.to_json()) == result
    result.validate_input(frozen)
    refs = tuple(sorted(key(kind, "op") for kind in (
        "d04.recollection_experience.v1", "memory.recollection.v1",
        "memory.projection.v1", "d07.final_selection.v1",
        "d07.current_interpretation.v1")))
    writes = tuple(PlannedWriteV3(ref, D) for ref in refs)
    write_digest = canonical_v3_digest(writes)
    plan = C04AdoptionPlanV3(NS, "op", frozen.input_digest, result.result_digest,
                             D, D, D, D, D, D, 3, 2, 1, D, writes, write_digest)
    receipt = C04AdoptionReceiptV3(NS, "op", plan.plan_digest,
                                    frozen.input_digest, result.result_digest,
                                    write_digest, 10)
    assert C04AdoptionPlanV3.from_json(plan.to_json()) == plan
    assert C04AdoptionReceiptV3.from_json(receipt.to_json()) == receipt
    receipt.validate_plan(plan)


def test_wrong_target_original_and_old_or_noncanonical_wire_rejected() -> None:
    frozen = work()
    wrong = replace(frozen.targets[0].condition, source_ref=frozen.targets[1].source_ref)
    with pytest.raises(ValueError):
        replace(frozen.targets[0], condition=wrong)
    with pytest.raises(ValueError):
        decode_v3(canonical_json({"algorithm_id": "d06.association_activation.v2"}),
                  AssociationWorkInputV3)
    with pytest.raises(ValueError):
        AssociationWorkInputV3.from_json(frozen.to_json() + " ")
    payload = json.loads(frozen.to_json())
    payload["unknown"] = True
    with pytest.raises(ValueError):
        AssociationWorkInputV3.from_json(canonical_json(payload))
    assert encode_v3(frozen) == frozen.to_json()
