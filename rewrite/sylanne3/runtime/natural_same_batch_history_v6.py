"""Readonly complete paid v6 batch continuation over its immutable multi-page prefix."""
from dataclasses import replace
import json
from ..authority_service.v2_contract import FencePermitV2,MutationReceiptV2
from ..domains.d09.natural_reply import natural_semantic_ranges_v3,natural_segment_identity_v3
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import canonical_digest
from .natural_reply_job_v2 import read_original_preparation
from .natural_same_batch_history_v3 import (NaturalSameBatchPreparedV3,read_parent_stop_original_v3,
    read_natural_roster_head_v1)

def same_batch_observation_hints_v6(db, namespace, parent_original_id):
    """Content-free effect hints. They are never proof that a suffix is own."""
    from ..domains.d09.turn_order import turn_order_key, validate_turn_order_v1
    generation = read_original_preparation(db, namespace, parent_original_id, "generation")
    if generation is None or generation.seal.schema != "sylanne.d09.natural_generation_seal.v6":
        return None
    review = read_original_preparation(db, namespace, parent_original_id, "review")
    if review is None or review.state != "terminal":
        return None
    data = json.loads(review.frozen.canonical_input)
    output = {"schema": data["generation_output_schema"], "body": data["body"],
              "units": data["units"], "semantic_segments": data["semantic_segments"]}
    if canonical_digest(output) != generation.terminal_output_digest:
        raise ValueError("same-batch whole paid output differs")
    count = len(natural_semantic_ranges_v3(output))
    frozen, plan = generation.frozen, generation.frozen.input.plan
    key = turn_order_key(namespace, plan.scene_id, plan.audience_id)
    row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
    if row is None or row[1] != 1:
        raise ValueError("same-batch current order is absent")
    order = json.loads(row[0])
    validate_turn_order_v1(order)
    suffix = order["high_watermark"] - frozen.input.history_selection.order_watermark
    if not 0 <= suffix <= count <= 4:
        raise ValueError("same-batch current suffix exceeds the complete manifest")
    return frozen, output, tuple(natural_segment_identity_v3(plan, output, index)[:2]
                                 for index in range(suffix))


def verify_same_batch_history_v6(db, *, issuer, prepared, namespace,
                               parent_original_id, frozen, now_utc, max_slots):
    """Compare a proven prefix projection, while returning current SQL reads.

    This content/paid-read entry requires every suffix child to be actually
    accepted or delivered. First-generation/model egress never calls it.
    """
    from ..domains.d09.turn_order import turn_order_key, turn_slot_key, validate_turn_slot_v1
    from ..domains.d09.natural_batch import validate_natural_verified_batch_value_v3
    from .d13_current_collection_v6 import read_current_d13_collection_v6
    from .dispatch_graph_claim import dispatch_claim_key, dispatch_claim_type_spec
    from .dispatch_admission import load_admission
    from .natural_dispatch_current_read_v2 import recover_natural_dispatch_candidate_in_transaction_v2
    from .ingress_observation import read_committed_ingress_identity
    if (type(prepared) is not NaturalSameBatchPreparedV3 or prepared.issuer is not issuer
            or prepared.namespace != namespace or prepared.parent_original_id != parent_original_id
            or prepared.frozen_digest != canonical_digest(frozen)
            or type(prepared.permit) is not FencePermitV2 or prepared.permit.operation != "read"
            or type(prepared.observations) is not tuple or len(prepared.observations) > 4
            or now_utc >= frozen.input.expires_at_utc):
        raise ValueError("qualified same-batch prepared original is unavailable")
    hints = same_batch_observation_hints_v6(db, namespace, parent_original_id)
    if hints is None or hints[0] != frozen or len(hints[2]) != len(prepared.observations):
        raise ValueError("same-batch original or actual suffix changed")
    generation = read_original_preparation(db, namespace, parent_original_id, "generation")
    review = read_original_preparation(db, namespace, parent_original_id, "review")
    if read_parent_stop_original_v3(db, namespace, generation) is not None:
        raise ValueError("same-batch parent was stopped by its actual Owner")
    selection, plan = frozen.input.history_selection, frozen.input.plan
    if prepared.permit.generation != selection.activation_generation:
        raise ValueError("same-batch activation changed")
    current = read_current_d13_collection_v6(db,namespace,plan.scene_id,plan.audience_id,now_utc,
        max_slots=max_slots,before_sequence=selection.order_watermark+1,
        expected_activation_generation=selection.activation_generation).window
    order_key = turn_order_key(namespace, plan.scene_id, plan.audience_id)
    old_reads = {ref.ref: ref for ref in selection.read_set}
    order_ref = old_reads.get(order_key.token)
    if order_ref is None:
        raise ValueError("same-batch original order head is missing")
    history = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
                         (order_ref.ref, order_ref.version)).fetchone()
    if (history is None or history[1] != 1
            or json.loads(history[0])["high_watermark"] != selection.order_watermark):
        raise ValueError("same-batch original order history differs")
    for ref in selection.read_set:
        if ref.ref == order_ref.ref:
            continue
        head = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?", (ref.ref,)).fetchone()
        if ((ref.version == 0 and head is not None)
                or ref.version > 0 and head != (ref.version, 1)):
            raise ValueError("same-batch baseline source, rights, cache or slot changed")
    projected_reads = tuple(order_ref if ref.ref == order_ref.ref else ref for ref in current.read_set)
    projected_gaps = tuple((start, min(end, selection.order_watermark))
                           for start, end in current.missing_ranges if start <= selection.order_watermark)
    projected = replace(current, trusted_utc=frozen.input.frozen_at_utc,
                        order_watermark=selection.order_watermark,
                        read_set=projected_reads, missing_ranges=projected_gaps)
    if canonical_digest(projected) != selection.window_digest:
        raise ValueError("same-batch original prefix changed or a gap was filled")
    reads = {ref.ref: GraphVersion(AtomKey.from_token(ref.ref), ref.version) for ref in current.read_set}
    roster = read_natural_roster_head_v1(db, namespace, parent_original_id)
    if roster is not None:
        if any(child.continuation_state in {"cancelled", "superseded"} for child in roster[2].children):
            raise ValueError("same-batch remaining manifest was durably stopped")
        reads[roster[0].token] = GraphVersion(roster[0], roster[1])
    for ref in selection.block_refs:
        reads[ref.ref] = GraphVersion(AtomKey.from_token(ref.ref),ref.version)
    for index, ((operation_id, effect_id), observed) in enumerate(zip(hints[2], prepared.observations)):
        if (type(observed) is not MutationReceiptV2 or observed.durable_state != "committed"
                or observed.pending.phase != "observed"
                or observed.pending.platform_observation is None):
            raise ValueError("same-batch independent Authority observation is unavailable")
        observation = observed.pending.platform_observation
        origin = observation.binding.origin
        if (observation.outcome not in {"accepted", "delivered"}
                or origin.operation_id != operation_id or origin.effect_id != effect_id
                or observed.pending.permit.namespace != prepared.permit.namespace
                or observed.pending.permit.generation != selection.activation_generation):
            raise ValueError("same-batch preceding effect is UNKNOWN or belongs elsewhere")
        recovered = recover_natural_dispatch_candidate_in_transaction_v2(db, namespace, operation_id)
        if (recovered is None or recovered.evidence.effect_id != effect_id
                or recovered.evidence.generation_original_operation_id != generation.seal.original_operation_id
                or recovered.evidence.review_original_operation_id != review.seal.original_operation_id):
            raise ValueError("same-batch child paid lineage differs")
        admission = load_admission(db, namespace, origin.admission_ref)
        if (admission is None or admission.admission.operation_id != operation_id
                or admission.admission.effect_id != effect_id
                or admission.admission.payload_digest != recovered.evidence.payload_digest):
            raise ValueError("same-batch original admission differs")
        batch_key = AtomKey.from_token(recovered.evidence.batch_ref)
        batch = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (batch_key.token,)).fetchone()
        if batch is None or batch[2] != 1:
            raise ValueError("same-batch child manifest is unavailable")
        value = json.loads(batch[1])
        validate_natural_verified_batch_value_v3(value)
        if (value["semantic_manifest"]["selected_index"] != index
                or value["semantic_manifest"]["generation_output"] != hints[1]):
            raise ValueError("same-batch whole output or child ordinal differs")
        claim_key = dispatch_claim_key(namespace, effect_id)
        claim = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (claim_key.token,)).fetchone()
        if claim is None or claim[0] != 1 or claim[2] != 1:
            raise ValueError("same-batch actual P2 Graph claim is absent")
        claim_value = json.loads(claim[1])
        dispatch_claim_type_spec().validator(claim_value)
        if (claim_value["operation_id"] != operation_id or claim_value["effect_id"] != effect_id
                or claim_value["admission_ref"] != origin.admission_ref):
            raise ValueError("same-batch actual P2 claim differs")
        outboxes = db.execute("SELECT outbox_ref FROM graph_outbox_jobs WHERE bot=? AND persona=? AND operation_id=?",
                              (*namespace.as_tuple, operation_id)).fetchall()
        if len(outboxes) != 1:
            raise ValueError("same-batch actual outbox is ambiguous")
        slot_key = turn_slot_key(namespace, plan.scene_id, plan.audience_id, selection.order_watermark + index + 1)
        slot = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (slot_key.token,)).fetchone()
        if slot is None or slot[2] != 1:
            raise ValueError("same-batch outbound slot is absent")
        slot_value = json.loads(slot[1])
        validate_turn_slot_v1(slot_value)
        if (slot_value["direction"] != "outbound" or slot_value["origin_ref"] != outboxes[0][0]
                or slot_value["scene_ref"] != plan.scene_id or slot_value["conversation_ref"] != plan.audience_id):
            raise ValueError("same-batch suffix has an unrelated inbound or outbound")
        for key, version in ((batch_key, batch[0]), (claim_key, claim[0]), (slot_key, slot[0])):
            reads[key.token] = GraphVersion(key, version)
    new_ingress = db.execute(
        "SELECT i.source_ref FROM graph_first_ingress_identity_v1 i JOIN graph_events e "
        "ON e.bot=i.bot AND e.persona=i.persona AND e.event_id=i.operation_id "
        "WHERE i.bot=? AND i.persona=? AND i.conversation_ref=? AND e.epoch_revision>? LIMIT 1",
        (*namespace.as_tuple, plan.audience_id, generation.graph_epoch)).fetchone()
    if new_ingress is not None:
        if read_committed_ingress_identity(db, namespace, new_ingress[0]) is None:
            raise ValueError("same-batch relevant ingress original is unqualified")
        raise ValueError("same-batch has a newer committed relevant ingress")
    return tuple(reads[key] for key in sorted(reads))
