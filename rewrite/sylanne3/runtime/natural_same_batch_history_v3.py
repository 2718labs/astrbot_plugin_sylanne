"""Read-only continuation proof for a complete paid natural batch.

Authority originals are collected before entering Graph SQL. This verifier
retains the original history bytes and admits only a fully proven own suffix.
It creates no call, permission, budget reservation or additional experience.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import json

from ..authority_service.v2_contract import FencePermitV2, MutationReceiptV2
from ..domains.d09.natural_reply import natural_semantic_ranges_v3, natural_segment_identity_v3
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest
from .natural_reply_job_v2 import read_original_preparation


@dataclass(frozen=True, slots=True)
class NaturalSameBatchPreparedV3:
    issuer: object
    namespace: NamespaceId
    parent_original_id: str
    frozen_digest: str
    permit: FencePermitV2
    observations: tuple[MutationReceiptV2, ...]


@dataclass(frozen=True, slots=True)
class NaturalReplyResumeWitnessV3:
    issuer: object
    namespace: NamespaceId
    parent_original_id: str
    generation_original_operation_id: str
    original_deadline_utc: float
    mode: str
    segment_index: int
    child_identities: tuple[tuple[str, str], ...]


def same_batch_observation_hints_v3(db, namespace, parent_original_id):
    """Content-free effect hints. They are never proof that a suffix is own."""
    from ..domains.d09.turn_order import turn_order_key, validate_turn_order_v1
    generation = read_original_preparation(db, namespace, parent_original_id, "generation")
    if generation is None or generation.seal.schema != "sylanne.d09.natural_generation_seal.v5":
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


def verify_same_batch_history_v3(db, *, issuer, prepared, namespace,
                               parent_original_id, frozen, now_utc, max_slots):
    """Compare a proven prefix projection, while returning current SQL reads.

    This content/paid-read entry requires every suffix child to be actually
    accepted or delivered. First-generation/model egress never calls it.
    """
    from ..domains.d09.turn_order import turn_order_key, turn_slot_key, validate_turn_slot_v1
    from ..domains.d09.natural_batch import validate_natural_verified_batch_value_v3
    from .d13_current_window import read_current_d13_window_for_authority_v1
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
    hints = same_batch_observation_hints_v3(db, namespace, parent_original_id)
    if hints is None or hints[0] != frozen or len(hints[2]) != len(prepared.observations):
        raise ValueError("same-batch original or actual suffix changed")
    generation = read_original_preparation(db, namespace, parent_original_id, "generation")
    review = read_original_preparation(db, namespace, parent_original_id, "review")
    if read_parent_stop_original_v3(db, namespace, generation) is not None:
        raise ValueError("same-batch parent was stopped by its actual Owner")
    selection, plan = frozen.input.history_selection, frozen.input.plan
    if prepared.permit.generation != selection.activation_generation:
        raise ValueError("same-batch activation changed")
    current = read_current_d13_window_for_authority_v1(db, namespace, plan.scene_id,
        plan.audience_id, max_slots, now_utc, before_sequence=selection.order_watermark + 1,
        expected_activation_generation=selection.activation_generation)
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
    if selection.block_ref is not None:
        ref = selection.block_ref
        reads[ref.ref] = GraphVersion(AtomKey.from_token(ref.ref), ref.version)
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


def read_parent_stop_original_v3(db, namespace, generation):
    """Actual Owner control/job-operation join; never trust a bare SQL marker."""
    from .lifecycle_operations_v1 import ControlCommandV1, OwnerOperationBindingV1, decode_original, digest
    from .jobs import _job_from_dict
    if not db.in_transaction:
        raise RuntimeError("parent reply stop needs a pinned Graph transaction")
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_d12_backend_operations_v1'").fetchone():
        return None
    row = db.execute(
        "SELECT j.operation_id,j.digest,j.job_json,o.request_digest,o.owner_json,o.input_json,"
        "r.original_digest,r.original_json FROM runtime_job_operations j "
        "JOIN graph_d12_backend_operations_v1 o ON o.bot=j.bot_id AND o.persona=j.persona_id "
        "AND o.operation_id=j.operation_id AND o.kind='control' "
        "JOIN graph_d12_backend_originals_v1 r ON r.bot=o.bot AND r.persona=o.persona "
        "AND r.original_ref=o.current_original_ref AND r.operation_id=o.operation_id "
        "WHERE j.bot_id=? AND j.persona_id=? AND j.phase='cancel' AND j.job_id=? "
        "ORDER BY j.operation_id LIMIT 1", (*namespace.as_tuple, generation.seal.job_id)).fetchone()
    if row is None:
        return None
    original = decode_original(json.loads(row[7]))
    command = ControlCommandV1.from_wire(json.loads(row[5]))
    owner_data = json.loads(row[4])
    owner_data["namespace"] = NamespaceId(**owner_data["namespace"])
    owner = OwnerOperationBindingV1(**owner_data)
    job = _job_from_dict(json.loads(row[2]))
    if (original.namespace != namespace or owner.namespace != namespace
            or original.operation_id != row[0] or original.kind != "control"
            or original.request_digest != row[3] or row[3] != "sha256:" + row[1]
            or original.original_digest != row[6]
            or (original.owner_grant_ref, original.owner_grant_revision, original.owner_grant_digest)
               != (owner.grant_ref, owner.grant_revision, owner.grant_digest)
            or original.activation_generation != owner.activation_generation
            or ("owner", owner.authority_ref, owner.authority_digest) not in original.authority_refs
            or command.object_ref != "job:" + generation.seal.job_id or command.control != "cancel_job"
            or command.config_diff or command.test_intent is not None
            or original.result.object_ref != command.object_ref or original.result.control != command.control
            or original.result.domain_receipt_refs != ("joboperation:" + row[0],)
            or ("persistent_job", command.object_ref, digest(job)) not in original.authority_refs
            or (job.bot_id, job.persona_id, job.job_id, job.operation_id, job.work_kind, job.budget_ref)
               != (*namespace.as_tuple, generation.seal.job_id, generation.seal.original_operation_id,
                   "natural_generation", generation.seal.parent_budget_lease_id)):
        raise ValueError("natural parent stop original binding differs")
    return original


def read_natural_roster_head_v1(db, namespace, parent_original_id):
    """Only persisted no-content roster; never reconstruct revoked review text."""
    from ..domains.d09.natural_disposition_v1 import TYPE, natural_disposition_from_wire_v1, natural_disposition_key_v1
    rows = db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name=? AND json_extract(value,'$.parent_original_id')=? LIMIT 2",
        (*namespace.as_tuple, TYPE, parent_original_id)).fetchall()
    if not rows:
        return None
    if len(rows) != 1 or rows[0][3] != 1:
        raise ValueError("natural disposition roster is retired or ambiguous")
    token, revision, raw, _ = rows[0]
    value = natural_disposition_from_wire_v1(json.loads(raw))
    key = natural_disposition_key_v1(value)
    if value.namespace != namespace or key.token != token or value.revision != revision:
        raise ValueError("natural disposition persisted key/revision differs")
    birth = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=1", (token,)).fetchone()
    if birth is None or birth[0] != value.creation_operation_id or birth[2] != 1:
        raise ValueError("natural disposition lacks its actual first final history")
    original = natural_disposition_from_wire_v1(json.loads(birth[1]))
    immutable = ("namespace", "installation_id", "parent_original_id", "activity_id", "generation_original_operation_id",
        "generation_original_digest", "review_original_operation_id", "review_original_digest", "whole_output_digest",
        "creation_operation_id", "identity_manifest_digest", "dependency_refs", "expires_at_utc", "birth_original_ref")
    if any(getattr(original, f) != getattr(value, f) for f in immutable):
        raise ValueError("natural disposition changed its adopted roster")
    # Select exact metadata fields, never the historical generated batch body.
    adopted = db.execute("SELECT activity_id,effect_id,receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, value.creation_operation_id)).fetchone()
    if adopted is None or adopted[:2] != (value.activity_id, value.children[0].effect_id):
        raise ValueError("natural disposition has no actual first child operation")
    candidate = json.loads(adopted[2]).get("natural_dispatch_candidate")
    if type(candidate) is not dict or len(candidate.get("refs", ())) != 4:
        raise ValueError("natural disposition lacks its actual paid admission candidate")
    batch_ref, batch_revision = candidate["refs"][3]
    member = db.execute("SELECT event_id,valid,"
        "json_extract(value,'$.paid_review.generation_original_operation_id'),"
        "json_extract(value,'$.paid_review.review_original_operation_id'),"
        "json_extract(value,'$.segment.payload_digest') "
        "FROM graph_history WHERE token=? AND revision=?", (batch_ref, batch_revision)).fetchone()
    if member != (value.creation_operation_id, 1, value.generation_original_operation_id,
            value.review_original_operation_id, value.children[0].payload_digest):
        raise ValueError("natural disposition first child metadata lineage differs")
    return key, revision, value


def require_natural_roster_continuation_v1(db, namespace, parent_original_id, segment_index):
    head = read_natural_roster_head_v1(db, namespace, parent_original_id)
    if head is None:
        return None  # Old admitted originals retain their existing strict qualification.
    child = head[2].children[segment_index]
    if child.continuation_state in {"cancelled", "superseded"}:
        raise ValueError("natural manifest continuation was durably stopped")
    return GraphVersion(head[0], head[1])


def close_unprepared_natural_parent_window_v1(graph, namespace, parent_original_id):
    """Observe an actual same-original window; errors never mean no submission."""
    from ..authority_service.natural_disposition_maintenance_v1 import NaturalUnpreparedWriteClosureRequestV1
    from ..runtime_contracts import FenceScope
    store,port=graph._GraphCoordinator__store,graph._GraphCoordinator__content_fence_v2
    with store._lock:
        db=store._db
        metadata,epoch=graph._v2_graph_stamp(namespace)
        table="graph_natural_generation_preparations_v2"
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() is None:
            return {"status":"bubble_details_unavailable"}
        row=db.execute("SELECT json_extract(frozen_json,'$.input.plan.final_operation_id') FROM "+table+
            " WHERE bot=? AND persona=? AND parent_original_id=?",(*namespace.as_tuple,parent_original_id)).fetchone()
        if row is None or type(row[0]) is not str:
            return {"status":"bubble_details_unavailable"}
    target=metadata.requirements;operation=row[0]
    identity=port.read_natural_current_graph_identity_v1(namespace=namespace,authority_namespace=target.authority_namespace)
    anchor=port.current_anchor(namespace=namespace,authority_namespace=target.authority_namespace)
    attempt="natural-final:"+canonical_digest({"namespace":namespace.as_tuple,"operation_id":operation})[:48]
    observed=port.observe_content_write_attempt_v1(namespace=namespace,authority_namespace=target.authority_namespace,
        operation_id=attempt,expected_anchor=anchor)
    if observed.state!="active":
        return {"status":"original_window_"+observed.state}
    permit=observed.permit
    scope=FenceScope(namespace,target.authority_namespace,permit.generation,"write",attempt,permit,permit.pinned_anchor,epoch,metadata.graph_revision)
    request=NaturalUnpreparedWriteClosureRequestV1(namespace,identity.installation_id,operation,metadata.graph_revision,
        epoch.revision,identity.graph_incarnation,identity.storage_commitment,"roster")
    terminal=port.reject_natural_unprepared_write_v1(scope=scope,request=request)
    return {"status":"original_window_closed","original_ref":terminal.original_ref,"kind":terminal.kind}


def commit_natural_disposition_maintenance_v1(graph, bootstrap, namespace, parent_original_id):
    """Adopt only an installed Authority's exact no-content D09 continuation CAS."""
    from .first_ingress_v2 import trusted_upper
    from ..authority_service.natural_disposition_maintenance_v1 import NaturalDispositionMaintenanceObservedV1
    from ..contracts import Event, Scope
    from ..graph_store import GraphStore, ProductionGraphStore
    from ..graph_types import GraphCandidate, NamespaceEpoch
    from ..runtime_contracts import FenceScope
    from ..domains.d09.natural_disposition_v1 import natural_disposition_write_v1
    graph._admin(bootstrap)
    store,port=graph._GraphCoordinator__store,graph._GraphCoordinator__content_fence_v2
    if not isinstance(store,ProductionGraphStore) or port is None:
        raise RuntimeError("actual installed natural metadata maintenance dependencies unavailable")
    with store._lock:
        db=store._db;db.execute("BEGIN")
        try:
            metadata,epoch=graph._v2_graph_stamp(namespace)
            head=read_natural_roster_head_v1(db,namespace,parent_original_id)
            db.commit()
        except BaseException:
            db.rollback();raise
    if head is None:
        return close_unprepared_natural_parent_window_v1(graph,namespace,parent_original_id)
    target=metadata.requirements
    from ..authority_service.v2_contract import from_wire
    # A committed Graph revision can finish its original Core confirmation after a lost ACK.
    prepared=port.read_natural_disposition_original_v1(namespace=namespace,
        authority_namespace=target.authority_namespace,original_ref=head[2].authority_original_ref)
    if prepared.kind not in {"roster_prepared","maintenance_prepared"} or prepared.payload["expected_next_value"]!=head[2].to_wire():
        raise ValueError("natural metadata head lacks its exact independent Core preparation")
    old_permit=from_wire(prepared.payload["permit"])
    old_scope=FenceScope(namespace,target.authority_namespace,old_permit.generation,"write",old_permit.operation_id,
        old_permit,old_permit.pinned_anchor,NamespaceEpoch(*namespace.as_tuple,prepared.payload["graph_epoch"]),prepared.payload["graph_revision"])
    port.confirm_natural_disposition_original_v1(scope=old_scope,original_ref=prepared.original_ref)
    known,state=port.get_fence_operation(namespace=namespace,authority_namespace=target.authority_namespace,operation_id=old_permit.operation_id)
    if known!=old_permit:
        raise ValueError("natural metadata original Core permit changed")
    if state=="active":
        if prepared.kind=="roster_prepared":
            digest="sha256:"+canonical_digest({"action":"finish_natural_final","attempt_id":old_permit.operation_id,"permit_token":old_permit.token})
        else:
            digest="sha256:"+canonical_digest(("natural_disposition_finish.v1",prepared.operation_id,old_permit.token,prepared.digest))
        port.finish_fence(old_scope,request_id="finish:"+old_permit.operation_id,request_digest=digest)
    plan=port.plan_natural_disposition_maintenance_v1(namespace=namespace,
        authority_namespace=target.authority_namespace,parent_original_id=parent_original_id)
    if plan is None:
        return {"status":"manifest_not_adopted"}
    if not plan.changed:
        return {"status":"unchanged","roster_ref":plan.request.roster_ref}
    identity=port.read_natural_current_graph_identity_v1(namespace=namespace,authority_namespace=target.authority_namespace)
    if identity.storage_commitment!=plan.storage_commitment:
        raise ValueError("natural metadata writer lost its actual current C09 identity")
    from .natural_disposition_write_barrier_v1 import natural_graph_barrier_for_store_v1
    with natural_graph_barrier_for_store_v1(store,identity):
        if (plan.graph_revision!=metadata.graph_revision or plan.graph_epoch!=epoch.revision
                or plan.request.expected_revision!=head[1]
                or not graph._accounting_anchor_covers(target,plan.anchor)):
            raise ValueError("natural metadata maintenance current C09/Graph stamp changed")
        op=plan.request.operation_id
        try:
            permit,state=port.get_fence_operation(namespace=namespace,authority_namespace=target.authority_namespace,operation_id=op)
        except Exception:
            permit=port.begin_fence(namespace=namespace,authority_namespace=target.authority_namespace,
                holder=graph._GraphCoordinator__holder,generation=target.activation_generation,
                operation="write",operation_id=op,expected_anchor=plan.anchor,retain_on_unknown=True)
            state="active"
        if state!="active" or permit.pinned_anchor!=plan.anchor:
            raise ValueError("natural metadata maintenance original write fence is unavailable")
        scope=FenceScope(namespace,target.authority_namespace,target.activation_generation,"write",op,
            permit,plan.anchor,epoch,metadata.graph_revision)
        if port.validate_fence(scope)!=permit:
            raise ValueError("natural metadata maintenance write fence changed")
        observed=port.observe_natural_disposition_maintenance_v1(scope=scope,request=plan.request)
        if (type(observed) is not NaturalDispositionMaintenanceObservedV1 or observed.permit!=permit
                or observed.plan.request!=plan.request or observed.plan.next_value!=plan.next_value):
            raise ValueError("natural metadata maintenance lacks its exact installed private witness")
        if observed.original.payload["storage_commitment"]!=identity.storage_commitment:
            raise ValueError("natural metadata observer changed the held actual C09 inode")
        write=natural_disposition_write_v1(observed.plan.next_value)
        if write.key.token!=plan.request.roster_ref or canonical_digest(write.value)!=plan.request.next_payload_digest:
            raise ValueError("natural metadata maintenance exact one-key payload differs")
        now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
        finish_digest="sha256:"+canonical_digest(("natural_disposition_finish.v1",op,permit.token,observed.original.digest))
        rejected=None
        with store._lock:
            db.execute("BEGIN IMMEDIATE")
            try:
                if graph._v2_graph_stamp(namespace)!=(metadata,epoch):
                    raise ValueError("natural metadata maintenance Graph changed before its CAS")
                current=read_natural_roster_head_v1(db,namespace,parent_original_id)
                if current is None or current[:2]!=(head[0],head[1]) or current[2]!=head[2]:
                    raise ValueError("natural metadata maintenance actual roster changed before CAS")
                receipt=GraphStore._graph_commit_in_transaction(store,GraphCandidate(
                    Event(Scope(*namespace.as_tuple,head[2].activity_id),op,now,"d09.natural_disposition_maintenance",
                        {"observation_digest":plan.observation_digest,"roster_ref":write.key.token}),
                    observed.plan.read_versions,(write,),(epoch,)),_capability=graph._GraphCoordinator__graph_capability)
                if receipt.status!="committed":
                    raise ValueError("natural metadata maintenance one-key CAS did not commit")
                store.cas_graph_recovery_metadata(metadata,replace(target,
                    execution_seq=plan.anchor.execution_seq,execution_digest=plan.anchor.execution_digest),
                    _capability=graph._GraphCoordinator__graph_capability)
                db.commit()
            except (ValueError,TypeError) as exc:
                db.rollback(); rejected=exc
            except BaseException:
                db.rollback(); raise
    if rejected is not None:
        # This branch proved the same local transaction rolled back. SQL or transport
        # uncertainty above retains the actual original fence instead of guessing.
        with store._lock:
            if db.in_transaction or graph._v2_graph_stamp(namespace)!=(metadata,epoch):
                raise rejected
        port.reject_natural_disposition_no_commit_v1(scope=scope,original_ref=observed.original.original_ref)
        raise rejected
    port.confirm_natural_disposition_original_v1(scope=scope,original_ref=observed.original.original_ref)
    port.finish_fence(scope,request_id="finish:"+op,request_digest=finish_digest)
    return {"status":"committed","roster_ref":write.key.token,"operation_id":op}
