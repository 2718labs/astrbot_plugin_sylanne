"""W01 adoption of independently read D11 outbound observations.

Accepted and unknown sends remain incomplete. Only an actual delivered
observation can create a confirmed D13 turn; peer-read remains unknown.
"""
from __future__ import annotations

from dataclasses import replace
from weakref import WeakKeyDictionary
from contextlib import nullcontext
from datetime import datetime
import json

from ..authority_service.v2_contract import MutationReceiptV2, PlatformObservationV2
from ..authority_service.observation_refinement_contract_v3 import (
    PlatformObservationRefinementReceiptV3, to_wire, from_wire, observation_original_dispatch_permit_v3,
    observation_platform_observation_v3, observation_effect_id_v3, observation_receipt_digest_v3)
from ..contracts import Event, Scope
from ..domains.d06 import D06DomainAdapter, SourceAdmission
from ..domains.d09.natural_batch import validate_natural_verified_batch_value
from ..domains.d09.turn_order import (
    reserve_turn_slot_v1, turn_order_key, observe_outbound_turn_v1,
    complete_outbound_turn_v1, validate_turn_completion_v1, turn_outbound_observation_key,
)
from ..graph_store import GraphStore
from ..graph_types import AtomKey, GraphAtom, GraphCandidate, GraphVersion, GraphWrite, NamespaceEpoch
from ..memory_types import SourceRecord, source_key, access_key, validate_access
from ..runtime_contracts import CompletedTurnV1, FenceScope, VersionedRef, canonical_digest, canonical_serialize
from .d11_types import RuntimeOutboxValue, outbox_graph_write, reconcile_runtime_write
from .natural_dispatch_current_read_v2 import recover_natural_dispatch_candidate_in_transaction_v2

TABLE = "graph_d13_outbound_observations_v1"


def install_d13_outbound_schema_v1(db):
    db.execute(f"""CREATE TABLE IF NOT EXISTS {TABLE} (
        bot TEXT NOT NULL, persona TEXT NOT NULL, final_operation_id TEXT NOT NULL,
        observation_digest TEXT NOT NULL, source_ref TEXT NOT NULL, slot_ref TEXT NOT NULL, batch_ref TEXT NOT NULL,
        observation_json TEXT NOT NULL, original_json TEXT NOT NULL,
        original_digest TEXT NOT NULL, PRIMARY KEY(bot,persona,final_operation_id,observation_digest))""")
    for action in ("UPDATE", "DELETE"):
        db.execute(f"CREATE TRIGGER IF NOT EXISTS {TABLE}_no_{action.lower()} "
            f"BEFORE {action} ON {TABLE} BEGIN SELECT RAISE(ABORT,'immutable D13 outbound original'); END")


def _atom(db, namespace, key):
    from .artifact_outbound_receipt_adoption_read_v3 import current_bound_artifact_outbound_receipt_adoption_v3
    artifact = current_bound_artifact_outbound_receipt_adoption_v3(db, namespace)
    if artifact is not None:
        atom = artifact.atom_v3(key)
        if not atom.valid or atom.revision < 1:
            raise ValueError('actual Artifact outbound selected atom is absent or invalid')
        return atom
    from .natural_outbound_receipt_adoption_read_v3 import current_bound_natural_outbound_receipt_adoption_v3
    proof=current_bound_natural_outbound_receipt_adoption_v3(db,namespace)
    if proof is not None:
        atom=proof.atom_v3(key)
        if not atom.valid or atom.revision<1:raise ValueError('actual outbound selected atom is absent or invalid')
        return atom
    from .d08_commitment_dispatch_read_v1 import current_named_dispatch_atom_v1
    named=current_named_dispatch_atom_v1(db,namespace,key)
    if named is not None:return named
    from .d13_paid_original_read_v3 import d13_paid_current_reader_v3
    paid=d13_paid_current_reader_v3(db)
    if paid is not None:
        if paid.namespace!=namespace:raise ValueError('D13 paid outbound atom crossed namespace')
        atom=paid.window_atom_v3(key)
        if not atom.valid:raise ValueError('D13 paid current outbound atom unavailable')
        return atom
    from ..authority_service.current_authority_graph_read_v3 import (
        _authority_attachment_owner_v3,authority_collection_source_atom_v6)
    work=_authority_attachment_owner_v3(db)
    if work is not None:
        if work.namespace!=namespace:raise ValueError('Authority outbound atom crossed namespace')
        if key.type_name=='memory.source':
            root=work.collection_record.get('source_ref')if work.collection_record is not None else None
            material=work.collection_source_materials.get(root)
            if material is None:raise ValueError('Authority outbound Source lacks its current record body EOF')
            return authority_collection_source_atom_v6(work,material,key.token)
        atom=work.projection.get(key)
        if not atom.valid:raise ValueError('current Authority outbound dependency unavailable')
        return atom
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                     (key.token, *namespace.as_tuple)).fetchone()
    if row is None or row[2] != 1:
        raise ValueError("current outbound source dependency unavailable")
    return GraphAtom(key, row[0], json.loads(row[1]), True)


def _recover_outbound_dispatch_v1(db, namespace, final_operation_id):
    from .artifact_outbound_receipt_adoption_read_v3 import current_bound_artifact_outbound_receipt_adoption_v3
    artifact = current_bound_artifact_outbound_receipt_adoption_v3(db, namespace, final_operation_id)
    if artifact is not None:
        return artifact.recovered
    from .natural_outbound_receipt_adoption_read_v3 import current_bound_natural_outbound_receipt_adoption_v3
    proof=current_bound_natural_outbound_receipt_adoption_v3(db,namespace,final_operation_id)
    if proof is not None:return proof.recovered
    from .d08_commitment_dispatch_read_v1 import current_named_dispatch_recovery_v1
    named=current_named_dispatch_recovery_v1(db,namespace,final_operation_id)
    if named is not None:return named
    if final_operation_id.startswith('artifact-receipt-message:'):
        from .artifact_receipt_dispatch_v1 import recover_artifact_receipt_dispatch_candidate_in_transaction_v1
        return recover_artifact_receipt_dispatch_candidate_in_transaction_v1(db,namespace,final_operation_id)
    return recover_natural_dispatch_candidate_in_transaction_v2(db,namespace,final_operation_id)



def _outbound_route_v1(batch):
    if batch.key.type_name=='d09.verified_segment_batch.v1':
        audiences=batch.value['audiences']
        if type(audiences) is not list or len(audiences)!=1:
            raise ValueError('Artifact receipt outbound requires its one actual audience')
        return batch.value['scene_ref'],audiences[0]
    if batch.key.type_name in {'d09.natural_verified_segment_batch.v2','d09.natural_verified_segment_batch.v3'}:
        return batch.value['scene_id'],batch.value['audience_id']
    raise ValueError('unregistered actual outbound batch type')


def reserve_natural_outbound_slot_at_claim_v1(db, namespace, final_operation_id):
    """Reserve order atomically with P2 Graph claim, before any Host send.

    Unknown/missing observations leave an explicit ordered gap. Recovery must
    not assign an old message a newer sequence after intervening user turns.
    """
    from .d08_commitment_dispatch_read_v1 import current_named_outbound_reservation_v1
    named=current_named_outbound_reservation_v1(db,namespace,final_operation_id)
    if named is not None:return named
    recovered = _recover_outbound_dispatch_v1(db, namespace, final_operation_id)
    if recovered is None:
        return (), ()  # A non-natural dispatch has its own domain ordering.
    batch = _atom(db, namespace, AtomKey.from_token(recovered.evidence.batch_ref))
    rows = db.execute("SELECT outbox_ref FROM graph_outbox_jobs WHERE bot=? AND persona=? AND operation_id=?",
                      (*namespace.as_tuple, final_operation_id)).fetchall()
    if len(rows) != 1:
        raise ValueError("natural P2 claim requires one original outbox")
    origin = rows[0][0]
    if db.execute("SELECT 1 FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d09.turn_slot.v1' "
            "AND json_extract(value,'$.origin_ref')=?", (*namespace.as_tuple, origin)).fetchone():
        raise ValueError("natural outbox turn was reserved without this original P2 claim")
    scene, conversation = _outbound_route_v1(batch)
    key = turn_order_key(namespace, scene, conversation)
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
    order = None if row is None else GraphAtom(key, row[0], json.loads(row[1]), bool(row[2]))
    result = reserve_turn_slot_v1(namespace, scene, conversation, "outbound", origin, current_order=order)
    return result.writes, (GraphVersion(key, 0 if order is None else order.revision),
                          GraphVersion(result.absent_slot, 0), GraphVersion(batch.key, batch.revision))

def outbound_source_inspection_write_v1(namespace, final_operation_id, observed, source, read_versions):
    """Project only this actual first outbound Source before its GraphCandidate commit."""
    from hashlib import sha256
    from ..contracts import canonical_json
    from ..domains.d06.inspection_metadata_v1 import (
        SOURCE_TYPE, SOURCE_FIELDS, inspection_key_v1, validate_inspection_metadata_v1)
    sid = 'outbound:' + canonical_digest((namespace, final_operation_id))[:48]
    if (type(observed) not in (MutationReceiptV2, PlatformObservationRefinementReceiptV3) or observed.durable_state != 'committed'
            or type(source) is not GraphAtom or source.key != source_key(*namespace.as_tuple, sid)
            or source.revision != 1 or not source.valid):
        raise ValueError('outbound inspection requires its actual first Source and committed observation')
    key = inspection_key_v1(source.key, 1)
    reads = {version.key: version.revision for version in read_versions}
    if reads.get(source.key) != 0 or reads.get(key) != 0:
        raise ValueError('outbound inspection requires actual Source and projection absence CAS reads')
    body = SourceRecord.from_dict(source.value).to_dict()
    payload = canonical_json(body).encode('utf8')
    operation_id = 'd13-outbound:' + canonical_digest((namespace, final_operation_id, observation_receipt_digest_v3(observed)))[:48]
    value = {'schema': SOURCE_TYPE, 'target_ref': source.key.token, 'target_revision': 1,
        'target_codec': 'canonical-json.ascii.v1', 'target_sha256': sha256(payload).hexdigest(),
        'target_bytes': len(payload), 'target_semantic_digest': canonical_digest(body),
        'producer_operation_id': operation_id, 'metadata': {name: body[name] for name in SOURCE_FIELDS}}
    validate_inspection_metadata_v1(value, source=True)
    return GraphWrite(key, value, (source.key,))


def _stage(db, namespace, final_operation_id, observed, now, *, graph=None):
    if type(observed) not in (MutationReceiptV2, PlatformObservationRefinementReceiptV3) or observed.durable_state != "committed":
        raise ValueError("actual durable outbound observation required")
    observation = observation_platform_observation_v3(observed)
    receipt_proof=None
    if not final_operation_id.startswith('artifact-receipt-message:'):
        from .natural_outbound_receipt_adoption_read_v3 import require_bound_natural_outbound_receipt_adoption_v3
        receipt_proof=require_bound_natural_outbound_receipt_adoption_v3(graph,db,namespace,final_operation_id,observed)
        recovered=receipt_proof.recovered
    else:
        from .artifact_outbound_receipt_adoption_read_v3 import require_bound_artifact_outbound_receipt_adoption_v3
        receipt_proof = require_bound_artifact_outbound_receipt_adoption_v3(graph, db, namespace, final_operation_id, observed)
        recovered = receipt_proof.recovered
    from .d08_commitment_communication_v1 import CommitmentDispatchRecoveryV1
    named=type(recovered)is CommitmentDispatchRecoveryV1
    if named and (receipt_proof is None or receipt_proof.family!='commitment_literal'
            or receipt_proof.named_original.result is not recovered):
        raise ValueError('named outbound must use its actual SourceALL historical Scope/Use receipt proof')
    if (recovered is None
            or type(observation) is not PlatformObservationV2
            or observation.binding.origin.operation_id != final_operation_id
            or observation.binding.origin.effect_id != recovered.evidence.effect_id
            or observation.outcome not in {"accepted", "unknown", "delivered"}):
        raise ValueError("outbound observation and original final differ")
    batch = _atom(db, namespace, AtomKey.from_token(recovered.evidence.batch_ref))
    artifact_receipt=final_operation_id.startswith('artifact-receipt-message:')
    if artifact_receipt:
        from ..domains.d09 import D09ExpressionProvider
        next(spec for spec in D09ExpressionProvider().register_types() if spec.name=='d09.verified_segment_batch.v1').validator(batch.value)
        receipt_fact, receipt_reads, receipt_actor = (receipt_proof.receipt_fact, receipt_proof.receipt_reads, receipt_proof.receipt_actor)
    elif named:
        from ..domains.d09 import D09ExpressionProvider
        next(spec for spec in D09ExpressionProvider().register_types() if spec.name=='d09.verified_segment_batch.v1').validator(batch.value)
    else:
        validate_natural_verified_batch_value(batch.value)
    # The actual observation permits recording an event that happened, but it
    # does not permit substituting a newer authored batch or route original.
    for token, revision in recovered.write_versions:
        if named and AtomKey.from_token(token).type_name in {'d08.commitment_promise_use.v1','d08.commitment_promise_use.v2'}:
            continue  # Past exact Use is independently streamed; it cannot renew send permission.
        current = _atom(db, namespace, AtomKey.from_token(token))
        if current.revision != revision:
            raise ValueError("outbound committed D08/D09 original changed")
    if not artifact_receipt:
        # The dedicated READ proof retains the exact already-adopted payload,
        # current SourceALL and historical producer metadata. No frozen execution
        # input, fresh model pin or renewed send grant is consumed here.
        if receipt_proof is None:
            raise ValueError("actual outbound receipt-adoption proof required")
    outboxes = db.execute("SELECT outbox_ref FROM graph_outbox_jobs WHERE bot=? AND persona=? AND operation_id=?",
                          (*namespace.as_tuple, final_operation_id)).fetchall()
    if len(outboxes) != 1:
        raise ValueError("outbound observation needs its unique actual outbox")
    outbox = _atom(db, namespace, AtomKey.from_token(outboxes[0][0]))
    value = RuntimeOutboxValue(**outbox.value)
    if (value.effect_id != recovered.evidence.effect_id
            or value.operation_id != final_operation_id
            or observation.binding.origin.payload_digest.removeprefix("sha256:") != recovered.evidence.payload_digest):
        raise ValueError("outbound effect/payload identity differs")
    phase = {"accepted": "ack", "unknown": "unknown", "delivered": "delivered"}[observation.outcome]
    if value.phase not in ({"pending", "sending", "unknown", phase} | ({"ack"} if phase == "delivered" else set())):
        raise ValueError("outbound observation would regress an existing result")
    outbox_write = outbox_graph_write(replace(value, phase=phase), AtomKey.from_token(value.job_ref))
    reconcile_runtime_write(db, outbox_write)
    outbox_after = GraphAtom(outbox.key, outbox.revision + 1, outbox_write.value, True)
    scene, conversation = _outbound_route_v1(batch)
    order_key = turn_order_key(namespace, scene, conversation)
    if receipt_proof is not None:
        order=receipt_proof.optional_atom_v3(order_key)
        selected_slots=receipt_proof.outbound_slots_v3(outbox.key.token)
        prior_slots=tuple((atom.key.token,atom.revision,atom.value,atom.valid)for atom in selected_slots)
    else:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (order_key.token,)).fetchone()
        order = None if row is None else GraphAtom(order_key, row[0], json.loads(row[1]), bool(row[2]))
        prior_slots = db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d09.turn_slot.v1' AND json_extract(value,'$.origin_ref')=?",
            (*namespace.as_tuple, outbox.key.token)).fetchall()
    if len(prior_slots) > 1:
        raise ValueError("outbound origin has conflicting turn slots")
    if prior_slots:
        raw_slot = prior_slots[0]
        slot = GraphAtom(AtomKey.from_token(raw_slot[0]), raw_slot[1], raw_slot[2] if receipt_proof is not None else json.loads(raw_slot[2]), bool(raw_slot[3]))
        if not slot.valid or slot.value["scene_ref"] != scene or slot.value["conversation_ref"] != conversation:
            raise ValueError("outbound prior slot scope changed")
        slot_writes = ()
    else:
        reservation = reserve_turn_slot_v1(namespace, scene, conversation, "outbound", outbox.key.token,
                                           current_order=order)
        slot_write = reservation.writes[1]
        slot = GraphAtom(slot_write.key, 1, slot_write.value, True)
        slot_writes = reservation.writes
    from ..domains.d09.turn_order import _outbound_segment
    segment,_=_outbound_segment(batch)
    sid = "outbound:" + canonical_digest((namespace, final_operation_id))[:48]
    parents = tuple(sorted({AtomKey.from_token(ref).owner.subject
        for claim in batch.value["claims"] for ref in claim["source_refs"]}))
    observed_time = datetime.fromisoformat(observation.observed_at_utc.replace("Z", "+00:00")).timestamp()
    author_ref=(receipt_actor if artifact_receipt else recovered.evidence.scope.subject_ref if named else "persona:"+namespace.persona_id)
    producer_ref=(receipt_fact.receipt_id if artifact_receipt else
        "commitment-communication:"+recovered.evidence.scope.approval_operation_id if named else
        "natural-generation:"+recovered.evidence.generation_original_operation_id)
    admitted = D06DomainAdapter(namespace).admit_source(SourceAdmission(
        sid, segment["body"], author_ref,
        "authored", "authored", "none", "committed", observed_time, now,
        producer_ref,
        (conversation,), ("context", "audit"), parents))
    source = GraphAtom(source_key(*namespace.as_tuple, sid), 1, admitted.source.to_dict(), True)
    access = GraphAtom(access_key(*namespace.as_tuple, sid), 1, {
        "source_id": sid, "audiences": [conversation], "purposes": ["context", "audit"],
        "status": "active", "recorded_at": now}, True)
    validate_access(access.value)
    existing_source = db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (source.key.token,)).fetchone()
    if existing_source is not None:
        source = _atom(db, namespace, source.key)
        access = _atom(db, namespace, access.key)
        if SourceRecord.from_dict(source.value).text != segment["body"]:
            raise ValueError("outbound authored original text changed")
        source_writes = ()
    else:
        source_writes = (GraphWrite(source.key, source.value),
            GraphWrite(access.key, access.value, (source.key,)))
    if observation.outcome == "delivered":
        turn = complete_outbound_turn_v1(namespace, slot, outbox_after, batch, source, access, observed)
    else:
        observation_key = turn_outbound_observation_key(namespace, scene, conversation, slot.value["sequence"])
        if receipt_proof is not None:
            previous=receipt_proof.optional_atom_v3(observation_key)
        else:
            previous_row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (observation_key.token,)).fetchone()
            previous = (None if previous_row is None else GraphAtom(observation_key, previous_row[0],
                json.loads(previous_row[1]), bool(previous_row[2])))
        turn = observe_outbound_turn_v1(namespace, slot, outbox_after, batch, source, access, observed, previous=previous)
    turn_write = (GraphWrite(turn.write.key, turn.write.value)
        if observation.outcome == "delivered" else turn.write)
    writes = (*source_writes, *slot_writes, outbox_write, turn_write)
    reads = {outbox.key: outbox.revision, batch.key: batch.revision,
             order_key: 0 if order is None else order.revision}
    job = _atom(db, namespace, AtomKey.from_token(value.job_ref))
    if (job.key.type_name != "runtime.job" or job.value.get("job_id") != value.job_id
            or job.value.get("operation_id") != final_operation_id):
        raise ValueError("outbound original outbox job identity differs")
    reads[job.key] = job.revision
    if prior_slots:
        reads[slot.key] = slot.revision
    if existing_source is not None:
        for atom in (source, access):
            reads[atom.key] = atom.revision
    previous = getattr(turn, "expected_observation", None)
    if previous is not None:
        reads[previous.key] = previous.revision
    for ref in (receipt_reads if artifact_receipt else receipt_proof.read_versions):
        if receipt_proof is None:
            row = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?", (ref.key.token,)).fetchone()
            if ((ref.revision == 0 and row is not None)
                    or (ref.revision > 0 and row != (ref.revision, 1))):
                raise ValueError("outbound original source or route read changed")
        reads[ref.key] = ref.revision
    for write in writes:
        if write.key not in reads:
            if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone():
                raise ValueError("outbound original target already exists")
            reads[write.key] = 0
    if source_writes:
        from ..domains.d06.inspection_metadata_v1 import inspection_key_v1
        metadata_key = inspection_key_v1(source.key, 1)
        if reads.get(metadata_key) != 0:
            raise ValueError('outbound first Source inspection lacks its actual SourceWork absence read')
        versions = tuple(GraphVersion(key, version) for key, version in reads.items())
        projection = outbound_source_inspection_write_v1(namespace, final_operation_id, observed, source, versions)
        writes = (*writes, projection)
    return source, slot, batch, writes, tuple(GraphVersion(key, version) for key, version in reads.items())


def commit_natural_outbound_observation_v1(graph, bootstrap, namespace, final_operation_id, *, _receipt_proof=None):
    graph._admin(bootstrap)
    from ..runtime_storage_v3 import runtime_storage_v3,bind_runtime_storage_operation_v3
    from .natural_outbound_receipt_adoption_read_v3 import (begin_natural_outbound_receipt_adoption_read_v3,
        observe_natural_outbound_receipt_adoption_write_v3,bind_natural_outbound_receipt_adoption_v3)
    db=graph._GraphCoordinator__store._db
    from .artifact_outbound_receipt_adoption_read_v3 import (begin_artifact_outbound_receipt_adoption_read_v3,
        observe_artifact_outbound_receipt_adoption_write_v3, bind_artifact_outbound_receipt_adoption_v3,
        PreparedArtifactOutboundReceiptAdoptionV3, PreparedArtifactOutboundReceiptReplayV3)
    artifact_receipt = final_operation_id.startswith('artifact-receipt-message:')
    if runtime_storage_v3(db) is not None and _receipt_proof is None:
        begin = begin_artifact_outbound_receipt_adoption_read_v3 if artifact_receipt else begin_natural_outbound_receipt_adoption_read_v3
        work = begin(graph, bootstrap, namespace, final_operation_id)
        def completed(proof):
            from .natural_outbound_receipt_adoption_read_v3 import PreparedNaturalOutboundReceiptReplayV3
            replay_type = PreparedArtifactOutboundReceiptReplayV3 if artifact_receipt else PreparedNaturalOutboundReceiptReplayV3
            if type(proof) is replay_type:
                first=None
                try:
                    result=proof.resume_original_ack_v3(graph,namespace,final_operation_id,proof.reader.observed)
                    if type(proof)is PreparedNaturalOutboundReceiptReplayV3:
                        proof.close_natural_parent_after_ack_v3(graph,namespace,final_operation_id,proof.reader.observed)
                    return result
                except BaseException as error:
                    first=error
                    raise
                finally:
                    try:proof.release_payload_v3()
                    except BaseException as cleanup:
                        if first is None:raise
                        first.add_note('outbound replay payload release failed: '+type(cleanup).__name__)
            observe = observe_artifact_outbound_receipt_adoption_write_v3 if artifact_receipt else observe_natural_outbound_receipt_adoption_write_v3
            observe(proof)
            try:
                with bind_runtime_storage_operation_v3(proof.operation,db):
                    return commit_natural_outbound_observation_v1(graph,bootstrap,namespace,final_operation_id,_receipt_proof=proof)
            finally:proof.release_payload_v3()
        def failed(error):raise error
        return work.map_terminal_v3('issuer',completed,failed)
    def receipt_scope():
        if _receipt_proof is None:
            return nullcontext()
        bind = (bind_artifact_outbound_receipt_adoption_v3
            if type(_receipt_proof) is PreparedArtifactOutboundReceiptAdoptionV3 else bind_natural_outbound_receipt_adoption_v3)
        return bind(_receipt_proof, graph, db, namespace, final_operation_id, _receipt_proof.reader.observed)

    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(namespace)
        db = store._db
        db.execute("BEGIN")
        try:
            with receipt_scope():
                recovered = _recover_outbound_dispatch_v1(db, namespace, final_operation_id)
            db.commit()
        except BaseException:
            db.rollback()
            raise
    if recovered is None:
        raise ValueError("outbound final original unavailable")
    target = metadata.requirements
    observed = port.read_current_observation_receipt_v1(namespace=namespace,
        authority_namespace=target.authority_namespace, effect_id=recovered.evidence.effect_id)
    observed_digest = observation_receipt_digest_v3(observed)
    if _receipt_proof is not None and observed_digest!=canonical_digest(_receipt_proof.reader.observed):
        raise ValueError('actual Core outbound observation changed after complete Source READ')
    if _receipt_proof is not None:
        saved=_receipt_proof.saved_observation_v3()
        if saved is not None:raise ValueError('saved observation must use its distinct metadata replay proof')
    else:
        with store._lock:
            saved = db.execute(f"SELECT observation_json,original_json,original_digest FROM {TABLE} "
                "WHERE bot=? AND persona=? AND final_operation_id=? AND observation_digest=?",
                (*namespace.as_tuple, final_operation_id, observed_digest)).fetchone()
    op = "d13-outbound:" + canonical_digest((namespace, final_operation_id, observed_digest))[:48]
    if saved is not None:
        original = json.loads(saved[1])
        if (canonical_digest(original) != saved[2] or saved[0] != canonical_serialize(to_wire(observed))):
            raise ValueError("outbound original observation changed")
        permit = from_wire(original["permit"])
        current, state = port.get_fence_operation(namespace=namespace,
            authority_namespace=target.authority_namespace, operation_id=op)
        if current != permit or state not in {"active", "finished"}:
            raise ValueError("outbound original fence unavailable")
        if state == "active":
            scope = FenceScope(namespace, target.authority_namespace, permit.generation, "write", op,
                permit, permit.pinned_anchor, NamespaceEpoch(*namespace.as_tuple, original["pre_epoch"]),
                original["pre_revision"])
            port.finish_fence(scope, request_id="finish:" + op, request_digest=original["finish_digest"])
        from .dispatch_candidate import NaturalDispatchCandidateRecoveryV2
        if type(recovered) is NaturalDispatchCandidateRecoveryV2:
            from .d13_natural_original_use_v3 import close_graph_natural_parent_after_outbound_v3
            close_graph_natural_parent_after_outbound_v3(graph, namespace=namespace,
                generation_original_id=recovered.evidence.generation_original_operation_id, permit=permit)
        return {"status": "duplicate", "observation_outcome": observation_platform_observation_v3(observed).outcome}
    anchor = port.current_anchor(namespace=namespace, authority_namespace=target.authority_namespace)
    if not graph._accounting_anchor_covers(target, anchor):
        raise ValueError("outbound current Authority anchor differs")
    permit = port.begin_fence(namespace=namespace, authority_namespace=target.authority_namespace,
        holder=graph._GraphCoordinator__holder, generation=target.activation_generation,
        operation="write", operation_id=op, expected_anchor=anchor, retain_on_unknown=True)
    scope = FenceScope(namespace, target.authority_namespace, target.activation_generation,
        "write", op, permit, anchor, epoch, metadata.graph_revision)
    if port.validate_fence(scope) != permit:
        raise ValueError("outbound write fence changed")
    from .first_ingress_v2 import trusted_upper
    adoption_clock = port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    now = trusted_upper(adoption_clock)
    finish_digest = "sha256:" + canonical_digest((op, permit.token, observation_receipt_digest_v3(observed)))
    rejected = None
    with store._lock:
        db.execute("BEGIN IMMEDIATE")
        try:
            if graph._v2_graph_stamp(namespace) != (metadata, epoch):
                raise ValueError("outbound graph changed before adoption")
            with receipt_scope():
                source, slot, batch, writes, reads = _stage(db, namespace, final_operation_id, observed, now, graph=graph)
            receipt = GraphStore._graph_commit_in_transaction(store, GraphCandidate(
                Event(Scope(*namespace.as_tuple, "d13-outbound-observation"), op, now,
                    "d13.outbound_observation", {"observation_digest": observation_receipt_digest_v3(observed)}),
                reads, writes, (epoch,)), _capability=graph._GraphCoordinator__graph_capability)
            if receipt.status != "committed":
                raise ValueError("outbound graph observation CAS did not commit")
            # Authored source bytes are immutable historical content. Their
            # original batch/parent linkage is provenance, not an invalidating
            # state dependency; every current history read still qualifies the
            # source/access/correction closure independently.
            source_record = SourceRecord.from_dict(source.value)
            provenance = (batch.key, *(source_key(*namespace.as_tuple, sid)
                for sid in source_record.parent_source_ids))
            for key in provenance:
                row = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
                if row is None or row[1] != 1:
                    raise ValueError("outbound authored source provenance disappeared")
                db.execute("INSERT OR IGNORE INTO graph_dependency_edges "
                    "(dependent_token,dependency_token,dependency_revision,edge_kind,operation_id) VALUES(?,?,?,?,?)",
                    (source.key.token, key.token, row[0], "historical_provenance", op))
            if observation_platform_observation_v3(observed).outcome == "delivered":
                completion = next(write for write in writes if write.key.type_name == "d09.turn_completion.v1")
                for ref in (slot.key.token, source.key.token, access_key(*namespace.as_tuple, source_record.source_id).token,
                            batch.key.token, slot.value["origin_ref"]):
                    row = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?", (ref,)).fetchone()
                    if row is None or row[1] != 1:
                        raise ValueError("outbound delivered completion provenance disappeared")
                    db.execute("INSERT INTO graph_dependency_edges "
                        "(dependent_token,dependency_token,dependency_revision,edge_kind,operation_id) VALUES(?,?,?,?,?)",
                        (completion.key.token, ref, row[0], "historical_provenance", op))
            store.cas_graph_recovery_metadata(metadata, replace(target,
                execution_seq=anchor.execution_seq, execution_digest=anchor.execution_digest),
                _capability=graph._GraphCoordinator__graph_capability)
            original = {"schema": "d13.outbound_adoption.v1", "operation_id": op,
                "source_ref": source.key.token, "slot_ref": slot.key.token, "batch_ref": batch.key.token,
                "pre_epoch": epoch.revision, "pre_revision": metadata.graph_revision,
                "permit": to_wire(permit), "finish_digest": finish_digest,
                "graph_receipt_digest": canonical_digest(receipt), "observation_digest": observation_receipt_digest_v3(observed),
                "trusted_latest_utc": now, "trusted_clock_digest": canonical_digest(adoption_clock)}
            db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?,?,?,?)", (*namespace.as_tuple,
                final_operation_id, observed_digest, source.key.token, slot.key.token, batch.key.token,
                canonical_serialize(to_wire(observed)), canonical_serialize(original), canonical_digest(original)))
            db.commit()
        except (ValueError, TypeError) as exc:
            db.rollback()
            rejected = exc
        except BaseException:
            db.rollback()
            raise
    if rejected is not None:
        # The actual external observation remains in Authority. A proven
        # rolled-back local projection does not retain an active write fence
        # forever; the exact finished Authority operation is its refusal
        # original. Transport/SQLite uncertainty never enters this branch.
        with store._lock:
            if (db.in_transaction or graph._v2_graph_stamp(namespace) != (metadata, epoch)
                    or db.execute(f"SELECT 1 FROM {TABLE} WHERE bot=? AND persona=? AND final_operation_id=? AND observation_digest=?",
                        (*namespace.as_tuple, final_operation_id, observed_digest)).fetchone() is not None):
                raise rejected
        port.finish_fence(scope, request_id="reject:" + op, request_digest="sha256:" + canonical_digest(
            ("d13.outbound_rejected_no_commit.v1", op, permit.token, observed_digest, metadata.graph_revision, epoch.revision)))
        raise rejected
    port.finish_fence(scope, request_id="finish:" + op, request_digest=finish_digest)
    from .dispatch_candidate import NaturalDispatchCandidateRecoveryV2
    if type(recovered) is NaturalDispatchCandidateRecoveryV2:
        from .d13_natural_original_use_v3 import close_graph_natural_parent_after_outbound_v3
        close_graph_natural_parent_after_outbound_v3(graph, namespace=namespace,
            generation_original_id=recovered.evidence.generation_original_operation_id, permit=permit)
    return {"status": "committed", "observation_outcome": observation_platform_observation_v3(observed).outcome}


def read_current_outbound_turn_v1(db, namespace, slot, completion, *, now_utc):
    """Reconstruct a confirmed delivered turn from its adopted W01 original."""
    validate_turn_completion_v1(completion.value)
    from ..authority_service.current_authority_graph_read_v3 import (
        _authority_attachment_owner_v3,read_bound_authority_graph_attachment_rows_v3,
        read_authority_current_point_v3,authority_current_json_v3,require_authority_outbound_collection_source_v6,
        authority_collection_source_atom_v6)
    work=_authority_attachment_owner_v3(db)
    from .d13_paid_original_read_v3 import d13_paid_current_reader_v3
    paid=d13_paid_current_reader_v3(db)
    if paid is not None:
        row=paid.window_original_point_v3(TABLE,
            ('source_ref','batch_ref','observation_json','original_json','original_digest'),
            ('bot','persona','slot_ref','observation_digest'),
            (*namespace.as_tuple,slot.key.token,completion.value['evidence_ref']))
    elif work is None:
        row = db.execute(f"SELECT source_ref,batch_ref,observation_json,original_json,original_digest "
            f"FROM {TABLE} WHERE bot=? AND persona=? AND slot_ref=? AND observation_digest=?",
            (*namespace.as_tuple, slot.key.token, completion.value["evidence_ref"])).fetchone()
    else:
        handled,refs=read_bound_authority_graph_attachment_rows_v3(db,table=TABLE,columns=('final_operation_id',),
            key_columns=('bot','persona','slot_ref','observation_digest'),
            key=(*namespace.as_tuple,slot.key.token,completion.value['evidence_ref']),order_column='final_operation_id')
        if not handled or len(refs)!=1:raise ValueError('Authority outbound completion has no unique adopted original')
        row=read_authority_current_point_v3(db,table=TABLE,
            columns=('source_ref','batch_ref','observation_json','original_json','original_digest'),
            key_columns=('bot','persona','final_operation_id','observation_digest'),
            key=(*namespace.as_tuple,refs[0][0],completion.value['evidence_ref']),legacy_reader=lambda:None)
    if row is None:
        raise ValueError("outbound completion lacks its actual adopted observation")
    original, receipt = authority_current_json_v3(row[3]), from_wire(authority_current_json_v3(row[2]))
    if (canonical_digest(original)if work is None else row[3].sha256) != row[4] or observation_receipt_digest_v3(receipt) != original["observation_digest"]:
        raise ValueError("outbound original commitment differs")
    batch = _atom(db, namespace, AtomKey.from_token(row[1]))
    outbox = _atom(db, namespace, AtomKey.from_token(slot.value['origin_ref']))
    material=None
    if work is None:source=_atom(db,namespace,AtomKey.from_token(row[0]))
    else:
        material=require_authority_outbound_collection_source_v6(work,slot=slot,completion=completion,
            batch=batch,outbox=outbox,source_ref=row[0],original=row[3],receipt=receipt)
        work.collection_record['source_ref']=row[0]
        source=authority_collection_source_atom_v6(work,material,row[0])
    record = SourceRecord.from_dict(source.value)
    access = _atom(db, namespace, access_key(*namespace.as_tuple, record.source_id))
    expected = complete_outbound_turn_v1(namespace, slot, outbox, batch, source, access, receipt)
    if expected.write.value != completion.value or expected.write.key != completion.key:
        raise ValueError("outbound completion is not the original delivered turn")
    audience = VersionedRef(**batch.value["audience_ref"])
    account = _atom(db, namespace, AtomKey.from_token(audience.ref))
    if account.revision != audience.version:
        raise ValueError("outbound current D03 audience changed")
    reads = [VersionedRef(atom.key.token, atom.revision) for atom in
             (slot, completion, source, access, batch, outbox, account)]
    # Include the authored source itself, every ancestor, and absent correction
    # heads. A cycle is invalid lineage rather than silently covered ancestry.
    from ..domains.d06 import source_correction_head_key
    from ..domains.d09.turn_order import _source_guard
    pending, seen, active = [(record.source_id, False)], set(), set()
    while pending:
        sid, leaving = pending.pop()
        if leaving:
            active.remove(sid)
            seen.add(sid)
            continue
        if sid in active:
            raise ValueError("outbound context ancestry contains a cycle")
        if sid in seen:
            continue
        active.add(sid)
        if len(seen) + len(active) > 128:
            raise ValueError("outbound context ancestry exceeds bounded coverage")
        if paid is not None:
            from types import SimpleNamespace
            ref=source_key(*namespace.as_tuple,sid).token
            leaf=paid.sources[ref]
            parent_record=SimpleNamespace(**leaf.metadata)
            access_parent=paid.window_atom_v3(access_key(*namespace.as_tuple,sid))
            correction=source_correction_head_key(namespace,sid)
            correction_atom=paid.window_atom_v3(correction)
            if correction_atom.revision!=0 or correction_atom.valid:
                raise ValueError('D13 paid outbound Source ancestor was corrected')
            reads.extend((VersionedRef(ref,leaf.revision),VersionedRef(access_parent.key.token,access_parent.revision),VersionedRef(correction.token,0)))
        elif work is None:
            parent = _atom(db, namespace, source_key(*namespace.as_tuple, sid))
            access_parent = _atom(db, namespace, access_key(*namespace.as_tuple, sid))
            parent_record = _source_guard(namespace, slot.value["conversation_ref"], parent, access_parent)
            correction = source_correction_head_key(namespace, sid)
            if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (correction.token,)).fetchone():
                raise ValueError("outbound source or ancestor was corrected")
            reads.extend((VersionedRef(parent.key.token, parent.revision),
                          VersionedRef(access_parent.key.token, access_parent.revision), VersionedRef(correction.token, 0)))
        else:
            ref=source_key(*namespace.as_tuple,sid).token
            witness=material.witnesses[ref].require_current_v3()
            parent_record=material.metadata_records[ref]
            access_parent=work.projection.get(access_key(*namespace.as_tuple,sid))
            correction=source_correction_head_key(namespace,sid);head=work.projection.get(correction)
            if head.valid or head.revision!=0:raise ValueError('Authority outbound Source ancestor was corrected')
            reads.extend((VersionedRef(ref,witness.revision),VersionedRef(access_parent.key.token,access_parent.revision),VersionedRef(correction.token,0)))
        pending.append((sid, True))
        pending.extend((parent_id, False) for parent_id in reversed(parent_record.parent_source_ids))
    turn = CompletedTurnV1(slot.value["conversation_ref"], audience, slot.value["sequence"],
        VersionedRef(completion.key.token, completion.revision), VersionedRef(source.key.token, source.revision),
        VersionedRef(access.key.token, access.revision), record.speaker_id, record.text,
        completion.value["trusted_utc"], "confirmed", completion.value["tool_state"])
    if turn.trusted_utc > now_utc:
        raise ValueError("outbound observation postdates the current trusted window")
    return turn, tuple(sorted(set(reads), key=lambda item: item.ref))


_OUTBOUND_INSPECTION_READS = WeakKeyDictionary()


class OutboundSourceInspectionProvenanceReadV1:
    """Authenticate this named GraphCandidate's metadata and independent Core fact."""
    def __init__(self, parent):
        from .source_inspection_metadata_read_v3 import InspectionMetadataReadV3, _TASKS
        if (type(parent) is not InspectionMetadataReadV3
                or _TASKS.get(parent) != (parent.owner, parent.owner.work, parent.owner.operation, parent.target)
                or parent.target.type_name != 'memory.source' or parent.target_head[0] != 1
                or parent.target_history != parent.metadata_history
                or parent.target_history[2:] != ('d13-outbound-observation', parent.value['producer_operation_id'], 1)):
            raise ValueError('exact outbound Source inspection producer history required')
        self.parent, self.owner = parent, parent.owner
        self.operation = parent.owner.operation
        self.after = ('', '')
        self.row = self.original = self.observation = self.event_header = None
        self.column = self.event_reads = self.event_writes = self.event_invalidated = None
        self.core_selector = self.authenticated_observation = None
        self.history_pending = ()
        self.history_index = 0
        self.phase, self.complete = 'locate', False
        _OUTBOUND_INSPECTION_READS[self] = (parent, self.owner, self.operation)
        self.operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        from .source_correction_read_v3 import _heap
        return 8192 + _heap((self.row, self.original, self.observation, self.event_header, self.event_reads,
            self.event_writes, self.event_invalidated, self.history_pending, self.core_selector, self.authenticated_observation))

    def _actual_v1(self, meter):
        if _OUTBOUND_INSPECTION_READS.get(self) != (self.parent, self.owner, self.operation):
            raise ValueError('outbound inspection lost its private producer task')
        self.parent._actual_v3(meter)

    def _fixed_v1(self, meter, table, columns, where, parameters):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        return _runtime_bounded_fixed_row_v3(self.owner.db, meter, table, columns, where, parameters)

    def _start_v1(self, table, column, columns, key):
        from .source_inspection_metadata_read_v3 import _InspectionColumnV3
        self.column = _InspectionColumnV3(self.owner, table=table, column=column, key_columns=columns, key=key)

    def _column_v1(self, meter):
        if not self.column.advance(meter):
            return False, None, None
        value, digest = self.column.value_v3(self.owner), self.column.sha256
        self.column.release_v3()
        self.column = None
        return True, value, digest

    def pending_core_request_v1(self):
        if _OUTBOUND_INSPECTION_READS.get(self) != (self.parent, self.owner, self.operation):
            raise ValueError('outbound inspection pending request lost its actual owner')
        return self.core_selector if self.phase == 'core' and self.authenticated_observation is None else None

    def advance(self, meter):
        from ..authority_service.v2_contract import FencePermitV2
        self._actual_v1(meter)
        p, ns = self.parent, self.owner.namespace
        pk = ('bot', 'persona', 'final_operation_id', 'observation_digest')
        if self.phase == 'locate':
            # Only fixed control columns are scanned, one actual PK per quantum.
            row = self._fixed_v1(meter, TABLE,
                ('final_operation_id', 'observation_digest', 'source_ref', 'slot_ref', 'batch_ref', 'original_digest'),
                'bot=? AND persona=? AND source_ref=? AND (final_operation_id>? OR '
                '(final_operation_id=? AND observation_digest>?)) ORDER BY final_operation_id,observation_digest',
                (*ns.as_tuple, p.target.token, self.after[0], self.after[0], self.after[1]))
            if row is None:
                if self.row is None:
                    raise ValueError('outbound inspection has no exact adoption original')
                self._start_v1(TABLE, 'original_json', pk, (*ns.as_tuple, *self.row[:2]))
                self.phase = 'original'
            else:
                self.after = row[:2]
                op = 'd13-outbound:' + canonical_digest((ns, row[0], row[1]))[:48]
                if op == p.value['producer_operation_id']:
                    if (self.row is not None or row[2] != p.target.token
                            or p.target != source_key(*ns.as_tuple, 'outbound:' + canonical_digest((ns, row[0]))[:48])):
                        raise ValueError('outbound inspection original identity is ambiguous')
                    self.row = row
        elif self.phase == 'original':
            done, value, digest = self._column_v1(meter)
            if done:
                fields = {'schema', 'operation_id', 'source_ref', 'slot_ref', 'batch_ref', 'pre_epoch',
                    'pre_revision', 'permit', 'finish_digest', 'graph_receipt_digest', 'observation_digest'}
                if (type(value) is not dict or set(value) != fields or value['schema'] != 'd13.outbound_adoption.v1'
                        or value['operation_id'] != p.value['producer_operation_id']
                        or (value['source_ref'], value['slot_ref'], value['batch_ref']) != self.row[2:5]
                        or value['observation_digest'] != self.row[1] or digest != self.row[5]
                        or canonical_digest(value) != digest
                        or type(value['pre_epoch']) is not int or value['pre_epoch'] < 0
                        or type(value['pre_revision']) is not int or value['pre_revision'] < 0):
                    raise ValueError('outbound inspection adoption original differs from its actual row/producer')
                for ref in self.row[2:5]:
                    from ..runtime_contracts import NamespaceId
                    if NamespaceId.from_key(AtomKey.from_token(ref)) != ns:
                        raise ValueError('outbound inspection adoption original crossed namespace')
                permit = from_wire(value['permit'])
                from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
                from .source_inspection_migration_v1 import SourceInspectionMigrationWorkV1
                if type(self.owner) is SourceInspectionMigrationWorkV1:
                    authority_ns = self.owner.service.lifecycle.namespace
                    # The later independent Core history check certifies this current generation.
                    generation = None
                elif type(self.owner) is AuthorityGraphReadWorkV3:
                    authority_ns, generation = self.owner.permit.namespace, self.owner.permit.generation
                else:
                    authority_ns = self.owner.graph_stamp[0].requirements.authority_namespace
                    generation = self.owner.graph_stamp[0].requirements.activation_generation
                if (type(permit) is not FencePermitV2 or permit.operation != 'write'
                        or permit.operation_id != value['operation_id'] or permit.namespace != authority_ns
                        or (generation is not None and permit.generation != generation)
                        or value['finish_digest'] != 'sha256:' + canonical_digest((value['operation_id'], permit.token, self.row[1]))):
                    raise ValueError('outbound inspection original WRITE permit/finish identity differs')
                self.original = value
                self._start_v1(TABLE, 'observation_json', pk, (*ns.as_tuple, *self.row[:2]))
                self.phase = 'observation'
        elif self.phase == 'observation':
            done, value, digest = self._column_v1(meter)
            if done:
                observed = from_wire(value)
                if (type(observed) not in (MutationReceiptV2, PlatformObservationRefinementReceiptV3) or observed.durable_state != 'committed'
                        or type(observation_platform_observation_v3(observed)) is not PlatformObservationV2
                        or observation_receipt_digest_v3(observed) != self.row[1]
                        or digest != canonical_digest(to_wire(observed))
                        or observation_platform_observation_v3(observed).binding.origin.operation_id != self.row[0]):
                    raise ValueError('outbound inspection observation wire/producer identity differs')
                birth_permit = from_wire(self.original['permit'])
                dispatch_permit = observation_original_dispatch_permit_v3(observed)
                if ((dispatch_permit.authority_id, dispatch_permit.namespace,
                        dispatch_permit.subject, dispatch_permit.generation) !=
                        (birth_permit.authority_id, birth_permit.namespace, birth_permit.subject, birth_permit.generation)):
                    raise ValueError('outbound inspection observation and original permit have different authority/Owner/generation')
                self.observation = observed
                self.core_selector = (observation_effect_id_v3(observed),
                    observed.pending.mutation_id, observation_receipt_digest_v3(observed))
                self.phase = 'core'
        elif self.phase == 'core':
            from .source_inspection_metadata_read_v3 import require_inspection_metadata_core_result_v3
            actual = require_inspection_metadata_core_result_v3(p, self, self.core_selector)
            if actual is not None:
                if type(actual) not in (MutationReceiptV2, PlatformObservationRefinementReceiptV3) or actual != self.observation:
                    raise ValueError('outbound inspection observation lacks the exact independent Core historical receipt')
                self.event_header = self._fixed_v1(meter, 'graph_events', ('digest', 'epoch_revision'),
                    'bot=? AND persona=? AND session=? AND event_id=?',
                    (*ns.as_tuple, 'd13-outbound-observation', self.original['operation_id']))
                if self.event_header is None or self.event_header[1] != self.original['pre_epoch'] + 1:
                    raise ValueError('outbound inspection original lacks its actual E+1 adoption event')
                self._start_v1('graph_events', 'reads', ('bot', 'persona', 'session', 'event_id'),
                    (*ns.as_tuple, 'd13-outbound-observation', self.original['operation_id']))
                self.phase = 'reads'
        elif self.phase in {'reads', 'writes', 'invalidated'}:
            done, value, digest = self._column_v1(meter)
            if done:
                from ..memory_types import access_key
                ak = access_key(*ns.as_tuple, p.target.owner.subject)
                if self.phase == 'reads':
                    if any([key.token, 0] not in value for key in (p.target, p.metadata_key, ak)):
                        raise ValueError('outbound inspection original lacks actual Source/Access/projection READ0')
                    self.event_reads = value
                    self._start_v1('graph_events', 'revisions', ('bot', 'persona', 'session', 'event_id'),
                        (*ns.as_tuple, 'd13-outbound-observation', self.original['operation_id']))
                    self.phase = 'writes'
                elif self.phase == 'writes':
                    if any([key.token, 1] not in value for key in (p.target, p.metadata_key, ak)):
                        raise ValueError('outbound inspection original lacks actual Source/Access/projection WRITE1')
                    self.event_writes = value
                    self._start_v1('graph_events', 'invalidated', ('bot', 'persona', 'session', 'event_id'),
                        (*ns.as_tuple, 'd13-outbound-observation', self.original['operation_id']))
                    self.phase = 'invalidated'
                else:
                    from ..graph_types import GraphReceipt
                    self.event_invalidated = value
                    revisions = tuple(GraphVersion(AtomKey.from_token(token), revision) for token, revision in self.event_writes)
                    invalidated = tuple(GraphVersion(AtomKey.from_token(token), revision) for token, revision in value)
                    receipt = GraphReceipt('committed', revisions, invalidated, NamespaceEpoch(*ns.as_tuple, self.event_header[1]))
                    if canonical_digest(receipt) != self.original['graph_receipt_digest']:
                        raise ValueError('outbound inspection adoption receipt differs from actual event versions')
                    self.history_pending = tuple((v, 1) for v in revisions) + tuple((v, 0) for v in invalidated)
                    self.phase = 'histories'
        elif self.phase == 'histories':
            if self.history_index < len(self.history_pending):
                version, valid = self.history_pending[self.history_index]
                row = self._fixed_v1(meter, 'graph_history', ('valid', 'event_bot', 'event_persona', 'event_session', 'event_id'),
                    'token=? AND revision=?', (version.key.token, version.revision))
                if row != (valid, *ns.as_tuple, 'd13-outbound-observation', self.original['operation_id']):
                    raise ValueError('outbound inspection receipt member lacks its exact immutable history')
                self.history_index += 1
            else:
                self.complete, self.phase = True, 'complete'
        elif self.phase == 'complete':
            self.require_current_v1(meter)
        else:
            raise ValueError('unregistered outbound inspection provenance phase')
        self.operation.refresh_retained_state_v3(self)
        return self.complete

    def require_current_v1(self, meter):
        self._actual_v1(meter)
        if not self.complete:
            raise ValueError('outbound inspection provenance is incomplete')
        row = self._fixed_v1(meter, TABLE, ('source_ref', 'slot_ref', 'batch_ref', 'original_digest'),
            'bot=? AND persona=? AND final_operation_id=? AND observation_digest=?',
            (*self.owner.namespace.as_tuple, *self.row[:2]))
        if row != self.row[2:]:
            raise ValueError('outbound inspection immutable adoption identity disappeared')
        from .source_inspection_metadata_read_v3 import require_inspection_metadata_core_result_v3
        if require_inspection_metadata_core_result_v3(self.parent, self, self.core_selector) != self.observation:
            raise ValueError('outbound inspection lost its independent actual Core receipt')
        return self

    def release_v1(self):
        if _OUTBOUND_INSPECTION_READS.pop(self, None) is None:
            return
        if self.column is not None:
            self.column.release_v3()
        from .source_inspection_metadata_read_v3 import release_inspection_metadata_core_result_v3
        release_inspection_metadata_core_result_v3(self)
        self.operation.unregister_retained_state_v3(self)
        self.row = self.original = self.observation = self.authenticated_observation = self.column = None
        self.event_reads = self.event_writes = self.event_invalidated = self.history_pending = None
