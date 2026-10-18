"""W01 adoption of independently read D11 outbound observations.

Accepted and unknown sends remain incomplete. Only an actual delivered
observation can create a confirmed D13 turn; peer-read remains unknown.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import json

from ..authority_service.v2_contract import MutationReceiptV2, PlatformObservationV2, to_wire, from_wire
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
from .natural_generation_issue_v2 import read_original_scoped_query_proof_v2
from .natural_reply_job_v2 import read_original_preparation
from .natural_scoped_query_proof_v2 import assert_natural_scoped_query_current_v2

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
    if final_operation_id.startswith('artifact-receipt-message:'):
        from .artifact_receipt_dispatch_v1 import recover_artifact_receipt_dispatch_candidate_in_transaction_v1
        return recover_artifact_receipt_dispatch_candidate_in_transaction_v1(db,namespace,final_operation_id)
    return recover_natural_dispatch_candidate_in_transaction_v2(db,namespace,final_operation_id)


def _current_receipt_outbound_v1(graph,db,namespace,final_operation_id,now):
    from ..graph_coordinator import GraphCoordinator
    from .artifact_completion_receipt_v1 import (read_current_artifact_completion_receipt_by_operation_v1,
        require_artifact_completion_receipt_history_v1)
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    if type(graph) is not GraphCoordinator:raise TypeError('receipt outbound needs its actual installed Graph')
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.installation_policy.namespace!=namespace:
        raise ValueError('receipt outbound crossed its actual installation')
    marker=final_operation_id.removeprefix('artifact-receipt-message:')
    original=read_adopted_domain_operation_v1(db,namespace,'artifact-completion-source:'+marker)
    if original is None:raise ValueError('receipt outbound lost actual D06 producer')
    historical=require_artifact_completion_receipt_history_v1(db,namespace=namespace,original=original)
    current=read_current_artifact_completion_receipt_by_operation_v1(db,namespace=namespace,operation_id=final_operation_id,
        issuer=graph._GraphCoordinator__d11_issuer,installed_bundle=assembly.admin_bundle,
        owner_guard=historical.owner_guard,now_utc=now,audiences=tuple(original['payload']['authority']['audience']))
    family=_source_family_current_sql_v1(db,namespace=namespace,roots=(current.source_ref,),purpose='expression',
        audiences=tuple(original['payload']['authority']['audience']))
    return current,(*family,GraphVersion(AtomKey.from_token(current.owner_guard.grant_ref),current.owner_guard.grant_revision)),original['payload']['authority']['actor']


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

def _stage(db, namespace, final_operation_id, observed, now, *, graph=None):
    if type(observed) is not MutationReceiptV2 or observed.durable_state != "committed":
        raise ValueError("actual durable outbound observation required")
    pending, observation = observed.pending, observed.pending.platform_observation
    recovered = _recover_outbound_dispatch_v1(db, namespace, final_operation_id)
    if (recovered is None or pending.phase != "observed"
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
        receipt_fact,receipt_reads,receipt_actor=_current_receipt_outbound_v1(graph,db,namespace,final_operation_id,now)
    else:
        validate_natural_verified_batch_value(batch.value)
    # The actual observation permits recording an event that happened, but it
    # does not permit substituting a newer authored batch or route original.
    for token, revision in recovered.write_versions:
        current = _atom(db, namespace, AtomKey.from_token(token))
        if current.revision != revision:
            raise ValueError("outbound committed D08/D09 original changed")
    if not artifact_receipt:
        generation_rows = db.execute("SELECT parent_original_id FROM graph_natural_generation_preparations_v2 "
            "WHERE bot=? AND persona=? AND original_operation_id=?",
            (*namespace.as_tuple, recovered.evidence.generation_original_operation_id)).fetchall()
        if len(generation_rows) != 1:
            raise ValueError("outbound generation original is ambiguous")
        generation = read_original_preparation(db, namespace, generation_rows[0][0], "generation")
        assert_natural_scoped_query_current_v2(db,
            read_original_scoped_query_proof_v2(db, generation), now_utc=now)
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
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (order_key.token,)).fetchone()
    order = None if row is None else GraphAtom(order_key, row[0], json.loads(row[1]), bool(row[2]))
    prior_slots = db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name='d09.turn_slot.v1' AND json_extract(value,'$.origin_ref')=?",
        (*namespace.as_tuple, outbox.key.token)).fetchall()
    if len(prior_slots) > 1:
        raise ValueError("outbound origin has conflicting turn slots")
    if prior_slots:
        raw_slot = prior_slots[0]
        slot = GraphAtom(AtomKey.from_token(raw_slot[0]), raw_slot[1], json.loads(raw_slot[2]), bool(raw_slot[3]))
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
    admitted = D06DomainAdapter(namespace).admit_source(SourceAdmission(
        sid, segment["body"], (receipt_actor if artifact_receipt else "persona:" + namespace.persona_id),
        "authored", "authored", "none", "committed", observed_time, now,
        (receipt_fact.receipt_id if artifact_receipt else "natural-generation:" + recovered.evidence.generation_original_operation_id),
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
    for ref in (receipt_reads if artifact_receipt else recovered.evidence.current_read_versions):
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
    return source, slot, batch, writes, tuple(GraphVersion(key, version) for key, version in reads.items())


def commit_natural_outbound_observation_v1(graph, bootstrap, namespace, final_operation_id):
    graph._admin(bootstrap)
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(namespace)
        db = store._db
        db.execute("BEGIN")
        try:
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
    observed_digest = canonical_digest(observed)
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
        return {"status": "duplicate", "observation_outcome": observed.pending.platform_observation.outcome}
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
    now = trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    finish_digest = "sha256:" + canonical_digest((op, permit.token, canonical_digest(observed)))
    rejected = None
    with store._lock:
        db.execute("BEGIN IMMEDIATE")
        try:
            if graph._v2_graph_stamp(namespace) != (metadata, epoch):
                raise ValueError("outbound graph changed before adoption")
            source, slot, batch, writes, reads = _stage(db, namespace, final_operation_id, observed, now, graph=graph)
            receipt = GraphStore._graph_commit_in_transaction(store, GraphCandidate(
                Event(Scope(*namespace.as_tuple, "d13-outbound-observation"), op, now,
                    "d13.outbound_observation", {"observation_digest": canonical_digest(observed)}),
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
            if observed.pending.platform_observation.outcome == "delivered":
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
                "graph_receipt_digest": canonical_digest(receipt), "observation_digest": canonical_digest(observed)}
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
    return {"status": "committed", "observation_outcome": observed.pending.platform_observation.outcome}


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
    if (canonical_digest(original)if work is None else row[3].sha256) != row[4] or canonical_digest(receipt) != original["observation_digest"]:
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
