"""Current D13 conversation window reconstructed from one pinned business DB view.

GraphCoordinator supplies Authority fencing and the trusted clock. Authority
uses the same reader under its pinned read transaction. No transaction starts
or ends here, and this module never writes the graph.
"""
from __future__ import annotations

from dataclasses import asdict
import json
import math
import sqlite3

from ..contracts import canonical_json
from ..runtime_contracts import (
    CompletedTurnV1, ConversationWindowProjectionV1, NamespaceId,
    QueryEpoch, VersionedRef, canonical_digest,
)


def _hold(message: str):
    from ..graph_coordinator import UnavailableGuard
    raise UnavailableGuard(message)


def _window_original_point_v6(db,*,table,columns,key_columns,key):
    from .d13_paid_original_read_v3 import d13_paid_current_reader_v3
    paid=d13_paid_current_reader_v3(db)
    if paid is not None:return paid.window_original_point_v3(table=table,columns=columns,key_columns=key_columns,key=key)
    from ..authority_service.current_authority_graph_read_v3 import read_bound_authority_graph_attachment_v3
    bound,row=read_bound_authority_graph_attachment_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if bound:return row
    return db.execute('SELECT '+','.join(columns)+' FROM '+table+' WHERE '+
        ' AND '.join(name+'=?'for name in key_columns),key).fetchone()


def _reply_ingress_identity_locked(db, namespace, ingress_operation_id):
    from .ingress_observation import read_committed_ingress_identity
    row=_window_original_point_v6(db,table='graph_first_ingress_identity_v1',columns=('source_ref',),
        key_columns=('bot','persona','operation_id'),key=namespace.as_tuple+(ingress_operation_id,))
    if row is None:_hold("original private ingress is absent; HOLD")
    receipt = read_committed_ingress_identity(db, namespace, row[0])
    if receipt is None:
        _hold("original private ingress is uncommitted; HOLD")
    identity = json.loads(receipt.identity_json)
    if identity["operation_id"] != ingress_operation_id or identity["visibility"] != "private":
        _hold("original ingress is not private; HOLD")
    return identity


def _current_d13_inbound_inputs_locked_v1(db, namespace, ingress_operation_id,
                                          c02_operation_id, now_utc):
    from ..graph_coordinator import UnavailableGuard
    from ..graph_types import GraphAtom
    from ..memory_types import SourceRecord, source_key, validate_access
    from .c02_bundle_codec import c02_bundle_from_wire
    from .first_ingress_v2 import scene_ref_for_conversation
    from .reply_entity_route_v2 import read_current_reply_entity_route_binding_v2
    from .reply_model_job import CurrentReplyRouteManifestV2
    if not db.in_transaction:
        raise RuntimeError("D13 inbound inputs require the held graph transaction")
    identity = _reply_ingress_identity_locked(db, namespace, ingress_operation_id)
    source_ref = source_key(*namespace.as_tuple, identity["source_ref"]).token
    seal = _window_original_point_v6(db,table='graph_first_ingress_c02_committed_seals_v2',
        columns=('schema','bundle_digest','bundle_json'),key_columns=('bot','persona','operation_id'),
        key=namespace.as_tuple+(c02_operation_id,))
    operation = db.execute(
        "SELECT digest FROM graph_bundle_operations WHERE bot=? AND persona=? "
        "AND operation_id=?", namespace.as_tuple + (c02_operation_id,),
    ).fetchone()
    if (seal is None or seal[0] != "sylanne.first-ingress-c02-candidate.v2"
            or operation != (seal[1],)):
        raise UnavailableGuard("D13 original C02 seal is absent; HOLD")
    bundle = c02_bundle_from_wire(seal[2])
    if (bundle.digest != seal[1]
            or bundle.envelope.identity.operation_id != c02_operation_id
            or bundle.envelope.authority.namespace != namespace
            or bundle.envelope.source_qualification.source_refs != (source_ref,)):
        raise UnavailableGuard("D13 C02 source lineage differs; HOLD")
    scene_ref = scene_ref_for_conversation(
        namespace, identity["platform_ref"], identity["conversation_ref"])
    route = CurrentReplyRouteManifestV2(
        namespace, c02_operation_id, source_ref,
        identity["platform_ref"], identity["conversation_ref"], scene_ref,
        canonical_digest({
            "account_ref": identity["platform_ref"],
            "destination_ref": identity["conversation_ref"],
            "scene_ref": scene_ref,
        }),
    )
    epoch_row = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    if epoch_row is None:
        raise UnavailableGuard("D13 graph epoch is absent; HOLD")
    epoch = QueryEpoch(namespace, "all", epoch_row[0])
    from ..authority_service.current_authority_graph_read_v3 import (
        _authority_attachment_owner_v3,AuthorityRouteMetadataInventoryV6,
        require_authority_collection_source_v6,authority_collection_source_atom_v6)
    work=_authority_attachment_owner_v3(db)
    from .d13_paid_original_read_v3 import d13_paid_current_reader_v3
    paid=d13_paid_current_reader_v3(db)
    inventory=(paid.window_body if paid is not None else None if work is None else AuthorityRouteMetadataInventoryV6(work))
    binding = read_current_reply_entity_route_binding_v2(
        db, namespace, route, epoch,now_utc=now_utc,prepared_inventory=inventory)
    material=None if work is None else require_authority_collection_source_v6(work,binding=binding)

    def atom(version):
        if paid is not None:
            value=paid.window_atom_v3(version.key)
            if not value.valid or value.revision!=version.revision:
                raise UnavailableGuard('D13 paid inbound actual current atom changed; HOLD')
            return value
        if work is not None:
            value=(authority_collection_source_atom_v6(work,material,version.key.token)
                if version.key.type_name=='memory.source'else work.projection.get(version.key))
            if not value.valid or value.revision!=version.revision:
                raise UnavailableGuard('D13 inbound actual current atom changed; HOLD')
            return value
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (version.key.token,),
        ).fetchone()
        if row is None or (row[0], row[2]) != (version.revision, 1):
            raise UnavailableGuard("D13 inbound source or arrival changed; HOLD")
        return GraphAtom(version.key, row[0], json.loads(row[1]), True)

    arrival = atom(binding.arrival_event_version)
    account = atom(binding.binding_version)
    source = atom(binding.source_version)
    access = atom(binding.access_version)
    record = SourceRecord.from_dict(source.value)
    validate_access(access.value)
    if ("context" not in record.purposes
            or "context" not in access.value["purposes"]
            or identity["conversation_ref"] not in record.audiences
            or identity["conversation_ref"] not in access.value["audiences"]
            or not record.recorded_at <= now_utc < record.recorded_at + 72 * 60 * 60):
        raise UnavailableGuard("D13 original context source is unavailable; HOLD")
    authority_epochs = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if authority_epochs is None:
        raise UnavailableGuard("D13 access or deletion epoch is absent; HOLD")
    return binding, arrival, account, source, access, epoch, authority_epochs

def _authority_window_dependency_v6():
    from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
    from ..authority_service.current_authority_graph_read_v3 import AuthorityCollectionSourceRequiredV6
    return (AuthorityGraphAttachmentRequiredV3,AuthorityCollectionSourceRequiredV6,D13PaidWindowInputNeededV3)


def _read_current_d13_window_for_authority_v1(db,namespace,scene_ref,conversation_ref,max_slots,now_utc,*,
        before_sequence=None,expected_activation_generation=None,expected_owner_authorization_head=None,
        _collector_context=None,_page_observation=None):
    program=_current_d13_window_program_v6(db,namespace,scene_ref,conversation_ref,max_slots,now_utc,
        before_sequence=before_sequence,expected_activation_generation=expected_activation_generation,
        expected_owner_authorization_head=expected_owner_authorization_head,
        _collector_context=_collector_context,_page_observation=_page_observation)
    while True:
        try:dependency=next(program)
        except StopIteration as complete:return complete.value
        if dependency is not None:raise dependency


def _current_d13_window_program_v6(
    db: sqlite3.Connection, namespace: NamespaceId, scene_ref: str,
    conversation_ref: str, max_slots: int, now_utc: float, *,
    before_sequence: int | None = None,
    expected_activation_generation: int | None = None,
    expected_owner_authorization_head: str | None = None,
    _collector_context=None,
    _page_observation=None,
) -> ConversationWindowProjectionV1:
    """Rebuild current source/access/correction closure in a caller-owned SQL view."""
    from ..graph_coordinator import D13InboundTurnReceiptV1, UnavailableGuard
    from ..authority_service.v2_owner_contract import (
        OwnerGraphCommitProofV1, canonical_digest as owner_contract_digest,
    )
    from ..domains.d01 import _activation_key, _validate_persona_activation
    from ..domains.d03 import RoleBinding
    from ..domains.d06 import source_correction_head_key
    from ..domains.d09.turn_order import (
        complete_inbound_turn_v1, turn_completion_key, turn_order_key,
        turn_slot_key, validate_turn_completion_v1, validate_turn_order_v1,
        validate_turn_slot_v1,
    )
    from ..domains.d13.raw_slice import _merge_ranges
    from ..graph_types import (
        AtomKey, GraphAtom, owner_grant_key, validate_owner_grant_v1,
    )
    from ..memory_types import SourceRecord

    if (not isinstance(db, sqlite3.Connection) or not db.in_transaction or
            type(namespace) is not NamespaceId or
            type(scene_ref) is not str or not scene_ref.startswith("scene:") or
            type(conversation_ref) is not str or not conversation_ref or
            type(max_slots) is not int or not 1 <= max_slots <= 64 or
            type(now_utc) not in (int, float) or not math.isfinite(now_utc) or
            type(expected_activation_generation) is not int or
            expected_activation_generation < 1 or
            before_sequence is not None and
            (type(before_sequence) is not int or before_sequence < 1)):
        raise ValueError("D13 current window needs a pinned bounded DB view")
    if _collector_context is not None:
        _collector_context.require_current(db, namespace, scene_ref, conversation_ref)
    conversation = conversation_ref
    recovery=_window_original_point_v6(db,table='graph_recovery_metadata_v2',
        columns=('schema','requirements_json','graph_revision'),key_columns=('bot','persona'),key=namespace.as_tuple)
    epoch_row = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if recovery is None or epoch_row is None or recovery[0] != "sylanne3.authority.v2":
        raise UnavailableGuard("D13 current graph recovery stamp is absent; HOLD")
    requirements = json.loads(recovery[1])
    if (requirements.get("namespace") != asdict(namespace) or
            requirements.get("activation_generation") !=
            expected_activation_generation or
            type(recovery[2]) is not int or recovery[2] < 1 or
            type(epoch_row[0]) is not int or epoch_row[0] < 1):
        raise UnavailableGuard("D13 graph recovery identity differs; HOLD")
    from ..authority_service.current_authority_graph_read_v3 import _authority_attachment_owner_v3
    authority_work=_authority_attachment_owner_v3(db)
    from .d13_paid_original_read_v3 import d13_paid_current_reader_v3
    paid=d13_paid_current_reader_v3(db)
    def current_atom(key):
        if paid is not None:
            atom=paid.window_atom_v3(key)
            if not atom.valid:raise UnavailableGuard('D13 paid current window atom unavailable; HOLD')
            return atom
        if authority_work is not None:
            atom=authority_work.projection.get(key)
            if not atom.valid:raise UnavailableGuard('D13 actual Authority window atom unavailable; HOLD')
            return atom
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (key.token,),
        ).fetchone()
        if row is None or row[2] != 1:
            raise UnavailableGuard("D13 window graph atom unavailable; HOLD")
        return GraphAtom(key, row[0], json.loads(row[1]), True)

    activation = current_atom(_activation_key(namespace))
    _validate_persona_activation(activation.value)
    grant = current_atom(owner_grant_key(*namespace.as_tuple))
    validate_owner_grant_v1(grant.value)
    if (activation.value["activation_generation"]
            != expected_activation_generation
            or activation.value["authorization_revision"]
            != 1
            or activation.value["owner_grant_id"] != grant.value["grant_id"]
            or activation.value["owner_grant_revision"] != grant.revision
            or activation.value["graph_incarnation"]
            != grant.value["graph_incarnation"]):
        raise UnavailableGuard("D13 current activation differs; HOLD")
    proof_row=_window_original_point_v6(db,table='graph_owner_issue_operations_v1',
        columns=('operation_id','request_digest','grant_id','grant_digest','graph_incarnation','graph_access_epoch',
            'graph_epoch','graph_receipt_digest','proof_json'),key_columns=('bot','persona'),key=namespace.as_tuple)
    if proof_row is None:
        raise UnavailableGuard("D13 Owner issue proof is absent; HOLD")
    proof = OwnerGraphCommitProofV1(
        namespace, proof_row[0], proof_row[1], proof_row[2],
        proof_row[3], proof_row[4], 1, proof_row[5],
        proof_row[6], proof_row[7])
    if (proof_row[8] != canonical_json(asdict(proof))
            or (expected_owner_authorization_head is not None and expected_owner_authorization_head != owner_contract_digest(proof))
            or proof_row[2] != grant.value["grant_id"]):
        raise UnavailableGuard("D13 Owner issue proof differs; HOLD")

    if paid is not None:
        scene_rows=[(atom.key.token,atom.revision,atom.value)for atom in paid.window_family_v3('d03.role_binding')
            if atom.key.owner.kind=='scene'and atom.key.owner.subject==scene_ref]
    elif authority_work is None:
        scene_rows = db.execute(
            "SELECT token,revision,value FROM graph_atoms WHERE bot=? "
            "AND persona=? AND owner_kind='scene' AND subject=? "
            "AND type_name='d03.role_binding' AND valid=1 LIMIT 2",
            namespace.as_tuple + (scene_ref,),
        ).fetchall()
    else:
        scene_rows=[]
        for token,head in authority_work.heads.items():
            key=AtomKey.from_token(token)
            if key.type_name=='d03.role_binding'and key.owner.kind=='scene'and key.owner.subject==scene_ref and head[1]:
                atom=authority_work.projection.get(key);scene_rows.append((token,atom.revision,atom.value))
                if len(scene_rows)==2:break
    if len(scene_rows) != 1:
        raise UnavailableGuard("D13 current scene binding unavailable; HOLD")
    scene_key = AtomKey.from_token(scene_rows[0][0])
    scene_value = json.loads(scene_rows[0][2])if authority_work is None and paid is None else scene_rows[0][2]
    scene_binding = RoleBinding(**{
        **scene_value,
        "norm_refs": tuple(scene_value["norm_refs"]),
        "source_refs": tuple(scene_value["source_refs"]),
    })
    if (scene_key.name != scene_binding.role_binding_id
            or scene_rows[0][1] != scene_binding.binding_version
            or scene_binding.scene_ref != scene_ref
            or scene_binding.status != "active"
            or scene_binding.visibility_scope != "private"
            or scene_binding.subject_persona_ref
            != f"persona:{namespace.persona_id}"
            or not scene_binding.effective_from <= now_utc
            or scene_binding.effective_until is not None
            and now_utc >= scene_binding.effective_until):
        raise UnavailableGuard("D13 scene binding is not current; HOLD")
    if authority_work is None and paid is None:
        scene_receipt = db.execute(
            "SELECT r.receipt_json FROM graph_history AS h "
            "JOIN graph_scene_binding_receipts_v1 AS r "
            "ON r.bot=h.event_bot AND r.persona=h.event_persona "
            "AND r.operation_id=h.event_id WHERE h.token=? AND "
            "h.revision=? AND h.event_session='d03-scene-binding'",
            (scene_key.token, scene_rows[0][1]),
        ).fetchone()
    else:
        event=db.execute('SELECT event_bot,event_persona,event_id,event_session FROM graph_history WHERE token=? AND revision=?',
            (scene_key.token,scene_rows[0][1])).fetchone()
        scene_receipt=(None if event is None or event[3]!='d03-scene-binding'else
            _window_original_point_v6(db,table='graph_scene_binding_receipts_v1',columns=('receipt_json',),
                key_columns=('bot','persona','operation_id'),key=tuple(event[:3])))
    if scene_receipt is None:
        raise UnavailableGuard("D13 scene binding seal is absent; HOLD")
    scene_seal = json.loads(scene_receipt[0])
    if (scene_seal.get("scene_ref") != scene_ref
            or scene_seal.get("binding_id")
            != scene_binding.role_binding_id
            or scene_seal.get("role_head_id")
            != activation.value["head_id"]):
        raise UnavailableGuard("D13 scene binding seal differs; HOLD")
    scene_version = VersionedRef(scene_key.token, scene_rows[0][1])

    order_key = turn_order_key(namespace, scene_ref, conversation)
    order = current_atom(order_key)
    validate_turn_order_v1(order.value)
    if (order.value["scene_ref"], order.value["conversation_ref"]) != (
            scene_ref, conversation) or order.value["version"] != order.revision:
        raise UnavailableGuard("D13 scene turn order differs; HOLD")
    high = order.value["high_watermark"]
    end = high if before_sequence is None else min(high, before_sequence - 1)
    if end < 0:
        raise UnavailableGuard("D13 window page is empty; HOLD")
    start = max(0, end - max_slots + 1)
    gaps = []
    if start:
        gaps.append((0, start - 1))
    if end < high:
        gaps.append((end + 1, high))
    reads = {
        item.key.token: VersionedRef(item.key.token, item.revision)
        for item in (activation, grant, order)
    }
    reads[scene_key.token] = scene_version
    turns = []
    audience_ref = None
    raw_bytes = 0
    def read_record(sequence):
        nonlocal audience_ref, raw_bytes
        slot = current_atom(turn_slot_key(
            namespace, scene_ref, conversation, sequence))
        validate_turn_slot_v1(slot.value)
        if (slot.value["sequence"] != sequence
                or slot.value["scene_ref"] != scene_ref
                or slot.value["conversation_ref"] != conversation):
            raise UnavailableGuard("D13 turn slot scope differs; HOLD")
        reads[slot.key.token] = VersionedRef(slot.key.token, slot.revision)
        completion_key = turn_completion_key(
            namespace, scene_ref, conversation, sequence)
        if paid is not None:
            completion_atom=paid.window_atom_v3(completion_key)
            completion_row=(None if completion_atom.revision==0 else
                (completion_atom.revision,completion_atom.value,int(completion_atom.valid)))
        elif authority_work is None:
            completion_row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (completion_key.token,),
            ).fetchone()
        else:
            completion_atom=authority_work.projection.get(completion_key)
            completion_row=(None if completion_atom.revision==0 else
                (completion_atom.revision,completion_atom.value,int(completion_atom.valid)))
        if completion_row is None:
            if _page_observation is not None:
                _page_observation['unclosed'].append(sequence)
            gaps.append((sequence, sequence))
            return
        if completion_row[2] != 1:
            raise UnavailableGuard("D13 turn completion is invalid; HOLD")
        completion = (GraphAtom(completion_key,completion_row[0],json.loads(completion_row[1]),True)
            if authority_work is None and paid is None else completion_atom)
        validate_turn_completion_v1(completion.value)
        if (completion.value["slot_ref"] != slot.key.token
                or completion.value["direction"]
                != slot.value["direction"]
                or completion.value["sequence"] != sequence
                or completion.value["scene_ref"] != scene_ref
                or completion.value["conversation_ref"] != conversation):
            raise UnavailableGuard("D13 turn completion differs; HOLD")
        reads[completion.key.token] = VersionedRef(
            completion.key.token, completion.revision)
        if slot.value["direction"] == "outbound":
            if now_utc >= completion.value["trusted_utc"] + 72 * 60 * 60:
                if _page_observation is not None:
                    _page_observation['expired'].append(sequence)
                gaps.append((sequence, sequence))
                return
            from .d13_outbound_observation_v1 import read_current_outbound_turn_v1
            turn, outbound_reads = read_current_outbound_turn_v1(
                db, namespace, slot, completion, now_utc=now_utc)
            if audience_ref is None:
                audience_ref = turn.audience_ref
            elif audience_ref != turn.audience_ref:
                raise UnavailableGuard("D13 outbound audience differs; HOLD")
            raw_bytes += len(turn.text.encode("utf-8"))
            if raw_bytes > 128 * 1024:
                raise UnavailableGuard("D13 window raw text exceeds bound; HOLD")
            reads.update((ref.ref, ref) for ref in outbound_reads)
            turns.append(turn)
            return
        if now_utc >= completion.value["trusted_utc"] + 72 * 60 * 60:
            if _page_observation is not None:
                _page_observation['expired'].append(sequence)
            gaps.append((sequence, sequence))
            return
        history = db.execute(
            "SELECT event_session,event_id FROM graph_history "
            "WHERE token=? AND revision=?",
            (slot.key.token, slot.revision),
        ).fetchone()
        if history is None or history[0] != "d13-inbound-turn":
            raise UnavailableGuard("D13 original inbound seal is absent; HOLD")
        ingress_operation_id = history[1]
        saved=_window_original_point_v6(db,table='graph_d13_inbound_turn_attempts_v1',
            columns=('c02_operation_id','receipt_json'),key_columns=('bot','persona','ingress_operation_id'),
            key=namespace.as_tuple+(ingress_operation_id,))
        if saved is None or saved[1] is None:
            raise UnavailableGuard("D13 inbound operation is uncommitted; HOLD")
        receipt = D13InboundTurnReceiptV1(**json.loads(saved[1]))
        if (receipt.ingress_operation_id != ingress_operation_id
                or receipt.c02_operation_id != saved[0]
                or receipt.sequence != sequence
                or receipt.order_ref != order_key.token
                or receipt.slot_ref != slot.key.token
                or receipt.completion_ref != completion.key.token):
            raise UnavailableGuard("D13 inbound operation seal differs; HOLD")
        completion_history = db.execute(
            "SELECT event_session,event_id FROM graph_history "
            "WHERE token=? AND revision=?",
            (completion.key.token, completion.revision),
        ).fetchone()
        if completion_history != history:
            raise UnavailableGuard("D13 completion event differs; HOLD")
        if authority_work is not None:
            record=authority_work.collection_record
            if record is None or record.get('sequence')!=sequence or record.get('scene_ref')!=scene_ref or record.get('conversation_ref')!=conversation:
                authority_work.collection_record={'slot':slot,'completion':completion,'sequence':sequence,
                    'scene_ref':scene_ref,'conversation_ref':conversation,'ingress_operation_id':ingress_operation_id,
                    'c02_operation_id':saved[0]}
        binding, arrival, account, source, access, _, _ = (
            _current_d13_inbound_inputs_locked_v1(
                db, namespace, ingress_operation_id, saved[0], now_utc))
        if (binding.scene_ref != scene_ref
                or binding.conversation_ref != conversation
                or arrival.key.token != slot.value["origin_ref"]):
            raise UnavailableGuard("D13 original inbound route differs; HOLD")
        evidence_version = binding.binding_evidence_event_version
        binding_evidence = current_atom(evidence_version.key)
        if (type(binding_evidence.revision) is not int or binding_evidence.revision < 1
                or binding_evidence.revision != evidence_version.revision):
            raise UnavailableGuard("D13 original binding evidence changed; HOLD")
        expected = complete_inbound_turn_v1(
            namespace, slot, arrival, account, source, access,
            binding_evidence=binding_evidence)
        if (expected.write.key != completion.key
                or expected.write.value != completion.value):
            raise UnavailableGuard("D13 current inbound completion differs; HOLD")
        source_record = SourceRecord.from_dict(source.value)
        if source_record.parent_source_ids:
            raise UnavailableGuard("D13 inbound source ancestry is unsupported; HOLD")
        correction_head = source_correction_head_key(
            namespace, source.key.owner.subject)
        if paid is not None:
            correction_atom=paid.window_atom_v3(correction_head)
            correction_row=(None if correction_atom.revision==0 else (correction_atom.revision,int(correction_atom.valid)))
        else:
            correction_row = db.execute(
                "SELECT revision,valid FROM graph_atoms WHERE token=?",
                (correction_head.token,),
            ).fetchone()
        if correction_row is not None:
            raise UnavailableGuard(
                "D13 original source has a current correction head; HOLD")
        reads[correction_head.token] = VersionedRef(correction_head.token, 0)
        current_audience = VersionedRef(
            account.key.token, account.revision)
        if audience_ref is None:
            audience_ref = current_audience
        elif audience_ref != current_audience:
            raise UnavailableGuard("D13 window has mixed audiences; HOLD")
        raw_bytes += len(source_record.text.encode("utf-8"))
        if raw_bytes > 128 * 1024:
            raise UnavailableGuard("D13 window raw text exceeds bound; HOLD")
        for atom in (arrival, account, source, access):
            reads[atom.key.token] = VersionedRef(
                atom.key.token, atom.revision)
        for version in (binding.anchor_version,
                        binding.binding_evidence_event_version,
                        *binding.binding_scan_versions):
            reads[version.key.token] = VersionedRef(
                version.key.token, version.revision)
        turns.append(CompletedTurnV1(
            conversation, current_audience, sequence,
            VersionedRef(completion.key.token, completion.revision),
            VersionedRef(source.key.token, source.revision),
            VersionedRef(access.key.token, access.revision),
            source_record.speaker_id, source_record.text,
            completion.value["trusted_utc"], "confirmed",
            completion.value["tool_state"]))
    yield None
    for sequence in range(start, end + 1):
        while True:
            try:
                read_record(sequence)
                break
            except _authority_window_dependency_v6() as required:
                yield required
        yield None
    if audience_ref is None:
        if _collector_context is None:
            raise UnavailableGuard("D13 page has no current inbound audience; HOLD")
        _collector_context.require_current(db, namespace, scene_ref, conversation_ref)
        audience_ref = _collector_context.window.audience_ref
        reads.update((ref.ref, ref) for ref in _collector_context.window.read_set)
    authority_epochs = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if authority_epochs is None:
        raise UnavailableGuard("D13 access or deletion epoch absent; HOLD")
    dependencies = tuple(dict.fromkeys(
        ref for turn in turns for ref in
        (turn.raw_ref, turn.source_ref, turn.access_ref)))
    result = ConversationWindowProjectionV1(
        namespace, scene_binding.subject_persona_ref,
        conversation, scene_version, audience_ref, tuple(turns),
        high, now_utc, dependencies,
        tuple(reads.values()), authority_epochs[0],
        authority_epochs[1],
        activation.value["activation_generation"],
        _merge_ranges(gaps))
    return result


def read_current_d13_window_for_authority_v1(db, namespace, scene_ref, conversation_ref, max_slots, now_utc, *,
        before_sequence=None, expected_activation_generation=None, expected_owner_authorization_head=None):
    # Legacy public semantics deliberately retain the empty-page HOLD.
    return _read_current_d13_window_for_authority_v1(db, namespace, scene_ref, conversation_ref, max_slots, now_utc,
        before_sequence=before_sequence, expected_activation_generation=expected_activation_generation,
        expected_owner_authorization_head=expected_owner_authorization_head)


def read_current_d13_frozen_window_for_authority_v1(
    db: sqlite3.Connection, original_window: ConversationWindowProjectionV1,
    now_utc: float, *, before_sequence: int | None = None,
    max_slots: int | None = None,
) -> ConversationWindowProjectionV1:
    """Re-read a frozen page; caller must compare its source fields to original."""
    if type(original_window) is not ConversationWindowProjectionV1:
        raise TypeError("frozen D13 window required")
    from ..graph_types import AtomKey
    scene = AtomKey.from_token(original_window.scene_ref.ref).owner.subject
    if max_slots is None:
        if before_sequence is not None or any(
            end == original_window.order_watermark and start > 0
            for start, end in original_window.missing_ranges
        ):
            raise ValueError("D13 paged original needs its exact cursor and max_slots")
        max_slots = original_window.order_watermark + 1
        if not 1 <= max_slots <= 64:
            raise ValueError("D13 original page size is not inferable")
    return read_current_d13_window_for_authority_v1(
        db, original_window.namespace, scene, original_window.conversation_ref,
        max_slots, now_utc, before_sequence=before_sequence,
        expected_activation_generation=original_window.activation_epoch,
    )


class D13PaidWindowInputNeededV3(Exception):
    def __init__(self, request):
        self.request = request
        super().__init__('D13 current window requires same-Work input EOF')


class _D13WindowMetadataColumnV3:
    """Only bounded D09 scalar metadata, never a turn or attachment body."""
    def __init__(self, reader, key, head):
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.reader,self.key,self.head=reader,key,head
        self.cell=(None if head[2] is None else begin_runtime_cell_read_v3(
            reader.db,head[2],erasure_owner_ref=key.token))
        codec=None if self.cell is None else self.cell.header[0]
        if codec not in {None,'canonical-json.ascii.v1','canonical-json.utf8.v1'}:
            _hold('D13 window metadata has another actual cell codec')
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=codec!='canonical-json.utf8.v1')
        self.values,self.buffers={},{}
        self.offset,self.total,self.fragment=0,None,b''
        self.complete=False
    def emit(self,event):
        if len(event.path)!=1 or type(event.path[0]) is not str:
            if event.kind=='scalar_start':_hold('D13 order/slot/completion metadata is not scalar')
            return
        if event.kind=='scalar_start':self.buffers[event.path]=bytearray()
        elif event.kind=='scalar_chunk':
            value=self.buffers[event.path]
            if len(value)+len(event.raw)>8192:_hold('D13 metadata scalar exceeds bounded refs')
            value.extend(event.raw)
        elif event.kind=='scalar_end':self.values[event.path[0]]=json.loads(self.buffers.pop(event.path))
    def advance_v3(self,meter):
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
        r=self.reader;r.require_current_v3(meter=meter)
        from .source_correction_read_v3 import _heap
        r.reserve_v3(_heap((self.values,self.buffers,self.fragment))+65536)
        if self.fragment:
            part=self.fragment[:1024];r.reserve_v3(65536+len(part)*16)
            self.parser.feed(part,self.emit);self.fragment=self.fragment[len(part):]
            return
        if self.cell is not None:chunk=self.cell.read_fragment(meter=meter)
        else:
            if self.total is None:
                meter.require_available(1024)
                row=r.db.execute('SELECT length(CAST(value AS BLOB)) FROM graph_atoms WHERE token=?',
                    (self.key.token,)).fetchone()
                meter.charge_read(16)
                if row is None:_hold('D13 metadata physical atom disappeared')
                self.total=row[0]
            if self.offset<self.total:
                chunk,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table='graph_atoms',column='value',
                    where='token=?',parameters=(self.key.token,),start=self.offset,
                    length=min(16384,self.total-self.offset),meter=meter)
                if (total,kind)!=(self.total,'text'):_hold('D13 metadata physical identity changed')
                self.offset+=len(chunk)
            else:chunk=None
        if chunk is not None:self.fragment=chunk;r.reserve_v3(65536+len(chunk)*2);return
        result=self.parser.finish()
        if self.cell is not None:
            if (result.sha256,result.byte_count)!=(self.cell.finish(meter=meter),self.cell.header[3]):
                _hold('D13 metadata cell EOF differs')
        elif result.byte_count!=self.total:_hold('D13 metadata TEXT EOF differs')
        self.complete=True


class _D13PaidWindowMetadataV3:
    def __init__(self,reader,scene_ref,max_slots):
        from ..domains.d01 import _activation_key
        from ..domains.d09.turn_order import turn_order_key
        from ..graph_types import owner_grant_key
        reader.require_current_v3()
        if type(max_slots)is not int or not 1<=max_slots<=64 or not scene_ref.startswith('scene:'):
            raise ValueError('D13 window metadata needs its actual bounded scene')
        self.reader,self.scene_ref,self.max_slots=reader,scene_ref,max_slots
        self.before_sequence=reader.args.get('before_sequence')
        if self.before_sequence is not None and (type(self.before_sequence)is not int or self.before_sequence<1):
            raise ValueError('D13 window metadata needs its actual exclusive cursor')
        self.conversation_ref=reader.authority.audience[0]
        self.expires_at_utc=reader.operation.deadline_utc
        self.initial_keys=(_activation_key(reader.namespace),owner_grant_key(*reader.namespace.as_tuple),
            turn_order_key(reader.namespace,scene_ref,self.conversation_ref))
        self.exact_keys={};self.family_heads={};self.coverage={}
        self.refroots=[];self.source_versions=[];self.records=[];self.expired_sequences=[]
        self.phase,self.family,self.cursor='families','d03.role_binding',''
        self.column=None;self.sequence=self.start=self.end=self.high=None
        self.slot=self.completion=None;self.complete=False
    def head_v3(self,meter,key):
        if key.token not in self.exact_keys:
            self.exact_keys[key.token]=meter.read_fixed_row(self.reader.db,'graph_atoms',
                ('revision','valid','value_cell_id'),'token=? AND bot=? AND persona=?',
                (key.token,*self.reader.namespace.as_tuple))
        return self.exact_keys[key.token]
    def advance_v3(self,meter):
        from ..domains.d09.turn_order import (turn_slot_key,turn_completion_key,
            validate_turn_order_v1,validate_turn_slot_v1,validate_turn_completion_v1)
        from ..graph_types import AtomKey
        from ..memory_types import source_key,access_key
        r=self.reader;r.require_current_v3(meter=meter)
        from .source_correction_read_v3 import _heap
        r.reserve_v3(_heap((self.exact_keys,self.family_heads,self.coverage,self.refroots,self.source_versions,self.records))+65536)
        if self.phase=='families':
            row=meter.read_fixed_row(r.db,'graph_atoms',('token','revision','valid','value_cell_id'),
                'bot=? AND persona=? AND type_name=? AND token>? ORDER BY token',
                (*r.namespace.as_tuple,self.family,self.cursor))
            family=self.family_heads.setdefault(self.family,{})
            if row is not None:
                family[row[0]]=tuple(row[1:]);self.exact_keys[row[0]]=tuple(row[1:]);self.cursor=row[0]
                r.reserve_v3();return
            self.coverage[self.family]=True
            if self.family=='d03.role_binding':self.family='d03.account_binding';self.cursor='';return
            self.phase='order';return
        if self.phase in {'order','slot','completion'}:
            key=(self.initial_keys[2] if self.phase=='order' else
                turn_slot_key(r.namespace,self.scene_ref,self.conversation_ref,self.sequence)if self.phase=='slot'else
                turn_completion_key(r.namespace,self.scene_ref,self.conversation_ref,self.sequence))
            if self.column is None:
                head=self.head_v3(meter,key)
                if head is None and self.phase=='completion':self.records.append((self.sequence,self.slot,None));self.phase='next';return
                if head is None or head[1]!=1:_hold('D13 window metadata exact head unavailable')
                self.column=_D13WindowMetadataColumnV3(r,key,head);return
            self.column.advance_v3(meter)
            if not self.column.complete:return
            value=self.column.values;self.column=None
            if self.phase=='order':
                validate_turn_order_v1(value)
                if (value['scene_ref'],value['conversation_ref'],value['version'])!=(self.scene_ref,self.conversation_ref,self.exact_keys[key.token][0]):
                    _hold('D13 window order metadata scope differs')
                self.high=value['high_watermark']
                self.end=self.high if self.before_sequence is None else min(self.high,self.before_sequence-1)
                self.start=max(0,self.end-self.max_slots+1)
                self.sequence=self.start;self.phase='slot';return
            if self.phase=='slot':
                validate_turn_slot_v1(value);self.slot=value
                if (value['scene_ref'],value['conversation_ref'],value['sequence'])!=(self.scene_ref,self.conversation_ref,self.sequence):
                    _hold('D13 window slot metadata scope differs')
                self.phase='completion';return
            validate_turn_completion_v1(value);self.completion=value
            expiry=value['trusted_utc']+72*60*60
            if r.initial_now<expiry:self.expires_at_utc=min(self.expires_at_utc,expiry)
            if (value['scene_ref'],value['conversation_ref'],value['sequence'],value['direction'],value['slot_ref'],value['version'])!=(
                    self.scene_ref,self.conversation_ref,self.sequence,self.slot['direction'],
                    turn_slot_key(r.namespace,self.scene_ref,self.conversation_ref,self.sequence).token,self.exact_keys[key.token][0]):
                _hold('D13 window completion metadata differs')
            if r.initial_now>=expiry:
                self.expired_sequences.append(self.sequence)
                self.records.append((self.sequence,self.slot,self.completion));self.phase='next';return
            skey=AtomKey.from_token(value['source_ref']);akey=AtomKey.from_token(value['access_ref'])
            if skey!=source_key(*r.namespace.as_tuple,skey.owner.subject)or akey!=access_key(*r.namespace.as_tuple,skey.owner.subject):
                _hold('D13 window completion Source/access metadata scope differs')
            shead=self.head_v3(meter,skey);self.head_v3(meter,akey)
            ahead=self.exact_keys[akey.token]
            if shead is None or shead[1]!=1 or ahead is None or ahead[1]!=1:
                _hold('D13 window completion Source/access head absent')
            self.refroots.append(skey.token);self.source_versions.append((skey.token,shead[0]))
            self.source_versions.append((akey.token,self.exact_keys[akey.token][0]))
            self.phase='original_refs';return
        if self.phase=='original_refs':
            skey=AtomKey.from_token(self.completion['source_ref'])
            if self.slot['direction']=='inbound':
                slotkey=turn_slot_key(r.namespace,self.scene_ref,self.conversation_ref,self.sequence)
                history=meter.read_fixed_row(r.db,'graph_history',('event_session','event_id'),
                    'token=? AND revision=?',(slotkey.token,self.exact_keys[slotkey.token][0]))
                if history is None or history[0]!='d13-inbound-turn':_hold('D13 window inbound original metadata absent')
                original=meter.read_fixed_row(r.db,'graph_first_ingress_identity_v1',('source_ref',),
                    'bot=? AND persona=? AND operation_id=?',(*r.namespace.as_tuple,history[1]))
                if original is None or source_key(*r.namespace.as_tuple,original[0])!=skey:
                    _hold('D13 window inbound physical Source ref differs')
            else:
                row=meter.read_fixed_row(r.db,'graph_d13_outbound_observations_v1',
                    ('final_operation_id','source_ref','batch_ref'),
                    'bot=? AND persona=? AND slot_ref=? AND observation_digest=?',
                    (*r.namespace.as_tuple,self.completion['slot_ref'],self.completion['evidence_ref']))
                if row is None or row[1]!=skey.token:_hold('D13 window outbound physical Source ref differs')
                duplicate=meter.read_fixed_row(r.db,'graph_d13_outbound_observations_v1',('final_operation_id',),
                    'bot=? AND persona=? AND slot_ref=? AND observation_digest=? AND final_operation_id<>?',
                    (*r.namespace.as_tuple,self.completion['slot_ref'],self.completion['evidence_ref'],row[0]))
                if duplicate is not None:_hold('D13 window outbound adopted original is ambiguous')
                batch=AtomKey.from_token(row[2]);self.head_v3(meter,batch)
                if (batch.owner.bot,batch.owner.persona)!=r.namespace.as_tuple:_hold('D13 outbound batch metadata crosses namespace')
            self.records.append((self.sequence,self.slot,self.completion));self.phase='next';return
        if self.phase=='next':
            if self.sequence<self.end:self.sequence+=1;self.phase='slot';return
            for key in self.initial_keys:self.head_v3(meter,key)
            self.refroots=tuple(dict.fromkeys(self.refroots));self.source_versions=tuple(dict.fromkeys(self.source_versions))
            self.expired_sequences=tuple(self.expired_sequences)
            self.complete=True;r.reserve_v3()


_D13_WINDOW_POINT_COLUMNS_V3={
    'graph_recovery_metadata_v2':(('bot','persona'),('schema','requirements_json','graph_revision')),
    'graph_owner_issue_operations_v1':(('bot','persona'),('operation_id','request_digest','grant_id','grant_digest','graph_incarnation','graph_access_epoch','graph_epoch','graph_receipt_digest','proof_json')),
    'graph_scene_binding_receipts_v1':(('bot','persona','operation_id'),('receipt_json',)),
    'graph_d13_inbound_turn_attempts_v1':(('bot','persona','ingress_operation_id'),('c02_operation_id','receipt_json')),
    'graph_first_ingress_identity_v1':(('bot','persona','operation_id'),('source_ref','platform_ref','conversation_ref','sender_ref','message_id','visibility','identity_json','content_fingerprint','learned_at','bundle_digest')),
    'graph_first_ingress_intents_v2':(('bot','persona','operation_id'),('identity_json',)),
    'ingress_first_observations':(('bot','persona','operation_id'),('content_fingerprint','learned_at','bundle_digest')),
    'graph_bundle_operations':(('bot','persona','operation_id'),('digest',)),
    'graph_first_ingress_c02_committed_seals_v2':(('bot','persona','operation_id'),('schema','bundle_digest','bundle_json')),
    'graph_d13_outbound_observations_v1':(('bot','persona','slot_ref','observation_digest'),('source_ref','batch_ref','observation_json','original_json','original_digest')),
}


class _D13PaidWindowBodyV3:
    def __init__(self,reader,metadata):
        reader.require_current_v3()
        if not reader.qualified or metadata.reader is not reader or not metadata.complete:
            _hold('D13 window body requires ALLwindow Sources/ancestors current rights')
        self.reader,self.metadata=reader,metadata
        self.atoms,self.points,self.families={},{},{}
        self.queue=[('atom',key.token)for key in metadata.initial_keys]+[('family','d03.role_binding')]
        self.queue += [('point','graph_recovery_metadata_v2',('schema','requirements_json','graph_revision'),('bot','persona'),reader.namespace.as_tuple),
            ('point','graph_owner_issue_operations_v1',_D13_WINDOW_POINT_COLUMNS_V3['graph_owner_issue_operations_v1'][1],('bot','persona'),reader.namespace.as_tuple)]
        self.request=self.column=self.point_values=None;self.column_index=0
        self.program=self.window=None;self.complete=False;self.startup=False
    def reserve_v3(self):
        from .source_correction_read_v3 import _heap
        payload=tuple(atom.value for atom in self.atoms.values())
        size=_heap(payload)+65536
        if self.column is not None:
            size+=_heap((self.column.fragment,self.column.body,self.column.value))
            if self.column.body is not None:size+=len(self.column.body)*10
        self.reader.reserve_v3(size)
    @property
    def namespace(self):return self.reader.namespace
    @property
    def query(self):
        return QueryEpoch(self.reader.namespace,'all',self.reader.graph_stamp[1].revision)
    @property
    def projection(self):return self
    def get(self,key):return self.atom_v3(key)
    def require_current(self,db,namespace,query):
        self.reader.require_current_v3()
        if db is not self.reader.db or namespace!=self.namespace or query!=self.query:
            _hold('D13 reply inventory crossed actual current scope')
    def source_metadata(self,db,namespace,query,key,*,require_grant):
        from types import SimpleNamespace
        self.require_current(db,namespace,query)
        source=self.reader.sources[key.token]
        return SimpleNamespace(key=source.key,revision=source.revision,valid=source.valid,
            metadata=source.metadata,**source.metadata)
    def atom_rows(self,db,namespace,query,kinds,columns):
        self.require_current(db,namespace,query)
        if kinds!=('d03.account_binding',)or columns!=('token','revision','value'):
            _hold('D13 reply inventory requested another family shape')
        return tuple((atom.key.token,atom.revision,atom.value)for atom in self.family_v3(kinds[0]))
    def atom_v3(self,key):
        self.reader.require_current_v3()
        if key.token not in self.atoms:raise D13PaidWindowInputNeededV3(('atom',key.token))
        return self.atoms[key.token]
    def family_v3(self,type_id):
        self.reader.require_current_v3()
        if type_id not in self.metadata.family_heads:_hold('D13 window requested unregistered family')
        if type_id not in self.families:raise D13PaidWindowInputNeededV3(('family',type_id))
        return self.families[type_id]
    def original_point_v3(self,table,columns,key_columns,key):
        self.reader.require_current_v3()
        registry=_D13_WINDOW_POINT_COLUMNS_V3[table]
        columns,key_columns,key=tuple(columns),tuple(key_columns),tuple(key)
        if key_columns!=registry[0]or any(c not in registry[1]for c in columns)or key[:2]!=self.reader.namespace.as_tuple:
            _hold('D13 window point request differs from registered actual original')
        request=('point',table,columns,key_columns,key)
        if request not in self.points:raise D13PaidWindowInputNeededV3(request)
        return self.points[request]
    def _advance_input_v3(self,meter):
        from ..graph_types import AtomKey,GraphAtom
        from .d13_paid_original_read_v3 import _ColumnV3
        r=self.reader;self.reserve_v3()
        if self.request is None:self.request=self.queue.pop(0)
        req=self.request
        if req[0]=='family':
            kind=req[1];heads=self.metadata.family_heads[kind]
            missing=[token for token,head in heads.items()if head[1] and token not in self.atoms]
            if missing:
                self.request=None;self.queue[:0]=[('atom',missing[0]),req];return
            self.families[kind]=tuple(self.atoms[token]for token,head in heads.items()if head[1])
            self.request=None;return
        if req[0]=='atom':
            key=AtomKey.from_token(req[1])
            if key.token in self.atoms:self.request=None;return
            if (key.owner.bot,key.owner.persona)!=r.namespace.as_tuple:_hold('D13 window atom crosses namespace')
            if self.column is None:
                head=meter.read_fixed_row(r.db,'graph_atoms',('revision','valid','value_cell_id'),
                    'token=? AND bot=? AND persona=?',(key.token,*r.namespace.as_tuple))
                frozen=self.metadata.exact_keys.get(key.token,head)
                if head!=frozen:_hold('D13 metadata exact atom head changed before body EOF')
                self.metadata.exact_keys[key.token]=head
                if head is None:self.atoms[key.token]=GraphAtom(key,0,{},False);self.request=None;return
                self.column=_ColumnV3(r,table='graph_atoms',column='value',key_columns=('token',),key=(key.token,),cell_id=head[2]);return
            self.column.advance(meter)
            if not self.column.complete:return
            head=self.metadata.exact_keys[key.token]
            self.atoms[key.token]=GraphAtom(key,head[0],json.loads(self.column.value),bool(head[1]))
            self.column=None;self.request=None;self.reserve_v3();return
        if self.point_values is None:
            table,columns,key_columns,key=req[1:]
            jsoncols=tuple(c for c in columns if c.endswith('_json'))
            fixed=tuple(c for c in columns if c not in jsoncols)
            row=meter.read_fixed_row(r.db,table,fixed or (key_columns[-1],),
                ' AND '.join(c+'=?'for c in key_columns),key)
            if row is None:self.points[req]=None;self.request=None;return
            self.point_values=dict(zip(fixed,row));self.column_index=0
        table,columns,key_columns,key=req[1:];jsoncols=tuple(c for c in columns if c.endswith('_json'))
        if self.column_index==len(jsoncols):
            self.points[req]=tuple(self.point_values[c]for c in columns)
            self.point_values=None;self.request=None;r.reserve_v3();return
        if self.column is None:
            self.column=_ColumnV3(r,table=table,column=jsoncols[self.column_index],key_columns=key_columns,key=key);return
        self.column.advance(meter)
        if self.column.complete:
            self.point_values[jsoncols[self.column_index]]=self.column.value
            self.column=None;self.column_index+=1;r.reserve_v3()
    def advance_v3(self,meter):
        from .d13_paid_original_read_v3 import bind_d13_paid_window_reader_v3
        r=self.reader;r.require_current_v3(meter=meter)
        self.reserve_v3()
        if not r.qualified:_hold('D13 window body lost all-root current rights')
        if self.queue or self.request is not None:self._advance_input_v3(meter);return
        if not self.startup:
            scenes=[atom for atom in self.families['d03.role_binding']
                if atom.key.owner.kind=='scene'and atom.key.owner.subject==self.metadata.scene_ref]
            if len(scenes)!=1:_hold('D13 current scene metadata has no unique current role')
            atom=scenes[0]
            event=meter.read_fixed_row(r.db,'graph_history',('event_bot','event_persona','event_id','event_session'),
                'token=? AND revision=?',(atom.key.token,atom.revision))
            if event is None or event[3]!='d03-scene-binding':_hold('D13 scene binding original absent')
            self.queue.append(('point','graph_scene_binding_receipts_v1',('receipt_json',),('bot','persona','operation_id'),tuple(event[:3])))
            self.startup=True;return
        if self.program is None:
            requirements=json.loads(self.points[('point','graph_recovery_metadata_v2',('schema','requirements_json','graph_revision'),('bot','persona'),r.namespace.as_tuple)][1])
            self.program=_current_d13_window_program_v6(r.db,r.namespace,self.metadata.scene_ref,
                self.metadata.conversation_ref,self.metadata.max_slots,r.initial_now,
                before_sequence=self.metadata.before_sequence,
                expected_activation_generation=requirements['activation_generation'],
                expected_owner_authorization_head=r.owner_guard_head)
        with bind_d13_paid_window_reader_v3(r):
            try:needed=next(self.program)
            except StopIteration as done:self.window=done.value;self.complete=True;r.reserve_v3();return
        if needed is not None:
            if type(needed)is not D13PaidWindowInputNeededV3:raise needed
            self.queue.append(needed.request)
        r.reserve_v3()


def begin_d13_paid_window_metadata_v3(reader,scene_ref,max_slots):
    return _D13PaidWindowMetadataV3(reader,scene_ref,max_slots)


def begin_d13_paid_window_body_v3(reader,metadata):
    return _D13PaidWindowBodyV3(reader,metadata)


__all__ = (
    "read_current_d13_window_for_authority_v1",
    "read_current_d13_frozen_window_for_authority_v1",
)
