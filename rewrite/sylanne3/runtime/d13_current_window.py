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


def _reply_ingress_identity_locked(db, namespace, ingress_operation_id):
    from .ingress_observation import read_committed_ingress_identity
    rows = db.execute(
        "SELECT source_ref FROM graph_first_ingress_identity_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (ingress_operation_id,),
    ).fetchall()
    if len(rows) != 1:
        _hold("original private ingress is absent; HOLD")
    receipt = read_committed_ingress_identity(db, namespace, rows[0][0])
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
    seal = db.execute(
        "SELECT schema,bundle_digest,bundle_json FROM "
        "graph_first_ingress_c02_committed_seals_v2 WHERE "
        "bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (c02_operation_id,),
    ).fetchone()
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
    binding = read_current_reply_entity_route_binding_v2(
        db, namespace, route, epoch,
        now_utc=now_utc)

    def atom(version):
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

def read_current_d13_window_for_authority_v1(
    db: sqlite3.Connection, namespace: NamespaceId, scene_ref: str,
    conversation_ref: str, max_slots: int, now_utc: float, *,
    before_sequence: int | None = None,
    expected_activation_generation: int | None = None,
    expected_owner_authorization_head: str | None = None,
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
    conversation = conversation_ref
    recovery = db.execute(
        "SELECT schema,requirements_json,graph_revision FROM "
        "graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
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
    def current_atom(key):
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
    proof_row = db.execute(
        "SELECT operation_id,request_digest,grant_id,grant_digest,"
        "graph_incarnation,graph_access_epoch,graph_epoch,"
        "graph_receipt_digest,proof_json FROM "
        "graph_owner_issue_operations_v1 WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
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

    scene_rows = db.execute(
        "SELECT token,revision,value FROM graph_atoms WHERE bot=? "
        "AND persona=? AND owner_kind='scene' AND subject=? "
        "AND type_name='d03.role_binding' AND valid=1 LIMIT 2",
        namespace.as_tuple + (scene_ref,),
    ).fetchall()
    if len(scene_rows) != 1:
        raise UnavailableGuard("D13 current scene binding unavailable; HOLD")
    scene_key = AtomKey.from_token(scene_rows[0][0])
    scene_value = json.loads(scene_rows[0][2])
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
    scene_receipt = db.execute(
        "SELECT r.receipt_json FROM graph_history AS h "
        "JOIN graph_scene_binding_receipts_v1 AS r "
        "ON r.bot=h.event_bot AND r.persona=h.event_persona "
        "AND r.operation_id=h.event_id WHERE h.token=? AND "
        "h.revision=? AND h.event_session='d03-scene-binding'",
        (scene_key.token, scene_rows[0][1]),
    ).fetchone()
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
    for sequence in range(start, end + 1):
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
        completion_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (completion_key.token,),
        ).fetchone()
        if completion_row is None:
            gaps.append((sequence, sequence))
            continue
        if completion_row[2] != 1:
            raise UnavailableGuard("D13 turn completion is invalid; HOLD")
        completion = GraphAtom(
            completion_key, completion_row[0],
            json.loads(completion_row[1]), True)
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
                gaps.append((sequence, sequence))
                continue
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
            continue
        if now_utc >= completion.value["trusted_utc"] + 72 * 60 * 60:
            gaps.append((sequence, sequence))
            continue
        history = db.execute(
            "SELECT event_session,event_id FROM graph_history "
            "WHERE token=? AND revision=?",
            (slot.key.token, slot.revision),
        ).fetchone()
        if history is None or history[0] != "d13-inbound-turn":
            raise UnavailableGuard("D13 original inbound seal is absent; HOLD")
        ingress_operation_id = history[1]
        saved = db.execute(
            "SELECT c02_operation_id,receipt_json FROM "
            "graph_d13_inbound_turn_attempts_v1 WHERE bot=? AND "
            "persona=? AND ingress_operation_id=?",
            namespace.as_tuple + (ingress_operation_id,),
        ).fetchone()
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
    if audience_ref is None:
        raise UnavailableGuard("D13 page has no current inbound audience; HOLD")
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


__all__ = (
    "read_current_d13_window_for_authority_v1",
    "read_current_d13_frozen_window_for_authority_v1",
)
