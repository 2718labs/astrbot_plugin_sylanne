"""W01 transaction read for source-specific current C04 projections.

The caller must hold the current Owner fence. This reader obtains historical
baselines and current graph/joint originals from that same graph connection;
it never accepts a caller's salience or tone interval as evidence.
"""

from __future__ import annotations

from dataclasses import asdict
import json
import sqlite3

from ..contracts import canonical_json
from ..domains.d04.affect import MoodField, _decode_mood
from ..domains.d04.c04_projection_issuer_v3 import (
    conditional_current_salience_contract_v3,
    issue_current_conditioned_projection_v3,
)
from ..domains.d04.interval_projection_v2 import D04IntervalProjectionPolicyV2
from ..domains.d04.encoding_baseline_v2 import ProjectionNumericErrorV2
from ..domains.d04.root import encode_numeric_checkpoint
from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..native_runtime.d04_tanh_readout_asset import D04LoadedTanhReadoutAsset
from ..runtime_contracts import NamespaceId, canonical_digest
from .c04_encoding_baseline_store_v3 import (
    _joint_numeric, _receipt, read_c04_encoding_baseline_v3,
)
from .c04_v3_contracts import AssociationTargetV3
from .d04_joint_advance_v2 import (
    JointNumericOriginalV1, JointNumericOriginalVerificationV1,
    _decode_numeric_candidate,
)
from .d04_joint_output_original_store_v1 import read_d04_joint_output_original_v1


class C04CurrentProjectionHold(ValueError):
    """Current graph, baseline, or installed numerical original differs."""


def _head(db: sqlite3.Connection, namespace: NamespaceId,
          ref: str) -> tuple[int, dict]:
    key = AtomKey.from_token(ref)
    if NamespaceId.from_key(key) != namespace:
        raise C04CurrentProjectionHold("C04 current head crosses namespace")
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
        "AND bot=? AND persona=?", (ref, *namespace.as_tuple),
    ).fetchone()
    if row is None or row[0] < 1 or row[2] != 1:
        raise C04CurrentProjectionHold("C04 current graph head is absent")
    try:
        value = json.loads(row[1])
        if type(value) is not dict or canonical_json(value) != row[1]:
            raise ValueError("noncanonical current graph head")
    except (TypeError, ValueError) as exc:
        raise C04CurrentProjectionHold("C04 current graph head is malformed") from exc
    return row[0], value


def _source_closure_digest(db: sqlite3.Connection, namespace: NamespaceId,
                           roots: tuple[str, ...], audience: str,
                           purpose: str) -> str:
    pending = list(roots)
    seen: set[str] = set()
    reads: list[tuple[str, int, str]] = []
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        if len(seen) >= 256:
            raise C04CurrentProjectionHold("source ancestry exceeds C04 bound")
        seen.add(ref)
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject):
            raise C04CurrentProjectionHold("source identity differs")
        source_revision, source_value = _head(db, namespace, ref)
        access_ref = access_key(*namespace.as_tuple, key.owner.subject).token
        access_revision, access_value = _head(db, namespace, access_ref)
        correction = source_correction_head_key(namespace, key.owner.subject)
        correction_row = db.execute(
            "SELECT revision,valid FROM graph_atoms WHERE token=?",
            (correction.token,),
        ).fetchone()
        if correction_row is not None and correction_row[1] == 1:
            raise C04CurrentProjectionHold("source has an active correction head")
        try:
            source = SourceRecord.from_dict(source_value)
            validate_access(access_value)
        except (TypeError, ValueError) as exc:
            raise C04CurrentProjectionHold("source or access value differs") from exc
        if (source.source_id != key.owner.subject
                or access_value["source_id"] != source.source_id
                or access_value["status"] != "active"
                or purpose not in source.purposes
                or purpose not in access_value["purposes"]
                or audience not in source.audiences
                or audience not in access_value["audiences"]):
            raise C04CurrentProjectionHold("source or ancestor is not authorized")
        reads.extend(((ref, source_revision, canonical_digest(source_value)),
                      (access_ref, access_revision, canonical_digest(access_value)),
                      (correction.token, correction_row[0] if correction_row else 0,
                       "absent" if correction_row is None else "invalid")))
        pending.extend(source_key(*namespace.as_tuple, parent).token
                       for parent in source.parent_source_ids)
    return canonical_digest(tuple(sorted(reads)))


def issue_current_c04_target_v3(
    db: sqlite3.Connection, *, namespace: NamespaceId, operation_id: str,
    encoding_operation_id: str, source_ref: str,
    mood_joint_operation_id: str, mood_ref: str,
    audience: str, purpose: str,
    owner_epoch: int, access_epoch: int, delete_epoch: int,
    asset: D04LoadedTanhReadoutAsset,
    policy: D04IntervalProjectionPolicyV2,
) -> AssociationTargetV3:
    """Issue one eligible target from authenticated baseline and current Mood.

    W01 supplies the Owner epoch from its live fence and invokes this inside
    its transaction. Access/delete epochs are independently checked here.
    """
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(namespace) is not NamespaceId
            or type(operation_id) is not str or not operation_id
            or type(audience) is not str or not audience
            or type(owner_epoch) is not int or owner_epoch < 0
            or type(asset) is not D04LoadedTanhReadoutAsset
            or type(policy) is not D04IntervalProjectionPolicyV2):
        raise C04CurrentProjectionHold("W01 current projection transaction differs")
    rights = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if rights != (access_epoch, delete_epoch):
        raise C04CurrentProjectionHold("current access or deletion epoch changed")
    baseline = read_c04_encoding_baseline_v3(
        db, namespace=namespace, encoding_operation_id=encoding_operation_id,
        source_ref=source_ref,
    )
    source_revision, _ = _head(db, namespace, source_ref)
    if source_revision != baseline.original.source.revision:
        raise C04CurrentProjectionHold("source changed since encoding baseline")
    mood_revision, mood_value = _head(db, namespace, mood_ref)
    from .c04_d04_state_codec_v3 import decode_c04_mood_v3
    from ..domains.d04.joint_state_output_v1 import joint_checkpoint_payload_v1
    mood = decode_c04_mood_v3(mood_ref, mood_value)
    from .d04_series_original_v1 import require_series_adopted_original_v1
    require_series_adopted_original_v1(db, namespace, mood_joint_operation_id)
    output = read_d04_joint_output_original_v1(
        db, namespace, mood_joint_operation_id)
    if output is None:
        raise C04CurrentProjectionHold("adopted current Mood output is absent")
    member = next((item for item in output.members
                   if item.predecessor_state_ref == mood_ref), None)
    if (member is None or member.predecessor_state_revision + 1 != mood_revision
            or member.next_state != mood):
        raise C04CurrentProjectionHold("Mood differs from adopted joint output")
    checkpoint_revision, checkpoint_value = _head(
        db, namespace, member.checkpoint_ref)
    if (checkpoint_revision != member.predecessor_checkpoint_revision + 1
            or canonical_digest(checkpoint_value)
               != canonical_digest(joint_checkpoint_payload_v1(
                   member.next_checkpoint))):
        raise C04CurrentProjectionHold("Mood checkpoint differs from joint output")
    for ref, revision in ((mood_ref, mood_revision),
                          (member.checkpoint_ref, checkpoint_revision)):
        row = db.execute(
            "SELECT event_id FROM graph_history WHERE token=? AND revision=?",
            (ref, revision),
        ).fetchone()
        if row != (mood_joint_operation_id,):
            raise C04CurrentProjectionHold("Mood graph history lacks joint adoption")
    joint_receipt_digest = canonical_digest(asdict(
        _receipt(db, namespace, mood_joint_operation_id)))
    numeric_row = db.execute(
        "SELECT numeric_receipt_json,verification_json "
        "FROM graph_d04_joint_numeric_originals_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (mood_joint_operation_id,),
    ).fetchone()
    if numeric_row is None:
        raise C04CurrentProjectionHold("current Mood numeric original is absent")
    try:
        candidate = _decode_numeric_candidate(numeric_row[0])
        verification_raw = json.loads(numeric_row[1])
        verification_raw["numeric_error"] = ProjectionNumericErrorV2(
            **verification_raw["numeric_error"])
        verification = JointNumericOriginalVerificationV1(**verification_raw)
        expected_numeric_digest = canonical_digest(asdict(JointNumericOriginalV1(
            member.checkpoint_ref, checkpoint_revision,
            mood_joint_operation_id, joint_receipt_digest,
            candidate, verification,
        )))
    except (TypeError, ValueError, KeyError) as exc:
        raise C04CurrentProjectionHold("current Mood numeric original is malformed") from exc
    numeric = _joint_numeric(
        db, namespace, mood_joint_operation_id, member.checkpoint_ref,
        checkpoint_revision, joint_receipt_digest, expected_numeric_digest,
    )
    closure = _source_closure_digest(
        db, namespace, (source_ref, *mood.source_refs), audience, purpose)
    projection = issue_current_conditioned_projection_v3(
        mood_joint_operation_id=mood_joint_operation_id,
        baseline=baseline.proof,
        baseline_receipt_ref=("graph_c04_encoding_baselines_v3/"
                              + encoding_operation_id + "/" + source_ref),
        baseline_receipt_revision=1,
        baseline_receipt_digest=baseline.record_digest,
        mood_ref=mood_ref, mood_revision=mood_revision,
        mood_output_original=output, mood_numeric_original=numeric,
        asset=asset, policy=policy,
    )
    condition = conditional_current_salience_contract_v3(
        projection, baseline_contract=baseline.original,
        operation_id=operation_id, source_closure_digest=closure,
        audience=audience, purpose=purpose,
        owner_epoch=owner_epoch, access_epoch=access_epoch,
        delete_epoch=delete_epoch,
    )
    from .c04_v3_contracts import AssociationTargetAuthoredV3, D04EncodingBaselineAuthoredOriginalV3
    target_type = (AssociationTargetAuthoredV3
                   if type(baseline.original) is D04EncodingBaselineAuthoredOriginalV3
                   else AssociationTargetV3)
    return target_type(source_ref, baseline.original, condition)


def issue_current_c04_targets_v3(
    db: sqlite3.Connection, *, namespace: NamespaceId, operation_id: str,
    encoding_operations: tuple[tuple[str, str], ...],
    mood_joint_operation_id: str, mood_ref: str,
    audience: str, purpose: str,
    owner_epoch: int, access_epoch: int, delete_epoch: int,
    asset: D04LoadedTanhReadoutAsset,
    policy: D04IntervalProjectionPolicyV2,
) -> tuple[AssociationTargetV3, ...]:
    """Issue all qualified source targets using each source's own baseline."""
    if (type(encoding_operations) is not tuple or not encoding_operations
            or any(type(item) is not tuple or len(item) != 2
                   or any(type(value) is not str or not value for value in item)
                   for item in encoding_operations)
            or tuple(sorted({item[0] for item in encoding_operations}))
               != tuple(item[0] for item in encoding_operations)):
        raise C04CurrentProjectionHold("candidate encoding operations differ")
    return tuple(issue_current_c04_target_v3(
        db, namespace=namespace, operation_id=operation_id,
        source_ref=source_ref, encoding_operation_id=encoding_operation_id,
        mood_joint_operation_id=mood_joint_operation_id, mood_ref=mood_ref,
        audience=audience, purpose=purpose,
        owner_epoch=owner_epoch, access_epoch=access_epoch,
        delete_epoch=delete_epoch, asset=asset, policy=policy,
    ) for source_ref, encoding_operation_id in encoding_operations)


__all__ = ["C04CurrentProjectionHold", "issue_current_c04_target_v3",
           "issue_current_c04_targets_v3"]
