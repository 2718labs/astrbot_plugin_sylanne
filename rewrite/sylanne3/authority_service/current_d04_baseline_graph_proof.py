"""Read-only proof that a frozen V3 baseline is a real earlier D04 commit."""

from __future__ import annotations

from dataclasses import asdict
import json
import sqlite3

from ..contracts import canonical_json
from ..domains.d04.encoding_baseline import decode_encoding_baseline
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch
from ..memory_types import source_key
from ..runtime.d03_self_identity_projection_identity import (
    d03_self_identity_projection_activity_id_v1,
    d03_self_identity_projection_operation_id_v1,
)
from ..runtime.encoding_call_binding import CommittedEncodingBaselineV1
from ..runtime.issuers import (
    D03_SELF_IDENTITY_PROJECTION_WORK_KIND, D04_BASELINE_WORK_KIND,
    D11BudgetJobIssuer, IssuerAuthorityDenied,
    d03_self_identity_projection_quote_id,
    d04_baseline_quote_id,
)
from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2, canonical_digest
from .v2_contract import FencePermitV2, from_wire as fence_from_wire, to_wire as fence_to_wire


def _canonical(raw: str):
    value = json.loads(raw)
    if canonical_json(value) != raw:
        raise ValueError("noncanonical D04 graph proof")
    return value


def _stage_lineage_current(
    db: sqlite3.Connection, *, namespace: NamespaceId, stage: str,
    source_ref: str, operation_id: str, bundle_digest: str,
    event_ref: str | None,
    perspective_ref: str | None, perspective_revision: int | None,
    certification_ref: str | None, requirements: SnapshotRequirementsV2,
) -> bool:
    """Walk a committed stage's immutable retry chain back to its v1 ID."""
    if stage not in {"d03", "d04"}:
        return False
    ns = namespace.as_tuple
    head_table = ("graph_d03_self_projection_intents_v1" if stage == "d03"
                  else "graph_d04_baseline_intents_v1")
    issuance_table = ("graph_d03_self_projection_issuance_v1" if stage == "d03"
                      else "graph_d04_baseline_issuance_v1")
    heads = db.execute(
        f"SELECT original_operation_id,operation_id,bundle_digest FROM {head_table} "
        "WHERE bot=? AND persona=? AND source_ref=?",
        ns + (source_ref,),
    ).fetchall()
    if len(heads) != 1 or heads[0][1:] != (operation_id, bundle_digest):
        return False
    original_ingress = heads[0][0]
    if type(original_ingress) is not str or not original_ingress:
        return False
    if stage == "d03":
        if type(certification_ref) is not str:
            return False
        v1_id = d03_self_identity_projection_operation_id_v1(
            namespace, source_ref, certification_ref)
    else:
        if (type(event_ref) is not str or type(perspective_ref) is not str
                or type(perspective_revision) is not int
                or perspective_revision < 1):
            return False
        v1_id = "d04-baseline-" + canonical_digest({
            "namespace": ns, "source": source_ref, "event": event_ref,
            "perspective": perspective_ref,
            "perspective_revision": perspective_revision,
        })[:40]
    has_lineage = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='graph_stage_retry_lineage_v1'",
    ).fetchone() is not None
    if operation_id == v1_id:
        return (not has_lineage or db.execute(
            "SELECT 1 FROM graph_stage_retry_lineage_v1 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (operation_id,),
        ).fetchone() is None)
    if not has_lineage:
        return False
    current = operation_id
    next_index = None
    seen = set()
    while current != v1_id:
        if current in seen or len(seen) >= 64:
            return False
        seen.add(current)
        rows = db.execute(
            "SELECT stage,source_ref,original_operation_id,"
            "previous_operation_id,retry_index,previous_bundle_digest,"
            "previous_attempt_id,previous_rejection_digest "
            "FROM graph_stage_retry_lineage_v1 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (current,),
        ).fetchall()
        if len(rows) != 1:
            return False
        (saved_stage, saved_source, saved_original, previous, index,
         previous_digest, previous_attempt, previous_rejection_digest) = rows[0]
        if (saved_stage != stage or saved_source != source_ref
                or saved_original != original_ingress
                or type(index) is not int or not 1 <= index <= 64
                or (next_index is not None and index != next_index - 1)):
            return False
        if stage == "d03":
            expected = "d03-self-projection-" + canonical_digest({
                "schema": "sylanne3.d03.self-identity-projection-retry.v2",
                "namespace": ns, "original_operation_id": v1_id,
                "previous_operation_id": previous,
                "retry_index": index,
            })[:40]
        else:
            expected = "d04-baseline-" + canonical_digest({
                "schema": "sylanne3.d04.encoding-baseline-retry.v2",
                "namespace": ns, "source_ref": source_ref,
                "event_ref": event_ref,
                "perspective_ref": perspective_ref,
                "perspective_revision": perspective_revision,
                "previous_operation_id": previous,
                "retry_index": index,
            })[:40]
        if expected != current or (index == 1) != (previous == v1_id):
            return False
        previous_intent = db.execute(
            "SELECT digest,fence_attempt_id,requirements_json,anchor_json,"
            "graph_revision,graph_epoch FROM graph_bundle_intents_v2 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (previous,),
        ).fetchone()
        rejection = db.execute(
            "SELECT digest,status,permit_json,graph_revision,graph_epoch,"
            "finish_request_id,finish_request_digest "
            "FROM graph_bundle_rejections_v2 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (previous,),
        ).fetchone()
        if (previous_intent is None or rejection is None
                or previous_intent[0] != previous_digest
                or rejection[0:2] != (previous_digest, "rejected_no_commit")
                or previous_intent[1] != previous_attempt
                or rejection[3:5] != previous_intent[4:6]
                or previous_rejection_digest != canonical_digest(list(rejection))
                or db.execute(
                    "SELECT 1 FROM graph_bundle_operations WHERE bot=? "
                    "AND persona=? AND operation_id=?", ns + (previous,),
                ).fetchone() is not None
                or db.execute(
                    "SELECT 1 FROM graph_bundle_fences_v2 WHERE bot=? "
                    "AND persona=? AND operation_id=?", ns + (previous,),
                ).fetchone() is not None
                or db.execute(
                    f"SELECT 1 FROM {issuance_table} WHERE bot=? "
                    "AND persona=? AND operation_id=?", ns + (previous,),
                ).fetchone() is not None):
            return False
        calculated_attempt = "graph-write-" + canonical_digest({
            "namespace": list(ns), "operation_id": previous,
            "bundle_digest": previous_digest,
        })[:48]
        permit_wire = _canonical(rejection[2])
        permit = fence_from_wire(permit_wire)
        saved_requirements = _canonical(previous_intent[2])
        if (previous_attempt != calculated_attempt
                or permit_wire != fence_to_wire(permit)
                or permit.operation != "write"
                or permit.operation_id != previous_attempt
                or permit.authority_id != requirements.authority_id
                or permit.namespace != requirements.authority_namespace
                or permit.generation != requirements.activation_generation
                or _canonical(previous_intent[3]) != asdict(permit.pinned_anchor)
                or saved_requirements.get("namespace") != asdict(namespace)
                or saved_requirements.get("graph_incarnation")
                   != requirements.graph_incarnation
                or rejection[5] != "abort:" + previous_attempt
                or rejection[6] != "sha256:" + canonical_digest({
                    "operation_id": previous_attempt,
                    "permit_token": permit.token,
                    "action": "rejected_no_commit",
                    "business_operation_id": previous,
                    "bundle_digest": previous_digest,
                })):
            return False
        current = previous
        next_index = index
    return next_index == 1


def _signed_stage_quote(
    db: sqlite3.Connection, *, issuer: D11BudgetJobIssuer,
    namespace: NamespaceId, stage: str, quote_id: str,
    operation_id: str, activity_id: str,
) -> bool:
    if type(issuer) is not D11BudgetJobIssuer:
        return False
    expected_id = (d03_self_identity_projection_quote_id(namespace, operation_id)
                   if stage == "d03" else
                   d04_baseline_quote_id(namespace, operation_id))
    quote = issuer.resource_issuer.original_signed_quote(db, quote_id, 1)
    reservations = db.execute(
        "SELECT lease_id,ceiling_json FROM runtime_budget_reservations "
        "WHERE operation_id=?", (operation_id,),
    ).fetchall()
    return (quote_id == expected_id and len(reservations) == 1
            and (quote.bot_id, quote.persona_id) == namespace.as_tuple
            and (quote.activity_id, quote.operation_id, quote.effect_id)
               == (activity_id, operation_id, None)
            and quote.work_kind == (
                D03_SELF_IDENTITY_PROJECTION_WORK_KIND if stage == "d03"
                else D04_BASELINE_WORK_KIND)
            and quote.parent_budget_lease_ref == reservations[0][0]
            and quote.required_worker_fence is None
            and quote.graph_job_ref is None
            and quote.outbox_refs == () and quote.d02_settlement_refs == ()
            and _canonical(reservations[0][1]) == dict(quote.ceiling))


def _committed_self_stage(
    db: sqlite3.Connection, *, namespace: NamespaceId, source_ref: str,
    perspective_ref: str, perspective_value: dict, mapping_ref: str,
    mapping_value: dict, baseline_pre_revision: int,
    baseline_pre_epoch: int, requirements: SnapshotRequirementsV2,
    issuer: D11BudgetJobIssuer,
) -> bool:
    """Pin the D03 issuer, finished write and exact two-atom stage history."""
    ns = namespace.as_tuple
    certification = mapping_value.get("certification_ref")
    activity_id = d03_self_identity_projection_activity_id_v1(namespace, source_ref)
    perspective_atom = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (perspective_ref,),
    ).fetchone()
    if perspective_atom is None or perspective_atom[2] != 1:
        return False
    origin = db.execute(
        "SELECT event_id FROM graph_history WHERE token=? AND revision=? "
        "AND event_bot=? AND event_persona=? AND event_session=? AND valid=1",
        (perspective_ref, perspective_atom[0]) + ns + (activity_id,),
    ).fetchall()
    if len(origin) != 1:
        return False
    operation_id = origin[0][0]
    issued = db.execute(
        "SELECT source_ref,certification_ref,quote_id,bundle_digest "
        "FROM graph_d03_self_projection_issuance_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        ns + (operation_id,),
    ).fetchone()
    operation = db.execute(
        "SELECT digest,activity_id,effect_id,commit_seq,receipt_json "
        "FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        ns + (operation_id,),
    ).fetchone()
    if (issued is None or issued[0:2] != (source_ref, certification)
            or type(issued[2]) is not str or not issued[2]
            or operation is None or operation[0] != issued[3]
            or operation[1] != activity_id or operation[2] is not None
            or type(operation[3]) is not int or operation[3] < 1):
        return False
    if not _stage_lineage_current(
            db, namespace=namespace, stage="d03", source_ref=source_ref,
            operation_id=operation_id, bundle_digest=issued[3],
            event_ref=None, perspective_ref=None, perspective_revision=None,
            certification_ref=certification, requirements=requirements):
        return False
    if not _signed_stage_quote(
            db, issuer=issuer, namespace=namespace, stage="d03",
            quote_id=issued[2], operation_id=operation_id,
            activity_id=activity_id):
        return False
    receipt = _canonical(operation[4])
    if receipt.get("commit_seq") != operation[3] or receipt.get("outbox_refs") != []:
        return False
    attempt_id = "graph-write-" + canonical_digest({
        "namespace": list(ns), "operation_id": operation_id,
        "bundle_digest": issued[3]})[:48]
    intent = db.execute(
        "SELECT digest,fence_attempt_id,requirements_json,anchor_json,"
        "graph_revision,graph_epoch FROM graph_bundle_intents_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        ns + (operation_id,),
    ).fetchone()
    fence = db.execute(
        "SELECT digest,permit_json,pre_graph_revision,pre_graph_epoch,"
        "post_graph_revision,post_graph_epoch,finish_request_id,"
        "finish_request_digest FROM graph_bundle_fences_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        ns + (operation_id,),
    ).fetchone()
    if (intent is None or fence is None
            or intent[0:2] != (issued[3], attempt_id)
            or fence[0] != issued[3] or fence[2:4] != intent[4:6]
            or fence[4] != fence[2] + 1
            or fence[4] > baseline_pre_revision
            or fence[5] > baseline_pre_epoch):
        return False
    saved_requirements = _canonical(intent[2])
    for field in ("namespace", "authority_id", "authority_namespace",
                  "activation_generation", "graph_incarnation"):
        if saved_requirements.get(field) != asdict(requirements).get(field):
            return False
    permit_wire = _canonical(fence[1])
    permit = fence_from_wire(permit_wire)
    if (type(permit) is not FencePermitV2 or permit_wire != fence_to_wire(permit)
            or permit.operation != "write" or permit.operation_id != attempt_id
            or permit.authority_id != requirements.authority_id
            or permit.namespace != requirements.authority_namespace
            or permit.generation != requirements.activation_generation
            or _canonical(intent[3]) != asdict(permit.pinned_anchor)
            or fence[6] != "finish:" + attempt_id
            or fence[7] != "sha256:" + canonical_digest({
                "operation_id": attempt_id, "permit_token": permit.token,
                "action": "finish_domain_bundle",
                "business_operation_id": operation_id,
                "bundle_digest": issued[3],
            })):
        return False
    event = db.execute(
        "SELECT revisions,epoch_revision FROM graph_events WHERE bot=? "
        "AND persona=? AND session=? AND event_id=?",
        ns + (activity_id, operation_id),
    ).fetchone()
    perspective_history = db.execute(
        "SELECT revision,value,valid FROM graph_history WHERE token=? "
        "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
        (perspective_ref,) + ns + (activity_id, operation_id),
    ).fetchone()
    mapping_atom = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (mapping_ref,),
    ).fetchone()
    if (event is None or perspective_history is None
            or mapping_atom is None or perspective_atom is None
            or event[1] != fence[5]
            or perspective_history[2] != 1
            or _canonical(perspective_history[1]) != perspective_value
            or perspective_atom != perspective_history):
        return False
    mapping_history = db.execute(
        "SELECT revision,value,valid,event_id FROM graph_history "
        "WHERE token=? AND revision=? AND valid=1",
        (mapping_ref, mapping_atom[0]),
    ).fetchone()
    if (mapping_history is None
            or mapping_atom != mapping_history[:3]
            or _canonical(mapping_history[1]) != mapping_value):
        return False
    revisions = _canonical(event[0])
    expected = [[perspective_ref, perspective_history[0]]]
    if mapping_history[3] == operation_id:
        expected.append([mapping_ref, mapping_history[0]])
    else:
        earlier = db.execute(
            "SELECT i.bundle_digest,o.digest FROM "
            "graph_d03_self_projection_issuance_v1 AS i "
            "JOIN graph_bundle_operations AS o ON o.bot=i.bot "
            "AND o.persona=i.persona AND o.operation_id=i.operation_id "
            "WHERE i.bot=? AND i.persona=? AND i.operation_id=? "
            "AND i.certification_ref=?",
            ns + (mapping_history[3], certification),
        ).fetchone()
        if earlier is None or earlier[0] != earlier[1]:
            return False
    return sorted(revisions) == sorted(expected)


def committed_baseline_current(
    db: sqlite3.Connection, *, namespace: NamespaceId,
    baseline: CommittedEncodingBaselineV1, source_id: str,
    requirements: SnapshotRequirementsV2, current_graph_revision: int,
    current_graph_epoch: int, acquire_graph_revision: int,
    acquire_graph_epoch: int,
    issuer: D11BudgetJobIssuer,
) -> bool:
    """Verify original D04 operation, fence, history, guard and current atom.

    The caller owns one read-only graph transaction.  This predicate does not
    qualify a source, issue a model call, or prove an eventual C02 write.
    """
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(namespace) is not NamespaceId
            or type(baseline) is not CommittedEncodingBaselineV1
            or type(requirements) is not SnapshotRequirementsV2
            or type(issuer) is not D11BudgetJobIssuer
            or requirements.namespace != namespace
            or baseline.graph_incarnation != requirements.graph_incarnation):
        return False
    for stamp in (current_graph_revision, current_graph_epoch,
                  acquire_graph_revision, acquire_graph_epoch):
        if type(stamp) is not int or stamp < 1:
            return False
    try:
        key = AtomKey.from_token(baseline.baseline_ref)
        if (NamespaceId.from_key(key) != namespace
                or key.type_name != "d04.encoding_baseline.v1"):
            return False
        ns = namespace.as_tuple
        issue = db.execute(
            "SELECT source_ref,event_ref,quote_id,bundle_digest "
            "FROM graph_d04_baseline_issuance_v1 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (baseline.operation_id,),
        ).fetchone()
        if (issue is None
                or issue[0] != source_key(*ns, source_id).token
                or NamespaceId.from_key(AtomKey.from_token(issue[1])) != namespace
                or AtomKey.from_token(issue[1]).type_name != "d03.world_event"
                or type(issue[2]) is not str or not issue[2]
                or issue[3] != baseline.bundle_digest):
            return False
        operation = db.execute(
            "SELECT digest,activity_id,effect_id,commit_seq,receipt_json "
            "FROM graph_bundle_operations "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (baseline.operation_id,),
        ).fetchone()
        if (operation is None or operation[0] != baseline.bundle_digest
                or operation[2] is not None
                or type(operation[3]) is not int or operation[3] < 1):
            return False
        if not _signed_stage_quote(
                db, issuer=issuer, namespace=namespace, stage="d04",
                quote_id=issue[2], operation_id=baseline.operation_id,
                activity_id=operation[1]):
            return False
        receipt = _canonical(operation[4])
        if (receipt.get("commit_seq") != operation[3]
                or receipt.get("outbox_refs") != []):
            return False
        attempt_id = "graph-write-" + canonical_digest({
            "namespace": list(ns), "operation_id": baseline.operation_id,
            "bundle_digest": baseline.bundle_digest})[:48]
        original = db.execute(
            "SELECT digest,fence_attempt_id,requirements_json,anchor_json,"
            "graph_revision,graph_epoch FROM graph_bundle_intents_v2 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (baseline.operation_id,),
        ).fetchone()
        fence = db.execute(
            "SELECT digest,permit_json,pre_graph_revision,pre_graph_epoch,"
            "post_graph_revision,post_graph_epoch,finish_request_id,"
            "finish_request_digest FROM graph_bundle_fences_v2 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (baseline.operation_id,),
        ).fetchone()
        if (original is None or fence is None
                or original[0:2] != (baseline.bundle_digest, attempt_id)
                or fence[0] != baseline.bundle_digest
                or fence[2:4] != original[4:6]
                or fence[4] != fence[2] + 1
                or fence[5] != baseline.graph_epoch
                or not (fence[4] <= acquire_graph_revision <= current_graph_revision)
                or not (fence[5] <= acquire_graph_epoch <= current_graph_epoch)):
            return False
        saved_requirements = _canonical(original[2])
        saved_anchor = _canonical(original[3])
        if (saved_requirements.get("namespace") != asdict(namespace)
                or saved_requirements.get("graph_incarnation")
                   != baseline.graph_incarnation
                or saved_requirements.get("authority_id") != requirements.authority_id
                or saved_requirements.get("authority_namespace")
                   != requirements.authority_namespace
                or saved_requirements.get("activation_generation")
                   != requirements.activation_generation):
            return False
        permit_wire = _canonical(fence[1])
        permit = fence_from_wire(permit_wire)
        if (type(permit) is not FencePermitV2
                or permit_wire != fence_to_wire(permit)
                or permit.operation != "write"
                or permit.operation_id != attempt_id
                or permit.authority_id != requirements.authority_id
                or permit.namespace != requirements.authority_namespace
                or permit.generation != requirements.activation_generation
                or saved_anchor != asdict(permit.pinned_anchor)
                or fence[6] != "finish:" + attempt_id
                or fence[7] != "sha256:" + canonical_digest({
                    "operation_id": attempt_id, "permit_token": permit.token,
                    "action": "finish_domain_bundle",
                    "business_operation_id": baseline.operation_id,
                    "bundle_digest": baseline.bundle_digest,
                })):
            return False
        event = db.execute(
            "SELECT revisions,reads,epoch_revision FROM graph_events "
            "WHERE bot=? AND persona=? AND session=? AND event_id=?",
            ns + (operation[1], baseline.operation_id),
        ).fetchone()
        history = db.execute(
            "SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
            "AND event_bot=? AND event_persona=? AND event_session=? "
            "AND event_id=?",
            (baseline.baseline_ref, baseline.baseline_revision)
            + ns + (operation[1], baseline.operation_id),
        ).fetchone()
        atom = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (baseline.baseline_ref,),
        ).fetchone()
        if (event is None or history is None or atom is None
                or _canonical(event[0]) != [[baseline.baseline_ref,
                                             baseline.baseline_revision]]
                or [baseline.baseline_ref, 0] not in _canonical(event[1])
                or event[2] != baseline.graph_epoch or history[1] != 1
                or atom != (baseline.baseline_revision, history[0], 1)):
            return False
        value = _canonical(history[0])
        decoded = decode_encoding_baseline(value)
        if (decoded.baseline_id != key.name
                or decoded.source_refs != (issue[0],)):
            return False
        perspective_key = AtomKey.from_token(decoded.perspective_ref)
        if (NamespaceId.from_key(perspective_key) != namespace
                or perspective_key.type_name != "d03.self_perspective.v1"):
            return False
        reads = _canonical(event[1])
        refs = (decoded.source_refs + (decoded.perspective_ref,)
                + tuple(item.ref for item in decoded.then_feeling_versions)
                + tuple(item.ref for item in decoded.interpretation_versions))
        for ref in refs:
            original_read = [entry for entry in reads if entry[0] == ref]
            edge = db.execute(
                "SELECT dependency_revision FROM graph_dependency_edges "
                "WHERE dependent_token=? AND dependency_token=? "
                "AND edge_kind='historical_provenance' AND operation_id=?",
                (baseline.baseline_ref, ref, baseline.operation_id),
            ).fetchone()
            if (len(original_read) != 1 or edge != (original_read[0][1],)):
                return False
        perspective_reads = [entry for entry in reads
                             if entry[0] == decoded.perspective_ref]
        if (len(perspective_reads) != 1
                or type(perspective_reads[0][1]) is not int
                or perspective_reads[0][1] < 1
                or not _stage_lineage_current(
                    db, namespace=namespace, stage="d04",
                    source_ref=issue[0], operation_id=baseline.operation_id,
                    bundle_digest=baseline.bundle_digest,
                    event_ref=issue[1],
                    perspective_ref=decoded.perspective_ref,
                    perspective_revision=perspective_reads[0][1],
                    certification_ref=None, requirements=requirements)):
            return False
        tokens = set(refs)
        perspective_row = db.execute(
            "SELECT value FROM graph_atoms WHERE token=? AND valid=1",
            (decoded.perspective_ref,),
        ).fetchone()
        if perspective_row is None:
            return False
        perspective = _canonical(perspective_row[0])
        mapping_ref = perspective.get("identity_mapping_ref")
        arrival_ref = perspective.get("arrival_event_ref")
        if arrival_ref != issue[1] or type(mapping_ref) is not str:
            return False
        tokens.update((mapping_ref, arrival_ref))
        atoms = []
        for token in sorted(tokens):
            row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (token,),
            ).fetchone()
            if row is None:
                return False
            atoms.append(GraphAtom(AtomKey.from_token(token), row[0],
                                   _canonical(row[1]), bool(row[2])))
        snapshot = GraphSnapshot(
            tuple(atoms), (NamespaceEpoch(*ns, current_graph_epoch),))
        decoded.verify_committed_refs(snapshot)
        mapping = _canonical(db.execute(
            "SELECT value FROM graph_atoms WHERE token=? AND valid=1",
            (mapping_ref,),
        ).fetchone()[0])
        if not _committed_self_stage(
            db, namespace=namespace, source_ref=issue[0],
            perspective_ref=decoded.perspective_ref,
            perspective_value=perspective, mapping_ref=mapping_ref,
            mapping_value=mapping,
            baseline_pre_revision=fence[2], baseline_pre_epoch=fence[3],
            requirements=requirements, issuer=issuer,
        ):
            return False
        return True
    except (IssuerAuthorityDenied, KeyError, TypeError, ValueError,
            sqlite3.Error):
        return False


__all__ = ("committed_baseline_current",)
