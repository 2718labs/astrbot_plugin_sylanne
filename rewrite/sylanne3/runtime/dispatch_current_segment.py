"""Current D09 segment and frozen AstrBot route read; never send authority."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math

from ..domains.d09 import D09ExpressionProvider
from ..graph_types import AtomKey
from ..host.identity import astrbot_namespace
from ..runtime_contracts import NamespaceId, canonical_digest
from .dispatch_admission import load_request
from .dispatch_candidate import dispatch_segment_payload_ref
from .dispatch_current_source_budget import CurrentDispatchHold
from .first_ingress_v2 import scene_ref_for_conversation


@dataclass(frozen=True, slots=True)
class CurrentDispatchSegmentV1:
    """Verified graph subset; the live host route is deliberately unresolved."""

    status: str
    admission_ref: str
    operation_id: str
    effect_id: str
    graph_epoch: int
    batch_ref: str
    batch_revision: int
    batch_digest: str
    payload_digest: str
    route_digest: str
    missing_sources: tuple[str, ...] = ("current_host_route_and_scene",)


def _hold(reason: str) -> None:
    raise CurrentDispatchHold(reason)


def _canonical_route(raw: str, count: int) -> list[str]:
    try:
        parts = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise CurrentDispatchHold("frozen AstrBot route is invalid") from exc
    if (type(parts) is not list or len(parts) != count
            or any(type(part) is not str or not part for part in parts)
            or json.dumps(parts, ensure_ascii=True, separators=(",", ":")) != raw):
        _hold("frozen AstrBot route is not canonical")
    return parts


def read_current_dispatch_segment(
    db, namespace: NamespaceId, admission_ref: str, *, now_utc: float,
) -> CurrentDispatchSegmentV1:
    """Verify one admitted finite segment in the caller's graph write transaction.

    The caller must hold its BEGIN IMMEDIATE fence through its final decision.
    The persisted admission, command, operation receipt, graph event and current
    D09 atom are the only inputs. This reader never accepts a caller's route or
    receipt and cannot establish the live host account/scene. The caller must
    supply its trusted UTC reading; this reader cannot authenticate a clock.
    """
    if not db.in_transaction:
        _hold("current D09 segment needs a held graph transaction")
    if type(namespace) is not NamespaceId or type(admission_ref) is not str or not admission_ref:
        _hold("current D09 segment identity is invalid")
    if type(now_utc) not in (int, float) or not math.isfinite(now_utc):
        _hold("current D09 clock is invalid")
    try:
        loaded = load_request(db, namespace, admission_ref)
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise CurrentDispatchHold("committed dispatch admission or command is invalid") from exc
    if loaded is None:
        _hold("committed dispatch admission and command are absent")
    receipt, request = loaded
    admission = receipt.admission
    row = db.execute(
        "SELECT activity_id,effect_id,receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (request.operation_id,),
    ).fetchone()
    if row is None or (row[0], row[1]) != (request.activity_id, request.effect_id):
        _hold("dispatch operation identity differs")
    try:
        operation = json.loads(row[2])
        candidate = operation["dispatch_candidate"]
        recorded_admission = operation["dispatch_admission"]
        refs = candidate["refs"]
        if (type(candidate) is not dict or candidate["status"] != "source_qualified"
                or candidate["digest"] != admission.candidate_digest
                or (candidate["graph_incarnation"] or "nonproduction-graphstore")
                != admission.graph_incarnation
                or (candidate["graph_revision"] or candidate["graph_epoch"])
                != receipt.graph_revision
                or candidate["access_epoch"] != admission.access_epoch
                or candidate["delete_epoch"] != admission.delete_epoch
                or type(refs) is not list or len(refs) != 4
                or recorded_admission != {"schema": admission.schema,
                                          "ref": admission_ref,
                                          "digest": receipt.receipt_digest}):
            _hold("dispatch candidate or admission receipt differs")
        batch_ref, batch_revision = refs[3]
        key = AtomKey.from_token(batch_ref)
        if (type(batch_revision) is not int or batch_revision < 1
                or key.type_name != "d09.verified_segment_batch.v1"
                or (key.owner.bot, key.owner.persona, key.owner.kind,
                    key.owner.subject) != (*namespace.as_tuple, "activity", request.activity_id)
                or candidate["graph_epoch"] != receipt.graph_epoch
                or request.payload_ref != dispatch_segment_payload_ref(
                    batch_ref, request.segment_index)):
            _hold("dispatch batch write identity differs")
        event = db.execute(
            "SELECT revisions,epoch_revision FROM graph_events WHERE bot=? "
            "AND persona=? AND session=? AND event_id=?",
            namespace.as_tuple + (request.activity_id, request.operation_id),
        ).fetchone()
        if (event is None or event[1] != receipt.graph_epoch
                or [batch_ref, batch_revision] not in json.loads(event[0])):
            _hold("dispatch batch has no matching commit event")
        historical = db.execute(
            "SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
            "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
            (batch_ref, batch_revision) + namespace.as_tuple + (
                request.activity_id, request.operation_id),
        ).fetchone()
        current = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? "
            "AND persona=? AND type_name='d09.verified_segment_batch.v1'",
            (batch_ref,) + namespace.as_tuple,
        ).fetchone()
        epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()
        if (historical is None or historical[1] != 1 or current is None
                or current[0] != batch_revision or current[2] != 1
                or json.loads(current[1]) != json.loads(historical[0])
                or epoch is None or epoch[0] < receipt.graph_epoch):
            _hold("current D09 batch differs from committed graph row")
        batch = json.loads(current[1])
        next(spec for spec in D09ExpressionProvider.register_types()
             if spec.name == "d09.verified_segment_batch.v1").validator(batch)
        index = request.segment_index
        if (type(index) is not int or not 0 <= index < len(batch["segments"])
                or batch["batch_digest"] != admission.batch_digest
                or len(batch["segments"]) != request.segment_count
                or batch["grant_manifest_digest"] != request.segment_manifest_digest
                or batch["grant_digest"] != admission.grant_digest
                or batch["scene_ref"] != admission.scene_ref
                or tuple(batch["audiences"]) != admission.audience
                or len(admission.audience) != 1
                or batch["communication_action_id"]
                != request.footprint.communication_action
                or batch["contact_id"] != request.footprint.contact_id
                or batch["cancellation_epoch"] != request.cancel_epoch
                or batch["valid_until"] <= now_utc
                or batch["required_check_refs"] != list(request.required_check_refs)):
            _hold("current D09 finite batch differs from committed command")
        segment = batch["segments"][index]
        if (segment["effect_id"] != request.effect_id
                or segment["segment_id"] != request.footprint.segment_id
                or segment["position"] != index
                or segment["payload_digest"] != request.payload_digest
                or segment["payload_digest"] != admission.payload_digest
                or segment["segment_authorization_ref"]
                != request.segment_authorization_ref
                or segment["audiences"] != list(admission.audience)):
            _hold("current D09 segment differs from committed command")
        account = _canonical_route(admission.account_ref, 3)
        _canonical_route(admission.destination_ref, 2)
        if (admission.destination_ref != admission.audience[0]
                or astrbot_namespace(account[0], account[2], "route-check").bot_id
                != namespace.bot_id
                or scene_ref_for_conversation(
                    namespace, admission.account_ref, admission.destination_ref,
                ) != admission.scene_ref):
            _hold("frozen AstrBot account, destination or scene differs")
    except (KeyError, IndexError, TypeError, ValueError, StopIteration,
            json.JSONDecodeError) as exc:
        raise CurrentDispatchHold("current D09 segment cannot be verified") from exc
    return CurrentDispatchSegmentV1(
        "hold", admission_ref, request.operation_id, request.effect_id,
        epoch[0], batch_ref, batch_revision, batch["batch_digest"],
        segment["payload_digest"], canonical_digest({
            "account_ref": admission.account_ref,
            "destination_ref": admission.destination_ref,
            "scene_ref": admission.scene_ref,
        }),
    )


__all__ = ["CurrentDispatchSegmentV1", "read_current_dispatch_segment"]
