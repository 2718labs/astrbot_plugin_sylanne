"""Read the live AstrBot route for one graph-frozen D09 dispatch segment."""

from __future__ import annotations

from dataclasses import dataclass
import json

from astrbot.api.platform import MessageType
from astrbot.core.platform.message_session import MessageSession

from ..dispatch_runtime import DispatchRequest
from ..domains.d09 import segment_payload_digest
from ..runtime.dispatch_admission import DispatchAdmissionReceiptV1
from ..runtime.dispatch_candidate import GraphDispatchTextSegmentV1
from ..runtime.dispatch_current_segment import CurrentDispatchSegmentV1
from ..runtime_contracts import NamespaceId, canonical_digest
from .current_scene import verify_current_host_scene
from .scene_candidates import ObservedSceneCandidate


@dataclass(frozen=True, slots=True)
class CurrentDispatchHostRouteV1:
    """A point-in-time host read, never a final graph claim or send permit."""

    status: str
    reason: str
    route_digest: str | None = None
    graph_epoch: int | None = None


def _hold(reason: str) -> CurrentDispatchHostRouteV1:
    return CurrentDispatchHostRouteV1("hold", reason)


async def read_current_dispatch_host_route(
    context, coordinator, authority, lease: object,
    request: DispatchRequest, frozen: CurrentDispatchSegmentV1,
) -> CurrentDispatchHostRouteV1:
    """Compare the graph route with live platform/account/conversation facts.

    Call this on the AstrBot event loop outside the graph write transaction.
    The coordinator supplies the original admission route; callers cannot
    substitute a route or a host receipt. A later final graph transaction must
    independently re-read the frozen route and all other dispatch guards.
    """
    if (type(request) is not DispatchRequest
            or type(frozen) is not CurrentDispatchSegmentV1
            or frozen.status != "hold"
            or "current_host_route_and_scene" not in frozen.missing_sources
            or (request.operation_id, request.effect_id) != (
                frozen.operation_id, frozen.effect_id)
            or not callable(getattr(coordinator, "get_dispatch_text_segment", None))
            or not callable(getattr(coordinator, "get_dispatch_admission", None))):
        return _hold("frozen D09 command identity is unavailable")
    try:
        namespace = NamespaceId(*request.namespace.split("/", 1))
        if namespace != authority.namespace:
            return _hold("frozen D09 namespace differs")
        admitted = coordinator.get_dispatch_admission(
            authority, lease, frozen.admission_ref,
        )
        if (type(admitted) is not DispatchAdmissionReceiptV1
                or (admitted.admission.operation_id,
                    admitted.admission.effect_id) != (
                        request.operation_id, request.effect_id)
                or admitted.admission.request_digest != canonical_digest(request)):
            return _hold("frozen D09 admission differs from graph command")
        segment = coordinator.get_dispatch_text_segment(authority, lease, request)
        if type(segment) is not GraphDispatchTextSegmentV1 or segment.media_refs:
            return _hold("committed graph route is unavailable")
        payload_digest = segment_payload_digest(
            segment.body, segment.media_refs, segment.claim_uses,
        )
        account_ref = json.dumps(
            [segment.platform_id, segment.platform_name, segment.self_id],
            ensure_ascii=True, separators=(",", ":"),
        )
        destination_ref = json.dumps(
            [segment.umo, segment.conversation_id],
            ensure_ascii=True, separators=(",", ":"),
        )
        route_digest = canonical_digest({
            "account_ref": account_ref, "destination_ref": destination_ref,
            "scene_ref": segment.scene_ref,
        })
        if (payload_digest != request.payload_digest
                or payload_digest != frozen.payload_digest
                or route_digest != frozen.route_digest):
            return _hold("committed graph payload or route changed")
        session = MessageSession.from_str(segment.umo)
        visibility = {
            MessageType.FRIEND_MESSAGE: "private",
            MessageType.GROUP_MESSAGE: "group",
        }.get(session.message_type)
        if (visibility is None or session.platform_id != segment.platform_id
                or not session.session_id.isascii()
                or not session.session_id.isdigit()):
            return _hold("frozen AstrBot session is not a text route")
        candidate = ObservedSceneCandidate(
            namespace, account_ref, destination_ref, visibility,
            segment.scene_ref,
        )
        live = await verify_current_host_scene(context, candidate)
        if (live is None or (
                live.namespace, live.platform_ref, live.conversation_ref,
                live.visibility, live.scene_ref) != (
                    namespace, account_ref, destination_ref, visibility,
                    segment.scene_ref)):
            return _hold("current AstrBot account, conversation or scene differs")
    except Exception:
        return _hold("current AstrBot route is unavailable")
    return CurrentDispatchHostRouteV1(
        "verified", "current_astrbot_route", route_digest, frozen.graph_epoch,
    )


__all__ = ["CurrentDispatchHostRouteV1", "read_current_dispatch_host_route"]
