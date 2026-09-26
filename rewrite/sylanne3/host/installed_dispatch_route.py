"""Installed, read-only AstrBot route check for a frozen D11 command.

This port can inform a later P2 graph claim. It neither validates the Owner
authorization head nor creates a graph claim or a platform send permit.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json

from astrbot.api.platform import MessageType
from astrbot.core.platform.message_session import MessageSession

from ..dispatch_runtime import DispatchRequest
from ..domains.d09 import segment_payload_digest
from ..runtime.dispatch_admission import DispatchAdmissionReceiptV1
from ..runtime.dispatch_candidate import GraphDispatchTextSegmentV1
from ..runtime.dispatch_current_segment import CurrentDispatchSegmentV1
from ..runtime_contracts import InstallationGrantV2, NamespaceId, canonical_digest
from ..installation_policy import AdminInstallationPolicy
from .current_scene import verify_current_host_scene
from .scene_candidates import SceneCandidateCatalog


@dataclass(frozen=True, slots=True)
class InstalledDispatchRouteReadV1:
    status: str
    reason: str
    route_digest: str | None = None
    graph_epoch: int | None = None
    missing_guards: tuple[str, ...] = ("current_owner_authorization",)


class InstalledDispatchRoutePort:
    """Check graph-frozen route against an observed, current installation.

    The request and frozen segment are selectors, never proof: the underlying
    reader gets the admission and D09 text from the coordinator again. A recent
    observed scene is required before the host loop rechecks its live state.
    """

    def __init__(self, *, context: object, host_loop: asyncio.AbstractEventLoop,
                 candidates: SceneCandidateCatalog, coordinator: object,
                 authority: object, lease: object,
                 policy: AdminInstallationPolicy,
                 grant: InstallationGrantV2,
                 timeout_seconds: float = 2.0) -> None:
        if (not isinstance(host_loop, asyncio.AbstractEventLoop)
                or not isinstance(candidates, SceneCandidateCatalog)
                or type(policy) is not AdminInstallationPolicy
                or type(grant) is not InstallationGrantV2
                or (grant.authority_id, grant.installation_id,
                    grant.administrator_holder, grant.manifest_digest) != (
                    policy.expected_authority_id, policy.installation_id,
                    policy.administrator_holder, policy.manifest_digest)
                or getattr(authority, "namespace", None) != policy.namespace
                or not 0 < timeout_seconds <= 10):
            raise ValueError("installed dispatch route dependencies are invalid")
        self._context = context
        self._host_loop = host_loop
        self._candidates = candidates
        self._coordinator = coordinator
        self._authority = authority
        self._lease = lease
        self._namespace = policy.namespace
        self._timeout_seconds = timeout_seconds

    async def _verify_on_host_loop(self, *, account_ref: str,
                                   destination_ref: str, visibility: str,
                                   scene_ref: str):
        candidate = self._candidates.get_exact(
            namespace=self._namespace, platform_ref=account_ref,
            conversation_ref=destination_ref, visibility=visibility,
            scene_ref=scene_ref)
        if candidate is None:
            return None
        return await verify_current_host_scene(self._context, candidate)

    def read(self, request: DispatchRequest,
             frozen: CurrentDispatchSegmentV1) -> InstalledDispatchRouteReadV1:
        if (type(request) is not DispatchRequest
                or type(frozen) is not CurrentDispatchSegmentV1
                or request.namespace != "/".join(self._namespace.as_tuple)
                or frozen.status != "hold"
                or "current_host_route_and_scene" not in frozen.missing_sources
                or (request.operation_id, request.effect_id) != (
                    frozen.operation_id, frozen.effect_id)):
            return InstalledDispatchRouteReadV1("hold", "installed dispatch identity differs")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._host_loop or not self._host_loop.is_running():
            return InstalledDispatchRouteReadV1("hold", "host loop unavailable")
        # These graph reads run on the caller's GraphWorker thread, outside
        # the host loop. DTO equality is a selector check, never authority.
        try:
            admitted = self._coordinator.get_dispatch_admission(
                self._authority, self._lease, frozen.admission_ref)
            segment = self._coordinator.get_dispatch_text_segment(
                self._authority, self._lease, request)
            if (type(admitted) is not DispatchAdmissionReceiptV1
                    or type(segment) is not GraphDispatchTextSegmentV1
                    or segment.media_refs
                    or admitted.admission.request_digest != canonical_digest(request)
                    or (admitted.admission.operation_id,
                        admitted.admission.effect_id) != (
                        request.operation_id, request.effect_id)):
                return InstalledDispatchRouteReadV1("hold", "current graph route differs")
            account_ref = json.dumps(
                [segment.platform_id, segment.platform_name, segment.self_id],
                ensure_ascii=True, separators=(",", ":"))
            destination_ref = json.dumps(
                [segment.umo, segment.conversation_id],
                ensure_ascii=True, separators=(",", ":"))
            route_digest = canonical_digest({
                "account_ref": account_ref, "destination_ref": destination_ref,
                "scene_ref": segment.scene_ref})
            payload_digest = segment_payload_digest(
                segment.body, segment.media_refs, segment.claim_uses)
            session = MessageSession.from_str(segment.umo)
            visibility = {MessageType.FRIEND_MESSAGE: "private",
                          MessageType.GROUP_MESSAGE: "group"}.get(session.message_type)
            if (route_digest != frozen.route_digest
                    or payload_digest != frozen.payload_digest
                    or payload_digest != request.payload_digest
                    or visibility is None or session.platform_id != segment.platform_id
                    or not session.session_id.isascii()
                    or not session.session_id.isdigit()):
                return InstalledDispatchRouteReadV1("hold", "frozen route or payload differs")
        except Exception:
            return InstalledDispatchRouteReadV1("hold", "current graph route unavailable")
        coro = self._verify_on_host_loop(
            account_ref=account_ref, destination_ref=destination_ref,
            visibility=visibility, scene_ref=segment.scene_ref)
        try:
            future = asyncio.run_coroutine_threadsafe(coro, self._host_loop)
        except RuntimeError:
            coro.close()
            return InstalledDispatchRouteReadV1("hold", "host loop unavailable")
        try:
            current = future.result(timeout=self._timeout_seconds)
        except Exception:
            future.cancel()
            return InstalledDispatchRouteReadV1("hold", "host route read unavailable")
        if (current is None or (current.namespace, current.platform_ref,
                current.conversation_ref, current.visibility, current.scene_ref)
                != (self._namespace, account_ref, destination_ref, visibility,
                    segment.scene_ref)):
            return InstalledDispatchRouteReadV1(
                "hold", "installed scene observation or current AstrBot route differs")
        return InstalledDispatchRouteReadV1(
            "verified_route", "current_installed_astrbot_route",
            route_digest, frozen.graph_epoch)


__all__ = ("InstalledDispatchRoutePort", "InstalledDispatchRouteReadV1")
