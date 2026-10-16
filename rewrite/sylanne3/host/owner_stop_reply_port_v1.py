"""Asynchronous Owner reply controls over the actual paired Authority channel."""
from __future__ import annotations

from .authority_client import AuthorityClient
from .authority_profile import AdminInstallationBundle
from ..authority_service.owner_stop_reply_v1 import (
    OwnerStopReplyRequestV1, OwnerReplyControlPageV1, owner_reply_control_metadata_from_wire_v1,
    owner_stop_reply_request_from_wire_v1,
)
from ..authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from ..authority_service.v2_owner_session import to_wire as session_to_wire
from ..runtime.lifecycle_operations_v1 import decode_original
from ..runtime_contracts import InstallationGrantV2
from ..workbench_api.service import AuthenticatedSession


class InstalledOwnerStopReplyPortV1:
    def __init__(self, *, client: AuthorityClient, bundle: AdminInstallationBundle,
                 grant: InstallationGrantV2) -> None:
        if (type(client) is not AuthorityClient or type(bundle) is not AdminInstallationBundle
                or type(grant) is not InstallationGrantV2):
            raise TypeError("installed paired Owner reply control dependencies required")
        self.client, self.bundle, self.grant = client, bundle, grant

    @property
    def namespace(self):
        return self.bundle.installation_policy.namespace

    async def _call(self, method, *, session, selector):
        if (type(session) is not AuthenticatedSession or not session.owner_session_token
                or session.owner_session_request is None):
            raise PermissionError("signed Owner reply control session required")
        # This existing check verifies package/profile/subject/channel identity;
        # it neither prepares a model nor grants content execution.
        request, handshake, policy = await self.client._model_installation_context(
            self.bundle, self.grant)
        login = session.owner_session_request
        if (login.authority_id, login.authority_namespace, login.installation_id) != (
                policy.expected_authority_id, policy.authority_namespace, policy.installation_id):
            raise PermissionError("Owner reply control installation differs")
        command = {"namespace": policy.authority_namespace,
                   "owner_actor_id": session.actor_id,
                   "owner_session_token": session.owner_session_token,
                   "owner_session_request": session_to_wire(login), **selector}
        return await self.client._transport._content_rpc(request, handshake, method,
            command, protocol=AUTHORITY_V2_PROTOCOL)

    async def submit_owner_goal_cancel_v1(self, *, session, request):
        from dataclasses import asdict
        from ..authority_service.owner_goal_cancellation_contract_v1 import OwnerGoalCancellationRequestV1
        policy=self.bundle.installation_policy
        if (type(request) is not OwnerGoalCancellationRequestV1
                or (request.namespace,request.authority_namespace,request.installation_id)!=(
                    policy.namespace,policy.authority_namespace,policy.installation_id)):
            raise PermissionError("Goal cancellation target installation differs")
        response=await self._call("owner_goal_cancel_submit_v1",session=session,
            selector={"cancel_request":asdict(request)})
        return self._goal_cancel_original_v1(response,session=session,request=request)

    async def read_owner_goal_cancel_status_v1(self, *, session, request):
        response=await self._call("owner_goal_cancel_status_v1",session=session,
            selector={"cancel_operation_id":request.cancel_operation_id})
        return self._goal_cancel_original_v1(response,session=session,request=request)

    def _goal_cancel_original_v1(self, response, *, session, request):
        from dataclasses import asdict
        from ..runtime_contracts import canonical_serialize
        from ..authority_service.owner_goal_cancellation_contract_v1 import (
            OwnerGoalCancellationOriginalV1,owner_goal_cancellation_from_wire_v1)
        if type(response) is not dict or set(response)!={"original","channel_binding_sha256"}:
            raise RuntimeError("Goal cancellation exact original response differs")
        original=owner_goal_cancellation_from_wire_v1(response["original"],OwnerGoalCancellationOriginalV1)
        if (original.request!=request or original.authority_id!=self.grant.authority_id
                or original.actor_id!=session.actor_id
                or original.principal_json!=canonical_serialize(asdict(session.owner_session_request.principal))):
            raise RuntimeError("Goal cancellation returned another initiating Owner/target original")
        return original

    async def list_owner_reply_controls_v1(self, *, session, cursor=None):
        response = await self._call("owner_stop_reply_list_v1", session=session, selector={"cursor": cursor})
        if (type(response) is not dict or set(response) != {"items", "next_cursor", "channel_binding_sha256"}
                or type(response["items"]) is not list or len(response["items"]) > 32
                or response["next_cursor"] is not None and (type(response["next_cursor"]) is not str
                    or not 1 <= len(response["next_cursor"]) <= 256 or len(response["items"]) != 32)):
            raise RuntimeError("Owner reply control metadata response differs")
        items = tuple(owner_reply_control_metadata_from_wire_v1(item) for item in response["items"])
        policy = self.bundle.installation_policy
        if any((item.namespace, item.installation_id) != (policy.namespace, policy.installation_id)
               for item in items):
            raise RuntimeError("Owner reply control metadata scope differs")
        return OwnerReplyControlPageV1(items, response["next_cursor"])

    async def submit_owner_stop_reply_v1(self, *, session, request: OwnerStopReplyRequestV1):
        policy = self.bundle.installation_policy
        if (type(request) is not OwnerStopReplyRequestV1
                or (request.namespace, request.installation_id) != (policy.namespace, policy.installation_id)):
            raise PermissionError("Owner StopReply target installation differs")
        response = await self._call("owner_stop_reply_submit_v1", session=session,
            selector={"stop_request": request.to_wire()})
        original = self._original(response)
        if original.result.object_ref != request.cycle_job_ref:
            raise RuntimeError("Owner StopReply returned a different cycle")
        return original

    async def read_owner_stop_reply_status_v1(self, *, session, original_ref):
        response = await self._call("owner_stop_reply_status_v1", session=session,
            selector={"original_ref": original_ref})
        return self._original(response)

    async def read_owner_stop_reply_projection_v1(self, *, original_ref):
        """Read the accepted metadata original for the private Owner W01 observer."""
        request, handshake, policy = await self.client._model_installation_context(
            self.bundle, self.grant)
        response = await self.client._transport._content_rpc(request, handshake,
            "owner_stop_reply_projection_v1", {"namespace": policy.authority_namespace,
                "holder": policy.administrator_holder, "original_ref": original_ref},
            protocol=AUTHORITY_V2_PROTOCOL)
        if type(response) is not dict or set(response) != {"request", "original", "channel_binding_sha256"}:
            raise RuntimeError("Owner StopReply projection response differs")
        target = owner_stop_reply_request_from_wire_v1(response["request"])
        original = self._original({"original": response["original"],
                                  "channel_binding_sha256": response["channel_binding_sha256"]})
        if ((target.namespace, target.installation_id) != (policy.namespace, policy.installation_id)
                or original.result.object_ref != target.cycle_job_ref):
            raise RuntimeError("Owner StopReply projection scope differs")
        return target, original

    def _original(self, response):
        if type(response) is not dict or set(response) != {"original", "channel_binding_sha256"}:
            raise RuntimeError("Owner StopReply original response differs")
        original = decode_original(response["original"])
        if (original.kind != "control" or original.namespace != self.namespace
                or original.result.control != "stop_reply_v1"):
            raise RuntimeError("Owner StopReply original identity differs")
        return original


__all__ = ("InstalledOwnerStopReplyPortV1",)
