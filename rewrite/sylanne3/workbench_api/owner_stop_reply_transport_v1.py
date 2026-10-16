"""Exact, content-free Owner reply controls outside the ordinary Graph reader."""
from __future__ import annotations

from dataclasses import asdict
from uuid import UUID

from ..authority_service.owner_stop_reply_v1 import owner_stop_reply_request_from_wire_v1
from ..host.owner_stop_reply_port_v1 import InstalledOwnerStopReplyPortV1
from ..runtime_contracts import NamespaceId
from .service import AuthenticatedSession, D12_SCHEMA


ACTIONS = frozenset({"read_reply_controls", "stop_reply", "read_reply_control_status",
    "cancel_artifact_goal", "read_artifact_goal_cancel_status"})


def parse_owner_reply_control_command_v1(payload):
    if (type(payload) is not dict or set(payload) != {
            "schema_version", "action", "scope", "purpose", "audience", "operation_id", "input"}
            or payload["schema_version"] != D12_SCHEMA or payload["action"] not in ACTIONS
            or payload["purpose"] != "workbench_user_action" or payload["audience"] != "owner"
            or type(payload["operation_id"]) is not str
            or type(payload["scope"]) is not str or len(payload["scope"]) > 192
            or len(payload["scope"].split("/")) != 2 or type(payload["input"]) is not dict):
        raise ValueError("exact Owner reply control envelope required")
    operation = UUID(payload["operation_id"])
    if operation.version != 4 or str(operation) != payload["operation_id"]:
        raise ValueError("canonical Owner reply control operation required")
    namespace = NamespaceId(*payload["scope"].split("/"))
    if payload["action"] in {"cancel_artifact_goal","read_artifact_goal_cancel_status"}:
        from ..authority_service.owner_goal_cancellation_contract_v1 import (
            OwnerGoalCancellationRequestV1,owner_goal_cancellation_from_wire_v1)
        request=owner_goal_cancellation_from_wire_v1(payload["input"],OwnerGoalCancellationRequestV1)
        if (request.namespace!=namespace or payload["action"]=="cancel_artifact_goal"
                and request.cancel_operation_id!=payload["operation_id"]):
            raise ValueError("Goal management envelope/actual target operation differs")
    elif payload["action"] == "stop_reply":
        request = owner_stop_reply_request_from_wire_v1(payload["input"])
        if request.namespace != namespace or request.operation_id != payload["operation_id"]:
            raise ValueError("Owner StopReply envelope and target identity differ")
    elif payload["action"] == "read_reply_controls":
        if payload["input"] and (set(payload["input"]) != {"cursor"}
                or type(payload["input"]["cursor"]) is not str
                or not 1 <= len(payload["input"]["cursor"]) <= 256):
            raise ValueError("Owner reply metadata listing requires its bounded page cursor")
    elif (set(payload["input"]) != {"original_ref"}
            or type(payload["input"]["original_ref"]) is not str
            or not 1 <= len(payload["input"]["original_ref"]) <= 128):
        raise ValueError("exact Owner StopReply original selector required")
    return payload


class InstalledOwnerReplyControlTransportV1:
    def __init__(self, port: InstalledOwnerStopReplyPortV1, *, project_stop=None, goal_runtime=None) -> None:
        if type(port) is not InstalledOwnerStopReplyPortV1:
            raise TypeError("actual paired Owner reply control port required")
        self.port = port
        self._project_stop = project_stop
        from ..runtime_context import RuntimeContext
        if goal_runtime is not None and type(goal_runtime) is not RuntimeContext:
            raise TypeError("actual installed Goal projection RuntimeContext required")
        self._goal_runtime=goal_runtime

    async def handle(self, payload, *, session):
        command = parse_owner_reply_control_command_v1(payload)
        scope = command["scope"]
        if (type(session) is not AuthenticatedSession
                or "workbench.control" not in session.scope_capabilities.get(scope, ())
                or "owner" not in session.scope_audiences.get(scope, ())
                or "workbench_user_action" not in session.scope_purposes.get(scope, ())
                or scope != "/".join(self.port.namespace.as_tuple)):
            raise PermissionError("current scoped Owner reply control admission required")
        action = command["action"]
        if action in {"cancel_artifact_goal","read_artifact_goal_cancel_status"}:
            from ..authority_service.owner_goal_cancellation_contract_v1 import (
                OwnerGoalCancellationRequestV1,owner_goal_cancellation_from_wire_v1)
            request=owner_goal_cancellation_from_wire_v1(command["input"],OwnerGoalCancellationRequestV1)
            original=(await self.port.submit_owner_goal_cancel_v1(session=session,request=request)
                if action=="cancel_artifact_goal" else
                await self.port.read_owner_goal_cancel_status_v1(session=session,request=request))
            projection=(await self._goal_runtime.project_owner_goal_cancellation_v1(original=original)
                if self._goal_runtime is not None else {"status":"held"})
            # Only actual metadata W01 can add metadata_projected. It neither
            # confirms job cancellation nor authorizes a zero cost.
            return {"status":"ready","control":{"schema":"d08.owner-goal-cancellation-status.v1",
                "namespace":asdict(original.request.namespace),"goal_ref":original.request.goal_ref,
                "operation_id":original.request.cancel_operation_id,"original_ref":original.original_ref,
                "original_digest":original.digest,"state":original.state,
                "projection_state":projection["status"],
                "observed_goal_atom_revision":original.metadata.goal_atom_revision,
                "observed_goal_semantic_revision":original.metadata.goal_semantic_revision,
                "cancellation_confirmed":False}}
        if action == "read_reply_controls":
            page = await self.port.list_owner_reply_controls_v1(session=session, cursor=command["input"].get("cursor"))
            return {"status": "ready", "items": [item.to_wire() for item in page.items], "next_cursor": page.next_cursor}
        if action == "stop_reply":
            request = owner_stop_reply_request_from_wire_v1(command["input"])
            original = await self.port.submit_owner_stop_reply_v1(session=session, request=request)
            original_ref = original.original_ref
        else:
            original_ref = command["input"]["original_ref"]
        if self._project_stop is not None:
            # One formal metadata projection attempt; an active model fence
            # remains pending until a later explicit/current-event attempt.
            await self._project_stop(original_ref=original_ref)
        original = await self.port.read_owner_stop_reply_status_v1(session=session,
            original_ref=original_ref)
        # Only the actual accepted/derived metadata original drives UI state.
        return {"status": "ready", "control": {
            "schema": "d12.owner-stop-reply-status.v1",
            "namespace": asdict(original.namespace),
            "cycle_job_ref": original.result.object_ref,
            "operation_id": original.operation_id, "original_ref": original.original_ref,
            "original_digest": original.original_digest, "state": original.state,
            "cancel_generation": original.result.effective_version,
            "cancellation_confirmed": original.result.cancellation_confirmed,
        }}


__all__ = ("ACTIONS", "parse_owner_reply_control_command_v1", "InstalledOwnerReplyControlTransportV1")
