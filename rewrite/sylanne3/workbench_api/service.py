"""Fail-closed D12 command service.

This module is deliberately transport-neutral.  W09 must bind authenticated
sessions and enforce Origin/CSRF before calling it; this service verifies that
binding was performed and does not accept actor/capability claims from JSON.
"""

from __future__ import annotations

from ..runtime.local_module_admission_v1 import LocalModuleAdmissionDeniedV1

from dataclasses import dataclass, field
from hashlib import sha256
import json
import math
import re
from typing import Any, Mapping, Protocol
from uuid import UUID

from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..runtime_contracts import NamespaceId
from .source_correction import SourceCorrectionRequestV1
from ..domains.d12.scoped_erasure import D12ScopedErasureRequestV2
from ..domains.d12.backend_operation_contracts_v1 import SCHEMA as BACKEND_ORIGINAL_SCHEMA, STATES as BACKEND_STATES


D12_SCHEMA = "d12.contract.v1"
SOURCE_CORRECTION_SCHEMA = "d12.source_correction.v1"
SOURCE_CORRECTION_RESPONSE_SCHEMA = "d12.source_correction_response.v1"
SOURCE_ACCESS_REVOCATION_SCHEMA = "d12.source_access_revocation.v1"
_SCOPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_BLUEPRINT_REF = re.compile(r"[A-Za-z0-9]+(?:[._:-][A-Za-z0-9]+)*\Z")
_ACTIONS = frozenset({
    "open_workspace", "create_character", "bind_scene", "compile_scheme", "preview_scheme", "activate_scheme", "read_character_view", "read_creator_draft",
    "correct_or_edit", "run_experiment", "prepare_transfer", "execute_transfer",
    "erase_or_retire", "diagnose_and_export_support", "install_or_upgrade",
    "configure_or_control", "read_backend_operation", "read_installation_lifecycle",
    "read_owner_artifact_project_context_options", "read_source_correction_context_v1",
    "read_project_control_context_v1", "read_project_control_context_v2", "pause_project_v1", "resume_project_v1",
    "read_owner_project_artifact_options_v1", "read_owner_project_artifact_v1",
})
_READ_ACTIONS = frozenset({"open_workspace", "read_character_view", "read_backend_operation", "read_installation_lifecycle",
    "read_owner_artifact_project_context_options", "read_source_correction_context_v1", "read_project_control_context_v1", "read_project_control_context_v2", "read_owner_project_artifact_options_v1", "read_owner_project_artifact_v1"})
_WIRED_COMMANDS = frozenset({
    "create_character", "bind_scene", "compile_scheme", "preview_scheme",
    "activate_scheme", "correct_or_edit", "run_experiment", "pause_project_v1", "resume_project_v1",
    "diagnose_and_export_support", "erase_or_retire",
    "prepare_transfer", "execute_transfer", "install_or_upgrade", "configure_or_control",
})
_MUTATION_CAPABILITIES = {
    "read_creator_draft": "workbench.create",
    "read_owner_artifact_project_context_options": "workbench.create",
    "read_source_correction_context_v1": "workbench.correct",
    "read_project_control_context_v1": "workbench.control",
    "read_project_control_context_v2": "workbench.control",
    "pause_project_v1": "workbench.control", "resume_project_v1": "workbench.control",
    "create_character": "workbench.create", "bind_scene": "workbench.bind_scene",
    "compile_scheme": "workbench.compile", "preview_scheme": "workbench.experiment",
    "activate_scheme": "workbench.activate",
    "correct_or_edit": "workbench.correct", "run_experiment": "workbench.experiment",
    "prepare_transfer": "workbench.transfer", "execute_transfer": "workbench.transfer",
    "erase_or_retire": "workbench.erase", "diagnose_and_export_support": "workbench.diagnose",
    "install_or_upgrade": "workbench.maintain", "configure_or_control": "workbench.control",
}
_ACTIONS |= {'read_owner_material_source_status_v1','read_owner_source_note_task_options_v1','read_owner_source_note_task_status_v1'}
_READ_ACTIONS |= {'read_owner_material_source_status_v1','read_owner_source_note_task_options_v1','read_owner_source_note_task_status_v1'}
_PROJECTION_STATES = frozenset({"loading", "empty", "unauthorized", "stale", "partial", "unavailable", "ready"})
_INPUT_FIELDS = {
    'read_owner_source_note_task_options_v1':frozenset({'project_ref'}),
    'read_owner_material_source_status_v1':frozenset({'owner_operation_id','input_digest'}),
    'read_owner_source_note_task_status_v1':frozenset({'owner_operation_id','input_digest'}),
    "read_backend_operation": frozenset({"original_ref"}),
    "read_installation_lifecycle": frozenset(),
    "read_owner_artifact_project_context_options": frozenset(),
    "read_source_correction_context_v1": frozenset({"source_id"}),
    "read_project_control_context_v1": frozenset({"project_ref"}),
    "read_project_control_context_v2": frozenset({"project_ref"}),
    "read_owner_project_artifact_options_v1": frozenset({"project_ref"}),
    "read_owner_project_artifact_v1": frozenset({"project_ref", "progress_ref", "expected_artifact_version", "expected_content_digest"}),
    "pause_project_v1": frozenset({"project_ref", "plan_ref", "expected_plan_revision"}),
    "resume_project_v1": frozenset({"project_ref", "plan_ref", "expected_plan_revision", "pause_original_ref"}),
    "open_workspace": frozenset({"client_protocol"}),
    "create_character": frozenset({"display_name", "blueprint", "model_capability_ref", "budget_ref"}),
    "bind_scene": frozenset({"scene_ref", "visibility", "acknowledgement"}),
    "compile_scheme": frozenset({"draft_ref", "budget_ref"}),
    "preview_scheme": frozenset({"compiled_digest", "budget_ref"}),
    "activate_scheme": frozenset({"compiled_digest", "preview_seal"}),
    "read_character_view": frozenset({"view_type", "cursor", "page_size"}),
    "read_creator_draft": frozenset({"draft_ref", "expected_graph_revision"}),
    "correct_or_edit": frozenset({"schema", "correction_kind", "statement", "source_refs",
                                   "target_refs", "access_epoch", "deletion_epoch",
                                   "impact_preview_ref", "source_id", "recorded_at"}),
    "run_experiment": frozenset({"experiment", "input_refs", "budget_ref", "retention_policy_ref"}),
    "prepare_transfer": frozenset({"mode", "target", "manifest_ref", "scope_selection"}),
    "execute_transfer": frozenset({"plan_ref", "current_epochs", "target_lease_ref"}),
    "erase_or_retire": frozenset({"schema", "source_id"}),
    "diagnose_and_export_support": frozenset({"question", "allowed_data", "retention_policy_ref", "local_destination"}),
    "install_or_upgrade": frozenset({"release_manifest_ref", "target_capability", "migration_plan_ref"}),
    "configure_or_control": frozenset({"config_diff", "object_ref", "control", "test_intent"}),
}

from .creator_configuration_v1 import READ_ACTION as _CONFIGURATION_READ, SAVE_ACTION as _CONFIGURATION_SAVE, SAVE_FIELDS as _CONFIGURATION_SAVE_FIELDS
_ACTIONS |= {_CONFIGURATION_READ, _CONFIGURATION_SAVE}
_READ_ACTIONS |= {_CONFIGURATION_READ}
_WIRED_COMMANDS |= {_CONFIGURATION_SAVE}
_MUTATION_CAPABILITIES.update({_CONFIGURATION_READ: "workbench.create", _CONFIGURATION_SAVE: "workbench.create"})
_INPUT_FIELDS.update({_CONFIGURATION_READ: frozenset(), _CONFIGURATION_SAVE: _CONFIGURATION_SAVE_FIELDS})

from .d04_initialization_v3 import ACTIONS as _D04_INITIALIZATION_ACTIONS
_ACTIONS |= frozenset(_D04_INITIALIZATION_ACTIONS) | {"read_d04_initialization_profile"}
_READ_ACTIONS |= {"read_d04_initialization_profile"}
_WIRED_COMMANDS |= frozenset(_D04_INITIALIZATION_ACTIONS)
_INPUT_FIELDS.update({action: spec[2] for action, spec in _D04_INITIALIZATION_ACTIONS.items()})
_INPUT_FIELDS["read_d04_initialization_profile"] = frozenset()
_MUTATION_CAPABILITIES.update({action: spec[1] for action, spec in _D04_INITIALIZATION_ACTIONS.items()})

from .domain_operations_v1 import ACTIONS as _DOMAIN_OPERATION_ACTIONS, INPUT_FIELDS as _DOMAIN_OPERATION_FIELDS
_ACTIONS |= frozenset(_DOMAIN_OPERATION_ACTIONS)
_WIRED_COMMANDS |= frozenset(_DOMAIN_OPERATION_ACTIONS)
from .domain_operations_v1 import input_fields_for_action_v1
_INPUT_FIELDS.update({action: input_fields_for_action_v1(action) for action in _DOMAIN_OPERATION_ACTIONS})
_MUTATION_CAPABILITIES.update({action: spec.capability for action, spec in _DOMAIN_OPERATION_ACTIONS.items()})
_ACTIONS |= {"d02_fixed_work_policy"}
_WIRED_COMMANDS |= {"d02_fixed_work_policy"}
_INPUT_FIELDS["d02_fixed_work_policy"] = frozenset({"policy"})
_MUTATION_CAPABILITIES["d02_fixed_work_policy"] = "d02.body_policy.install"
_ACTIONS |= {"d07_cognition_budget"}
_WIRED_COMMANDS |= {"d07_cognition_budget"}
_INPUT_FIELDS["d07_cognition_budget"] = frozenset({"parent_budget_lease_ref", "ceiling"})
_MUTATION_CAPABILITIES["d07_cognition_budget"] = "workbench.create"
from .context_catalogue_v1 import ACTION as _CONTEXT_CATALOGUE_ACTION, INPUT_FIELDS as _CONTEXT_CATALOGUE_FIELDS
_ACTIONS |= {_CONTEXT_CATALOGUE_ACTION}
_WIRED_COMMANDS |= {_CONTEXT_CATALOGUE_ACTION}
_INPUT_FIELDS[_CONTEXT_CATALOGUE_ACTION] = _CONTEXT_CATALOGUE_FIELDS
_MUTATION_CAPABILITIES[_CONTEXT_CATALOGUE_ACTION] = "workbench.activate"
from .c04_work_v3 import ACTIONS as _C04_ACTIONS, INPUTS as _C04_INPUTS
_ACTIONS |= set(_C04_ACTIONS)
_WIRED_COMMANDS |= set(_C04_ACTIONS)
_INPUT_FIELDS.update(_C04_INPUTS)
_MUTATION_CAPABILITIES.update(_C04_ACTIONS)

_PACKAGE_ACTIONS=frozenset({"read_package_maintenance","accept_package_switch","read_package_operation"})
_ACTIONS |= _PACKAGE_ACTIONS
_READ_ACTIONS |= {"read_package_maintenance","read_package_operation"}
_INPUT_FIELDS.update({"read_package_maintenance":frozenset(),"read_package_operation":frozenset({"operation_id"}),
    "accept_package_switch":frozenset({"candidate_cohort_ref","expected_selection_digest","expected_lifecycle_epoch"})})
_MUTATION_CAPABILITIES["accept_package_switch"]="workbench.maintain"



@dataclass(frozen=True)
class RequestContext:
    """Facts asserted by the trusted W09 transport adapter, never browser JSON."""

    origin_verified: bool
    csrf_verified: bool
    session_bound: bool


@dataclass(frozen=True)
class AuthenticatedSession:
    actor_id: str
    session_id: str
    scope_capabilities: Mapping[str, frozenset[str]]
    scope_audiences: Mapping[str, frozenset[str]]
    scope_purposes: Mapping[str, frozenset[str]]
    host_username: str | None = None
    owner_session_token: str | None = field(default=None, repr=False)
    owner_session_request: OwnerSessionLoginRequestV1 | None = field(
        default=None, repr=False)
    backend_operation_ref: str | None = None
    package_operation_id: str | None = None

    def allows(self, scope: str, capability: str, purpose: str, audience: str) -> bool:
        return (capability in self.scope_capabilities.get(scope, frozenset())
                and audience in self.scope_audiences.get(scope, frozenset())
                and purpose in self.scope_purposes.get(scope, frozenset()))


@dataclass(frozen=True)
class ApiResponse:
    status: str
    projection: Mapping[str, Any] | None = None
    receipt: Mapping[str, Any] | None = None
    problem: Mapping[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"status": self.status}
        if self.projection is not None:
            result["projection"] = dict(self.projection)
        if self.receipt is not None:
            result["receipt"] = dict(self.receipt)
        if self.problem is not None:
            result["problem"] = dict(self.problem)
        return result


class WorkbenchIssuer(Protocol):
    """W01/W09-backed coordinator facade. It is the only route to real writes."""

    def read_projection(self, *, session: AuthenticatedSession, scope: str, view_type: str,
                        purpose: str, audience: str, cursor: str | None = None,
                        page_size: int = 100) -> Mapping[str, Any]: ...

    def open_workspace(self, *, session: AuthenticatedSession, scope: str, purpose: str,
                       audience: str) -> Mapping[str, Any]: ...

    def read_creator_draft(self, *, session: AuthenticatedSession, scope: str,
                           draft_ref: str, purpose: str, audience: str,
                           expected_graph_revision: int | None = None
                           ) -> Mapping[str, Any]: ...

    def execute(self, *, session: AuthenticatedSession, action: str, scope: str, purpose: str,
                audience: str, operation_id: str, input_data: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def correct_source_claim(self, *, session: AuthenticatedSession, scope: str,
                             purpose: str, audience: str,
                             request: SourceCorrectionRequestV1) -> Mapping[str, Any]: ...


class WorkbenchService:
    """Validate D12 requests then delegate to an authenticated coordinator facade."""

    def __init__(self, issuer: WorkbenchIssuer | None = None) -> None:
        self._issuer = issuer

    def handle(self, payload: object, *, session: AuthenticatedSession | None,
               context: RequestContext) -> ApiResponse:
        if not context.session_bound or session is None:
            return self._problem("unauthorized", "session_unbound", "未建立已认证会话。", False)
        if not context.origin_verified or not context.csrf_verified:
            return self._problem("unauthorized", "request_context_unverified", "请求来源或防跨站校验未通过。", False)
        try:
            command = self._parse(payload)
        except (TypeError, ValueError) as exc:
            return self._problem("unavailable", "invalid_request", str(exc), False)
        capability = ("workbench.package_status" if command["action"] == "read_package_operation"
            else "workbench.operation_status" if command["action"] == "read_backend_operation"
            else "workbench.read" if command["action"] in _READ_ACTIONS
            else _MUTATION_CAPABILITIES[command["action"]])
        # Audience and capability resolve from server-session grants. Browser text only
        # selects a permitted audience; it can never expand one.
        if not session.allows(command["scope"], capability, command["purpose"], command["audience"]):
            return self._problem("unauthorized", "capability_denied", "当前会话没有此范围、用途或受众的能力。", False)
        if self._issuer is None:
            if command["action"] == "correct_or_edit":
                return self._correction_hold()
            if command["action"] == "erase_or_retire":
                return self._problem("unavailable", "erasure_authority_unavailable",
                                     "C09 删除权威尚未接入；未准备删除。", False)
            return self._problem("unavailable", "provider_unavailable", "工作台协调器尚未接入；未执行任何领域写入。", True)
        try:
            if command["action"] in _PACKAGE_ACTIONS:
                from .issuer import GraphWorkbenchIssuer
                from .package_maintenance_v2 import VIEW_SCHEMA,decode_package_profile_v2,decode_package_status_v2
                if type(self._issuer) is not GraphWorkbenchIssuer:
                    return self._problem("unavailable","package_issuer_unavailable","安装维护权威尚未接入。",False)
                returned=self._issuer.execute_package_maintenance(session=session,action=command["action"],scope=command["scope"],
                    purpose=command["purpose"],audience=command["audience"],operation_id=command["operation_id"],input_data=command["input"])
                status=returned.get("status")
                if status=="pending_confirmation":
                    problem=returned.get("problem",{})
                    if problem.get("operation_id")!=command["operation_id"] or problem.get("recovery_action")!="read_package_operation":
                        raise ValueError("package unknown result lacks exact original identity")
                    return ApiResponse(status=status,problem=problem)
                if status in {"unavailable","unauthorized"}:return ApiResponse(status=status,problem=returned.get("problem"))
                key="receipt" if command["action"]=="accept_package_switch" else "projection"
                value=returned.get(key)
                if command["action"]=="read_package_maintenance":decode_package_profile_v2(value,scope=command["scope"])
                else:
                    if type(value) is not dict or value.get("schema")!=VIEW_SCHEMA:raise ValueError("exact package operation view required")
                    target=command["operation_id"] if command["action"]=="accept_package_switch" else command["input"]["operation_id"]
                    decode_package_status_v2({k:v for k,v in value.items() if k!="schema"},scope=command["scope"],operation_id=target)
                return ApiResponse(status=status,**{key:value})
            if command["action"] == "correct_or_edit":
                if command["input"].get("correction_kind") == "source_access_revocation":
                    revoke = getattr(self._issuer, "revoke_source_access", None)
                    if not callable(revoke):
                        return self._correction_hold()
                    input_data = command["input"]
                    digest = "sha256:" + request_digest({
                        "action": "correct_or_edit", "scope": command["scope"],
                        "purpose": command["purpose"], "audience": command["audience"],
                        "operation_id": command["operation_id"], "input": input_data,
                    })
                    returned = revoke(
                        session=session, scope=command["scope"],
                        purpose=command["purpose"], audience=command["audience"],
                        operation_id=command["operation_id"], input_data=input_data,
                        request_digest=digest,
                    )
                    return self._command_response(
                        "correct_or_edit", command["operation_id"], input_data,
                        returned, expected_digest=digest,
                    )
                submit = getattr(self._issuer, "correct_source_claim", None)
                if not callable(submit):
                    return self._correction_hold()
                scope_parts = command["scope"].split("/")
                if len(scope_parts) != 2:
                    return self._problem("unavailable", "invalid_request", "纠错需要精确的角色范围。", False)
                input_data = command["input"]
                digest = "sha256:" + request_digest({
                    "action": "correct_or_edit", "scope": command["scope"],
                    "purpose": command["purpose"], "audience": command["audience"],
                    "operation_id": command["operation_id"], "input": input_data,
                })
                correction = SourceCorrectionRequestV1(
                    namespace=NamespaceId(*scope_parts),
                    operation_id=command["operation_id"], request_digest=digest,
                    statement=input_data["statement"],
                    source_refs=tuple(input_data["source_refs"]),
                    target_refs=tuple(input_data["target_refs"]),
                    access_epoch=input_data["access_epoch"],
                    deletion_epoch=input_data["deletion_epoch"],
                    impact_preview_ref=input_data.get("impact_preview_ref"),
                )
                returned = submit(session=session, scope=command["scope"],
                                  purpose=command["purpose"], audience=command["audience"],
                                  request=correction)
                if (returned.get("status") == "unavailable"
                        and isinstance(returned.get("problem"), Mapping)
                        and returned["problem"].get("code") == "source_correction_commit_unavailable"):
                    return self._correction_hold()
                return self._command_response("correct_or_edit", command["operation_id"],
                                              input_data, returned, expected_digest=digest)
            if command["action"] == "read_installation_lifecycle":
                reader = getattr(self._issuer, "read_installation_lifecycle", None)
                if not callable(reader):
                    return self._problem("unavailable", "installed_whole_host_controller_unavailable", "整机维护控制尚未接入。", False)
                returned = reader(session=session, scope=command["scope"], purpose=command["purpose"], audience=command["audience"])
                if returned.get("status") == "ready":
                    view = returned.get("projection")
                    expected = {"schema", "scope", "installation_id", "state", "lifecycle_epoch", "head_digest", "operation_id"}
                    if (type(view) is not dict or set(view) != expected
                            or view["schema"] != "d12.installation_lifecycle_view.v1" or view["scope"] != "whole_host"
                            or type(view["installation_id"]) is not str or not view["installation_id"]
                            or view["state"] not in {"active", "quiescing", "drained", "paused", "resuming"}
                            or type(view["lifecycle_epoch"]) is not int or view["lifecycle_epoch"] < 0
                            or re.fullmatch(r"sha256:[0-9a-f]{64}", str(view["head_digest"])) is None
                            or view["operation_id"] is not None and (type(view["operation_id"]) is not str or not view["operation_id"])):
                        return self._problem("unavailable", "invalid_provider_response", "维护控制当前状态原件无效。", False)
                return self._projection_response(returned)
            if command["action"] == "read_d04_initialization_profile":
                return self._projection_response(self._issuer.read_d04_initialization_profile(
                    session=session, scope=command["scope"], purpose=command["purpose"], audience=command["audience"]))
            if command["action"] == "open_workspace":
                returned = self._issuer.open_workspace(session=session, scope=command["scope"],
                                                       purpose=command["purpose"],
                                                       audience=command["audience"])
                return self._projection_response(returned)
            if command["action"] == "read_character_view":
                returned = self._issuer.read_projection(session=session, scope=command["scope"],
                                                         view_type=command["input"]["view_type"],
                                                         purpose=command["purpose"], audience=command["audience"],
                                                         cursor=command["input"].get("cursor"),
                                                         page_size=command["input"].get("page_size", 100))
                return self._projection_response(returned)
            if command["action"] == "read_backend_operation":
                reader = getattr(self._issuer, "read_backend_operation", None)
                if not callable(reader):
                    return self._problem("unavailable", "backend_status_unavailable",
                                         "当前操作状态读取端口尚未接入。", False)
                returned = reader(session=session, scope=command["scope"],
                    purpose=command["purpose"], audience=command["audience"],
                    original_ref=command["input"]["original_ref"])
                if (not isinstance(returned, Mapping) or returned.get("status") not in BACKEND_STATES):
                    return self._problem("unavailable", "invalid_provider_response", "操作状态原件无效。", False)
                receipt = returned.get("receipt")
                if receipt is None:
                    return ApiResponse(status=returned["status"], problem=returned.get("problem"))
                from ..runtime.lifecycle_operations_v1 import decode_original
                original = decode_original(receipt)
                if original.namespace.as_tuple != tuple(command["scope"].split("/")):
                    return self._problem("unavailable", "invalid_provider_response", "操作状态范围不符。", False)
                return ApiResponse(status=original.state, receipt=original.to_wire())
            if command["action"] == "read_creator_draft":
                returned = self._issuer.read_creator_draft(
                    session=session, scope=command["scope"],
                    draft_ref=command["input"]["draft_ref"],
                    purpose=command["purpose"], audience=command["audience"],
                    expected_graph_revision=command["input"].get("expected_graph_revision"),
                )
                return self._projection_response(returned)
            if command["action"] == _CONFIGURATION_READ:
                from .issuer import GraphWorkbenchIssuer
                if type(self._issuer) is not GraphWorkbenchIssuer:
                    return self._problem("unavailable", "creator_configuration_unavailable", "当前配置权威尚未接入。", False)
                returned = self._issuer.read_configuration_draft(
                    session=session, scope=command["scope"], purpose=command["purpose"], audience=command["audience"])
                return self._projection_response(returned)
            if command['action']=='read_owner_material_source_status_v1':
                from .issuer import GraphWorkbenchIssuer
                if type(self._issuer) is not GraphWorkbenchIssuer:
                    return self._problem('unavailable','owner_material_read_unavailable','当前材料读取权威尚未接入。',False)
                return self._projection_response(self._issuer.read_owner_material_source_status_v1(session=session,
                    scope=command['scope'],purpose=command['purpose'],audience=command['audience'],input_data=command['input']))
            if command['action'] in {'read_owner_source_note_task_options_v1','read_owner_source_note_task_status_v1'}:
                from .issuer import GraphWorkbenchIssuer
                if type(self._issuer) is not GraphWorkbenchIssuer:
                    return self._problem('unavailable','owner_source_note_task_read_unavailable','当前任务读取权威尚未接入。',False)
                returned=self._issuer.read_owner_source_note_task_v1(session=session,scope=command['scope'],
                    purpose=command['purpose'],audience=command['audience'],input_data=command['input'],
                    options=command['action']=='read_owner_source_note_task_options_v1')
                return self._projection_response(returned)
            if command["action"] in {"read_owner_project_artifact_options_v1", "read_owner_project_artifact_v1"}:
                from .issuer import GraphWorkbenchIssuer
                if type(self._issuer) is not GraphWorkbenchIssuer:
                    return self._problem("unavailable", "artifact_read_authority_unavailable", "当前作品读取权威尚未接入。", False)
                returned = self._issuer.read_owner_project_artifact_v1(session=session,
                    scope=command["scope"], purpose=command["purpose"], audience=command["audience"],
                    input_data=command["input"], options=command["action"] == "read_owner_project_artifact_options_v1")
                return self._projection_response(returned)
            if command["action"] in {"read_project_control_context_v1", "read_project_control_context_v2"}:
                from .issuer import GraphWorkbenchIssuer
                if type(self._issuer) is not GraphWorkbenchIssuer:
                    return self._problem("unavailable", "project_control_context_unavailable", "当前项目控制权威尚未接入。", False)
                reader = (self._issuer.read_project_control_context_v1 if command["action"] == "read_project_control_context_v1"
                    else self._issuer.read_project_control_context_v2)
                returned = reader(session=session,
                    scope=command["scope"], purpose=command["purpose"], audience=command["audience"],
                    project_ref=command["input"]["project_ref"])
                return self._projection_response(returned)
            if command["action"] == "read_source_correction_context_v1":
                from .issuer import GraphWorkbenchIssuer
                if type(self._issuer) is not GraphWorkbenchIssuer:
                    return self._problem("unavailable", "source_correction_context_unavailable", "当前来源纠错权威尚未接入。", False)
                returned = self._issuer.read_source_correction_context_v1(session=session,
                    scope=command["scope"], purpose=command["purpose"], audience=command["audience"],
                    source_id=command["input"]["source_id"])
                from ..graph_worker import GraphStorageWorkV3
                if type(returned) is GraphStorageWorkV3:
                    return returned.map_terminal_v3("service", self._projection_response,
                                                     self._projection_error_v3)
                return self._projection_response(returned)
            if command["action"] == "read_owner_artifact_project_context_options":
                from .issuer import GraphWorkbenchIssuer
                if type(self._issuer) is not GraphWorkbenchIssuer:
                    return self._problem("unavailable", "project_context_unavailable", "当前项目配置权威尚未接入。", False)
                returned = self._issuer.read_owner_artifact_project_context_options(
                    session=session, scope=command["scope"], purpose=command["purpose"], audience=command["audience"])
                return self._projection_response(returned)
            if command["action"] == _CONFIGURATION_SAVE:
                from .issuer import GraphWorkbenchIssuer
                if type(self._issuer) is not GraphWorkbenchIssuer:
                    return self._problem("unavailable", "creator_configuration_unavailable", "当前配置权威尚未接入。", False)
                returned = self._issuer.save_creator_draft(
                    session=session, scope=command["scope"], purpose=command["purpose"], audience=command["audience"],
                    operation_id=command["operation_id"], input_data=command["input"])
                return self._command_response(command["action"], command["operation_id"], command["input"], returned)
            if command["action"] == "run_experiment":
                # This route depends on W01's signed Owner read and persisted
                # paid original. A generic WorkbenchIssuer receipt is not proof.
                from .issuer import GraphWorkbenchIssuer
                if type(self._issuer) is not GraphWorkbenchIssuer:
                    return self._problem("unavailable", "experiment_issuer_unavailable",
                                         "实验权威尚未接入。", False)
            if command["action"] == "diagnose_and_export_support":
                from .issuer import GraphWorkbenchIssuer
                if type(self._issuer) is not GraphWorkbenchIssuer:
                    return self._problem("unavailable", "support_issuer_unavailable",
                                         "诊断导出权威尚未接入。", False)
            if command["action"] == "erase_or_retire":
                from .issuer import GraphWorkbenchIssuer
                if type(self._issuer) is not GraphWorkbenchIssuer:
                    return self._problem("unavailable", "erasure_authority_unavailable",
                                         "C09 删除权威尚未接入；未准备删除。", False)
            if command["action"] in {"prepare_transfer", "execute_transfer", "install_or_upgrade", "configure_or_control"}:
                from .issuer import GraphWorkbenchIssuer
                if type(self._issuer) is not GraphWorkbenchIssuer:
                    return self._problem("unavailable", "backend_issuer_unavailable",
                                         "当前领域后端原件读取端口尚未接入。", False)
            if command["action"] not in _WIRED_COMMANDS:
                return self._problem(
                    "unavailable", "domain_action_unavailable",
                    "此操作尚未接入领域权威；未执行领域写入。", False)
            returned = self._issuer.execute(session=session, action=command["action"], scope=command["scope"],
                                            purpose=command["purpose"], audience=command["audience"],
                                            operation_id=command["operation_id"], input_data=command["input"])
            from ..graph_worker import GraphStorageWorkV3
            if type(returned) is GraphStorageWorkV3:
                action, operation_id, input_data = command["action"], command["operation_id"], command["input"]
                if returned.kind == "current_method_learning_read_v3":
                    from .domain_operations_v1 import ACTIONS
                    from ..runtime.current_method_learning_read_v3 import (
                        METHOD_INPUT_OPERATIONS_V3, _MethodLearningReadV3)
                    state = returned.state
                    if (action not in ACTIONS or ACTIONS[action].operation_kind not in METHOD_INPUT_OPERATIONS_V3
                            or type(state) is not _MethodLearningReadV3 or state.work is not returned
                            or returned.coordinator is not self._issuer._coordinator
                            or returned.operation_id != operation_id
                            or state.operation_kind != ACTIONS[action].operation_kind):
                        raise ValueError("service continuation differs from its actual Owner method command")
                    return returned.map_terminal_v3("service",
                        lambda value: self._command_response(action, operation_id, input_data, value),
                        self._projection_error_v3)
                if (action != "domain_admit_owner_material_source_v1"
                        or returned.kind != "owner_material_source_write_v3" or returned.operation_id != operation_id):
                    raise ValueError("service continuation differs from the actual Owner Source command")
                state = returned.state
                return returned.map_terminal_v3("service",
                    lambda value: self._command_response(action, operation_id, input_data, value,
                        owner_material_input_witness=state.input_witness), self._projection_error_v3)
            return self._command_response(command["action"], command["operation_id"], command["input"], returned)
        except PermissionError:
            return self._problem("unauthorized", "capability_denied", "服务端拒绝了当前能力。", False)
        except LocalModuleAdmissionDeniedV1 as exc:
            modules = ", ".join(value.upper() for value in exc.disabled_modules)
            return self._problem("unavailable", "local_module_disabled",
                f"本机模块 {modules} 已关闭新工作。请在插件配置页开启并重载后再创建新操作。", False)
        except LookupError:
            return self._problem("unavailable", "provider_unavailable", "请求的领域提供方不可用。", True)
        except Exception:
            return self._problem("unavailable", "provider_failed", "领域提供方未能完成请求。", True)

    def _projection_error_v3(self, error):
        # Pure terminal packaging, matching handle's existing exception order.
        if isinstance(error, PermissionError):
            return self._problem("unauthorized", "capability_denied", "服务端拒绝了当前能力。", False)
        if isinstance(error, LocalModuleAdmissionDeniedV1):
            modules = ", ".join(value.upper() for value in error.disabled_modules)
            return self._problem("unavailable", "local_module_disabled",
                f"本机模块 {modules} 已关闭新工作。请在插件配置页开启并重载后再创建新操作。", False)
        if isinstance(error, LookupError):
            return self._problem("unavailable", "provider_unavailable", "请求的领域提供方不可用。", True)
        if isinstance(error, Exception):
            return self._problem("unavailable", "provider_failed", "领域提供方未能完成请求。", True)
        raise error

    @staticmethod
    def _parse(payload: object) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise TypeError("request body must be an object")
        allowed = {"schema_version", "action", "scope", "purpose", "audience", "operation_id", "input"}
        unknown = set(payload) - allowed
        missing = allowed - set(payload)
        if unknown or missing:
            raise ValueError("request fields do not match d12.contract.v1")
        if payload["schema_version"] != D12_SCHEMA:
            raise ValueError("unsupported workbench schema")
        action, scope, purpose, audience, operation_id = (payload[key] for key in ("action", "scope", "purpose", "audience", "operation_id"))
        if action not in _ACTIONS:
            raise ValueError("unknown workbench action")
        if not isinstance(scope, str) or not _SCOPE.fullmatch(scope):
            raise ValueError("invalid role scope")
        if not isinstance(purpose, str) or not purpose or len(purpose) > 128:
            raise ValueError("invalid purpose")
        if not isinstance(audience, str) or not audience or len(audience) > 128:
            raise ValueError("invalid audience")
        if not isinstance(operation_id, str):
            raise ValueError("operation_id must be a canonical UUID4")
        try:
            parsed_operation_id = UUID(operation_id)
        except ValueError as exc:
            raise ValueError("operation_id must be a canonical UUID4") from exc
        if parsed_operation_id.version != 4 or str(parsed_operation_id) != operation_id:
            raise ValueError("operation_id must be a canonical UUID4")
        if not isinstance(payload["input"], Mapping):
            raise TypeError("input must be an object")
        input_data = dict(payload["input"])
        unexpected_input = set(input_data) - _INPUT_FIELDS[action]
        if unexpected_input:
            raise ValueError("input fields are not valid for this workbench action")
        try:
            json.dumps(input_data, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("input must be JSON-safe") from exc
        if action in _PACKAGE_ACTIONS:
            from .package_maintenance_v2 import validate_package_input_v2
            if len(scope.split("/"))!=2:raise ValueError("exact Owner package namespace required")
            validate_package_input_v2(action,input_data,purpose=purpose,audience=audience)
        if action in _C04_ACTIONS:
            from .c04_work_v3 import validate_c04_input_v3
            if audience != "owner" or len(scope.split("/")) != 2:
                raise ValueError("C04 requires exact signed Owner scope")
            validate_c04_input_v3(action, input_data)
        if action == "d07_cognition_budget":
            from .d07_budget_v1 import validate_d07_budget_input_v1
            if audience != "owner" or len(scope.split("/")) != 2:
                raise ValueError("D07 budget requires exact signed Owner scope")
            validate_d07_budget_input_v1(input_data)
        if action == "d02_fixed_work_policy":
            from .body_policy_v1 import decode_fixed_body_policy_v1
            if audience != "owner" or len(scope.split("/")) != 2 or set(input_data) != {"policy"}:
                raise ValueError("fixed body policy requires exact signed Owner input")
            decode_fixed_body_policy_v1(input_data["policy"])
        if action == _CONTEXT_CATALOGUE_ACTION:
            from .context_catalogue_v1 import validate_context_catalogue_input_v1
            if audience != "owner" or len(scope.split("/")) != 2:
                raise ValueError("Context catalogue requires the exact signed Owner scope")
            validate_context_catalogue_input_v1(input_data)
        if action in _DOMAIN_OPERATION_ACTIONS:
            from .domain_operations_v1 import validate_input_v1
            if audience != "owner" or len(scope.split("/")) != 2:
                raise ValueError("domain commands require the exact signed Owner scope")
            validate_input_v1(action, input_data)
        if action in {_CONFIGURATION_READ, _CONFIGURATION_SAVE}:
            from .creator_configuration_v1 import validate_creator_configuration_input_v1
            if len(scope.split("/")) != 2:
                raise ValueError("creator configuration requires the exact Owner scope")
            validate_creator_configuration_input_v1(action, input_data, purpose=purpose,
                                                   audience=audience, operation_id=operation_id)
        if action in _D04_INITIALIZATION_ACTIONS:
            from .d04_initialization_v3 import validate_input_v3
            if audience != "owner" or len(scope.split("/")) != 2:
                raise ValueError("D04 initialization requires the exact Owner scope")
            validate_input_v3(action, input_data)
        if action == "read_character_view" and input_data.get("view_type") not in {
                "overview", "creation", "relations", "memory", "d06.memory_sources.v1",
                "cognition", "action", "expression", "diagnostics", "lifecycle"}:
            raise ValueError("read_character_view requires a known view_type")
        if action == "open_workspace" and input_data.get("client_protocol") != D12_SCHEMA:
            raise ValueError("open_workspace requires the current client protocol")
        if action in {"prepare_transfer", "execute_transfer", "install_or_upgrade", "configure_or_control"}:
            if (set(input_data) != _INPUT_FIELDS[action] or len(scope.split("/")) != 2
                    or audience != "owner"):
                raise ValueError("backend operation requires its exact Owner-scoped input")
            ref_fields = {"prepare_transfer": ("target", "manifest_ref"),
                          "execute_transfer": ("plan_ref", "target_lease_ref"),
                          "install_or_upgrade": ("release_manifest_ref", "target_capability", "migration_plan_ref"),
                          "configure_or_control": ("object_ref", "control")}[action]
            for name in ref_fields:
                ref = input_data[name]
                if (type(ref) is not str or not 1 <= len(ref) <= 4096 or not ref.strip()
                        or any(char in ref for char in ("\\", "\x00", "\r", "\n"))):
                    raise ValueError(f"{name} must be a bounded opaque selector")
            if action == "prepare_transfer":
                refs = input_data["scope_selection"]
                if (input_data["mode"] not in {"backup", "share", "relocate", "import"}
                        or type(refs) is not list or not 1 <= len(refs) <= 100
                        or any(type(ref) is not str or not 1 <= len(ref) <= 4096 or not ref.strip() for ref in refs)
                        or len(set(refs)) != len(refs)):
                    raise ValueError("transfer preparation requires a known mode and bounded unique scope selectors")
            if action == "execute_transfer":
                expected = input_data["current_epochs"]
                if (type(expected) is not dict or set(expected) != {
                        "schema", "plan_digest", "graph_revision", "access_epoch", "delete_epoch", "activation_generation"}
                        or expected["schema"] != "d12.transfer_expected_epochs.v1"
                        or type(expected["plan_digest"]) is not str
                        or re.fullmatch(r"sha256:[0-9a-f]{64}", expected["plan_digest"]) is None
                        or any(type(expected[name]) is not int or expected[name] < 0
                               for name in ("graph_revision", "access_epoch", "delete_epoch"))
                        or type(expected["activation_generation"]) is not int
                        or expected["activation_generation"] < 1):
                    raise ValueError("transfer execution requires its versioned expected plan and epochs")
            if action == "configure_or_control":
                if (type(input_data["config_diff"]) is not dict or len(input_data["config_diff"]) > 100
                        or type(input_data["test_intent"]) not in (dict, type(None))):
                    raise ValueError("control requires a bounded configuration object and explicit test intent")
                if len(json.dumps(input_data, ensure_ascii=False, allow_nan=False).encode("utf-8")) > 65536:
                    raise ValueError("control input exceeds its bounded contract")
        if action == "read_installation_lifecycle" and (
                input_data or audience != "owner" or purpose not in {"audit", "workbench_view"}):
            raise ValueError("installation lifecycle read requires empty input and current Owner audience")
        if action == "read_backend_operation":
            if set(input_data) != {"original_ref"}:
                raise ValueError("backend status requires exactly one original reference")
            ref = input_data["original_ref"]
            if (audience != "owner" or purpose not in {"audit", "workbench_view"} or type(ref) is not str
                    or re.fullmatch(r"d12authority:[0-9a-f]{64}", ref) is None):
                raise ValueError("backend status requires an exact Authority operation reference and Owner audience")
        if action in {'read_owner_material_source_status_v1','read_owner_source_note_task_options_v1','read_owner_source_note_task_status_v1'}:
            if audience!='owner' or purpose!='workbench_view' or len(scope.split('/'))!=2:
                raise ValueError('Owner task read requires its exact authenticated Owner scope')
            if action=='read_owner_source_note_task_options_v1':
                from ..graph_types import AtomKey
                key=AtomKey.from_token(input_data['project_ref'])
                if key.type_name!='d10.life_project.v1' or (key.owner.bot,key.owner.persona)!=tuple(scope.split('/')):
                    raise ValueError('Owner task project selector crossed namespace/type')
            else:
                if (type(input_data['owner_operation_id']) is not str or not 1<=len(input_data['owner_operation_id'])<=128
                        or type(input_data['input_digest']) is not str or re.fullmatch(r'[0-9a-f]{64}',input_data['input_digest']) is None):
                    raise ValueError('Owner task status needs its original operation and public input digest')
        if action in {"read_owner_project_artifact_options_v1", "read_owner_project_artifact_v1"}:
            if (set(input_data) != _INPUT_FIELDS[action] or audience != "owner"
                    or purpose != "workbench_view" or len(scope.split("/")) != 2):
                raise ValueError("artifact read requires exact current Owner view selectors")
            from ..graph_types import AtomKey
            for name, expected in (("project_ref", "d10.life_project.v1"), ("progress_ref", "d10.life_progress.v1")):
                if name not in input_data:
                    continue
                ref = input_data[name]
                if type(ref) is not str or not 1 <= len(ref) <= 4096:
                    raise ValueError("artifact read selector must be bounded")
                key = AtomKey.from_token(ref)
                if key.type_name != expected or (key.owner.bot, key.owner.persona) != tuple(scope.split("/")):
                    raise ValueError("artifact read selector crossed actual scope")
            if action == "read_owner_project_artifact_v1":
                if type(input_data["expected_artifact_version"]) is not int or input_data["expected_artifact_version"] < 1:
                    raise ValueError("artifact read requires an actual selected version")
                if type(input_data["expected_content_digest"]) is not str or re.fullmatch(r"[0-9a-f]{64}", input_data["expected_content_digest"]) is None:
                    raise ValueError("artifact read requires its actual content commitment")
        if action in {"read_project_control_context_v1", "read_project_control_context_v2", "pause_project_v1", "resume_project_v1"}:
            if (set(input_data) != _INPUT_FIELDS[action] or audience != "owner"
                    or purpose != "workbench_user_action" or len(scope.split("/")) != 2):
                raise ValueError("project control requires its exact current Owner input")
            from ..graph_types import AtomKey
            types = {"project_ref": "d10.life_project.v1", "plan_ref": "d08.personal_plan.v1"}
            for name, expected in types.items():
                if name not in input_data:
                    continue
                ref = input_data[name]
                if type(ref) is not str or not 1 <= len(ref) <= 4096:
                    raise ValueError("project control selector must be bounded")
                key = AtomKey.from_token(ref)
                if key.type_name != expected or (key.owner.bot, key.owner.persona) != tuple(scope.split("/")):
                    raise ValueError("project control selector crosses current scope")
            if action not in {"read_project_control_context_v1", "read_project_control_context_v2"}:
                revision = input_data["expected_plan_revision"]
                if type(revision) is not int or revision < 1:
                    raise ValueError("project control requires actual Plan head CAS")
            if action == "resume_project_v1" and (type(input_data["pause_original_ref"]) is not str
                    or not 1 <= len(input_data["pause_original_ref"]) <= 4096):
                raise ValueError("project resume requires its actual pause original")
        if action == "read_source_correction_context_v1":
            if (set(input_data) != {"source_id"} or audience != "owner"
                    or purpose != "workbench_user_action" or len(scope.split("/")) != 2):
                raise ValueError("source correction context requires exact current Owner scope")
            source_id = input_data["source_id"]
            if type(source_id) is not str or not 1 <= len(source_id) <= 256 or not source_id.strip():
                raise ValueError("source correction requires one bounded Source identity")
        if action == "read_creator_draft":
            if (not isinstance(input_data.get("draft_ref"), str)
                    or not 1 <= len(input_data["draft_ref"]) <= 4096):
                raise ValueError("read_creator_draft requires a bounded draft reference")
            epoch = input_data.get("expected_graph_revision")
            if epoch is not None and (type(epoch) is not int or epoch < 0):
                raise ValueError("expected_graph_revision must be a nonnegative exact integer")
        if action in {"compile_scheme", "preview_scheme", "activate_scheme"}:
            fields = set(input_data)
            if (fields != _INPUT_FIELDS[action]
                    and not (action == "activate_scheme"
                             and fields == {"compiled_digest"})):
                raise ValueError("scheme command requires its exact versioned input")
            for name, value in input_data.items():
                if type(value) is not str or not 1 <= len(value) <= 4096:
                    raise ValueError(f"{name} must be a bounded reference")
            if "compiled_digest" in input_data and (
                    len(input_data["compiled_digest"]) != 64
                    or any(ch not in "0123456789abcdef"
                           for ch in input_data["compiled_digest"])):
                raise ValueError("compiled_digest must be lowercase SHA-256")
            if "preview_seal" in input_data and (
                    len(input_data["preview_seal"]) != 64
                    or any(ch not in "0123456789abcdef"
                           for ch in input_data["preview_seal"])):
                raise ValueError("preview_seal must be lowercase SHA-256")
        if action == "create_character":
            if set(input_data) != _INPUT_FIELDS[action]:
                raise ValueError("create_character requires display_name, blueprint, model_capability_ref and budget_ref")
            if (not isinstance(input_data["display_name"], str)
                    or not 1 <= len(input_data["display_name"].strip()) <= 80):
                raise ValueError("create_character requires a display name")
            blueprint = input_data["blueprint"]
            if (not isinstance(blueprint, str) or len(blueprint) > 192
                    or _BLUEPRINT_REF.fullmatch(blueprint) is None):
                raise ValueError("create_character requires a bounded blueprint reference")
            if any(not isinstance(input_data[name], str) or not _SCOPE.fullmatch(input_data[name])
                   for name in ("model_capability_ref", "budget_ref")):
                raise ValueError("create_character requires server-resolvable capability and budget references")
        if action == "run_experiment":
            if (set(input_data) != _INPUT_FIELDS[action]
                    or type(input_data["experiment"]) is not str
                    or not 1 <= len(input_data["experiment"]) <= 192
                    or type(input_data["retention_policy_ref"]) is not str
                    or not 1 <= len(input_data["retention_policy_ref"]) <= 4096
                    or type(input_data["input_refs"]) is not list
                    or not 1 <= len(input_data["input_refs"]) <= 100
                    or any(type(ref) is not str or not 1 <= len(ref) <= 4096
                           for ref in input_data["input_refs"])
                    or len(set(input_data["input_refs"])) != len(input_data["input_refs"])
                    or type(input_data["budget_ref"]) is not str
                    or not 1 <= len(input_data["budget_ref"]) <= 4096):
                raise ValueError("run_experiment requires bounded server-resolved experiment inputs")
            if input_data["experiment"] == "d12.scheme_preview.v1" and (
                    input_data["retention_policy_ref"] != "d12.preview_original.v1"
                    or len(input_data["input_refs"]) != 1
                    or re.fullmatch(r"[0-9a-f]{64}", input_data["input_refs"][0]) is None):
                raise ValueError("scheme preview requires its versioned original contract")
        if action == "diagnose_and_export_support":
            if (set(input_data) != _INPUT_FIELDS[action]
                    or type(input_data["question"]) is not str
                    or not 1 <= len(input_data["question"].strip()) <= 4096
                    or type(input_data["allowed_data"]) is not list
                    or not 1 <= len(input_data["allowed_data"]) <= 32
                    or any(type(item) is not str or not 1 <= len(item) <= 192
                           for item in input_data["allowed_data"])
                    or len(set(input_data["allowed_data"])) != len(input_data["allowed_data"])
                    or type(input_data["retention_policy_ref"]) is not str
                    or not 1 <= len(input_data["retention_policy_ref"]) <= 4096
                    or input_data["local_destination"] != "managed"):
                raise ValueError("support export requires explicitly allowed data and a managed destination")
        if action == "bind_scene":
            if set(input_data) != _INPUT_FIELDS[action]:
                raise ValueError("bind_scene requires scene_ref, visibility and acknowledgement")
            if (not isinstance(input_data["scene_ref"], str)
                    or not input_data["scene_ref"].startswith("scene:")
                    or len(input_data["scene_ref"]) <= len("scene:")
                    or not _SCOPE.fullmatch(input_data["scene_ref"])):
                raise ValueError("bind_scene requires a server-resolvable scene reference")
            if input_data["visibility"] not in {"private", "group"} or input_data["acknowledgement"] is not True:
                raise ValueError("bind_scene requires an acknowledged visibility")
        if action == "erase_or_retire":
            if (set(input_data) != _INPUT_FIELDS[action]
                    or purpose != "audit" or audience != "owner"
                    or len(scope.split("/")) != 2):
                raise ValueError("erase_or_retire requires the Owner scoped-erasure v2 request")
            try:
                D12ScopedErasureRequestV2.from_wire(input_data)
            except (TypeError, ValueError) as exc:
                raise ValueError("erase_or_retire requires one bounded source id") from exc
        if action == "correct_or_edit":
            if len(scope.split("/")) != 2:
                raise ValueError("source correction requires an exact role scope")
            if input_data.get("correction_kind") == "source_access_revocation":
                required = {"schema", "correction_kind", "source_id", "recorded_at"}
                if set(input_data) != required:
                    raise ValueError("source access revocation requires schema, source_id and recorded_at")
                if (input_data["schema"] != SOURCE_ACCESS_REVOCATION_SCHEMA
                        or purpose != "audit" or audience != "owner"):
                    raise ValueError("source access revocation requires the Owner audit contract")
                if (type(input_data["source_id"]) is not str
                        or not 1 <= len(input_data["source_id"]) <= 256
                        or not input_data["source_id"].strip()):
                    raise ValueError("source access revocation requires a bounded source id")
                try:
                    finite_recorded_at = (type(input_data["recorded_at"]) in (int, float)
                                          and math.isfinite(float(input_data["recorded_at"])))
                except (OverflowError, ValueError):
                    finite_recorded_at = False
                if (not finite_recorded_at or input_data["recorded_at"] < 0):
                    raise ValueError("recorded_at must be finite and nonnegative")
                try:
                    request_uuid = UUID(operation_id)
                except ValueError as exc:
                    raise ValueError("source access revocation operation_id must be UUID4") from exc
                if request_uuid.version != 4 or str(request_uuid) != operation_id:
                    raise ValueError("source access revocation operation_id must be canonical UUID4")
                return {"action": action, "scope": scope, "purpose": purpose,
                        "audience": audience, "operation_id": operation_id,
                        "input": input_data}
            required = {"schema", "correction_kind", "statement", "source_refs",
                        "target_refs", "access_epoch", "deletion_epoch"}
            if set(input_data) not in (required, required | {"impact_preview_ref"}):
                raise ValueError("source correction requires its versioned claim, sources, targets and epochs")
            if (input_data["schema"] != SOURCE_CORRECTION_SCHEMA
                    or input_data["correction_kind"] != "source_claim"):
                raise ValueError("unsupported source correction contract")
            if (type(input_data["statement"]) is not str
                    or not 1 <= len(input_data["statement"].strip()) <= 4096):
                raise ValueError("source correction requires a bounded statement")
            for name in ("source_refs", "target_refs"):
                refs = input_data[name]
                if (type(refs) is not list or not 1 <= len(refs) <= 100
                        or any(type(ref) is not str or not 1 <= len(ref) <= 4096
                               or not ref.strip() for ref in refs)
                        or len(set(refs)) != len(refs)):
                    raise ValueError(f"{name} must contain unique bounded references")
            for name in ("access_epoch", "deletion_epoch"):
                if type(input_data[name]) is not int or input_data[name] < 0:
                    raise ValueError(f"{name} must be a nonnegative exact integer")
            if "impact_preview_ref" in input_data and (
                    type(input_data["impact_preview_ref"]) is not str
                    or not 1 <= len(input_data["impact_preview_ref"]) <= 4096):
                raise ValueError("impact_preview_ref must be a bounded reference")
        if "page_size" in input_data and (type(input_data["page_size"]) is not int or not 1 <= input_data["page_size"] <= 100):
            raise ValueError("page_size must be an integer from 1 through 100")
        if "cursor" in input_data and (type(input_data["cursor"]) is not str
                                        or not 1 <= len(input_data["cursor"]) <= 4096):
            raise ValueError("cursor must be a bounded string")
        return {"action": action, "scope": scope, "purpose": purpose, "audience": audience,
                "operation_id": operation_id, "input": input_data}

    @classmethod
    def _projection_response(cls, returned: Mapping[str, Any]) -> ApiResponse:
        status = returned.get("status")
        if status not in _PROJECTION_STATES:
            return cls._problem("unavailable", "invalid_provider_response", "提供方返回了未知投影状态。", False)
        projection = returned.get("projection")
        if status in {"stale", "partial", "unavailable", "unauthorized"} and projection is not None:
            # No client-side assembly or retained content on a degraded projection.
            projection = None
        return ApiResponse(status=status, projection=projection if isinstance(projection, Mapping) else None,
                           receipt=returned.get("receipt") if status == "ready" and isinstance(returned.get("receipt"), Mapping) else None,
                           problem=returned.get("problem") if isinstance(returned.get("problem"), Mapping) else None)

    @classmethod
    def _command_response(cls, action: str, operation_id: str, input_data: Mapping[str, Any],
                          returned: Mapping[str, Any], *,
                          expected_digest: str | None = None,
                          owner_material_input_witness=None) -> ApiResponse:
        status = returned.get("status")
        backend_original = (action in {"prepare_transfer", "execute_transfer", "install_or_upgrade", "configure_or_control"}
                            or action == "run_experiment" and input_data.get("experiment") != "d12.scheme_preview.v1"
                            or action == "diagnose_and_export_support" and not (
                                input_data.get("question") == "view_health"
                                and input_data.get("allowed_data") == ["view_status"]
                                and input_data.get("retention_policy_ref") == "d12.local_manual_retention.v1"))
        if backend_original:
            if status == "pending_confirmation" and returned.get("receipt") is None:
                problem = returned.get("problem")
                if (isinstance(problem, Mapping)
                        and problem.get("operation_id") == operation_id
                        and problem.get("recovery_action") == "inspect_same_operation"):
                    return ApiResponse(status=status, problem=problem)
                return cls._problem("unavailable", "invalid_provider_response", "未确认操作缺少原操作恢复身份。", False)
            if status in {"unavailable", "unauthorized", "stale"} and returned.get("receipt") is None:
                return ApiResponse(status=status, problem=returned.get("problem") if isinstance(returned.get("problem"), Mapping) else None)
            receipt = returned.get("receipt")
            if (status not in BACKEND_STATES or not isinstance(receipt, Mapping)
                    or receipt.get("schema") != BACKEND_ORIGINAL_SCHEMA
                    or receipt.get("operation_id") != operation_id
                    or receipt.get("state") != status
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", str(receipt.get("original_digest", ""))) is None):
                return cls._problem("unavailable", "invalid_provider_response", "后端没有与当前请求绑定的耐久原件。", False)
            projection = returned.get("projection")
            if projection is not None:
                if (action != "prepare_transfer" or type(projection) is not dict
                        or projection.get("schema") != "d12.transfer_preview.v1"
                        or projection.get("original_ref") != receipt["original_ref"]
                        or type(projection.get("current_epochs")) is not dict
                        or projection["current_epochs"].get("plan_digest") != receipt["plan_digest"]):
                    return cls._problem("unavailable", "invalid_provider_response", "迁移预览原件不符。", False)
            return ApiResponse(status=status, receipt=receipt, projection=projection)
        if status not in {"ready", "partial", "stale", "unavailable", "unauthorized", "pending", "accepted"}:
            return cls._problem("unavailable", "invalid_provider_response", "提供方返回了未知操作状态。", False)
        if status == "accepted":
            receipt = returned.get("receipt")
            if (action != "erase_or_retire" or not isinstance(receipt, Mapping)
                    or receipt.get("operation_id") != operation_id
                    or receipt.get("phase") != "authority_accepted"
                    or receipt.get("schema") != "d12.scoped_erasure_accepted.v1"
                    or receipt.get("source_id") != input_data.get("source_id")
                    or type(receipt.get("deletion_epoch")) is not int
                    or receipt["deletion_epoch"] < 1
                    or any(not (type(receipt.get(name)) is str
                                and re.fullmatch(r"sha256:[0-9a-f]{64}", receipt[name]))
                           for name in ("scope_digest", "graph_barrier_digest"))
                    or receipt.get("cleanup_complete") is not False):
                return cls._problem("unavailable", "invalid_provider_response",
                                    "Authority 未返回当前 accepted 原件；清理状态未证明。", False)
            return ApiResponse(status="accepted", receipt=receipt)
        if status == "pending":
            receipt = returned.get("receipt")
            if (action != "erase_or_retire" or not isinstance(receipt, Mapping)
                    or receipt.get("operation_id") != operation_id
                    or receipt.get("phase") != "authority_pending"
                    or receipt.get("schema") != "d12.scoped_erasure_pending.v2"
                    or receipt.get("source_id") != input_data.get("source_id")
                    or type(receipt.get("deletion_epoch")) is not int
                    or receipt["deletion_epoch"] < 1
                    or type(receipt.get("request_digest")) is not str
                    or not receipt["request_digest"].startswith("sha256:")):
                return cls._problem("unavailable", "invalid_provider_response",
                                    "Authority 未返回与请求绑定的 durable pending 原件。", False)
            return ApiResponse(status="pending", receipt=receipt)
        # Compilation is candidate-only. A provider cannot use this endpoint to
        # claim activation, and service does not synthesize a successful receipt.
        if action in {"compile_scheme", "preview_scheme"} and returned.get("activated"):
            return cls._problem("unavailable", "invalid_provider_response", "编译提供方试图越过采用边界。", False)
        if status in {"partial", "stale", "unavailable", "unauthorized"}:
            return ApiResponse(status=status, problem=returned.get("problem") if isinstance(returned.get("problem"), Mapping) else None)
        receipt = returned.get("receipt")
        if not isinstance(receipt, Mapping) or receipt.get("operation_id") != operation_id:
            return cls._problem("unavailable", "invalid_provider_response", "提供方没有与请求绑定的耐久操作收据。", False)
        if action in {"pause_project_v1", "resume_project_v1"}:
            from ..runtime_contracts import canonical_digest
            if (receipt.get("schema") != "d12.project-control-receipt.v1" or receipt.get("action") != action
                    or receipt.get("input_digest") != canonical_digest(dict(input_data))
                    or type(receipt.get("original")) is not dict
                    or receipt["original"].get("operation_id") != operation_id
                    or receipt.get("original_digest") != canonical_digest(receipt["original"])):
                return cls._problem("unavailable", "invalid_provider_response", "项目控制缺少匹配的真实领域原件。", False)
        if action == _CONFIGURATION_SAVE:
            from .creator_configuration_v1 import valid_creator_save_receipt_v1
            if not valid_creator_save_receipt_v1(receipt, operation_id, input_data):
                return cls._problem("unavailable", "invalid_provider_response", "配置保存缺少当前草稿的真实原件。", False)
        if action in _C04_ACTIONS:
            from ..runtime_contracts import canonical_digest
            if (receipt.get("schema") != "d12.c04-work-receipt.v3" or receipt.get("action") != action
                    or receipt.get("input_digest") != canonical_digest(dict(input_data))
                    or type(receipt.get("original")) is not dict
                    or receipt.get("original_digest") != canonical_digest(receipt["original"])):
                return cls._problem("unavailable", "invalid_provider_response", "回忆工作缺少匹配的真实原件。", False)
        if action in {"d02_fixed_work_policy", "d07_cognition_budget"}:
            from ..runtime_contracts import canonical_digest
            expected_schema = "d12.body-policy-receipt.v1" if action == "d02_fixed_work_policy" else "d12.d07-budget-receipt.v1"
            if (receipt.get("schema") != expected_schema
                    or receipt.get("input_digest") != canonical_digest(dict(input_data))
                    or type(receipt.get("original")) is not dict
                    or receipt["original"].get("operation_id") != operation_id
                    or receipt.get("original_digest") != canonical_digest(receipt["original"])):
                return cls._problem("unavailable", "invalid_provider_response", "身体工作政策缺少匹配的真实原件。", False)
        if action in _DOMAIN_OPERATION_ACTIONS:
            from ..runtime_contracts import canonical_digest
            if owner_material_input_witness is not None:
                from ..runtime.owner_material_source_storage_v3 import require_owner_material_input_witness_v3
                if action != "domain_admit_owner_material_source_v1":
                    raise ValueError("Owner Source input witness cannot bind another domain command")
                input_digest = require_owner_material_input_witness_v3(owner_material_input_witness,
                    request=input_data, operation_id=operation_id)
            else:
                input_digest = canonical_digest(dict(input_data))
            if (receipt.get("schema") != "d12.domain-operation-receipt.v1"
                    or receipt.get("action") != action
                    or receipt.get("input_digest") != input_digest
                    or type(receipt.get("original")) is not dict
                    or receipt["original"].get("operation_id") != operation_id
                    or receipt.get("original_digest") != canonical_digest(receipt["original"])):
                return cls._problem("unavailable", "invalid_provider_response", "领域操作缺少匹配的真实原件。", False)
        if action == _CONTEXT_CATALOGUE_ACTION:
            from ..runtime_contracts import canonical_digest
            original = receipt.get("original")
            if (receipt.get("schema") != "d12.context-catalogue-receipt.v1"
                    or receipt.get("action") != action or receipt.get("input_digest") != canonical_digest(dict(input_data))
                    or type(original) is not dict or original.get("operation_id") != operation_id
                    or original.get("schema") != "d12.owner-context-catalogue-original.v1"
                    or receipt.get("original_digest") != canonical_digest(original)
                    or original.get("compatibility_digest") != canonical_digest(original.get("compatibility"))):
                return cls._problem("unavailable", "invalid_provider_response", "情境目录缺少匹配的真实采用与兼容原件。", False)
        if action in _D04_INITIALIZATION_ACTIONS:
            from ..runtime_contracts import canonical_digest
            if (receipt.get("schema") != "d12.d04_initialization_receipt.v3"
                    or receipt.get("action") != action or receipt.get("phase") != "owner_operation_committed"
                    or receipt.get("input_digest") != canonical_digest(dict(input_data))
                    or type(receipt.get("original")) is not dict
                    or receipt["original"].get("operation_id") != operation_id
                    or receipt.get("original_digest") != canonical_digest(receipt["original"])):
                return cls._problem("unavailable", "invalid_provider_response", "D04 初始化缺少匹配的真实原件。", False)
        if action == "compile_scheme" and (
                receipt.get("phase") != "compiled_candidate_recorded"
                or receipt.get("draft_ref") != input_data["draft_ref"]
                or type(receipt.get("draft_revision")) is not int
                or receipt["draft_revision"] < 1
                or type(receipt.get("graph_revision")) is not int
                or receipt["graph_revision"] < 0
                or any(type(receipt.get(name)) is not str
                       or len(receipt[name]) != 64
                       or any(ch not in "0123456789abcdef" for ch in receipt[name])
                       for name in ("compiled_digest", "source_input_digest",
                                    "budget_receipt_digest"))):
            return cls._problem("unavailable", "invalid_provider_response", "编译缺少耐久原件回执。", False)
        if action == "preview_scheme" and (
                receipt.get("phase") != "isolated_preview_recorded"
                or receipt.get("compiled_digest") != input_data["compiled_digest"]
                or any(type(receipt.get(name)) is not str
                       or len(receipt[name]) != 64
                       or any(ch not in "0123456789abcdef" for ch in receipt[name])
                       for name in ("preview_seal", "isolation_result_digest"))
                or type(receipt.get("actual_cost_receipt_ref")) is not str
                or not receipt["actual_cost_receipt_ref"]):
            return cls._problem("unavailable", "invalid_provider_response", "预览缺少隔离原件回执。", False)
        if action == "run_experiment" and (
                receipt.get("phase") != "isolated_experiment_recorded"
                or receipt.get("experiment") != input_data["experiment"]
                or receipt.get("compiled_digest") != input_data["input_refs"][0]
                or receipt.get("retention_policy_ref") != input_data["retention_policy_ref"]
                or receipt.get("production_revision_unchanged") is not True
                or receipt.get("external_effect_refs") != []
                or receipt.get("formal_contribution_refs") != []
                or receipt.get("production_write_refs") != []
                or any(type(receipt.get(name)) is not str
                       or len(receipt[name]) != 64
                       or any(ch not in "0123456789abcdef" for ch in receipt[name])
                       for name in ("preview_seal", "report_digest", "isolation_result_digest"))
                or type(receipt.get("actual_cost_receipt_ref")) is not str
                or not receipt["actual_cost_receipt_ref"]):
            return cls._problem("unavailable", "invalid_provider_response", "实验缺少隔离报告与费用原件。", False)
        if action == "diagnose_and_export_support" and (
                receipt.get("phase") != "local_support_export_recorded"
                or receipt.get("schema") != "d12.support_view_status.v1"
                or receipt.get("allowed_data") != input_data["allowed_data"]
                or receipt.get("retention_policy_ref") != input_data["retention_policy_ref"]
                or type(receipt.get("local_path")) is not str
                or not receipt["local_path"]
                or type(receipt.get("view_count")) is not int
                or not 0 <= receipt["view_count"] <= 64
                or any(type(receipt.get(name)) is not str
                       or len(receipt[name]) != 64
                       or any(ch not in "0123456789abcdef" for ch in receipt[name])
                       for name in ("manifest_sha256", "payload_sha256"))):
            return cls._problem("unavailable", "invalid_provider_response", "支持包缺少可核验的本地清单。", False)
        if action == "activate_scheme" and (
                receipt.get("phase") != "scheme_adopted"
                or receipt.get("compiled_digest") != input_data["compiled_digest"]
                or type(receipt.get("previous_head_revision")) is not int
                or type(receipt.get("active_head_revision")) is not int
                or receipt["active_head_revision"] <= receipt["previous_head_revision"]
                or type(receipt.get("graph_revision")) is not int
                or receipt["graph_revision"] < 1
                or type(receipt.get("active_head_ref")) is not str
                or not receipt["active_head_ref"]):
            return cls._problem("unavailable", "invalid_provider_response", "采用缺少当前图提交回执。", False)
        if action == "create_character" and (
                receipt.get("phase") != "role_initialized"
                or not isinstance(receipt.get("role_ref"), str)
                or not receipt["role_ref"]
                or type(receipt.get("owner_grant_revision")) is not int
                or receipt["owner_grant_revision"] < 1):
            return cls._problem("unavailable", "invalid_provider_response", "角色初始化缺少权威收据。", False)
        if action == "bind_scene" and (
                receipt.get("phase") != "scene_bound"
                or receipt.get("scene_ref") != input_data["scene_ref"]
                or type(receipt.get("binding_revision")) is not int
                or receipt["binding_revision"] < 1):
            return cls._problem("unavailable", "invalid_provider_response", "场景绑定缺少权威收据。", False)
        if action == "correct_or_edit" and (
                input_data.get("correction_kind") == "source_access_revocation"
                and (receipt.get("phase") != "source_access_revoked"
                     or receipt.get("schema") != "d12.source_access_revocation_receipt.v1"
                     or receipt.get("request_digest") != expected_digest
                     or receipt.get("operation_id") != operation_id
                     or type(receipt.get("graph_revision")) is not int
                     or receipt["graph_revision"] < 1
                     or type(receipt.get("access_epoch")) is not int
                     or receipt["access_epoch"] < 1
                     or type(receipt.get("delete_epoch")) is not int
                     or receipt["delete_epoch"] < 0
                     or receipt.get("source_id") != input_data.get("source_id")
                     or not isinstance(receipt.get("coordinator_operation_id"), str)
                     or not receipt["coordinator_operation_id"])):
            return cls._problem("unavailable", "invalid_provider_response", "来源访问撤销缺少权威提交收据。", False)
        if action == "correct_or_edit" and input_data.get("correction_kind") != "source_access_revocation" and (
                receipt.get("phase") != "source_correction_committed"
                or receipt.get("schema") != "d12.source_correction_receipt.v1"
                or receipt.get("request_digest") != expected_digest
                or receipt.get("source_refs") != input_data["source_refs"]
                or receipt.get("invalidated_target_refs") != input_data["target_refs"]
                or type(receipt.get("graph_revision")) is not int
                or receipt["graph_revision"] < 1
                or receipt.get("access_epoch") != input_data["access_epoch"]
                or receipt.get("deletion_epoch") != input_data["deletion_epoch"]
                or not isinstance(receipt.get("correction_source_ref"), str)
                or not receipt["correction_source_ref"]
                or not isinstance(receipt.get("reevaluation_outbox_ref"), str)
                or not receipt["reevaluation_outbox_ref"]
                or not isinstance(receipt.get("audit_event_ref"), str)
                or not receipt["audit_event_ref"]):
            return cls._problem("unavailable", "invalid_provider_response", "来源纠错缺少权威提交收据。", False)
        return ApiResponse(status="ready", projection=returned.get("projection") if isinstance(returned.get("projection"), Mapping) else None,
                           receipt=receipt)

    @staticmethod
    def _correction_hold() -> ApiResponse:
        return ApiResponse(status="unavailable", problem={
            "schema": SOURCE_CORRECTION_RESPONSE_SCHEMA,
            "code": "source_correction_commit_unavailable",
            "message": "来源纠错提交尚未接入权威协调器；未修改来源或解释。",
            "retryable": False,
        })

    @staticmethod
    def _problem(status: str, code: str, message: str, retryable: bool) -> ApiResponse:
        return ApiResponse(status=status, problem={"code": code, "message": message, "retryable": retryable})


def request_digest(payload: Mapping[str, Any]) -> str:
    """Useful to issuers for receipt binding; never replaces coordinator admission."""
    return sha256(json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
