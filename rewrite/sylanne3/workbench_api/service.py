"""Fail-closed D12 command service.

This module is deliberately transport-neutral.  W09 must bind authenticated
sessions and enforce Origin/CSRF before calling it; this service verifies that
binding was performed and does not accept actor/capability claims from JSON.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any, Mapping, Protocol
from uuid import UUID


D12_SCHEMA = "d12.contract.v1"
_SCOPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_ACTIONS = frozenset({
    "open_workspace", "compile_scheme", "activate_scheme", "read_character_view",
    "correct_or_edit", "run_experiment", "prepare_transfer", "execute_transfer",
    "erase_or_retire", "diagnose_and_export_support", "install_or_upgrade",
    "configure_or_control",
})
_READ_ACTIONS = frozenset({"open_workspace", "read_character_view"})
_MUTATION_CAPABILITIES = {
    "compile_scheme": "workbench.compile", "activate_scheme": "workbench.activate",
    "correct_or_edit": "workbench.correct", "run_experiment": "workbench.experiment",
    "prepare_transfer": "workbench.transfer", "execute_transfer": "workbench.transfer",
    "erase_or_retire": "workbench.erase", "diagnose_and_export_support": "workbench.diagnose",
    "install_or_upgrade": "workbench.maintain", "configure_or_control": "workbench.control",
}
_PROJECTION_STATES = frozenset({"loading", "empty", "unauthorized", "stale", "partial", "unavailable", "ready"})
_INPUT_FIELDS = {
    "open_workspace": frozenset({"client_protocol"}),
    "compile_scheme": frozenset({"draft", "draft_ref", "field_diff", "view_type", "intent", "budget_ref"}),
    "activate_scheme": frozenset({"compiled_scheme_ref", "read_set", "adopt_intent"}),
    "read_character_view": frozenset({"view_type", "cursor", "page_size"}),
    "correct_or_edit": frozenset({"correction_kind", "statement", "source_refs", "impact_preview_ref", "draft_ref"}),
    "run_experiment": frozenset({"experiment", "input_refs", "budget_ref", "retention_policy_ref"}),
    "prepare_transfer": frozenset({"mode", "target", "manifest_ref", "scope_selection"}),
    "execute_transfer": frozenset({"plan_ref", "current_epochs", "target_lease_ref"}),
    "erase_or_retire": frozenset({"mode", "scope_selection", "plan_ref", "data_choice"}),
    "diagnose_and_export_support": frozenset({"question", "allowed_data", "retention_policy_ref", "local_destination"}),
    "install_or_upgrade": frozenset({"release_manifest_ref", "target_capability", "migration_plan_ref"}),
    "configure_or_control": frozenset({"config_diff", "object_ref", "control", "test_intent"}),
}


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
                        purpose: str, audience: str) -> Mapping[str, Any]: ...

    def open_workspace(self, *, session: AuthenticatedSession, scope: str, purpose: str,
                       audience: str) -> Mapping[str, Any]: ...

    def execute(self, *, session: AuthenticatedSession, action: str, scope: str, purpose: str,
                audience: str, operation_id: str, input_data: Mapping[str, Any]) -> Mapping[str, Any]: ...


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
        capability = "workbench.read" if command["action"] in _READ_ACTIONS else _MUTATION_CAPABILITIES[command["action"]]
        # Audience and capability resolve from server-session grants. Browser text only
        # selects a permitted audience; it can never expand one.
        if not session.allows(command["scope"], capability, command["purpose"], command["audience"]):
            return self._problem("unauthorized", "capability_denied", "当前会话没有此范围、用途或受众的能力。", False)
        if self._issuer is None:
            return self._problem("unavailable", "provider_unavailable", "工作台协调器尚未接入；未执行任何领域写入。", True)
        try:
            if command["action"] == "open_workspace":
                returned = self._issuer.open_workspace(session=session, scope=command["scope"],
                                                       purpose=command["purpose"],
                                                       audience=command["audience"])
                return self._projection_response(returned)
            if command["action"] == "read_character_view":
                returned = self._issuer.read_projection(session=session, scope=command["scope"],
                                                         view_type=command["input"]["view_type"],
                                                         purpose=command["purpose"], audience=command["audience"])
                return self._projection_response(returned)
            returned = self._issuer.execute(session=session, action=command["action"], scope=command["scope"],
                                            purpose=command["purpose"], audience=command["audience"],
                                            operation_id=command["operation_id"], input_data=command["input"])
            return self._command_response(command["action"], command["operation_id"], returned)
        except PermissionError:
            return self._problem("unauthorized", "capability_denied", "服务端拒绝了当前能力。", False)
        except LookupError:
            return self._problem("unavailable", "provider_unavailable", "请求的领域提供方不可用。", True)
        except Exception:
            return self._problem("unavailable", "provider_failed", "领域提供方未能完成请求。", True)

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
            raise ValueError("operation_id must be a UUID")
        try:
            UUID(operation_id)
        except ValueError as exc:
            raise ValueError("operation_id must be a UUID") from exc
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
        if action == "read_character_view" and input_data.get("view_type") not in {
                "overview", "creation", "relations", "memory", "cognition", "action", "expression", "diagnostics", "lifecycle"}:
            raise ValueError("read_character_view requires a known view_type")
        if action == "open_workspace" and input_data.get("client_protocol") != D12_SCHEMA:
            raise ValueError("open_workspace requires the current client protocol")
        if "page_size" in input_data and (type(input_data["page_size"]) is not int or not 1 <= input_data["page_size"] <= 100):
            raise ValueError("page_size must be an integer from 1 through 100")
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
    def _command_response(cls, action: str, operation_id: str, returned: Mapping[str, Any]) -> ApiResponse:
        status = returned.get("status")
        if status not in {"ready", "partial", "stale", "unavailable", "unauthorized"}:
            return cls._problem("unavailable", "invalid_provider_response", "提供方返回了未知操作状态。", False)
        # Compilation is candidate-only. A provider cannot use this endpoint to
        # claim activation, and service does not synthesize a successful receipt.
        if action == "compile_scheme" and returned.get("activated"):
            return cls._problem("unavailable", "invalid_provider_response", "编译提供方试图越过采用边界。", False)
        if status in {"partial", "stale", "unavailable", "unauthorized"}:
            return ApiResponse(status=status, problem=returned.get("problem") if isinstance(returned.get("problem"), Mapping) else None)
        receipt = returned.get("receipt")
        if not isinstance(receipt, Mapping) or receipt.get("operation_id") != operation_id:
            return cls._problem("unavailable", "invalid_provider_response", "提供方没有与请求绑定的耐久操作收据。", False)
        return ApiResponse(status="ready", projection=returned.get("projection") if isinstance(returned.get("projection"), Mapping) else None,
                           receipt=receipt)

    @staticmethod
    def _problem(status: str, code: str, message: str, retryable: bool) -> ApiResponse:
        return ApiResponse(status=status, problem={"code": code, "message": message, "retryable": retryable})


def request_digest(payload: Mapping[str, Any]) -> str:
    """Useful to issuers for receipt binding; never replaces coordinator admission."""
    return sha256(json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
