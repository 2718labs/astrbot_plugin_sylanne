"""Dashboard-scoped SDK configuration; saved intent never grants runtime rights."""
from __future__ import annotations

import asyncio
from copy import deepcopy
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import uuid
from urllib.parse import urlsplit

from astrbot.api.star import Context
from astrbot.core.config.astrbot_config import AstrBotConfig
from astrbot.core.provider.entities import ProviderType
from astrbot.core.provider.provider import Provider
from astrbot.dashboard.services.auth_service import DASHBOARD_JWT_COOKIE_NAME

from .authority_client import AuthoritySelection
from .authority_profile import AdminInstallationBundle, AdminModelWorkflowsV2
from .model_selection import observe_host_model_selection_v1
from .model_workflows_v3 import AdminModelWorkflowsV3
from .model_workflows_v4 import AdminModelWorkflowsV4
from .model_workflows_v5 import AdminModelWorkflowsV5
from .model_workflows_v6 import AdminModelWorkflowsV6
from .model_workflows_v7 import AdminModelWorkflowsV7
from .model_workflows_v8 import AdminModelWorkflowsV8
from ..runtime_contracts import canonical_digest


SCHEMA = "sylanne.webui-configuration.v1"
CSRF_HEADER = "X-Sylanne-Configuration-CSRF"
OPTIONAL_SLOTS = ("encode", "context_reply", "natural_generation", "natural_review",
                  "appraisal", "d07_cognition", "contact_generation", "contact_review",
                  "life_content", "life_numeric")
SLOTS = ("reply", *OPTIONAL_SLOTS)
FIELDS = ("enabled", "authority_profile", "llm_provider_id", "model_selection")
MAX_REQUEST_BYTES = 64 * 1024


class ConfigurationProblem(ValueError):
    def __init__(self, code, status, *, retryable=False):
        super().__init__(code)
        self.code, self.status, self.retryable = code, status, retryable

    def json(self):
        return {"schema_version": "sylanne.webui-configuration-error.v1",
                "problem": {"code": self.code, "retryable": self.retryable}}


def default_model_selection_v1():
    return {"version": 1, "auxiliary_provider_id": "",
            "overrides": {slot: "" for slot in OPTIONAL_SLOTS}}


def _provider_id(value):
    if (type(value) is not str or len(value) > 256 or value != value.strip()
            or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value)):
        raise ValueError("provider selection is not a bounded identifier")
    return value


def configuration_values_v1(value):
    if type(value) is not dict or set(value) != set(FIELDS):
        raise ValueError("configuration fields differ")
    if type(value["enabled"]) is not bool:
        raise ValueError("enabled must be boolean")
    AuthoritySelection(value["authority_profile"])
    _provider_id(value["llm_provider_id"])
    selected = value["model_selection"]
    if (type(selected) is not dict or set(selected) != {"version", "auxiliary_provider_id", "overrides"}
            or type(selected["version"]) is not int or selected["version"] != 1):
        raise ValueError("model selection schema differs")
    _provider_id(selected["auxiliary_provider_id"])
    overrides = selected["overrides"]
    if type(overrides) is not dict or set(overrides) != set(OPTIONAL_SLOTS):
        raise ValueError("model override fields differ")
    for value_id in overrides.values():
        _provider_id(value_id)
    return deepcopy(value)


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate configuration field")
        value[key] = item
    return value


def decode_configuration_request_v1(body):
    if len(body) > MAX_REQUEST_BYTES:
        raise ConfigurationProblem("request_too_large", 413)
    try:
        return json.loads(body, object_pairs_hook=_unique_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (ValueError, UnicodeDecodeError):
        raise ConfigurationProblem("invalid_json", 400) from None


class WebuiConfigurationV1:
    def __init__(self, config, context, *, startup_values, installation_bundle=None):
        if type(config) is not AstrBotConfig or not isinstance(context, Context):
            raise TypeError("actual SDK configuration and Context required")
        self._config, self._context = config, context
        self._startup_values = configuration_values_v1(startup_values)
        self._bundle = None
        self.set_installation_bundle(installation_bundle)
        self._lock = asyncio.Lock()
        self._csrf_secret = secrets.token_bytes(32)
        self._revision, self._digest = 1, None
        self._operations = {}
        self._closed = False

    def set_installation_bundle(self, bundle):
        if bundle is not None and type(bundle) is not AdminInstallationBundle:
            raise TypeError("actual installation bundle required")
        self._bundle = bundle

    def close(self):
        self._closed = True
        self._csrf_secret = b""
        self._operations.clear()

    def _session(self, request):
        if self._closed:
            raise ConfigurationProblem("configuration_unavailable", 503)
        username = request.username
        authorization = request.headers.get("authorization", "")
        token = (authorization[7:].strip() if authorization.startswith("Bearer ") else
                 request.cookies.get(DASHBOARD_JWT_COOKIE_NAME, "") or
                 request.headers.get("x-astrbot-desktop-session", ""))
        if type(username) is not str or not username or not token:
            raise ConfigurationProblem("host_session_missing", 401)
        raw = request._request
        origin = f"{raw.url.scheme}://{raw.url.netloc}"
        supplied = request.headers.get("origin")
        site = request.headers.get("sec-fetch-site")
        referer = request.headers.get("referer")
        if request.method == "GET":
            same_origin = supplied == origin if supplied is not None else (
                f"{urlsplit(referer).scheme}://{urlsplit(referer).netloc}" == origin
                if referer else site == "same-origin")
        else:
            same_origin = supplied == origin
        if (raw.url.scheme not in {"http", "https"} or not same_origin
                or site not in {None, "same-origin"}):
            raise ConfigurationProblem("origin_denied", 403)
        return canonical_digest({"username": username,
                                 "session_digest": hashlib.sha256(token.encode()).hexdigest()})

    def _csrf(self, session):
        return hmac.new(self._csrf_secret, session.encode(), hashlib.sha256).hexdigest()

    def _current(self):
        value = {"enabled": self._config.get("enabled", False),
                 "authority_profile": self._config.get("authority_profile", "default"),
                 "llm_provider_id": self._config.get("llm_provider_id", ""),
                 "model_selection": self._config.get("model_selection", default_model_selection_v1())}
        try:
            value = configuration_values_v1(value)
        except (ValueError, TypeError):
            raise ConfigurationProblem("configuration_unavailable", 503) from None
        digest = canonical_digest(value)
        if self._digest is not None and digest != self._digest:
            self._revision += 1
        self._digest = digest
        return value

    def _public_model_slots(self):
        workflows = None if self._bundle is None else self._bundle.model_workflows
        if type(workflows) is AdminModelWorkflowsV8:
            return (*SLOTS, "d07_relationship_cognition", "growth_cognition", "general_growth_cognition")
        if type(workflows) in {AdminModelWorkflowsV6,AdminModelWorkflowsV7}:
            return (*SLOTS, "d07_relationship_cognition", "growth_cognition")
        return (*SLOTS, "d07_relationship_cognition") if type(workflows) is AdminModelWorkflowsV5 else SLOTS

    def _installed_slots(self):
        if self._bundle is None:
            return {}
        workflows = self._bundle.model_workflows
        if type(workflows) in {AdminModelWorkflowsV2, AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8}:
            return {slot: getattr(workflows, slot, None) for slot in self._public_model_slots()}
        return {"reply": self._bundle.ingress_model} if self._bundle.ingress_model is not None else {}

    def _model_rows(self, values, installed):
        rows = []
        selection = values["model_selection"]
        for slot in self._public_model_slots():
            current = installed.get(slot)
            provider_id = values["llm_provider_id"] if slot == "reply" else (
                ("" if slot in {"d07_relationship_cognition", "growth_cognition", "general_growth_cognition"} else selection["overrides"][slot]) or selection["auxiliary_provider_id"] or
                (current.provider_id if current is not None else ""))
            observed = observe_host_model_selection_v1(
                context=self._context, authority_profile=values["authority_profile"],
                provider_id=provider_id, installation_bundle=None)
            bound = None if current is None else {
                "provider_id": current.provider_id, "model_id": current.model_id,
                "provider_config_digest": current.provider_config_digest,
                "max_output_tokens": current.max_output_tokens}
            state, reason = "pending", observed.reason_code
            if observed.plan is not None:
                state, reason = "selected", "model_awaiting_installation"
                if bound is not None:
                    if values["authority_profile"] != self._bundle.tls_profile.profile_id:
                        state, reason = "pending", "model_profile_mismatch"
                    elif observed.plan.provider_id != bound["provider_id"]:
                        state, reason = "pending", "model_provider_mismatch"
                    elif observed.plan.model_id != bound["model_id"]:
                        state, reason = "pending", "model_id_mismatch"
                    elif observed.plan.provider_config_digest != bound["provider_config_digest"]:
                        state, reason = "pending", "model_config_mismatch"
                    else:
                        state, reason = "installed", "none"
            rows.append({"slot": slot, "selected_provider_id": observed.provider_id,
                         "model_id": observed.model_id,
                         "provider_config_digest": None if observed.plan is None else observed.plan.provider_config_digest,
                         "installed": bound, "state": state, "reason_code": reason})
        return rows

    def _policy(self, installed):
        options = []
        for provider in self._context.get_all_providers():
            if not isinstance(provider, Provider):
                continue
            meta = provider.meta()
            if (meta.provider_type is ProviderType.CHAT_COMPLETION
                    and provider.provider_config.get("enable", True) is not False):
                model = provider.get_model()
                if (type(meta.id) is str and 1 <= len(meta.id) <= 256
                        and type(model) is str and 1 <= len(model) <= 256):
                    options.append({"provider_id": meta.id, "model_id": model})
        workflows = None if self._bundle is None else self._bundle.model_workflows
        return {"profile_id": None if self._bundle is None else self._bundle.tls_profile.profile_id,
                "installation_id": None if self._bundle is None else self._bundle.installation_policy.installation_id,
                "workflow_version": None if workflows is None else workflows.version,
                "configured_model_slots": [slot for slot in self._public_model_slots() if installed.get(slot) is not None],
                "limits": {slot: installed[slot].max_output_tokens for slot in self._public_model_slots() if installed.get(slot) is not None},
                "provider_options": options}

    def _response(self, session, values):
        installed = self._installed_slots()
        return {"schema_version": SCHEMA, "revision": self._revision,
                "csrf_token": self._csrf(session), "values": values,
                "startup_values": deepcopy(self._startup_values), "writable_fields": list(FIELDS),
                "model_slots": self._model_rows(values, installed),
                "installed_policy": self._policy(installed), "apply_semantics": "next_reload"}

    async def read(self, request):
        session = self._session(request)
        async with self._lock:
            return self._response(session, self._current())

    async def write(self, request, payload):
        session = self._session(request)
        token = request.headers.get(CSRF_HEADER, "")
        if not hmac.compare_digest(token, self._csrf(session)):
            raise ConfigurationProblem("csrf_invalid", 403)
        try:
            if (type(payload) is not dict or set(payload) != {"schema_version", "operation_id", "expected_revision", "patch"}
                    or payload["schema_version"] != SCHEMA):
                raise ValueError("configuration command fields differ")
            operation = uuid.UUID(payload["operation_id"])
            if operation.version != 4 or str(operation) != payload["operation_id"]:
                raise ValueError("UUID4 operation required")
            if type(payload["expected_revision"]) is not int or payload["expected_revision"] < 1:
                raise ValueError("positive configuration revision required")
            patch = payload["patch"]
            if type(patch) is not dict or not patch or not set(patch) <= set(FIELDS):
                raise ValueError("configuration patch fields differ")
        except (ValueError, TypeError, AttributeError):
            raise ConfigurationProblem("validation_failed", 400) from None
        async with self._lock:
            current = self._current()
            proposed = dict(current)
            proposed.update(patch)
            try:
                proposed = configuration_values_v1(proposed)
            except (ValueError, TypeError):
                raise ConfigurationProblem("validation_failed", 400) from None
            digest = canonical_digest(payload)
            key = (session, payload["operation_id"])
            previous = self._operations.get(key)
            if previous is not None:
                if previous[0] != digest:
                    raise ConfigurationProblem("idempotency_conflict", 409)
                if previous[1] is None:
                    raise ConfigurationProblem("unknown_outcome", 503)
                return deepcopy(previous[1])
            if payload["expected_revision"] != self._revision:
                raise ConfigurationProblem("configuration_changed", 409)
            self._operations[key] = (digest, None)
            try:
                self._config.save_config(proposed)
                persisted = json.loads(Path(self._config.config_path).read_text(encoding="utf-8-sig"))
                if {field: persisted[field] for field in FIELDS} != proposed:
                    raise ValueError("configuration readback differs")
                saved = self._current()
                if saved != proposed:
                    raise ValueError("current configuration differs after save")
            except (OSError, ValueError, KeyError, TypeError):
                raise ConfigurationProblem("unknown_outcome", 503) from None
            result = self._response(session, saved)
            self._operations[key] = (digest, deepcopy(result))
            return result
