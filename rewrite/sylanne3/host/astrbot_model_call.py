"""Local one-attempt AstrBot call mechanics for a future Authority executor.

The UMO is supplied by trusted host composition. This adapter rechecks its
current chat-provider selection before each call. The existing Broker invoke
port has no admission proof and therefore never sends. A lost outcome remains
unknown; this process-local registry is not durable Authority observation.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import Future
from dataclasses import dataclass, field
import json
import re
import secrets
from threading import Lock

from astrbot.api.star import Context
from astrbot.core.provider.entities import ProviderMeta, ProviderType
from astrbot.core.provider.sources.openai_source import ProviderOpenAIOfficial
from openai import AsyncAzureOpenAI, AsyncOpenAI
from openai.types.chat.chat_completion import ChatCompletion

from ..runtime_contracts import canonical_digest, canonical_serialize
from ..model_broker.broker import (
    ModelCallRequest, ModelProviderDescriptor, ProviderResponse,
)
from ..model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST,
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
)
from ..model_broker.reply_language import (
    REPLY_TEMPLATE_VERSION, reply_request_shape_valid,
)
from ..model_broker.context_reply import (
    CONTEXT_REPLY_TEMPLATE_DIGEST, CONTEXT_REPLY_TEMPLATE_VERSION,
    INPUT_SCHEMA as CONTEXT_REPLY_INPUT_SCHEMA, SYSTEM_MESSAGE as CONTEXT_REPLY_SYSTEM_MESSAGE,
)
from ..model_broker.d13_precompression import (
    D13PrecompressionCallGateV1, D13PrecompressionInstallationV1,
    FrozenD13PrecompressionRequestV1,
    INPUT_SCHEMA as D13_INPUT_SCHEMA,
    SYSTEM_MESSAGE as D13_SYSTEM_MESSAGE,
    TEMPLATE_DIGEST as D13_TEMPLATE_DIGEST,
    freeze_d13_precompression_request_v1, gate_d13_exact_token_count_v1,
)
from ..model_broker.natural_reply import (
    INPUT_SCHEMA as NATURAL_INPUT_SCHEMA,
    SYSTEM_MESSAGE as NATURAL_SYSTEM_MESSAGE,
    TEMPLATE_DIGEST as NATURAL_TEMPLATE_DIGEST,
    TEMPLATE_VERSION as NATURAL_TEMPLATE_VERSION,
)
from ..model_broker.natural_review import (
    INPUT_SCHEMA as REVIEW_INPUT_SCHEMA,
    SYSTEM_MESSAGE as REVIEW_SYSTEM_MESSAGE,
    REVIEW_TEMPLATE_DIGEST, REVIEW_TEMPLATE_VERSION,
)
from ..model_broker.natural_reply_history_v4 import (
    INPUT_SCHEMA as NATURAL_INPUT_SCHEMA_V4, SYSTEM_MESSAGE as NATURAL_SYSTEM_MESSAGE_V4,
    TEMPLATE_DIGEST as NATURAL_TEMPLATE_DIGEST_V4, TEMPLATE_VERSION as NATURAL_TEMPLATE_VERSION_V4,
)
from ..model_broker.natural_reply_history_v3 import (
    INPUT_SCHEMA as NATURAL_INPUT_SCHEMA_V3,
    SYSTEM_MESSAGE as NATURAL_SYSTEM_MESSAGE_V3,
    TEMPLATE_DIGEST as NATURAL_TEMPLATE_DIGEST_V3,
    TEMPLATE_VERSION as NATURAL_TEMPLATE_VERSION_V3,
)
from ..model_broker.d04_appraisal import (
    INPUT_SCHEMA as APPRAISAL_INPUT_SCHEMA,
    MAX_INPUT_BYTES as APPRAISAL_MAX_INPUT_BYTES,
    SYSTEM_MESSAGE as APPRAISAL_SYSTEM_MESSAGE,
    TEMPLATE_DIGEST as APPRAISAL_TEMPLATE_DIGEST,
    TEMPLATE_VERSION as APPRAISAL_TEMPLATE_VERSION,
)
from ..model_broker.d07_cognition_v1 import (
    d07_cognition_messages_v1, TEMPLATE_VERSION as D07_COGNITION_TEMPLATE_VERSION,
    TEMPLATE_DIGEST as D07_COGNITION_TEMPLATE_DIGEST,
)
from ..native_runtime.d04_engineering_scheme import MECHANISMS
from .authority_profile import (
    AdminIngressEncodingPolicy, AdminIngressModelPolicy, AdminModelWorkflowV2,
    AdminInstallationBundle, installed_model_config_ref,
)
from ..installation_policy import AdminInstallationPolicy


@dataclass
class _CallEntry:
    digest: str
    admission_id: str
    host_incarnation: str
    provider_config_digest: str
    binding: tuple[object, ...]
    terminal: Future[ProviderResponse] = field(default_factory=Future)
    task: asyncio.Task[ProviderResponse] | None = None


# Process-local dispatch memory. An unresolved entry is intentionally retained:
# a stopped host loop provides no evidence that its provider call did not run.
_call_lock = Lock()
_calls: dict[str, _CallEntry] = {}
_admissions: dict[str, str] = {}
_HOST_INCARNATION = secrets.token_hex(32)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _context_reply_messages(request: ModelCallRequest) -> list[dict[str, str]] | None:
    """Accept only the sealed three-message V2 workflow wire shape."""
    payload = request.payload
    if (set(payload) != {"model", "messages", "max_output_tokens"}
            or payload["model"] != request.model_id
            or payload["max_output_tokens"] != request.max_output_tokens
            or type(payload["messages"]) is not list
            or len(payload["messages"]) != 3):
        return None
    messages = payload["messages"]
    if (any(type(item) is not dict or set(item) != {"role", "content"}
            or type(item["content"]) is not str for item in messages)
            or [item["role"] for item in messages] != ["system", "user", "user"]
            or messages[0]["content"] != CONTEXT_REPLY_SYSTEM_MESSAGE):
        return None
    try:
        stable = json.loads(messages[1]["content"])
        dynamic = json.loads(messages[2]["content"])
    except (TypeError, ValueError):
        return None
    if (type(stable) is not dict or type(dynamic) is not dict
            or set(stable) != {"schema", "scope", "stable_history"}
            or set(dynamic) != {"schema", "scope", "sections"}
            or stable["schema"] != CONTEXT_REPLY_INPUT_SCHEMA
            or dynamic["schema"] != CONTEXT_REPLY_INPUT_SCHEMA
            or type(stable["scope"]) is not dict
            or type(dynamic["scope"]) is not dict
            or type(stable["stable_history"]) is not list
            or type(dynamic["sections"]) is not list
            or len(dynamic["sections"]) != 6
            or any(type(section) is not dict
                   or set(section) != {"kind", "parts"}
                   or type(section["parts"]) is not list
                   for section in dynamic["sections"])
            or [section["kind"] for section in dynamic["sections"]] != [
                    "question", "d06_evidence", "d07_focus", "required_check",
                    "d09_state", "d13_history"]):
        return None
    return [{"role": item["role"], "content": item["content"]}
            for item in messages]


def _natural_messages(
    request: ModelCallRequest, stage: str,
) -> list[dict[str, str]] | None:
    """Validate the internal provider-bound wire, then strip its selector."""
    payload = request.payload
    if (set(payload) != {"provider_id", "model", "messages", "max_output_tokens"}
            or payload["provider_id"] != request.provider_id
            or payload["model"] != request.model_id
            or payload["max_output_tokens"] != request.max_output_tokens
            or type(payload["messages"]) is not list
            or len(payload["messages"]) != (3 if stage == "generation" else 2)):
        return None
    messages = payload["messages"]
    if (any(type(item) is not dict or set(item) != {"role", "content"}
            or type(item["content"]) is not str for item in messages)
            or [item["role"] for item in messages] !=
               (["system", "user", "user"] if stage == "generation" else
                ["system", "user"])):
        return None
    v3 = stage == "generation" and request.prompt_template_digest == NATURAL_TEMPLATE_DIGEST_V3
    v4 = stage == "generation" and request.prompt_template_digest == NATURAL_TEMPLATE_DIGEST_V4
    natural_schema = NATURAL_INPUT_SCHEMA_V4 if v4 else NATURAL_INPUT_SCHEMA_V3 if v3 else NATURAL_INPUT_SCHEMA
    if messages[0]["content"] != (
            (NATURAL_SYSTEM_MESSAGE_V4 if v4 else NATURAL_SYSTEM_MESSAGE_V3 if v3 else NATURAL_SYSTEM_MESSAGE) if stage == "generation" else
            REVIEW_SYSTEM_MESSAGE):
        return None
    try:
        user = [json.loads(item["content"]) for item in messages[1:]]
    except (TypeError, ValueError):
        return None
    if (any(type(item) is not dict
            or canonical_serialize(item) != messages[index + 1]["content"]
            for index, item in enumerate(user))):
        return None
    if stage == "generation":
        stable, dynamic = user
        if (set(stable) != {"schema", "scope", "stable_history"}
                or stable["schema"] != natural_schema
                or type(stable["scope"]) is not dict
                or type(stable["stable_history"]) is not list
                or set(dynamic) != ({
                    "schema", "frozen_at_utc", "expires_at_utc", "question",
                    "expression_plan", "qualified_units"} |
                    ({"scope", "recent_history", "history_selection"} if v3 or v4 else set()) |
                    ({"detail_history"} if v4 else set()))
                or dynamic["schema"] != natural_schema
                or type(dynamic["question"]) is not dict
                or type(dynamic["expression_plan"]) is not dict
                or type(dynamic["qualified_units"]) is not list):
            return None
        if (v3 or v4) and (dynamic["scope"] != stable["scope"]
                or type(dynamic["recent_history"]) is not list
                or type(dynamic["history_selection"]) is not dict
                or v4 and type(dynamic["detail_history"]) is not list):
            return None
    else:
        review = user[0]
        if (set(review) != {
                "schema", "template_version", "generation_frozen_input_digest",
                "generation_output_digest", "qualified_units_digest",
                "review_policy_version", "body", "units", "qualified_basis"}
                or review["schema"] != REVIEW_INPUT_SCHEMA
                or review["template_version"] != REVIEW_TEMPLATE_VERSION
                or type(review["body"]) is not str
                or type(review["units"]) is not list
                or type(review["qualified_basis"]) is not list):
            return None
    return [{"role": item["role"], "content": item["content"]}
            for item in messages]


def _appraisal_messages(request: ModelCallRequest) -> list[dict[str, str]] | None:
    """Accept only the frozen D04 two-message wire, stripping its selector."""
    payload = request.payload
    if (set(payload) != {"provider_id", "model", "messages", "max_output_tokens"}
            or payload["provider_id"] != request.provider_id
            or payload["model"] != request.model_id
            or payload["max_output_tokens"] != request.max_output_tokens
            or type(payload["messages"]) is not list
            or len(payload["messages"]) != 2):
        return None
    messages = payload["messages"]
    if (any(type(item) is not dict or set(item) != {"role", "content"}
            or type(item["content"]) is not str for item in messages)
            or [item["role"] for item in messages] != ["system", "user"]
            or messages[0]["content"] != APPRAISAL_SYSTEM_MESSAGE
            or len(messages[1]["content"].encode("utf-8")) > APPRAISAL_MAX_INPUT_BYTES):
        return None
    try:
        data = json.loads(messages[1]["content"])
    except (TypeError, ValueError):
        return None
    if (type(data) is not dict
            or canonical_serialize(data) != messages[1]["content"]
            or set(data) != {
                "schema", "namespace", "sources", "source_qualification",
                "event_ref", "event", "role_ref", "role", "interpretations",
                "target_ref", "concern_ref", "registered_mechanisms"}
            or data["schema"] != APPRAISAL_INPUT_SCHEMA
            or data["registered_mechanisms"] != list(MECHANISMS)
            or type(data["sources"]) is not list
            or not 1 <= len(data["sources"]) <= 4
            or type(data["interpretations"]) is not list
            or not 1 <= len(data["interpretations"]) <= 4):
        return None
    return [{"role": item["role"], "content": item["content"]}
            for item in messages]


@dataclass(frozen=True, slots=True)
class LocalModelAdmission:
    """Executor-supplied local start identity; not an Authority credential."""

    admission_id: str
    host_incarnation: str
    call_id: str
    request_digest: str
    provider_config_digest: str

    def __post_init__(self) -> None:
        if (not all(type(value) is str and value for value in (
                self.admission_id, self.host_incarnation, self.call_id,
                self.request_digest, self.provider_config_digest))
                or _SHA256.fullmatch(self.admission_id) is None
                or _SHA256.fullmatch(self.host_incarnation) is None
                or _SHA256.fullmatch(self.request_digest) is None
                or _SHA256.fullmatch(self.provider_config_digest) is None):
            raise ValueError("invalid local model admission identity")


class AstrBotModelProvider:
    """Bound to one trusted UMO and one exact configured provider/model."""

    def __init__(
        self, *, context: Context, host_loop: asyncio.AbstractEventLoop,
        trusted_umo: str, descriptor: ModelProviderDescriptor,
        admin_model: AdminIngressModelPolicy | AdminModelWorkflowV2,
        installation_bundle: AdminInstallationBundle,
    ) -> None:
        if (not isinstance(context, Context)
                or not isinstance(host_loop, asyncio.AbstractEventLoop)
                or type(trusted_umo) is not str or not trusted_umo
                or type(descriptor) is not ModelProviderDescriptor
                or descriptor.is_test_double or descriptor.timeout_cancellable
                or descriptor.supports_idempotency
                or descriptor.cost_reporting != "unknown"):
            raise ValueError("trusted non-retrying AstrBot model binding is required")
        if (type(admin_model) not in (AdminIngressModelPolicy, AdminModelWorkflowV2)
                or admin_model.provider_id != descriptor.provider_id
                or admin_model.model_id != descriptor.model_id
                or admin_model.provider_config_ref != installed_model_config_ref(
                    descriptor.provider_id, descriptor.model_id,
                    admin_model.provider_config_digest)
                or type(installation_bundle) is not AdminInstallationBundle):
            raise ValueError("exact administrator model configuration is required")
        workflows = installation_bundle.model_workflows
        if type(admin_model) is AdminIngressModelPolicy:
            installed = admin_model is installation_bundle.ingress_model
        else:
            installed = (workflows is not None and
                         (admin_model is workflows.encode
                          or admin_model is workflows.reply
                          or admin_model is workflows.context_reply
                          or admin_model is workflows.natural_generation
                          or admin_model is workflows.natural_review
                          or admin_model is workflows.contact_generation
                          or admin_model is workflows.contact_review
                          or admin_model is workflows.appraisal
                          or admin_model is workflows.d07_cognition))
        if not installed:
            raise ValueError("model selection is absent from installed administrator snapshot")
        self._context = context
        self._host_loop = host_loop
        self._trusted_umo = trusted_umo
        self._descriptor = descriptor
        self._admin_model = admin_model
        self._installation_bundle = installation_bundle
        self._aborted = False
        self._started_calls: set[str] = set()
        self._binding = (context, host_loop, trusted_umo,
                         descriptor.provider_id, descriptor.model_id,
                         admin_model.provider_config_ref,
                         (admin_model.work_kind, admin_model.template_version)
                         if type(admin_model) is AdminModelWorkflowV2 else "legacy")

    @property
    def host_incarnation(self) -> str:
        return _HOST_INCARNATION

    def _same_binding(self, entry: _CallEntry) -> bool:
        return (entry.binding[0] is self._context
                and entry.binding[1] is self._host_loop
                and entry.binding[2:] == self._binding[2:])

    @property
    def descriptor(self) -> ModelProviderDescriptor:
        return self._descriptor

    def _contact_messages(self, request: ModelCallRequest):
        from ..model_broker.contact_expression_v1 import contact_provider_messages_v1
        from ..model_broker.natural_reply import NaturalReplyInstallationV2
        model = self._admin_model
        installation = NaturalReplyInstallationV2(self._installation_bundle.installation_policy.installation_id,
            model.provider_config_digest, model.provider_id, model.model_id, model.max_output_tokens)
        try:
            return contact_provider_messages_v1(request, installation)
        except (ValueError, TypeError, KeyError):
            return None

    def _request_allowed(self, request: ModelCallRequest) -> bool:
        """Recheck the installed scope and exact request before host dispatch."""
        model = self._admin_model
        bundle = self._installation_bundle
        policy = bundle.installation_policy
        encoding = bundle.ingress_encoding
        authority = request.envelope.authority
        descriptor = self._descriptor
        if type(model) is AdminModelWorkflowV2:
            workflows = bundle.model_workflows
            if (workflows is None
                    or (model is not workflows.encode
                        and model is not workflows.reply
                        and model is not workflows.context_reply
                        and model is not workflows.natural_generation
                        and model is not workflows.natural_review
                        and model is not workflows.contact_generation
                        and model is not workflows.contact_review
                        and model is not workflows.appraisal
                        and model is not workflows.d07_cognition)
                    or type(policy) is not AdminInstallationPolicy
                    or policy.namespace != authority.namespace
                    or model.work_kind not in policy.root_grant.allowed_work_kinds
                    or request.provider_id != model.provider_id
                    or request.model_id != model.model_id
                    or descriptor.capabilities != frozenset({"text"})
                    or not request.required_capabilities
                    or not request.required_capabilities <= descriptor.capabilities
                    or not request.required_capabilities <= set(model.required_capabilities)
                    or descriptor.purposes != frozenset({model.purpose})
                    or authority.purpose != model.purpose
                    or not authority.audience
                    or not set(authority.audience) <= set(model.audiences)
                    or descriptor.privacy_tiers != frozenset({model.privacy_tier})
                    or request.privacy_tier != model.privacy_tier
                    or request.timeout_seconds > model.timeout_seconds
                    or request.max_output_tokens > model.max_output_tokens):
                return False
            for dimension, amount in model.quote_ceiling.items():
                if (amount > policy.root_lease.limits.get(dimension, 0)
                        or amount > policy.root_grant.max_ceiling.get(dimension, 0)):
                    return False
            if model is workflows.encode:
                return (type(encoding) is AdminIngressEncodingPolicy
                        and all(amount <= encoding.quote_ceiling.get(dimension, 0)
                                for dimension, amount in model.quote_ceiling.items())
                        and model.template_version
                        == FIRST_INGRESS_ENCODING_TEMPLATE_VERSION
                        and request.prompt_template_digest
                        == FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST)
            if model is workflows.reply:
                if request.identity.phase == "d13.precompress":
                    payload = request.payload
                    if (model.template_version != REPLY_TEMPLATE_VERSION
                            or authority.issuer_domain != "d13"
                            or type(authority.worker_fence) is not int
                            or authority.worker_fence < 1
                            or request.prompt_template_digest != D13_TEMPLATE_DIGEST
                            or set(payload) != {"system_prompt", "prompt"}
                            or payload["system_prompt"] != D13_SYSTEM_MESSAGE
                            or type(payload["prompt"]) is not str):
                        return False
                    try:
                        frozen_input = json.loads(payload["prompt"])
                    except (ValueError, TypeError):
                        return False
                    return (type(frozen_input) is dict
                            and frozen_input.get("schema") == D13_INPUT_SCHEMA
                            and canonical_serialize(frozen_input) == payload["prompt"]
                            and type(frozen_input.get("scope")) is dict
                            and frozen_input.get("scope", {}).get("namespace") == {
                                "bot_id": authority.namespace.bot_id,
                                "persona_id": authority.namespace.persona_id,
                            })
                return (model.template_version == REPLY_TEMPLATE_VERSION
                        and reply_request_shape_valid(request))
            if model is workflows.natural_generation:
                return (request.identity.phase == "natural_generation"
                        and type(authority.worker_fence) is int
                        and authority.worker_fence >= 1
                        and (model.template_version, request.prompt_template_digest) in (
                            (NATURAL_TEMPLATE_VERSION, NATURAL_TEMPLATE_DIGEST),
                            (NATURAL_TEMPLATE_VERSION_V3, NATURAL_TEMPLATE_DIGEST_V3),
                            (NATURAL_TEMPLATE_VERSION_V4, NATURAL_TEMPLATE_DIGEST_V4))
                        and _natural_messages(request, "generation") is not None)
            if model is workflows.natural_review:
                return (request.identity.phase == "natural_review"
                        and type(authority.worker_fence) is int
                        and authority.worker_fence >= 1
                        and model.template_version == REVIEW_TEMPLATE_VERSION
                        and request.prompt_template_digest == REVIEW_TEMPLATE_DIGEST
                        and _natural_messages(request, "review") is not None)
            if model is workflows.contact_generation or model is workflows.contact_review:
                from ..model_broker.contact_expression_v1 import (
                    GENERATION_TEMPLATE_VERSION, GENERATION_TEMPLATE_DIGEST,
                    REVIEW_TEMPLATE_VERSION as CONTACT_REVIEW_VERSION,
                    REVIEW_TEMPLATE_DIGEST as CONTACT_REVIEW_DIGEST)
                generation = model is workflows.contact_generation
                return (request.identity.phase == ("contact_generation" if generation else "contact_review")
                        and type(authority.worker_fence) is int and authority.worker_fence >= 1
                        and model.template_version == (GENERATION_TEMPLATE_VERSION if generation else CONTACT_REVIEW_VERSION)
                        and request.prompt_template_digest == (GENERATION_TEMPLATE_DIGEST if generation else CONTACT_REVIEW_DIGEST)
                        and self._contact_messages(request) is not None)
            if model is workflows.appraisal:
                return (request.identity.phase == "d04.appraisal"
                        and type(authority.worker_fence) is int
                        and authority.worker_fence >= 1
                        and model.template_version == APPRAISAL_TEMPLATE_VERSION
                        and request.prompt_template_digest == APPRAISAL_TEMPLATE_DIGEST
                        and _appraisal_messages(request) is not None)
            if model is workflows.d07_cognition:
                return (request.identity.phase == "d07.cognition"
                        and type(authority.worker_fence) is int and authority.worker_fence >= 1
                        and model.template_version == D07_COGNITION_TEMPLATE_VERSION
                        and request.prompt_template_digest == D07_COGNITION_TEMPLATE_DIGEST
                        and d07_cognition_messages_v1(request) is not None)
            return (model is workflows.context_reply
                    and request.identity.phase == "context_reply"
                    and type(authority.worker_fence) is int
                    and authority.worker_fence >= 1
                    and model.template_version == CONTEXT_REPLY_TEMPLATE_VERSION
                    and request.prompt_template_digest == CONTEXT_REPLY_TEMPLATE_DIGEST
                    and _context_reply_messages(request) is not None)
        if (model is not bundle.ingress_model
                or type(policy) is not AdminInstallationPolicy
                or type(encoding) is not AdminIngressEncodingPolicy
                or policy.namespace != authority.namespace
                or descriptor.capabilities != frozenset({"text"})
                or not set(model.required_capabilities) <= {"text"}
                or not request.required_capabilities
                or not request.required_capabilities <= descriptor.capabilities
                or not request.required_capabilities <= set(model.required_capabilities)
                or not descriptor.purposes <= set(model.allowed_purposes)
                or authority.purpose not in descriptor.purposes
                or authority.purpose not in model.allowed_purposes
                or not authority.audience
                or not set(authority.audience) <= set(model.allowed_audiences)
                or not descriptor.privacy_tiers <= set(model.allowed_privacy_tiers)
                or request.privacy_tier != model.privacy_tier
                or request.privacy_tier not in descriptor.privacy_tiers
                or request.privacy_tier not in model.allowed_privacy_tiers
                or "reply" not in policy.root_grant.allowed_work_kinds):
            return False
        output = model.max_output_tokens
        return (encoding.quote_ceiling.get("output_tokens", 0) >= output
                and policy.root_lease.limits.get("output_tokens", 0) >= output
                and policy.root_grant.max_ceiling.get("output_tokens", 0) >= output
                and request.max_output_tokens <= output)

    def _matches_live_provider(self, provider: object) -> bool:
        if type(provider) is not ProviderOpenAIOfficial:
            return False
        installed = self._context.get_all_providers()
        meta = provider.meta()
        if (type(installed) is not list
                or sum(item is provider for item in installed) != 1
                or not isinstance(meta, ProviderMeta)
                or meta.provider_type is not ProviderType.CHAT_COMPLETION
                or meta.id != self._descriptor.provider_id
                or meta.model != self._descriptor.model_id
                or provider.get_model() != meta.model
                or self._context.get_provider_by_id(meta.id) is not provider
                or type(provider.provider_config) is not dict
                or "api_version" in provider.provider_config
                or not isinstance(provider.client, AsyncOpenAI)
                or isinstance(provider.client, AsyncAzureOpenAI)):
            return False
        digest = canonical_digest(provider.provider_config)
        return (digest == self._admin_model.provider_config_digest
                and installed_model_config_ref(meta.id, meta.model, digest)
                == self._admin_model.provider_config_ref)

    async def _selected_provider(self):
        """Read AstrBot's current UMO selection on its owning host loop."""
        async_selector = getattr(self._context, "get_using_provider_async", None)
        if callable(async_selector):
            return await async_selector(self._trusted_umo)
        selector = getattr(self._context, "get_using_provider", None)
        if callable(selector):
            return selector(self._trusted_umo)
        raise RuntimeError("AstrBot chat provider selection is unavailable")

    async def selected_d13_main_installation_v1(
        self,
    ) -> D13PrecompressionInstallationV1 | None:
        """Observe the selected UMO's installed main model on the host loop.

        A later D13 dispatch must recheck selection against this frozen main
        workflow. This read does not grant a paid egress or budget reservation.
        """
        workflows = self._installation_bundle.model_workflows
        if (asyncio.get_running_loop() is not self._host_loop
                or self._aborted or workflows is None
                or self._admin_model is not workflows.reply):
            return None
        try:
            provider = await self._selected_provider()
            if not self._matches_live_provider(provider):
                return None
        except Exception:
            return None
        model = workflows.reply
        return D13PrecompressionInstallationV1(
            self._installation_bundle.installation_policy.installation_id,
            model.provider_id, model.model_id,
            model.provider_config_digest, model.max_output_tokens)

    async def preflight_d13_precompression_v1(
        self, frozen: FrozenD13PrecompressionRequestV1,
    ) -> D13PrecompressionCallGateV1:
        """Check the frozen wire against the live main model before any paid job.

        Exact pre-call counting is optional. The signed D11 quote and reserved
        ceiling must be authenticated separately before paid dispatch.
        """
        if type(frozen) is not FrozenD13PrecompressionRequestV1:
            raise TypeError("frozen D13 request required")
        try:
            expected = freeze_d13_precompression_request_v1(
                frozen.window, frozen.plan, frozen.installation)
            selected = await self.selected_d13_main_installation_v1()
        except (TypeError, ValueError):
            selected = None
            expected = None
        if expected != frozen or selected != frozen.installation:
            return D13PrecompressionCallGateV1(
                "hold", frozen.digest, frozen.wire_digest, None,
                "frozen D13 wire differs from the selected conversation model")
        return gate_d13_exact_token_count_v1(frozen, None)

    async def _invoke_on_host(self, request: ModelCallRequest) -> ProviderResponse:
        try:
            provider = await self._selected_provider()
            if not self._matches_live_provider(provider):
                return ProviderResponse("not_dispatched", None, {}, {}, None)
        except asyncio.CancelledError:
            return ProviderResponse("not_dispatched", None, {}, {}, None)
        except Exception:
            return ProviderResponse("not_dispatched", None, {}, {}, None)
        payload = request.payload
        if (type(self._admin_model) is AdminModelWorkflowV2
                and self._admin_model is self._installation_bundle.model_workflows.context_reply):
            messages = _context_reply_messages(request)
        elif (type(self._admin_model) is AdminModelWorkflowV2
              and self._admin_model is self._installation_bundle.model_workflows.natural_generation):
            messages = _natural_messages(request, "generation")
        elif (type(self._admin_model) is AdminModelWorkflowV2
              and self._admin_model is self._installation_bundle.model_workflows.natural_review):
            messages = _natural_messages(request, "review")
        elif (type(self._admin_model) is AdminModelWorkflowV2
              and (self._admin_model is self._installation_bundle.model_workflows.contact_generation
                   or self._admin_model is self._installation_bundle.model_workflows.contact_review)):
            messages = self._contact_messages(request)
        elif (type(self._admin_model) is AdminModelWorkflowV2
              and self._admin_model is self._installation_bundle.model_workflows.appraisal):
            messages = _appraisal_messages(request)
        elif (type(self._admin_model) is AdminModelWorkflowV2
              and self._admin_model is self._installation_bundle.model_workflows.d07_cognition):
            messages = d07_cognition_messages_v1(request)
        elif (set(payload) in ({"prompt"}, {"prompt", "system_prompt"})
              and type(payload.get("prompt")) is str and payload["prompt"]
              and ("system_prompt" not in payload
                   or type(payload["system_prompt"]) is str)):
            messages = []
            if payload.get("system_prompt"):
                messages.append({"role": "system", "content": payload["system_prompt"]})
            messages.append({"role": "user", "content": payload["prompt"]})
        else:
            messages = None
        if messages is None:
            return ProviderResponse("not_dispatched", None, {}, {}, None)
        try:
            selected_client = provider.client
            client = selected_client.with_options(
                max_retries=0, timeout=request.timeout_seconds,
            )
            # No network operation has begun. Re-read the selected provider and
            # its live configuration immediately before creating the call.
            try:
                selected = await self._selected_provider()
                if (selected is not provider
                        or not self._matches_live_provider(provider)
                        or provider.client is not selected_client
                        or not self._request_allowed(request)):
                    return ProviderResponse("not_dispatched", None, {}, {}, None)
            except asyncio.CancelledError:
                return ProviderResponse("not_dispatched", None, {}, {}, None)
            except Exception:
                return ProviderResponse("not_dispatched", None, {}, {}, None)
            # Selection hooks may request host shutdown without suspending the
            # coroutine. Check the pending cancellation before the SDK call.
            if asyncio.current_task().cancelling():
                try:
                    await asyncio.sleep(0)
                except asyncio.CancelledError:
                    return ProviderResponse("not_dispatched", None, {}, {}, None)
                return ProviderResponse("not_dispatched", None, {}, {}, None)
            response = await client.chat.completions.create(
                model=self._descriptor.model_id,
                messages=messages, stream=False,
                max_completion_tokens=request.max_output_tokens,
            )
            if (not isinstance(response, ChatCompletion)
                    or len(response.choices) != 1
                    or response.choices[0].finish_reason != "stop"):
                return ProviderResponse("unknown", None, {}, {}, None)
            message = response.choices[0].message
            if (message.role != "assistant" or type(message.content) is not str
                    or message.refusal is not None
                    or message.tool_calls or message.function_call):
                return ProviderResponse("unknown", None, {}, {}, None)
            usage = response.usage
            if usage is None:
                amounts = {}
            elif all(type(value) is int and value >= 0 for value in (
                    usage.prompt_tokens, usage.completion_tokens, usage.total_tokens)):
                cached = (usage.prompt_tokens_details.cached_tokens
                          if usage.prompt_tokens_details is not None else None)
                if cached is not None and (
                        type(cached) is not int or cached < 0
                        or cached > usage.prompt_tokens):
                    return ProviderResponse("unknown", None, {}, {}, None)
                amounts = {
                    "input_tokens": usage.prompt_tokens,
                    "output_tokens": usage.completion_tokens,
                }
                if cached is not None:
                    amounts["cached_input_tokens"] = cached
            else:
                return ProviderResponse("unknown", None, {}, {}, None)
            call_ref = response.id if type(response.id) is str and response.id else None
            return ProviderResponse("completed", {"text": message.content}, amounts, {}, call_ref)
        except asyncio.CancelledError:
            return ProviderResponse("unknown", None, {}, {}, None)
        except Exception:
            return ProviderResponse("unknown", None, {}, {}, None)

    def terminal_response(self, call_id: str, request_digest: str,
                          admission_id: str) -> ProviderResponse | None:
        """Read an exact call's terminal response; None means absent or unresolved.

        The host executor must retain this bound adapter. This process-local
        observation is neither durable recovery nor proof of remote cancellation.
        """
        with _call_lock:
            entry = _calls.get(call_id)
            if entry is None:
                return None
            if (entry.digest != request_digest or entry.admission_id != admission_id
                    or entry.host_incarnation != self.host_incarnation
                    or entry.provider_config_digest != self._admin_model.provider_config_digest
                    or not self._same_binding(entry)):
                raise ValueError("call_id belongs to a different request or binding")
            if not entry.terminal.done():
                return None
            return entry.terminal.result()

    def _launch_on_host(self, entry: _CallEntry,
                        request: ModelCallRequest) -> None:
        if self._aborted:
            if not entry.terminal.done():
                entry.terminal.set_result(
                    ProviderResponse("unknown", None, {}, {}, None))
            return
        coroutine = self._invoke_on_host(request)
        try:
            task = asyncio.create_task(coroutine)
        except RuntimeError:
            coroutine.close()
            entry.terminal.set_result(
                ProviderResponse("not_dispatched", None, {}, {}, None))
            return
        entry.task = task

        def finish(done: asyncio.Task[ProviderResponse]) -> None:
            try:
                response = done.result()
            except asyncio.CancelledError:
                # The host's shutdown/cancellation did not settle remote egress.
                return
            except Exception:
                response = ProviderResponse("unknown", None, {}, {}, None)
            entry.task = None
            if not entry.terminal.done():
                entry.terminal.set_result(response)

        task.add_done_callback(finish)

    async def invoke(self, request: ModelCallRequest,
                     cancellation: asyncio.Event) -> ProviderResponse:
        """The old Broker port has no Authority admission or recovery identity."""
        return ProviderResponse("unknown", None, {}, {}, None)

    async def invoke_admitted(self, request: ModelCallRequest,
                              admission: LocalModelAdmission,
                              cancellation: asyncio.Event) -> ProviderResponse:
        """Exercise one local start claim; a future executor must prove its provenance.

        A process restart loses this registry. No durable replay or remote-stop
        guarantee follows from this method or from a finished asyncio task.
        """
        if type(request) is not ModelCallRequest:
            return ProviderResponse("not_dispatched", None, {}, {}, None)
        if (type(admission) is not LocalModelAdmission
                or admission.host_incarnation != self.host_incarnation
                or admission.call_id != request.call_id
                or admission.request_digest != request.digest
                or admission.provider_config_digest != self._admin_model.provider_config_digest):
            raise ValueError("model admission differs from local request or configuration")
        with _call_lock:
            entry = _calls.get(request.call_id)
            if entry is not None:
                if (entry.digest != request.digest
                        or entry.admission_id != admission.admission_id
                        or entry.host_incarnation != admission.host_incarnation
                        or entry.provider_config_digest != admission.provider_config_digest
                        or not self._same_binding(entry)):
                    raise ValueError("call_id belongs to a different request or binding")
                first = False
            else:
                old_call = _admissions.get(admission.admission_id)
                if old_call is not None and old_call != request.call_id:
                    raise ValueError("model admission already belongs to another call")
                entry = _CallEntry(
                    request.digest, admission.admission_id, admission.host_incarnation,
                    admission.provider_config_digest, self._binding)
                _calls[request.call_id] = entry
                _admissions[admission.admission_id] = request.call_id
                first = True
        self._started_calls.add(request.call_id)
        if first:
            if (request.provider_id != self._descriptor.provider_id
                    or request.model_id != self._descriptor.model_id
                    or request.timeout_seconds > self._admin_model.timeout_seconds
                    or request.max_output_tokens > self._admin_model.max_output_tokens
                    or not self._request_allowed(request)
                    or cancellation.is_set() or not self._host_loop.is_running()):
                entry.terminal.set_result(
                    ProviderResponse("not_dispatched", None, {}, {}, None))
            else:
                try:
                    self._host_loop.call_soon_threadsafe(
                        self._launch_on_host, entry, request)
                except RuntimeError:
                    # The callback was not accepted, so no provider task exists.
                    entry.terminal.set_result(
                        ProviderResponse("not_dispatched", None, {}, {}, None))
        # A cancelled waiter must never cancel the one accepted provider task.
        return await asyncio.shield(asyncio.wrap_future(entry.terminal))

    async def abort_local_dispatches(self) -> None:
        """Stop this host binding during shutdown; remote outcome stays unknown."""
        if asyncio.get_running_loop() is not self._host_loop:
            raise RuntimeError("model host loop required")
        self._aborted = True
        with _call_lock:
            entries = tuple(
                _calls[call_id] for call_id in self._started_calls
                if call_id in _calls and self._same_binding(_calls[call_id])
            )
        for entry in entries:
            if entry.task is not None and not entry.task.done():
                entry.task.cancel()
            if not entry.terminal.done():
                entry.terminal.set_result(
                    ProviderResponse("unknown", None, {}, {}, None))

    async def cancel(self, request: ModelCallRequest) -> bool:
        """No host cancellation proof: preserve Broker's unknown outcome."""
        return False


__all__ = ("AstrBotModelProvider", "LocalModelAdmission")
