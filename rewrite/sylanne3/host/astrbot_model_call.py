"""One-start AstrBot call mechanics for the paired Authority executor.

The UMO is supplied by trusted host composition. This adapter rechecks the
installed auxiliary provider or current dialogue selection before each call. The existing Broker invoke
port has no admission proof and therefore never sends. A lost outcome remains
unknown; this process-local registry is not durable Authority observation.
"""

from __future__ import annotations
from .model_workflows_v3 import AdminModelWorkflowsV3
from .model_workflows_v4 import AdminModelWorkflowsV4
from .model_workflows_v5 import AdminModelWorkflowsV5, is_installed_relationship_cognition_slot_v2
from .model_workflows_v6 import AdminModelWorkflowsV6, is_installed_growth_cognition_slot_v2
from .model_workflows_v7 import AdminModelWorkflowsV7, is_installed_growth_cognition_slot_v3, is_installed_relationship_cognition_slot_v3
from .model_workflows_v8 import AdminModelWorkflowsV8, is_installed_growth_cognition_slot_v4, is_installed_relationship_cognition_slot_v4
from .model_workflows_v9 import AdminModelWorkflowsV9
from ..runtime.d11_artifact_draft_model_v1 import is_installed_artifact_draft_slot_v1
from .authority_profile import is_installed_artifact_draft_phase_slot_v2

import asyncio
from concurrent.futures import Future
from dataclasses import dataclass, field
import json
import re
import secrets
from threading import Lock
import weakref

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
    INPUT_SCHEMA_V2 as REVIEW_INPUT_SCHEMA_V2, SYSTEM_MESSAGE_V2 as REVIEW_SYSTEM_MESSAGE_V2,
    REVIEW_TEMPLATE_DIGEST_V2, REVIEW_TEMPLATE_VERSION_V2,
)
from ..model_broker.natural_reply_history_v4 import (
    INPUT_SCHEMA as NATURAL_INPUT_SCHEMA_V4, SYSTEM_MESSAGE as NATURAL_SYSTEM_MESSAGE_V4,
    TEMPLATE_DIGEST as NATURAL_TEMPLATE_DIGEST_V4, TEMPLATE_VERSION as NATURAL_TEMPLATE_VERSION_V4,
    INPUT_SCHEMA_V5 as NATURAL_INPUT_SCHEMA_V5, SYSTEM_MESSAGE_V5 as NATURAL_SYSTEM_MESSAGE_V5,
    TEMPLATE_DIGEST_V5 as NATURAL_TEMPLATE_DIGEST_V5, TEMPLATE_VERSION_V5 as NATURAL_TEMPLATE_VERSION_V5,
)
from ..model_broker.natural_reply_history_v6 import (
    INPUT_SCHEMA as NATURAL_INPUT_SCHEMA_V6, SYSTEM_MESSAGE as NATURAL_SYSTEM_MESSAGE_V6,
    TEMPLATE_DIGEST as NATURAL_TEMPLATE_DIGEST_V6, TEMPLATE_VERSION as NATURAL_TEMPLATE_VERSION_V6,
)
from ..model_broker.natural_reply_history_v7 import (
    INPUT_SCHEMA as NATURAL_INPUT_SCHEMA_V7,SYSTEM_MESSAGE as NATURAL_SYSTEM_MESSAGE_V7,
    TEMPLATE_DIGEST as NATURAL_TEMPLATE_DIGEST_V7,TEMPLATE_VERSION as NATURAL_TEMPLATE_VERSION_V7,
    UNIT_SEMANTIC_FIELDS_V7,
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
    d07_cognition_messages_v1, D07_COGNITION_TEMPLATE_DIGESTS_V1,
)
from ..native_runtime.d04_engineering_scheme import MECHANISMS
from .authority_profile import (
    AdminIngressEncodingPolicy, AdminIngressModelPolicy, AdminModelWorkflowV2, AdminModelWorkflowsV2,
    AdminInstallationBundle, installed_model_config_ref,
)
from ..installation_policy import AdminInstallationPolicy


# Process-local capacity policy. Two simultaneous calls require a separate
# qualification and composition change; there is intentionally no runtime knob.
_MODEL_INFLIGHT_GLOBAL = 1
_MODEL_INFLIGHT_NAMESPACE = 1
_MODEL_BACKGROUND_GLOBAL = 1
_MODEL_BACKGROUND_NAMESPACE = 1
_MODEL_INDEX_ITEMS = 512
_MODEL_INDEX_BYTES = 8_388_608
_MODEL_INDEX_ENTRY_BYTES = 16_384
_MODEL_IDENTITY_TEXT_BYTES = 2_048
_MODEL_REQUEST_BYTES = 262_144
_MODEL_RESPONSE_BYTES = 65_536
_MODEL_ARENA_PER_CALL_BYTES = 2_097_152


class LocalModelCapacityDeniedV1(RuntimeError):
    """The process-local host cannot reserve another original model call."""


@dataclass(frozen=True, slots=True)
class _ModelCapacity:
    namespace: str
    background: bool
    # An encoded metadata reservation, not a measurement of Python/SDK RSS.
    index_bytes: int = _MODEL_INDEX_ENTRY_BYTES
    arena_bytes: int = _MODEL_ARENA_PER_CALL_BYTES


@dataclass(slots=True)
class _PendingCallIdentity:
    digest: str
    admission_id: str
    host_incarnation: str
    provider_config_digest: str
    context: weakref.ReferenceType
    loop: weakref.ReferenceType
    binding_suffix: tuple[object, ...]
    owner: weakref.ReferenceType
    capacity: _ModelCapacity
    executor: weakref.ReferenceType
    stage: str
    resume_stage: str | None = None


@dataclass
class _CallEntry:
    digest: str
    admission_id: str
    host_incarnation: str
    provider_config_digest: str
    binding: tuple[object, ...]
    owner: weakref.ReferenceType
    capacity: _ModelCapacity
    terminal: Future[ProviderResponse] | None = field(default_factory=Future)
    task: asyncio.Task[ProviderResponse] | None = None
    response: ProviderResponse | None = None
    retirement: tuple[str, ...] | None = None
    d13_http_binding: object | None = None


@dataclass(frozen=True, slots=True)
class _SpentCallIdentity:
    digest: str
    admission_id: str
    host_incarnation: str
    provider_config_digest: str
    context: weakref.ReferenceType
    loop: weakref.ReferenceType
    binding_suffix: tuple[object, ...]
    owner: weakref.ReferenceType
    capacity: _ModelCapacity


class _OneStartHandle:
    """Private one-use start; the public identity DTO cannot recreate it."""
    __slots__ = ("seal", "admission_id", "host_incarnation", "call_id", "request_digest",
                 "provider_config_digest", "consumed", "d13_http_binding")

    def __init__(self, seal, admission, d13_http_binding=None):
        self.seal = seal
        self.admission_id = admission.admission_id
        self.host_incarnation = admission.host_incarnation
        self.call_id = admission.call_id
        self.request_digest = admission.request_digest
        self.provider_config_digest = admission.provider_config_digest
        self.consumed = False
        self.d13_http_binding = d13_http_binding


def _retire_entry_locked(call_id, entry):
    """Drop only a physically finished entry with its verified retirement fact."""
    if type(entry) is _CallEntry:
        if (entry.task is not None and not entry.task.done()
                or entry.terminal is None or not entry.terminal.done() or entry.retirement is None):
            return False
        proof = entry.retirement
        if (entry.admission_id, call_id, entry.digest, entry.provider_config_digest, entry.host_incarnation) != proof[:5]:
            return False
        if entry.response is not None and entry.response.status == "completed":
            from ..authority_service.v2_model_egress_contract import HostObservedModelCompletionV2
            report = HostObservedModelCompletionV2(entry.admission_id, entry.host_incarnation, call_id,
                entry.digest, entry.binding[3], entry.binding[4],
                entry.provider_config_digest, canonical_serialize(dict(entry.response.result)),
                tuple(sorted(entry.response.usage.items())), tuple(sorted(entry.response.cost.items())),
                entry.response.provider_call_ref, entry.response.billing_receipt_json)
            if report.digest != proof[5]:
                return False
    owner = entry.owner()
    if owner is not None:
        owner._started_calls.discard(call_id)
    _calls.pop(call_id, None)
    _admissions.pop(entry.admission_id, None)
    if type(entry) is _CallEntry:
        entry.task = None
        entry.terminal = None
        entry.response = None
        entry.binding = ()
        entry.retirement = None
    return True


def _finish_local_entry_locked(call_id, entry):
    if _calls.get(call_id) is not entry:
        return
    if entry.retirement is not None and _retire_entry_locked(call_id, entry):
        return
    if (entry.task is None and entry.terminal is not None and entry.terminal.done()
            and (entry.response is None or entry.response.status != "completed")):
        spent = _SpentCallIdentity(entry.digest, entry.admission_id, entry.host_incarnation,
            entry.provider_config_digest, weakref.ref(entry.binding[0]), weakref.ref(entry.binding[1]),
            entry.binding[2:], entry.owner, entry.capacity)
        _calls[call_id] = spent
        entry.terminal = None
        entry.response = None
        entry.binding = ()


# Process-local dispatch memory. An unresolved entry is intentionally retained:
# a stopped host loop provides no evidence that its provider call did not run.
_call_lock = Lock()
_calls: dict[str, _CallEntry | _SpentCallIdentity | _PendingCallIdentity] = {}
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
    v5 = stage == "generation" and request.prompt_template_digest == NATURAL_TEMPLATE_DIGEST_V5
    v6 = stage == "generation" and request.prompt_template_digest == NATURAL_TEMPLATE_DIGEST_V6
    v7 = stage == "generation" and request.prompt_template_digest == NATURAL_TEMPLATE_DIGEST_V7
    review_v2 = stage == "review" and request.prompt_template_digest == REVIEW_TEMPLATE_DIGEST_V2
    natural_schema = NATURAL_INPUT_SCHEMA_V7 if v7 else NATURAL_INPUT_SCHEMA_V6 if v6 else NATURAL_INPUT_SCHEMA_V5 if v5 else NATURAL_INPUT_SCHEMA_V4 if v4 else NATURAL_INPUT_SCHEMA_V3 if v3 else NATURAL_INPUT_SCHEMA
    if messages[0]["content"] != (
            (NATURAL_SYSTEM_MESSAGE_V7 if v7 else NATURAL_SYSTEM_MESSAGE_V6 if v6 else NATURAL_SYSTEM_MESSAGE_V5 if v5 else NATURAL_SYSTEM_MESSAGE_V4 if v4 else NATURAL_SYSTEM_MESSAGE_V3 if v3 else NATURAL_SYSTEM_MESSAGE) if stage == "generation" else
            REVIEW_SYSTEM_MESSAGE_V2 if review_v2 else REVIEW_SYSTEM_MESSAGE):
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
        if v7:
            if (set(stable)!={'schema','stable_history'} or stable['schema']!=natural_schema
                    or type(stable['stable_history']) is not list
                    or set(dynamic)!={'schema','authority_input_digest','frozen_at_utc','expires_at_utc','question',
                        'expression_plan','qualified_units','speaker_dictionary','recent_history','detail_history','history_selection'}
                    or dynamic['schema']!=natural_schema or type(dynamic['question']) is not dict
                    or set(dynamic['question'])!={'kind','text'} or dynamic['question']['kind']!='question'
                    or type(dynamic['expression_plan']) is not dict
                    or set(dynamic['expression_plan'])!={'required_slots','allowed_speech_acts','promise_grants','scene_id','audience_id'}
                    or type(dynamic['qualified_units']) is not list
                    or any(type(unit) is not dict or set(unit)!=set(UNIT_SEMANTIC_FIELDS_V7) for unit in dynamic['qualified_units'])
                    or any(type(dynamic[name]) is not list for name in ('speaker_dictionary','recent_history','detail_history'))
                    or type(dynamic['history_selection']) is not dict
                    or set(dynamic['history_selection'])!={'order_watermark','coverage','gaps'}):
                return None
            if (any(type(row) is not dict or set(row)!={'block_index','sequence','speaker_key','text'} for row in stable['stable_history'])
                    or any(type(row) is not dict or set(row)!={'sequence','text','trusted_utc','speaker_key','delivery_state','tool_state'} for row in dynamic['recent_history'])
                    or any(type(row) is not dict or set(row)!={'sequence','text','speaker_key'} for row in dynamic['detail_history'])
                    or any(type(row) is not dict or set(row)!={'speaker_key','speaker_ref'} for row in dynamic['speaker_dictionary'])):
                return None
            return messages
        if (set(stable) != {"schema", "scope", "stable_history"}
                or stable["schema"] != natural_schema
                or type(stable["scope"]) is not dict
                or type(stable["stable_history"]) is not list
                or set(dynamic) != ({
                    "schema", "frozen_at_utc", "expires_at_utc", "question",
                    "expression_plan", "qualified_units"} |
                    ({"scope", "recent_history", "history_selection"} if v3 or v4 or v5 or v6 else set()) |
                    ({"detail_history"} if v4 or v5 or v6 else set()))
                or dynamic["schema"] != natural_schema
                or type(dynamic["question"]) is not dict
                or type(dynamic["expression_plan"]) is not dict
                or type(dynamic["qualified_units"]) is not list):
            return None
        if (v3 or v4 or v5 or v6) and (dynamic["scope"] != stable["scope"]
                or type(dynamic["recent_history"]) is not list
                or type(dynamic["history_selection"]) is not dict
                or (v4 or v5 or v6) and type(dynamic["detail_history"]) is not list):
            return None
    else:
        review = user[0]
        if (set(review) != ({
                "schema", "template_version", "generation_frozen_input_digest",
                "generation_output_digest", "qualified_units_digest",
                "review_policy_version", "body", "units", "qualified_basis"} |
                ({"semantic_segments", "generation_output_schema"} if review_v2 else set()))
                or review["schema"] != (REVIEW_INPUT_SCHEMA_V2 if review_v2 else REVIEW_INPUT_SCHEMA)
                or review["template_version"] != (REVIEW_TEMPLATE_VERSION_V2 if review_v2 else REVIEW_TEMPLATE_VERSION)
                or type(review["body"]) is not str
                or type(review["units"]) is not list
                or type(review["qualified_basis"]) is not list):
            return None
        if review_v2:
            from ..domains.d09.natural_reply import NATURAL_REPLY_OUTPUT_SCHEMA_V3, natural_semantic_ranges_v3
            if review["generation_output_schema"] != NATURAL_REPLY_OUTPUT_SCHEMA_V3:
                return None
            try:
                natural_semantic_ranges_v3({"schema": review["generation_output_schema"],
                    "body": review["body"], "units": review["units"],
                    "semantic_segments": review["semantic_segments"]})
            except (TypeError, ValueError):
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
    """Serializable local identity only; never a provider start handle."""

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


class _D13ProviderHTTPRejectedV1(ValueError):
    """Actual SDK bytes rejected before the underlying transport is entered."""


def _checked_d13_http_client_v1(actual_client,*,template,model_request,current_binding,observations,core_binding=None):
    """Wrap this one SDK call; preserve the selected client's actual transport."""
    import httpx
    from ..model_broker.d13_provider_http_template_v1 import require_actual_provider_http_v1
    if not isinstance(actual_client,httpx.AsyncClient):
        raise _D13ProviderHTTPRejectedV1('installed SDK has no actual async HTTP client')
    class CheckedTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self,http_request):
            if observations or not current_binding():
                raise _D13ProviderHTTPRejectedV1('original SDK wire already consumed or current provider changed')
            try:
                actual_digest=require_actual_provider_http_v1(template,request=model_request,content=http_request.content)
            except (TypeError,ValueError) as exc:
                raise _D13ProviderHTTPRejectedV1('actual SDK wire differs from admitted fixed HTTP template') from exc
            observations.append((model_request.call_id,model_request.digest,template.template_digest,
                actual_digest,len(http_request.content)))
            if core_binding is not None:
                await core_binding(http_request.content)
            # The original client owns its connection pool, proxy and MockTransport.
            return await actual_client.send(http_request,stream=True,follow_redirects=False)
        async def aclose(self):
            # Closing this call's wrapper cannot close another selected SDK client.
            return None
    return httpx.AsyncClient(transport=CheckedTransport(),follow_redirects=False)


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
                          or admin_model is workflows.d07_cognition
                          or (is_installed_relationship_cognition_slot_v2(installation_bundle, admin_model) or (is_installed_relationship_cognition_slot_v3(installation_bundle, admin_model) or is_installed_relationship_cognition_slot_v4(installation_bundle, admin_model)))
                           or (is_installed_growth_cognition_slot_v2(installation_bundle, admin_model) or (is_installed_growth_cognition_slot_v3(installation_bundle, admin_model) or is_installed_growth_cognition_slot_v4(installation_bundle, admin_model)))
                           or is_installed_artifact_draft_slot_v1(installation_bundle,admin_model)
                           or is_installed_artifact_draft_phase_slot_v2(installation_bundle,admin_model)
                           or (type(workflows) in {AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}
                              and (admin_model is workflows.life_content
                                   or admin_model is workflows.life_numeric))))
        if not installed:
            raise ValueError("model selection is absent from installed administrator snapshot")
        self._context = context
        self._host_loop = host_loop
        self._trusted_umo = trusted_umo
        self._descriptor = descriptor
        self._admin_model = admin_model
        self._installation_bundle = installation_bundle
        from ..model_broker.provider_billing_receipt_v1 import require_installed_provider_billing_policy_v1
        billing = installation_bundle.provider_billing_policy_v1
        self._billing_policy = None
        if billing is not None and (billing.provider_id, billing.model_id, billing.provider_config_digest) == (
                admin_model.provider_id, admin_model.model_id, admin_model.provider_config_digest):
            self._billing_policy = require_installed_provider_billing_policy_v1(
                billing, installation_bundle, admin_model)
        self._aborted = False
        self._started_calls: set[str] = set()
        self._d13_provider_http_observations_v1 = {}
        self._start_handle_seal = object()
        self._binding = (context, host_loop, trusted_umo,
                         descriptor.provider_id, descriptor.model_id,
                         admin_model.provider_config_ref,
                         (admin_model.work_kind, admin_model.template_version)
                         if type(admin_model) is AdminModelWorkflowV2 else "legacy")

    @property
    def host_incarnation(self) -> str:
        return _HOST_INCARNATION

    def _same_binding(self, entry: _CallEntry) -> bool:
        if type(entry) in {_SpentCallIdentity, _PendingCallIdentity}:
            return (entry.context() is self._context and entry.loop() is self._host_loop
                    and entry.binding_suffix == self._binding[2:])
        return (entry.binding[0] is self._context
                and entry.binding[1] is self._host_loop
                and entry.binding[2:] == self._binding[2:])

    def _claim_capacity_from_executor_v1(self, executor, request, *, preparing):
        """Reserve before Authority I/O, or advance this exact pending prepare.

        No waiter queue, timer, GC callback or cache eviction frees a slot.
        A lost RPC, stopped loop or unknown provider outcome keeps its slot.
        """
        from .model_egress_executor import HostModelEgressExecutor
        if (type(executor) is not HostModelEgressExecutor or executor._adapter is not self
                or type(request) is not ModelCallRequest
                or request.envelope.authority.namespace != self._installation_bundle.installation_policy.namespace):
            return False
        policy = self._installation_bundle.installation_policy
        namespace = canonical_digest((policy.expected_authority_id, policy.authority_namespace,
                                      policy.namespace.as_tuple))
        workflows = self._installation_bundle.model_workflows
        foreground = (type(self._admin_model) is AdminIngressModelPolicy
                      or workflows is not None and any(self._admin_model is getattr(workflows, slot, None)
                          for slot in ("reply", "context_reply", "natural_generation", "natural_review")))
        background = request.identity.phase == "d13.precompress" or not foreground
        # The fixed index charge covers bounded identity text in both lookup
        # dictionaries and the entry. It excludes borrowed Context/loop objects.
        identity_text = canonical_serialize((request.call_id, self._binding[2:]))
        if (len(identity_text.encode("utf-8")) > _MODEL_IDENTITY_TEXT_BYTES
                or len(canonical_serialize(dict(request.payload)).encode("utf-8")) > _MODEL_REQUEST_BYTES):
            return False
        digest = request.digest
        with _call_lock:
            old = _calls.get(request.call_id)
            if old is not None:
                if (preparing or type(old) is not _PendingCallIdentity
                        or old.stage != "prepare_sent"
                        or old.digest != digest or old.capacity.namespace != namespace
                        or not self._same_binding(old)):
                    return False
                # An exact prepared original may continue in a replacement
                # executor. The lock transfers ownership; admit_sent never does.
                old.executor = weakref.ref(executor)
                old.owner = weakref.ref(self)
                old.resume_stage = "prepare_sent"
                old.stage = "admit_reserved"
                return old
            entries = tuple(_calls.values())
            same_namespace = tuple(entry for entry in entries if entry.capacity.namespace == namespace)
            if (len(entries) >= _MODEL_INFLIGHT_GLOBAL
                    or len(same_namespace) >= _MODEL_INFLIGHT_NAMESPACE
                    or len(entries) >= _MODEL_INDEX_ITEMS
                    or sum(entry.capacity.arena_bytes for entry in entries) + _MODEL_ARENA_PER_CALL_BYTES
                       > _MODEL_INFLIGHT_GLOBAL * _MODEL_ARENA_PER_CALL_BYTES
                    or sum(entry.capacity.index_bytes for entry in entries) + _MODEL_INDEX_ENTRY_BYTES > _MODEL_INDEX_BYTES
                    or background and (sum(entry.capacity.background for entry in entries) >= _MODEL_BACKGROUND_GLOBAL
                        or sum(entry.capacity.background for entry in same_namespace) >= _MODEL_BACKGROUND_NAMESPACE)):
                return False
            entry = _PendingCallIdentity(
                digest, "", self.host_incarnation, self._admin_model.provider_config_digest,
                weakref.ref(self._context), weakref.ref(self._host_loop), self._binding[2:], weakref.ref(self),
                _ModelCapacity(namespace, background), weakref.ref(executor),
                "prepare_reserved" if preparing else "admit_reserved")
            _calls[request.call_id] = entry
            return entry

    def _mark_capacity_rpc_dispatched_v1(self, executor, call_id, reservation):
        """Called synchronously immediately before this model RPC writer.write."""
        with _call_lock:
            if (_calls.get(call_id) is not reservation
                    or type(reservation) is not _PendingCallIdentity
                    or reservation.executor() is not executor
                    or reservation.stage not in {"prepare_reserved", "admit_reserved"}):
                raise ValueError("model RPC dispatch differs from its local reservation")
            reservation.stage = ("prepare_sent" if reservation.stage == "prepare_reserved"
                                 else "admit_sent")
            reservation.resume_stage = None

    def _release_unsent_capacity_v1(self, executor, call_id, reservation):
        """Only a never-invoked model write may release or restore its reservation."""
        with _call_lock:
            if (_calls.get(call_id) is not reservation
                    or type(reservation) is not _PendingCallIdentity
                    or reservation.executor() is not executor
                    or reservation.stage not in {"prepare_reserved", "admit_reserved"}):
                return False
            if reservation.resume_stage == "prepare_sent":
                # This admit never wrote, but its earlier prepare did. Keep
                # the original and allow only its exact first-admit continuation.
                reservation.stage = "prepare_sent"
                reservation.resume_stage = None
                return False
            _calls.pop(call_id)
            return True

    def _retire_unadmitted_from_executor_v1(self, executor):
        """Consume a paired Core closure fact; never a public DTO or absence guess."""
        from .model_egress_executor import HostModelEgressExecutor
        if (type(executor) is not HostModelEgressExecutor or executor._adapter is not self
                or executor._verified_capacity_return is None):
            return False
        call_id, digest, provider_digest, status = executor._verified_capacity_return
        executor._verified_capacity_return = None
        if status not in {"not_dispatched", "never_begun"}:
            return False
        with _call_lock:
            entry = _calls.get(call_id)
            policy = self._installation_bundle.installation_policy
            namespace = canonical_digest((policy.expected_authority_id, policy.authority_namespace,
                                          policy.namespace.as_tuple))
            if (type(entry) is not _PendingCallIdentity or not self._same_binding(entry)
                    or entry.capacity.namespace != namespace or entry.digest != digest
                    or entry.provider_config_digest != provider_digest
                    or entry.admission_id
                    or entry.stage not in {"prepare_reserved", "prepare_sent",
                                           "admit_reserved", "admit_sent"}):
                return False
            # A later callback for this retired reservation fails the exact
            # dictionary-object check before its write; Core also seals replay.
            _calls.pop(call_id)
            return True

    def _issue_start_from_executor_v1(self, executor):
        from .model_egress_executor import HostModelEgressExecutor
        if (type(executor) is not HostModelEgressExecutor or executor._adapter is not self
                or executor._verified_start_return is None):
            raise ValueError("a verified paired executor admission is required")
        admission = executor._verified_start_return
        executor._verified_start_return = None
        with _call_lock:
            entry = _calls.get(admission.call_id)
            if (type(entry) is not _PendingCallIdentity or entry.executor() is not executor
                    or entry.stage != "admit_sent" or not self._same_binding(entry)
                    or (entry.digest, entry.host_incarnation, entry.provider_config_digest) !=
                       (admission.request_digest, admission.host_incarnation, admission.provider_config_digest)
                    or admission.admission_id in _admissions):
                raise ValueError("model admission has no original capacity reservation")
            entry.admission_id = admission.admission_id
            entry.stage = "handle_issued"
            _admissions[admission.admission_id] = admission.call_id
        d13_binding=None
        if (type(self._installation_bundle.model_workflows) in {AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}
                and self._admin_model is self._installation_bundle.model_workflows.natural_generation):
            from .model_egress_executor import _bound_model_admission_v1
            current=executor._verified_start_binding_v1
            executor._verified_start_binding_v1=None
            if current is None or current[2] is not admission or not _bound_model_admission_v1(
                    self,self._installation_bundle,executor._grant,current[0],current[1],admission):
                raise ValueError('V7 actual HTTP capture requires its same verified private executor admission')
            intent,permit,actual_admission,model_request=current
            if (model_request.call_id,model_request.digest)!=(admission.call_id,admission.request_digest):
                raise ValueError('V7 private HTTP binding request differs')
            async def d13_binding(content):
                return await executor._authority.bind_observed_d13_provider_http_v1(
                    executor._bundle,executor._grant,intent=intent,admission=actual_admission,content=content)
        else:
            executor._verified_start_binding_v1=None
        return _OneStartHandle(self._start_handle_seal, admission,d13_binding)

    def _retire_confirmed_from_executor_v1(self, executor):
        from .model_egress_executor import HostModelEgressExecutor
        if (type(executor) is not HostModelEgressExecutor or executor._adapter is not self
                or executor._verified_terminal_return is None):
            raise ValueError("a verified paired terminal query is required")
        proof = executor._verified_terminal_return
        executor._verified_terminal_return = None
        with _call_lock:
            entry = _calls.get(proof[1])
            if entry is None:
                return True
            admission_id = entry.admission_id
            if type(entry) is _PendingCallIdentity and not admission_id:
                # An admit ACK may have been lost. Only this already-verified
                # paired original terminal can bind the missing admission id.
                admission_id = proof[0]
            if (admission_id, proof[1], entry.digest, entry.provider_config_digest, entry.host_incarnation) != proof[:5] or not self._same_binding(entry):
                return False
            if type(entry) in {_SpentCallIdentity, _PendingCallIdentity}:
                owner = entry.owner()
                if owner is not None:
                    owner._started_calls.discard(proof[1])
                _calls.pop(proof[1]); _admissions.pop(entry.admission_id, None)
                return True
            entry.retirement = proof
            if entry.task is not None and not entry.task.done() or entry.terminal is None or not entry.terminal.done():
                # A real durable fact may arrive before the local callback.
                # The callback performs the same retirement once physically done.
                return True
            return _retire_entry_locked(proof[1], entry)

    @property
    def descriptor(self) -> ModelProviderDescriptor:
        return self._descriptor

    def _life_numeric_messages(self, request: ModelCallRequest):
        from ..model_broker.internal_life_numeric_v1 import WORK_KIND, TEMPLATE_VERSION, TEMPLATE_DIGEST
        model = self._admin_model
        if (model.work_kind != WORK_KIND or model.template_version != TEMPLATE_VERSION
                or request.identity.phase != "internal_life_numeric_v1"
                or request.envelope.authority.issuer_domain != "d11"
                or request.envelope.authority.purpose != "consolidation"
                or request.prompt_template_digest != TEMPLATE_DIGEST):
            return None
        # Wire reuse is limited to the candidate appraisal format. Actual
        # internal Source/before/worker authority is verified by Core admission.
        return _appraisal_messages(request)

    def _life_messages(self, request: ModelCallRequest):
        from ..model_broker.internal_life_content_v1 import internal_life_provider_messages_v2
        try:
            return internal_life_provider_messages_v2(request, self._admin_model)
        except (ValueError, TypeError, KeyError):
            return None

    def _contact_messages(self, request: ModelCallRequest):
        from ..model_broker.contact_expression_v1 import contact_provider_messages_v1
        from ..model_broker.natural_reply import NaturalReplyInstallationV2
        model = self._admin_model
        installation = NaturalReplyInstallationV2(self._installation_bundle.installation_policy.installation_id,
            model.provider_config_digest, model.provider_id, model.model_id, model.max_output_tokens)
        try:
            from .model_workflows_v3 import AdminModelWorkflowsV3
            if type(self._installation_bundle.model_workflows) in {AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}:
                from ..model_broker.contact_expression_v2 import contact_provider_messages_v2
                return contact_provider_messages_v2(request, installation)
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
            expected_purpose = model.purpose
            if request.identity.phase == "d13.precompress":
                from ..runtime.d13_installed_paid_purpose_v1 import installed_d13_paid_context_request_v1
                if not installed_d13_paid_context_request_v1(bundle, model, request):
                    return False
                expected_purpose = "context"
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
                        and model is not workflows.d07_cognition
                        and not (is_installed_relationship_cognition_slot_v2(bundle, model) or (is_installed_relationship_cognition_slot_v3(bundle, model) or is_installed_relationship_cognition_slot_v4(bundle, model)))
                        and not (is_installed_growth_cognition_slot_v2(bundle, model) or (is_installed_growth_cognition_slot_v3(bundle, model) or is_installed_growth_cognition_slot_v4(bundle, model)))
                        and not is_installed_artifact_draft_slot_v1(bundle,model)
                        and not is_installed_artifact_draft_phase_slot_v2(bundle,model)
                        and not (type(workflows) in {AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}
                                 and (model is workflows.life_content
                                      or model is workflows.life_numeric)))
                    or type(policy) is not AdminInstallationPolicy
                    or policy.namespace != authority.namespace
                    or model.work_kind not in policy.root_grant.allowed_work_kinds
                    or request.provider_id != model.provider_id
                    or request.model_id != model.model_id
                    or descriptor.capabilities != frozenset({"text"})
                    or not request.required_capabilities
                    or not request.required_capabilities <= descriptor.capabilities
                    or not request.required_capabilities <= set(model.required_capabilities)
                    or descriptor.purposes != frozenset({expected_purpose})
                    or authority.purpose != expected_purpose
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
            if is_installed_artifact_draft_phase_slot_v2(bundle, model):
                from ..model_broker.artifact_draft_v1 import (
                    artifact_draft_input_from_wire_v2, artifact_draft_provider_messages_v2,
                    artifact_draft_phase_token_limits_v2, TEMPLATE_VERSION_V2, TEMPLATE_DIGEST_V2, WORK_KIND,
                )
                from .authority_profile import AdminArtifactDraftToolScopeV2
                from ..domains.d01 import TONE_SAMPLE_METHOD_V1
                if (model.template_version != TEMPLATE_VERSION_V2 or request.prompt_template_digest != TEMPLATE_DIGEST_V2
                        or request.identity.phase != WORK_KIND or authority.issuer_domain != "d11"
                        or type(authority.worker_fence) is not int or authority.worker_fence < 1):
                    return False
                artifact_draft_provider_messages_v2(request)
                frozen = artifact_draft_input_from_wire_v2(dict(request.payload)["input"])
                limits = artifact_draft_phase_token_limits_v2(frozen.selector)
                from .artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4, require_paired_phase_frozen_target_v4
                tool_scope = bundle.artifact_draft.tool_scope
                if type(bundle.artifact_draft) is AdminArtifactDraftPairedPolicyV4:
                    tool_scope = require_paired_phase_frozen_target_v4(bundle.artifact_draft,frozen)
                if (request.max_output_tokens != min(model.max_output_tokens, limits["output_tokens"])
                        or frozen.selector.method_ref == TONE_SAMPLE_METHOD_V1
                            and (type(tool_scope) is not AdminArtifactDraftToolScopeV2
                                or tool_scope.maximum_artifact_version < 2)):
                    return False
                return True
            if is_installed_artifact_draft_slot_v1(bundle,model):
                from ..model_broker.artifact_draft_v1 import artifact_draft_provider_messages_v1,TEMPLATE_VERSION,TEMPLATE_DIGEST
                if (model.template_version!=TEMPLATE_VERSION or request.prompt_template_digest!=TEMPLATE_DIGEST
                        or request.identity.phase!="artifact_draft_v1" or authority.issuer_domain!="d11"
                        or type(authority.worker_fence) is not int or authority.worker_fence<1):return False
                artifact_draft_provider_messages_v1(request)
                return True
            if type(workflows) in {AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9} and model is workflows.life_numeric:
                return self._life_numeric_messages(request) is not None
            if type(workflows) in {AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9} and model is workflows.life_content:
                return self._life_messages(request) is not None
            if model is workflows.encode:
                from ..model_broker.first_ingress_encoding import encoding_template_digest_v1, ENCODING_TEMPLATE_VERSIONS
                return (type(encoding) is AdminIngressEncodingPolicy
                        and all(amount <= encoding.quote_ceiling.get(dimension, 0)
                                for dimension, amount in model.quote_ceiling.items())
                        and model.template_version
                        in ENCODING_TEMPLATE_VERSIONS
                        and request.prompt_template_digest
                        == encoding_template_digest_v1(model.template_version))
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
                            (NATURAL_TEMPLATE_VERSION_V4, NATURAL_TEMPLATE_DIGEST_V4),
                            (NATURAL_TEMPLATE_VERSION_V5, NATURAL_TEMPLATE_DIGEST_V5),
                            (NATURAL_TEMPLATE_VERSION_V6, NATURAL_TEMPLATE_DIGEST_V6))
                        and _natural_messages(request, "generation") is not None)
            if model is workflows.natural_review:
                return (request.identity.phase == "natural_review"
                        and type(authority.worker_fence) is int
                        and authority.worker_fence >= 1
                        and (model.template_version, request.prompt_template_digest) in (
                            (REVIEW_TEMPLATE_VERSION, REVIEW_TEMPLATE_DIGEST),
                            (REVIEW_TEMPLATE_VERSION_V2, REVIEW_TEMPLATE_DIGEST_V2))
                        and _natural_messages(request, "review") is not None)
            if model is workflows.contact_generation or model is workflows.contact_review:
                from ..model_broker.contact_expression_v1 import (
                    GENERATION_TEMPLATE_VERSION, GENERATION_TEMPLATE_DIGEST,
                    REVIEW_TEMPLATE_VERSION as CONTACT_REVIEW_VERSION,
                    REVIEW_TEMPLATE_DIGEST as CONTACT_REVIEW_DIGEST)
                if type(workflows) in {AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}:
                    from ..model_broker.contact_expression_v2 import (
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
            if (model is workflows.d07_cognition or (is_installed_relationship_cognition_slot_v2(bundle, model) or (is_installed_relationship_cognition_slot_v3(bundle, model) or is_installed_relationship_cognition_slot_v4(bundle, model)))
                    or (is_installed_growth_cognition_slot_v2(bundle, model) or (is_installed_growth_cognition_slot_v3(bundle, model) or is_installed_growth_cognition_slot_v4(bundle, model)))):
                return (request.identity.phase == "d07.cognition"
                        and type(authority.worker_fence) is int and authority.worker_fence >= 1
                        and D07_COGNITION_TEMPLATE_DIGESTS_V1.get(model.template_version)
                            == request.prompt_template_digest
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
        """Resolve an exact installed auxiliary slot, or the current dialogue UMO."""
        workflows = self._installation_bundle.model_workflows
        if is_installed_artifact_draft_phase_slot_v2(self._installation_bundle, self._admin_model):
            return self._context.get_provider_by_id(self._descriptor.provider_id)
        if is_installed_artifact_draft_slot_v1(self._installation_bundle,self._admin_model):
            return self._context.get_provider_by_id(self._descriptor.provider_id)
        if (type(workflows) in {AdminModelWorkflowsV2, AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}
                and any(self._admin_model is getattr(workflows, slot, None)
                        for slot in ("encode", "appraisal", "d07_cognition", "d07_relationship_cognition", "growth_cognition",
                                     "general_growth_cognition", "artifact_observation_cognition", "life_content", "life_numeric"))):
            return self._context.get_provider_by_id(self._descriptor.provider_id)
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
        phase_provider_request = None
        checked_http_client = None
        actual_http_observations = []
        if is_installed_artifact_draft_phase_slot_v2(self._installation_bundle, self._admin_model):
            from ..model_broker.artifact_phase_count_v1 import artifact_phase_provider_request_v1
            phase_provider_request = artifact_phase_provider_request_v1(request, billing_policy=self._billing_policy)
            messages = phase_provider_request["messages"]
        elif is_installed_artifact_draft_slot_v1(self._installation_bundle,self._admin_model):
            from ..model_broker.artifact_draft_v1 import artifact_draft_provider_messages_v1
            messages=artifact_draft_provider_messages_v1(request)
        elif (type(self._installation_bundle.model_workflows) in {AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}
                and self._admin_model is self._installation_bundle.model_workflows.life_content):
            messages = self._life_messages(request)
        elif (type(self._installation_bundle.model_workflows) in {AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}
                and self._admin_model is self._installation_bundle.model_workflows.life_numeric):
            messages = self._life_numeric_messages(request)
        elif (type(self._admin_model) is AdminModelWorkflowV2
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
              and (self._admin_model is self._installation_bundle.model_workflows.d07_cognition
                   or (is_installed_relationship_cognition_slot_v2(self._installation_bundle, self._admin_model) or (is_installed_relationship_cognition_slot_v3(self._installation_bundle, self._admin_model) or is_installed_relationship_cognition_slot_v4(self._installation_bundle, self._admin_model)))
                   or (is_installed_growth_cognition_slot_v2(self._installation_bundle, self._admin_model) or (is_installed_growth_cognition_slot_v3(self._installation_bundle, self._admin_model) or is_installed_growth_cognition_slot_v4(self._installation_bundle, self._admin_model))))):
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
            if (type(self._installation_bundle.model_workflows) in {AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}
                    and self._admin_model is self._installation_bundle.model_workflows.natural_generation):
                from ..model_broker.d13_provider_http_template_v1 import D13ProviderHTTPTemplateV1
                policy=self._installation_bundle.d13_wire_policy
                if policy is None or self._billing_policy is None:
                    return ProviderResponse("not_dispatched", None, {}, {}, None)
                template=D13ProviderHTTPTemplateV1(request.model_id,
                    tuple((message['role'],message['content']) for message in messages),request.max_output_tokens,
                    request.call_id,self._billing_policy.contract_digest,policy.serializer_fingerprint)
                with _call_lock:
                    current_call=_calls.get(request.call_id)
                    binding_port=(current_call.d13_http_binding if type(current_call) is _CallEntry
                        and current_call.owner() is self and current_call.digest==request.digest else None)
                if binding_port is None:
                    return ProviderResponse("not_dispatched", None, {}, {}, None)
                checked_http_client=_checked_d13_http_client_v1(selected_client._client,
                    template=template,model_request=request,
                    current_binding=lambda: not self._aborted and self._matches_live_provider(provider)
                        and provider.client is selected_client and self._request_allowed(request),
                    observations=actual_http_observations,core_binding=binding_port)
                client=selected_client.with_options(max_retries=0,timeout=request.timeout_seconds,http_client=checked_http_client)
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
            if phase_provider_request is not None:
                response = await client.chat.completions.create(**phase_provider_request)
            else:
                from ..model_broker.provider_billing_receipt_v1 import provider_billing_request_metadata_v1
                response = await client.chat.completions.create(
                    model=self._descriptor.model_id,
                    messages=messages, stream=False,
                    max_completion_tokens=request.max_output_tokens,
                    **provider_billing_request_metadata_v1(self._billing_policy, request),
                )
            if checked_http_client is not None:
                if len(actual_http_observations)!=1:
                    raise _D13ProviderHTTPRejectedV1('V7 completion lacks its one actual SDK HTTP capture')
                self._d13_provider_http_observations_v1[request.call_id]=actual_http_observations[0]
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
            cost, billing_receipt_json = {}, None
            if self._billing_policy is not None:
                from ..model_broker.provider_billing_receipt_v1 import (
                    EXTENSION_KEY, verify_provider_billing_receipt_v1,
                )
                extra = response.model_extra
                raw = extra.get(EXTENSION_KEY) if type(extra) is dict else None
                try:
                    bill = verify_provider_billing_receipt_v1(self._billing_policy,
                        request=request, provider_call_ref=call_ref, response_model=response.model,
                        usage=amounts, raw=raw)
                except (TypeError, ValueError):
                    # Completion remains observed; missing/invalid money stays unknown.
                    pass
                else:
                    cost = {"model_microusd": bill.final_charged_amount}
                    billing_receipt_json = bill.encoded
            return ProviderResponse("completed", {"text": message.content}, amounts, cost, call_ref,
                billing_receipt_json)
        except _D13ProviderHTTPRejectedV1:
            return ProviderResponse("not_dispatched", None, {}, {}, None) if not actual_http_observations else ProviderResponse("unknown", None, {}, {}, None)
        except asyncio.CancelledError:
            return ProviderResponse("unknown", None, {}, {}, None)
        except Exception:
            return ProviderResponse("unknown", None, {}, {}, None)
        finally:
            if checked_http_client is not None:
                await checked_http_client.aclose()

    def terminal_response(self, call_id: str, request_digest: str,
                          admission_id: str) -> ProviderResponse | None:
        """Read an exact call's terminal response; None means absent or unresolved.

        The host executor must retain this bound adapter. This process-local
        observation is neither durable recovery nor proof of remote cancellation.
        """
        with _call_lock:
            entry = _calls.get(call_id)
            if entry is None or type(entry) is _PendingCallIdentity:
                return None
            if (entry.digest != request_digest or entry.admission_id != admission_id
                    or entry.host_incarnation != self.host_incarnation
                    or entry.provider_config_digest != self._admin_model.provider_config_digest
                    or not self._same_binding(entry)):
                raise ValueError("call_id belongs to a different request or binding")
            if type(entry) is _SpentCallIdentity:
                return ProviderResponse("unknown", None, {}, {}, None)
            if entry.response is not None:
                return entry.response
            if not entry.terminal.done():
                return None
            return entry.terminal.result()

    def _launch_on_host(self, entry: _CallEntry,
                         request: ModelCallRequest) -> None:
        with _call_lock:
            if _calls.get(request.call_id) is not entry or entry.terminal is None:
                return
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
        terminal = entry.terminal

        def finish(done: asyncio.Task[ProviderResponse]) -> None:
            try:
                response = done.result()
            except asyncio.CancelledError:
                # The host's shutdown/cancellation did not settle remote egress.
                response = ProviderResponse("unknown", None, {}, {}, None)
            except Exception:
                response = ProviderResponse("unknown", None, {}, {}, None)
            finally:
                with _call_lock:
                    entry.task = None
            if (response.status == "completed" and len(canonical_serialize({
                    "result": dict(response.result), "usage": dict(response.usage),
                    "cost": dict(response.cost), "provider_call_ref": response.provider_call_ref,
                    "billing_receipt_json": response.billing_receipt_json}).encode("utf-8")) > _MODEL_RESPONSE_BYTES):
                response = ProviderResponse("unknown", None, {}, {}, None)
            with _call_lock:
                entry.response = response
                if not terminal.done():
                    terminal.set_result(response)
                _finish_local_entry_locked(request.call_id, entry)

        task.add_done_callback(finish)

    async def invoke(self, request: ModelCallRequest,
                     cancellation: asyncio.Event) -> ProviderResponse:
        """The old Broker port has no Authority admission or recovery identity."""
        return ProviderResponse("unknown", None, {}, {}, None)

    async def invoke_admitted(self, request: ModelCallRequest,
                               admission: _OneStartHandle,
                              cancellation: asyncio.Event) -> ProviderResponse:
        """Consume one private executor-issued handle, or join its live entry.

        A process restart loses this registry. No durable replay or remote-stop
        guarantee follows from this method or from a finished asyncio task.
        """
        if type(request) is not ModelCallRequest:
            return ProviderResponse("not_dispatched", None, {}, {}, None)
        if (type(admission) is not _OneStartHandle or admission.seal is not self._start_handle_seal
                or admission.host_incarnation != self.host_incarnation
                or admission.call_id != request.call_id
                or admission.request_digest != request.digest
                or admission.provider_config_digest != self._admin_model.provider_config_digest):
            raise ValueError("model admission differs from local request or configuration")
        with _call_lock:
            entry = _calls.get(request.call_id)
            if entry is not None and type(entry) is not _PendingCallIdentity:
                if (entry.digest != request.digest
                        or entry.admission_id != admission.admission_id
                        or entry.host_incarnation != admission.host_incarnation
                        or entry.provider_config_digest != admission.provider_config_digest
                        or not self._same_binding(entry)):
                    raise ValueError("call_id belongs to a different request or binding")
                if type(entry) is _SpentCallIdentity:
                    raise ValueError("consumed model start has no live call to join")
                first = False
            else:
                if admission.consumed:
                    raise ValueError("consumed model start cannot dispatch again")
                if (type(entry) is not _PendingCallIdentity or entry.stage != "handle_issued"
                        or (entry.digest, entry.admission_id, entry.host_incarnation, entry.provider_config_digest) !=
                           (request.digest, admission.admission_id, admission.host_incarnation, admission.provider_config_digest)
                        or _admissions.get(admission.admission_id) != request.call_id
                        or not self._same_binding(entry)):
                    raise ValueError("model admission has no reserved local capacity")
                entry = _CallEntry(
                    request.digest, admission.admission_id, admission.host_incarnation,
                    admission.provider_config_digest, self._binding, weakref.ref(self), entry.capacity)
                entry.d13_http_binding = admission.d13_http_binding
                _calls[request.call_id] = entry
                _admissions[admission.admission_id] = request.call_id
                first = True
            admission.consumed = True
            terminal = entry.terminal
        self._started_calls.add(request.call_id)
        if first:
            if (request.provider_id != self._descriptor.provider_id
                    or request.model_id != self._descriptor.model_id
                    or request.timeout_seconds > self._admin_model.timeout_seconds
                    or request.max_output_tokens > self._admin_model.max_output_tokens
                    or not self._request_allowed(request)
                    or cancellation.is_set() or not self._host_loop.is_running()):
                terminal.set_result(
                    ProviderResponse("not_dispatched", None, {}, {}, None))
            else:
                try:
                    self._host_loop.call_soon_threadsafe(
                        self._launch_on_host, entry, request)
                except RuntimeError:
                    # The callback was not accepted, so no provider task exists.
                    terminal.set_result(
                        ProviderResponse("not_dispatched", None, {}, {}, None))
        # A cancelled waiter must never cancel the one accepted provider task.
        response = await asyncio.shield(asyncio.wrap_future(terminal))
        with _call_lock:
            if entry.task is None:
                _finish_local_entry_locked(request.call_id, entry)
        return response

    async def abort_local_dispatches(self) -> None:
        """Stop this host binding during shutdown; remote outcome stays unknown."""
        if asyncio.get_running_loop() is not self._host_loop:
            raise RuntimeError("model host loop required")
        self._aborted = True
        with _call_lock:
            entries = tuple(
                _calls[call_id] for call_id in self._started_calls
                if call_id in _calls and type(_calls[call_id]) is _CallEntry
                and self._same_binding(_calls[call_id])
            )
        for entry in entries:
            with _call_lock:
                task, terminal = entry.task, entry.terminal
            if task is not None and not task.done():
                task.cancel()
            if terminal is not None and not terminal.done():
                terminal.set_result(
                    ProviderResponse("unknown", None, {}, {}, None))

    async def cancel(self, request: ModelCallRequest) -> bool:
        """No host cancellation proof: preserve Broker's unknown outcome."""
        return False


__all__ = ("AstrBotModelProvider", "LocalModelAdmission")
