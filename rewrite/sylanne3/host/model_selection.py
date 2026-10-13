"""Observe the configured SDK LLM on its Host loop; never invoke a provider.

The exported plan records current provider/model/config identity only. Exact
installed workflow matching is separate from Owner or model-call admission.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re

from astrbot.api.star import Context
from astrbot.core.provider.entities import ProviderMeta, ProviderType
from astrbot.core.provider.provider import Provider
from astrbot.core.provider.sources.openai_source import ProviderOpenAIOfficial
from openai import AsyncAzureOpenAI, AsyncOpenAI

from .authority_client import AuthoritySelection
from .authority_profile import (
    AdminIngressModelPolicy, AdminInstallationBundle, AdminModelWorkflowV2,
    AdminModelWorkflowsV2, installed_model_config_ref,
)
from .model_workflows_v3 import AdminModelWorkflowsV3
from .model_workflows_v4 import AdminModelWorkflowsV4
from .model_workflows_v5 import AdminModelWorkflowsV5
from .model_workflows_v6 import AdminModelWorkflowsV6
from .model_workflows_v7 import AdminModelWorkflowsV7
from .mtls_transport import AuthorityTlsProfile
from ..installation_policy import AdminInstallationPolicy
from ..runtime_contracts import canonical_digest


SCHEMA = "sylanne.host-model-selection.v1"
MODEL_REASON_CODES = frozenset({
    "model_unselected", "model_unavailable", "model_not_chat", "model_changed",
    "model_registry_changed", "model_adapter_unsupported", "model_client_unsupported",
    "model_config_invalid", "model_awaiting_installation", "model_workflows_unavailable",
    "model_provider_mismatch", "model_id_mismatch", "model_config_mismatch",
})


def _bounded(value):
    return (type(value) is str and 1 <= len(value) <= 256 and bool(value.strip())
            and not any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value))


@dataclass(frozen=True, slots=True)
class HostModelSelectionV1:
    authority_profile: str
    provider_id: str
    model_id: str
    provider_config_digest: str
    schema: str = SCHEMA

    def __post_init__(self):
        if self.schema != SCHEMA:
            raise ValueError("unknown host model selection schema")
        AuthoritySelection(self.authority_profile)
        if not _bounded(self.provider_id) or not _bounded(self.model_id):
            raise ValueError("host model selection identifiers exceed contract")
        if type(self.provider_config_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", self.provider_config_digest) is None:
            raise ValueError("host model selection needs canonical configuration digest")

    def to_dict(self):
        return asdict(self)


def parse_host_model_selection_v1(value):
    if type(value) is not dict or set(value) != {
            "schema", "authority_profile", "provider_id", "model_id", "provider_config_digest"}:
        raise ValueError("host model selection fields differ")
    return HostModelSelectionV1(**value)


@dataclass(frozen=True, slots=True)
class ObservedHostModelSelectionV1:
    provider_id: str | None
    model_id: str | None
    state: str
    reason_code: str
    plan: HostModelSelectionV1 | None = None

    def to_dict(self):
        return {"provider_id": self.provider_id, "model_id": self.model_id, "state": self.state}


def _installed_reason(plan, bundle):
    if type(bundle) is not AdminInstallationBundle:
        return "model_awaiting_installation"
    if (type(bundle.installation_policy) is not AdminInstallationPolicy
            or type(bundle.tls_profile) is not AuthorityTlsProfile
            or bundle.tls_profile.profile_id != plan.authority_profile):
        return "model_awaiting_installation"
    workflows = bundle.model_workflows
    if type(workflows) in {AdminModelWorkflowsV2, AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7}:
        # The installed reply slot defines the main model. Optional generation,
        # review, cognition and Life slots retain their independent identities.
        selected = [workflows.reply]
    elif workflows is None and type(bundle.ingress_model) is AdminIngressModelPolicy:
        selected = [bundle.ingress_model]
    else:
        return "model_workflows_unavailable"
    for workflow in selected:
        if type(workflow) not in {AdminModelWorkflowV2, AdminIngressModelPolicy}:
            return "model_workflows_unavailable"
        if workflow.provider_id != plan.provider_id:
            return "model_provider_mismatch"
        if workflow.model_id != plan.model_id:
            return "model_id_mismatch"
        if (workflow.provider_config_digest != plan.provider_config_digest
                or workflow.provider_config_ref != installed_model_config_ref(
                    plan.provider_id, plan.model_id, plan.provider_config_digest)):
            return "model_config_mismatch"
    return "none"


def observe_host_model_selection_v1(*, context, authority_profile, provider_id,
                                    installation_bundle=None, authorized_baseline=None):
    """Call on the SDK Host loop. This performs no remote catalogue/model call."""
    if provider_id == "":
        return ObservedHostModelSelectionV1(None, None, "unselected", "model_unselected")
    if not _bounded(provider_id) or not isinstance(context, Context):
        return ObservedHostModelSelectionV1(None, None, "unavailable", "model_unavailable")
    try:
        provider = context.get_provider_by_id(provider_id)
        if provider is None:
            return ObservedHostModelSelectionV1(provider_id, None, "unavailable", "model_unavailable")
        if not isinstance(provider, Provider):
            return ObservedHostModelSelectionV1(provider_id, None, "unsupported", "model_not_chat")
        meta = provider.meta()
        if not isinstance(meta, ProviderMeta) or meta.provider_type is not ProviderType.CHAT_COMPLETION:
            return ObservedHostModelSelectionV1(provider_id, None, "unsupported", "model_not_chat")
        model = provider.get_model()
        if not _bounded(model) or model != meta.model or meta.id != provider_id:
            return ObservedHostModelSelectionV1(provider_id, None, "changed", "model_changed")
        loaded = context.get_all_providers()
        matches = [item for item in loaded if isinstance(item, Provider) and item.meta().id == provider_id]
        if type(loaded) is not list or len(matches) != 1 or matches[0] is not provider:
            return ObservedHostModelSelectionV1(provider_id, model, "changed", "model_registry_changed")
        if type(provider) is not ProviderOpenAIOfficial:
            return ObservedHostModelSelectionV1(provider_id, model, "unsupported", "model_adapter_unsupported")
        if (not isinstance(provider.client, AsyncOpenAI) or isinstance(provider.client, AsyncAzureOpenAI)
                or "api_version" in provider.provider_config):
            return ObservedHostModelSelectionV1(provider_id, model, "unsupported", "model_client_unsupported")
        if type(provider.provider_config) is not dict:
            return ObservedHostModelSelectionV1(provider_id, model, "unavailable", "model_config_invalid")
        plan = HostModelSelectionV1(authority_profile, provider_id, model, canonical_digest(provider.provider_config))
        if authorized_baseline is not None and plan != authorized_baseline:
            return ObservedHostModelSelectionV1(provider_id, model, "changed", "model_changed", plan)
        reason = _installed_reason(plan, installation_bundle)
        state = "authorized" if reason == "none" else "awaiting_installation"
        return ObservedHostModelSelectionV1(provider_id, model, state, reason, plan)
    except (AttributeError, KeyError, TypeError, ValueError):
        return ObservedHostModelSelectionV1(provider_id, None, "unavailable", "model_config_invalid")
