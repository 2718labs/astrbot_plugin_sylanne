"""One Authority-admitted local model attempt and designated host observation.

This is an independent host slice. No Broker or plugin route calls it yet.
Only the paired Authority v2 response may supply the local start identity.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import asdict, dataclass

from ..authority_service.v2_model_egress_contract import (
    HostObservedModelCompletionV2, ModelEgressDraftV1, ModelEgressIntentV1,
    ModelTerminalReceiptV2,
)
from ..authority_service.v2_model_egress_wire import from_wire as model_from_wire
from ..authority_service.v2_model_result_read_contract import ModelResultReadRequestV1
from ..authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, WorkerModelResultReadV1,
)
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..graph_types import AtomKey
from ..model_broker.broker import ModelCallRequest, ProviderResponse
from ..model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST,
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
)
from ..memory_types import source_key
from ..runtime.encoding_call_binding import EncodingCallBinding, binding_to_json
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import InstallationGrantV2, canonical_serialize
from .astrbot_model_call import AstrBotModelProvider, LocalModelAdmission
from .authority_client import AuthorityClient
from .authority_profile import (
    AdminIngressModelPolicy, AdminInstallationBundle, AdminModelWorkflowV2,
)
from .first_ingress_result import OriginalFirstIngressRead


@dataclass(frozen=True, slots=True)
class FrozenEncodingEgressResult:
    """Original operation identity and a content-free terminal, if observed."""

    intent: ModelEgressIntentV1
    terminal: ModelTerminalReceiptV2 | None


def _plain_frozen(value):
    """Remove canonical storage type tags before strict model wire parsing."""
    if type(value) is dict:
        if set(value) == {"token"}:
            return asdict(AtomKey.from_token(value["token"]))
        if set(value) == {"$type", "token"}:
            return asdict(AtomKey.from_token(value["token"]))
        return {key: _plain_frozen(item) for key, item in value.items()
                if key != "$type"}
    if type(value) is list:
        return [_plain_frozen(item) for item in value]
    return value


class HostModelEgressExecutor:
    """A short-lived executor for one installed adapter and paired Authority client."""

    def __init__(self, *, authority: AuthorityClient, bundle: AdminInstallationBundle,
                 grant: InstallationGrantV2, adapter: AstrBotModelProvider) -> None:
        if (type(authority) is not AuthorityClient
                or type(bundle) is not AdminInstallationBundle
                or type(grant) is not InstallationGrantV2
                or type(adapter) is not AstrBotModelProvider
                or adapter._installation_bundle is not bundle):
            raise ValueError("trusted installed model executor binding is required")
        model = adapter._admin_model
        workflows = bundle.model_workflows
        if type(model) is AdminIngressModelPolicy:
            installed = model is bundle.ingress_model
        else:
            installed = (type(model) is AdminModelWorkflowV2
                         and workflows is not None
                         and (model is workflows.encode
                              or model is workflows.reply))
        if not installed:
            raise ValueError("executor model workflow is not installed")
        self._authority = authority
        self._bundle = bundle
        self._grant = grant
        self._adapter = adapter
        self._frozen_attempts: set[str] = set()

    def _frozen_encoding_request(
        self, binding: EncodingCallBinding, draft: ModelEgressDraftV1,
        expected_anchor: RestoreAnchor,
    ) -> ModelCallRequest:
        """Rebuild the immutable V2 request; Authority still checks graph truth."""
        if (type(binding) is not EncodingCallBinding
                or type(draft) is not ModelEgressDraftV1
                or type(expected_anchor) is not RestoreAnchor
                or type(self._adapter._admin_model) is not AdminModelWorkflowV2):
            raise ValueError("V2 encoding binding, draft and anchor are required")
        binding_to_json(binding)
        frozen = binding.request
        model = self._adapter._admin_model
        policy = self._bundle.installation_policy
        if (frozen.get("schema") != "sylanne.first-ingress-encoding-call.v2"
                or model is not self._bundle.model_workflows.encode
                or model.work_kind != "d06.encode_source"
                or model.template_version != FIRST_INGRESS_ENCODING_TEMPLATE_VERSION
                or binding.namespace != policy.namespace
                or draft.namespace != policy.authority_namespace
                or draft.authority_id != self._grant.authority_id
                or expected_anchor.authority_id != draft.authority_id
                or expected_anchor.namespace != draft.namespace):
            raise ValueError("installed V2 encoding authority differs")
        fields = (
            "envelope", "call_id", "provider_id", "model_id",
            "required_capabilities", "privacy_tier", "prompt_template_digest",
            "payload", "timeout_seconds", "max_output_tokens",
        )
        request = model_from_wire(
            {name: _plain_frozen(frozen[name]) for name in fields}, ModelCallRequest)
        authority = request.envelope.authority
        guard = request.envelope.version_guard
        source_token = source_key(*binding.namespace.as_tuple, binding.source_id).token
        if (request.digest != binding.model_request_digest
                or request.call_id != binding.call_id
                or request.identity.operation_id != frozen["acquire_operation_id"]
                or request.identity.phase != "encode"
                or request.envelope.input_refs != (source_token,)
                or request.envelope.source_qualification.source_refs != (source_token,)
                or request.prompt_template_digest != FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST
                or frozen["prompt_template_version"] != FIRST_INGRESS_ENCODING_TEMPLATE_VERSION
                or frozen["provider_config_ref"] != model.provider_config_ref
                or frozen["provider_config_digest"] != model.provider_config_digest
                or authority.namespace != binding.namespace
                or authority.issuer_domain != "d11"
                or authority.purpose != "consolidation"
                or authority.worker_fence != frozen["worker_fence"]
                or request.envelope.parent_budget_lease_ref != binding.budget_lease_id
                or (draft.subject, draft.operation_id, draft.call_id,
                    draft.request_digest, draft.job_id, draft.worker_fence)
                != (authority.actor, request.identity.operation_id, request.call_id,
                    request.digest, binding.job_id, frozen["worker_fence"])
                or draft.source_refs != (binding.source_id,)
                or draft.source_revisions != ((binding.source_id, binding.source_revision),)
                or draft.access_revisions != ((binding.source_id, binding.access_revision),)
                or (draft.access_epoch, draft.delete_epoch)
                != (guard.access_epoch, guard.delete_epoch)
                or draft.authority_activation_generation != authority.activation_generation
                or (draft.budget_lease_id, draft.budget_reservation_operation_id)
                != (binding.budget_lease_id, binding.budget_reservation_operation_id)
                or (draft.provider_id, draft.model_id, draft.provider_config_digest,
                    draft.max_output_tokens)
                != (request.provider_id, request.model_id, model.provider_config_digest,
                    request.max_output_tokens)
                or not self._adapter._request_allowed(request)):
            raise ValueError("frozen encoding request differs from original model draft")
        return request

    async def execute_frozen_encoding_once(
        self, *, binding: EncodingCallBinding, draft: ModelEgressDraftV1,
        expected_anchor: RestoreAnchor,
    ) -> FrozenEncodingEgressResult | None:
        """Prepare and spend one exact V2 call; uncertainty remains HOLD.

        Re-entry in this executor never reissues prepare or admission. Across
        host restarts the Authority's original operation/terminal must be read
        before any new orchestration decision.
        """
        try:
            request = self._frozen_encoding_request(binding, draft, expected_anchor)
        except (KeyError, TypeError, ValueError):
            return None
        if binding.call_id in self._frozen_attempts:
            return None
        self._frozen_attempts.add(binding.call_id)
        try:
            record, permit = await self._authority.model_prepare_fenced_v1(
                self._bundle, self._grant, draft=draft,
                expected_anchor=expected_anchor)
        except Exception:
            return None
        intent = record.intent
        if (ModelEgressDraftV1.from_intent(intent) != draft
                or permit.operation != "model_egress"
                or permit.operation_id != draft.operation_id
                or permit.pinned_anchor != expected_anchor):
            return FrozenEncodingEgressResult(intent, None)
        if record.state != "prepared":
            return FrozenEncodingEgressResult(intent, None)
        terminal = await self.execute_once(
            intent=intent, expected_anchor=expected_anchor, request=request)
        if terminal is None:
            terminal = await self.recover_original_terminal(intent)
        return FrozenEncodingEgressResult(intent, terminal)

    async def recover_original_terminal(
        self, intent: ModelEgressIntentV1,
    ) -> ModelTerminalReceiptV2 | None:
        """Read original Authority facts after an uncertain dispatch or finish."""
        if type(intent) is not ModelEgressIntentV1:
            return None
        try:
            record, permit, admission, receipt = (
                await self._authority.model_terminal_fact_v2(
                    self._bundle, self._grant, intent=intent))
        except Exception:
            return None
        if (record.intent != intent
                or permit.operation_id != intent.operation_id
                or admission.call_id != intent.call_id
                or receipt is None
                or record.state != "observed"):
            return None
        return receipt

    async def read_original_for_owner(
        self, *, binding: EncodingCallBinding, draft: ModelEgressDraftV1,
        expected_anchor: RestoreAnchor, intent: ModelEgressIntentV1,
        owner_actor_id: str, owner_session_request: OwnerSessionLoginRequestV1,
        owner_session_token: str,
    ) -> OriginalFirstIngressRead | None:
        """Read the original cost fact, then Owner-authorized content once.

        The binding/draft/anchor must come from the current W01 job read. An
        uncertain terminal or Owner read remains HOLD. No model admission or
        provider call occurs on this path.
        """
        if (type(intent) is not ModelEgressIntentV1
                or type(owner_session_request) is not OwnerSessionLoginRequestV1
                or type(owner_session_token) is not str or not owner_session_token):
            return None
        try:
            request = self._frozen_encoding_request(binding, draft, expected_anchor)
        except (KeyError, TypeError, ValueError):
            return None
        authority = request.envelope.authority
        if (ModelEgressDraftV1.from_intent(intent) != draft
                or intent.call_id != request.call_id
                or intent.request_digest != request.digest
                or intent.operation_id != request.identity.operation_id
                or intent.source_refs != (binding.source_id,)
                or intent.source_revisions != ((binding.source_id, binding.source_revision),)
                or intent.access_revisions != ((binding.source_id, binding.access_revision),)
                or len(authority.audience) != 1
                or owner_session_request.authority_id != intent.authority_id
                or owner_session_request.authority_namespace != intent.namespace
                or owner_session_request.installation_id != self._grant.installation_id):
            return None
        try:
            record, permit, admission, terminal = (
                await self._authority.model_terminal_fact_v2(
                    self._bundle, self._grant, intent=intent))
        except Exception:
            return None
        if (record.intent != intent or record.state != "observed"
                or terminal is None
                or permit.operation != "model_egress"
                or permit.operation_id != intent.operation_id
                or (admission.authority_id, admission.namespace,
                    admission.operation_id, admission.call_id,
                    admission.request_digest, admission.installation_id) !=
                   (intent.authority_id, intent.namespace, intent.operation_id,
                    intent.call_id, intent.request_digest,
                    self._grant.installation_id)
                or (terminal.admission_id, terminal.call_id,
                    terminal.request_digest, terminal.installation_id,
                    terminal.observation_digest) !=
                   (admission.admission_id, intent.call_id,
                    intent.request_digest, self._grant.installation_id,
                    record.observation_digest)):
            return None
        operation_key = hashlib.sha256((
            intent.operation_id + ":" + intent.call_id + ":"
            + owner_actor_id + ":" + owner_session_request.credential_id
            + ":" + owner_session_token
        ).encode("utf-8")).hexdigest()
        try:
            read_request = ModelResultReadRequestV1(
                intent.authority_id, intent.namespace, binding.namespace,
                self._grant.installation_id, owner_actor_id, owner_session_request,
                "workbench_view", authority.purpose, tuple(authority.audience),
                intent.call_id, "first-ingress-result-read:" + operation_key)
        except (TypeError, ValueError):
            return None
        try:
            read = await self._authority.model_result_read_v1(
                self._bundle, self._grant, read_request=read_request,
                owner_session_token=owner_session_token)
        except Exception:
            # A lost read reply cannot be treated as content proof. Closing
            # its original fence is safe and never calls the model again.
            try:
                await self._authority.model_result_read_recover_finish_v1(
                    self._bundle, self._grant, read_request=read_request)
            except Exception:
                pass
            return None
        observation = read.observation
        if (read.call_id != intent.call_id
                or read.terminal_receipt != terminal
                or record.usage != observation.usage
                or record.cost != observation.cost
                or (observation.authority_id, observation.namespace,
                    observation.subject, observation.operation_id,
                    observation.call_id, observation.request_digest) !=
                   (intent.authority_id, intent.namespace, intent.subject,
                    intent.operation_id, intent.call_id, intent.request_digest)):
            return None
        return OriginalFirstIngressRead(
            intent, record, permit, admission, terminal, read_request, read)

    async def read_original_for_worker(
        self, *, read_request: WorkerModelResultReadRequestV1,
        intent: ModelEgressIntentV1, terminal: ModelTerminalReceiptV2,
    ) -> WorkerModelResultReadV1 | None:
        """Read the original completed body with the installed worker identity.

        An uncertain read response is closed by its original read attempt and
        remains HOLD; it never retries the model or treats finish as content.
        """
        if (type(read_request) is not WorkerModelResultReadRequestV1
                or type(intent) is not ModelEgressIntentV1
                or type(terminal) is not ModelTerminalReceiptV2
                or (read_request.authority_id, read_request.authority_namespace,
                    read_request.namespace, read_request.installation_id,
                    read_request.job_id, read_request.acquire_operation_id,
                    read_request.call_id, read_request.model_request_digest) != (
                    intent.authority_id, intent.namespace,
                    self._bundle.installation_policy.namespace,
                    self._grant.installation_id, intent.job_id,
                    intent.operation_id, intent.call_id, intent.request_digest)):
            return None
        try:
            record, permit, admission, original_terminal = (
                await self._authority.model_terminal_fact_v2(
                    self._bundle, self._grant, intent=intent))
        except Exception:
            return None
        if (record.intent != intent or record.state != "observed"
                or original_terminal != terminal
                or permit.operation_id != intent.operation_id
                or admission.installation_id != self._grant.installation_id):
            return None
        try:
            read = await self._authority.worker_model_result_read_v1(
                self._bundle, self._grant, read_request=read_request)
        except Exception:
            try:
                await self._authority.worker_model_result_recover_finish_v1(
                    self._bundle, self._grant, read_request=read_request)
            except Exception:
                pass
            return None
        if (read.request != read_request
                or read.terminal_receipt != terminal
                or read.observation.digest != record.observation_digest
                or read.observation.usage != record.usage
                or read.observation.cost != record.cost):
            return None
        return read

    async def execute_once(
        self, *, intent: ModelEgressIntentV1, expected_anchor: RestoreAnchor,
        request: ModelCallRequest,
    ) -> ModelTerminalReceiptV2 | None:
        """Return a durable content-free receipt, or HOLD without another send.

        An uncertain admit reply, non-completed local result, cancelled waiter,
        changed installation or uncertain completion reply has no retry path.
        """
        if (type(intent) is not ModelEgressIntentV1
                or type(expected_anchor) is not RestoreAnchor
                or type(request) is not ModelCallRequest):
            return None
        model = self._adapter._admin_model
        if type(model) is AdminModelWorkflowV2:
            if (intent.request_digest != request.digest
                    or intent.operation_id != request.identity.operation_id
                    or intent.call_id != request.call_id
                    or intent.provider_id != model.provider_id
                    or intent.model_id != model.model_id
                    or intent.provider_config_digest != model.provider_config_digest
                    or intent.max_output_tokens != request.max_output_tokens
                    or intent.budget_lease_id
                       != request.envelope.parent_budget_lease_ref
                    or any(amount > model.quote_ceiling.get(dimension, 0)
                           for dimension, amount in intent.budget_ceiling)
                    or not self._adapter._request_allowed(request)):
                return None
        try:
            record, permit, admission = await self._authority.model_admit_dispatch_once_v2(
                self._bundle, self._grant, intent=intent,
                expected_anchor=expected_anchor, model_request=request,
                host_incarnation=self._adapter.host_incarnation)
        except Exception:
            return None
        if (record.state != "dispatch_started" or record.intent != intent
                or permit.operation != "model_egress"
                or permit.pinned_anchor != expected_anchor
                or admission.host_incarnation != self._adapter.host_incarnation
                or admission.request_digest != request.digest
                or admission.provider_config_digest !=
                   self._adapter._admin_model.provider_config_digest):
            return None
        # LocalModelAdmission is not itself an Authority credential. Its values
        # are minted here only after the paired v2 client verified the reply.
        try:
            local = LocalModelAdmission(
                admission.admission_id, admission.host_incarnation,
                admission.call_id, admission.request_digest,
                admission.provider_config_digest)
            response = await self._adapter.invoke_admitted(
                request, local, asyncio.Event())
        except Exception:
            return None
        if (type(response) is not ProviderResponse
                or response.status != "completed" or response.result is None):
            return None
        try:
            report = HostObservedModelCompletionV2(
                admission.admission_id, admission.host_incarnation,
                intent.call_id, intent.request_digest, intent.provider_id,
                intent.model_id, intent.provider_config_digest,
                canonical_serialize(dict(response.result)),
                tuple(sorted(response.usage.items())),
                tuple(sorted(response.cost.items())), response.provider_call_ref)
            completed, terminal_permit, receipt = (
                await self._authority.model_complete_observed_v2(
                    self._bundle, self._grant, intent=intent,
                    expected_anchor=expected_anchor, admission=admission,
                    report=report))
        except Exception:
            return None
        if (completed.state != "observed" or completed.intent != intent
                or terminal_permit != permit
                or receipt.report_digest != report.digest):
            return None
        return receipt


__all__ = ("HostModelEgressExecutor", "FrozenEncodingEgressResult")
