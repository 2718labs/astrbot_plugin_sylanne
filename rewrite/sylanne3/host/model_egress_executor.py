"""One Authority-admitted local model attempt and designated host observation.

The installed first-ingress route uses this executor. Only a paired Authority
response may supply the local start identity; recovery reads the original fact.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import asdict, dataclass, replace

from ..authority_service.v2_model_egress_contract import (
    HostObservedModelCompletionV2, ModelEgressDraftV1, ModelEgressIntentV1,
    ModelTerminalReceiptV2,
)
from ..authority_service.v2_model_egress_wire import from_wire as model_from_wire
from ..authority_service.v2_model_result_read_contract import ModelResultReadRequestV1
from ..authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, WorkerModelResultReadV1,
    d13_paid_read_attempt_id_v1,
)
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..graph_types import AtomKey, GraphVersion
from ..model_broker.broker import ModelCallRequest, ProviderResponse
from ..model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST,
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
)
from ..model_broker.d13_precompression import (
    FrozenD13PrecompressionRequestV1,
    compile_untrusted_d13_candidate_v1,
    issue_unadmitted_d13_model_request_v1,
    parse_d13_precompression_output_v1,
)
from ..domains.d13.paid_lifecycle import D13PaidOriginalBindingV1
from ..runtime.d13_paid_intent_original_v1 import (
    D13PaidCallOriginalV1, D13PaidIntentOriginalV1,
)
from ..authority_service.v2_model_egress_wire import to_wire as model_to_wire
from ..memory_types import source_key
from ..runtime.encoding_call_binding import (
    CommittedEncodingBaselineV1, EncodingCallBinding, EncodingCallConflict,
    binding_to_json,
)
from ..runtime.c02_cost_settlement import C02OriginalIntentLookupV1
from ..runtime.first_ingress_c02_identity import (
    first_ingress_c02_consumer_operation_id_v1,
)
from ..runtime.first_ingress_recovery import FirstIngressRecoveryItemV1
from ..runtime.original_model_result_context import OriginalModelResultContextV1
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import (
    CommandEnvelope, CompressedTurnBlockV2, InstallationGrantV2,
    canonical_digest, canonical_serialize,
)
from .astrbot_model_call import AstrBotModelProvider, LocalModelAdmission
from ..authority_service.natural_original_binding_verifier import (
    NaturalOriginalCallIdentityReadV2,
)
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


@dataclass(frozen=True, slots=True)
class FrozenNaturalEgressResultV2:
    """An original Authority intent with an observed terminal, or HOLD."""

    original: NaturalOriginalCallIdentityReadV2
    intent: ModelEgressIntentV1
    terminal: ModelTerminalReceiptV2 | None


@dataclass(frozen=True, slots=True)
class FrozenD13EgressResultV1:
    """One Authority original and observed terminal, or an unresolved attempt."""

    original: D13PaidIntentOriginalV1
    intent: ModelEgressIntentV1
    terminal: ModelTerminalReceiptV2 | None


@dataclass(frozen=True, slots=True)
class FrozenD13CandidateReadV1:
    """Authority-read provider bytes and source-checked, unadopted candidate."""

    read_attempt_id: str
    observation_digest: str
    output_digest: str | None
    candidate: CompressedTurnBlockV2 | None
    usage: tuple[tuple[str, int], ...]
    cost: tuple[tuple[str, int], ...]


def d13_paid_worker_read_request_v1(
    original: D13PaidIntentOriginalV1,
    call_original: D13PaidCallOriginalV1,
    intent: ModelEgressIntentV1,
) -> WorkerModelResultReadRequestV1:
    """Derive the first original D13 read identity; never mint a second call."""
    if (type(original) is not D13PaidIntentOriginalV1
            or type(call_original) is not D13PaidCallOriginalV1
            or type(intent) is not ModelEgressIntentV1
            or (call_original.namespace, call_original.job_ref,
                call_original.binding_digest,
                call_original.request_digest) != (
                    original.namespace, original.binding.job_ref,
                    original.binding.binding_digest, intent.request_digest)
            or intent.operation_id != original.binding.original_operation_id
            or intent.call_id != original.binding.call_id):
        raise ValueError("D13 worker read differs from original paid call")
    consumer = "d13-adopt:" + original.binding.binding_digest
    return WorkerModelResultReadRequestV1(
        intent.authority_id, intent.namespace, original.namespace,
        original.binding.installation_id, original.binding.job_ref,
        intent.operation_id, original.budget_operation_id,
        original.binding.call_id, original.binding.binding_digest,
        call_original.request_digest, consumer,
        d13_paid_read_attempt_id_v1(consumer, 1),
        "d13_precompress_paid",
    )


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
                              or model is workflows.reply
                              or model is workflows.context_reply
                              or model is workflows.natural_generation
                              or model is workflows.natural_review
                              or model is workflows.appraisal
                              or model is workflows.d07_cognition))
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
        """Rebuild the frozen V2/V3 request; Authority still checks graph truth."""
        if (type(binding) is not EncodingCallBinding
                or type(draft) is not ModelEgressDraftV1
                or type(expected_anchor) is not RestoreAnchor
                or type(self._adapter._admin_model) is not AdminModelWorkflowV2):
            raise ValueError("frozen encoding binding, draft and anchor are required")
        binding_to_json(binding)
        frozen = binding.request
        model = self._adapter._admin_model
        policy = self._bundle.installation_policy
        schema = frozen.get("schema")
        if (schema not in {"sylanne.first-ingress-encoding-call.v2",
                           "sylanne.first-ingress-encoding-call.v3"}
                or model is not self._bundle.model_workflows.encode
                or model.work_kind != "d06.encode_source"
                or model.template_version != FIRST_INGRESS_ENCODING_TEMPLATE_VERSION
                or binding.namespace != policy.namespace
                or draft.namespace != policy.authority_namespace
                or draft.authority_id != self._grant.authority_id
                or expected_anchor.authority_id != draft.authority_id
                or expected_anchor.namespace != draft.namespace):
            raise ValueError("installed encoding authority differs")
        fields = (
            "envelope", "call_id", "provider_id", "model_id",
            "required_capabilities", "privacy_tier", "prompt_template_digest",
            "payload", "timeout_seconds", "max_output_tokens",
        )
        request = model_from_wire(
            {name: _plain_frozen(frozen[name]) for name in fields}, ModelCallRequest)
        if schema == "sylanne.first-ingress-encoding-call.v3":
            baseline = CommittedEncodingBaselineV1(**frozen["baseline"])
            baseline_version = GraphVersion(
                AtomKey.from_token(baseline.baseline_ref),
                baseline.baseline_revision,
            )
            if request.envelope.version_guard.read_versions.count(baseline_version) != 1:
                raise ValueError("frozen D04 baseline guard differs")
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
        """Prepare and spend one exact frozen call; uncertainty remains HOLD.

        Re-entry in this executor never reissues prepare or admission. Across
        host restarts the Authority's original operation/terminal must be read
        before any new orchestration decision.
        """
        try:
            request = self._frozen_encoding_request(binding, draft, expected_anchor)
        except (EncodingCallConflict, KeyError, TypeError, ValueError):
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

    async def execute_frozen_natural_once(
        self, *, original: NaturalOriginalCallIdentityReadV2,
        draft: ModelEgressDraftV1, expected_anchor: RestoreAnchor,
    ) -> FrozenNaturalEgressResultV2 | None:
        """Use one graph draft and original binding; uncertain calls never restart.

        This entry requires W01's current graph draft. The original binding
        alone remains HOLD and cannot initiate an Authority prepare.
        """
        if (type(original) is not NaturalOriginalCallIdentityReadV2
                or type(draft) is not ModelEgressDraftV1
                or type(expected_anchor) is not RestoreAnchor):
            return None
        model = self._adapter._admin_model
        workflows = self._bundle.model_workflows
        if (type(model) is not AdminModelWorkflowV2 or workflows is None
                or (model is not workflows.natural_generation
                    and model is not workflows.natural_review)):
            return None
        stage = ("generation" if model is workflows.natural_generation
                 else "review")
        seal, request = original.seal, original.request
        binding_digest = canonical_digest({
            "original_seal_digest": canonical_digest(asdict(seal)),
            "model_call_request_digest": request.digest,
            "worker_fence": original.worker_fence,
        })
        if (original.stage != stage
                or original.status != "original_call_binding_only_hold"
                or not self._adapter._request_allowed(request)
                or (draft.authority_id, draft.namespace) != (
                    self._grant.authority_id,
                    self._bundle.installation_policy.authority_namespace)
                or (expected_anchor.authority_id, expected_anchor.namespace)
                   != (draft.authority_id, draft.namespace)
                or (draft.subject, draft.job_id, draft.operation_id,
                    draft.acquire_operation_id, draft.call_id,
                    draft.request_digest, draft.worker_fence,
                    draft.binding_digest,
                    draft.budget_reservation_operation_id,
                    draft.budget_lease_id, draft.provider_id, draft.model_id,
                    draft.provider_config_digest, draft.max_output_tokens)
                   != (request.envelope.authority.actor, seal.job_id,
                       seal.acquire_operation_id, seal.acquire_operation_id,
                       seal.call_id, original.typed_request_digest,
                       original.worker_fence, binding_digest,
                       seal.reservation_operation_id,
                       seal.parent_budget_lease_id, model.provider_id,
                       model.model_id, model.provider_config_digest,
                       request.max_output_tokens)
                or seal.installation_id != self._grant.installation_id
                or seal.namespace != self._bundle.installation_policy.namespace
                or request.digest != original.typed_request_digest
                or request.call_id in self._frozen_attempts):
            return None
        self._frozen_attempts.add(request.call_id)
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
            return FrozenNaturalEgressResultV2(original, intent, None)
        terminal = await self.recover_original_terminal(intent)
        if terminal is not None:
            return FrozenNaturalEgressResultV2(original, intent, terminal)
        if record.state != "prepared":
            return FrozenNaturalEgressResultV2(original, intent, None)
        try:
            recovered, recovered_permit = (
                await self._authority.model_recover_fenced_v1(
                    self._bundle, self._grant, intent=intent))
        except Exception:
            return FrozenNaturalEgressResultV2(original, intent, None)
        if (recovered != record or recovered_permit != permit
                or recovered.state != "prepared"):
            return FrozenNaturalEgressResultV2(original, intent, None)
        terminal = await self.execute_once(
            intent=intent, expected_anchor=expected_anchor, request=request,
            natural_original=original)
        if terminal is None:
            terminal = await self.recover_original_terminal(intent)
        return FrozenNaturalEgressResultV2(original, intent, terminal)

    async def execute_frozen_d13_once(
        self, *, original: D13PaidIntentOriginalV1,
        call_original: D13PaidCallOriginalV1,
        frozen: FrozenD13PrecompressionRequestV1,
        envelope: CommandEnvelope, draft: ModelEgressDraftV1,
        expected_anchor: RestoreAnchor,
    ) -> FrozenD13EgressResultV1 | None:
        """Spend one W01 authenticated D13 original through normal Authority egress.

        W01 supplies the current signed quote, reservation and source-bound
        original. A failed or uncertain prepare stays unresolved for recovery;
        this method never sends the same call twice.
        """
        model = self._adapter._admin_model
        workflows = self._bundle.model_workflows
        if (type(original) is not D13PaidIntentOriginalV1
                or type(call_original) is not D13PaidCallOriginalV1
                or type(frozen) is not FrozenD13PrecompressionRequestV1
                or type(envelope) is not CommandEnvelope
                or type(draft) is not ModelEgressDraftV1
                or type(expected_anchor) is not RestoreAnchor
                or type(model) is not AdminModelWorkflowV2
                or workflows is None or model is not workflows.reply):
            return None
        binding: D13PaidOriginalBindingV1 = original.binding
        if (original.namespace != self._bundle.installation_policy.namespace
                or frozen.installation.installation_id != self._grant.installation_id
                or frozen.installation.provider_id != model.provider_id
                or frozen.installation.model_id != model.model_id
                or frozen.installation.provider_config_digest
                   != model.provider_config_digest
                or original.frozen_json != canonical_serialize(asdict(frozen))
                or binding.frozen_input_digest != frozen.digest
                or binding.wire_digest != frozen.wire_digest
                or binding.read_closure_digest != frozen.read_closure_digest
                or binding.original_operation_id != envelope.identity.operation_id
                or binding.job_ref != frozen.plan.job_ref
                or (call_original.namespace, call_original.job_ref,
                    call_original.binding_digest,
                    call_original.intent_original_digest) != (
                        original.namespace, binding.job_ref,
                        binding.binding_digest, original.original_digest)
                or binding.call_id in self._frozen_attempts):
            return None
        try:
            request = issue_unadmitted_d13_model_request_v1(
                envelope, frozen, call_id=binding.call_id,
                timeout_seconds=model.timeout_seconds,
                privacy_tier=model.privacy_tier)
            if not self._adapter._host_loop.is_running():
                return None
            selected_call = self._adapter.preflight_d13_precompression_v1(frozen)
            if asyncio.get_running_loop() is self._adapter._host_loop:
                selected = await selected_call
            else:
                selected = await asyncio.wait_for(
                    asyncio.wrap_future(asyncio.run_coroutine_threadsafe(
                        selected_call, self._adapter._host_loop)), timeout=5)
        except Exception:
            return None
        if (selected.status != "ready"
                or call_original.request_digest != request.digest
                or call_original.request_json != canonical_serialize(
                    model_to_wire(request))
                or call_original.worker_fence != envelope.authority.worker_fence
                or request.digest != draft.request_digest
                or not self._adapter._request_allowed(request)
                or (draft.authority_id, draft.namespace) != (
                    self._grant.authority_id,
                    self._bundle.installation_policy.authority_namespace)
                or (expected_anchor.authority_id, expected_anchor.namespace)
                   != (draft.authority_id, draft.namespace)
                or (draft.subject, draft.job_id, draft.operation_id,
                    draft.call_id, draft.worker_fence, draft.binding_digest,
                    draft.budget_lease_id, draft.budget_reservation_operation_id,
                    draft.budget_reservation_digest, draft.budget_ceiling,
                    draft.provider_id, draft.model_id,
                    draft.provider_config_digest, draft.max_output_tokens)
                   != (envelope.authority.actor, binding.job_ref,
                       binding.original_operation_id, binding.call_id,
                       envelope.authority.worker_fence,
                       binding.binding_digest, envelope.parent_budget_lease_ref,
                       original.budget_operation_id,
                       original.budget_reservation_digest,
                       tuple(sorted(original.ceiling.items())),
                       model.provider_id, model.model_id,
                       model.provider_config_digest, model.max_output_tokens)):
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
            return FrozenD13EgressResultV1(original, intent, None)
        terminal = await self.recover_original_terminal(intent)
        if terminal is None and record.state == "prepared":
            terminal = await self.execute_once(
                intent=intent, expected_anchor=expected_anchor, request=request)
            if terminal is None:
                terminal = await self.recover_original_terminal(intent)
        return FrozenD13EgressResultV1(original, intent, terminal)

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

    async def recover_observed_frozen_encoding(
        self, *, context: OriginalModelResultContextV1,
        original: FirstIngressRecoveryItemV1,
    ) -> FrozenEncodingEgressResult | None:
        """Resume only an Authority-observed original call; never admit/send."""
        if (type(original) is not FirstIngressRecoveryItemV1
                or type(context) is not OriginalModelResultContextV1
                or original.recovery_state != "original_fence"
                or original.namespace != self._bundle.installation_policy.namespace
                or original.installation_id != self._grant.installation_id
                or (original.namespace, original.installation_id,
                    original.job_id, original.acquire_operation_id,
                    original.original_operation_id, original.call_id,
                    original.binding_digest, original.model_request_digest,
                    original.original_worker_actor,
                    original.original_worker_fence,
                    original.original_worker_lease_expires_utc) != (
                    context.namespace, context.installation_id,
                    context.job_id, context.acquire_operation_id,
                    context.original_operation_id, context.call_id,
                    context.binding_digest, context.model_request_digest,
                    context.worker_actor, context.worker_fence,
                    context.worker_lease_expires_utc)
                or original.consumer_operation_id !=
                   first_ingress_c02_consumer_operation_id_v1(
                       namespace=context.namespace,
                       authority_id=context.authority_id,
                       authority_namespace=context.authority_namespace,
                       installation_id=context.installation_id,
                       job_id=context.job_id,
                       acquire_operation_id=context.acquire_operation_id,
                       original_operation_id=context.original_operation_id,
                       call_id=context.call_id,
                       binding_digest=context.binding_digest,
                       model_request_digest=context.model_request_digest)):
            return None
        if (context.authority_id != self._grant.authority_id
                or context.authority_namespace !=
                   self._bundle.installation_policy.authority_namespace):
            return None
        lookup = C02OriginalIntentLookupV1(
            context.namespace, context.authority_id,
            context.authority_namespace, context.installation_id,
            context.job_id, context.original_operation_id,
            context.acquire_operation_id, context.call_id,
            context.binding_digest, context.model_request_digest,
            original.consumer_operation_id)
        try:
            intent = await self._authority.model_original_intent_lookup_v1(
                self._bundle, self._grant, lookup=lookup)
        except Exception:
            return None
        if (type(intent) is not ModelEgressIntentV1
                or (intent.authority_id, intent.namespace,
                    intent.job_id, intent.operation_id,
                    intent.acquire_operation_id, intent.call_id,
                    intent.binding_digest, intent.request_digest,
                    intent.budget_reservation_operation_id,
                    intent.subject, intent.worker_fence,
                    intent.source_refs, intent.source_revisions,
                    intent.access_revisions) != (
                    context.authority_id, context.authority_namespace,
                    context.job_id, context.acquire_operation_id,
                    context.acquire_operation_id, context.call_id,
                    context.binding_digest, context.model_request_digest,
                    context.original_operation_id,
                    context.worker_actor, context.worker_fence,
                    (context.source_id,),
                    ((context.source_id, context.source_revision),),
                    ((context.source_id, context.access_revision),))
                or intent.anchor_digest != canonical_digest(asdict(context.anchor))):
            return None
        return FrozenEncodingEgressResult(
            intent, await self.recover_original_terminal(intent))

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
        except (EncodingCallConflict, KeyError, TypeError, ValueError):
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

    async def read_frozen_d13_candidate_once(
        self, *, original: D13PaidIntentOriginalV1,
        call_original: D13PaidCallOriginalV1,
        frozen: FrozenD13PrecompressionRequestV1,
        intent: ModelEgressIntentV1,
        terminal: ModelTerminalReceiptV2,
        read_request: WorkerModelResultReadRequestV1,
    ) -> FrozenD13CandidateReadV1 | None:
        """Read one paid result through Authority and compile exact excerpts.

        Invalid model JSON remains a charged terminal with no candidate. W01
        settles the measured usage before any standby graph transition.
        """
        if (type(original) is not D13PaidIntentOriginalV1
                or type(call_original) is not D13PaidCallOriginalV1
                or type(frozen) is not FrozenD13PrecompressionRequestV1
                or type(intent) is not ModelEgressIntentV1
                or type(terminal) is not ModelTerminalReceiptV2
                or type(read_request) is not WorkerModelResultReadRequestV1
                or read_request.purpose != "d13_precompress_paid"
                or (read_request.namespace, read_request.job_id,
                    read_request.call_id, read_request.binding_digest,
                    read_request.model_request_digest) != (
                        original.namespace, original.binding.job_ref,
                        original.binding.call_id,
                        original.binding.binding_digest,
                        call_original.request_digest)
                or (call_original.intent_original_digest,
                    call_original.binding_digest) != (
                        original.original_digest,
                        original.binding.binding_digest)
                or intent.request_digest != call_original.request_digest):
            return None
        read = await self.read_original_for_worker(
            read_request=read_request, intent=intent, terminal=terminal)
        if read is None:
            return None
        observation = read.observation
        candidate = None
        output_digest = None
        if observation.result_json is not None:
            try:
                result = json.loads(observation.result_json)
                if (type(result) is dict and set(result) == {"text"}
                        and type(result["text"]) is str):
                    parsed = parse_d13_precompression_output_v1(
                        result["text"], frozen)
                    output_digest = parsed.output_digest
                    candidate = compile_untrusted_d13_candidate_v1(
                        frozen, parsed)
            except (TypeError, ValueError):
                pass
        return FrozenD13CandidateReadV1(
            read_request.read_attempt_id, observation.digest,
            output_digest, candidate, observation.usage, observation.cost)

    async def select_original_worker_read_attempt(
        self, first_request: WorkerModelResultReadRequestV1,
    ) -> WorkerModelResultReadRequestV1 | None:
        """Choose a current read identity without admitting or sending a model call."""
        if type(first_request) is not WorkerModelResultReadRequestV1:
            return None
        try:
            selected = await self._authority.worker_model_result_select_attempt_v1(
                self._bundle, self._grant, first_request=first_request)
        except Exception:
            return None
        if (type(selected) is not WorkerModelResultReadRequestV1
                or replace(selected, read_attempt_id=first_request.read_attempt_id)
                   != first_request):
            return None
        return selected

    async def execute_once(
        self, *, intent: ModelEgressIntentV1, expected_anchor: RestoreAnchor,
        request: ModelCallRequest,
        natural_original: NaturalOriginalCallIdentityReadV2 | None = None,
        appraisal_original=None,
        d07_original=None,
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
            workflows = self._bundle.model_workflows
            if model is workflows.d07_cognition:
                from ..runtime.d07_execution_v1 import D07PreparedExecutionV1
                from ..model_broker.d07_cognition_v1 import thaw_d07_cognition_request_v1
                if type(d07_original) is not D07PreparedExecutionV1:
                    return None
                frozen = thaw_d07_cognition_request_v1(json.loads(d07_original.frozen_json))
                if (d07_original.namespace != self._bundle.installation_policy.namespace
                        or d07_original.activation_generation != intent.authority_activation_generation
                        or d07_original.digest != intent.binding_digest
                        or dict(request.payload) != json.loads(frozen.canonical_wire)
                        or (d07_original.job_id, d07_original.call_id, d07_original.operation_id,
                            d07_original.reservation_digest) !=
                           (intent.job_id, intent.call_id, intent.budget_reservation_operation_id,
                            intent.budget_reservation_digest)
                        or model.work_kind != "d07.cognition"):
                    return None
            if model is workflows.appraisal:
                from ..runtime.d04_appraisal_driver_v3 import D04AppraisalOriginalV3
                if (type(appraisal_original) is not D04AppraisalOriginalV3
                        or appraisal_original.namespace != self._bundle.installation_policy.namespace
                        or appraisal_original.activation_generation != intent.authority_activation_generation
                        or appraisal_original.model_request_digest != canonical_digest({
                            "template_digest": request.prompt_template_digest,
                            "installation_id": self._grant.installation_id,
                            "provider_config_ref": model.provider_config_ref,
                            "provider_config_digest": model.provider_config_digest,
                            "provider_wire_digest": __import__("hashlib").sha256(canonical_serialize(dict(request.payload)).encode()).hexdigest()})
                        or appraisal_original.digest != intent.binding_digest
                        or (appraisal_original.job_id, appraisal_original.call_id,
                            appraisal_original.operation_id, appraisal_original.reservation_digest) !=
                           (intent.job_id, intent.call_id, intent.budget_reservation_operation_id,
                            intent.budget_reservation_digest)
                        or model.work_kind != "d04.appraisal"):
                    return None
                # Authority independently reopens the pinned Graph and requires
                # the sealed original/current worker, signed quote and source
                # closure before the only provider admission below.
            if model is workflows.natural_generation or model is workflows.natural_review:
                stage = ("generation" if model is workflows.natural_generation
                         else "review")
                if type(natural_original) is not NaturalOriginalCallIdentityReadV2:
                    return None
                seal = natural_original.seal
                if (natural_original.stage != stage
                        or natural_original.status != "original_call_binding_only_hold"
                        or natural_original.request != request
                        or natural_original.typed_request_digest != request.digest
                        or seal.namespace != self._bundle.installation_policy.namespace
                        or seal.installation_id != self._grant.installation_id
                        or seal.provider_config_digest != model.provider_config_digest
                        or (intent.job_id, intent.operation_id,
                            intent.acquire_operation_id, intent.call_id,
                            intent.request_digest, intent.worker_fence,
                            intent.budget_reservation_operation_id,
                            intent.budget_lease_id) != (
                            seal.job_id, seal.acquire_operation_id,
                            seal.acquire_operation_id, seal.call_id,
                            natural_original.typed_request_digest,
                            natural_original.worker_fence,
                            seal.reservation_operation_id,
                            seal.parent_budget_lease_id)):
                    return None
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


__all__ = ("HostModelEgressExecutor", "FrozenEncodingEgressResult",
           "FrozenNaturalEgressResultV2", "FrozenD13EgressResultV1",
           "FrozenD13CandidateReadV1", "d13_paid_worker_read_request_v1")
