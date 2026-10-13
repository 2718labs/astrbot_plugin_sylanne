"""One source-bound post-C02 reply model attempt, pending worker result read.

The graph worker must issue the original D11 job, D02 quote/reservation,
current source/access/D07 read and Authority intent. This host never invents
those authorities. Unknown egress remains on the same operation/call identity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json

from ..authority_service.v2_model_egress_contract import (
    ModelEgressDraftV1, ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelTerminalReceiptV2,
)
from ..authority_service.v2_contract import FencePermitV2
from ..authority_service.v2_reply_worker_model_result_contract import (
    ReplyWorkerModelResultReadRequestV1, ReplyWorkerModelResultReadV1,
    reply_worker_read_attempt_id_v1,
)
from ..domains.d07 import AttentionTicket
from ..domains.d09 import SourceReplyExpressionV1, issue_source_reply_expression_v1
from ..model_broker.reply_language import (
    InstalledReplyRequestV1, ReplyLanguageCandidate, ReplySourceSnapshot,
    freeze_installed_reply_request_v1, parse_reply_result_v1,
)
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime.model_cost_settlement import (
    OriginalModelCostCommitV1, original_model_cost_operation_id_v1,
)
from ..runtime.issuers import ResourceQuote
from ..runtime.jobs import PersistentJob
from ..runtime.reply_model_job import (
    ReplyModelQueuedPreparationV1, reply_job_id_v1,
    reply_job_original_operation_id_v1,
)
from ..runtime_contracts import (
    CommandEnvelope, CommitReceipt, canonical_digest,
)
from .authority_profile import AdminInstallationBundle
from .installation_grant_identity import same_installed_grant_identity_v2
from .model_egress_executor import HostModelEgressExecutor


def reply_model_operation_id_v1(c02_operation_id: str, source_ref: str) -> str:
    if not c02_operation_id or not source_ref:
        raise ValueError("original C02 and source identity required")
    return "post-c02-reply-model:" + canonical_digest({
        "version": 1, "c02_operation_id": c02_operation_id,
        "source_ref": source_ref,
    })


@dataclass(frozen=True, slots=True)
class FrozenReplyModelPreparationV1:
    """Strongly bound graph/Authority preparation, still subject to live checks."""

    c02_receipt: CommitReceipt
    envelope: CommandEnvelope
    source: ReplySourceSnapshot
    attention: AttentionTicket
    focus_revision: int
    intent: ModelEgressIntentV1
    expected_anchor: RestoreAnchor
    installed: InstalledReplyRequestV1

    def __post_init__(self) -> None:
        if (type(self.c02_receipt) is not CommitReceipt
                or self.c02_receipt.status not in {"committed", "duplicate"}
                or not {"memory.episode.v1", "memory.subjective_trace.v2"}
                   <= {row.key.type_name for row in self.c02_receipt.write_versions}
                or type(self.envelope) is not CommandEnvelope
                or type(self.source) is not ReplySourceSnapshot
                or type(self.attention) is not AttentionTicket
                or type(self.focus_revision) is not int
                or self.focus_revision < 1
                or type(self.intent) is not ModelEgressIntentV1
                or type(self.expected_anchor) is not RestoreAnchor
                or type(self.installed) is not InstalledReplyRequestV1):
            raise ValueError("typed committed C02 reply model preparation required")
        request = self.installed.request
        intent = self.intent
        source_id = self.source.source.source_id
        if (self.envelope.identity.operation_id != reply_model_operation_id_v1(
                self.c02_receipt.operation_id, self.source.source_ref)
                or self.c02_receipt.operation_id not in self.envelope.causation
                or self.attention.causal_root != self.source.source_ref
                or self.attention.category != "interaction"
                or request.envelope != self.envelope
                or intent.operation_id != request.identity.operation_id
                or intent.acquire_operation_id != intent.operation_id
                or intent.binding_digest is None
                or intent.call_id != request.call_id
                or intent.request_digest != request.digest
                or intent.authority_id != self.expected_anchor.authority_id
                or intent.namespace != self.expected_anchor.namespace
                or intent.anchor_digest != canonical_digest(asdict(self.expected_anchor))
                or intent.subject != self.envelope.authority.actor
                or intent.worker_fence != self.envelope.authority.worker_fence
                or intent.source_refs != (source_id,)
                or intent.source_revisions != ((source_id, self.source.source_revision),)
                or intent.access_revisions != ((source_id, self.source.access_revision),)
                or intent.access_epoch != self.envelope.version_guard.access_epoch
                or intent.delete_epoch != self.envelope.version_guard.delete_epoch
                or intent.budget_lease_id != self.envelope.parent_budget_lease_ref
                or intent.provider_id != request.provider_id
                or intent.model_id != request.model_id
                or intent.provider_config_digest != self.installed.provider_config_digest
                or intent.max_output_tokens != request.max_output_tokens
                or any(amount > self.installed.quote_ceiling.get(name, 0)
                       for name, amount in intent.budget_ceiling)):
            raise ValueError("reply model preparation differs from original evidence")


def freeze_reply_model_preparation_v1(
    *, c02_receipt: CommitReceipt, envelope: CommandEnvelope,
    source: ReplySourceSnapshot, attention: AttentionTicket,
    focus_revision: int,
    intent: ModelEgressIntentV1, expected_anchor: RestoreAnchor,
    bundle: AdminInstallationBundle,
) -> FrozenReplyModelPreparationV1:
    """Rebuild exact installed request; never accept a caller-authored prompt."""
    installed = freeze_installed_reply_request_v1(envelope, source, bundle=bundle)
    return FrozenReplyModelPreparationV1(
        c02_receipt, envelope, source, attention, focus_revision, intent,
        expected_anchor, installed)


@dataclass(frozen=True, slots=True)
class ReplyModelTerminalHoldV1:
    """Content-free durable outcome; absent terminal means original attempt HOLD."""

    operation_id: str
    call_id: str
    terminal: ModelTerminalReceiptV2 | None
    status: str  # observed_pending_result_read | unresolved


@dataclass(frozen=True, slots=True)
class InstalledReplyModelRunV1:
    preparation: FrozenReplyModelPreparationV1
    terminal: ReplyModelTerminalHoldV1


@dataclass(frozen=True, slots=True)
class InstalledReplyProgressV1:
    """Content stays unadmitted even after original cost is durable."""

    run: InstalledReplyModelRunV1
    cost: OriginalModelCostCommitV1 | None
    candidate: ReplyLanguageCandidate | None
    result_read: ReplyWorkerModelResultReadV1 | None = None


@dataclass(frozen=True, slots=True)
class InstalledReplyReadV1:
    """Parsed source content and the same verified Authority read response."""

    candidate: ReplyLanguageCandidate
    result_read: ReplyWorkerModelResultReadV1


def issue_installed_post_c02_source_expression_v1(
    queued: ReplyModelQueuedPreparationV1,
    progress: InstalledReplyProgressV1, *,
    current_source: ReplySourceSnapshot,
    current_envelope: CommandEnvelope,
    scene_ref: str, covered_slots: tuple[str, ...],
    max_chars: int,
) -> SourceReplyExpressionV1:
    """Turn one paid Authority result into a source-bound D09 candidate.

    W01 must supply the graph-issued queued job and current source/envelope,
    and must verify the signed quote and current dispatch clock in its own
    transaction. An expired original model quote does not erase an already
    completed, settled and Authority-read result.
    This pure host bridge does not issue checks, admission, or send authority.
    """
    from ..host.post_c02_reply_driver import post_c02_reply_operation_id
    from ..runtime.d11_types import runtime_job_key

    if (type(queued) is not ReplyModelQueuedPreparationV1
            or type(progress) is not InstalledReplyProgressV1
            or type(current_source) is not ReplySourceSnapshot
            or type(current_envelope) is not CommandEnvelope):
        raise ValueError("typed current reply inputs required")
    run, cost, candidate, read = (
        progress.run, progress.cost, progress.candidate, progress.result_read)
    if (type(run) is not InstalledReplyModelRunV1
            or type(run.preparation) is not FrozenReplyModelPreparationV1
            or type(run.terminal) is not ReplyModelTerminalHoldV1
            or type(cost) is not OriginalModelCostCommitV1
            or type(candidate) is not ReplyLanguageCandidate
            or type(read) is not ReplyWorkerModelResultReadV1
            or type(run.terminal.terminal) is not ModelTerminalReceiptV2):
        raise ValueError("paid original Authority reply result required")
    prep = run.preparation
    intent = prep.intent
    terminal = run.terminal.terminal
    quote = queued.quote
    job = queued.job
    namespace = current_envelope.authority.namespace
    cost_operation_id = original_model_cost_operation_id_v1(
        namespace, intent.call_id)
    if (type(quote) is not ResourceQuote or type(job) is not PersistentJob
            or queued.c02_operation_id != prep.c02_receipt.operation_id
            or queued.source_ref != prep.source.source_ref
            or queued.source_ref != current_source.source_ref
            or queued.original_operation_id != reply_job_original_operation_id_v1(
                queued.c02_operation_id, queued.source_ref)
            or job.job_id != reply_job_id_v1(
                queued.c02_operation_id, queued.source_ref)
            or job.operation_id != queued.original_operation_id
            or (job.bot_id, job.persona_id) != namespace.as_tuple
            or (quote.bot_id, quote.persona_id) != namespace.as_tuple
            or quote.work_kind != "reply"
            or quote.operation_id != queued.original_operation_id
            or quote.graph_job_ref != runtime_job_key(
                *namespace.as_tuple, job.activity_id, job.job_id).token
            or quote.activity_id != job.activity_id
            or quote.parent_budget_lease_ref != intent.budget_lease_id
            or dict(quote.ceiling) != dict(intent.budget_ceiling)
            or intent.job_id != job.job_id
            or intent.budget_reservation_operation_id != queued.original_operation_id
            or intent.budget_reservation_digest != queued.reservation_digest
            or current_envelope.identity.operation_id != post_c02_reply_operation_id(
                queued.c02_operation_id, queued.source_ref)
            or queued.c02_operation_id not in current_envelope.causation):
        raise ValueError("original C02/source or signed budget differs")
    if (run.terminal.status != "observed_pending_result_read"
            or (run.terminal.operation_id, run.terminal.call_id) != (
                intent.operation_id, intent.call_id)
            or read.terminal_receipt != terminal
            or read.request.installation_id != terminal.installation_id
            or cost.status != "committed"
            or (cost.operation_id, cost.call_id, cost.quote_id,
                cost.quote_version) != (
                    cost_operation_id, intent.call_id,
                    quote.quote_id, quote.version)
            or cost.terminal_receipt_digest != canonical_digest(asdict(terminal))):
        raise ValueError("original Authority read or durable model cost differs")
    return issue_source_reply_expression_v1(
        candidate, result_read=read, model_request=prep.installed.request,
        original_intent=intent, current_source=current_source,
        current_envelope=current_envelope, scene_ref=scene_ref,
        covered_slots=covered_slots, max_chars=max_chars)


async def prepare_and_run_installed_reply_model_v1(
    *, c02_receipt: CommitReceipt, envelope: CommandEnvelope,
    source: ReplySourceSnapshot, attention: AttentionTicket,
    focus_revision: int, draft: ModelEgressDraftV1,
    expected_anchor: RestoreAnchor, executor: HostModelEgressExecutor,
) -> InstalledReplyModelRunV1 | None:
    """Pair a graph-issued draft, then attempt the same Authority call once.

    A lost prepare response or mismatched live result is HOLD. The graph worker
    must keep its original D11 lease through the later result-read and C02 reply.
    """
    if (type(draft) is not ModelEgressDraftV1
            or type(executor) is not HostModelEgressExecutor
            or type(c02_receipt) is not CommitReceipt
            or c02_receipt.status not in {"committed", "duplicate"}
            or not {"memory.episode.v1", "memory.subjective_trace.v2"}
               <= {row.key.type_name for row in c02_receipt.write_versions}
            or type(source) is not ReplySourceSnapshot
            or type(envelope) is not CommandEnvelope
            or c02_receipt.operation_id not in envelope.causation
            or type(attention) is not AttentionTicket
            or attention.causal_root != source.source_ref
            or attention.category != "interaction"
            or type(focus_revision) is not int or focus_revision < 1):
        return None
    bundle = executor._bundle
    grant = executor._grant
    if (type(bundle) is not AdminInstallationBundle
            or bundle.model_workflows is None
            or executor._adapter._admin_model is not bundle.model_workflows.reply
            or grant.authority_id != bundle.installation_policy.expected_authority_id
            or grant.installation_id != bundle.installation_policy.installation_id):
        return None
    try:
        installed = freeze_installed_reply_request_v1(
            envelope, source, bundle=bundle)
    except (TypeError, ValueError):
        return None
    request = installed.request
    source_id = source.source.source_id
    if (draft.authority_id != grant.authority_id
            or draft.namespace != bundle.installation_policy.authority_namespace
            or draft.subject != envelope.authority.actor
            or draft.operation_id != reply_model_operation_id_v1(
                c02_receipt.operation_id, source.source_ref)
            or envelope.identity.operation_id != draft.operation_id
            or draft.acquire_operation_id != draft.operation_id
            or draft.binding_digest is None
            or draft.call_id != request.call_id
            or draft.request_digest != request.digest
            or draft.worker_fence != envelope.authority.worker_fence
            or draft.source_refs != (source_id,)
            or draft.source_revisions != ((source_id, source.source_revision),)
            or draft.access_revisions != ((source_id, source.access_revision),)
            or draft.access_epoch != envelope.version_guard.access_epoch
            or draft.delete_epoch != envelope.version_guard.delete_epoch
            or draft.budget_lease_id != envelope.parent_budget_lease_ref
            or draft.provider_id != request.provider_id
            or draft.model_id != request.model_id
            or draft.provider_config_digest != installed.provider_config_digest
            or draft.max_output_tokens != request.max_output_tokens
            or any(amount > installed.quote_ceiling.get(name, 0)
                   for name, amount in draft.budget_ceiling)):
        return None
    try:
        recovery, permit = await executor.prepare_once(
            draft=draft, expected_anchor=expected_anchor, request=request)
    except Exception:
        return None
    if (type(recovery) is not ModelEgressRecoveryV1
            or ModelEgressDraftV1.from_intent(recovery.intent) != draft
            or type(permit) is not FencePermitV2
            or permit.operation != "model_egress"
            or permit.operation_id != draft.operation_id
            or permit.pinned_anchor != expected_anchor
            or (permit.token, permit.fence_epoch, permit.revision) != (
                recovery.intent.fence_token,
                recovery.intent.fence_epoch,
                recovery.intent.fence_revision)):
        return None
    try:
        preparation = freeze_reply_model_preparation_v1(
            c02_receipt=c02_receipt, envelope=envelope, source=source,
            attention=attention, focus_revision=focus_revision,
            intent=recovery.intent, expected_anchor=expected_anchor,
            bundle=bundle)
        terminal = await execute_or_recover_reply_model_v1(
            preparation, executor=executor)
    except (TypeError, ValueError):
        return None
    return InstalledReplyModelRunV1(preparation, terminal)


async def execute_or_recover_reply_model_v1(
    preparation: FrozenReplyModelPreparationV1, *,
    executor: HostModelEgressExecutor,
) -> ReplyModelTerminalHoldV1:
    """Observe the original call first, then attempt only its exact identity."""
    if (type(preparation) is not FrozenReplyModelPreparationV1
            or type(executor) is not HostModelEgressExecutor
            or executor._adapter._admin_model is not
               executor._bundle.model_workflows.reply
            or executor._bundle.installation_policy.namespace
               != preparation.envelope.authority.namespace):
        raise ValueError("installed reply executor and frozen preparation required")
    intent = preparation.intent
    terminal = await executor.recover_original_terminal(intent)
    if terminal is None:
        try:
            recovery, permit = await executor._authority.model_recover_fenced_v1(
                executor._bundle, executor._grant, intent=intent)
        except Exception:
            recovery, permit = None, None
        if (type(recovery) is ModelEgressRecoveryV1
                and recovery.intent == intent and recovery.state == "prepared"
                and type(permit) is FencePermitV2
                and permit.operation == "model_egress"
                and permit.operation_id == intent.operation_id
                and permit.pinned_anchor == preparation.expected_anchor
                and (permit.token, permit.fence_epoch, permit.revision) ==
                    (intent.fence_token, intent.fence_epoch, intent.fence_revision)):
            terminal = await executor.execute_once(
                intent=intent, expected_anchor=preparation.expected_anchor,
                request=preparation.installed.request)
    if terminal is not None and (
            type(terminal) is not ModelTerminalReceiptV2
            or terminal.call_id != intent.call_id
            or terminal.request_digest != intent.request_digest):
        raise ValueError("original reply terminal differs")
    return ReplyModelTerminalHoldV1(
        intent.operation_id, intent.call_id, terminal,
        "observed_pending_result_read" if terminal else "unresolved")


def parse_authority_reply_observation_v1(
    preparation: FrozenReplyModelPreparationV1, *,
    observation, terminal: ModelTerminalReceiptV2,
) -> ReplyLanguageCandidate:
    """Parse an observation already released by the reply-scoped read RPC.

    This parser does not itself prove current read eligibility. The installed
    driver must obtain the result through Authority before invoking it.
    """
    from ..authority_service.v2_model_egress_contract import ModelEgressObservationV1

    if (type(preparation) is not FrozenReplyModelPreparationV1
            or type(observation) is not ModelEgressObservationV1
            or type(terminal) is not ModelTerminalReceiptV2
            or observation.status != "completed"
            or observation.result_json is None
            or (observation.authority_id, observation.namespace,
                observation.subject, observation.operation_id,
                observation.call_id, observation.request_digest) != (
                    preparation.intent.authority_id,
                    preparation.intent.namespace, preparation.intent.subject,
                    preparation.intent.operation_id,
                    preparation.intent.call_id,
                    preparation.intent.request_digest)
            or terminal.observation_digest != observation.digest
            or terminal.call_id != observation.call_id
            or terminal.request_digest != observation.request_digest):
        raise ValueError("original completed Authority reply observation required")
    result = json.loads(observation.result_json)
    return parse_reply_result_v1(
        result, request=preparation.installed.request,
        snapshot=preparation.source)


async def read_and_parse_installed_reply_with_receipt_v1(
    preparation: FrozenReplyModelPreparationV1, *,
    executor: HostModelEgressExecutor,
    read_request: ReplyWorkerModelResultReadRequestV1,
    terminal: ModelTerminalReceiptV2,
) -> InstalledReplyReadV1 | None:
    """Use only the Authority's reply-scoped worker read; failures remain HOLD."""
    from .post_c02_reply_driver import post_c02_reply_operation_id

    if (type(preparation) is not FrozenReplyModelPreparationV1
            or type(executor) is not HostModelEgressExecutor
            or type(read_request) is not ReplyWorkerModelResultReadRequestV1
            or type(terminal) is not ModelTerminalReceiptV2):
        return None
    intent = preparation.intent
    namespace = preparation.envelope.authority.namespace
    grant = executor._grant
    if (intent.binding_digest is None
            or read_request.authority_id != intent.authority_id
            or read_request.authority_namespace != intent.namespace
            or read_request.namespace != namespace
            or read_request.installation_id != grant.installation_id
            or read_request.job_id != intent.job_id
            or read_request.acquire_operation_id != intent.operation_id
            or read_request.original_operation_id !=
               intent.budget_reservation_operation_id
            or read_request.call_id != intent.call_id
            or read_request.binding_digest != intent.binding_digest
            or read_request.model_request_digest != intent.request_digest
            or read_request.consumer_operation_id != post_c02_reply_operation_id(
                preparation.c02_receipt.operation_id, preparation.source.source_ref)
            or read_request.read_attempt_id != reply_worker_read_attempt_id_v1(
                read_request.consumer_operation_id, 1)
            or read_request.c02_operation_id != preparation.c02_receipt.operation_id
            or read_request.source_ref != preparation.source.source_ref
            or read_request.source_revision != preparation.source.source_revision
            or read_request.access_revision != preparation.source.access_revision
            or read_request.attention_ticket_id != preparation.attention.ticket_id
            or read_request.focus_revision != preparation.focus_revision
            or read_request.audience != preparation.envelope.authority.audience
            or terminal.call_id != intent.call_id
            or terminal.request_digest != intent.request_digest
            or terminal.installation_id != grant.installation_id):
        return None
    client = executor._authority
    select = getattr(client, "reply_worker_model_result_select_attempt_v1", None)
    read = getattr(client, "reply_worker_model_result_read_v1", None)
    if not callable(select) or not callable(read):
        return None
    try:
        selected = await select(executor._bundle, grant,
                                first_request=read_request)
        if (type(selected) is not ReplyWorkerModelResultReadRequestV1
                or replace(selected, read_attempt_id=read_request.read_attempt_id)
                   != read_request):
            return None
        result = await read(executor._bundle, grant, read_request=selected)
        if (type(result) is not ReplyWorkerModelResultReadV1
                or result.request != selected
                or result.terminal_receipt != terminal):
            return None
        candidate = parse_authority_reply_observation_v1(
            preparation, observation=result.observation,
            terminal=result.terminal_receipt)
        return InstalledReplyReadV1(candidate, result)
    except Exception:
        return None


async def read_and_parse_installed_reply_v1(
    preparation: FrozenReplyModelPreparationV1, *,
    executor: HostModelEgressExecutor,
    read_request: ReplyWorkerModelResultReadRequestV1,
    terminal: ModelTerminalReceiptV2,
) -> ReplyLanguageCandidate | None:
    """Compatibility view of a verified read; discards its provenance DTO."""
    read = await read_and_parse_installed_reply_with_receipt_v1(
        preparation, executor=executor, read_request=read_request,
        terminal=terminal)
    return read.candidate if read is not None else None


async def run_installed_post_c02_reply_model_v1(
    runtime, installation, *, context, trusted_umo: str,
    queued: ReplyModelQueuedPreparationV1,
) -> InstalledReplyProgressV1 | None:
    """Continue one graph-issued reply job through its original model call.

    The returned language candidate has not passed D09/D08/D11 final
    admission and grants no platform send authorization.
    """
    import asyncio

    from astrbot.api.star import Context

    from ..model_broker.broker import ModelProviderDescriptor
    from ..runtime_context import RuntimeContext
    from .astrbot_model_call import AstrBotModelProvider
    from .authority_client import AuthorityClient, AuthoritySelection
    from .mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
    from .v2_installation import V2InstallationAssembly

    if (type(runtime) is not RuntimeContext
            or type(installation) is not V2InstallationAssembly
            or not isinstance(context, Context)
            or type(trusted_umo) is not str or not trusted_umo
            or type(queued) is not ReplyModelQueuedPreparationV1
            or queued.original_operation_id != queued.job.operation_id
            or queued.quote.operation_id != queued.original_operation_id
            or queued.quote.work_kind != "reply"
            or not queued.c02_operation_id or not queued.source_ref):
        return None
    c02_operation_id, source_ref = queued.c02_operation_id, queued.source_ref
    bundle = installation.admin_bundle
    grant = installation.installation_grant
    if (type(bundle) is not AdminInstallationBundle
            or type(bundle.tls_profile) is not AuthorityTlsProfile
            or bundle.installation_policy is not installation.installation_policy
            or bundle.model_workflows is None
            or bundle.model_workflows.reply.work_kind != "reply"
            or bundle.model_workflows.reply.purpose != "proposal"):
        return None
    transport = MtlsAuthorityTransport({
        bundle.tls_profile.profile_id: bundle.tls_profile})
    adapter = None
    try:
        client = AuthorityClient(
            AuthoritySelection(bundle.tls_profile.profile_id),
            package_root=installation.package_root,
            data_dir=installation.data_dir, transport=transport)
        status = await client.status_v2()
        client_grant = await client.installation_grant_v2()
        if (status.state != "paired"
                or not same_installed_grant_identity_v2(grant, client_grant)):
            return None
        async with runtime.acquired_post_c02_reply_model_v1(
                c02_operation_id=c02_operation_id,
                source_ref=source_ref) as acquired:
            if acquired is None:
                return None
            prepared = await runtime.read_post_c02_reply_model_egress_v1(acquired)
            if prepared is None or len(prepared) != 7:
                return None
            (c02, envelope, source, attention, focus_revision,
             draft, anchor) = prepared
            try:
                audience = json.loads(envelope.authority.audience[0])
            except (AttributeError, IndexError, TypeError, ValueError):
                return None
            if (type(audience) is not list or len(audience) != 2
                    or any(type(value) is not str or not value for value in audience)
                    or audience[0] != trusted_umo
                    or len(envelope.authority.audience) != 1
                    or source.source_ref != source_ref
                    or c02.operation_id != c02_operation_id
                    or draft.operation_id != acquired.acquire_operation_id):
                return None
            workflow = bundle.model_workflows.reply
            descriptor = ModelProviderDescriptor(
                workflow.provider_id, "astrbot-openai-official-v1",
                workflow.model_id, frozenset({"text"}),
                frozenset({workflow.purpose}),
                frozenset({workflow.privacy_tier}),
                workflow.provider_config_ref, "unknown", False, False)
            adapter = AstrBotModelProvider(
                context=context, host_loop=asyncio.get_running_loop(),
                trusted_umo=trusted_umo, descriptor=descriptor,
                admin_model=workflow, installation_bundle=bundle)
            executor = HostModelEgressExecutor(
                authority=client, bundle=bundle, grant=client_grant, adapter=adapter, local_module_admission=runtime.local_module_admission)
            run = await prepare_and_run_installed_reply_model_v1(
                c02_receipt=c02, envelope=envelope, source=source,
                attention=attention, focus_revision=focus_revision,
                draft=draft, expected_anchor=anchor, executor=executor)
            if run is None:
                return None
            terminal = run.terminal.terminal
            if terminal is None:
                return InstalledReplyProgressV1(run, None, None)
            request = await runtime.read_post_c02_reply_model_result_request_v1(
                acquired)
            read = (await read_and_parse_installed_reply_with_receipt_v1(
                run.preparation, executor=executor, read_request=request,
                terminal=terminal) if request is not None else None)
            cost = await runtime.commit_post_c02_reply_model_cost_v1(
                queued, run.preparation.intent, terminal)
            return InstalledReplyProgressV1(
                run, cost,
                read.candidate if cost is not None and read is not None else None,
                read.result_read if cost is not None and read is not None else None)
    except asyncio.CancelledError:
        if adapter is not None:
            await adapter.abort_local_dispatches()
        raise
    except Exception:
        return None
    finally:
        await transport.close()


__all__ = (
    "reply_model_operation_id_v1", "FrozenReplyModelPreparationV1",
    "freeze_reply_model_preparation_v1", "ReplyModelTerminalHoldV1",
    "execute_or_recover_reply_model_v1", "parse_authority_reply_observation_v1",
    "read_and_parse_installed_reply_v1",
    "read_and_parse_installed_reply_with_receipt_v1", "InstalledReplyReadV1",
    "InstalledReplyModelRunV1", "prepare_and_run_installed_reply_model_v1",
    "InstalledReplyProgressV1", "run_installed_post_c02_reply_model_v1",
    "issue_installed_post_c02_source_expression_v1",
)
