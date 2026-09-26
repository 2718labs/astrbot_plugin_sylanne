"""One source-bound post-C02 reply model attempt, pending worker result read.

The graph worker must issue the original D11 job, D02 quote/reservation,
current source/access/D07 read and Authority intent. This host never invents
those authorities. Unknown egress remains on the same operation/call identity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json

from ..authority_service.v2_model_egress_contract import (
    ModelEgressIntentV1, ModelEgressRecoveryV1, ModelTerminalReceiptV2,
)
from ..authority_service.v2_contract import FencePermitV2
from ..authority_service.v2_reply_worker_model_result_contract import (
    ReplyWorkerModelResultReadRequestV1, ReplyWorkerModelResultReadV1,
    reply_worker_read_attempt_id_v1,
)
from ..domains.d07 import AttentionTicket
from ..model_broker.reply_language import (
    InstalledReplyRequestV1, ReplyLanguageCandidate, ReplySourceSnapshot,
    freeze_installed_reply_request_v1, parse_reply_result_v1,
)
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import (
    CommandEnvelope, CommitReceipt, canonical_digest,
)
from .authority_profile import AdminInstallationBundle
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
    """Parse an Authority-read observation after its future reply read gate.

    This function does not accept a result-read DTO as qualification. The
    calling installed driver must first obtain it through a reply-scoped
    Authority result-read RPC, which is not yet present in alpha1.
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


async def read_and_parse_installed_reply_v1(
    preparation: FrozenReplyModelPreparationV1, *,
    executor: HostModelEgressExecutor,
    read_request: ReplyWorkerModelResultReadRequestV1,
    terminal: ModelTerminalReceiptV2,
) -> ReplyLanguageCandidate | None:
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
        return parse_authority_reply_observation_v1(
            preparation, observation=result.observation,
            terminal=result.terminal_receipt)
    except Exception:
        return None


__all__ = (
    "reply_model_operation_id_v1", "FrozenReplyModelPreparationV1",
    "freeze_reply_model_preparation_v1", "ReplyModelTerminalHoldV1",
    "execute_or_recover_reply_model_v1", "parse_authority_reply_observation_v1",
    "read_and_parse_installed_reply_v1",
)
