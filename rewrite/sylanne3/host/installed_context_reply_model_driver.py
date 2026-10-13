"""Run one sealed context_reply V2 paid call through the installed host.

This produces an Authority current result read, not a platform reply grant.
The public graph readiness gate stays closed until D09 and final admission
have a product consumer for this independently versioned workflow.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json

from ..authority_service.v2_context_reply_result_contract import (
    ContextReplyPaidResultReadV2,
)
from ..authority_service.v2_contract import FencePermitV2
from ..authority_service.v2_model_egress_contract import (
    ModelEgressDraftV1, ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelTerminalReceiptV2,
)
from ..model_broker.broker import ModelCallRequest, ModelProviderDescriptor
from ..runtime.context_reply_job_v2 import SavedContextReplyPreparationV2
from ..runtime.model_cost_settlement import OriginalModelCostCommitV1
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import CommitReceipt
from .astrbot_model_call import AstrBotModelProvider
from .authority_client import AuthorityClient, AuthoritySelection
from .authority_profile import AdminInstallationBundle
from .installation_grant_identity import same_installed_grant_identity_v2
from .model_egress_executor import HostModelEgressExecutor
from .mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from .v2_installation import V2InstallationAssembly


@dataclass(frozen=True, slots=True)
class InstalledContextReplyPaidReadV2:
    """A paid current read that remains outside reply adoption and dispatch."""

    saved: SavedContextReplyPreparationV2
    intent: ModelEgressIntentV1
    terminal: ModelTerminalReceiptV2
    cost: OriginalModelCostCommitV1
    result: ContextReplyPaidResultReadV2


async def run_installed_post_c02_context_reply_model_v2(
    runtime, installation: V2InstallationAssembly, *, context,
    trusted_umo: str, c02_operation_id: str, source_ref: str,
    attention_receipt: CommitReceipt,
) -> InstalledContextReplyPaidReadV2 | None:
    """Use only W01's original paid binding; unknown dispatch never retries."""
    from astrbot.api.star import Context
    from ..runtime_context import RuntimeContext

    if (type(runtime) is not RuntimeContext
            or type(installation) is not V2InstallationAssembly
            or not isinstance(context, Context)
            or type(trusted_umo) is not str or not trusted_umo
            or type(c02_operation_id) is not str or not c02_operation_id
            or type(source_ref) is not str or not source_ref
            or type(attention_receipt) is not CommitReceipt):
        return None
    bundle, grant = installation.admin_bundle, installation.installation_grant
    if (type(bundle) is not AdminInstallationBundle
            or type(bundle.tls_profile) is not AuthorityTlsProfile
            or bundle.installation_policy is not installation.installation_policy
            or bundle.model_workflows is None
            or bundle.model_workflows.context_reply is None):
        return None
    workflow = bundle.model_workflows.context_reply
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
        saved = await runtime.prepare_post_c02_context_reply_model_job_v2(
            c02_operation_id=c02_operation_id, source_ref=source_ref,
            attention_receipt=attention_receipt)
        if (type(saved) is not SavedContextReplyPreparationV2
                or saved.seal.c02_operation_id != c02_operation_id
                or saved.seal.source_ref != source_ref):
            return None
        async with runtime.acquired_post_c02_context_reply_model_v2(saved) as acquired:
            if acquired is None:
                return None
            prepared = await runtime.read_post_c02_context_reply_model_egress_v2(
                acquired)
            if (type(prepared) is not tuple or len(prepared) != 3):
                return None
            call, draft, anchor = prepared
            if (type(call) is not ModelCallRequest or call != acquired.call
                    or type(draft) is not ModelEgressDraftV1
                    or type(anchor) is not RestoreAnchor
                    or draft.operation_id != saved.seal.acquire_operation_id
                    or draft.call_id != saved.seal.call_id
                    or draft.request_digest != call.digest
                    or call.identity.phase != "context_reply"):
                return None
            try:
                audience = json.loads(call.envelope.authority.audience[0])
            except (AttributeError, IndexError, TypeError, ValueError):
                return None
            if (type(audience) is not list or len(audience) != 2
                    or audience[0] != trusted_umo
                    or len(call.envelope.authority.audience) != 1):
                return None
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
            recovery, permit = await executor.prepare_once(
                draft=draft, expected_anchor=anchor, request=call)
            if (type(recovery) is not ModelEgressRecoveryV1
                    or ModelEgressDraftV1.from_intent(recovery.intent) != draft
                    or type(permit) is not FencePermitV2
                    or permit.operation != "model_egress"
                    or permit.pinned_anchor != anchor):
                return None
            intent = recovery.intent
            terminal = await executor.recover_original_terminal(intent)
            if terminal is None:
                recovered, recovered_permit = await client.model_recover_fenced_v1(
                    bundle, client_grant, intent=intent)
                if (recovered == recovery and recovered.state == "prepared"
                        and recovered_permit == permit):
                    terminal = await executor.execute_once(
                        intent=intent, expected_anchor=anchor, request=call)
            if (type(terminal) is not ModelTerminalReceiptV2
                    or terminal.call_id != intent.call_id
                    or terminal.request_digest != intent.request_digest):
                return None
            settled = await runtime.settle_post_c02_context_reply_model_v2(
                acquired, intent, terminal)
            if settled is None:
                return None
            cost, read_request = settled
            result = await client.context_reply_result_read_v2(
                bundle, client_grant, read_request=read_request)
            if (type(result) is not ContextReplyPaidResultReadV2
                    or result.read_attempt_id != read_request.read_attempt_id
                    or result.original_seal != saved.seal
                    or result.terminal_receipt != terminal):
                return None
            return InstalledContextReplyPaidReadV2(
                saved, intent, terminal, cost, result)
    except asyncio.CancelledError:
        if adapter is not None:
            await adapter.abort_local_dispatches()
        raise
    except Exception:
        return None
    finally:
        await transport.close()


__all__ = ("InstalledContextReplyPaidReadV2",
           "run_installed_post_c02_context_reply_model_v2")
