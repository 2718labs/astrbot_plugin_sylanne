"""Installed, optional D13 paid background call through the main chat model.

The caller schedules this coroutine independently of foreground reply output.
It never creates a separate compression provider or a second budget ledger.
"""

from __future__ import annotations

import asyncio
import json

from astrbot.api import logger
from astrbot.api.star import Context

from ..model_broker.broker import ModelProviderDescriptor
from ..runtime.first_ingress_v2 import ingress_ids
from ..runtime.d13_technical_policy import AdminD13PaidPrecompressionPolicyV1
from ..runtime_contracts import InstallationGrantV2
from .astrbot_model_call import AstrBotModelProvider
from .authority_client import AuthorityClient, AuthoritySelection
from .authority_profile import AdminInstallationBundle, AdminModelWorkflowV2
from .ingress import HostIngressEnvelope
from .installation_grant_identity import same_installed_grant_identity_v2
from .model_egress_executor import HostModelEgressExecutor
from .mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from .v2_installation import V2InstallationAssembly


async def run_installed_d13_paid_precompression_v1(
    runtime, installation: V2InstallationAssembly, *,
    context: Context, trusted_umo: str,
    envelope: HostIngressEnvelope, ingress_operation_id: str,
):
    """Run one W01 original when its paid lifecycle is installed; else HOLD."""
    from ..runtime_context import RuntimeContext

    if (type(runtime) is not RuntimeContext
            or type(installation) is not V2InstallationAssembly
            or not isinstance(context, Context)
            or type(trusted_umo) is not str or not trusted_umo
            or type(envelope) is not HostIngressEnvelope
            or envelope.visibility != "private"
            or type(ingress_operation_id) is not str
            or ingress_ids(envelope.lineage.source_ref)[2]
               != ingress_operation_id):
        return None
    try:
        conversation = json.loads(envelope.conversation_ref)
    except (TypeError, ValueError):
        return None
    if (type(conversation) is not list or len(conversation) != 2
            or conversation[0] != trusted_umo):
        return None
    bundle = installation.admin_bundle
    grant = installation.installation_grant
    if (type(bundle) is not AdminInstallationBundle
            or type(grant) is not InstallationGrantV2
            or type(bundle.tls_profile) is not AuthorityTlsProfile
            or bundle.installation_policy is not installation.installation_policy
            or type(bundle.d13_paid_precompression)
               is not AdminD13PaidPrecompressionPolicyV1
            or bundle.model_workflows is None
            or type(bundle.model_workflows.reply) is not AdminModelWorkflowV2
            or envelope.namespace != bundle.installation_policy.namespace
            or bundle.d13_paid_precompression.namespace != envelope.namespace):
        return None
    run_paid = getattr(runtime, "run_installed_d13_paid_precompression_v1", None)
    if not callable(run_paid):
        logger.warning("Sylanne 3 D13 paid lifecycle unavailable; not dispatched; HOLD")
        return None
    workflow = bundle.model_workflows.reply
    from ..runtime.d13_installed_paid_purpose_v1 import installed_d13_paid_context_model_v1
    if not installed_d13_paid_context_model_v1(bundle, workflow):
        logger.warning("Sylanne 3 D13 installed context binding unavailable; HOLD")
        return None
    descriptor = ModelProviderDescriptor(
        workflow.provider_id, "astrbot-openai-official-v1", workflow.model_id,
        frozenset({"text"}), frozenset({"context"}),
        frozenset({workflow.privacy_tier}), workflow.provider_config_ref,
        "unknown", False, False,
    )
    adapter = AstrBotModelProvider(
        context=context, host_loop=asyncio.get_running_loop(),
        trusted_umo=trusted_umo, descriptor=descriptor,
        admin_model=workflow, installation_bundle=bundle,
    )
    selected = await adapter.selected_d13_main_installation_v1()
    if selected != bundle.d13_paid_precompression.selected_main:
        return None
    transport = MtlsAuthorityTransport({
        bundle.tls_profile.profile_id: bundle.tls_profile,
    })
    try:
        client = AuthorityClient(
            AuthoritySelection(bundle.tls_profile.profile_id),
            package_root=installation.package_root,
            data_dir=installation.data_dir, transport=transport,
        )
        status = await client.status_v2()
        client_grant = await client.installation_grant_v2()
        if (status.state != "paired"
                or not same_installed_grant_identity_v2(grant, client_grant)):
            return None
        executor = HostModelEgressExecutor(
            authority=client, bundle=bundle, grant=client_grant, adapter=adapter)
        try:
            return await run_paid(
                envelope, ingress_operation_id, executor=executor)
        except asyncio.CancelledError:
            await adapter.abort_local_dispatches()
            raise
    finally:
        await transport.close()


__all__ = ("run_installed_d13_paid_precompression_v1",)
