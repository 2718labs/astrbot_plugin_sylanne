"""Installed AstrBot composition for one committed first-ingress encoding job."""

from __future__ import annotations

import asyncio
import json

from astrbot.api.star import Context

from ..model_broker.broker import ModelProviderDescriptor
from ..runtime_context import RuntimeContext
from ..runtime_contracts import InstallationGrantV2
from .astrbot_model_call import AstrBotModelProvider
from .authority_client import AuthorityClient, AuthoritySelection
from .authority_profile import AdminInstallationBundle, AdminModelWorkflowV2
from .ingress import HostIngressEnvelope, IngressReceipt
from .model_egress_executor import FrozenEncodingEgressResult, HostModelEgressExecutor
from .mtls_transport import MtlsAuthorityTransport
from .v2_installation import V2InstallationAssembly


async def run_installed_first_ingress_encoding_v2(
    runtime: RuntimeContext, installation: V2InstallationAssembly, *,
    context: Context, trusted_umo: str, envelope: HostIngressEnvelope,
    receipt: IngressReceipt,
) -> FrozenEncodingEgressResult | None:
    """Use the paired mTLS observer and exact AstrBot selection for one job.

    The graph's original job and Authority preparation remain the only source
    of model-call inputs. This composition supplies neither draft nor anchor.
    """
    if (type(runtime) is not RuntimeContext
            or type(installation) is not V2InstallationAssembly
            or not isinstance(context, Context)
            or type(trusted_umo) is not str or not trusted_umo
            or type(envelope) is not HostIngressEnvelope
            or type(receipt) is not IngressReceipt
            or receipt.status != "accepted"):
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
            or bundle.installation_policy is not installation.installation_policy
            or bundle.model_workflows is None
            or type(bundle.model_workflows.encode) is not AdminModelWorkflowV2):
        return None
    workflow = bundle.model_workflows.encode
    if envelope.namespace != bundle.installation_policy.namespace:
        return None
    descriptor = ModelProviderDescriptor(
        workflow.provider_id, "astrbot-openai-official-v1", workflow.model_id,
        frozenset({"text"}), frozenset({workflow.purpose}),
        frozenset({workflow.privacy_tier}), workflow.provider_config_ref,
        "unknown", False, False,
    )
    host_loop = asyncio.get_running_loop()
    adapter = AstrBotModelProvider(
        context=context, host_loop=host_loop, trusted_umo=trusted_umo,
        descriptor=descriptor, admin_model=workflow,
        installation_bundle=bundle,
    )
    transport = MtlsAuthorityTransport({bundle.tls_profile.profile_id: bundle.tls_profile})
    try:
        client = AuthorityClient(
            AuthoritySelection(bundle.tls_profile.profile_id),
            package_root=installation.package_root,
            data_dir=installation.data_dir, transport=transport,
        )
        status = await client.status_v2()
        if status.state != "paired" or await client.installation_grant_v2() != grant:
            return None
        executor = HostModelEgressExecutor(
            authority=client, bundle=bundle, grant=grant, adapter=adapter)
        try:
            return await runtime.run_committed_first_ingress_encoding_v2(
                envelope, receipt, executor=executor)
        except asyncio.CancelledError:
            await adapter.abort_local_dispatches()
            raise
    finally:
        await transport.close()


__all__ = ("run_installed_first_ingress_encoding_v2",)
