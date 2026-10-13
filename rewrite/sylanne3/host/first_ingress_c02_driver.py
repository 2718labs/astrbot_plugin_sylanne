"""Explicit installed host composition for the original V3 encoding C02."""

from __future__ import annotations

import asyncio
import json

from astrbot.api.star import Context

from ..authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from ..authority_service.v2_terminal_c02_recovery_contract import (
    TerminalRecoveryReadRequestV1,
)
from ..model_broker.broker import ModelProviderDescriptor
from ..runtime.c02_terminal_job import pin_finished_terminal_read_from_host
from ..runtime_context import RuntimeContext
from ..runtime.first_ingress_recovery import FirstIngressRecoveryItemV1
from ..runtime.first_ingress_unacquired import FirstIngressUnacquiredItemV1
from ..runtime.first_ingress_v2 import ingress_ids
from ..runtime_contracts import CommitReceipt, InstallationGrantV2
from .astrbot_model_call import AstrBotModelProvider
from .authority_client import (
    AUTHORITY_PROTOCOL, AuthorityClient, AuthorityProvisioningRequest,
    AuthoritySelection, PublisherPackageIdentity,
)
from .authority_profile import (
    AdminD06FirstIngressC02Policy, AdminIngressClockPolicy,
    AdminInstallationBundle, AdminModelWorkflowV2,
)
from .ingress import HostIngressEnvelope, IngressReceipt
from .installation_grant_identity import same_installed_grant_identity_v2
from .model_egress_executor import HostModelEgressExecutor
from .mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from .terminal_c02_recovery_query import PinnedTerminalC02RecoveryQueryV1
from .v2_installation import V2InstallationAssembly


def original_unacquired_handoff_v1(
    item: FirstIngressUnacquiredItemV1,
    installation: V2InstallationAssembly,
) -> tuple[str, HostIngressEnvelope, IngressReceipt] | None:
    """Rehydrate only graph-attested original identity; issue no authority."""
    if (type(item) is not FirstIngressUnacquiredItemV1
            or type(installation) is not V2InstallationAssembly
            or item.installation_id != installation.installation_grant.installation_id
            or item.namespace != installation.installation_policy.namespace):
        return None
    try:
        conversation = json.loads(item.envelope.conversation_ref)
    except (TypeError, ValueError):
        return None
    if (type(conversation) is not list or len(conversation) != 2
            or type(conversation[0]) is not str or not conversation[0]
            or type(conversation[1]) is not str or not conversation[1]):
        return None
    return (conversation[0], item.envelope,
            IngressReceipt("accepted", item.original_operation_id))


def original_acquired_handoff_v1(
    item: FirstIngressRecoveryItemV1,
    envelope: HostIngressEnvelope,
    installation: V2InstallationAssembly,
) -> tuple[str, HostIngressEnvelope, IngressReceipt] | None:
    """Restore the original host identity for a graph-qualified V3 lease."""
    if (type(item) is not FirstIngressRecoveryItemV1
            or item.recovery_state != "original_fence"
            or type(envelope) is not HostIngressEnvelope
            or type(installation) is not V2InstallationAssembly
            or item.installation_id != installation.installation_grant.installation_id
            or item.namespace != installation.installation_policy.namespace
            or envelope.namespace != item.namespace):
        return None
    _, _, original_id, job_id, _, _ = ingress_ids(
        envelope.lineage.source_ref)
    if (item.original_operation_id, item.job_id) != (original_id, job_id):
        return None
    try:
        conversation = json.loads(envelope.conversation_ref)
    except (TypeError, ValueError):
        return None
    if (type(conversation) is not list or len(conversation) != 2
            or type(conversation[0]) is not str or not conversation[0]
            or type(conversation[1]) is not str or not conversation[1]):
        return None
    return conversation[0], envelope, IngressReceipt("accepted", original_id)


async def installed_first_ingress_c02_pairing_ready_v1(
    installation: V2InstallationAssembly,
) -> bool:
    """Check the current installed pairing before startup recovery discovery."""
    if (type(installation) is not V2InstallationAssembly
            or type(installation.admin_bundle) is not AdminInstallationBundle
            or type(installation.installation_grant) is not InstallationGrantV2
            or type(installation.admin_bundle.tls_profile) is not AuthorityTlsProfile
            or installation.admin_bundle.installation_policy
               is not installation.installation_policy):
        return False
    profile = installation.admin_bundle.tls_profile
    transport = MtlsAuthorityTransport({profile.profile_id: profile})
    try:
        client = AuthorityClient(
            AuthoritySelection(profile.profile_id),
            package_root=installation.package_root,
            data_dir=installation.data_dir, transport=transport,
        )
        return ((await client.status_v2()).state == "paired"
                and same_installed_grant_identity_v2(
                    installation.installation_grant,
                    await client.installation_grant_v2()))
    except Exception:
        return False
    finally:
        await transport.close()


async def run_installed_first_ingress_c02_v2(
    runtime: RuntimeContext, installation: V2InstallationAssembly, *,
    context: Context, trusted_umo: str, envelope: HostIngressEnvelope,
    receipt: IngressReceipt,
    original_recovery: FirstIngressRecoveryItemV1 | None = None,
) -> CommitReceipt | None:
    """Keep one live D11 lease through model, cost, read and C02 adoption."""
    if (type(runtime) is not RuntimeContext
            or type(installation) is not V2InstallationAssembly
            or not isinstance(context, Context)
            or type(trusted_umo) is not str or not trusted_umo
            or type(envelope) is not HostIngressEnvelope
            or type(receipt) is not IngressReceipt
            or receipt.status != "accepted"
            or original_recovery is not None and (
                type(original_recovery) is not FirstIngressRecoveryItemV1
                or original_recovery.recovery_state != "original_fence")):
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
            or type(bundle.d06_first_ingress_c02)
               is not AdminD06FirstIngressC02Policy
            or type(bundle.ingress_clock) is not AdminIngressClockPolicy
            or bundle.model_workflows is None
            or type(bundle.model_workflows.encode) is not AdminModelWorkflowV2
            or envelope.namespace != bundle.installation_policy.namespace):
        return None
    workflow = bundle.model_workflows.encode
    descriptor = ModelProviderDescriptor(
        workflow.provider_id, "astrbot-openai-official-v1", workflow.model_id,
        frozenset({"text"}), frozenset({workflow.purpose}),
        frozenset({workflow.privacy_tier}), workflow.provider_config_ref,
        "unknown", False, False,
    )
    adapter = AstrBotModelProvider(
        context=context, host_loop=asyncio.get_running_loop(),
        trusted_umo=trusted_umo, descriptor=descriptor,
        admin_model=workflow, installation_bundle=bundle,
    )
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
            authority=client, bundle=bundle, grant=client_grant, adapter=adapter, local_module_admission=runtime.local_module_admission)
        try:
            return await runtime.commit_first_ingress_c02_v2(
                envelope, receipt, executor=executor,
                original_recovery=original_recovery)
        except asyncio.CancelledError:
            await adapter.abort_local_dispatches()
            raise
        except Exception:
            return None
    except Exception:
        return None
    finally:
        await transport.close()


async def run_installed_pending_first_ingress_c02_v2(
    runtime: RuntimeContext, installation: V2InstallationAssembly,
    consumer_operation_id: str,
) -> tuple[CommitReceipt, bool] | None:
    """Query the exact durable attempt; resend its same ID if still absent."""
    if (type(runtime) is not RuntimeContext
            or type(installation) is not V2InstallationAssembly
            or type(consumer_operation_id) is not str or not consumer_operation_id
            or type(installation.admin_bundle) is not AdminInstallationBundle
            or type(installation.admin_bundle.tls_profile) is not AuthorityTlsProfile
            or installation.admin_bundle.installation_policy
               is not installation.installation_policy):
        return None
    request = await runtime.read_pending_first_ingress_c02_terminal_request_v2(
        consumer_operation_id)
    if (type(request) is CommitReceipt
            and request.status == "duplicate"
            and request.operation_id == consumer_operation_id):
        return request, False
    if (type(request) is not TerminalRecoveryReadRequestV1
            or request.original_key.namespace
               != installation.installation_policy.namespace
            or request.original_key.installation_id
               != installation.installation_grant.installation_id):
        return None
    profile = installation.admin_bundle.tls_profile
    provisioning = AuthorityProvisioningRequest(
        protocol=AUTHORITY_PROTOCOL, profile_id=profile.profile_id,
        plugin_name="astrbot_plugin_sylanne", host_api_version="4.28.1",
        package_root=installation.package_root, data_dir=installation.data_dir,
        publisher_package=PublisherPackageIdentity(
            installation.installation_policy.manifest_digest),
    )
    transport = MtlsAuthorityTransport({profile.profile_id: profile})
    try:
        handshake = await transport.handshake(
            provisioning, protocol=AUTHORITY_V2_PROTOCOL)
        grant = await transport.installation_grant_v2(provisioning, handshake)
        if (not handshake.valid_pairing()
                or not same_installed_grant_identity_v2(
                    installation.installation_grant, grant)
                or grant.channel_binding_sha256 != handshake.channel_binding_sha256):
            return None
        pinned_query = PinnedTerminalC02RecoveryQueryV1(
            transport=transport, provisioning=provisioning,
            handshake=handshake, grant=grant,
            namespace=request.original_key.authority_namespace,
            request=request)
        attempt, _ = await transport.terminal_c02_recovery_query_v1(
            provisioning, handshake, grant,
            namespace=request.original_key.authority_namespace,
            read_request=request)
        if attempt is None:
            # A prior process may have committed the local claim but died
            # before sending the read. A repeated exact claim verifies that
            # identity; Authority de-duplicates the same attempt ID.
            claim = await runtime.claim_pending_first_ingress_c02_terminal_read_v2(
                consumer_operation_id, request)
            if claim is None:
                return None
            try:
                # The mTLS transport returns only after the exact body is
                # acknowledged on this channel. A lost response is resolved
                # solely by querying this same durable attempt ID.
                await transport.terminal_c02_recovery_read_v1(
                    provisioning, handshake, grant,
                    namespace=request.original_key.authority_namespace,
                    read_request=request)
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
        elif attempt.state != "finished":
            return None
        pinned_read = await pin_finished_terminal_read_from_host(pinned_query)
        receipt = await runtime.recover_pending_first_ingress_c02_v2_pinned(
            consumer_operation_id, pinned_query, pinned_read)
        if receipt is None:
            return None
        settled = await runtime.recover_committed_first_ingress_c02_unknown_cost_v2_pinned(
            consumer_operation_id, pinned_read)
        return receipt, settled
    except asyncio.CancelledError:
        raise
    except Exception:
        return None
    finally:
        await transport.close()


async def run_installed_committed_first_ingress_c02_cost_v2(
    runtime: RuntimeContext, installation: V2InstallationAssembly,
    consumer_operation_id: str,
) -> bool | None:
    """Return False for legacy cost, True for settled terminal v2, None on HOLD."""
    if (type(runtime) is not RuntimeContext
            or type(installation) is not V2InstallationAssembly
            or type(consumer_operation_id) is not str or not consumer_operation_id
            or type(installation.admin_bundle) is not AdminInstallationBundle
            or type(installation.admin_bundle.tls_profile) is not AuthorityTlsProfile):
        return None
    request = await runtime.read_committed_first_ingress_c02_terminal_request_v2(
        consumer_operation_id)
    if request is False:
        return False
    if (type(request) is not TerminalRecoveryReadRequestV1
            or request.original_key.namespace
               != installation.installation_policy.namespace
            or request.original_key.installation_id
               != installation.installation_grant.installation_id):
        return None
    profile = installation.admin_bundle.tls_profile
    provisioning = AuthorityProvisioningRequest(
        protocol=AUTHORITY_PROTOCOL, profile_id=profile.profile_id,
        plugin_name="astrbot_plugin_sylanne", host_api_version="4.28.1",
        package_root=installation.package_root, data_dir=installation.data_dir,
        publisher_package=PublisherPackageIdentity(
            installation.installation_policy.manifest_digest),
    )
    transport = MtlsAuthorityTransport({profile.profile_id: profile})
    try:
        handshake = await transport.handshake(
            provisioning, protocol=AUTHORITY_V2_PROTOCOL)
        grant = await transport.installation_grant_v2(provisioning, handshake)
        if (not handshake.valid_pairing()
                or not same_installed_grant_identity_v2(
                    installation.installation_grant, grant)
                or grant.channel_binding_sha256 != handshake.channel_binding_sha256):
            return None
        pinned_query = PinnedTerminalC02RecoveryQueryV1(
            transport=transport, provisioning=provisioning,
            handshake=handshake, grant=grant,
            namespace=request.original_key.authority_namespace,
            request=request)
        pinned = await pin_finished_terminal_read_from_host(pinned_query)
        return (True if await runtime.recover_committed_first_ingress_c02_unknown_cost_v2_pinned(
            consumer_operation_id, pinned) else None)
    except asyncio.CancelledError:
        raise
    except Exception:
        return None
    finally:
        await transport.close()


async def run_installed_first_ingress_c02_v1(
    runtime: RuntimeContext, installation: V2InstallationAssembly, **kwargs,
) -> CommitReceipt | None:
    """Compatibility entry uses the v2 first seal on the installed host."""
    return await run_installed_first_ingress_c02_v2(
        runtime, installation, **kwargs)


__all__ = (
    "run_installed_first_ingress_c02_v1",
    "run_installed_first_ingress_c02_v2",
    "run_installed_pending_first_ingress_c02_v2",
    "run_installed_committed_first_ingress_c02_cost_v2",
    "original_unacquired_handoff_v1",
    "original_acquired_handoff_v1",
    "installed_first_ingress_c02_pairing_ready_v1",
)
