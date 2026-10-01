"""One actual installed appraisal call; unknown resumes only its original state."""
from __future__ import annotations

import asyncio

from ..authority_service.v2_model_egress_contract import ModelEgressDraftV1
from ..model_broker.broker import ModelProviderDescriptor
from .astrbot_model_call import AstrBotModelProvider
from .model_egress_executor import HostModelEgressExecutor
from .v2_installation import V2InstallationAssembly
from .authority_client import AuthorityClient, AuthoritySelection
from .installation_grant_identity import same_installed_grant_identity_v2
from .mtls_transport import MtlsAuthorityTransport
from .d04_appraisal_result_port_v3 import InstalledD04AppraisalResultPortV3
from .model_terminal_cost_port import InstalledModelTerminalCostPort
from .accounting_maintenance_port import InstalledAccountingMaintenancePort


async def run_installed_post_c02_appraisal_v3(runtime, installation, *, context, trusted_umo, c02_operation_id, source_ref):
    if type(installation) is not V2InstallationAssembly or installation is not getattr(runtime._v2_natural_readiness_receipt, "installation", None):
        return {"status": "not_ready", "missing_inputs": ["installed_appraisal_authority"]}
    bundle = installation.admin_bundle
    workflow = bundle.model_workflows.appraisal
    if workflow is None:
        return {"status": "not_configured", "missing_inputs": ["appraisal_workflow"]}
    worker, bootstrap = runtime._worker, runtime._v2_bootstrap
    profile = bundle.tls_profile
    transport = MtlsAuthorityTransport({profile.profile_id: profile})
    client = AuthorityClient(AuthoritySelection(profile.profile_id),
        package_root=installation.package_root, data_dir=installation.data_dir, transport=transport)
    old_ports = None
    try:
        status = await client.status_v2()
        client_grant = await client.installation_grant_v2()
        if (status.state != "paired" or not same_installed_grant_identity_v2(
                installation.installation_grant, client_grant)):
            raise RuntimeError("D04 appraisal current installed pairing differs")
        owner_loop = asyncio.get_running_loop()
        def bind_ports(graph):
            names = ("_GraphCoordinator__d04_appraisal_result_port",
                "_GraphCoordinator__model_terminal_cost_port",
                "_GraphCoordinator__accounting_maintenance_port")
            previous = tuple(getattr(graph, name) for name in names)
            for name, cls in zip(names, (InstalledD04AppraisalResultPortV3,
                    InstalledModelTerminalCostPort, InstalledAccountingMaintenancePort), strict=True):
                setattr(graph, name, cls(client=client, bundle=bundle, grant=client_grant,
                                        owner_loop=owner_loop))
            return names, previous
        old_ports = await worker.call(bind_ports)
        return await _run_appraisal_on_installed_channel_v3(runtime, bundle, workflow,
            client, client_grant, context=context, trusted_umo=trusted_umo,
            c02_operation_id=c02_operation_id, source_ref=source_ref)
    finally:
        if old_ports is not None:
            def restore_ports(graph):
                for name, previous in zip(*old_ports, strict=True):
                    setattr(graph, name, previous)
            await worker.call(restore_ports)
        await transport.close()


async def _run_appraisal_on_installed_channel_v3(runtime, bundle, workflow, client, client_grant,
        *, context, trusted_umo, c02_operation_id, source_ref):
    worker, bootstrap = runtime._worker, runtime._v2_bootstrap
    args = {"c02_operation_id": c02_operation_id, "source_ref": source_ref}
    prepared = await worker.call(lambda graph: graph.prepare_post_c02_appraisal_v3(bootstrap, bundle, **args))
    if prepared["status"] == "not_configured":
        return prepared
    await worker.call(lambda graph: graph.acquire_post_c02_appraisal_v3(bootstrap, bundle, **args))
    try:
        original, job, call, draft, anchor, sealed_intent = await worker.call(lambda graph:
            graph.read_acquired_appraisal_v3(bootstrap, bundle, **args))
    except Exception:
        # A completed original skips execution and proceeds to current adoption.
        return await worker.call(lambda graph: graph.adopt_post_c02_appraisal_v3(bootstrap, bundle, **args))
    if sealed_intent is None:
        record, permit = await client.model_prepare_fenced_v1(bundle, client_grant, draft=draft, expected_anchor=anchor)
    else:
        record, permit = await client.model_recover_fenced_v1(bundle, client_grant, intent=sealed_intent)
        if record.intent != sealed_intent:
            raise ValueError("D04 recovered model call differs from durable original")
        draft = ModelEgressDraftV1.from_intent(sealed_intent)
        anchor = permit.pinned_anchor
    if ModelEgressDraftV1.from_intent(record.intent) != draft or permit.pinned_anchor != anchor:
        raise ValueError("D04 Authority returned another original call")
    if record.state == "prepared":
        await worker.call(lambda graph: graph.seal_appraisal_egress_v3(bootstrap, bundle.installation_policy.namespace,
            intent=record.intent, permit=permit))
        descriptor = ModelProviderDescriptor(workflow.provider_id, "astrbot-openai-official-v1", workflow.model_id,
            frozenset({"text"}), frozenset({workflow.purpose}), frozenset({workflow.privacy_tier}),
            workflow.provider_config_ref, "unknown", False, False)
        adapter = AstrBotModelProvider(context=context, host_loop=asyncio.get_running_loop(), trusted_umo=trusted_umo,
            descriptor=descriptor, admin_model=workflow, installation_bundle=bundle)
        executor = HostModelEgressExecutor(authority=client, bundle=bundle, grant=client_grant, adapter=adapter)
        terminal = await executor.execute_once(intent=record.intent, expected_anchor=anchor, request=call, appraisal_original=original)
        if terminal is None:
            return {"status": "original_terminal_unknown", "job_id": job.job_id}
    elif record.state != "observed":
        return {"status": "original_terminal_unknown", "job_id": job.job_id}
    try:
        paid = await worker.call(lambda graph: graph.settle_post_c02_appraisal_v3(bootstrap, bundle, **args))
    except Exception:
        await worker.call(lambda graph: graph.reconcile_d04_appraisal_cost_v3(bootstrap, bundle, **args))
        raise
    if paid.get("paid") is not True:
        return paid
    return await worker.call(lambda graph: graph.adopt_post_c02_appraisal_v3(bootstrap, bundle, **args))
