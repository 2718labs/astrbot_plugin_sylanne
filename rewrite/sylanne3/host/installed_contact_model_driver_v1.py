"""Real installed provider continuation for one fixed proactive model phase."""
import asyncio
from dataclasses import dataclass, asdict
import json
from ..authority_service.v2_model_egress_contract import ModelEgressDraftV1
from ..runtime.contact_graph_runtime_v1 import contact_model_runtime_v1
from ..runtime.contact_model_job_v1 import ContactModelPreparedV1
from ..runtime.model_cost_settlement import OriginalModelCostCommitV1
from ..runtime_contracts import canonical_digest
from ..model_broker.broker import ModelProviderDescriptor
from ..model_broker.contact_expression_v1 import contact_provider_messages_v1
from .astrbot_model_call import AstrBotModelProvider
from .authority_client import AuthorityClient, AuthoritySelection
from .installation_grant_identity import same_installed_grant_identity_v2
from .model_egress_executor import HostModelEgressExecutor
from .mtls_transport import MtlsAuthorityTransport
from .v2_installation import V2InstallationAssembly


@dataclass(frozen=True, slots=True)
class InstalledContactModelProgressV1:
    prepared: ContactModelPreparedV1
    status: str
    terminal: object = None
    cost: OriginalModelCostCommitV1 | None = None
    candidate: object = None

    def __post_init__(self):
        if type(self.prepared) is not ContactModelPreparedV1 or self.status not in {
                "terminal_hold", "cost_hold", "content_hold", "no_contact_hold", "review_required", "whole_batch_paid_pass", "review_rewrite_hold", "review_hold"}:
            raise ValueError("contact installed progress status differs")
        if self.status in {"review_required", "no_contact_hold", "whole_batch_paid_pass", "review_rewrite_hold", "review_hold"} and (self.terminal is None or self.cost is None or self.candidate is None):
            raise ValueError("contact content progress requires its actual paid completed terminal")


def _paid_progress(prepared, phase, candidate, terminal, cost):
    if phase == "contact_generation":
        status = "no_contact_hold" if candidate.status == "no_contact_hold" else "review_required"
    else:
        status = {"pass": "whole_batch_paid_pass", "rewrite": "review_rewrite_hold", "hold": "review_hold"}[candidate.verdict]
    return InstalledContactModelProgressV1(prepared, status, terminal, cost, candidate)


async def run_installed_contact_model_v1(runtime, installation, *, context, trusted_umo, contact_id, phase):
    from astrbot.api.star import Context
    from ..runtime_context import RuntimeContext
    if (type(runtime) is not RuntimeContext or type(installation) is not V2InstallationAssembly
            or not isinstance(context, Context) or phase not in {"contact_generation", "contact_review"}):
        raise TypeError("actual installed contact runtime/provider required")
    worker, bootstrap = runtime._worker, runtime._v2_bootstrap
    bundle, policy, grant = installation.admin_bundle, installation.installation_policy, installation.installation_grant
    if (worker is None or bootstrap is None or runtime._v2_port is None or not runtime._v2_namespace_provisioned
            or runtime._v2_model_bundle is not bundle or runtime._v2_policy is not policy
            or runtime._v2_installation_grant != grant or runtime._data_dir != installation.data_dir):
        raise ValueError("contact Host does not own the actual paired installation")
    workflow = getattr(bundle.model_workflows, phase)
    if workflow is None or workflow.work_kind != phase:
        raise ValueError("contact fixed workflow is not installed")
    transport = MtlsAuthorityTransport({bundle.tls_profile.profile_id: bundle.tls_profile})
    adapter = None
    try:
        client = AuthorityClient(AuthoritySelection(bundle.tls_profile.profile_id), package_root=installation.package_root,
            data_dir=installation.data_dir, transport=transport)
        if (await client.status_v2()).state != "paired":
            raise ValueError("contact Authority is not paired")
        actual_grant = await client.installation_grant_v2()
        if not same_installed_grant_identity_v2(grant, actual_grant):
            raise ValueError("contact actual installation grant changed")
        service = await worker.call(lambda graph: contact_model_runtime_v1(graph, bootstrap, bundle))
        prepared, frozen, job = await worker.call(lambda graph: service.read_preparation(contact_id=contact_id, phase=phase))
        audience = json.loads(frozen.input.adopted_plan.audience_id)
        if (type(audience) is not list or len(audience) != 2 or any(type(v) is not str or not v for v in audience)
                or audience[0] != trusted_umo or frozen.input.adopted_plan.audience_id not in workflow.audiences):
            raise ValueError("contact provider session is outside its actual private route")
        attempts = await worker.call(lambda graph: service.read_result_attempts(contact_id=contact_id, phase=phase))
        if attempts:
            # Recover old delivery gates before any new read or cost fence.
            previous = await worker.call(lambda graph: service.prepare_result_read(
                contact_id=contact_id, phase=phase, attempt=len(attempts)))
            if previous != attempts[-1]:
                raise ValueError("contact result recovery changed its actual saved selector")
            await client.contact_model_result_recover_finish_v1(bundle, actual_grant, read_request=previous)
        if job.phase == "completed":
            await worker.call(lambda graph: service.finish(contact_id=contact_id, phase=phase))
            actual, candidate, terminal, cost = await worker.call(lambda graph:
                service.read_paid_progress(contact_id=contact_id, phase=phase))
            return _paid_progress(actual, phase, candidate, terminal, cost)
        await worker.call(lambda graph: service.acquire(contact_id=contact_id, phase=phase))
        prepared, frozen, job, request, draft, intent, anchor = await worker.call(lambda graph:
            service.read_egress(contact_id=contact_id, phase=phase))
        contact_provider_messages_v1(request, frozen.installation)
        descriptor = ModelProviderDescriptor(workflow.provider_id, "astrbot-openai-official-v1", workflow.model_id,
            frozenset({"text"}), frozenset({workflow.purpose}), frozenset({workflow.privacy_tier}),
            workflow.provider_config_ref, "unknown", False, False)
        adapter = AstrBotModelProvider(context=context, host_loop=asyncio.get_running_loop(), trusted_umo=trusted_umo,
            descriptor=descriptor, admin_model=workflow, installation_bundle=bundle)
        executor = HostModelEgressExecutor(authority=client, bundle=bundle, grant=actual_grant, adapter=adapter)
        if intent is None:
            record, permit = await client.model_prepare_fenced_v1(bundle, actual_grant, draft=draft, expected_anchor=anchor)
            intent = record.intent
            if ModelEgressDraftV1.from_intent(intent) != draft or permit.pinned_anchor != anchor:
                raise ValueError("contact Authority changed its frozen actual model draft")
            if record.state != "prepared":
                return InstalledContactModelProgressV1(prepared, "terminal_hold")
            await worker.call(lambda graph: service.seal_egress(contact_id=contact_id, phase=phase, intent=intent, permit=permit))
            terminal = await executor.execute_once(intent=intent, expected_anchor=anchor, request=request)
        else:
            # Reentry inspects the existing terminal. It never submits another
            # provider admission for a sealed original from an earlier attempt.
            terminal = await executor.recover_original_terminal(intent)
        if terminal is None:
            return InstalledContactModelProgressV1(prepared, "terminal_hold")
        cost = await worker.call(lambda graph: service.commit_cost(contact_id=contact_id, phase=phase, intent=intent))
        if (type(cost) is not OriginalModelCostCommitV1 or cost.call_id != prepared.call_id
                or cost.terminal_receipt_digest != canonical_digest(asdict(terminal))):
            raise ValueError("contact independent actual cost differs from its terminal")
        read_request = await worker.call(lambda graph: service.prepare_result_read(
            contact_id=contact_id, phase=phase, attempt=len(attempts) + 1))
        await service.read_result_delivery(client=client, grant=actual_grant, request=read_request)
        await worker.call(lambda graph: service.finish(contact_id=contact_id, phase=phase))
        _, _, candidate, paid = await worker.call(lambda graph: service.read_paid_result(contact_id=contact_id, phase=phase))
        return _paid_progress(prepared, phase, candidate, terminal, cost)
    except asyncio.CancelledError:
        if adapter is not None:
            await adapter.abort_local_dispatches()
        raise
    finally:
        await transport.close()
