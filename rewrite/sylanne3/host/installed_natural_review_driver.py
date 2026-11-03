"""Run one sealed natural review call through Authority and durable graph cost."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
import json
import math

from ..authority_service.natural_original_binding_verifier import (
    NaturalOriginalCallIdentityReadV2,
    PinnedNaturalOriginalCallIdentityVerifierV2,
)
from ..authority_service.v2_model_egress_contract import ModelTerminalReceiptV2
from ..authority_service.v2_natural_review_output_contract import (
    NaturalReviewOriginalOutputV2,
)
from ..model_broker.broker import ModelProviderDescriptor
from ..runtime.jobs import PersistentJob
from ..runtime.model_cost_settlement import (
    OriginalModelCostCommitV1, original_model_cost_operation_id_v1,
)
from ..runtime.natural_reply_job_v2 import SavedNaturalPreparationV2
from ..runtime_contracts import AuthorityContext, canonical_digest
from .astrbot_model_call import AstrBotModelProvider
from .authority_client import AuthorityClient, AuthoritySelection
from .authority_profile import AdminInstallationBundle, AdminModelWorkflowV2
from .installation_grant_identity import same_installed_grant_identity_v2
from .model_egress_executor import (
    FrozenNaturalEgressResultV2, HostModelEgressExecutor,
)
from .mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from .v2_installation import V2InstallationAssembly




@dataclass(frozen=True, slots=True)
class InstalledNaturalReviewProgressV3:
    """Finite progress/receipt metadata; no model request or Source payload."""
    output: NaturalReviewOriginalOutputV2 | None
    status: str
    job_id: str | None = None
    call_id: str | None = None
    typed_request_digest: str | None = None
    cost_operation_id: str | None = None


def _natural_review_progress_v3(original, job, call, egress, cost, output, completed_job, status):
    from ..authority_service.v2_natural_review_output_contract import from_wire, to_wire
    detached = None if output is None else from_wire(to_wire(output), NaturalReviewOriginalOutputV2)
    return InstalledNaturalReviewProgressV3(detached, status,
        job.job_id if job is not None else None,
        call.call_id if call is not None else None,
        call.digest if call is not None else None,
        cost.operation_id if cost is not None else None)


async def run_installed_post_c02_natural_review_v2(
    runtime, installation: V2InstallationAssembly, *, context,
    trusted_umo: str, generation_saved: SavedNaturalPreparationV2,
    review_saved: SavedNaturalPreparationV2,
) -> InstalledNaturalReviewProgressV3 | None:
    """Acquire and settle the review original once; return no model body."""
    from astrbot.api.star import Context

    from ..runtime_context import RuntimeContext

    if (type(runtime) is not RuntimeContext
            or type(installation) is not V2InstallationAssembly
            or not isinstance(context, Context)
            or type(trusted_umo) is not str or not trusted_umo
            or type(generation_saved) is not SavedNaturalPreparationV2
            or generation_saved.stage != "generation"
            or type(review_saved) is not SavedNaturalPreparationV2
            or review_saved.stage != "review"
            or review_saved.state not in {"queued", "acquired", "terminal"}
            or review_saved.parent_original_id != generation_saved.parent_original_id):
        return None
    bundle, grant, policy = (
        installation.admin_bundle, installation.installation_grant,
        installation.installation_policy)
    worker, bootstrap, port = (
        runtime._worker, runtime._v2_bootstrap, runtime._v2_port)
    if (worker is None or bootstrap is None or port is None
            or not runtime._v2_namespace_provisioned
            or runtime._v2_model_bundle is not bundle
            or runtime._v2_policy is not policy
            or runtime._v2_installation_grant != grant
            or runtime._data_dir != installation.data_dir
            or type(bundle) is not AdminInstallationBundle
            or type(bundle.tls_profile) is not AuthorityTlsProfile
            or bundle.installation_policy is not policy
            or generation_saved.seal.namespace != policy.namespace
            or review_saved.seal.namespace != policy.namespace
            or review_saved.seal.installation_id != policy.installation_id
            or bundle.model_workflows is None):
        return None
    workflow = bundle.model_workflows.natural_review
    if (type(workflow) is not AdminModelWorkflowV2
            or workflow.work_kind != "natural_review"
            or workflow.purpose != "proposal"):
        return None
    audience_id = generation_saved.frozen.input.plan.audience_id
    from ..graph_worker import retained_graph_calls_v3
    from ..runtime.natural_stage_egress_work_v3 import (
        NaturalStageEgressV3, start_installed_natural_stage_v3,
    )
    try:
        audience = json.loads(audience_id)
    except (TypeError, ValueError):
        return None
    if (type(audience) is not list or len(audience) != 2
            or any(type(value) is not str or not value for value in audience)
            or audience[0] != trusted_umo
            or audience_id not in workflow.audiences):
        return None

    transport = MtlsAuthorityTransport({
        bundle.tls_profile.profile_id: bundle.tls_profile})
    adapter = None
    acquired = None
    with retained_graph_calls_v3(worker) as graph_call:
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


            acquired = await graph_call(lambda graph: start_installed_natural_stage_v3(
                graph, bootstrap, bundle, saved=review_saved, generation_saved=generation_saved,
                lease_seconds=min(3600, math.ceil(workflow.timeout_seconds) + 120)), slot="acquire")
            if acquired is None:
                return None
            if type(acquired) is tuple and acquired[0] == "terminal":
                output = acquired[1]
                if (type(output) is not NaturalReviewOriginalOutputV2
                        or output.request.parent_original_id
                           != review_saved.parent_original_id
                        or output.original_seal_digest
                           != canonical_digest(asdict(review_saved.seal))):
                    return None
                return _natural_review_progress_v3(
                    None, None, None, None, None, output, None,
                    "paid_review_current_hold" if output.verdict == "pass"
                    else "paid_review_hold")
            if type(acquired) is not NaturalStageEgressV3:
                return None
            authority, job, call, prepared = (acquired.authority, acquired.job,
                acquired.call, acquired.prepared)
            verifier = PinnedNaturalOriginalCallIdentityVerifierV2(
                installation.graph_path,
                installation_id=policy.installation_id,
                generation=bundle.model_workflows.natural_generation,
                review=workflow)
            original = verifier.read(
                policy.namespace, review_saved.parent_original_id, "review")
            seal = review_saved.seal
            if (type(original) is not NaturalOriginalCallIdentityReadV2
                    or original.stage != "review" or original.seal != seal
                    or original.request != call
                    or original.typed_request_digest != call.digest
                    or original.worker_fence != job.fence
                    or type(prepared) is not tuple or len(prepared) != 3):
                return None
            current_call, draft, anchor = prepared
            if (current_call != call
                    or (job.job_id, job.operation_id, job.work_kind,
                        job.phase, job.budget_ref) !=
                       (seal.job_id, seal.original_operation_id,
                        "natural_review", "running", seal.parent_budget_lease_id)
                    or (call.identity.operation_id, call.identity.phase,
                        call.call_id, call.envelope.parent_budget_lease_ref) !=
                       (seal.acquire_operation_id, "natural_review",
                        seal.call_id, seal.parent_budget_lease_id)
                    or (draft.job_id, draft.operation_id,
                        draft.acquire_operation_id, draft.call_id,
                        draft.request_digest, draft.worker_fence,
                        draft.budget_reservation_operation_id,
                        draft.budget_lease_id) !=
                       (seal.job_id, seal.acquire_operation_id,
                        seal.acquire_operation_id, seal.call_id,
                        call.digest, job.fence, seal.reservation_operation_id,
                        seal.parent_budget_lease_id)
                    or draft.subject != grant.subject
                    or draft.authority_id != grant.authority_id
                    or draft.namespace != policy.authority_namespace):
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
                authority=client, bundle=bundle, grant=client_grant,
                adapter=adapter, local_module_admission=runtime.local_module_admission)
            egress = await executor.execute_frozen_natural_once(
                original=original, draft=draft, expected_anchor=anchor)
            if (type(egress) is not FrozenNaturalEgressResultV2
                    or egress.original != original
                    or egress.intent.call_id != call.call_id
                    or egress.intent.request_digest != call.digest):
                return None
            terminal = egress.terminal
            if terminal is None:
                return _natural_review_progress_v3(
                    original, job, call, egress, None, None, None, "terminal_hold")
            if (type(terminal) is not ModelTerminalReceiptV2
                    or terminal.call_id != call.call_id
                    or terminal.request_digest != call.digest
                    or terminal.installation_id != policy.installation_id):
                return None
            try:
                quote_id, version = job.operator_versions["resource_quote"].rsplit(":", 1)
                quote_version = int(version)
                if quote_version < 1:
                    return None
                cost = await graph_call(lambda graph:
                    graph.commit_natural_review_model_cost_v2(
                        bootstrap, policy.namespace, egress.intent,
                        quote_id=quote_id, quote_version=quote_version), slot="cost")
            except Exception:
                cost = None
            if (type(cost) is not OriginalModelCostCommitV1
                    or cost.status not in {"committed", "duplicate"}
                    or cost.operation_id != original_model_cost_operation_id_v1(
                        policy.namespace, call.call_id)
                    or (cost.call_id, cost.quote_id, cost.quote_version,
                        cost.terminal_receipt_digest) !=
                       (call.call_id, quote_id, quote_version,
                        canonical_digest(asdict(terminal)))):
                return _natural_review_progress_v3(
                    original, job, call, egress, None, None, None, "cost_hold")

            def complete(graph):
                current_anchor = port.current_anchor(
                    namespace=policy.namespace,
                    authority_namespace=policy.authority_namespace)
                operation_id = "natural-review-terminal-" + canonical_digest({
                    "namespace": policy.namespace.as_tuple,
                    "original_operation_id": seal.original_operation_id,
                })[:48]
                terminal_lease, capability = graph.grant(
                    bootstrap, actor=grant.subject, issuer_domain="d11",
                    namespace=policy.namespace, domains=("d11",),
                    activation_generation=current_anchor.activation_generation,
                    operation_id=operation_id)
                try:
                    terminal_authority = AuthorityContext(
                        grant.subject, "d11", capability, policy.namespace,
                        ("activity",), workflow.purpose, (audience_id,),
                        workflow.provider_config_ref,
                        current_anchor.activation_generation)
                    completed = graph.complete_natural_review_model_job_v2(
                        terminal_authority, terminal_lease,
                        review_saved.parent_original_id, egress.intent, bundle)
                    output = graph.read_natural_review_terminal_receipt_v2(
                        terminal_authority, terminal_lease,
                        review_saved.parent_original_id, bundle)
                    return completed, output
                finally:
                    graph.release_authority_lease(bootstrap, terminal_lease)

            try:
                completed, output = await graph_call(complete, slot="terminal")
            except Exception:
                completed, output = None, None
            if (type(completed) is not PersistentJob
                    or type(output) is not NaturalReviewOriginalOutputV2
                    or completed.job_id != job.job_id
                    or completed.operation_id != job.operation_id
                    or completed.phase != "completed"
                    or completed.result_ref != call.call_id
                    or (output.request.authority_id,
                        output.request.authority_namespace,
                        output.request.namespace,
                        output.request.parent_original_id,
                        output.request.installation_id,
                        output.request.job_id,
                        output.request.original_operation_id,
                        output.request.acquire_operation_id,
                        output.request.call_id,
                        output.request.typed_model_request_digest) !=
                       (grant.authority_id, policy.authority_namespace,
                        policy.namespace, review_saved.parent_original_id,
                        policy.installation_id, job.job_id,
                        seal.original_operation_id, seal.acquire_operation_id,
                        call.call_id, call.digest)
                    or output.original_seal_digest !=
                       canonical_digest(asdict(seal))
                    or output.original_intent_digest !=
                       canonical_digest(asdict(egress.intent))
                    or output.typed_model_request_digest != call.digest
                    or output.terminal_receipt_digest !=
                       canonical_digest(asdict(terminal))
                    or output.observation_digest != terminal.observation_digest):
                return _natural_review_progress_v3(
                    original, job, call, egress, cost, None, None,
                    "terminal_commit_hold")
            return _natural_review_progress_v3(
                original, job, call, egress, cost, output, completed,
                "paid_review_hold" if output.verdict != "pass" else
                "paid_review_current_hold")
        except asyncio.CancelledError:
            if adapter is not None:
                await adapter.abort_local_dispatches()
            raise
        except Exception:
            return None
        finally:
            acquired = prepared = original = job = call = egress = None
            binding = current_call = draft = anchor = executor = adapter = None
            completed = output = None
            await transport.close()


__all__ = (
    "InstalledNaturalReviewProgressV3",
    "run_installed_post_c02_natural_review_v2",
)
