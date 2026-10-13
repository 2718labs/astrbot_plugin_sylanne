"""Host continuation of one graph-issued natural generation call.

The graph owns the original job and typed request. Authority owns admission,
the terminal and the worker result. A paid terminal is only accounting evidence;
it cannot become a review input or a platform reply without a trusted result
selector and the later D09/D11 product gates.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, replace
import json
import math

from ..authority_service.natural_original_binding_verifier import (
    NaturalOriginalCallIdentityReadV2,
    PinnedNaturalOriginalCallIdentityVerifierV2,
)
from ..authority_service.v2_model_egress_contract import (
    ModelEgressDraftV1, ModelTerminalReceiptV2,
)
from ..authority_service.v2_natural_generation_output_contract import (
    NaturalGenerationOriginalOutputV2,
)
from ..model_broker.broker import ModelCallRequest, ModelProviderDescriptor
from ..runtime.jobs import PersistentJob
from ..runtime.model_cost_settlement import (
    OriginalModelCostCommitV1, original_model_cost_operation_id_v1,
)
from ..runtime.natural_reply_job_v2 import SavedNaturalPreparationV2
from ..runtime.restore_anchor import RestoreAnchor
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
class InstalledNaturalGenerationProgressV2:
    """Original generation progress; no model body or review authority."""

    original: NaturalOriginalCallIdentityReadV2 | None
    job: PersistentJob | None
    call: ModelCallRequest | None
    egress: FrozenNaturalEgressResultV2 | None
    cost: OriginalModelCostCommitV1 | None
    output: NaturalGenerationOriginalOutputV2 | None
    completed_job: PersistentJob | None
    status: str  # terminal_hold | cost_hold | terminal_commit_hold | review_content_hold | no_reply_hold

    def __post_init__(self) -> None:
        if self.egress is None:
            if (self.original is not None or self.job is not None
                    or self.call is not None or self.cost is not None
                    or self.completed_job is not None
                    or type(self.output) is not NaturalGenerationOriginalOutputV2
                    or self.status not in {"review_content_hold", "no_reply_hold"}
                    or (self.output.status == "no_reply_hold") !=
                       (self.status == "no_reply_hold")):
                raise ValueError("natural generation terminal replay differs")
            return
        if (type(self.original) is not NaturalOriginalCallIdentityReadV2
                or type(self.job) is not PersistentJob
                or type(self.call) is not ModelCallRequest
                or type(self.egress) is not FrozenNaturalEgressResultV2
                or self.egress.original != self.original
                or self.original.request != self.call
                or (self.cost is not None and
                    type(self.cost) is not OriginalModelCostCommitV1)
                or (self.output is not None and
                    type(self.output) is not NaturalGenerationOriginalOutputV2)
                or (self.completed_job is not None and
                    type(self.completed_job) is not PersistentJob)
                or self.status not in {
                    "terminal_hold", "cost_hold", "terminal_commit_hold",
                    "review_content_hold", "no_reply_hold",
                }
                or (self.egress.terminal is None) !=
                   (self.status == "terminal_hold")
                or (self.cost is None) !=
                   (self.status not in {
                       "terminal_commit_hold", "review_content_hold",
                       "no_reply_hold",
                   })
                or (self.output is None) !=
                   (self.status not in {"review_content_hold", "no_reply_hold"})
                or (self.completed_job is None) !=
                   (self.status not in {"review_content_hold", "no_reply_hold"})
                or (self.status in {"review_content_hold", "no_reply_hold"}
                    and (self.output.status == "no_reply_hold") !=
                        (self.status == "no_reply_hold"))
                or (self.completed_job is not None and
                    (self.completed_job.job_id != self.job.job_id
                     or self.completed_job.phase != "completed"))):
            raise ValueError("natural generation progress differs from original facts")


def _original_generation_binding(
    saved: SavedNaturalPreparationV2, job: PersistentJob,
    call: ModelCallRequest, prepared: tuple,
    original: NaturalOriginalCallIdentityReadV2,
) -> tuple[ModelEgressDraftV1, RestoreAnchor] | None:
    """Join W01's current read to W07's independently pinned original row."""
    if (type(saved) is not SavedNaturalPreparationV2
            or saved.stage != "generation"
            or type(job) is not PersistentJob
            or type(call) is not ModelCallRequest
            or type(prepared) is not tuple or len(prepared) != 3
            or type(original) is not NaturalOriginalCallIdentityReadV2):
        return None
    current_call, draft, anchor = prepared
    seal = saved.seal
    if (type(current_call) is not ModelCallRequest or current_call != call
            or type(draft) is not ModelEgressDraftV1
            or type(anchor) is not RestoreAnchor
            or original.stage != "generation" or original.seal != seal
            or original.request != call
            or original.typed_request_digest != call.digest
            or original.worker_fence != job.fence
            or (job.job_id, job.operation_id, job.work_kind,
                job.phase, job.budget_ref) !=
               (seal.job_id, seal.original_operation_id,
                "natural_generation", "running", seal.parent_budget_lease_id)
            or job.lease_holder != call.envelope.authority.actor
            or (call.identity.operation_id, call.identity.phase,
                call.call_id, call.envelope.parent_budget_lease_ref) !=
               (seal.acquire_operation_id, "natural_generation",
                seal.call_id, seal.parent_budget_lease_id)
            or (draft.job_id, draft.operation_id,
                draft.acquire_operation_id, draft.call_id,
                draft.request_digest, draft.worker_fence,
                draft.budget_reservation_operation_id,
                draft.budget_lease_id) !=
               (seal.job_id, seal.acquire_operation_id,
                seal.acquire_operation_id, seal.call_id,
                call.digest, job.fence, seal.reservation_operation_id,
                seal.parent_budget_lease_id)):
        return None
    return draft, anchor


async def run_installed_post_c02_natural_generation_v2(
    runtime, installation: V2InstallationAssembly, *, context,
    trusted_umo: str, saved: SavedNaturalPreparationV2,
) -> InstalledNaturalGenerationProgressV2 | None:
    """Acquire, execute, and account for one original natural generation.

    W01's paid-consumer readiness gate controls acquisition. If the installed
    terminal, cost or current graph read is unavailable, the operation holds on
    its original identity. Result content and review remain unavailable until
    W01/W09 provide a scoped worker result selector.
    """
    from astrbot.api.star import Context

    from ..runtime_context import RuntimeContext

    if (type(runtime) is not RuntimeContext
            or type(installation) is not V2InstallationAssembly
            or not isinstance(context, Context)
            or type(trusted_umo) is not str or not trusted_umo
            or type(saved) is not SavedNaturalPreparationV2
            or saved.stage != "generation"
            or saved.state not in {"queued", "acquired", "terminal"}):
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
            or saved.seal.namespace != policy.namespace
            or saved.seal.installation_id != policy.installation_id
            or bundle.model_workflows is None):
        return None
    workflow = bundle.model_workflows.natural_generation
    if (type(workflow) is not AdminModelWorkflowV2
            or workflow.work_kind != "natural_generation"
            or workflow.purpose != "proposal"):
        return None
    try:
        audience = json.loads(saved.frozen.input.plan.audience_id)
    except (TypeError, ValueError):
        return None
    if (type(audience) is not list or len(audience) != 2
            or any(type(value) is not str or not value for value in audience)
            or audience[0] != trusted_umo
            or saved.frozen.input.plan.audience_id not in workflow.audiences):
        return None

    transport = MtlsAuthorityTransport({
        bundle.tls_profile.profile_id: bundle.tls_profile})
    adapter = None
    acquired = None
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

        def acquire(graph):
            anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.subject, issuer_domain="d11",
                namespace=policy.namespace, domains=("d11",),
                activation_generation=anchor.activation_generation,
                operation_id=saved.seal.acquire_operation_id)
            try:
                unacquired = AuthorityContext(
                    grant.subject, "d11", capability, policy.namespace,
                    ("activity",), workflow.purpose,
                    (saved.frozen.input.plan.audience_id,),
                    workflow.provider_config_ref,
                    anchor.activation_generation)
                current = graph.read_natural_original_stage_preparation_v2(
                    unacquired, lease, saved.seal.c02_operation_id,
                    "generation", bundle)
                if (type(current) is not SavedNaturalPreparationV2
                        or current.seal != saved.seal
                        or current.frozen != saved.frozen):
                    graph.release_authority_lease(bootstrap, lease)
                    return None
                if current.state == "terminal":
                    output = graph.read_natural_generation_terminal_receipt_v2(
                        unacquired, lease, saved.seal.c02_operation_id,
                        bundle)
                    graph.release_authority_lease(bootstrap, lease)
                    return ("terminal", output)
                if current.state not in {"queued", "acquired"}:
                    graph.release_authority_lease(bootstrap, lease)
                    return None
                job, call = graph.acquire_post_c02_natural_generation_v2(
                    unacquired, lease, saved.seal.c02_operation_id,
                    bundle, lease_seconds=min(3600, math.ceil(
                        workflow.timeout_seconds) + 120))
                return (replace(unacquired, worker_fence=job.fence),
                        lease, job, call)
            except BaseException:
                graph.release_authority_lease(bootstrap, lease)
                raise

        acquired = await worker.call(acquire)
        if acquired is None:
            return None
        if acquired[0] == "terminal":
            output = acquired[1]
            if (type(output) is not NaturalGenerationOriginalOutputV2
                    or output.request.c02_operation_id
                       != saved.seal.c02_operation_id
                    or output.request.source_ref != saved.seal.source_ref
                    or output.original_seal_digest
                       != canonical_digest(asdict(saved.seal))):
                return None
            return InstalledNaturalGenerationProgressV2(
                None, None, None, None, None, output, None,
                "no_reply_hold" if output.status == "no_reply_hold"
                else "review_content_hold")
        authority, lease, job, call = acquired
        prepared = await worker.call(lambda graph:
            graph.read_natural_model_egress_preparation_v2(
                authority, lease, saved.seal.c02_operation_id,
                "generation", bundle))
        verifier = PinnedNaturalOriginalCallIdentityVerifierV2(
            installation.graph_path,
            installation_id=policy.installation_id,
            generation=workflow, review=bundle.model_workflows.natural_review)
        original = verifier.read(
            policy.namespace, saved.seal.c02_operation_id, "generation")
        if original is None:
            return None
        binding = _original_generation_binding(
            saved, job, call, prepared, original)
        if binding is None:
            return None
        draft, anchor = binding
        if (call.envelope.authority != authority
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
            return InstalledNaturalGenerationProgressV2(
                original, job, call, egress, None, None, None,
                "terminal_hold")
        if (type(terminal) is not ModelTerminalReceiptV2
                or terminal.call_id != call.call_id
                or terminal.request_digest != call.digest
                or terminal.installation_id != policy.installation_id):
            return None
        try:
            quote_ref = job.operator_versions["resource_quote"]
            quote_id, version = quote_ref.rsplit(":", 1)
            quote_version = int(version)
            if quote_version < 1:
                return None
            cost = await worker.call(lambda graph:
                graph.commit_natural_generation_model_cost_v2(
                    bootstrap, policy.namespace, egress.intent,
                    quote_id=quote_id, quote_version=quote_version))
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
            return InstalledNaturalGenerationProgressV2(
                original, job, call, egress, None, None, None,
                "cost_hold")
        # W01 is the sole consumer of the original result read attempt. Its
        # installed port reads the Authority output digest once, then commits
        # that digest with the D11 terminal in the same graph transaction.

        def complete(graph):
            current_anchor = port.current_anchor(
                namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            operation_id = "natural-generation-terminal-" + canonical_digest({
                "namespace": policy.namespace.as_tuple,
                "original_operation_id": saved.seal.original_operation_id,
            })[:48]
            terminal_lease, capability = graph.grant(
                bootstrap, actor=grant.subject, issuer_domain="d11",
                namespace=policy.namespace, domains=("d11",),
                activation_generation=current_anchor.activation_generation,
                operation_id=operation_id)
            try:
                terminal_authority = AuthorityContext(
                    grant.subject, "d11", capability, policy.namespace,
                    ("activity",), workflow.purpose,
                    authority.audience, workflow.provider_config_ref,
                    current_anchor.activation_generation)
                completed = graph.complete_natural_generation_model_job_v2(
                    terminal_authority, terminal_lease,
                    saved.seal.c02_operation_id, egress.intent, bundle)
                output = graph.read_natural_generation_terminal_receipt_v2(
                    terminal_authority, terminal_lease,
                    saved.seal.c02_operation_id, bundle)
                return completed, output
            finally:
                graph.release_authority_lease(bootstrap, terminal_lease)

        try:
            completed, output = await worker.call(complete)
        except Exception:
            completed, output = None, None
        if (type(completed) is not PersistentJob
                or type(output) is not NaturalGenerationOriginalOutputV2
                or completed.job_id != job.job_id
                or completed.operation_id != job.operation_id
                or completed.phase != "completed"
                or completed.result_ref != call.call_id
                or (output.request.authority_id,
                    output.request.authority_namespace,
                    output.request.namespace,
                    output.request.c02_operation_id,
                    output.request.source_ref,
                    output.request.installation_id,
                    output.request.job_id,
                    output.request.original_operation_id,
                    output.request.acquire_operation_id,
                    output.request.call_id,
                    output.request.typed_model_request_digest) !=
                   (grant.authority_id, policy.authority_namespace,
                    policy.namespace, saved.seal.c02_operation_id,
                    saved.seal.source_ref, policy.installation_id,
                    job.job_id, saved.seal.original_operation_id,
                    saved.seal.acquire_operation_id, call.call_id,
                    call.digest)
                or output.original_seal_digest !=
                   canonical_digest(asdict(saved.seal))
                or output.original_intent_digest !=
                   canonical_digest(asdict(egress.intent))
                or output.typed_model_request_digest != call.digest
                or output.terminal_receipt_digest !=
                   canonical_digest(asdict(terminal))
                or output.observation_digest != terminal.observation_digest):
            return InstalledNaturalGenerationProgressV2(
                original, job, call, egress, cost, None, None,
                "terminal_commit_hold")
        return InstalledNaturalGenerationProgressV2(
            original, job, call, egress, cost, output, completed,
            "no_reply_hold" if output.status == "no_reply_hold" else
            "review_content_hold")
    except asyncio.CancelledError:
        if adapter is not None:
            await adapter.abort_local_dispatches()
        raise
    except Exception:
        return None
    finally:
        if acquired is not None and len(acquired) == 4:
            await worker.call(lambda graph:
                graph.release_authority_lease(bootstrap, acquired[1]))
        await transport.close()


__all__ = (
    "InstalledNaturalGenerationProgressV2",
    "run_installed_post_c02_natural_generation_v2",
)
