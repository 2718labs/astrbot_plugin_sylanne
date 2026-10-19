"""One finite Host continuation of the installed C4 artifact model task.

W01 owns each preparation, acquisition, terminal wake and content adoption.
The existing paired model runtime owns the original call, once admission,
terminal and accounting. This driver retains only content-free progress.
"""
from __future__ import annotations

import asyncio

from ..model_broker.artifact_draft_v1 import (
    ArtifactDraftTaskSelectorV1, artifact_draft_model_ids_v1,
)
from ..runtime.d11_artifact_draft_model_v1 import (
    InstalledArtifactDraftModelRuntimeV1,
    execute_prepared_artifact_draft_model_v1,
    installed_artifact_draft_workflow_v1,
)
from .authority_profile import AdminInstallationBundle
from .v2_installation import V2InstallationAssembly


def _retained_artifact_graph_calls_v3(worker):
    """Consume each actual result once; replacement drops only its previous DTO lease."""
    from contextlib import contextmanager,ExitStack
    from ..graph_worker import OwnedGraphStorageResultV3

    @contextmanager
    def retain():
        slots={}
        with ExitStack()as lifetime:
            async def call(callback,*,slot):
                result=await worker.call(callback)
                current=None
                if type(result)is OwnedGraphStorageResultV3:
                    value,retention=result.take_value_v3()
                    current=ExitStack();current.callback(retention.release)
                    lifetime.callback(current.close)
                else:value=result
                previous=slots.pop(slot,None)
                if previous is not None:previous.close()
                if current is not None:
                    if value is None:current.close()
                    else:slots[slot]=current
                return value
            yield call
    return retain()


async def run_installed_post_c02_artifact_draft_v1(
    runtime, installation, *, c02_operation_id: str, source_ref: str,
    fresh_cause_hint: bool = False,
) -> dict[str, object]:
    """Advance at most four current operations and one original model call.

    The live cause hint permits asking W01 to prepare. It supplies no Source,
    Owner, worker, budget or deadline authority. Cold entry only consumes an
    existing prepared task, and every subsequent stage is admitted anew.
    """
    from ..runtime_context import RuntimeContext

    if type(runtime) is not RuntimeContext or type(installation) is not V2InstallationAssembly:
        raise TypeError("C4 Host continuation requires its actual installed RuntimeContext")
    if type(fresh_cause_hint) is not bool:
        raise TypeError("C4 live scheduling hint must be boolean")
    model = runtime._v2_artifact_draft_model_runtime_v1
    bundle = installation.admin_bundle
    if (type(model) is not InstalledArtifactDraftModelRuntimeV1
            or type(bundle) is not AdminInstallationBundle
            or bundle is not runtime._v2_model_bundle or model.bundle is not bundle
            or model.graph is not runtime._v2_coordinator
            or model.worker is not runtime._worker
            or model.bootstrap is not runtime._v2_bootstrap
            or model.authority_client is not runtime._v2_authority_client
            or model.client_grant is not runtime._v2_authority_client_grant
            or model.owner_loop is not runtime._v2_authority_loop
            or model.owner_loop is not asyncio.get_running_loop()
            or not runtime._v2_namespace_provisioned):
        return {"status": "held", "missing_inputs": ["actual_installed_artifact_model_runtime"]}
    installed_artifact_draft_workflow_v1(bundle)
    arguments = {"c02_operation_id": c02_operation_id, "source_ref": source_ref}
    progress = None
    with _retained_artifact_graph_calls_v3(model.worker)as artifact_call:

        def held(missing, *, reason_code=None):
            value = {"status": "held", **arguments, "missing_inputs": [missing]}
            if progress is not None:
                value.update(model_job_id=progress["model_job_id"],
                             cycle_phase=progress["cycle_phase"],
                             model_phase=progress["model_phase"],
                             paid=progress["paid"], result=progress["result"])
            if reason_code is not None:
                value["reason_code"] = reason_code
            return value

        async def read():
            value = await artifact_call(lambda graph:
                graph.read_current_post_c02_artifact_draft_resume_v1(
                    model.bootstrap, bundle, **arguments), slot='value')
            task = value["selector"]
            if (value["schema"] != "d11.artifact-draft-resume.v1"
                    or value["c02_operation_id"] != c02_operation_id
                    or value["source_ref"] != source_ref
                    or type(task) is not ArtifactDraftTaskSelectorV1
                    or task.namespace != bundle.installation_policy.namespace
                    or task.c02_operation_id != c02_operation_id
                    or artifact_draft_model_ids_v1(task)["job"] != value["model_job_id"]):
                raise ValueError("C4 current resume metadata differs from its original task")
            return value

        async def operate(operation_kind):
            await artifact_call(lambda graph:
                graph.run_current_post_c02_artifact_draft_operation_v1(
                    model.bootstrap, bundle, operation_kind=operation_kind, **arguments), slot='run_current_post_c02_artifact_draft_operation_v1')
            # The returned Future or receipt status does not establish the next
            # stage. Re-read the real Source-qualified originals and job state.
            return await read()

        try:
            phase_progress = await artifact_call(lambda graph:
                graph.read_current_post_c02_artifact_phase_resume_v2(model.bootstrap, bundle,
                    c02_operation_id=c02_operation_id, source_ref=source_ref), slot='phase_progress')
            if phase_progress is not None:
                return await _run_installed_artifact_phase_model_v2(model, phase_progress,
                    c02_operation_id=c02_operation_id, source_ref=source_ref, fresh_cause_hint=fresh_cause_hint, runtime=runtime)
            progress = await read()
            if not progress["prepared"]:
                if not fresh_cause_hint:
                    return held("original_prepared_artifact_task")
                progress = await operate("prepare_artifact_draft_model")
                if not progress["prepared"]:
                    return held("actual_committed_artifact_preparation")

            if not progress["adopted"]:
                if not progress["request_sealed"]:
                    if (progress["model_phase"] != "queued"
                            or progress["model_cancel_generation"] != 0):
                        return held("current_original_artifact_worker_admission")
                    progress = await operate("acquire_artifact_draft_model")
                    if not progress["request_sealed"]:
                        return held("actual_committed_artifact_worker_request")

                if progress["paid"] != progress["result"]:
                    # A paid fact cannot prove that a one-shot content delivery
                    # was never attempted. Preserve the original partial state.
                    return held("actual_paired_artifact_paid_and_result_originals")
                if not progress["paid"]:
                    if (progress["model_phase"] != "running"
                            or progress["model_cancel_generation"] != 0):
                        return held("original_artifact_terminal_and_cost_recovery")
                    await execute_prepared_artifact_draft_model_v1(
                        model, job_id=progress["model_job_id"])
                    progress = await read()
                    if not progress["paid"] or not progress["result"]:
                        return held("original_artifact_terminal_and_cost_recovery")

                if progress["cycle_phase"] in {"waiting", "queued"}:
                    progress = await operate("wake_artifact_draft_cycle_v1")
                if progress["cycle_phase"] != "running":
                    return held("actual_artifact_terminal_wake_and_cycle_acquisition")
                progress = await operate("adopt_artifact_draft_content")
                if not progress["adopted"]:
                    return held("actual_current_artifact_content_adoption")

            return {"status": "artifact_draft_content_adopted", **arguments,
                    "selector": progress["selector"], "target_mode": progress["target_mode"],
                    "model_job_id": progress["model_job_id"],
                    "cycle_job_id": progress["cycle_job_id"]}
        except (RuntimeError, ValueError) as exc:
            # Every action retains its original IDs. An uncertain call or delivery
            # has no retry in this invocation and cannot authorize another call.
            return held("actual_current_artifact_original_qualification",
                        reason_code=type(exc).__name__)


async def _run_installed_artifact_phase_model_v2(model, progress, *, c02_operation_id, source_ref, fresh_cause_hint, runtime):
    """Consume one real selected generation phase with its original once call."""
    with _retained_artifact_graph_calls_v3(model.worker)as artifact_call:
        from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2, artifact_draft_model_ids_v2
        from ..runtime.d11_artifact_draft_model_v1 import (installed_artifact_draft_workflow_v2,
            execute_prepared_artifact_draft_model_v2)
        arguments = {"c02_operation_id": c02_operation_id, "source_ref": source_ref}
        original_phase = progress["selector"]
        if type(original_phase) is not ArtifactDraftPhaseSelectorV2:
            raise ValueError("installed phase driver requires its actual selected typed phase")

        def held(missing):
            return {"status": "held", **arguments, "selector": original_phase,
                "phase_kind": original_phase.phase_kind, "missing_inputs": [missing]}

        async def read():
            value = await artifact_call(lambda graph:
                graph.read_current_post_c02_artifact_phase_resume_v2(model.bootstrap, model.bundle, **arguments), slot='value')
            if (value is None or value["schema"] != "d11.artifact-draft-phase-resume.v2"
                    or value["selector"] != original_phase or value["c02_operation_id"] != c02_operation_id
                    or value["source_ref"] != source_ref):
                raise ValueError("phase driver changed its original selected phase while running")
            return value

        async def operate(kind):
            await artifact_call(lambda graph:
                graph.run_current_post_c02_artifact_phase_operation_v2(model.bootstrap, model.bundle,
                    operation_kind=kind, **arguments), slot='run_current_post_c02_artifact_phase_operation_v2')
            return await read()

        try:
            if progress["phase_group_complete"]:
                return {"status": "artifact_phase_group_verified", **arguments, "selector": original_phase}
            if not progress["generation"]:
                if not progress["contract_registered"]:
                    return held("actual_preregistered_artifact_phase_contract")
                if model.bundle.artifact_phase_observer is not None and not progress['assessment_registered']:
                    async def observation_state():
                        return await artifact_call(lambda graph:graph.read_current_artifact_phase_observation_progress_v3(
                            model.bootstrap,model.bundle,**arguments), slot='read_current_artifact_phase_observation_progress_v3')
                    observation=await observation_state()
                    if not observation['basis_prepared']:
                        progress=await operate('prepare_artifact_phase_observation_v1')
                        observation=await observation_state()
                    if not observation['basis_prepared']:
                        return held('actual_committed_independent_observation_basis')
                    if observation['job'] is None:
                        progress=await operate('serve_concern')
                        observation=await observation_state()
                    job=observation['job']
                    if job is None:return held('actual_independent_observer_ticket_selected_and_prepared')
                    if not observation['observation_complete']:
                        if job.phase not in {'queued','running'} or job.cancel_epoch:
                            return held('actual_uncancelled_original_independent_observer_job')
                        from ..runtime.d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
                        service=runtime._v2_d07_execution_service
                        if (type(service)is not InstalledD07ExecutionServiceV1 or service.bundle is not model.bundle
                                or service.graph is not model.graph or service.worker is not model.worker):
                            return held('actual_installed_independent_observer_execution_service')
                        await service.execute_current_d07_job_v1(job)
                        observation=await observation_state()
                    if not observation['observation_complete']:
                        return held('actual_independent_observer_terminal_settlement_and_all_adopted_findings')
                if not progress["assessment_registered"]:
                    progress = await operate("observe_artifact_phase_postconditions_v1")
                if not progress["assessment_registered"]:
                    return held("actual_registered_artifact_phase_semantic_assessment")
                statuses = progress["assessment_statuses"]
                if not statuses or any(status != "satisfied" for status in statuses):
                    result = held("actual_satisfied_artifact_phase_postconditions")
                    result["condition_statuses"] = statuses
                    return result
                if not progress["verified"]:
                    progress = await operate("verify_artifact_draft_phase_v2")
                if not progress["verified"]:
                    return held("actual_independently_verified_artifact_check_phase")
                checkpoint = await artifact_call(lambda graph:
                    graph.checkpoint_current_artifact_phase_v2(model.bootstrap, model.bundle, **arguments), slot='checkpoint')
                return {"status": "artifact_phase_check_verified", **arguments,
                    "selector": original_phase, "checkpoint": checkpoint}
            if not progress["checkpoint_activated"]:
                progress = await operate(progress["checkpoint_activation_operation"])
                if not progress["checkpoint_activated"]:
                    return held("actual_selected_task_checkpoint_activation")
            if not progress["contract_registered"]:
                progress = await operate("register_artifact_phase_postcondition_contract_v1")
                if not progress["contract_registered"]:
                    return held("actual_preregistered_artifact_phase_contract")
            installed_artifact_draft_workflow_v2(model.bundle)
            if progress["model_job_id"] != artifact_draft_model_ids_v2(original_phase)["job"]:
                raise ValueError("phase driver model job differs from its original phase")
            if not progress["prepared"]:
                if not fresh_cause_hint:
                    return held("original_prepared_artifact_phase")
                progress = await operate("prepare_artifact_draft_model_v2")
                if not progress["prepared"]:
                    return held("actual_committed_artifact_phase_preparation")
            if not progress["adopted"]:
                if not progress["request_sealed"]:
                    if progress["model_phase"] != "queued" or progress["model_cancel_generation"] != 0:
                        return held("current_original_artifact_phase_worker_admission")
                    progress = await operate("acquire_artifact_draft_model_v2")
                if not progress["request_sealed"]:
                    return held("actual_double_counted_artifact_phase_acquisition")
                if progress["paid"] != progress["result"]:
                    return held("actual_paired_artifact_phase_paid_and_result_originals")
                if not progress["paid"]:
                    if progress["model_phase"] != "running" or progress["model_cancel_generation"] != 0:
                        return held("original_artifact_phase_terminal_and_cost_recovery")
                    await execute_prepared_artifact_draft_model_v2(model, job_id=progress["model_job_id"])
                    progress = await read()
                if not progress["paid"] or not progress["result"]:
                    return held("original_artifact_phase_terminal_and_cost_recovery")
                if progress["cycle_phase"] in {"waiting", "queued"}:
                    progress = await operate("wake_artifact_draft_cycle_v2")
                if progress["cycle_phase"] != "running":
                    return held("actual_artifact_phase_terminal_wake_and_cycle_acquisition")
                progress = await operate("adopt_artifact_draft_content_v2")
            if not progress["adopted"]:
                return held("actual_current_artifact_phase_content_adoption")
            return {"status": "artifact_draft_phase_content_adopted", **arguments,
                "selector": original_phase, "target_mode": progress["target_mode"],
                "model_job_id": progress["model_job_id"], "cycle_job_id": progress["cycle_job_id"]}
        except (RuntimeError, ValueError) as exc:
            result = held("actual_current_artifact_phase_original_qualification")
            result["reason_code"] = type(exc).__name__
            return result
