"""Fixed Goal cancellation gates over already qualified Artifact originals."""
from .contract import AuthorityUnavailable
from .owner_goal_cancellation_contract_v1 import require_goal_not_cancelled_in_tx_v1
from ..runtime.d08_personal_plan_v1 import artifact_goal_plan_keys_v1


def require_artifact_task_not_cancelled_in_tx_v1(db, *, service, namespace,
        c02_operation_id, root_registration_ref, action):
    goal = artifact_goal_plan_keys_v1(namespace, c02_operation_id=c02_operation_id,
        root_registration_ref=root_registration_ref)[0]
    if service.namespace_id != namespace:
        raise AuthorityUnavailable("actual Artifact Goal gate namespace differs")
    return require_goal_not_cancelled_in_tx_v1(db, service=service, goal_ref=goal.token,
        c02_operation_id=c02_operation_id, root_registration_ref=root_registration_ref, action=action)


def observe_current_artifact_goal_target_v1(verifier, *, model_service, credential,
        subject, holder, intent, expected_anchor, permit=None):
    from .model_reply_scope_observation_v3 import observe_authority_model_reply_scope_v3
    from ..runtime.jobs import get_job
    from ..model_broker.artifact_draft_v1 import (ArtifactDraftTaskSelectorV1,
        ArtifactDraftPhaseSelectorV2, artifact_draft_from_wire_v1, artifact_draft_from_wire_v2)
    from ..runtime.d11_artifact_draft_model_v1 import (read_artifact_draft_prepared_v1,
        read_artifact_draft_prepared_v2)
    observation = observe_authority_model_reply_scope_v3(verifier, model_service=model_service,
        credential=credential, subject=subject, holder=holder, intent=intent,
        expected_anchor=expected_anchor, permit=permit)
    def read_target(db):
        job = get_job(db, intent.job_id)
        if job is None: raise AuthorityUnavailable("actual model Goal parent job is absent")
        if job.work_kind != "artifact_draft_v1": return None
        raw = job.continuation
        if type(raw) is not dict or set(raw) != {"schema","selector","prepared_digest"}:
            raise AuthorityUnavailable("actual Artifact model job parent differs")
        if raw["schema"] == "d11.artifact-draft-phase-model-job.v2":
            selector = artifact_draft_from_wire_v2(raw["selector"], ArtifactDraftPhaseSelectorV2)
            task = selector.task
            prepared = read_artifact_draft_prepared_v2(db, namespace=task.namespace,
                issuer=verifier._issuer, selector=selector)
        elif raw["schema"] == "d11.artifact-draft-model-job.v1":
            selector = artifact_draft_from_wire_v1(raw["selector"], ArtifactDraftTaskSelectorV1)
            task = selector
            prepared = read_artifact_draft_prepared_v1(db, namespace=task.namespace,
                issuer=verifier._issuer, selector=selector)
        else: raise AuthorityUnavailable("unregistered Artifact model parent variant")
        if prepared is None or (prepared.job_id,prepared.call_id,prepared.digest) != (
                intent.job_id,intent.call_id,intent.binding_digest):
            raise AuthorityUnavailable("model Goal target lacks its exact signed prepared call")
        return task.namespace, task.c02_operation_id, task.root_registration_ref
    return observation.evaluate_v3(read_target)


def require_model_artifact_goal_not_cancelled_in_tx_v1(db, *, model_service, target, action):
    if target is None: return
    from .owner_goal_cancellation_v1 import InstalledOwnerGoalCancellationServiceV1
    service = model_service._owner_goal_cancellation_service_v1
    if (type(service) is not InstalledOwnerGoalCancellationServiceV1
            or service.core is not model_service._fences.core
            or service.fences is not model_service._fences):
        raise AuthorityUnavailable("actual installed Artifact Goal barrier service unavailable")
    return require_artifact_task_not_cancelled_in_tx_v1(db, service=service,
        namespace=target[0], c02_operation_id=target[1], root_registration_ref=target[2], action=action)
