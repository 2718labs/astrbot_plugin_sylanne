"""Pure exact Artifact Original child locators; never a read capability."""
from dataclasses import dataclass

@dataclass(frozen=True,slots=True)
class ArtifactOriginalChildLocatorsV3:
    life_originals:tuple=()
    production_originals:tuple=()
    operation_ids:tuple=()
    source_refs:tuple=()

def artifact_original_child_locators_v3(*,kind,value):
    from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV1,IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3
    if kind=="artifact_task_scope":
        if type(value)not in{IngressArtifactTaskScopeOriginalV1,IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3}:
            raise TypeError("actual typed Artifact TaskScope parent required")
        life=[("draft_root_capability",value.root.registration_ref),("c1_task_intent",value.c1_intent_ref)]
        if value.objective_ref is not None:life.append(("artifact_task_objective",value.objective_ref))
        if type(value)in{IngressArtifactTaskScopeOriginalV2,IngressArtifactTaskScopeOriginalV3}:
            life.append(("artifact_standing_predecision_approval",value.approval_original_ref))
        if type(value)is IngressArtifactTaskScopeOriginalV3:
            life.append(("artifact_task_continuation_authorization_v2",value.continuation_authorization.original_ref))
        return ArtifactOriginalChildLocatorsV3(tuple(life),(),(value.c02_operation_id,),(value.source_ref,))
    if kind=="joint_executor_index_v1":
        from .joint_node_execution_v1 import JointExecutorIndexV1
        if type(value)is not JointExecutorIndexV1:raise TypeError("actual typed Joint executor index required")
        return ArtifactOriginalChildLocatorsV3((),(("d10",value.binding_ref),),(),value.source_refs)
    if kind=="joint_artifact_prospective_binding_v1":
        from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
        if type(value)is not JointArtifactProspectiveBindingV1:raise TypeError("actual typed Artifact prospective binding required")
        return ArtifactOriginalChildLocatorsV3((("artifact_task_scope",value.task_scope_ref),
            ("artifact_task_objective",value.objective_ref)),(),(),value.source_refs)
    if kind=="joint_node_execution_binding_v1":
        from .joint_node_execution_v1 import JointNodeExecutionBindingV1,ArtifactJointExecutorV1
        from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
        if type(value)is not JointNodeExecutionBindingV1 or type(value.executor)is not ArtifactJointExecutorV1:
            raise TypeError("actual typed legacy Artifact Joint binding required")
        return ArtifactOriginalChildLocatorsV3((("artifact_task_scope",task_scope_ref_v1(value.executor.root_registration_ref)),),
            (),(),value.source_refs)
    raise ValueError("unregistered pure Artifact Original child-locator family")
