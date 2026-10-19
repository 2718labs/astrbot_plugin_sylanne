"""Closed foreground command contracts; no Source permission or default family."""
from dataclasses import dataclass
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import NamespaceId

_CYCLE_V3=frozenset({'create_foreground_cycle','create_foreground_cycle_v2','create_source_note_foreground_cycle_v1',
    'acquire_foreground_cycle','checkpoint_source_note_foreground_cycle_v1',
    'checkpoint_foreground_cycle_v2','checkpoint_foreground_cycle'})
_TASK_V3=frozenset({'derive_ingress_artifact_task_scope_v1','create_artifact_task_plan_v1',
    'create_artifact_task_project_v1','initialize_artifact_task_project_checkpoint_v1','revise_artifact_task_plan_v2',
    'input:freeze_artifact_candidate_preparation_v1','input:freeze_values','input:register_artifact_task_text_extent',
    'input:register_artifact_phase_postcondition_policy_v1','prepare_personal_candidate_eligibility_v1',
    'adopt_personal_candidate_eligibility_v1','prepare_personal_candidates_v1','select_personal_step_v2','evaluate_values',
    'await_existing_artifact_revision_v1','select_existing_artifact_continuation_v1','revise_existing_artifact_v1',
    'input:register_artifact_draft_plan_v3','propose_artifact_draft_action','prepare_selected_source_note_action_v2',
    'compose_artifact_goal_plan','create_artifact_project','initialize_project_checkpoint',
    'prepare_artifact_draft_project_context'})
_PHASE_V3=frozenset({'adopt_artifact_draft_content','adopt_artifact_draft_content_v2','verify_artifact_draft_phase_v2',
    'wake_artifact_draft_cycle_v1','wake_artifact_draft_cycle_v2','register_artifact_phase_postcondition_contract_v1',
    'observe_artifact_phase_postconditions_v1','activate_artifact_task_project_checkpoint_v1',
    'activate_artifact_task_project_checkpoint_v2','register_artifact_task_milestone_v2','serve_concern',
    'prepare_artifact_phase_observation_v1'})
_RECEIPT_V3=frozenset({'finish_artifact_receipt_cycle_v1','derive_artifact_completion_receipt_v1',
    'input:register_life_outcome_v2','advance_life','settle_project_checkpoint','settle_personal_goal'})
_RECALL_V3=frozenset({'prepare_ingress_recall_need_v1','prepare_ingress_recall_model_v1',
    'acquire_ingress_recall_model_v1','adopt_ingress_recall_model_v1','adopt_current_task_no_search_v1',
    'select_ingress_recall_seed_v1','prepare_ingress_c04_v1','adopt_ingress_c04_v1'})

@dataclass(frozen=True,slots=True)
class ForegroundCommandSourceSpecV3:
    operation_kind:str
    family:str
    request_type:type


def foreground_command_source_spec_v3(operation_kind,request,selector):
    from ..authority_service.current_foreground_activity_v1 import (ForegroundActivityRequestV1,
        ForegroundActivityRequestV2,ForegroundActivityPreparationParentRequestV2,foreground_typed_command_digest_v1)
    from .domain_production_registry_v1 import installed_operation_v1
    if type(selector)not in {ForegroundActivityRequestV1,ForegroundActivityRequestV2,ForegroundActivityPreparationParentRequestV2}:
        return None
    families={'cycle':_CYCLE_V3,'task':_TASK_V3,'phase':_PHASE_V3,'receipt':_RECEIPT_V3,'recall':_RECALL_V3}
    family=next((name for name,kinds in families.items()if operation_kind in kinds),None)
    if family is None:return None
    if operation_kind == 'serve_concern' and selector.draft_root_registration_ref is None:
        return None
    operation=installed_operation_v1(operation_kind)
    if (type(request)is not operation.request_type or selector.operation_kind!=operation_kind
            or selector.request_digest!=foreground_typed_command_digest_v1(operation,request)):
        raise AuthorityUnavailable('Foreground Source contract changed its exact registered request/command digest')
    return ForegroundCommandSourceSpecV3(operation_kind,family,operation.request_type)


def foreground_command_evidence_locators_v3(reader,spec):
    """Only locator/version bounds. Independent Owner and ALL Source remain required."""
    from .foreground_activity_issuance_v1 import _IssuedForegroundActivityV1,require_foreground_activity_issuance_v1
    from .current_method_learning_read_v3 import BorrowedMethodLearningReadV3,_READERS
    if (type(reader)is not BorrowedMethodLearningReadV3 or reader not in _READERS
            or type(reader.issued)is not _IssuedForegroundActivityV1
            or foreground_command_source_spec_v3(reader.operation_kind,reader.request,reader.selector)!=spec):
        raise AuthorityUnavailable('Foreground metadata locators require their actual borrowed WRITE and registered contract')
    evidence=require_foreground_activity_issuance_v1(reader.issued,reader.graph,reader.issued.scope)
    if evidence is not reader.evidence or evidence.request!=reader.selector:
        raise AuthorityUnavailable('Foreground metadata bounds differ from their actual fresh Core issuance')
    versions=tuple(evidence.read_versions)
    if len({v.key for v in versions})!=len(versions)or any(NamespaceId.from_key(v.key)!=reader.namespace for v in versions):
        raise AuthorityUnavailable('Foreground metadata bounds contain conflicting or foreign Graph versions')
    roots=tuple(v.key.token for v in versions if v.key.type_name=='memory.source')
    if reader.selector.cue_source_ref not in roots:
        raise AuthorityUnavailable('Foreground metadata bounds lost their actual admitted cue Source')
    return versions,roots
