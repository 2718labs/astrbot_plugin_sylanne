"""Dedicated D07 preparation identity for an actual independent Artifact check."""
from dataclasses import dataclass,fields,replace
import json
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest
from .d07_execution_v1 import D07PreparedExecutionV1
from .foreground_artifact_observation_plan_v3 import (ForegroundCallPlanV3,
    ForegroundArtifactObservationAttemptV3,artifact_observation_ids_v1)


@dataclass(frozen=True,slots=True,kw_only=True)
class D07ArtifactObservationPreparedV3(D07PreparedExecutionV1):
    semantic_question_ref:str
    semantic_question_digest:str
    observation_basis_ref:str
    observation_basis_digest:str
    cycle_ref:GraphVersion
    cycle_digest:str
    call_plan_digest:str
    c02_operation_id:str
    cancel_generation:int
    schema:str='d07.artifact-observation-prepared.v3'

    def __post_init__(self):
        if (self.schema!='d07.artifact-observation-prepared.v3'or self.work_kind!='concern'
                or type(self.namespace)is not NamespaceId or type(self.cycle_ref)is not GraphVersion
                or self.cycle_ref.key.type_name!='runtime.job'or self.cycle_ref.revision<1
                or NamespaceId.from_key(self.cycle_ref.key)!=self.namespace
                or type(self.cancel_generation)is not int or self.cancel_generation!=0
                or not self.operation_id.startswith('artifact-phase-observe:')
                or self.effect_id!='artifact-observation-effect:'+self.operation_id.removeprefix('artifact-phase-observe:')
                or self.attempt_id!=self.operation_id):
            raise ValueError('actual independent Artifact D07 preparation identity required')
        for name in('semantic_question_digest','observation_basis_digest','cycle_digest','call_plan_digest'):
            value=getattr(self,name)
            if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):
                raise ValueError('Artifact observation preparation requires exact original commitments')
        for name in('semantic_question_ref','observation_basis_ref','c02_operation_id'):
            if type(getattr(self,name))is not str or not getattr(self,name):
                raise ValueError('Artifact observation preparation requires actual original selectors')

    @property
    def digest(self):
        from ..domains.d01.production_operations_v1 import plain_v1
        return canonical_digest(plain_v1(self))


def artifact_observation_prepared_from_wire_v3(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    value=decode_typed_production_value_v1(raw,D07ArtifactObservationPreparedV3)
    if plain_v1(value)!=raw:raise ValueError('Artifact observation preparation is noncanonical')
    return value


def current_artifact_observation_basis_for_d07_v1(service,db,frame,question):
    from .artifact_phase_observation_v1 import (ArtifactPhaseObservationQuestionV1,
        read_artifact_phase_observation_basis_v1,require_current_artifact_phase_observation_basis_v1)
    from .artifact_phase_postconditions_v1 import _readers
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
    if type(question)is not ArtifactPhaseObservationQuestionV1:
        raise TypeError('actual producer-issued Artifact observation question required')
    readers=_readers(InstalledArtifactDraftModelReadersV1(service.d11_issuer,service.bundle,
        service.graph._GraphCoordinator__artifact_draft_model_runtime_v1))
    basis=read_artifact_phase_observation_basis_v1(db,namespace=question.selector.task.namespace,
        original_ref=question.observation_basis_ref,issuer=service.d11_issuer)
    if basis is None or basis.question!=question:
        raise ValueError('D07 observation question lacks its actual signed Artifact preparation')
    return require_current_artifact_phase_observation_basis_v1(db,frame=frame,basis=basis,installed_readers=readers)


def specialize_artifact_observation_prepared_v3(db,*,frame,stage,prepared,quote,issuer):
    from .artifact_phase_observation_v1 import ArtifactPhaseObservationBasisV1
    from .d07_execution_v1 import read_d07_original_v1
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from .jobs import get_job
    basis=stage.provenance.get('artifact_observation_basis')
    if type(basis)is not ArtifactPhaseObservationBasisV1 or basis.namespace!=prepared.namespace:
        raise ValueError('D07 observation preparation lost its actual qualified basis')
    ids=basis.ids
    if ((prepared.operation_id,prepared.job_id,prepared.call_id,frame.envelope.parent_budget_lease_ref)!=
            (ids['operation'],ids['job'],ids['call'],basis.parent_budget_lease_ref)):
        raise ValueError('D07 observer cannot replace its original same-task operation/job/lease')
    atom=frame.snapshot.get(AtomKey.from_token(basis.request.selector.task.cycle_job_ref))
    if atom is None or not atom.valid:raise ValueError('D07 observer needs its current real task cycle')
    job=get_job(db,atom.key.name);cycle=foreground_cycle_from_wire_v1(job.continuation)
    plan=cycle.call_plan
    if (type(plan)is not ForegroundCallPlanV3 or cycle.cancel_generation or job.cancel_epoch
            or job.phase in{'completed','failed','cancelled','draining','pending_confirmation'}
            or(plan.observer_policy_ref,plan.observer_policy_digest)!=(basis.observer_asset_ref,basis.observer_asset_digest)
            or plan.phase_group.selector!=basis.request.selector):
        raise ValueError('D07 observation cannot borrow an old plan, another task or model installation')
    attempt=ForegroundArtifactObservationAttemptV3(slot='C3',call_id=prepared.call_id,original_call_id=None,
        reservation_operation_id=prepared.operation_id,reservation_digest=prepared.reservation_digest,
        budget_lease_ref=basis.parent_budget_lease_ref,input_ceiling=quote.ceiling['input_tokens'],
        output_ceiling=quote.ceiling['output_tokens'],state='reserved',phase_selector=basis.request.selector,
        condition_id=basis.request.condition_id,observation_basis_ref=basis.original_ref,observation_basis_digest=basis.digest)
    replace(plan,attempts=(*plan.attempts,attempt))
    original=read_d07_original_v1(db,issuer,prepared.namespace,'semantic_question',basis.ids['question'])
    if original is None:raise ValueError('observation question was not actually signed after basis CAS')
    return D07ArtifactObservationPreparedV3(**{**{f.name:getattr(prepared,f.name)for f in fields(D07PreparedExecutionV1)},
        'schema':'d07.artifact-observation-prepared.v3','semantic_question_ref':basis.ids['question'],
        'semantic_question_digest':original[1],'observation_basis_ref':basis.original_ref,
        'observation_basis_digest':basis.digest,'cycle_ref':GraphVersion(atom.key,atom.revision),
        'cycle_digest':canonical_digest(atom.value),'call_plan_digest':canonical_digest(plan),
        'c02_operation_id':basis.request.selector.task.c02_operation_id,'cancel_generation':cycle.cancel_generation})
