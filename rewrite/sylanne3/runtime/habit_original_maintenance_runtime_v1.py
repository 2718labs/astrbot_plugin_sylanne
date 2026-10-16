"""Same-Work historical Habit metadata maintenance; never issues execution or billing."""
import json
from dataclasses import replace
from ..runtime_contracts import (AuthorityContext,CommandEnvelope,OperationIdentity,VersionGuard,
    QueryEpoch,SourceQualification,RUNTIME_SCHEMA,canonical_digest)
from .issuers import canonical_serialize


def _maintenance_kind_v1(selector):
    from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1
    if type(selector)is not HabitOriginalMaintenanceSelectorV1:
        raise TypeError('exact independently qualified Habit original-maintenance selector required')
    return selector.operation_kind


def run_current_habit_original_maintenance_v1(graph,context,*,selector,operation_kind,request,source_inputs):
    from .habit_activity_runtime_v1 import _run_current_habit_control_write_v1
    from .habit_maintenance_issuance_v1 import (habit_maintenance_request_digest_v1,
        habit_maintenance_typed_command_digest_v1,habit_maintenance_for_fence_v1,
        reobserve_habit_maintenance_v1,habit_maintenance_finish_digest_v1)
    _maintenance_kind_v1(selector)
    protocol=(_maintenance_kind_v1,habit_maintenance_request_digest_v1,habit_maintenance_typed_command_digest_v1,
        habit_maintenance_for_fence_v1,reobserve_habit_maintenance_v1,habit_maintenance_finish_digest_v1,
        compile_and_commit_current_habit_maintenance_v1,'w01.habit-maintenance-write.v1')
    return _run_current_habit_control_write_v1(graph,context,selector=selector,
        operation_kind=operation_kind,request=request,source_inputs=source_inputs,protocol=protocol)


def compile_and_commit_current_habit_maintenance_v1(runtime,db,*,selector,operation,request,
        issued,scope,metadata,epoch,now_utc,external_originals):
    from .habit_maintenance_issuance_v1 import require_habit_maintenance_issuance_v1
    from .current_habit_source_read_v3 import (require_habit_compile_inputs_v3,
        read_bound_current_habit_frame_inputs_v3,register_current_habit_source_frame_v3)
    from .habit_maintenance_source_v3 import habit_maintenance_source_reader_v3
    from .habit_control_issuance_v1 import habit_control_deadline_v1
    from .habit_maintenance_frame_v1 import CurrentHabitMaintenanceFrameV1
    from .domain_production_frame_v1 import _materialize_current_domain_frame_fields_v1
    from .domain_production_contracts_v1 import ProductionOperationLimitsV1
    from .domain_production_registry_v1 import stage_installed_domain_operation_v1
    from .domain_production_commit_v1 import commit_installed_domain_operation_v1
    from .local_module_admission_v1 import required_operation_modules_v1
    from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1
    from ..graph_types import AtomKey
    runtime._current();graph=runtime.graph
    facts=require_habit_maintenance_issuance_v1(issued,graph,scope)
    if (facts.request!=selector or issued.operation!=operation or issued.command!=request
            or operation.domain!='d10' or operation.operation_kind!=_maintenance_kind_v1(selector)
            or db is not graph._GraphCoordinator__store._db or not db.in_transaction
            or not graph._GraphCoordinator__store._lock._is_owned()):
        raise ValueError('Habit maintenance compiler lost its actual private W01 command')
    graph.local_module_admission.require_v1(required_operation_modules_v1(operation.operation_kind),operation.operation_kind)
    token,capability=graph.grant(runtime._bootstrap,actor=facts.current_self.self_entity_ref,
        issuer_domain='d10',namespace=selector.namespace,domains=('d10','d11'),
        activation_generation=facts.current_self.activation_generation,operation_id=selector.operation_id)
    runtime._active_habit_issuance_v1=issued
    try:
        plan,originals,policies,readers=require_habit_compile_inputs_v3(db,graph=graph,scope=scope,
            issued=issued,operation=operation,request=request,now_utc=now_utc)
        prepared=read_bound_current_habit_frame_inputs_v3(db,graph=graph,scope=scope,plan=plan,issued=issued)
        reader=prepared.owner;state=habit_maintenance_source_reader_v3(reader)
        if state is None or now_utc>=habit_control_deadline_v1(issued,reader):
            raise ValueError('Habit maintenance lost its actual current control lifetime')
        from .habit_maintenance_source_v3 import require_habit_maintenance_original_root_v3
        grant=require_habit_maintenance_original_root_v3(reader,facts)
        occurrence=habit_value_from_wire_v1('d10.habit_occurrence.v1',prepared.head_v3(
            AtomKey.from_token(selector.occurrence_ref)).value)
        guard=reader.selected_envelope.version_guard
        authority=AuthorityContext(facts.current_self.self_entity_ref,'d10',capability,selector.namespace,
            tuple(sorted(graph._GraphCoordinator__leases[token][5])),reader.authority.purpose,
            reader.authority.audience,grant.policy_ref,facts.current_self.activation_generation)
        envelope=CommandEnvelope(RUNTIME_SCHEMA,OperationIdentity(occurrence.activity_id,None,selector.operation_id,
            selector.operation_kind,selector.operation_id,canonical_digest({'input_refs':[]})),authority,
            replace(guard,read_versions=(),query_epochs=(QueryEpoch(selector.namespace,'namespace',epoch.revision),)),
            SourceQualification((),'derived',None,now_utc,'inference','ineligible',None,'not_applicable'),(),
            facts.original_root_ref,facts.original_deadline_utc,
            reader.initial_monotonic_deadline+(facts.original_deadline_utc-reader.operation.deadline_utc),
            'habit-original-maintenance:'+selector.operation_id,())
        graph._authorize(token,authority,frozenset(('d10','d11')))
        fields=_materialize_current_domain_frame_fields_v1(graph,db,envelope=envelope,scope=scope,plan=plan,
            now_utc=now_utc,expected_owner_guard=facts.owner_guard,
            expected_rights=(facts.access_epoch,facts.delete_epoch),observed_originals=(*originals,*external_originals),
            installed_policy_refs=policies,limits=ProductionOperationLimitsV1(),prepared_inputs=prepared)
        frame=CurrentHabitMaintenanceFrameV1(*fields,issuance=issued)
        register_current_habit_source_frame_v3(db,frame,scope)
        from .habit_maintenance_followup_v3 import bind_habit_maintenance_followup_frame_v3
        with bind_habit_maintenance_followup_frame_v3(frame,reader):
            stage=stage_installed_domain_operation_v1(db,operation=operation,frame=frame,request=request,installed_readers=readers)
            require_current_habit_maintenance_commit_v1(runtime,db,operation=operation,request=request,frame=frame,stage=stage,scope=scope)
            return commit_installed_domain_operation_v1(runtime,db,operation=operation,request=request,frame=frame,
                stage=stage,readers=readers,scope=scope,owner=None,guard=facts.owner_guard,metadata=metadata,epoch=epoch,
                process_lease=token,external_originals=external_originals)
    finally:
        runtime._active_habit_issuance_v1=None
        graph.release_authority_lease(runtime._bootstrap,token)


def require_current_habit_maintenance_commit_v1(runtime,db,*,operation,request,frame,stage,scope):
    from .habit_maintenance_frame_v1 import require_habit_maintenance_frame_v1
    from .habit_maintenance_issuance_v1 import require_habit_maintenance_issuance_v1
    from .habit_maintenance_provenance_v1 import (MAINTENANCE_PROVENANCE_V1,
        validate_habit_maintenance_provenance_v1,append_current_habit_maintenance_provenance_v1)
    from .habit_census_provenance_v1 import require_current_habit_census_payload_v1
    from .current_habit_source_read_v3 import require_current_habit_source_frame_v3
    from .habit_maintenance_source_v3 import require_habit_maintenance_original_root_v3
    from .domain_production_commit_v1 import _members
    issued=runtime._active_habit_issuance_v1
    facts=require_habit_maintenance_issuance_v1(issued,runtime.graph,scope)
    if (require_habit_maintenance_frame_v1(frame)is not facts or frame.issuance is not issued
            or issued.command!=request or issued.operation!=operation
            or db is not runtime.graph._GraphCoordinator__store._db or not db.in_transaction
            or not runtime.graph._GraphCoordinator__store._lock._is_owned()
            or runtime._active_foreground_issuance_v1 is not None
            or getattr(runtime,'_active_owner_task_issuance_v1',None)is not None):
        raise ValueError('Habit maintenance commit changed its actual independent private writer')
    pending=require_current_habit_source_frame_v3(db,frame=frame,operation_kind=operation.operation_kind,request=request)
    require_habit_maintenance_original_root_v3(pending.reader,facts)
    primary,proposals,new_sources,resource_settlements,cost_settlements=_members(stage)
    if (primary.domain!='d10' or primary.operation_kind!=facts.request.operation_kind or primary.jobs
            or primary.outbox or primary.paid_cost_originals or new_sources or resource_settlements or cost_settlements
            or primary.coverage!='complete' or not proposals):
        raise ValueError('Habit original maintenance cannot create jobs, outbox, Sources, settlements or new execution')
    payload=json.loads(primary.original_payload_json)
    require_current_habit_census_payload_v1(frame,payload)
    provenance=payload['provenance'];raw=provenance[MAINTENANCE_PROVENANCE_V1]
    validate_habit_maintenance_provenance_v1('d10',operation.operation_kind,raw)
    expected=append_current_habit_maintenance_provenance_v1(frame,'d10',operation.operation_kind,request,
        {key:value for key,value in provenance.items()if key!=MAINTENANCE_PROVENANCE_V1})[MAINTENANCE_PROVENANCE_V1]
    if raw!=json.loads(canonical_serialize(expected)):
        raise ValueError('Habit maintenance commit differs from its actual private Source/Owner census')
    registry=runtime.graph._GraphCoordinator__store._registry
    for proposal in proposals:
        if proposal.domain not in {'d10','d11'}:
            raise ValueError('Habit maintenance exceeds its exact registered metadata domains')
        for write in proposal.typed_writes:
            if (registry.spec(write.key.type_name).writer_domain!=proposal.domain
                    or(write.key.owner.bot,write.key.owner.persona)!=facts.request.namespace.as_tuple):
                raise ValueError('Habit maintenance metadata writer or namespace differs')
