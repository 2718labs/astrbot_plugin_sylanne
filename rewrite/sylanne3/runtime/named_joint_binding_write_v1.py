"""Original binding/index registration under privately issued same-Work fresh WRITE."""
from contextlib import contextmanager
from dataclasses import asdict,replace
from weakref import WeakKeyDictionary
import json
import time

from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import (FenceScope,CommandEnvelope,OperationIdentity,VersionGuard,SourceQualification,
    QueryEpoch,RUNTIME_SCHEMA,canonical_digest,canonical_serialize)
from ..graph_types import GraphSnapshot,NamespaceEpoch
from ..contracts import canonical_json
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .named_joint_binding_issuance_v1 import (named_joint_binding_for_fence_v1,require_named_joint_issuance_v1,
    reobserve_named_joint_binding_v1,named_joint_finish_digest_v1,require_named_joint_same_facts_v1)
from .named_joint_binding_provenance_v1 import KEY,current_named_joint_provenance_v1

_WRITES=WeakKeyDictionary()


def current_named_joint_write_v1(runtime):return _WRITES.get(runtime)


def named_joint_host_frame_read_versions_v3(frame):
    for runtime,record in _WRITES.items():
        reader,issued,scope,actual_frame=record
        if actual_frame is frame:
            require_named_joint_issuance_v1(issued,reader.graph,scope)
            from .named_joint_source_note_inputs_v1 import note_original_profile_v1
            return frame.envelope.version_guard.read_versions if note_original_profile_v1(reader.inputs)is not None else issued.evidence.read_versions
    return None


def _frame(reader,issued,now):
    from .domain_production_contracts_v1 import CurrentOperationFrameV1
    state=reader.inputs;current=issued.evidence;ns=reader.namespace
    guard_versions={}
    with state.work.quantum_v3()as meter:
        for kind in('scheme','operator','policy'):
            row=meter.read_fixed_row(reader.db,'graph_guard_versions',('version',),
                'bot=? AND persona=? AND kind=? AND ref=?',(*ns.as_tuple,kind,'current'))
            if row is None:raise AuthorityUnavailable('Named Joint actual installed guard version is absent')
            guard_versions[kind]=row[0]
    deadline=min(reader.operation.deadline_utc,current.valid_until_utc)
    from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteCurrentV1
    note=type(current)is NamedJointSourceNoteCurrentV1
    future=current.future_identity if note else None
    identity=OperationIdentity(activity_id=future.activity_id if note else reader.activity_id,
        effect_id=future.effect_id if note else None,attempt_id=future.attempt_id if note else reader.operation_id,
        phase=reader.operation_kind,operation_id=future.action_operation_id if note else reader.operation_id,
        canonical_input_digest=canonical_digest({'input_refs':[]}))
    if note:deadline=future.deadline_utc
    from .named_joint_source_note_inputs_v1 import named_source_note_original_versions_v1
    actual_reads=named_source_note_original_versions_v1(state)if note else current.read_versions
    envelope=CommandEnvelope(RUNTIME_SCHEMA,identity,reader.authority,
        VersionGuard(actual_reads,(QueryEpoch(ns,'namespace',reader.graph_stamp[1].revision),),
            *reader.authority_epochs,reader.store._registry.catalogue_hash,guard_versions['scheme'],
            guard_versions['operator'],guard_versions['policy'],(),(),()),
        SourceQualification(tuple(state.roots),'derived',None,now,'inference','ineligible',None,'not_applicable'),
        (),reader.parent_budget_lease_ref,deadline,time.monotonic()+deadline-now,
        'named-joint-current:'+reader.operation_id,())
    from .named_joint_source_note_inputs_v1 import named_source_note_original_coverage_v1
    coverage={row.type_id:row for row in current.query_coverage}
    if note:coverage.update((row.type_id,row)for row in named_source_note_original_coverage_v1(state))
    return CurrentOperationFrameV1(envelope,GraphSnapshot(tuple(state.bodies.values()),(reader.graph_stamp[1],)),now,
        current.owner_guard,current.current_self.activation_generation,tuple(coverage[k]for k in sorted(coverage)),(),tuple(state.original_refs.values()))


def _attach(reader,issued,frame,stage):
    from .domain_production_inputs_v1 import StagedDomainInputV1
    from .domain_production_contracts_v1 import ProductionOriginalRefV1,ProductionOutboxStageV1
    from .d08_source_note_action_v1 import SourceNoteActionStageV1
    if type(stage)not in {StagedDomainInputV1,SourceNoteActionStageV1}:raise AuthorityUnavailable('Named Joint changed its original typed producer stage')
    base=stage.stage;raw=json.loads(base.original_payload_json)
    if KEY in raw['provenance']:raise AuthorityUnavailable('Named Joint provenance cannot be prefilled')
    raw['provenance'][KEY]=current_named_joint_provenance_v1(reader,issued,frame)
    digest=canonical_digest(raw)
    original=ProductionOriginalRefV1(base.domain+'.current-'+base.operation_kind,base.domain+'-current:'+digest[:48],digest,base.read_versions)
    outbox=tuple(ProductionOutboxStageV1(item.namespace,item.causal_operation_id,item.receiver_domain,item.event_kind,original)for item in base.outbox)
    return replace(stage,stage=replace(base,original_payload_json=canonical_serialize(raw),original_digest=digest,outbox=outbox))


def compile_named_joint_binding_v1(reader,issued,frame):
    from .domain_production_registry_v1 import installed_operation_v1,stage_installed_domain_operation_v1
    from .domain_production_registry_v1 import installed_readers_for_operation_v1
    from .current_joint_window_source_read_v3 import bind_current_joint_window_source_frame_v3
    from ..authority_service.named_joint_binding_body_v1 import _BOUND
    require_named_joint_issuance_v1(issued,reader.graph,reader.write_scope)
    if reader.inputs.semantic_frame is not frame:raise AuthorityUnavailable('Named Joint compiler changed its actual selected Host frame')
    operation=installed_operation_v1(reader.operation_kind)
    from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1,ForegroundActivityRequestV1
    kwargs={};note=type(reader.selector)is NamedJointSourceNoteSelectorV1
    if note:
        kwargs['foreground_issuance'if type(reader.selector.original_selector)is ForegroundActivityRequestV1 else 'owner_task_issuance']=issued.original_issuance
    actual_guard=issued.evidence.owner_guard if note else reader.write_owner_entry.current_owner_guard
    readers=installed_readers_for_operation_v1(reader.graph,operation,scope=reader.write_scope,owner_guard=actual_guard,**kwargs)
    token=_BOUND.set(reader.inputs)
    try:
        with bind_current_joint_window_source_frame_v3(frame,graph=reader.graph,argument=reader.selector.argument,selector=reader.selector):
            if note:
                from .d08_source_note_action_v1 import selected_source_note_action_schema_key_v2
                schema=selected_source_note_action_schema_key_v2(reader.db,frame=frame,request=reader.request,installed_readers=readers)
                reader.inputs.note_original_profile['schema_key']=schema
                reader.inputs.semantic_read.head(reader.db,schema)
            stage=stage_installed_domain_operation_v1(reader.db,operation=operation,frame=frame,request=reader.request,installed_readers=readers)
            stage=_attach(reader,issued,frame,stage)
    finally:_BOUND.reset(token)
    primary=stage.stage
    if primary.coverage!='complete'or primary.jobs or primary.paid_cost_originals or primary.outbox:
        raise AuthorityUnavailable('Named Joint preparation must remain complete and zero-job/reserve/provider')
    if note:
        from .domain_production_commit_v1 import _members
        _,proposals,_,settlements,costs=_members(stage)
        if settlements or costs or len(proposals)!=1 or proposals[0].domain!='d08':raise AuthorityUnavailable('SourceNote preserves only its original selected Action/schema proposal')
    elif primary.proposals:raise AuthorityUnavailable('Prospective registration remains binding/index-only')
    return operation,stage,readers


def require_named_joint_commit_witness_v1(witness,graph,db,bundle):
    from .domain_production_commit_v1 import _ACTIVE,_members
    record=_WRITES.get(witness.runtime)
    if record is None or _ACTIVE.get(id(witness))is not witness:
        raise AuthorityUnavailable('Named Joint W01 requires its actual same-transaction private witness')
    reader,issued,scope,frame=record
    current=require_named_joint_issuance_v1(issued,graph,scope)
    if(witness.graph is not graph or witness.scope is not scope or witness.frame is not frame
            or db is not reader.db or not db.in_transaction or not reader.store._lock._is_owned()
            or witness.guard!=current.owner_guard or witness.request!=reader.request):
        raise AuthorityUnavailable('Named Joint W01 left its actual selector/Source/Owner/Scope/CAS')
    operation,rebuilt,_=compile_named_joint_binding_v1(reader,issued,frame)
    if rebuilt!=witness.stage or operation!=witness.operation:
        raise AuthorityUnavailable('Named Joint original binding/index stage changed before actual CAS')
    primary,proposals,_,settlements,costs=_members(rebuilt)
    from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1
    note=type(reader.selector)is NamedJointSourceNoteSelectorV1
    if (primary.jobs or (proposals and not note) or settlements or costs or bundle.persistent_job_refs
            or bundle.experience_refs or bundle.choice_refs or bundle.d02_settlement_refs or bundle.d11_cost_settlement_refs
            or bundle.outbox_refs or bundle.root_adoption is not None or bundle.product_advance is not None
            or any(proposal.domain!=('d08'if note else 'd10')or (proposal.typed_writes and not note) for proposal in bundle.proposals)):
        raise AuthorityUnavailable('Named Joint same-CAS registration attempted executor or resource effects')
    return witness


def rebuild_named_joint_stage_v1(runtime,db,*,operation,request,frame,scope):
    record=_WRITES.get(runtime)
    if record is None:raise AuthorityUnavailable('Named Joint rebuild lacks its actual originating WRITE')
    reader,issued,actual_scope,actual_frame=record
    if db is not reader.db or scope is not actual_scope or frame is not actual_frame or request!=reader.request:
        raise AuthorityUnavailable('Named Joint rebuild changed its exact original compiler inputs')
    selected,stage,readers=compile_named_joint_binding_v1(reader,issued,frame)
    if selected!=operation:raise AuthorityUnavailable('Named Joint rebuild changed its installed registration')
    return frame,stage,readers


def run_named_joint_binding_write_v1(reader):
    from ..authority_service.v2_contract import FencePermitV2,from_wire,to_wire
    from .restore_anchor import RestoreAnchor
    from .first_ingress_v2 import trusted_upper
    from ..authority_service.owner_location_read_v3 import prepare_current_host_named_joint_owner_write_entry_v3
    from ..authority_service.named_joint_binding_body_v1 import _pump
    from .domain_production_commit_v1 import commit_installed_domain_operation_v1
    graph,store,runtime=reader.graph,reader.store,reader.runtime
    port=graph._GraphCoordinator__content_fence_v2;selector=reader.selector;ns=reader.namespace
    key=(*ns.as_tuple,selector.operation_id);saved=reader.attempt_snapshot
    from .named_joint_binding_issuance_v1 import named_joint_scope_operation_id_v1
    from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1
    digest=canonical_digest(selector.original_selector if type(selector)is NamedJointSourceNoteSelectorV1 else selector)
    attempt_id=named_joint_scope_operation_id_v1(selector);metadata,epoch=reader.graph_stamp;target=metadata.requirements
    if saved is not None and saved[:2]!=(digest,attempt_id):raise AuthorityUnavailable('Named Joint durable attempt belongs to another immutable selector')
    if saved is not None and saved[6]is not None:
        permit=None if saved[5]is None else from_wire(json.loads(saved[5]))
        observed,status=port.get_fence_operation(namespace=ns,authority_namespace=target.authority_namespace,operation_id=attempt_id)
        if type(permit)is not FencePermitV2 or observed!=permit or status not in {'active','finished'}:
            raise AuthorityUnavailable('Named Joint committed attempt has no confirmed original WRITE')
        from ..authority_service.named_joint_binding_source_read_v3 import _positive
        original=reader.replay_original
        if original is None:raise AuthorityUnavailable('Named Joint replay lost its actual Source-read positive producer')
        result=json.loads(saved[6])
        if canonical_digest(original['receipt'])!=canonical_digest(result['receipt'])or original['payload']['request']!=json.loads(canonical_serialize(reader.request)):
            raise AuthorityUnavailable('Named Joint durable receipt differs from its actual original COMMIT')
        scope=FenceScope(ns,target.authority_namespace,permit.generation,'write',attempt_id,permit,permit.pinned_anchor,
            NamespaceEpoch(*ns.as_tuple,saved[4]),saved[3])
        if status=='active':port.finish_fence(scope,request_id='finish:'+attempt_id,request_digest=named_joint_finish_digest_v1(selector,permit))
        return result
    anchor=port.current_anchor(namespace=ns,authority_namespace=target.authority_namespace)
    if not graph._anchor_matches(target,anchor):raise AuthorityUnavailable('Named Joint current recovery anchor differs')
    if saved is not None and saved[2:5]!=(canonical_json(asdict(anchor)),metadata.graph_revision,epoch.revision):
        raise AuthorityUnavailable('Named Joint unresolved original attempt stamp changed; preserve it')
    observed=port.observe_content_write_attempt_v1(namespace=ns,authority_namespace=target.authority_namespace,
        operation_id=attempt_id,expected_anchor=anchor)
    if saved is None:
        if observed.state!='absent'or observed.permit is not None:raise AuthorityUnavailable('Named Joint unrecorded WRITE outcome is unresolved')
        with store._lock,runtime_storage_quantum_v3(reader.db):
            reader.db.execute('BEGIN IMMEDIATE')
            try:
                if graph._v2_graph_stamp(ns)!=(metadata,epoch):raise AuthorityUnavailable('Named Joint Graph changed before immutable WRITE intent')
                reader.db.execute('INSERT INTO graph_owner_domain_attempts_v3(bot,persona,operation_id,request_digest,attempt_id,anchor_json,graph_revision,graph_epoch) VALUES(?,?,?,?,?,?,?,?)',
                    (*key,digest,attempt_id,canonical_json(asdict(anchor)),metadata.graph_revision,epoch.revision))
                reader.db.commit()
            except BaseException:reader.db.rollback();raise
    permit,status=observed.permit,observed.state
    if saved is not None and saved[5]is not None:
        if status!='active'or permit!=from_wire(json.loads(saved[5])):raise AuthorityUnavailable('Named Joint saved actual WRITE permit changed')
    elif status=='absent'and permit is None:
        permit=port.begin_fence(namespace=ns,authority_namespace=target.authority_namespace,holder=graph._GraphCoordinator__holder,
            generation=target.activation_generation,operation='write',operation_id=attempt_id,expected_anchor=anchor,retain_on_unknown=True)
        status='active'
    if type(permit)is not FencePermitV2 or status!='active'or permit.operation_id!=attempt_id or permit.pinned_anchor!=anchor:
        raise AuthorityUnavailable('Named Joint WRITE outcome is unconfirmed; retain the original attempt')
    scope=FenceScope(ns,target.authority_namespace,target.activation_generation,'write',attempt_id,permit,anchor,epoch,metadata.graph_revision)
    if port.validate_fence(scope)!=permit:raise AuthorityUnavailable('Named Joint actual WRITE permit changed')
    with store._lock,runtime_storage_quantum_v3(reader.db):
        row=reader.db.execute('UPDATE graph_owner_domain_attempts_v3 SET permit_json=? WHERE bot=? AND persona=? AND operation_id=? AND request_digest=? AND attempt_id=? AND receipt_json IS NULL AND(permit_json IS NULL OR permit_json=?)',
            (canonical_json(to_wire(permit)),*key,digest,attempt_id,canonical_json(to_wire(permit))))
        if row.rowcount!=1:raise AuthorityUnavailable('Named Joint durable actual permit changed')
    with named_joint_binding_for_fence_v1(reader,scope)as issued:
        reobserve_named_joint_binding_v1(issued)
        entry=prepare_current_host_named_joint_owner_write_entry_v3(reader,scope=scope,issued=issued)
        reader.write_owner_entry=entry
        state=reader.inputs;state.work.scope, state.work.permit=scope,permit;state.current_self=issued.evidence.current_self
        try:
            owner=entry.require_permission_v3(reader)
            if owner.grant_revision!=issued.evidence.owner_guard.grant_revision:raise AuthorityUnavailable('Named Joint fresh Owner grant changed')
            from ..authority_service.named_joint_binding_body_v1 import qualify_current_named_joint_body_v1
            from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1,qualify_named_source_note_body_v1
            state.observed=(qualify_named_source_note_body_v1(state,issued.evidence.original_evidence)if type(selector)is NamedJointSourceNoteSelectorV1 else qualify_current_named_joint_body_v1(state))
            require_named_joint_same_facts_v1(issued.evidence,state.observed)
            from .named_joint_source_note_inputs_v1 import prepare_named_source_note_original_inputs_v1
            prepare_named_source_note_original_inputs_v1(reader,issued)
            now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
            state.frame_factory=lambda:_frame(reader,issued,now)
            prepared={}
            def compile(frame):
                _WRITES[runtime]=(reader,issued,scope,frame)
                prepared['result']=compile_named_joint_binding_v1(reader,issued,frame)
                return prepared['result']
            _pump(state,compile)
            frame=state.semantic_frame;operation,stage,readers=prepared['result']
            reobserve_named_joint_binding_v1(issued);entry.require_permission_v3(reader)
            from ..authority_service.named_joint_binding_body_v1 import _BOUND
            token=_BOUND.set(state)
            try:
              with store._lock,runtime_storage_quantum_v3(reader.db):
                reader.db.execute('BEGIN IMMEDIATE')
                try:
                    if graph._v2_graph_stamp(ns)!=(metadata,epoch):raise AuthorityUnavailable('Named Joint original Source stamp changed before actual CAS')
                    result=commit_installed_domain_operation_v1(runtime,reader.db,operation=operation,request=reader.request,
                        frame=frame,stage=stage,readers=readers,scope=scope,owner=None,guard=issued.evidence.owner_guard,
                        metadata=metadata,epoch=epoch,process_lease=reader.lease)
                    reader.db.execute('UPDATE graph_owner_domain_attempts_v3 SET receipt_json=? WHERE bot=? AND persona=? AND operation_id=? AND request_digest=? AND attempt_id=? AND permit_json=? AND receipt_json IS NULL',
                        (canonical_json(result),*key,digest,attempt_id,canonical_json(to_wire(permit))))
                    if reader.db.execute('SELECT changes()').fetchone()!=(1,):raise AuthorityUnavailable('Named Joint original durable receipt raced')
                    reader.db.commit()
                except BaseException:reader.db.rollback();raise
            finally:_BOUND.reset(token)
            port.finish_fence(scope,request_id='finish:'+attempt_id,request_digest=named_joint_finish_digest_v1(selector,permit))
            return result
        finally:
            _WRITES.pop(runtime,None);state.frame_factory=None
            entry.release_v3();reader.write_owner_entry=None
