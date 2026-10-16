"""Same-Work conditioned child WRITE, immutable attempt and actual W01 witness."""
from dataclasses import asdict,replace
from weakref import WeakKeyDictionary
import json

from ..authority_service.contract import AuthorityUnavailable
from ..contracts import canonical_json
from ..runtime_contracts import FenceScope,canonical_digest,canonical_serialize
from ..graph_types import NamespaceEpoch
from ..authority_service.conditioned_child_contract_v1 import (ConditionedChildSelectorV1,
    conditioned_child_fence_operation_id_v1,conditioned_child_finish_digest_v1)

_WRITES=WeakKeyDictionary()


def current_conditioned_child_write_v1(runtime):
    return _WRITES.get(runtime)


def run_conditioned_child_business_v1(graph,runtime,*,reader,inputs,selector,operation,request):
    from ..authority_service.v2_contract import FencePermitV2,from_wire,to_wire
    from .current_conditioned_self_read_v3 import (read_bound_conditioned_child_attempt_snapshot_v3,
        install_conditioned_child_write_readers_v3)
    from .conditioned_child_issuance_v1 import (conditioned_child_for_fence_v1,reobserve_conditioned_child_v1,
        conditioned_child_process_for_fence_v1)
    from ..authority_service.owner_location_read_v3 import prepare_current_host_conditioned_child_owner_write_entry_v3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .first_ingress_v2 import trusted_upper
    runtime._current()
    if(type(selector)is not ConditionedChildSelectorV1 or runtime.graph is not graph or reader.runtime is not runtime
            or reader.result is not inputs or operation.operation_kind!=selector.operation_kind or type(request)is not operation.request_type
            or canonical_digest(request)!=selector.typed_request_digest or runtime in _WRITES
            or reader.operation.deadline_utc>selector.original_deadline_utc):
        raise AuthorityUnavailable('conditioned WRITE changed its exact independently sealed same-Work command')
    store=graph._GraphCoordinator__store;db=store._db;port=graph._GraphCoordinator__content_fence_v2
    saved=read_bound_conditioned_child_attempt_snapshot_v3(db,graph=graph,selector=selector)
    digest=canonical_digest(selector);attempt_id=conditioned_child_fence_operation_id_v1(selector)
    key=(*selector.namespace.as_tuple,selector.operation_id)
    if saved is not None and saved[:2]!=(digest,attempt_id):
        raise AuthorityUnavailable('conditioned durable attempt changed its exact immutable child selector')
    metadata,epoch=reader.graph_stamp;target=metadata.requirements
    anchor=port.current_anchor(namespace=selector.namespace,authority_namespace=target.authority_namespace)
    if not graph._anchor_matches(target,anchor):raise AuthorityUnavailable('conditioned fresh WRITE requires its actual current recovery anchor')
    if saved is not None and saved[6]is not None:
        permit=None if saved[5]is None else from_wire(json.loads(saved[5]))
        observed,state=port.get_fence_operation(namespace=selector.namespace,authority_namespace=target.authority_namespace,operation_id=attempt_id)
        if(type(permit)is not FencePermitV2 or observed!=permit or state not in {'active','finished'}
                or permit.operation!='write'or permit.operation_id!=attempt_id
                or saved[2]!=canonical_json(asdict(permit.pinned_anchor))):
            raise AuthorityUnavailable('conditioned committed receipt has no actual same original Core WRITE state')
        old_scope=FenceScope(selector.namespace,target.authority_namespace,permit.generation,'write',attempt_id,
            permit,permit.pinned_anchor,NamespaceEpoch(*selector.namespace.as_tuple,saved[4]),saved[3])
        with store._lock:
            db.execute('BEGIN')
            try:
                original=read_adopted_domain_operation_v1(db,selector.namespace,selector.operation_id)
                if(original is None or original['operation_kind']!=selector.operation_kind
                        or original['payload']['request']!=json.loads(selector.typed_request_json)
                        or original['payload']['provenance']['conditioned_child_execution_v1']['payload']!=json.loads(canonical_serialize(selector))
                        or canonical_digest(original['receipt'])!=json.loads(saved[6])['receipt_digest']):
                    raise AuthorityUnavailable('conditioned replay receipt changed its exact actual semantic original')
            finally:db.rollback()
        if state=='active':port.finish_fence(old_scope,request_id='finish:'+attempt_id,request_digest=conditioned_child_finish_digest_v1(selector,permit))
        return json.loads(saved[6])
    observed=port.observe_content_write_attempt_v1(namespace=selector.namespace,authority_namespace=target.authority_namespace,
        operation_id=attempt_id,expected_anchor=anchor)
    if saved is None:
        if observed.state!='absent'or observed.permit is not None:
            raise AuthorityUnavailable('conditioned child has an unrecorded existing WRITE; preserve its unresolved original')
        with store._lock:
            from ..runtime_storage_v3 import runtime_storage_quantum_v3
            with runtime_storage_quantum_v3(db):
                db.execute('BEGIN IMMEDIATE')
                try:
                    if graph._v2_graph_stamp(selector.namespace)!=(metadata,epoch):raise AuthorityUnavailable('conditioned Graph changed before immutable WRITE intent')
                    db.execute('INSERT INTO graph_owner_domain_attempts_v3(bot,persona,operation_id,request_digest,attempt_id,anchor_json,graph_revision,graph_epoch) VALUES(?,?,?,?,?,?,?,?)',
                        (*key,digest,attempt_id,canonical_json(asdict(anchor)),metadata.graph_revision,epoch.revision))
                    db.commit()
                except BaseException:db.rollback();raise
    elif(saved[2:5]!=(canonical_json(asdict(anchor)),metadata.graph_revision,epoch.revision)):
        raise AuthorityUnavailable('conditioned unresolved original WRITE stamp changed; no automatic resurrection')
    permit,state=observed.permit,observed.state
    if saved is not None and saved[5]is not None:
        if state!='active'or permit!=from_wire(json.loads(saved[5])):
            raise AuthorityUnavailable('conditioned saved actual WRITE permit is no longer active')
    elif state=='absent'and permit is None:
        permit=port.begin_fence(namespace=selector.namespace,authority_namespace=target.authority_namespace,
            holder=graph._GraphCoordinator__holder,generation=target.activation_generation,operation='write',
            operation_id=attempt_id,expected_anchor=anchor,retain_on_unknown=True);state='active'
    if(type(permit)is not FencePermitV2 or state!='active'or permit.operation!='write'or permit.operation_id!=attempt_id
            or permit.holder!=graph._GraphCoordinator__holder or permit.pinned_anchor!=anchor):
        raise AuthorityUnavailable('conditioned WRITE outcome is not confirmed; retain its immutable attempt')
    scope=FenceScope(selector.namespace,target.authority_namespace,target.activation_generation,'write',attempt_id,permit,anchor,epoch,metadata.graph_revision)
    if port.validate_fence(scope)!=permit:raise AuthorityUnavailable('conditioned actual WRITE permit changed')
    with store._lock:
        from ..runtime_storage_v3 import runtime_storage_quantum_v3
        with runtime_storage_quantum_v3(db):
            cursor=db.execute('UPDATE graph_owner_domain_attempts_v3 SET permit_json=? WHERE bot=? AND persona=? AND operation_id=? AND request_digest=? AND attempt_id=? AND receipt_json IS NULL AND(permit_json IS NULL OR permit_json=?)',
                (canonical_json(to_wire(permit)),*key,digest,attempt_id,canonical_json(to_wire(permit))))
            if cursor.rowcount!=1:raise AuthorityUnavailable('conditioned durable permit was changed before qualification')
    with conditioned_child_for_fence_v1(graph,scope=scope,request=selector)as issued:
        reobserve_conditioned_child_v1(issued,graph,scope)
        entry=prepare_current_host_conditioned_child_owner_write_entry_v3(reader,scope=scope,issued=issued)
        try:
            install_conditioned_child_write_readers_v3(reader,scope=scope,issued=issued,entry=entry)
            with conditioned_child_process_for_fence_v1(issued,graph,scope)as(authority,lease):
                envelope=replace(inputs.envelope,authority=authority,identity=replace(inputs.envelope.identity,
                    activity_id=selector.activity_id,effect_id=None,operation_id=selector.operation_id,phase=selector.operation_kind,attempt_id=selector.operation_id),
                    deadline_utc=min(inputs.envelope.deadline_utc,issued.evidence.valid_until_utc))
                _WRITES[runtime]=(reader,inputs,selector,issued,scope,lease,envelope)
                try:
                    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
                    reobserve_conditioned_child_v1(issued,graph,scope);entry.require_permission_v3(reader)
                    with store._lock,runtime_storage_quantum_v3(db):
                        db.execute('BEGIN IMMEDIATE')
                        try:
                            if graph._v2_graph_stamp(selector.namespace)!=(metadata,epoch):raise AuthorityUnavailable('conditioned Source READ stamp changed before actual W01')
                            frame,stage,readers=compile_conditioned_child_v1(runtime,db,operation=operation,request=request,scope=scope,now_utc=now)
                            from .domain_production_commit_v1 import commit_installed_domain_operation_v1
                            result=commit_installed_domain_operation_v1(runtime,db,operation=operation,request=request,
                                frame=frame,stage=stage,readers=readers,scope=scope,owner=None,guard=issued.evidence.owner_guard,
                                metadata=metadata,epoch=epoch,process_lease=lease)
                            cursor=db.execute('UPDATE graph_owner_domain_attempts_v3 SET receipt_json=? WHERE bot=? AND persona=? AND operation_id=? AND request_digest=? AND attempt_id=? AND permit_json=? AND receipt_json IS NULL',
                                (canonical_json(result),*key,digest,attempt_id,canonical_json(to_wire(permit))))
                            if cursor.rowcount!=1:raise AuthorityUnavailable('conditioned actual receipt raced within original W01 transaction')
                            db.commit()
                        except BaseException:db.rollback();raise
                    port.finish_fence(scope,request_id='finish:'+attempt_id,request_digest=conditioned_child_finish_digest_v1(selector,permit))
                    return result
                finally:_WRITES.pop(runtime,None)
        finally:entry.release_v3()


def compile_conditioned_child_v1(runtime,db,*,operation,request,scope,now_utc):
    from .conditioned_child_issuance_v1 import require_conditioned_child_process_v1
    from .domain_production_frame_v1 import freeze_conditioned_child_frame_v1
    from .domain_production_read_plans_v1 import read_current_domain_original_refs_v1,read_current_domain_policy_refs_v1
    from .domain_production_registry_v1 import stage_installed_domain_operation_v1
    state=_WRITES.get(runtime)
    if state is None:raise AuthorityUnavailable('conditioned compiler has no actual private same-Work WRITE invocation')
    reader,inputs,selector,issued,actual_scope,lease,envelope=state
    evidence=require_conditioned_child_process_v1(issued,runtime.graph,scope,envelope.authority,lease)
    if(actual_scope is not scope or selector.operation_kind!=operation.operation_kind or canonical_digest(request)!=selector.typed_request_digest
            or now_utc>=envelope.deadline_utc):raise AuthorityUnavailable('conditioned compiler changed its actual command, scope or original deadline')
    readers=reader.installed_readers;plan=reader.selected_plan
    originals=read_current_domain_original_refs_v1(db,namespace=selector.namespace,plan=plan,installed_readers=readers)
    policies=read_current_domain_policy_refs_v1(db,namespace=selector.namespace,plan=plan,installed_readers=readers)
    frame=freeze_conditioned_child_frame_v1(runtime.graph,db,envelope=envelope,issued=issued,scope=scope,plan=plan,
        now_utc=now_utc,operation=operation,request=request,process_lease=lease,observed_originals=originals,installed_policy_refs=policies)
    stage=stage_installed_domain_operation_v1(db,operation=operation,frame=frame,request=request,installed_readers=readers)
    from .domain_production_commit_v1 import _members
    primary,proposals,_,_,_=_members(stage)
    actual_keys=tuple(write.key for proposal in proposals for write in proposal.typed_writes)
    if(primary.operation_kind!=selector.operation_kind or not set(actual_keys)<=set(selector.allowed_write_keys)
            or any(p.domain not in evidence.allowed_write_domains for p in proposals)):
        raise AuthorityUnavailable('conditioned actual typed stage exceeded independent Core semantic write keys')
    return frame,stage,readers


def require_conditioned_child_witness_v1(witness,graph,db,bundle):
    from .domain_production_commit_v1 import _members
    state=_WRITES.get(witness.runtime)
    if state is None:raise AuthorityUnavailable('conditioned W01 witness lost its actual private WRITE invocation')
    reader,inputs,selector,issued,scope,lease,envelope=state
    if(witness.graph is not graph or witness.scope is not scope or witness.owner is not None
            or witness.guard!=issued.evidence.owner_guard or witness.frame.envelope.authority!=envelope.authority
            or witness.frame.envelope.identity.operation_id!=selector.operation_id):
        raise AuthorityUnavailable('conditioned W01 witness borrowed another scope, actor, Owner or command')
    frame,stage,_=compile_conditioned_child_v1(witness.runtime,db,operation=witness.operation,request=witness.request,
        scope=scope,now_utc=witness.frame.now_utc)
    if frame!=witness.frame or stage!=witness.stage or _members(stage)[1]!=bundle.proposals:
        raise AuthorityUnavailable('conditioned actual complete current semantic stage changed before original CAS')
    return witness
