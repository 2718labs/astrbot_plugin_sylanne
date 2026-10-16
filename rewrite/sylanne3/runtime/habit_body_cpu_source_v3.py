"""Actual Host/Core Source reads for the fixed Habit Body CPU preparation."""
import hashlib,hmac,json
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..graph_types import AtomKey,GraphVersion
from ..authority_service.habit_body_preparation_v3 import HabitBodyPreparationSelectorV3,body_basis_v3

BODY_TYPES_V3=frozenset({'d02.body_profile.v1','d02.body_state.v1','d02.reservation.v1'})
_LEASE=('lease_id','parent_id','bot_id','persona_id','currency','limits_json','used_json','reserved_json','unconfirmed_json','version','state')
_FIXED=('policy_json','signature','status')
_EFFECT=('kind','payload_json','payload_digest','signature')
_POINT_SHAPES={
    'd02_fixed_body_policies_v1':(_FIXED,('bot','persona','policy_id','version')),
    'graph_d02_production_policies_v1':(_EFFECT,('bot','persona','policy_ref','revision')),
    'runtime_budget_leases':(_LEASE,('lease_id',)),
}

def body_read_phase_v3(request):
    from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
    return type(request)is HabitBodyPreparationSelectorV3 or type(request)is HabitOccurrenceExecutionSelectorV1 and request.operation_kind=='prepare_source_note_body'

def _policy_authority(bundle):
    from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
    key=hmac.digest(bundle.d02_signing_key,b'sylanne3.d02.body_quote_original.v1\0'+bundle.installation_policy.installation_id.encode('utf8'),'sha256')
    return D02BodyQuoteAuthority(key)

def _decode_fixed(bundle,namespace,policy_id,version,row):
    from ..domains.d02.body_quote_original import FixedBodyPolicyV1
    from ..domains.d02 import BodyProfile,BodyState,WorkComponent
    if row is None or row[2]!='active':raise AuthorityUnavailable('Habit fixed Body policy is absent or inactive')
    encoded,signature,_=row
    _policy_authority(bundle)._verify('d02-fixed-body-policy.v1',encoded,signature)
    raw=json.loads(encoded)
    if canonical_serialize(raw)!=encoded:raise AuthorityUnavailable('Habit fixed Body policy canonical original changed')
    p=raw['profile'];p={**p,'namespace':NamespaceId(**p['namespace']),'applicable_axes':tuple(p['applicable_axes']),'work_kinds':tuple(p['work_kinds'])}
    policy=FixedBodyPolicyV1(**{**raw,'profile':BodyProfile(**p),'initial_state':BodyState(**raw['initial_state']),'component':WorkComponent(**raw['component'])})
    if(policy.policy_id,policy.version,policy.profile.namespace)!=(policy_id,version,namespace):raise AuthorityUnavailable('Habit fixed Body policy original identity changed')
    return policy

def _decode_effect(issuer,namespace,ref,revision,row):
    from .d02_production_operations_v1 import SettledBodyEffectPolicyV1
    if row is None or row[0]!='effect':raise AuthorityUnavailable('Habit actual signed component effect policy is absent')
    _,encoded,digest,signature=row
    issuer._signer.verify('d11.d02-production-policy.v1',encoded,signature)
    raw=json.loads(encoded)
    if canonical_serialize(raw)!=encoded or canonical_digest(raw)!=digest:raise AuthorityUnavailable('Habit effect policy original changed')
    value=SettledBodyEffectPolicyV1(**{**raw,'namespace':NamespaceId(**raw['namespace'])})
    if(value.namespace,value.policy_ref,value.revision)!=(namespace,ref,revision):raise AuthorityUnavailable('Habit effect policy exact identity changed')
    return value

def _metadata_rows(db,namespace,*,work=None,reader=None):
    from .domain_production_contracts_v1 import ProductionOperationLimitsV1
    limit=ProductionOperationLimitsV1().max_query_rows
    def read(meter):
        fixed=tuple(db.execute("SELECT policy_id,version FROM d02_fixed_body_policies_v1 WHERE bot=? AND persona=? AND status='active' ORDER BY policy_id,version LIMIT ?",(*namespace.as_tuple,limit+1)))
        effect=tuple(db.execute("SELECT p.policy_ref,p.revision FROM graph_d02_production_policies_v1 p WHERE p.bot=? AND p.persona=? AND p.kind='effect' AND p.revision=(SELECT max(q.revision) FROM graph_d02_production_policies_v1 q WHERE q.bot=p.bot AND q.persona=p.persona AND q.policy_ref=p.policy_ref) ORDER BY p.policy_ref LIMIT ?",(*namespace.as_tuple,limit+1)))
        meter.charge_read(4096+256*(len(fixed)+len(effect)))
        if len(fixed)>limit or len(effect)>limit:raise AuthorityUnavailable('Habit Body installed policy catalogue requires its complete bounded EOF')
        return fixed,effect
    if work is not None:
        with work.quantum_v3()as meter:return read(meter)
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db)as meter:
        reader.require_current(meter=meter);return read(meter)

def _core_point(inputs,table,columns,key_columns,key):
    from ..authority_service.habit_authority_source_read_v3 import _fixed_row_v3,_run_column_v3
    from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
    work=inputs.work
    plain=tuple(c for c in columns if not c.endswith('_json'))
    header=_fixed_row_v3(work,table,plain,' AND '.join(c+'=?'for c in key_columns),key)
    if header is None:return None
    values=dict(zip(plain,header))
    for c in columns:
        if c.endswith('_json'):
            column=DispatchOriginalJSONReadV3(work,table=table,column=c,key_columns=key_columns,key=key)
            values[c]=canonical_serialize(_run_column_v3(work,column))
    again=_fixed_row_v3(work,table,plain,' AND '.join(c+'=?'for c in key_columns),key)
    if again!=header:raise AuthorityUnavailable('Habit Body actual signed row changed during EOF')
    return tuple(values[c]for c in columns)

def _host_point(reader,table,columns,key_columns,key):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_background_read_v3 import background_json_loads_v3
    row=_producer_original_point_v3(reader.db,table=table,columns=columns,key_columns=key_columns,key=key,legacy_reader=lambda:None)
    if row is None:return None
    return tuple(canonical_serialize(background_json_loads_v3(value))if c.endswith('_json')else value for c,value in zip(columns,row,strict=True))

def require_body_point_v3(reader,request):
    from .current_habit_source_read_v3 import require_habit_source_work_v3
    from .habit_followup_source_v3 import READ_KIND,_require_selector,_CHILDREN
    state=require_habit_source_work_v3(reader);table,columns,key_columns,key=request
    if table not in _POINT_SHAPES:return False
    if reader.operation_kind==READ_KIND:
        locator=_require_selector(state.selector)
        if locator.header[2]!='habit_source_note_action_requires_original_life':return False
    elif not body_read_phase_v3(state.selector):return False
    if request[1:3]!=_POINT_SHAPES[table]:raise AuthorityUnavailable('Habit Body original point shape differs')
    if state.source_permission is None:raise AuthorityUnavailable('Habit Body original cannot precede Owner and all Source groups')
    state.source_permission.require_for_v3(reader)
    if table=='runtime_budget_leases':
        if key!=(reader.parent_budget_lease_ref,):raise AuthorityUnavailable('Habit Body selected another original parent')
    elif tuple(key[:2])!=reader.namespace.as_tuple:raise AuthorityUnavailable('Habit Body installed original crossed namespace')
    return True

def select_host_body_metadata_v3(reader):
    from .current_habit_source_read_v3 import require_habit_source_work_v3,_metadata
    from .habit_followup_source_v3 import READ_KIND,_require_selector
    state=require_habit_source_work_v3(reader)
    from ..authority_service.d10_habit_execution_contract_v1 import HabitOccurrenceExecutionSelectorV1
    if type(state.selector)is HabitOccurrenceExecutionSelectorV1 and state.selector.operation_kind in {'register_current_habit_source_note_life_plan_v1','prepare_life'}:
        from .d02_life_body_preparation_v1 import _refs as body_refs
        q=state.selector.qualification_selector
        key=body_refs(reader.namespace,q.activity_id,'d02-life-body:'+q.execution_operation_id)[0]
        state.selected_keys.add(key);state.body_keys.add(key);_metadata(reader,('head',key.token))
        return
    if reader.operation_kind==READ_KIND:
        if _require_selector(state.selector).header[2]!='habit_source_note_action_requires_original_life':return
    elif not body_read_phase_v3(state.selector):return
    for token in reader.heads:
        key=AtomKey.from_token(token)
        if key.type_name not in BODY_TYPES_V3 or reader.heads[token][1]!=1:continue
        state.selected_keys.add(key);state.body_keys.add(key);_metadata(reader,('head',token))

def select_core_body_metadata_v3(state):
    if not body_read_phase_v3(state.work.request):return
    from ..authority_service.habit_authority_source_read_v3 import _HabitMetadataColumnV3,_run_column_v3
    for token,(revision,valid,cell)in state.work.heads.items():
        key=AtomKey.from_token(token)
        if key.type_name not in BODY_TYPES_V3 or valid!=1:continue
        state.extra_keys.add(key)
        column=_HabitMetadataColumnV3(state,key,revision,valid,cell,locator=False,selected=True)
        _run_column_v3(state.work,column);column.finish_metadata_v3()

def _policies(bundle,issuer,namespace,point,rows,profile,selector=None):
    from .d11_life_contract_v1 import WORK_KIND
    fixed,effects=rows
    selected=[]
    for policy_id,version in fixed:
        policy=_decode_fixed(bundle,namespace,policy_id,version,point('d02_fixed_body_policies_v1',_FIXED,('bot','persona','policy_id','version'),(*namespace.as_tuple,policy_id,version)))
        if policy.work_kind==WORK_KIND and policy.profile==profile:selected.append(policy)
    if len(selected)!=1:raise AuthorityUnavailable('Habit needs one actual active SourceNote fixed Body policy')
    policy=selected[0];matched=[]
    if selector is not None and(policy.policy_id,policy.version)!=(selector.body_policy_id,selector.body_policy_version):
        raise AuthorityUnavailable('Habit actual unique Body policy changed after preparation')
    for ref,revision in effects:
        effect=_decode_effect(issuer,namespace,ref,revision,point('graph_d02_production_policies_v1',_EFFECT,('bot','persona','policy_ref','revision'),(*namespace.as_tuple,ref,revision)))
        if(effect.profile_id,effect.work_kind,effect.component_id)==(policy.profile.profile_id,WORK_KIND,policy.component.component_id):matched.append(effect)
    if len(matched)!=1:raise AuthorityUnavailable('Habit needs one actual current effect original for its exact fixed component')
    if selector is not None and matched[0].policy_ref!=selector.effect_policy_ref:
        raise AuthorityUnavailable('Habit actual unique component effect policy changed after preparation')
    return policy,matched[0]

def _check_body_state(atoms,policy):
    from ..domains.d02 import BodyState,BodyDomain,_reservation
    profiles=tuple(a for a in atoms if a.key.type_name=='d02.body_profile.v1'and a.valid and a.key.name==policy.profile.profile_id)
    states=tuple(a for a in atoms if a.key.type_name=='d02.body_state.v1'and a.valid and a.key.name==policy.profile.profile_id)
    if len(profiles)!=1 or len(states)!=1:raise AuthorityUnavailable('Habit fixed Body profile requires its actual unique current state')
    from ..domains.d01.production_operations_v1 import plain_v1
    if profiles[0].value!=plain_v1(policy.profile):raise AuthorityUnavailable('Habit actual Body profile differs from installed signed policy')
    state=BodyState(**states[0].value)
    if state.version!=states[0].revision:raise AuthorityUnavailable('Habit current Body state version differs')
    reservations=tuple(_reservation(a.value)for a in atoms if a.valid and a.key.type_name=='d02.reservation.v1')
    if BodyDomain().check_work_start(state,reservations,additional_cost=policy.component.fixed_cost).status!='clear':
        raise AuthorityUnavailable('Habit actual Body availability is not clear')
    return tuple(GraphVersion(a.key,a.revision)for a in (*profiles,*states)),canonical_digest(tuple((a.key.token,a.revision,a.value)for a in atoms))

def host_body_basis_v3(reader,*,occurrence,occurrence_atom,qualification_selector,qualification_ref,qualification_digest,selector=None):
    from .current_habit_source_read_v3 import require_habit_source_work_v3,_metadata
    from .current_method_learning_read_v3 import method_graph_head_v3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .budget import _lease_from_row,require_budget_family_admissible
    state=require_habit_source_work_v3(reader);bundle=state.context._v2_model_bundle
    point=lambda table,columns,keys,key:_host_point(reader,table,columns,keys,key)
    atoms=tuple(method_graph_head_v3(reader.db,reader.namespace,key)for key in sorted(state.body_keys,key=lambda k:k.token)if key.type_name in BODY_TYPES_V3)
    profile=_actual_profile_v3(atoms)
    policy,effect=_policies(bundle,reader.graph._GraphCoordinator__d11_issuer,reader.namespace,point,
        _metadata_rows(reader.db,reader.namespace,reader=reader),profile,selector)
    if selector is None:
        selector=HabitBodyPreparationSelectorV3(reader.namespace,bundle.installation_policy.installation_id,qualification_selector,
            qualification_ref,qualification_digest,occurrence_atom.key.token,occurrence_atom.revision,occurrence.action_intent_ref,
            policy.policy_id,policy.version,effect.policy_ref)
    body_heads,body_state_digest=_check_body_state(atoms,policy)
    parent=_lease_from_row(point('runtime_budget_leases',_LEASE,('lease_id',),(reader.parent_budget_lease_ref,)))
    require_budget_family_admissible(reader.db,parent.lease_id)
    root=state.root_locator;grant=_metadata(reader,('budget_grant',(root[0],root[2])))
    action=method_graph_head_v3(reader.db,reader.namespace,AtomKey.from_token(occurrence.action_intent_ref))
    actual=read_adopted_domain_operation_v1(reader.db,reader.namespace,occurrence.occurrence_operation_id)
    if actual is None or actual['operation_kind']!='prepare_current_habit_source_note_action_v1'or GraphVersion(action.key,action.revision)not in actual['receipt'].write_versions:
        raise AuthorityUnavailable('Habit CPU preparation lacks exact adopted Action A')
    versions=tuple(v for v in state.source_permission.versions if v.key.type_name in {'memory.source','memory.access','d06.source_correction_head.v1'})
    basis=body_basis_v3(selector=selector,occurrence_head=GraphVersion(occurrence_atom.key,occurrence_atom.revision),
        occurrence_digest=canonical_digest(occurrence_atom.value),action_head=GraphVersion(action.key,action.revision),
        action_digest=canonical_digest(action.value),action_producer_digest=actual['original_digest'],
        action_receipt_digest=canonical_digest(actual['receipt']),body_policy=policy,effect_policy=effect,parent=parent,grant=grant,
        owner_guard=reader.material_owner_guard,current_self=reader.current_self,source_versions=versions,
        graph_revision=reader.graph_stamp[0].graph_revision,graph_epoch=reader.graph_stamp[1].revision,
        access_epoch=reader.owner_binding.access_epoch,delete_epoch=reader.owner_binding.delete_epoch,
        body_heads=body_heads,body_state_digest=body_state_digest)
    return selector,basis

def core_body_basis_v3(service,inputs,selector,policy_original):
    from ..authority_service.habit_authority_source_read_v3 import require_habit_authority_work_v3,_read_habit_committed_original_v3,_fixed_row_v3
    from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    require_habit_authority_work_v3(inputs.work);inputs.require_for_v3(service=service,permit=inputs.work.permit)
    point=lambda table,columns,keys,key:_core_point(inputs,table,columns,keys,key)
    atoms=tuple(a for k,a in sorted(inputs.bodies.items(),key=lambda pair:pair[0].token)if k.type_name in BODY_TYPES_V3)
    profile=_actual_profile_v3(atoms)
    policy,effect=_policies(service.installed_bundle,service.issuer,inputs.work.namespace,point,
        _metadata_rows(inputs.work.db,inputs.work.namespace,work=inputs.work),profile,selector)
    body_heads,body_state_digest=_check_body_state(atoms,policy)
    occurrence_atom=inputs.bodies[AtomKey.from_token(selector.occurrence_ref)]
    occurrence=habit_value_from_wire_v1('d10.habit_occurrence.v1',occurrence_atom.value)
    action=inputs.bodies[AtomKey.from_token(selector.action_intent_ref)]
    digest,payload=_read_habit_committed_original_v3(inputs,operation_id=occurrence.occurrence_operation_id,
        expected_kind='prepare_current_habit_source_note_action_v1',member=action)
    receipt=_fixed_row_v3(inputs.work,'graph_domain_production_originals_v1',('receipt_digest',),
        'bot=? AND persona=? AND operation_id=?',(*inputs.work.namespace.as_tuple,occurrence.occurrence_operation_id))
    owner=inputs.owner_entry
    from ..graph_types import owner_grant_key
    key=owner_grant_key(*inputs.work.namespace.as_tuple)
    guard=ProductionOwnerGuardV1(key.token,inputs.work.heads[key.token][0],canonical_digest(owner.grant),owner.head.guard.authorization_head.removeprefix('sha256:'))
    versions=tuple(v for v in inputs.read_versions if v.key.type_name in {'memory.source','memory.access','d06.source_correction_head.v1'})
    return body_basis_v3(selector=selector,occurrence_head=GraphVersion(occurrence_atom.key,occurrence_atom.revision),
        occurrence_digest=canonical_digest(occurrence_atom.value),action_head=GraphVersion(action.key,action.revision),
        action_digest=canonical_digest(action.value),action_producer_digest=digest,action_receipt_digest=receipt[0],
        body_policy=policy,effect_policy=effect,parent=inputs.root_lease,grant=inputs.root_grant,owner_guard=guard,
        current_self=inputs.current_self,source_versions=versions,graph_revision=inputs.current_self.graph_revision,
        graph_epoch=inputs.current_self.graph_epoch,access_epoch=inputs.work.graph_stamp[1],delete_epoch=inputs.work.graph_stamp[2],
        body_heads=body_heads,body_state_digest=body_state_digest)


def _actual_profile_v3(atoms):
    from ..domains.d02 import BodyProfile
    states=tuple(a for a in atoms if a.valid and a.key.type_name=='d02.body_state.v1')
    if len(states)!=1:raise AuthorityUnavailable('Habit Body preparation requires the unique actual current Body state')
    profiles=tuple(a for a in atoms if a.valid and a.key.type_name=='d02.body_profile.v1'and a.key.name==states[0].value['profile_id'])
    if len(profiles)!=1:raise AuthorityUnavailable('Habit Body preparation actual profile is absent')
    raw=profiles[0].value
    return BodyProfile(**{**raw,'namespace':NamespaceId(**raw['namespace']),
        'applicable_axes':tuple(raw['applicable_axes']),'work_kinds':tuple(raw['work_kinds'])})


def require_current_body_basis_rows_v3(reader,preparation):
    from .current_habit_source_read_v3 import require_habit_write_phase_v3
    from .budget import require_budget_family_admissible
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    pending=require_habit_write_phase_v3(reader)
    if not reader.db.in_transaction or pending.graph is not reader.graph:raise AuthorityUnavailable('Habit Body basis current comparison requires actual W01')
    b=preparation.basis;p=preparation.selector;ns=reader.namespace.as_tuple
    body=canonical_serialize(b['body_policy']);effect=canonical_serialize(b['effect_policy'])
    body_signature=_policy_authority(pending.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle)._sign('d02-fixed-body-policy.v1',body)
    effect_signature=reader.graph._GraphCoordinator__d11_issuer._signer.sign('d11.d02-production-policy.v1',effect)
    with runtime_storage_quantum_v3(reader.db)as meter:
        actual=meter.read_fixed_row(reader.db,'d02_fixed_body_policies_v1',('version',),
            'bot=? AND persona=? AND policy_id=? AND version=? AND policy_json=? AND signature=? AND status=?',
            (*ns,p.body_policy_id,p.body_policy_version,body,body_signature,'active'))
        if actual!=(p.body_policy_version,):raise AuthorityUnavailable('Habit actual installed Body policy changed before W01')
        actual=meter.read_fixed_row(reader.db,'graph_d02_production_policies_v1',('revision',),
            'bot=? AND persona=? AND policy_ref=? AND revision=? AND kind=? AND payload_json=? AND payload_digest=? AND signature=?',
            (*ns,p.effect_policy_ref,b['effect_policy']['revision'],'effect',effect,b['effect_policy_digest'],effect_signature))
        if actual!=(b['effect_policy']['revision'],):raise AuthorityUnavailable('Habit actual component effect original changed before W01')
        parent=b['parent_lease']
        key=('lease_id','parent_id','bot_id','persona_id','currency','limits_json','used_json','reserved_json','unconfirmed_json','version','state')
        values=(parent['lease_id'],parent['parent_id'],parent['bot_id'],parent['persona_id'],parent['currency'],
            *(canonical_serialize(parent[name])for name in('limits','used','reserved','unconfirmed')),parent['version'],parent['state'])
        actual=meter.read_fixed_row(reader.db,'runtime_budget_leases',('version',),
            ' AND '.join(name+(' IS ?'if name=='parent_id'else'=?')for name in key),values)
        if actual!=(parent['version'],):raise AuthorityUnavailable('Habit actual original parent available CPU changed before W01')
    require_budget_family_admissible(reader.db,p.qualification_selector.parent_root_grant_ref)


def require_core_committed_habit_body_v3(service,inputs,occurrence,body_payload):
    from ..authority_service.habit_authority_source_read_v3 import _fixed_row_v3,_run_column_v3
    from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
    from .d02_life_body_preparation_v1 import life_body_preparation_original_from_wire_v1
    from .issuers import _decode_quote
    from ..domains.d02 import BodyQuote,WorkComponent
    from .domain_production_originals_v1 import _receipt
    from .habit_activity_history_v1 import validate_habit_activity_provenance_v1
    from ..authority_service.habit_body_preparation_v3 import BODY_PREPARATION_PROVENANCE_V3,preparation_from_domain_plain_v3,preparation_signature_material_v3
    from .d11_life_contract_v1 import WORK_KIND
    w=inputs.work;ns=w.namespace;operation='d02-life-body:'+occurrence.occurrence_operation_id
    ref='life-body:'+operation
    row=_core_point(inputs,'graph_d11_life_originals_v1',('producing_operation_id','payload_json','payload_digest','signature'),
        ('bot','persona','kind','original_ref'),(*ns.as_tuple,'life_body_preparation',ref))
    if row is None or row[0]!=operation:raise AuthorityUnavailable('Habit Life plan lacks actual signed Body B preparation')
    service.issuer._signer.verify('d11.life-original.v1',canonical_serialize((ns,'life_body_preparation',ref,row[2])),row[3])
    raw=json.loads(row[1])
    if canonical_digest(raw)!=row[2]:raise AuthorityUnavailable('Habit signed Body B payload digest changed')
    body=life_body_preparation_original_from_wire_v1(raw)
    selected,_=validate_habit_activity_provenance_v1('d02','prepare_source_note_body',body_payload['provenance']['habit_activity_execution_v1'])
    prep=preparation_from_domain_plain_v3(body_payload['provenance'][BODY_PREPARATION_PROVENANCE_V3])
    if selected.command.preparation!=prep:raise AuthorityUnavailable('Habit actual Body B changed its prepared CPU original')
    expected=hmac.new(service._key,preparation_signature_material_v3(prep.selector,prep.basis,prep.read_permit),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(prep.signature,expected):raise AuthorityUnavailable('Habit Body B preparation was not issued by actual Core')
    if(body.action_intent_ref,body.action_operation_id,body.body_prepare_operation_id,body.activity_id,body.effect_id)!=(
            occurrence.action_intent_ref,occurrence.occurrence_operation_id,operation,occurrence.activity_id,occurrence.effect_id):
        raise AuthorityUnavailable('Habit signed Body B belongs to another exact Action/effect/occurrence')
    action=inputs.bodies[AtomKey.from_token(occurrence.action_intent_ref)]
    if body.action_intent_digest!=canonical_digest(action.value):raise AuthorityUnavailable('Habit Body B current Action differs')
    quote_row=_core_point(inputs,'runtime_resource_quotes',('quote_json','signature','status'),('quote_id','version'),(body.resource_quote_ref,body.resource_quote_version))
    if quote_row is None:raise AuthorityUnavailable('Habit Life plan requires actual signed ResourceQuote')
    service.issuer.resource_issuer._signer.verify('resource-quote.v1',quote_row[0],quote_row[1])
    quote=_decode_quote(quote_row[0])
    body_row=_core_point(inputs,'d02_body_quotes_v1',('quote_version','policy_id','policy_version','operation_id','resource_quote_digest','body_quote_json','signature'),
        ('bot','persona','quote_id'),(*ns.as_tuple,body.body_quote_ref))
    if body_row is None or body_row[:5]!=(body.body_quote_version,prep.selector.body_policy_id,prep.selector.body_policy_version,operation,canonical_digest(quote)):
        raise AuthorityUnavailable('Habit actual signed BodyQuote changed its fixed policy/ResourceQuote binding')
    body_raw=json.loads(body_row[5])
    signed={'quote':body_raw,'quote_version':body_row[0],'policy_id':body_row[1],'policy_version':body_row[2],
        'operation_id':body_row[3],'resource_quote_digest':body_row[4]}
    _policy_authority(service.installed_bundle)._verify('d02-body-quote.v1',canonical_serialize(signed),body_row[6])
    body_quote=BodyQuote(**{**body_raw,'components':tuple(WorkComponent(**x)for x in body_raw['components'])})
    if(canonical_digest(quote)!=body.resource_quote_digest or canonical_digest(body_quote)!=body.body_quote_digest
            or quote.ceiling!={'cpu_ms':prep.cpu_ceiling_ms}
            or(quote.operation_id,quote.activity_id,quote.effect_id,quote.parent_budget_lease_ref,quote.work_kind)!=(
                operation,occurrence.activity_id,occurrence.effect_id,occurrence.parent_root_grant_ref,WORK_KIND)
            or(quote.bot_id,quote.persona_id)!=ns.as_tuple or quote.valid_until_utc>prep.valid_until_utc
            or quote.valid_until_utc>occurrence.original_deadline_utc
            or body_quote.quote_id!=body.body_quote_ref or body_quote.profile_id!=prep.basis['body_policy']['profile']['profile_id']
            or tuple(x.component_id for x in body_quote.components)!=(body.component_id,)
            or body.component_id!=prep.basis['body_policy']['component']['component_id']
            or(body.effect_policy_ref,body.effect_policy_revision,body.effect_policy_digest)!=(prep.selector.effect_policy_ref,
                prep.basis['effect_policy']['revision'],prep.basis['effect_policy_digest'])):
        raise AuthorityUnavailable('Habit actual quotes changed CPU/component/parent/deadline identity')
    receipt_column=DispatchOriginalJSONReadV3(w,table='graph_domain_production_originals_v1',column='receipt_json',
        key_columns=('bot','persona','operation_id'),key=(*ns.as_tuple,operation))
    receipt=_receipt(_run_column_v3(w,receipt_column))
    reservation=inputs.bodies[AtomKey.from_token(body.reservation_ref)]
    if(canonical_digest(receipt)!=body.receipt_digest or receipt.write_versions!=(GraphVersion(reservation.key,reservation.revision),)
            or reservation.revision!=body.reservation_revision or canonical_digest(reservation.value)!=body.reservation_digest):
        raise AuthorityUnavailable('Habit Body reservation lost its exact producing receipt/current head')
    history=_fixed_row_v3(w,'graph_history',('event_id','valid','event_bot','event_persona','event_session'),
        'token=? AND revision=?',(body.reservation_ref,body.reservation_revision))
    if history!=(operation,1,*ns.as_tuple,occurrence.activity_id):raise AuthorityUnavailable('Habit Body reservation has another actual producing history')
    history_body=DispatchOriginalJSONReadV3(w,table='graph_history',column='value',key_columns=('token','revision'),
        key=(body.reservation_ref,body.reservation_revision))
    if _run_column_v3(w,history_body)!=reservation.value:raise AuthorityUnavailable('Habit Body reservation differs from its actual original COMMIT member')
    reading=service.clock();now=reading.utc_seconds+reading.utc_error_seconds
    if now>=min(quote.valid_until_utc,body_quote.valid_until,occurrence.original_deadline_utc):
        raise AuthorityUnavailable('Habit normal Life plan cannot extend actual signed Body quote lifetime')
    return body,quote,body_quote
