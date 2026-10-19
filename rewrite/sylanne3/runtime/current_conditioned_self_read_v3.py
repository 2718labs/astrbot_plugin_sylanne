"""Conditioned Self owns metadata, Source closure and selected READ/WRITE issuance.

Only bounded locator metadata is retained before Source authorization. The common
Beta1 kernel supplies fragments and current Owner EOF; it grants no permission.
"""
from __future__ import annotations
from dataclasses import dataclass,field
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,owner_grant_key
from ..runtime_contracts import NamespaceId,canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3

CONDITIONED_SELF_WORK_KIND_V3='current_conditioned_self_source_read_v3'
CONDITIONED_OPERATION_DOMAINS_V1={
    'register_calibration_policy_v1':('d01','d06','d08','d10','d11'),
    'register_condition_predicate_v1':('d01','d06','d08','d10','d11'),
    'register_simulation_forecast_plan_v1':('d01','d06','d07','d08','d10','d11'),
    'register_current_prediction_v1':('d01','d06','d07','d08','d10','d11'),
    'record_current_simulation_v1':('d01','d06','d07','d08','d10','d11'),
    'resolve_current_prediction_v1':('d01','d06','d07','d08','d10','d11'),
    'review_current_conditioned_self_v1':('d01','d02','d06','d07','d08','d11'),
    'adopt_current_conditioned_self_v1':('d01','d02','d06','d07','d08','d10','d11'),
    'rollback_current_conditioned_strategy_v1':('d01','d02','d06','d07','d08','d10','d11'),
    'match_current_conditioned_strategy_v1':('d01','d06','d07','d08','d10','d11'),
    'select_current_conditioned_personal_step_v1':('d01','d02','d06','d07','d08','d10','d11'),
    'project_current_conditioned_life_strategy_v1':('d01','d06','d07','d08','d10','d11')}
CONDITIONED_SELF_READ_KIND_V4='read_current_self_view_v4'
_STATES=WeakKeyDictionary()
_WRITES=WeakKeyDictionary()
_INSTALLED=WeakKeyDictionary()
_ISSUER=object()


def conditioned_operation_types_v3():
    from .conditioned_self_operations_v1 import OPERATIONS,ProjectCurrentSelfViewRequestV4
    return {**{kind:row[1]for kind,row in OPERATIONS.items()},
        CONDITIONED_SELF_READ_KIND_V4:ProjectCurrentSelfViewRequestV4,
        _CONDITIONED_FOLLOWUP_READ_KIND_V3:_ConditionedFollowupLocatorRequestV3}


def _identity(reader):
    return(reader.work,reader.operation,reader.fence,reader.namespace,reader.selection_digest,
        reader.graph_stamp,reader.request,reader.operation_id,reader.authority)


@dataclass(slots=True)
class _ConditionedSourceStateV3:
    reader: object
    identity: tuple
    owner_binding: object
    tasks: dict=field(default_factory=dict)
    selectors: set=field(default_factory=set)
    selected_keys: set=field(default_factory=set)
    allowed_history: set=field(default_factory=set)
    adoption_operations: set=field(default_factory=set)
    required_domain_producers: set=field(default_factory=set)
    signed_originals: set=field(default_factory=set)
    observed_originals: dict=field(default_factory=dict)
    source_roots: set=field(default_factory=set)
    source_permission: object=None
    source_caps: object=field(default_factory=WeakKeyDictionary)
    prepared_plan: object=None
    life_prepared_facts: list=field(default_factory=list)
    output_phase: str='unplanned'
    output_keys: tuple|None=None
    output_previous_plan: object=None
    output_replay_operations: set=field(default_factory=set)
    output_previous_groups: tuple|None=None
    budget_ancestry: tuple|None=None
    root_locator: object=None
    read_stage: str='source'


def register_conditioned_self_owner_work_v3(reader):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(reader)
    types=conditioned_operation_types_v3()
    if(reader.work.kind!=CONDITIONED_SELF_WORK_KIND_V3 or reader.operation_kind not in types
            or type(reader.request)is not types[reader.operation_kind]or reader in _STATES):
        raise AuthorityUnavailable('conditioned Self requires its once-issued exact own Source Work')
    _STATES[reader]=_ConditionedSourceStateV3(reader,_identity(reader),reader.owner_binding)
    import time
    _SELF_VIEW_CLOCKS_V4.setdefault(reader,(reader.initial_now_utc,time.monotonic()))


def require_conditioned_self_work_v3(reader):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(reader)
    state=_STATES.get(reader)
    if(state is None or state.reader is not reader or state.identity!=_identity(reader)
            or reader.operation_kind not in conditioned_operation_types_v3()
            or reader.owner_binding is not state.owner_binding and state.source_permission is not None):
        raise AuthorityUnavailable('conditioned Self lost its private Work/request/Owner/selection')
    return state


def pin_conditioned_owner_entry_v3(reader):
    state=require_conditioned_self_work_v3(reader)
    if reader.general_owner_entry is None:raise AuthorityUnavailable('conditioned Self requires completed actual Owner EOF')
    state.owner_binding=reader.owner_binding


def _active(db):
    from .current_method_learning_read_v3 import _method_active
    reader=_method_active(db)
    if reader is None or reader.operation_kind not in conditioned_operation_types_v3():return None
    require_conditioned_self_work_v3(reader)
    return reader


from .conditioned_producer_source_metadata_v3 import(
    CONDITIONED_LOCATOR_FIELDS_V3 as _LOCATOR_FIELDS_V3,
    ConditionedLocatorJSONV3 as _ConditionedLocatorJSONV3,
    ConditionedClaimCaptureV3 as _ConditionedClaimCaptureV3)


def retain_conditioned_metadata_path_v3(task,path):
    from .current_conditioned_personal_choice_v3 import choice_metadata_retain_v3
    retained=choice_metadata_retain_v3(task,path)
    if retained is not None:return retained
    from .conditioned_producer_source_metadata_v3 import retain_conditioned_business_locator_path_v3
    return retain_conditioned_business_locator_path_v3(task.identity,path)

def conditioned_metadata_spec_v3(reader,identity):
    state=require_conditioned_self_work_v3(reader)
    if identity not in state.selectors:raise AuthorityUnavailable('conditioned locator was not selected by its actual recipe')
    kind,value=identity
    if kind in {'personal_choice_life','personal_choice_policy'}:
        from .current_conditioned_personal_choice_v3 import choice_signed_metadata_spec_v3
        spec=choice_signed_metadata_spec_v3(reader,identity)
        if spec is None:raise AuthorityUnavailable('personal choice signed metadata has no actual locator')
        return spec
    if kind=='root_grant':
        lease_id,version=value
        policy=reader.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.installation_policy
        if(lease_id,version)!=(policy.root_lease.lease_id,policy.root_grant.version):
            raise AuthorityUnavailable('conditioned Root locator is not the actual installed signed Root grant version')
        return('runtime_budget_grants','grant_json',('lease_id','version'),value,('lease_id','version','signature','status'),(),'budget-grant.v1')
    if kind=='general_signed':
        table,signed_kind,ref=value
        allowed={'growth_proposal','growth_counterevidence','general_growth_intent_v1','general_growth_trial_start_v1','general_growth_trial_v1'}
        if table=='graph_d01_production_inputs_v1'and signed_kind in allowed:
            from .d01_production_operations_v1 import SIGN_KIND
            return(table,'payload_json',('bot','persona','original_ref'),(*reader.namespace.as_tuple,ref),
                ('kind','producing_operation_id','payload_digest','signature'),(),SIGN_KIND)
        if table=='graph_d07_execution_originals_v1'and signed_kind in {'prepared','adopted','semantic_question'}:
            return(table,'payload_json',('bot','persona','kind','original_ref'),(*reader.namespace.as_tuple,signed_kind,ref),
                ('kind','payload_digest','signature'),(),None)
        raise AuthorityUnavailable('conditioned General signed locator escaped its exact existing Original families')
    if kind=='simulation_request':
        return('graph_d07_execution_originals_v1','payload_json',('bot','persona','kind','original_ref'),
            (*reader.namespace.as_tuple,'simulation_request',value),('payload_digest','signature'),(),None)
    if kind=='life_prepared':
        from .life_prepared_source_metadata_v3 import life_prepared_locator_spec_v3
        return life_prepared_locator_spec_v3(reader.namespace,value)
    if kind=='head':
        key=AtomKey.from_token(value)
        if NamespaceId.from_key(key)!=reader.namespace:raise AuthorityUnavailable('conditioned head locator crossed namespace')
        return('graph_atoms','value',('token','bot','persona'),(value,*reader.namespace.as_tuple),
            ('revision','valid','value_cell_id'),tuple((name,)for name in _LOCATOR_FIELDS_V3),None)
    if kind=='history':
        token,revision=value
        if(token,revision)not in state.allowed_history:raise AuthorityUnavailable('conditioned historical locator has no frozen selected revision')
        return('graph_history','value',('token','revision'),(token,revision),
            ('event_bot','event_persona','event_id','valid','value_cell_id'),tuple((name,)for name in _LOCATOR_FIELDS_V3),None)
    if kind=='producer':
        if value not in state.adoption_operations:raise AuthorityUnavailable('conditioned original has no actual selected graph producer')
        return('graph_domain_production_originals_v1','original_payload_json',('bot','persona','operation_id'),
            (*reader.namespace.as_tuple,value),('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest'),
            (('schema',),('namespace',),('identity',),('read_versions',),('provenance',)),None)
    raise AuthorityUnavailable('unregistered conditioned metadata selector')


def _source_tokens(value):
    if type(value)is str:
        if not value.startswith('["'):return()
        key=AtomKey.from_token(value)
        return(value,)if key.type_name=='memory.source'else()
    if type(value)is dict:return tuple(ref for child in value.values()for ref in _source_tokens(child))
    if type(value)in(tuple,list):return tuple(ref for child in value for ref in _source_tokens(child))
    return ()


def _graph_tokens(value):
    if type(value)is str:
        return(AtomKey.from_token(value),)if value.startswith('["')else()
    if type(value)is dict:
        if set(value)=={'owner','type_name','name'}and type(value['owner'])is dict:
            from ..graph_types import Owner
            return(AtomKey(Owner(**value['owner']),value['type_name'],value['name']),)
        return tuple(key for child in value.values()for key in _graph_tokens(child))
    if type(value)in(tuple,list):return tuple(key for child in value for key in _graph_tokens(child))
    return()


def _metadata_versions_v3(value):
    if type(value)is dict:
        if set(value)=={'key','revision'}and type(value['key'])is str and type(value['revision'])is int:
            return(GraphVersion(AtomKey.from_token(value['key']),value['revision']),)
        return tuple(version for child in value.values()for version in _metadata_versions_v3(child))
    if type(value)in(tuple,list):return tuple(version for child in value for version in _metadata_versions_v3(child))
    return()


def finish_conditioned_metadata_v3(task,value):
    from .dispatch_current_inventory_v3 import _freeze_value_v3
    state=require_conditioned_self_work_v3(task.reader);reader=task.reader
    kind,selected=task.identity
    if kind in {'personal_choice_life','personal_choice_policy'}:
        from .current_conditioned_personal_choice_v3 import finish_choice_signed_metadata_v3
        return finish_choice_signed_metadata_v3(task,value)
    if kind=='root_grant':
        from .issuers import BudgetLeaseGrant
        raw=dict(value);raw['allowed_work_kinds']=tuple(raw['allowed_work_kinds']);grant=BudgetLeaseGrant(**raw)
        expected=reader.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.installation_policy.root_grant
        if(grant!=expected or grant.lease_id!=selected[0]or grant.version!=selected[1]
                or task.metadata[3]!='active'or task.column.signature_verified is not True):
            raise AuthorityUnavailable('conditioned current signed Root differs from the actual installation grant')
        with runtime_storage_quantum_v3(reader.db)as meter:
            latest=meter.read_fixed_row(reader.db,'runtime_budget_grants',('lease_id','version','signature','status'),
                'lease_id=? ORDER BY version DESC',(grant.lease_id,))
        if latest!=task.metadata:raise AuthorityUnavailable('conditioned installed Root grant is superseded or inactive')
        state.signed_originals.add(('runtime_budget_grants',selected))
        return _freeze_value_v3(raw)
    if kind in {'general_signed','simulation_request'}:
        return _finish_conditioned_signed_metadata_v3(task,value)
    if kind=='life_prepared':
        from .life_prepared_source_metadata_v3 import finish_life_prepared_locator_v3
        from ..domains.d01.production_operations_v1 import plain_v1
        facts=finish_life_prepared_locator_v3(namespace=reader.namespace,original_ref=selected,header=task.metadata,
            projection=value,fields_seen=task.column.beta1_metadata_fields_seen,whole_digest=task.column.canonical_digest,
            signer=reader.graph._GraphCoordinator__d11_issuer._signer)
        state.life_prepared_facts.append(facts);state.source_roots.update(facts.source_roots)
        state.adoption_operations.add(facts.producing_operation_id)
        for version in facts.read_versions:
            state.selected_keys.add(version.key)
            if version.revision:state.allowed_history.add((version.key.token,version.revision))
        state.signed_originals.add(('graph_d11_life_originals_v1',(*reader.namespace.as_tuple,'prepared',selected)))
        return _freeze_value_v3(plain_v1(facts))
    if kind in {'head','history'}:
        token=selected if kind=='head'else selected[0]
        key=AtomKey.from_token(token)
        if kind=='head':revision,valid,_=task.metadata
        else:
            bot,persona,operation_id,valid,_=task.metadata
            if(bot,persona)!=reader.namespace.as_tuple:raise AuthorityUnavailable('conditioned history event crossed namespace')
            revision=selected[1];state.adoption_operations.add(operation_id)
            from .conditioned_self_operations_v1 import VALUE_TYPES
            if key.type_name in VALUE_TYPES or key.type_name=='d07.current_interpretation.v1':
                state.required_domain_producers.add(operation_id)
        if type(revision)is not int or revision<1 or valid not in(0,1):raise AuthorityUnavailable('conditioned graph locator changed revision/validity')
        from .conditioned_self_operations_v1 import VALUE_TYPES
        if key.type_name in VALUE_TYPES:
            from ..domains.d01.conditioned_self_v1 import require_conditioned_record_locator_v1
            require_conditioned_record_locator_v1(value,task.column.beta1_metadata_fields_seen,
                namespace=reader.namespace,type_name=key.type_name)
            from ..domains.d01.conditioned_self_v1 import CAPABILITY_TYPE,STRATEGY_TYPE,conditioned_revision_record_name_v1
            if key.type_name in {CAPABILITY_TYPE,STRATEGY_TYPE}:
                expected_name=conditioned_revision_record_name_v1(namespace=reader.namespace,type_name=key.type_name,
                    record_id=value['capability_id']if key.type_name==CAPABILITY_TYPE else value['strategy_id'],
                    revision=value['revision'],review_ref=value['last_review_ref']if key.type_name==CAPABILITY_TYPE else value['review_ref'])
                if key.name!=expected_name:raise AuthorityUnavailable('conditioned immutable candidate key lost its exact producing review branch')
        for ref in _source_tokens(value):
            if NamespaceId.from_key(AtomKey.from_token(ref))!=reader.namespace:raise AuthorityUnavailable('conditioned Source locator crossed namespace')
            state.source_roots.add(ref)
        state.selected_keys.add(key)
        state.allowed_history.add((token,revision))
        for version in _metadata_versions_v3(value):
            if NamespaceId.from_key(version.key)!=reader.namespace:raise AuthorityUnavailable('conditioned frozen version crossed namespace')
            if version.revision:state.allowed_history.add((version.key.token,version.revision))
        capture=getattr(task,'conditioned_wire_capture',None)
        if capture is not None:
            capture.finish_v3()
            for locator in capture.locators:
                state.source_roots.update(_source_tokens(locator))
                state.selected_keys.update(_graph_tokens(locator))
        return _freeze_value_v3({'key':token,'revision':revision,'valid':valid,'locator':value})
    domain,operation_kind,_,digest,bundle_digest,_=task.metadata
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    with runtime_storage_quantum_v3(reader.db)as meter:
        commit=_beta1_metadata_row_v3(reader,meter,'graph_bundle_operations',('digest','commit_seq'),
            'bot=? AND persona=? AND operation_id=?',(*reader.namespace.as_tuple,selected))
    if commit is None or commit[0]!=bundle_digest or type(commit[1])is not int or commit[1]<1:
        raise AuthorityUnavailable('conditioned producing original lacks actual positive shared W01 COMMIT metadata')
    if(value.get('namespace')!={'bot_id':reader.namespace.bot_id,'persona_id':reader.namespace.persona_id}
            or value.get('identity',{}).get('operation_id')!=selected
            or value.get('schema')!=domain+'.current-'+operation_kind+'.v1'):
        raise AuthorityUnavailable('conditioned producer locator does not bind its exact COMMIT identity/schema')
    provenance=value.get('provenance',{})
    state.source_roots.update(_source_tokens(provenance))
    frozen=provenance.get('conditioned_frozen_targets')
    if type(frozen)is dict:
        targets=frozen.get('targets',())
        if type(targets)not in(tuple,list)or len(targets)>16:
            raise AuthorityUnavailable('conditioned frozen metadata target tuple exceeds its exact bound')
        for target in targets:
            if type(target)is not dict or set(target)!={'child_id','operation_kind'}:
                raise AuthorityUnavailable('conditioned frozen locator must retain only fixed child identity fields')
            state.adoption_operations.add(target['child_id'])
    for version in (*_metadata_versions_v3(value.get('read_versions',())),*_metadata_versions_v3(provenance.get('conditioned_frozen_targets',{}))):
        if NamespaceId.from_key(version.key)!=reader.namespace:raise AuthorityUnavailable('conditioned producer read version crossed namespace')
        state.selected_keys.add(version.key)
        if version.revision:state.allowed_history.add((version.key.token,version.revision))
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    original=ProductionOriginalRefV1(domain+'.current-'+operation_kind,domain+'-current:'+digest[:48],digest)
    state.observed_originals[original.original_ref]=original
    return _freeze_value_v3({'operation_kind':operation_kind,'operation_id':selected,'original_digest':digest,'locator':value})


def create_current_conditioned_metadata_task_v3(reader,identity):
    from .current_beta1_source_read_v3 import create_current_beta1_metadata_task_v3
    state=require_conditioned_self_work_v3(reader)
    if identity not in state.selectors:raise AuthorityUnavailable('conditioned metadata task has no fixed selector')
    if identity not in state.tasks:
        state.tasks[identity]=(_ConditionedControlMetadataTaskV3(_ISSUER,reader,identity)if identity[0]in {'attempt','disposition'}
            else create_current_beta1_metadata_task_v3(reader,identity))
    return state.tasks[identity]


def conditioned_metadata_v3(db,namespace,identity):
    from .current_method_learning_read_v3 import _need_method_input
    from .dispatch_current_inventory_v3 import _detach_value_v3
    reader=_active(db)
    if reader is None or namespace!=reader.namespace:raise AuthorityUnavailable('conditioned metadata needs its actual own current Work')
    state=require_conditioned_self_work_v3(reader);state.selectors.add(identity)
    task=state.tasks.get(identity)
    if task is None or not task.complete:_need_method_input(reader,('conditioned_owner_metadata',identity))
    with runtime_storage_quantum_v3(db)as meter:task.require_header_v3(meter)
    return None if task.result is None else _detach_value_v3(task.result)


def conditioned_source_groups_v3(reader,roots):
    state=require_conditioned_self_work_v3(reader)
    if(reader.selected_envelope is None or reader.authority.purpose!='consolidation'
            or reader.selected_envelope.authority.purpose!='consolidation'
            or not reader.selected_envelope.authority.audience):
        raise AuthorityUnavailable('conditioned Source must retain its actual caller purpose and audiences')
    if tuple(sorted(set(roots)))!=tuple(sorted(state.source_roots)):
        raise AuthorityUnavailable('conditioned Source union differs from complete actual locator closure')
    from .life_prepared_source_metadata_v3 import life_prepared_source_groups_v3
    life_groups=tuple(group for facts in state.life_prepared_facts for group in life_prepared_source_groups_v3(facts))
    return(('consolidation',reader.selected_envelope.authority.audience,tuple(sorted(set(roots)))),*life_groups)


def require_conditioned_sources_v3(reader,roots):
    require_conditioned_owner_ready_v3(reader)
    from .current_beta1_source_read_v3 import qualify_current_beta1_source_groups_v3
    state=require_conditioned_self_work_v3(reader)
    state.source_permission=qualify_current_beta1_source_groups_v3(reader,roots)
    return state.source_permission


def register_conditioned_write_phase_v3(inputs,scope,current_owner):
    reader=inputs.owner;state=require_conditioned_self_work_v3(reader)
    if not reader.inputs_sealed:return
    if(reader.operation_kind==CONDITIONED_SELF_READ_KIND_V4 or not reader.read_finished or not reader.business_started
            or scope.operation!='write' or scope is reader.fence.scope or inputs.plan!=reader.selected_plan
            or current_owner!=reader.owner_binding or state.source_permission is None):
        raise AuthorityUnavailable('conditioned WRITE requires same sealed Work/current Owner/Source capsule')
    _WRITES[reader]=(inputs,scope,current_owner,_identity(reader),reader.selected_plan)


def require_conditioned_write_phase_v3(reader):
    from .current_method_learning_read_v3 import _method_active,_INPUTS
    state=require_conditioned_self_work_v3(reader);saved=_WRITES.get(reader)
    if saved is None:raise AuthorityUnavailable('conditioned body has no actual fresh WRITE phase')
    inputs,scope,owner,identity,plan=saved
    if(identity!=_identity(reader)or plan!=reader.selected_plan or _method_active(reader.db)is not reader
            or _INPUTS.get(inputs)!=(reader,inputs.plan,inputs.envelope,inputs.read_scope,inputs.graph_stamp,inputs.owner_rights)
            or scope.operation!='write'or owner!=reader.owner_binding or not reader.inputs_sealed or not reader.business_started):
        raise AuthorityUnavailable('conditioned WRITE lost its actual same-operation Source input capsule')
    return saved


def require_conditioned_body_v3(reader,table,key):
    require_conditioned_owner_ready_v3(reader)
    state=require_conditioned_self_work_v3(reader)
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    if require_beta1_source_control_point_v3(reader,(table,('revision','value','valid'),('token','bot','persona'),tuple(key))):return
    if table=='runtime_budget_grants'and key[0]==reader.parent_budget_lease_ref:return
    cap=state.source_permission
    if cap is None:raise AuthorityUnavailable('conditioned protected body requires complete current all-parent Source EOF')
    cap.require_for_v3(reader)
    from .current_conditioned_personal_choice_v3 import require_personal_choice_c1_body_v3
    if require_personal_choice_c1_body_v3(reader,table,key):return
    if table in {'graph_atoms','graph_history'}:
        atom=AtomKey.from_token(key[0])
        if table=='graph_history':selected=(atom.token,key[1])in state.allowed_history
        else:selected=atom in state.selected_keys or atom in reader.selected_plan.exact_keys or atom.token in cap.source_refs
        if not selected:raise AuthorityUnavailable('conditioned body escaped its exact source-qualified graph selection')
    elif table=='graph_domain_production_originals_v1':
        if key[-1]not in state.adoption_operations:raise AuthorityUnavailable('conditioned original escaped actual producer selection')
    elif(table,tuple(key))not in state.signed_originals:
        raise AuthorityUnavailable('conditioned attachment escaped actual fixed original locator')


def require_conditioned_point_v3(reader,request):
    state=require_conditioned_self_work_v3(reader)
    table,columns,key_columns,key=request
    if len(key)!=len(key_columns):raise AuthorityUnavailable('conditioned attachment requires its full registered point key')
    from .current_conditioned_personal_choice_v3 import require_personal_choice_c1_point_v3
    if require_personal_choice_c1_point_v3(reader,request):return
    if table in {'graph_atoms','graph_history'}:
        atom=AtomKey.from_token(key[0])
        if NamespaceId.from_key(atom)!=reader.namespace:raise AuthorityUnavailable('conditioned point crossed namespace')
        if table=='graph_history'and(atom.token,key[1])not in state.allowed_history:
            raise AuthorityUnavailable('conditioned historical point has no actual frozen locator')
    elif table!='runtime_budget_grants'and tuple(key[:2])!=reader.namespace.as_tuple:
        raise AuthorityUnavailable('conditioned original point crossed namespace')
    if table=='graph_bundle_operations':
        if key_columns!=('bot','persona','operation_id')or key[-1]not in state.adoption_operations:
            raise AuthorityUnavailable('conditioned receipt has no actual selected producing COMMIT')
        if not set(columns)<={'digest','receipt_json','commit_seq','activity_id','effect_id'}:
            raise AuthorityUnavailable('conditioned receipt projection is not registered')
        return
    require_conditioned_body_v3(reader,table,key)


def conditioned_history_v3(db,token,revision):
    from .current_method_learning_read_v3 import read_bound_method_learning_attachment_v3
    reader=_active(db)
    if reader is None:
        from .current_d07_simulation_source_read_v3 import read_current_d07_simulation_history_v3
        return read_current_d07_simulation_history_v3(db,token,revision)
    state=require_conditioned_self_work_v3(reader)
    if(token,revision)not in state.allowed_history:raise AuthorityUnavailable('conditioned history is outside frozen request/metadata closure')
    handled,row=read_bound_method_learning_attachment_v3(db,table='graph_history',columns=('event_id','value','valid'),
        key_columns=('token','revision'),key=(token,revision))
    if not handled:raise AuthorityUnavailable('conditioned historical lookup requires actual bound Source Work')
    return row


def _commit_sequence(db,reader,operation_id):
    from .current_method_learning_read_v3 import read_bound_method_learning_attachment_v3
    state=require_conditioned_self_work_v3(reader)
    if operation_id not in state.adoption_operations:raise AuthorityUnavailable('conditioned sequence is not from selected actual COMMIT')
    handled,row=read_bound_method_learning_attachment_v3(db,table='graph_bundle_operations',columns=('commit_seq',),
        key_columns=('bot','persona','operation_id'),key=(*reader.namespace.as_tuple,operation_id))
    if not handled or row is None or type(row[0])is not int or row[0]<1:raise AuthorityUnavailable('conditioned original has no positive actual commit sequence')
    return row[0]


def require_prediction_original_sequence_v3(db,read,prediction,prediction_original,outcome_original):
    reader=_active(db)
    if reader is None:raise AuthorityUnavailable('prediction sequence needs actual own current Source Work')
    first=prediction_original['receipt'].operation_id
    if outcome_original.original_ref!=prediction.resolution_target_ref:
        raise AuthorityUnavailable('prediction sequence changed its exact frozen outcome original')
    if prediction.target_observable.startswith('artifact_'):
        from .artifact_task_observer_v1 import read_current_artifact_task_milestone_v2
        actual=read_current_artifact_task_milestone_v2(db,namespace=prediction.namespace,
            original_ref=outcome_original.original_ref,issuer=reader.graph._GraphCoordinator__d11_issuer)
        if actual.digest!=outcome_original.original_digest:raise AuthorityUnavailable('artifact outcome digest changed')
        second=actual.registration_operation_id
    else:
        atom=read.head(db,prediction.resolution_target_ref,required=True)
        history=conditioned_history_v3(db,atom.key.token,atom.revision)
        if history is None or history[2]!=1:raise AuthorityUnavailable('actual observed result has no producing COMMIT member')
        second=history[0]
    require_conditioned_self_work_v3(reader).adoption_operations.update((first,second))
    if _commit_sequence(db,reader,first)>=_commit_sequence(db,reader,second):
        raise AuthorityUnavailable('prediction was not durably committed before its actual outcome')


def release_conditioned_self_work_v3(reader):
    from .current_conditioned_personal_choice_v3 import release_personal_choice_reader_v3
    release_personal_choice_reader_v3(reader)
    _WRITES.pop(reader,None)
    _CONDITIONED_CHILD_TARGETS_V3.pop(reader,None)
    _CONDITIONED_CHILD_SELECTORS_V3.pop(reader,None)
    _CONDITIONED_ACTIVE_CHILD_ISSUES_V3.pop(reader,None)
    state=_STATES.pop(reader,None)
    if state is not None:
        for task in state.tasks.values():_CONDITIONED_ATTEMPT_METADATA_V3.pop(task,None)
        state.tasks.clear();state.selectors.clear();state.selected_keys.clear();state.allowed_history.clear();state.source_caps.clear()
    capsule=_CONDITIONED_PENDING_READERS_V3.pop(reader,None)
    if capsule is not None:_PENDING_CONDITIONED_OWNER_V3.pop(capsule,None)
    _CONDITIONED_CURRENT_READ_SELF_V3.pop(reader,None)
    if reader.work.state is reader and reader.session_proof is None:
        locator=reader.conditioned_cause_locator
        _CONDITIONED_LOCATOR_READERS_V3.pop(locator,None);_CONDITIONED_CHILD_LOCATORS_V3.pop(locator,None)
        _CONDITIONED_SCOPE_TRANSITIONS_V3.pop(locator,None)
        from .current_conditioned_personal_choice_v3 import release_personal_choice_locator_v3
        release_personal_choice_locator_v3(locator)


class InstalledConditionedSelfReadersV1:
    def __init__(self,issuer,graph,scope,owner_guard,base,personal):
        if issuer is not _ISSUER:raise AuthorityUnavailable('conditioned readers require actual installed private factory')
        self.graph,self.scope,self.owner_guard,self.base,self.personal=graph,scope,owner_guard,base,personal
        self.issuer,self.role_clock_reader=base.issuer,base.role_clock_reader
        _INSTALLED[self]=(graph,scope,owner_guard,base,personal,graph._GraphCoordinator__d04_installed_joint_assembly)
    def read_self_model_v3(self,db,frame,request):return self.base.read_self_model_v3(db,frame,request)


def install_conditioned_self_readers_v1(graph,*,scope,owner_guard,operation_kind,owner_binding=None,
        foreground_issuance=None,owner_task_issuance=None):
    from ..graph_coordinator import GraphCoordinator
    from .d01_production_operations_v1 import InstalledD01ProductionReadersV1
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    if(type(graph)is not GraphCoordinator or type(owner_guard)is not OwnerAuthorizationGuardV1
            or owner_guard.namespace!=scope.namespace or operation_kind not in conditioned_operation_types_v3()):
        raise AuthorityUnavailable('conditioned readers need exact installed Graph and current own scope')
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None:raise AuthorityUnavailable('conditioned readers need actual installed production assembly')
    base=InstalledD01ProductionReadersV1(issuer=graph._GraphCoordinator__d11_issuer,owner_guard=owner_guard,
        role_clock_reader=graph._GraphCoordinator__d04_semantic_mapping_reader)
    personal=None
    if operation_kind=='select_current_conditioned_personal_step_v1':
        from .d08_personal_candidate_v1 import install_personal_candidate_readers_v1
        personal=install_personal_candidate_readers_v1(graph=graph,
            bootstrap=graph._GraphCoordinator__domain_production_runtime_v1._bootstrap,bundle=assembly.admin_bundle)
    return InstalledConditionedSelfReadersV1(_ISSUER,graph,scope,owner_guard,base,personal)


def require_conditioned_stage_readers_v3(db,frame,readers,kind,request):
    reader=_active(db)
    if(reader is None or reader.operation_kind!=kind or reader.request!=request
            or type(request)is not conditioned_operation_types_v3()[kind]
            or type(readers)is not InstalledConditionedSelfReadersV1 or readers is not reader.installed_readers
            or _INSTALLED.get(readers)!=(reader.graph,readers.scope,readers.owner_guard,readers.base,readers.personal,
                reader.graph._GraphCoordinator__d04_installed_joint_assembly)
            or frame.owner_guard!=reader.material_owner_guard or frame.envelope.identity.phase!=kind):
        raise AuthorityUnavailable('conditioned stage has no exact actual installed own current reader')
    require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
    if kind!=CONDITIONED_SELF_READ_KIND_V4:require_conditioned_write_phase_v3(reader)
    return reader


def require_conditioned_output_plan_v3(db,frame,readers,operation_kind,request):
    from .domain_production_contracts_v1 import CurrentOperationFrameV1
    reader=_active(db)
    if(reader is None or reader.operation_kind!=operation_kind or reader.request!=request
            or operation_kind not in CONDITIONED_OPERATION_DOMAINS_V1
            or reader.installed_readers is not readers or type(readers)is not InstalledConditionedSelfReadersV1
            or readers.scope is not reader.fence.scope or reader.fence.scope.operation!='read'
            or reader.read_finished or reader.inputs_sealed or reader.business_started or reader.frame_fields is None
            or type(frame)is not CurrentOperationFrameV1 or frame!=CurrentOperationFrameV1(*reader.frame_fields)
            or frame.owner_guard!=reader.material_owner_guard
            or frame.envelope.identity.operation_id!=reader.operation_id
            or frame.envelope.identity.phase!=operation_kind):
        raise AuthorityUnavailable('conditioned output plan requires exact own current Source READ materialization')
    require_conditioned_owner_ready_v3(reader)
    require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
    return reader


def require_conditioned_output_requalification_v3(reader):
    state=require_conditioned_owner_ready_v3(reader)
    previous=state.output_previous_plan
    if(state.output_phase!='requalifying'or state.output_keys is None or previous is None
            or reader.read_finished or reader.inputs_sealed or reader.business_started
            or reader.fence.scope.operation!='read'or state.prepared_plan!=reader.selected_plan
            or not set(previous.exact_keys)<=set(reader.selected_plan.exact_keys)
            or not set(previous.source_roots)<=set(reader.selected_plan.source_roots)
            or not set(state.output_keys)<=set(reader.selected_plan.exact_keys)):
        raise AuthorityUnavailable('conditioned Source renewal is outside its private output metadata fixed point')
    return state


def augment_current_conditioned_output_plan_v3(reader):
    from .domain_production_contracts_v1 import CurrentOperationFrameV1
    from .conditioned_self_operations_v1 import plan_current_conditioned_output_keys_v3,OPERATIONS
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    state=require_conditioned_owner_ready_v3(reader)
    if(reader.operation_kind not in OPERATIONS or reader.read_finished or reader.inputs_sealed
            or reader.business_started or reader.frame_fields is None):
        raise AuthorityUnavailable('conditioned output metadata must finish inside the original unsealed Source READ')
    if state.output_phase=='complete':return False
    if state.output_phase=='unplanned':
        frame=CurrentOperationFrameV1(*reader.frame_fields)
        keys=plan_current_conditioned_output_keys_v3(reader.db,frame=frame,
            operation_kind=reader.operation_kind,request=reader.request,readers=reader.installed_readers)
        if(type(keys)is not tuple or len(keys)>frame.limits.max_writes or len(set(keys))!=len(keys)
                or any(type(key)is not AtomKey or NamespaceId.from_key(key)!=reader.namespace for key in keys)):
            raise AuthorityUnavailable('conditioned pure output recipe escaped its actual namespace/output bounds')
        state.output_keys=keys;state.output_previous_plan=reader.selected_plan
        state.output_previous_groups=state.source_permission.groups;state.output_phase='metadata'
    if state.output_phase=='metadata':
        for key in state.output_keys:
            if key in state.output_previous_plan.exact_keys:continue
            meta=conditioned_metadata_v3(reader.db,reader.namespace,('head',key.token))
            if meta is None:continue
            history=conditioned_metadata_v3(reader.db,reader.namespace,('history',(key.token,meta['revision'])))
            if history is None:raise AuthorityUnavailable('conditioned positive output has no actual producing COMMIT locator')
            producer_id=state.tasks[('history',(key.token,meta['revision']))].metadata[2]
            if producer_id!=reader.operation_id:
                raise AuthorityUnavailable('conditioned positive output belongs to another business operation')
            producer=conditioned_metadata_v3(reader.db,reader.namespace,('producer',producer_id))
            if producer is None or producer['operation_kind']!=reader.operation_kind:
                raise AuthorityUnavailable('conditioned positive output is not the exact command producer replay')
            state.output_replay_operations.add(producer_id)
        plan=read_plan_current_conditioned_self_v1(reader.db,reader.namespace,reader.activity_id,
            reader.operation_kind,reader.request,reader.installed_readers)
        if len(plan.exact_keys)>CurrentOperationFrameV1(*reader.frame_fields).limits.max_graph_heads:
            raise MissingProductionOriginalV1('bounded_conditioned_output_metadata_closure')
        reader.selected_plan=plan;state.output_phase='requalifying'
        if conditioned_source_groups_v3(reader,plan.source_roots)!=state.output_previous_groups:
            from .current_beta1_source_read_v3 import reset_current_beta1_source_permission_v3
            reset_current_beta1_source_permission_v3(reader)
            state.source_permission=None
    if state.output_phase=='requalifying':
        require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
        state.output_phase='checking'
        return True
    if state.output_phase!='checking':raise AuthorityUnavailable('conditioned output metadata phase differs')
    frame=CurrentOperationFrameV1(*reader.frame_fields)
    keys=plan_current_conditioned_output_keys_v3(reader.db,frame=frame,operation_kind=reader.operation_kind,
        request=reader.request,readers=reader.installed_readers)
    if keys!=state.output_keys:raise AuthorityUnavailable('conditioned output recipe changed after exact metadata and all-Source renewal')
    if state.output_replay_operations:
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        from ..domains.d01.production_operations_v1 import plain_v1
        for operation_id in state.output_replay_operations:
            original=read_adopted_domain_operation_v1(reader.db,reader.namespace,operation_id)
            if(original is None or original['receipt'].operation_id!=reader.operation_id
                    or original['operation_kind']!=reader.operation_kind
                    or original['payload']['request']!=plain_v1(reader.request)
                    or any(key not in {v.key for v in original['receipt'].write_versions}
                        for key in state.output_keys if key not in state.output_previous_plan.exact_keys
                            and reader.heads.get(key.token,(0,))[0]>0)):
                raise AuthorityUnavailable('conditioned positive output lost its exact typed original/receipt write members')
    state.output_phase='complete'
    return False


_BASE_SELF_TYPES_V3=('d01.persona_activation.v1','d01.persona_plan.v1')
_SELF_VIEW_TYPES_V3=(*_BASE_SELF_TYPES_V3,'d01.conditioned_capability_revision.v1','d01.conditioned_strategy_revision.v1',
    'd01.condition_predicate.v1','d01.calibration_policy.v1','d01.conditioned_self_review.v1','d07.prediction_record.v1',
    'd07.prediction_resolution.v1','d08.commitment.v1','d02.body_state.v1')
_READ_FAMILIES_V3={
    'register_calibration_policy_v1':_BASE_SELF_TYPES_V3,
    'register_condition_predicate_v1':(*_BASE_SELF_TYPES_V3,'d01.calibration_policy.v1'),
    'register_simulation_forecast_plan_v1':(*_BASE_SELF_TYPES_V3,'d07.current_interpretation.v1'),
    'register_current_prediction_v1':(*_BASE_SELF_TYPES_V3,'d07.current_interpretation.v1'),
    'record_current_simulation_v1':_BASE_SELF_TYPES_V3,
    'resolve_current_prediction_v1':_BASE_SELF_TYPES_V3,
    'review_current_conditioned_self_v1':_SELF_VIEW_TYPES_V3,
    'adopt_current_conditioned_self_v1':_SELF_VIEW_TYPES_V3,
    'rollback_current_conditioned_strategy_v1':(*_SELF_VIEW_TYPES_V3,'d07.current_interpretation.v1'),
    'match_current_conditioned_strategy_v1':(*_BASE_SELF_TYPES_V3,'d07.current_interpretation.v1'),
    'select_current_conditioned_personal_step_v1':(*_BASE_SELF_TYPES_V3,'d07.current_interpretation.v1'),
    'project_current_conditioned_life_strategy_v1':(*_BASE_SELF_TYPES_V3,'d07.current_interpretation.v1'),
    CONDITIONED_SELF_READ_KIND_V4:_SELF_VIEW_TYPES_V3}
_READ_FAMILIES_V3['register_simulation_forecast_plan_v1']+=('d07.simulation_branch.v1',)
_READ_FAMILIES_V3['register_current_prediction_v1']+=('d07.simulation_branch.v1',)
_READ_FAMILIES_V3['record_current_simulation_v1']+=('d07.simulation_branch.v1',)


def read_plan_current_conditioned_self_v1(db,namespace,activity_id,operation_kind,request,installed_readers):
    from ..domains.d01.production_operations_v1 import plain_v1
    from .d01_production_operations_v1 import production_read_plan_v1,MissingProductionOriginalV1
    reader=_active(db)
    if(reader is None or reader.namespace!=namespace or reader.operation_kind!=operation_kind
            or reader.request!=request or reader.installed_readers is not installed_readers
            or not reader.graph_eof):
        raise AuthorityUnavailable('conditioned plan requires its actual completed header census and own installed reader')
    state=require_conditioned_owner_ready_v3(reader)
    from .current_conditioned_personal_choice_v3 import personal_choice_locator_for_reader_v3,seed_personal_choice_plan_v3
    personal_choice=personal_choice_locator_for_reader_v3(reader)
    types=_READ_FAMILIES_V3[operation_kind]
    if operation_kind==CONDITIONED_SELF_READ_KIND_V4:
        types=tuple(name for name in types if name not in {'d01.conditioned_capability_revision.v1',
            'd01.conditioned_strategy_revision.v1','d01.condition_predicate.v1','d01.calibration_policy.v1','d01.conditioned_self_review.v1'})
    state.source_roots.update(_source_tokens(plain_v1(request)))
    if operation_kind=='select_current_conditioned_personal_step_v1':
        state.adoption_operations.add(request.prepared_candidates_operation_id)
        state.required_domain_producers.add(request.prepared_candidates_operation_id)
        producer=conditioned_metadata_v3(db,namespace,('producer',request.prepared_candidates_operation_id))
        if producer is None:raise MissingProductionOriginalV1('actual_conditioned_personal_prepared_producer')
        types=seed_personal_choice_plan_v3(reader,types)
    if reader.session_proof is None and type(reader.conditioned_cause_locator)is _ConditionedChildLocatorReaderV3:
        prepared=reader.conditioned_cause_locator.prepared_targets
        prepared.require_for_v3(reader.graph,prepared.bootstrap,prepared.bundle)
        state.source_roots.update(prepared.target_census['source_roots'])
        for version in _metadata_versions_v3(prepared.target_census['read_versions']):
            state.selected_keys.add(version.key)
            if version.revision:state.allowed_history.add((version.key.token,version.revision))
    if reader.session_proof is None and personal_choice is None:
        disposition=prepare_current_conditioned_disposition_metadata_v3(reader)
        if disposition is not None:
            state.adoption_operations.add(disposition['first_child_operation_id'])
            state.required_domain_producers.add(disposition['first_child_operation_id'])
        if type(reader.conditioned_cause_locator)is _ConditionedChildLocatorReaderV3:
            state.adoption_operations.update(prepared.child_ids)
        for operation_id in tuple(state.adoption_operations):
            producer=conditioned_metadata_v3(db,namespace,('producer',operation_id))
            if operation_id in state.required_domain_producers and producer is None:
                raise MissingProductionOriginalV1('conditioned_committed_producer_original')
    general_plan=None
    if operation_kind in {'adopt_current_conditioned_self_v1','rollback_current_conditioned_strategy_v1'}:
        from .d01_general_growth_v1 import read_plan_adopt_current_general_growth_v1
        general_plan=read_plan_adopt_current_general_growth_v1(db,namespace=namespace,request=request.general_request,
            issuer=installed_readers.issuer)
        state.source_roots.update(general_plan.source_roots);state.selected_keys.update(general_plan.exact_keys)
        types=tuple(dict.fromkeys((*types,*general_plan.fixed_type_ids)))
    if operation_kind=='register_simulation_forecast_plan_v1':
        if conditioned_metadata_v3(db,namespace,('simulation_request',request.value.simulation_request_ref))is None:
            raise MissingProductionOriginalV1('actual_registered_simulation_request')
    selected={owner_grant_key(*namespace.as_tuple),*_graph_tokens(plain_v1(request)),*state.selected_keys,*(state.output_keys or())}
    for token,(revision,valid,*_)in reader.heads.items():
        key=AtomKey.from_token(token)
        if key.type_name in types and valid:selected.add(key)
    from .domain_production_contracts_v1 import ProductionOperationLimitsV1
    if len(selected)>ProductionOperationLimitsV1().max_graph_heads:
        raise MissingProductionOriginalV1('bounded_complete_conditioned_metadata_selection')
    pending=sorted(selected,key=lambda key:key.token);seen=set()
    while pending:
        key=pending.pop(0)
        if key in seen:continue
        seen.add(key)
        if NamespaceId.from_key(key)!=namespace:raise AuthorityUnavailable('conditioned request locator crossed actual namespace')
        if key.type_name=='memory.source':state.source_roots.add(key.token)
        if key==owner_grant_key(*namespace.as_tuple)or key.type_name in {'memory.source','memory.access','d06.source_correction_head.v1'}:
            state.selected_keys.add(key);continue
        meta=conditioned_metadata_v3(db,namespace,('head',key.token))
        state.selected_keys.add(key)
        if meta is None:continue
        locator=meta['locator']
        terminal=locator.get('terminal_provenance')
        if type(terminal)is dict and type(terminal.get('binding'))is dict:
            binding=terminal['binding']
            if binding.get('namespace')!={'bot_id':namespace.bot_id,'persona_id':namespace.persona_id}:
                raise AuthorityUnavailable('Life prepared metadata reference crossed actual namespace')
            conditioned_metadata_v3(db,namespace,('life_prepared',binding['prepared_original_ref']))
        history=conditioned_metadata_v3(db,namespace,('history',(key.token,meta['revision'])))
        if history is None:raise AuthorityUnavailable('conditioned current graph value has no actual adopted history locator')
        for operation_id in tuple(state.adoption_operations):
            producer=conditioned_metadata_v3(db,namespace,('producer',operation_id))
            if operation_id in state.required_domain_producers and producer is None:
                raise AuthorityUnavailable('conditioned actual graph producer original is absent')
        for child in (*_graph_tokens(locator),*state.selected_keys):
            if child not in seen and child not in pending:pending.append(child)
        if len(seen)+len(pending)>1024:raise MissingProductionOriginalV1('bounded_complete_conditioned_locator_closure')
    for operation_id in tuple(state.adoption_operations):
        conditioned_metadata_v3(db,namespace,('producer',operation_id))
    for token,revision in sorted(state.allowed_history):
        historical=conditioned_metadata_v3(db,namespace,('history',(token,revision)))
        if historical is None:raise AuthorityUnavailable('conditioned frozen historical locator is unavailable')
    roots=tuple(sorted(state.source_roots))
    reader.observed_originals=tuple(state.observed_originals.values())
    originals=tuple(state.observed_originals)if general_plan is None else tuple(dict.fromkeys((*state.observed_originals,*general_plan.required_original_refs)))
    result=production_read_plan_v1(types,tuple(sorted(state.selected_keys,key=lambda key:key.token)),roots,originals)
    if state.prepared_plan is not None and result!=state.prepared_plan:
        if(state.output_phase!='metadata'or state.output_previous_plan!=state.prepared_plan
                or not set(state.prepared_plan.exact_keys)<=set(result.exact_keys)
                or not set(state.prepared_plan.source_roots)<=set(result.source_roots)
                or not set(state.output_keys or())<=set(result.exact_keys)):
            raise AuthorityUnavailable('conditioned metadata plan changed outside its private bounded output phase')
    state.prepared_plan=result
    return result


def require_conditioned_prediction_before_outcome_v3(db,read,prediction):
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    reader=_active(db)
    if reader is None:raise AuthorityUnavailable('frozen prediction requires actual own Source Work')
    if prediction.target_observable.startswith('artifact_'):
        from .artifact_task_observer_v1 import read_current_artifact_task_milestone_v2
        try:actual=read_current_artifact_task_milestone_v2(db,namespace=prediction.namespace,
            original_ref=prediction.resolution_target_ref,issuer=reader.graph._GraphCoordinator__d11_issuer)
        except MissingProductionOriginalV1:return
        if actual is not None:raise ValueError('prediction cannot be registered after its actual artifact outcome')
    else:
        outcome=read.head(db,prediction.resolution_target_ref)
        if outcome.revision:raise ValueError('prediction cannot be registered after its actual Action/Life outcome')


def require_conditioned_forecast_preregistration_v3(db,read,plan):
    reader=_active(db)
    if reader is None:raise AuthorityUnavailable('forecast declaration requires own current Owner Source Work')
    from .conditioned_self_operations_v1 import OPERATIONS,conditioned_key_v1
    from ..domains.d07.prediction_v1 import FORECAST_PLAN_TYPE
    if reader.operation_kind!='register_simulation_forecast_plan_v1' or reader.request.value is not plan and reader.request.value.plan_id!=plan.plan_id:
        raise AuthorityUnavailable('forecast declaration changed actual Owner registered request')
    for atom in read.complete_inventory(db,'d07.simulation_branch.v1'):
        if atom.valid and atom.key.owner.subject==plan.simulation_activity_id:
            raise ValueError('declared forecast must precede actual simulation branch adoption')


def require_forecast_plan_before_execution_v3(db,read,plan_ref,execution_original):
    import json
    from .d07_execution_v1 import d07_execution_ids_v1,read_prepared_d07_execution_v1
    from ..model_broker.d07_cognition_v1 import thaw_d07_cognition_request_v1
    reader=_active(db)
    if reader is None:raise AuthorityUnavailable('forecast ordering requires own actual Source Work')
    atom=read.head(db,plan_ref,required=True)
    history=conditioned_history_v3(db,atom.key.token,atom.revision)
    if history is None or history[2]!=1:raise AuthorityUnavailable('forecast plan has no actual committed member')
    first=history[0];second=execution_original['receipt'].operation_id
    state=require_conditioned_self_work_v3(reader);state.adoption_operations.update((first,second))
    if _commit_sequence(db,reader,first)>=_commit_sequence(db,reader,second):
        raise ValueError('forecast plan was not committed before actual simulation execution adoption')
    execution=execution_original['payload']['provenance']['execution']
    job=d07_execution_ids_v1(reader.namespace,execution['operation_id'],'simulation')['job']
    prepared=read_prepared_d07_execution_v1(db,reader.graph._GraphCoordinator__d11_issuer,reader.namespace,job)
    if(prepared is None or prepared.work_kind!='simulation'or prepared.execution_id!=execution['execution_id']
            or prepared.stage_input_digest!=execution['input_digest']or execution['parent_budget_ref']!=read.frame.envelope.parent_budget_lease_ref):
        raise AuthorityUnavailable('forecast has no exact signed actual simulation preparation/execution/Root')
    plan_head=GraphVersion(atom.key,atom.revision)
    versions=tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision)for row in prepared.read_rows)
    if plan_head not in versions:raise AuthorityUnavailable('actual simulation preparation omitted its declared forecast Plan head')
    frozen=thaw_d07_cognition_request_v1(json.loads(prepared.frozen_json))
    item=frozen.input
    if item.work_kind!='simulation'or item.target_original_kind!='simulation_forecast_context_v1':
        raise AuthorityUnavailable('actual model input did not contain its typed forecast assumption context')
    context=json.loads(item.target_original_json)
    if(context['schema']!='d07.simulation-forecast-context.v1'or context['plan_ref']!=plan_ref
            or context['plan_revision']!=atom.revision or context['plan_digest']!=canonical_digest(atom.value)
            or item.target_original_digest!=canonical_digest(context)):
        raise AuthorityUnavailable('actual model input changed its exact declared Plan context commitment')


def require_conditioned_rollback_predicate_v3(db,read,predicate_ref,scope_refs):
    from .conditioned_self_operations_v1 import _typed,_condition_question_locator_v1,read_current_conditioned_match_v1,MatchCurrentConditionedStrategyRequestV1
    from ..domains.d01.conditioned_self_v1 import ConditionPredicateV1
    _,predicate=_typed(db,read,predicate_ref,ConditionPredicateV1)
    if not set(scope_refs)<=set(predicate.scope_refs):raise ValueError('rollback predicate does not cover rejected actual strategy scope')
    from ..domains.d07 import decode_method_condition_question_v1
    values={}
    for atom in read.complete_inventory(db,'d07.current_interpretation.v1'):
        if not atom.valid or atom.value.get('current')is not True:continue
        question=decode_method_condition_question_v1(atom.value.get('question_key'))
        if question is None or question['goal_ref']not in scope_refs:continue
        if(question['condition_id']in dict(predicate.conditions)and atom.value.get('stance')=='support'
                and atom.value.get('evidence_status')=='supported'and not atom.value.get('meaningful_unknowns')
                and atom.value.get('proposition')in {'true','false'}):
            identity=(question['goal_ref'],question['condition_id'])
            if identity in values:raise ValueError('rollback predicate has conflicting actual current condition heads')
            values[identity]=atom.value['proposition']=='true'
    if not any(all(values.get((scope,condition))is expected for condition,expected in predicate.conditions)for scope in scope_refs):
        raise ValueError('rollback predicate is not supported by actual complete current conditions')


def require_conditioned_self_view_observer_v3(db,*,work,frame,request,readers):
    reader=_active(db)
    if(reader is None or reader.work is not work or reader.operation_kind!=CONDITIONED_SELF_READ_KIND_V4
            or reader.request!=request or reader.installed_readers is not readers or frame.owner_guard!=reader.material_owner_guard
            or frame.envelope.identity.operation_id!=reader.operation_id or reader.read_finished):
        raise AuthorityUnavailable('SelfView requires its actual independent own READ invocation')
    return require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)


def require_conditioned_life_projection_consumer_v3(db,read,issuer):
    from .current_habit_source_read_v3 import require_current_habit_source_frame_v3
    from .current_method_learning_read_v3 import _method_active
    reader=_method_active(db)
    if reader is None:raise AuthorityUnavailable('conditioned Life consumer needs actual B3 Source Work')
    require_current_habit_source_frame_v3(db,frame=read.frame,operation_kind=reader.operation_kind,request=reader.request)
    if(issuer is not reader.graph._GraphCoordinator__d11_issuer
            or read.frame.envelope.identity.operation_id!=reader.operation_id):
        raise AuthorityUnavailable('conditioned Life consumer needs its actual current B3 Work/frame/issuer')
    return install_conditioned_self_readers_v1(reader.graph,scope=reader.fence.scope,
        owner_guard=read.frame.owner_guard,operation_kind='project_current_conditioned_life_strategy_v1')


def conditioned_recovery_original_v3(db,namespace,producer_operation_id,*,work,issuer):
    from .semantic_recovery_source_v3 import read_committed_semantic_producer_v3
    return read_committed_semantic_producer_v3(work,db=db,namespace=namespace,
        producer_operation_id=producer_operation_id,issuer=issuer)


def require_conditioned_recovery_observer_v3(db,*,work,frame,producer_operation_id,issuer):
    from .semantic_recovery_source_v3 import require_current_semantic_recovery_work_v3
    reader=require_current_semantic_recovery_work_v3(work,db=db,namespace=frame.envelope.authority.namespace,producer_operation_id=producer_operation_id)
    if(reader.db is not db or issuer is not reader.graph._GraphCoordinator__d11_issuer
            or reader.read_scope is not reader.fence.scope or reader.read_scope.operation!='read'
            or frame.envelope.identity.operation_id!=reader.read_scope.operation_id):
        raise AuthorityUnavailable('conditioned recovery requires actual fixed current Source READ observer')
    return reader




def conditioned_metadata_wire_capture_v3(task):
    if task.identity[0]not in {'head','history'}:return None
    token=task.identity[1]if task.identity[0]=='head'else task.identity[1][0]
    if AtomKey.from_token(token).type_name!='d01.persona_plan.v1':return None
    capture=_ConditionedClaimCaptureV3(task);task.conditioned_wire_capture=capture
    return capture


_SELF_VIEW_RESULTS_V4=WeakKeyDictionary()
_SELF_VIEW_CLOCKS_V4=WeakKeyDictionary()
_SELF_VIEW_DOMAINS_V4=frozenset({'d01','d02','d06','d07','d08','d11'})


def prepare_current_self_view_source_read_v4(graph,authority,lease,*,request):
    import time
    from uuid import uuid4
    from .conditioned_self_operations_v1 import ProjectCurrentSelfViewRequestV4
    from .first_ingress_v2 import trusted_upper
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from ..runtime_storage_v3 import(begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
        finish_runtime_storage_operation_v3)
    from .current_method_learning_read_v3 import begin_current_method_learning_read_v3
    from .current_beta1_source_read_v3 import register_current_beta1_source_work_v3
    require_graph_storage_work_admission_v3(graph)
    if type(request)is not ProjectCurrentSelfViewRequestV4:raise TypeError('SelfView requires its exact block selector')
    if authority.purpose!='consolidation'or authority.audience!=('owner',):
        raise AuthorityUnavailable('SelfView requires its exact current Owner consolidation audience')
    graph._authorize(lease,authority,_SELF_VIEW_DOMAINS_V4,owner_read=True)
    owner=graph._GraphCoordinator__owner_leases.get(lease)
    session=graph._GraphCoordinator__owner_session_proofs.get(lease)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if owner is None or session is None or assembly is None or 'workbench.read'not in owner.capabilities:
        raise AuthorityUnavailable('SelfView requires its installed current Owner READ capability and session')
    if assembly.admin_bundle.installation_policy.namespace!=authority.namespace:
        raise AuthorityUnavailable('SelfView crossed actual installation namespace')
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    operation_id='self-view-read:'+uuid4().hex
    operation=begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,operation_id,now+60.0)
    fence=None
    try:
        with bind_runtime_storage_operation_v3(operation,graph._GraphCoordinator__store._db):
            fence=graph._begin_read_fence_v3(authority,operation_id=operation_id,owner_session_proof=session)
            reader=begin_current_method_learning_read_v3(graph,operation,fence,
                runtime=graph._GraphCoordinator__domain_production_runtime_v1,authority=authority,lease=lease,
                operation_kind=CONDITIONED_SELF_READ_KIND_V4,request=request,operation_id=operation_id,activity_id=operation_id,
                audience_ref='owner',parent_budget_lease_ref=assembly.admin_bundle.installation_policy.root_grant.lease_id,
                request_digest=canonical_digest((CONDITIONED_SELF_READ_KIND_V4,request)),owner_binding=owner,owner_guard=None,
                session_proof=session,initial_now_utc=now)
            reader.initial_monotonic_deadline=time.monotonic()+60.0
            reader.background_followup=reader.background_host_lifecycle=reader.background_offline=None
        work=create_graph_storage_work_v3(graph,kind=CONDITIONED_SELF_WORK_KIND_V3,operation_id=operation_id,
            selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=reader,operation=operation)
        work._require_invocation(graph,initial=True);reader.work=work
        register_current_beta1_source_work_v3(reader,work)
        _SELF_VIEW_CLOCKS_V4[reader]=(now,time.monotonic())
        work.phase='conditioned_self_owner_eof'
        return work
    except BaseException:
        try:
            if fence is not None:graph._finish_read_fence_v3(fence)
        finally:finish_runtime_storage_operation_v3(operation)
        raise


def require_current_self_view_work_v4(work,graph,authority,lease,request):
    from ..graph_worker import GraphStorageWorkV3
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_identity_v3
    if type(work)is not GraphStorageWorkV3:raise AuthorityUnavailable('SelfView requires its exact issued Source Work')
    reader=require_current_beta1_source_work_identity_v3(work.state)
    if(reader.graph is not graph or reader.work is not work or reader.authority is not authority or reader.lease is not lease
            or reader.operation_kind!=CONDITIONED_SELF_READ_KIND_V4 or reader.request!=request
            or work.kind!=CONDITIONED_SELF_WORK_KIND_V3):
        raise AuthorityUnavailable('SelfView Work changed its actual Owner READ command')
    return reader


def _self_view_now_v4(reader):
    import time
    first,started=_SELF_VIEW_CLOCKS_V4[reader]
    current=time.monotonic()
    now=first+max(0.0,current-started)
    if current>=reader.initial_monotonic_deadline or now>=reader.operation.deadline_utc:
        raise AuthorityUnavailable('SelfView exceeded its original absolute READ deadline')
    return now


def _self_view_envelope_v4(reader):
    import time
    from ..runtime_contracts import(CommandEnvelope,OperationIdentity,VersionGuard,QueryEpoch,SourceQualification,RUNTIME_SCHEMA)
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    reader.require_current()
    with runtime_storage_quantum_v3(reader.db)as meter:
        versions={}
        for kind in('scheme','operator','policy'):
            row=_beta1_metadata_row_v3(reader,meter,'graph_guard_versions',('version',),
                'bot=? AND persona=? AND ref=? AND kind=?',(*reader.namespace.as_tuple,'current',kind))
            if row is None:raise AuthorityUnavailable('SelfView requires actual registered guard version heads')
            versions[kind]=row[0]
    now=_self_view_now_v4(reader)
    return CommandEnvelope(RUNTIME_SCHEMA,OperationIdentity(reader.activity_id,None,reader.operation_id,
        reader.operation_kind,reader.operation_id,canonical_digest({'input_refs':[]})),reader.authority,
        VersionGuard((),(QueryEpoch(reader.namespace,'namespace',reader.graph_stamp[1].revision),),
            reader.owner_binding.access_epoch,reader.owner_binding.delete_epoch,reader.catalogue_hash,
            versions['scheme'],versions['operator'],versions['policy'],(),(),()),
        SourceQualification((),'derived',None,now,'inference','ineligible',None,'not_applicable'),(),
        reader.parent_budget_lease_ref,reader.operation.deadline_utc,reader.initial_monotonic_deadline,
        'self-view-current:'+reader.operation_id,())


class _ConditionedReadResultV3:
    def __init__(self,reader,value):
        self.reader,self.value=reader,value
        _SELF_VIEW_RESULTS_V4[self]=(reader,reader.work,reader.operation,reader.selection_digest,value)
    def require_result_v3(self,work):
        reader=self.reader
        if(_SELF_VIEW_RESULTS_V4.get(self)!=(reader,work,reader.operation,reader.selection_digest,self.value)
                or work.state is not reader or reader.operation_kind not in {CONDITIONED_SELF_READ_KIND_V4,_CONDITIONED_FOLLOWUP_READ_KIND_V3}
                or not reader.complete or not reader.read_finished):
            raise AuthorityUnavailable('SelfView result lost its exact complete current own READ Work')
        return self.value
    def release_payload_v3(self):
        if _SELF_VIEW_RESULTS_V4.pop(self,None)is None:return
        from .current_method_learning_read_v3 import _release_method_registered_payloads_v3
        reader=self.reader
        if type(self.value)is ConditionedFollowupPreparedV3:_CONDITIONED_PREPARED_FOLLOWUPS_V3.pop(self.value,None)
        _SELF_VIEW_CLOCKS_V4.pop(reader,None)
        _release_method_registered_payloads_v3(reader)
        if reader.inventory is not None:reader.inventory.release_payload_v3()
        reader.points.clear();reader.inventories.clear();reader.input_heads.clear()
        reader.result=None;self.value=None


def advance_current_conditioned_self_read_v3(graph,work):
    from .current_conditioned_personal_choice_v3 import is_personal_choice_locator_v3,advance_personal_choice_locator_v3
    if is_personal_choice_locator_v3(work.state):return advance_personal_choice_locator_v3(graph,work)
    if type(work.state)in {_ConditionedFollowupLocatorReaderV3,_ConditionedChildLocatorReaderV3}:return _advance_conditioned_locator_work_v3(graph,work)
    from .current_method_learning_read_v3 import(advance_current_method_learning_read_v3,_READING,
        bind_prepared_method_learning_read_v3,MethodInputNeededV3,_MethodPointReadV3,_MethodInventoryReadV3,
        _MethodBudgetGrantReadV3,_ISSUER,PreparedMethodDomainInputsV3)
    from .current_beta1_source_read_v3 import prepare_current_beta1_owner_entry_v3,create_current_beta1_source_metadata_task_v3
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    from ..graph_worker import GraphStorageStepV3
    reader=require_conditioned_self_work_v3(work.state).reader
    if reader.graph is not graph:raise AuthorityUnavailable('conditioned Source Work advanced on another installed graph')
    if reader.read_finished:
        if reader.operation_kind in {CONDITIONED_SELF_READ_KIND_V4,_CONDITIONED_FOLLOWUP_READ_KIND_V3}:
            raise AuthorityUnavailable('conditioned readonly observer cannot enter a business branch')
        if reader in _CONDITIONED_CHILD_SELECTORS_V3:return advance_current_conditioned_child_business_v3(graph,work)
        return advance_current_method_learning_read_v3(graph,work)
    with bind_runtime_storage_operation_v3(work.operation,reader.db):
        _self_view_now_v4(reader)
        prepare_conditioned_owner_entry_v3(reader)
        if require_conditioned_self_work_v3(reader).read_stage=='metadata_owner':
            return _transition_conditioned_source_read_scope_v3(reader)
        require_current_conditioned_self_read_identity_v3(reader)
        graph._validate_read_fence_v3(reader.fence)
        if reader.operation_kind not in {CONDITIONED_SELF_READ_KIND_V4,_CONDITIONED_FOLLOWUP_READ_KIND_V3}:
            from .current_conditioned_personal_choice_v3 import personal_choice_locator_for_reader_v3,advance_personal_choice_source_v3
            if personal_choice_locator_for_reader_v3(reader)is not None:return advance_personal_choice_source_v3(graph,work)
            return advance_current_method_learning_read_v3(graph,work)
        if not reader.inventory_sealed:
            with reader.store._lock:reader.advance()
            return GraphStorageStepV3('progress')
        if reader.pending_input is not None:
            with reader.store._lock,runtime_storage_quantum_v3(reader.db)as meter:
                reader.require_current(meter=meter);reader.pending_input.advance(meter)
                if reader.pending_input.complete:reader.pending_input=None
            return GraphStorageStepV3('progress')
        token=_READING.set(reader)
        try:
            with bind_prepared_method_learning_read_v3(reader.inventory,graph,reader.db),reader.store._lock:
                reader.db.execute('BEGIN')
                try:
                    if reader.selected_envelope is None:reader.selected_envelope=_self_view_envelope_v4(reader)
                    if reader.installed_readers is None:
                        reader.installed_readers=install_conditioned_self_readers_v1(graph,scope=reader.fence.scope,
                            owner_guard=reader.owner_guard,operation_kind=reader.operation_kind,owner_binding=reader.owner_binding)
                    plan=read_plan_current_conditioned_self_v1(reader.db,reader.namespace,reader.activity_id,
                        reader.operation_kind,reader.request,reader.installed_readers)
                    reader.selected_plan=plan
                    require_conditioned_sources_v3(reader,plan.source_roots)
                    frame=freeze_current_conditioned_source_read_frame_v3(reader,plan)
                    from .conditioned_self_operations_v1 import read_conditioned_self_view_v4
                    value=(read_conditioned_self_view_v4(reader.db,work=work,frame=frame,request=reader.request,readers=reader.installed_readers)
                        if reader.operation_kind==CONDITIONED_SELF_READ_KIND_V4 else _read_conditioned_followup_prepared_v3(reader,frame))
                    from .dispatch_current_inventory_v3 import _heap
                    reader.operation.retain(_heap(value)*2+65536)
                    reader.result=_ConditionedReadResultV3(reader,value);reader.complete=True
                finally:reader.db.rollback()
            _self_view_now_v4(reader);graph._validate_read_fence_v3(reader.fence)
            graph._finish_read_fence_v3(reader.fence);reader.read_finished=True
            return GraphStorageStepV3('complete',reader.result)
        except MethodInputNeededV3 as needed:
            kind,actual=needed.request
            with reader.store._lock,runtime_storage_quantum_v3(reader.db):
                if kind=='conditioned_owner_metadata':task=create_current_conditioned_metadata_task_v3(reader,actual)
                elif kind=='beta1_source_metadata':task=create_current_beta1_source_metadata_task_v3(reader,actual)
                elif kind=='point':
                    require_conditioned_point_v3(reader,actual)
                    task=reader.points.get(actual)
                    if task is None:task=_MethodPointReadV3(reader,actual);reader.points[actual]=task
                elif kind=='inventory':
                    if reader.selected_plan is None or actual not in reader.selected_plan.fixed_type_ids:
                        raise AuthorityUnavailable('SelfView inventory escaped its actual complete selected plan')
                    task=reader.inventories.get(actual)
                    if task is None:task=_MethodInventoryReadV3(reader,actual);reader.inventories[actual]=task
                elif kind=='budget_grant':
                    if actual!=reader.parent_budget_lease_ref:raise AuthorityUnavailable('SelfView parent budget locator changed')
                    if reader.budget_task is None:reader.budget_task=_MethodBudgetGrantReadV3(reader,actual)
                    task=reader.budget_task
                else:raise AuthorityUnavailable('unregistered SelfView own READ dependency')
                reader.pending_input=task
            return GraphStorageStepV3('progress')
        finally:_READING.reset(token)


def finish_current_conditioned_self_read_v3(graph,work,error):
    from .current_conditioned_personal_choice_v3 import is_personal_choice_locator_v3,finish_personal_choice_locator_v3
    if is_personal_choice_locator_v3(work.state):return finish_personal_choice_locator_v3(graph,work,error)
    reader=work.state
    if type(reader)in {_ConditionedFollowupLocatorReaderV3,_ConditionedChildLocatorReaderV3}:
        from ..runtime_storage_v3 import finish_runtime_storage_operation_v3
        if reader.fence is not None:graph._finish_read_fence_v3(reader.fence)
        _CONDITIONED_LOCATOR_READERS_V3.pop(reader,None);_CONDITIONED_CHILD_LOCATORS_V3.pop(reader,None)
        finish_runtime_storage_operation_v3(work.operation)
        return
    if reader.operation_kind not in {CONDITIONED_SELF_READ_KIND_V4,_CONDITIONED_FOLLOWUP_READ_KIND_V3}:
        from .current_method_learning_read_v3 import finish_current_method_learning_read_v3
        return finish_current_method_learning_read_v3(graph,work,error)
    from ..runtime_storage_v3 import finish_runtime_storage_operation_v3
    try:
        if not reader.read_finished:graph._finish_read_fence_v3(reader.fence);reader.read_finished=True
        if error is None:work.result_lease=work.operation
    finally:
        if error is not None:
            from .current_method_learning_read_v3 import _release_method_registered_payloads_v3
            _SELF_VIEW_CLOCKS_V4.pop(reader,None);_release_method_registered_payloads_v3(reader)
            if reader.inventory is not None:reader.inventory.release_payload_v3()
            finish_runtime_storage_operation_v3(work.operation)


def conditioned_runtime_identity_v3(db,read):
    from ..domains.d01.identity_v3 import RuntimeIdentityRef
    reader=_active(db)
    if reader is None or read.frame.envelope.identity.operation_id!=reader.operation_id:
        raise AuthorityUnavailable('conditioned RuntimeIdentity requires its actual complete current Owner Work')
    require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
    return RuntimeIdentityRef.from_owner_guard(reader.namespace,reader.owner_guard)


def conditioned_prediction_execution_assumptions_v3(db,read,prediction,outcome):
    import json
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    reader=_active(db)
    if reader is None:raise AuthorityUnavailable('prediction history requires actual current own Source Work')
    require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
    required=(*prediction.assumption_heads,prediction.condition_goal_head,prediction.target_head)
    if prediction.target_observable.startswith('artifact_'):
        from .artifact_task_observer_v1 import read_current_artifact_task_milestone_v2
        from .d11_artifact_draft_content_v1 import read_current_artifact_phase_verified_v2
        from .d11_artifact_draft_model_v1 import read_artifact_draft_prepared_v2,read_artifact_draft_frozen_v2
        actual=read_current_artifact_task_milestone_v2(db,namespace=prediction.namespace,
            original_ref=outcome.original_ref,issuer=reader.graph._GraphCoordinator__d11_issuer)
        verified=read_current_artifact_phase_verified_v2(db,namespace=prediction.namespace,
            selector=actual.selector,issuer=reader.graph._GraphCoordinator__d11_issuer)
        if verified.readback!=actual.readback:return None
        prepared=read_artifact_draft_prepared_v2(db,namespace=prediction.namespace,selector=verified.content_selector,
            issuer=reader.graph._GraphCoordinator__d11_issuer)
        if prepared is None:return None
        frozen=read_artifact_draft_frozen_v2(db,prepared=prepared,issuer=reader.graph._GraphCoordinator__d11_issuer)
        execution_versions=frozen.source_read_versions
    elif prediction.target_observable=='life_postcondition':
        from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from .d10_life_progress_provenance_v1 import require_current_life_progress_v1
        atom=read.head(db,prediction.resolution_target_ref,required=True)
        progress=decode_typed_production_value_v1(atom.value,LifeProgressHeadV1)
        prepared,terminal,production=require_current_life_progress_v1(db,namespace=prediction.namespace,
            progress=progress,issuer=reader.graph._GraphCoordinator__d11_issuer,read=read)
        execution_versions=tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision)for row in prepared.read_rows)
    else:
        row=conditioned_history_v3(db,prediction.target_head.key.token,prediction.target_head.revision)
        if row is None or row[2]!=1:return None
        planning=read_adopted_domain_operation_v1(db,prediction.namespace,row[0])
        if planning is None or prediction.target_head not in planning['receipt'].write_versions:return None
        execution_versions=planning['read_versions']
    if not set(required)<=set(execution_versions):return None
    state=require_conditioned_self_work_v3(reader);facts=[]
    for version in prediction.assumption_heads:
        if(version.key.token,version.revision)not in state.allowed_history:
            raise AuthorityUnavailable('frozen execution assumption was not selected before actual Source EOF')
        row=conditioned_history_v3(db,version.key.token,version.revision)
        if row is None or row[2]!=1:return None
        producer=read_adopted_domain_operation_v1(db,prediction.namespace,row[0])
        if(producer is None or producer['operation_kind']!='adopt_current_c1_method_conditions_v1'
                or version not in producer['receipt'].write_versions):return None
        raw=json.loads(row[1]);roots=tuple(raw['source_refs'])
        if roots:read.source_family(db,roots,purpose='consolidation')
        facts.append((version,raw,row[0]))
    return tuple(facts)



_PENDING_CONDITIONED_OWNER_V3=WeakKeyDictionary()
_CONDITIONED_PENDING_READERS_V3=WeakKeyDictionary()
_CONDITIONED_LOCATOR_READERS_V3=WeakKeyDictionary()


class _ConditionedPendingOwnerV3:
    def __init__(self,issuer,locator,*,authority,fence,operation_kind,request):
        if issuer is not _ISSUER:raise AuthorityUnavailable('conditioned pending Owner requires its actual Source factory')
        record=_CONDITIONED_LOCATOR_READERS_V3.get(locator)
        if record is None or not _require_conditioned_pending_origin_v3(locator)or not locator.cause_complete:
            raise AuthorityUnavailable('conditioned pending Owner requires complete actual cause metadata EOF')
        self.locator,self.authority,self.fence,self.operation_kind,self.request=locator,authority,fence,operation_kind,request
        _PENDING_CONDITIONED_OWNER_V3[self]=(locator,locator.graph,locator.work,locator.operation,fence,
            authority,operation_kind,request,locator.cause_metadata,locator.operation.deadline_utc)


def require_pending_conditioned_factory_v3(capsule,*,graph,operation,fence,authority,operation_kind,request):
    if type(capsule)is not _ConditionedPendingOwnerV3:raise AuthorityUnavailable('conditioned pending Owner capsule must be privately issued')
    locator=capsule.locator
    expected=(locator,graph,locator.work,operation,fence,authority,operation_kind,request,
        locator.cause_metadata,operation.deadline_utc)
    if(_PENDING_CONDITIONED_OWNER_V3.get(capsule)!=expected or locator.graph is not graph
            or locator.operation is not operation or locator.work.operation is not operation
            or locator.work.kind!=CONDITIONED_SELF_WORK_KIND_V3 or not locator.cause_complete
            or fence.scope.operation!='read'or fence.scope.namespace!=locator.namespace
            or authority.namespace!=locator.namespace):
        raise AuthorityUnavailable('conditioned pending Owner changed its actual cause/Work/Root/deadline/READ')
    locator.work._require_invocation(graph)
    return capsule


def bind_pending_conditioned_reader_v3(reader,capsule):
    require_pending_conditioned_factory_v3(capsule,graph=reader.graph,operation=reader.operation,
        fence=reader.fence,authority=reader.authority,operation_kind=reader.operation_kind,request=reader.request)
    if reader.owner_binding is not None or reader.owner_guard is not None or reader.material_owner_guard is not None:
        raise AuthorityUnavailable('conditioned pending stage must not invent an Owner binding')
    if reader in _CONDITIONED_PENDING_READERS_V3:raise AuthorityUnavailable('conditioned pending reader binds once')
    _CONDITIONED_PENDING_READERS_V3[reader]=capsule


def require_conditioned_background_owner_identity_v3(reader):
    state=require_conditioned_self_work_v3(reader)
    capsule=_CONDITIONED_PENDING_READERS_V3.get(reader)
    if capsule is not None:
        require_pending_conditioned_factory_v3(capsule,graph=reader.graph,operation=reader.operation,
            fence=reader.fence,authority=reader.authority,operation_kind=reader.operation_kind,request=reader.request)
        if reader.owner_binding is not None or reader.owner_guard is not None or state.source_permission is not None:
            raise AuthorityUnavailable('pending conditioned Owner has unauthorized prepared body/Source state')
        return state
    if reader.session_proof is not None or reader.owner_binding is None or reader.owner_guard is None:
        raise AuthorityUnavailable('conditioned background Owner requires its exact installed pending/current Source recipe')
    cause=condition_followup_cause_metadata_v3(reader)
    if cause.namespace!=reader.namespace or cause.original_deadline_utc<reader.operation.deadline_utc:
        raise AuthorityUnavailable('conditioned background Owner changed actual cause or original deadline')
    return state


def require_conditioned_owner_ready_v3(reader):
    state=require_conditioned_self_work_v3(reader)
    if(state.read_stage!='source'or reader in _CONDITIONED_PENDING_READERS_V3 or reader.owner_binding is None
            or reader.owner_guard is None or reader.material_owner_guard is None or reader.general_owner_entry is None):
        raise AuthorityUnavailable('conditioned census/Source/body/plan requires true completed Owner17 EOF')
    return state


def pin_conditioned_background_owner_v3(reader,entry):
    capsule=_CONDITIONED_PENDING_READERS_V3.get(reader)
    if capsule is None:raise AuthorityUnavailable('conditioned background Owner can be pinned exactly once')
    require_pending_conditioned_factory_v3(capsule,graph=reader.graph,operation=reader.operation,
        fence=reader.fence,authority=reader.authority,operation_kind=reader.operation_kind,request=reader.request)
    owner=entry.require_for_v3(reader)
    guard=entry.current_owner_guard
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    if(owner.namespace!=reader.namespace or guard.namespace!=reader.namespace
            or owner.authorization_head!=guard.authorization_head or guard.pending_revoke_operation_id is not None):
        raise AuthorityUnavailable('conditioned Owner17 completion changed actual namespace/current Owner head')
    reader.owner_binding,reader.owner_guard=owner,guard
    reader.owner_acl_authority=entry.owner_acl_authority
    reader.owner_principal=entry.owner_principal
    reader.body_authority=reader.authority
    reader.material_owner_guard=ProductionOwnerGuardV1(owner_grant_key(*reader.namespace.as_tuple).token,
        owner.grant_revision,owner.grant_digest.removeprefix('sha256:'),owner.authorization_head.removeprefix('sha256:'))
    reader.general_owner_entry=entry
    reader.conditioned_cause_locator=capsule.locator
    state=_STATES[reader];state.identity=_identity(reader);state.owner_binding=owner
    _CONDITIONED_PENDING_READERS_V3.pop(reader,None);_PENDING_CONDITIONED_OWNER_V3.pop(capsule,None)
    return owner


def prepare_conditioned_owner_entry_v3(reader):
    require_conditioned_self_work_v3(reader)
    if reader.session_proof is not None:
        from ..authority_service.owner_location_read_v3 import prepare_current_host_method_owner_read_entry_v3
        if reader.general_owner_entry is None:reader.general_owner_entry=prepare_current_host_method_owner_read_entry_v3(reader)
        reader.general_owner_entry.require_permission_v3(reader)
        with reader.store._lock:reader.general_owner_entry.require_for_v3(reader)
        pin_conditioned_owner_entry_v3(reader)
        return reader.general_owner_entry
    from ..authority_service.owner_location_read_v3 import prepare_current_host_semantic_background_owner_read_entry_v3
    if reader.general_owner_entry is None:
        reader.general_owner_entry=prepare_current_host_semantic_background_owner_read_entry_v3(reader)
    entry=reader.general_owner_entry;entry.require_permission_v3(reader)
    with reader.store._lock:
        if reader in _CONDITIONED_PENDING_READERS_V3:pin_conditioned_background_owner_v3(reader,entry)
        else:entry.require_for_v3(reader)
    return entry


_CONDITIONED_FOLLOWUP_READ_KIND_V3='resolve_current_conditioned_followup_v3'


@dataclass(frozen=True,slots=True)
class _ConditionedFollowupLocatorRequestV3:
    dedupe_key: str


class _ConditionedCauseColumnV3:
    def __init__(self,reader,*,column,header):
        self.reader,self.column,self.header=reader,column,header
        self.operation=reader.operation;self.offset=0;self.total=None;self.fragment=b'';self.complete=False
        self.capture=_ConditionedLocatorJSONV3(self)
        from .conditioned_producer_source_metadata_v3 import retain_conditioned_producer_locator_path_v3
        self.capture.retain_path_v3=retain_conditioned_producer_locator_path_v3
        self.result=None;self.digest=None
    def _actual(self):
        reader=self.reader
        expected=_CONDITIONED_LOCATOR_READERS_V3.get(reader)
        if expected is None or reader.work.state is not reader or reader.operation.closed:
            raise AuthorityUnavailable('conditioned cause column requires its actual private locator Work')
        reader.work._require_invocation(reader.graph)
        return self
    def advance(self,meter):
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        self._actual();reader=self.reader
        if self.complete:return True
        current=meter.read_fixed_row(reader.db,'graph_domain_production_originals_v1',
            ('domain','operation_kind','request_digest','original_digest','receipt_digest','bundle_digest'),
            'bot=? AND persona=? AND operation_id=?',(*reader.namespace.as_tuple,reader.causal_operation_id))
        if current!=self.header:raise AuthorityUnavailable('conditioned cause original header changed during complete metadata EOF')
        if self.total is None:
            with legacy_cell_read_transaction_v2(reader.db):
                raw=reader.db.execute('SELECT typeof('+self.column+'),length(CAST('+self.column+' AS BLOB)) '
                    'FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND operation_id=?',
                    (*reader.namespace.as_tuple,reader.causal_operation_id)).fetchone()
            meter.charge_read(16)
            if raw is None or raw[0]!='text':raise AuthorityUnavailable('conditioned cause has no canonical original metadata')
            self.total=raw[1];return False
        if self.offset<self.total:
            with legacy_cell_read_transaction_v2(reader.db):
                chunk,total,kind=read_legacy_sql_cell_fragment_v2(reader.db,
                    table='graph_domain_production_originals_v1',column=self.column,
                    where='bot=? AND persona=? AND operation_id=?',parameters=(*reader.namespace.as_tuple,reader.causal_operation_id),
                    start=self.offset,length=min(1024,self.total-self.offset),meter=meter)
            if(total,kind)!=(self.total,'text'):raise AuthorityUnavailable('conditioned cause metadata physical byte count changed')
            self.capture._reserve_v3(len(chunk)*8+65536)
            self.capture.parser.feed(chunk,self.capture._emit_v3);self.offset+=len(chunk)
            return False
        parsed=self.capture.parser.finish();self.capture._flush_text_v3()
        if parsed.byte_count!=self.total or parsed.sha256!=self.header[3]:
            raise AuthorityUnavailable('conditioned cause metadata lacks exact full canonical original digest')
        self.result=self.capture.value;self.digest=parsed.sha256;self.complete=True
        return True


class _ConditionedFollowupLocatorReaderV3:
    def __init__(self,issuer,graph,bootstrap,bundle,operation,dedupe_key,outbox_header):
        import time
        if issuer is not _ISSUER:raise AuthorityUnavailable('conditioned locator requires actual installed factory')
        self.graph,self.bootstrap,self.bundle,self.operation=graph,bootstrap,bundle,operation
        self.store,self.db=graph._GraphCoordinator__store,graph._GraphCoordinator__store._db
        self.runtime=graph._GraphCoordinator__domain_production_runtime_v1
        self.namespace=bundle.installation_policy.namespace
        from uuid import uuid4
        self.read_scope_nonce=uuid4().hex
        self.dedupe_key,self.outbox_header=dedupe_key,outbox_header
        self.causal_operation_id=outbox_header[0];self.header=None;self.bundle_metadata=None;self.column=None
        self.work=self.fence=self.authority=None
        self.operation_kind=_CONDITIONED_FOLLOWUP_READ_KIND_V3
        self.request=_ConditionedFollowupLocatorRequestV3(dedupe_key)
        self.cause_complete=False;self.cause_metadata=None
        self.owner_binding=self.owner_guard=self.material_owner_guard=None
        self.graph_stamp=graph._v2_graph_stamp(self.namespace)
        self.selection_digest=operation.selection_digest
        self.initial_monotonic_deadline=time.monotonic()+60.0
        _CONDITIONED_LOCATOR_READERS_V3[self]=(graph,bootstrap,bundle,operation,dedupe_key,outbox_header)
    def advance(self,meter):
        from ..runtime_contracts import AuthorityContext
        from .first_ingress_v2 import trusted_upper
        from .conditioned_self_operations_v1 import CONDITIONED_PRODUCER_EVENTS_V1
        current=meter.read_fixed_row(self.db,'graph_domain_production_outbox_v1',
            ('causal_operation_id','receiver_domain','event_kind','original_ref','original_digest','state'),
            'bot=? AND persona=? AND dedupe_key=?',(*self.namespace.as_tuple,self.dedupe_key))
        if current!=self.outbox_header:raise AuthorityUnavailable('conditioned outbox changed during fixed cause metadata EOF')
        if self.header is None:
            self.header=meter.read_fixed_row(self.db,'graph_domain_production_originals_v1',
                ('domain','operation_kind','request_digest','original_digest','receipt_digest','bundle_digest'),
                'bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,self.causal_operation_id))
            if self.header is None:raise AuthorityUnavailable('conditioned outbox has no actual committed producer original')
            return False
        if self.bundle_metadata is None:
            self.bundle_metadata=meter.read_fixed_row(self.db,'graph_bundle_operations',('digest','commit_seq'),
                'bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,self.causal_operation_id))
            if(self.bundle_metadata is None or self.bundle_metadata[0]!=self.header[5]
                    or type(self.bundle_metadata[1])is not int or self.bundle_metadata[1]<1):
                raise AuthorityUnavailable('conditioned cause lacks its actual positive shared W01 COMMIT metadata')
            return False
        if self.column is None:
            self.column=_ConditionedCauseColumnV3(self,column='original_payload_json',header=self.header)
            return False
        if not self.column.advance(meter):return False
        from .conditioned_producer_source_metadata_v3 import finish_conditioned_producer_locator_v3
        self.cause_metadata=finish_conditioned_producer_locator_v3(namespace=self.namespace,dedupe_key=self.dedupe_key,
            outbox_header=self.outbox_header,header=self.header,bundle_metadata=self.bundle_metadata,
            projection=self.column.result,whole_digest=self.column.digest,producer_events=CONDITIONED_PRODUCER_EVENTS_V1)
        self.authority=self.cause_metadata.authority
        now=trusted_upper(self.graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
            self.graph._GraphCoordinator__scene_clock_policy))
        if now>=self.cause_metadata.original_deadline_utc:
            raise AuthorityUnavailable('conditioned cause original absolute Root/task deadline expired')
        self.cause_complete=True
        return True


def condition_followup_cause_metadata_v3(reader):
    capsule=_CONDITIONED_PENDING_READERS_V3.get(reader)
    locator=capsule.locator if capsule is not None else getattr(reader,'conditioned_cause_locator',None)
    if(locator is None or _CONDITIONED_LOCATOR_READERS_V3.get(locator)is None or not locator.cause_complete
            or locator.graph is not reader.graph or locator.operation is not reader.operation
            or locator.work is not reader.work):
        raise AuthorityUnavailable('conditioned background Owner has no private complete actual cause locator EOF')
    return locator.cause_metadata


_READ_FAMILIES_V3[_CONDITIONED_FOLLOWUP_READ_KIND_V3]=(*_SELF_VIEW_TYPES_V3,
    'd07.current_interpretation.v1','d07.simulation_forecast_plan.v1','d07.simulation_branch.v1',
    'd07.simulation_record.v1','d07.condition_match.v1','d07.self_discrepancy.v1',
    'd08.goal.v1','d08.personal_plan.v1','d10.life_project.v1','d10.project_checkpoint.v1',
    'd10.conditioned_strategy_projection.v1','d10.activity_recipe.v1')


_CONDITIONED_PREPARED_FOLLOWUPS_V3=WeakKeyDictionary()


class ConditionedFollowupPreparedV3:
    """Private actual READ result; the async driver submits each next Work."""
    def __init__(self,issuer,reader,*,event,producer,commands,frame,frozen=None,pointer=None):
        if issuer is not _ISSUER:raise AuthorityUnavailable('conditioned followup result requires actual own READ factory')
        self.reader,self.event,self.producer,self.commands=reader,event,producer,commands
        self.namespace=reader.namespace;self.dedupe_key=event.dedupe_key
        self.cause=condition_followup_cause_metadata_v3(reader)
        self.original_deadline_utc=self.cause.original_deadline_utc
        self.parent_budget_lease_ref=self.cause.parent_budget_lease_ref
        self.read_versions=frame.snapshot.versions;self.query_coverage=frame.query_coverage
        self.child_ids=tuple('conditioned-child:'+canonical_digest((self.namespace,self.dedupe_key,kind,request))[:48]
            for kind,request in commands)
        from ..domains.d01.production_operations_v1 import plain_v1
        self.target_census={'read_versions':plain_v1(frame.snapshot.versions),
            'query_coverage':plain_v1(frame.query_coverage),'source_roots':plain_v1(frame.envelope.source_qualification.source_refs)}
        self.target_census_digest=canonical_digest(self.target_census)
        self.targets=tuple({'child_id':child_id,'operation_kind':kind,'request':plain_v1(request)}
            for child_id,(kind,request)in zip(self.child_ids,commands,strict=True))
        self.targets_digest=canonical_digest(self.targets)
        self.frozen_original_ref=None if pointer is None else pointer['first_child_original_ref']
        self.frozen_original_digest=None if pointer is None else pointer['first_child_original_digest']
        if frozen is not None:
            self.target_census=frozen['target_census'];self.target_census_digest=frozen['target_census_digest']
            self.targets=tuple(frozen['targets']);self.targets_digest=frozen['targets_digest']
            if tuple(item['child_id']for item in self.targets)!=self.child_ids:
                raise AuthorityUnavailable('conditioned restored target order changed its immutable full tuple')
        self.bootstrap=reader.conditioned_cause_locator.bootstrap;self.bundle=reader.conditioned_cause_locator.bundle
        _CONDITIONED_PREPARED_FOLLOWUPS_V3[self]=(reader.graph,reader.work,reader.operation,
            reader.selection_digest,event,canonical_digest(producer['receipt']),commands,self.child_ids,self.targets_digest,
            self.target_census_digest,canonical_digest(_conditioned_frozen_targets_wire_v3(self)),
            self.frozen_original_ref,self.frozen_original_digest)
    def require_for_v3(self,graph,bootstrap,bundle):
        expected=(graph,self.reader.work,self.reader.operation,self.reader.selection_digest,self.event,
            canonical_digest(self.producer['receipt']),self.commands,self.child_ids,self.targets_digest,
            self.target_census_digest,canonical_digest(_conditioned_frozen_targets_wire_v3(self)),
            self.frozen_original_ref,self.frozen_original_digest)
        if(_CONDITIONED_PREPARED_FOLLOWUPS_V3.get(self)!=expected or self.bootstrap is not bootstrap
                or self.bundle is not bundle or self.reader.graph is not graph):
            raise AuthorityUnavailable('conditioned handoff changed its exact installed cause/frozen targets')
        return self


def prepare_current_conditioned_followup_v3(graph,bootstrap,bundle,*,dedupe_key):
    import time
    from uuid import uuid4
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from ..runtime_storage_v3 import(begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
        finish_runtime_storage_operation_v3)
    from .first_ingress_v2 import trusted_upper
    from .conditioned_self_operations_v1 import CONDITIONED_PRODUCER_EVENTS_V1
    graph._admin(bootstrap);require_graph_storage_work_admission_v3(graph)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is not bundle:
        raise AuthorityUnavailable('conditioned followup requires its actual installed assembly')
    if type(dedupe_key)is not str or not dedupe_key:raise ValueError('exact durable conditioned outbox key required')
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    operation_id='conditioned-followup-read:'+uuid4().hex
    db=graph._GraphCoordinator__store._db
    operation=begin_runtime_storage_operation_v3(db,operation_id,now+60.0)
    try:
        with bind_runtime_storage_operation_v3(operation,db),graph._GraphCoordinator__store._lock,runtime_storage_quantum_v3(db)as meter:
            header=meter.read_fixed_row(db,'graph_domain_production_outbox_v1',
                ('causal_operation_id','receiver_domain','event_kind','original_ref','original_digest','state'),
                'bot=? AND persona=? AND dedupe_key=?',(*bundle.installation_policy.namespace.as_tuple,dedupe_key))
            if header is None or header[2]not in CONDITIONED_PRODUCER_EVENTS_V1:
                finish_runtime_storage_operation_v3(operation)
                return False,None
            if header[5]not in {'pending','waiting','completed'}:raise AuthorityUnavailable('conditioned outbox has no registered durable state')
            reader=_ConditionedFollowupLocatorReaderV3(_ISSUER,graph,bootstrap,bundle,operation,dedupe_key,header)
        work=create_graph_storage_work_v3(graph,kind=CONDITIONED_SELF_WORK_KIND_V3,operation_id=operation_id,
            selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=reader,operation=operation)
        work._require_invocation(graph,initial=True);reader.work=work
        work.phase='conditioned_cause_metadata_eof'
        return True,work
    except BaseException:
        finish_runtime_storage_operation_v3(operation);raise


def _advance_conditioned_locator_work_v3(graph,work):
    import time
    from dataclasses import replace
    from ..graph_worker import GraphStorageStepV3
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    from .first_ingress_v2 import trusted_upper
    from .current_method_learning_read_v3 import begin_current_method_learning_read_v3
    from .current_beta1_source_read_v3 import register_current_beta1_source_work_v3
    locator=work.state
    if(type(locator)not in {_ConditionedFollowupLocatorReaderV3,_ConditionedChildLocatorReaderV3}or _CONDITIONED_LOCATOR_READERS_V3.get(locator)is None
            or locator.graph is not graph or locator.work is not work or work.operation is not locator.operation):
        raise AuthorityUnavailable('conditioned locator advancement escaped actual private factory')
    with bind_runtime_storage_operation_v3(work.operation,locator.db):
        with locator.store._lock,runtime_storage_quantum_v3(locator.db)as meter:
            if not locator.advance(meter):return GraphStorageStepV3('progress')
        cause=locator.cause_metadata
        now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
        deadline=min(work.operation.deadline_utc,cause.original_deadline_utc)
        if now>=deadline:raise AuthorityUnavailable('conditioned cause expired before actual Owner READ')
        work.operation.deadline_utc=deadline;work.deadline_utc=deadline
        authority=replace(cause.authority,issuer_domain='d12',capability_ref='conditioned-source:'+locator.dedupe_key[:48],
            purpose='consolidation')
        fence=graph._begin_read_fence_v3(authority,operation_id=work.operation_id+':owner:'+locator.read_scope_nonce)
        capsule=_ConditionedPendingOwnerV3(_ISSUER,locator,authority=authority,fence=fence,
            operation_kind=locator.operation_kind,request=locator.request)
        reader=begin_current_method_learning_read_v3(graph,work.operation,fence,
            runtime=locator.runtime,authority=authority,lease=None,operation_kind=locator.operation_kind,
            request=locator.request,operation_id=work.operation_id,activity_id=work.operation_id,
            audience_ref=authority.audience[0],parent_budget_lease_ref=cause.parent_budget_lease_ref,
            request_digest=canonical_digest((locator.operation_kind,locator.request,cause.original_digest)),
            owner_binding=None,owner_guard=None,session_proof=None,initial_now_utc=now,
            source_pending_owner=capsule)
        reader.work=work;reader.conditioned_cause_locator=locator
        reader.initial_monotonic_deadline=min(locator.initial_monotonic_deadline,time.monotonic()+deadline-now)
        reader.background_followup=reader.background_host_lifecycle=reader.background_offline=None
        _SELF_VIEW_CLOCKS_V4[reader]=(now,time.monotonic())
        work.state=reader
        register_current_beta1_source_work_v3(reader,work)
        bind_pending_conditioned_reader_v3(reader,capsule)
        state=_STATES[reader];state.read_stage='metadata_owner'
        state.adoption_operations.add(cause.causal_operation_id);state.required_domain_producers.add(cause.causal_operation_id)
        state.source_roots.update(cause.source_refs)
        work.phase='conditioned_background_owner_eof'
    return GraphStorageStepV3('progress')


def require_conditioned_followup_resolver_v3(db,frame,event,producer_original,readers):
    from .domain_production_contracts_v1 import ProductionOutboxStageV1
    from .conditioned_self_operations_v1 import CONDITIONED_PRODUCER_EVENTS_V1
    reader=_active(db)
    if(reader is None or reader.operation_kind!=_CONDITIONED_FOLLOWUP_READ_KIND_V3
            or type(event)is not ProductionOutboxStageV1 or reader.installed_readers is not readers
            or frame.envelope.identity.operation_id!=reader.operation_id or frame.owner_guard!=reader.material_owner_guard):
        raise AuthorityUnavailable('conditioned resolver requires actual private own Source READ/frame')
    cap=require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
    cause=condition_followup_cause_metadata_v3(reader)
    if(event.namespace!=reader.namespace or event.dedupe_key!=cause.dedupe_key
            or event.causal_operation_id!=cause.causal_operation_id or event.receiver_domain!=cause.receiver_domain
            or event.event_kind!=cause.event_kind or event.trigger_original.original_ref!=cause.trigger_ref
            or event.trigger_original.original_digest!=cause.trigger_digest
            or(producer_original['domain'],producer_original['operation_kind'])not in CONDITIONED_PRODUCER_EVENTS_V1[event.event_kind]
            or producer_original['receipt'].operation_id!=cause.causal_operation_id
            or producer_original['original_digest']!=cause.original_digest
            or canonical_digest(producer_original['receipt'])!=cause.receipt_digest
            or not set(cause.source_refs)<=set(cap.source_refs)
            or frame.envelope.deadline_utc>cause.original_deadline_utc
            or frame.envelope.parent_budget_lease_ref!=cause.parent_budget_lease_ref):
        raise AuthorityUnavailable('conditioned resolver changed its actual COMMIT/Root/deadline/Source cause')
    return reader



def _read_conditioned_followup_prepared_v3(reader,frame):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_contracts_v1 import ProductionOutboxStageV1,ProductionOriginalRefV1
    from .conditioned_self_operations_v1 import resolve_current_conditioned_followup_command_v1
    cause=condition_followup_cause_metadata_v3(reader)
    original=read_adopted_domain_operation_v1(reader.db,reader.namespace,cause.causal_operation_id)
    if original is None:raise AuthorityUnavailable('conditioned actual producing original is unavailable')
    event=ProductionOutboxStageV1(reader.namespace,cause.causal_operation_id,cause.receiver_domain,cause.event_kind,
        ProductionOriginalRefV1(cause.domain+'.current-'+cause.operation_kind,cause.trigger_ref,cause.trigger_digest))
    require_conditioned_followup_resolver_v3(reader.db,frame,event,original,reader.installed_readers)
    pointer=_conditioned_disposition_task_v3(reader).result
    frozen=None
    if pointer is None:
        commands=resolve_current_conditioned_followup_command_v1(reader.db,frame=frame,event=event,
            producer_original=original,readers=reader.installed_readers)
    else:
        first=read_adopted_domain_operation_v1(reader.db,reader.namespace,pointer['first_child_operation_id'])
        frozen,commands=_require_conditioned_frozen_original_v3(reader,first,pointer=pointer)
    if type(commands)is not tuple or not commands or len(commands)>frame.limits.max_followup_jobs:
        from .d01_production_operations_v1 import MissingProductionOriginalV1
        raise MissingProductionOriginalV1('conditioned_whole_target_tuple_or_no_match_maintenance')
    prepared=ConditionedFollowupPreparedV3(_ISSUER,reader,event=event,producer=original,commands=commands,frame=frame,
        frozen=frozen,pointer=pointer)
    _preload_conditioned_child_receipts_v3(reader,prepared)
    return prepared


def require_conditioned_source_terminal_value_v3(value,work):
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3
    reader=work.state
    if reader.operation_kind in {CONDITIONED_SELF_READ_KIND_V4,_CONDITIONED_FOLLOWUP_READ_KIND_V3}:
        if type(value)is not _ConditionedReadResultV3:raise AuthorityUnavailable('conditioned READ requires its private retained result')
        return value.require_result_v3(work)
    if type(value)is not PreparedMethodDomainInputsV3:raise AuthorityUnavailable('conditioned WRITE requires its actual same-Work sealed inputs')
    return value.require_business_result_v3(work)


def _conditioned_frozen_targets_wire_v3(prepared):
    from ..domains.d01.production_operations_v1 import plain_v1
    cause=prepared.cause
    return plain_v1({'schema':'d01.conditioned-frozen-targets.v1','namespace':prepared.namespace,
        'dedupe_key':prepared.dedupe_key,'causal_operation_id':cause.causal_operation_id,'event_kind':cause.event_kind,
        'producer_original_digest':cause.original_digest,'producer_receipt_digest':cause.receipt_digest,
        'parent_budget_lease_ref':cause.parent_budget_lease_ref,'original_deadline_utc':cause.original_deadline_utc,
        'target_census':prepared.target_census,'target_census_digest':prepared.target_census_digest,
        'targets':prepared.targets,'targets_digest':prepared.targets_digest})


_CONDITIONED_CHILD_TARGETS_V3=WeakKeyDictionary()


def bind_current_conditioned_followup_child_source_v3(reader,*,prepared,child_id):
    """Bind selected input material only; Core independently qualifies the WRITE."""
    state=require_conditioned_owner_ready_v3(reader)
    if(type(prepared)is not ConditionedFollowupPreparedV3
            or reader.inputs_sealed or reader.read_finished or reader.business_started):
        raise AuthorityUnavailable('conditioned child target input must bind once in actual fresh Source READ')
    prepared.require_for_v3(reader.graph,prepared.bootstrap,prepared.bundle)
    existing=_CONDITIONED_CHILD_TARGETS_V3.get(reader)
    expected=(prepared,child_id,canonical_digest(_conditioned_frozen_targets_wire_v3(prepared)))
    if existing is not None:
        if existing!=expected:raise AuthorityUnavailable('conditioned child target binding changed during actual READ continuation')
        return child_id
    if child_id not in prepared.child_ids:raise AuthorityUnavailable('conditioned child is outside the whole fixed target tuple')
    index=prepared.child_ids.index(child_id);kind,request=prepared.commands[index]
    if(reader.namespace!=prepared.namespace or reader.operation_kind!=kind or reader.request!=request
            or reader.operation_id!=child_id or reader.parent_budget_lease_ref!=prepared.parent_budget_lease_ref
            or reader.operation.deadline_utc>prepared.original_deadline_utc
            or reader.selected_envelope is None or reader.selected_envelope.deadline_utc>prepared.original_deadline_utc):
        raise AuthorityUnavailable('conditioned child changed exact target command/original Root or deadline')
    cap=require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
    if not set(prepared.cause.source_refs)<=set(cap.source_refs):
        raise AuthorityUnavailable('conditioned child omitted its original producing Source closure')
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    original=read_adopted_domain_operation_v1(reader.db,reader.namespace,prepared.cause.causal_operation_id)
    if(original is None or original['original_digest']!=prepared.cause.original_digest
            or canonical_digest(original['receipt'])!=prepared.cause.receipt_digest):
        raise AuthorityUnavailable('conditioned child lost actual COMMIT producer original and receipt')
    _CONDITIONED_CHILD_TARGETS_V3[reader]=(prepared,child_id,canonical_digest(_conditioned_frozen_targets_wire_v3(prepared)))
    return child_id


def _conditioned_child_targets_v3(db,frame):
    reader=_active(db)
    if reader is None:return None
    saved=_CONDITIONED_CHILD_TARGETS_V3.get(reader)
    if saved is None:return None
    prepared,child_id,digest=saved
    require_conditioned_stage_readers_v3(db,frame,reader.installed_readers,reader.operation_kind,reader.request)
    prepared.require_for_v3(reader.graph,prepared.bootstrap,prepared.bundle)
    if(frame.envelope.identity.operation_id!=child_id or child_id!=reader.operation_id
            or digest!=canonical_digest(_conditioned_frozen_targets_wire_v3(prepared))):
        raise AuthorityUnavailable('conditioned staged target changed its actual same command or whole census commitment')
    return prepared,child_id


def conditioned_followup_frozen_targets_v3(db,frame):
    value=_conditioned_child_targets_v3(db,frame)
    return None if value is None else _conditioned_frozen_targets_wire_v3(value[0])


def conditioned_followup_target_commitment_v3(db,frame):
    value=_conditioned_child_targets_v3(db,frame)
    if value is None:return None
    prepared,child_id=value
    return {'schema':'d01.conditioned-followup-target-commitment.v1','dedupe_key':prepared.dedupe_key,
        'targets_digest':prepared.targets_digest,'target_census_digest':prepared.target_census_digest,
        'producer_receipt_digest':prepared.cause.receipt_digest,'child_id':child_id}


def _finish_conditioned_signed_metadata_v3(task,value):
    from .dispatch_current_inventory_v3 import _freeze_value_v3
    from ..runtime_contracts import canonical_serialize
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    state=require_conditioned_self_work_v3(task.reader);reader=task.reader
    if task.identity[0]=='general_signed':
        from .d01_general_growth_v1 import validate_general_growth_owner_metadata_fields_v1
        table,kind,ref=task.identity[1]
        if task.metadata[0]!=kind:raise AuthorityUnavailable('conditioned signed General input has another exact Original kind')
        validate_general_growth_owner_metadata_fields_v1(table,kind,value,task.column.beta1_metadata_fields_seen)
        digest=task.metadata[-2]
        if table=='graph_d01_production_inputs_v1':
            if task.column.signature_verified is not True:raise AuthorityUnavailable('conditioned D01 raw signature lacks complete original EOF')
            state.adoption_operations.add(task.metadata[1]);prefix='d01.'+kind
            point_key=(*reader.namespace.as_tuple,ref)
        else:
            from .d07_execution_v1 import SIGN_KIND
            reader.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
                canonical_serialize((reader.namespace,kind,ref,digest)),task.metadata[-1])
            prefix='d07.'+kind;point_key=(*reader.namespace.as_tuple,kind,ref)
    else:
        from .d07_execution_v1 import SIGN_KIND
        table='graph_d07_execution_originals_v1';kind='simulation_request';ref=task.identity[1]
        digest=task.metadata[0]
        if(task.column.beta1_metadata_fields_seen!={'schema','request','request_digest','dedicated_budget_ref','owner_guard'}
                or value.get('schema')!='d07.registered-simulation-original.v1'):
            raise AuthorityUnavailable('conditioned simulation request locator does not match its actual registered writer')
        reader.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((reader.namespace,kind,ref,digest)),task.metadata[1])
        prefix='d07.'+kind;point_key=(*reader.namespace.as_tuple,kind,ref)
    if task.column.canonical_digest!=digest:raise AuthorityUnavailable('conditioned signed locator full canonical digest differs')
    state.signed_originals.add((table,point_key))
    state.observed_originals[ref]=ProductionOriginalRefV1(prefix,ref,digest)
    state.source_roots.update(_source_tokens(value));state.selected_keys.update(_graph_tokens(value))
    for version in _metadata_versions_v3(value):
        if NamespaceId.from_key(version.key)!=reader.namespace:raise AuthorityUnavailable('conditioned signed input frozen head crossed namespace')
        if version.revision:state.allowed_history.add((version.key.token,version.revision))
    return _freeze_value_v3({'kind':kind,'ref':ref,'digest':digest,'locator':value})


def read_bound_conditioned_general_signed_metadata_v3(db,*,namespace,issuer,table,original_ref,kind):
    reader=_active(db)
    if reader is None:return False,None
    if(reader.namespace!=namespace or reader.operation_kind not in {'adopt_current_conditioned_self_v1','rollback_current_conditioned_strategy_v1'}
            or issuer is not reader.graph._GraphCoordinator__d11_issuer):
        raise AuthorityUnavailable('conditioned General metadata lacks its own exact adopter Source Work')
    meta=conditioned_metadata_v3(db,namespace,('general_signed',(table,kind,original_ref)))
    if meta is None:return True,None
    return True,(meta['locator'],require_conditioned_self_work_v3(reader).observed_originals[original_ref])


class _ConditionedGraphLocatorV3:
    def __init__(self,issuer,reader,key,meta):
        if issuer is not _ISSUER:raise AuthorityUnavailable('conditioned graph metadata requires its own private producer')
        self.reader,self.key,self.revision,self.valid=reader,key,meta['revision'],bool(meta['valid'])
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        self.locator=_freeze_value_v3(meta['locator'])
    @property
    def value(self):
        from .dispatch_current_inventory_v3 import _detach_value_v3
        state=require_conditioned_owner_ready_v3(self.reader)
        task=state.tasks[('head',self.key.token)]
        with runtime_storage_quantum_v3(self.reader.db)as meter:task.require_header_v3(meter)
        return _detach_value_v3(self.locator)


def read_bound_conditioned_general_graph_metadata_v3(db,*,namespace,key,kind):
    reader=_active(db)
    if reader is None:return False,None
    kinds={'activation':'d01.persona_activation.v1','persona_plan':'d01.persona_plan.v1',
        'interpretation':'d07.current_interpretation.v1','goal':'d08.goal.v1','cancellation':'d08.action_cancellation.v1',
        'action':'d08.action_intent.v1','outcome':'d08.action_outcome.v1','life_progress':'d10.life_progress.v1',
        'life_progress_provenance':'d10.life_progress_provenance.v1','cost':'runtime.cost_settlement','job':'runtime.job'}
    if(reader.namespace!=namespace or reader.operation_kind not in {'adopt_current_conditioned_self_v1','rollback_current_conditioned_strategy_v1'}
            or kind not in kinds or type(key)is not AtomKey or key.type_name!=kinds[kind]or NamespaceId.from_key(key)!=namespace):
        raise AuthorityUnavailable('conditioned General metadata graph locator escaped its exact current family')
    meta=conditioned_metadata_v3(db,namespace,('head',key.token))
    return True,None if meta is None else _ConditionedGraphLocatorV3(_ISSUER,reader,key,meta)


def read_bound_conditioned_general_type_metadata_v3(db,*,namespace,type_id,limit=129):
    reader=_active(db)
    if reader is None:return False,None
    kinds={'d07.current_interpretation.v1':'interpretation','runtime.cost_settlement':'cost'}
    if type_id not in kinds or limit!=129 or namespace!=reader.namespace:
        raise AuthorityUnavailable('conditioned General metadata census escaped its exact original family/bound')
    rows=[]
    for token in sorted(reader.heads):
        key=AtomKey.from_token(token)
        if key.type_name==type_id:
            _,row=read_bound_conditioned_general_graph_metadata_v3(db,namespace=namespace,key=key,kind=kinds[type_id])
            if row is not None:rows.append(row)
            if len(rows)>128:return True,(tuple(rows),False)
    return True,(tuple(rows),True)


def read_bound_conditioned_d01_input_v3(db,*,read,ref,kind,issuer):
    reader=_active(db)
    if reader is None:return False,None
    if issuer is not reader.graph._GraphCoordinator__d11_issuer or reader.installed_readers.issuer is not issuer:
        raise AuthorityUnavailable('conditioned D01 body reader changed its actual installed issuer')
    state=require_conditioned_owner_ready_v3(reader)
    selected=('general_signed',('graph_d01_production_inputs_v1',kind,ref))
    task=state.tasks.get(selected)
    if task is None or not task.complete or task.result is None:
        raise AuthorityUnavailable('conditioned D01 body has no complete selected signed locator before all-Source')
    require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
    if reader.read_finished:require_conditioned_write_phase_v3(reader)
    elif reader.frame_fields is None or read.frame.envelope.identity.operation_id!=reader.operation_id:
        raise AuthorityUnavailable('conditioned D01 body left its actual Source READ frame')
    from .current_method_learning_read_v3 import read_bound_method_learning_attachment_v3
    handled,row=read_bound_method_learning_attachment_v3(db,table='graph_d01_production_inputs_v1',
        columns=('kind','producing_operation_id','payload_json','payload_digest','signature'),
        key_columns=('bot','persona','original_ref'),key=(*reader.namespace.as_tuple,ref))
    if not handled or row is None:raise AuthorityUnavailable('conditioned signed D01 original disappeared after its metadata EOF')
    from .d01_production_operations_v1 import SIGN_KIND,_ORIGINAL_TYPES
    from ..runtime_contracts import canonical_serialize
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    import json
    with runtime_storage_quantum_v3(db)as meter:task.require_header_v3(meter)
    if row[0]!=kind or(row[0],row[1],row[3],row[4])!=task.metadata:
        raise AuthorityUnavailable('conditioned D01 body differs from its selected immutable signed metadata')
    issuer._signer.verify(SIGN_KIND,row[2],row[4]);value=json.loads(row[2])
    if canonical_serialize(value)!=row[2]or canonical_digest(value)!=row[3]:
        raise AuthorityUnavailable('conditioned D01 canonical signed body differs')
    read.committed_operation(db,row[1]);original=read.original(ref,kind='d01.'+kind,digest=row[3])
    return True,(plain_v1(decode_typed_production_value_v1(value,_ORIGINAL_TYPES[kind])),original)


_CONDITIONED_CHILD_SELECTORS_V3=WeakKeyDictionary()
_CONDITIONED_CHILD_FRAME_INPUTS_V3=WeakKeyDictionary()
_CONDITIONED_ACTIVE_CHILD_ISSUES_V3=WeakKeyDictionary()


def bind_current_conditioned_child_selector_v3(reader,selector):
    from ..authority_service.conditioned_child_contract_v1 import ConditionedChildSelectorV1
    from ..runtime_contracts import canonical_serialize
    from ..domains.d01.production_operations_v1 import plain_v1
    state=require_conditioned_owner_ready_v3(reader)
    if(type(selector)is not ConditionedChildSelectorV1 or reader in _CONDITIONED_CHILD_SELECTORS_V3
            or reader.read_finished or reader.business_started or reader.inputs_sealed
            or state.output_phase!='complete'or selector.namespace!=reader.namespace
            or selector.operation_id!=reader.operation_id or selector.operation_kind!=reader.operation_kind
            or selector.typed_request_json!=canonical_serialize(plain_v1(reader.request))
            or selector.typed_request_digest!=canonical_digest(reader.request)
            or selector.parent_budget_lease_ref!=reader.parent_budget_lease_ref
            or state.root_locator is None or selector.original_deadline_utc!=state.root_locator[4]
            or not set(reader.selected_plan.source_roots)<=set(selector.source_refs)
            or tuple(selector.allowed_write_keys)!=tuple(state.output_keys)):
        raise AuthorityUnavailable('conditioned child selector lost exact final own Source READ command/Root/allowed keys')
    require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
    _CONDITIONED_CHILD_SELECTORS_V3[reader]=(selector,reader.selected_plan,_identity(reader))
    return selector


class _ConditionedChildFrameInputsV3:
    def __init__(self,issuer,reader,proof,selector):
        if issuer is not _ISSUER:raise AuthorityUnavailable('conditioned child inputs require actual private Source factory')
        self.owner,self.proof,self.selector=reader,proof,selector
        self.plan,self.envelope,self.read_scope=proof.plan,proof.envelope,proof.read_scope
        _CONDITIONED_CHILD_FRAME_INPUTS_V3[self]=(reader,proof,selector,self.plan,self.envelope,self.read_scope,_identity(reader))
    def require_issued_current_v3(self,db,scope,issued):
        from .conditioned_child_issuance_v1 import require_conditioned_child_issuance_v1
        from .current_method_learning_read_v3 import _INPUTS,_method_active
        r=self.owner;state=require_conditioned_self_work_v3(r)
        evidence=require_conditioned_child_issuance_v1(issued,r.graph,scope)
        if(_CONDITIONED_CHILD_FRAME_INPUTS_V3.get(self)!=(r,self.proof,self.selector,self.plan,self.envelope,self.read_scope,_identity(r))
                or _CONDITIONED_CHILD_SELECTORS_V3.get(r)!=(self.selector,r.selected_plan,_identity(r))
                or _INPUTS.get(self.proof)!=(r,self.proof.plan,self.proof.envelope,self.proof.read_scope,self.proof.graph_stamp,self.proof.owner_rights)
                or _method_active(db)is not r or db is not r.db or scope.operation!='write'or scope is self.read_scope
                or not r.read_finished or not r.inputs_sealed or not r.business_started or state.output_phase!='complete'
                or evidence.selector!=self.selector or evidence.owner_guard!=r.material_owner_guard
                or evidence.query_epoch.revision!=r.graph_stamp[1].revision
                or(evidence.access_epoch,evidence.delete_epoch)!=(r.owner_binding.access_epoch,r.owner_binding.delete_epoch)
                or evidence.valid_until_utc>r.operation.deadline_utc
                or self.plan!=r.selected_plan or not set(self.plan.source_roots)<=set(self.selector.source_refs)):
            raise AuthorityUnavailable('conditioned child inputs lost actual paired Core WRITE/Owner/Root/epoch/Source evidence')
        entry=r.conditioned_write_owner_entry
        bind_conditioned_write_owner_entry_v3(r,scope=scope,issued=issued,entry=entry)
        _WRITES[r]=(self.proof,scope,r.owner_binding,_identity(r),r.selected_plan)
        require_conditioned_write_phase_v3(r)
        require_conditioned_sources_v3(r,r.selected_plan.source_roots)
        _CONDITIONED_ACTIVE_CHILD_ISSUES_V3[r]=(scope,issued,self.selector)
        return self
    def head_v3(self,key):return self.proof.head_v3(key)
    def inventory_v3(self,type_id):return self.proof.inventory_v3(type_id)


def read_bound_conditioned_child_frame_inputs_v3(db,*,graph,scope,plan,issued):
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3
    reader=_active(db)
    if reader is None:raise AuthorityUnavailable('conditioned child frame has no actual bound own Source Work')
    saved=_CONDITIONED_CHILD_SELECTORS_V3.get(reader)
    if(saved is None or reader.graph is not graph or db is not reader.db or plan!=reader.selected_plan
            or type(reader.result)is not PreparedMethodDomainInputsV3 or not reader.inputs_sealed or not reader.read_finished):
        raise AuthorityUnavailable('conditioned child frame requires its exact sealed own Source inputs and private selector')
    selector,_,_=saved
    result=_ConditionedChildFrameInputsV3(_ISSUER,reader,reader.result,selector)
    return result.require_issued_current_v3(db,scope,issued)


def conditioned_current_root_locator_v3(reader):
    from .issuers import BudgetLeaseGrant
    from .current_method_learning_read_v3 import read_bound_method_budget_grant_v3
    state=require_conditioned_owner_ready_v3(reader)
    if reader.inputs_sealed or reader.read_finished:
        raise AuthorityUnavailable('conditioned Root must be fully frozen before the actual Source READ input seal')
    require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
    policy=reader.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.installation_policy
    expected_root=policy.root_lease.lease_id
    chain=[];seen=set();cursor=reader.parent_budget_lease_ref
    with runtime_storage_quantum_v3(reader.db)as meter:
        while cursor is not None:
            if cursor in seen or len(chain)>=64:raise AuthorityUnavailable('conditioned actual budget ancestry is cyclic or exceeds its fixed bound')
            seen.add(cursor)
            row=meter.read_fixed_row(reader.db,'runtime_budget_leases',
                ('lease_id','parent_id','bot_id','persona_id','version','state'),'lease_id=?',(cursor,))
            if(row is None or row[0]!=cursor or tuple(row[2:4])!=reader.namespace.as_tuple
                    or type(row[4])is not int or row[4]<1 or row[5]!='active'):
                raise AuthorityUnavailable('conditioned actual parent budget ancestry is absent, foreign or inactive')
            chain.append(row)
            if cursor==expected_root:
                if row[1]is not None:raise AuthorityUnavailable('conditioned expected Root is not the actual root of this lease ancestry')
                break
            cursor=row[1]
    if not chain or chain[-1][0]!=expected_root:
        raise AuthorityUnavailable('conditioned actual parent budget does not descend from the installed Root')
    chain=tuple(chain)
    if state.budget_ancestry is not None and state.budget_ancestry!=chain:
        raise AuthorityUnavailable('conditioned actual parent/Root lease ancestry changed before input seal')
    state.budget_ancestry=chain
    handled,parent=read_bound_method_budget_grant_v3(reader.db,reader.parent_budget_lease_ref)
    if not handled:raise AuthorityUnavailable('conditioned parent budget grant lacks actual complete signed metadata')
    raw=conditioned_metadata_v3(reader.db,reader.namespace,('root_grant',(expected_root,policy.root_grant.version)))
    if raw is None:raise AuthorityUnavailable('conditioned current actual signed Root grant is absent')
    raw['allowed_work_kinds']=tuple(raw['allowed_work_kinds']);root_grant=BudgetLeaseGrant(**raw)
    now=_self_view_now_v4(reader)
    work_kind='d01.conditioned_self_child.v1'
    if(work_kind not in root_grant.allowed_work_kinds or work_kind not in parent.allowed_work_kinds
            or now>=min(parent.valid_until_utc,root_grant.valid_until_utc)):
        raise AuthorityUnavailable('conditioned actual parent/Root grant does not permit this current child work')
    result=(expected_root,root_grant.grant_id,root_grant.version,canonical_digest(root_grant),
        min(_conditioned_child_original_deadline_v3(reader),parent.valid_until_utc,root_grant.valid_until_utc))
    if state.root_locator is not None and state.root_locator!=result:
        raise AuthorityUnavailable('conditioned current signed Root descriptor changed before input seal')
    state.root_locator=result
    return result


_CONDITIONED_SCOPE_TRANSITIONS_V3=WeakKeyDictionary()
_CONDITIONED_CURRENT_READ_SELF_V3=WeakKeyDictionary()


def _require_conditioned_pending_origin_v3(locator):
    if locator.work.state is locator:return True
    saved=_CONDITIONED_SCOPE_TRANSITIONS_V3.get(locator)
    if saved is None:return False
    old,descriptor,authority,deadline,mono=saved
    return(locator.work.state is old and old.read_finished and old.operation is locator.operation
        and old.operation.deadline_utc==deadline and old.initial_monotonic_deadline==mono
        and old.current_self_descriptor==descriptor and authority.actor==old.current_self.self_entity_ref)


def _current_conditioned_self_descriptor_v3(reader):
    from dataclasses import fields
    from ..authority_service.v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
    scope=reader.fence.scope
    current=reader.graph._GraphCoordinator__self_identity_port.current_self_identity(
        namespace=reader.namespace,authority_namespace=scope.authority_namespace,
        request_operation_id=scope.operation_id,permit=scope.permit)
    policy=reader.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.installation_policy
    if(type(current)is not AuthorityCurrentSelfIdentityV1 or current.permit!=scope.permit
            or current.request_operation_id!=scope.operation_id or current.namespace!=reader.namespace
            or current.installation_id!=policy.installation_id or current.authority_namespace!=scope.authority_namespace
            or current.activation_generation!=reader.authority.activation_generation
            or current.graph_revision!=reader.graph_stamp[0].graph_revision
            or current.graph_epoch!=reader.graph_stamp[1].revision
            or current.authority_id!=reader.owner_guard.authority_id
            or current.owner_authorization_revision!=reader.owner_guard.authorization_revision
            or current.owner_authorization_head.removeprefix('sha256:')!=reader.owner_guard.authorization_head.removeprefix('sha256:')
            or current.owner_minimum_revocation_revision!=reader.owner_guard.minimum_revocation_revision
            or current.owner_revocation_epoch!=reader.owner_guard.minimum_revocation_epoch):
        raise AuthorityUnavailable('conditioned Source READ lost actual paired current Self/fence/namespace/stamp')
    descriptor=tuple((field.name,getattr(current,field.name))for field in fields(current)
        if field.name not in {'request_operation_id','permit'})
    return current,descriptor


def require_current_conditioned_self_read_identity_v3(reader):
    state=require_conditioned_self_work_v3(reader)
    if reader.session_proof is not None:return None
    saved=_CONDITIONED_CURRENT_READ_SELF_V3.get(reader)
    if saved is None or state.read_stage!='source':
        raise AuthorityUnavailable('conditioned body requires its separately issued actual Self Source READ scope')
    current,descriptor=_current_conditioned_self_descriptor_v3(reader)
    if(saved!=(descriptor,reader.fence,reader.body_authority,reader.graph_stamp)
            or current.self_entity_ref!=reader.body_authority.actor or reader.authority is not reader.body_authority):
        raise AuthorityUnavailable('conditioned Source READ Self descriptor changed after metadata scope EOF')
    reader.current_self=current;reader.current_self_descriptor=descriptor
    return current


def _transition_conditioned_source_read_scope_v3(old):
    from dataclasses import replace
    from .current_method_learning_read_v3 import begin_current_method_learning_read_v3,_READERS
    from .current_beta1_source_read_v3 import register_current_beta1_source_work_v3,release_current_beta1_source_work_v3
    from ..graph_worker import GraphStorageStepV3
    state=require_conditioned_self_work_v3(old)
    if(state.read_stage!='metadata_owner'or old.inventory_sealed or old.selected_plan is not None
            or state.source_permission is not None or old.read_finished or old.general_owner_entry is None):
        raise AuthorityUnavailable('conditioned metadata scope must end before census, Source or body')
    current,descriptor=_current_conditioned_self_descriptor_v3(old)
    old.current_self,old.current_self_descriptor=current,descriptor
    old.graph._validate_read_fence_v3(old.fence)
    old.graph._finish_read_fence_v3(old.fence);old.read_finished=True
    locator=old.conditioned_cause_locator
    authority=replace(old.authority,actor=current.self_entity_ref,purpose='consolidation')
    _CONDITIONED_SCOPE_TRANSITIONS_V3[locator]=(old,descriptor,authority,old.operation.deadline_utc,old.initial_monotonic_deadline)
    new_fence=old.graph._begin_read_fence_v3(authority,operation_id=old.operation_id+':source:'+locator.read_scope_nonce)
    capsule=_ConditionedPendingOwnerV3(_ISSUER,locator,authority=authority,fence=new_fence,
        operation_kind=old.operation_kind,request=old.request)
    reader=begin_current_method_learning_read_v3(old.graph,old.operation,new_fence,runtime=old.runtime,
        authority=authority,lease=None,operation_kind=old.operation_kind,request=old.request,
        operation_id=old.operation_id,activity_id=old.activity_id,audience_ref=old.audience_ref,
        parent_budget_lease_ref=old.parent_budget_lease_ref,request_digest=old.request_digest,
        owner_binding=None,owner_guard=None,session_proof=None,initial_now_utc=old.initial_now_utc,source_pending_owner=capsule)
    reader.work=old.work;reader.conditioned_cause_locator=locator
    reader.initial_monotonic_deadline=old.initial_monotonic_deadline
    reader.background_followup=reader.background_host_lifecycle=reader.background_offline=None
    reader.body_authority=authority;reader.current_self_descriptor=descriptor
    _SELF_VIEW_CLOCKS_V4[reader]=_SELF_VIEW_CLOCKS_V4[old]
    old.work.state=reader
    register_current_beta1_source_work_v3(reader,old.work)
    bind_pending_conditioned_reader_v3(reader,capsule)
    new_state=_STATES[reader];new_state.read_stage='source'
    cause=locator.cause_metadata
    new_state.adoption_operations.add(cause.causal_operation_id);new_state.required_domain_producers.add(cause.causal_operation_id)
    new_state.source_roots.update(cause.source_refs)
    _CONDITIONED_CURRENT_READ_SELF_V3[reader]=(descriptor,new_fence,authority,reader.graph_stamp)
    release_current_beta1_source_work_v3(old);_READERS.discard(old);_SELF_VIEW_CLOCKS_V4.pop(old,None)
    _CONDITIONED_SCOPE_TRANSITIONS_V3.pop(locator,None)
    reader.work.phase='conditioned_source_owner_eof'
    return GraphStorageStepV3('progress')


def freeze_current_conditioned_source_read_frame_v3(reader,plan):
    if reader.session_proof is not None:
        from .domain_production_frame_v1 import freeze_domain_production_frame_v1
        return freeze_domain_production_frame_v1(reader.graph,reader.db,envelope=reader.selected_envelope,
            current_owner=reader.owner_binding,scope=reader.fence.scope,plan=plan,now_utc=_self_view_now_v4(reader))
    require_conditioned_owner_ready_v3(reader)
    require_current_conditioned_self_read_identity_v3(reader)
    require_conditioned_sources_v3(reader,plan.source_roots)
    from .domain_production_frame_v1 import _materialize_current_domain_frame_v1
    from .domain_production_contracts_v1 import ProductionOperationLimitsV1
    return _materialize_current_domain_frame_v1(reader.graph,reader.db,envelope=reader.selected_envelope,
        scope=reader.fence.scope,plan=plan,prepared_inputs=None,now_utc=_self_view_now_v4(reader),
        expected_owner_guard=reader.material_owner_guard,
        expected_rights=(reader.owner_binding.access_epoch,reader.owner_binding.delete_epoch),
        observed_originals=reader.observed_originals,installed_policy_refs=reader.installed_policy_refs,
        limits=ProductionOperationLimitsV1())


def conditioned_source_required_domains_v3(operation_kind):
    if operation_kind in CONDITIONED_OPERATION_DOMAINS_V1:return frozenset(CONDITIONED_OPERATION_DOMAINS_V1[operation_kind])
    if operation_kind==CONDITIONED_SELF_READ_KIND_V4:return frozenset({'d01','d02','d06','d07','d08','d11'})
    if operation_kind==_CONDITIONED_FOLLOWUP_READ_KIND_V3:return frozenset({'d01','d02','d06','d07','d08','d10','d11'})
    raise AuthorityUnavailable('conditioned Source has no registered exact operation domains')


def require_conditioned_source_factory_reader_v3(reader,work,*,registration=False):
    from .current_method_learning_read_v3 import _MethodLearningReadV3,_READERS
    from ..graph_worker import GraphStorageWorkV3
    from .conditioned_self_operations_v1 import OWNER_CONFIGURED_CONDITIONED_OPERATIONS_V1
    if(type(reader)is not _MethodLearningReadV3 or reader not in _READERS or type(work)is not GraphStorageWorkV3
            or work.kind!=CONDITIONED_SELF_WORK_KIND_V3 or work.state is not reader or reader.work is not work
            or work.operation is not reader.operation or work.coordinator is not reader.graph
            or reader.runtime is not reader.graph._GraphCoordinator__domain_production_runtime_v1
            or reader.operation_kind not in conditioned_operation_types_v3()
            or type(reader.request)is not conditioned_operation_types_v3()[reader.operation_kind]
            or reader.fence.scope.operation!='read'or reader.projection_types or reader.preplan_families
            or reader.background_followup is not None or reader.background_host_lifecycle is not None
            or reader.background_offline is not None):
        raise AuthorityUnavailable('conditioned Source constructor/registry is outside its exact actual own Work')
    work._require_invocation(reader.graph)
    if reader.session_proof is not None:
        if(reader.operation_kind not in OWNER_CONFIGURED_CONDITIONED_OPERATIONS_V1
                and reader.operation_kind!=CONDITIONED_SELF_READ_KIND_V4):
            raise AuthorityUnavailable('Owner invocation cannot construct a conditioned producer command')
        if registration:work._require_invocation(reader.graph,initial=True)
        reader.graph._authorize(reader.lease,reader.authority,conditioned_source_required_domains_v3(reader.operation_kind),owner_read=True)
        return reader
    capsule=reader.source_pending_owner
    if capsule in _PENDING_CONDITIONED_OWNER_V3:
        require_pending_conditioned_factory_v3(capsule,graph=reader.graph,operation=reader.operation,
            fence=reader.fence,authority=reader.authority,operation_kind=reader.operation_kind,request=reader.request)
        if capsule.locator.work is not work:raise AuthorityUnavailable('conditioned pending reader crossed its actual once-admitted Work')
        return reader
    state=_STATES.get(reader)
    if state is None or state.identity!=_identity(reader)or state.owner_binding is not reader.owner_binding:
        raise AuthorityUnavailable('conditioned sessionless Source lost its actual consumed pending factory/current Owner')
    return reader


_CONDITIONED_CHILD_LOCATORS_V3=WeakKeyDictionary()


class _ConditionedChildLocatorReaderV3(_ConditionedFollowupLocatorReaderV3):
    def __init__(self,issuer,graph,bootstrap,bundle,operation,handoff,child_id,outbox_header):
        handoff.require_for_v3(graph,bootstrap,bundle)
        if child_id not in handoff.child_ids:raise AuthorityUnavailable('conditioned child factory requires an actual fixed target member')
        super().__init__(issuer,graph,bootstrap,bundle,operation,handoff.dedupe_key,outbox_header)
        index=handoff.child_ids.index(child_id)
        self.operation_kind,self.request=handoff.commands[index]
        self.prepared_targets,self.child_id=handoff,child_id
        _CONDITIONED_CHILD_LOCATORS_V3[self]=(handoff,child_id,canonical_digest(_conditioned_frozen_targets_wire_v3(handoff)))
    def advance(self,meter):
        if not super().advance(meter):return False
        prepared,child_id,digest=_CONDITIONED_CHILD_LOCATORS_V3[self]
        prepared.require_for_v3(self.graph,self.bootstrap,self.bundle)
        cause=self.cause_metadata;original=prepared.cause
        if(digest!=canonical_digest(_conditioned_frozen_targets_wire_v3(prepared))or child_id!=self.operation.operation_id
                or cause.namespace!=original.namespace or cause.causal_operation_id!=original.causal_operation_id
                or cause.event_kind!=original.event_kind or cause.trigger_ref!=original.trigger_ref
                or cause.original_digest!=original.original_digest or cause.receipt_digest!=original.receipt_digest
                or cause.parent_budget_lease_ref!=original.parent_budget_lease_ref
                or cause.original_deadline_utc!=original.original_deadline_utc or cause.source_refs!=original.source_refs):
            raise AuthorityUnavailable('conditioned actual child cause changed after its complete target census')
        return True


def prepare_current_conditioned_followup_child_v3(graph,bootstrap,bundle,*,handoff,child_id):
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from ..runtime_storage_v3 import begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,finish_runtime_storage_operation_v3
    from .first_ingress_v2 import trusted_upper
    graph._admin(bootstrap);require_graph_storage_work_admission_v3(graph)
    if type(handoff)is not ConditionedFollowupPreparedV3:raise AuthorityUnavailable('conditioned child requires actual private qualified target material')
    handoff.require_for_v3(graph,bootstrap,bundle)
    if child_id not in handoff.child_ids:raise AuthorityUnavailable('conditioned child is not an actual target census member')
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    deadline=min(now+60.0,handoff.original_deadline_utc)
    if now>=deadline:raise AuthorityUnavailable('conditioned original producer/Root deadline expired before child Source READ')
    db=graph._GraphCoordinator__store._db
    operation=begin_runtime_storage_operation_v3(db,child_id,deadline)
    try:
        with bind_runtime_storage_operation_v3(operation,db),graph._GraphCoordinator__store._lock,runtime_storage_quantum_v3(db)as meter:
            from .conditioned_producer_source_metadata_v3 import OUTBOX_HEADER_COLUMNS_V3
            header=meter.read_fixed_row(db,'graph_domain_production_outbox_v1',OUTBOX_HEADER_COLUMNS_V3,
                'bot=? AND persona=? AND dedupe_key=?',(*handoff.namespace.as_tuple,handoff.dedupe_key))
        if header is None or header[5]not in {'pending','waiting'}:
            raise AuthorityUnavailable('conditioned child actual durable producer event is no longer pending')
        reader=_ConditionedChildLocatorReaderV3(_ISSUER,graph,bootstrap,bundle,operation,handoff,child_id,header)
        work=create_graph_storage_work_v3(graph,kind=CONDITIONED_SELF_WORK_KIND_V3,operation_id=child_id,
            selection_digest=operation.selection_digest,deadline_utc=deadline,state=reader,operation=operation)
        work._require_invocation(graph,initial=True);reader.work=work
        work.phase='conditioned_child_cause_metadata_eof'
        return work
    except BaseException:
        finish_runtime_storage_operation_v3(operation);raise


def _conditioned_inline_choice_original_v3(reader):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    state=require_conditioned_owner_ready_v3(reader)
    from .current_conditioned_personal_choice_v3 import personal_choice_locator_for_reader_v3,require_personal_choice_original_v3
    personal_choice=personal_choice_locator_for_reader_v3(reader)
    if(reader.operation_kind!='select_current_conditioned_personal_step_v1'or reader.session_proof is None and personal_choice is None
            or reader.read_finished or reader.inputs_sealed or state.output_phase!='complete'):
        raise AuthorityUnavailable('conditioned inline choice needs its actual unsealed completed prepared-candidate Source Work')
    require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
    original=read_adopted_domain_operation_v1(reader.db,reader.namespace,reader.request.prepared_candidates_operation_id)
    if original is None or(original['domain'],original['operation_kind'])!=('d08','prepare_personal_candidates_v1'):
        raise AuthorityUnavailable('conditioned inline choice has no exact actual committed candidate preparation')
    prepared=decode_typed_production_value_v1(original['payload']['provenance']['prepared_candidates'],PreparedPersonalCandidateSetV1)
    if(prepared.namespace!=reader.namespace or prepared.selection_operation_id!=reader.operation_id
            or prepared.parent_budget_lease_ref!=reader.parent_budget_lease_ref
            or prepared.plan_head.key.token!=reader.request.plan_ref or prepared.goal_head.key.token!=reader.request.goal_ref):
        raise AuthorityUnavailable('conditioned inline choice changed its frozen prepared namespace, selection or original Root')
    require_personal_choice_original_v3(reader,original,prepared)
    return original,prepared


def _conditioned_child_original_deadline_v3(reader):
    if reader.session_proof is None:return condition_followup_cause_metadata_v3(reader).original_deadline_utc
    _,prepared=_conditioned_inline_choice_original_v3(reader)
    return min(row.future_identity.deadline_utc for row in prepared.candidates)


def _finalize_conditioned_inline_choice_v3(reader):
    from ..authority_service.conditioned_child_contract_v1 import ConditionedChildSelectorV1
    from ..runtime_contracts import canonical_serialize
    from ..domains.d01.production_operations_v1 import plain_v1
    state=require_conditioned_owner_ready_v3(reader)
    if reader in _CONDITIONED_CHILD_SELECTORS_V3:
        prepare_current_conditioned_attempt_metadata_v3(reader);return
    original,prepared=_conditioned_inline_choice_original_v3(reader)
    from .current_conditioned_personal_choice_v3 import restore_personal_choice_selector_v3
    if restore_personal_choice_selector_v3(reader):return
    root_lease,grant_id,grant_version,grant_digest,deadline=conditioned_current_root_locator_v3(reader)
    cap=require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
    selector=ConditionedChildSelectorV1(namespace=reader.namespace,
        installation_id=reader.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.installation_policy.installation_id,
        phase='personal_choice',operation_id=reader.operation_id,activity_id=reader.activity_id,operation_kind=reader.operation_kind,
        typed_request_json=canonical_serialize(plain_v1(reader.request)),typed_request_digest=canonical_digest(reader.request),
        producer_domain=original['domain'],producer_kind=original['operation_kind'],producer_operation_id=prepared.preparation_operation_id,
        producer_original_ref='d08-current:'+original['original_digest'][:48],producer_original_digest=original['original_digest'],
        producer_receipt_digest=canonical_digest(original['receipt']),dedupe_key=None,event_kind=None,
        targets_digest=canonical_digest((reader.operation_kind,reader.request,prepared.future_decision_ref)),
        target_census_digest=canonical_digest((prepared.read_versions,prepared.query_coverage,prepared.source_refs)),
        frozen_targets_original_ref=None,frozen_targets_original_digest=None,frozen_targets_json=None,
        parent_budget_lease_ref=reader.parent_budget_lease_ref,root_budget_lease_ref=root_lease,root_grant_id=grant_id,
        root_grant_version=grant_version,root_grant_digest=grant_digest,original_deadline_utc=deadline,purpose=reader.authority.purpose,
        audiences=reader.authority.audience,source_refs=tuple(cap.source_refs),allowed_write_keys=tuple(state.output_keys))
    bind_current_conditioned_child_selector_v3(reader,selector);prepare_current_conditioned_attempt_metadata_v3(reader)


def finalize_current_conditioned_source_inputs_v3(reader):
    """Before input seal; this only freezes a selector, never a WRITE grant."""
    state=require_conditioned_owner_ready_v3(reader)
    locator=reader.conditioned_cause_locator if reader.session_proof is None else None
    if type(locator)is not _ConditionedChildLocatorReaderV3:
        from .current_conditioned_personal_choice_v3 import personal_choice_locator_for_reader_v3
        if reader.operation_kind=='select_current_conditioned_personal_step_v1'and(reader.session_proof is not None or personal_choice_locator_for_reader_v3(reader)is not None):
            return _finalize_conditioned_inline_choice_v3(reader)
        return
    if reader in _CONDITIONED_CHILD_SELECTORS_V3:
        prepare_current_conditioned_attempt_metadata_v3(reader);return
    if state.output_phase!='complete':raise AuthorityUnavailable('conditioned child cannot freeze a partial output plan')
    prepared,child_id,_=_CONDITIONED_CHILD_LOCATORS_V3[locator]
    bind_current_conditioned_followup_child_source_v3(reader,prepared=prepared,child_id=child_id)
    root_lease,grant_id,grant_version,grant_digest,deadline=conditioned_current_root_locator_v3(reader)
    from ..authority_service.conditioned_child_contract_v1 import ConditionedChildSelectorV1
    from ..runtime_contracts import canonical_serialize
    from ..domains.d01.production_operations_v1 import plain_v1
    cause=condition_followup_cause_metadata_v3(reader)
    cap=require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
    _preload_conditioned_child_receipts_v3(reader,prepared)
    pointer=_conditioned_disposition_task_v3(reader).result
    selector=ConditionedChildSelectorV1(namespace=reader.namespace,installation_id=locator.bundle.installation_policy.installation_id,
        phase='child',operation_id=reader.operation_id,activity_id=reader.activity_id,operation_kind=reader.operation_kind,
        typed_request_json=canonical_serialize(plain_v1(reader.request)),typed_request_digest=canonical_digest(reader.request),
        producer_domain=cause.domain,producer_kind=cause.operation_kind,producer_operation_id=cause.causal_operation_id,
        producer_original_ref=cause.trigger_ref,producer_original_digest=cause.original_digest,producer_receipt_digest=cause.receipt_digest,
        dedupe_key=cause.dedupe_key,event_kind=cause.event_kind,targets_digest=prepared.targets_digest,
        target_census_digest=prepared.target_census_digest,frozen_targets_json=canonical_serialize(_conditioned_frozen_targets_wire_v3(prepared)),
        frozen_targets_original_ref=None if pointer is None else pointer['first_child_original_ref'],
        frozen_targets_original_digest=None if pointer is None else pointer['first_child_original_digest'],parent_budget_lease_ref=reader.parent_budget_lease_ref,
        root_budget_lease_ref=root_lease,root_grant_id=grant_id,root_grant_version=grant_version,root_grant_digest=grant_digest,
        original_deadline_utc=deadline,purpose=reader.authority.purpose,audiences=reader.authority.audience,
        source_refs=tuple(cap.source_refs),allowed_write_keys=tuple(state.output_keys))
    bind_current_conditioned_child_selector_v3(reader,selector)
    prepare_current_conditioned_attempt_metadata_v3(reader)


def require_conditioned_write_owner_identity_v3(reader,scope,issued):
    from .conditioned_child_issuance_v1 import require_conditioned_child_issuance_v1
    from ..authority_service.conditioned_child_contract_v1 import conditioned_child_fence_operation_id_v1
    from .current_method_learning_read_v3 import _INPUTS,_method_active,PreparedMethodDomainInputsV3
    state=require_conditioned_self_work_v3(reader)
    evidence=require_conditioned_child_issuance_v1(issued,reader.graph,scope)
    saved=_CONDITIONED_CHILD_SELECTORS_V3.get(reader)
    proof=reader.result
    if(saved is None or saved!=(evidence.selector,reader.selected_plan,_identity(reader))
            or state.output_phase!='complete'or not reader.inputs_sealed or not reader.read_finished
            or not reader.business_started or reader.business_completed or type(proof)is not PreparedMethodDomainInputsV3
            or _INPUTS.get(proof)!=(reader,proof.plan,proof.envelope,proof.read_scope,proof.graph_stamp,proof.owner_rights)
            or _method_active(reader.db)is not reader or scope.operation!='write'or scope is reader.fence.scope
            or scope.namespace!=reader.namespace or scope.operation_id!=conditioned_child_fence_operation_id_v1(evidence.selector)
            or evidence.current_self.namespace!=reader.namespace or evidence.current_self.permit!=scope.permit
            or evidence.owner_guard!=reader.material_owner_guard
            or(evidence.access_epoch,evidence.delete_epoch)!=(reader.owner_binding.access_epoch,reader.owner_binding.delete_epoch)
            or evidence.valid_until_utc>reader.operation.deadline_utc
            or evidence.selector.parent_budget_lease_ref!=reader.parent_budget_lease_ref
            or tuple(evidence.selector.allowed_write_keys)!=tuple(state.output_keys)):
        raise AuthorityUnavailable('conditioned WRITE Owner17 requires actual fresh paired Core issue and sealed same-Work Source identity')
    reader.work._require_invocation(reader.graph)
    return state


def bind_conditioned_write_owner_entry_v3(reader,*,scope,issued,entry):
    state=require_conditioned_write_owner_identity_v3(reader,scope,issued)
    owner=entry.require_for_v3(reader)
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    guard=ProductionOwnerGuardV1(owner_grant_key(*reader.namespace.as_tuple).token,
        owner.grant_revision,owner.grant_digest.removeprefix('sha256:'),owner.authorization_head.removeprefix('sha256:'))
    if(guard!=reader.material_owner_guard or entry.current_owner_guard.namespace!=reader.namespace
            or(owner.access_epoch,owner.delete_epoch)!=(reader.owner_binding.access_epoch,reader.owner_binding.delete_epoch)):
        raise AuthorityUnavailable('conditioned fresh WRITE Owner17 differs from independently sealed Source inputs')
    reader.conditioned_write_owner_entry=entry
    return owner


def conditioned_child_execution_provenance_v3(db,frame):
    reader=_active(db)
    if reader is None:return None
    saved=_CONDITIONED_ACTIVE_CHILD_ISSUES_V3.get(reader)
    if saved is None:
        if reader in _CONDITIONED_CHILD_SELECTORS_V3:
            raise AuthorityUnavailable('conditioned child stage lost its actual fresh Core issue')
        return None
    scope,issued,selector=saved
    from .conditioned_child_issuance_v1 import require_conditioned_child_issuance_v1
    from ..authority_service.conditioned_child_contract_v1 import conditioned_child_to_wire_v1
    evidence=require_conditioned_child_issuance_v1(issued,reader.graph,scope)
    require_conditioned_stage_readers_v3(db,frame,reader.installed_readers,reader.operation_kind,reader.request)
    if(evidence.selector!=selector or selector.operation_id!=frame.envelope.identity.operation_id
            or selector.operation_kind!=reader.operation_kind or selector.typed_request_digest!=canonical_digest(reader.request)
            or selector.parent_budget_lease_ref!=frame.envelope.parent_budget_lease_ref):
        raise AuthorityUnavailable('conditioned child execution provenance differs from actual paired issue and command')
    return conditioned_child_to_wire_v1(selector)


def conditioned_source_cap_registry_v3(reader):
    return require_conditioned_self_work_v3(reader).source_caps


def require_conditioned_pending_current_v3(reader,*,meter=None):
    capsule=_CONDITIONED_PENDING_READERS_V3.get(reader)
    if(capsule is None or reader.owner_binding is not None or reader.owner_guard is not None
            or reader.material_owner_guard is not None or reader.selected_plan is not None
            or reader.inventory_sealed or reader.inputs_sealed or reader.read_finished):
        raise AuthorityUnavailable('conditioned pending Owner stage allows only actual locator control, never census/body')
    require_pending_conditioned_factory_v3(capsule,graph=reader.graph,operation=reader.operation,
        fence=reader.fence,authority=reader.authority,operation_kind=reader.operation_kind,request=reader.request)
    if reader.graph._v2_graph_stamp(reader.namespace)!=reader.graph_stamp:
        raise AuthorityUnavailable('conditioned pending Owner graph stamp changed before true Owner17 EOF')
    _self_view_now_v4(reader)
    return reader


def advance_current_conditioned_child_business_v3(graph,work):
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3,_INPUTS,_BUSINESS_RESULTS,bind_prepared_method_learning_read_v3
    from .domain_production_registry_v1 import installed_operation_v1
    from .domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    from ..graph_worker import GraphStorageWorkV3,GraphStorageStepV3
    reader=require_conditioned_self_work_v3(work.state).reader
    saved=_CONDITIONED_CHILD_SELECTORS_V3.get(reader)
    proof=reader.result
    if(reader.graph is not graph or reader.work is not work or saved is None
            or saved!=(saved[0],reader.selected_plan,_identity(reader))or not reader.read_finished
            or not reader.inputs_sealed or reader.business_started or reader.business_completed
            or type(proof)is not PreparedMethodDomainInputsV3
            or _INPUTS.get(proof)!=(reader,proof.plan,proof.envelope,proof.read_scope,proof.graph_stamp,proof.owner_rights)
            or type(reader.runtime)is not InstalledDomainOperationRuntimeV1
            or reader.runtime is not graph._GraphCoordinator__domain_production_runtime_v1):
        raise AuthorityUnavailable('conditioned child WRITE must enter its one actual sealed same-Work business branch')
    operation=installed_operation_v1(reader.operation_kind)
    reader.business_started=True;work.phase='conditioned_core_child_write'
    from .conditioned_child_write_v1 import run_conditioned_child_business_v1
    with bind_runtime_storage_operation_v3(work.operation,reader.db),bind_prepared_method_learning_read_v3(proof,graph,reader.db):
        result=run_conditioned_child_business_v1(graph,reader.runtime,reader=reader,inputs=proof,
            selector=saved[0],operation=operation,request=reader.request)
    if type(result)is GraphStorageWorkV3:raise AuthorityUnavailable('conditioned same-Work business cannot create or return another Work')
    proof.business_result=result;_BUSINESS_RESULTS[proof]=(work,result)
    reader.business_completed=True;work.phase='business_completed'
    return GraphStorageStepV3('complete',proof)


def install_conditioned_child_write_readers_v3(reader,*,scope,issued,entry):
    owner=bind_conditioned_write_owner_entry_v3(reader,scope=scope,issued=issued,entry=entry)
    result=install_conditioned_self_readers_v1(reader.graph,scope=scope,owner_guard=entry.current_owner_guard,
        operation_kind=reader.operation_kind,owner_binding=owner)
    reader.installed_readers=result
    return result


_CONDITIONED_ATTEMPT_METADATA_V3=WeakKeyDictionary()


class _ConditionedControlMetadataTaskV3:
    def __init__(self,issuer,reader,identity):
        if issuer is not _ISSUER:raise AuthorityUnavailable('conditioned control metadata needs actual private constructor')
        self.reader,self.identity=reader,identity
        if identity==('attempt',reader.operation_id):
            self.profile=('graph_owner_domain_attempts_v3',('bot','persona','operation_id'),(*reader.namespace.as_tuple,reader.operation_id),
                ('request_digest','attempt_id','graph_revision','graph_epoch'),('anchor_json','permit_json','receipt_json'))
        elif identity==('disposition',condition_followup_cause_metadata_v3(reader).dedupe_key):
            self.profile=('graph_domain_production_outbox_v1',('bot','persona','dedupe_key'),(*reader.namespace.as_tuple,identity[1]),
                ('causal_operation_id','receiver_domain','event_kind','original_ref','original_digest','state','consumer_operation_id'),('receipt_json',))
        else:raise AuthorityUnavailable('conditioned control metadata escaped its exact child attempt/event')
        self.metadata=None;self.information=None;self.column_index=0;self.offset=0;self.capture=None
        self.values=[];self.complete=False;self.result=None;self.wire=None
        _CONDITIONED_ATTEMPT_METADATA_V3[self]=(reader,reader.work,reader.operation,reader.fence,identity,self.profile)
    def _actual(self):
        r=self.reader;require_conditioned_owner_ready_v3(r)
        if(_CONDITIONED_ATTEMPT_METADATA_V3.get(self)!=(r,r.work,r.operation,r.fence,self.identity,self.profile)
                or r.read_finished or r.inputs_sealed):
            raise AuthorityUnavailable('conditioned control metadata escaped its actual unsealed Source READ')
        return r
    def require_header_v3(self,meter):
        r=self._actual();table,columns,key,header,_=self.profile
        row=meter.read_fixed_row(r.db,table,header,' AND '.join(name+'=?'for name in columns),key)
        if row!=self.metadata:raise AuthorityUnavailable('conditioned durable control row changed during complete metadata EOF')
        return row
    def _information_v3(self,meter):
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2
        r=self._actual();table,columns,key,_,json_columns=self.profile
        projection=','.join('typeof('+name+'),length(CAST('+name+' AS BLOB))'for name in json_columns)
        with legacy_cell_read_transaction_v2(r.db):
            row=r.db.execute('SELECT '+projection+' FROM '+table+' WHERE '+' AND '.join(name+'=?'for name in columns),key).fetchone()
        meter.charge_read(32*len(json_columns));return row
    def advance(self,meter):
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        r=self._actual();table,key_columns,key,header,json_columns=self.profile
        if self.identity[0]=='attempt':require_conditioned_sources_v3(r,r.selected_plan.source_roots)
        if self.complete:self.require_header_v3(meter);return True
        if self.metadata is None and self.information is None:
            self.metadata=meter.read_fixed_row(r.db,table,header,' AND '.join(name+'=?'for name in key_columns),key)
            if self.metadata is None:
                if self.identity[0]=='disposition':raise AuthorityUnavailable('conditioned actual producer event disappeared')
                self.complete=True;self.result=None;return True
            self.information=self._information_v3(meter)
            if self.information is None or self.identity[0]=='attempt'and self.information[0]!='text':
                raise AuthorityUnavailable('conditioned durable control metadata is incomplete')
            return False
        self.require_header_v3(meter)
        if self._information_v3(meter)!=self.information:raise AuthorityUnavailable('conditioned control JSON physical metadata changed during EOF')
        if self.column_index==len(json_columns):
            if self.identity[0]=='attempt':
                self.result=(self.metadata[0],self.metadata[1],self.values[0],self.metadata[2],self.metadata[3],self.values[1],self.values[2])
            else:
                self.wire=self.values[0]
                if self.wire is None:
                    if self.metadata[5]!='pending'or self.metadata[6]is not None:
                        raise AuthorityUnavailable('conditioned nonvirgin event has no dedicated disposition original')
                    self.result=None
                else:
                    import json
                    value=json.loads(self.wire)
                    self.result=validate_conditioned_disposition_locator_v3(value,reader=r,header=self.metadata)
            self.complete=True;return True
        kind,total=self.information[2*self.column_index:2*self.column_index+2]
        if kind=='null':self.values.append(None);self.column_index+=1;return False
        if kind!='text'or type(total)is not int or total<0:raise AuthorityUnavailable('conditioned control JSON storage type differs')
        if self.capture is None:
            self.capture=_ConditionedLocatorJSONV3(self);self.capture.retain_path_v3=lambda path:True
        if self.offset<total:
            with legacy_cell_read_transaction_v2(r.db):
                chunk,actual,storage=read_legacy_sql_cell_fragment_v2(r.db,table=table,column=json_columns[self.column_index],
                    where=' AND '.join(name+'=?'for name in key_columns),parameters=key,start=self.offset,length=min(1024,total-self.offset),meter=meter)
            if(actual,storage)!=(total,'text'):raise AuthorityUnavailable('conditioned control JSON byte count changed')
            self.capture._reserve_v3(len(chunk)*8+65536);self.capture.parser.feed(chunk,self.capture._emit_v3)
            self.offset+=len(chunk);return False
        parsed=self.capture.parser.finish();self.capture._flush_text_v3()
        from ..contracts import canonical_json
        from hashlib import sha256
        self.capture._reserve_v3(total*8+65536);wire=canonical_json(self.capture.value)
        if parsed.byte_count!=total or parsed.sha256!=sha256(wire.encode('utf8')).hexdigest():
            raise AuthorityUnavailable('conditioned durable control metadata is not complete canonical JSON')
        r.operation.retain(len(wire)*4+128);self.values.append(wire)
        self.column_index+=1;self.offset=0;self.capture=None
        return False
    @property
    def operation(self):return self.reader.operation


def prepare_current_conditioned_attempt_metadata_v3(reader):
    from .current_method_learning_read_v3 import _need_method_input
    state=require_conditioned_owner_ready_v3(reader)
    if reader not in _CONDITIONED_CHILD_SELECTORS_V3 or reader.inputs_sealed or reader.read_finished:
        raise AuthorityUnavailable('conditioned attempt metadata must follow actual selector freeze before Source input seal')
    identity=('attempt',reader.operation_id);state.selectors.add(identity)
    task=state.tasks.get(identity)
    if task is None or not task.complete:_need_method_input(reader,('conditioned_owner_metadata',identity))
    with runtime_storage_quantum_v3(reader.db)as meter:task.require_header_v3(meter)
    return task.result


def read_bound_conditioned_child_attempt_snapshot_v3(db,*,graph,selector):
    reader=_active(db)
    if reader is None or reader.graph is not graph or _CONDITIONED_CHILD_SELECTORS_V3.get(reader)!=(selector,reader.selected_plan,_identity(reader)):
        raise AuthorityUnavailable('conditioned durable attempt requires actual private selector and same Source Work')
    if not reader.inputs_sealed or not reader.read_finished or not reader.business_started:
        raise AuthorityUnavailable('conditioned durable attempt is consumed only after real READ finish and one business entry')
    task=require_conditioned_self_work_v3(reader).tasks.get(('attempt',reader.operation_id))
    if task is None or not task.complete or _CONDITIONED_ATTEMPT_METADATA_V3.get(task)!=(reader,reader.work,reader.operation,reader.fence,task.identity,task.profile):
        raise AuthorityUnavailable('conditioned actual durable attempt metadata was not fully frozen before READ ended')
    return task.result


_CONDITIONED_DISPOSITION_SCHEMA_V3='d01.conditioned-followup-disposition.v1'
_CONDITIONED_DISPOSITION_RESOLVER_V3='conditioned-fixed-targets.v1'
_CONDITIONED_DISPOSITION_KEYS_V3=frozenset({'schema','resolver_version','namespace','dedupe_key',
    'causal_operation_id','causal_original_digest','trigger_original_digest','producer_receipt_digest',
    'manifest_digest','state','observed_epoch','completed_commands','missing_originals','continuation_ref',
    'consumer_operation_id','first_child_operation_id','first_child_original_ref','first_child_original_digest',
    'targets_digest','target_census_digest'})


def validate_conditioned_disposition_locator_v3(value,*,reader,header):
    cause=condition_followup_cause_metadata_v3(reader)
    from ..domains.d01.production_operations_v1 import plain_v1
    if(type(value)is not dict or set(value)!=_CONDITIONED_DISPOSITION_KEYS_V3
            or value['schema']!=_CONDITIONED_DISPOSITION_SCHEMA_V3
            or value['resolver_version']!=_CONDITIONED_DISPOSITION_RESOLVER_V3
            or value['namespace']!=plain_v1(reader.namespace)
            or(value['dedupe_key'],value['causal_operation_id'],value['causal_original_digest'],
                value['trigger_original_digest'],value['producer_receipt_digest'])!=(cause.dedupe_key,
                cause.causal_operation_id,cause.original_digest,cause.trigger_digest,cause.receipt_digest)
            or header[:5]!=(cause.causal_operation_id,cause.receiver_domain,cause.event_kind,cause.trigger_ref,cause.trigger_digest)
            or value['state']!=header[5]or value['state']not in {'waiting','completed'}
            or value['consumer_operation_id']!=header[6]
            or type(value['observed_epoch'])is not int or value['observed_epoch']<0
            or value['missing_originals']!=[]or value['continuation_ref']is not None
            or type(value['completed_commands'])is not list or not 1<=len(value['completed_commands'])<=16):
        raise AuthorityUnavailable('conditioned durable disposition changed its exact event, version or bounded state')
    def digest(raw):return type(raw)is str and len(raw)==64 and all(c in '0123456789abcdef'for c in raw)
    for name in('manifest_digest','first_child_original_digest','targets_digest','target_census_digest'):
        if not digest(value[name]):raise AuthorityUnavailable('conditioned disposition lacks canonical complete digest')
    if(type(value['first_child_operation_id'])is not str or not value['first_child_operation_id'].startswith('conditioned-child:')
            or type(value['first_child_original_ref'])is not str
            or value['first_child_original_ref'].split('-current:')[-1]!=value['first_child_original_digest'][:48]):
        raise AuthorityUnavailable('conditioned disposition lost its immutable first actual child original pointer')
    seen=set()
    for item in value['completed_commands']:
        if(type(item)is not dict or set(item)!={'command_digest','operation_id','receipt_digest'}
                or not digest(item['command_digest'])or not digest(item['receipt_digest'])
                or type(item['operation_id'])is not str or item['operation_id']in seen):
            raise AuthorityUnavailable('conditioned disposition changed its bounded completed receipt members')
        seen.add(item['operation_id'])
    if value['first_child_operation_id']not in seen or value['consumer_operation_id']not in seen:
        raise AuthorityUnavailable('conditioned disposition pointer is not an actual recorded completed child')
    return value


def prepare_current_conditioned_disposition_metadata_v3(reader):
    cause=condition_followup_cause_metadata_v3(reader)
    return conditioned_metadata_v3(reader.db,reader.namespace,('disposition',cause.dedupe_key))


def _conditioned_disposition_task_v3(reader):
    cause=condition_followup_cause_metadata_v3(reader)
    task=require_conditioned_self_work_v3(reader).tasks.get(('disposition',cause.dedupe_key))
    if task is None or not task.complete:
        raise AuthorityUnavailable('conditioned event progress was not completely preloaded in actual Source READ')
    return task


def _conditioned_original_ref_v3(original):
    return original['domain']+'-current:'+original['original_digest'][:48]


def _require_conditioned_frozen_original_v3(reader,original,*,pointer,expected_wire=None):
    from ..authority_service.conditioned_child_contract_v1 import validate_conditioned_frozen_targets_v1
    from .conditioned_self_operations_v1 import conditioned_request_from_wire_v1
    if(original is None or original['receipt'].status!='committed'
            or original['receipt'].operation_id!=pointer['first_child_operation_id']
            or original['original_digest']!=pointer['first_child_original_digest']
            or _conditioned_original_ref_v3(original)!=pointer['first_child_original_ref']):
        raise AuthorityUnavailable('conditioned frozen target pointer has no matching actual signed W01 original/receipt')
    provenance=original['payload']['provenance'];wire=provenance.get('conditioned_frozen_targets')
    validate_conditioned_frozen_targets_v1(wire,namespace=reader.namespace)
    cause=condition_followup_cause_metadata_v3(reader)
    if((wire['dedupe_key'],wire['causal_operation_id'],wire['event_kind'],wire['producer_original_digest'],
            wire['producer_receipt_digest'],wire['parent_budget_lease_ref'],wire['original_deadline_utc'])!=
            (cause.dedupe_key,cause.causal_operation_id,cause.event_kind,cause.original_digest,cause.receipt_digest,
                cause.parent_budget_lease_ref,cause.original_deadline_utc)
            or wire['targets_digest']!=pointer['targets_digest']or wire['target_census_digest']!=pointer['target_census_digest']
            or canonical_digest(wire)!=pointer['manifest_digest']or expected_wire is not None and wire!=expected_wire):
        raise AuthorityUnavailable('conditioned first child original changed its complete original target census')
    members=[item for item in wire['targets']if item['child_id']==original['receipt'].operation_id]
    if len(members)!=1 or original['operation_kind']!=members[0]['operation_kind']or original['payload']['request']!=members[0]['request']:
        raise AuthorityUnavailable('conditioned first child is not its actual full target tuple member')
    commitment=provenance.get('conditioned_followup_target_commitment')
    expected={'schema':'d01.conditioned-followup-target-commitment.v1','dedupe_key':cause.dedupe_key,
        'targets_digest':wire['targets_digest'],'target_census_digest':wire['target_census_digest'],
        'producer_receipt_digest':cause.receipt_digest,'child_id':original['receipt'].operation_id}
    if commitment!=expected:raise AuthorityUnavailable('conditioned first child original lost its actual target commitment')
    return wire,tuple((item['operation_kind'],conditioned_request_from_wire_v1(item['operation_kind'],item['request']))for item in wire['targets'])


_CONDITIONED_PRELOADED_CHILD_RECEIPTS_V3=WeakKeyDictionary()
_CONDITIONED_PREPARED_COMPLETIONS_V3=WeakKeyDictionary()


def _preload_conditioned_child_receipts_v3(reader,prepared):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    state=require_conditioned_owner_ready_v3(reader)
    task=_conditioned_disposition_task_v3(reader);pointer=task.result
    wire=_conditioned_frozen_targets_wire_v3(prepared)
    if pointer is not None:
        first=read_adopted_domain_operation_v1(reader.db,reader.namespace,pointer['first_child_operation_id'])
        _require_conditioned_frozen_original_v3(reader,first,pointer=pointer,expected_wire=wire)
    completed=[];originals=[]
    for target in prepared.targets:
        child_id=target['child_id'];state.adoption_operations.add(child_id)
        meta=conditioned_metadata_v3(reader.db,reader.namespace,('producer',child_id))
        if meta is None:continue
        if pointer is None:raise AuthorityUnavailable('conditioned child COMMIT has no same-transaction fixed-target disposition')
        original=read_adopted_domain_operation_v1(reader.db,reader.namespace,child_id)
        if(original is None or original['receipt'].status!='committed'or original['operation_kind']!=target['operation_kind']
                or original['payload']['request']!=target['request']
                or original['payload']['provenance'].get('conditioned_frozen_targets')!=wire):
            raise AuthorityUnavailable('conditioned completed child lost actual typed request, receipt or immutable full targets')
        expected={'schema':'d01.conditioned-followup-target-commitment.v1','dedupe_key':prepared.dedupe_key,
            'targets_digest':prepared.targets_digest,'target_census_digest':prepared.target_census_digest,
            'producer_receipt_digest':prepared.cause.receipt_digest,'child_id':child_id}
        if original['payload']['provenance'].get('conditioned_followup_target_commitment')!=expected:
            raise AuthorityUnavailable('conditioned completed child has no exact same event target commitment')
        completed.append({'command_digest':canonical_digest(target),'operation_id':child_id,
            'receipt_digest':canonical_digest(original['receipt'])})
        originals.append(original)
    if pointer is not None:
        if pointer['completed_commands']!=completed or(pointer['state']=='completed')!=(len(completed)==len(prepared.targets)):
            raise AuthorityUnavailable('conditioned disposition differs from actual complete W01 child receipts')
    frozen=(tuple(completed),tuple(originals),canonical_digest((completed,originals)),task,task.metadata,task.wire,
        canonical_digest(wire))
    _CONDITIONED_PRELOADED_CHILD_RECEIPTS_V3[reader]=frozen
    _CONDITIONED_PREPARED_COMPLETIONS_V3[prepared]=tuple(item['operation_id']for item in completed)
    return frozen


def conditioned_followup_pending_children_v3(prepared,*,graph,bootstrap,bundle):
    prepared.require_for_v3(graph,bootstrap,bundle)
    completed=_CONDITIONED_PREPARED_COMPLETIONS_V3.get(prepared)
    if completed is None:raise AuthorityUnavailable('conditioned async driver has no verified complete child receipt census')
    return tuple(child_id for child_id in prepared.child_ids if child_id not in completed)


def record_conditioned_followup_child_disposition_after_cas_v3(witness,db,*,frame,stage,receipt,original):
    from .domain_production_commit_v1 import _ACTIVE,_ProductionCommitWitnessV1
    from .conditioned_child_issuance_v1 import require_conditioned_child_issuance_v1
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    from ..runtime_contracts import CommitReceipt
    from ..runtime_contracts import canonical_serialize
    reader=_active(db)
    if reader is None or reader not in _CONDITIONED_CHILD_TARGETS_V3:
        raise AuthorityUnavailable('conditioned postCAS maintenance has no actual own child Source binding')
    scope,issued,selector=_CONDITIONED_ACTIVE_CHILD_ISSUES_V3[reader]
    evidence=require_conditioned_child_issuance_v1(issued,reader.graph,scope)
    prepared,child_id,_=_CONDITIONED_CHILD_TARGETS_V3[reader]
    prepared.require_for_v3(reader.graph,prepared.bootstrap,prepared.bundle)
    saved=_CONDITIONED_PRELOADED_CHILD_RECEIPTS_V3.get(reader)
    if(type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness
            or witness.graph is not reader.graph or witness.runtime is not reader.runtime or witness.scope is not scope
            or witness.frame is not frame or witness.stage is not stage or witness.request!=reader.request
            or witness.operation.operation_kind!=reader.operation_kind or frame.envelope.identity.operation_id!=child_id
            or not db.in_transaction or db is not reader.db or type(receipt)is not CommitReceipt
            or receipt.status!='committed'or receipt.operation_id!=child_id or receipt.operation_digest!=witness.bundle.digest
            or type(original)is not ProductionOriginalRefV1 or original.original_digest!=stage.original_digest
            or original.original_ref!=stage.domain+'-current:'+stage.original_digest[:48]
            or evidence.selector!=selector or saved is None):
        raise AuthorityUnavailable('conditioned outbox progress requires the actual active same-TX W01 witness and original member')
    completed,originals,digest,task,header,old_wire,targets_hash=saved
    if(canonical_digest((completed,originals))!=digest or targets_hash!=canonical_digest(_conditioned_frozen_targets_wire_v3(prepared))
            or child_id in {item['operation_id']for item in completed}):
        raise AuthorityUnavailable('conditioned postCAS changed preloaded child receipts or full canonical actual original')
    import json
    payload=json.loads(stage.original_payload_json)
    if(payload['provenance'].get('conditioned_frozen_targets')!=_conditioned_frozen_targets_wire_v3(prepared)
            or payload['provenance'].get('conditioned_followup_target_commitment')!={'schema':'d01.conditioned-followup-target-commitment.v1',
                'dedupe_key':prepared.dedupe_key,'targets_digest':prepared.targets_digest,
                'target_census_digest':prepared.target_census_digest,'producer_receipt_digest':prepared.cause.receipt_digest,'child_id':child_id}):
        raise AuthorityUnavailable('conditioned postCAS original does not seal the full prepared target set')
    entries={item['operation_id']:item for item in completed}
    target=next(item for item in prepared.targets if item['child_id']==child_id)
    entries[child_id]={'command_digest':canonical_digest(target),'operation_id':child_id,'receipt_digest':canonical_digest(receipt)}
    ordered=[entries[item['child_id']]for item in prepared.targets if item['child_id']in entries]
    previous=task.result;cause=prepared.cause
    first_id=child_id if previous is None else previous['first_child_operation_id']
    first_ref=original.original_ref if previous is None else previous['first_child_original_ref']
    first_digest=original.original_digest if previous is None else previous['first_child_original_digest']
    from ..domains.d01.production_operations_v1 import plain_v1
    value={'schema':_CONDITIONED_DISPOSITION_SCHEMA_V3,'resolver_version':_CONDITIONED_DISPOSITION_RESOLVER_V3,
        'namespace':plain_v1(reader.namespace),'dedupe_key':prepared.dedupe_key,'causal_operation_id':cause.causal_operation_id,
        'causal_original_digest':cause.original_digest,'trigger_original_digest':cause.trigger_digest,
        'producer_receipt_digest':cause.receipt_digest,'manifest_digest':canonical_digest(_conditioned_frozen_targets_wire_v3(prepared)),
        'state':'completed'if len(ordered)==len(prepared.targets)else'waiting','observed_epoch':reader.graph_stamp[1].revision,
        'completed_commands':ordered,'missing_originals':[],'continuation_ref':None,'consumer_operation_id':child_id,
        'first_child_operation_id':first_id,'first_child_original_ref':first_ref,'first_child_original_digest':first_digest,
        'targets_digest':prepared.targets_digest,'target_census_digest':prepared.target_census_digest}
    new_header=(*header[:5],value['state'],child_id)
    validate_conditioned_disposition_locator_v3(value,reader=reader,header=new_header)
    cursor=db.execute('UPDATE graph_domain_production_outbox_v1 SET state=?,consumer_operation_id=?,receipt_json=? '
        'WHERE bot=? AND persona=? AND dedupe_key=? AND causal_operation_id=? AND receiver_domain=? AND event_kind=? '
        'AND original_ref=? AND original_digest=? AND state=? AND consumer_operation_id IS ? AND receipt_json IS ?',
        (value['state'],child_id,canonical_serialize(value),*reader.namespace.as_tuple,prepared.dedupe_key,*header,old_wire))
    if cursor.rowcount!=1:raise AuthorityUnavailable('conditioned durable event changed before same-TX postCAS maintenance')
    return value
