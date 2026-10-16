"""Exact Owner W09 selection, inert prepared input and fresh formal Source Work.

A prepared command is a readonly intent DTO, never current state or authority.
The freeze call requalifies the same exact command and cannot silently select a
new phase on retry. Named node preparation resolves its real frozen Original in
one ordinary worker call and starts its actual Work in a second ordinary call.
"""
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from ..graph_types import AtomKey
from ..graph_worker import OwnedGraphStorageResultV3,GraphStorageWorkV3
from ..runtime_contracts import NamespaceId,canonical_digest
from ..runtime.named_joint_node_descriptor_v3 import NamedJointNodeDescriptorV1,prepare_named_joint_descriptor_v3
from ..runtime.named_joint_command_selection_v1 import JointCommandSelectionV1,JointCommandSelectionResultV1,prepare_joint_command_selection_v1
from ..runtime.joint_window_command_v1 import FreezeJointWindowNodeCommandRequestV1

ACTION='prepare_current_joint_window_node_v1'
INPUT_FIELDS=frozenset({'window_ref','node_id'})
PREPARE_ACTION='prepare_current_joint_window_command_v1'
PREPARE_FIELDS=frozenset({'long_plan_ref','joint_plan_ref','node_id','executor_kind','input_original_ref','role_ref'})
FREEZE_ACTION='freeze_current_joint_window_command_v1'
FREEZE_FIELDS=frozenset({'prepared'})
_DOMAINS=('d03','d05','d06','d07','d08','d10','d11','d12')
_HANDOFFS=WeakKeyDictionary()
class _NamedNodeHandoffV1:pass

def validate_named_joint_node_input_v1(data):
    if type(data)is not dict or set(data)!=INPUT_FIELDS or type(data['node_id'])is not str or not 1<=len(data['node_id'])<=192:
        raise ValueError('Select one actual adopted Window node')
    if AtomKey.from_token(data['window_ref']).type_name!='d08.joint_window.v1':raise ValueError('Select an actual typed Window')
    return data['window_ref'],data['node_id']

def validate_joint_command_selection_input_v1(data):
    if type(data)is not dict or set(data)!=PREPARE_FIELDS:raise ValueError('Exact prospective business selection fields required')
    return JointCommandSelectionV1(**data)

def _prepared_digest(namespace,selection,request):
    return canonical_digest(('d12.prepared-joint-command.v1',namespace,selection,request))

def validate_frozen_joint_command_input_v1(data,namespace):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..runtime.joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
    if type(data)is not dict or set(data)!=FREEZE_FIELDS:raise ValueError('The exact readonly prepared intent is required')
    prepared=data['prepared']
    if type(prepared)is not dict or set(prepared)!={'schema','selection','request','digest'}or prepared['schema']!='d12.prepared-joint-command.v1':raise ValueError('Prepared command exact fields differ')
    selection=validate_joint_command_selection_input_v1(prepared['selection'])
    request=decode_typed_production_value_v1(prepared['request'],FreezeJointWindowNodeCommandRequestV1)
    binding=request.command.binding;artifact=type(binding)is JointArtifactProspectiveBindingV1
    selected_ref=binding.task_scope_ref if artifact else binding.prospective_original_ref
    if(binding.namespace!=namespace or binding.node_id!=selection.node_id or binding.plan_ref!=selection.joint_plan_ref
            or selected_ref!=selection.input_original_ref or('draft_file'if artifact else 'contact')!=selection.executor_kind
            or artifact and binding.role_ref!=selection.role_ref
            or prepared['digest']!=_prepared_digest(namespace,selection,request)):
        raise ValueError('Prepared command changed its fixed business selection or exact immutable request')
    return selection,request

def _grant(issuer,session,scope,purpose,audience,*,domains=('d06','d08','d10','d11')):
    from ..runtime_context import RuntimeContext
    context=issuer._runtime_context
    if(type(context)is not RuntimeContext or context._v2_coordinator is not issuer._coordinator
            or type(session.owner_session_request)is not OwnerSessionLoginRequestV1 or not session.owner_session_token
            or purpose!='context'or audience!='owner'
            or any(not session.allows(scope,cap,purpose,audience)for cap in('workbench.read','workbench.create'))):
        raise AuthorityUnavailable('Named command needs actual RuntimeContext and current signed Owner read/create')
    grant=issuer._resolve(session,scope,purpose,audience,domains=domains)
    if grant is None or not {'workbench.read','workbench.create'}<=set(grant.capabilities):raise AuthorityUnavailable('Named command current Owner authority is unavailable')
    return grant

def _raise(error):raise error

def named_node_error_v1(error):
    from .service import ApiResponse
    from ..runtime.d01_production_operations_v1 import MissingProductionOriginalV1
    if isinstance(error,(AuthorityUnavailable,MissingProductionOriginalV1,ValueError)):
        return ApiResponse(status='unavailable',problem={'code':'joint_node_input_hold','message':str(error)[:768],'retryable':False})
    return ApiResponse(status='unavailable',problem={'code':'joint_node_provider_failed','message':'当前原件读取或提交未完成；原请求身份需保留并另行核对。','retryable':False})

def execute_prepared_joint_command_v1(issuer,*,session,scope,purpose,audience,operation_id,input_data):
    from ..domains.d01.production_operations_v1 import plain_v1
    selection=validate_joint_command_selection_input_v1(input_data)
    grant=_grant(issuer,session,scope,purpose,audience,domains=_DOMAINS)
    for ref in(selection.long_plan_ref,selection.joint_plan_ref,selection.role_ref):
        if ref is not None and NamespaceId.from_key(AtomKey.from_token(ref))!=grant.authority.namespace:raise ValueError('Prospective business selection crossed actual Owner scope')
    work=prepare_joint_command_selection_v1(issuer._coordinator,grant.authority,grant.lease,selection)
    def selected(value):
        if type(value)is not JointCommandSelectionResultV1 or value.selection!=selection:raise AuthorityUnavailable('Prospective intent differs from its actual complete Source READ')
        prepared={'schema':'d12.prepared-joint-command.v1','selection':plain_v1(selection),'request':plain_v1(value.request),
            'digest':_prepared_digest(grant.authority.namespace,selection,value.request)}
        return {'status':'ready','projection':{'schema':'d12.prepared-joint-command-view.v1','scope':scope,
            'operation_id':operation_id,'prepared':prepared}}
    return work.map_terminal_v3('issuer',selected,_raise)

def execute_frozen_joint_command_v1(issuer,*,session,scope,purpose,audience,operation_id,input_data):
    from ..runtime.joint_window_command_v1 import OPERATION,joint_window_command_ref_v1,joint_window_command_freeze_operation_id_v1
    from ..runtime.joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
    from ..runtime.foreground_cycle_v1 import foreground_cycle_ids_v1
    gate=_grant(issuer,session,scope,purpose,audience,domains=_DOMAINS)
    selection,request=validate_frozen_joint_command_input_v1(input_data,gate.authority.namespace)
    binding=request.command.binding;artifact=type(binding)is JointArtifactProspectiveBindingV1
    if not session.allows(scope,'workbench.create',binding.purpose,'owner'):raise AuthorityUnavailable('Actual executor purpose lacks current signed Owner create')
    grant=issuer._resolve(session,scope,binding.purpose,'owner',domains=_DOMAINS)
    if grant is None or 'workbench.create'not in grant.capabilities:raise AuthorityUnavailable('Current prospective command Owner authority is unavailable')
    actual_operation=joint_window_command_freeze_operation_id_v1(binding.namespace,request.command)
    activity=foreground_cycle_ids_v1(binding.namespace,binding.executor.c02_operation_id)[0]if artifact else AtomKey.from_token(binding.action_ref).owner.subject
    work=issuer._coordinator.run_current_domain_operation_v1(grant.authority,grant.lease,operation_kind=OPERATION,
        request=request,operation_id=actual_operation,activity_id=activity,audience_ref='owner',parent_budget_lease_ref=binding.parent_budget_lease_ref)
    if type(work)is not GraphStorageWorkV3:raise AuthorityUnavailable('Frozen command requires its actual serial Source Work')
    request_digest=canonical_digest(request.command);frozen_ref=joint_window_command_ref_v1(binding.namespace,request_digest)
    input_ref,input_digest=(binding.task_scope_ref,binding.task_scope_digest)if artifact else(binding.prospective_original_ref,binding.prospective_original_digest)
    def receipt(value):
        produced=tuple(v for v in value.get('produced_originals',())if v.get('original_ref')==frozen_ref)if type(value)is dict else ()
        if(type(value)is not dict or value.get('operation_id')!=actual_operation or value.get('receipt',{}).get('status')!='committed'or len(produced)!=1):
            raise AuthorityUnavailable('Frozen command has no actual signed same-W01 Original receipt')
        return {'status':'ready','receipt':{'schema':'d12.frozen-joint-command-receipt.v1','operation_id':operation_id,'actual_operation_id':actual_operation,
            'command_original_ref':frozen_ref,'command_original_digest':produced[0]['original_digest'],'node_id':binding.node_id,
            'executor_kind':selection.executor_kind,'typed_input_original_ref':input_ref,'typed_input_original_digest':input_digest,
            'typed_request_digest':request_digest,'original_digest':canonical_digest(value),'original':value}}
    return work.map_terminal_v3('issuer',receipt,_raise)

def execute_named_joint_node_v1(issuer,*,session,scope,purpose,audience,operation_id,input_data):
    window,node=validate_named_joint_node_input_v1(input_data);grant=_grant(issuer,session,scope,purpose,audience)
    if NamespaceId.from_key(AtomKey.from_token(window))!=grant.authority.namespace:raise ValueError('Selected Window crossed the exact Owner scope')
    work=prepare_named_joint_descriptor_v3(issuer._coordinator,grant.authority,grant.lease,window_ref=window,node_id=node)
    def selected(value):
        if type(value)is not NamedJointNodeDescriptorV1 or value.argument.window_ref!=window or value.argument.node_id!=node:raise AuthorityUnavailable('Named node descriptor differs from actual selected identities')
        proof=_NamedNodeHandoffV1();_HANDOFFS[proof]={'graph':issuer._coordinator,'context':issuer._runtime_context,'session':session,
            'scope':scope,'purpose':purpose,'audience':audience,'operation_id':operation_id,'descriptor':value,'ticket':work.ticket,'state':'selected'}
        return proof
    return work.map_terminal_v3('issuer',selected,_raise)

def named_node_service_terminal_v1(value):
    if type(value)is not _NamedNodeHandoffV1 or value not in _HANDOFFS:raise AuthorityUnavailable('Named node has no exact owned descriptor handoff')
    return value

def take_named_joint_node_handoff_v1(response):
    if type(response)is not OwnedGraphStorageResultV3:return None
    with response._lock:
        proof=response._value
        if type(proof)is not _NamedNodeHandoffV1:return None
        record=_HANDOFFS.get(proof)
        if record is None or record['state']!='selected':raise AuthorityUnavailable('Named node descriptor ownership was already moved')
        record['state']='enqueued'
    value,lease=response.take_value_v3();record['retention']=lease
    return value

def abandon_named_joint_node_handoff_v1(proof):
    record=_HANDOFFS.pop(proof,None)
    if record is not None:record['retention'].release()

def resume_named_joint_node_v1(issuer,proof):
    from ..graph_worker import require_graph_storage_work_admission_v3
    from ..runtime.joint_window_management_v1 import prepare_current_joint_window_node_v1
    from .service import ApiResponse
    record=_HANDOFFS.get(proof)
    if(record is None or record['state']!='enqueued'or record['graph']is not issuer._coordinator or record['context']is not issuer._runtime_context
            or require_graph_storage_work_admission_v3(issuer._coordinator)==record['ticket']):raise AuthorityUnavailable('Named node requires its actual second ordinary worker invocation')
    try:
        _grant(issuer,record['session'],record['scope'],record['purpose'],record['audience'])
        descriptor=record['descriptor'];work=prepare_current_joint_window_node_v1(issuer._coordinator,issuer._runtime_context,descriptor.argument,descriptor.command)
        if type(work)is not GraphStorageWorkV3:raise AuthorityUnavailable('Named preparation returned no actual serial Source Work')
        def receipt(value):
            if(type(value)is not dict or value.get('operation_id')!=work.operation_id or value.get('receipt',{}).get('status')!='committed'):raise AuthorityUnavailable('Named node returned no actual successful W01 receipt')
            return {'schema':'d12.named-joint-node-receipt.v1','operation_id':record['operation_id'],'actual_operation_id':work.operation_id,
                'window_ref':descriptor.argument.window_ref,'node_id':descriptor.argument.node_id,'command_original_ref':descriptor.frozen_original_ref,
                'command_original_digest':descriptor.frozen_original_digest,'original_digest':canonical_digest(value),'original':value}
        work.map_terminal_v3('issuer',receipt,_raise)
        return work.map_terminal_v3('service',lambda value:ApiResponse(status='ready',receipt=value),named_node_error_v1)
    finally:_HANDOFFS.pop(proof,None);record['retention'].release()
