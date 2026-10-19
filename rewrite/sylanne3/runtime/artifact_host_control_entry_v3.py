"""Finite Source READ -> current W01 -> independent receipt READ continuation.

The detached command and receipt locators convey no Source permission. Every
child uses the real installed runtime and its own current Core/Owner/Source path.
"""
from contextvars import ContextVar
from dataclasses import dataclass
from weakref import WeakKeyDictionary
import json
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..graph_worker import GraphStorageWorkV3,require_graph_storage_work_admission_v3
from ..graph_storage_handoff_v3 import issue_graph_storage_handoff_v3
from .first_ingress_v2 import trusted_upper

_ACTIVE=ContextVar('sylanne_artifact_control_execution_v3',default=None)
_EXECUTIONS=WeakKeyDictionary()


@dataclass(frozen=True,eq=False,slots=True,weakref_slot=True)
class _ControlExecutionV3:
    graph:object
    runtime:object
    selector:object
    request:object
    entry_kind:str
    after:str
    preparation_task:object
    arguments:tuple
    completed_receipts:tuple


def _require_execution_v3(execution):
    expected=_EXECUTIONS.get(execution)
    if expected is None or expected!=(execution.graph,execution.runtime,execution.selector,
            execution.request,execution.entry_kind,execution.after,execution.preparation_task,
            execution.arguments,execution.completed_receipts):
        raise AuthorityUnavailable('Artifact command lost its exact installed private continuation')
    if execution.runtime is not execution.graph._GraphCoordinator__domain_production_runtime_v1:
        raise AuthorityUnavailable('Artifact command changed its actual installed runtime')
    return execution


def current_control_execution_v3(runtime,selector):
    execution=_ACTIVE.get()
    if execution is None:return None
    _require_execution_v3(execution)
    if execution.runtime is not runtime or execution.selector!=selector:
        raise AuthorityUnavailable('Artifact current command crossed its exact foreground request')
    return execution


def borrowed_control_preparation_task_v3(reader):
    execution=reader.write_context.get('control_execution')
    if execution is None:return None
    _require_execution_v3(execution)
    if(execution.graph is not reader.graph or execution.runtime is not reader.runtime
            or execution.selector!=reader.selector or execution.request!=reader.request
            or execution.selector.operation_kind!=reader.operation_kind):
        raise AuthorityUnavailable('Artifact preparation locator crossed its actual borrowed Work')
    return execution.preparation_task


@dataclass(frozen=True,slots=True)
class _CommittedControlResultV3:
    execution:object
    result:dict
    original_selector_digest:str


def control_committed_result_v3(runtime,selector,result,execution,*,original_selector_digest):
    if execution is None:return False,None
    _require_execution_v3(execution)
    if execution.runtime is not runtime or execution.selector!=selector:
        raise AuthorityUnavailable('Artifact W01 result crossed its original command')
    _require_committed_wrapper_v3(execution,result)
    # This result stays inside the private pipeline. The independent post-commit
    # current READ controls disclosure; this is not an Owner receipt shortcut.
    return True,_CommittedControlResultV3(execution,result,original_selector_digest)


def _require_committed_wrapper_v3(execution,result):
    from .domain_production_originals_v1 import _receipt
    if type(result)is _CommittedControlResultV3:
        if result.execution is not execution:raise AuthorityUnavailable('Committed Artifact result crossed its actual private command')
        result=result.result
    if(type(result)is not dict or result.get('schema')!='sylanne.domain-production-receipt.v1'
            or result.get('operation_kind')!=execution.selector.operation_kind
            or result.get('operation_id')!=execution.selector.operation_id):
        raise AuthorityUnavailable('Artifact command has no actual same-operation W01 wrapper')
    receipt=_receipt(result['receipt'])
    if(receipt.status!='committed'or receipt.operation_id!=execution.selector.operation_id
            or result['receipt_digest']!=canonical_digest(receipt)):
        raise AuthorityUnavailable('Artifact result lost its immutable original committed receipt')
    return receipt


def _base_v3(graph,bootstrap,bundle):
    graph._admin(bootstrap);require_graph_storage_work_admission_v3(graph)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is not bundle:
        raise AuthorityUnavailable('Artifact entry requires its actual installed assembly')
    return bundle.installation_policy


def start_artifact_control_entry_v3(graph,bootstrap,bundle,*,entry_kind,c02_operation_id,source_ref,arguments=()):
    from .artifact_host_control_metadata_v3 import (ArtifactEntryPrepareSelectorV3,
        prepare_current_artifact_entry_metadata_v3)
    policy=_base_v3(graph,bootstrap,bundle)
    from .artifact_host_control_algorithms_v3 import normalize_artifact_entry_arguments_v3
    arguments=normalize_artifact_entry_arguments_v3(entry_kind,arguments)
    selector=ArtifactEntryPrepareSelectorV3(namespace=policy.namespace,installation_id=policy.installation_id,
        c02_operation_id=c02_operation_id,source_ref=source_ref,entry_kind=entry_kind,arguments=tuple(arguments))
    work=prepare_current_artifact_entry_metadata_v3(graph,bootstrap,bundle,selector=selector)
    return _map_control_work_v3(work)


def _wire_entry_v3(selector):
    from ..domains.d01.production_operations_v1 import plain_v1
    return {'entry_kind':selector.entry_kind,'c02_operation_id':selector.c02_operation_id,
        'source_ref':selector.source_ref,'stage':selector.stage,
        'completed_receipts':plain_v1(selector.completed_receipts)}


def _map_control_work_v3(work):
    from .artifact_host_control_algorithms_v3 import ArtifactControlCommandV3,ArtifactControlValueV3,ArtifactControlNextV3
    def consume(value):
        reader=work.state;q=reader.selector
        if type(value)is ArtifactControlValueV3:return value.value
        now=trusted_upper(reader.graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
            reader.graph._GraphCoordinator__scene_clock_policy))
        if type(value)is ArtifactControlCommandV3:
            raise AuthorityUnavailable('command must be sealed with its actual selector inside the completed Source algorithm')
        if type(value)is _SealedControlCommandV3:
            command=_command_wire_v3(q,value)
            deadline=value.selector.requested_deadline_utc
            return issue_graph_storage_handoff_v3(work,factory=_start_formal_command_v3,
                command=canonical_serialize(command).encode(),deadline_utc=deadline,observed_utc=now)
        if type(value)is ArtifactControlNextV3:
            command={'schema':'artifact.control-next.v3','base':_wire_entry_v3(q),
                'entry_kind':value.entry_kind,'stage':value.stage,'arguments':value.arguments,
                'business_deadline_utc':_business_deadline_v3(reader)}
            if value.completed_receipts is not None:
                command['base']['completed_receipts']=value.completed_receipts
            return issue_graph_storage_handoff_v3(work,factory=_start_next_entry_v3,
                command=canonical_serialize(command).encode(),deadline_utc=command['business_deadline_utc'],observed_utc=now)
        raise AuthorityUnavailable('Artifact control produced no registered terminal value or command')
    def failed(error):raise error
    work.map_terminal_v3('service',consume,failed)
    return work


@dataclass(frozen=True,slots=True)
class _SealedControlCommandV3:
    selector:object
    command:object
    arguments:tuple=()


def seal_artifact_control_command_v3(reader,state,command,*,arguments=()):
    from .artifact_host_control_algorithms_v3 import ArtifactControlCommandV3,read_artifact_foreground_selector_v3
    if type(command)is not ArtifactControlCommandV3:
        raise TypeError('Exact finite Artifact command recipe required')
    # Runs before Source READ completion, while its actual points and metadata
    # are still qualified. The returned selector is a locator, not WRITE rights.
    if command.preparation_task is None:
        selector=read_artifact_foreground_selector_v3(reader,state,
            operation_kind=command.operation_kind,request=command.request)
    else:
        from .artifact_phase_postconditions_v1 import (
            prepare_candidate_preparation_parent_for_graph_v3,activate_candidate_preparation_parent_for_graph_v3)
        from .d08_personal_candidate_v1 import CurrentArtifactTaskChoiceRequestV2
        from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
        from .artifact_phase_postconditions_v1 import install_artifact_phase_postcondition_readers_v1
        graph=reader.graph;model=graph._GraphCoordinator__artifact_draft_model_runtime_v1
        model_readers=InstalledArtifactDraftModelReadersV1(graph._GraphCoordinator__d11_issuer,reader.bundle,model)
        installed=install_artifact_phase_postcondition_readers_v1(graph=graph,bootstrap=reader.bootstrap,
            bundle=reader.bundle,model_readers=model_readers)
        with reader.store._lock:
            reader.db.execute('BEGIN')
            try:
                handle,_=prepare_candidate_preparation_parent_for_graph_v3(graph,
                    request=CurrentArtifactTaskChoiceRequestV2(command.preparation_task),installed_readers=installed)
            finally:reader.db.rollback()
        with activate_candidate_preparation_parent_for_graph_v3(graph,handle=handle):
            selector=read_artifact_foreground_selector_v3(reader,state,
                operation_kind=command.operation_kind,request=command.request)
    return _SealedControlCommandV3(selector,command,tuple(arguments))


def _command_wire_v3(entry,sealed):
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..authority_service.current_foreground_activity_v1 import (ForegroundActivityRequestV1,
        ForegroundActivityRequestV2,ForegroundActivityPreparationParentRequestV2)
    tag={ForegroundActivityRequestV1:'v1',ForegroundActivityRequestV2:'v2',
        ForegroundActivityPreparationParentRequestV2:'parent_v2'}[type(sealed.selector)]
    return {'schema':'artifact.control-command.v3','entry':_wire_entry_v3(entry),
        'selector_kind':tag,'selector':plain_v1(sealed.selector),
        'operation_kind':sealed.command.operation_kind,'request':plain_v1(sealed.command.request),
        'after':sealed.command.after,'preparation_task':plain_v1(sealed.command.preparation_task),
        'arguments':plain_v1(sealed.arguments)}


def _decode_command_v3(graph,command):
    from ..authority_service.current_foreground_activity_v1 import (ForegroundActivityRequestV1,
        ForegroundActivityRequestV2,ForegroundActivityPreparationParentRequestV2,
        foreground_typed_command_digest_v1)
    from .domain_production_registry_v1 import installed_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1 as typed
    from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
    from .artifact_host_control_algorithms_v3 import _AFTER_STAGES_V3,_ENTRY_FIELDS_V3,normalize_artifact_entry_arguments_v3
    raw=json.loads(command)
    if(raw['schema']!='artifact.control-command.v3'or raw['after']not in _AFTER_STAGES_V3
            or raw['entry']['entry_kind']not in _ENTRY_FIELDS_V3):
        raise ValueError('Artifact handoff changed its fixed command or continuation recipe')
    cls={'v1':ForegroundActivityRequestV1,'v2':ForegroundActivityRequestV2,
        'parent_v2':ForegroundActivityPreparationParentRequestV2}[raw['selector_kind']]
    selector=typed(raw['selector'],cls);operation=installed_operation_v1(raw['operation_kind'])
    request=typed(raw['request'],operation.request_type)
    if(selector.operation_kind!=operation.operation_kind
            or selector.request_digest!=foreground_typed_command_digest_v1(operation,request)
            or selector.c02_operation_id!=raw['entry']['c02_operation_id']
            or selector.cue_source_ref!=raw['entry']['source_ref']):
        raise AuthorityUnavailable('Artifact detached command changed its actual typed selector/C02/Source')
    runtime=graph._GraphCoordinator__domain_production_runtime_v1
    policy=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.installation_policy
    if(selector.namespace,selector.installation_id)!=(policy.namespace,policy.installation_id):
        raise AuthorityUnavailable('Artifact command crossed its actual installation namespace')
    task=None if raw['preparation_task']is None else typed(raw['preparation_task'],ArtifactDraftTaskSelectorV1)
    execution=_ControlExecutionV3(graph,runtime,selector,request,raw['entry']['entry_kind'],raw['after'],task,
        normalize_artifact_entry_arguments_v3(raw['entry']['entry_kind'],raw['arguments']),tuple(tuple(item)for item in raw['entry']['completed_receipts']))
    _EXECUTIONS[execution]=(graph,runtime,selector,request,execution.entry_kind,execution.after,task,
        execution.arguments,execution.completed_receipts)
    return execution


def _business_deadline_v3(reader):
    from .artifact_host_control_metadata_v3 import control_state_for_dispatch_v3
    state=control_state_for_dispatch_v3(reader)
    if state is None:raise AuthorityUnavailable('Actual control Work required for original business deadline')
    # The seed's business facts are original; the temporary READ window cannot
    # become a new execution deadline.
    return state.seed.business_deadline_v3()


def _post_descriptor_v3(execution,result):
    from .artifact_host_control_metadata_v3 import ArtifactPostCommitReadSelectorV3
    receipt=_require_committed_wrapper_v3(execution,result);s=execution.selector
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(result)is not _CommittedControlResultV3 or result.execution is not execution:
        raise AuthorityUnavailable('Post-commit control requires its actual private W01 result')
    return ArtifactPostCommitReadSelectorV3(namespace=s.namespace,installation_id=s.installation_id,
        c02_operation_id=s.c02_operation_id,source_ref=s.cue_source_ref,entry_kind=execution.entry_kind,
        arguments=execution.arguments,stage=execution.after,completed_receipts=execution.completed_receipts,
        operation_id=s.operation_id,operation_kind=s.operation_kind,request_digest=result.original_selector_digest,
        command_digest=canonical_digest(plain_v1(execution.request)),receipt_digest=canonical_digest(receipt),
        write_versions=receipt.write_versions,business_deadline_utc=s.requested_deadline_utc)


def _start_post_read_v3(graph,command):
    from .artifact_host_control_metadata_v3 import ArtifactPostCommitReadSelectorV3,prepare_current_artifact_post_commit_metadata_v3
    raw=json.loads(command)
    if raw['schema']!='artifact.control-post-read.v3':raise ValueError('Exact Artifact receipt READ command required')
    from .artifact_host_control_algorithms_v3 import artifact_post_commit_selector_from_wire_v3
    selector=artifact_post_commit_selector_from_wire_v3(raw['selector'])
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    work=prepare_current_artifact_post_commit_metadata_v3(graph,graph._GraphCoordinator__domain_production_runtime_v1._bootstrap,
        assembly.admin_bundle,selector=selector)
    return _map_control_work_v3(work)


def _start_formal_command_v3(graph,command):
    from ..domains.d01.production_operations_v1 import plain_v1
    execution=_decode_command_v3(graph,command)
    token=_ACTIVE.set(execution)
    try:result=execution.runtime.run_foreground_current(selector=execution.selector,
        operation_kind=execution.selector.operation_kind,request=execution.request)
    finally:_ACTIVE.reset(token)
    if type(result)is GraphStorageWorkV3:
        def committed(actual):
            selector=_post_descriptor_v3(execution,actual)
            now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
            return issue_graph_storage_handoff_v3(result,factory=_start_post_read_v3,
                command=canonical_serialize({'schema':'artifact.control-post-read.v3','selector':plain_v1(selector)}).encode(),
                deadline_utc=selector.business_deadline_utc,observed_utc=now)
        def failed(error):raise error
        result.map_terminal_v3('issuer',committed,failed)
        return result
    selector=_post_descriptor_v3(execution,result)
    return _start_post_read_v3(graph,canonical_serialize({'schema':'artifact.control-post-read.v3','selector':plain_v1(selector)}).encode())


def _start_next_entry_v3(graph,command):
    from .artifact_host_control_metadata_v3 import ArtifactEntryPrepareSelectorV3,prepare_current_artifact_entry_metadata_v3
    raw=json.loads(command)
    if raw['schema']!='artifact.control-next.v3':raise ValueError('Exact bounded next Artifact entry required')
    runtime=graph._GraphCoordinator__domain_production_runtime_v1;bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    policy=bundle.installation_policy;base=raw['base']
    from .artifact_host_control_algorithms_v3 import normalize_artifact_entry_arguments_v3
    arguments=normalize_artifact_entry_arguments_v3(raw['entry_kind'],raw['arguments'])
    selector=ArtifactEntryPrepareSelectorV3(namespace=policy.namespace,installation_id=policy.installation_id,
        c02_operation_id=base['c02_operation_id'],source_ref=base['source_ref'],entry_kind=raw['entry_kind'],
        arguments=arguments,stage=raw['stage'],completed_receipts=tuple(tuple(row)for row in base['completed_receipts']))
    work=prepare_current_artifact_entry_metadata_v3(graph,runtime._bootstrap,bundle,selector=selector)
    if work.deadline_utc>raw['business_deadline_utc']:
        work.deadline_utc=work.operation.deadline_utc=raw['business_deadline_utc']
    return _map_control_work_v3(work)
