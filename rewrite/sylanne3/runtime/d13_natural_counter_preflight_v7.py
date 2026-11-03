"""Finite original-operation CPU preparation, accounting and generation handoffs."""
from dataclasses import asdict, dataclass
from math import isfinite
from weakref import WeakKeyDictionary
import base64
import json

from ..authority_service.d13_core_counter_contract_v1 import (
    D13CurrentFramePrepareSelectorV7,D13CurrentWireCountSelectorV1,D13CoreFrameIntentHeaderV7,
    D13CounterCPUPrepareInstructionV1,D13CounterAwaitingAccountingV1,D13CoreFullWireEnvelopeV1,
    d13_core_counter_from_wire_v1,verify_signed_d13_core_wire_evidence_v1)
from ..host.d13_core_counter_port_v1 import InstalledD13CoreCounterPortV1
from ..runtime_contracts import VersionedRef,canonical_digest,canonical_serialize
from ..contracts import canonical_json
from ..domains.d08.natural_plan import natural_plan_id_v2,natural_plan_key_v2
from ..model_broker.natural_reply_history_v7 import TEMPLATE_VERSION
from ..graph_worker import GraphStorageWorkV3,require_graph_storage_work_admission_v3
from ..graph_storage_handoff_v3 import issue_graph_storage_handoff_v3
from .first_ingress_v2 import trusted_upper

_CONSUMERS=frozenset({'generation_only','generation_with_pressure'})
_COMMAND_SCHEMA='sylanne3.d13.natural-preflight-handoff.v7'
_COMMAND_FIELDS=frozenset({'schema','stage','installation_id','manifest_digest','policy_digest',
    'c02_operation_id','source_ref','terminal_consumer','deadline_utc','prepare_selector',
    'instruction','frame','count_selector','awaiting','receipt'})
_RESUME_KEY=object()
_RESUMES=WeakKeyDictionary()


@dataclass(frozen=True,slots=True)
class D13CountedNaturalPreflightV7:
    frame:D13CoreFrameIntentHeaderV7
    selector:D13CurrentWireCountSelectorV1
    envelope:D13CoreFullWireEnvelopeV1


@dataclass(frozen=True,slots=True)
class D13NaturalPreparationTerminalV1:
    saved:object
    pressure:object
    def __post_init__(self):
        from .natural_reply_job_v2 import SavedNaturalPreparationV2
        from .d13_deterministic_applicability_v3 import D13CurrentPressureOriginalsV1
        if type(self.saved)is not SavedNaturalPreparationV2 or self.saved.stage!='generation':
            raise TypeError('actual generation preparation terminal required')
        if self.pressure is not None:
            if type(self.pressure)is not D13CurrentPressureOriginalsV1:
                raise TypeError('actual same-call signed pressure originals required')
            frame=self.pressure.counter_envelope.payload.frame
            if (self.saved.seal.call_id,self.saved.seal.c02_operation_id,self.saved.seal.installation_id)!=(
                    frame.generation_call_id,frame.c02_operation_id,frame.install_id):
                raise ValueError('generation terminal pressure belongs to another actual call')


class _D13NaturalGenerationResumeV7:
    def __init__(self,key):
        if key is not _RESUME_KEY:raise TypeError('actual counted generation continuation required')


def _installed_preflight_v7(graph,bootstrap,bundle,consumer):
    graph._admin(bootstrap)
    require_graph_storage_work_admission_v3(graph)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if (consumer not in _CONSUMERS or assembly is None or assembly.admin_bundle is not bundle
            or bundle.model_workflows.natural_generation.template_version!=TEMPLATE_VERSION):
        raise ValueError('preflight requires its actual installed V7 generation consumer')
    store=graph._GraphCoordinator__store
    if store._db.in_transaction:
        raise ValueError('counter continuation must precede the generation business transaction')
    port=graph._GraphCoordinator__content_fence_v2
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    if now>=bundle.installation_policy.root_grant.valid_until_utc:
        raise ValueError('original installed Root deadline expired before counter continuation')
    return port,InstalledD13CoreCounterPortV1(port,policy=bundle.d13_wire_policy),now


def _require_frame_v7(bundle,selector,frame,now,deadline):
    if (type(frame)is not D13CoreFrameIntentHeaderV7 or frame.policy_digest!=bundle.d13_wire_policy.policy_digest
            or (frame.install_id,frame.authority_namespace,frame.namespace,frame.c02_operation_id,
                frame.plan_ref,frame.counter_operation_id)!=(selector.install_id,selector.authority_namespace,
                selector.namespace,selector.c02_operation_id,selector.plan_ref,selector.counter_operation_id)
            or not frame.frozen_at_utc<=now<min(deadline,frame.expires_at_utc)):
        raise ValueError('counter continuation changed its original frame or absolute deadline')


def _require_prepare_receipt_v7(receipt,instruction):
    if (type(receipt)is not dict or set(receipt)!={'schema','frame_intent_id','counter_operation_id',
            'instruction_digest','input_digest','binding_digest','prepared_digest','job_id','status'}
            or (receipt['schema'],receipt['frame_intent_id'],receipt['counter_operation_id'],
                receipt['instruction_digest'],receipt['input_digest'],receipt['job_id'],receipt['status'])!=(
                'sylanne3.d13.counter-cpu-preparation-receipt.v1',instruction.frame_intent_id,
                instruction.counter_operation_id,canonical_digest(instruction),instruction.input_digest,
                instruction.job_id,'prepared')):
        raise ValueError('CPU preparation terminal differs from its original instruction')
    for name in ('binding_digest','prepared_digest'):
        value=receipt[name]
        if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):
            raise ValueError('CPU preparation original commitment is incomplete')


def _require_accounting_receipt_v7(receipt,frame,awaiting):
    if (type(receipt)is not dict or set(receipt)!={'schema','frame_intent_id','operation_id','binding_digest',
            'cpu_original_digest','body_original_digest','graph_receipt_digest','job_id','status'}
            or (receipt['schema'],receipt['frame_intent_id'],receipt['operation_id'],receipt['binding_digest'],
                receipt['job_id'],receipt['status'])!=('sylanne3.d13.counter-accounting-receipt.v1',
                frame.frame_intent_id,frame.counter_operation_id,awaiting.binding_digest,frame.job_id,awaiting.status)
            or awaiting.status not in {'completed','failed'}):
        raise ValueError('CPU accounting terminal differs from its original completed frame')
    for name in ('cpu_original_digest','body_original_digest','graph_receipt_digest'):
        value=receipt[name]
        if name=='body_original_digest' and value is None and awaiting.status=='failed':continue
        if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):
            raise ValueError('CPU accounting original commitment is incomplete')


def _command_v7(bundle,*,stage,c02_operation_id,source_ref,terminal_consumer,deadline,
        selector,instruction=None,frame=None,count_selector=None,awaiting=None):
    return {'schema':_COMMAND_SCHEMA,'stage':stage,
        'installation_id':bundle.installation_policy.installation_id,
        'manifest_digest':bundle.installation_policy.manifest_digest,'policy_digest':bundle.d13_wire_policy.policy_digest,
        'c02_operation_id':c02_operation_id,'source_ref':source_ref,'terminal_consumer':terminal_consumer,
        'deadline_utc':deadline,'prepare_selector':asdict(selector),
        'instruction':None if instruction is None else asdict(instruction),
        'frame':None if frame is None else asdict(frame),
        'count_selector':None if count_selector is None else asdict(count_selector),
        'awaiting':None if awaiting is None else asdict(awaiting),'receipt':None}


def _handoff_after_cpu_v7(graph,work,command):
    if type(work)is not GraphStorageWorkV3 or work.coordinator is not graph:
        raise TypeError('actual installed CPU producer Work required')
    command['deadline_utc']=min(command['deadline_utc'],work.deadline_utc)
    def completed(receipt):
        from ..graph_storage_handoff_v3 import _TERMINAL_RETENTION
        actual=_TERMINAL_RETENTION.get()
        parent=work if actual is None else actual[0]
        if (type(parent)is not GraphStorageWorkV3 or parent.coordinator is not graph
                or parent.ticket!=work.ticket or not parent.terminal or not parent._finish_called
                or parent.phase!='complete' or parent.operation.closed
                or actual is not None and actual[1]is not parent.operation):
            raise ValueError('CPU continuation lost its actual retained terminal Work')
        parent._require_invocation(graph)
        if command['stage']=='after_cpu_prepare':
            from .current_graph_full_read_v3 import require_actual_d13_counter_prepare_terminal_v1
            from .d13_counter_prepare_owner_v1 import (KIND as OWNER_METADATA_KIND,
                require_d13_counter_owner_recovered_receipt_v1)
            instruction=d13_core_counter_from_wire_v1(command['instruction'],D13CounterCPUPrepareInstructionV1)
            _require_prepare_receipt_v7(receipt,instruction)
            if parent.kind=='current_graph_full_read_v3':
                if parent is not work and work.kind!=OWNER_METADATA_KIND:
                    raise ValueError('CPU preparation terminal has another original Owner parent')
                original=parent.state.d13_counter_instruction
                if original!=instruction:
                    raise ValueError('CPU preparation child replaced its original instruction')
                require_actual_d13_counter_prepare_terminal_v1(parent,instruction=original,receipt=receipt)
            elif parent is work and parent.kind==OWNER_METADATA_KIND:
                require_d13_counter_owner_recovered_receipt_v1(parent,instruction=instruction,receipt=receipt)
            else:
                raise ValueError('CPU preparation terminal is not its actual FULL or readonly original Work')
        else:
            if parent is not work or parent.kind!='c04_body_accounting_inputs_v3':
                raise ValueError('CPU accounting terminal is not its actual original resource Work')
            frame=d13_core_counter_from_wire_v1(command['frame'],D13CoreFrameIntentHeaderV7)
            awaiting=d13_core_counter_from_wire_v1(command['awaiting'],D13CounterAwaitingAccountingV1)
            _require_accounting_receipt_v7(receipt,frame,awaiting)
        command['deadline_utc']=min(command['deadline_utc'],parent.deadline_utc)
        command['receipt']=dict(receipt)
        wire=canonical_json(command).encode('utf-8')
        if len(wire)>262144:raise ValueError('CPU continuation locator exceeds its original handoff bound')
        port=graph._GraphCoordinator__content_fence_v2
        now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
        return issue_graph_storage_handoff_v3(parent,factory=_resume_d13_natural_generation_preflight_v7,
            command=wire,deadline_utc=command['deadline_utc'],observed_utc=now)
    def failed(error):raise error
    return work.map_terminal_v3('service',completed,failed)


def _resume_d13_natural_generation_preflight_v7(graph,wire):
    if type(wire)is not bytes or not 0<len(wire)<=262144:
        raise ValueError('closed bounded CPU continuation bytes required')
    command=json.loads(wire)
    if (type(command)is not dict or set(command)!=_COMMAND_FIELDS or canonical_json(command).encode('utf-8')!=wire
            or command['schema']!=_COMMAND_SCHEMA or command['stage']not in {'after_cpu_prepare','after_accounting'}
            or type(command['deadline_utc'])not in(int,float)or not isfinite(command['deadline_utc'])):
        raise ValueError('CPU continuation changed its closed original metadata')
    bootstrap=graph._GraphCoordinator__bootstrap
    bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    _,client,now=_installed_preflight_v7(graph,bootstrap,bundle,command['terminal_consumer'])
    if ((command['installation_id'],command['manifest_digest'],command['policy_digest'])!=(
            bundle.installation_policy.installation_id,bundle.installation_policy.manifest_digest,
            bundle.d13_wire_policy.policy_digest)or now>=command['deadline_utc']
            or command['deadline_utc']>bundle.installation_policy.root_grant.valid_until_utc):
        raise ValueError('CPU continuation crossed its original installation or Root deadline')
    selector=d13_core_counter_from_wire_v1(command['prepare_selector'],D13CurrentFramePrepareSelectorV7)
    if (selector.install_id!=command['installation_id']or selector.namespace!=bundle.installation_policy.namespace
            or selector.c02_operation_id!=command['c02_operation_id']):
        raise ValueError('CPU continuation changed its original C02 selector')
    if command['stage']=='after_cpu_prepare':
        if any(command[name]is not None for name in ('frame','count_selector','awaiting')):
            raise ValueError('CPU preparation continuation carries another phase original')
        instruction=d13_core_counter_from_wire_v1(command['instruction'],D13CounterCPUPrepareInstructionV1)
        return _after_cpu_prepare_v7(graph,bootstrap,bundle,client,selector,instruction,command['receipt'],
            command['source_ref'],command['terminal_consumer'],command['deadline_utc'])
    if command['instruction']is not None:
        raise ValueError('CPU accounting continuation cannot restart preparation')
    frame=d13_core_counter_from_wire_v1(command['frame'],D13CoreFrameIntentHeaderV7)
    count_selector=d13_core_counter_from_wire_v1(command['count_selector'],D13CurrentWireCountSelectorV1)
    awaiting=d13_core_counter_from_wire_v1(command['awaiting'],D13CounterAwaitingAccountingV1)
    _require_frame_v7(bundle,selector,frame,now,command['deadline_utc'])
    return _after_accounting_v7(graph,bootstrap,bundle,client,frame,count_selector,awaiting,command['receipt'],
        command['source_ref'],command['terminal_consumer'],command['deadline_utc'])


def _after_cpu_prepare_v7(graph,bootstrap,bundle,client,selector,instruction,receipt,source_ref,consumer,deadline):
    _require_prepare_receipt_v7(receipt,instruction)
    if (instruction.install_id,instruction.authority_namespace,instruction.namespace,instruction.c02_operation_id,
            instruction.plan_ref,instruction.counter_operation_id)!=(selector.install_id,selector.authority_namespace,
            selector.namespace,selector.c02_operation_id,selector.plan_ref,selector.counter_operation_id):
        raise ValueError('CPU preparation continuation replaced its original selector')
    frame=client.prepare_current_d13_frame_v7(selector)
    port=graph._GraphCoordinator__content_fence_v2
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    _require_frame_v7(bundle,selector,frame,now,deadline)
    if (frame.frame_intent_id,frame.frame_intent_digest,frame.job_id,frame.generation_call_id,
            frame.owner_responsibility_digest,frame.source_scope_digest,frame.parent_budget_lease_ref,
            frame.expires_at_utc)!=(instruction.frame_intent_id,instruction.frame_intent_digest,instruction.job_id,
            instruction.generation_call_id,instruction.owner_responsibility_digest,instruction.source_scope_digest,
            instruction.parent_budget_lease_ref,instruction.expires_at_utc):
        raise ValueError('prepared Core header changed its actual original instruction')
    return _count_prepared_frame_v7(graph,bootstrap,bundle,client,selector,frame,source_ref,consumer,deadline,
        expected_binding=receipt['binding_digest'])


def _count_prepared_frame_v7(graph,bootstrap,bundle,client,selector,frame,source_ref,consumer,deadline,*,expected_binding=None):
    port=graph._GraphCoordinator__content_fence_v2
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    _require_frame_v7(bundle,selector,frame,now,deadline)
    count_selector,result=client.count_original_header_v7(frame=frame,now_utc=now)
    if type(result)is D13CoreFullWireEnvelopeV1:
        if expected_binding is not None and result.payload.cpu_worker_binding_digest!=expected_binding:
            raise ValueError('count evidence replaced its original prepared CPU binding')
        return _resume_generation_v7(graph,bootstrap,bundle,frame,count_selector,result,source_ref,consumer,deadline)
    if (type(result)is not D13CounterAwaitingAccountingV1 or result.status not in {'completed','failed'}
            or expected_binding is not None and result.binding_digest!=expected_binding):
        raise ValueError('original CPU terminal is unresolved or failed; no generation admission')
    receipt=graph.settle_current_d13_counter_cpu_v1(bootstrap,bundle,
        frame_intent_id=frame.frame_intent_id,counter_operation_id=frame.counter_operation_id,awaiting=result)
    if type(receipt)is GraphStorageWorkV3:
        command=_command_v7(bundle,stage='after_accounting',c02_operation_id=frame.c02_operation_id,
            source_ref=source_ref,terminal_consumer=consumer,deadline=min(deadline,frame.expires_at_utc),
            selector=selector,frame=frame,count_selector=count_selector,awaiting=result)
        return _handoff_after_cpu_v7(graph,receipt,command)
    return _after_accounting_v7(graph,bootstrap,bundle,client,frame,count_selector,result,receipt,
        source_ref,consumer,deadline)


def _after_accounting_v7(graph,bootstrap,bundle,client,frame,selector,awaiting,receipt,source_ref,consumer,deadline):
    _require_accounting_receipt_v7(receipt,frame,awaiting)
    if awaiting.status!='completed':
        raise ValueError('original failed CPU was accounted but yields no generation evidence')
    port=graph._GraphCoordinator__content_fence_v2
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    if now>=min(deadline,frame.expires_at_utc):
        raise ValueError('accounted-only continuation exceeded its original frame deadline')
    envelope=client.read_or_finalize_accounted_d13_wire_v1(selector,frame=frame,awaiting=awaiting,
        accounting_receipt=receipt,now_utc=now)
    return _resume_generation_v7(graph,bootstrap,bundle,frame,selector,envelope,source_ref,consumer,deadline)


def _resume_generation_v7(graph,bootstrap,bundle,frame,selector,envelope,source_ref,consumer,deadline):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from ..authority_service.d13_current_pressure_mapping_v1 import SIGNING_DOMAIN
    from .d13_deterministic_applicability_v3 import D13CurrentPressureOriginalsV1
    port=graph._GraphCoordinator__content_fence_v2
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    if now>=min(deadline,frame.expires_at_utc):raise ValueError('original counted frame expired before generation')
    verify_signed_d13_core_wire_evidence_v1(bundle.d13_wire_policy,envelope,selector=selector,frame=frame,now_utc=now)
    pressure=None
    if consumer=='generation_with_pressure':
        mapping=port.read_current_d13_pressure_mapping_v1(frame=frame)
        if mapping is not None:
            payload=mapping.payload
            if (mapping.key_id!=bundle.d13_wire_policy.counter_key_id
                    or payload.counter_evidence_digest!=envelope.evidence_digest
                    or payload.collection_digest!=frame.collection_digest
                    or payload.collection_snapshot_commitment!=frame.collection_snapshot_commitment
                    or not payload.frozen_at_utc<=now<payload.expires_at_utc):
                raise ValueError('pressure original differs from its same-call counted frame')
            key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(bundle.d13_wire_policy.counter_public_key_hex))
            key.verify(base64.b64decode(mapping.signature,validate=True),
                SIGNING_DOMAIN+canonical_serialize(payload).encode('utf-8'))
            pressure=D13CurrentPressureOriginalsV1(bundle.d13_wire_policy,envelope,mapping)
    counted=D13CountedNaturalPreflightV7(frame,selector,envelope)
    resume=_D13NaturalGenerationResumeV7(_RESUME_KEY)
    ticket=require_graph_storage_work_admission_v3(graph)
    _RESUMES[resume]=(graph,bundle,ticket,frame.c02_operation_id,source_ref,consumer,
        min(deadline,frame.expires_at_utc),counted,pressure)
    try:
        return graph._prepare_post_c02_natural_generation_v2(bootstrap,frame.namespace,frame.c02_operation_id,
            source_ref,bundle,d13_resume=resume,terminal_consumer=consumer)
    finally:
        _RESUMES.pop(resume,None)


def _require_d13_natural_generation_resume_record_v7(value,graph,bundle,*,c02_operation_id,source_ref,terminal_consumer):
    record=_RESUMES.get(value)if type(value)is _D13NaturalGenerationResumeV7 else None
    ticket=require_graph_storage_work_admission_v3(graph)
    if (record is None or record[:6]!=(graph,bundle,ticket,c02_operation_id,source_ref,terminal_consumer)
            or graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not bundle):
        raise ValueError('generation requires its exact once-only counted continuation')
    port=graph._GraphCoordinator__content_fence_v2
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    if now>=record[6]:raise ValueError('counted generation continuation exceeded its original deadline')
    return record


def require_d13_natural_generation_resume_deadline_v7(value,graph,bundle,*,c02_operation_id,source_ref,terminal_consumer):
    return _require_d13_natural_generation_resume_record_v7(value,graph,bundle,
        c02_operation_id=c02_operation_id,source_ref=source_ref,terminal_consumer=terminal_consumer)[6]


def require_d13_natural_generation_resume_v7(value,graph,bundle,*,c02_operation_id,source_ref,terminal_consumer):
    record=_require_d13_natural_generation_resume_record_v7(value,graph,bundle,
        c02_operation_id=c02_operation_id,source_ref=source_ref,terminal_consumer=terminal_consumer)
    _RESUMES.pop(value)
    return record[7],record[8]


def begin_d13_natural_generation_preflight_v7(graph,bootstrap,bundle,*,c02_operation_id,source_ref,terminal_consumer):
    _,client,now=_installed_preflight_v7(graph,bootstrap,bundle,terminal_consumer)
    store=graph._GraphCoordinator__store;ns=bundle.installation_policy.namespace
    with store._lock:
        rows=store._db.execute('SELECT activity_id FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
            (*ns.as_tuple,c02_operation_id)).fetchall()
        if len(rows)!=1:raise ValueError('actual C02 bundle metadata locator is absent or ambiguous')
        metadata,_=graph._v2_graph_stamp(ns)
        plan_key=natural_plan_key_v2(ns,rows[0][0],natural_plan_id_v2(ns,c02_operation_id,source_ref))
    operation='d13-count:'+canonical_digest({'schema':'sylanne3.d13.first-counter-operation.v7','namespace':ns,
        'installation_id':bundle.installation_policy.installation_id,'parent':c02_operation_id,'source_ref':source_ref})[:48]
    selector=D13CurrentFramePrepareSelectorV7(bundle.installation_policy.installation_id,
        metadata.requirements.authority_namespace,ns,c02_operation_id,VersionedRef(plan_key.token,1),operation)
    graph._recover_current_d13_counter_write_ack_v1(bootstrap,bundle,selector)
    graph._GraphCoordinator__local_module_admission.require_v1(('d13',),'prepare_current_d13_natural_preflight_v7')
    frame=client.prepare_current_d13_frame_v7(selector)
    deadline=min(bundle.installation_policy.root_grant.valid_until_utc,frame.expires_at_utc)
    if type(frame)is D13CounterCPUPrepareInstructionV1:
        receipt=graph.prepare_current_d13_counter_cpu_v1(bootstrap,bundle,instruction=frame)
        if type(receipt)is GraphStorageWorkV3:
            command=_command_v7(bundle,stage='after_cpu_prepare',c02_operation_id=c02_operation_id,
                source_ref=source_ref,terminal_consumer=terminal_consumer,deadline=deadline,
                selector=selector,instruction=frame)
            return _handoff_after_cpu_v7(graph,receipt,command)
        return _after_cpu_prepare_v7(graph,bootstrap,bundle,client,selector,frame,receipt,source_ref,
            terminal_consumer,deadline)
    _require_frame_v7(bundle,selector,frame,now,deadline)
    return _count_prepared_frame_v7(graph,bootstrap,bundle,client,selector,frame,source_ref,terminal_consumer,deadline)


def record_counted_d13_preflight_v7(db,*,bundle,counted,now_utc):
    from ..authority_service.d13_wire_evidence_v7 import (install_d13_core_wire_evidence_schema_v1,
        record_signed_d13_core_wire_evidence_v1)
    if type(counted)is not D13CountedNaturalPreflightV7 or not db.in_transaction:
        raise ValueError('Core count original import requires the actual generation short transaction')
    install_d13_core_wire_evidence_schema_v1(db)
    return record_signed_d13_core_wire_evidence_v1(db,policy=bundle.d13_wire_policy,
        selector=counted.selector,frame=counted.frame,envelope=counted.envelope,now_utc=now_utc)
