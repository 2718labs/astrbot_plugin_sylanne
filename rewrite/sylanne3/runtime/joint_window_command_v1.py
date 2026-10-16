"""Immutable command commitment before a descriptive managed Window is born.

This producer freezes the original command only. It creates neither an executor
binding/index nor an Action, quote, reservation, job or provider invocation.
"""
from dataclasses import dataclass
import json
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1,stage_result_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1
from .joint_node_execution_v1 import RegisterJointNodeExecutionBindingRequestV1,JointContactProspectiveBindingV1,decode_joint_binding_v1
from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1

PRODUCER='freeze_joint_window_node_command_v1'
OPERATION='input:'+PRODUCER
KIND='joint_window_node_command_v1'


def joint_window_command_freeze_operation_id_v1(namespace,command):
    return 'joint-window-command-freeze:'+canonical_digest(('d10.joint-window-command-freeze.v1',namespace,command))[:48]


def joint_window_command_ref_v1(namespace,request_digest):
    return 'joint-window-command:'+canonical_digest((namespace,request_digest))[:48]


@dataclass(frozen=True,slots=True)
class FreezeJointWindowNodeCommandRequestV1:
    command:RegisterJointNodeExecutionBindingRequestV1
    def __post_init__(self):
        if type(self.command)is not RegisterJointNodeExecutionBindingRequestV1 or type(self.command.binding)not in {JointArtifactProspectiveBindingV1,JointContactProspectiveBindingV1}:
            raise TypeError('Freeze selects one complete actual prospective registration command')


@dataclass(frozen=True,slots=True)
class JointWindowNodeCommandOriginalV1:
    namespace:NamespaceId
    command:RegisterJointNodeExecutionBindingRequestV1
    executor_kind:str
    typed_input_original_ref:str
    typed_input_original_digest:str
    typed_request_digest:str
    parent_grant_ref:str
    parent_grant_digest:str
    original_deadline_utc:float
    source_refs:tuple[str,...]
    source_purpose_groups:tuple[tuple[str,tuple[str,...],tuple[str,...]],...]
    producing_operation_id:str
    schema:str='d10.joint-window-node-command.v1'
    def __post_init__(self):
        FreezeJointWindowNodeCommandRequestV1(self.command)
        binding=self.command.binding
        expected=('draft_file',binding.task_scope_ref,binding.task_scope_digest)if type(binding)is JointArtifactProspectiveBindingV1 else('contact',binding.prospective_original_ref,binding.prospective_original_digest)
        if(self.schema!='d10.joint-window-node-command.v1'or self.namespace!=binding.namespace
                or(self.executor_kind,self.typed_input_original_ref,self.typed_input_original_digest)!=expected
                or self.typed_request_digest!=canonical_digest(plain_v1(self.command))
                or(self.parent_grant_ref,self.parent_grant_digest,self.original_deadline_utc,self.source_refs)!=
                    (binding.parent_budget_lease_ref,binding.parent_grant_digest,binding.original_deadline_utc,binding.source_refs)
                or not self.producing_operation_id or not self.source_purpose_groups
                or {ref for _,_,roots in self.source_purpose_groups for ref in roots}!=set(self.source_refs)
                or any(purpose not in {'context','expression','consolidation'}or audiences!=binding.audience or not roots for purpose,audiences,roots in self.source_purpose_groups)):
            raise ValueError('Frozen command must preserve the exact existing input/Root/deadline commitment')
    @property
    def original_ref(self):return joint_window_command_ref_v1(self.namespace,self.typed_request_digest)
    @property
    def digest(self):return canonical_digest(self)


def qualify_joint_window_command_v1(db,*,frame,request,readers):
    if type(request)is not FreezeJointWindowNodeCommandRequestV1:raise TypeError('Exact typed freeze command required')
    from .current_joint_window_source_read_v3 import _binding_input
    read=CurrentDomainReadV1(frame);read.check(db)
    binding=request.command.binding;issuer=readers.issuer
    if frame.envelope.identity.operation_id!=joint_window_command_freeze_operation_id_v1(binding.namespace,request.command):
        raise ValueError('Frozen command producer preserves its one exact namespace/command operation identity')
    if type(binding)is JointArtifactProspectiveBindingV1:
        from .joint_artifact_execution_v1 import require_installed_artifact_joint_contract_v1
        require_installed_artifact_joint_contract_v1(binding,readers=readers)
    kind,ref,digest,_=_binding_input(db,read,binding,issuer)
    grant=issuer.current_budget_grant(db,binding.parent_budget_lease_ref)
    if(grant.grant_id,grant.version,canonical_digest(grant))!=(binding.parent_grant_id,binding.parent_grant_version,binding.parent_grant_digest):
        raise MissingProductionOriginalV1('actual_original_parent_grant_for_frozen_joint_command')
    if type(binding)is JointArtifactProspectiveBindingV1:
        from .d11_artifact_draft_contract_v1 import WORK_KIND as FILE_KIND
        required={FILE_KIND}
        if binding.executor.phase_selector is not None:
            from ..model_broker.artifact_draft_v1 import WORK_KIND as MODEL_KIND
            required.add(MODEL_KIND)
        if not required<=set(grant.allowed_work_kinds):raise MissingProductionOriginalV1('actual_original_root_did_not_admit_artifact_routes')
    if frame.envelope.parent_budget_lease_ref!=binding.parent_budget_lease_ref or frame.envelope.deadline_utc>binding.original_deadline_utc:
        raise ValueError('Freezing cannot replace the existing parent Root or extend its original deadline')
    if type(binding)is JointArtifactProspectiveBindingV1:
        groups=(('consolidation',binding.audience,binding.source_refs),)
    else:
        from .contact_prospective_v1 import read_contact_prospective_original_v1
        from .joint_contact_preparation_v1 import read_current_joint_contact_preparation_v1
        birth=read_contact_prospective_original_v1(db,issuer,binding.namespace,binding.contact_id)
        raw=json.loads(birth.payload_json)
        preparation=read_current_joint_contact_preparation_v1(db,namespace=binding.namespace,original_ref=raw['joint_preparation']['ref'],issuer=issuer)
        purposes=dict(preparation.source_purpose_groups)
        groups=tuple((purpose,binding.audience,tuple(ref for ref in binding.source_refs if purpose in purposes[ref]))for purpose in ('context','expression')if any(purpose in purposes[ref]for ref in binding.source_refs))
    return JointWindowNodeCommandOriginalV1(binding.namespace,request.command,kind,ref,digest,
        canonical_digest(plain_v1(request.command)),binding.parent_budget_lease_ref,binding.parent_grant_digest,
        binding.original_deadline_utc,binding.source_refs,groups,frame.envelope.identity.operation_id)


def stage_freeze_joint_window_command_v1(db,*,frame,request,registration,readers):
    from .domain_production_inputs_v1 import StagedDomainInputV1
    value=qualify_joint_window_command_v1(db,frame=frame,request=request,readers=readers)
    stage=stage_result_v1(frame,'d10',OPERATION,request,provenance={
        'producer_kind':PRODUCER,'input_request_digest':canonical_digest(plain_v1(request)),
        'joint_window_node_command':plain_v1(value),'joint_window_node_command_digest':value.digest})
    return StagedDomainInputV1(registration,request,stage)


def record_frozen_joint_window_command_v1(db,*,frame,staged_input,actual_receipt,readers):
    from .joint_prevalidated_input_v1 import _record_exact_joint_row_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    stage=staged_input.stage;payload=json.loads(stage.original_payload_json)
    value=decode_typed_production_value_v1(payload['provenance']['joint_window_node_command'],JointWindowNodeCommandOriginalV1)
    if(stage.operation_kind!=OPERATION or value.producing_operation_id!=stage.operation_id
            or value.command!=staged_input.request.command or actual_receipt.status!='committed'
            or actual_receipt.operation_id!=stage.operation_id or value.digest!=payload['provenance']['joint_window_node_command_digest']):
        raise ValueError('Frozen command requires its exact actual successful same-W01 producer')
    row=db.execute('SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
        (*value.namespace.as_tuple,stage.operation_id)).fetchone()
    if row!=(actual_receipt.operation_digest,actual_receipt.activity_id,actual_receipt.effect_id,actual_receipt.commit_seq):
        raise ValueError('Frozen command actual same-CAS bundle differs')
    return(_record_exact_joint_row_v1(db,table='graph_d10_production_inputs_v1',namespace=value.namespace,kind=KIND,
        ref=value.original_ref,value=plain_v1(value),digest=value.digest,operation_id=stage.operation_id,
        signer=readers.issuer._signer,sign_kind='d11.d10-production-input.v1',roots=value.source_refs),)


def read_frozen_joint_window_command_v1(db,*,frame,node,issuer):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_background_read_v3 import background_verify_signature_v3,background_json_loads_v3
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    read=CurrentDomainReadV1(frame);read.check(db);ns=frame.envelope.authority.namespace
    ref=joint_window_command_ref_v1(ns,node.typed_request_digest)
    row=_producer_original_point_v3(db,table='graph_d10_production_inputs_v1',
        columns=('kind','producing_operation_id','payload_json','payload_digest','signature','source_refs_json'),
        key_columns=('bot','persona','original_ref'),key=(*ns.as_tuple,ref),legacy_reader=lambda:None)
    if row is None:raise MissingProductionOriginalV1('actual_frozen_joint_window_command_original')
    background_verify_signature_v3(issuer._signer,'d11.d10-production-input.v1',row[2],row[4])
    value=decode_typed_production_value_v1(background_json_loads_v3(row[2]),JointWindowNodeCommandOriginalV1)
    if(row[0]!=KIND or value.namespace!=ns or value.original_ref!=ref or value.digest!=row[3]
            or value.producing_operation_id!=row[1]
            or(value.executor_kind,value.typed_input_original_ref,value.typed_input_original_digest,value.typed_request_digest,
                value.parent_grant_ref,value.parent_grant_digest,value.original_deadline_utc)!=
                (node.executor_kind,node.typed_request_ref,node.typed_input_original_digest,node.typed_request_digest,
                node.parent_grant_ref,node.parent_grant_digest,node.original_deadline_utc)):
        raise ValueError('Frozen command differs from the exact adopted Window node commitment')
    if(node.purpose,node.audience,node.source_refs)!=(value.command.binding.purpose,value.command.binding.audience,value.command.binding.source_refs):
        raise ValueError('Frozen command cannot change adopted node Source purpose/audience roots')
    for purpose,audiences,roots in value.source_purpose_groups:
        for audience in audiences:read.source_family(db,roots,purpose=purpose,audience=audience)
    actual=read_adopted_domain_operation_v1(db,ns,row[1])
    if(actual is None or actual['operation_kind']!=OPERATION or actual['receipt'].status!='committed'
            or actual['payload']['request']!=plain_v1(FreezeJointWindowNodeCommandRequestV1(value.command))
            or actual['payload']['provenance']['joint_window_node_command']!=plain_v1(value)):
        raise MissingProductionOriginalV1('actual_frozen_joint_command_positive_commit')
    return value
