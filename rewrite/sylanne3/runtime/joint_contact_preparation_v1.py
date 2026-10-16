"""Explicit Joint Contact preparation intent over the actual paid Contact tuple."""
from dataclasses import asdict,dataclass
import json
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1,production_read_plan_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .natural_producer_qualification_v1 import _producer_original_point_v3
from .domain_background_read_v3 import (background_json_loads_v3,background_json_matches_v3,background_verify_signature_v3)

KIND="joint_contact_preparation_v1"
PRODUCER="register_joint_contact_preparation_v1"
EVENT="qualified_joint_contact_requires_prospective_v1"


@dataclass(frozen=True,slots=True)
class RegisterJointContactPreparationRequestV1:
    namespace: NamespaceId
    contact_id: str
    joint_plan_ref: str
    joint_plan_revision: int
    node_id: str
    qualified_contact_dedupe_key: str
    prepare_contact_operation_id: str
    schema: str="d10.register-joint-contact-preparation.v1"

    def __post_init__(self):
        key=AtomKey.from_token(self.joint_plan_ref)
        if (self.schema!="d10.register-joint-contact-preparation.v1" or type(self.namespace) is not NamespaceId
                or key.type_name!="d08.joint_plan.v1" or NamespaceId.from_key(key)!=self.namespace
                or type(self.joint_plan_revision) is not int or self.joint_plan_revision<1
                or not self.node_id.startswith("task:")):
            raise ValueError("explicit exact future Joint plan/node identity required")
        for value in (self.contact_id,self.qualified_contact_dedupe_key,self.prepare_contact_operation_id):
            if type(value) is not str or not 1<=len(value)<=4096:
                raise ValueError("actual registered Contact causal selectors required")

    @property
    def digest(self):return canonical_digest(plain_v1(self))


@dataclass(frozen=True,slots=True)
class JointContactPreparationOriginalV1:
    request: RegisterJointContactPreparationRequestV1
    owner_ref: str
    owner_acl_actor: str
    contact_plan_ref: str
    contact_plan_revision: int
    contact_plan_original_digest: str
    reviewed_content_digest: str
    contact_causal_original_ref: str
    contact_causal_original_digest: str
    parent_budget_lease_ref: str
    parent_grant_id: str
    parent_grant_version: int
    parent_grant_digest: str
    absolute_deadline_utc: float
    source_refs: tuple[str,...]
    purpose: str
    audience: tuple[str,...]
    producer_operation_id: str
    input_request_digest: str
    source_purpose_groups: tuple[tuple[str,tuple[str,...]],...]
    schema: str="d10.joint-contact-preparation-original.v1"

    def __post_init__(self):
        if (type(self.request) is not RegisterJointContactPreparationRequestV1
                or self.schema!="d10.joint-contact-preparation-original.v1"
                or self.owner_ref!="persona:"+self.request.namespace.persona_id
                or self.purpose!="expression" or type(self.audience) is not tuple or len(self.audience)!=1
                or not self.source_refs or type(self.source_refs) is not tuple
                or self.parent_grant_version<1 or self.contact_plan_revision<1):
            raise ValueError("actual frozen Joint Contact Source/Owner/parent tuple required")
        import math
        if type(self.absolute_deadline_utc) not in (int,float) or not math.isfinite(self.absolute_deadline_utc):
            raise ValueError("actual original absolute Contact business deadline required")
        for name in ("contact_plan_original_digest","reviewed_content_digest","contact_causal_original_digest",
                "parent_grant_digest","input_request_digest"):
            value=getattr(self,name)
            if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("Joint Contact preparation exact immutable commitments required")

    @property
    def namespace(self):return self.request.namespace
    @property
    def digest(self):return canonical_digest(plain_v1(self))
    @property
    def original_ref(self):return "joint-contact-preparation:"+self.request.digest


def joint_contact_preparation_operation_id_v1(request):
    if type(request) is not RegisterJointContactPreparationRequestV1:raise TypeError("actual typed Joint Contact request required")
    return "joint-contact-prepare:"+request.digest[:48]


def _derive_joint_contact_preparation_v1(db,*,frame,request,issuer,producer_operation_id,require_input_identity):
    from .contact_host_source_v3 import contact_host_work_for_db_v3
    from .contact_owner_command_source_v3 import require_contact_owner_source_write_v3
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2
    from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
    from .contact_background_inputs_v1 import read_contact_background_inputs_v1
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    if type(request) is not RegisterJointContactPreparationRequestV1 or request.namespace!=frame.envelope.authority.namespace:
        raise ValueError("actual Joint Contact input namespace differs")
    work=contact_host_work_for_db_v3(db)
    binding=require_contact_owner_source_write_v3(work,db)
    if (binding.command.request!=request or binding.state is not work
            or work.result["namespace"]!=request.namespace or work.result["contact_id"]!=request.contact_id):
        raise MissingProductionOriginalV1("actual_owner_command_joint_contact_source_work")
    read=CurrentDomainReadV1(frame);read.check(db)
    plan,expression,raw,plan_digest=read_adopted_contact_plan_v2(db,namespace=request.namespace,
        contact_id=request.contact_id,issuer=issuer)
    content=read_contact_reviewed_content_original_v2(db,namespace=request.namespace,contact_id=request.contact_id,
        issuer=issuer,resource_issuer=issuer.resource_issuer)
    final_operation=content.segments[0].operation_id
    final_request_digest=canonical_digest(("sylanne.domain-production-command.v1",request.namespace,
        frame.envelope.authority.actor,"prepare_contact_dispatch_v3",PrepareCurrentContactDispatchRequestV3(request.contact_id,0),
        final_operation,plan.activity_id,plan.audience_id,plan.parent_budget_lease_id))
    terms,results,actual_plan,actual_content=read_contact_background_inputs_v1(db,
        namespace=request.namespace,contact_id=request.contact_id,operation_id=final_operation,
        request_digest=final_request_digest,dedupe_key=request.qualified_contact_dedupe_key,
        issuer=issuer,now=frame.now_utc,owner_actor=frame.envelope.authority.actor)
    if (terms["causal_operation_id"]!=request.prepare_contact_operation_id
            or require_input_identity and frame.envelope.identity.operation_id!=joint_contact_preparation_operation_id_v1(request)
            or frame.envelope.authority.purpose!="context"
            or frame.envelope.authority.audience!=("owner",)
            or frame.envelope.parent_budget_lease_ref!=terms["budget_lease_ref"]
            or frame.envelope.deadline_utc is None or frame.envelope.deadline_utc>terms["deadline_utc"]
            or frame.envelope.identity.activity_id!=plan.activity_id):
        raise ValueError("Joint Contact preparation changed actual source authority/parent/absolute deadline")
    from .contact_host_source_v3 import require_contact_host_material_scope_v3
    require_contact_host_material_scope_v3(work.source_material,work=work,db=db)
    material=work.source_material
    groups=dict(work.result["source_purpose_groups"])
    if groups!=dict(work.source_selection.purpose_groups):
        raise ValueError("Joint preparation changed its actual Source purpose groups")
    if (groups is None or material is None or not set(terms["source_refs"])<=set(groups)
            or any(set(purposes)!=set(material.purposes.get(ref,())) for ref,purposes in groups.items())):
        raise ValueError("Joint preparation lost actual independent expression/context Source coverage")
    for ref,purposes in groups.items():
        if not set(purposes)<={"expression","context"} or not purposes:
            raise ValueError("unregistered Joint Contact Source purpose")
        material.witnesses[ref].require_current_v3()
        for parent in material.metadata_records[ref].parent_source_ids:
            from ..memory_types import source_key
            parent_ref=source_key(*request.namespace.as_tuple,parent).token
            if not set(purposes)<=set(groups.get(parent_ref,())):
                raise ValueError("Joint Contact Source purpose ancestry is incomplete")
    read.original(terms["causal_original_ref"],kind="d10.current-prepare_contact",digest=terms["causal_original_digest"])
    return JointContactPreparationOriginalV1(request,"persona:"+request.namespace.persona_id,
        frame.envelope.authority.actor,terms["plan_ref"],terms["plan_revision"],terms["plan_original_digest"],
        terms["reviewed_content_digest"],terms["causal_original_ref"],terms["causal_original_digest"],
        terms["budget_lease_ref"],terms["grant_id"],terms["grant_version"],terms["grant_digest"],
        terms["deadline_utc"],tuple(terms["source_refs"]),"expression",(plan.audience_id,),
        producer_operation_id,request.digest,tuple((ref,tuple(sorted(purposes))) for ref,purposes in sorted(groups.items())))


def prepare_joint_contact_preparation_input_v1(db,*,frame,request,issuer):
    return _derive_joint_contact_preparation_v1(db,frame=frame,request=request,issuer=issuer,
        producer_operation_id=joint_contact_preparation_operation_id_v1(request),require_input_identity=True)


def record_joint_contact_preparation_after_commit_v1(db,*,frame,staged_input,actual_receipt,readers):
    from .domain_production_inputs_v1 import StagedDomainInputV1
    from ..runtime_contracts import CommitReceipt
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(staged_input) is not StagedDomainInputV1 or type(actual_receipt) is not CommitReceipt or not db.in_transaction:
        raise TypeError("actual same-CAS Joint Contact input descriptor/receipt required")
    stage,request=staged_input.stage,staged_input.request
    raw=json.loads(stage.original_payload_json)
    provenance=raw["provenance"]
    value=decode_typed_production_value_v1(provenance["joint_contact_preparation"],JointContactPreparationOriginalV1)
    if ((stage.domain,stage.operation_kind,stage.operation_id,stage.namespace)!=(
            "d10","input:"+PRODUCER,value.producer_operation_id,value.namespace)
            or actual_receipt.status!="committed" or actual_receipt.operation_id!=stage.operation_id
            or actual_receipt.activity_id!=stage.activity_id or value.request!=request
            or raw["request"]!=plain_v1(request) or value.input_request_digest!=request.digest
            or provenance["input_request_digest"]!=request.digest
            or provenance["joint_contact_preparation_digest"]!=value.digest
            or canonical_digest(raw)!=stage.original_digest):
        raise ValueError("Joint preparation prevalidated immutable value/stage provenance changed")
    actual=db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",(*value.namespace.as_tuple,stage.operation_id)).fetchone()
    if actual!=(actual_receipt.operation_digest,actual_receipt.activity_id,actual_receipt.effect_id,actual_receipt.commit_seq):
        raise ValueError("Joint preparation lacks its actual same-CAS W01 receipt")
    encoded=canonical_serialize(plain_v1(value))
    expected=(KIND,value.producer_operation_id,encoded,value.digest,
        readers.issuer._signer.sign("d11.d10-production-input.v1",encoded),canonical_serialize(value.source_refs))
    prior=db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature,source_refs_json "
        "FROM graph_d10_production_inputs_v1 WHERE bot=? AND persona=? AND original_ref=?",
        (*value.namespace.as_tuple,value.original_ref)).fetchone()
    if prior is None:
        db.execute("INSERT INTO graph_d10_production_inputs_v1 VALUES(?,?,?,?,?,?,?,?,?)",
            (*value.namespace.as_tuple,value.original_ref,*expected))
    elif prior!=expected:raise ValueError("Joint Contact immutable preparation replay differs")
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    return (ProductionOriginalRefV1(KIND,value.original_ref,value.digest),)


def read_current_joint_contact_preparation_v1(db,*,namespace,original_ref,issuer):
    row=_producer_original_point_v3(db,table="graph_d10_production_inputs_v1",
        columns=("kind","producing_operation_id","payload_json","payload_digest","signature"),
        key_columns=("bot","persona","original_ref"),key=(*namespace.as_tuple,original_ref),
        legacy_reader=lambda:db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature "
            "FROM graph_d10_production_inputs_v1 WHERE bot=? AND persona=? AND original_ref=?",
            (*namespace.as_tuple,original_ref)).fetchone())
    if row is None:raise MissingProductionOriginalV1("actual_registered_joint_contact_preparation")
    background_verify_signature_v3(issuer._signer,"d11.d10-production-input.v1",row[2],row[4])
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    raw=background_json_loads_v3(row[2])
    value=decode_typed_production_value_v1(raw,JointContactPreparationOriginalV1)
    actual=read_adopted_domain_operation_v1(db,namespace,row[1])
    if (row[0]!=KIND or value.namespace!=namespace or value.original_ref!=original_ref or value.digest!=row[3]
            or value.producer_operation_id!=row[1] or not background_json_matches_v3(row[2],raw)
            or actual is None or (actual["domain"],actual["operation_kind"])!=("d10","input:"+PRODUCER)
            or actual["payload"]["request"]!=plain_v1(value.request)
            or value.input_request_digest!=value.request.digest
            or actual["payload"]["provenance"]["input_request_digest"]!=value.request.digest
            or actual["payload"]["provenance"]["joint_contact_preparation_digest"]!=value.digest):
        raise ValueError("Joint Contact preparation lost its actual same-CAS producer/request")
    return value


def require_current_joint_contact_preparation_v1(db,*,frame,original_ref,issuer):
    value=read_current_joint_contact_preparation_v1(db,namespace=frame.envelope.authority.namespace,
        original_ref=original_ref,issuer=issuer)
    # The current real frame/scope remains unchanged. Historical producer IDs
    # are comparison data and never a replacement authority or operation frame.
    current=_derive_joint_contact_preparation_v1(db,frame=frame,request=value.request,issuer=issuer,
        producer_operation_id=value.producer_operation_id,require_input_identity=False)
    if current!=value:raise MissingProductionOriginalV1("joint_contact_preparation_current_original_tuple_changed")
    return value
