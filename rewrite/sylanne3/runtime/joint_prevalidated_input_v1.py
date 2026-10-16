"""Same-CAS Joint originals over the actual prevalidated input stage."""
import json
from ..domains.d01.production_operations_v1 import plain_v1
from ..runtime_contracts import canonical_digest,canonical_serialize,CommitReceipt
from .domain_production_contracts_v1 import ProductionOriginalRefV1

JOINT_PREVALIDATED_PRODUCERS_V1=frozenset({
    "register_joint_node_execution_binding_v1","qualify_joint_plan_nodes_v1",
    "register_joint_compensation_v1","register_joint_external_contract_v1",
    "observe_joint_external_node_v1","prepare_joint_external_semantic_question_v1"})

def freeze_current_joint_input_v1(db,*,frame,producer_kind,request,readers):
    if producer_kind not in JOINT_PREVALIDATED_PRODUCERS_V1:raise ValueError("unregistered fixed Joint input producer")
    if producer_kind in {"register_joint_node_execution_binding_v1","qualify_joint_plan_nodes_v1"}:
        from .joint_node_execution_v1 import validate_joint_input_v1,joint_executor_index_values_v1,JointPlanQualificationV1
        value=validate_joint_input_v1(db,frame=frame,request=request,issuer=readers.issuer,installed_readers=readers)
        from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
        from .joint_node_execution_v1 import JointNodeExecutionBindingV1,JointContactProspectiveBindingV1
        kind=({JointArtifactProspectiveBindingV1:"joint_artifact_prospective_binding_v1",
            JointContactProspectiveBindingV1:"joint_contact_prospective_binding_v1",
            JointNodeExecutionBindingV1:"joint_node_execution_binding_v1",
            JointPlanQualificationV1:"joint_plan_qualification_v1"})[type(value)]
        indices=() if type(value) is JointPlanQualificationV1 else joint_executor_index_values_v1(value)
        if type(value) is not JointPlanQualificationV1:
            from .joint_node_execution_v1 import read_joint_executor_index_v1
            selected=[]
            for index in indices:
                if index.selector_kind=="artifact_task":
                    prior=read_joint_executor_index_v1(db,namespace=value.namespace,selector_kind=index.selector_kind,
                        selector_key=index.selector_key,issuer=readers.issuer)
                    if prior is not None:
                        if (prior.plan_ref,prior.plan_revision)!=(value.plan_ref,value.plan_revision):
                            raise ValueError("Artifact task belongs to another current Joint responsibility")
                        continue
                selected.append(index)
            indices=tuple(selected)
        return {"kind":kind,"value":plain_v1(value),"value_digest":value.digest,
            "indices":tuple(plain_v1(index) for index in indices)}
    if producer_kind=="register_joint_compensation_v1":
        from .joint_compensation_v1 import validate_joint_compensation_input_v1
        value=validate_joint_compensation_input_v1(db,frame=frame,request=request,issuer=readers.issuer)
        kind="compensation_authorization_v1"
    elif producer_kind in {"register_joint_external_contract_v1","observe_joint_external_node_v1"}:
        from .joint_external_observation_v1 import validate_joint_external_input_v1
        value=validate_joint_external_input_v1(db,frame=frame,request=request,issuer=readers.issuer)
        kind="external_node_contract_v1" if producer_kind=="register_joint_external_contract_v1" else "external_node_observation_v1"
    else:
        from .joint_external_observation_v1 import (prepare_joint_external_question_v1,_external_node_v1,
            JointExternalSemanticBasisV1,joint_semantic_question_ref_v1)
        from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1
        from .d07_execution_v1 import resolve_current_d07_semantic_target_v1,_source_input
        question=prepare_joint_external_question_v1(db,frame=frame,request=request,issuer=readers.issuer)
        target=resolve_current_d07_semantic_target_v1(db,readers.issuer,frame,question);_source_input(frame,question.source_refs)
        grant=readers.issuer.current_budget_grant(db,frame.envelope.parent_budget_lease_ref)
        if (grant.bot_id,grant.persona_id)!=frame.envelope.authority.namespace.as_tuple or "d07.cognition" not in grant.allowed_work_kinds:
            raise MissingProductionOriginalV1("actual_joint_semantic_parent_grant_for_d07_cognition")
        _,_,_,contract=_external_node_v1(db,frame=frame,plan_ref=request.plan_ref,
            revision=request.expected_plan_revision,node_id=request.node_id,issuer=readers.issuer)
        ticket=CurrentDomainReadV1(frame).head(db,request.attention_ticket.key,required=True)
        deadline=min(contract.original_deadline_utc,ticket.value["valid_until"],grant.valid_until_utc)
        if frame.now_utc>=deadline:raise MissingProductionOriginalV1("actual_unexpired_joint_semantic_parent_lifetime")
        ref=joint_semantic_question_ref_v1(request);q=plain_v1(question)
        basis=JointExternalSemanticBasisV1(frame.envelope.authority.namespace,ref,canonical_digest(q),request,
            question.source_refs,grant.lease_id,grant.grant_id,grant.version,canonical_digest(grant),
            deadline,frame.envelope.identity.operation_id)
        return {"kind":"semantic_question","question_ref":ref,"question":q,
            "question_digest":canonical_digest(q),"question_target_versions":plain_v1(target.read_versions),
            "basis":plain_v1(basis),"basis_ref":basis.original_ref,"basis_digest":canonical_digest(plain_v1(basis))}
    return {"kind":kind,"value":plain_v1(value),"value_digest":value.digest,"indices":()}

def _record_exact_joint_row_v1(db,*,table,namespace,kind,ref,value,digest,operation_id,signer,sign_kind,roots):
    encoded=canonical_serialize(value)
    if canonical_digest(value)!=digest:raise ValueError("Joint prevalidated original digest changed")
    expected=(kind,operation_id,encoded,digest,signer.sign(sign_kind,encoded),canonical_serialize(tuple(roots)))
    row=db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature,source_refs_json FROM "+table+
        " WHERE bot=? AND persona=? AND original_ref=?",(*namespace.as_tuple,ref)).fetchone()
    if row is None:db.execute("INSERT INTO "+table+" VALUES(?,?,?,?,?,?,?,?,?)",(*namespace.as_tuple,ref,*expected))
    elif row!=expected:
        if table=="graph_d08_joint_node_originals_v1" and kind=="external_node_observation_v1":
            from .joint_external_observation_v1 import ORIGINAL_TYPES
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            previous=decode_typed_production_value_v1(json.loads(row[2]),ORIGINAL_TYPES[kind])
            signer.verify(sign_kind,row[2],row[4])
            old=plain_v1(previous);same=dict(value);same["producing_operation_id"]=old["producing_operation_id"]
            if same==old and previous.digest==row[3]:
                return ProductionOriginalRefV1("d08."+kind,previous.original_ref,previous.digest)
        raise ValueError("Joint immutable original replay differs from its actual same-CAS producer")
    return ProductionOriginalRefV1(("d10." if table=="graph_d10_production_inputs_v1" else "d08.")+kind,ref,digest)

def record_prevalidated_joint_input_after_commit_v1(db,*,frame,staged_input,actual_receipt,readers):
    from .domain_production_inputs_v1 import StagedDomainInputV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if type(staged_input) is not StagedDomainInputV1 or type(actual_receipt) is not CommitReceipt or not db.in_transaction:
        raise TypeError("actual same-CAS Joint input descriptor/receipt required")
    stage,request=staged_input.stage,staged_input.request;producer=staged_input.registration.producer_kind
    raw=json.loads(stage.original_payload_json);provenance=raw["provenance"];frozen=provenance["joint_prevalidated"]
    if (producer not in JOINT_PREVALIDATED_PRODUCERS_V1 or stage.operation_kind!="input:"+producer
            or actual_receipt.status!="committed" or stage.operation_id!=actual_receipt.operation_id
            or stage.activity_id!=actual_receipt.activity_id or stage.namespace!=frame.envelope.authority.namespace
            or raw["request"]!=plain_v1(request) or provenance["input_request_digest"]!=canonical_digest(plain_v1(request))
            or provenance["joint_prevalidated_digest"]!=canonical_digest(frozen)
            or canonical_digest(raw)!=stage.original_digest):
        raise ValueError("Joint prevalidated stage/actual same-CAS producer commitment changed")
    row=db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",(*stage.namespace.as_tuple,stage.operation_id)).fetchone()
    if row!=(actual_receipt.operation_digest,actual_receipt.activity_id,actual_receipt.effect_id,actual_receipt.commit_seq):
        raise ValueError("Joint producer lost its actual same-CAS bundle receipt")
    signer=readers.issuer._signer
    if producer=="prepare_joint_external_semantic_question_v1":
        from .d07_execution_v1 import KINDS,TABLE,SIGN_KIND
        from .joint_external_observation_v1 import JointExternalSemanticBasisV1
        from .d07_execution_v1 import D07SemanticQuestionV1
        question=decode_typed_production_value_v1(frozen["question"],D07SemanticQuestionV1)
        basis=decode_typed_production_value_v1(frozen["basis"],JointExternalSemanticBasisV1)
        if basis.request!=request or basis.producing_operation_id!=stage.operation_id:
            raise ValueError("Joint semantic prevalidated basis changed its real C02/request/producer")
        originals=[]
        for kind,ref,value,digest in (("semantic_question",frozen["question_ref"],frozen["question"],frozen["question_digest"]),
                ("joint_external_semantic_basis_v1",frozen["basis_ref"],frozen["basis"],frozen["basis_digest"])):
            if kind not in KINDS or canonical_digest(value)!=digest:raise ValueError("Joint D07 original kind/digest differs")
            encoded=canonical_serialize(value);signature=signer.sign(SIGN_KIND,canonical_serialize((stage.namespace,kind,ref,digest)))
            prior=db.execute("SELECT payload_json,payload_digest,signature FROM "+TABLE+" WHERE bot=? AND persona=? AND kind=? AND original_ref=?",
                (*stage.namespace.as_tuple,kind,ref)).fetchone()
            expected=(encoded,digest,signature)
            if prior is None:db.execute("INSERT INTO "+TABLE+" VALUES(?,?,?,?,?,?,?)",(*stage.namespace.as_tuple,kind,ref,*expected))
            elif prior!=expected:raise ValueError("Joint D07 immutable question/basis replay changed")
            originals.append(ProductionOriginalRefV1("d07."+kind,ref,digest))
        return tuple(originals)
    from .joint_node_execution_v1 import decode_joint_binding_v1,JointPlanQualificationV1,JointExecutorIndexV1,joint_executor_index_values_v1
    if producer=="register_joint_node_execution_binding_v1":value=decode_joint_binding_v1(frozen["value"])
    elif producer=="qualify_joint_plan_nodes_v1":value=decode_typed_production_value_v1(frozen["value"],JointPlanQualificationV1)
    else:
        from .joint_external_observation_v1 import ORIGINAL_TYPES
        value=decode_typed_production_value_v1(frozen["value"],ORIGINAL_TYPES[frozen["kind"]])
    if value.digest!=frozen["value_digest"]:raise ValueError("Joint frozen typed original changed")
    table="graph_d10_production_inputs_v1" if producer in {"register_joint_node_execution_binding_v1","qualify_joint_plan_nodes_v1"} else "graph_d08_joint_node_originals_v1"
    sign_kind="d11.d10-production-input.v1" if table=="graph_d10_production_inputs_v1" else "d08.joint-node-original.v1"
    if table!="graph_d10_production_inputs_v1":
        from .joint_external_observation_v1 import SIGN_KIND
        sign_kind=SIGN_KIND
    result=[_record_exact_joint_row_v1(db,table=table,namespace=stage.namespace,kind=frozen["kind"],
        ref=value.original_ref,value=frozen["value"],digest=value.digest,operation_id=stage.operation_id,
        signer=signer,sign_kind=sign_kind,roots=value.source_refs)]
    if producer=="register_joint_node_execution_binding_v1":
        expected_indices=tuple(joint_executor_index_values_v1(value))
        indices=tuple(decode_typed_production_value_v1(index,JointExecutorIndexV1) for index in frozen["indices"])
        if any(index not in expected_indices for index in indices) or any(index.selector_kind!="artifact_task" and index not in indices for index in expected_indices):
            raise ValueError("Joint frozen executor index changed its concrete identity")
        for index in indices:
            result.append(_record_exact_joint_row_v1(db,table=table,namespace=stage.namespace,kind="joint_executor_index_v1",
                ref=index.original_ref,value=plain_v1(index),digest=index.digest,operation_id=stage.operation_id,
                signer=signer,sign_kind=sign_kind,roots=index.source_refs))
    return tuple(result)
