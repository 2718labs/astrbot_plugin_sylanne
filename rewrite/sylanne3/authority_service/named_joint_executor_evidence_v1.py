"""Actual closed executor originals for named Joint registration; no job/quote issuance."""
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..graph_types import AtomKey
from ..runtime.domain_production_contracts_v1 import ProductionOriginalRefV1
from .current_named_joint_binding_v1 import NamedJointExecutorOriginalV1
from .contract import AuthorityUnavailable
from .named_joint_binding_source_read_v3 import _life,_fixed,_column,_positive


def _domain_proof(state,role,ref,digest,operation):
    state.producer_ids.add(operation)
    original=_positive(state,operation)
    return NamedJointExecutorOriginalV1(role,ref,digest,operation,original['original_digest'],canonical_digest(original['receipt']))


def _c02(state,binding):
    from ..runtime.domain_production_originals_v1 import reconstruct_graph_bundle_commit_receipt_v1
    work=state.work;operation=binding.executor.c02_operation_id;key=(*work.namespace.as_tuple,operation)
    row=_fixed(work,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),'bot=? AND persona=? AND operation_id=?',key)
    if row is None or row[3]<1:raise AuthorityUnavailable('Named Draft actual C02 COMMIT is absent')
    receipt_raw=_column(state,'graph_bundle_operations','receipt_json',('bot','persona','operation_id'),key)
    if 'first_ingress_c02'not in receipt_raw:raise AuthorityUnavailable('Named Draft C02 is not the actual first ingress original')
    event_key=(*work.namespace.as_tuple,row[1],operation)
    epoch=_fixed(work,'graph_events',('epoch_revision',),'bot=? AND persona=? AND session=? AND event_id=?',event_key)
    reads=_column(state,'graph_events','reads',('bot','persona','session','event_id'),event_key)
    revisions=_column(state,'graph_events','revisions',('bot','persona','session','event_id'),event_key)
    receipt=reconstruct_graph_bundle_commit_receipt_v1(work.namespace,operation,(*row,canonical_serialize(receipt_raw)),
        (canonical_serialize(reads),canonical_serialize(revisions),epoch[0]))
    if receipt.status!='committed':raise AuthorityUnavailable('Named Draft C02 is not positive committed evidence')
    digest=canonical_digest(receipt)
    state.original_refs[operation]=ProductionOriginalRefV1('d06.first_ingress_c02',operation,digest,receipt.write_versions)
    return NamedJointExecutorOriginalV1('c02_cycle',operation,digest,operation,receipt.operation_digest,digest)


def prepare_named_joint_executor_originals_v1(state):
    from ..runtime.joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
    binding=state.request.command.binding
    if type(binding)is JointArtifactProspectiveBindingV1:
        result=[]
        for role,ref,kind in (('objective',binding.objective_ref,'artifact_task_objective'),
                ('task_scope',binding.task_scope_ref,'artifact_task_scope'),
                ('draft_root',binding.executor.root_registration_ref,'draft_root_capability')):
            raw,proof=_life(state,role,ref,kind)
            state.original_refs[ref]=ProductionOriginalRefV1('d11.life_'+kind,ref,canonical_digest(raw))
            result.append(proof)
        result.append(_c02(state,binding))
        return tuple(result)
    from ..runtime.contact_prospective_v1 import TABLE,SIGN_KIND
    work=state.work;key=(*work.namespace.as_tuple,binding.prospective_original_ref)
    row=_fixed(work,TABLE,('contact_id','birth_operation_id','payload_digest','signature'),
        'bot=? AND persona=? AND original_ref=?',key)
    raw=_column(state,TABLE,'payload_json',('bot','persona','original_ref'),key)
    if row is None or(row[0],row[2])!=(binding.contact_id,binding.prospective_original_digest)or canonical_digest(raw)!=row[2]:
        raise AuthorityUnavailable('Named Contact actual prospective birth changed its immutable signed input')
    state.service.issuer._signer.verify(SIGN_KIND,canonical_serialize((work.namespace,row[0],row[1],row[2])),row[3])
    birth=_domain_proof(state,'prospective_birth',binding.prospective_original_ref,row[2],row[1])
    state.original_refs[binding.prospective_original_ref]=ProductionOriginalRefV1(SIGN_KIND,binding.prospective_original_ref,row[2])
    prep=state.contact_metadata['preparation']
    preparation=_domain_proof(state,'joint_preparation',prep.original_ref,prep.digest,prep.producer_operation_id)
    state.original_refs[prep.original_ref]=ProductionOriginalRefV1('d10.joint-contact-preparation-original.v1',prep.original_ref,prep.digest)
    from .named_joint_contact_plan_v1 import prepare_named_joint_contact_plan_v1
    state.contact_plan=prepare_named_joint_contact_plan_v1(state)
    plan,expression,plan_raw,plan_digest=state.contact_plan
    if plan_digest!=prep.contact_plan_original_digest:raise AuthorityUnavailable('Named Contact actual adopted Plan changed')
    plan_operation=plan_raw['producing_operation_id']
    plan_proof=_domain_proof(state,'contact_plan',prep.contact_plan_ref,plan_digest,plan_operation)
    cause=_fixed(work,'graph_domain_production_originals_v1',('operation_id','domain'),
        'bot=? AND persona=? AND original_digest=?',(*work.namespace.as_tuple,prep.contact_causal_original_digest))
    if cause is None or cause[1]+'-current:'+prep.contact_causal_original_digest[:48]!=prep.contact_causal_original_ref:
        raise AuthorityUnavailable('Named Contact actual original cause is absent or ambiguous')
    cause_proof=_domain_proof(state,'contact_cause',prep.contact_causal_original_ref,prep.contact_causal_original_digest,cause[0])
    state.original_refs[prep.contact_causal_original_ref]=ProductionOriginalRefV1(cause[1]+'.current-original',prep.contact_causal_original_ref,prep.contact_causal_original_digest)
    return birth,preparation,plan_proof,cause_proof
