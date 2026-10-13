"""Self C04 terminal adoption using the original paid CPU/Body evidence."""
from dataclasses import dataclass, replace
from datetime import datetime
import json

from ..runtime_contracts import DomainBundle,DomainProposal,DependencySet,canonical_digest,canonical_serialize
from ..contracts import canonical_json
from ..graph_types import AtomKey,GraphVersion
from ..domains.d01.production_operations_v1 import stage_result_v1,plain_v1
from .c04_ingress_preparation_v4 import (
    ADOPT_OPERATION,InstalledSelfC04ReadersV4,_environment,_selection,require_current_self_c04_parent_v4)
from .c04_self_scope_v4 import ingress_c04_ids_v4
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from .c04_frozen_association_original_v3 import read_c04_frozen_association_original_v4
from .c04_product_lifecycle_v3 import read_original_c04_product_job_v3
from .c04_interpretation_policy_v3 import read_installed_c04_interpretation_policy_v3
from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
from .d11_types import job_graph_write,RuntimeOutboxValue,outbox_graph_write
from .jobs import get_job,_save_job,_record_operation
from .domain_production_originals_v1 import record_adopted_domain_operation_v1,_receipt_wire


@dataclass(frozen=True,slots=True)
class SelfC04AdoptionStageV4:
    frame: object
    stage: object
    request: object
    bundle: DomainBundle
    prepared: object
    work: object
    plan: object
    before_child: object
    after_child: object
    before_parent: object
    after_parent: object
    interpretation: object


def stage_self_c04_adopt_v4(db,*,frame,request,installed_readers):
    from .c04_self_adoption_kernel_v4 import build_self_c04_adoption_bundle_v4,build_self_c04_adoption_plan_v4
    readers=installed_readers;environment=_environment(readers,request)
    evidence=require_foreground_activity_issuance_v1(readers.issued,readers.graph,readers.scope)
    selected,original,_=_selection(db,frame.envelope.authority.namespace,request)
    ids=ingress_c04_ids_v4(selected.namespace,selected.c02_operation_id,original["original_digest"])
    prepared=read_c04_internal_work_prepared_v1(db,selected.namespace,ids["prepare"])
    work=read_c04_frozen_association_original_v4(db,selected.namespace,prepared.binding)
    if environment.proof is None or prepared.binding!=environment.proof.binding or frame.envelope.identity.operation_id!=ids["adopt"]:
        raise ValueError("Self C04 adoption lacks its actual independently inspected terminal")
    parent=require_current_self_c04_parent_v4(db,namespace=selected.namespace,binding=prepared.binding,
        work=work,prepared=prepared,installed_bundle=readers.installed_bundle,issuer=readers.issuer,
        current_self=evidence.current_self,now_utc=frame.now_utc)
    child=read_original_c04_product_job_v3(db,selected.namespace,prepared)
    policy,policy_original=read_installed_c04_interpretation_policy_v3(db,selected.namespace,prepared,
        installation_id=readers.installed_bundle.installation_policy.installation_id,
        manifest_digest=readers.installed_bundle.installation_policy.manifest_digest)
    providers=readers.graph._GraphCoordinator__providers
    assembly=build_self_c04_adoption_bundle_v4(db,authority=frame.envelope.authority,
        proof=environment.proof,verified=environment.verified,now_utc=frame.now_utc,
        query_epoch=frame.snapshot.epochs[0],current_owner_version=GraphVersion(AtomKey.from_token(frame.owner_guard.grant_ref),frame.owner_guard.grant_revision),
        catalogue_version=frame.envelope.version_guard.catalogue_version,scheme=providers["d04"][0]._active_scheme,
        policy_version=frame.envelope.version_guard.policy_version,projection_policy=environment.projection_policy,
        interpretation_policy=policy,d04_provider=providers["d04"][0],d06_provider=providers["d06"][0],d07_provider=providers["d07"][0],
        adoption_identity=frame.envelope.identity)
    assembled=replace(assembly.bundle,proposals=tuple(replace(p,proposal_schema=providers[p.domain][1],
        proposal_schema_hash=providers[p.domain][2]) for p in assembly.bundle.proposals))
    plan=build_self_c04_adoption_plan_v4(db,namespace=selected.namespace,operation_id=ids["prepare"],
        adoption_operation_id=ids["adopt"],proof=environment.proof,verified=environment.verified,bundle=assembled,
        installation_id=readers.installed_bundle.installation_policy.installation_id,
        manifest_digest=readers.installed_bundle.installation_policy.manifest_digest)
    after_child=replace(child,phase="completed",lease_holder=None,lease_expires_utc=None,wake_condition=None,
        result_ref="c04-adoption-plan:"+plan.plan_digest[:48],
        continuation={**child.continuation,"product_status":"adopted","adoption_plan_digest":plan.plan_digest},
        usage={**child.usage,"cpu_ms":environment.proof.terminal.actual_cpu_ms})
    continuation=foreground_cycle_from_wire_v1(parent.continuation)
    after_parent=replace(parent,phase="queued",wake_condition=None,
        continuation=plain_v1(replace(continuation,stage="revise_plan",wait=None,
            completed_operation_refs=tuple(dict.fromkeys((*continuation.completed_operation_refs,ids["adopt"]))))),
        lease_holder=None,lease_expires_utc=None)
    child_write,parent_write=job_graph_write(after_child),job_graph_write(after_parent)
    outbox_key=AtomKey.from_token(assembled.outbox_refs[0])
    outbox=RuntimeOutboxValue(*selected.namespace.as_tuple,child.activity_id,child.operation_id,child.effect_id,
        outbox_key.name,child.job_id,child_write.key.token,"c04-adoption-plan:"+plan.plan_digest[:48],
        "c04-adopted:"+prepared.binding.binding_digest[:48],"pending",frame.activation_generation)
    writes=(child_write,parent_write,outbox_graph_write(outbox,child_write.key))
    versions={v.key:v for v in assembled.envelope.version_guard.read_versions}
    for write in writes:
        row=db.execute("SELECT revision FROM graph_atoms WHERE token=?",(write.key.token,)).fetchone()
        versions[write.key]=GraphVersion(write.key,0 if row is None else row[0])
    envelope=replace(assembled.envelope,version_guard=replace(assembled.envelope.version_guard,
        read_versions=tuple(sorted(versions.values(),key=lambda v:v.key.token))))
    proposals=tuple(replace(p,envelope=envelope) for p in assembled.proposals)
    reg=providers["d11"]
    proposals+=(DomainProposal("d11",reg[1],reg[2],envelope,writes,DependencySet(),(),()),)
    bundle=replace(assembled,envelope=envelope,proposals=proposals,
        persistent_job_refs=(child_write.key.token,parent_write.key.token))
    stage=stage_result_v1(frame,"d06",ADOPT_OPERATION,request,
        provenance={"schema":"c04.self-foreground-adoption.v4","binding_digest":prepared.binding.binding_digest,
            "prepare_operation_id":ids["prepare"],"adoption_operation_id":ids["adopt"],"plan_digest":plan.plan_digest,
            "proof_digest":environment.verified.proof_digest,"before_parent":plain_v1(parent),"after_parent":plain_v1(after_parent)},
        coverage="complete")
    return SelfC04AdoptionStageV4(frame,stage,request,bundle,prepared,work,plan,child,after_child,parent,after_parent,assembly.interpretation_provenance)


def require_self_c04_adoption_commit_v4(witness,graph,db,bundle,v2_write):
    from .domain_production_commit_v1 import _ACTIVE,_FOREGROUND_VALIDATED,_require_foreground_witness_v1
    from .domain_production_registry_v1 import installed_readers_for_operation_v1
    if (_ACTIVE.get(id(witness)) is not witness or type(witness.stage) is not SelfC04AdoptionStageV4
            or witness.graph is not graph or v2_write is None or graph._v2_graph_stamp(bundle.envelope.authority.namespace)!=v2_write[:2]
            or witness.scope.graph_revision!=v2_write[0].graph_revision or witness.scope.graph_epoch!=v2_write[1]):
        raise ValueError("Self C04 adoption lacks its actual current Foreground fence")
    issued,evidence=_require_foreground_witness_v1(witness,graph,db,bundle)
    readers=installed_readers_for_operation_v1(graph,witness.operation,scope=witness.scope,owner_guard=evidence.owner_guard,foreground_issuance=issued)
    if stage_self_c04_adopt_v4(db,frame=witness.frame,request=witness.request,installed_readers=readers)!=witness.stage or witness.stage.bundle!=bundle:
        raise ValueError("Self C04 actual terminal/paid/domain adoption changed before CAS")
    if witness.stage.plan.algorithm_build_digest!="sha256:"+str(graph._GraphCoordinator__c04_direct_seed_build_digest):
        raise ValueError("Self C04 actual adoption plan changed its installed V4 pin")
    _FOREGROUND_VALIDATED[id(witness)]=witness
    return witness


def apply_self_c04_adoption_once_v4(witness,graph,db):
    from .domain_production_commit_v1 import _ACTIVE,_FOREGROUND_VALIDATED,_FOREGROUND_APPLIED
    if (_ACTIVE.get(id(witness)) is not witness or _FOREGROUND_VALIDATED.get(id(witness)) is not witness
            or id(witness) in _FOREGROUND_APPLIED):
        raise ValueError("Self C04 adoption once hook is not privately validated")
    s=witness.stage
    if get_job(db,s.before_child.job_id)!=s.before_child or get_job(db,s.before_parent.job_id)!=s.before_parent:
        raise ValueError("Self C04 original parent/worker changed before adoption")
    for job in (s.after_child,s.after_parent):
        _save_job(db,job)
        _record_operation(db,job,witness.bundle.envelope.identity.operation_id,"checkpoint",canonical_digest(plain_v1(job)))
    _FOREGROUND_APPLIED[id(witness)]=witness
    return True


def commit_self_c04_adopt_v4(runtime,db,*,operation,request,frame,stage,readers,scope,metadata,epoch,process_lease,guard,owner,external_originals):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE,_FOREGROUND_VALIDATED,_FOREGROUND_APPLIED,foreground_domain_finish_digest_v1
    from ..authority_service.v2_contract import to_wire
    witness=_ProductionCommitWitnessV1(runtime,runtime.graph,scope,frame,stage,operation,request,None,guard,stage.bundle,())
    evidence=require_foreground_activity_issuance_v1(readers.issued,runtime.graph,scope)
    _ACTIVE[id(witness)]=witness
    try:
        receipt=runtime.graph._commit_domain_bundle_fenced(stage.bundle,process_lease,in_transaction=True,now_utc=frame.now_utc,
            v2_write=(metadata,epoch,"finish:"+scope.operation_id,foreground_domain_finish_digest_v1(evidence.request,scope.permit),
                canonical_json(to_wire(scope.permit))),domain_production_issuance_v1=witness)
        if _FOREGROUND_APPLIED.get(id(witness)) is not witness:
            raise ValueError("Self C04 actual adoption job hook was not applied")
    finally:
        _ACTIVE.pop(id(witness),None);_FOREGROUND_VALIDATED.pop(id(witness),None);_FOREGROUND_APPLIED.pop(id(witness),None)
    from .c04_v3_contracts import C04AdoptionReceiptV3
    plan_receipt=C04AdoptionReceiptV3(stage.work.namespace,frame.envelope.identity.operation_id,stage.plan.plan_digest,
        stage.plan.input_digest,stage.plan.result_digest,stage.plan.write_set_digest,receipt.invalidated_epochs[0].revision)
    plan_receipt.validate_plan(stage.plan)
    db.execute("INSERT INTO graph_c04_adoptions_v3 VALUES(?,?,?,?,?,?)",
        (*stage.work.namespace.as_tuple,frame.envelope.identity.operation_id,receipt.operation_digest,
            stage.plan.to_json(),plan_receipt.to_json()))
    original=record_adopted_domain_operation_v1(db,stage.stage,receipt)
    provenance={"schema":"c04.adopted-current-interpretation-original.v4","binding_digest":stage.prepared.binding.binding_digest,
        "prepare_operation_id":stage.prepared.binding.operation_id,"adoption_operation_id":frame.envelope.identity.operation_id,
        "plan_digest":stage.plan.plan_digest,"receipt_digest":canonical_digest(receipt),"interpretation":stage.interpretation}
    db.execute("INSERT INTO graph_c04_adoption_provenance_v3 VALUES(?,?,?,?,?)",
        (*stage.work.namespace.as_tuple,stage.prepared.binding.operation_id,canonical_json(plain_v1(provenance)), canonical_digest(plain_v1(provenance))))
    return {"schema":"sylanne.domain-production-receipt.v1","domain":"d06","operation_kind":ADOPT_OPERATION,
        "operation_id":frame.envelope.identity.operation_id,"activity_id":stage.work.activity_id,
        "original_ref":original.original_ref,"original_digest":original.original_digest,"receipt":_receipt_wire(receipt),
        "receipt_digest":canonical_digest(receipt),"job_states":[[stage.after_child.job_id,"completed"],[stage.after_parent.job_id,"queued"]],
        "coverage":"complete","missing_inputs":[],"continuation_ref":None,"outbox":list(stage.bundle.outbox_refs),"produced_originals":[]}


def require_self_c04_adoption_member_v4(witness,ref):
    from .domain_production_commit_v1 import _ACTIVE,_FOREGROUND_APPLIED
    if (_ACTIVE.get(id(witness)) is not witness or _FOREGROUND_APPLIED.get(id(witness)) is not witness
            or type(witness.stage) is not SelfC04AdoptionStageV4
            or ref not in {job_graph_write(witness.stage.after_child).key.token,job_graph_write(witness.stage.after_parent).key.token}):
        raise ValueError("Self C04 adoption persistent member differs")
