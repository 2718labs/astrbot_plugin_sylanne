"""Exact installed Owner/GCP preparation witness and same-tx original membership."""
from ..contracts import canonical_json
from ..runtime_contracts import DomainBundle, canonical_digest
from .d11_types import job_graph_write, reconcile_runtime_write
from .internal_life_content_preparation_v1 import (
    InternalLifeContentPreparationStageV1,
    verify_internal_life_content_preparation_in_transaction_v1,
    record_internal_life_preparation_after_cas_v1,
)


def internal_life_content_preparation_bundle_v1(preparation):
    if type(preparation) is not InternalLifeContentPreparationStageV1:
        raise TypeError('closed installed Life content prepared stage required')
    primary=preparation.stage
    writes=tuple(write for proposal in primary.proposals for write in proposal.typed_writes)
    if (primary.jobs or primary.outbox or len(primary.proposals)!=1
            or writes!=(job_graph_write(preparation.job),)
            or primary.proposals[0].envelope!=preparation.frame.envelope):
        raise ValueError('Life preparation changed its actual reserved queued-job projection')
    return DomainBundle(preparation.frame.envelope,primary.proposals,(),(),(),(),
        (preparation.prepared.prepare_operation_id,),(writes[0].key.token,),())


def commit_internal_life_content_preparation_v1(runtime,db,*,operation,request,preparation,readers,
        scope,owner,guard,metadata,epoch,process_lease,external_originals):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE
    from .domain_production_originals_v1 import record_adopted_domain_operation_v1,_receipt_wire
    from ..authority_service.v2_contract import to_wire
    graph=runtime.graph
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or readers.life_content_bundle is not assembly.admin_bundle:
        raise ValueError('Life preparation lost its actual installed workflow bundle')
    verify_internal_life_content_preparation_in_transaction_v1(db,preparation,readers,assembly.admin_bundle)
    bundle=internal_life_content_preparation_bundle_v1(preparation);prepared=preparation.prepared
    attempt=db.execute('SELECT request_digest,attempt_id,permit_json FROM graph_owner_domain_attempts_v3 '
        'WHERE bot=? AND persona=? AND operation_id=?',(*prepared.namespace.as_tuple,prepared.prepare_operation_id)).fetchone()
    if (attempt is None or attempt[1]!=scope.operation_id or attempt[2]!=canonical_json(to_wire(scope.permit))
            or request.episode_ref!=prepared.episode_ref
            or request.causal_operation_id!=preparation.frozen.input.cause.occurrence.event.causal_operation_id):
        raise ValueError('Life preparation has no exact Owner command/permit attempt')
    reconcile_runtime_write(db,job_graph_write(preparation.job))
    witness=_ProductionCommitWitnessV1(runtime,graph,scope,preparation.frame,
        preparation,operation,request,owner,guard,bundle,tuple(external_originals))
    finish='sha256:'+canonical_digest({'schema':'w01.owner-domain-write.v3',
        'operation_id':prepared.prepare_operation_id,'request_digest':attempt[0],'permit_token':scope.permit.token})
    _ACTIVE[id(witness)]=witness
    try:
        receipt=graph._commit_domain_bundle_fenced(bundle,process_lease,in_transaction=True,
            v2_write=(metadata,epoch,'finish:'+scope.operation_id,finish,canonical_json(to_wire(scope.permit))),
            now_utc=preparation.frame.now_utc,domain_production_issuance_v1=witness)
    finally:
        _ACTIVE.pop(id(witness),None)
    record_internal_life_preparation_after_cas_v1(db,prepared=prepared,issuer=readers.issuer,receipt=receipt)
    original=record_adopted_domain_operation_v1(db,preparation.stage,receipt)
    return {'schema':'sylanne.domain-production-receipt.v1','domain':'d11',
        'operation_kind':operation.operation_kind,'operation_id':prepared.prepare_operation_id,
        'activity_id':prepared.activity_id,'original_ref':original.original_ref,
        'original_digest':original.original_digest,'receipt':_receipt_wire(receipt),
        'receipt_digest':canonical_digest(receipt),'job_states':[[prepared.job_id,'queued']],
        'coverage':'deferred','missing_inputs':['actual_internal_life_content_terminal_and_adoption'],
        'continuation_ref':prepared.job_id,'outbox':[]}
