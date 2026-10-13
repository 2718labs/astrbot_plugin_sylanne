"""Atomic installed life preparation, using actual running-job originals."""
from dataclasses import replace

from ..contracts import canonical_json
from ..runtime_contracts import DomainBundle, DomainProposal, DependencySet, canonical_digest
from .d11_types import job_graph_write, reconcile_runtime_write


def life_preparation_bundle_v1(graph, preparation):
    from .d11_life_preparation_v1 import LifePreparationStageV1
    if type(preparation) is not LifePreparationStageV1:
        raise TypeError("exact installed life preparation required")
    envelope = preparation.frame.envelope
    if preparation.stage.proposals or preparation.writes != (job_graph_write(preparation.job),):
        raise ValueError("life preparation must have only its actual running-job projection")
    proposals = []
    for domain, writes in (("d10", ()), ("d11", preparation.writes)):
        provider = graph._GraphCoordinator__providers[domain]
        dependencies = {key for write in writes for key in write.dependencies}
        proposals.append(DomainProposal(domain, provider[1], provider[2], envelope, writes,
            DependencySet(current_invalidation=tuple(version for version in preparation.read_versions
                if version.key in dependencies)), (), ("persistent_job",)))
    return DomainBundle(envelope, tuple(proposals), (), (), (), (),
        (preparation.prepared.prepare_operation_id,), (job_graph_write(preparation.job).key.token,), ())


def commit_life_preparation_v1(runtime, db, *, operation, request, preparation, readers,
        scope, owner, guard, metadata, epoch, process_lease, external_originals):
    from .d11_life_preparation_v1 import (
        record_life_preparation_after_cas_v1, verify_life_preparation_in_transaction_v1)
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1, _ACTIVE
    from .domain_production_originals_v1 import record_adopted_domain_operation_v1, _receipt_wire
    from ..authority_service.v2_contract import to_wire
    graph = runtime.graph
    verify_life_preparation_in_transaction_v1(db, preparation,
        issuer=readers.issuer, resource_issuer=graph._GraphCoordinator__d02_issuer)
    bundle = life_preparation_bundle_v1(graph, preparation)
    for write in preparation.writes:
        reconcile_runtime_write(db, write)
    witness = _ProductionCommitWitnessV1(runtime, graph, scope, preparation.frame,
        preparation, operation, request, owner, guard, bundle, tuple(external_originals))
    binding = preparation.prepared.binding
    attempt = db.execute("SELECT request_digest,attempt_id,permit_json FROM graph_owner_domain_attempts_v3 "
        "WHERE bot=? AND persona=? AND operation_id=?", (*binding.namespace.as_tuple, binding.prepare_operation_id)).fetchone()
    if (attempt is None or attempt[1] != scope.operation_id or attempt[2] != canonical_json(to_wire(scope.permit))
            or attempt[:2] != (preparation.prepared.owner_prepare_request_digest,preparation.prepared.owner_prepare_attempt_id)
            or request.prepare_operation_id != binding.prepare_operation_id or preparation.frame.envelope.identity.operation_id != binding.prepare_operation_id
            or bundle.envelope != preparation.frame.envelope):
        raise ValueError("life preparation has no exact current Owner fence attempt")
    owner_task=getattr(runtime,'_active_owner_task_issuance_v1',None)
    issued = runtime._active_foreground_issuance_v1
    if owner_task is not None:
        from .owner_source_note_task_issuance_v1 import require_owner_source_note_task_issuance_v1
        from .domain_production_commit_v1 import owner_task_domain_finish_digest_v1
        from .d11_life_contract_v1 import D11LifeExecutionBindingV1
        evidence=require_owner_source_note_task_issuance_v1(owner_task,graph,scope)
        if (issued is not None or type(binding) is not D11LifeExecutionBindingV1
                or evidence.request.operation_kind!='prepare_life'
                or evidence.request.operation_id!=binding.prepare_operation_id
                or attempt[0]!=canonical_digest(evidence.request)
                or preparation.frame.envelope.authority.actor!=evidence.current_self.self_entity_ref
                or preparation.prepared.plan.input_source.ref!=evidence.authorization.request.body_source_ref
                or preparation.prepared.plan.project.ref!=evidence.authorization.request.project_ref):
            raise ValueError('SourceNote Life preparation lost its exact independent Owner task witness')
        finish_digest=owner_task_domain_finish_digest_v1(evidence.request,scope.permit)
    elif issued is not None:
        from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
        from .domain_production_commit_v1 import foreground_domain_finish_digest_v1
        from .d11_life_contract_v1 import D11DraftExecutionBindingV1
        evidence = require_foreground_activity_issuance_v1(issued, graph, scope)
        if (type(binding) is not D11DraftExecutionBindingV1
                or evidence.request.operation_kind != "prepare_life"
                or evidence.request.operation_id != binding.prepare_operation_id
                or attempt[0] != canonical_digest(evidence.request)
                or preparation.frame.envelope.authority.actor != evidence.current_self.self_entity_ref):
            raise ValueError("draft Life preparation lost its exact independently issued foreground self witness")
        finish_digest = foreground_domain_finish_digest_v1(evidence.request, scope.permit)
    else:
        finish_digest = "sha256:" + canonical_digest({"schema": "w01.owner-domain-write.v3",
            "operation_id": binding.prepare_operation_id, "request_digest": attempt[0], "permit_token": scope.permit.token})
    _ACTIVE[id(witness)] = witness
    try:
        receipt = graph._commit_domain_bundle_fenced(bundle, process_lease, in_transaction=True,
            v2_write=(metadata, epoch, "finish:" + scope.operation_id, finish_digest, canonical_json(to_wire(scope.permit))),
            now_utc=preparation.frame.now_utc, domain_production_issuance_v1=witness)
    finally:
        _ACTIVE.pop(id(witness), None)
    prepared_original = record_life_preparation_after_cas_v1(db, issuer=readers.issuer,
        preparation=preparation, graph_receipt=receipt)
    original = record_adopted_domain_operation_v1(db, preparation.stage, receipt)
    return {"schema": "sylanne.domain-production-receipt.v1", "domain": "d10",
        "operation_kind": operation.operation_kind, "operation_id": binding.prepare_operation_id,
        "action_operation_id": binding.operation_id,
        "prepare_operation_id": preparation.prepared.prepare_operation_id, "activity_id": binding.activity_id,
        "original_ref": original.original_ref, "original_digest": original.original_digest,
        "receipt": _receipt_wire(receipt), "receipt_digest": canonical_digest(receipt),
        "job_states": [[preparation.job.job_id, preparation.job.phase]], "coverage": "deferred",
        "missing_inputs": ["actual_life_once_claim_and_durable_artifact_terminal"], "continuation_ref": preparation.job.job_id,
        "outbox": [], "produced_originals": [{"kind": prepared_original.kind,
            "original_ref": prepared_original.original_ref,
            "original_digest": prepared_original.original_digest}]}
