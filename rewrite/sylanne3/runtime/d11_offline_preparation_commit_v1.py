"""Atomic installed offline preparation, using actual running-job originals."""
from dataclasses import replace

from ..contracts import canonical_json
from ..runtime_contracts import DomainBundle, DomainProposal, DependencySet, canonical_digest
from .d11_types import job_graph_write, reconcile_runtime_write


def offline_preparation_bundle_v1(graph, preparation):
    from .d10_offline_tick_execution_v1 import D10OfflineTickPreparationStageV1
    if type(preparation) is not D10OfflineTickPreparationStageV1:
        raise TypeError("exact installed offline preparation required")
    envelope = replace(preparation.frame.envelope, identity=replace(preparation.frame.envelope.identity,
        operation_id=preparation.prepared.prepare_operation_id, effect_id=None, phase="d11.offline_tick.prepare.v1"))
    if preparation.stage.proposals or preparation.writes != (job_graph_write(preparation.job),):
        raise ValueError("offline preparation must have only its actual running-job projection")
    proposals = []
    for domain, writes in (("d10", ()), ("d11", preparation.writes)):
        provider = graph._GraphCoordinator__providers[domain]
        dependencies = {key for write in writes for key in write.dependencies}
        proposals.append(DomainProposal(domain, provider[1], provider[2], envelope, writes,
            DependencySet(current_invalidation=tuple(version for version in preparation.read_versions
                if version.key in dependencies)), (), ("persistent_job",)))
    return DomainBundle(envelope, tuple(proposals), (), (), (), (),
        (preparation.prepared.prepare_operation_id,), (job_graph_write(preparation.job).key.token,), ())


def commit_offline_preparation_v1(runtime, db, *, operation, request, preparation, readers,
        scope, owner, guard, metadata, epoch, process_lease, external_originals):
    from .d10_offline_tick_execution_v1 import (
        record_offline_tick_preparation_after_cas_v1, verify_offline_preparation_in_transaction_v1)
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1, _ACTIVE
    from .domain_production_originals_v1 import _receipt_wire
    from ..authority_service.v2_contract import to_wire
    graph = runtime.graph
    verify_offline_preparation_in_transaction_v1(db, preparation,
        issuer=readers.issuer, resource_issuer=graph._GraphCoordinator__d02_issuer)
    bundle = offline_preparation_bundle_v1(graph, preparation)
    for write in preparation.writes:
        reconcile_runtime_write(db, write)
    witness = _ProductionCommitWitnessV1(runtime, graph, scope, preparation.frame,
        preparation, operation, request, owner, guard, bundle, tuple(external_originals))
    binding = preparation.prepared.binding
    attempt = db.execute("SELECT request_digest,attempt_id FROM graph_owner_domain_attempts_v3 "
        "WHERE bot=? AND persona=? AND operation_id=?", (*binding.namespace.as_tuple, binding.operation_id)).fetchone()
    if attempt is None or attempt[1] != scope.operation_id:
        raise ValueError("offline preparation has no exact current Owner fence attempt")
    finish_digest = "sha256:" + canonical_digest({"schema": "w01.owner-domain-write.v3",
        "operation_id": binding.operation_id, "request_digest": attempt[0], "permit_token": scope.permit.token})
    _ACTIVE[id(witness)] = witness
    try:
        receipt = graph._commit_domain_bundle_fenced(bundle, process_lease, in_transaction=True,
            v2_write=(metadata, epoch, "finish:" + scope.operation_id, finish_digest, canonical_json(to_wire(scope.permit))),
            now_utc=preparation.frame.now_utc, domain_production_issuance_v1=witness)
    finally:
        _ACTIVE.pop(id(witness), None)
    original = record_offline_tick_preparation_after_cas_v1(db, issuer=readers.issuer,
        preparation=preparation, graph_receipt=receipt)
    return {"schema": "sylanne.domain-production-receipt.v1", "domain": "d10",
        "operation_kind": operation.operation_kind, "operation_id": binding.operation_id,
        "prepare_operation_id": preparation.prepared.prepare_operation_id, "activity_id": binding.activity_id,
        "original_ref": original.original_ref, "original_digest": original.original_digest,
        "receipt": _receipt_wire(receipt), "receipt_digest": canonical_digest(receipt),
        "job_states": [[preparation.job.job_id, preparation.job.phase]], "coverage": "deferred",
        "missing_inputs": ["actual_offline_tick_once_claim_and_terminal"], "continuation_ref": preparation.job.job_id,
        "outbox": []}
