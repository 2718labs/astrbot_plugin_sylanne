"""Actual W01 witness boundary for independent numeric Life operations."""


def require_exact_life_numeric_context_issuance_v1(witness, graph, bundle):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1, _ACTIVE
    from .d06_life_numeric_context_v1 import LifeNumericContextStageV1, OPERATION
    if (type(witness) is not _ProductionCommitWitnessV1
            or _ACTIVE.get(id(witness)) is not witness
            or witness.graph is not graph or witness.runtime.graph is not graph
            or type(witness.stage) is not LifeNumericContextStageV1
            or witness.operation.operation_kind != OPERATION
            or witness.bundle is not bundle or bundle.envelope != witness.stage.frame.envelope
            or bundle.proposals != witness.stage.proposals):
        raise ValueError('numeric Life context requires its exact active installed W01 witness')
    return witness


def _numeric_stage_types():
    from .d06_life_numeric_task_v1 import InternalLifeNumericPreparationStageV1, LifeNumericAppraisalAdoptionStageV1
    from .d06_life_numeric_worker_v1 import LifeNumericAcquisitionStageV1
    return InternalLifeNumericPreparationStageV1, LifeNumericAcquisitionStageV1, LifeNumericAppraisalAdoptionStageV1


def life_numeric_task_bundle_v1(stage):
    from ..runtime_contracts import DomainBundle
    from .d11_types import job_graph_write
    prepare, acquire, adopt = _numeric_stage_types()
    if type(stage) not in (prepare, acquire, adopt):
        raise TypeError('exact numeric Life task stage required')
    primary = stage.stage
    job = stage.completed_job if type(stage) is adopt else stage.job
    proposals = (*primary.proposals, stage.job_proposal) if type(stage) is adopt else primary.proposals
    if primary.jobs or primary.outbox or any(p.envelope != stage.frame.envelope for p in proposals):
        raise ValueError('numeric Life stage cannot add jobs or unrelated envelopes')
    writes = tuple(w for p in proposals for w in p.typed_writes)
    job_write = job_graph_write(job)
    if (sum(w == job_write for w in writes) != 1 or len(writes) != (2 if type(stage) is adopt else 1)):
        raise ValueError('numeric Life exact committed member inventory differs')
    return DomainBundle(stage.frame.envelope, proposals, (), (), (), (),
        (primary.operation_id,), (job_write.key.token,), ())


def require_exact_life_numeric_task_issuance_v1(witness, graph, bundle):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1, _ACTIVE
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.graph is not graph or witness.runtime.graph is not graph
            or type(witness.stage) not in _numeric_stage_types()
            or witness.bundle is not bundle or life_numeric_task_bundle_v1(witness.stage) != bundle):
        raise ValueError('numeric Life task requires its actual private W01 witness')
    return witness


def verify_life_numeric_task_commit_v1(db, witness, readers):
    from .d06_life_numeric_task_v1 import verify_life_numeric_preparation_in_transaction_v1, verify_life_numeric_appraisal_adoption_in_transaction_v1
    from .d06_life_numeric_worker_v1 import verify_life_numeric_acquisition_in_transaction_v1
    prepare, acquire, adopt = _numeric_stage_types()
    stage = witness.stage
    if type(stage) is prepare:
        verify_life_numeric_preparation_in_transaction_v1(db, stage, readers, readers.life_numeric_bundle)
    elif type(stage) is acquire:
        verify_life_numeric_acquisition_in_transaction_v1(db, stage, readers)
    elif type(stage) is adopt:
        verify_life_numeric_appraisal_adoption_in_transaction_v1(db, stage, readers)
    else:
        raise TypeError('numeric Life stage is unregistered')


def require_life_numeric_job_registration_v1(witness, db):
    require_exact_life_numeric_task_issuance_v1(witness, witness.graph, witness.bundle)
    prepare, _, _ = _numeric_stage_types()
    if type(witness.stage) is prepare:
        raise ValueError('numeric Life first prepare cannot reuse a persistent job registration')
    ref, = witness.bundle.persistent_job_refs
    p = witness.stage.prepared
    row = db.execute("SELECT operation_id FROM graph_bundle_refs WHERE bot=? AND persona=? AND ref_kind='persistent_job_refs' AND ref=?",
        (*p.namespace.as_tuple, ref)).fetchone()
    if row != (p.operation_id,):
        raise ValueError('numeric Life worker/adoption lost its first prepare registration')
    return (ref,)


def commit_life_numeric_task_v1(runtime, db, *, operation, request, preparation, readers,
        scope, owner, guard, metadata, epoch, process_lease, external_originals):
    import json
    from dataclasses import replace
    from types import SimpleNamespace
    from ..contracts import canonical_json
    from ..runtime_contracts import canonical_digest, canonical_serialize
    from ..authority_service.v2_contract import to_wire
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1, _ACTIVE
    from .domain_production_originals_v1 import record_adopted_domain_operation_v1, _receipt_wire
    from .d11_types import job_graph_write, reconcile_runtime_write
    from .d06_life_numeric_task_v1 import record_life_numeric_preparation_after_cas_v1, record_life_numeric_appraisal_acceptance_after_cas_v1
    from .d06_life_numeric_worker_v1 import record_life_numeric_acquisition_after_cas_v1
    graph = runtime.graph
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or readers.life_numeric_bundle is not assembly.admin_bundle:
        raise ValueError('numeric Life task lost its actual installation bundle')
    verify_life_numeric_task_commit_v1(db, SimpleNamespace(stage=preparation), readers)
    bundle = life_numeric_task_bundle_v1(preparation)
    primary = preparation.stage
    attempt = db.execute('SELECT request_digest,attempt_id,permit_json FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',
        (*primary.namespace.as_tuple, primary.operation_id)).fetchone()
    if (attempt is None or attempt[1] != scope.operation_id
            or attempt[2] != canonical_json(to_wire(scope.permit)) or preparation.frame.envelope.authority.actor != owner.actor):
        raise ValueError('numeric Life task lacks its actual Owner command/permit')
    prepare, acquire, adopt = _numeric_stage_types()
    job = preparation.completed_job if type(preparation) is adopt else preparation.job
    reconcile_runtime_write(db, job_graph_write(job))
    witness = _ProductionCommitWitnessV1(runtime, graph, scope, preparation.frame, preparation,
        operation, request, owner, guard, bundle, tuple(external_originals))
    finish = 'sha256:' + canonical_digest({'schema':'w01.owner-domain-write.v3',
        'operation_id':primary.operation_id, 'request_digest':attempt[0], 'permit_token':scope.permit.token})
    _ACTIVE[id(witness)] = witness
    try:
        receipt = graph._commit_domain_bundle_fenced(bundle, process_lease, in_transaction=True,
            v2_write=(metadata, epoch, 'finish:' + scope.operation_id, finish, canonical_json(to_wire(scope.permit))),
            now_utc=preparation.frame.now_utc, domain_production_issuance_v1=witness)
    finally:
        _ACTIVE.pop(id(witness), None)
    if type(preparation) is prepare:
        record_life_numeric_preparation_after_cas_v1(db, staged=preparation, issuer=readers.issuer, receipt=receipt)
    elif type(preparation) is acquire:
        record_life_numeric_acquisition_after_cas_v1(db, staged=preparation, issuer=readers.issuer, receipt=receipt)
    else:
        record_life_numeric_appraisal_acceptance_after_cas_v1(db, staged=preparation, issuer=readers.issuer, receipt=receipt)
        payload = json.loads(primary.original_payload_json)
        payload['writes'] = [{'key': w.key.token, 'value': w.value,
            'dependencies': [key.token for key in w.dependencies]} for p in bundle.proposals for w in p.typed_writes]
        primary = replace(primary, original_payload_json=canonical_serialize(payload), original_digest=canonical_digest(payload))
    original = record_adopted_domain_operation_v1(db, primary, receipt)
    return {'schema':'sylanne.domain-production-receipt.v1', 'domain':primary.domain,
        'operation_kind':operation.operation_kind, 'operation_id':primary.operation_id,
        'activity_id':primary.activity_id, 'original_ref':original.original_ref,
        'original_digest':original.original_digest, 'receipt':_receipt_wire(receipt),
        'receipt_digest':canonical_digest(receipt), 'job_states':[[job.job_id,job.phase]],
        'coverage':'complete' if type(preparation) is adopt else 'deferred',
        'missing_inputs':[] if type(preparation) is adopt else ['actual_numeric_terminal_and_appraisal_adoption'],
        'continuation_ref':None if type(preparation) is adopt else job.job_id, 'outbox':[]}


def life_numeric_math_stages_v1():
    from .d06_life_numeric_drive_v1 import LifeNumericDriveStageV1
    from .d04_life_encoding_baseline_v1 import LifeEncodingBaselineStageV1
    from .d06_life_numeric_trace_v1 import LifeNumericTraceStageV1
    return LifeNumericDriveStageV1, LifeEncodingBaselineStageV1, LifeNumericTraceStageV1


def require_exact_life_numeric_math_issuance_v1(witness, graph, bundle):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1, _ACTIVE
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.graph is not graph or witness.runtime.graph is not graph
            or type(witness.stage) not in life_numeric_math_stages_v1()
            or witness.bundle is not bundle or bundle.envelope != witness.stage.frame.envelope
            or witness.operation.operation_kind != witness.stage.primary_stage.operation_kind):
        raise ValueError('numeric Life math requires its exact active installed W01 witness')
    proposals = witness.stage.primary_stage.proposals
    if proposals:
        if bundle.proposals != proposals:
            raise ValueError('numeric Life math exact proposal inventory differs')
    elif (len(bundle.proposals) != 1 or bundle.proposals[0].typed_writes
            or bundle.proposals[0].domain != witness.stage.primary_stage.domain):
        raise ValueError('numeric Life interval baseline must retain its exact empty graph write set')
    return witness


def verify_life_numeric_math_stage_v1(db, stage, readers):
    from .d06_life_numeric_drive_v1 import verify_life_numeric_drive_stage_v1
    from .d04_life_encoding_baseline_v1 import verify_life_encoding_baseline_stage_v1
    from .d06_life_numeric_trace_v1 import verify_life_numeric_trace_stage_v1
    for kind, verify in zip(life_numeric_math_stages_v1(), (verify_life_numeric_drive_stage_v1,
            verify_life_encoding_baseline_stage_v1, verify_life_numeric_trace_stage_v1), strict=True):
        if type(stage) is kind:
            return verify(db, stage, installed_readers=readers)
    raise TypeError('unregistered numeric Life math stage')


def record_life_numeric_math_stage_v1(db, stage, issuer, receipt):
    from .d06_life_numeric_drive_v1 import record_life_numeric_drive_after_cas_v1
    from .d04_life_encoding_baseline_v1 import record_life_encoding_baseline_after_cas_v1
    from .d06_life_numeric_trace_v1 import record_life_numeric_trace_after_cas_v1
    for kind, record in zip(life_numeric_math_stages_v1(), (record_life_numeric_drive_after_cas_v1,
            record_life_encoding_baseline_after_cas_v1, record_life_numeric_trace_after_cas_v1), strict=True):
        if type(stage) is kind:
            result = record(db, stage=stage, issuer=issuer, receipt=receipt)
            from .d04_life_encoding_baseline_v1 import LifeEncodingBaselineStageV1, KIND
            if type(stage) is LifeEncodingBaselineStageV1:
                from .d11_life_preparation_v1 import _read
                from .domain_production_contracts_v1 import ProductionOriginalRefV1
                from ..domains.d01.production_operations_v1 import plain_v1
                from ..runtime_contracts import canonical_digest
                saved = _read(db, namespace=result.namespace, issuer=issuer, kind=KIND, ref=result.original_ref)
                if saved is None or saved[0] != plain_v1(result) or saved[1] != result.encoding_operation_id:
                    raise ValueError('Life baseline returned original differs from its actual signed row')
                return ProductionOriginalRefV1('d11.life_' + KIND, result.original_ref, canonical_digest(plain_v1(result)))
            return result
    raise TypeError('unregistered numeric Life math stage')


def commit_life_numeric_joint_stage_v1(runtime, db, *, stage, operation, frame, scope, metadata, epoch):
    from .d06_life_numeric_joint_v1 import LifeNumericJointStageV1, OPERATION, prepare_life_numeric_joint_in_transaction_v1
    runtime._current()
    graph = runtime.graph
    if (type(stage) is not LifeNumericJointStageV1 or operation.operation_kind != OPERATION
            or stage.graph is not graph or stage.frame is not frame
            or stage.metadata != metadata or stage.epoch != epoch
            or stage.installed_readers.life_numeric_scope is not scope
            or stage.bundle is not graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle):
        raise ValueError('Life joint requires its actual registered current Owner transaction')
    # The private producer rechecks its SQL-issued stage and commits the single
    # job CAS before freezing the numerical input. A second W01 CAS would stale it.
    ready, receipt = prepare_life_numeric_joint_in_transaction_v1(db, stage=stage)
    prepared = ready.prepared
    return {'status': 'numeric_prepared', 'operation_id': frame.envelope.identity.operation_id,
        'joint_operation_id': prepared.binding.operation_id, 'prepared_digest': prepared.digest,
        'binding_digest': prepared.binding.digest, 'job_id': prepared.binding.job_id,
        'worker_fence': ready.worker_fence}
