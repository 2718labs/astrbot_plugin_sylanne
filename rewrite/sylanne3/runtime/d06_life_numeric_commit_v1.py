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
    from ..runtime_contracts import PERSISTENT_JOB_REF_KIND
    require_exact_life_numeric_task_issuance_v1(witness, witness.graph, witness.bundle)
    prepare, _, _ = _numeric_stage_types()
    if type(witness.stage) is prepare:
        raise ValueError('numeric Life first prepare cannot reuse a persistent job registration')
    ref, = witness.bundle.persistent_job_refs
    p = witness.stage.prepared
    row = db.execute("SELECT operation_id FROM graph_bundle_refs WHERE bot=? AND persona=? AND ref_kind=? AND ref=?",
        (*p.namespace.as_tuple, PERSISTENT_JOB_REF_KIND, ref)).fetchone()
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
    if type(preparation) is adopt:
        from .jobs import transition_job
        original = preparation.original_job
        completed = transition_job(db, original.job_id, original.lease_holder, original.fence,
            target_phase='completed', result_ref=job.result_ref)
        if completed != job:
            raise ValueError('numeric Life official job transition differs from its exact staged completion')
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


def require_current_life_numeric_trace_write_v3(db, *, witness, stage, receipt, writes):
    from .d06_life_numeric_trace_v1 import LifeNumericTraceStageV1, OPERATION
    from ..graph_types import GraphVersion
    from ..runtime_contracts import CommitReceipt,NamespaceId
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE
    if type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness:
        raise ValueError("Life trace post-CAS requires its actual active WRITE witness")
    from ..runtime_storage_v3 import (runtime_storage_v3,runtime_storage_quantum_v3,
        _runtime_bounded_fixed_row_v3,begin_runtime_cell_read_v3,read_runtime_cell_origin_v3)
    from ..contracts import Event,Scope
    from hashlib import sha256
    import json
    require_exact_life_numeric_math_issuance_v1(witness,witness.graph,witness.bundle)
    graph=witness.graph;store=graph._GraphCoordinator__store;ns=stage.provenance.trace.namespace
    if (type(stage)is not LifeNumericTraceStageV1 or witness.stage is not stage
            or witness.frame is not stage.frame or witness.scope.operation!="write"
            or witness.operation.operation_kind!=OPERATION or witness.runtime.graph is not graph
            or not db.in_transaction or not store._lock._is_owned()
            or runtime_storage_v3(db)is None or witness.scope.namespace!=ns
            or type(receipt)is not CommitReceipt or receipt.status!="committed"
            or receipt.operation_id!=stage.provenance.trace.producing_operation_id
            or receipt.activity_id!=stage.frame.envelope.identity.activity_id
            or receipt.effect_id!=stage.frame.envelope.identity.effect_id
            or tuple(receipt.invalidated_epochs)!=(graph._v2_graph_stamp(ns)[1],)
            or receipt.read_versions!=stage.frame.envelope.version_guard.read_versions
            or tuple(w for proposal in witness.bundle.proposals for w in proposal.typed_writes)!=tuple(writes)
            or set(receipt.write_versions)!={GraphVersion(w.key,1)for w in writes}
            or witness.bundle.d11_cost_settlement_refs or witness.bundle.d02_settlement_refs
            or witness.bundle.persistent_job_refs or witness.bundle.outbox_refs or receipt.outbox_refs):
        raise ValueError("Life trace metadata witness differs from actual fresh WRITE/stage/COMMIT")
    expected_event=Event(Scope(*ns.as_tuple,receipt.activity_id),receipt.operation_id,
        stage.frame.envelope.source_qualification.learned_at,"domain_bundle",{"bundle_digest":receipt.operation_digest})
    with runtime_storage_quantum_v3(db)as meter:
        bundle=_runtime_bounded_fixed_row_v3(db,meter,"graph_bundle_operations",
            ("digest","activity_id","effect_id","commit_seq"),"bot=? AND persona=? AND operation_id=?",
            (*ns.as_tuple,receipt.operation_id))
        event=_runtime_bounded_fixed_row_v3(db,meter,"graph_events",("digest","epoch_revision"),
            "bot=? AND persona=? AND session=? AND event_id=?",(*ns.as_tuple,receipt.activity_id,receipt.operation_id))
        if (bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)
                or receipt.commit_seq<1 or event is None or event[0]!=expected_event.digest
                or len(receipt.invalidated_epochs)!=1 or receipt.invalidated_epochs[0].revision!=event[1]):
            raise ValueError("Life trace metadata lost actual W01 bundle/event/epoch membership")
        for write in writes:
            if NamespaceId.from_key(write.key)!=ns:
                raise ValueError("Life trace typed writes crossed actual namespace")
            head=_runtime_bounded_fixed_row_v3(db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(write.key.token,*ns.as_tuple))
            history=_runtime_bounded_fixed_row_v3(db,meter,"graph_history",
                ("valid","value_cell_id","event_bot","event_persona","event_session","event_id"),
                "token=? AND revision=1 AND event_bot=? AND event_persona=?",(write.key.token,*ns.as_tuple))
            if (head is None or head[:2]!=(1,1) or history!=(1,head[2],*ns.as_tuple,receipt.activity_id,receipt.operation_id)):
                raise ValueError("Life trace typed write lacks exact current head/history cell membership")
            cell=begin_runtime_cell_read_v3(db,head[2],erasure_owner_ref=write.key.token)
            origin=read_runtime_cell_origin_v3(db,head[2],header=cell.header,meter=meter)
            normalized=store._registry.validate(write.key,write.value)
            wire=json.dumps(normalized,sort_keys=True,separators=(",",":"),ensure_ascii=cell.header[0]!="canonical-json.utf8.v1")
            expected=wire.encode("utf8")
            if (cell.header[2]!=receipt.operation_id or cell.header[3]!=len(expected)
                    or cell.header[5]!=sha256(expected).hexdigest()
                    or origin is None or origin["operation_id"]!=receipt.operation_id
                    or origin["event_digest"]!=event[0]
                    or origin["locator"]!={"table":"graph_atoms","token":write.key.token,"revision":1}):
                raise ValueError("Life trace output cell metadata differs from actual typed W01 write")
    return receipt

def record_current_life_numeric_trace_original_v3(db, *, witness, stage, issuer, receipt):
    from .d06_life_numeric_trace_v1 import SIGNED_KIND,_writes
    from .d11_life_preparation_v1 import TABLE,SIGN_KIND
    from .issuers import D11BudgetJobIssuer
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..runtime_contracts import canonical_digest,canonical_serialize
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    require_current_life_numeric_trace_write_v3(db,witness=witness,stage=stage,receipt=receipt,writes=_writes(stage.provenance))
    if type(issuer)is not D11BudgetJobIssuer or issuer is not witness.runtime.graph._GraphCoordinator__d11_issuer:
        raise ValueError("Life trace WRITE original requires actual installed W01 issuer")
    trace=stage.provenance.trace
    value=plain_v1(stage.provenance);wire=canonical_serialize(value);digest=canonical_digest(value)
    signature=issuer._signer.sign(SIGN_KIND,canonical_serialize((trace.namespace,SIGNED_KIND,trace.trace_ref,digest)))
    key=(*trace.namespace.as_tuple,SIGNED_KIND,trace.trace_ref)
    expected=(trace.producing_operation_id,digest,signature)
    with runtime_storage_quantum_v3(db)as meter:
        old=_runtime_bounded_fixed_row_v3(db,meter,TABLE,("producing_operation_id","payload_digest","signature"),
            "bot=? AND persona=? AND kind=? AND original_ref=?",key)
    if old is not None and old!=expected:raise ValueError("Life immutable trace original replay differs")
    if old is None:
        db.execute("INSERT INTO "+TABLE+" VALUES(?,?,?,?,?,?,?,?)",(*key,expected[0],wire,digest,signature))
    return ProductionOriginalRefV1("d11.life_"+SIGNED_KIND,trace.trace_ref,digest)

def require_current_life_encoding_write_v3(db,*,witness,stage,receipt):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE
    from .d04_life_encoding_baseline_v1 import LifeEncodingBaselineStageV1,OPERATION,life_encoding_baseline_ids_v1
    from ..runtime_contracts import CommitReceipt
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    from ..contracts import Event,Scope
    if type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness:
        raise ValueError("Life encoding requires actual active W01 WRITE witness")
    require_exact_life_numeric_math_issuance_v1(witness,witness.graph,witness.bundle)
    graph=witness.graph;ns=stage.context.original.namespace
    ids=life_encoding_baseline_ids_v1(ns,stage.request.episode_ref,stage.request.joint_operation_id)
    if (type(stage)is not LifeEncodingBaselineStageV1 or witness.stage is not stage
            or witness.frame is not stage.frame or witness.scope.operation!="write"
            or witness.operation.operation_kind!=OPERATION or not db.in_transaction
            or not graph._GraphCoordinator__store._lock._is_owned() or witness.scope.namespace!=ns
            or type(receipt)is not CommitReceipt or receipt.status!="committed"
            or receipt.operation_id!=ids["operation"] or receipt.activity_id!=stage.frame.envelope.identity.activity_id
            or receipt.effect_id!=stage.frame.envelope.identity.effect_id
            or receipt.read_versions!=stage.frame.envelope.version_guard.read_versions or receipt.write_versions
            or tuple(receipt.invalidated_epochs)!=(graph._v2_graph_stamp(ns)[1],)
            or any(proposal.typed_writes for proposal in witness.bundle.proposals)
            or witness.bundle.d11_cost_settlement_refs or witness.bundle.d02_settlement_refs
            or witness.bundle.persistent_job_refs or witness.bundle.outbox_refs or receipt.outbox_refs):
        raise ValueError("Life encoding changed actual zero-write W01 scope/receipt/member inventory")
    from .current_method_learning_read_v3 import _method_active
    prepared=_method_active(db).prepared_encoding_inputs_v3
    current_stamp=graph._v2_graph_stamp(ns)
    if (prepared is None or current_stamp[0].graph_revision!=prepared.before_stamp[0].graph_revision+1
            or current_stamp[1].revision!=prepared.before_stamp[1].revision+1):
        raise ValueError("Life encoding requires actual one-commit E+1 transition")
    expected_event=Event(Scope(*ns.as_tuple,receipt.activity_id),receipt.operation_id,
        stage.frame.envelope.source_qualification.learned_at,"domain_bundle",{"bundle_digest":receipt.operation_digest})
    with runtime_storage_quantum_v3(db)as meter:
        bundle=_runtime_bounded_fixed_row_v3(db,meter,"graph_bundle_operations",
            ("digest","activity_id","effect_id","commit_seq"),"bot=? AND persona=? AND operation_id=?",
            (*ns.as_tuple,receipt.operation_id))
        event=_runtime_bounded_fixed_row_v3(db,meter,"graph_events",("digest","epoch_revision"),
            "bot=? AND persona=? AND session=? AND event_id=?",(*ns.as_tuple,receipt.activity_id,receipt.operation_id))
    if (bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)
            or receipt.commit_seq<1 or event is None or event[0]!=expected_event.digest
            or receipt.invalidated_epochs[0].revision!=event[1]):
        raise ValueError("Life encoding lost actual W01 zero-write event/bundle/current epoch")
    return receipt

def record_current_life_encoding_original_v3(db,*,witness,stage,issuer,receipt,original):
    from .d11_life_preparation_v1 import TABLE,SIGN_KIND
    from .issuers import D11BudgetJobIssuer
    from .d04_life_encoding_baseline_v1 import KIND
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..runtime_contracts import canonical_serialize,canonical_digest
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    from .c04_encoding_context_original_v3 import active_w01_life_encoding_inputs_v3
    require_current_life_encoding_write_v3(db,witness=witness,stage=stage,receipt=receipt)
    prepared=active_w01_life_encoding_inputs_v3(db)
    if prepared is None or type(issuer)is not D11BudgetJobIssuer or issuer is not witness.graph._GraphCoordinator__d11_issuer:
        raise ValueError("Life encoding original requires installed ACTIVE W01 prepared input/issuer")
    value=plain_v1(original);wire=canonical_serialize(value);digest=canonical_digest(value)
    signature=issuer._signer.sign(SIGN_KIND,canonical_serialize((original.namespace,KIND,original.original_ref,digest)))
    key=(*original.namespace.as_tuple,KIND,original.original_ref)
    expected=(original.encoding_operation_id,digest,signature)
    with runtime_storage_quantum_v3(db)as meter:
        old=_runtime_bounded_fixed_row_v3(db,meter,TABLE,("producing_operation_id","payload_digest","signature"),
            "bot=? AND persona=? AND kind=? AND original_ref=?",key)
    if old!=(None if prepared.life_prior is None else (prepared.life_prior[0],prepared.life_prior[2],prepared.life_prior[3])):
        raise ValueError("Life encoding signed prior changed after prepared EOF")
    if old is not None and old!=expected:raise ValueError("Life immutable encoding original replay differs")
    if old is None:db.execute("INSERT INTO "+TABLE+" VALUES(?,?,?,?,?,?,?,?)",(*key,expected[0],wire,digest,signature))
    return original

def record_life_numeric_math_stage_v1(db, stage, issuer, receipt, *, trace_commit_witness_v3=None, encoding_commit_witness_v3=None, drive_commit_witness_v3=None):
    from .d06_life_numeric_drive_v1 import record_life_numeric_drive_after_cas_v1
    from .d04_life_encoding_baseline_v1 import record_life_encoding_baseline_after_cas_v1
    from .d06_life_numeric_trace_v1 import record_life_numeric_trace_after_cas_v1
    for kind, record in zip(life_numeric_math_stages_v1(), (record_life_numeric_drive_after_cas_v1,
            record_life_encoding_baseline_after_cas_v1, record_life_numeric_trace_after_cas_v1), strict=True):
        if type(stage) is kind:
            if kind is life_numeric_math_stages_v1()[2]:
                result=record(db,stage=stage,issuer=issuer,receipt=receipt,trace_commit_witness_v3=trace_commit_witness_v3)
            elif kind is life_numeric_math_stages_v1()[1]:
                result=record(db,stage=stage,issuer=issuer,receipt=receipt,encoding_commit_witness_v3=encoding_commit_witness_v3)
            else:result = record(db, stage=stage, issuer=issuer, receipt=receipt,drive_commit_witness_v3=drive_commit_witness_v3)
            from .d04_life_encoding_baseline_v1 import LifeEncodingBaselineStageV1, KIND
            if type(stage) is LifeEncodingBaselineStageV1:
                from .domain_production_contracts_v1 import ProductionOriginalRefV1
                from ..domains.d01.production_operations_v1 import plain_v1
                from ..runtime_contracts import canonical_digest
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

def require_current_life_numeric_drive_write_v3(db, *, witness, stage, receipt, writes):
    from .d06_life_numeric_drive_v1 import LifeNumericDriveStageV1, OPERATION,require_active_numeric_drive_inputs_v3
    from ..graph_types import GraphVersion
    from ..runtime_contracts import CommitReceipt,NamespaceId
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE
    if type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness:
        raise ValueError("Life drive post-CAS requires its actual active WRITE witness")
    from ..runtime_storage_v3 import (runtime_storage_v3,runtime_storage_quantum_v3,
        _runtime_bounded_fixed_row_v3,begin_runtime_cell_read_v3,read_runtime_cell_origin_v3)
    from ..contracts import Event,Scope
    from hashlib import sha256
    import json
    require_exact_life_numeric_math_issuance_v1(witness,witness.graph,witness.bundle)
    graph=witness.graph;store=graph._GraphCoordinator__store;ns=stage.original.namespace
    if (type(stage)is not LifeNumericDriveStageV1 or witness.stage is not stage
            or witness.frame is not stage.frame or witness.scope.operation!="write"
            or witness.operation.operation_kind!=OPERATION or witness.runtime.graph is not graph
            or not db.in_transaction or not store._lock._is_owned()
            or runtime_storage_v3(db)is None or witness.scope.namespace!=ns
            or type(receipt)is not CommitReceipt or receipt.status!="committed"
            or receipt.operation_id!=stage.original.operation_id
            or receipt.activity_id!=stage.frame.envelope.identity.activity_id
            or receipt.effect_id!=stage.frame.envelope.identity.effect_id
            or tuple(receipt.invalidated_epochs)!=(graph._v2_graph_stamp(ns)[1],)
            or receipt.read_versions!=stage.frame.envelope.version_guard.read_versions
            or tuple(w for proposal in witness.bundle.proposals for w in proposal.typed_writes)!=tuple(writes)
            or set(receipt.write_versions)!={GraphVersion(w.key,1)for w in writes}
            or witness.bundle.d11_cost_settlement_refs or witness.bundle.d02_settlement_refs
            or witness.bundle.persistent_job_refs or witness.bundle.outbox_refs or receipt.outbox_refs):
        raise ValueError("Life drive metadata witness differs from actual fresh WRITE/stage/COMMIT")
    expected_event=Event(Scope(*ns.as_tuple,receipt.activity_id),receipt.operation_id,
        stage.frame.envelope.source_qualification.learned_at,"domain_bundle",{"bundle_digest":receipt.operation_digest})
    with runtime_storage_quantum_v3(db)as meter:
        bundle=_runtime_bounded_fixed_row_v3(db,meter,"graph_bundle_operations",
            ("digest","activity_id","effect_id","commit_seq"),"bot=? AND persona=? AND operation_id=?",
            (*ns.as_tuple,receipt.operation_id))
        event=_runtime_bounded_fixed_row_v3(db,meter,"graph_events",("digest","epoch_revision"),
            "bot=? AND persona=? AND session=? AND event_id=?",(*ns.as_tuple,receipt.activity_id,receipt.operation_id))
        if (bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)
                or receipt.commit_seq<1 or event is None or event[0]!=expected_event.digest
                or len(receipt.invalidated_epochs)!=1 or receipt.invalidated_epochs[0].revision!=event[1]):
            raise ValueError("Life drive metadata lost actual W01 bundle/event/epoch membership")
        for write in writes:
            if NamespaceId.from_key(write.key)!=ns:
                raise ValueError("Life drive typed writes crossed actual namespace")
            head=_runtime_bounded_fixed_row_v3(db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(write.key.token,*ns.as_tuple))
            history=_runtime_bounded_fixed_row_v3(db,meter,"graph_history",
                ("valid","value_cell_id","event_bot","event_persona","event_session","event_id"),
                "token=? AND revision=1 AND event_bot=? AND event_persona=?",(write.key.token,*ns.as_tuple))
            if (head is None or head[:2]!=(1,1) or history!=(1,head[2],*ns.as_tuple,receipt.activity_id,receipt.operation_id)):
                raise ValueError("Life drive typed write lacks exact current head/history cell membership")
            cell=begin_runtime_cell_read_v3(db,head[2],erasure_owner_ref=write.key.token)
            origin=read_runtime_cell_origin_v3(db,head[2],header=cell.header,meter=meter)
            normalized=store._registry.validate(write.key,write.value)
            wire=json.dumps(normalized,sort_keys=True,separators=(",",":"),ensure_ascii=cell.header[0]!="canonical-json.utf8.v1")
            expected=wire.encode("utf8")
            if (cell.header[2]!=receipt.operation_id or cell.header[3]!=len(expected)
                    or cell.header[5]!=sha256(expected).hexdigest()
                    or origin is None or origin["operation_id"]!=receipt.operation_id
                    or origin["event_digest"]!=event[0]
                    or origin["locator"]!={"table":"graph_atoms","token":write.key.token,"revision":1}):
                raise ValueError("Life drive output cell metadata differs from actual typed W01 write")
    capsule=require_active_numeric_drive_inputs_v3(db,witness,stage,receipt)
    current=graph._v2_graph_stamp(ns)
    if (current[0].graph_revision!=capsule.before_stamp[0].graph_revision+1
            or current[1].revision!=capsule.before_stamp[1].revision+1
            or tuple(writes)!=stage.mapping_stage.writes):
        raise ValueError("Life drive lacks its actual one-commit all-member mapping transition")
    return receipt


def record_current_life_numeric_drive_original_v3(db,*,witness,stage,issuer,receipt,writes):
    from ..runtime_contracts import canonical_serialize,canonical_digest
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    from .d06_life_numeric_drive_v1 import KIND,require_active_numeric_drive_inputs_v3
    from .d11_life_preparation_v1 import TABLE,SIGN_KIND
    from .issuers import D11BudgetJobIssuer
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    from ..domains.d01.production_operations_v1 import plain_v1
    require_current_life_numeric_drive_write_v3(db,witness=witness,stage=stage,receipt=receipt,writes=writes)
    capsule=require_active_numeric_drive_inputs_v3(db,witness,stage,receipt)
    if type(issuer)is not D11BudgetJobIssuer or issuer is not witness.graph._GraphCoordinator__d11_issuer:
        raise ValueError("Life drive original requires actual installed ACTIVE W01 issuer")
    original=stage.original;value=plain_v1(original);wire=canonical_serialize(value);digest=canonical_digest(value)
    signature=issuer._signer.sign(SIGN_KIND,canonical_serialize((original.namespace,KIND,original.original_ref,digest)))
    key=(*original.namespace.as_tuple,KIND,original.original_ref);expected=(original.operation_id,digest,signature)
    with runtime_storage_quantum_v3(db)as meter:
        old=_runtime_bounded_fixed_row_v3(db,meter,TABLE,("producing_operation_id","payload_digest","signature"),
            "bot=? AND persona=? AND kind=? AND original_ref=?",key)
    prior=None if capsule.life_prior is None else (capsule.life_prior[0],capsule.life_prior[2],capsule.life_prior[3])
    if old!=prior:raise ValueError("Life drive signed original prior changed after actual EOF")
    if old is not None and (old!=expected or capsule.life_prior[1]!=wire):
        raise ValueError("Life immutable drive original replay differs")
    if old is None:db.execute("INSERT INTO "+TABLE+" VALUES(?,?,?,?,?,?,?,?)",(*key,expected[0],wire,digest,signature))
    return ProductionOriginalRefV1("d11.life_"+KIND,original.original_ref,digest)
