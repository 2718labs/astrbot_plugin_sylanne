"""Private, current-fenced commit of the installed finite domain operation set.

No public DTO can issue a witness. The concrete installed runtime rebuilds the
stage in the actual transaction and binds it to that Graph, permit and bundle.
"""
from dataclasses import dataclass, replace
import json

from ..runtime_contracts import DomainBundle, DomainProposal, DependencySet, canonical_digest, canonical_serialize
from .domain_production_contracts_v1 import StagedDomainOperationV1
from .domain_production_originals_v1 import record_adopted_domain_operation_v1, _receipt_wire
from .d11_types import D11_PROPOSAL_SCHEMA, D11RuntimeProvider, job_graph_write, reconcile_runtime_write
from .jobs import create_job

OUTBOX_TABLE = 'graph_domain_production_outbox_v1'


def install_domain_production_outbox_v1(db):
    db.execute('''CREATE TABLE IF NOT EXISTS graph_domain_production_outbox_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, dedupe_key TEXT NOT NULL,
        causal_operation_id TEXT NOT NULL, receiver_domain TEXT NOT NULL, event_kind TEXT NOT NULL,
        original_ref TEXT NOT NULL, original_digest TEXT NOT NULL, state TEXT NOT NULL,
        consumer_operation_id TEXT, receipt_json TEXT,
        PRIMARY KEY(bot,persona,dedupe_key))''')
    db.execute('CREATE INDEX IF NOT EXISTS graph_domain_production_outbox_pending_v1 '
        'ON graph_domain_production_outbox_v1(bot,persona,state,dedupe_key)')


@dataclass(frozen=True, slots=True)
class _ProductionCommitWitnessV1:
    runtime: object
    graph: object
    scope: object
    frame: object
    stage: object
    operation: object
    request: object
    owner: object
    guard: object
    bundle: DomainBundle
    external_originals: tuple


_ACTIVE = {}


def require_current_production_commit_v1(witness, graph, db, bundle, v2_write):
    from .d11_offline_adoption_v1 import _OfflineCommitWitnessV1, require_offline_commit_v1
    if type(witness) is _OfflineCommitWitnessV1:
        return require_offline_commit_v1(witness, graph, db, bundle, v2_write)
    from .d11_life_adoption_v1 import _LifeCommitWitnessV1, require_life_commit_v1
    if type(witness) is _LifeCommitWitnessV1:
        return require_life_commit_v1(witness, graph, db, bundle, v2_write)
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.graph is not graph or witness.runtime.graph is not graph
            or db is not graph._GraphCoordinator__store._db or not db.in_transaction
            or not graph._GraphCoordinator__store._lock._is_owned()
            or bundle != witness.bundle or v2_write is None
            or witness.scope.graph_revision != v2_write[0].graph_revision
            or witness.scope.graph_epoch != v2_write[1]
            or witness.scope.permit.pinned_anchor != witness.scope.pinned_anchor
            or not graph._anchor_matches(v2_write[0].requirements, witness.scope.pinned_anchor)):
        raise ValueError('installed domain commit witness/current Graph fence differs')
    witness.runtime._current()
    # Rebuild before jobs/projections are staged; the concrete runtime froze it
    # under this exact independently validated write permit, with all policies
    # and current originals. Rechecking its full frozen readset below remains a
    # separate Graph CAS and never grants a model/native/platform execution.
    from .d07_execution_v1 import D07PreparationStageV1
    from .d10_offline_tick_execution_v1 import D10OfflineTickPreparationStageV1
    from .d11_life_preparation_v1 import LifePreparationStageV1
    from .contact_product_adapter_v1 import ContactModelStageV1
    if type(witness.stage) is D07PreparationStageV1:
        service = getattr(graph, '_GraphCoordinator__d07_execution_service_v1', None)
        if service is None:
            raise ValueError('actual D07 installed service disappeared')
        service.verify_preparation_in_transaction_v1(db, witness.stage)
        if _d07_preparation_bundle_v1(graph, witness.stage) != bundle:
            raise ValueError('D07 exact independently reissued preparation bundle differs')
    elif type(witness.stage) is D10OfflineTickPreparationStageV1:
        from .d10_offline_tick_execution_v1 import verify_offline_preparation_in_transaction_v1
        from .d11_offline_preparation_commit_v1 import offline_preparation_bundle_v1
        verify_offline_preparation_in_transaction_v1(db, witness.stage,
            issuer=graph._GraphCoordinator__d11_issuer, resource_issuer=graph._GraphCoordinator__d02_issuer)
        if offline_preparation_bundle_v1(graph, witness.stage) != bundle:
            raise ValueError('offline current prepared bundle differs')
    elif type(witness.stage) is LifePreparationStageV1:
        from .d11_life_preparation_v1 import verify_life_preparation_in_transaction_v1
        from .d11_life_preparation_commit_v1 import life_preparation_bundle_v1
        if type(witness.stage) is not LifePreparationStageV1:
            raise TypeError('exact installed Life preparation stage required')
        verify_life_preparation_in_transaction_v1(db, witness.stage,
            issuer=graph._GraphCoordinator__d11_issuer, resource_issuer=graph._GraphCoordinator__d02_issuer)
        if life_preparation_bundle_v1(graph, witness.stage) != bundle:
            raise ValueError('Life current prepared bundle differs')
    elif type(witness.stage) is ContactModelStageV1:
        from .contact_product_adapter_v1 import verify_contact_model_preparation_in_transaction_v1
        from .contact_model_preparation_commit_v1 import contact_model_preparation_bundle_v1
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        if assembly is None:
            raise ValueError('actual installed contact model assembly disappeared')
        verify_contact_model_preparation_in_transaction_v1(db, witness.stage,
            issuer=graph._GraphCoordinator__d11_issuer, resource_issuer=graph._GraphCoordinator__d02_issuer,
            installed_bundle=assembly.admin_bundle)
        if contact_model_preparation_bundle_v1(graph, witness.stage) != bundle:
            raise ValueError('contact current prepared bundle differs')
    elif witness.frame.envelope != bundle.envelope:
        raise ValueError('installed domain witness envelope differs')
    return witness


def _members(stage):
    from .contact_plan_adoption_v1 import ContactPlanStageV1
    if type(stage) is ContactPlanStageV1:
        from .contact_product_adapter_v1 import verify_contact_plan_stage_v1
        verify_contact_plan_stage_v1(stage)
        return stage.stage, stage.stage.proposals, (), (), ()
    from .d08_source_note_action_v1 import SourceNoteActionStageV1
    from .d02_life_body_preparation_v1 import LifeBodyPreparationStageV1
    if type(stage) is SourceNoteActionStageV1:
        return stage.stage, stage.stage.proposals, (), (), ()
    if type(stage) is LifeBodyPreparationStageV1:
        return stage.stage, stage.stage.proposals, (), (), ()
    from ..domains.d06.structured_experience_v1 import StructuredExperienceBundleV1
    from ..domains.d10.production_operations_v1 import CurrentLifeEffectExperienceBundleV1
    from .domain_production_inputs_v1 import StagedDomainInputV1
    from .d11_host_lifecycle_v1 import HostLifecycleStageV1
    if type(stage) is HostLifecycleStageV1:
        return stage.stage, (*stage.stage.proposals, stage.memory_proposal), (stage.original.source_ref,), (), ()
    if type(stage) is StagedDomainInputV1:
        return stage.stage, stage.stage.proposals, (), (), ()
    if type(stage) is StagedDomainOperationV1:
        return stage, stage.proposals, (), (), ()
    if type(stage) is CurrentLifeEffectExperienceBundleV1:
        return (stage.life_stage, (*stage.life_stage.proposals, *stage.body_stage.proposals, stage.memory_proposal),
            stage.experience_refs, stage.d02_settlement_refs, stage.d11_cost_settlement_refs)
    if type(stage) is StructuredExperienceBundleV1:
        return stage.memory_stage, (*stage.memory_stage.proposals, stage.context_proposal), stage.episode_refs, (), ()
    raise TypeError('registered operation returned an unrecognized concrete stage')


def commit_installed_domain_operation_v1(runtime, db, *, operation, request, frame, stage,
        readers, scope, owner, guard, metadata, epoch, process_lease, external_originals=()):
    graph = runtime.graph
    from .contact_product_adapter_v1 import ContactModelStageV1
    if type(stage) is ContactModelStageV1:
        from .contact_model_preparation_commit_v1 import commit_contact_model_preparation_v1
        return commit_contact_model_preparation_v1(runtime, db, operation=operation, request=request,
            preparation=stage, readers=readers, scope=scope, owner=owner, guard=guard,
            metadata=metadata, epoch=epoch, process_lease=process_lease, external_originals=external_originals)
    from .d11_life_preparation_v1 import LifePreparationStageV1
    if type(stage) is LifePreparationStageV1:
        from .d11_life_preparation_commit_v1 import commit_life_preparation_v1
        return commit_life_preparation_v1(runtime, db, operation=operation, request=request,
            preparation=stage, readers=readers, scope=scope, owner=owner, guard=guard,
            metadata=metadata, epoch=epoch, process_lease=process_lease, external_originals=external_originals)
    from .d10_offline_tick_execution_v1 import D10OfflineTickPreparationStageV1
    if type(stage) is D10OfflineTickPreparationStageV1:
        from .d11_offline_preparation_commit_v1 import commit_offline_preparation_v1
        return commit_offline_preparation_v1(runtime, db, operation=operation, request=request,
            preparation=stage, readers=readers, scope=scope, owner=owner, guard=guard,
            metadata=metadata, epoch=epoch, process_lease=process_lease, external_originals=external_originals)
    from .d07_execution_v1 import D07PreparationStageV1
    if type(stage) is D07PreparationStageV1:
        return commit_d07_preparation_v1(runtime, db, operation=operation, request=request,
            preparation=stage, readers=readers, scope=scope, owner=owner, guard=guard,
            metadata=metadata, epoch=epoch, process_lease=process_lease, external_originals=external_originals)
    # Pure/current readers are replayed from the same real DB before any new
    # projection row. A caller cannot pass a prebuilt proposal as authorization.
    rebuilt_frame, rebuilt, _ = runtime.compile_in_transaction(db, operation=operation, request=request,
        envelope=frame.envelope, scope=scope, owner=owner, guard=guard,
        now_utc=frame.now_utc, external_originals=external_originals)
    if rebuilt_frame != frame or rebuilt != stage:
        raise ValueError('current installed domain stage changed before atomic adoption')
    from .d02_life_body_preparation_v1 import LifeBodyPreparationStageV1, issue_life_body_quotes_before_cas_v1
    if type(stage) is LifeBodyPreparationStageV1:
        issue_life_body_quotes_before_cas_v1(db, frame=frame, staged=stage, installed_readers=readers)
    primary, proposals, experiences, settlements, paid_costs = _members(stage)
    if any(job.phase != 'waiting' or job.lease_holder is not None or job.fence or job.cancel_epoch
            or job.resource_ref != 'resource:unallocated' for job in primary.jobs):
        raise ValueError('pure domain staging can only persist unallocated waiting work')
    # Actual paid originals were independently reread by the fixed operation
    # reader. Referencing them here never settles them a second time.
    if paid_costs and not set(paid_costs) <= {value.original_ref for value in primary.paid_cost_originals}:
        raise ValueError('composite domain stage lacks its exact existing paid originals')
    job_writes = tuple(job_graph_write(job) for job in primary.jobs)
    if not set(write.key for write in job_writes) <= {v.key for v in frame.snapshot.versions}:
        raise ValueError('waiting job absence was not part of the original complete readset')
    for job, write in zip(primary.jobs, job_writes, strict=True):
        create_job(db, job, 'domain-wait:' + canonical_digest((primary.namespace, primary.operation_id, job.job_id))[:48],
            canonical_digest((primary.original_digest, job)))
        reconcile_runtime_write(db, write)
    if job_writes:
        provider = D11RuntimeProvider()
        proposals += (DomainProposal('d11', D11_PROPOSAL_SCHEMA, provider.descriptor.request_schema_hash,
            frame.envelope, job_writes, DependencySet(), (), ()),)
    if not proposals:
        registration = graph._GraphCoordinator__providers[operation.domain]
        proposals = (DomainProposal(operation.domain, registration[1], registration[2], frame.envelope,
            (), DependencySet(), (), ()),)
    bundle = DomainBundle(frame.envelope, tuple(proposals), experiences, (), settlements, (),
        (primary.operation_id,), tuple(write.key.token for write in job_writes), ())
    witness = _ProductionCommitWitnessV1(runtime, graph, scope, frame, stage, operation, request,
        owner, guard, bundle, tuple(external_originals))
    from ..authority_service.v2_contract import to_wire
    from ..contracts import canonical_json
    finish_id = 'finish:' + scope.operation_id
    attempt = db.execute('SELECT request_digest,attempt_id FROM graph_owner_domain_attempts_v3 '
        'WHERE bot=? AND persona=? AND operation_id=?', (*primary.namespace.as_tuple, primary.operation_id)).fetchone()
    if attempt is None or attempt[1] != scope.operation_id:
        raise ValueError('actual Owner operation original is absent')
    finish_digest = 'sha256:' + canonical_digest({'schema': 'w01.owner-domain-write.v3',
        'operation_id': primary.operation_id, 'request_digest': attempt[0], 'permit_token': scope.permit.token})
    _ACTIVE[id(witness)] = witness
    try:
        receipt = graph._commit_domain_bundle_fenced(bundle, process_lease, in_transaction=True,
            v2_write=(metadata, epoch, finish_id, finish_digest, canonical_json(to_wire(scope.permit))),
            now_utc=frame.now_utc, domain_production_issuance_v1=witness)
    finally:
        _ACTIVE.pop(id(witness), None)
    from .domain_production_inputs_v1 import StagedDomainInputV1, record_current_domain_input_after_commit_v1
    produced = ()
    from .contact_plan_adoption_v1 import ContactPlanStageV1, record_contact_plan_after_cas_v1
    if type(stage) is ContactPlanStageV1:
        from .domain_production_contracts_v1 import ProductionOriginalRefV1
        digest = record_contact_plan_after_cas_v1(db, stage=stage, issuer=readers.issuer, receipt=receipt)
        produced = (ProductionOriginalRefV1("d10.contact_plan", stage.plan.contact_id, digest),)
    from .d08_source_note_action_v1 import SourceNoteActionStageV1, record_source_note_action_after_cas_v1
    from .d02_life_body_preparation_v1 import record_life_body_preparation_after_cas_v1
    if type(stage) is SourceNoteActionStageV1:
        produced = (record_source_note_action_after_cas_v1(db, frame=frame, staged=stage, receipt=receipt, issuer=readers.issuer),)
    if type(stage) is LifeBodyPreparationStageV1:
        produced = (record_life_body_preparation_after_cas_v1(db, frame=frame, staged=stage, receipt=receipt, issuer=readers.issuer),)
    from .d11_host_lifecycle_v1 import HostLifecycleStageV1, record_host_lifecycle_after_cas_v1
    if type(stage) is HostLifecycleStageV1:
        produced = (record_host_lifecycle_after_cas_v1(db, frame=frame,
            staged=stage, graph_receipt=receipt, issuer=readers.issuer),)
    if type(stage) is StagedDomainInputV1:
        produced = record_current_domain_input_after_commit_v1(db, frame=frame, staged_input=stage,
            actual_receipt=receipt, installed_readers=readers)
    original = record_adopted_domain_operation_v1(db, primary, receipt)
    for event in primary.outbox:
        row = (*primary.namespace.as_tuple, event.dedupe_key, event.causal_operation_id,
            event.receiver_domain, event.event_kind, event.trigger_original.original_ref,
            event.trigger_original.original_digest, 'pending', None, None)
        old = db.execute('SELECT * FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?',
            row[:3]).fetchone()
        if old is not None and old != row:
            raise ValueError('domain followup event changed its durable identity')
        if old is None:
            db.execute('INSERT INTO graph_domain_production_outbox_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)', row)
    return {'schema': 'sylanne.domain-production-receipt.v1', 'domain': primary.domain,
        'operation_kind': primary.operation_kind, 'operation_id': primary.operation_id,
        'activity_id': primary.activity_id, 'original_ref': original.original_ref,
        'original_digest': original.original_digest, 'receipt': _receipt_wire(receipt),
        'receipt_digest': canonical_digest(receipt), 'job_states': [[j.job_id, j.phase] for j in primary.jobs],
        'coverage': primary.coverage, 'missing_inputs': list(primary.missing_inputs),
        'continuation_ref': primary.continuation_ref,
        'outbox': [event.dedupe_key for event in primary.outbox],
        'produced_originals': [{'kind': item.kind, 'original_ref': item.original_ref,
            'original_digest': item.original_digest} for item in produced]}


def _d07_preparation_bundle_v1(graph, preparation):
    from .d07_execution_v1 import D07PreparationStageV1
    if type(preparation) is not D07PreparationStageV1 or preparation.replayed:
        raise ValueError('D07 needs its actual first preparation, not a replayed DTO')
    frame, prepared = preparation.frame, preparation.prepared
    envelope = replace(frame.envelope, identity=replace(frame.envelope.identity,
        operation_id=prepared.prepare_operation_id, effect_id=None, phase='d07.cognitive.prepare.v1'))
    proposals = [replace(preparation.stage.proposal, envelope=envelope)]
    for domain, selected in (('d02', tuple(w for w in preparation.writes if w.key.type_name.startswith('d02.'))),
            ('d11', tuple(w for w in preparation.writes if w.key.type_name == 'runtime.job'))):
        registration = graph._GraphCoordinator__providers[domain]
        deps = {key for write in selected for key in write.dependencies}
        proposals.append(DomainProposal(domain, registration[1], registration[2], envelope, selected,
            DependencySet(current_invalidation=tuple(v for v in preparation.read_versions if v.key in deps)), (), ()))
    return DomainBundle(envelope, tuple(proposals), (), (), (), (), (prepared.prepare_operation_id,),
        (job_graph_write(preparation.job).key.token,), ())


def commit_d07_preparation_v1(runtime, db, *, operation, request, preparation, readers,
        scope, owner, guard, metadata, epoch, process_lease, external_originals):
    from .d07_execution_v1 import record_d07_preparation_after_cas_v1
    from ..authority_service.v2_contract import to_wire
    from ..contracts import canonical_json
    service = readers.execution_reader
    if service is not getattr(runtime.graph, '_GraphCoordinator__d07_execution_service_v1', None):
        raise ValueError('D07 preparation is not from this installed execution service')
    service.verify_preparation_in_transaction_v1(db, preparation)
    bundle = _d07_preparation_bundle_v1(runtime.graph, preparation)
    for write in preparation.writes:
        if write.key.type_name == 'runtime.job':
            reconcile_runtime_write(db, write)
    witness = _ProductionCommitWitnessV1(runtime, runtime.graph, scope, preparation.frame,
        preparation, operation, request, owner, guard, bundle, tuple(external_originals))
    base = preparation.prepared.operation_id
    attempt = db.execute('SELECT request_digest,attempt_id FROM graph_owner_domain_attempts_v3 '
        'WHERE bot=? AND persona=? AND operation_id=?', (*preparation.prepared.namespace.as_tuple, base)).fetchone()
    if attempt is None or attempt[1] != scope.operation_id:
        raise ValueError('D07 original Owner operation is absent')
    finish_digest = 'sha256:' + canonical_digest({'schema':'w01.owner-domain-write.v3',
        'operation_id':base,'request_digest':attempt[0],'permit_token':scope.permit.token})
    _ACTIVE[id(witness)] = witness
    try:
        receipt = runtime.graph._commit_domain_bundle_fenced(bundle, process_lease, in_transaction=True,
            v2_write=(metadata, epoch, 'finish:'+scope.operation_id, finish_digest, canonical_json(to_wire(scope.permit))),
            now_utc=preparation.frame.now_utc, domain_production_issuance_v1=witness)
    finally:
        _ACTIVE.pop(id(witness), None)
    original_digest = record_d07_preparation_after_cas_v1(db, service.d11_issuer, preparation, receipt)
    return {'schema':'sylanne.domain-production-receipt.v1','domain':'d07',
        'operation_kind':operation.operation_kind,'operation_id':base,
        'prepare_operation_id':preparation.prepared.prepare_operation_id,
        'activity_id':preparation.prepared.activity_id,'original_ref':'d07-prepared:'+base,
        'original_digest':original_digest,'receipt':_receipt_wire(receipt),
        'receipt_digest':canonical_digest(receipt),'job_states':[[preparation.job.job_id,preparation.job.phase]],
        'coverage':'deferred','missing_inputs':['actual_d07_original_execution'],
        'continuation_ref':preparation.job.job_id,'outbox':[]}
