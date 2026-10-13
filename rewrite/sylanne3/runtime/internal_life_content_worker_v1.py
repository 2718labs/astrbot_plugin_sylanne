"""Life-only acquired model input on the installed Owner/GCP transaction.

Public requests are locators. This stage requalifies the actual occurrence;
neither a frozen DTO nor a signed preparation supplies current permission.
"""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..graph_types import AtomKey, GraphVersion
from ..model_broker.broker import ModelCallRequest
from ..model_broker.internal_life_content_v1 import WORK_KIND, TEMPLATE_DIGEST, thaw_internal_life_content_request_v1
from ..runtime_contracts import QueryEpoch, VersionedRef, canonical_digest, canonical_serialize
from .d06_internal_life_encoding_v1 import EncodeInternalLifeRequestV1, read_current_internal_life_encoding_cause_v1
from .d01_production_operations_v1 import CurrentDomainReadV1
from .d11_types import TYPE_SCHEMA_HASHES, job_graph_write
from .jobs import acquire_job, get_job
from .internal_life_content_preparation_v1 import (
    TABLE, SIGN_KIND, InternalLifeContentPreparedV1, PrepareInternalLifeContentRequestV1, read_plan_internal_life_content_v1,
    read_committed_internal_life_prepared_v1, require_internal_life_content_schema_v1,
)
from .reply_model_job import reply_request_wire_v1
from .natural_reply_job_v2 import _request_from_wire
from .domain_production_contracts_v1 import StagedDomainOperationV1, CurrentOperationFrameV1
from .jobs import PersistentJob
from ..model_broker.internal_life_content_v1 import FrozenInternalLifeContentRequestV1

OPERATION = 'acquire_internal_life_content'
PROPOSAL_SCHEMA = 'd11.internal-life-content-acquisition.proposal.v1'
from ..runtime_contracts import schema_hash
PROPOSAL_HASH = schema_hash({'schema':PROPOSAL_SCHEMA,
    'job_schema_hash':TYPE_SCHEMA_HASHES['runtime.job'],
    'transition':'original_prepare_operation/queued_to_running_once'})


@dataclass(frozen=True, slots=True)
class AcquireInternalLifeContentRequestV1:
    episode_ref: str
    causal_operation_id: str

    def __post_init__(self):
        EncodeInternalLifeRequestV1(self.episode_ref, self.causal_operation_id)


@dataclass(frozen=True, slots=True)
class InternalLifeContentAcquisitionStageV1:
    stage: StagedDomainOperationV1
    prepared: InternalLifeContentPreparedV1
    frozen: FrozenInternalLifeContentRequestV1
    job: PersistentJob
    request: ModelCallRequest
    frame: CurrentOperationFrameV1


def read_life_worker_original_v1(db, *, namespace, issuer, kind, ref):
    require_internal_life_content_schema_v1(db)
    row = db.execute(f'SELECT payload_json,payload_digest,signature FROM {TABLE} '
        'WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
        (*namespace.as_tuple, kind, ref)).fetchone()
    if row is None:
        return None
    from .c09_internal_life_content_v1 import COLUMNS, validate_internal_life_content_inventory_row_v1
    raw = validate_internal_life_content_inventory_row_v1(COLUMNS,
        (*namespace.as_tuple, kind, ref, *row))
    issuer._signer.verify(SIGN_KIND, canonical_serialize((namespace, kind, ref, row[1])), row[2])
    return raw


def record_life_worker_original_v1(db, *, namespace, issuer, kind, ref, value):
    if not db.in_transaction:
        raise ValueError('Life worker original requires its actual producing SQL transaction')
    require_internal_life_content_schema_v1(db)
    encoded = canonical_serialize(plain_v1(value)); digest = canonical_digest(json.loads(encoded))
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((namespace, kind, ref, digest)))
    from .c09_internal_life_content_v1 import COLUMNS, validate_internal_life_content_inventory_row_v1
    row = (*namespace.as_tuple, kind, ref, encoded, digest, signature)
    validate_internal_life_content_inventory_row_v1(COLUMNS, row)
    old = read_life_worker_original_v1(db, namespace=namespace, issuer=issuer, kind=kind, ref=ref)
    if old is not None:
        if canonical_serialize(old) != encoded:
            raise ValueError('Life once worker original cannot change')
        return old
    db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)', row)
    return json.loads(encoded)


def read_plan_internal_life_acquire_v1(db, *, namespace, activity_id, operation_kind, request):
    if operation_kind != OPERATION or type(request) is not AcquireInternalLifeContentRequestV1:
        raise TypeError('exact registered Life acquisition locator required')
    return read_plan_internal_life_content_v1(db, namespace=namespace, activity_id=activity_id,
        operation_kind='prepare_internal_life_content',
        request=PrepareInternalLifeContentRequestV1(request.episode_ref, request.causal_operation_id))


def _current(db, frame, request, readers):
    from ..host.model_workflows_v3 import AdminModelWorkflowsV3
    from ..host.model_workflows_v4 import AdminModelWorkflowsV4
    from ..host.model_workflows_v5 import AdminModelWorkflowsV5
    from ..host.model_workflows_v6 import AdminModelWorkflowsV6
    from ..host.model_workflows_v7 import AdminModelWorkflowsV7
    from ..model_broker.internal_life_content_v1 import internal_life_content_ids_v1, TEMPLATE_VERSION
    read = CurrentDomainReadV1(frame); read.check(db)
    cause = read_current_internal_life_encoding_cause_v1(db, frame=frame,
        request=EncodeInternalLifeRequestV1(request.episode_ref, request.causal_operation_id), installed_readers=readers)
    ids = internal_life_content_ids_v1(cause)
    prepared = read_committed_internal_life_prepared_v1(db, namespace=frame.envelope.authority.namespace,
        issuer=readers.issuer, job_id=ids['job'])
    frozen = thaw_internal_life_content_request_v1(json.loads(prepared.frozen_json))
    bundle = readers.life_content_bundle
    workflow = bundle.model_workflows.life_content
    if (type(bundle.model_workflows) not in (AdminModelWorkflowsV3,AdminModelWorkflowsV4,AdminModelWorkflowsV5,AdminModelWorkflowsV6,AdminModelWorkflowsV7) or workflow is None
            or (workflow.work_kind, workflow.purpose, workflow.template_version) !=
                (WORK_KIND, 'consolidation', TEMPLATE_VERSION)
            or prepared.occurrence_digest != canonical_digest(plain_v1(cause.occurrence.event))
            or prepared.owner_head_digest != frame.owner_guard.owner_head_digest
            or prepared.episode_ref != request.episode_ref
            or prepared.provider_config_ref != workflow.provider_config_ref
            or (frozen.provider_id, frozen.model_id, frozen.provider_config_digest, frozen.max_output_tokens) !=
                (workflow.provider_id, workflow.model_id, workflow.provider_config_digest, workflow.max_output_tokens)
            or frame.envelope.identity.operation_id != ids['acquire']
            or frame.envelope.authority.purpose != 'consolidation'
            or frame.envelope.authority.audience != (frozen.input.audience,)
            or not frame.now_utc < frozen.input.expires_at_utc):
        raise ValueError('Life acquisition changed its actual occurrence/current Owner/workflow/once identity')
    quote = readers.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
    reservation = db.execute('SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
        (quote.parent_budget_lease_ref, prepared.prepare_operation_id)).fetchone()
    if (canonical_digest(quote) != prepared.quote_digest
            or (quote.operation_id, quote.work_kind, quote.resource_ref) !=
                (prepared.prepare_operation_id, WORK_KIND, prepared.provider_config_ref)
            or frame.envelope.parent_budget_lease_ref != quote.parent_budget_lease_ref
            or reservation != (prepared.reservation_digest, canonical_serialize(dict(quote.ceiling)), 'reserved')):
        raise ValueError('Life acquisition lacks its actual signed once quote/reservation')
    return prepared, frozen, workflow


def stage_acquire_internal_life_content_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(request) is not AcquireInternalLifeContentRequestV1 or not db.in_transaction:
        raise ValueError('actual installed Life acquisition transaction required')
    prepared, frozen, workflow = _current(db, frame, request, installed_readers)
    job = get_job(db, prepared.job_id)
    if job is None or job.phase != 'queued' or job.fence != 0 or job.cancel_epoch != 0:
        raise ValueError('Life once queued job cannot be replaced or reacquired')
    job = acquire_job(db, job.job_id, frame.envelope.authority.actor,
        now_utc=datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace('+00:00', 'Z'),
        lease_seconds=min(3600, int(workflow.timeout_seconds) + 120))
    key = job_graph_write(job).key
    model = _acquired_model_request(frame, prepared, frozen, workflow, job)
    record_life_worker_original_v1(db, namespace=prepared.namespace, issuer=installed_readers.issuer,
        kind='request', ref=prepared.job_id, value={'schema':'d06.internal-life-content-request.v1',
            'prepared_digest':prepared.digest, 'request_digest':model.digest, 'worker_fence':job.fence,
            'wire':canonical_serialize(reply_request_wire_v1(model.envelope, model))})
    primary = stage_result_v1(frame, 'd11', OPERATION, request, writes=(job_graph_write(job),),
        provenance={'schema':'d06.internal-life-content-acquisition.v1', 'prepared_digest':prepared.digest,
            'episode_ref':prepared.episode_ref, 'request_digest':model.digest, 'job_ref':key.token},
        proposal_schema=PROPOSAL_SCHEMA, proposal_hash=PROPOSAL_HASH)
    validate_internal_life_acquisition_proposal_v1(primary.proposals[0], frame.snapshot)
    return InternalLifeContentAcquisitionStageV1(primary, prepared, frozen, job, model, frame)


def validate_internal_life_acquisition_proposal_v1(proposal, snapshot):
    """Closed pure transition shape; this function issues no permission."""
    from .d11_types import _decode, RuntimeJobValue
    from ..runtime_contracts import DomainProposal
    from ..graph_types import GraphSnapshot
    if (type(proposal) is not DomainProposal or type(snapshot) is not GraphSnapshot
            or (proposal.domain,proposal.proposal_schema,proposal.proposal_schema_hash) !=
                ('d11',PROPOSAL_SCHEMA,PROPOSAL_HASH) or len(proposal.typed_writes) != 1):
        raise ValueError('Life acquisition requires its independent closed proposal')
    write = proposal.typed_writes[0]
    value = _decode(write)
    before = snapshot.get(write.key)
    suffix = value.job_id.removeprefix('life-content-job:') if type(value) is RuntimeJobValue else ''
    if (type(value) is not RuntimeJobValue or len(suffix) != 48 or any(c not in '0123456789abcdef' for c in suffix)
            or value.job_id != 'life-content-job:' + suffix
            or value.operation_id != 'life-content-prepare:' + suffix
            or proposal.envelope.identity.operation_id != 'life-content-acquire:' + suffix
            or proposal.envelope.identity.phase != OPERATION
            or write.key.type_name != 'runtime.job' or write.key.owner.kind != 'activity' or write.key.name != value.job_id
            or (write.key.owner.bot,write.key.owner.persona,write.key.owner.subject) !=
                (*proposal.envelope.authority.namespace.as_tuple,proposal.envelope.identity.activity_id)
            or (value.bot_id,value.persona_id,value.activity_id,value.effect_id,value.work_kind) !=
                (*proposal.envelope.authority.namespace.as_tuple,proposal.envelope.identity.activity_id,None,WORK_KIND)
            or value.parent_budget_lease_ref != proposal.envelope.parent_budget_lease_ref
            or value.phase != 'running' or value.fence != 1 or value.cancel_epoch != 0 or value.result_ref is not None
            or value.lease_holder != proposal.envelope.authority.actor or value.lease_expires_utc is None
            or write.dependencies or before is None or not before.valid or before.revision != 1
            or before.value.get('phase') != 'queued' or before.value.get('fence') != 0
            or before.value.get('lease_holder') is not None or before.value.get('lease_expires_utc') is not None):
        raise ValueError('Life acquisition does not preserve its exact original once job')
    expected = {**before.value,'phase':'running','fence':1,
        'lease_holder':value.lease_holder,'lease_expires_utc':value.lease_expires_utc}
    if canonical_serialize(write.value) != canonical_serialize(expected):
        raise ValueError('Life acquisition changed fields outside its actual worker transition')
    return proposal


def require_exact_internal_life_acquisition_issuance_v1(witness, graph, bundle):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1, _ACTIVE
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.graph is not graph or witness.runtime.graph is not graph
            or type(witness.stage) is not InternalLifeContentAcquisitionStageV1
            or witness.operation.operation_kind != OPERATION or type(witness.request) is not AcquireInternalLifeContentRequestV1
            or witness.bundle is not bundle or witness.frame is not witness.stage.frame
            or witness.stage.stage.proposals != bundle.proposals):
        raise ValueError('Life acquisition needs its actual active installed Owner/GCP witness')
    return witness


def require_internal_life_acquisition_job_registration_v1(witness, db):
    """An acquire transition updates only its already registered once job."""
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1
    if type(witness) is not _ProductionCommitWitnessV1:
        raise ValueError('Life acquisition job has no actual installed witness')
    require_exact_internal_life_acquisition_issuance_v1(witness,witness.graph,witness.bundle)
    if db is not witness.graph._GraphCoordinator__store._db or not db.in_transaction:
        raise ValueError('Life acquisition job registration requires its actual producing transaction')
    prepared = read_committed_internal_life_prepared_v1(db,
        namespace=witness.stage.prepared.namespace,
        issuer=witness.graph._GraphCoordinator__d11_issuer,job_id=witness.stage.prepared.job_id)
    refs=witness.bundle.persistent_job_refs
    expected=job_graph_write(witness.stage.job).key.token
    row=db.execute('SELECT operation_id FROM graph_bundle_refs WHERE bot=? AND persona=? '
        "AND ref_kind='persistent_job' AND ref=?",(*prepared.namespace.as_tuple,expected)).fetchone()
    if (prepared != witness.stage.prepared or refs != (expected,)
            or row != (prepared.prepare_operation_id,)):
        raise ValueError('Life acquisition job is not registered to its actual once preparation')
    return refs


def _acquired_model_request(frame, prepared, frozen, workflow, job):
    key = job_graph_write(job).key
    old = tuple(row for row in frame.envelope.version_guard.read_versions if row.key == key)
    if len(old) != 1 or old[0].revision != 1:
        raise ValueError('Life acquired input requires its exact queued-job Graph read')
    epochs = tuple(QueryEpoch(row.namespace, row.scope_ref, row.revision + 1) for row in frame.envelope.version_guard.query_epochs)
    guard = replace(frame.envelope.version_guard,
        read_versions=tuple(GraphVersion(row.key, row.revision + 1) if row.key == key else row
            for row in frame.envelope.version_guard.read_versions), query_epochs=epochs,
        resource_lease_versions=(VersionedRef(prepared.quote_id, prepared.quote_version),))
    deadline = min(frame.envelope.deadline_utc, frozen.input.expires_at_utc)
    envelope = replace(frame.envelope, identity=replace(frame.envelope.identity, phase='internal_life_content'),
        authority=replace(frame.envelope.authority, worker_fence=job.fence), version_guard=guard,
        deadline_utc=deadline, monotonic_deadline=min(frame.envelope.monotonic_deadline,
            frame.envelope.monotonic_deadline - (frame.envelope.deadline_utc - deadline)))
    return ModelCallRequest(envelope, prepared.call_id, workflow.provider_id, workflow.model_id,
        frozenset(workflow.required_capabilities), workflow.privacy_tier, TEMPLATE_DIGEST,
        json.loads(frozen.wire_json), workflow.timeout_seconds, workflow.max_output_tokens)


def verify_internal_life_acquisition_in_transaction_v1(db, stage, readers):
    if type(stage) is not InternalLifeContentAcquisitionStageV1 or not db.in_transaction:
        raise ValueError('exact Life acquisition stage and SQL transaction required')
    actual, frozen, workflow = _current(db, stage.frame,
        AcquireInternalLifeContentRequestV1(stage.prepared.episode_ref,
            stage.frozen.input.cause.occurrence.event.causal_operation_id), readers)
    saved = read_life_worker_original_v1(db, namespace=actual.namespace, issuer=readers.issuer,
        kind='request', ref=actual.job_id)
    model = None if saved is None else _request_from_wire(saved['wire'])
    job = get_job(db, actual.job_id)
    if model is None or job is None:
        raise ValueError('Life acquired input lost its actual saved request or job')
    if (actual != stage.prepared or frozen != stage.frozen or model != stage.request or job != stage.job
            or canonical_serialize(reply_request_wire_v1(model.envelope,model)) != canonical_serialize(
                reply_request_wire_v1((_acquired_model_request(stage.frame,actual,frozen,workflow,job)).envelope,
                    _acquired_model_request(stage.frame,actual,frozen,workflow,job)))
            or job.phase != 'running' or job.lease_holder != stage.frame.envelope.authority.actor
            or job.fence != model.envelope.authority.worker_fence
            or saved['prepared_digest'] != actual.digest or saved['request_digest'] != model.digest
            or tuple(w for p in stage.stage.proposals for w in p.typed_writes) != (job_graph_write(job),)
            or model.prompt_template_digest != TEMPLATE_DIGEST or model.payload != json.loads(frozen.wire_json)):
        raise ValueError('Life acquired request is not its actual once current job/input')
    return stage


def internal_life_acquisition_bundle_v1(stage):
    from ..runtime_contracts import DomainBundle
    if type(stage) is not InternalLifeContentAcquisitionStageV1:
        raise TypeError('exact installed Life acquired stage required')
    return DomainBundle(stage.frame.envelope, stage.stage.proposals, (), (), (), (), (),
        (job_graph_write(stage.job).key.token,), ())


def commit_internal_life_acquisition_v1(runtime, db, *, operation, request, preparation, readers,
        scope, owner, guard, metadata, epoch, process_lease, external_originals):
    from ..contracts import canonical_json
    from ..authority_service.v2_contract import to_wire
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1, _ACTIVE
    from .domain_production_originals_v1 import record_adopted_domain_operation_v1, _receipt_wire
    from .d11_types import reconcile_runtime_write
    graph = runtime.graph
    verify_internal_life_acquisition_in_transaction_v1(db, preparation, readers)
    prepared = preparation.prepared
    operation_id = prepared.acquire_operation_id
    attempt = db.execute('SELECT request_digest,attempt_id,permit_json FROM graph_owner_domain_attempts_v3 '
        'WHERE bot=? AND persona=? AND operation_id=?', (*prepared.namespace.as_tuple, operation_id)).fetchone()
    if (attempt is None or attempt[1] != scope.operation_id
            or attempt[2] != canonical_json(to_wire(scope.permit)) or operation.operation_kind != OPERATION):
        raise ValueError('Life acquisition lacks its exact actual Owner command/permit')
    bundle = internal_life_acquisition_bundle_v1(preparation)
    reconcile_runtime_write(db, job_graph_write(preparation.job))
    witness = _ProductionCommitWitnessV1(runtime, graph, scope, preparation.frame, preparation,
        operation, request, owner, guard, bundle, tuple(external_originals))
    finish = 'sha256:' + canonical_digest({'schema':'w01.owner-domain-write.v3',
        'operation_id':operation_id, 'request_digest':attempt[0], 'permit_token':scope.permit.token})
    _ACTIVE[id(witness)] = witness
    try:
        receipt = graph._commit_domain_bundle_fenced(bundle, process_lease, in_transaction=True,
            v2_write=(metadata, epoch, 'finish:' + scope.operation_id, finish, canonical_json(to_wire(scope.permit))),
            now_utc=preparation.frame.now_utc, domain_production_issuance_v1=witness)
    finally:
        _ACTIVE.pop(id(witness), None)
    record_life_worker_original_v1(db, namespace=prepared.namespace, issuer=readers.issuer,
        kind='acquire_commit', ref=prepared.job_id,
        value={'schema':'d06.internal-life-content-acquire-commit.v1', 'prepared_digest':prepared.digest,
            'request_digest':preparation.request.digest, 'operation_id':operation_id,
            'receipt':_receipt_wire(receipt), 'receipt_digest':canonical_digest(receipt)})
    original = record_adopted_domain_operation_v1(db, preparation.stage, receipt)
    return {'schema':'sylanne.domain-production-receipt.v1', 'domain':'d11',
        'operation_kind':OPERATION, 'operation_id':operation_id, 'activity_id':prepared.activity_id,
        'original_ref':original.original_ref, 'original_digest':original.original_digest,
        'receipt':_receipt_wire(receipt), 'receipt_digest':canonical_digest(receipt),
        'job_states':[[prepared.job_id, 'running']], 'coverage':'deferred',
        'missing_inputs':['actual_internal_life_content_terminal_and_adoption'],
        'continuation_ref':prepared.job_id, 'outbox':[]}


def read_committed_internal_life_request_v1(db, *, namespace, issuer, job_id):
    """Historical durable input proof; the installed worker rechecks current permission."""
    from .d04_root_original_store_v1 import _receipt
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1, _receipt_wire
    prepared = read_committed_internal_life_prepared_v1(db, namespace=namespace, issuer=issuer, job_id=job_id)
    saved = read_life_worker_original_v1(db, namespace=namespace, issuer=issuer, kind='request', ref=job_id)
    commit = read_life_worker_original_v1(db, namespace=namespace, issuer=issuer, kind='acquire_commit', ref=job_id)
    if saved is None or commit is None:
        raise ValueError('Life input lacks its actual durable acquisition')
    model = _request_from_wire(saved['wire'])
    receipt = _receipt(db, namespace, prepared.acquire_operation_id)
    adopted = read_adopted_domain_operation_v1(db, namespace, prepared.acquire_operation_id)
    from .d11_types import runtime_job_key
    key = runtime_job_key(*namespace.as_tuple, prepared.activity_id, prepared.job_id)
    actual = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=?',
        (key.token, receipt.write_versions[0].revision if len(receipt.write_versions) == 1 else -1)).fetchone()
    if adopted is None or actual is None:
        raise ValueError('Life input has no actual acquisition production/history original')
    payload = adopted['payload']
    expected_authority = {**payload['authority'], 'worker_fence':saved['worker_fence']}
    expected_reads = tuple(GraphVersion(row.key, row.revision + 1) if row.key == key else row
        for row in receipt.read_versions)
    if (commit != {'schema':'d06.internal-life-content-acquire-commit.v1',
            'prepared_digest':prepared.digest, 'request_digest':model.digest,
            'operation_id':prepared.acquire_operation_id, 'receipt':_receipt_wire(receipt),
            'receipt_digest':canonical_digest(receipt)} or saved['prepared_digest'] != prepared.digest
            or saved['request_digest'] != model.digest or model.call_id != prepared.call_id
            or model.identity.operation_id != prepared.acquire_operation_id
            or model.identity.phase != 'internal_life_content' or model.envelope.authority.namespace != namespace
            or model.envelope.authority.worker_fence != saved['worker_fence']
            or model.prompt_template_digest != TEMPLATE_DIGEST
            or model.payload != json.loads(thaw_internal_life_content_request_v1(json.loads(prepared.frozen_json)).wire_json)
            or adopted['domain'] != 'd11' or adopted['operation_kind'] != OPERATION or adopted['receipt'] != receipt
            or receipt.write_versions != (GraphVersion(key, 2),)
            or actual[1:] != (1, prepared.acquire_operation_id)
            or canonical_serialize(payload['writes']) != canonical_serialize([
                {'key':key.token, 'value':json.loads(actual[0]), 'dependencies':[]}])
            or canonical_serialize(plain_v1(model.envelope.authority)) != canonical_serialize(expected_authority)
            or model.envelope.version_guard.read_versions != expected_reads
            or payload['provenance']['request_digest'] != model.digest
            or payload['provenance']['prepared_digest'] != prepared.digest):
        raise ValueError('Life input durable command/event/history/original bindings differ')
    return prepared, model
