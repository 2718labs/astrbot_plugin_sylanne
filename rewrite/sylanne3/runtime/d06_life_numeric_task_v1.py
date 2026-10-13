"""Independent once preparation for the actual internal-Life appraisal.

No content task, reservation or paid result is reusable here. W01 owns the
current frame and CAS; the companion is signed only after its actual job CAS.
"""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
import weakref

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, CommitReceipt, canonical_digest, canonical_serialize
from ..model_broker.internal_life_numeric_v1 import (
    WORK_KIND, TEMPLATE_VERSION, InternalLifeNumericIdentityV1, FrozenInternalLifeNumericRequestV1,
    internal_life_numeric_ids_v1, thaw_internal_life_numeric_request_v1,
)
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .d04_appraisal_driver_v3 import D04GraphReadV3
from .d11_life_preparation_v1 import _read, _record
from .d11_types import D11RuntimeProvider, D11_PROPOSAL_SCHEMA, runtime_job_key, job_graph_write
from .jobs import PersistentJob, create_job, get_job
from .budget import get_budget_lease, require_budget_family_admissible, reserve_budget
from .issuers import ResourceQuote

OPERATION = 'prepare_internal_life_numeric'
PREPARED_KIND = 'numeric_prepared_v1'
_STAGES = {}
ADOPT_OPERATION = 'adopt_internal_life_numeric'
APPRAISAL_SCHEMA = 'd04.internal-life-numeric-appraisal-adoption.v1'
JOB_SCHEMA = 'd11.internal-life-numeric-completion.v1'
from ..runtime_contracts import schema_hash
APPRAISAL_HASH = schema_hash({'schema': APPRAISAL_SCHEMA, 'type': 'd04.appraisal_bundle.v1',
    'issuer': 'actual_numeric_paid_candidate_current_W01'})
JOB_HASH = schema_hash({'schema': JOB_SCHEMA, 'transition': 'same_numeric_paid_adoption_running_to_completed'})
_ADOPTIONS = {}


@dataclass(frozen=True, slots=True)
class PrepareInternalLifeNumericRequestV1:
    episode_ref: str
    causal_operation_id: str

    def __post_init__(self):
        from .d06_internal_life_encoding_v1 import EncodeInternalLifeRequestV1
        EncodeInternalLifeRequestV1(self.episode_ref, self.causal_operation_id)


def _identity(original):
    return InternalLifeNumericIdentityV1(original.namespace, original.episode_ref,
        original.execution_id, original.source_ref, original.occurrence_digest,
        original.before_digest, original.digest)


@dataclass(frozen=True, slots=True)
class InternalLifeNumericPreparedV1:
    namespace: NamespaceId
    operation_id: str
    job_id: str
    call_id: str
    activity_id: str
    causal_operation_id: str
    frozen: FrozenInternalLifeNumericRequestV1
    read_rows: tuple[D04GraphReadV3, ...]
    owner_head_digest: str
    activation_generation: int
    graph_incarnation: str
    audience: tuple[str, ...]
    quote_id: str
    quote_digest: str
    reservation_digest: str
    access_epoch: int
    delete_epoch: int
    schema: str = 'd06.internal-life-numeric-prepared.v1'

    def __post_init__(self):
        from .d06_internal_life_episode_v2 import _sha
        if (self.schema != 'd06.internal-life-numeric-prepared.v1'
                or type(self.namespace) is not NamespaceId
                or type(self.frozen) is not FrozenInternalLifeNumericRequestV1
                or self.frozen.identity.namespace != self.namespace
                or type(self.read_rows) is not tuple or not 1 <= len(self.read_rows) <= 1024
                or any(type(r) is not D04GraphReadV3 for r in self.read_rows)
                or len({r.ref for r in self.read_rows}) != len(self.read_rows)
                or type(self.audience) is not tuple or len(self.audience) != 1
                or not self.audience[0] or not self.graph_incarnation):
            raise ValueError('Life numeric preparation closed scope differs')
        ids = internal_life_numeric_ids_v1(self.frozen.identity)
        if (self.operation_id, self.job_id, self.call_id, self.quote_id) != tuple(
                ids[k] for k in ('prepare', 'job', 'call', 'quote')):
            raise ValueError('Life numeric preparation changed its independent once identity')
        for v in (self.owner_head_digest, self.quote_digest, self.reservation_digest): _sha(v)
        if (type(self.activation_generation) is not int or self.activation_generation < 1
                or any(type(v) is not int or v < 0 for v in (self.access_epoch, self.delete_epoch))):
            raise ValueError('Life numeric preparation epochs differ')
        if any(NamespaceId.from_key(AtomKey.from_token(r.ref)) != self.namespace for r in self.read_rows):
            raise ValueError('Life numeric preparation crosses namespace')

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))

    @property
    def quote_version(self):
        return 1

    @property
    def prepare_operation_id(self): return self.operation_id

    @property
    def acquire_operation_id(self): return internal_life_numeric_ids_v1(self.frozen.identity)['acquire']

    @property
    def episode_ref(self): return self.frozen.identity.episode_ref

    @property
    def occurrence_digest(self): return self.frozen.identity.occurrence_digest

    @property
    def installation_id(self): return self.frozen.appraisal.installation.installation_id

    @property
    def frozen_digest(self): return self.frozen.digest

    @property
    def provider_config_ref(self): return self.frozen.appraisal.installation.provider_config_ref


def decode_life_numeric_prepared_v1(raw):
    if type(raw) is not dict or set(raw) != set(InternalLifeNumericPreparedV1.__dataclass_fields__):
        raise ValueError('Life numeric prepared wire fields differ')
    result = InternalLifeNumericPreparedV1(**{**raw,
        'namespace': NamespaceId(**raw['namespace']),
        'frozen': thaw_internal_life_numeric_request_v1(raw['frozen']),
        'read_rows': tuple(D04GraphReadV3(**r) for r in raw['read_rows']),
        'audience': tuple(raw['audience'])})
    if canonical_serialize(plain_v1(result)) != canonical_serialize(raw):
        raise ValueError('Life numeric preparation noncanonical')
    return result


def read_life_numeric_prepared_v1(db, *, namespace, issuer, job_id):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    saved = _read(db, issuer=issuer, namespace=namespace, kind=PREPARED_KIND, ref=job_id)
    if saved is None:
        raise MissingProductionOriginalV1('actual_independent_numeric_preparation')
    value = decode_life_numeric_prepared_v1(saved[0])
    if value.namespace != namespace or value.job_id != job_id or saved[1] != value.operation_id:
        raise ValueError('Life numeric prepared selector differs')
    row = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1',
        (runtime_job_key(*namespace.as_tuple, value.activity_id, job_id).token,)).fetchone()
    if row is None or row[1:] != (1, value.operation_id):
        raise ValueError('Life numeric signed preparation lacks its actual job history')
    actual = json.loads(row[0])
    if (actual.get('work_kind') != WORK_KIND or actual.get('job_id') != job_id
            or actual.get('operation_id') != value.operation_id or actual.get('phase') != 'queued'):
        raise ValueError('Life numeric historical job differs')
    adopted = read_adopted_domain_operation_v1(db, namespace, value.operation_id)
    key = runtime_job_key(*namespace.as_tuple, value.activity_id, job_id)
    if (adopted is None or adopted['domain'] != 'd11' or adopted['operation_kind'] != OPERATION
            or type(adopted['receipt']) is not CommitReceipt or adopted['receipt'].status != 'committed'
            or adopted['receipt'].write_versions != (GraphVersion(key, 1),)
            or adopted['payload']['provenance']['prepared_digest'] != value.digest
            or adopted['payload']['provenance']['numeric_input_digest'] != value.frozen.digest):
        raise ValueError('Life numeric preparation lacks its actual adopted domain bundle')
    return value


def read_plan_life_numeric_prepare_v1(db, *, namespace, activity_id, operation_kind, request):
    from .d06_life_numeric_context_v1 import (read_plan_life_numeric_context_v1,
        PrepareLifeNumericContextRequestV1, OPERATION as CONTEXT_OPERATION,
        life_numeric_context_ids_v1, decode_life_numeric_context_original_v1, KIND)
    from .d11_life_product_adapter_v1 import raw_life_original_v1
    if type(request) is not PrepareInternalLifeNumericRequestV1 or operation_kind != OPERATION:
        raise TypeError('Life numeric preparation requires its registered locator')
    plan = read_plan_life_numeric_context_v1(db, namespace=namespace, activity_id=activity_id,
        operation_kind=CONTEXT_OPERATION,
        request=PrepareLifeNumericContextRequestV1(request.episode_ref, request.causal_operation_id))
    raw = raw_life_original_v1(db, namespace, KIND, life_numeric_context_ids_v1(namespace, request.episode_ref)['original'])
    if raw is None: raise MissingProductionOriginalV1('actual_life_numeric_context')
    original = decode_life_numeric_context_original_v1(raw)
    ids = internal_life_numeric_ids_v1(_identity(original))
    return production_read_plan_v1(plan.fixed_type_ids,
        (*plan.exact_keys, runtime_job_key(*namespace.as_tuple, activity_id, ids['job'])),
        plan.source_roots, plan.required_original_refs)


def _current(db, frame, request, readers):
    from .d06_life_numeric_context_v1 import (
        PrepareLifeNumericContextRequestV1, freeze_current_life_numeric_appraisal_v1,
        require_current_life_numeric_context_v1)
    from ..host.authority_profile import AdminInstallationBundle
    read = CurrentDomainReadV1(frame); read.check(db)
    bundle = readers.life_numeric_bundle
    if type(bundle) is not AdminInstallationBundle:
        raise TypeError('Life numeric requires its actual installed bundle')
    workflow = getattr(bundle.model_workflows, 'life_numeric', None)
    if (workflow is None or (workflow.work_kind, workflow.purpose, workflow.template_version) !=
            (WORK_KIND, 'consolidation', TEMPLATE_VERSION)
            or frame.envelope.authority.purpose != 'consolidation'
            or len(frame.envelope.authority.audience) != 1
            or frame.envelope.authority.audience[0] not in workflow.audiences):
        raise MissingProductionOriginalV1('installed_isolated_numeric_workflow')
    context, appraisal = freeze_current_life_numeric_appraisal_v1(db, frame=frame,
        request=PrepareLifeNumericContextRequestV1(request.episode_ref, request.causal_operation_id),
        installed_readers=readers)
    require_current_life_numeric_context_v1(context, db=db, frame=frame)
    frozen = FrozenInternalLifeNumericRequestV1(_identity(context.original), appraisal)
    return bundle, workflow, context, frozen


@dataclass(frozen=True, slots=True, weakref_slot=True)
class InternalLifeNumericPreparationStageV1:
    stage: object
    prepared: InternalLifeNumericPreparedV1
    frozen: FrozenInternalLifeNumericRequestV1
    job: PersistentJob
    frame: object


def stage_prepare_life_numeric_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(request) is not PrepareInternalLifeNumericRequestV1:
        raise TypeError('Life numeric prepare requires its exact locator')
    bundle, workflow, context, frozen = _current(db, frame, request, installed_readers)
    ids = internal_life_numeric_ids_v1(frozen.identity)
    ns, now = frame.envelope.authority.namespace, frame.now_utc
    if frame.envelope.identity.operation_id != ids['prepare'] or frame.envelope.identity.phase != OPERATION:
        raise ValueError('Life numeric preparation cannot change its once operation')
    key = runtime_job_key(*ns.as_tuple, frame.envelope.identity.activity_id, ids['job'])
    atom = CurrentDomainReadV1(frame).head(db, key)
    if (atom.revision or atom.valid
            or db.execute('SELECT 1 FROM runtime_jobs WHERE job_id=?',
                (ids['job'],)).fetchone() is not None):
        raise ValueError('Life numeric once job already exists; use original recovery')
    grant = installed_readers.issuer.current_budget_grant(db, frame.envelope.parent_budget_lease_ref)
    lease = get_budget_lease(db, grant.lease_id)
    require_budget_family_admissible(db, lease.lease_id)
    deadline = min(frame.envelope.deadline_utc, now + workflow.timeout_seconds, grant.valid_until_utc)
    if (lease.state != 'active' or WORK_KIND not in grant.allowed_work_kinds or deadline <= now
            or db.execute('SELECT 1 FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
                (lease.lease_id, ids['prepare'])).fetchone() is not None):
        raise ValueError('Life numeric actual independent budget is unavailable')
    quote = ResourceQuote(ids['quote'], 1, *ns.as_tuple, frame.envelope.identity.activity_id,
        ids['prepare'], None, lease.lease_id, WORK_KIND, ids['snapshot'], deadline,
        workflow.provider_config_ref, key.token, (), (), dict(workflow.quote_ceiling), None, deadline)
    installed_readers.resource_issuer.issue_quote(db, quote)
    reservation = canonical_digest({'schema': 'd06.internal-life-numeric-reservation.v1',
        'frozen_digest': frozen.digest, 'quote': plain_v1(quote)})
    reserved = reserve_budget(db, lease.lease_id, ids['prepare'], reservation, dict(quote.ceiling))
    if reserved.status != 'reserved': raise ValueError('Life numeric independent reservation failed')
    job = PersistentJob(ids['job'], ids['prepare'], frame.envelope.identity.activity_id, None,
        *ns.as_tuple, ids['snapshot'], 'queued', WORK_KIND,
        {'episode_ref': request.episode_ref, 'causal_operation_id': request.causal_operation_id,
         'numeric_input_digest': frozen.digest}, None,
        datetime.fromtimestamp(deadline, timezone.utc).isoformat().replace('+00:00', 'Z'),
        lease.lease_id, workflow.provider_config_ref, {'resource_quote': ids['quote'] + ':1'},
        None, None, 0, 0, {}, None)
    create_job(db, job, 'create:' + ids['prepare'], reservation)
    rows = tuple(D04GraphReadV3(a.key.token, a.revision, a.valid, canonical_serialize(a.value))
                 for a in frame.snapshot.atoms if a.key != key)
    original = InternalLifeNumericPreparedV1(ns, ids['prepare'], ids['job'], ids['call'],
        job.activity_id, request.causal_operation_id, frozen, rows, frame.owner_guard.owner_head_digest,
        frame.activation_generation, context.original.graph_incarnation, frame.envelope.authority.audience,
        quote.quote_id, canonical_digest(quote), reservation, frame.envelope.version_guard.access_epoch,
        frame.envelope.version_guard.delete_epoch)
    provider = D11RuntimeProvider()
    primary = stage_result_v1(frame, 'd11', OPERATION, request, writes=(job_graph_write(job),),
        provenance={'prepared_digest': original.digest, 'numeric_input_digest': frozen.digest,
                    'episode_ref': request.episode_ref, 'before_digest': frozen.identity.before_digest},
        proposal_schema=D11_PROPOSAL_SCHEMA, proposal_hash=provider.descriptor.request_schema_hash)
    provider.validate(primary.proposals[0], frame.snapshot)
    stage = InternalLifeNumericPreparationStageV1(primary, original, frozen, job, frame)
    identity = id(stage)
    _STAGES[identity] = (weakref.ref(stage, lambda _: _STAGES.pop(identity, None)), db,
        context, bundle, frozen.digest, installed_readers.issuer, installed_readers.resource_issuer, db.total_changes)
    return stage


def verify_life_numeric_preparation_in_transaction_v1(db, staged, readers, bundle):
    item = _STAGES.get(id(staged))
    if item is None or item[0]() is not staged or item[1] is not db or not db.in_transaction:
        raise ValueError('Life numeric preparation was not issued in this transaction')
    p, frame = staged.prepared, staged.frame
    # The registered qualification remains valid only in this untouched W01 snapshot.
    # Never update the saved counter or use this proof after an intervening write.
    if (db.total_changes != item[7] or readers.life_numeric_bundle is not item[3]
            or readers.issuer is not item[5] or readers.resource_issuer is not item[6]
            or staged.frozen.digest != item[4]):
        raise ValueError('Life numeric preparation qualification changed before CAS')
    from .d06_life_numeric_context_v1 import require_current_life_numeric_context_v1
    require_current_life_numeric_context_v1(item[2], db=db, frame=frame)
    actual_bundle, frozen = item[3], staged.frozen
    quote = readers.resource_issuer.original_signed_quote(db, p.quote_id, 1)
    reserved = db.execute('SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
        (quote.parent_budget_lease_ref, p.operation_id)).fetchone()
    if (actual_bundle is not bundle or frozen != p.frozen or get_job(db, p.job_id) != staged.job
            or canonical_digest(quote) != p.quote_digest
            or reserved != (p.reservation_digest, canonical_serialize(dict(quote.ceiling)), 'reserved')
            or tuple(w for pr in staged.stage.proposals for w in pr.typed_writes) != (job_graph_write(staged.job),)):
        raise ValueError('Life numeric actual input/quote/reservation/job changed before CAS')
    return staged


def record_life_numeric_preparation_after_cas_v1(db, *, staged, issuer, receipt):
    item = _STAGES.get(id(staged))
    p = staged.prepared
    if (item is None or item[0]() is not staged or item[1] is not db or not db.in_transaction
            or type(receipt) is not CommitReceipt or receipt.status != 'committed'
            or receipt.operation_id != p.operation_id):
        raise ValueError('Life numeric preparation requires its actual same-transaction CAS')
    actual = db.execute('SELECT digest,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
        (*p.namespace.as_tuple, p.operation_id)).fetchone()
    write = job_graph_write(staged.job)
    history = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1', (write.key.token,)).fetchone()
    if (actual != (receipt.operation_digest, receipt.commit_seq)
            or receipt.write_versions != (GraphVersion(write.key, 1),)
            or history != (canonical_serialize(write.value), 1, p.operation_id)
            or get_job(db, p.job_id) != staged.job):
        raise ValueError('Life numeric signed original requires its exact committed job member')
    result = _record(db, issuer=issuer, namespace=p.namespace, kind=PREPARED_KIND,
        ref=p.job_id, operation_id=p.operation_id, value=p)
    _STAGES.pop(id(staged), None)
    return result


@dataclass(frozen=True, slots=True)
class AdoptInternalLifeNumericRequestV1:
    episode_ref: str
    causal_operation_id: str

    def __post_init__(self):
        PrepareInternalLifeNumericRequestV1(self.episode_ref, self.causal_operation_id)


@dataclass(frozen=True, slots=True)
class LifeNumericAppraisalAcceptanceV1:
    namespace: NamespaceId
    operation_id: str
    job_id: str
    context_digest: str
    before_digest: str
    appraisal_ref: str
    appraisal_revision: int
    appraisal_value_json: str
    prepared_digest: str
    result_original_ref: str
    result_original_digest: str
    cost_original_ref: str
    cost_original_digest: str
    suggestion_json: str
    read_rows: tuple[D04GraphReadV3, ...]
    schema: str = 'd04.life-numeric-appraisal-acceptance.v1'

    def __post_init__(self):
        from .d06_internal_life_episode_v2 import _sha
        key = AtomKey.from_token(self.appraisal_ref)
        if (type(self.namespace) is not NamespaceId or self.schema != 'd04.life-numeric-appraisal-acceptance.v1'
                or key.type_name != 'd04.appraisal_bundle.v1' or NamespaceId.from_key(key) != self.namespace
                or self.appraisal_revision != 1 or type(self.appraisal_revision) is not int
                or type(self.read_rows) is not tuple or not 1 <= len(self.read_rows) <= 1024
                or any(type(r) is not D04GraphReadV3 for r in self.read_rows)):
            raise ValueError('Life numeric acceptance closed scope differs')
        for v in (self.context_digest, self.before_digest, self.prepared_digest,
                  self.result_original_digest, self.cost_original_digest): _sha(v)
        for v in (self.appraisal_value_json, self.suggestion_json):
            if type(v) is not str or len(v.encode('utf-8')) > 262144 or canonical_serialize(json.loads(v)) != v:
                raise ValueError('Life numeric appraisal original bytes differ')
        suffix = self.job_id.removeprefix('life-numeric-job:')
        if (len(suffix) != 48 or any(c not in '0123456789abcdef' for c in suffix)
                or self.job_id != 'life-numeric-job:' + suffix or self.operation_id != 'life-numeric-adopt:' + suffix
                or self.cost_original_ref != self.job_id or self.result_original_ref != self.job_id):
            raise ValueError('Life numeric acceptance original once family differs')

    @property
    def digest(self): return canonical_digest(plain_v1(self))


def decode_life_numeric_appraisal_acceptance_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value = decode_typed_production_value_v1(raw, LifeNumericAppraisalAcceptanceV1)
    if canonical_serialize(plain_v1(value)) != canonical_serialize(raw):
        raise ValueError('Life numeric acceptance noncanonical')
    return value


def read_life_numeric_appraisal_acceptance_v1(db, namespace, appraisal_ref, issuer):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d06_life_numeric_paid_v1 import read_life_numeric_paid_result_v1
    saved = _read(db, issuer=issuer, namespace=namespace, kind='numeric_appraisal_acceptance_v1', ref=appraisal_ref)
    if saved is None: return None
    value = decode_life_numeric_appraisal_acceptance_v1(saved[0])
    adopted = read_adopted_domain_operation_v1(db, namespace, value.operation_id)
    p, _, _, _, _ = read_life_numeric_paid_result_v1(
        db, namespace=namespace, issuer=issuer, job_id=value.job_id)
    key = AtomKey.from_token(appraisal_ref)
    job_key = runtime_job_key(*namespace.as_tuple, p.activity_id, value.job_id)
    if (value.namespace != namespace or value.appraisal_ref != appraisal_ref or saved[1] != value.operation_id
            or adopted is None or adopted['domain'] != 'd04' or adopted['operation_kind'] != ADOPT_OPERATION
            or type(adopted['receipt']) is not CommitReceipt or adopted['receipt'].status != 'committed'
            or set(adopted['receipt'].write_versions) != {GraphVersion(key, 1), GraphVersion(job_key, 3)}
            or adopted['payload']['provenance']['acceptance_digest'] != value.digest
            or p.digest != value.prepared_digest or p.frozen.identity.context_digest != value.context_digest
            or p.frozen.identity.before_digest != value.before_digest):
        raise ValueError('Life numeric acceptance lacks its actual composite adoption')
    history = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1', (appraisal_ref,)).fetchone()
    completed = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=3', (job_key.token,)).fetchone()
    if (history != (value.appraisal_value_json, 1, value.operation_id)
            or completed is None or completed[1:] != (1, value.operation_id)
            or json.loads(completed[0]).get('phase') != 'completed'
            or json.loads(completed[0]).get('result_ref') != p.call_id
            or json.loads(completed[0]).get('work_kind') != WORK_KIND):
        raise ValueError('Life numeric acceptance actual history differs')
    read_life_numeric_paid_cost_for_acceptance_v1(db, value, issuer)
    return value


def read_life_numeric_paid_cost_for_acceptance_v1(db, acceptance, issuer):
    from .d06_life_numeric_paid_v1 import read_life_numeric_paid_result_v1
    p, b, result, cost, digest = read_life_numeric_paid_result_v1(db,
        namespace=acceptance.namespace, issuer=issuer, job_id=acceptance.job_id)
    saved = _read(db, issuer=issuer, namespace=acceptance.namespace, kind='numeric_paid_v1', ref=p.job_id)
    from ..authority_service.current_life_numeric_v1 import life_numeric_result_to_wire_v1
    if (digest != acceptance.cost_original_digest or p.digest != acceptance.prepared_digest
            or canonical_digest(life_numeric_result_to_wire_v1(result)) != acceptance.result_original_digest):
        raise ValueError('Life numeric accepted candidate has a different actual cost/result')
    return saved[0], digest


def require_current_life_numeric_appraisal_acceptance_v1(db, *, frame, context, appraisal_ref, installed_readers):
    from .d06_life_numeric_context_v1 import require_current_life_numeric_context_v1
    require_current_life_numeric_context_v1(context, db=db, frame=frame)
    value = read_life_numeric_appraisal_acceptance_v1(db, context.original.namespace, appraisal_ref, installed_readers.issuer)
    if value is None: raise MissingProductionOriginalV1('actual_paid_life_numeric_appraisal_adoption')
    atom = CurrentDomainReadV1(frame).head(db, appraisal_ref, required=True)
    if (value.context_digest != context.original.digest or value.before_digest != context.before.digest
            or atom.revision != value.appraisal_revision or canonical_serialize(atom.value) != value.appraisal_value_json):
        raise ValueError('Life numeric appraisal current context/actual value differs')
    # Later D04 advances may change old checkpoints. Their exact old read set
    # remains historical evidence; current context/Source/Owner is requalified.
    return value


def _appraisal_candidate(p, result):
    from ..model_broker.internal_life_numeric_v1 import parse_internal_life_numeric_candidate_v1
    from ..graph_types import Owner, GraphWrite
    raw = json.loads(result.observation.result_json)
    if type(raw) is not dict or set(raw) != {'text'} or type(raw['text']) is not str:
        raise ValueError('Life numeric actual provider result is not its bounded text response')
    suggestion = parse_internal_life_numeric_candidate_v1(raw['text'], p.frozen)
    if suggestion.bundle is None:
        raise MissingProductionOriginalV1('supported_internal_life_meaning_facets')
    appraisal = suggestion.bundle
    key = AtomKey(Owner('event', *p.namespace.as_tuple, appraisal.event_ref), 'd04.appraisal_bundle.v1', appraisal.appraisal_id)
    return suggestion, GraphWrite(key, plain_v1(appraisal))


def read_plan_life_numeric_adopt_v1(db, *, namespace, activity_id, operation_kind, request):
    from .d06_life_numeric_context_v1 import life_numeric_context_ids_v1, KIND, decode_life_numeric_context_original_v1
    from .d11_life_product_adapter_v1 import raw_life_original_v1
    from ..authority_service.current_life_numeric_v1 import life_numeric_result_from_wire_v1, LifeNumericModelResultReadV1
    if type(request) is not AdoptInternalLifeNumericRequestV1 or operation_kind != ADOPT_OPERATION:
        raise TypeError('Life numeric appraisal adoption exact locator required')
    plan = read_plan_life_numeric_prepare_v1(db, namespace=namespace, activity_id=activity_id, operation_kind=OPERATION,
        request=PrepareInternalLifeNumericRequestV1(request.episode_ref, request.causal_operation_id))
    raw = raw_life_original_v1(db, namespace, KIND, life_numeric_context_ids_v1(namespace, request.episode_ref)['original'])
    ids = internal_life_numeric_ids_v1(_identity(decode_life_numeric_context_original_v1(raw)))
    p = decode_life_numeric_prepared_v1(raw_life_original_v1(db, namespace, PREPARED_KIND, ids['job']))
    paid = raw_life_original_v1(db, namespace, 'numeric_paid_v1', ids['job'])
    if paid is None: raise MissingProductionOriginalV1('actual_independent_numeric_paid_result')
    result = life_numeric_result_from_wire_v1(paid['result'], LifeNumericModelResultReadV1)
    _, write = _appraisal_candidate(p, result)
    return production_read_plan_v1(plan.fixed_type_ids,
        (*plan.exact_keys, write.key, AtomKey.from_token(paid['cost']['cost_ref'])),
        plan.source_roots, plan.required_original_refs)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LifeNumericAppraisalAdoptionStageV1:
    stage: object
    job_proposal: object
    frame: object
    prepared: InternalLifeNumericPreparedV1
    acceptance: LifeNumericAppraisalAcceptanceV1
    original_job: PersistentJob
    completed_job: PersistentJob


def stage_adopt_life_numeric_appraisal_in_transaction_v1(db, *, frame, request, installed_readers):
    from .d06_life_numeric_paid_v1 import read_life_numeric_paid_result_v1
    from ..authority_service.current_life_numeric_v1 import life_numeric_result_to_wire_v1
    if type(request) is not AdoptInternalLifeNumericRequestV1:
        raise TypeError('Life numeric adoption exact locator required')
    _, _, context, frozen = _current(db, frame, request, installed_readers)
    ids = internal_life_numeric_ids_v1(frozen.identity)
    p, b, result, cost, paid_digest = read_life_numeric_paid_result_v1(db,
        namespace=context.original.namespace, issuer=installed_readers.issuer, job_id=ids['job'])
    if (frame.envelope.identity.operation_id != ids['adopt'] or frame.envelope.identity.phase != ADOPT_OPERATION
            or p.frozen != frozen or p.owner_head_digest != frame.owner_guard.owner_head_digest):
        raise ValueError('Life numeric adoption is not its actual current once input')
    read = CurrentDomainReadV1(frame)
    job = get_job(db, p.job_id)
    if (job is None or job.phase != 'running' or job.fence != 1 or job.cancel_epoch
            or job.lease_holder != b.worker_subject or job.lease_expires_utc is None
            or frame.now_utc >= datetime.fromisoformat(job.lease_expires_utc.replace('Z', '+00:00')).timestamp()
            or read.head(db, job_graph_write(job).key, required=True).value != job_graph_write(job).value):
        raise ValueError('Life numeric adoption lost its current actual worker')
    suggestion, write = _appraisal_candidate(p, result)
    absent = read.head(db, write.key)
    if absent.revision or absent.valid:
        raise ValueError('Life numeric appraisal already adopted; use original read')
    read.head(db, cost.cost_ref, required=True)
    completed = replace(job, phase='completed', result_ref=p.call_id,
        wake_condition=None, lease_holder=None, lease_expires_utc=None)
    rows = tuple(D04GraphReadV3(a.key.token, a.revision, a.valid, canonical_serialize(a.value)) for a in frame.snapshot.atoms)
    acceptance = LifeNumericAppraisalAcceptanceV1(p.namespace, ids['adopt'], p.job_id,
        context.original.digest, context.before.digest, write.key.token, 1, canonical_serialize(write.value),
        p.digest, p.job_id, canonical_digest(life_numeric_result_to_wire_v1(result)), p.job_id,
        paid_digest, canonical_serialize(plain_v1(suggestion)), rows)
    primary = stage_result_v1(frame, 'd04', ADOPT_OPERATION, request, writes=(write,),
        provenance={'acceptance_digest': acceptance.digest, 'acceptance': plain_v1(acceptance)},
        proposal_schema=APPRAISAL_SCHEMA, proposal_hash=APPRAISAL_HASH)
    jp = stage_result_v1(frame, 'd11', ADOPT_OPERATION, request, writes=(job_graph_write(completed),),
        proposal_schema=JOB_SCHEMA, proposal_hash=JOB_HASH).proposals[0]
    staged = LifeNumericAppraisalAdoptionStageV1(primary, jp, frame, p, acceptance, job, completed)
    identity = id(staged)
    _ADOPTIONS[identity] = (weakref.ref(staged, lambda _: _ADOPTIONS.pop(identity, None)), db)
    return staged


def verify_life_numeric_appraisal_adoption_in_transaction_v1(db, staged, readers):
    entry = _ADOPTIONS.get(id(staged))
    if entry is None or entry[0]() is not staged or entry[1] is not db or not db.in_transaction:
        raise ValueError('Life numeric adoption lacks this exact privately issued stage')
    p = staged.prepared
    _, _, context, frozen = _current(db, staged.frame,
        AdoptInternalLifeNumericRequestV1(p.episode_ref, p.causal_operation_id), readers)
    read_life_numeric_paid_cost_for_acceptance_v1(db, staged.acceptance, readers.issuer)
    if (frozen != p.frozen or context.original.digest != staged.acceptance.context_digest
            or get_job(db, p.job_id) not in (staged.original_job, staged.completed_job)
            or len(staged.stage.proposals) != 1 or len(staged.stage.proposals[0].typed_writes) != 1
            or canonical_serialize(staged.stage.proposals[0].typed_writes[0].value) != staged.acceptance.appraisal_value_json
            or staged.job_proposal.typed_writes != (job_graph_write(staged.completed_job),)):
        raise ValueError('Life numeric adoption current stage/job/input changed')
    return staged


def record_life_numeric_appraisal_acceptance_after_cas_v1(db, *, staged, issuer, receipt):
    entry = _ADOPTIONS.get(id(staged))
    a = staged.acceptance
    key = AtomKey.from_token(a.appraisal_ref)
    jw = job_graph_write(staged.completed_job)
    if (entry is None or entry[0]() is not staged or entry[1] is not db or not db.in_transaction
            or type(receipt) is not CommitReceipt or receipt.status != 'committed'
            or receipt.operation_id != a.operation_id
            or set(receipt.write_versions) != {GraphVersion(key, 1), GraphVersion(jw.key, 3)}):
        raise ValueError('Life numeric adoption needs its exact two-member actual CAS')
    actual = db.execute('SELECT digest,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
        (*a.namespace.as_tuple, a.operation_id)).fetchone()
    for ref, revision, value in ((a.appraisal_ref, 1, a.appraisal_value_json), (jw.key.token, 3, canonical_serialize(jw.value))):
        if db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=?', (ref, revision)).fetchone() != (value, 1, a.operation_id):
            raise ValueError('Life numeric adoption actual graph history differs')
    if actual != (receipt.operation_digest, receipt.commit_seq) or get_job(db, a.job_id) != staged.completed_job:
        raise ValueError('Life numeric adoption actual bundle/SQL job differs')
    result = _record(db, issuer=issuer, namespace=a.namespace, kind='numeric_appraisal_acceptance_v1',
        ref=a.appraisal_ref, operation_id=a.operation_id, value=a)
    _ADOPTIONS.pop(id(staged), None)
    return result
