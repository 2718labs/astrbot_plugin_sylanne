"""Independent numeric-Life actual call, cost COMMIT and released result originals.

No new tables; all companions use the existing signed Life store. Nothing in
this module calls a model or treats a decoded response as a current read grant.
"""
from dataclasses import asdict, fields
import json
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_types import AtomKey
from .d11_life_preparation_v1 import _read, _record
from .model_cost_settlement import OriginalModelCostCommitV1, original_model_cost_operation_id_v1
from ..model_broker.internal_life_numeric_v1 import WORK_KIND


def life_numeric_model_draft_v1(db, *, namespace, issuer, job_id, metadata, epoch):
    from .d06_life_numeric_worker_v1 import read_committed_life_numeric_request_v1
    from .jobs import get_job
    from ..graph_store import GraphStore
    from ..authority_service.v2_model_egress_contract import ModelEgressDraftV1
    if not db.in_transaction:
        raise ValueError('Life numeric model draft needs an actual SQL snapshot')
    actual = GraphStore._decode_recovery(db.execute('SELECT schema,requirements_json,graph_revision '
        'FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?', namespace.as_tuple).fetchone(), namespace)
    if actual != metadata or db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?', namespace.as_tuple).fetchone() != (epoch.revision,):
        raise ValueError('Life numeric draft Graph stamp differs from actual selected database')
    p, b, model = read_committed_life_numeric_request_v1(db, namespace=namespace, issuer=issuer, job_id=job_id)
    job = get_job(db, job_id)
    quote = issuer.resource_issuer.original_signed_quote(db, p.quote_id, 1)
    if (job.phase != 'running' or job.fence != 1 or job.cancel_epoch or job.lease_holder != b.worker_subject
            or canonical_digest(quote) != p.quote_digest or quote.work_kind != WORK_KIND):
        raise ValueError('Life numeric draft actual worker/quote differs')
    target = metadata.requirements
    sources = tuple(sorted((v.key.owner.subject, v.revision) for v in model.envelope.version_guard.read_versions
        if v.key.type_name == 'memory.source' and v.revision > 0))
    accesses = tuple(sorted((v.key.owner.subject, v.revision) for v in model.envelope.version_guard.read_versions
        if v.key.type_name == 'memory.access' and v.revision > 0))
    draft = ModelEgressDraftV1(target.authority_id, target.authority_namespace, b.worker_subject,
        b.acquire_operation_id, p.call_id, model.digest, job_id, job.fence,
        tuple(ref for ref, _ in sources), sources, accesses, model.envelope.version_guard.access_epoch,
        model.envelope.version_guard.delete_epoch, epoch.revision, metadata.graph_revision,
        target.activation_generation, target.revocation_epoch, target.deletion_seq, target.execution_seq,
        quote.parent_budget_lease_ref, p.operation_id, p.reservation_digest, tuple(sorted(quote.ceiling.items())),
        model.provider_id, model.model_id, p.frozen.appraisal.installation.provider_config_digest,
        model.max_output_tokens, acquire_operation_id=b.acquire_operation_id, binding_digest=b.digest)
    return p, b, model, draft


def seal_life_numeric_call_v1(db, *, namespace, issuer, intent, permit, metadata, epoch):
    from .d06_life_numeric_worker_v1 import read_committed_life_numeric_request_v1
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1, ModelEgressDraftV1
    from ..authority_service.v2_model_egress_wire import to_wire
    from ..authority_service.v2_contract import FencePermitV2, to_wire as permit_wire
    from .jobs import get_job
    if not db.in_transaction or type(intent) is not ModelEgressIntentV1 or type(permit) is not FencePermitV2:
        raise TypeError('Life numeric call requires its actual acquired intent and egress permit')
    p, b, model = read_committed_life_numeric_request_v1(db, namespace=namespace, issuer=issuer, job_id=intent.job_id)
    _, _, _, draft = life_numeric_model_draft_v1(db, namespace=namespace, issuer=issuer,
        job_id=intent.job_id, metadata=metadata, epoch=epoch)
    if ModelEgressDraftV1.from_intent(intent) != draft:
        raise ValueError('Life numeric Core intent differs from its exact actual acquired draft')
    job = get_job(db, p.job_id)
    if ((intent.binding_digest, intent.call_id, intent.request_digest, intent.acquire_operation_id,
            intent.budget_reservation_operation_id, intent.budget_reservation_digest) !=
            (b.digest, p.call_id, model.digest, b.acquire_operation_id, p.operation_id, p.reservation_digest)
            or intent.subject != b.worker_subject or job.lease_holder != b.worker_subject
            or job.fence != intent.worker_fence or job.phase != 'running'
            or permit.subject != intent.subject or permit.operation_id != intent.operation_id
            or permit.operation != 'model_egress'
            or (permit.token, permit.fence_epoch, permit.revision) !=
               (intent.fence_token, intent.fence_epoch, intent.fence_revision)
            or canonical_digest(asdict(permit.pinned_anchor)) != intent.anchor_digest):
        raise ValueError('Life numeric call differs from its actual worker/once binding')
    return _record(db, issuer=issuer, namespace=namespace, kind='numeric_call_v1', ref=p.job_id,
        operation_id=b.acquire_operation_id,
        value={'schema': 'd06.internal-life-numeric-call.v1', 'prepared_digest': p.digest,
            'binding_digest': b.digest, 'request_digest': model.digest,
            'intent': to_wire(intent), 'permit': permit_wire(permit)})

def read_life_numeric_cost_commit_v1(db,*,namespace,issuer,prepared,intent,terminal,fact=None):
    """Exact seven-field accounting family, distinct from a Domain COMMIT."""
    from ..contracts import canonical_json
    from .budget import _receipt_from_json
    if not db.in_transaction:raise ValueError('Life actual cost requires a pinned SQL snapshot')
    saved=_read(db,namespace=namespace,issuer=issuer,kind='numeric_call_v1',ref=prepared.job_id)
    sealed=None if saved is None else saved[0]
    from ..authority_service.v2_model_egress_wire import to_wire
    if sealed is None or sealed['intent']!=to_wire(intent):raise ValueError('Life cost lacks authenticated sealed call')
    op=original_model_cost_operation_id_v1(namespace,prepared.call_id)
    row=db.execute('SELECT activity_id,effect_id,commit_seq,receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,op)).fetchone()
    if row is None:raise ValueError('Life actual paid cost COMMIT absent')
    raw=json.loads(row[3])
    if type(raw) is not dict or set(raw)!={'original_model_cost','original_intent_digest','terminal_receipt_digest','quote_id','quote_version','work_kind','accounting_attempt_id'} or canonical_json(raw)!=row[3]:
        raise ValueError('Life cost actual receipt closed fields differ')
    c=raw['original_model_cost']
    if type(c) is not dict or set(c)!={f.name for f in fields(OriginalModelCostCommitV1)}:raise ValueError('Life actual typed cost fields differ')
    for n in ('quote_version','commit_seq','graph_revision','graph_epoch'):
        if type(c[n]) is not int or c[n]<1:raise ValueError('Life cost version is not strict positive integer')
    cost=OriginalModelCostCommitV1(**c);quote=issuer.resource_issuer.original_signed_quote(db,prepared.quote_id,prepared.quote_version)
    budget=db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",(*namespace.as_tuple,prepared.prepare_operation_id)).fetchone()
    reservation=db.execute('SELECT state,digest FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',(quote.parent_budget_lease_ref,prepared.prepare_operation_id)).fetchone()
    attempt=db.execute('SELECT state,attempt_id FROM graph_original_model_cost_attempts_v1 WHERE bot=? AND persona=? AND call_id=?',(*namespace.as_tuple,prepared.call_id)).fetchone()
    digest=canonical_digest(asdict(terminal))
    if (budget is None or reservation!=('settled',prepared.reservation_digest)
            or attempt!=('committed',raw['accounting_attempt_id']) or raw['original_intent_digest']!=canonical_digest(asdict(intent))
            or raw['terminal_receipt_digest']!=digest or raw['work_kind']!=WORK_KIND or type(raw['quote_version']) is not int
            or (raw['quote_id'],raw['quote_version'])!=(prepared.quote_id,prepared.quote_version)
            or (cost.schema,cost.status,cost.operation_id,cost.call_id,cost.quote_id,cost.quote_version,cost.terminal_receipt_digest,cost.commit_seq)!=
               ('sylanne.d11.original-model-cost-commit.v1','committed',op,prepared.call_id,prepared.quote_id,prepared.quote_version,digest,row[2])
            or cost.budget_receipt_digest!=canonical_digest(asdict(_receipt_from_json(budget[0])))
            or (row[0],row[1])!=(prepared.activity_id,quote.effect_id)):
        raise ValueError('Life actual cost/quote/settlement/original call linkage differs')
    key=AtomKey.from_token(cost.cost_ref)
    if key.type_name!='runtime.cost_settlement' or NamespaceId.from_key(key)!=namespace:raise ValueError('Life cost locator differs')
    event=db.execute('SELECT reads,revisions,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?',(*namespace.as_tuple,prepared.activity_id,op)).fetchone()
    def pair(encoded,rev):
        a=json.loads(encoded)
        return type(a) is list and len(a)==1 and type(a[0]) is list and len(a[0])==2 and type(a[0][0]) is str and a[0][0]==key.token and type(a[0][1]) is int and a[0][1]==rev and canonical_json(a)==encoded
    history=db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=1',(key.token,)).fetchone()
    head=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
    if (event is None or not pair(event[0],0) or not pair(event[1],1) or event[2]!=cost.graph_epoch
            or history is None or history[0]!=op or history[2]!=1 or head!=(1,history[1],1)):
        raise ValueError('Life cost actual exact event/history/immutable head differs')
    value=json.loads(history[1])
    from .d11_types import RuntimeCostSettlement,cost_settlement_from_runtime
    expected=cost_settlement_from_runtime(db,bot_id=namespace.bot_id,persona_id=namespace.persona_id,
        activity_id=prepared.activity_id,bundle_operation_id=op,effect_id=quote.effect_id,
        settlement_id=op,lease_id=quote.parent_budget_lease_ref,cost_operation_id=prepared.prepare_operation_id,
        budget_operation_id=prepared.prepare_operation_id,budget_phase='settle',prior_unknown_ref=None,
        execution_revoked=True)
    if (type(value) is not dict or canonical_serialize(value)!=history[1]
            or canonical_serialize(plain_v1(expected))!=history[1]
            or expected.status!='settled' or expected.unconfirmed):
        raise ValueError('Life cost unknown dimensions or noncanonical body HOLD')
    if fact is not None:
        from .model_cost_settlement import OriginalModelCostFactV1,original_model_budget_actual
        if (type(fact) is not OriginalModelCostFactV1 or fact.intent!=intent or fact.receipt!=terminal
                or dict(expected.actual)!=original_model_budget_actual(fact,quote,work_kind=WORK_KIND)):
            raise ValueError('Life cost measured amount differs from actual Authority observation')
    return cost


def record_life_numeric_paid_result_v1(db, *, namespace, issuer, job_id, result_read, fact):
    """After the independent actual cost COMMIT; never performs another settle."""
    from ..authority_service.current_life_numeric_v1 import LifeNumericModelResultReadV1, life_numeric_result_to_wire_v1
    from .d06_life_numeric_worker_v1 import read_committed_life_numeric_request_v1
    from .model_cost_settlement import OriginalModelCostFactV1
    if not db.in_transaction or type(result_read) is not LifeNumericModelResultReadV1 or type(fact) is not OriginalModelCostFactV1:
        raise TypeError('Life numeric requires actual released original result and cost fact')
    p, b, model = read_committed_life_numeric_request_v1(db, namespace=namespace, issuer=issuer, job_id=job_id)
    result_read.require_original(fact.intent, p, p.frozen, b)
    if (fact.recovery.state != 'observed' or fact.recovery.content_erased
            or result_read.terminal_receipt != fact.receipt
            or result_read.observation.digest != fact.recovery.observation_digest
            or result_read.observation.usage != fact.recovery.usage or result_read.observation.cost != fact.recovery.cost
            or result_read.request.model_request_digest != model.digest):
        raise ValueError('Life numeric result differs from its actual observed cost/terminal')
    cost = read_life_numeric_cost_commit_v1(db, namespace=namespace, issuer=issuer, prepared=p,
        intent=fact.intent, terminal=fact.receipt, fact=fact)
    raw = {'schema': 'd06.internal-life-numeric-paid-result.v1', 'prepared_digest': p.digest,
        'binding_digest': b.digest, 'result': life_numeric_result_to_wire_v1(result_read),
        'cost': plain_v1(cost), 'cost_digest': canonical_digest(cost), 'paid': True}
    return _record(db, issuer=issuer, namespace=namespace, kind='numeric_paid_v1', ref=p.job_id,
        operation_id=cost.operation_id, value=raw)


def read_life_numeric_paid_result_v1(db, *, namespace, issuer, job_id):
    from ..authority_service.current_life_numeric_v1 import LifeNumericModelResultReadV1, life_numeric_result_from_wire_v1
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    from ..authority_service.v2_model_egress_wire import from_wire
    from .d06_life_numeric_worker_v1 import read_committed_life_numeric_request_v1
    p, b, model = read_committed_life_numeric_request_v1(db, namespace=namespace, issuer=issuer, job_id=job_id)
    saved = _read(db, issuer=issuer, namespace=namespace, kind='numeric_paid_v1', ref=job_id)
    call = _read(db, issuer=issuer, namespace=namespace, kind='numeric_call_v1', ref=job_id)
    if saved is None or call is None: raise ValueError('Life numeric actual paid/call originals absent')
    raw = saved[0]
    if (type(raw) is not dict or set(raw) != {'schema', 'prepared_digest', 'binding_digest', 'result', 'cost', 'cost_digest', 'paid'}
            or raw['schema'] != 'd06.internal-life-numeric-paid-result.v1' or raw['paid'] is not True):
        raise ValueError('Life numeric paid original closed version differs')
    result = life_numeric_result_from_wire_v1(raw['result'], LifeNumericModelResultReadV1)
    intent = from_wire(call[0]['intent'], ModelEgressIntentV1)
    result.require_original(intent, p, p.frozen, b)
    cost = read_life_numeric_cost_commit_v1(db, namespace=namespace, issuer=issuer, prepared=p,
        intent=intent, terminal=result.terminal_receipt)
    if (saved[1] != cost.operation_id or raw['prepared_digest'] != p.digest or raw['binding_digest'] != b.digest
            or raw['cost'] != plain_v1(cost) or raw['cost_digest'] != canonical_digest(cost)
            or result.request.model_request_digest != model.digest):
        raise ValueError('Life numeric paid original lost exact cost/worker membership')
    return p, b, result, cost, canonical_digest(raw)


def prepare_life_numeric_result_selector_v1(db, *, namespace, issuer, job_id,
        authority_id, authority_namespace, attempt=1):
    from ..authority_service.current_life_numeric_v1 import LifeNumericModelResultReadRequestV1, life_numeric_read_attempt_id_v1
    from ..model_broker.internal_life_numeric_v1 import internal_life_numeric_ids_v1
    from .d06_life_numeric_worker_v1 import read_committed_life_numeric_request_v1
    p, b, model = read_committed_life_numeric_request_v1(db, namespace=namespace, issuer=issuer, job_id=job_id)
    ids = internal_life_numeric_ids_v1(p.frozen.identity)
    selector = LifeNumericModelResultReadRequestV1(authority_id, authority_namespace, namespace,
        p.installation_id, p.episode_ref, p.occurrence_digest, p.causal_operation_id, p.job_id,
        b.acquire_operation_id, p.operation_id, p.call_id, b.digest, p.digest, model.digest,
        ids['adopt'], life_numeric_read_attempt_id_v1(ids['adopt'], attempt))

    from ..authority_service.current_life_numeric_v1 import life_numeric_result_to_wire_v1
    _record(db, issuer=issuer, namespace=namespace, kind='numeric_read_attempt_v1',
        ref=selector.read_attempt_id, operation_id=p.acquire_operation_id,
        value=life_numeric_result_to_wire_v1(selector))
    return selector
