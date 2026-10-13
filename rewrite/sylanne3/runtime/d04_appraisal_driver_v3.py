"""D04 paid appraisal transaction bodies; W01 owns fences and Graph CAS.

The immutable originals share the business database. Authority independently
qualifies and releases the original model result; a caller response is never
an accounting or appraisal original. Network calls run outside SQL locks.
"""
from __future__ import annotations


from dataclasses import asdict, dataclass
from datetime import datetime
from hashlib import sha256
import json
import sqlite3

from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
from ..authority_service.v2_model_egress_wire import from_wire as model_from_wire, to_wire as model_to_wire
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion, GraphWrite, Owner
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..domains.d06 import source_correction_head_key
from ..model_broker.d04_appraisal import (
    FrozenAppraisalRequestV1, freeze_appraisal_request_v1, parse_appraisal_output_v1,
)
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .budget import reserve_budget
from .d11_types import job_graph_write
from .jobs import PersistentJob, create_job, get_job, acquire_job, transition_job
from .model_cost_settlement import (
    OriginalModelCostFactV1, apply_original_model_budget_in_transaction,
    prepare_original_model_cost_plan,
)

WORK_KIND = "d04.appraisal"


@dataclass(frozen=True, slots=True)
class D04GraphReadV3:
    ref: str
    revision: int
    valid: bool
    value_json: str

    def __post_init__(self):
        AtomKey.from_token(self.ref)
        if type(self.revision) is not int or self.revision < 0 or type(self.valid) is not bool:
            raise ValueError("invalid D04 read revision/validity")
        if canonical_serialize(json.loads(self.value_json)) != self.value_json:
            raise ValueError("noncanonical D04 read payload")


@dataclass(frozen=True, slots=True)
class D04AppraisalOriginalV3:
    namespace: NamespaceId
    operation_id: str
    job_id: str
    call_id: str
    frozen_json: str
    read_rows: tuple[D04GraphReadV3, ...]
    audience: tuple[str, ...]
    purpose: str
    quote_id: str
    quote_version: int
    quote_digest: str
    reservation_digest: str
    model_request_digest: str
    activation_generation: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    schema: str = "d04.paid_appraisal_original.v3"

    @property
    def digest(self):
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class D04AppraisalStageV3:
    original: D04AppraisalOriginalV3
    writes: tuple[GraphWrite, ...]
    read_versions: tuple[GraphVersion, ...]


@dataclass(frozen=True, slots=True)
class D04AppraisalAcceptanceV3:
    namespace: NamespaceId
    operation_id: str
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
    schema: str = "d04.appraisal_acceptance_original.v3"

    @property
    def digest(self):
        return canonical_digest(asdict(self))


def install_d04_appraisal_schema_v3(db: sqlite3.Connection) -> None:
    # No executescript: usable within caller-owned installation transactions.
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d04_originals_v3 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, kind TEXT NOT NULL,
        original_ref TEXT NOT NULL, payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL,
        PRIMARY KEY(bot,persona,kind,original_ref))""")
    for action in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS graph_d04_originals_v3_no_{action.lower()}
            BEFORE {action} ON graph_d04_originals_v3
            BEGIN SELECT RAISE(ABORT,'D04 original is immutable'); END""")


def record_d04_original_in_transaction_v3(db, namespace, kind, original_ref, payload):
    if not db.in_transaction:
        raise ValueError("D04 original requires caller-owned fenced transaction")
    wire = canonical_serialize(payload)
    digest = canonical_digest(json.loads(wire))
    prior = read_d04_original_v3(db, namespace, kind, original_ref)
    if prior is not None:
        if prior != (json.loads(wire), digest):
            raise ValueError("D04 original identity reused with changed payload")
        return digest
    db.execute("INSERT INTO graph_d04_originals_v3 VALUES(?,?,?,?,?,?)",
               (*namespace.as_tuple, kind, original_ref, wire, digest))
    return digest


def read_d04_original_v3(db, namespace, kind, original_ref):
    from .domain_background_read_v3 import background_json_loads_v3,background_json_matches_v3,background_json_digest_v3
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    row = _producer_original_point_v3(db, table='graph_d04_originals_v3', columns=('payload_json', 'payload_digest'), key_columns=('bot', 'persona', 'kind', 'original_ref'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2],_producer_params_v3[3]))((*namespace.as_tuple, kind, original_ref)), legacy_reader=lambda: db.execute("SELECT payload_json,payload_digest FROM graph_d04_originals_v3 "
                     "WHERE bot=? AND persona=? AND kind=? AND original_ref=?",
                     (*namespace.as_tuple, kind, original_ref)).fetchone())
    if row is None:
        return None
    raw = background_json_loads_v3(row[0])
    if not background_json_matches_v3(row[0],raw) or background_json_digest_v3(row[0],raw) != row[1]:
        raise ValueError("D04 immutable original payload changed")
    return raw, row[1]


def graph_read_rows_v3(snapshot: GraphSnapshot, versions: tuple[GraphVersion, ...]):
    if len({v.key for v in versions}) != len(versions):
        raise ValueError("D04 duplicate graph read")
    rows = []
    for version in sorted(versions, key=lambda v: v.key.token):
        atom = snapshot.get(version.key)
        if atom is None or atom.revision != version.revision:
            raise ValueError("D04 graph read not in frozen snapshot")
        rows.append(D04GraphReadV3(atom.key.token, atom.revision, atom.valid,
                                   canonical_serialize(atom.value)))
    return tuple(rows)


def require_current_read_rows_v3(db, rows, namespace):
    if not db.in_transaction:
        raise ValueError("current D04 reads require pinned transaction")
    for row in rows:
        key = AtomKey.from_token(row.ref)
        if (key.owner.bot, key.owner.persona) != namespace.as_tuple:
            raise ValueError("D04 read crosses namespace")
        current = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (row.ref,)).fetchone()
        if row.revision == 0:
            if row.valid or current is not None:
                raise ValueError("D04 negative read now exists")
        elif (current is None or (current[0], bool(current[2])) != (row.revision, row.valid)
                or canonical_serialize(json.loads(current[1])) != row.value_json):
            raise ValueError("D04 current dependency changed")


def qualify_appraisal_sources_v3(snapshot, frozen, *, audience, purpose):
    """Verify complete ancestor/access/correction closure, including absence."""
    namespace = frozen.input.namespace
    active, done = set(), {}
    versions = {}

    def walk(ref):
        if ref in active or len(done) + len(active) >= 256:
            raise ValueError("D04 source ancestry is cyclic or exceeds bound")
        if ref in done:
            return done[ref]
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
            raise ValueError("D04 source scope differs")
        keys = (key, access_key(*namespace.as_tuple, key.owner.subject),
                source_correction_head_key(namespace, key.owner.subject))
        source, access, correction = (snapshot.get(k) for k in keys)
        if (source is None or not source.valid or access is None or not access.valid
                or correction is None or correction.valid or correction.revision != 0):
            raise ValueError("D04 source/access/correction is unavailable")
        record = SourceRecord.from_dict(source.value)
        validate_access(access.value)
        if (record.source_id != key.owner.subject or access.value["source_id"] != record.source_id
                or access.value["status"] != "active" or purpose not in record.purposes
                or purpose not in access.value["purposes"]
                or not set(audience) <= set(record.audiences)
                or not set(audience) <= set(access.value["audiences"])):
            raise ValueError("D04 source use no longer qualified")
        active.add(ref)
        for parent in record.parent_source_ids:
            walk(source_key(*namespace.as_tuple, parent).token)
        active.remove(ref)
        done[ref] = record
        for atom in (source, access, correction):
            versions[atom.key] = GraphVersion(atom.key, atom.revision)
        return record

    for qualified in frozen.input.sources:
        record = walk(qualified.source_ref.ref)
        if (record != qualified.record or
                snapshot.get(AtomKey.from_token(qualified.source_ref.ref)).revision != qualified.source_ref.version or
                snapshot.get(AtomKey.from_token(qualified.access_ref.ref)).revision != qualified.access_ref.version):
            raise ValueError("D04 frozen source differs from current original")
    return tuple(versions.values()), {ref: record.provenance_root for ref, record in done.items()}


def stage_current_d04_appraisal_in_transaction_v3(
    db, *, frozen: FrozenAppraisalRequestV1, current_frozen: FrozenAppraisalRequestV1,
    snapshot: GraphSnapshot, read_versions: tuple[GraphVersion, ...],
    job: PersistentJob, call_id: str, quote, resource_issuer,
    model_request_digest: str, audience: tuple[str, ...], purpose: str,
    activation_generation: int, access_epoch: int, delete_epoch: int,
) -> D04AppraisalStageV3:
    """W01 passes its installed current issuer's rederived request, never wire from UI."""
    if (not db.in_transaction or type(frozen) is not FrozenAppraisalRequestV1
            or current_frozen != frozen
            or freeze_appraisal_request_v1(frozen.input, frozen.installation) != frozen):
        raise ValueError("current installed D04 appraisal request required")
    namespace = frozen.input.namespace
    if (job.work_kind != WORK_KIND or job.phase != "queued" or job.fence != 0
            or job.effect_id is not None or job.cancel_epoch != 0
            or (job.bot_id, job.persona_id) != namespace.as_tuple
            or quote.work_kind != WORK_KIND or quote.operation_id != job.operation_id
            or quote.activity_id != job.activity_id or quote.parent_budget_lease_ref != job.budget_ref
            or quote.graph_job_ref != job_graph_write(job).key.token
            or (quote.bot_id, quote.persona_id) != namespace.as_tuple
            or call_id == job.operation_id):
        raise ValueError("D04 quote/job/original identity differs")
    source_versions, _families = qualify_appraisal_sources_v3(snapshot, frozen, audience=audience, purpose=purpose)
    mandatory = {AtomKey.from_token(ref.ref): ref.version for ref in (
        frozen.input.event_ref, frozen.input.role_ref,
        *(item.ref for item in frozen.input.interpretations))}
    versions = {v.key: v for v in (*read_versions, *source_versions)}
    for key, revision in mandatory.items():
        if key not in versions or versions[key].revision != revision:
            raise ValueError("D04 D01/D03/D07 current qualification absent")
    rows = graph_read_rows_v3(snapshot, tuple(versions.values()))
    require_current_read_rows_v3(db, rows, namespace)
    resource_issuer.issue_quote(db, quote)
    if resource_issuer.original_signed_quote(db, quote.quote_id, quote.version) != quote:
        raise ValueError("D04 signed appraisal quote differs")
    reservation_digest = canonical_digest({"schema": "d04.appraisal-reservation.v3",
        "frozen": asdict(frozen), "job": asdict(job), "quote": quote,
        "call_id": call_id, "model_request_digest": model_request_digest})
    reserve_budget(db, job.budget_ref, job.operation_id, reservation_digest, quote.ceiling)
    persisted = create_job(db, job, job.operation_id, reservation_digest)
    original = D04AppraisalOriginalV3(namespace, job.operation_id, job.job_id, call_id,
        canonical_serialize(asdict(frozen)), rows, audience, purpose, quote.quote_id,
        quote.version, canonical_digest(quote), reservation_digest, model_request_digest,
        activation_generation, snapshot.epochs[0].revision, access_epoch, delete_epoch)
    record_d04_original_in_transaction_v3(db, namespace, "appraisal", job.job_id, asdict(original))
    return D04AppraisalStageV3(original, (job_graph_write(persisted),),
                               tuple(versions.values()))


def read_current_d04_appraisal_original_v3(db, namespace, job_id):
    row = read_d04_original_v3(db, namespace, "appraisal", job_id)
    if row is None:
        return None
    raw = row[0]
    result = D04AppraisalOriginalV3(**{**raw, "namespace": NamespaceId(**raw["namespace"]),
        "audience": tuple(raw["audience"]),
        "read_rows": tuple(D04GraphReadV3(**r) for r in raw["read_rows"])})
    if result.namespace != namespace or result.job_id != job_id or result.digest != row[1]:
        raise ValueError("D04 appraisal original identity differs")
    return result


def seal_d04_appraisal_request_in_transaction_v3(db, original, request):
    from .reply_model_job import reply_request_wire_v1
    from ..model_broker.d04_appraisal import thaw_appraisal_request_v1, TEMPLATE_DIGEST
    from ..model_broker.broker import ModelCallRequest
    if not db.in_transaction or type(request) is not ModelCallRequest:
        raise ValueError("actual acquired appraisal request required")
    frozen = thaw_appraisal_request_v1(json.loads(original.frozen_json))
    job = get_job(db, original.job_id)
    if (frozen.model_request_digest != original.model_request_digest
            or request.call_id != original.call_id or request.prompt_template_digest != TEMPLATE_DIGEST
            or dict(request.payload) != json.loads(frozen.canonical_wire)
            or request.envelope.authority.namespace != original.namespace
            or request.envelope.authority.worker_fence != job.fence
            or request.envelope.authority.actor != job.lease_holder
            or job.phase != "running" or job.operation_id != original.operation_id
            or request.identity.phase != "d04.appraisal"):
        raise ValueError("appraisal acquired request differs from frozen input or current worker")
    return record_d04_original_in_transaction_v3(db, original.namespace, "appraisal_request", original.job_id,
        reply_request_wire_v1(request.envelope, request))


def read_original_d04_request_v3(db, original):
    from .natural_reply_job_v2 import _request_from_wire
    row = read_d04_original_v3(db, original.namespace, "appraisal_request", original.job_id)
    if row is None:
        raise ValueError("appraisal typed request original is absent")
    return _request_from_wire(canonical_serialize(row[0]))


def seal_d04_appraisal_call_in_transaction_v3(db, original, intent: ModelEgressIntentV1):
    if (not db.in_transaction or intent.job_id != original.job_id
            or intent.call_id != original.call_id or intent.request_digest != read_original_d04_request_v3(db, original).digest
            or intent.budget_reservation_operation_id != original.operation_id
            or intent.budget_reservation_digest != original.reservation_digest
            or intent.binding_digest != original.digest):
        raise ValueError("D04 original model call binding differs")
    job = get_job(db, original.job_id)
    if job.phase != "running" or job.fence != intent.worker_fence or job.lease_holder != intent.subject:
        raise ValueError("D04 current worker fence differs")
    return record_d04_original_in_transaction_v3(db, original.namespace, "appraisal_call",
                                                 original.job_id, model_to_wire(intent))


def _previous_independent_cost_v3(db, original, fact, resource_issuer):
    """Recover the same durable accounting commit without settling it twice."""
    from .model_cost_settlement import original_model_cost_operation_id_v1, OriginalModelCostApplicationV1, original_model_budget_measurement
    from .budget import _receipt_from_json
    operation_id = original_model_cost_operation_id_v1(original.namespace, original.call_id)
    row = db.execute("SELECT receipt_json,activity_id FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*original.namespace.as_tuple, operation_id)).fetchone()
    if row is None:
        return None
    body = json.loads(row[0])
    committed = body.get("original_model_cost", {})
    quote = resource_issuer.original_signed_quote(db, original.quote_id, original.quote_version)
    if (body.get("original_intent_digest") != canonical_digest(asdict(fact.intent))
            or body.get("terminal_receipt_digest") != canonical_digest(asdict(fact.receipt))
            or body.get("quote_id") != original.quote_id or body.get("quote_version") != original.quote_version
            or body.get("work_kind") != WORK_KIND or committed.get("status") != "committed"
            or committed.get("call_id") != original.call_id or committed.get("operation_id") != operation_id
            or row[1] != quote.activity_id or canonical_digest(quote) != original.quote_digest):
        raise ValueError("D04 original historical cost commit differs")
    budget = db.execute("SELECT digest,lease_id,receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
        (*original.namespace.as_tuple, original.operation_id)).fetchone()
    atom = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (committed.get("cost_ref"),)).fetchone()
    event = db.execute("SELECT 1 FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*original.namespace.as_tuple, quote.activity_id, operation_id)).fetchone()
    if (budget is None or budget[:2] != (original.reservation_digest, quote.parent_budget_lease_ref)
            or atom is None or atom[1] != 1 or event != (1,)):
        raise ValueError("D04 historical cost lacks actual budget/Graph event originals")
    receipt = _receipt_from_json(budget[2])
    if canonical_digest(asdict(receipt)) != committed.get("budget_receipt_digest"):
        raise ValueError("D04 historical budget receipt differs")
    _, unknown = original_model_budget_measurement(fact, quote, work_kind=WORK_KIND)
    return OriginalModelCostApplicationV1(receipt,
        GraphWrite(AtomKey.from_token(committed["cost_ref"]), json.loads(atom[0]))), unknown


def settle_d04_appraisal_result_in_transaction_v3(
    db, original, *, result_read, fact: OriginalModelCostFactV1, resource_issuer,
    holder: str, fence: int,
):
    """Persist an Authority-released result before accounting; unknown never parses."""
    from ..authority_service.current_d04_appraisal_v3 import D04AppraisalResultReadV3
    if not db.in_transaction or type(result_read) is not D04AppraisalResultReadV3:
        raise ValueError("fenced D04 Authority result required")
    saved_call = read_d04_original_v3(db, original.namespace, "appraisal_call", original.job_id)
    if saved_call is None or saved_call[0] != model_to_wire(fact.intent):
        raise ValueError("D04 paid result differs from sealed call")
    result_read.require_original(fact.intent, original)
    if (fact.recovery.state != "observed" or fact.recovery.content_erased
            or result_read.terminal_receipt != fact.receipt
            or result_read.observation.digest != fact.recovery.observation_digest
            or result_read.observation.usage != fact.recovery.usage
            or result_read.observation.cost != fact.recovery.cost):
        raise ValueError("D04 result and Authority actual cost differ")
    result_ref = "d04-result:" + original.call_id
    result_digest = record_d04_original_in_transaction_v3(db, original.namespace,
        "appraisal_result", result_ref, asdict(result_read))
    existing = read_d04_original_v3(db, original.namespace, "appraisal_cost", original.job_id)
    if existing is not None:
        if (not existing[0].get("paid") or existing[0]["prepared_digest"] != original.digest
                or existing[0]["result_original_digest"] != result_digest):
            raise ValueError("D04 final paid original conflicts with original model result")
        return existing[0], ()
    previous = _previous_independent_cost_v3(db, original, fact, resource_issuer)
    if previous is None:
        plan = prepare_original_model_cost_plan(db, resource_issuer, original.namespace, fact,
            quote_id=original.quote_id, quote_version=original.quote_version, work_kind=WORK_KIND)
        application = apply_original_model_budget_in_transaction(db, resource_issuer, plan, fact)
        unknown_dimensions = plan.unknown_dimensions
    else:
        application, unknown_dimensions = previous
    # Unknown actual dimensions remain reserved and are explicitly ineligible.
    paid = application.receipt.status in {"settled", "overrun"} and not unknown_dimensions
    receipt = {"schema": "d04.appraisal-paid-result.v3", "prepared_digest": original.digest,
        "result_original_ref": result_ref, "result_original_digest": result_digest,
        "cost_ref": application.cost_write.key.token, "cost_value": application.cost_write.value,
        "budget_receipt": asdict(application.receipt), "paid": paid,
        "unknown_dimensions": unknown_dimensions}
    if paid:
        record_d04_original_in_transaction_v3(db, original.namespace, "appraisal_cost", original.job_id, receipt)
    else:
        # A partial cost observation is immutable evidence of that observation,
        # not the final bill for the call. Keep unresolved dimensions reserved
        # so a later original cost reconciliation may produce the final bill.
        partial_ref = original.job_id + ":" + canonical_digest(receipt)
        record_d04_original_in_transaction_v3(db, original.namespace, "appraisal_cost_partial", partial_ref, receipt)
    writes = [application.cost_write] if previous is None else []
    if paid:
        job = transition_job(db, original.job_id, holder, fence, target_phase="completed", result_ref=result_ref)
        writes.append(job_graph_write(job))
    return receipt, tuple(writes)


def stage_current_d04_appraisal_adoption_in_transaction_v3(
    db, original, *, frozen, current_frozen, snapshot, current_read_versions,
):
    """Produce subjective appraisal Graph CAS and acceptance; record only after CAS."""
    if (not db.in_transaction or frozen != current_frozen
            or canonical_serialize(asdict(frozen)) != original.frozen_json):
        raise ValueError("D04 adoption current installed input changed")
    qualify_appraisal_sources_v3(snapshot, frozen, audience=original.audience, purpose=original.purpose)
    require_current_read_rows_v3(db, original.read_rows, original.namespace)
    cost = read_d04_original_v3(db, original.namespace, "appraisal_cost", original.job_id)
    if cost is None or cost[0]["paid"] is not True:
        raise ValueError("D04 original model cost is not fully paid")
    result = read_d04_original_v3(db, original.namespace, "appraisal_result", cost[0]["result_original_ref"])
    if result is None or result[1] != cost[0]["result_original_digest"]:
        raise ValueError("D04 paid model result original missing")
    response = json.loads(result[0]["observation"]["result_json"])
    if set(response) != {"text"} or type(response["text"]) is not str:
        raise ValueError("D04 exact provider text result differs")
    suggestion = parse_appraisal_output_v1(response["text"], frozen)
    if suggestion.bundle is None:
        raise ValueError("D04 appraisal has no supported meaning facets")
    appraisal = suggestion.bundle
    key = AtomKey(Owner("event", *original.namespace.as_tuple, appraisal.event_ref),
                  "d04.appraisal_bundle.v1", appraisal.appraisal_id)
    existing = snapshot.get(key)
    if existing is None or existing.revision != 0 or existing.valid:
        raise ValueError("D04 appraisal CAS must include true absence")
    original_versions = tuple(GraphVersion(AtomKey.from_token(row.ref), row.revision) for row in original.read_rows)
    versions = {v.key: v for v in (*current_read_versions, *original_versions, GraphVersion(key, 0))}
    rows = graph_read_rows_v3(snapshot, tuple(versions.values()))
    require_current_read_rows_v3(db, rows, original.namespace)
    write = GraphWrite(key, json.loads(canonical_serialize(asdict(appraisal))),
        tuple(AtomKey.from_token(r.ref) for r in original.read_rows if r.revision > 0))
    acceptance = D04AppraisalAcceptanceV3(original.namespace, original.operation_id,
        key.token, 1, canonical_serialize(asdict(appraisal)), original.digest,
        cost[0]["result_original_ref"], result[1], original.job_id, cost[1],
        canonical_serialize(asdict(suggestion)), rows)
    return acceptance, (write,), tuple(versions.values())


def record_d04_appraisal_acceptance_after_cas_v3(db, acceptance):
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                     (acceptance.appraisal_ref,)).fetchone()
    if (row is None or row[0] != acceptance.appraisal_revision or row[2] != 1
            or canonical_serialize(json.loads(row[1])) != acceptance.appraisal_value_json):
        raise ValueError("D04 appraisal acceptance must follow actual same-transaction CAS")
    return record_d04_original_in_transaction_v3(db, acceptance.namespace,
        "appraisal_acceptance", acceptance.appraisal_ref, asdict(acceptance))


def read_d04_appraisal_acceptance_v3(db, namespace, appraisal_ref):
    row = read_d04_original_v3(db, namespace, "appraisal_acceptance", appraisal_ref)
    if row is None:
        return None
    raw = row[0]
    return D04AppraisalAcceptanceV3(**{**raw, "namespace": NamespaceId(**raw["namespace"]),
        "read_rows": tuple(D04GraphReadV3(**r) for r in raw["read_rows"])})
