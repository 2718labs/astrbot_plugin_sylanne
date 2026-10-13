"""D11 runtime admission for a whole, actually paid contact batch."""
from dataclasses import dataclass
import json

from ..runtime_storage_v3 import read_graph_row_v3
from ..domains.d08.execution import ActionSchema, RequiredCheckRegistry, GoalExecutionProvider
from ..domains.d09.contact_batch_v2 import validate_contact_verified_batch_v2
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest
from .budget import get_budget_lease
from .contact_dispatch_candidate_v2 import contact_dispatch_segment_payload_ref_v2
from .contact_reviewed_content_v1 import read_contact_reviewed_content_original_v1
from .d11_types import RuntimeOutboxValue, job_graph_write, outbox_graph_write
from .dispatch_graph_claim import dispatch_claim_key
from .jobs import get_job


@dataclass(frozen=True, slots=True)
class ContactFinalD11RuntimeV2:
    runtime_admission: object
    candidate_digest: str
    qualification_digest: str
    payload_digest: str
    job_ref: str
    outbox_ref: str


def _value(db, namespace, ref, type_name):
    key = AtomKey.from_token(ref)
    row = read_graph_row_v3(db, columns=('revision', 'value', 'valid'), where='token=? AND bot=? AND persona=?', parameters=(ref, *namespace.as_tuple))
    if key.type_name != type_name or row is None or row[2] != 1:
        raise ValueError('contact current graph material is absent')
    return row[0], json.loads(row[1])


def inspect_contact_final_d11_v2(db, *, bundle, candidate, qualification,
        d11_issuer, now_utc):
    """Join real model settlements, current checks, quote and runtime ledger."""
    if not db.in_transaction:
        raise ValueError('contact D11 admission requires the actual write transaction')
    envelope, ns = bundle.envelope, bundle.envelope.authority.namespace
    identity = envelope.identity
    validators = {s.name: s.validator for s in GoalExecutionProvider().register_types()}
    _, av = _value(db, ns, candidate.action_ref, 'd08.action_intent.v1')
    _, sv = _value(db, ns, candidate.schema_ref, 'd08.action_schema.v1')
    _, gv = _value(db, ns, candidate.grant_ref, 'd08.communication_intent_grant.v1')
    _, bv = _value(db, ns, candidate.batch_ref, 'd09.contact_verified_batch.v2')
    intent, schema, grant = (validators[name](raw) for name, raw in (
        ('d08.action_intent.v1', av), ('d08.action_schema.v1', sv),
        ('d08.communication_intent_grant.v1', gv)))
    from .contact_batch_current_v2 import require_current_contact_batch_v2
    row = db.execute('SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',
        ns.as_tuple).fetchone()
    from ..graph_store import GraphStore
    if row is None:
        raise ValueError('Contact v2 admission lacks actual recovery metadata')
    metadata = GraphStore._decode_recovery(row, ns).requirements
    batch, proof, eligible = require_current_contact_batch_v2(db, namespace=ns,
        batch_ref=candidate.batch_ref, operation_id=identity.operation_id,
        generation=envelope.authority.activation_generation, graph_incarnation=metadata.graph_incarnation)
    if metadata.namespace != ns or metadata.activation_generation != envelope.authority.activation_generation:
        raise ValueError('Contact v2 D11 current recovery generation differs')
    if (proof.qualification.checks != qualification.checks
            or proof.qualification.owner_policy_digest != qualification.owner_policy_digest
            or proof.qualification.route_semantic_digest != qualification.route_semantic_digest):
        raise ValueError('Contact v2 actual SQL proof differs from the freshly issued six providers')
    content = read_contact_reviewed_content_original_v1(db, namespace=ns,
        contact_id=batch.content.contact_id, issuer=d11_issuer,
        resource_issuer=d11_issuer._d02)
    if content != batch.content or content.digest != candidate.reviewed_content_digest:
        raise ValueError('contact admission differs from its two actual paid model calls')
    registry = RequiredCheckRegistry()
    registry.register(ActionSchema(schema.schema_id, schema.action_kind, True, schema.required_checks))
    decision = registry.qualify(intent, qualification.checks, now=now_utc)
    if (decision.status != 'qualified' or len(qualification.checks) != 6
            or decision.receipt_digest != grant.qualification_receipt_digest
            or decision.valid_until != grant.valid_until
            or intent.identity != identity or candidate.operation_id != identity.operation_id
            or candidate.effect_id != identity.effect_id
            or canonical_digest(intent) != candidate.action_digest
            or canonical_digest(schema) != candidate.schema_digest
            or canonical_digest(grant) != candidate.grant_digest
            or batch.digest != candidate.batch_digest):
        raise ValueError('contact final qualification or whole-batch identity changed')
    for v in candidate.content_dependency_versions:
        row = read_graph_row_v3(db, columns=('revision', 'valid'), where='token=? AND bot=? AND persona=?', parameters=(v.key.token, *ns.as_tuple))
        if (v.revision == 0 and row is not None) or (v.revision > 0 and row != (v.revision, 1)):
            raise ValueError('contact whole-content dependency changed')
    if db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',
            ns.as_tuple).fetchone() != (candidate.access_epoch, candidate.delete_epoch):
        raise ValueError('contact source rights changed')
    if db.execute('SELECT 1 FROM graph_atoms WHERE token=?',
            (dispatch_claim_key(ns, identity.effect_id).token,)).fetchone() is not None:
        raise ValueError('contact effect is already claimed')
    quote = d11_issuer._d02.qualified_quote(envelope, db, now_utc=now_utc)
    if (len(bundle.persistent_job_refs) != 1 or len(bundle.outbox_refs) != 1
            or len(bundle.idempotency_keys) != 1 or quote.work_kind != 'message'
            or quote.graph_job_ref != bundle.persistent_job_refs[0]
            or quote.outbox_refs != bundle.outbox_refs or quote.effect_id != identity.effect_id):
        raise ValueError('contact signed message quote changed')
    admission = d11_issuer.admit_runtime(bundle, db, now_utc=now_utc)
    lease = get_budget_lease(db, admission.budget.lease_id)
    reservation = db.execute('SELECT digest,ceiling_json,state FROM runtime_budget_reservations '
        'WHERE lease_id=? AND operation_id=?', (lease.lease_id, identity.operation_id)).fetchone()
    from ..graph_coordinator import budget_operation_digest
    if (not admission.budget.pre_reserved or admission.budget.settle_now
            or admission.budget.lease_id != envelope.parent_budget_lease_ref
            or len(admission.jobs) != 1 or lease.state != 'active'
            or lease.version != admission.budget.expected_version
            or reservation is None or reservation[2] != 'reserved'
            or reservation[0] != budget_operation_digest(envelope, lease.lease_id, dict(quote.ceiling))
            or json.loads(reservation[1]) != dict(quote.ceiling)):
        raise ValueError('contact actual message reservation changed')
    job = get_job(db, AtomKey.from_token(bundle.persistent_job_refs[0]).name)
    _, job_raw = _value(db, ns, bundle.persistent_job_refs[0], 'runtime.job')
    _, outbox_raw = _value(db, ns, bundle.outbox_refs[0], 'runtime.outbox')
    outbox = RuntimeOutboxValue(**outbox_raw)
    if (job != admission.jobs[0].job or job_graph_write(job).value != job_raw
            or outbox_graph_write(outbox, AtomKey.from_token(bundle.persistent_job_refs[0])).value != outbox_raw
            or job.phase != 'waiting' or job.fence != 0
            or job.wake_condition != {'kind': 'contact_host_takeover', 'operation_id': identity.operation_id}
            or outbox.phase != 'pending' or outbox.effect_id != identity.effect_id
            or outbox.payload_ref != contact_dispatch_segment_payload_ref_v2(candidate.batch_ref, candidate.segment_index)
            or outbox.idempotency_key != bundle.idempotency_keys[0]
            or outbox.dispatch_generation != envelope.authority.activation_generation):
        raise ValueError('contact actual job or outbox changed')
    return ContactFinalD11RuntimeV2(admission, candidate.digest, qualification.digest,
        candidate.payload_digest, bundle.persistent_job_refs[0], bundle.outbox_refs[0])
