"""D11's transaction-bound natural V2 runtime admission inspection.

This is the narrow bridge from a reviewed natural batch to the existing signed
D02/D11 runtime issuer. It does not issue a dispatch command or a graph effect
claim: those require the coordinator's current Owner, route, journal and P2
fence observations in the same write transaction.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
import sqlite3

from ..authority_service.v2_natural_paid_review_contract import (
    NaturalPaidReviewCurrentReadV2,
)
from ..domains.d08.execution import (
    ActionSchema, ActionSchemaRecord, BASE_REQUIRED_PROVIDERS,
    GoalExecutionProvider,
    RequiredCheckRegistry,
)
from ..domains.d09.natural_batch import (
    NATURAL_BATCH_SCHEMA_V2, NATURAL_BATCH_SCHEMA_V3, rebind_natural_verified_batch_proposal, natural_batch_segment_count,
    validate_natural_verified_batch_value,
)
from ..domains.d09.natural_reply import NaturalFinalActionCandidateV2
from ..graph_types import AtomKey
from ..runtime_contracts import (
    CheckReceipt, DomainBundle, canonical_digest,
)
from .budget import BudgetError, get_budget_lease
from .d11_types import RuntimeOutboxValue, job_graph_write, outbox_graph_write
from .dispatch_candidate import (
    NaturalDispatchCandidateEvidenceV2,
    natural_dispatch_segment_payload_ref_v2,
    validate_natural_dispatch_candidate_writes,
)
from .dispatch_graph_claim import dispatch_claim_key
from .issuers import D11BudgetJobIssuer, IssuerAuthorityDenied
from .jobs import JobConflict, get_job


class NaturalFinalIssuerHold(RuntimeError):
    """Exact missing authority for a natural final D11 inspection."""

    def __init__(self, missing: tuple[str, ...]):
        self.missing = missing
        super().__init__(", ".join(missing))


@dataclass(frozen=True, slots=True)
class NaturalFinalD11RuntimeV2:
    """Signed runtime admission evidence, still awaiting final graph claim."""

    status: str
    runtime_admission: object
    candidate_digest: str
    checks_digest: str
    payload_digest: str
    job_ref: str
    outbox_ref: str
    missing: tuple[str, ...] = (
        "dispatch.natural_v2_owner_route_journal_command_admission",
        "graph.atomic_final_claim",
    )


def _hold(reason: str) -> None:
    raise NaturalFinalIssuerHold((reason,))


def _current_value(db, ref: str, namespace: tuple[str, str],
                   expected_type: str) -> dict:
    key = AtomKey.from_token(ref)
    if (key.type_name != expected_type
            or (key.owner.bot, key.owner.persona) != namespace):
        _hold("natural.current_graph_atom_scope")
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
        "AND bot=? AND persona=?", (ref, *namespace),
    ).fetchone()
    if row is None or row[2] != 1 or row[0] < 1:
        _hold("natural.current_graph_atom_absent")
    return json.loads(row[1])


def inspect_natural_final_d11_v2(
    db, bundle: DomainBundle, candidate: NaturalDispatchCandidateEvidenceV2,
    final: NaturalFinalActionCandidateV2,
    paid_read: NaturalPaidReviewCurrentReadV2,
    checks: tuple[CheckReceipt, ...], *,
    d11_issuer: D11BudgetJobIssuer, now_utc: float,
) -> NaturalFinalD11RuntimeV2:
    """Re-read exact natural graph and signed D11 state under W01's write fence.

    W01 must first verify ``paid_read`` against the original Authority model
    calls and issue ``checks`` with its installed providers from the current
    E+1 graph. This function checks their exact binding and calls the real
    D11 runtime issuer; a returned value is never a send permit.
    """
    if not getattr(db, "in_transaction", False):
        _hold("graph.current_write_transaction")
    if (type(bundle) is not DomainBundle
            or type(candidate) is not NaturalDispatchCandidateEvidenceV2
            or type(final) is not NaturalFinalActionCandidateV2
            or type(paid_read) is not NaturalPaidReviewCurrentReadV2
            or type(checks) is not tuple
            or any(type(check) is not CheckReceipt for check in checks)
            or type(d11_issuer) is not D11BudgetJobIssuer
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        _hold("natural.typed_final_transaction_material")
    envelope = bundle.envelope
    namespace = envelope.authority.namespace
    identity = envelope.identity
    material = final.material
    if (tuple(proposal.domain for proposal in bundle.proposals)
            != ("d08", "d09", "d11")
            or bundle.d02_settlement_refs
            or bundle.d11_cost_settlement_refs
            or len(bundle.idempotency_keys) != 1):
        _hold("natural.final_bundle_scope_changed")
    if (candidate.status != "natural_paid_review_current_hold"
            or final.status != "candidate_hold_w01_final_admission"
            or material is None
            or final.material.paid_receipt != paid_read.paid_receipt
            or paid_read.paid_receipt.verdict != "pass"
            or paid_read.request.namespace != namespace
            or paid_read.expires_at_utc <= now_utc
            or (paid_read.access_epoch, paid_read.delete_epoch)
               != (candidate.access_epoch, candidate.delete_epoch)
            or paid_read.graph_epoch != candidate.query_epoch
            or not set(paid_read.current_read_versions).issubset(
                set(candidate.current_read_versions))
            or (material.final_activity_id, material.final_operation_id,
                material.final_effect_id) != (
                    identity.activity_id, identity.operation_id, identity.effect_id)
            or candidate.operation_id != identity.operation_id
            or candidate.effect_id != identity.effect_id
            or material.payload_digest != candidate.payload_digest
            or material.segment.segment_id != candidate.segment_id
            or material.paid_receipt.parent_budget_lease_id
               != envelope.parent_budget_lease_ref):
        _hold("natural.paid_original_or_final_identity_changed")
    writes = tuple((proposal.domain, write)
                   for proposal in bundle.proposals
                   for write in proposal.typed_writes)
    try:
        rebuilt = validate_natural_dispatch_candidate_writes(
            writes, namespace=namespace, identity=identity,
            read_versions=envelope.version_guard.read_versions,
            source_refs=envelope.source_qualification.source_refs,
            access_epoch=candidate.access_epoch,
            delete_epoch=candidate.delete_epoch,
            query_epoch=candidate.query_epoch,
        )
    except (TypeError, ValueError) as exc:
        raise NaturalFinalIssuerHold(("natural.typed_bundle_candidate_changed",)) from exc
    if rebuilt != candidate:
        _hold("natural.typed_bundle_candidate_changed")
    try:
        action = GoalExecutionProvider().register_types()
        validator = {spec.name: spec.validator for spec in action}
        action_value = _current_value(db, candidate.action_ref,
                                      namespace.as_tuple, "d08.action_intent.v1")
        schema_value = _current_value(db, candidate.schema_ref,
                                      namespace.as_tuple, "d08.action_schema.v1")
        grant_value = _current_value(db, candidate.grant_ref,
                                     namespace.as_tuple,
                                     "d08.communication_intent_grant.v1")
        batch = _current_value(db, candidate.batch_ref,
                               namespace.as_tuple, AtomKey.from_token(candidate.batch_ref).type_name)
        intent = validator["d08.action_intent.v1"](action_value)
        schema_record = validator["d08.action_schema.v1"](schema_value)
        grant = validator["d08.communication_intent_grant.v1"](grant_value)
        validate_natural_verified_batch_value(batch)
        frozen_batch = rebind_natural_verified_batch_proposal(final, grant, batch)
        if (not isinstance(schema_record, ActionSchemaRecord)
                or frozen_batch.write is None
                or frozen_batch.write.key.token != candidate.batch_ref
                or frozen_batch.write.value != batch
                or canonical_digest(intent) != candidate.action_digest
                or canonical_digest(schema_record) != candidate.schema_digest
                or canonical_digest(grant) != candidate.grant_digest
                or batch["batch_digest"] != candidate.batch_digest
                or batch["segment"]["payload_digest"]
                   != candidate.payload_digest
                or batch["paid_review"]["receipt_digest"]
                   != candidate.paid_review_digest
                or batch["paid_review"]["receipt_digest"]
                   != canonical_digest(paid_read.paid_receipt)):
            _hold("natural.current_graph_or_paid_digest_changed")
        paid = asdict(paid_read.paid_receipt)
        if any(batch["paid_review"][key] != paid[key]
               for key in batch["paid_review"] if key != "receipt_digest"):
            _hold("natural.paid_original_fields_changed")
        action_schema = ActionSchema(
            schema_record.schema_id, schema_record.action_kind,
            schema_record.proactive, schema_record.required_checks,
        )
        registry = RequiredCheckRegistry()
        registry.register(action_schema)
        decision = registry.qualify(intent, checks, now=now_utc)
        if (decision.status != "qualified"
                or decision.receipt_digest
                   != grant.qualification_receipt_digest
                or decision.valid_until != grant.valid_until
                or tuple(spec.check_kind for spec in intent.required_checks)
                   != tuple(check.check_kind for check in checks)
                or {(spec.check_kind, spec.provider_id)
                    for spec in intent.required_checks}
                   != set(BASE_REQUIRED_PROVIDERS)
                or len(checks) != 5):
            _hold("natural.five_current_checks_or_grant_changed")
        # Every material read, including the paid review subset, must still
        # be the current SQL head. W01 separately owns negative-query closure.
        for version in candidate.current_read_versions:
            row = db.execute(
                "SELECT revision,valid FROM graph_atoms WHERE token=? "
                "AND bot=? AND persona=?",
                (version.key.token, *namespace.as_tuple),
            ).fetchone()
            if ((version.revision == 0 and row is not None)
                    or (version.revision > 0
                        and row != (version.revision, 1))):
                _hold("natural.current_source_or_access_changed")
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchone()
        if epochs != (candidate.access_epoch, candidate.delete_epoch):
            _hold("natural.current_source_or_access_changed")
        if db.execute(
            "SELECT 1 FROM graph_atoms WHERE token=?",
            (dispatch_claim_key(namespace, identity.effect_id).token,),
        ).fetchone() is not None:
            _hold("graph.effect_already_claimed")
        quote = d11_issuer._d02.qualified_quote(
            envelope, db, now_utc=now_utc)
        if (len(bundle.persistent_job_refs) != 1
                or len(bundle.outbox_refs) != 1
                or quote.work_kind != "message"
                or quote.graph_job_ref != bundle.persistent_job_refs[0]
                or quote.outbox_refs != bundle.outbox_refs
                or quote.effect_id != identity.effect_id):
            _hold("d11.signed_final_quote_or_refs_changed")
        admission = d11_issuer.admit_runtime(bundle, db, now_utc=now_utc)
        if (not admission.budget.pre_reserved
                or admission.budget.settle_now
                or admission.budget.lease_id != envelope.parent_budget_lease_ref
                or len(admission.jobs) != 1
                or admission.jobs[0].graph_job_ref
                   != bundle.persistent_job_refs[0]
                or admission.jobs[0].outbox_refs != bundle.outbox_refs):
            _hold("d11.final_runtime_admission_changed")
        lease = get_budget_lease(db, admission.budget.lease_id)
        reservation = db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (lease.lease_id, identity.operation_id),
        ).fetchone()
        from ..graph_coordinator import budget_operation_digest
        if (reservation is None or reservation[2] != "reserved"
                or reservation[0] != budget_operation_digest(
                    envelope, lease.lease_id, dict(quote.ceiling))
                or json.loads(reservation[1]) != dict(quote.ceiling)
                or lease.state != "active"
                or lease.version != admission.budget.expected_version):
            _hold("d11.current_final_reservation_changed")
        job = get_job(db, AtomKey.from_token(bundle.persistent_job_refs[0]).name)
        job_value = _current_value(db, bundle.persistent_job_refs[0],
                                   namespace.as_tuple, "runtime.job")
        outbox_value = _current_value(db, bundle.outbox_refs[0],
                                      namespace.as_tuple, "runtime.outbox")
        outbox = RuntimeOutboxValue(**outbox_value)
        if (job != admission.jobs[0].job
                or job_graph_write(job).value != job_value
                or outbox_graph_write(outbox,
                        AtomKey.from_token(bundle.persistent_job_refs[0])).value
                   != outbox_value
                or job.phase != "waiting"
                or job.wake_condition != {
                    "kind": "post_c02_reply_host_takeover",
                    "operation_id": identity.operation_id,
                }
                or job.effect_id != identity.effect_id
                or outbox.phase != "pending"
                or outbox.payload_ref != natural_dispatch_segment_payload_ref_v2(
                    candidate.batch_ref, batch["segment"]["position"])
                or outbox.effect_id != identity.effect_id
                or outbox.idempotency_key
                   != bundle.idempotency_keys[0]
                or outbox.dispatch_generation
                   != envelope.authority.activation_generation):
            _hold("d11.current_job_outbox_payload_changed")
    except NaturalFinalIssuerHold:
        raise
    except (IssuerAuthorityDenied, BudgetError, JobConflict, KeyError,
            IndexError, ValueError, TypeError, sqlite3.Error,
            json.JSONDecodeError) as exc:
        raise NaturalFinalIssuerHold((
            "natural.current_signed_admission_unavailable",)) from exc
    return NaturalFinalD11RuntimeV2(
        "admitted_runtime_hold_graph_final_claim", admission, candidate.digest,
        canonical_digest(checks), candidate.payload_digest,
        bundle.persistent_job_refs[0], bundle.outbox_refs[0],
    )


__all__ = [
    "NaturalFinalIssuerHold", "NaturalFinalD11RuntimeV2",
    "inspect_natural_final_d11_v2",
]
