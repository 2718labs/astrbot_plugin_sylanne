"""D02's fixed body charge for a completed historical C04 execution.

The caller commits these three writes in one graph transaction before C04
adoption. The fixed BodyQuote is the only body price; measured CPU is D11's
separate base-unit cost and never becomes body energy.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import sqlite3

from ...authority_service.internal_work_contract import (
    InternalWorkTerminalProofV1, InternalWorkTerminalV2,
)
from ...graph_types import AtomKey, GraphWrite
from ...runtime.c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from ...runtime.d11_c04_internal_cost import read_c04_cpu_cost_original_v1
from ...runtime.issuers import D02ResourceIssuer, ResourceOutcome
from ...runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from . import BodyDomain, BodyReservation, BodyState
from .body_quote_original import BodyQuoteUnavailable, D02BodyQuoteAuthority
from .resource_outcome_verifier import install_resource_outcome_evidence_schema


@dataclass(frozen=True, slots=True)
class C04FixedComponentCostV1:
    writes: tuple[GraphWrite, GraphWrite, GraphWrite]
    settlement_ref: str
    component_receipt_ref: str
    actual_fixed_cost: float
    outcome: ResourceOutcome


@dataclass(frozen=True, slots=True)
class C04BodyCostOriginalV1:
    namespace: NamespaceId
    operation_id: str
    binding_digest: str
    proof_digest: str
    state_ref: str
    reservation_ref: str
    settlement_ref: str
    component_receipt_ref: str
    fixed_cost: float
    writes_digest: str
    outcome_id: str


def install_d02_c04_body_cost_schema(db: sqlite3.Connection) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS d02_c04_body_cost_originals_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        original_json TEXT NOT NULL, original_digest TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id))""")
    for operation in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS
            d02_c04_body_cost_originals_v1_{operation.lower()}_immutable
            BEFORE {operation} ON d02_c04_body_cost_originals_v1
            BEGIN SELECT RAISE(ABORT, 'C04 body cost original is immutable'); END""")


def read_c04_body_cost_original_v1(
    db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
) -> C04BodyCostOriginalV1 | None:
    if db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='d02_c04_body_cost_originals_v1'",
    ).fetchone() is None:
        return None
    row = db.execute(
        "SELECT original_json,original_digest FROM d02_c04_body_cost_originals_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id),
    ).fetchone()
    if row is None:
        return None
    raw = json.loads(row[0])
    if (type(raw) is not dict or set(raw) != set(C04BodyCostOriginalV1.__dataclass_fields__)
            or canonical_serialize(raw) != row[0] or type(raw.get("namespace")) is not dict
            or set(raw["namespace"]) != {"bot_id", "persona_id"}):
        raise BodyQuoteUnavailable("C04 body cost original fields changed")
    raw["namespace"] = NamespaceId(**raw["namespace"])
    original = C04BodyCostOriginalV1(**raw)
    # Preserve exact existing local-import and historical-import commitments.
    if row[1] not in {canonical_digest(asdict(original)), canonical_digest(original)}:
        raise BodyQuoteUnavailable("C04 body cost original changed")
    if original.namespace != namespace or original.operation_id != operation_id:
        raise BodyQuoteUnavailable("C04 body cost identity changed")
    return original


def record_committed_c04_body_cost_v1(
    db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
    proof: InternalWorkTerminalProofV1, staged: C04FixedComponentCostV1,
) -> C04BodyCostOriginalV1:
    """W01 invokes this after its three-write graph CAS, in that transaction."""
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(namespace) is not NamespaceId
            or type(proof) is not InternalWorkTerminalProofV1
            or type(staged) is not C04FixedComponentCostV1):
        raise BodyQuoteUnavailable("committed C04 body graph transaction required")
    prepared = read_c04_internal_work_prepared_v1(db, namespace, operation_id)
    if prepared is None or prepared.binding != proof.binding:
        raise BodyQuoteUnavailable("original C04 preparation differs")
    expected_revisions = (prepared.body_state_revision + 1,
                          prepared.body_reservation_revision + 1, 1)
    for write, revision in zip(staged.writes, expected_revisions, strict=True):
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (write.key.token,),
        ).fetchone()
        if (row is None or row[0] != revision or row[2] != 1
                or json.loads(row[1]) != write.value):
            raise BodyQuoteUnavailable("C04 body graph write did not commit")
    binding = proof.binding
    if (binding.operation_id != operation_id
            or staged.settlement_ref != staged.writes[2].key.token
            or staged.component_receipt_ref !=
            proof.terminal.component_receipt_ref):
        raise BodyQuoteUnavailable("C04 body cost proof differs")
    original = C04BodyCostOriginalV1(
        namespace, operation_id, binding.binding_digest,
        canonical_digest(proof), staged.writes[0].key.token,
        staged.writes[1].key.token, staged.writes[2].key.token,
        staged.component_receipt_ref, staged.actual_fixed_cost,
        canonical_digest(staged.writes), staged.outcome.outcome_id,
    )
    install_d02_c04_body_cost_schema(db)
    prior = read_c04_body_cost_original_v1(db, namespace, operation_id)
    if prior is not None and prior != original:
        raise BodyQuoteUnavailable("replayed C04 body cost differs")
    if prior is None:
        encoded = canonical_serialize(asdict(original))
        db.execute("INSERT INTO d02_c04_body_cost_originals_v1 VALUES(?,?,?,?,?)",
                   (*namespace.as_tuple, operation_id, encoded,
                    canonical_digest(asdict(original))))
    return original


def stage_c04_fixed_component_cost_v1(
    db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
    proof: InternalWorkTerminalProofV1,
    issuer: D02ResourceIssuer, body_authority: D02BodyQuoteAuthority,
    state: BodyState, reservation: BodyReservation,
) -> C04FixedComponentCostV1:
    """Sign the original outcome and produce exactly three D02 graph writes.

    W01 owns the open graph transaction and rechecks all current graph heads
    before committing. No write is emitted for a failed or unknown execution.
    """
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(namespace) is not NamespaceId
            or type(proof) is not InternalWorkTerminalProofV1
            or type(issuer) is not D02ResourceIssuer
            or type(body_authority) is not D02BodyQuoteAuthority
            or type(state) is not BodyState
            or type(reservation) is not BodyReservation):
        raise BodyQuoteUnavailable("typed C04 body settlement transaction required")
    terminal = proof.terminal
    if type(terminal) is not InternalWorkTerminalV2 or terminal.status != "completed":
        raise BodyQuoteUnavailable("completed installed terminal required")
    prepared = read_c04_internal_work_prepared_v1(db, namespace, operation_id)
    cpu_cost = read_c04_cpu_cost_original_v1(db, namespace, operation_id)
    if prepared is None or cpu_cost is None or prepared.binding != proof.binding:
        raise BodyQuoteUnavailable("prepared and settled C04 originals required")
    binding = prepared.binding
    if (cpu_cost.binding_digest != binding.binding_digest
            or cpu_cost.prepared_digest != prepared.prepared_digest
            or cpu_cost.proof_digest != canonical_digest(proof)
            or cpu_cost.terminal_receipt_ref != proof.terminal_receipt_ref
            or cpu_cost.terminal_receipt_digest != proof.terminal_receipt_digest
            or cpu_cost.status != "completed" or not cpu_cost.component_completed
            or cpu_cost.actual_cpu_ms != terminal.actual_cpu_ms
            or cpu_cost.budget_receipt_status not in {"settled", "overrun"}
            or terminal.component_receipt_ref !=
            "internal-work:component:" + binding.binding_digest):
        raise BodyQuoteUnavailable("authenticated component completion differs")
    quote = issuer.original_signed_quote(
        db, binding.resource_quote_ref, binding.resource_quote_version)
    if canonical_digest(quote) != binding.resource_quote_digest:
        raise BodyQuoteUnavailable("original signed resource quote differs")
    body_quote = body_authority.original_body_quote(
        db, binding.body_quote_ref, binding.body_quote_version,
        quote, operation_id,
    )
    if (canonical_digest(body_quote) != binding.body_quote_digest
            or (quote.bot_id, quote.persona_id, quote.activity_id,
                quote.operation_id) != (*namespace.as_tuple,
                                        binding.activity_id, operation_id)
            or body_quote.activity_id != binding.activity_id
            or body_quote.profile_id != state.profile_id
            or prepared.body_state_revision != state.version
            or reservation.quote_id != body_quote.quote_id
            or reservation.effect_id != quote.effect_id
            or body_quote.state_version > state.version):
        raise BodyQuoteUnavailable("original body reservation differs")
    reservation_key = BodyDomain.reservation_write(
        namespace, binding.activity_id, reservation,
    ).key
    if (reservation_key.token != binding.body_reservation_ref
            or not any(token == reservation_key.token and
                       revision == prepared.body_reservation_revision
                       for token, revision in prepared.read_versions)):
        raise BodyQuoteUnavailable("prepared reservation head differs")
    components = tuple(part for part in body_quote.components
                       if part.component_id == binding.component_id)
    if len(components) != 1 or components[0].duration_rate != 0:
        raise BodyQuoteUnavailable("one original fixed component required")
    component = components[0]
    settlement = BodyDomain().settle_component(
        state, reservation, component.component_id,
        actual_cost=component.fixed_cost,
        component_receipt=terminal.component_receipt_ref,
    )
    if settlement.duplicate or settlement.overrun or settlement.unpaid_cost:
        raise BodyQuoteUnavailable("body settlement cannot be fully represented")
    refs = quote.d02_settlement_refs
    if len(refs) != 1:
        raise BodyQuoteUnavailable("one original D02 settlement ref required")
    settlement_key = AtomKey.from_token(refs[0])
    expected = BodyDomain.settlement_write(
        namespace, binding.activity_id, settlement_key.name, settlement,
    )
    if expected.key != settlement_key:
        raise BodyQuoteUnavailable("D02 settlement key differs")
    writes = (
        BodyDomain.state_write(namespace, settlement.state),
        BodyDomain.reservation_write(namespace, binding.activity_id,
                                     settlement.reservation),
        expected,
    )
    outcome = ResourceOutcome(
        "internal-work-outcome:" + binding.execution_id, 1,
        quote.quote_id, quote.bot_id, quote.persona_id,
        quote.activity_id, quote.operation_id,
        ({"cpu_ms": terminal.actual_cpu_ms}
         if terminal.actual_cpu_ms else {}), True,
        proof.terminal_receipt_ref,
    )
    install_resource_outcome_evidence_schema(db)
    quote_json = canonical_serialize(asdict(quote))
    quote_digest = hashlib.sha256(quote_json.encode("utf-8")).hexdigest()
    actual_json = canonical_serialize({"cpu_ms": terminal.actual_cpu_ms})
    actual_digest = hashlib.sha256(actual_json.encode("utf-8")).hexdigest()
    identity = (quote.quote_id, operation_id, proof.terminal_receipt_ref)
    owner = (quote.bot_id, quote.persona_id, quote.activity_id, quote_digest)
    actual_row = (*owner, actual_json)
    receipt_row = (*owner, actual_digest, "completed", 1)
    existing_actual = db.execute(
        "SELECT bot_id,persona_id,activity_id,quote_digest,actual_json "
        "FROM d02_resource_actuals_v1 WHERE quote_id=? AND operation_id=? "
        "AND provider_receipt_ref=?", identity,
    ).fetchone()
    existing_receipt = db.execute(
        "SELECT bot_id,persona_id,activity_id,quote_digest,actual_digest,"
        "state,execution_revoked FROM d02_resource_execution_receipts_v1 "
        "WHERE quote_id=? AND operation_id=? AND provider_receipt_ref=?",
        identity,
    ).fetchone()
    if ((existing_actual is not None and existing_actual != actual_row)
            or (existing_receipt is not None and
                existing_receipt != receipt_row)):
        raise BodyQuoteUnavailable("resource execution evidence replay differs")
    if existing_actual is None:
        db.execute("INSERT INTO d02_resource_actuals_v1 VALUES(?,?,?,?,?,?,?,?)",
                   (*identity, *actual_row))
    if existing_receipt is None:
        db.execute("INSERT INTO d02_resource_execution_receipts_v1 "
                   "VALUES(?,?,?,?,?,?,?,?,?,?)", (*identity, *receipt_row))
    issuer.issue_outcome(db, outcome)
    if issuer.qualified_outcome(quote, db) != outcome:
        raise BodyQuoteUnavailable("signed C04 outcome differs")
    return C04FixedComponentCostV1(
        writes, refs[0], terminal.component_receipt_ref,
        component.fixed_cost, outcome,
    )
