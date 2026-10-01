"""Inspect C04 fixed-body originals before a separate cost transaction.

The Authority terminal currently authenticates a terminal row but has no
independent proof that the named body component completed. Therefore this
module cannot yet authorize the three D02 graph writes.
"""

from __future__ import annotations

from dataclasses import dataclass
import sqlite3

from ...authority_service.internal_work_contract import InternalWorkTerminalProofV1
from ...authority_service.internal_work_service import (
    AuthorityInternalWorkVerifiedReceiptV1,
)
from ...graph_types import AtomKey
from ...runtime.c04_internal_work_original_v1 import C04InternalWorkPreparedV1
from ...runtime.issuers import D02ResourceIssuer, ResourceOutcome, ResourceQuote
from ...runtime_contracts import CommandEnvelope
from . import BodyDomain, BodyQuote, BodyReservation, BodyState
from .body_quote_original import BodyQuoteUnavailable, D02BodyQuoteAuthority
from .resource_outcome_verifier import candidate_outcome_from_verified_terminal


@dataclass(frozen=True)
class FixedComponentOriginalsV1:
    """Consistent original values; this is not completion authority."""

    body_quote: BodyQuote
    state: BodyState
    reservation: BodyReservation
    component_id: str
    fixed_cost: float
    settlement_ref: str
    provider_receipt_ref: str


def inspect_fixed_component_originals(
    db: sqlite3.Connection,
    issuer: D02ResourceIssuer,
    body_quote_authority: D02BodyQuoteAuthority,
    envelope: CommandEnvelope,
    resource_quote: ResourceQuote,
    outcome: ResourceOutcome,
    body_quote_id: str,
    body_quote_version: int,
    state: BodyState,
    reservation: BodyReservation,
    component_id: str,
    *,
    verified: AuthorityInternalWorkVerifiedReceiptV1,
    proof: InternalWorkTerminalProofV1,
    prepared: C04InternalWorkPreparedV1,
) -> FixedComponentOriginalsV1:
    """Check signed originals and typed terminal identity without charging."""
    if (not isinstance(db, sqlite3.Connection) or not db.in_transaction
            or type(issuer) is not D02ResourceIssuer
            or type(body_quote_authority) is not D02BodyQuoteAuthority
            or type(envelope) is not CommandEnvelope
            or type(resource_quote) is not ResourceQuote
            or type(outcome) is not ResourceOutcome
            or type(body_quote_id) is not str or not body_quote_id
            or type(body_quote_version) is not int or body_quote_version < 1
            or type(state) is not BodyState
            or type(reservation) is not BodyReservation
            or type(component_id) is not str or not component_id):
        raise BodyQuoteUnavailable("typed C04 originals and transaction required")
    namespace = envelope.authority.namespace
    identity = envelope.identity
    binding = prepared.binding if type(prepared) is C04InternalWorkPreparedV1 else None
    if (candidate_outcome_from_verified_terminal(
            verified, proof, prepared, resource_quote, envelope) != outcome
            or binding is None
            or binding.body_quote_ref != body_quote_id
            or binding.body_quote_version != body_quote_version
            or binding.body_reservation_ref != BodyDomain.reservation_write(
                namespace, identity.activity_id, reservation).key.token
            or binding.component_id != component_id):
        raise BodyQuoteUnavailable("C04 terminal and body original differ")
    body_quote = body_quote_authority.original_body_quote(
        db, body_quote_id, body_quote_version, resource_quote,
        identity.operation_id,
    )
    if (namespace.as_tuple != (resource_quote.bot_id, resource_quote.persona_id)
            or identity.activity_id != resource_quote.activity_id
            or identity.operation_id != resource_quote.operation_id
            or identity.effect_id != resource_quote.effect_id
            or body_quote.activity_id != identity.activity_id
            or body_quote.work_kind != resource_quote.work_kind
            or body_quote.profile_id != state.profile_id
            or body_quote.state_version > state.version
            or reservation.quote_id != body_quote.quote_id
            or (resource_quote.effect_id is not None
                and reservation.effect_id != resource_quote.effect_id)
            or outcome.actual is None):
        raise BodyQuoteUnavailable("measured C04 body/resource identity differs")
    if issuer.original_signed_quote(db, resource_quote.quote_id,
                                    resource_quote.version) != resource_quote:
        raise BodyQuoteUnavailable("original signed resource quote differs")
    if issuer.qualified_outcome(resource_quote, db) != outcome:
        raise BodyQuoteUnavailable("original signed outcome differs")
    if len(resource_quote.d02_settlement_refs) != 1:
        raise BodyQuoteUnavailable("one D02 settlement ref is required")
    settlement_ref = resource_quote.d02_settlement_refs[0]
    settlement_key = AtomKey.from_token(settlement_ref)
    if (settlement_key.type_name != "d02.settlement.v1"
            or settlement_key.owner.kind != "activity"
            or (settlement_key.owner.bot, settlement_key.owner.persona,
                settlement_key.owner.subject) != (
                    namespace.bot_id, namespace.persona_id, identity.activity_id)):
        raise BodyQuoteUnavailable("D02 settlement ref differs from C04 activity")
    components = tuple(item for item in body_quote.components
                       if item.component_id == component_id)
    if len(components) != 1 or components[0].duration_rate != 0:
        raise BodyQuoteUnavailable("original fixed body component is required")
    guarded = {item.key: item.revision
               for item in envelope.version_guard.read_versions}
    state_key = BodyDomain.state_write(namespace, state).key
    reservation_key = BodyDomain.reservation_write(
        namespace, identity.activity_id, reservation,
    ).key
    if (guarded.get(state_key) != state.version
            or reservation_key not in guarded):
        raise BodyQuoteUnavailable("current D02 state and reservation must be guarded")
    if any(item.split("|", 1)[0] == component_id
           for item in reservation.settled_components):
        raise BodyQuoteUnavailable("body component is already settled")
    return FixedComponentOriginalsV1(
        body_quote, state, reservation, component_id,
        components[0].fixed_cost, settlement_ref,
        outcome.provider_receipt_ref,
    )


def build_measured_fixed_component_settlement(*args, **kwargs):
    """HOLD until Authority authenticates named component completion.

    The previous implementation charged fixed_cost on a receipt reference
    alone. An authenticated, original component-completion fact must be added
    before D02 may produce body state/reservation/settlement writes.
    """
    raise BodyQuoteUnavailable(
        "trusted Authority component completion receipt is unavailable")
