"""Retain actual internal-work reservation obligations when CPU is unknown."""
from __future__ import annotations

import hashlib
import json

from ..runtime_contracts import canonical_digest
from ..runtime_journal import BudgetConstraint, RecoveryConstraintFootprint, ReservationConstraint
from .budget import get_budget_lease
from .c09_storage_rebase_contract_v1 import SanitizedUnknownFactV4


def read_internal_unknown_original_v4(db, *, namespace, authority_namespace,
        binding, prepared, issuer, numeric=False, authored_root=False, body_authority=None, offline_tick=False, life=False):
    if not db.in_transaction:
        raise ValueError("internal unknown requires the installed frozen Graph read")
    if numeric or authored_root:
        execution, generation = binding.execution_id, binding.activation_generation
        if authored_root:
            from .d04_root_execution_v3 import root_execution_ids_v3
            activity = root_execution_ids_v3(namespace, binding.operation_id)["activity"]
        else:
            activity = binding.activity_id
        operation, reserve_digest = binding.reservation_operation_id, binding.reservation_digest
        quote_id, quote_version, quote_digest = binding.quote_id, binding.quote_version, binding.quote_digest
        reserve_json = prepared.reserve_receipt_json
    else:
        execution, activity, generation = binding.execution_id, binding.activity_id, binding.activation_generation
        operation, reserve_digest = prepared.budget_reservation_operation_id, binding.binding_digest
        quote_id, quote_version, quote_digest = binding.resource_quote_ref, binding.resource_quote_version, binding.resource_quote_digest
        reserve_json = None
    quote = issuer.original_signed_quote(db, quote_id, quote_version)
    dimension = "thread_cpu_ms" if authored_root or offline_tick or life else "cpu_ms"
    if (canonical_digest(quote) != quote_digest or set(quote.ceiling) != {dimension}
            or (quote.bot_id, quote.persona_id) != namespace.as_tuple
            or quote.parent_budget_lease_ref != binding.parent_budget_lease_ref):
        raise ValueError("internal unknown original signed CPU quote differs")
    lease = get_budget_lease(db, binding.parent_budget_lease_ref)
    if (lease.bot_id, lease.persona_id) != namespace.as_tuple:
        raise ValueError("internal unknown parent budget crosses namespace")
    reserve = db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (lease.lease_id, operation)).fetchone()
    original = db.execute("SELECT receipt_json,digest,lease_id FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*namespace.as_tuple, operation)).fetchone()
    if (reserve is None or reserve[0] != reserve_digest
            or json.loads(reserve[1]) != dict(quote.ceiling)
            or reserve[2] not in {"reserved", "unknown"} or reserve[3] is not None
            or original is None or original[1:] != (reserve_digest, lease.lease_id)
            or ((numeric or authored_root) and original[0] != reserve_json)
            or (not numeric and not authored_root and hashlib.sha256(original[0].encode()).hexdigest()
                != prepared.budget_reservation_digest)):
        raise ValueError("unknown execution lost its original unmeasured CPU reservation")
    ceiling = quote.ceiling[dimension]
    held = lease.reserved if reserve[2] == "reserved" else lease.unconfirmed
    if held.get(dimension, 0) < ceiling:
        raise ValueError("unknown execution CPU upper bound occupancy was lost")
    reservations = ()
    if not numeric and not authored_root:
        from ..domains.d02 import BodyReservation
        if body_authority is None:
            raise ValueError("installed original body quote reader unavailable")
        body_quote = body_authority.original_body_quote(db, binding.body_quote_ref,
            binding.body_quote_version, quote, binding.operation_id)
        if canonical_digest(body_quote) != binding.body_quote_digest:
            raise ValueError("unknown C04 original signed body quote differs")
        row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (binding.body_reservation_ref,)).fetchone()
        if row is None or row[1] != 1:
            raise ValueError("unknown C04 body reservation original unavailable")
        raw = json.loads(row[0]); raw.pop("schema", None)
        raw["settled_components"] = tuple(raw.get("settled_components", ()))
        body = BodyReservation(**raw)
        if (body.quote_id != binding.body_quote_ref or body.effect_id != quote.effect_id
                or body.status not in {"reserved", "pending_confirmation"}
                or body.settled_components or body.remaining_cost != body.reserved_cost):
            raise ValueError("unknown C04 body occupancy differs from its original component")
        reservations = (ReservationConstraint(binding.body_reservation_ref, binding.component_id,
                                               str(body.remaining_cost)),)
    footprint = RecoveryConstraintFootprint(authority_namespace, activity, execution,
        conflict_keys=("internal-execution:" + execution,), reservations=reservations,
        budgets=(BudgetConstraint(binding.parent_budget_lease_ref, "0", None, str(ceiling)),))
    return SanitizedUnknownFactV4(execution, generation, None, 0,
        ((binding.parent_budget_lease_ref, None, str(ceiling)),), footprint)
