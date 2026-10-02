"""Actual Life Body component joins; CPU cost is never charged twice as Body."""
import json

from ..runtime_contracts import canonical_digest
from .d11_life_contract_v1 import LifeBodyComponentContractV1, WORK_KIND
from .d11_life_terminal_v1 import read_adopted_life_original_v1
from .d11_life_preparation_v1 import TABLE, read_prepared_life_v1
from .d11_life_contract_v1 import life_from_wire_v1, D11LifeTerminalV1
from .d01_production_operations_v1 import MissingProductionOriginalV1, table_exists_v1


def require_life_body_quote_v1(db, *, prepared, issuer, resource_issuer, body_quote_authority):
    raw = prepared.plan.body_effect_request_json
    if raw is None:
        raise MissingProductionOriginalV1("actual_life_body_component_quote")
    contract = LifeBodyComponentContractV1(**json.loads(raw))
    quote = resource_issuer.original_signed_quote(db, contract.resource_quote_ref, contract.resource_quote_version)
    body = body_quote_authority.original_body_quote(db, contract.body_quote_ref, contract.body_quote_version, quote, quote.operation_id)
    b = prepared.binding
    from .d02_life_body_preparation_v1 import require_life_body_preparation_v1
    require_life_body_preparation_v1(db,prepared=prepared,issuer=issuer,resource_issuer=resource_issuer,body_quote_authority=body_quote_authority)
    if (canonical_digest(quote) != contract.resource_quote_digest or canonical_digest(body) != contract.body_quote_digest
            or (quote.bot_id, quote.persona_id, quote.activity_id, quote.operation_id, quote.effect_id) !=
                (*b.namespace.as_tuple, b.activity_id, contract.body_prepare_operation_id, b.effect_id)
            or body.work_kind != WORK_KIND or quote.work_kind != WORK_KIND
            or contract.component_id not in {part.component_id for part in body.components}):
        raise ValueError("Life Body quote/component differs from real execution identity")
    from .domain_production_read_plans_v1 import _committed
    _committed(db,b.namespace,contract.body_prepare_operation_id)
    history=db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND event_id=?",
        (contract.reservation_ref,contract.body_prepare_operation_id)).fetchall()
    if len(history)!=1 or history[0][2]!=1:
        raise MissingProductionOriginalV1("actual_life_body_prepare_reservation_history")
    from ..domains.d02 import _reservation
    original_reservation=_reservation(json.loads(history[0][1]))
    if original_reservation.quote_id!=body.quote_id or original_reservation.effect_id!=b.effect_id:
        raise ValueError("Life Body reservation is not its actual prepare-CAS original")
    component = next(part for part in body.components if part.component_id == contract.component_id)
    if component.duration_rate != 0 or quote.d02_settlement_refs != (contract.settlement_ref,):
        raise ValueError("Life Body component requires its genuine fixed-cost settlement contract")
    return contract, quote, body


def read_life_body_effect_v1(readers, db, read, request):
    if not table_exists_v1(db, TABLE):
        return None
    rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='adopted_life' "
        "AND json_extract(payload_json,'$.terminal.original_ref')=? LIMIT 2",
        (*read.frame.envelope.authority.namespace.as_tuple, request.component_terminal_ref)).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise ValueError("Life terminal has conflicting adopted Body component originals")
    adopted = read_adopted_life_original_v1(db, namespace=read.frame.envelope.authority.namespace, result_ref=rows[0][0], issuer=readers.issuer)
    terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
    if terminal.status != "completed":
        raise MissingProductionOriginalV1("actual_completed_life_body_component")
    prepared = read_prepared_life_v1(db, binding=terminal.binding, issuer=readers.issuer)
    if prepared is None:
        raise MissingProductionOriginalV1("actual_life_body_preparation")
    from .d11_life_fact_provenance_v1 import require_current_life_fact_eligibility_v1
    require_current_life_fact_eligibility_v1(db,prepared=prepared,terminal=terminal,adopted=adopted)
    contract, quote, body = require_life_body_quote_v1(db, prepared=prepared, issuer=readers.issuer,
        resource_issuer=readers.issuer.resource_issuer, body_quote_authority=readers.body_quote_authority)
    if (request.body_quote_ref != contract.body_quote_ref or request.effect_policy_ref != contract.effect_policy_ref
            or request.settlement_operation_ref != adopted["producing_operation_id"]):
        raise ValueError("Life Body request differs from frozen actual component")
    read.committed_operation(db, adopted["producing_operation_id"])
    original = read.original(terminal.original_ref, kind="d11.life_terminal", digest=canonical_digest(terminal))
    from .d02_production_operations_v1 import _reservation
    reservation = _reservation(read.head(db, contract.reservation_ref, required=True).value)
    if reservation.quote_id != body.quote_id or reservation.effect_id != terminal.binding.effect_id:
        raise ValueError("Life actual Body reservation differs")
    profile, state, _ = readers._current_body(db, read, body.profile_id)
    policies = db.execute("SELECT policy_ref,revision,kind,payload_json,payload_digest,signature FROM graph_d02_production_policies_v1 "
        "WHERE bot=? AND persona=? AND policy_ref=? AND kind='effect' ORDER BY revision DESC LIMIT 1",
        (*read.frame.envelope.authority.namespace.as_tuple, contract.effect_policy_ref)).fetchall()
    if not policies:
        raise MissingProductionOriginalV1("installed_life_body_effect_policy")
    policy, policy_original = readers._policy(read, policies[0])
    if (policy.profile_id, policy.work_kind, policy.component_id) != (profile.profile_id, WORK_KIND, contract.component_id):
        raise ValueError("Life actual Body effect policy differs")
    component = next(part for part in body.components if part.component_id == contract.component_id)
    from .d11_types import runtime_cost_settlement_key
    b = terminal.binding
    cost_ref = runtime_cost_settlement_key(*b.namespace.as_tuple, b.activity_id, b.reservation_operation_id).token
    cost = read.settled_cost_original(db, cost_ref, activity_id=b.activity_id, effect_id=b.effect_id,
        operation_id=b.reservation_operation_id)
    settlement = read.head(db, contract.settlement_ref)
    from ..domains.d02.production_operations_v1 import CurrentBodyEffectInputsV1
    return CurrentBodyEffectInputsV1(state, reservation, body, contract.component_id, terminal.original_ref,
        contract.settlement_ref, WORK_KIND, policy.fatigue_increase, policy.load_increase, component.fixed_cost,
        original, policy_original, (cost,), bool(settlement.revision))
