"""C09 facts from real signed life execution and cost originals."""
from __future__ import annotations

import json

from .contract import AuthorityUnavailable
from ..runtime.d11_life_contract_v1 import D11LifeClaimV1, D11LifeTerminalV1
from .d11_life_journal_v1 import ENTRY_PREFIX
from .v2_fence_store import AuthorityV2FenceStore
from ..runtime_contracts import canonical_digest
from ..runtime.c09_storage_rebase_contract_v1 import SanitizedD11FactV4


def _closed_gate(core_db, binding, phase, original):
    gate_id = "d11-life-gate:" + phase + ":" + canonical_digest(
        (binding.authority_namespace, binding.installation_id, binding.execution_id))
    row = AuthorityV2FenceStore._row(core_db, gate_id)
    if row is None:
        raise AuthorityUnavailable("C09 life actual consumed gate absent")
    permit = AuthorityV2FenceStore._permit(row)
    expected = (gate_id + ":consumed", "sha256:" + canonical_digest(
        (binding.digest, original.original_ref,
         original.claim_digest if phase == "claim" else original.terminal_digest)))
    if (permit.namespace != binding.authority_namespace
            or permit.subject != "d11-life:" + binding.installation_id
            or permit.authority_id != binding.authority_id
            or permit.generation != binding.activation_generation
            or permit.operation != ("write" if phase == "claim" else "accounting")
            or row[6] != "finished" or row[8:10] != expected or row[10] is not None):
        raise AuthorityUnavailable("C09 life original consumed gate differs")
    return permit


def _cost_original(business, binding, terminal, service):
    from ..runtime.d11_life_adoption_v1 import _read_signed, verify_life_adoption_commit_v1
    from .d11_life_bridge_v1 import life_bridge_from_wire_v1
    from ..runtime.d11_life_historical_accounting_v1 import (
        _read_signed as read_historical, verify_life_historical_accounting_commit_v1)
    from .d11_life_historical_accounting_v1 import historical_accounting_from_wire_v1
    adopted = _read_signed(business, binding.namespace, "adoption_bridge", binding.execution_id, service.issuer)
    historical = read_historical(business, binding, "historical_accounting_gate", service.issuer)
    if (adopted is None) == (historical is None):
        raise AuthorityUnavailable("C09 life terminal needs one actual signed cost closure")
    if adopted is not None:
        gate = life_bridge_from_wire_v1(adopted[1])
        if gate.binding != binding or gate.terminal != terminal:
            raise AuthorityUnavailable("C09 life adoption crossed terminal original")
        verify_life_adoption_commit_v1(business, gate=gate, issuer=service.issuer,
            resource_issuer=service.resource_issuer, require_current_metadata=False)
    else:
        gate = historical_accounting_from_wire_v1(historical)
        if (gate.binding != binding or gate.terminal_digest != terminal.terminal_digest
                or gate.status != terminal.status or gate.actual_cpu_ms != terminal.actual_cpu_ms):
            raise AuthorityUnavailable("C09 life historical cost crossed terminal original")
        verify_life_historical_accounting_commit_v1(business, gate=gate,
            issuer=service.issuer, resource_issuer=service.resource_issuer)
    row = business.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (binding.parent_budget_lease_ref, binding.reservation_operation_id)).fetchone()
    amount = terminal.actual_cpu_ms
    expected_state = {"unknown"} if amount is None else {"settled", "overrun"}
    if (row is None or row[0] != binding.reservation_digest or row[2] not in expected_state
            or json.loads(row[1]) != {"thread_cpu_ms": binding.cpu_ceiling_ms}
            or (None if row[3] is None else json.loads(row[3])) !=
               (None if amount is None else {"thread_cpu_ms": amount})):
        raise AuthorityUnavailable("C09 life exact reservation and measured CPU differ")
    if amount is None:
        return None
    settlement = binding.reservation_operation_id
    return SanitizedD11FactV4(settlement, binding.parent_budget_lease_ref,
        binding.reservation_operation_id, binding.cpu_ceiling_ms, amount, amount, 0,
        max(0, amount - binding.cpu_ceiling_ms), "thread_cpu_ms")


def read_life_recovery_originals_v1(*, business, core_db, journal, rows, service, namespace):
    from .d11_life_service_v1 import AuthorityD11LifeServiceV1
    from ..runtime.d11_life_accounting_v1 import read_life_accounting_prepared_v1
    from .c09_installed_original_verifiers_v1 import InstalledC09OriginalVerifierV1
    if not business.in_transaction or not core_db.in_transaction:
        raise AuthorityUnavailable("C09 life facts need pinned actual snapshots")
    originals = {}
    for row in rows:
        if not row[4].startswith(ENTRY_PREFIX):
            continue
        if (type(service) not in {AuthorityD11LifeServiceV1, InstalledC09OriginalVerifierV1}
                or (type(service) is InstalledC09OriginalVerifierV1 and service.kind != "life")):
            raise AuthorityUnavailable("C09 actual installed life verifier absent")
        binding, claim_payload, terminal_payload = service.verify_life_journal_row_v1(journal, row)
        prepared = read_life_accounting_prepared_v1(business, binding=binding,
            issuer=service.issuer, resource_issuer=service.resource_issuer)
        if (binding.authority_namespace != namespace or prepared is None
                or prepared.prepared_digest != claim_payload.prepared_digest):
            raise AuthorityUnavailable("C09 life signed accounting preparation differs")
        prior = originals.get(binding.execution_id)
        if terminal_payload is None:
            if prior is not None:
                raise AuthorityUnavailable("C09 life duplicate consuming claim")
            claim = D11LifeClaimV1(binding, claim_payload, journal.journal_id, row[6], row[1])
            _closed_gate(core_db, binding, "claim", claim)
            originals[binding.execution_id] = (binding, claim, None, prepared, None)
        else:
            if prior is None or prior[0] != binding or prior[1].payload != claim_payload or prior[2] is not None:
                raise AuthorityUnavailable("C09 life terminal has no exact earlier claim")
            terminal = D11LifeTerminalV1(binding, prior[1], terminal_payload,
                journal.journal_id, row[0], row[6], row[1])
            permit = _closed_gate(core_db, binding, "terminal", terminal)
            if permit.command_digest != "sha256:" + canonical_digest((binding.digest, prior[1].claim_digest)):
                raise AuthorityUnavailable("C09 life terminal gate crossed its claim")
            originals[binding.execution_id] = (binding, prior[1], terminal, prepared,
                _cost_original(business, binding, terminal, service))
    return tuple(originals[key] for key in sorted(originals))
