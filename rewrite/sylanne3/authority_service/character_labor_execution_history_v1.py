"""Control-authenticated, content-free history of real labor execution originals.

The projection preserves previously authenticated signed start/terminal values.
It is never a claim, execution permit, Body permission or budget settlement.
"""
from __future__ import annotations
from dataclasses import dataclass
import json
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..runtime.d11_life_contract_v1 import RoleSegmentStartV1, LifeTerminalPayloadV1, D11LifeClaimV1, D11LifeTerminalV1, life_from_wire_v1, life_to_wire_v1
KIND = 'character_labor_execution_history_v1'
SCHEMA = 'sylanne3.c09.character-labor-execution-history.v1'
FIELDS = frozenset(('schema', 'authority_id', 'installation_id', 'control_store_id', 'namespace', 'execution_id', 'binding_digest', 'basis_ref', 'basis_digest', 'accounting_ref', 'accounting_digest', 'journal_id', 'claim_ref', 'claim_sequence', 'claim_digest', 'claim_payload', 'claim_membership', 'claim_gate', 'terminal_ref', 'terminal_sequence', 'terminal_digest', 'terminal_payload', 'terminal_membership', 'terminal_gate', 'segment_original', 'segment_original_digest', 'd02_closure_digest', 'package_provenance', 'execution_fact_digest', 'execution_binding_digest', 'cpu_closure', 'core_source_digest', 'execution_source_digest', 'maintenance_operation_id', 'scope_digest', 'accepted_receipt_digest', 'facts_pin_digest', 'graph_issue_digest', 'target_core_identity', 'target_storage_instance_id', 'maintenance_generation', 'key_id', 'history_digest', 'signature'))
ENTRY_FIELDS = frozenset(('sequence', 'mutation_id', 'request_digest', 'append_id', 'previous_digest', 'chain_digest', 'payload_sha256', 'payload_bytes', 'row_commitment'))
GATE_FIELDS = frozenset(('permit', 'finish_request_id', 'finish_request_digest', 'row_commitment'))
PACKAGE_FIELDS = frozenset(('manifest_digest', 'executor_installation_id', 'executor_incarnation', 'algorithm_build_digest', 'postcondition_build_digest'))
CPU_FIELDS = frozenset(('kind', 'operation_id', 'original_digest', 'fact_digest', 'budget_receipt_sha256', 'settlement_binding_sha256'))

def _digest(value, *, prefixed=False):
    if prefixed:
        if type(value) is not str or not value.startswith('sha256:'):
            raise AuthorityUnavailable('labor history original digest domain differs')
        value = value[7:]
    if type(value) is not str or len(value) != 64 or any((c not in '0123456789abcdef' for c in value)):
        raise AuthorityUnavailable('labor history authentic complete commitment required')

def _entry(value, *, ref, sequence, chain):
    if type(value) is not dict or set(value) != ENTRY_FIELDS or value['mutation_id'] != ref or (value['sequence'] != sequence) or (value['chain_digest'] != chain) or (type(value['payload_bytes']) is not int) or (value['payload_bytes'] < 1):
        raise AuthorityUnavailable('labor history actual journal membership changed')
    for name in ('request_digest', 'previous_digest', 'chain_digest'):
        _digest(value[name], prefixed=True)
    for name in ('payload_sha256', 'row_commitment'):
        _digest(value[name])

def _gate(value, entry, *, binding, phase):
    from .v2_contract import from_wire, FencePermitV2
    if type(value) is not dict or set(value) != GATE_FIELDS:
        raise AuthorityUnavailable('labor history exact finished Core gate original required')
    permit = from_wire(value['permit'])
    expected_id = 'd11-life-gate:' + phase + ':' + canonical_digest((binding.authority_namespace, binding.installation_id, binding.execution_id))
    if type(permit) is not FencePermitV2 or permit.operation_id != expected_id or permit.authority_id != binding.authority_id or (permit.namespace != binding.authority_namespace) or (permit.subject != 'd11-life:' + binding.installation_id) or (permit.operation != ('write' if phase == 'claim' else 'accounting')) or (permit.generation != binding.activation_generation) or (permit.pinned_anchor.execution_seq != entry['sequence'] - 1) or (permit.pinned_anchor.execution_digest != entry['previous_digest']) or (value['finish_request_id'] != expected_id + ':consumed'):
        raise AuthorityUnavailable('labor history original gate/anchor is not its actual journal predecessor')
    if value['finish_request_digest'] != 'sha256:' + canonical_digest((binding.digest, entry['mutation_id'], entry['chain_digest'])):
        raise AuthorityUnavailable('labor history consumed gate lost its exact original finish commitment')
    _digest(value['finish_request_digest'], prefixed=True)
    _digest(value['row_commitment'])
    return permit

def validate_character_labor_execution_history_v1(control, original, *, namespace, basis, accounting):
    from ..runtime.d11_character_labor_accounting_v1 import _require_accounting
    from ..runtime.c09_paged_capture_contract_v2 import C09CaptureScopeV2
    if type(original) is not dict or set(original) != FIELDS or original['schema'] != SCHEMA or ((original['authority_id'], original['installation_id'], original['control_store_id']) != (control.authority_id, control.installation_id, control.control_store_id)) or (original['namespace'] != namespace):
        raise AuthorityUnavailable('labor execution history differs from actual installed Control/namespace')
    control.verify_original_v1(original, 'history_digest')
    _require_accounting(basis, accounting)
    b = accounting.binding
    if (b.authority_namespace, b.authority_id, b.installation_id, b.execution_id, b.digest) != (namespace, original['authority_id'], original['installation_id'], original['execution_id'], original['binding_digest']) or original['basis_ref'] != 'character-labor-accounting:' + b.execution_id or original['basis_digest'] != canonical_digest(plain_v1(basis)) or (original['accounting_ref'] != basis.accounting_ref) or (original['accounting_digest'] != basis.accounting_digest):
        raise AuthorityUnavailable('labor execution history changed its independent signed B/C accounting basis')
    scope_original = control.read_build_original_v1(operation_id=original['maintenance_operation_id'], kind='capture_scope_v2')
    if scope_original is None:
        raise AuthorityUnavailable('labor history actual signed capture scope is absent')
    scope = C09CaptureScopeV2(**scope_original['details'])
    if (scope.scope_digest, scope.authority_namespace, scope.accepted_receipt_digest, scope.maintenance_generation) != (original['scope_digest'], namespace, original['accepted_receipt_digest'], original['maintenance_generation']):
        raise AuthorityUnavailable('labor execution history capture scope/accepted original changed')
    claim_payload = life_from_wire_v1(original['claim_payload'], RoleSegmentStartV1)
    claim = D11LifeClaimV1(b, claim_payload, original['journal_id'], original['claim_digest'], original['claim_ref'])
    if original['claim_sequence'] != claim.claim_sequence or claim_payload.prepared_digest != basis.prepared_digest:
        raise AuthorityUnavailable('labor history original start differs from its actual C preparation')
    _entry(original['claim_membership'], ref=claim.original_ref, sequence=claim.claim_sequence, chain=claim.claim_digest)
    claim_permit = _gate(original['claim_gate'], original['claim_membership'], binding=b, phase='claim')
    if claim_permit.pinned_anchor.execution_journal_id != original['journal_id']:
        raise AuthorityUnavailable('labor history claim gate belongs to another original journal')
    terminal = None
    terminal_values = tuple((original[name] for name in ('terminal_ref', 'terminal_sequence', 'terminal_digest', 'terminal_payload', 'terminal_membership', 'terminal_gate')))
    if any((value is not None for value in terminal_values)):
        if any((value is None for value in terminal_values)):
            raise AuthorityUnavailable('labor history may not fabricate a partial terminal')
        payload = life_from_wire_v1(original['terminal_payload'], LifeTerminalPayloadV1)
        terminal = D11LifeTerminalV1(b, claim, payload, original['journal_id'], original['terminal_sequence'], original['terminal_digest'], original['terminal_ref'])
        _entry(original['terminal_membership'], ref=terminal.original_ref, sequence=terminal.terminal_sequence, chain=terminal.terminal_digest)
        terminal_permit = _gate(original['terminal_gate'], original['terminal_membership'], binding=b, phase='terminal')
        if terminal_permit.pinned_anchor.execution_journal_id != original['journal_id'] or terminal_permit.command_digest != 'sha256:' + canonical_digest((b.digest, claim.claim_digest)):
            raise AuthorityUnavailable('labor history original terminal gate lost its authentic start')
    package = original['package_provenance']
    if type(package) is not dict or set(package) != PACKAGE_FIELDS or tuple((package[name] for name in ('manifest_digest', 'executor_installation_id', 'executor_incarnation', 'algorithm_build_digest', 'postcondition_build_digest'))) != (b.manifest_digest, claim_payload.executor_installation_id, claim_payload.executor_incarnation, b.algorithm_build_digest, b.postcondition_build_digest):
        raise AuthorityUnavailable('labor history lost the actual registered package/key-selection provenance')
    from ..runtime.clock import _mapping_from_dict
    from decimal import Decimal
    mapping = _mapping_from_dict(json.loads(basis.clock_mapping_json))
    if (claim_payload.clock_mapping_ref, claim_payload.clock_mapping_version) != (mapping.mapping_id, mapping.version) or Decimal(claim_payload.character_at) != mapping.character_at(claim_payload.claimed_at_utc) or (terminal is not None and terminal.payload.character_at is not None and (Decimal(terminal.payload.character_at) != mapping.character_at(terminal.payload.completed_at_utc))):
        raise AuthorityUnavailable('labor history signed duration endpoint differs from its authentic scalar clock')
    closure = original['cpu_closure']
    if type(closure) is not dict or set(closure) != CPU_FIELDS or closure['kind'] not in {'original_adoption_cost', 'original_historical_cost', 'claimed_unconfirmed'} or ((terminal is None) != (closure['kind'] == 'claimed_unconfirmed')):
        raise AuthorityUnavailable('labor history requires the actual CPU closure or still-unconfirmed claim')
    from ..runtime.d11_life_contract_v1 import life_adoption_operation_id_v1
    from .d11_life_historical_accounting_v1 import historical_accounting_operation_id_v1
    expected_operation = life_adoption_operation_id_v1(b) if closure['kind'] == 'original_adoption_cost' else historical_accounting_operation_id_v1(b) if closure['kind'] == 'original_historical_cost' else claim.original_ref
    if closure['operation_id'] != expected_operation or closure['original_digest'] is None:
        raise AuthorityUnavailable('labor history CPU closure lost its actual immutable producer')
    for name in ('original_digest', 'fact_digest'):
        if closure[name] is not None:
            _digest(closure[name])
    for name in ('budget_receipt_sha256', 'settlement_binding_sha256'):
        if terminal is None:
            if closure[name] is not None:
                raise AuthorityUnavailable('active labor cannot invent a terminal CPU settle receipt')
        else:
            _digest(closure[name])
    if terminal is None and closure['fact_digest'] is not None:
        raise AuthorityUnavailable('an active labor interval cannot claim a measured closed CPU fact')
    for name in ('binding_digest', 'basis_digest', 'accounting_digest', 'execution_fact_digest', 'execution_binding_digest', 'core_source_digest', 'execution_source_digest', 'scope_digest', 'accepted_receipt_digest', 'facts_pin_digest', 'graph_issue_digest', 'target_storage_instance_id', 'history_digest'):
        _digest(original[name])
    target = original['target_core_identity']
    if type(target) is not list or len(target) != 2 or any((type(v) is not int or v < 0 for v in target)):
        raise AuthorityUnavailable('labor history actual target Core identity changed')
    segment = None
    if (original['segment_original'] is None) != (original['segment_original_digest'] is None):
        raise AuthorityUnavailable('labor history cannot fabricate a partial retained Segment')
    if original['segment_original'] is not None:
        from ..runtime.d11_character_work_segment_v1 import character_work_segment_from_wire_v1
        from ..runtime.c09_character_labor_originals_v1 import require_character_labor_segment_basis_v1
        segment = character_work_segment_from_wire_v1(original['segment_original'])
        if canonical_digest(plain_v1(segment)) != original['segment_original_digest']:
            raise AuthorityUnavailable('labor history changed the original retained Segment bytes')
        require_character_labor_segment_basis_v1(segment, basis, accounting)
        if (segment.claim_original_ref, segment.claim_sequence, segment.claim_digest, segment.started_at_utc, segment.from_character) != (claim.original_ref, claim.claim_sequence, claim.claim_digest, claim_payload.claimed_at_utc, claim_payload.character_at) or (segment.terminal_original_ref, segment.terminal_sequence, segment.terminal_digest) != ((None, None, None) if terminal is None else (terminal.original_ref, terminal.terminal_sequence, terminal.terminal_digest)) or (terminal is not None and (segment.ended_at_utc, segment.to_character, segment.status) != (terminal.payload.completed_at_utc, terminal.payload.character_at, terminal.status)):
            raise AuthorityUnavailable('labor history Segment lost its actual original signed interval')
    if (segment is None) != (original['d02_closure_digest'] is None):
        raise AuthorityUnavailable('labor history Segment needs its verified original numeric Body membership')
    if original['d02_closure_digest'] is not None:
        _digest(original['d02_closure_digest'])
    return (claim, terminal, segment)

@dataclass(frozen=True, slots=True)
class HistoricalCharacterLaborExecutionV1:
    original: dict
    claim: D11LifeClaimV1
    terminal: D11LifeTerminalV1 | None
    segment: object | None

def require_character_labor_history_ancestor_v1(builder, original, *, meter):
    from .observation_fact_history_v3 import require_frozen_fact_history_ancestor_v3
    require_frozen_fact_history_ancestor_v3(builder, original, meter=meter)

def read_frozen_character_labor_execution_history_v1(builder, basis, accounting, *, meter):
    from .c09_authority_storage_rebase_v2 import _InstalledAuthorityRoleBuilderV2
    if type(builder) is not _InstalledAuthorityRoleBuilderV2 or builder.transform.role != 'core':
        raise AuthorityUnavailable('labor archived execution needs its actual final frozen Core builder')
    builder.require_current()
    schema = meter.read_fixed_row(builder.pair.source, 'sqlite_master', ('sql',), 'type=? AND name=?', ('table', 'authority_c09_originals_archive_v1'))
    if schema is None:
        return None
    from .c09_originals_archive_v1 import ARCHIVE_DDL
    if schema != (ARCHIVE_DDL,):
        raise AuthorityUnavailable('labor frozen archive schema differs')
    row = meter.read_fixed_row(builder.pair.source, 'authority_c09_originals_archive_v1', ('original_digest', 'original_json', 'maintenance_generation'), 'namespace=? AND operation_id=? AND original_kind=?', (builder.scope.authority_namespace, basis.execution_id, KIND))
    if row is None:
        return None
    original = json.loads(row[1])
    claim, terminal, segment = validate_character_labor_execution_history_v1(builder.session._control.maintenance.control, original, namespace=builder.scope.authority_namespace, basis=basis, accounting=accounting)
    if canonical_serialize(original) != row[1] or row[0] != original['history_digest'] or row[2] != original['maintenance_generation']:
        raise AuthorityUnavailable('labor archived original bytes/digest/generation changed')
    require_character_labor_history_ancestor_v1(builder, original, meter=meter)
    builder.require_current()
    return HistoricalCharacterLaborExecutionV1(original, claim, terminal, segment)

def issue_character_labor_execution_history_v1(builder, qualified, *, meter):
    from .c09_character_labor_execution_v1 import _CharacterLaborCoreReverseReadV1
    if type(qualified) is not _CharacterLaborCoreReverseReadV1:
        raise AuthorityUnavailable('actual completed labor Core/journal/source proof required')
    body = qualified.require_archive_body_v1(builder, meter=meter)
    control = builder.session._control.maintenance.control
    meter.require_available(len(canonical_serialize(body).encode('utf-8')) * 4 + 32768)
    original = control.sign_original_v1(SCHEMA, body, 'history_digest')
    validate_character_labor_execution_history_v1(control, original, namespace=builder.scope.authority_namespace, basis=qualified.basis, accounting=qualified.accounting)
    return original

def read_runtime_character_labor_execution_history_v1(service, db, *, binding, permit, basis):
    """Exact selected-Core archive; no Source text or current execution right."""
    from .d11_life_service_v1 import AuthorityD11LifeServiceV1
    from ..runtime_storage_v3 import runtime_storage_v3, runtime_source_identity_v4, runtime_storage_operation_v3
    from .c09_originals_archive_v1 import ARCHIVE_DDL
    from .observation_fact_history_v3 import require_runtime_fact_history_ancestor_v3
    if type(service) is not AuthorityD11LifeServiceV1 or service.bridge.namespace != basis.authority_namespace:
        raise AuthorityUnavailable('actual namespace-bound installed Life historical metadata reader required')
    from .character_labor_census_v1 import require_character_labor_census_segment_context_v1
    facade, work, entry, accounting = require_character_labor_census_segment_context_v1(service, binding=binding, permit=permit, basis=basis)
    if accounting.binding != binding or entry.execution_id != basis.execution_id:
        raise AuthorityUnavailable('labor history left its actual full-Census derived binding')
    handle = runtime_storage_v3(db)
    if handle is None:
        raise AuthorityUnavailable('labor history requires its actual selected bounded Core storage')
    with runtime_storage_operation_v3(db, operation_id='character-labor-history:' + basis.execution_id) as operation:
        with handle.quantum() as meter:
            identity = runtime_source_identity_v4(handle, meter=meter)
            schema = meter.read_fixed_row(db, 'sqlite_master', ('sql',), 'type=? AND name=?', ('table', 'authority_c09_originals_archive_v1'))
            if schema is None:
                return None
            if schema != (ARCHIVE_DDL,):
                raise AuthorityUnavailable('labor history selected archive schema differs')
            row = meter.read_fixed_row(db, 'authority_c09_originals_archive_v1', ('original_digest', 'original_json', 'maintenance_generation'), 'namespace=? AND operation_id=? AND original_kind=?', (basis.authority_namespace, basis.execution_id, KIND))
            if row is None:
                return None
            operation.retain(len(row[1].encode('utf-8')) * 12 + 65536)
            original = json.loads(row[1])
            claim, terminal, segment = validate_character_labor_execution_history_v1(identity.control, original, namespace=basis.authority_namespace, basis=basis, accounting=accounting)
            if row[0] != original['history_digest'] or row[2] != original['maintenance_generation'] or canonical_serialize(original) != row[1]:
                raise AuthorityUnavailable('labor selected archive bytes/digest/generation changed')
            require_runtime_fact_history_ancestor_v3(handle, original, meter=meter)
    return HistoricalCharacterLaborExecutionV1(original, claim, terminal, segment)
