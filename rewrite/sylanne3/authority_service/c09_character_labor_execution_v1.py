"""Bounded complete labor Core/execution proof and independent cold replay."""
from hashlib import sha256
from weakref import WeakSet
import json
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..runtime.c09_paged_sql_v2 import C09PagedCaptureHold
from .c09_character_labor_history_v1 import basis_binding_v1, require_character_labor_cpu_closure_v1, require_character_labor_membership_history_v1
_LABOR_SOURCES = WeakSet()
_LABOR_SOURCE_TOKEN = object()
_LABOR_REVERSE = WeakSet()
_LABOR_REVERSE_TOKEN = object()

class _LaborFrozenSourcesV1:

    def __init__(self, token, session, graph_pair, core_pair, execution_pair, meter, connections):
        from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
        from .c09_role_capture_pair_v2 import InstalledC09RolePairV2
        from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
        if token is not _LABOR_SOURCE_TOKEN or type(session) is not C09PagedCaptureSessionV2:
            raise C09PagedCaptureHold('actual labor frozen sources issuer required')
        pairs = (graph_pair, core_pair, execution_pair)
        if any((type(p) is not InstalledC09RolePairV2 or p._producer.session is not session or p.source_original.scope_digest != session.scope.scope_digest or (p.source_original.role != role) for p, role in zip(pairs, ('graph', 'core', 'execution'), strict=True))):
            raise C09PagedCaptureHold('labor originals need all actual same-scope frozen role pairs')
        if any((type(db) is not _BoundedReadConnectionV2 or db.db is not pair.source or (not db.in_transaction) or (db._character_labor_source_v1 is not None) for db, pair in zip(connections, pairs, strict=True))):
            raise C09PagedCaptureHold('labor original readers are not their actual frozen sources')
        self.session, self.pairs, self.meter, self.connections = (session, pairs, meter, connections)
        self.rows = []
        self.values = []
        self.decode_peak = 0
        _LABOR_SOURCES.add(self)
        session._source_parser_arena_v3.add(self)
        for db in connections:
            db._character_labor_source_v1 = self

    def _source_heap_bytes(self):
        from ..runtime.c09_logical_source_v3 import _retained_size
        return 8192 + max(_retained_size((self.rows, self.values), set()), self.decode_peak)

    def require_current(self, db):
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        if self not in _LABOR_SOURCES or db not in self.connections or db._character_labor_source_v1 is not self or (current_c09_sql_meter_v2() is not self.meter):
            raise C09PagedCaptureHold('labor originals left their registered source quantum')
        self.session.require_current()
        for pair in self.pairs:
            pair.require_current()

    def close(self):
        for db in self.connections:
            db._character_labor_source_v1 = None
        self.rows.clear()
        self.values.clear()
        _LABOR_SOURCES.discard(self)

def preflight_character_labor_native_v1(db, size):
    source = db._character_labor_source_v1
    if type(source) is not _LaborFrozenSourcesV1:
        raise C09PagedCaptureHold('actual private labor native source required')
    source.require_current(db)
    source.session._control.require_c09_retained_arena_v3(meter=source.meter, additional_bytes=size * 12 + 32768)

def retain_character_labor_native_v1(db, row, size):
    source = db._character_labor_source_v1
    if type(source) is not _LaborFrozenSourcesV1:
        raise C09PagedCaptureHold('actual private labor native source required')
    source.require_current(db)
    source.rows.append(row)
    source.decode_peak += size * 12
    source.session._control.require_c09_retained_arena_v3(meter=source.meter)

class _CharacterLaborCoreReverseReadV1:
    """Whole Graph basis/Segment census against real final Core/execution sources."""

    def __init__(self, token, builder, *, production):
        from .c09_authority_storage_rebase_v2 import _InstalledAuthorityRoleBuilderV2
        if token is not _LABOR_REVERSE_TOKEN or type(builder) is not _InstalledAuthorityRoleBuilderV2 or builder.transform.role != 'core' or (type(production) is not bool):
            raise C09PagedCaptureHold('actual final labor Core producer required')
        builder.require_current()
        self.builder = builder
        self.graph = builder.session.require_actual_post_mirror_graph_v3()
        self.graph.require_current()
        self.production = production
        self.after = None
        self.phase = 'basis'
        self.complete = False
        self.count = 0
        self.basis = None
        self.accounting = None
        self.archive_body = None
        self.member_identity = None
        self.membership_task = None
        self.membership_checked = False
        self.terminal_task = None
        self.binding_task = None
        self.root = canonical_digest(('sylanne3.c09.character-labor-final.v1', builder.scope.scope_digest, builder.pair.source_original.role_source_digest, self.graph.pair.source_original.role_source_digest))
        _LABOR_REVERSE.add(self)
        builder.session._control.maintenance.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        from ..runtime.c09_logical_source_v3 import _retained_size
        return 8192 + _retained_size((self.after, self.member_identity, self.basis, self.accounting, self.archive_body), set())

    def require_complete(self, builder):
        if self not in _LABOR_REVERSE or self.builder is not builder or (not self.complete):
            raise C09PagedCaptureHold('actual complete labor Graph/Core reverse census required')
        builder.require_current()
        self.graph.require_current()
        return (self.root, self.count)

    def require_archive_body_v1(self, builder, *, meter):
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        if self not in _LABOR_REVERSE or self.builder is not builder or self.archive_body is None or (current_c09_sql_meter_v2() is not meter) or (not self.production):
            raise C09PagedCaptureHold('archive issuance needs this actual verified labor source member')
        builder.require_current()
        self.graph.require_current()
        return self.archive_body

    def _entry(self, row):
        from .c09_paged_recovery_facts_v2 import _journal_commitment
        return dict(sequence=row[0], mutation_id=row[1], request_digest=row[2], append_id=row[3], previous_digest=row[5], chain_digest=row[6], payload_sha256=sha256(row[4]).hexdigest(), payload_bytes=len(row[4]), row_commitment=_journal_commitment(row))

    def _gate(self, core, binding, phase, original):
        from .c09_life_recovery_originals_v1 import _closed_gate
        from .v2_fence_store import AuthorityV2FenceStore
        from .v2_contract import to_wire
        permit = _closed_gate(core, binding, phase, original)
        row = AuthorityV2FenceStore._row(core, permit.operation_id)
        return dict(permit=to_wire(permit), finish_request_id=row[8], finish_request_digest=row[9], row_commitment=canonical_digest(('authority_v2_fences', ('operation_id', 'namespace', 'subject', 'token', 'fence_epoch', 'revision', 'state', 'permit', 'finish_request_id', 'finish_request_digest', 'pending'), row)))

    def _qualify(self, graph, core, execution, meter):
        from dataclasses import replace
        from ..runtime.d11_character_labor_accounting_v1 import KIND as BASIS_KIND, _signed, read_character_labor_accounting_prepared_v1
        from ..runtime.d11_life_contract_v1 import D11LifeClaimV1, D11LifeTerminalV1, life_to_wire_v1
        from ..runtime.d11_character_work_segment_v1 import character_work_segment_from_wire_v1
        from ..runtime.c09_character_labor_originals_v1 import require_character_labor_segment_basis_v1
        from ..runtime.c09_storage_rebase_contract_v1 import SanitizedExecutionFactV4
        from .c09_execution_connection_v1 import C09ExecutionOriginalsConnectionV1
        from .c09_paged_recovery_facts_v2 import _journal_commitment
        from .character_labor_execution_history_v1 import read_frozen_character_labor_execution_history_v1
        builder = self.builder
        session = builder.session
        facts = builder.transform.facts
        facts.require_complete(scope_digest=builder.scope.scope_digest, facts_pin_digest=facts._completion.pin_digest)
        ns = NamespaceId(*json.loads(builder.scope.graph_namespace))
        issuer = session.get_c09_domain_original_issuer_v2()
        if self.phase == 'basis':
            saved = _signed(graph, ns, BASIS_KIND, self.member_identity[1], issuer)
            from ..runtime.d11_character_labor_accounting_v1 import character_labor_accounting_basis_from_wire_v1
            basis = character_labor_accounting_basis_from_wire_v1(saved[0])
        else:
            saved = _signed(graph, ns, 'character_work_segment_v1', self.member_identity[1], issuer)
            segment = character_work_segment_from_wire_v1(saved[0])
            found = _signed(graph, ns, BASIS_KIND, 'character-labor-accounting:' + segment.execution_id, issuer)
            if found is None:
                raise C09PagedCaptureHold('orphan labor Segment has no independent accounting basis')
            from ..runtime.d11_character_labor_accounting_v1 import character_labor_accounting_basis_from_wire_v1
            basis = character_labor_accounting_basis_from_wire_v1(found[0])
        binding = basis_binding_v1(graph, basis, issuer)
        authentic = read_character_labor_accounting_prepared_v1(graph, binding=binding, issuer=issuer, resource_issuer=issuer.resource_issuer)
        if authentic is None or authentic[0] != basis:
            raise C09PagedCaptureHold('labor final census lost its authentic B/C accounting chain')
        self.basis, self.accounting = authentic
        accounting = self.accounting
        archived = read_frozen_character_labor_execution_history_v1(builder, basis, accounting, meter=meter)
        fact = facts.lookup_execution(binding.execution_id, meter=meter)
        source_binding = facts.lookup_execution_binding(binding.execution_id, meter=meter)
        from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
        indices = _BoundedReadConnectionV2(facts._db, meter).execute('SELECT seq,row_commitment FROM c09_recovery_journal_index_v2 WHERE scope_digest=? AND execution_id=? ORDER BY seq LIMIT 3', (builder.scope.scope_digest, binding.execution_id)).fetchall()
        if archived is not None:
            claim, terminal = (archived.claim, archived.terminal)
            if indices:
                raise C09PagedCaptureHold('labor historical archive and new journal rows need an explicit full transition proof')
            if fact is None or source_binding is None:
                raise C09PagedCaptureHold('labor historical interval lost its retained current signed facts')
            expected_binding = replace(source_binding, prior_fact_frame_digest_or_none=None)
            if canonical_digest(fact) != archived.original['execution_fact_digest'] or canonical_digest(expected_binding) != archived.original['execution_binding_digest']:
                raise C09PagedCaptureHold('labor history crossed its current authenticated prior execution facts')
            certificate = archived.original
            actual_segment = archived.segment
            cpu = facts.lookup_d11(binding.reservation_operation_id, meter=meter)
            if (None if cpu is None else canonical_digest(cpu)) != certificate['cpu_closure']['fact_digest']:
                raise C09PagedCaptureHold('labor history lost its actual retained original CPU fact')
            if terminal is not None:
                budget = graph.execute('SELECT digest,lease_id,receipt_json,resolution_binding_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase=?', (*ns.as_tuple, binding.reservation_operation_id, 'settle')).fetchone()
                if budget is None or budget[:2] != (binding.reservation_digest, binding.parent_budget_lease_ref) or budget[3] is None or (sha256(budget[2].encode('utf-8')).hexdigest() != certificate['cpu_closure']['budget_receipt_sha256']) or (sha256(budget[3].encode('utf-8')).hexdigest() != certificate['cpu_closure']['settlement_binding_sha256']):
                    raise C09PagedCaptureHold('labor retained CPU immutable original bytes changed')
            if fact.status == 'unknown' and facts.lookup_unknown(binding.execution_id, meter=meter) is None:
                raise C09PagedCaptureHold('labor historical unknown interval lost its actual unresolved obligation')
        else:
            if fact is None and source_binding is None and (not indices):
                if self.phase != 'basis':
                    raise C09PagedCaptureHold('labor Segment cannot exist before its actual unique claim')
                from .v2_fence_store import AuthorityV2FenceStore
                gate = 'd11-life-gate:claim:' + canonical_digest((binding.authority_namespace, binding.installation_id, binding.execution_id))
                if AuthorityV2FenceStore._row(core, gate) is not None:
                    raise C09PagedCaptureHold('unindexed labor claim gate is an unresolved execution obligation')
                self.membership_task.require_complete(self, basis)
                return None
            if fact is None or source_binding is None or (not 1 <= len(indices) <= 2) or (source_binding.execution_kind != 'life') or (source_binding.business_operation_id != binding.operation_id) or (source_binding.input_commitment != binding.input_digest):
                raise C09PagedCaptureHold('labor basis lacks its actual complete execution fact/journal binding')
            journal = C09ExecutionOriginalsConnectionV1(db=execution, control=session._control.maintenance.control, namespace=builder.scope.authority_namespace)
            verifier = session.require_fact_original_verifier_v2('life', core_db=core, business_db=graph, execution_reader=journal)
            rows = []
            for seq, commitment in indices:
                row = execution.execute('SELECT seq,mutation_id,request_digest,append_id,pending,previous_digest,chain_digest FROM authority_v2_execution_entries WHERE seq=?', (seq,)).fetchone()
                if row is None or _journal_commitment(row) != commitment:
                    raise C09PagedCaptureHold('labor journal original differs from actual complete indexed source')
                facts.require_execution_journal_row(builder.execution_pair.source_original, ('seq', 'mutation_id', 'request_digest', 'append_id', 'pending', 'previous_digest', 'chain_digest'), row, meter=meter)
                rows.append(row)
            b, p, t = verifier.verify_life_journal_row_v1(journal, rows[0])
            if b != binding or t is not None or p.prepared_digest != basis.prepared_digest:
                raise C09PagedCaptureHold('labor first original is not its actual signed claim')
            claim = D11LifeClaimV1(binding, p, journal.journal_id, rows[0][6], rows[0][1])
            terminal = None
            if len(rows) == 2:
                b, p, t = verifier.verify_life_journal_row_v1(journal, rows[1])
                if b != binding or p != claim.payload or t is None:
                    raise C09PagedCaptureHold('labor terminal lost its exact earlier signed claim')
                terminal = D11LifeTerminalV1(binding, claim, t, journal.journal_id, rows[1][0], rows[1][6], rows[1][1])
            expected = SanitizedExecutionFactV4(binding.execution_id, binding.input_digest, None if terminal is None else terminal.payload.artifact_digest, None if terminal is None else terminal.terminal_digest.removeprefix('sha256:'), claim.payload.signature if terminal is None else terminal.payload.signature, 'unknown' if terminal is None else terminal.status, True)
            if fact != expected or source_binding.originating_journal_id != journal.journal_id:
                raise C09PagedCaptureHold('labor full signed originals differ from actual current sanitized facts')
            if terminal is None:
                closure = dict(kind='claimed_unconfirmed', operation_id=claim.original_ref, original_digest=canonical_digest(life_to_wire_v1(claim)), fact_digest=None, budget_receipt_sha256=None, settlement_binding_sha256=None)
            else:
                cost, closure = require_character_labor_cpu_closure_v1(session, self.graph.pair, business=graph, core_db=core, basis=basis, accounting=accounting, terminal=terminal, meter=meter)
                if facts.lookup_d11(binding.reservation_operation_id, meter=meter) != cost:
                    raise C09PagedCaptureHold('labor actual CPU fact differs from its immutable closure')
            if fact.status == 'unknown' and facts.lookup_unknown(binding.execution_id, meter=meter) is None:
                raise C09PagedCaptureHold('labor unknown execution lost its retained unresolved obligation')
            segment_ref = 'character-work:' + canonical_digest((binding.namespace, binding.effect_id, binding.execution_id, binding.digest, claim.claim_sequence, claim.claim_digest))
            original_segment = _signed(graph, ns, 'character_work_segment_v1', segment_ref, issuer)
            actual_segment = None
            if original_segment is not None:
                from ..runtime.d11_life_contract_v1 import life_adoption_operation_id_v1
                actual_segment = character_work_segment_from_wire_v1(original_segment[0])
                if original_segment[1] != life_adoption_operation_id_v1(binding):
                    raise C09PagedCaptureHold('labor Segment has another actual Graph adoption producer')
                verifier.verify_character_labor_segment_original_v1(actual_segment, binding=binding, claim=claim)
                require_character_labor_segment_basis_v1(actual_segment, basis, accounting)
            d02_closure = None
            if actual_segment is not None:
                from .c09_character_labor_terminal_membership_v1 import _TerminalD02MembershipReadV1, bind_terminal_d02_membership_v1
                if self.terminal_task is None:
                    self.terminal_task = _TerminalD02MembershipReadV1(self, binding=binding, segment=actual_segment, basis=basis)
                    return None
                membership = bind_terminal_d02_membership_v1(self.terminal_task, self, binding=binding, terminal=terminal, segment=actual_segment, basis=basis, core=core, meter=meter)
                from .c09_character_labor_body_history_v1 import require_character_labor_terminal_body_history_v1
                d02_closure = require_character_labor_terminal_body_history_v1(graph, binding=binding, segment=actual_segment, basis=basis, membership=membership, meter=meter)
            self.membership_task.require_complete(self, basis)
            c = session._control.maintenance.control
            s = builder.scope
            certificate = dict(schema='sylanne3.c09.character-labor-execution-history.v1', authority_id=s.authority_id, installation_id=s.installation_id, control_store_id=c.control_store_id, namespace=s.authority_namespace, execution_id=binding.execution_id, binding_digest=binding.digest, basis_ref='character-labor-accounting:' + binding.execution_id, basis_digest=canonical_digest(plain_v1(basis)), accounting_ref=basis.accounting_ref, accounting_digest=basis.accounting_digest, journal_id=journal.journal_id, claim_ref=claim.original_ref, claim_sequence=claim.claim_sequence, claim_digest=claim.claim_digest, claim_payload=life_to_wire_v1(claim.payload), claim_membership=self._entry(rows[0]), claim_gate=self._gate(core, binding, 'claim', claim), terminal_ref=None if terminal is None else terminal.original_ref, terminal_sequence=None if terminal is None else terminal.terminal_sequence, terminal_digest=None if terminal is None else terminal.terminal_digest, terminal_payload=None if terminal is None else life_to_wire_v1(terminal.payload), terminal_membership=None if terminal is None else self._entry(rows[1]), terminal_gate=None if terminal is None else self._gate(core, binding, 'terminal', terminal), segment_original=None if actual_segment is None else plain_v1(actual_segment), segment_original_digest=None if actual_segment is None else canonical_digest(plain_v1(actual_segment)), d02_closure_digest=d02_closure, package_provenance=dict(manifest_digest=binding.manifest_digest, executor_installation_id=claim.payload.executor_installation_id, executor_incarnation=claim.payload.executor_incarnation, algorithm_build_digest=binding.algorithm_build_digest, postcondition_build_digest=binding.postcondition_build_digest), execution_fact_digest=canonical_digest(fact), execution_binding_digest=canonical_digest(replace(source_binding, prior_fact_frame_digest_or_none=None)), cpu_closure=closure, core_source_digest=builder.pair.source_original.role_source_digest, execution_source_digest=builder.execution_pair.source_original.role_source_digest, maintenance_operation_id=s.operation_id, scope_digest=s.scope_digest, accepted_receipt_digest=s.accepted_receipt_digest, facts_pin_digest=facts._completion.pin_digest, graph_issue_digest=builder.basis.graph_issue_digest, target_core_identity=list(builder.pair.target_identity), target_storage_instance_id=builder.segmented_target_v3.storage_instance_id, maintenance_generation=s.maintenance_generation)
            self.archive_body = certificate
        if self.phase == 'segment' and (actual_segment is None or plain_v1(actual_segment) != saved[0]):
            raise C09PagedCaptureHold('Graph labor Segment differs from its actual authenticated retained interval')
        return certificate

    def _graph_build_view(self):
        return _FinalLaborGraphHistoryScopeV1(_FINAL_LABOR_TOKEN, self)

    def advance(self):
        from copy import copy
        from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2, legacy_cell_read_transaction_v2
        if self not in _LABOR_REVERSE:
            raise C09PagedCaptureHold('actual labor reverse source cursor required')
        b = self.builder
        b.require_current()
        self.graph.require_current()
        meter = current_c09_sql_meter_v2()
        result = copy(self)
        _LABOR_REVERSE.add(result)
        b.session._control.maintenance.control.register_c09_retained_state_v3(result)
        kind = {'basis':'character_labor_accounting_basis_v1',
            'segment':'character_work_segment_v1',
            'binding':'character_labor_rebuild_selection_binding_v1'}[self.phase]
        ns = NamespaceId(*json.loads(b.scope.graph_namespace))
        with legacy_cell_read_transaction_v2(self.graph.pair.source), legacy_cell_read_transaction_v2(b.pair.source), legacy_cell_read_transaction_v2(b.execution_pair.source):
            exists = meter.read_fixed_row(self.graph.pair.source, 'sqlite_master', ('name',), 'type=? AND name=?', ('table', 'graph_d11_life_originals_v1'))
            identity = self.member_identity
            if identity is None and exists is not None:
                identity = meter.read_fixed_row(self.graph.pair.source, 'graph_d11_life_originals_v1', ('kind', 'original_ref', 'payload_digest'), 'bot=? AND persona=? AND kind=? AND original_ref COLLATE BINARY>? ORDER BY original_ref COLLATE BINARY', (*ns.as_tuple, kind, '' if self.after is None else self.after[1]))
            if identity is None:
                result.after = None
                if self.phase == 'basis':
                    result.phase = 'segment'
                elif self.phase == 'segment':
                    result.phase = 'binding'
                else:
                    result.complete = True
                return result
            result.member_identity = identity
            graph, core, execution = (_BoundedReadConnectionV2(pair.source, meter) for pair in (self.graph.pair, b.pair, b.execution_pair))
            source = _LaborFrozenSourcesV1(_LABOR_SOURCE_TOKEN, b.session, self.graph.pair, b.pair, b.execution_pair, meter, (graph, core, execution))
            try:
                if self.phase == 'binding':
                    from .c09_character_labor_rebuild_binding_v1 import (
                        read_frozen_character_labor_rebuild_binding_v1,
                        begin_character_labor_rebuild_binding_graph_v1,
                        require_character_labor_rebuild_binding_core_v1)
                    view = result._graph_build_view()
                    task = result.binding_task
                    if task is None:
                        value, digest = read_frozen_character_labor_rebuild_binding_v1(view,ns,identity[1],meter=meter)
                        if digest != identity[2]:
                            raise C09PagedCaptureHold('labor selection binding changed during its complete Source census')
                        result.binding_task = begin_character_labor_rebuild_binding_graph_v1(view,value)
                        return result
                    if not task.complete:
                        result.binding_task = task.advance_v1(view,meter=meter)
                        return result
                    value = task.value
                    graph_proof = task.require_complete_v1(view,value)
                    core_proof = require_character_labor_rebuild_binding_core_v1(b,value,core,meter=meter)
                    result.root = canonical_digest(('sylanne3.c09.character-labor-final-member.v1',
                        self.root,self.count+1,*identity,graph_proof,core_proof))
                    result.count += 1
                    result.after = identity[:2]
                    result.member_identity = None
                    result.binding_task = None
                    return result
                if not result.membership_checked:
                    from ..runtime.d11_character_labor_accounting_v1 import KIND as BASIS_KIND, _signed, character_labor_accounting_basis_from_wire_v1
                    issuer = b.session.get_c09_domain_original_issuer_v2()
                    if self.phase == 'basis':
                        raw = _signed(graph, ns, BASIS_KIND, identity[1], issuer)
                    else:
                        from ..runtime.d11_character_work_segment_v1 import character_work_segment_from_wire_v1
                        raw_segment = _signed(graph, ns, 'character_work_segment_v1', identity[1], issuer)
                        segment = character_work_segment_from_wire_v1(raw_segment[0])
                        raw = _signed(graph, ns, BASIS_KIND, 'character-labor-accounting:' + segment.execution_id, issuer)
                    if raw is None:
                        raise C09PagedCaptureHold('labor source member has no authentic independent basis')
                    basis = character_labor_accounting_basis_from_wire_v1(raw[0])
                    archive_schema = meter.read_fixed_row(b.pair.source, 'sqlite_master', ('name',), 'type=? AND name=?', ('table', 'authority_c09_originals_archive_v1'))
                    archived = None if archive_schema is None else meter.read_fixed_row(b.pair.source, 'authority_c09_originals_archive_v1', ('operation_id',), 'namespace=? AND operation_id=? AND original_kind=?', (b.scope.authority_namespace, basis.execution_id, 'character_labor_execution_history_v1'))
                    result.membership_checked = True
                    if archived is None:
                        from .c09_character_labor_membership_v1 import _CharacterLaborMembershipReadV1
                        result.membership_task = _CharacterLaborMembershipReadV1(result, basis)
                        return result
                if result.membership_task is not None and (not result.membership_task.complete):
                    result.membership_task = result.membership_task.advance(meter)
                    return result
                if result.terminal_task is not None and (not result.terminal_task.complete):
                    result.terminal_task = result.terminal_task.advance(result, meter)
                    return result
                certificate = result._qualify(graph, core, execution, meter)
                if result.terminal_task is not None and (not result.terminal_task.complete):
                    return result
                if certificate is not None:
                    certificate = result._archive(certificate, meter)
                result.root = canonical_digest(('sylanne3.c09.character-labor-final-member.v1', self.root, self.count + 1, *identity, None if certificate is None else certificate.get('history_digest')))
                result.count += 1
                result.after = identity[:2]
                result.member_identity = None
                result.membership_task = None
                result.membership_checked = False
                result.terminal_task = None
            finally:
                source.close()
                result.basis = None
                result.accounting = None
                result.archive_body = None
        b.require_current()
        self.graph.require_current()
        return result

    def _archive(self, certificate, meter):
        from .character_labor_execution_history_v1 import KIND, issue_character_labor_execution_history_v1, validate_character_labor_execution_history_v1
        from .c09_originals_archive_v1 import ARCHIVE_DDL
        from .c09_authority_storage_rebase_v2 import _same_insert, _generated, C09AuthorityRowMeterV2
        from ..runtime.c09_paged_sql_v2 import capture_transaction_v2
        b = self.builder
        table = 'authority_c09_originals_archive_v1'
        schema = meter.read_fixed_row(b.pair.candidate, 'sqlite_master', ('sql',), 'type=? AND name=?', ('table', table))
        if schema != (ARCHIVE_DDL,):
            raise C09PagedCaptureHold('labor actual target archive schema differs')
        columns = ('namespace', 'operation_id', 'original_kind', 'original_digest', 'original_json', 'maintenance_generation')
        key = (b.scope.authority_namespace, self.basis.execution_id, KIND)
        prior = meter.read_fixed_row(b.pair.candidate, table, columns, 'namespace=? AND operation_id=? AND original_kind=?', key)
        if 'history_digest' not in certificate:
            if prior is not None:
                original = json.loads(prior[4])
                validate_character_labor_execution_history_v1(b.session._control.maintenance.control, original, namespace=b.scope.authority_namespace, basis=self.basis, accounting=self.accounting)
                if any((original.get(name) != value for name, value in certificate.items())):
                    raise C09PagedCaptureHold('labor target certificate differs from actual complete source replay')
                certificate = original
            else:
                phase = meter.read_fixed_row(b.pair.candidate, 'authority_c09_role_build_v2', ('phase',), 'scope_digest=? AND role=?', (b.scope.scope_digest, 'core'))
                if not self.production or phase is None or phase[0] not in {'next_table', 'table_census', 'table_rows', 'table_seal'}:
                    raise C09PagedCaptureHold('a sealed target cannot acquire a missing labor history certificate')
                certificate = issue_character_labor_execution_history_v1(b, self, meter=meter)
        row = (*key, certificate['history_digest'], canonical_serialize(certificate), certificate['maintenance_generation'])
        if self.production:
            writer = C09AuthorityRowMeterV2(meter.budget.max_bytes)
            with capture_transaction_v2(b.pair.candidate):
                inserted = _same_insert(b.pair.candidate, table, columns, row, columns[:3], writer)
                if inserted and certificate['scope_digest'] == b.scope.scope_digest:
                    _generated(b.pair, b.scope, table, columns, row, 'character-labor-execution-history-v1', certificate['history_digest'], writer)
        elif prior != row:
            raise C09PagedCaptureHold('cold labor archive differs from its fully authenticated actual source')
        return certificate
_FINAL_LABOR_TOKEN = object()
_FINAL_LABOR_SCOPES = WeakSet()

class _FinalLaborGraphHistoryScopeV1:
    """Private final Graph read scope over its actual final Core owner."""

    def __init__(self, token, owner):
        if token is not _FINAL_LABOR_TOKEN or type(owner) is not _CharacterLaborCoreReverseReadV1 or owner not in _LABOR_REVERSE:
            raise C09PagedCaptureHold('actual registered final labor Graph reader required')
        self.owner = owner
        self.session = owner.builder.session
        self.pair = owner.graph.pair
        _FINAL_LABOR_SCOPES.add(self)

    def require_current(self):
        if self not in _FINAL_LABOR_SCOPES or self.owner not in _LABOR_REVERSE:
            raise C09PagedCaptureHold('final labor Graph metadata scope expired')
        self.owner.builder.require_current()
        self.owner.graph.require_current()

def advance_character_labor_core_reverse_v1(builder, *, production):
    name = 'labor_core_production_v1' if production else 'labor_core_reverse_v1'
    pending = '_pending_labor_core_production_v1' if production else '_pending_labor_core_reverse_v1'
    state = getattr(builder, name)
    if state is None:
        state = _CharacterLaborCoreReverseReadV1(_LABOR_REVERSE_TOKEN, builder, production=production)
    setattr(builder, pending, state.advance())

def verify_character_labor_archive_row_v1(builder, columns, row, *, source, meter):
    from .character_labor_execution_history_v1 import KIND, validate_character_labor_execution_history_v1, require_character_labor_history_ancestor_v1
    from ..runtime.d11_character_labor_accounting_v1 import KIND as BASIS_KIND, _signed, character_labor_accounting_basis_from_wire_v1, read_character_labor_accounting_prepared_v1
    from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
    from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2
    if tuple(columns) != ('namespace', 'operation_id', 'original_kind', 'original_digest', 'original_json', 'maintenance_generation') or row[0] != builder.scope.authority_namespace or row[2] != KIND or (type(source) is not bool):
        raise C09PagedCaptureHold('labor archive exact physical identity changed')
    builder.require_current()
    original = json.loads(row[4])
    control = builder.session._control.maintenance.control
    control.verify_original_v1(original, 'history_digest')
    if row[1] != original['execution_id'] or row[3] != original['history_digest'] or row[5] != original['maintenance_generation'] or (canonical_serialize(original) != row[4]):
        raise C09PagedCaptureHold('labor archive actual bytes/digest/natural identity changed')
    graph = builder.session.require_actual_post_mirror_graph_v3()
    with legacy_cell_read_transaction_v2(graph.pair.source):
        db = _BoundedReadConnectionV2(graph.pair.source, meter)
        ns = NamespaceId(*json.loads(builder.scope.graph_namespace))
        issuer = builder.session.get_c09_domain_original_issuer_v2()
        saved = _signed(db, ns, BASIS_KIND, 'character-labor-accounting:' + row[1], issuer)
        if saved is None:
            raise C09PagedCaptureHold('labor archive has no authentic frozen signed basis')
        basis = character_labor_accounting_basis_from_wire_v1(saved[0])
        binding = basis_binding_v1(db, basis, issuer)
        authentic = read_character_labor_accounting_prepared_v1(db, binding=binding, issuer=issuer, resource_issuer=issuer.resource_issuer)
        if authentic is None or authentic[0] != basis:
            raise C09PagedCaptureHold('labor archive lost real CPU preparation')
        validate_character_labor_execution_history_v1(control, original, namespace=builder.scope.authority_namespace, basis=basis, accounting=authentic[1])
    if source:
        require_character_labor_history_ancestor_v1(builder, original, meter=meter)
    builder.require_current()
    graph.require_current()
    return original
