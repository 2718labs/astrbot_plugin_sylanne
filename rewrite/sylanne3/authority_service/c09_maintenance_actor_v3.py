"""One installed same-thread C09 actor; every producer retains its real budget."""
from __future__ import annotations

from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3

import threading
from time import sleep

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest
from ..runtime.c09_paged_sql_v2 import C09SqlByteMeterV2, c09_sql_meter_quantum_v2


class InstalledC09MaintenanceActorV3:
    def __init__(self, maintenance, operation_id):
        from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
        if type(maintenance) is not InstalledC09MaintenanceV1:
            raise AuthorityUnavailable('actual installed C09 maintenance actor required')
        self.maintenance, self.operation_id = maintenance, operation_id
        self.lock = threading.Lock()
        self.status = dict(status='progress', phase='control_preflight', operation_id=operation_id)
        self.failure = None
        self.result = None
        self.failure_basis = None
        self.thread = None
        self.owner_thread = None
        self.program = self._program()

    def start(self):
        if self.thread is not None or self.owner_thread is not None:
            raise AuthorityUnavailable('actual installed C09 actor already has its thread owner')
        self.thread = threading.Thread(target=self._run, name='c09-maintenance-' + self.operation_id, daemon=True)
        self.thread.start()

    def close_current_thread_v3(self):
        if self.owner_thread is not None and self.owner_thread != threading.get_ident():
            raise AuthorityUnavailable('actual C09 final continuation must close on its owner thread')
        self.program.close()
        self._close_surface_work_v3()

    def _close_surface_work_v3(self):
        for service in self.maintenance.surface_services.values():
            for name in ('_selected_surface_progress_v3','_selected_surface_reread_v3','_selected_provider_cleanup_v3','_selected_provider_reread_v3'):
                progress=getattr(service,name,None)
                if progress is not None:progress.close()

    def snapshot(self):
        with self.lock:
            return dict(self.status)

    def _set(self, phase, **details):
        with self.lock:
            self.status = dict(status='progress', phase=phase, operation_id=self.operation_id, **details)

    def _run(self):
        while self.advance_one_quantum_v3()['status'] == 'progress':
            sleep(0)

    def advance_one_quantum_v3(self):
        owner = threading.get_ident()
        if self.owner_thread is None:
            self.owner_thread = owner
        elif self.owner_thread != owner:
            raise AuthorityUnavailable('actual installed C09 continuation cannot migrate between threads')
        if self.snapshot()['status'] in {'complete', 'failed'}:
            return self.snapshot()
        self.failure_basis = getattr(self.maintenance.control, '_c09_control_chain_proof_v2', self.failure_basis) or self.failure_basis
        try:
            next(self.program)
        except StopIteration:
            self._close_surface_work_v3()
            with self.lock:
                if self.result.get('schema') == 'sylanne3.c09.storage_prepared_original.v3':
                    self.status = dict(status='complete', phase='PREPARED', operation_id=self.operation_id,
                        prepared_digest=self.result['prepared_digest'])
                else:
                    self.status = dict(self.result, operation_id=self.operation_id)
        except BaseException as exc:
            with self.lock:
                self.failure = str(exc)
                self.status = dict(status='failed', phase=self.status['phase'], operation_id=self.operation_id,
                    reason=self.failure)
            cleanup_errors=[]
            for close in (self.program.close,self._close_surface_work_v3):
                try:close()
                except BaseException as cleanup_error:cleanup_errors.append(str(cleanup_error))
            if cleanup_errors:
                with self.lock:self.status['cleanup_errors']=tuple(cleanup_errors)
            self._persist_failure()
        return self.snapshot()

    def _program(self):
        m = self.maintenance
        while True:
            result = m.control.advance_current_control_read_v3()
            self._set('control_preflight')
            yield self.snapshot()
            if result['status'] == 'complete':
                break
        with m.control.reserve_control_read_v3() as budget:
            meter = require_c09_reserved_meter_v3(budget)
            with c09_sql_meter_quantum_v2(meter):
                from .c09_selected_history_v3 import _bounded, _read_one
                with m.control._db() as db:
                    present = _read_one(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='c09_maintenance_failures_v3'", (), meter)
                    failure = None if present is None else _bounded(db, meter).execute('SELECT failure_json,failure_digest '
                        'FROM c09_maintenance_failures_v3 WHERE operation_id=?', (self.operation_id,)).fetchone()
                    if present is not None:
                        _require_failure_schema(m.control, db)
                if failure is not None:
                    import json
                    original = json.loads(failure[0])
                    m.control.verify_original_v1(original, 'failure_digest')
                    if original['operation_id'] != self.operation_id or original['failure_digest'] != failure[1]:
                        raise AuthorityUnavailable('actual first maintenance failure original differs')
                    self._set(original['phase'])
                    raise AuthorityUnavailable(original['reason'])
        yield self.snapshot()
        current = m.control._c09_control_chain_proof_v2.current
        if current['stage'] in {'PREPARED', 'SWITCHED', 'CLEANED'}:
            if current['active_operation_id'] != self.operation_id:
                raise AuthorityUnavailable('actual resumed actor operation differs from Control')
            while True:
                if current['stage'] == 'PREPARED':
                    from .c09_writer_peer_originals_v3 import VerifiedPeerRetirementCoverageV3
                    while True:
                        peers = m.gate.advance_peer_retirement_coverage_v3(operation_id=self.operation_id)
                        yield self.snapshot()
                        if type(peers) is VerifiedPeerRetirementCoverageV3:
                            break
                        self._set(peers['phase'])
                    progress = m.switch_prepared_storage_v1(operation_id=self.operation_id)
                    if progress['status'] == 'complete':
                        progress = dict(progress, restart_required=True, phase='SWITCHED')
                else:
                    if getattr(m.gate, '_peer_retirement_coverage_v3', None) is None:
                        with m.control._resource_sql_quantum_v3() as meter:
                            context = m.control.read_verified_current_storage_v3(meter=meter)
                            m.gate.restore_prepared_peer_retirement_v3(operation_id=self.operation_id, context=context)
                        yield self.snapshot()
                    progress = m.cleanup_and_release_v1(operation_id=self.operation_id)
                with self.lock:
                    self.status = dict(progress, operation_id=self.operation_id)
                yield self.snapshot()
                if progress['status'] in {'complete', 'failed'}:
                    self.result = progress
                    return
        if current['stage'] == 'RELEASED' and current['active_operation_id'] == self.operation_id:
            from .c09_close_apply_v1 import SelectedAppliedReadV3
            while True:
                applied = m.control.advance_selected_storage_applied_read_v3()
                yield self.snapshot()
                if type(applied) is SelectedAppliedReadV3:
                    break
                self._set(applied['phase'])
            context = m.control.read_verified_current_storage_v3()
            context.require_current('business')
            self.result = dict(status='complete', phase='RELEASED', stage='RELEASED', restart_required=False)
            return
        while True:
            result = m.advance_current_c09_prepared_preflight_v2()
            self._set('selected_source_preflight')
            yield self.snapshot()
            if result['status'] == 'complete':
                break
        from .c09_writer_peer_originals_v3 import VerifiedPeerRetirementCoverageV3
        while True:
            peers = m.gate.advance_peer_retirement_coverage_v3(operation_id=self.operation_id)
            yield self.snapshot()
            if type(peers) is VerifiedPeerRetirementCoverageV3:
                break
            self._set(peers['phase'])
        self._prepare_intent()
        yield self.snapshot()
        with m.gate.hold_final_continuation_v3(operation_id=self.operation_id) as continuation:
            m._c09_final_continuation_v2 = continuation
            try:
                self.result = yield from self._capture(continuation)
            finally:
                m._c09_final_continuation_v2 = None

    def _prepare_intent(self):
        m = self.maintenance
        from .erasure_closure_inventory import CleanupRunV2, _TABLES
        current = m.control.read_verified_current_storage_v1()
        m.core._require(m.credential, 'delete', m.closure.namespace)
        with m.core._tx() as db:
            run = m.closure._read_record(db, _TABLES[1], self.operation_id, CleanupRunV2)
            if run is None:
                raise AuthorityUnavailable('actual accepted C09 cleanup required')
            accepted = m.closure._accepted_locked(db, run, m.subject)
        quiescence = m.gate.revoke_and_drain_v1(operation_id=self.operation_id)
        if current.stage in {'READY', 'RELEASED'}:
            targets = m._targets(self.operation_id, current.storage_generation + 1)
            m.control.record_maintenance_intent_v1(operation_id=self.operation_id, namespace=m.closure.namespace,
                installed_intent=dict(expected_pointer_version=current.pointer_version,
                    old_manifest_digest=current.manifest_digest, targets=targets,
                    accepted_receipt_digest=canonical_digest(accepted), quiescence_original=quiescence))
        elif current.stage != 'INTENT':
            raise AuthorityUnavailable('actual C09 capture actor requires its unfinished INTENT')
        self._set('source_freeze')
        m._checkpoint(m.graph, close=True)
        m._checkpoint(m.core)
        m._checkpoint(m.closure.execution)
        m._checkpoint(m.closure.deletion)

    def _capture(self, continuation):
        m = self.maintenance
        from .c09_role_capture_pair_v2 import C09RolePairProgressV2
        from .c09_paged_recovery_facts_v2 import begin_installed_c09_recovery_facts_v2, C09PagedRecoveryFactsResolverV2
        from ..runtime.c09_graph_rebase_candidate_v2 import (
            begin_current_graph_rebase_candidate_v2, advance_current_graph_rebase_candidate_v2,
            begin_current_graph_rebase_cold_v2, advance_current_graph_rebase_cold_v2,
            mirror_current_graph_rebase_v2, VerifiedGraphRebaseColdV2,
        )
        from ..runtime.c09_paged_capture_contract_v2 import GraphRebaseCandidateV2
        from .c09_graph_rebase_issue_v2 import issue_current_graph_rebase_v2
        from .c09_prepared_storage_v2 import retain_verified_graph_role_v2, retain_verified_authority_role_v2
        from .c09_authority_storage_rebase_v2 import (
            begin_installed_authority_role_rebase_v2, advance_installed_authority_role_rebase_v2,
            VerifiedAuthorityRoleRebaseV2,
        )
        from .c09_segmented_census_v3 import begin_segmented_census_v3, retain_segmented_role_complete_v3, VerifiedSegmentedPhysicalSweepV3
        from .c09_physical_inventory_bound_v2 import begin_current_physical_inventory_v2, advance_current_physical_inventory_v2, advance_current_prepared_publication_v3
        from .c09_physical_inventory_stream_v2 import VerifiedPhysicalInventoryV2
        session = m.begin_current_c09_capture_v2(operation_id=self.operation_id)
        yield self.snapshot()
        graph_pair = session.open_role_pair('graph')
        yield self.snapshot()
        while type(graph_pair) is C09RolePairProgressV2:
            self._set('graph_source', bytes_processed=graph_pair.bytes_processed)
            yield self.snapshot()
            graph_pair = session.open_role_pair('graph')
            yield self.snapshot()
        facts = begin_installed_c09_recovery_facts_v2(session, graph_pair)
        yield self.snapshot()
        while True:
            result = facts.advance()
            yield self.snapshot()
            if type(result) is C09PagedRecoveryFactsResolverV2:
                break
            self._set('recovery_facts', producer_phase=result['phase'])
            yield self.snapshot()
        build = begin_current_graph_rebase_candidate_v2(session)
        yield self.snapshot()
        while type(build) is C09RolePairProgressV2:
            yield self.snapshot()
            build = begin_current_graph_rebase_candidate_v2(session)
            yield self.snapshot()
        while True:
            candidate = advance_current_graph_rebase_candidate_v2(build)
            yield self.snapshot()
            if type(candidate) is GraphRebaseCandidateV2:
                break
            self._set('graph_candidate', producer_phase=candidate.get('phase', 'building'))
            yield self.snapshot()
        cold = begin_current_graph_rebase_cold_v2(session, candidate)
        yield self.snapshot()
        while True:
            verified = advance_current_graph_rebase_cold_v2(cold)
            yield self.snapshot()
            if type(verified) is VerifiedGraphRebaseColdV2:
                break
            self._set('graph_pre_mirror_cold')
            yield self.snapshot()
        issued = issue_current_graph_rebase_v2(session, verified)
        yield self.snapshot()
        cold = mirror_current_graph_rebase_v2(session, verified, issued)
        yield self.snapshot()
        while True:
            verified = advance_current_graph_rebase_cold_v2(cold)
            yield self.snapshot()
            if type(verified) is VerifiedGraphRebaseColdV2:
                break
            self._set('graph_post_mirror_cold')
            yield self.snapshot()
        session.retain_actual_post_mirror_graph_v3(verified)
        yield self.snapshot()
        with session.reserve_batch() as budget:
            meter = require_c09_reserved_meter_v3(budget)
            with c09_sql_meter_quantum_v2(meter):
                retain_verified_graph_role_v2(session, verified, issued)
        yield self.snapshot()
        from .c09_role_capture_pair_v2 import close_completed_c09_authority_sources_v2
        with session.reserve_batch() as budget:
            meter = require_c09_reserved_meter_v3(budget)
            with c09_sql_meter_quantum_v2(meter):
                close_completed_c09_authority_sources_v2(session)
        yield self.snapshot()
        actual_core_role = None
        for role in ('core', 'execution', 'deletion'):
            builder = begin_installed_authority_role_rebase_v2(session, role)
            yield self.snapshot()
            while type(builder) is C09RolePairProgressV2:
                self._set('authority_source', role=role, bytes_processed=builder.bytes_processed)
                yield self.snapshot()
                builder = begin_installed_authority_role_rebase_v2(session, role)
                yield self.snapshot()
            while True:
                completed = advance_installed_authority_role_rebase_v2(builder)
                yield self.snapshot()
                if type(completed) is VerifiedAuthorityRoleRebaseV2:
                    break
                self._set('authority_candidate', role=role, producer_phase=completed.get('phase', 'building'))
                yield self.snapshot()
            with session.reserve_batch() as budget:
                meter = require_c09_reserved_meter_v3(budget)
                with c09_sql_meter_quantum_v2(meter):
                    retain_verified_authority_role_v2(session, completed)
            if role == 'core':
                actual_core_role = completed
            yield self.snapshot()
        for role in ('graph', 'core', 'execution', 'deletion'):
            census = begin_segmented_census_v3(session, role)
            yield self.snapshot()
            while True:
                sweep = census.advance()
                yield self.snapshot()
                if type(sweep) is VerifiedSegmentedPhysicalSweepV3:
                    break
                self._set('segmented_physical', role=role)
                yield self.snapshot()
            while True:
                original = retain_segmented_role_complete_v3(session, sweep)
                yield self.snapshot()
                if original.get('original_kind') == 'segmented_role_complete_v1_' + role:
                    break
                self._set('segmented_originals', role=role)
                yield self.snapshot()
        physical = begin_current_physical_inventory_v2(session, actual_core_role=actual_core_role)
        yield self.snapshot()
        while True:
            complete = advance_current_physical_inventory_v2(physical)
            yield self.snapshot()
            if type(complete) is VerifiedPhysicalInventoryV2:
                break
            self._set('physical_inventory')
            yield self.snapshot()
        while True:
            prepared = advance_current_prepared_publication_v3(physical.bound, complete, closing_continuation=continuation)
            yield self.snapshot()
            if prepared.get('schema') == 'sylanne3.c09.storage_prepared_original.v3':
                session.close()
                return prepared
            self._set('publication', producer_phase=prepared['phase'])
            yield self.snapshot()


    def _persist_failure(self):
        m, proof = self.maintenance, self.failure_basis
        if proof is None:
            # No authenticated operation has begun; retain the caller's failure.
            return
        with m.control.reserve_control_read_v3() as budget:
            meter = require_c09_reserved_meter_v3(budget)
            with c09_sql_meter_quantum_v2(meter):
                from .c09_selected_history_v3 import _bounded
                with m.control._db(write=True) as db:
                    current = proof.require_current(db, meter)
                    if current['active_operation_id'] != self.operation_id:
                        return
                    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='c09_maintenance_failures_v3'").fetchone() is None:
                        meter.write(db, _FAILURE_DDL)
                        for action in ('UPDATE', 'DELETE'):
                            meter.write(db, m.control._immutable_ddl('c09_maintenance_failures_v3', action))
                    _require_failure_schema(m.control, db)
                    row = _bounded(db, meter).execute('SELECT failure_json FROM c09_maintenance_failures_v3 WHERE operation_id=?',
                        (self.operation_id,)).fetchone()
                    if row is not None:
                        import json
                        original = json.loads(row[0])
                        m.control.verify_original_v1(original, 'failure_digest')
                        if original['phase'] != self.status['phase'] or original['reason'] != self.failure:
                            raise AuthorityUnavailable('actual first maintenance failure cannot be replaced')
                        return
                    original = m.control.sign_original_v1('sylanne3.c09.maintenance-first-failure.v3', dict(
                        schema='sylanne3.c09.maintenance-first-failure.v3', authority_id=m.control.authority_id,
                        installation_id=m.control.installation_id, operation_id=self.operation_id,
                        pointer_version=current['pointer_version'], manifest_digest=current['current_manifest_digest'],
                        phase=self.status['phase'], reason=self.failure), 'failure_digest')
                    from .c09_storage_control_v1 import canonical
                    meter.write_row(db, 'c09_maintenance_failures_v3', ('operation_id', 'failure_json', 'failure_digest', 'key_id', 'signature'),
                        (self.operation_id, canonical(original), original['failure_digest'], m.control.key_id, original['signature']))
                m.control._c09_control_chain_proof_v2 = proof


_FAILURE_DDL = 'CREATE TABLE c09_maintenance_failures_v3 (operation_id TEXT PRIMARY KEY,failure_json TEXT NOT NULL,failure_digest TEXT NOT NULL UNIQUE,key_id TEXT NOT NULL,signature TEXT NOT NULL) STRICT'


def _require_failure_schema(control, db):
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='c09_maintenance_failures_v3'").fetchone()
    if row is None or row[0] != _FAILURE_DDL:
        raise AuthorityUnavailable('actual first maintenance failure schema differs')
    for action in ('UPDATE', 'DELETE'):
        name = 'c09_maintenance_failures_v3_no_' + action.lower()
        row = db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone()
        if row is None or row[0] != control._immutable_ddl('c09_maintenance_failures_v3', action):
            raise AuthorityUnavailable('actual first maintenance failure immutable trigger differs')


def prepare_current_storage_v3(maintenance, *, operation_id):
    with maintenance._maintenance_lock:
        actor = getattr(maintenance, '_maintenance_actor_v3', None)
        if actor is None:
            actor = InstalledC09MaintenanceActorV3(maintenance, operation_id)
            maintenance._maintenance_actor_v3 = actor
            if getattr(maintenance, '_c09_actor_host_thread_v3', None) is None:
                actor.start()
        elif actor.operation_id != operation_id:
            raise AuthorityUnavailable('actual installed C09 actor already owns another operation')
        if getattr(maintenance, '_c09_actor_host_thread_v3', None) is not None:
            return actor.advance_one_quantum_v3()
        return actor.snapshot()
