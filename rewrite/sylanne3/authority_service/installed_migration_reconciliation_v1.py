"""Content-free reconciliation from current independent execution originals.

Unknown remains unknown. Activation can preserve an original blocked job,
Body reservation and D11 occupancy; it cannot replace that identity with a
new dispatch/call or manufacture a terminal/zero bill. The source/target graph
equality proof is checked separately by InstalledMigrationTargetVerifierV1.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from ..runtime.graph_migration_snapshot_v1 import _inventory, _hash
from ..runtime.jobs import get_job
from ..runtime.budget import get_budget_lease
from ..runtime.c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from ..runtime.d11_c04_internal_cost import read_c04_cpu_cost_original_v1
from ..runtime_contracts import canonical_digest, NamespaceId
from .v2_fence_service import AuthorityV2FenceService
from .contract import AuthorityUnavailable
from .v2_contract import decode_bytes, canonical_bytes
from .v2_migration_service import AuthorityV2MigrationService
from .v2_model_egress_store import AuthorityV2ModelEgressStore


def _digest(value):
    return "sha256:" + canonical_digest(value)


@dataclass(frozen=True, slots=True)
class MigrationReconciliationOriginalV1:
    transfer_id: str
    authority_namespace: str
    target_generation: int
    source_snapshot_digest: str
    retained_graph_digest: str
    deletion_head_digest: str
    execution_head_digest: str
    authority_originals_digest: str
    constraints: tuple[tuple[str, str, str, str], ...]
    original_digest: str


@dataclass(frozen=True, slots=True)
class NamespaceExecutionReconciliationV1:
    namespace: NamespaceId
    authority_namespace: str
    retained_graph_digest: str
    deletion_head_digest: str
    execution_head_digest: str
    authority_originals_digest: str
    constraints: tuple[tuple[str, str, str, str], ...]
    original_digest: str


class InstalledNamespaceExecutionReconciliationV1:
    """Internal actual-ledger projection; caller supplies its own current gate.

    This reads only the caller's already held Core/Graph transactions and frozen
    journal heads. It never grants Owner, lifecycle, migration or execution rights.
    """
    def __init__(self, *, fences, model_store=None, maximum_originals=100_000):
        if type(fences) is not AuthorityV2FenceService:
            raise TypeError("installed actual Authority fence service required")
        if (model_store is not None and (type(model_store) is not AuthorityV2ModelEgressStore
                or model_store._db is not fences.core._db)):
            raise ValueError("model ledger must belong to the same Authority Core")
        if type(maximum_originals) is not int or not 1 <= maximum_originals <= 1_000_000:
            raise ValueError("bounded actual ledger inventory required")
        self.core, self.fences, self.namespace = fences.core, fences, fences.namespace
        self.models, self.maximum_originals = model_store, maximum_originals

    def _reservation(self, target_db, namespace, lease_id, operation_id, expected_digest, ceiling=None):
        lease = get_budget_lease(target_db, lease_id)
        if (lease.bot_id, lease.persona_id) != namespace.as_tuple:
            raise AuthorityUnavailable("retained budget crosses migration namespace")
        row = target_db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                                (lease_id, operation_id)).fetchone()
        if row is None or row[0] != expected_digest:
            raise AuthorityUnavailable("original budget reservation absent or replaced")
        if ceiling is not None and json.loads(row[1]) != dict(ceiling):
            raise AuthorityUnavailable("retained original ceiling differs")
        if row[2] == "reserved":
            amounts = json.loads(row[1])
            if row[3] is not None or any(lease.reserved.get(k, 0) < v for k, v in amounts.items()):
                raise AuthorityUnavailable("reserved work lost its occupancy")
        elif row[2] == "unknown":
            amounts = json.loads(row[1])
            if row[3] is not None or any(lease.unconfirmed.get(k, 0) < v for k, v in amounts.items()):
                raise AuthorityUnavailable("unknown work lost its unconfirmed occupancy")
        elif row[2] in {"partial_unknown", "partial_overrun"}:
            if row[3] is None:
                raise AuthorityUnavailable("partial cost lost its measured dimensions")
            known = json.loads(row[3])
            ceiling_values = json.loads(row[1])
            unknown = {k: v for k, v in ceiling_values.items() if k not in known}
            if not unknown or any(lease.unconfirmed.get(k, 0) < v for k, v in unknown.items()):
                raise AuthorityUnavailable("partial cost lost original unknown occupancy")
        elif row[2] not in {"settled", "overrun"}:
            raise AuthorityUnavailable("unsupported original budget recovery state")
        return row

    def _model_constraint(self, db, target_db, namespace, call_id, *, qualified_context=None, verified_model=None):
        if self.models is None:
            raise AuthorityUnavailable("current original model ledger reader unavailable")
        consumed=(db.execute("SELECT 1 FROM sqlite_master WHERE name='authority_c09_consumed_execution_v1'").fetchone() is not None
            and db.execute("SELECT 1 FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind='model_call' AND item_id=?",(self.namespace,call_id)).fetchone() is not None)
        if consumed:
            from .c09_model_budget_original_v1 import read_authenticated_model_budget_original_in_tx_v1,read_model_audit_metadata_v1
            original=verified_model
            if original is None:
                if qualified_context is None:raise AuthorityUnavailable("consumed model needs actual prequalified C09 accounting context")
                original=read_authenticated_model_budget_original_in_tx_v1(db,namespace=self.namespace,call_id=call_id,context=qualified_context)
            audit=read_model_audit_metadata_v1(db,call_id)
            if (original is None or audit is None or original.call_id!=call_id or original.namespace!=self.namespace
                    or original.request_digest!=audit.intent.request_digest or original.binding_digest!=audit.intent.binding_digest
                    or original.model_operation_id!=audit.intent.operation_id or not audit.content_erased):
                raise AuthorityUnavailable("consumed model current audit/signed recovery binding differs")
            ceiling={unit.unit:unit.ceiling for unit in original.units}
            reservation=self._reservation(target_db,namespace,original.parent_budget_id,original.reservation_operation_id,original.reservation_digest,ceiling)
            expected=None if original.reservation_state in {'reserved','unknown'} else {unit.unit:unit.settled for unit in original.units if unit.actual_or_none is not None}
            if reservation[2]!=original.reservation_state or (None if reservation[3] is None else json.loads(reservation[3]))!=expected:
                raise AuthorityUnavailable("consumed model actual per-unit reservation changed without current recovery settlement")
            return ("model",call_id,original.provider_state,_digest({"consumed_original":asdict(original),"reservation":reservation}))
        recovery = self.models._read(db, call_id)
        if recovery is None:
            raise AuthorityUnavailable("current original model call disappeared")
        intent = recovery.intent
        if intent.authority_id != self.core._id(db) or intent.namespace != self.namespace:
            raise AuthorityUnavailable("model call belongs to another Authority")
        job = get_job(target_db, intent.job_id)
        if (job.bot_id, job.persona_id) != namespace.as_tuple or job.budget_ref != intent.budget_lease_id:
            raise AuthorityUnavailable("model original job/parent budget lost")
        reservation = self._reservation(target_db, namespace, intent.budget_lease_id,
            intent.budget_reservation_operation_id, intent.budget_reservation_digest,
            intent.budget_ceiling)
        if recovery.state in {"dispatch_started", "unknown"}:
            if job.phase in {"queued", "completed", "failed", "cancelled"} and reservation[2] in {"settled", "overrun"}:
                raise AuthorityUnavailable("unknown model was converted to a completed/zero bill")
            if reservation[2] not in {"reserved", "unknown", "partial_unknown", "partial_overrun"}:
                raise AuthorityUnavailable("unknown model reservation cannot be released")
        if recovery.state in {"observed", "unknown"}:
            admission, _, terminal = self.models.read_admission_locked(db, intent)
            if terminal is None or terminal.observation_digest != recovery.observation_digest:
                raise AuthorityUnavailable("model status lacks original durable terminal")
            if reservation[2] in {"settled", "overrun", "partial_unknown", "partial_overrun"}:
                if recovery.state != "observed" or reservation[3] is None:
                    raise AuthorityUnavailable("unmeasured model cost was asserted settled")
                actual = json.loads(reservation[3])
                usage, money = dict(recovery.usage), dict(recovery.cost)
                dimensions = (dict(intent.budget_ceiling) if reservation[2] in {"settled", "overrun"} else actual)
                for dimension in dimensions:
                    amount = actual.get(dimension, 0)
                    measured = (usage.get(dimension) if dimension in {"input_tokens", "output_tokens"}
                        else usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
                        if dimension == "model_tokens" and {"input_tokens", "output_tokens"} <= usage.keys()
                        else money.get(dimension) if dimension == "model_microusd" else None)
                    if measured is None or amount != measured:
                        raise AuthorityUnavailable("model settled cost differs from actual original usage")
            terminal_digest = _digest(terminal)
        else:
            terminal_digest = "sha256:" + sha256(b"no-terminal-original").hexdigest()
        return ("model", call_id, recovery.state,
                _digest({"recovery": asdict(recovery), "job": asdict(job),
                         "reservation": reservation, "terminal_digest": terminal_digest}))

    def authenticate_execution_rows_under_writer_locks_v1(self):
        """Actual independent signatures before opening the Graph snapshot."""
        if self.core._db.in_transaction or not all(getattr(lock,'_is_owned',lambda:False)() for lock in
                (self.core._lock,self.fences.deletion._lock,self.fences.execution._lock)):
            raise AuthorityUnavailable("actual existing writer locks without Core SQL required")
        journal=self.fences.execution;head,rows=journal._scan_locked();verified={}
        if len(rows)>self.maximum_originals:raise AuthorityUnavailable("reconciliation original bound exceeded")
        from .d04_numeric_journal_v3 import ENTRY_PREFIX
        from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3
        from .d04_series_journal_v1 import ENTRY_PREFIX as SERIES_PREFIX
        for row in rows:
            if row[4].startswith(SERIES_PREFIX):
                service=self.core._execution_redaction_d04_series_services_v1.get(self.namespace)
                if service is None:raise AuthorityUnavailable("actual series original verifier absent")
                verified[row[0]]=service.verify_series_journal_row_v1(journal,row)
            elif row[4].startswith(ENTRY_PREFIX):
                service=self.core._execution_redaction_d04_numeric_services_v3.get(self.namespace)
                if service is None:raise AuthorityUnavailable("actual numeric original verifier absent")
                verified[row[0]]=service.verify_numeric_journal_row_v3(journal,row)
            elif row[4].startswith(ROOT_ENTRY_PREFIX_V3):
                service=self.core._execution_redaction_d04_root_services_v3.get(self.namespace)
                if service is None:raise AuthorityUnavailable("actual root original verifier absent")
                verified[row[0]]=service.verify_root_journal_row_v3(journal,row)
        from .d11_life_journal_v1 import ENTRY_PREFIX as LIFE_PREFIX
        from .d11_offline_tick_journal_v1 import ENTRY_PREFIX as OFFLINE_PREFIX
        for prefix,registry,method in ((LIFE_PREFIX,self.core._execution_redaction_d11_life_services_v1,"verify_life_journal_row_v1"),
                (OFFLINE_PREFIX,self.core._execution_redaction_d11_offline_services_v1,"verify_offline_tick_journal_row_v1")):
            for row in rows:
                if row[4].startswith(prefix):
                    service=registry.get(self.namespace)
                    if service is None: raise AuthorityUnavailable("actual bounded execution migration verifier absent")
                    verified[row[0]]=getattr(service,method)(journal,row)
        internal=tuple(row for row in rows if row[4].startswith(b'{"binding":'))
        self.core._verify_execution_redaction_c04_rows(journal,internal,journal_id=head.journal_id)
        verified.update({row[0]:True for row in internal})
        models={}
        present=self.core._db.execute("SELECT 1 FROM sqlite_master WHERE name='authority_c09_consumed_execution_v1'").fetchone()
        consumed=() if present is None else tuple(row[0] for row in self.core._db.execute("SELECT item_id FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind='model_call' ORDER BY item_id",(self.namespace,)))
        if consumed:
            reader=getattr(self.core,'_c09_storage_reader_v1',None)
            if reader is None:raise AuthorityUnavailable('consumed model current storage reader absent')
            context=reader.read_verified_current_storage_v1();context.require_current('accounting')
            from .c09_model_budget_original_v1 import read_authenticated_model_budget_original_in_tx_v1
            with self.core._tx() as db:
                for call in consumed:
                    models[call]=read_authenticated_model_budget_original_in_tx_v1(db,namespace=self.namespace,call_id=call,context=context)
                    if models[call] is None:raise AuthorityUnavailable('consumed model actual current original absent')
        handle=object()
        self._backup_rows=(handle,head,tuple(rows),verified,models)
        return handle

    def read_namespace_constraints_under_writer_locks_v1(self,*,db,target_db,namespace_id,deletion_head,execution_head,authenticated_rows):
        if (db is not self.core._db or db.in_transaction or not target_db.in_transaction
                or not all(getattr(lock,'_is_owned',lambda:False)() for lock in
                    (self.core._lock,self.fences.deletion._lock,self.fences.execution._lock))):
            raise AuthorityUnavailable("actual exclusive writers and Graph-only snapshot required")
        saved=getattr(self,'_backup_rows',None)
        actual,rows=self.fences.execution._scan_locked()
        if saved is None or saved[0] is not authenticated_rows or saved[1]!=execution_head or actual!=saved[1] or tuple(rows)!=saved[2]:
            raise AuthorityUnavailable("actual authenticated independent row observation expired")
        return self._project_namespace_constraints_v1(db=db,target_db=target_db,namespace_id=namespace_id,
            deletion_head=deletion_head,execution_head=execution_head,verified_rows=saved[3],verified_models=saved[4])

    def read_namespace_constraints_in_authority_tx_v1(self, *, db, target_db,
            namespace_id, deletion_head, execution_head, qualified_context=None):
        if (db is not self.core._db or not db.in_transaction or not target_db.in_transaction
                or type(namespace_id) is not NamespaceId):
            raise AuthorityUnavailable("existing Core/Graph transactions and typed namespace required")
        return self._project_namespace_constraints_v1(db=db,target_db=target_db,namespace_id=namespace_id,
            deletion_head=deletion_head,execution_head=execution_head,qualified_context=qualified_context)

    def _project_namespace_constraints_v1(self,*,db,target_db,namespace_id,deletion_head,execution_head,verified_rows=None,verified_models=None,qualified_context=None):
        # Complete namespace inventory retains D10 quotas, D02 reservations,
        # costs and every old call/effect/job identity, not selected happy rows.
        inventory = _inventory(target_db, namespace_id)
        retained = tuple(item for item in inventory if item[0] not in
                         {"graph_recovery_metadata_v2", "graph_migration_import_receipts_v1"})
        journal = self.fences.execution
        verified_head, rows = journal._scan_locked()
        if verified_head != execution_head:
            raise AuthorityUnavailable("independent execution head changed")
        if len(rows) > self.maximum_originals:
            raise AuthorityUnavailable("execution inventory exceeds installed migration bound")
        effects, internal, numeric, root_cpu, series_cpu, bounded_cpu, constraints, originals = {}, {}, {}, {}, {}, {}, [], []
        for row in rows:
            body = json.loads(row[4])
            from .d11_life_journal_v1 import ENTRY_PREFIX as LIFE_PREFIX
            from .d11_offline_tick_journal_v1 import ENTRY_PREFIX as OFFLINE_PREFIX
            family = "life" if row[4].startswith(LIFE_PREFIX) else "offline_tick" if row[4].startswith(OFFLINE_PREFIX) else None
            if family is not None:
                registry,method = (self.core._execution_redaction_d11_life_services_v1,"verify_life_journal_row_v1") if family=="life" else (self.core._execution_redaction_d11_offline_services_v1,"verify_offline_tick_journal_row_v1")
                verifier=registry.get(self.namespace)
                if verifier is None: raise AuthorityUnavailable("actual bounded migration family verifier absent")
                authenticated=getattr(verifier,method)(journal,row) if verified_rows is None else verified_rows.get(row[0])
                if authenticated is None: raise AuthorityUnavailable("bounded migration row was not authenticated")
                binding,claim,terminal=authenticated
                if binding.namespace!=namespace_id or binding.authority_namespace!=self.namespace: raise AuthorityUnavailable("bounded execution migration crossed namespace")
                bounded_cpu[(family,binding.execution_id)]=(verifier,binding,claim,terminal)
                originals.append((row[0],row[1],row[6]))
                continue
            from .d04_series_journal_v1 import ENTRY_PREFIX as SERIES_PREFIX, decode_series_row_v1
            if row[4].startswith(SERIES_PREFIX):
                binding, claim, measurement = decode_series_row_v1(journal, row)
                verifier = self.core._execution_redaction_d04_series_services_v1.get(self.namespace)
                if verifier is None:
                    raise AuthorityUnavailable("installed series migration verifier unavailable")
                if verified_rows is None:
                    authenticated = verifier.verify_series_journal_row_v1(journal, row)
                else:
                    authenticated = verified_rows.get(row[0])
                if authenticated is None or authenticated[:2] != (binding, claim):
                    raise AuthorityUnavailable("series row lacks its actual installed signature qualification")
                series_cpu[binding.numeric.execution_id] = (binding, claim, measurement, authenticated[2])
                originals.append((row[0], row[1], row[6]))
                continue
            from .d04_numeric_journal_v3 import ENTRY_PREFIX, decode_numeric_row_v3, numeric_cost_closure_basis_v3
            if row[4].startswith(ENTRY_PREFIX):
                binding, claim, measurement = decode_numeric_row_v3(journal, row)
                verifier = self.core._execution_redaction_d04_numeric_services_v3.get(self.namespace)
                if verifier is None:
                    raise AuthorityUnavailable("installed numeric migration verifier unavailable")
                if verified_rows is None:verifier.verify_numeric_journal_row_v3(journal, row)
                elif row[0] not in verified_rows:raise AuthorityUnavailable("numeric row was not independently authenticated")
                numeric[binding.execution_id] = (binding, claim, measurement, numeric_cost_closure_basis_v3(row))
                originals.append((row[0], row[1], row[6]))
                continue
            from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3,decode_root_execution_row_v3,root_cost_closure_basis_v3
            if row[4].startswith(ROOT_ENTRY_PREFIX_V3):
                binding,claim,measurement=decode_root_execution_row_v3(journal,row)
                verifier=self.core._execution_redaction_d04_root_services_v3.get(self.namespace)
                if verifier is None:raise AuthorityUnavailable("installed authored-root migration verifier unavailable")
                _,_,terminal=(verifier.verify_root_journal_row_v3(journal,row) if verified_rows is None else verified_rows[row[0]])
                root_cpu[binding.execution_id]=(binding,claim,measurement,terminal,root_cost_closure_basis_v3(row))
                originals.append((row[0],row[1],row[6]))
                continue
            if body.get("schema", "").startswith("sylanne3.internal_work.journal_entry."):
                if verified_rows is not None and row[0] not in verified_rows:raise AuthorityUnavailable("internal row lacks its actual installed signature qualification")
                binding, claim, terminal = journal._decode_internal_row(row)
                internal[binding.binding_digest] = (binding, claim, terminal)
                originals.append((row[0], row[1], row[6]))
                continue
            pending = decode_bytes(row[4])
            if pending.permit.namespace != self.namespace:
                raise AuthorityUnavailable("execution original crosses namespace")
            mutation = db.execute("SELECT state,pending,receipt,footprint FROM authority_v2_mutations WHERE mutation_id=? AND namespace=?",
                                  (pending.mutation_id, self.namespace)).fetchone()
            if mutation is None or mutation[0] != "committed" or mutation[1] != canonical_bytes(pending) or mutation[2] is None or mutation[3] is None:
                raise AuthorityUnavailable("execution append lacks original committed footprint")
            effects[pending.permit.effect_id] = (pending, row[0], row[6], mutation)
            originals.append((row[0], row[1], row[6], sha256(mutation[3]).hexdigest()))
        effect_rows = db.execute("SELECT effect_id,state,conflict_keys_json,execution_seq FROM authority_effects WHERE namespace=? ORDER BY effect_id",
                                 (self.namespace,)).fetchall()
        if {row[0] for row in effect_rows} != set(effects):
            raise AuthorityUnavailable("current effect inventory differs from independent chain")
        for effect_id, state, conflicts, sequence in effect_rows:
            pending, latest_sequence, chain_digest, mutation = effects[effect_id]
            if state != "unresolved" or sequence != latest_sequence:
                raise AuthorityUnavailable("effect conflict/recovery state differs")
            # Retaining Core's unresolved row preserves all conflict/quota gates.
            # No content, execution permission or successful outcome is issued.
            constraints.append(("effect", effect_id, pending.phase,
                _digest((state, json.loads(conflicts), sequence, chain_digest,
                         sha256(mutation[3]).hexdigest()))))
        model_table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_model_egress_v1'").fetchone()
        calls = [] if model_table is None else db.execute("SELECT call_id FROM authority_model_egress_v1 WHERE namespace=? ORDER BY call_id", (self.namespace,)).fetchall()
        if len(calls) + len(rows) > self.maximum_originals:
            raise AuthorityUnavailable("model inventory exceeds installed migration bound")
        for (call_id,) in calls:
            constraints.append(self._model_constraint(db, target_db, namespace_id, call_id,qualified_context=qualified_context,
                verified_model=None if verified_models is None else verified_models.get(call_id)))
        for binding, claim, terminal in internal.values():
            prepared = read_c04_internal_work_prepared_v1(target_db, namespace_id, binding.operation_id)
            if prepared is None or prepared.binding != binding:
                raise AuthorityUnavailable("internal execution original preparation lost")
            reservation = self._reservation(target_db, namespace_id, binding.parent_budget_lease_ref,
                prepared.budget_reservation_operation_id, binding.binding_digest)
            reserve_original = target_db.execute("SELECT receipt_json FROM runtime_budget_operations "
                "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
                (*namespace_id.as_tuple, prepared.budget_reservation_operation_id)).fetchone()
            if (reserve_original is None or sha256(reserve_original[0].encode()).hexdigest()
                    != prepared.budget_reservation_digest):
                raise AuthorityUnavailable("retained C04 reserve receipt commitment differs")
            body = target_db.execute("SELECT revision,valid,value FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
                (*namespace_id.as_tuple, binding.body_reservation_ref)).fetchone()
            if body is None or body[1] != 1 or body[0] < prepared.body_reservation_revision:
                raise AuthorityUnavailable("internal body reservation original lost")
            state = "unknown" if terminal is None else terminal.status
            cost = read_c04_cpu_cost_original_v1(target_db, namespace_id, binding.operation_id)
            if state == "unknown" and reservation[2] in {"settled", "overrun"}:
                raise AuthorityUnavailable("unknown CPU was assigned a completed bill")
            if cost is not None:
                if terminal is None or cost.binding_digest != binding.binding_digest or cost.actual_cpu_ms != terminal.actual_cpu_ms:
                    raise AuthorityUnavailable("CPU cost original differs from measured terminal")
            constraints.append(("internal", binding.execution_id, state,
                _digest({"binding": asdict(binding), "claim": asdict(claim),
                         "terminal": None if terminal is None else asdict(terminal),
                         "reservation": reservation, "body": body,
                         "cost": None if cost is None else asdict(cost)})))
        from ..runtime.d04_numeric_cost_v3 import read_d04_numeric_cost_original_v3
        from ..runtime.d04_numeric_accounting_prepared_v3 import read_numeric_accounting_prepared_v3
        for binding, claim, measurement, cost_only in numeric.values():
            verifier=self.core._execution_redaction_d04_numeric_services_v3.get(self.namespace)
            if verifier is None:raise AuthorityUnavailable("numeric actual accounting verifier unavailable")
            prepared = read_numeric_accounting_prepared_v3(target_db, namespace_id, binding.operation_id,issuer=verifier.resource_issuer)
            if prepared is None or prepared.binding != binding:
                raise AuthorityUnavailable("numeric signed accounting preparation lost during transfer")
            reservation = self._reservation(target_db, namespace_id, binding.parent_budget_lease_ref,
                binding.reservation_operation_id, binding.reservation_digest, {"cpu_ms": binding.cpu_ceiling_ms})
            cost = read_d04_numeric_cost_original_v3(target_db, namespace_id, binding.operation_id)
            if measurement is None and (cost is not None or reservation[2] in {"settled", "overrun"}):
                raise AuthorityUnavailable("unknown numeric CPU was asserted measured")
            if cost is not None and (measurement is None or cost.binding_digest != binding.digest
                    or cost.actual_cpu_ns != measurement.actual_cpu_ns
                    or cost.actual_cpu_ms != measurement.actual_cpu_ms):
                raise AuthorityUnavailable("numeric paid CPU original differs from observed measurement")
            constraints.append(("numeric", binding.execution_id,
                "unknown" if measurement is None else "measured_cost_only" if cost_only is not None else measurement.status,
                _digest({"binding": asdict(binding), "claim": asdict(claim),
                    "measurement": None if measurement is None else asdict(measurement), "cost_only_closure":cost_only,
                    "prepared_digest": prepared.prepared_digest, "reservation": reservation,
                    "cost": None if cost is None else asdict(cost)})))
        from ..runtime.d04_root_accounting_prepared_v3 import read_root_accounting_prepared_v3,decode_root_accounting_prepared_payload_v3
        from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
        for binding,claim,measurement,terminal,cost_only in root_cpu.values():
            verifier=self.core._execution_redaction_d04_root_services_v3.get(self.namespace)
            prepared=read_root_accounting_prepared_v3(target_db,namespace_id,binding.operation_id,
                resource_issuer=verifier.resource_issuer,budget_issuer=verifier.budget_issuer)
            if prepared is None or decode_root_accounting_prepared_payload_v3(prepared[0])[0]!=binding:raise AuthorityUnavailable("root signed accounting preparation lost during transfer")
            reservation=self._reservation(target_db,namespace_id,binding.parent_budget_lease_ref,
                binding.reservation_operation_id,binding.reservation_digest,{binding.cpu_dimension:binding.cpu_ceiling_ms})
            cost=read_d04_original_v3(target_db,namespace_id,"root_cost",binding.operation_id)
            if measurement is None and (cost is not None or reservation[2] in {"settled","overrun"}):raise AuthorityUnavailable("unknown root CPU was asserted measured")
            if cost is not None and (measurement is None or terminal is None or cost[0].get("binding_digest")!=binding.digest
                    or cost[0].get("terminal_digest")!=terminal.digest
                    or (cost[0].get("actual_cpu_ns"),cost[0].get("actual_cpu_ms"))!=(measurement.actual_cpu_ns,measurement.actual_cpu_ms)):
                raise AuthorityUnavailable("root paid CPU original differs from independent measured terminal")
            constraints.append(("authored_root_cpu",binding.execution_id,
                "unknown" if measurement is None else "measured_cost_only" if cost_only is not None else measurement.status,
                _digest({"binding":asdict(binding),"claim":asdict(claim),"measurement":None if measurement is None else asdict(measurement),
                    "cost_only_closure":cost_only,"prepared_digest":prepared[0]["prepared_digest"],"reservation":reservation,
                    "cost":None if cost is None else cost[0]})))
        from ..runtime.d04_series_accounting_original_v1 import (read_series_accounting_original_v1,
            read_series_cpu_cost_original_v1)
        for binding, claim, measurement, terminal in series_cpu.values():
            verifier = self.core._execution_redaction_d04_series_services_v1.get(self.namespace)
            prepared = read_series_accounting_original_v1(target_db, namespace_id,
                binding.numeric.operation_id, issuer=verifier.numeric.resource_issuer)
            if prepared is None or prepared.binding != binding:
                raise AuthorityUnavailable("series signed accounting preparation lost during transfer")
            numeric_binding = binding.numeric
            reservation = self._reservation(target_db, namespace_id, numeric_binding.parent_budget_lease_ref,
                numeric_binding.reservation_operation_id, numeric_binding.reservation_digest,
                {"cpu_ms": numeric_binding.cpu_ceiling_ms})
            cost = read_series_cpu_cost_original_v1(target_db, namespace_id, binding, terminal)
            if measurement is None and (cost is not None or reservation[2] in {"settled", "overrun"}):
                raise AuthorityUnavailable("unknown series CPU was asserted measured")
            if cost is not None and (reservation[2] not in {"settled", "overrun"}
                    or json.loads(reservation[3]) != {"cpu_ms": measurement.actual_cpu_ms}):
                raise AuthorityUnavailable("series actual cost/reservation differs from its independent terminal")
            if cost is None and reservation[2] in {"settled", "overrun"}:
                raise AuthorityUnavailable("settled series CPU lost its committed cost original")
            constraints.append(("d04_series_cpu", numeric_binding.execution_id,
                "unknown" if measurement is None else measurement.status,
                _digest({"binding": asdict(binding), "claim": asdict(claim),
                    "measurement": None if measurement is None else asdict(measurement),
                    "terminal_digest": None if terminal is None else terminal.digest,
                    "accounting_original_digest": prepared.digest, "reservation": reservation, "cost": cost})))
        for (family,_execution_id),(verifier,binding,claim_payload,terminal_payload) in bounded_cpu.items():
            if family=="life":
                from ..runtime.d11_life_accounting_v1 import read_life_accounting_prepared_v1
                from .d11_life_journal_v1 import read_life_rows_locked_v1
                from .c09_life_recovery_originals_v1 import _cost_original,_closed_gate
                prepared=read_life_accounting_prepared_v1(target_db,binding=binding,issuer=verifier.issuer,resource_issuer=verifier.resource_issuer)
                _,claim,terminal,_,_=read_life_rows_locked_v1(journal,binding)
            else:
                from ..runtime.d11_offline_accounting_v1 import read_offline_accounting_prepared_v1
                from .d11_offline_tick_journal_v1 import read_offline_tick_rows_locked_v1
                from .c09_offline_recovery_originals_v1 import _cost_original,_closed_gate
                prepared=read_offline_accounting_prepared_v1(target_db,binding=binding,issuer=verifier.issuer,resource_issuer=verifier.resource_issuer)
                _,claim,terminal,_,_=read_offline_tick_rows_locked_v1(journal,binding)
            if prepared is None or prepared.prepared_digest!=claim_payload.prepared_digest or claim.payload!=claim_payload or (None if terminal is None else terminal.payload)!=terminal_payload:
                raise AuthorityUnavailable("bounded execution lost exact signed preparation/claim/terminal")
            _closed_gate(db,binding,"claim",claim)
            if terminal is not None: _closed_gate(db,binding,"terminal",terminal)
            reservation=self._reservation(target_db,namespace_id,binding.parent_budget_lease_ref,binding.reservation_operation_id,binding.reservation_digest,{"thread_cpu_ms":binding.cpu_ceiling_ms})
            settle=target_db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",(*namespace_id.as_tuple,binding.reservation_operation_id)).fetchone()
            cost=None
            if settle is not None:
                if terminal is None: raise AuthorityUnavailable("unmeasured bounded claim cannot settle")
                cost=_cost_original(target_db,binding,terminal,verifier)
            elif reservation[2]!="reserved": raise AuthorityUnavailable("unsettled bounded terminal lost its reserved occupancy")
            constraints.append((family,binding.execution_id,"claimed" if terminal is None else terminal.status,
                _digest({"binding":asdict(binding),"claim":asdict(claim),"terminal":None if terminal is None else asdict(terminal),
                    "accounting_prepared":asdict(prepared),"reservation":reservation,"cost":None if cost is None else asdict(cost)})))
        values = dict(namespace=namespace_id, authority_namespace=self.namespace,
            retained_graph_digest=_hash(retained), deletion_head_digest=_digest(asdict(deletion_head)),
            execution_head_digest=_digest(asdict(execution_head)),
            authority_originals_digest=_digest(originals), constraints=tuple(sorted(constraints)))
        return NamespaceExecutionReconciliationV1(**values, original_digest=_digest(values))


class InstalledMigrationReconciliationV1(InstalledNamespaceExecutionReconciliationV1):
    """One pinned Authority, model ledger, mixed journal and graph inventory.

read_current_constraints_v1(target_db,plan,permit) executes an authenticated
Authority-current read without granting target content access. During final
activation, read_constraints_in_authority_tx_v1 consumes the service's already
frozen independent heads and Core transaction. Thus a stale caller digest can
never stand in for a current reconciliation read.
"""
    def __init__(self, *, authority: AuthorityV2MigrationService, credential,
                 subject: str, model_store: AuthorityV2ModelEgressStore | None,
                 maximum_originals: int = 100_000):
        if type(authority) is not AuthorityV2MigrationService or not subject:
            raise ValueError("installed migration Authority identity required")
        if (model_store is not None and (type(model_store) is not AuthorityV2ModelEgressStore
                or model_store._db is not authority.core._db)):
            raise ValueError("model ledger must belong to the same Authority Core")
        if type(maximum_originals) is not int or not 1 <= maximum_originals <= 1_000_000:
            raise ValueError("bounded reconciliation inventory required")
        super().__init__(fences=authority.fences, model_store=model_store, maximum_originals=maximum_originals)
        self.authority, self.credential, self.subject = authority, credential, subject

    def read_current_constraints_v1(self, *, target_db, plan, permit):
        self.authority.core._require(self.credential, "migration_recover", plan.namespace)
        with self.authority.fences._frozen() as (db, deletion, execution, history):
            if history:
                self.authority.core.require_current_content_ready_locked(db, namespace=plan.namespace)
            return self.read_constraints_in_authority_tx_v1(
                db=db, target_db=target_db, plan=plan, permit=permit,
                deletion_head=deletion, execution_head=execution)

    def read_constraints_in_authority_tx_v1(self, *, db, target_db, plan, permit,
                                           deletion_head, execution_head):
        authority = self.authority
        if (db is not authority.core._db or not db.in_transaction or not target_db.in_transaction
                or permit.kind != "target_recovery" or plan.namespace != authority.namespace):
            raise AuthorityUnavailable("current Authority and target transactions required")
        status = authority._status_locked(db, deletion_head, execution_head, plan.transfer_id)
        if status is None or status.phase != "target_prepared" or status.plan != plan or status.target_permit != permit:
            raise AuthorityUnavailable("original target recovery phase differs")
        if status.source_snapshot is None:
            raise AuthorityUnavailable("independent original source snapshot absent")
        projection = self.read_namespace_constraints_in_authority_tx_v1(db=db,
            target_db=target_db, namespace_id=plan.namespace_id,
            deletion_head=deletion_head, execution_head=execution_head)
        values = dict(transfer_id=plan.transfer_id, authority_namespace=plan.namespace,
            target_generation=permit.generation, source_snapshot_digest=status.source_snapshot.snapshot_digest,
            retained_graph_digest=projection.retained_graph_digest,
            deletion_head_digest=projection.deletion_head_digest,
            execution_head_digest=projection.execution_head_digest,
            authority_originals_digest=projection.authority_originals_digest,
            constraints=projection.constraints)
        return MigrationReconciliationOriginalV1(**values, original_digest=_digest(values))


__all__ = ("InstalledMigrationReconciliationV1", "MigrationReconciliationOriginalV1",
           "InstalledNamespaceExecutionReconciliationV1", "NamespaceExecutionReconciliationV1")
