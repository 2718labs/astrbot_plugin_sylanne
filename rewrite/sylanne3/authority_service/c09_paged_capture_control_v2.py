"""Installed C09 V2 capture scope and same-operation session admission.

The public entry takes only an operation identifier.  Typed capture values and
batch ceilings never confer Owner, Source, Control or filesystem permission.
"""
from __future__ import annotations

from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3

from dataclasses import asdict, dataclass
from contextlib import contextmanager
from time import monotonic_ns

from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
from .contract import AuthorityUnavailable, identifier
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.c09_paged_capture_contract_v2 import (
    C09CaptureScopeV2, PROFILE_INPUT_SHA256_V2, MAX_DESCRIPTOR_BYTES_V2,
)
from ..runtime.c09_paged_sql_v2 import C09BatchBudgetV2

_PROFILE_ID = "small-host-2c2gb-v3-c09-capture"
_SESSION = object()


@dataclass(frozen=True, slots=True)
class InstalledC09CaptureProfileV2:
    profile_id: str = _PROFILE_ID
    input_sha256: str = PROFILE_INPUT_SHA256_V2
    batch_records: int = 100
    batch_bytes: int = 262144
    batch_local_ns: int = 25000000
    read_transaction_ns: int = 250000000
    arena_bytes: int = 8388608
    managed_disk_bytes: int = 4294967296
    control_effect_fee_reserve_bytes: int = 268435456
    schema: str = "sylanne3.c09.installed-capture-profile.v2"

    def __post_init__(self):
        expected = (_PROFILE_ID, PROFILE_INPUT_SHA256_V2, 100, 262144, 25000000,
                    250000000, 8388608, 4294967296, 268435456,
                    "sylanne3.c09.installed-capture-profile.v2")
        if tuple(asdict(self).values()) != expected:
            raise AuthorityUnavailable("C09 capture profile differs from the approved finite v3 inputs")

    @property
    def digest(self):
        return canonical_digest(self)


class C09PagedCaptureSessionV2:
    __slots__ = ("_issuer", "_control", "scope", "_closed", "_source_parser_arena_v3", "_d13_runtime_cursor_v3", "_post_mirror_graph_v3", "__weakref__")

    def __init__(self, token, control, scope):
        if token is not _SESSION or type(scope) is not C09CaptureScopeV2:
            raise AuthorityUnavailable("actual installed C09 capture session required")
        self._issuer, self._control, self.scope, self._closed = token, control, scope, False
        import weakref
        self._source_parser_arena_v3=weakref.WeakSet()
        self._d13_runtime_cursor_v3=None;self._post_mirror_graph_v3=None
        control.maintenance.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        return 1024+sum(state._source_heap_bytes() for state in self._source_parser_arena_v3)

    def require_current(self):
        if self._closed:
            raise AuthorityUnavailable("C09 capture session closed")
        self._control.require_session(self)
        return self.scope

    @contextmanager
    def reserve_batch(self):
        self.require_current()
        with self._control.reserve_batch(self) as budget:
            yield budget
        self.require_current()

    def require_segmented_storage_transition_v1(self):
        """Protected format plan at this actual accepted source/freeze, not selection."""
        self.require_current()
        from ..segmented_sql_cell_v1 import TRANSITION_SCHEMA,LAYOUTS,LAYOUT_SCHEMA_DIGEST
        original=self._control.maintenance.control.read_build_original_v1(
            operation_id=self.scope.operation_id,kind='segmented_storage_transition_v1')
        expected={'schema':TRANSITION_SCHEMA,'source_scope_digest':self.scope.scope_digest,
            'authority_id':self.scope.authority_id,'installation_id':self.scope.installation_id,
            'authority_namespace':self.scope.authority_namespace,'operation_id':self.scope.operation_id,
            'source_manifest_digest':self.scope.old_manifest_digest,'expected_pointer_version':self.scope.expected_pointer_version,
            'target_storage_generation':self.scope.maintenance_generation,'accepted_receipt_digest':self.scope.accepted_receipt_digest,
            'barrier_digest':self.scope.barrier_digest,'writer_freeze_digest':self.scope.writer_freeze_digest,
            'layout_schema_digest':LAYOUT_SCHEMA_DIGEST,'role_layouts':LAYOUTS}
        if original is None or original['details']!=expected:
            raise AuthorityUnavailable('actual protected segmented layout transition missing or changed')
        return expected

    def open_segmented_target_v1(self, role):
        self.require_current()
        from .c09_role_capture_pair_v2 import C09RolePairProgressV2
        from ..segmented_sql_cell_v1 import open_c09_segmented_target_v1
        pair=self.open_role_pair(role)
        if type(pair) is C09RolePairProgressV2:return pair
        return open_c09_segmented_target_v1(self,pair)

    def begin_segmented_census_v3(self, role):
        from .c09_segmented_census_v3 import begin_segmented_census_v3
        return begin_segmented_census_v3(self,role)

    def retain_segmented_role_complete_v3(self, sweep):
        from .c09_segmented_census_v3 import retain_segmented_role_complete_v3
        return retain_segmented_role_complete_v3(self,sweep)

    def require_installed_d13_counter_service_v1(self):
        """Return the actual installed historical verifier, never caller keys or authority."""
        self.require_current()
        from .d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
        maintenance=self._control.maintenance
        service=getattr(maintenance, "_d13_core_counter_v1", None)
        if (type(service) is not InstalledD13CoreCounterServiceV1
                or service.core is not maintenance.core
                or service.namespace != maintenance.namespace_id
                or service.bridge.namespace != maintenance.closure.namespace
                or service.policy.installation.installation_id != maintenance.control.installation_id
                or service.bridge.journal is not maintenance.closure.execution):
            raise AuthorityUnavailable("historical D13 verifier crosses actual installed Core, execution or namespace")
        return service

    def advance_d13_runtime_qualification_v3(self):
        """A separate actual reserved hash quantum, before frozen fact consumers."""
        self.require_current()
        service=getattr(self._control.maintenance,'_d13_core_counter_v1',None)
        if service is None:return True
        service=self.require_installed_d13_counter_service_v1()
        cursor=self._d13_runtime_cursor_v3
        if cursor is not None and cursor.complete:return True
        from ..runtime.c09_paged_sql_v2 import C09SqlByteMeterV2,c09_sql_meter_quantum_v2
        try:
            with self.reserve_batch() as budget:
                meter=require_c09_reserved_meter_v3(budget)
                with c09_sql_meter_quantum_v2(meter):
                    if cursor is None:
                        cursor=service._installed_runtime.begin_c09_runtime_check_v1(self,meter)
                        self._d13_runtime_cursor_v3=cursor
                    cursor.advance(meter)
            cursor._adopt_completed_quantum_v1(self)
        except BaseException:
            if cursor is not None:cursor.close()
            self._d13_runtime_cursor_v3=None;raise
        return False

    def require_d13_runtime_qualification_v3(self,service,meter):
        if service is not self.require_installed_d13_counter_service_v1():
            raise AuthorityUnavailable('C09 D13 runtime qualification crossed actual service')
        cursor=self._d13_runtime_cursor_v3
        if cursor is None:raise AuthorityUnavailable('actual D13 bounded runtime qualification is incomplete')
        try:
            return service._installed_runtime.require_current(service.worker,qualification=cursor,session=self,meter=meter)
        except BaseException:
            cursor.close();self._d13_runtime_cursor_v3=None;raise

    def retain_actual_post_mirror_graph_v3(self,verified):
        """Take ownership only of the real current post-mirror cold completion."""
        from ..runtime.c09_graph_rebase_candidate_v2 import VerifiedGraphRebaseColdV2
        if type(verified) is not VerifiedGraphRebaseColdV2 or verified.session is not self:
            raise AuthorityUnavailable('actual same-session private post-mirror Graph required')
        candidate=verified.require_current()
        completion=self._control.require_graph_rebase_completion_v2(self)
        if (verified.cold_phase!='post_mirror' or candidate.scope!=self.scope
                or verified.issued_digest!=completion.graph_issue_digest):
            raise AuthorityUnavailable('post-mirror Graph handle crossed actual completed issue/scope')
        previous=self._post_mirror_graph_v3
        if previous is verified:return
        self._post_mirror_graph_v3=verified
        if previous is not None:previous.close()

    def require_actual_post_mirror_graph_v3(self):
        self.require_current()
        from ..runtime.c09_graph_rebase_candidate_v2 import VerifiedGraphRebaseColdV2
        verified=self._post_mirror_graph_v3
        if type(verified) is not VerifiedGraphRebaseColdV2 or verified.session is not self:
            raise AuthorityUnavailable('actual post-mirror cold completion must be rerun after restart')
        candidate=verified.require_current()
        completion=self._control.require_graph_rebase_completion_v2(self)
        if (verified.cold_phase!='post_mirror' or candidate.scope!=self.scope
                or verified.issued_digest!=completion.graph_issue_digest):
            raise AuthorityUnavailable('retained Graph cold handle lost current issue/scope')
        return verified

    def require_fact_original_verifier_v2(self, kind, *, core_db, business_db,
                                         execution_reader, algorithm=None):
        self.require_current()
        m = self._control.maintenance
        from .deployment_config import AuthorityDeploymentConfig
        from .c09_execution_connection_v1 import C09ExecutionOriginalsConnectionV1
        from .c09_installed_original_verifiers_v1 import InstalledC09OriginalVerifierV1
        config = getattr(m, "_installed_deployment_config_v2", None)
        if (type(config) is not AuthorityDeploymentConfig
                or type(execution_reader) is not C09ExecutionOriginalsConnectionV1
                or not core_db.in_transaction or not business_db.in_transaction):
            raise AuthorityUnavailable("actual installed passive original verifier composition required")
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        meter = current_c09_sql_meter_v2()
        if meter is None:
            raise AuthorityUnavailable("C09 passive original verifier requires the actual reserved I/O meter")
        current = m.control.read_verified_current_storage_v2(meter=meter, verify_files=False)
        paths = {member["role"]: member["resolved_path"] for member in current.manifest["members"]}
        for db, role in ((core_db, "core"), (business_db, "graph")):
            if db.execute("PRAGMA database_list").fetchone()[2] != paths[role]:
                raise AuthorityUnavailable("C09 passive original verifier crosses the actual current source")
        if (execution_reader.namespace != m.closure.namespace
                or str(execution_reader.path) != paths["execution"]
                or execution_reader._db.execute("PRAGMA database_list").fetchone()[2] != paths["execution"]):
            raise AuthorityUnavailable("C09 passive original verifier crosses namespace or current execution source")
        if kind=='internal' and algorithm=='d13.full_http_counter.v1':
            from .c09_installed_original_verifiers_v1 import InstalledC09D13OriginalVerifierV1
            return InstalledC09D13OriginalVerifierV1(self,execution_reader)
        return InstalledC09OriginalVerifierV1(config=config, control=m.control,
            core_db=core_db, business_db=business_db, execution_reader=execution_reader,
            kind=kind, algorithm=algorithm)

    def read_finished_foreground_graph_original_v2(self, pair, row, *, meter):
        """Join one real frozen Graph occurrence to its actual selected Core fence."""
        from contextlib import closing
        from pathlib import Path
        import sqlite3
        from time import monotonic_ns
        from .c09_role_capture_pair_v2 import InstalledC09RolePairV2
        from .c09_paged_recovery_facts_v2 import (
            _BoundedReadConnectionV2, read_foreground_attempt_original_row_v2)
        from ..runtime.c09_foreground_attempt_v1 import require_foreground_core_finished_v1
        self.require_current()
        if (type(pair) is not InstalledC09RolePairV2 or pair.source_original.role != "graph"
                or pair.source_original.scope_digest != self.scope.scope_digest):
            raise AuthorityUnavailable("actual registered Graph source occurrence required")
        producer = self._control._role_pairs.get("graph")
        if producer is None or producer.pair is not pair:
            raise AuthorityUnavailable("foreground Graph source is not this installed pair")
        pair.require_current()
        if not pair.source.in_transaction:
            raise AuthorityUnavailable("foreground original requires its actual short Graph source snapshot")
        original = read_foreground_attempt_original_row_v2(_BoundedReadConnectionV2(pair.source,meter),row,meter=meter)
        m = self._control.maintenance
        if (original.namespace != m.namespace_id or original.permit.namespace != self.scope.authority_namespace
                or original.permit.authority_id != self.scope.authority_id):
            raise AuthorityUnavailable("foreground original crosses the installed namespace")
        current, _ = self._control._current(self.scope.operation_id)
        member = next(item for item in current.manifest["members"] if item["role"] == "core")
        m.control.verify_member_v1(member,prepared=False)
        path = Path(member["resolved_path"])
        closed = m._closed_connection_originals_v3.get(id(m.core))
        immutable = closed is not None and closed[0] is m.core
        if immutable and (Path(closed[2]["path"]).resolve(strict=True) != path.resolve(strict=True)
                or any(Path(str(path)+suffix).exists() for suffix in ("-wal","-shm","-journal"))):
            raise AuthorityUnavailable("foreground closed Core source differs from actual completion")
        started=monotonic_ns()
        with closing(sqlite3.connect(path.as_uri()+"?mode=ro"+("&immutable=1" if immutable else ""),uri=True)) as db:
            db.execute("PRAGMA query_only=ON");db.execute("BEGIN")
            require_foreground_core_finished_v1(_BoundedReadConnectionV2(db,meter),original)
            db.rollback()
        if monotonic_ns()-started>self._control.profile.read_transaction_ns:
            raise AuthorityUnavailable("foreground actual Core source read exceeded its installed quantum")
        m.control.verify_member_v1(member,prepared=False)
        pair.require_current();self.require_current()
        return original

    @contextmanager
    def graph_closure_verification_transaction_v2(self, progress, *, budget, meter):
        """Actual protected work index for an independent fresh cold traversal."""
        from ..runtime.c09_graph_rebase_candidate_v2 import (
            GraphRebaseColdProgressV2, _SWEEP, CLOSURE_VERIFICATION_CONTROL_DDLS_V2,
            CLOSURE_VERIFICATION_CONTROL_INDEXES_V2, CLOSURE_VERIFICATION_CONTROL_TRIGGERS_V2)
        self.require_current()
        producer=self._control._role_pairs.get("graph")
        if (type(progress) is not GraphRebaseColdProgressV2 or progress._issuer is not _SWEEP
                or progress.session is not self or producer is None or producer.pair is not progress.pair
                or progress.candidate.scope!=self.scope
                or meter.budget is not budget):
            raise AuthorityUnavailable("actual same-session private cold verification progress required")
        if (type(progress.verification_run_id) is not str or len(progress.verification_run_id)!=32
                or any(c not in "0123456789abcdef" for c in progress.verification_run_id)):
            raise AuthorityUnavailable("actual private cold verification run identity required")
        progress.pair.require_current()
        control=self._control.maintenance.control
        with control._db(write=True) as db:
            control._current(db)
            objects=(("table",name,ddl) for name,ddl in CLOSURE_VERIFICATION_CONTROL_DDLS_V2.items())
            for kind,name,ddl in objects:
                row=db.execute("SELECT sql FROM sqlite_master WHERE type=? AND name=?",(kind,name)).fetchone()
                if row is None:
                    meter.charge_write(len(ddl.encode("utf-8")));db.execute(ddl)
                elif row[0]!=ddl:
                    raise AuthorityUnavailable("registered Control cold verification schema differs")
            for kind,values in (("index",CLOSURE_VERIFICATION_CONTROL_INDEXES_V2),("trigger",CLOSURE_VERIFICATION_CONTROL_TRIGGERS_V2)):
                for ddl in values:
                    name=ddl.split()[2]
                    row=db.execute("SELECT sql FROM sqlite_master WHERE type=? AND name=?",(kind,name)).fetchone()
                    if row is None:
                        meter.charge_write(len(ddl.encode("utf-8")));db.execute(ddl)
                    elif row[0]!=ddl:
                        raise AuthorityUnavailable("registered Control cold verification object differs")
            yield db
        progress.pair.require_current();self.require_current()

    def require_historical_capture_scope_v2(self, historical_scope_digest):
        from .c09_historical_capture_scope_v2 import require_historical_capture_scope_v2
        return require_historical_capture_scope_v2(self, historical_scope_digest)

    def require_historical_graph_issue_v2(self, schema, operation_id, certificate_digest):
        from .c09_graph_rebase_issue_v2 import require_historical_graph_issue_v2
        return require_historical_graph_issue_v2(self, schema, operation_id, certificate_digest)

    def get_c09_domain_original_issuer_v2(self):
        """Return only the genuine same-installation domain signature issuer."""
        self.require_current()
        from ..runtime.issuers import D11BudgetJobIssuer, D02ResourceIssuer
        m = self._control.maintenance
        issuer = getattr(m, "_installed_d11_budget_job_issuer_v2", None)
        resource = getattr(m, "_installed_d02_resource_issuer_v2", None)
        if (type(issuer) is not D11BudgetJobIssuer or type(resource) is not D02ResourceIssuer
                or issuer.resource_issuer is not resource):
            raise AuthorityUnavailable("actual installed D11/D02 domain original issuer absent")
        return issuer

    def require_recovery_facts_v2(self, pair):
        self.require_current()
        from .c09_paged_recovery_facts_v2 import mint_installed_recovery_facts_resolver_v2
        return mint_installed_recovery_facts_resolver_v2(self, pair)

    def require_authority_role_basis_v2(self, pair):
        self.require_current()
        from .c09_paged_recovery_facts_v2 import mint_installed_authority_role_basis_v2
        return mint_installed_authority_role_basis_v2(self, pair)

    def begin_source_physical_read_v3(self, pair, *, meter):
        from .c09_source_physical_read_v3 import begin_source_physical_read_v3
        return begin_source_physical_read_v3(self, pair, meter=meter)

    def open_role_pair(self, role):
        self.require_current()
        from .c09_role_capture_pair_v2 import open_current_c09_role_pair_v2
        return open_current_c09_role_pair_v2(self, role)

    def close_completed_authority_sources_v2(self):
        self.require_current()
        from .c09_role_capture_pair_v2 import close_completed_c09_authority_sources_v2
        return close_completed_c09_authority_sources_v2(self)

    def close(self):
        if self._closed:
            return
        from .c09_role_capture_pair_v2 import close_current_c09_role_pairs_v2
        verified=self._post_mirror_graph_v3;self._post_mirror_graph_v3=None
        try:
            if verified is not None:verified.close()
        finally:
            try:close_current_c09_role_pairs_v2(self)
            finally:
                try:
                    cursor=self._d13_runtime_cursor_v3;self._d13_runtime_cursor_v3=None
                    if cursor is not None:cursor.close()
                finally:self._closed=True


class InstalledC09PagedCaptureControlV2:
    __slots__ = ("maintenance", "profile", "_session", "_arena", "_role_pairs", "_selected_preflight")

    def __init__(self, maintenance):
        from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
        if type(maintenance) is not InstalledC09MaintenanceV1:
            raise AuthorityUnavailable("installed C09 maintenance composition required")
        maintenance.control.lease.require_held()
        if maintenance.core._c09_maintenance_authority_v1 is None:
            raise AuthorityUnavailable("actual C09 maintenance authority required")
        self.maintenance = maintenance
        self.profile = InstalledC09CaptureProfileV2()
        self._session = None
        self._arena = maintenance.control._resource_arena_v3
        self._role_pairs = {}
        self._selected_preflight = None

    def _registered(self):
        if getattr(self.maintenance, "_paged_capture_control_v2", None) is not self:
            raise AuthorityUnavailable("C09 capture service is not this installed composition")
        self.maintenance.control.lease.require_held()
        self.maintenance.core._require(self.maintenance.credential, "delete",
                                       self.maintenance.closure.namespace)

    def _current(self, operation_id):
        self._registered()
        m = self.maintenance
        from ..runtime.c09_paged_sql_v2 import C09SqlByteMeterV2, current_c09_sql_meter_v2, c09_sql_meter_quantum_v2, C09PagedCaptureHold
        try:
            meter = current_c09_sql_meter_v2()
        except C09PagedCaptureHold:
            with m.control.reserve_control_read_v3() as budget:
                meter = require_c09_reserved_meter_v3(budget)
                with c09_sql_meter_quantum_v2(meter):
                    return self._current(operation_id)
        current = m.control.read_verified_current_storage_v2(meter=meter, verify_files=False)
        if current.stage != "INTENT":
            raise AuthorityUnavailable("C09 capture requires its actual current INTENT")
        intent = m.control.read_operation_event_v1(operation_id, "INTENT")
        if (intent["operation_id"] != operation_id
                or intent["details"]["expected_pointer_version"] != current.pointer_version
                or intent["details"]["old_manifest_digest"] != current.manifest_digest):
            raise AuthorityUnavailable("C09 capture operation, pointer or manifest changed")
        with m.control._db() as db:
            row = m.control._current(db)
            if row["active_operation_id"] != operation_id:
                raise AuthorityUnavailable("C09 capture is not the active operation")
        refusal = m.control.read_build_original_v1(operation_id=operation_id, kind="capture_resource_refusal_v2")
        if refusal is not None:
            raise AuthorityUnavailable("C09 capture preserves its first actual resource refusal")
        if tuple(sorted(intent["details"]["targets"])) != ("core", "deletion", "execution", "graph"):
            raise AuthorityUnavailable("C09 capture requires the registered four targets")
        return current, intent

    def advance_selected_prepared_preflight_v2(self):
        """Authenticate the actual selected source under its installed arena."""
        self._registered()
        from ..runtime.c09_paged_sql_v2 import C09SqlByteMeterV2, c09_sql_meter_quantum_v2
        from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
        with self.maintenance.control.reserve_control_read_v3() as budget:
            meter = require_c09_reserved_meter_v3(budget)
            with c09_sql_meter_quantum_v2(meter):
                view = getattr(self.maintenance.control, '_selected_history_read_v3', None)
                if type(view) is VerifiedSelectedHistoryReadV3:
                    view.require_current(meter=meter)
                    return dict(status='complete', generation=view.basis.manifest['generation'],
                        prepared_digest=view.basis.prepared['prepared_digest'])
                return self._advance_selected_legacy_preflight_v2(meter)

    def _advance_selected_legacy_preflight_v2(self, meter):
        from .c09_paged_recovery_facts_v2 import begin_selected_legacy_prepared_reader_v2, C09VerifiedLegacyPreparedSummaryV2
        if self._selected_preflight is None:
            from .c09_prepared_storage_v2 import read_selected_prepared_v2
            with self.maintenance.control._db() as db:
                current = self.maintenance.control._current(db)
                manifest = self.maintenance.control._read_manifest(db, current["current_manifest_digest"])
                if manifest["generation"] == 0:
                    return {"status": "complete", "generation": 0}
                selected = read_selected_prepared_v2(self.maintenance.control, db, manifest)
                if selected is not None:
                    return {"status": "complete", "generation": manifest["generation"],
                            "prepared_digest": selected["prepared_digest"]}
            self._selected_preflight = begin_selected_legacy_prepared_reader_v2(
                self.maintenance.control, meter=meter)
            if self._selected_preflight is None:
                return {"status": "complete", "generation": 0}
        summary = self._selected_preflight.advance(meter=meter)
        if summary is None:
            return {"status": "progress", "actual_meter_bytes": meter.consumed_bytes}
        if type(summary) is not C09VerifiedLegacyPreparedSummaryV2 or summary._control is not self.maintenance.control:
            raise AuthorityUnavailable("actual selected legacy PREPARED summary required")
        summary.require_current(meter=meter)
        self.maintenance.control._c09_selected_legacy_prepared_v2 = summary
        return {"status": "complete", "generation": summary["maintenance_generation"],
                "prepared_digest": summary["prepared_digest"], "actual_meter_bytes": meter.consumed_bytes}

    def begin(self, operation_id):
        identifier(operation_id, "operation_id")
        m = self.maintenance
        with m._maintenance_lock:
            current, intent = self._current(operation_id)
            from .c09_prepared_storage_v2 import install_prepared_schema_v2
            with m.control._db(write=True) as db:
                m.control._current(db)
                install_prepared_schema_v2(m.control, db)
            from .erasure_closure_inventory import CleanupRunV2, _TABLES
            with m.core._tx() as db:
                run = m.closure._read_record(db, _TABLES[1], operation_id, CleanupRunV2)
                if run is None:
                    raise AuthorityUnavailable("C09 capture requires the actual accepted cleanup run")
                accepted = m.closure._accepted_locked(db, run, m.subject)
            if (run.authority_id != m.control.authority_id
                    or run.namespace != m.closure.namespace
                    or intent["details"]["accepted_receipt_digest"] != canonical_digest(accepted)):
                raise AuthorityUnavailable("C09 capture accepted run differs from current INTENT")
            frozen = intent["details"]["quiescence_original"]
            from .c09_writer_peer_originals_v3 import require_writer_quiescence_original_v3
            require_writer_quiescence_original_v3(m.control,frozen,meter=current_c09_sql_meter_v2(),operation_id=operation_id)
            if frozen["operation_id"] != operation_id or frozen["active_writers"] != 0:
                raise AuthorityUnavailable("C09 capture writer freeze differs")
            profile = m.control.record_build_original_v1(operation_id=operation_id,
                kind="capture_profile_v2", details=asdict(self.profile))
            facts_intent = m.control.record_build_original_v1(operation_id=operation_id,
                kind="capture_facts_intent_v2", details={
                    "schema": "sylanne3.c09.capture-facts-intent.v2",
                    "namespace": m.closure.namespace, "run_digest": run.run_digest,
                    "accepted_receipt_digest": run.accepted_receipt_digest,
                    "barrier_digest": run.graph_barrier_receipt_digest,
                    "execution_anchor": [run.execution_journal_id, run.execution_seq, run.execution_digest],
                    "profile_original_digest": profile["original_digest"],
                })
            scope = C09CaptureScopeV2(
                authority_id=m.control.authority_id, installation_id=m.control.installation_id,
                authority_namespace=m.closure.namespace,
                graph_namespace=canonical_serialize(m.namespace_id.as_tuple),
                operation_id=operation_id, maintenance_generation=current.storage_generation + 1,
                old_manifest_digest=current.manifest_digest, expected_pointer_version=current.pointer_version,
                accepted_receipt_digest=run.accepted_receipt_digest,
                barrier_digest=run.graph_barrier_receipt_digest,
                writer_freeze_digest=frozen["quiescence_digest"],
                facts_pin_ref="capture_facts_intent_v2", facts_pin_intent_digest=facts_intent["original_digest"],
                profile_id=self.profile.profile_id, profile_digest=self.profile.digest,
                codec_catalogue_digest=run.registry_digest)
            original = m.control.record_build_original_v1(operation_id=operation_id,
                kind="capture_scope_v2", details=asdict(scope))
            from ..segmented_sql_cell_v1 import TRANSITION_SCHEMA,LAYOUTS,LAYOUT_SCHEMA_DIGEST
            m.control.record_build_original_v1(operation_id=operation_id,kind='segmented_storage_transition_v1',details={
                'schema':TRANSITION_SCHEMA,'source_scope_digest':scope.scope_digest,
                'authority_id':scope.authority_id,'installation_id':scope.installation_id,
                'authority_namespace':scope.authority_namespace,'operation_id':scope.operation_id,
                'source_manifest_digest':scope.old_manifest_digest,'expected_pointer_version':scope.expected_pointer_version,
                'target_storage_generation':scope.maintenance_generation,'accepted_receipt_digest':scope.accepted_receipt_digest,
                'barrier_digest':scope.barrier_digest,'writer_freeze_digest':scope.writer_freeze_digest,
                'layout_schema_digest':LAYOUT_SCHEMA_DIGEST,'role_layouts':LAYOUTS})
            if len(canonical_serialize(original).encode("utf-8")) > MAX_DESCRIPTOR_BYTES_V2:
                raise AuthorityUnavailable("C09 capture scope original exceeds the fixed descriptor bound")
            prior = self._session
            if prior is not None and not prior._closed and prior.scope.operation_id == operation_id:
                if prior.scope != scope:
                    raise AuthorityUnavailable("C09 capture scope replay differs")
                prior.require_current()
                return prior
            session = C09PagedCaptureSessionV2(_SESSION, self, scope)
            if prior is not None:
                prior.close()
            self._session = session
            return session

    def begin_selected_history_read_v2(self, *, operation_id, purpose="cleanup"):
        """Actual post-switch read, with independent resource and permission gates."""
        if purpose != "cleanup":
            raise AuthorityUnavailable("registered selected history consumer purpose required")
        self._registered()
        result = self.maintenance.control.advance_selected_history_read_v3()
        from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
        if type(result) is VerifiedSelectedHistoryReadV3:
            if result.basis.prepared["operation_id"] != operation_id:
                raise AuthorityUnavailable("actual selected history belongs to another cleanup operation")
        return result

    @contextmanager
    def reserve_selected_history_quantum_v2(self, view):
        from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
        from ..runtime.c09_paged_sql_v2 import C09SqlByteMeterV2, c09_sql_meter_quantum_v2
        self._registered()
        if type(view) is not VerifiedSelectedHistoryReadV3 or view.basis.control is not self.maintenance.control:
            raise AuthorityUnavailable("actual installed selected history session required")
        with self.maintenance.control.reserve_control_read_v3() as budget:
            meter = require_c09_reserved_meter_v3(budget)
            with c09_sql_meter_quantum_v2(meter):
                current = view.basis.require_current(meter=meter)
                if current["stage"] not in {"SWITCHED", "CLEANED"}:
                    raise AuthorityUnavailable("actual selected cleanup admission is closed")
                self.maintenance.control.require_c09_retained_arena_v3(meter=meter)
                yield meter
                self.maintenance.control.require_c09_retained_arena_v3(meter=meter)
                view.basis.require_current(meter=meter)

    def require_graph_rebase_completion_v2(self, session):
        self.require_session(session)
        from .c09_graph_rebase_issue_v2 import require_graph_rebase_completion_v2
        return require_graph_rebase_completion_v2(session)

    def require_session(self, session):
        if (type(session) is not C09PagedCaptureSessionV2 or session._issuer is not _SESSION
                or session._control is not self or session._closed
                or self._session is not session):
            raise AuthorityUnavailable("C09 session is not this actual installed operation")
        current, intent = self._current(session.scope.operation_id)
        if (current.pointer_version != session.scope.expected_pointer_version
                or current.manifest_digest != session.scope.old_manifest_digest
                or intent["details"]["quiescence_original"]["quiescence_digest"] != session.scope.writer_freeze_digest):
            raise AuthorityUnavailable("C09 capture session currentness changed")
        original = self.maintenance.control.read_build_original_v1(
            operation_id=session.scope.operation_id, kind="capture_scope_v2")
        if original is None or original["details"] != asdict(session.scope):
            raise AuthorityUnavailable("C09 capture scope original missing or changed")

    def current_source_plan_selection_v2(self, namespace):
        from .c09_source_plan_location_v2 import current_source_plan_selection_v2
        return current_source_plan_selection_v2(self, namespace)

    @contextmanager
    def reserve_source_plan_quantum_v2(self, namespace, operation_id):
        """Reserve bounded work before a barrier exists; confer no permission."""
        from ..runtime_contracts import NamespaceId
        identifier(operation_id, "operation_id")
        self._registered()
        if type(namespace) is not NamespaceId or namespace != self.maintenance.namespace_id:
            raise AuthorityUnavailable("C09 Source-plan resource reservation crosses installed namespace")
        if not self._arena.acquire(blocking=False):
            raise AuthorityUnavailable("C09 capture arena is already occupied")
        try:
            p = self.profile
            started = monotonic_ns()
            from ..runtime.c09_paged_sql_v2 import C09SqlByteMeterV2, c09_sql_meter_quantum_v2
            budget = C09BatchBudgetV2(p.batch_records, p.batch_bytes, p.batch_local_ns,
                p.read_transaction_ns, p.arena_bytes)
            meter = C09SqlByteMeterV2(budget)
            with c09_sql_meter_quantum_v2(meter):
                yield budget
                self._registered()
            if monotonic_ns() - started > p.batch_local_ns:
                raise AuthorityUnavailable("C09 Source-plan quantum exceeded its unchanged local duration")
        finally:
            self._arena.release()

    @contextmanager
    def reserve_batch(self, session):
        from ..runtime.c09_paged_sql_v2 import C09SqlByteMeterV2, c09_sql_meter_quantum_v2
        if (type(session) is not C09PagedCaptureSessionV2 or session._issuer is not _SESSION
                or session._control is not self or self._session is not session or session._closed):
            raise AuthorityUnavailable('actual registered installed capture session required')
        self._registered()
        if not self._arena.acquire(blocking=False):
            raise AuthorityUnavailable("C09 capture arena is already occupied")
        try:
            p = self.profile
            started = monotonic_ns()
            budget = C09BatchBudgetV2(p.batch_records, p.batch_bytes, p.batch_local_ns,
                p.read_transaction_ns, p.arena_bytes)
            meter = C09SqlByteMeterV2(budget)
            with c09_sql_meter_quantum_v2(meter):
                self.require_session(session)
                self.maintenance.control.require_c09_retained_arena_v3(meter=meter)
                yield budget
                self.maintenance.control.require_c09_retained_arena_v3(meter=meter)
                self.require_session(session)
            if monotonic_ns() - started > p.batch_local_ns:
                raise AuthorityUnavailable('C09 capture quantum exceeded its unchanged local duration')
        finally:
            self._arena.release()


def begin_current_c09_capture_v2(maintenance, operation_id):
    from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
    if type(maintenance) is not InstalledC09MaintenanceV1:
        raise AuthorityUnavailable("actual installed maintenance entry required")
    control = getattr(maintenance, "_paged_capture_control_v2", None)
    if control is None:
        control = InstalledC09PagedCaptureControlV2(maintenance)
        maintenance._paged_capture_control_v2 = control
    return control.begin(operation_id)
