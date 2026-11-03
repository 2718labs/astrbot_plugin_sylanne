"""Owner-admitted, paused installation maintenance for legacy inspection originals."""
from dataclasses import asdict, dataclass
import json
import threading
import time
from uuid import UUID

from .contract import AuthorityUnavailable
from .d12_lifecycle_gate_v1 import read_lifecycle_head_in_tx_v1
from ..contracts import canonical_json
from ..runtime_contracts import canonical_digest

TABLE = "authority_source_inspection_migrations_v1"
DDL = f"CREATE TABLE {TABLE}(namespace TEXT NOT NULL,operation_id TEXT NOT NULL,request_digest TEXT NOT NULL,pause_operation_id TEXT NOT NULL,owner_head TEXT NOT NULL,request_json TEXT NOT NULL,started_at REAL NOT NULL,state TEXT NOT NULL,receipt_json TEXT,accepted_digest TEXT NOT NULL,accepted_original_json TEXT NOT NULL,PRIMARY KEY(namespace,operation_id))"
COLUMNS = ("namespace","operation_id","request_digest","pause_operation_id","owner_head","request_json","started_at","state","receipt_json","accepted_digest","accepted_original_json")


def require_no_pending_source_inspection_migration_in_tx_v1(db, namespace, *, lifecycle=None, inspection_workflow_phase=None):
    if not db.in_transaction:
        raise AuthorityUnavailable("inspection migration exclusion requires the actual Core transaction")
    migration=None if lifecycle is None else getattr(lifecycle,"_source_inspection_migration_service_v1",None)
    from .source_inspection_held_reconciliation_v1 import (
        ACCEPT_SCHEMA as HELD_SCHEMA,replacement_for_operation_v1)
    from .source_inspection_workflow_v1 import TABLE as WORKFLOWS
    def replacement(operation_id):
        if type(migration) is not InstalledSourceInspectionMigrationV1:return None
        return replacement_for_operation_v1(migration,db,operation_id)
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone():
        for row in db.execute(f"SELECT operation_id FROM {TABLE} WHERE namespace=? AND state!='completed'",(namespace,)):
            if replacement(row[0]) is None:
                raise AuthorityUnavailable("accepted Source inspection maintenance must finish before Host resume")
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(WORKFLOWS,)).fetchone():
        pending=[]
        for row in db.execute(f"SELECT * FROM {WORKFLOWS} WHERE namespace=? AND state!='completed'",(namespace,)):
            if replacement(row[1]) is not None:continue
            value=json.loads(row[5])
            if value["schema"]==HELD_SCHEMA and row[6]=="held" and row[9] is None:
                if type(migration) is not InstalledSourceInspectionMigrationV1:
                    raise AuthorityUnavailable("held recovery artifact needs its actual installed verifier")
                from .source_inspection_workflow_v1 import COLUMNS as WORKFLOW_COLUMNS,validate_inspection_workflow_core_row_v1
                validate_inspection_workflow_core_row_v1(WORKFLOW_COLUMNS,row,authority_namespace=namespace)
                migration.lifecycle.control.verify_original_v1(value,"accepted_digest")
                continue
            pending.append(row)
        if pending:
            if type(migration) is not InstalledSourceInspectionMigrationV1 or migration.lifecycle is not lifecycle:
                raise AuthorityUnavailable("accepted inspection workflow owns the installation")
            migration.workflow.require_resume_exclusion_v1(db,inspection_workflow_phase,pending_rows=pending)


@dataclass(frozen=True, slots=True)
class _InspectionBatchScopeV1:
    service: object
    request: dict
    request_digest: str
    owner_head: str
    started_at: float
    accepted_digest: str
    context: object
    storage: dict
    thread_id: int

    @property
    def namespace(self):
        return self.service.lifecycle.namespace_id

    @property
    def operation_id(self):
        return self.request["operation_id"]


    def sign_member_admission_v1(self,*,producer_operation_id,target,target_head,target_header,metadata_key,parents):
        self.require_current_v1()
        from ..runtime.source_inspection_migration_v1 import MEMBER_ADMISSION_SCHEMA,validate_member_admission_v1
        from .d12_installation_lifecycle_v1 import RECEIPTS
        lifecycle=self.service.lifecycle
        work=self.service._active.get(self.operation_id)
        if work is None or work.scope is not self or work.target!=target or work.target_head!=target_head:
            raise AuthorityUnavailable("member admission must come from its actual selected maintenance Work")
        if self.request["scope_kind"]=="exact_parent_closed_targets" and target.token not in self.request["target_refs"]:
            raise AuthorityUnavailable("selected target leaves its accepted inspection subset")
        pause=lifecycle._operation(lifecycle.core._db,self.request["pause_operation_id"])
        head=read_lifecycle_head_in_tx_v1(lifecycle.core._db,lifecycle.namespace)
        receipt=lifecycle.core._db.execute(f"SELECT original_digest FROM {RECEIPTS} WHERE original_ref=?",(pause[14],)).fetchone()
        if head is None or head.state!="paused" or head.operation_id!=pause[1] or receipt is None:
            raise AuthorityUnavailable("member admission lost its actual original paused freeze")
        body=dict(schema=MEMBER_ADMISSION_SCHEMA,namespace=asdict(self.namespace),
            authority_id=lifecycle.control.authority_id,authority_namespace=lifecycle.namespace,
            installation_id=lifecycle.installation_id,control_store_id=lifecycle.control.control_store_id,
            migration_operation_id=self.operation_id,producer_operation_id=producer_operation_id,
            request_digest=self.request_digest,accepted_digest=self.accepted_digest,
            owner_head_digest=canonical_digest(self.owner_head),storage_identity_digest=canonical_digest(self.storage),
            selected_pointer_version=self.storage["pointer_version"],selected_manifest_digest=self.storage["manifest_digest"],
            selected_storage_generation=self.storage["storage_generation"],pause_operation_id=pause[1],
            paused_lifecycle_epoch=head.epoch,pause_receipt_digest=receipt[0].removeprefix("sha256:"),
            effective_deadline_utc=self.request["deadline_utc"],metadata_schema_digest=self.request["metadata_schema_digest"],
            target_ref=target.token,target_revision=target_head[0],
            target_header_digest=None if target_header is None else canonical_digest(target_header),
            metadata_ref=None if metadata_key is None else metadata_key.token,
            interpretation_status_discovery=self.request["interpretation_status_discovery"],parent_source_refs=sorted(set(parents)))
        header=work.require_target_producer_commit_header_v1()
        body.update(attestation_kind="verified_target_producer_membership_v1",
            original_target_commit_header_digest=canonical_digest(header))
        signed=lifecycle.control.sign_original_v1(MEMBER_ADMISSION_SCHEMA,body,"admission_digest")
        return validate_member_admission_v1(signed)

    def require_current_v1(self):
        service = self.service
        if (type(service) is not InstalledSourceInspectionMigrationV1 or service._issued is not self
                or self.thread_id != threading.get_ident() or not service.lifecycle.core._db.in_transaction
                or canonical_digest(self.request) != self.request_digest
                or time.time() >= self.request["deadline_utc"]):
            raise AuthorityUnavailable("actual live Owner-admitted Source inspection batch required")
        self.context.require_current("business")
        observed = service.lifecycle.supervisor.read_current_host_state_v1()
        if not observed.stopped_and_drained:
            raise AuthorityUnavailable("inspection migration lost actual stopped/drained Host")
        return self


def require_issued_source_inspection_batch_v1(scope):
    if type(scope) is not _InspectionBatchScopeV1:
        raise AuthorityUnavailable("private installed Source inspection batch required")
    return scope.require_current_v1()


class InstalledSourceInspectionMigrationV1:
    """Each call performs one bounded quantum under the current Owner session."""
    def __init__(self, *, lifecycle, package_files, registry, workflow_resource):
        from .d12_installation_lifecycle_v1 import InstalledD12InstallationLifecycleV1
        from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
        from ..graph_types import TypeRegistry
        if (type(lifecycle) is not InstalledD12InstallationLifecycleV1
                or type(package_files) is not InstalledPackageSelectionFilesV2
                or type(registry) is not TypeRegistry):
            raise TypeError("actual installed lifecycle, package files and frozen registry required")
        from ..domains.d06.inspection_metadata_v1 import inspection_metadata_type_specs_v1
        if any(registry.spec(spec.name)!=spec for spec in inspection_metadata_type_specs_v1()):
            raise AuthorityUnavailable("installed inspection metadata registry differs from its target schema")
        self.lifecycle, self.files, self.registry = lifecycle, package_files, registry.freeze()
        self._issued = None
        self._active = {}
        self._lock = threading.RLock()
        lifecycle._source_inspection_migration_service_v1 = self
        lifecycle.control._source_inspection_migration_service_v1 = self
        from .source_inspection_workflow_v1 import InstalledInspectionWorkflowV1
        self.workflow = InstalledInspectionWorkflowV1(service=self,resource_provider=workflow_resource)

    def install_schema(self, administrator_credential):
        self.lifecycle.core._require(administrator_credential, "d12_lifecycle_install", self.lifecycle.namespace)
        with self.lifecycle.core._tx() as db:
            row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone()
            if row is None:
                db.execute(DDL)
            elif row != (DDL,):
                raise AuthorityUnavailable("installed inspection migration Core schema differs")

        self.workflow.install_schema(administrator_credential)

    def _admit(self, db, context, storage, pause_id, actor, token, request):
        lifecycle = self.lifecycle
        pause = lifecycle._operation(db, pause_id)
        head = read_lifecycle_head_in_tx_v1(db, lifecycle.namespace)
        guard = lifecycle._owner_still_current(db, pause)
        lifecycle.status_service._current_session_in_tx(db, actor=actor, token=token,
            request=request, expected_head=guard.authorization_head)
        if (pause[3] != "pause" or pause[13] != "paused" or head is None
                or head.state != "paused" or head.operation_id != pause_id
                or canonical_json(storage) != pause[10] or any(lifecycle._counts(db))):
            raise AuthorityUnavailable("inspection maintenance requires the current drained pause original")
        if actor!=pause[7]:
            raise AuthorityUnavailable("inspection maintenance belongs to another initiating Owner")
        self._actual_owner_grant_v1(db,context,storage,actor=actor,session_request=request,
            required={"workbench.read","workbench.maintain","workbench.control"})
        context.require_current("business")
        return pause

    def advance_current_migration_v1(self, *, credential, actor, session_token, session_request,
            operation_id, pause_operation_id, scope_kind, target_refs, deadline_utc, interpretation_status_discovery):
        from .d12_configuration_cohort_v2 import read_verified_configuration_cohort_v2
        from ..domains.d06.inspection_metadata_v1 import inspection_metadata_type_specs_v1
        from ..graph_types import AtomKey
        from ..runtime.source_inspection_migration_v1 import SourceInspectionMigrationWorkV1
        operation = UUID(operation_id)
        if operation.version != 4 or str(operation) != operation_id:
            raise ValueError("inspection migration requires one canonical UUID4 operation")
        refs = tuple(target_refs)
        if (scope_kind not in {"exact_parent_closed_targets", "namespace_source_family"}
                or type(interpretation_status_discovery) is not bool
                or len(refs) > 32 or tuple(sorted(set(refs))) != refs
                or (scope_kind == "namespace_source_family") != (not refs)
                or type(deadline_utc) not in (int, float) or not time.time() < deadline_utc
                or deadline_utc > time.time() + 3600):
            raise ValueError("explicit bounded target closure or whole namespace family and original deadline required")
        for ref in refs:
            key = AtomKey.from_token(ref)
            if ((key.owner.bot,key.owner.persona) != self.lifecycle.namespace_id.as_tuple
                    or key.type_name not in {"memory.source","memory.interpretation"} or key.token != ref):
                raise ValueError("inspection migration target crosses its exact namespace/type scope")
        lifecycle = self.lifecycle
        lifecycle.core._require(credential, "d12_lifecycle_control", lifecycle.namespace)
        selected, cohort, configuration = self.files.read_selected_configuration_cohort_v2()
        read_verified_configuration_cohort_v2(cohort)
        specs = inspection_metadata_type_specs_v1()
        for spec in specs:
            if self.registry.spec(spec.name) != spec:
                raise AuthorityUnavailable("compiled inspection schema differs from its registered exact type")
        if (selected.installation_id != lifecycle.installation_id
                or selected.manifest_sha256 != lifecycle.expected_manifest_digest
                or configuration["host_profile"]["installation_policy"]["catalogue_hash"] != self.registry.catalogue_hash):
            raise AuthorityUnavailable("inspection maintenance requires its actual selected package/catalogue")
        context, storage = lifecycle._storage()
        if not lifecycle.supervisor.read_current_host_state_v1().stopped_and_drained:
            raise AuthorityUnavailable("inspection migration requires actual whole-Host retirement")
        request = dict(schema="sylanne.source-inspection-migration-request.v1",
            namespace=asdict(lifecycle.namespace_id), authority_namespace=lifecycle.namespace,
            installation_id=lifecycle.installation_id, operation_id=operation_id,
            pause_operation_id=pause_operation_id, actor=actor, storage=storage,
            selected_pointer=asdict(selected), cohort_digest=cohort.cohort_digest,
            catalogue_hash=self.registry.catalogue_hash,
            metadata_schema_digest=canonical_digest([(s.name,s.schema_hash) for s in specs]),
            scope_kind=scope_kind, target_refs=list(refs), deadline_utc=deadline_utc,
            interpretation_status_discovery=interpretation_status_discovery)
        request_digest = canonical_digest(request)
        if len(canonical_json(request).encode()) > 32768:
            raise ValueError("inspection migration accepted scope exceeds its fixed original bound")
        with self._lock:
            with lifecycle.fences._frozen() as (db, deletion, execution, _):
                pause = self._admit(db,context,storage,pause_operation_id,actor,session_token,session_request)
                from .source_inspection_workflow_v1 import TABLE as WORKFLOWS
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(WORKFLOWS,)).fetchone():
                    if db.execute(f"SELECT 1 FROM {WORKFLOWS} WHERE namespace=? AND (operation_id=? OR json_extract(accepted_json,'$.source_request.operation_id')=?) LIMIT 1",
                            (lifecycle.namespace,operation_id,operation_id)).fetchone():
                        raise AuthorityUnavailable("workflow-owned migration requires its actual issued fresh phase")
                row = db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=?",
                    (lifecycle.namespace,operation_id)).fetchone()
                if row is None:
                    require_no_pending_source_inspection_migration_in_tx_v1(db,lifecycle.namespace,lifecycle=lifecycle)
                    lifecycle._constraints_in_tx(db,deletion,execution,storage,qualified_context=context)
                    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_c09_consumed_execution_v1'").fetchone():
                        if db.execute("SELECT 1 FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind IN ('source_inspection_migration_operation','source_inspection_workflow_operation','d12_lifecycle_operation') AND item_id=?",
                                (lifecycle.namespace,operation_id)).fetchone():
                            raise AuthorityUnavailable("retired inspection migration cannot be replayed")
                    started_at=time.time()
                    accepted=self._sign_source_acceptance_v1(request,pause[9],started_at)
                    row = (lifecycle.namespace,operation_id,request_digest,pause_operation_id,pause[9],
                        canonical_json(request),started_at,"pending",None,accepted["accepted_digest"],canonical_json(accepted))
                    db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?,?,?,?,?)",row)
                elif row[2] != request_digest or row[4] != pause[9]:
                    raise AuthorityUnavailable("inspection retry changes its frozen Owner request")
                if row[7] == "completed":
                    return json.loads(row[8])
            # Resolve one actual metadata verification outside BOTH Core and Graph SQL.
            active=self._active.get(operation_id)
            if active is not None:
                from ..runtime.source_inspection_metadata_read_v3 import resolve_pending_inspection_metadata_core_v3
                resolve_pending_inspection_metadata_core_v3(active)
            # The accepted Core exclusion commits before any independent Graph write.
            with lifecycle.fences._frozen() as (db,deletion,execution,_):
                pause = self._admit(db,context,storage,pause_operation_id,actor,session_token,session_request)
                row = db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=?",
                    (lifecycle.namespace,operation_id)).fetchone()
                if row[2] != request_digest or row[4] != pause[9]:
                    raise AuthorityUnavailable("accepted inspection original or current Owner changed")
                lifecycle._constraints_in_tx(db,deletion,execution,storage,qualified_context=context)
                scope = _InspectionBatchScopeV1(self,request,request_digest,pause[9],row[6],row[9],
                    context,storage,threading.get_ident())
                self._issued = scope
                try:
                    work = self._active.get(operation_id)
                    if work is None:
                        work = SourceInspectionMigrationWorkV1(scope)
                        self._active[operation_id] = work
                    previous = None if row[8] is None else json.loads(row[8])
                    result = work.advance_v1(scope, previous)
                    if result.get("producer_operation_id") is not None or result["phase"] == "completed":
                        work.close_v1()
                        self._active.pop(operation_id)
                    db.execute(f"UPDATE {TABLE} SET state=?,receipt_json=? WHERE namespace=? AND operation_id=? AND request_digest=?",
                        ("completed" if result["phase"] == "completed" else "pending",canonical_json(result),
                         lifecycle.namespace,operation_id,request_digest))
                    return result
                except BaseException:
                    work = self._active.pop(operation_id,None)
                    if work is not None:
                        work.close_v1()
                    raise
                finally:
                    self._issued = None




    def advance_accepted_workflow_phase_v1(self,phase):
        from .source_inspection_workflow_v1 import _InspectionWorkflowPhaseV1
        from .source_inspection_held_reconciliation_v1 import _HeldInspectionMigrationPhaseV1
        if type(phase) not in {_InspectionWorkflowPhaseV1,_HeldInspectionMigrationPhaseV1}:
            raise AuthorityUnavailable("actual private inspection workflow migration phase required")
        phase.require_v1(self.lifecycle,"migrate")
        original=phase.original
        request=original["source_request"];operation_id=request["operation_id"]
        request_digest=canonical_digest(request)
        db=self.lifecycle.core._db
        context,storage=phase.accepted.require_current_v1(db)
        with self._lock:
            row=db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=?",
                (self.lifecycle.namespace,operation_id)).fetchone()
            if row is None:
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_c09_consumed_execution_v1'").fetchone():
                    if db.execute("SELECT 1 FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind IN ('source_inspection_migration_operation','source_inspection_workflow_operation','d12_lifecycle_operation') AND item_id=?",
                            (self.lifecycle.namespace,operation_id)).fetchone():
                        raise AuthorityUnavailable("retired workflow child migration cannot be replayed")
                allowed_parent=(original["parent_child_operation_id"]
                    if type(phase) is _HeldInspectionMigrationPhaseV1 else None)
                for pending in db.execute(f"SELECT operation_id FROM {TABLE} WHERE namespace=? AND state!='completed'",(self.lifecycle.namespace,)):
                    if pending[0]!=allowed_parent:
                        from .source_inspection_held_reconciliation_v1 import replacement_for_operation_v1
                        if replacement_for_operation_v1(self,db,pending[0]) is None:
                            raise AuthorityUnavailable("another accepted Source migration owns this installation")
                started=original["accepted_at_utc"]
                accepted=self._sign_source_acceptance_v1(request,original["owner_head"],started,original["accepted_digest"])
                row=(self.lifecycle.namespace,operation_id,request_digest,request["pause_operation_id"],
                    original["owner_head"],canonical_json(request),started,"pending",None,
                    accepted["accepted_digest"],canonical_json(accepted))
                db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?,?,?,?,?)",row)
            elif row[2]!=request_digest or row[4]!=original["owner_head"]:
                raise AuthorityUnavailable("workflow child migration changed its signed accepted request")
            accepted=json.loads(row[10]);self.lifecycle.control.verify_original_v1(accepted,"accepted_digest")
            if row[7]=="completed":return json.loads(row[8])
            scope=_InspectionBatchScopeV1(self,request,request_digest,row[4],row[6],row[9],
                context,storage,threading.get_ident())
            self._issued=scope
            try:
                work=self._active.get(operation_id)
                if work is None:
                    from ..runtime.source_inspection_migration_v1 import SourceInspectionMigrationWorkV1
                    work=SourceInspectionMigrationWorkV1(scope);self._active[operation_id]=work
                result=work.advance_v1(scope,None if row[8] is None else json.loads(row[8]))
                if result.get("producer_operation_id") is not None or result["phase"]=="completed":
                    work.close_v1();self._active.pop(operation_id)
                db.execute(f"UPDATE {TABLE} SET state=?,receipt_json=? WHERE namespace=? AND operation_id=? AND request_digest=?",
                    ("completed" if result["phase"]=="completed" else "pending",canonical_json(result),
                     self.lifecycle.namespace,operation_id,request_digest))
                return result
            except BaseException:
                work=self._active.pop(operation_id,None)
                if work is not None:work.close_v1()
                raise
            finally:self._issued=None


    def verify_member_admission_v1(self,admission):
        from ..runtime.source_inspection_migration_v1 import validate_member_admission_v1
        validate_member_admission_v1(admission)
        lifecycle=self.lifecycle
        lifecycle.control.verify_original_v1(admission,"admission_digest")
        if (admission["authority_id"]!=lifecycle.control.authority_id
                or admission["authority_namespace"]!=lifecycle.namespace
                or admission["installation_id"]!=lifecycle.installation_id
                or admission["control_store_id"]!=lifecycle.control.control_store_id
                or admission["namespace"]!=asdict(lifecycle.namespace_id)):
            raise AuthorityUnavailable("inspection signed member belongs to another installed Control")
        return dict(schema="sylanne.source-inspection-member-admission-verification.v1",
            **{name:admission[name] for name in ("authority_id","authority_namespace","installation_id",
                "control_store_id","namespace","admission_digest","migration_operation_id","producer_operation_id",
                "target_ref","target_revision","metadata_ref","metadata_schema_digest")})

    def _sign_source_acceptance_v1(self,request,owner_head,started_at,workflow_accepted_digest=None):
        return self.lifecycle.control.sign_original_v1("sylanne.source-inspection-maintenance-accepted.v1",
            dict(schema="sylanne.source-inspection-maintenance-accepted.v1",request=request,
                owner_head=owner_head,started_at=started_at,workflow_accepted_digest=workflow_accepted_digest),
            "accepted_digest")

    def _actual_owner_grant_v1(self,db,context,storage,*,actor,session_request,required):
        """Only the fixed Owner grant cell is read; no SourceALL/Body admission."""
        import sqlite3
        from pathlib import Path
        from ..graph_types import owner_grant_key,validate_owner_grant_v1
        from ..runtime_storage_v3 import (runtime_storage_operation_v3,
            runtime_storage_quantum_v3,materialize_runtime_cell_v3)
        from ..runtime.source_inspection_migration_v1 import install_source_inspection_runtime_v1
        head=self.lifecycle.status_service.tickets.current_migration_head_in_tx(
            db,authority_namespace=self.lifecycle.namespace)
        if head is None or head.state!="active":
            raise AuthorityUnavailable("inspection maintenance requires its actual current Owner grant head")
        path=next(m["resolved_path"] for m in storage["members"] if m["role"]=="graph")
        graph=sqlite3.connect(Path(path).as_uri()+"?mode=ro",uri=True,isolation_level=None)
        handle=None
        try:
            handle=install_source_inspection_runtime_v1(graph,control=self.lifecycle.control,context=context)
            with runtime_storage_operation_v3(graph,operation_id="inspection-owner:"+actor):
                with runtime_storage_quantum_v3(graph) as meter:
                    graph.execute("BEGIN")
                    try:
                        key=owner_grant_key(*self.lifecycle.namespace_id.as_tuple)
                        row=meter.read_fixed_row(graph,"graph_atoms",("revision","valid","value_cell_id"),
                            "bot=? AND persona=? AND token=?",(*self.lifecycle.namespace_id.as_tuple,key.token))
                        if row is None or row[:2]!=(head.grant_revision,1):
                            raise AuthorityUnavailable("inspection maintenance actual Owner grant head differs")
                        raw=materialize_runtime_cell_v3(graph,row[2],erasure_owner_ref=key.token)
                        grant=json.loads(raw)
                        validate_owner_grant_v1(grant)
                        if (canonical_json(grant)!=raw or "sha256:"+canonical_digest(grant)!=head.grant_digest
                                or grant["principal"]!=asdict(session_request.principal)
                                or grant["principal"]!=asdict(head.issue_operation.principal)
                                or not set(required)<=set(grant["capabilities"])
                                or grant["scope"]!="/".join(self.lifecycle.namespace_id.as_tuple)
                                or grant["state"]!="pending_authority" or "owner" not in grant["audiences"]):
                            raise AuthorityUnavailable("inspection maintenance current Owner capabilities/location differ")
                    finally:
                        graph.execute("ROLLBACK")
            return grant,head
        finally:
            if handle is not None:handle.close()
            graph.close()

    def read_current_access_v1(self,*,credential,actor,session_token,session_request):
        lifecycle=self.lifecycle
        lifecycle.core._require(credential,"d12_lifecycle_control",lifecycle.namespace)
        context,storage=lifecycle._storage()
        with lifecycle.fences._frozen() as (db,deletion,execution,_):
            guard=lifecycle.status_service.tickets._checked_current_head(db,lifecycle.namespace)
            if guard is None:raise AuthorityUnavailable("inspection Owner authorization head absent")
            lifecycle.status_service._current_session_in_tx(db,actor=actor,token=session_token,
                request=session_request,expected_head=guard.authorization_head)
            grant,head=self._actual_owner_grant_v1(db,context,storage,actor=actor,
                session_request=session_request,required={"workbench.read"})
            lifecycle_head=read_lifecycle_head_in_tx_v1(db,lifecycle.namespace)
            return dict(schema="d12.source-inspection-maintenance-access.v1",
                scope="/".join(lifecycle.namespace_id.as_tuple),installation_id=lifecycle.installation_id,
                actor=actor,owner_head=head.guard.authorization_head,capabilities=grant["capabilities"],
                purposes=grant["purposes"],audiences=grant["audiences"],
                lifecycle_head=asdict(lifecycle_head) if lifecycle_head is not None else None)

    def _view_v1(self,row):
        decoded=validate_source_inspection_migration_core_row_v1(COLUMNS,row,authority_namespace=self.lifecycle.namespace)
        request=decoded["request"]
        return dict(schema="d12.source-inspection-migration-view.v1",
            scope="/".join(self.lifecycle.namespace_id.as_tuple),installation_id=self.lifecycle.installation_id,
            operation_id=decoded["operation_id"],request_digest=decoded["request_digest"],state=decoded["state"],
            progress=decoded["receipt"],**{name:request[name] for name in (
                "pause_operation_id","scope_kind","target_refs","deadline_utc","interpretation_status_discovery")})

    def read_current_status_v1(self,*,credential,actor,session_token,session_request,operation_id):
        _uuid_v1(operation_id)
        lifecycle=self.lifecycle
        lifecycle.core._require(credential,"d12_lifecycle_control",lifecycle.namespace)
        context,storage=lifecycle._storage()
        with lifecycle.fences._frozen() as (db,deletion,execution,_):
            row=db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=?",
                (lifecycle.namespace,operation_id)).fetchone()
            if row is None:raise AuthorityUnavailable("inspection_migration_not_found")
            accepted=validate_source_inspection_migration_core_row_v1(COLUMNS,row,authority_namespace=lifecycle.namespace)
            if accepted["request"]["actor"]!=actor:
                raise AuthorityUnavailable("inspection operation belongs to another Owner actor")
            lifecycle.status_service._current_session_in_tx(db,actor=actor,token=session_token,
                request=session_request,expected_head=row[4])
            self._actual_owner_grant_v1(db,context,storage,actor=actor,session_request=session_request,
                required={"workbench.read"})
            return self._view_v1(row)

    def close(self):
        self.workflow.close()
        with self._lock:
            for work in self._active.values():
                work.close_v1()
            self._active.clear()

_REQUEST_FIELDS=frozenset({"schema","namespace","authority_namespace","installation_id","operation_id",
    "pause_operation_id","actor","storage","selected_pointer","cohort_digest","catalogue_hash",
    "metadata_schema_digest","scope_kind","target_refs","deadline_utc","interpretation_status_discovery"})
_PROGRESS_FIELDS=frozenset({"schema","operation_id","request_digest","phase","batch_index","cursor",
    "migrated","retired","local_phase"})
_RECEIPT_FIELDS=frozenset({"schema","operation_id","request_digest","producer_operation_id","batch_index",
    "phase","cursor","migrated","retired","before_stamp","after_stamp","event_digest"})


def _sha_v1(value):
    if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("inspection original digest differs")
    return value


def _uuid_v1(value):
    parsed=UUID(value)
    if parsed.version!=4 or str(parsed)!=value:
        raise ValueError("inspection accepted operation must be canonical UUID4")
    return value


def decode_source_inspection_migration_request_v1(raw,*,authority_namespace=None):
    from ..runtime_contracts import NamespaceId
    from ..graph_types import AtomKey
    from ..domains.d06.inspection_metadata_v1 import inspection_metadata_type_specs_v1
    from .d12_package_files_v2 import decode_package_selection_v2
    import math
    value=json.loads(raw)
    if (type(value) is not dict or set(value)!=_REQUEST_FIELDS or canonical_json(value)!=raw
            or value["schema"]!="sylanne.source-inspection-migration-request.v1"):
        raise ValueError("inspection accepted request has another closed schema")
    ns=NamespaceId(**value["namespace"])
    if authority_namespace is not None and value["authority_namespace"]!=authority_namespace:
        raise ValueError("inspection request crosses Authority namespace")
    for field in ("authority_namespace","installation_id","actor"):
        if type(value[field]) is not str or not value[field]:
            raise ValueError("inspection accepted identity absent")
    for field in ("operation_id","pause_operation_id"):_uuid_v1(value[field])
    for field in ("cohort_digest","catalogue_hash","metadata_schema_digest"):_sha_v1(value[field])
    specs=inspection_metadata_type_specs_v1()
    if value["metadata_schema_digest"]!=canonical_digest([(s.name,s.schema_hash) for s in specs]):
        raise ValueError("inspection original metadata schema contract differs")
    refs=value["target_refs"]
    if (value["scope_kind"] not in {"exact_parent_closed_targets","namespace_source_family"}
            or type(refs) is not list or refs!=sorted(set(refs)) or len(refs)>32
            or (value["scope_kind"]=="namespace_source_family")!=(not refs)
            or type(value["interpretation_status_discovery"]) is not bool
            or type(value["deadline_utc"]) not in (int,float) or not math.isfinite(value["deadline_utc"])):
        raise ValueError("inspection original exact scope/deadline differs")
    for ref in refs:
        key=AtomKey.from_token(ref)
        if key.token!=ref or (key.owner.bot,key.owner.persona)!=ns.as_tuple or key.type_name not in {"memory.source","memory.interpretation"}:
            raise ValueError("inspection accepted target leaves registered namespace")
    selected=decode_package_selection_v2(value["selected_pointer"])
    if selected.installation_id!=value["installation_id"]:
        raise ValueError("inspection accepted package installation differs")
    storage=value["storage"]
    if type(storage) is not dict or set(storage)!={"pointer_version","manifest_digest","storage_generation","members"}:
        raise ValueError("inspection original selected storage fields differ")
    _sha_v1(storage["manifest_digest"])
    for field in ("pointer_version","storage_generation"):
        if type(storage[field]) is not int or storage[field]<0:raise ValueError("inspection storage version differs")
    if type(storage["members"]) is not list or len(storage["members"])!=4:
        raise ValueError("inspection original storage roles differ")
    roles=set()
    for member in storage["members"]:
        if type(member) is not dict or set(member)!={"role","resolved_path","device","file_id","incarnation_or_journal_id"}:
            raise ValueError("inspection original storage member fields differ")
        roles.add(member["role"])
        for field in ("device","file_id"):
            if type(member[field]) is not int or member[field]<0:raise ValueError("inspection member identity differs")
        for field in ("resolved_path","incarnation_or_journal_id"):
            if type(member[field]) is not str or not member[field]:raise ValueError("inspection selected member absent")
    if roles!={"core","deletion","execution","graph"}:raise ValueError("inspection selected member roles differ")
    return value


def decode_source_inspection_migration_progress_v1(raw,*,operation_id,request_digest):
    value=json.loads(raw)
    fields=_PROGRESS_FIELDS if value.get("schema")=="sylanne.source-inspection-migration-progress.v1" else _RECEIPT_FIELDS
    if (type(value) is not dict or set(value)!=fields or canonical_json(value)!=raw
            or value["operation_id"]!=operation_id or value["request_digest"]!=request_digest
            or value["phase"] not in {"pending","completed"}):
        raise ValueError("inspection actual progress/receipt shape differs")
    for field in ("migrated","retired"):
        if type(value[field]) is not int or value[field]<0:raise ValueError("inspection receipt counter differs")
    if type(value["batch_index"]) is not int or value["batch_index"]<(-1 if fields==_PROGRESS_FIELDS else 0):
        raise ValueError("inspection receipt batch index differs")
    if fields==_PROGRESS_FIELDS:
        if value["phase"]!="pending" or type(value["local_phase"]) is not str:
            raise ValueError("inspection progress cannot claim completion")
    else:
        if value["schema"]!="sylanne.source-inspection-migration-receipt.v1":
            raise ValueError("inspection receipt schema differs")
        _sha_v1(value["event_digest"])
        UUID(value["producer_operation_id"])
        before,after=value["before_stamp"],value["after_stamp"]
        if (type(before) is not list or len(before)!=3 or type(after) is not list or len(after)!=3
                or after!=[before[0],before[1]+1,before[2]+1]):
            raise ValueError("inspection receipt Graph stamp transition differs")
    return value


def validate_source_inspection_migration_core_row_v1(columns,row,*,authority_namespace):
    import math
    if columns!=COLUMNS or len(row)!=len(COLUMNS) or row[0]!=authority_namespace:
        raise AuthorityUnavailable("inspection Core row columns/namespace differ")
    try:
        request=decode_source_inspection_migration_request_v1(row[5],authority_namespace=authority_namespace)
        if (request["operation_id"]!=row[1] or canonical_digest(request)!=row[2]
                or request["pause_operation_id"]!=row[3]
                or row[7] not in {"pending","completed"} or type(row[6]) not in (int,float)
                or not math.isfinite(row[6]) or row[6]<0):
            raise ValueError("inspection Core accepted original binding differs")
        _sha_v1(row[4].removeprefix("sha256:"))
        receipt=None if row[8] is None else decode_source_inspection_migration_progress_v1(
            row[8],operation_id=row[1],request_digest=row[2])
        if (row[7]=="completed")!=(receipt is not None and receipt["phase"]=="completed"):
            raise ValueError("inspection Core completion differs from actual receipt")
        accepted=json.loads(row[10])
        from .c09_storage_control_v1 import digest as control_digest
        if (type(accepted) is not dict or set(accepted)!={"schema","request","owner_head","started_at",
                "workflow_accepted_digest","key_id","accepted_digest","signature"}
                or canonical_json(accepted)!=row[10] or accepted["schema"]!="sylanne.source-inspection-maintenance-accepted.v1"
                or accepted["request"]!=request or accepted["owner_head"]!=row[4] or accepted["started_at"]!=row[6]
                or accepted["accepted_digest"]!=row[9]
                or control_digest({k:v for k,v in accepted.items() if k not in {"accepted_digest","signature"}})!=row[9]):
            raise ValueError("inspection signed accepted original differs")
        _sha_v1(row[9]);_sha_v1(accepted["signature"])
        return dict(operation_id=row[1],state=row[7],request_digest=row[2],pause_operation_id=row[3],
            owner_head=row[4],installation_id=request["installation_id"],request=request,receipt=receipt,
            accepted_digest=row[9],accepted_original=accepted)
    except (ValueError,TypeError,KeyError,AttributeError) as exc:
        raise AuthorityUnavailable("inspection Core original cannot be classified") from exc
