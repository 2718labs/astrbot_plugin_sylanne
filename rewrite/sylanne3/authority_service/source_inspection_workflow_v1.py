"""Signed Owner pause/inspection/resume maintenance, owned by the Authority."""
from dataclasses import asdict,dataclass
import json
import threading
import time
from uuid import UUID
from weakref import WeakKeyDictionary

from .contract import AuthorityUnavailable
from .d12_lifecycle_gate_v1 import read_lifecycle_head_in_tx_v1
from ..contracts import canonical_json
from ..runtime_contracts import canonical_digest

TABLE="authority_source_inspection_workflows_v1"
DDL=f"CREATE TABLE {TABLE}(namespace TEXT NOT NULL,operation_id TEXT NOT NULL,input_digest TEXT NOT NULL,input_json TEXT NOT NULL,accepted_digest TEXT NOT NULL,accepted_json TEXT NOT NULL,state TEXT NOT NULL,phase TEXT NOT NULL,hold_code TEXT,progress_json TEXT,PRIMARY KEY(namespace,operation_id))"
COLUMNS=("namespace","operation_id","input_digest","input_json","accepted_digest","accepted_json","state","phase","hold_code","progress_json")
ACCEPT_SCHEMA="sylanne.source-inspection-workflow-accepted.v1"
CONTROL_SCHEMA="d12.source-inspection-control-original.v1"
VIEW_SCHEMA="d12.source-inspection-workflow-view.v1"
INPUT_FIELDS=frozenset({"pause_operation_id","resume_operation_id","scope_kind","target_refs","deadline_utc",
    "interpretation_status_discovery","resume_on_complete"})
_PHASES=frozenset({"accepted","pausing","paused","migrating","migration_complete","resuming","active","held"})
_ISSUER=object()
_ACCEPTED=WeakKeyDictionary()
_PHASE_ISSUED=WeakKeyDictionary()


def validate_workflow_input_v1(operation_id,value):
    from .source_inspection_migration_v1 import _uuid_v1
    _uuid_v1(operation_id)
    if type(value) is not dict or set(value)!=INPUT_FIELDS:
        raise ValueError("inspection workflow exact request fields required")
    _uuid_v1(value["pause_operation_id"])
    if value["pause_operation_id"]==operation_id or type(value["resume_on_complete"]) is not bool:
        raise ValueError("inspection workflow pause/outer identity differs")
    if value["resume_on_complete"]:
        _uuid_v1(value["resume_operation_id"])
        if len({operation_id,value["pause_operation_id"],value["resume_operation_id"]})!=3:
            raise ValueError("inspection workflow requires three distinct originals")
    elif value["resume_operation_id"] is not None:
        raise ValueError("inspection paused-only workflow has no resume operation")
    return value


@dataclass(frozen=True,eq=False)
class _InspectionWorkflowPhaseV1:
    accepted: object
    action: str
    operation_id: str
    expected_lifecycle_epoch: int
    db: object
    thread_id: int
    context: object
    anchor: object

    def require_v1(self,lifecycle,action):
        accepted=self.accepted
        if (_PHASE_ISSUED.get(self)!=(accepted,action,self.db,self.thread_id)
                or action!=self.action or accepted.service.lifecycle is not lifecycle
                or accepted.service._phase_context is not self.context
                or self.db is not lifecycle.core._db or not self.db.in_transaction
                or self.thread_id!=threading.get_ident()):
            raise AuthorityUnavailable("actual same-transaction inspection workflow phase required")
        accepted.require_current_v1(self.db)
        return self

    @property
    def original(self):
        return self.accepted.original


class _AcceptedInspectionWorkflowV1:
    def __init__(self,issuer,service,row):
        if issuer is not _ISSUER:raise AuthorityUnavailable("private accepted workflow issuer required")
        self.service,self.operation_id,self.row=service,row[1],row
        self.original=json.loads(row[5])
        _ACCEPTED[self]=(service,row[1],row[4])

    def require_current_v1(self,db):
        service=self.service
        if (_ACCEPTED.get(self)!=(service,self.operation_id,self.row[4]) or db is not service.lifecycle.core._db
                or not db.in_transaction):
            raise AuthorityUnavailable("actual accepted workflow/Core transaction required")
        row=service._row_v1(db,self.operation_id)
        if row[4]!=self.row[4] or row[5]!=self.row[5] or row[6] not in {"accepted","running"}:
            raise AuthorityUnavailable("inspection workflow no longer owns its durable phase")
        original=self.original
        service.lifecycle.control.verify_original_v1(original,"accepted_digest")
        if time.time()>=original["effective_deadline_utc"]:
            raise AuthorityUnavailable("inspection workflow original deadline expired")
        resource=service.resources.qualify_current_v1(lifecycle=service.lifecycle)
        resource.require_current_v1(lifecycle=service.lifecycle)
        if resource.as_original_v1()!=original["resource_original"]:
            raise AuthorityUnavailable("inspection workflow actual Root resource binding changed")
        context,storage=service.lifecycle._storage()
        if storage!=original["storage"]:
            raise AuthorityUnavailable("inspection workflow selected four-role storage changed")
        selected,cohort,configuration=service.source.files.read_selected_configuration_cohort_v2()
        child=original["source_request"]
        if (asdict(selected)!=child["selected_pointer"] or cohort.cohort_digest!=child["cohort_digest"]
                or service.source.registry.catalogue_hash!=child["catalogue_hash"]
                or configuration["host_profile"]["installation_policy"]["catalogue_hash"]!=child["catalogue_hash"]):
            raise AuthorityUnavailable("inspection workflow selected package/cohort/catalogue changed")
        request=service._session_request_v1(original)
        sessions=service.lifecycle.status_service.sessions
        sessions._current_key(db,request)
        sessions._current_pairing_source.require_current_actor_in_tx(db,
            authority_namespace=service.lifecycle.namespace,installation_id=request.installation_id,
            actor_id=original["actor"],principal=request.principal)
        guard=service.lifecycle.status_service.tickets._checked_current_head(db,service.lifecycle.namespace)
        if (guard is None or guard.authorization_head!=original["owner_head"]
                or guard.pending_revoke_operation_id is not None or guard.minimum_revocation_revision
                or guard.minimum_revocation_epoch):
            raise AuthorityUnavailable("inspection workflow initiating Owner authorization changed")
        service.source._actual_owner_grant_v1(db,context,storage,actor=original["actor"],
            session_request=request,required={"workbench.read","workbench.maintain","workbench.control"})
        return context,storage

    def issue_phase_v1(self,action,db,resource):
        from .source_inspection_workflow_resource_v1 import VerifiedInspectionWorkflowResourceV1
        if type(resource) is not VerifiedInspectionWorkflowResourceV1:
            raise AuthorityUnavailable("actual installed Root workflow resource proof required")
        resource.require_current_v1(lifecycle=self.service.lifecycle)
        self.require_current_v1(db)
        original=self.original
        head=read_lifecycle_head_in_tx_v1(db,self.service.lifecycle.namespace)
        if action=="pause":
            operation=original["input"]["pause_operation_id"];epoch=original["initial_lifecycle_epoch"]
            if head is None or head.state!="active" or head.epoch!=epoch:
                raise AuthorityUnavailable("inspection pause does not bind its original active epoch")
        elif action in {"migrate","resume"}:
            operation=self.operation_id if action=="migrate" else original["input"]["resume_operation_id"]
            epoch=original["initial_lifecycle_epoch"]+1
            if (head is None or head.state!="paused" or head.epoch!=epoch
                    or head.operation_id!=original["input"]["pause_operation_id"]
                    or not self.service.lifecycle.supervisor.read_current_host_state_v1().stopped_and_drained):
                raise AuthorityUnavailable("inspection phase requires its actual original stopped/drained pause")
            if any(self.service.lifecycle._counts(db)):
                raise AuthorityUnavailable("inspection phase lost actual drained Core admission")
            if action=="resume":
                if not original["input"]["resume_on_complete"]:
                    raise AuthorityUnavailable("inspection workflow did not authorize resume")
                from .source_inspection_migration_v1 import TABLE as SOURCE
                result=db.execute(f"SELECT state,receipt_json FROM {SOURCE} WHERE namespace=? AND operation_id=?",
                    (self.service.lifecycle.namespace,self.operation_id)).fetchone()
                if result is None or result[0]!="completed" or json.loads(result[1])["phase"]!="completed":
                    raise AuthorityUnavailable("inspection resume requires actual committed migration completion")
        else:raise AuthorityUnavailable("unregistered inspection workflow phase")
        context=self.service._phase_context
        if context is None or context[0] is not db or context[3]!=threading.get_ident():
            raise AuthorityUnavailable("inspection phase requires its actual frozen journal context")
        anchor=self.service.lifecycle.fences._current_locked(db,context[1],context[2],require_no_pending=False)
        phase=_InspectionWorkflowPhaseV1(self,action,operation,epoch,db,threading.get_ident(),context,anchor)
        _PHASE_ISSUED[phase]=(self,action,db,phase.thread_id)
        return phase


class InstalledInspectionWorkflowV1:
    def __init__(self,*,service,resource_provider):
        from .source_inspection_workflow_resource_v1 import InstalledInspectionWorkflowResourceV1
        if type(resource_provider) is not InstalledInspectionWorkflowResourceV1:
            raise TypeError("actual installed Root inspection workflow resource provider required")
        self.source,self.lifecycle,self.resources=service,service.lifecycle,resource_provider
        self._closed=threading.Event()
        self._lock=threading.RLock()
        self._workers={}
        self._phase_context=None
        from .source_inspection_recovery_v1 import InstalledInspectionRecoveryV1
        self.recovery=InstalledInspectionRecoveryV1(self)
        from .source_inspection_held_reconciliation_v1 import InstalledHeldInspectionReconciliationV1
        self.held_reconciliation=InstalledHeldInspectionReconciliationV1(self)

    def install_schema(self,administrator_credential):
        self.lifecycle.core._require(administrator_credential,"d12_lifecycle_install",self.lifecycle.namespace)
        with self.lifecycle.core._tx() as db:
            row=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone()
            if row is None:db.execute(DDL)
            elif row!=(DDL,):raise AuthorityUnavailable("inspection workflow Core schema differs")

    def _row_v1(self,db,operation_id):
        row=db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=?",
            (self.lifecycle.namespace,operation_id)).fetchone()
        if row is None:raise AuthorityUnavailable("inspection_migration_not_found")
        return row

    def _session_request_v1(self,original):
        from .v2_owner_session import from_wire
        return from_wire(dict(kind="owner_session_login_request_v1",**original["public_session_request"]))

    def _view_v1(self,row):
        original=json.loads(row[5])
        from .source_inspection_recovery_v1 import ACCEPT_SCHEMA as RECOVERY_SCHEMA
        if original["schema"]==RECOVERY_SCHEMA:return self.recovery.view_v1(row)
        from .source_inspection_held_reconciliation_v1 import ACCEPT_SCHEMA as HELD_SCHEMA
        if original["schema"]==HELD_SCHEMA:return self.held_reconciliation.view_v1(row)
        value=original["input"]
        return dict(schema=VIEW_SCHEMA,scope="/".join(self.lifecycle.namespace_id.as_tuple),
            installation_id=self.lifecycle.installation_id,operation_id=row[1],request_digest=row[2],
            state=row[6],phase=row[7],hold_code=row[8],
            progress=None if row[9] is None else json.loads(row[9]),**value,
            effective_deadline_utc=original["effective_deadline_utc"])

    def accept_current_v1(self,*,credential,actor,session_token,session_request,operation_id,input_data):
        from .v2_owner_session import _verifier,_time
        from .source_inspection_migration_v1 import decode_source_inspection_migration_request_v1
        from ..domains.d06.inspection_metadata_v1 import inspection_metadata_type_specs_v1
        from .d12_configuration_cohort_v2 import read_verified_configuration_cohort_v2
        validate_workflow_input_v1(operation_id,input_data)
        submitted=canonical_json(input_data);input_digest=canonical_digest(input_data)
        lifecycle=self.lifecycle
        lifecycle.core._require(credential,"d12_lifecycle_control",lifecycle.namespace)
        context,storage=lifecycle._storage()
        with lifecycle.fences._frozen() as (db,deletion,execution,_):
            guard=lifecycle.status_service.tickets._checked_current_head(db,lifecycle.namespace)
            if guard is None:raise AuthorityUnavailable("inspection workflow Owner head absent")
            lifecycle.status_service._current_session_in_tx(db,actor=actor,token=session_token,
                request=session_request,expected_head=guard.authorization_head)
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_c09_consumed_execution_v1'").fetchone():
                for item in (input_data["pause_operation_id"],input_data["resume_operation_id"]):
                    if item is not None and db.execute("SELECT 1 FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind='d12_lifecycle_operation' AND item_id=?",
                            (lifecycle.namespace,item)).fetchone():
                        raise AuthorityUnavailable("retired inspection lifecycle phase cannot authorize a new workflow")
                if db.execute("SELECT 1 FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind IN ('source_inspection_workflow_operation','source_inspection_migration_operation') AND item_id=?",
                        (lifecycle.namespace,operation_id)).fetchone():
                    raise AuthorityUnavailable("retired inspection workflow cannot be replayed")
            prior=db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=?",
                (lifecycle.namespace,operation_id)).fetchone()
            if prior is not None:
                accepted_original=json.loads(prior[5])
                lifecycle.control.verify_original_v1(accepted_original,"accepted_digest")
                if (prior[2]!=input_digest or prior[3]!=submitted or accepted_original["actor"]!=actor
                        or accepted_original["owner_head"]!=guard.authorization_head
                        or accepted_original["public_session_request"]["principal"]!=asdict(session_request.principal)):
                    raise AuthorityUnavailable("inspection workflow retry changes its original submitted request/Owner")
                self.source._actual_owner_grant_v1(db,context,storage,actor=actor,
                    session_request=session_request,required={"workbench.read"})
                return self._view_v1(prior)
            from .source_inspection_migration_v1 import require_no_pending_source_inspection_migration_in_tx_v1
            require_no_pending_source_inspection_migration_in_tx_v1(db,lifecycle.namespace)
            from .graph_catalogue_upgrade_v1 import require_no_pending_catalogue_upgrade_in_tx_v1
            require_no_pending_catalogue_upgrade_in_tx_v1(db,lifecycle.namespace)
            if db.execute(f"SELECT 1 FROM {TABLE} WHERE namespace=? AND state!='completed' LIMIT 1",(lifecycle.namespace,)).fetchone():
                raise AuthorityUnavailable("an accepted inspection workflow already owns this installation")
            grant,owner=self.source._actual_owner_grant_v1(db,context,storage,actor=actor,
                session_request=session_request,required={"workbench.read","workbench.maintain","workbench.control"})
            head=read_lifecycle_head_in_tx_v1(db,lifecycle.namespace)
            observed=lifecycle.supervisor.read_current_host_state_v1()
            if head is None or head.state!="active" or observed.active_state!="active" or observed.main_pid<1:
                raise AuthorityUnavailable("inspection workflow must be accepted before whole-Host pause")
            session=db.execute("SELECT expires_at_utc FROM authority_owner_sessions_v1 WHERE verifier=?",(_verifier(session_token),)).fetchone()
            resource=self.resources.qualify_current_v1(lifecycle=lifecycle)
            resource.require_current_v1(lifecycle=lifecycle)
            effective=min(input_data["deadline_utc"],_time(session[0]).timestamp(),resource.deadline_utc,time.time()+3600)
            if effective<=time.time():raise AuthorityUnavailable("inspection workflow original authorization/resource deadline elapsed")
            selected,cohort,configuration=self.source.files.read_selected_configuration_cohort_v2()
            read_verified_configuration_cohort_v2(cohort)
            if (selected.installation_id!=lifecycle.installation_id
                    or selected.manifest_sha256!=lifecycle.expected_manifest_digest
                    or configuration["host_profile"]["installation_policy"]["catalogue_hash"]!=self.source.registry.catalogue_hash):
                raise AuthorityUnavailable("inspection workflow selected package/catalogue differs")
            specs=inspection_metadata_type_specs_v1()
            child=dict(schema="sylanne.source-inspection-migration-request.v1",namespace=asdict(lifecycle.namespace_id),
                authority_namespace=lifecycle.namespace,installation_id=lifecycle.installation_id,
                operation_id=operation_id,pause_operation_id=input_data["pause_operation_id"],actor=actor,storage=storage,
                selected_pointer=asdict(selected),cohort_digest=cohort.cohort_digest,catalogue_hash=self.source.registry.catalogue_hash,
                metadata_schema_digest=canonical_digest([(s.name,s.schema_hash) for s in specs]),
                scope_kind=input_data["scope_kind"],target_refs=input_data["target_refs"],deadline_utc=effective,
                interpretation_status_discovery=input_data["interpretation_status_discovery"])
            encoded_child=canonical_json(child)
            if len(encoded_child.encode())>32768:
                raise ValueError("inspection workflow child exceeds its registered original bound")
            decode_source_inspection_migration_request_v1(encoded_child,authority_namespace=lifecycle.namespace)
            original=lifecycle.control.sign_original_v1(ACCEPT_SCHEMA,dict(schema=ACCEPT_SCHEMA,
                namespace=asdict(lifecycle.namespace_id),authority_namespace=lifecycle.namespace,
                installation_id=lifecycle.installation_id,operation_id=operation_id,input=input_data,
                input_digest=input_digest,actor=actor,owner_head=guard.authorization_head,
                public_session_request=asdict(session_request),owner_grant_digest=owner.grant_digest,
                storage=storage,source_request=child,initial_lifecycle_epoch=head.epoch,accepted_at_utc=time.time(),
                owner_authorization_deadline_utc=_time(session[0]).timestamp(),
                resource_original=resource.as_original_v1(),effective_deadline_utc=effective),"accepted_digest")
            row=(lifecycle.namespace,operation_id,input_digest,submitted,original["accepted_digest"],
                canonical_json(original),"accepted","accepted",None,None)
            db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?,?,?,?)",row)
            result=self._view_v1(row)
        self._start_worker_v1(operation_id)
        return result

    def read_current_v1(self,*,credential,actor,session_token,session_request,operation_id):
        from .source_inspection_migration_v1 import _uuid_v1
        _uuid_v1(operation_id)
        lifecycle=self.lifecycle
        lifecycle.core._require(credential,"d12_lifecycle_control",lifecycle.namespace)
        context,storage=lifecycle._storage()
        with lifecycle.fences._frozen() as (db,deletion,execution,_):
            row=self._row_v1(db,operation_id);original=json.loads(row[5])
            lifecycle.control.verify_original_v1(original,"accepted_digest")
            validate_inspection_workflow_core_row_v1(COLUMNS,row,authority_namespace=lifecycle.namespace)
            if original["actor"]!=actor:raise AuthorityUnavailable("inspection workflow belongs to another Owner")
            guard=lifecycle.status_service.tickets._checked_current_head(db,lifecycle.namespace)
            if guard is None:raise AuthorityUnavailable("current inspection status Owner head is absent")
            lifecycle.status_service._current_session_in_tx(db,actor=actor,token=session_token,
                request=session_request,expected_head=guard.authorization_head)
            self.source._actual_owner_grant_v1(db,context,storage,actor=actor,session_request=session_request,required={"workbench.read"})
            return self._view_v1(row)

    def _start_worker_v1(self,operation_id):
        with self._lock:
            prior=self._workers.get(operation_id)
            if prior is not None and prior.is_alive():return
            thread=threading.Thread(target=self._run_v1,args=(operation_id,),
                name="sylanne-inspection-"+operation_id[:8],daemon=True)
            self._workers[operation_id]=thread;thread.start()

    def _held_v1(self,operation_id,code):
        with self.lifecycle.core._tx() as db:
            db.execute(f"UPDATE {TABLE} SET state='held',phase='held',hold_code=? WHERE namespace=? AND operation_id=? AND state IN ('accepted','running')",
                (code,self.lifecycle.namespace,operation_id))

    def _run_v1(self,operation_id):
        from .source_inspection_recovery_v1 import ACCEPT_SCHEMA as RECOVERY_SCHEMA
        with self.lifecycle.core._tx() as db:
            original=json.loads(self._row_v1(db,operation_id)[5])
        if original["schema"]==RECOVERY_SCHEMA:
            self.recovery.run_v1(operation_id)
            return
        from .source_inspection_held_reconciliation_v1 import ACCEPT_SCHEMA as HELD_SCHEMA
        if original["schema"]==HELD_SCHEMA:
            self.held_reconciliation.run_v1(operation_id)
            return
        lifecycle=self.lifecycle
        try:
            while not self._closed.is_set() and not lifecycle._closed.is_set():
                active=self.source._active.get(operation_id)
                if active is not None:
                    from ..runtime.source_inspection_metadata_read_v3 import resolve_pending_inspection_metadata_core_v3
                    resolve_pending_inspection_metadata_core_v3(active)
                start=None
                with lifecycle.fences._frozen() as (db,deletion,execution,_):
                    row=self._row_v1(db,operation_id)
                    if row[6] in {"completed","held"}:return
                    self._phase_context=(db,deletion,execution,threading.get_ident())
                    accepted=_AcceptedInspectionWorkflowV1(_ISSUER,self,row)
                    context,storage=accepted.require_current_v1(db)
                    resource=self.resources.qualify_current_v1(lifecycle=lifecycle)
                    phase=row[7];original=accepted.original
                    input_data=original["input"]
                    if phase=="accepted":
                        issued=accepted.issue_phase_v1("pause",db,resource)
                        lifecycle.accept_maintenance_pause_in_tx_v1(issued)
                        phase="pausing";start=input_data["pause_operation_id"]
                    elif phase=="pausing":
                        pause=lifecycle._operation(db,input_data["pause_operation_id"])
                        if pause[15] is not None:raise AuthorityUnavailable("original pause held")
                        head=read_lifecycle_head_in_tx_v1(db,lifecycle.namespace)
                        if pause[13]=="paused" and head.state=="paused" and head.operation_id==pause[1]:
                            phase="paused"
                    elif phase in {"paused","migrating"}:
                        lifecycle._constraints_in_tx(db,deletion,execution,storage,qualified_context=context)
                        issued=accepted.issue_phase_v1("migrate",db,resource)
                        result=self.source.advance_accepted_workflow_phase_v1(issued)
                        db.execute(f"UPDATE {TABLE} SET progress_json=? WHERE namespace=? AND operation_id=?",
                            (canonical_json(result),lifecycle.namespace,operation_id))
                        phase="migration_complete" if result["phase"]=="completed" else "migrating"
                    elif phase=="migration_complete":
                        if input_data["resume_on_complete"]:
                            issued=accepted.issue_phase_v1("resume",db,resource)
                            lifecycle.submit_accepted_maintenance_resume_in_tx_v1(issued)
                            phase="resuming";start=input_data["resume_operation_id"]
                        else:
                            accepted.issue_phase_v1("migrate",db,resource)
                            db.execute(f"UPDATE {TABLE} SET state='completed',phase='paused' WHERE namespace=? AND operation_id=?",
                                (lifecycle.namespace,operation_id))
                            return
                    elif phase=="resuming":
                        resumed=lifecycle._operation(db,input_data["resume_operation_id"])
                        if resumed[15] is not None:raise AuthorityUnavailable("original resume held")
                        head=read_lifecycle_head_in_tx_v1(db,lifecycle.namespace)
                        if resumed[13]=="active" and head.state=="active" and head.operation_id==resumed[1]:
                            db.execute(f"UPDATE {TABLE} SET state='completed',phase='active' WHERE namespace=? AND operation_id=?",
                                (lifecycle.namespace,operation_id))
                            return
                    else:raise AuthorityUnavailable("unknown inspection workflow phase")
                    db.execute(f"UPDATE {TABLE} SET state='running',phase=? WHERE namespace=? AND operation_id=?",
                        (phase,lifecycle.namespace,operation_id))
                self._phase_context=None
                if start is not None:lifecycle._start_worker(start)
                self._closed.wait(0.05)
        except Exception:
            self._phase_context=None
            self._held_v1(operation_id,"original_phase_reconciliation_required")
            work=self.source._active.pop(operation_id,None)
            if work is not None:work.close_v1()

        finally:
            self._phase_context=None

    def require_resume_exclusion_v1(self,db,phase=None,*,pending_rows=None):
        pending=tuple(db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND state!='completed'",(self.lifecycle.namespace,))) if pending_rows is None else tuple(pending_rows)
        if not pending:return
        if len(pending)!=1:raise AuthorityUnavailable("another inspection workflow owns the installation")
        row=pending[0]
        if phase is not None:
            from .source_inspection_recovery_v1 import _InspectionRecoveryPhaseV1
            if type(phase) is _InspectionRecoveryPhaseV1:
                if phase.accepted.manager is not self.recovery or row[1]!=phase.operation_id or row[7]!="accepted":
                    raise AuthorityUnavailable("fresh recovery phase does not own its accepted row")
                phase.require_v1(self.lifecycle,"resume")
                return
            if type(phase) is not _InspectionWorkflowPhaseV1 or phase.accepted.service is not self:
                raise AuthorityUnavailable("actual accepted inspection resume phase required")
            phase.require_v1(self.lifecycle,"resume")
            if row[1]!=phase.accepted.operation_id or row[7]!="migration_complete":
                raise AuthorityUnavailable("resume phase does not own completed inspection workflow")
            return
        head=read_lifecycle_head_in_tx_v1(db,self.lifecycle.namespace)
        if head is None or head.state!="resuming" or row[6]!="running" or row[7]!="resuming":
            raise AuthorityUnavailable("accepted inspection workflow must finish before unrelated Host resume")
        control=self.lifecycle._operation(db,head.operation_id)
        self.require_control_continuation_v1(db,control)
        original=json.loads(row[5])
        from .source_inspection_recovery_v1 import ACCEPT_SCHEMA as RECOVERY_SCHEMA
        if original["schema"]==RECOVERY_SCHEMA:
            if head.operation_id!=row[1]:raise AuthorityUnavailable("another recovery owns the native resume")
            return
        if (not original["input"]["resume_on_complete"] or head.operation_id!=original["input"]["resume_operation_id"]
                or control[3]!="resume"):
            raise AuthorityUnavailable("current lifecycle resume is not the exact accepted workflow")

    def require_control_continuation_v1(self,db,control_row):
        if not control_row[4].startswith("d12inspectioncontrol:"):return
        from .source_inspection_recovery_v1 import CONTROL_SCHEMA as RECOVERY_CONTROL
        if json.loads(control_row[5])["schema"]==RECOVERY_CONTROL:
            return self.recovery.require_continuation_v1(db,control_row)
        native=validate_inspection_control_original_v1(control_row[5],authority_namespace=self.lifecycle.namespace)
        self.lifecycle.control.verify_original_v1(native,"original_digest")
        row=self._row_v1(db,native["workflow_operation_id"])
        accepted=_AcceptedInspectionWorkflowV1(_ISSUER,self,row)
        accepted.require_current_v1(db)
        original=accepted.original
        action=native["action"]
        expected_phase={"pause":"pausing","resume":"resuming"}[action]
        if (row[7]!=expected_phase or native["accepted_digest"]!=row[4] or native["operation_id"]!=control_row[1]
                or native["operation_id"]!=original["input"][action+"_operation_id"]
                or native["action"]!=control_row[3] or native["request_digest"]!=control_row[2]
                or native["storage_identity_digest"]!=canonical_digest(original["storage"])
                or control_row[15] is not None):
            raise AuthorityUnavailable("native inspection control lost its accepted workflow")

    def resume_pending_v1(self):
        with self.lifecycle.core._tx() as db:
            rows=tuple(db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND state IN ('accepted','running')",(self.lifecycle.namespace,)))
            for row in rows:
                from .source_inspection_recovery_v1 import ACCEPT_SCHEMA as RECOVERY_SCHEMA
                from .source_inspection_held_reconciliation_v1 import ACCEPT_SCHEMA as HELD_SCHEMA
                if json.loads(row[5])["schema"]==HELD_SCHEMA:
                    continue
                if json.loads(row[5])["schema"]==RECOVERY_SCHEMA:
                    self.recovery.reconcile_restart_v1(db,row)
                    continue
                if row[7] in {"pausing","resuming"}:
                    original=json.loads(row[5]);kind="pause" if row[7]=="pausing" else "resume"
                    action=original["input"][kind+"_operation_id"]
                    from .d12_installation_lifecycle_v1 import OPS
                    control=db.execute(f"SELECT * FROM {OPS} WHERE namespace=? AND operation_id=?",
                        (self.lifecycle.namespace,action)).fetchone()
                    terminal="paused" if kind=="pause" else "active"
                    if control is None or control[13]!=terminal or control[15] is not None:
                        db.execute(f"UPDATE {TABLE} SET state='held',phase='held',hold_code='restart_unknown_native_control' WHERE namespace=? AND operation_id=?",
                            (self.lifecycle.namespace,row[1]))
        for row in rows:
            with self.lifecycle.core._tx() as db:
                current=self._row_v1(db,row[1])
            if current[6]!="held":self._start_worker_v1(row[1])

    def close(self):
        self._closed.set()
        with self._lock:workers=tuple(self._workers.values())
        for worker in workers:
            if worker is not threading.current_thread():worker.join(timeout=self.lifecycle.drain_timeout_seconds+5)
            if worker.is_alive():raise AuthorityUnavailable("inspection workflow must settle before Authority close")


def validate_inspection_workflow_core_row_v1(columns,row,*,authority_namespace):
    from .source_inspection_migration_v1 import (_sha_v1,decode_source_inspection_migration_request_v1,
        decode_source_inspection_migration_progress_v1)
    from .c09_storage_control_v1 import digest as control_digest
    if columns!=COLUMNS or len(row)!=len(COLUMNS) or row[0]!=authority_namespace:
        raise AuthorityUnavailable("inspection workflow Core row fields differ")
    value=json.loads(row[5])
    from .source_inspection_recovery_v1 import ACCEPT_SCHEMA as RECOVERY_SCHEMA,validate_recovery_core_row_v1
    if value["schema"]==RECOVERY_SCHEMA:
        return validate_recovery_core_row_v1(columns,row,authority_namespace=authority_namespace)
    from .source_inspection_held_reconciliation_v1 import ACCEPT_SCHEMA as HELD_SCHEMA,validate_held_core_row_v1
    if value["schema"]==HELD_SCHEMA:
        return validate_held_core_row_v1(columns,row,authority_namespace=authority_namespace)
    submitted=json.loads(row[3])
    fields={"schema","namespace","authority_namespace","installation_id","operation_id","input","input_digest",
        "actor","owner_head","public_session_request","owner_grant_digest","storage","source_request",
        "initial_lifecycle_epoch","accepted_at_utc","owner_authorization_deadline_utc","resource_original",
        "effective_deadline_utc","key_id","accepted_digest","signature"}
    if (type(value) is not dict or set(value)!=fields or value["schema"]!=ACCEPT_SCHEMA
            or canonical_json(value)!=row[5] or canonical_json(submitted)!=row[3]
            or value["input"]!=submitted or canonical_digest(submitted)!=row[2] or value["input_digest"]!=row[2]
            or value["operation_id"]!=row[1] or value["authority_namespace"]!=row[0]
            or value["accepted_digest"]!=row[4]
            or control_digest({k:v for k,v in value.items() if k not in {"accepted_digest","signature"}})!=row[4]
            or row[6] not in {"accepted","running","completed","held"} or row[7] not in _PHASES):
        raise AuthorityUnavailable("inspection workflow signed accepted original differs")
    validate_workflow_input_v1(row[1],submitted)
    _sha_v1(row[4]);_sha_v1(value["signature"])
    child=decode_source_inspection_migration_request_v1(canonical_json(value["source_request"]),
        authority_namespace=authority_namespace)
    if child["operation_id"]!=row[1] or child["namespace"]!=value["namespace"] or child["storage"]!=value["storage"]:
        raise AuthorityUnavailable("inspection child migration changed accepted workflow scope")
    progress=None if row[9] is None else decode_source_inspection_migration_progress_v1(
        row[9],operation_id=row[1],request_digest=canonical_digest(child))
    if row[6]=="completed" and (progress is None or progress["phase"]!="completed"
            or row[7]!=("active" if submitted["resume_on_complete"] else "paused")):
        raise AuthorityUnavailable("inspection workflow claims completion without its actual terminal phase")
    if (row[6]=="held")!=(row[7]=="held" and type(row[8]) is str and bool(row[8])):
        raise AuthorityUnavailable("inspection workflow hold classification differs")
    return dict(operation_id=row[1],state=row[6],phase=row[7],input_digest=row[2],accepted_digest=row[4],
        accepted_original=value,input=submitted,progress=progress,graph_refs=tuple(child["target_refs"]))


def native_inspection_control_original_v1(phase,intent):
    from ..runtime.lifecycle_operations_v1 import digest
    phase.require_v1(phase.accepted.service.lifecycle,phase.action)
    original=phase.original
    material=dict(workflow_operation_id=original["operation_id"],accepted_digest=original["accepted_digest"],
        operation_id=phase.operation_id,intent=asdict(intent))
    request_digest=digest(material)
    body=dict(schema=CONTROL_SCHEMA,authority_namespace=original["authority_namespace"],
        installation_id=original["installation_id"],workflow_operation_id=original["operation_id"],
        accepted_digest=original["accepted_digest"],operation_id=phase.operation_id,action=phase.action,
        request_digest=request_digest,owner_head=original["owner_head"],intent=asdict(intent),
        storage_identity_digest=canonical_digest(original["storage"]))
    signed=phase.accepted.service.lifecycle.control.sign_original_v1(CONTROL_SCHEMA,body,"original_digest")
    return signed


def validate_inspection_control_original_v1(raw,*,authority_namespace):
    from .c09_storage_control_v1 import digest as control_digest
    from .d12_lifecycle_contract_v1 import D12InstallationControlIntentV1
    from ..runtime.lifecycle_operations_v1 import digest
    value=json.loads(raw)
    from .source_inspection_recovery_v1 import CONTROL_SCHEMA as RECOVERY_CONTROL,validate_recovery_control_original_v1
    if value["schema"]==RECOVERY_CONTROL:
        return validate_recovery_control_original_v1(raw,authority_namespace=authority_namespace)
    fields={"schema","authority_namespace","installation_id","workflow_operation_id","accepted_digest",
        "operation_id","action","request_digest","owner_head","intent","storage_identity_digest",
        "key_id","original_digest","signature"}
    if (type(value) is not dict or set(value)!=fields or canonical_json(value)!=raw
            or value["schema"]!=CONTROL_SCHEMA or value["authority_namespace"]!=authority_namespace
            or value["action"] not in {"pause","resume"}
            or control_digest({k:v for k,v in value.items() if k not in {"original_digest","signature"}})!=value["original_digest"]):
        raise AuthorityUnavailable("inspection native control original differs")
    intent=D12InstallationControlIntentV1(**value["intent"])
    if intent.action!=value["action"] or intent.installation_id!=value["installation_id"]:
        raise AuthorityUnavailable("inspection native control intent differs")
    material=dict(workflow_operation_id=value["workflow_operation_id"],accepted_digest=value["accepted_digest"],
        operation_id=value["operation_id"],intent=value["intent"])
    if digest(material)!=value["request_digest"]:
        raise AuthorityUnavailable("inspection native control request digest differs")
    return value

