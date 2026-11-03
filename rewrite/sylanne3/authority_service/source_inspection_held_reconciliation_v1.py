"""Fresh Owner reconciliation of an immutable held inspection workflow."""
from dataclasses import asdict,dataclass
import json
import math
import threading
import time
from weakref import WeakKeyDictionary
from uuid import UUID

from .contract import AuthorityUnavailable
from .d12_lifecycle_gate_v1 import read_lifecycle_head_in_tx_v1
from ..contracts import canonical_json
from ..runtime_contracts import canonical_digest

ACCEPT_SCHEMA="sylanne.source-inspection-held-reconciliation-accepted.v1"
LINK_SCHEMA="sylanne.source-inspection-held-resolution.v1"
VIEW_SCHEMA="d12.source-inspection-held-reconciliation-view.v1"
INPUT_FIELDS=frozenset({"parent_workflow_operation_id","parent_accepted_digest","parent_hold_digest",
    "expected_lifecycle_epoch","expected_lifecycle_head_digest","expected_storage_identity_digest",
    "expected_resource_binding_digest","deadline_utc","disposition","child_migration_operation_id"})
DISPOSITIONS=frozenset({"reconcile_only","continue_remaining","terminate_paused","reconcile_active_completed"})
_ISSUER=object()
_ACCEPTED=WeakKeyDictionary()
_PHASES=WeakKeyDictionary()


def hold_snapshot_digest_v1(row):
    return canonical_digest(dict(operation_id=row[1],accepted_digest=row[4],state=row[6],phase=row[7],
        hold_code=row[8],progress_digest=None if row[9] is None else canonical_digest(json.loads(row[9]))))


def validate_held_input_v1(operation_id,value):
    from .source_inspection_migration_v1 import _uuid_v1,_sha_v1
    _uuid_v1(operation_id)
    if type(value) is not dict or set(value)!=INPUT_FIELDS or value["disposition"] not in DISPOSITIONS:
        raise ValueError("held inspection recovery exact input fields required")
    _uuid_v1(value["parent_workflow_operation_id"])
    if operation_id==value["parent_workflow_operation_id"]:
        raise ValueError("held inspection reconciliation needs a new operation")
    for name in ("parent_accepted_digest","parent_hold_digest","expected_storage_identity_digest","expected_resource_binding_digest"):
        _sha_v1(value[name])
    _sha_v1(value["expected_lifecycle_head_digest"].removeprefix("sha256:"))
    if (type(value["expected_lifecycle_epoch"]) is not int or value["expected_lifecycle_epoch"]<0
            or type(value["deadline_utc"]) not in (int,float) or not math.isfinite(value["deadline_utc"])):
        raise ValueError("held reconciliation current epoch/deadline differs")
    child=value["child_migration_operation_id"]
    if value["disposition"]=="continue_remaining":
        _uuid_v1(child)
        if child in {operation_id,value["parent_workflow_operation_id"]}:
            raise ValueError("remaining migration requires a separate new child operation")
    elif child is not None:raise ValueError("read/terminate reconciliation does not authorize a new child")
    return value


def authenticated_recovery_links_v1(source,db,*,parent_operation_id):
    """Actual signed per-parent ownership; no operation-wide member closure."""
    from .source_inspection_workflow_v1 import TABLE,COLUMNS
    rows=tuple(db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND json_extract(accepted_json,'$.schema')=? AND progress_json IS NOT NULL AND json_extract(input_json,'$.parent_workflow_operation_id')=? LIMIT 2",
        (source.lifecycle.namespace,ACCEPT_SCHEMA,parent_operation_id)))
    links={}
    for row in rows:
        accepted=json.loads(row[5]);value=json.loads(row[9])
        validate_held_core_row_v1(COLUMNS,row,authority_namespace=source.lifecycle.namespace)
        source.lifecycle.control.verify_original_v1(accepted,"accepted_digest")
        validate_resolution_v1(value,accepted)
        source.lifecycle.control.verify_original_v1(value,"resolution_digest")
        parent=source.workflow._row_v1(db,value["parent_workflow_operation_id"])
        if (parent[6]!="held" or parent[4]!=value["parent_accepted_digest"]
                or hold_snapshot_digest_v1(parent)!=value["parent_hold_digest"]):
            raise AuthorityUnavailable("held recovery resolution lost its exact immutable parent")
        if parent[1] in links:
            raise AuthorityUnavailable("more than one signed recovery owns the same held parent")
        links[parent[1]]=(row,value)
    return links


@dataclass(frozen=True,eq=False)
class _HeldInspectionMigrationPhaseV1:
    accepted: object
    action: str
    operation_id: str
    db: object
    thread_id: int
    context: object

    @property
    def original(self):return self.accepted.original

    def require_v1(self,lifecycle,action):
        if (_PHASES.get(self)!=(self.accepted,self.db,self.thread_id)
                or action!="migrate" or self.action!=action or self.accepted.manager.lifecycle is not lifecycle
                or self.db is not lifecycle.core._db or not self.db.in_transaction
                or self.thread_id!=threading.get_ident()
                or self.accepted.manager.workflow._phase_context is not self.context):
            raise AuthorityUnavailable("actual held recovery migration phase required")
        self.accepted.require_current_v1(self.db)
        links=authenticated_recovery_links_v1(self.accepted.manager.source,self.db,parent_operation_id=self.original["input"]["parent_workflow_operation_id"])
        binding=links.get(self.original["input"]["parent_workflow_operation_id"])
        if binding is None or binding[0][1]!=self.original["operation_id"] or binding[1]["kind"]!="ownership":
            raise AuthorityUnavailable("new child lost its exact signed held-parent ownership")
        return self


class _AcceptedHeldInspectionV1:
    def __init__(self,issuer,manager,row):
        if issuer is not _ISSUER:raise AuthorityUnavailable("actual held inspection issuer required")
        self.manager,self.row=manager,row
        self.original=json.loads(row[5])
        _ACCEPTED[self]=(manager,row[1],row[4])

    def require_current_v1(self,db):
        manager=self.manager;lifecycle=manager.lifecycle;value=self.original
        row=manager.workflow._row_v1(db,self.row[1])
        if (_ACCEPTED.get(self)!=(manager,row[1],row[4]) or row[5]!=self.row[5]
                or row[6] not in {"accepted","running"} or db is not lifecycle.core._db or not db.in_transaction):
            raise AuthorityUnavailable("held recovery lost its actual new durable authorization")
        lifecycle.control.verify_original_v1(value,"accepted_digest")
        if time.time()>=value["effective_deadline_utc"]:raise AuthorityUnavailable("new held recovery authorization expired")
        resource=manager.workflow.resources.qualify_current_v1(lifecycle=lifecycle)
        resource.require_current_v1(lifecycle=lifecycle)
        context,storage=lifecycle._storage()
        selected,cohort,configuration=manager.source.files.read_selected_configuration_cohort_v2()
        if (resource.as_original_v1()!=value["resource_original"] or storage!=value["storage"]
                or asdict(selected)!=value["selected_pointer"] or cohort.cohort_digest!=value["cohort_digest"]
                or manager.source.registry.catalogue_hash!=value["catalogue_hash"]
                or configuration["host_profile"]["installation_policy"]["catalogue_hash"]!=value["catalogue_hash"]):
            raise AuthorityUnavailable("new held recovery resource/storage/package binding changed")
        request=manager.workflow._session_request_v1(value);sessions=lifecycle.status_service.sessions
        sessions._current_key(db,request)
        sessions._current_pairing_source.require_current_actor_in_tx(db,authority_namespace=lifecycle.namespace,
            installation_id=lifecycle.installation_id,actor_id=value["actor"],principal=request.principal)
        guard=lifecycle.status_service.tickets._checked_current_head(db,lifecycle.namespace)
        if (guard is None or guard.authorization_head!=value["owner_head"] or guard.pending_revoke_operation_id is not None
                or guard.minimum_revocation_revision or guard.minimum_revocation_epoch):
            raise AuthorityUnavailable("new held recovery current Owner changed")
        manager.source._actual_owner_grant_v1(db,context,storage,actor=value["actor"],session_request=request,
            required={"workbench.read","workbench.maintain","workbench.control"})
        facts=manager.require_original_pause_v1(db,value,storage)
        if value["input"]["disposition"]=="reconcile_active_completed":
            current=facts[4];saved=value["active_evidence"]
            if saved is None or any(current[key]!=saved[key] for key in current if key!="supervisor_observation_digest"):
                raise AuthorityUnavailable("active reconciliation Host birth/receipt changed after acceptance")
        frozen=manager.workflow._phase_context
        if frozen is not None and value["input"]["disposition"]!="reconcile_active_completed":
            lifecycle._constraints_in_tx(db,frozen[1],frozen[2],storage,qualified_context=context)
        return context,storage

    def issue_migration_v1(self,db):
        self.require_current_v1(db)
        manager=self.manager;value=self.original
        frozen=manager.workflow._phase_context
        if (frozen is None or frozen[0] is not db or value["input"]["disposition"]!="continue_remaining"
                or any(manager.lifecycle._counts(db))):
            raise AuthorityUnavailable("new remaining migration needs actual frozen/drained admission")
        phase=_HeldInspectionMigrationPhaseV1(self,"migrate",value["source_request"]["operation_id"],
            db,threading.get_ident(),frozen)
        _PHASES[phase]=(self,db,phase.thread_id)
        phase.require_v1(manager.lifecycle,"migrate")
        return phase


class InstalledHeldInspectionReconciliationV1:
    def __init__(self,workflow):
        self.workflow,self.source,self.lifecycle=workflow,workflow.source,workflow.lifecycle

    def require_original_pause_v1(self,db,accepted,storage):
        if accepted["input"]["disposition"]=="reconcile_active_completed":
            return self.require_active_completed_v1(db,accepted,storage)
        return self._require_paused_original_v1(db,accepted,storage)

    def _require_paused_original_v1(self,db,accepted,storage):
        from .source_inspection_workflow_v1 import validate_inspection_control_original_v1
        from .d12_installation_lifecycle_v1 import OPS,RECEIPTS
        from .d12_lifecycle_contract_v1 import lifecycle_receipt_from_wire_v1
        parent=self.workflow._row_v1(db,accepted["input"]["parent_workflow_operation_id"])
        if (parent[6]!="held" or parent[4]!=accepted["input"]["parent_accepted_digest"]
                or hold_snapshot_digest_v1(parent)!=accepted["input"]["parent_hold_digest"]):
            raise AuthorityUnavailable("original held workflow snapshot changed")
        original=json.loads(parent[5])
        self.lifecycle.control.verify_original_v1(original,"accepted_digest")
        if original["schema"]=="sylanne.source-inspection-workflow-accepted.v1":
            pause_id=original["input"]["pause_operation_id"]
            root_operation_id=parent[1];root_accepted_digest=parent[4]
        elif original["schema"]==ACCEPT_SCHEMA and original["source_request"] is not None and parent[9] is not None:
            previous=validate_resolution_v1(json.loads(parent[9]),original)
            self.lifecycle.control.verify_original_v1(previous,"resolution_digest")
            if previous["kind"]!="ownership":raise AuthorityUnavailable("only actual held migration ownership can be reconciled")
            pause_id=original["pause_operation_id"]
            root_operation_id=original["root_workflow_operation_id"];root_accepted_digest=original["root_accepted_digest"]
        else:
            raise AuthorityUnavailable("held recovery has no registered current migration ownership")
        head=read_lifecycle_head_in_tx_v1(db,self.lifecycle.namespace)
        pause=db.execute(f"SELECT * FROM {OPS} WHERE namespace=? AND operation_id=?",(self.lifecycle.namespace,pause_id)).fetchone()
        if (head is None or head.state!="paused" or head.operation_id!=pause_id
                or head.epoch!=accepted["input"]["expected_lifecycle_epoch"]
                or head.head_digest!=accepted["input"]["expected_lifecycle_head_digest"]
                or pause is None or pause[3]!="pause" or pause[13]!="paused" or pause[15] is not None
                or json.loads(pause[10])!=storage or not self.lifecycle.supervisor.read_current_host_state_v1().stopped_and_drained):
            raise AuthorityUnavailable("held recovery has no actual terminal stopped/drained native pause")
        native=validate_inspection_control_original_v1(pause[5],authority_namespace=self.lifecycle.namespace)
        self.lifecycle.control.verify_original_v1(native,"original_digest")
        if (native["schema"]!="d12.source-inspection-control-original.v1"
                or native["workflow_operation_id"]!=root_operation_id or native["accepted_digest"]!=root_accepted_digest
                or native["operation_id"]!=pause[1] or native["request_digest"]!=pause[2]
                or pause[4]!="d12inspectioncontrol:"+native["original_digest"]
                or native["owner_head"]!=pause[9] or native["storage_identity_digest"]!=canonical_digest(storage)):
            raise AuthorityUnavailable("held native pause has another actual causal parent")
        row=db.execute(f"SELECT original_json FROM {RECEIPTS} WHERE original_ref=?",(pause[14],)).fetchone()
        if row is None:raise AuthorityUnavailable("held native paused receipt is absent")
        receipt=lifecycle_receipt_from_wire_v1(json.loads(row[0]))
        from ..runtime.lifecycle_operations_v1 import digest
        if (receipt.stage!="paused" or receipt.action!="pause" or receipt.operation_id!=pause_id
                or receipt.lifecycle_epoch!=head.epoch or receipt.authority_namespace!=self.lifecycle.namespace
                or receipt.installation_id!=self.lifecycle.installation_id or receipt.original_ref!=pause[14]
                or receipt.request_digest!=pause[2] or receipt.owner_head!=pause[9]
                or receipt.storage_identity_digest!=digest(storage)
                or db.execute("SELECT current_receipt_ref FROM authority_d12_lifecycle_heads_v1 WHERE namespace=?",
                    (self.lifecycle.namespace,)).fetchone()!=(pause[14],)):
            raise AuthorityUnavailable("held native pause lacks its actual terminal receipt/OPS/head binding")
        return parent,original,pause,receipt


    def require_active_completed_v1(self,db,accepted,storage):
        """Authenticate actual active originals and Host birth; never start or stop."""
        from .source_inspection_workflow_v1 import validate_inspection_control_original_v1
        from .source_inspection_recovery_v1 import ACCEPT_SCHEMA as RESUME_SCHEMA
        from .d12_installation_lifecycle_v1 import OPS,RECEIPTS,BOOTS
        from .d12_lifecycle_contract_v1 import lifecycle_receipt_from_wire_v1
        from .c09_process_identity_v1 import read_process_identity_v1
        from ..runtime.lifecycle_operations_v1 import digest
        from ..runtime_contracts import canonical_serialize
        value=accepted["input"];lifecycle=self.lifecycle
        parent=self.workflow._row_v1(db,value["parent_workflow_operation_id"])
        if (parent[6]!="held" or parent[4]!=value["parent_accepted_digest"] or hold_snapshot_digest_v1(parent)!=value["parent_hold_digest"]):
            raise AuthorityUnavailable("active reconciliation original held snapshot changed")
        original=json.loads(parent[5]);lifecycle.control.verify_original_v1(original,"accepted_digest")
        if original["schema"]=="sylanne.source-inspection-workflow-accepted.v1" and original["input"]["resume_on_complete"]:
            resume_id=original["input"]["resume_operation_id"];pause_id=original["input"]["pause_operation_id"]
        elif original["schema"]==RESUME_SCHEMA:
            resume_id=parent[1];pause_id=original["input"]["pause_operation_id"]
        else:raise AuthorityUnavailable("held parent has no registered completed native resume")
        head=read_lifecycle_head_in_tx_v1(db,lifecycle.namespace)
        resumed=db.execute(f"SELECT * FROM {OPS} WHERE namespace=? AND operation_id=?",(lifecycle.namespace,resume_id)).fetchone()
        pause=db.execute(f"SELECT * FROM {OPS} WHERE namespace=? AND operation_id=?",(lifecycle.namespace,pause_id)).fetchone()
        if (head.state!="active" or head.operation_id!=resume_id or head.epoch!=value["expected_lifecycle_epoch"]
                or head.head_digest!=value["expected_lifecycle_head_digest"] or resumed is None or pause is None
                or resumed[3]!="resume" or resumed[13]!="active" or resumed[15] is not None
                or json.loads(resumed[10])!=storage or json.loads(pause[10])!=storage):
            raise AuthorityUnavailable("active reconciliation has no exact terminal native resume/current head")
        native=validate_inspection_control_original_v1(resumed[5],authority_namespace=lifecycle.namespace)
        lifecycle.control.verify_original_v1(native,"original_digest")
        if (native["workflow_operation_id"]!=parent[1] or native["accepted_digest"]!=parent[4]
                or native["operation_id"]!=resume_id or native["action"]!="resume"
                or native["request_digest"]!=resumed[2] or native["owner_head"]!=resumed[9]
                or native["storage_identity_digest"]!=canonical_digest(storage)
                or resumed[4]!="d12inspectioncontrol:"+native["original_digest"]
                or native["intent"]["prior_pause_operation_id"]!=pause_id):
            raise AuthorityUnavailable("active native resume has another actual causal authorization")
        row=db.execute(f"SELECT original_json FROM {RECEIPTS} WHERE original_ref=?",(resumed[14],)).fetchone()
        paused_row=db.execute(f"SELECT original_json FROM {RECEIPTS} WHERE original_ref=?",(pause[14],)).fetchone()
        if row is None or paused_row is None:raise AuthorityUnavailable("actual active/paused native receipts are absent")
        receipt=lifecycle_receipt_from_wire_v1(json.loads(row[0]))
        paused=lifecycle_receipt_from_wire_v1(json.loads(paused_row[0]))
        if (receipt.stage!="active" or receipt.action!="resume" or receipt.operation_id!=resume_id
                or receipt.authority_namespace!=lifecycle.namespace or receipt.installation_id!=lifecycle.installation_id
                or receipt.original_ref!=resumed[14] or receipt.request_digest!=resumed[2]
                or receipt.owner_head!=resumed[9] or receipt.storage_identity_digest!=digest(storage)
                or receipt.lifecycle_epoch!=head.epoch or paused.stage!="paused" or paused.action!="pause"
                or paused.operation_id!=pause_id or paused.original_ref!=pause[14] or paused.request_digest!=pause[2]
                or paused.authority_namespace!=lifecycle.namespace or paused.installation_id!=lifecycle.installation_id
                or paused.owner_head!=pause[9] or paused.storage_identity_digest!=digest(storage)
                or paused.lifecycle_epoch!=native["intent"]["expected_lifecycle_epoch"]
                or receipt.lifecycle_epoch!=paused.lifecycle_epoch+1
                or db.execute("SELECT current_receipt_ref FROM authority_d12_lifecycle_heads_v1 WHERE namespace=?",
                    (lifecycle.namespace,)).fetchone()!=(resumed[14],)):
            raise AuthorityUnavailable("actual active receipt does not bind its OPS/storage/current head")
        boot=db.execute(f"SELECT * FROM {BOOTS} WHERE namespace=? AND epoch=? AND operation_id=? AND original_ref=?",
            (lifecycle.namespace,head.epoch,resume_id,receipt.bootstrap_original_ref)).fetchone()
        observed=lifecycle.supervisor.read_current_host_state_v1()
        process=None if observed.main_pid==0 else read_process_identity_v1(observed.main_pid)
        verified=lifecycle._verify_package_in_host(observed)
        if (boot is None or observed.active_state!="active" or process is None or observed.main_pid not in observed.process_ids
                or boot[3:5]!=lifecycle.peer or boot[5]!=canonical_serialize(process) or boot[6]!=observed.invocation_id
                or boot[7]!=lifecycle.expected_manifest_digest or verified.catalogue_hash!=self.source.registry.catalogue_hash
                or boot[10]!="d12bootstrap:"+digest(tuple(boot[:10]))[7:]
                or boot[11]!=digest(tuple(boot[:11])) or receipt.process_identity_digest!=digest(process)):
            raise AuthorityUnavailable("actual Host birth/package/bootstrap does not prove the original active completion")
        return parent,original,pause,paused,dict(schema="sylanne.source-inspection-active-completion-evidence.v1",
            resume_operation_id=resume_id,active_receipt_digest=receipt.original_digest,active_receipt_ref=receipt.original_ref,
            bootstrap_original_ref=boot[10],bootstrap_original_digest=boot[11],process_identity_digest=digest(process),
            supervisor_observation_digest=observed.observation_digest,invocation_id=observed.invocation_id,
            package_manifest_digest=lifecycle.expected_manifest_digest)

    def _available_parent_v1(self,db,parent_id,operation_id=None):
        from .source_inspection_workflow_v1 import TABLE
        links=authenticated_recovery_links_v1(self.source,db,parent_operation_id=parent_id)
        if parent_id in links:raise AuthorityUnavailable("held parent already has its own signed recovery owner")
        rows=db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND state!='completed' AND operation_id!=?",
            (self.lifecycle.namespace,parent_id)).fetchall()
        for row in rows:
            if row[1]==operation_id or replacement_for_operation_v1(self.source,db,row[1]) is not None:continue
            value=json.loads(row[5])
            if value["schema"]==ACCEPT_SCHEMA and row[6]=="held" and row[9] is None:
                from .source_inspection_workflow_v1 import COLUMNS
                validate_held_core_row_v1(COLUMNS,row,authority_namespace=self.lifecycle.namespace)
                self.lifecycle.control.verify_original_v1(value,"accepted_digest")
                continue
            raise AuthorityUnavailable("another actual maintenance recovery owns this installation")

    def _link_v1(self,db,row,kind,classification,commitment):
        from .source_inspection_workflow_v1 import TABLE
        value=json.loads(row[5])
        parent_id=value["input"]["parent_workflow_operation_id"]
        actual=authenticated_recovery_links_v1(self.source,db,parent_operation_id=parent_id).get(parent_id)
        if actual is not None and actual[0][1]!=row[1]:
            raise AuthorityUnavailable("another signed resolution already owns this immutable held parent")
        body=dict(schema=LINK_SCHEMA,kind=kind,authority_namespace=self.lifecycle.namespace,
            installation_id=self.lifecycle.installation_id,recovery_operation_id=row[1],recovery_accepted_digest=row[4],
            parent_workflow_operation_id=parent_id,parent_accepted_digest=value["input"]["parent_accepted_digest"],
            parent_hold_digest=value["input"]["parent_hold_digest"],parent_child_operation_id=value["parent_child_operation_id"],
            child_operation_id=value["input"]["child_migration_operation_id"],classification=classification,
            pause_operation_id=value["pause_operation_id"],pause_receipt_digest=value["pause_receipt_digest"],
            boundary_digest=canonical_digest(value["boundary"]),completed_commitment=commitment,
            active_evidence_digest=None if value["active_evidence"] is None else canonical_digest(value["active_evidence"]))
        link=self.lifecycle.control.sign_original_v1(LINK_SCHEMA,body,"resolution_digest")
        previous=row[9]
        if db.execute(f"UPDATE {TABLE} SET progress_json=? WHERE namespace=? AND operation_id=? AND accepted_digest=? AND progress_json IS ?",
                (canonical_json(link),self.lifecycle.namespace,row[1],row[4],previous)).rowcount!=1:
            raise AuthorityUnavailable("held parent resolution ownership CAS changed")
        return link

    def accept_v1(self,*,credential,actor,session_token,session_request,operation_id,input_data):
        from .source_inspection_workflow_v1 import TABLE
        from .source_inspection_migration_v1 import decode_source_inspection_migration_request_v1
        from .v2_owner_session import _verifier,_time
        validate_held_input_v1(operation_id,input_data)
        lifecycle=self.lifecycle
        lifecycle.core._require(credential,"d12_lifecycle_control",lifecycle.namespace)
        context,storage=lifecycle._storage()
        with lifecycle.fences._frozen() as (db,deletion,execution,_):
            guard=lifecycle.status_service.tickets._checked_current_head(db,lifecycle.namespace)
            if guard is None:raise AuthorityUnavailable("held recovery current Owner head absent")
            lifecycle.status_service._current_session_in_tx(db,actor=actor,token=session_token,request=session_request,
                expected_head=guard.authorization_head)
            grant,owner=self.source._actual_owner_grant_v1(db,context,storage,actor=actor,session_request=session_request,
                required={"workbench.read","workbench.maintain","workbench.control"})
            prior=db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=?",(lifecycle.namespace,operation_id)).fetchone()
            if prior is not None:
                value=json.loads(prior[5]);lifecycle.control.verify_original_v1(value,"accepted_digest")
                if (value["schema"]!=ACCEPT_SCHEMA or prior[2]!=canonical_digest(input_data)
                        or value["actor"]!=actor or value["owner_head"]!=guard.authorization_head
                        or value["public_session_request"]["principal"]!=asdict(session_request.principal)):
                    raise AuthorityUnavailable("held reconciliation retry changes its original submitted authorization")
                return self.view_v1(prior)
            parent=self.workflow._row_v1(db,input_data["parent_workflow_operation_id"])
            self._available_parent_v1(db,parent[1],operation_id)
            if parent[6]!="held" or parent[4]!=input_data["parent_accepted_digest"] or hold_snapshot_digest_v1(parent)!=input_data["parent_hold_digest"]:
                raise AuthorityUnavailable("held reconciliation expected first-failure snapshot differs")
            original=json.loads(parent[5]);lifecycle.control.verify_original_v1(original,"accepted_digest")
            resource=self.workflow.resources.qualify_current_v1(lifecycle=lifecycle)
            resource.require_current_v1(lifecycle=lifecycle)
            session=db.execute("SELECT expires_at_utc FROM authority_owner_sessions_v1 WHERE verifier=?",(_verifier(session_token),)).fetchone()
            effective=min(input_data["deadline_utc"],_time(session[0]).timestamp(),resource.deadline_utc,time.time()+3600)
            if (effective<=time.time() or canonical_digest(storage)!=input_data["expected_storage_identity_digest"]
                    or resource.binding_digest!=input_data["expected_resource_binding_digest"]):
                raise AuthorityUnavailable("held reconciliation actual resource/storage/deadline differs")
            provisional=dict(input=input_data)
            facts=self.require_original_pause_v1(db,provisional,storage)
            parent,original,pause,receipt=facts[:4]
            active_evidence=facts[4] if input_data["disposition"]=="reconcile_active_completed" else None
            self.workflow.recovery._unconsumed_v1(db,operation_id,pause[1])
            child_id=input_data["child_migration_operation_id"]
            if child_id is not None:
                if child_id in {pause[1],original["input"].get("resume_operation_id"),original["source_request"]["operation_id"]}:
                    raise AuthorityUnavailable("remaining child reuses an original native operation")
                self.workflow.recovery._unconsumed_v1(db,child_id,pause[1])
            if active_evidence is not None:
                if original["schema"]=="sylanne.source-inspection-workflow-accepted.v1":
                    commitment=self.workflow.recovery._completed_child_v1(db,parent,context,storage,operation_id,effective)
                else:
                    commitment=original["child_commitment"]
                active_evidence["completed_commitment"]=commitment
                boundary=dict(kind="active_completed",completed_commitment_digest=canonical_digest(commitment),
                    active_evidence_digest=canonical_digest(active_evidence))
            else:
                if any(lifecycle._counts(db)):raise AuthorityUnavailable("held reconciliation Core admissions are not drained")
                lifecycle._constraints_in_tx(db,deletion,execution,storage,qualified_context=context)
                try:
                    boundary=self.workflow.recovery.read_child_boundary_v1(db,parent,context,storage,operation_id,effective)
                except Exception:
                    boundary={"kind":"unknown"}
            selected,cohort,configuration=self.source.files.read_selected_configuration_cohort_v2()
            request=None
            if child_id is not None:
                request=dict(original["source_request"])
                request.update(operation_id=child_id,actor=actor,storage=storage,selected_pointer=asdict(selected),
                    cohort_digest=cohort.cohort_digest,catalogue_hash=self.source.registry.catalogue_hash,deadline_utc=effective)
                decode_source_inspection_migration_request_v1(canonical_json(request),authority_namespace=lifecycle.namespace)
            value=lifecycle.control.sign_original_v1(ACCEPT_SCHEMA,dict(schema=ACCEPT_SCHEMA,namespace=asdict(lifecycle.namespace_id),
                authority_namespace=lifecycle.namespace,installation_id=lifecycle.installation_id,operation_id=operation_id,
                input=input_data,input_digest=canonical_digest(input_data),actor=actor,owner_head=guard.authorization_head,
                public_session_request=asdict(session_request),owner_grant_digest=owner.grant_digest,storage=storage,
                selected_pointer=asdict(selected),cohort_digest=cohort.cohort_digest,catalogue_hash=self.source.registry.catalogue_hash,
                accepted_at_utc=time.time(),owner_authorization_deadline_utc=_time(session[0]).timestamp(),
                resource_original=resource.as_original_v1(),effective_deadline_utc=effective,pause_operation_id=pause[1],
                pause_receipt_digest=receipt.original_digest,boundary=boundary,source_request=request,
                parent_child_operation_id=(original["source_request"]["operation_id"] if "source_request" in original
                    and original["source_request"] is not None else parent[1]),
                root_workflow_operation_id=parent[1] if original["schema"]!=ACCEPT_SCHEMA else original["root_workflow_operation_id"],
                root_accepted_digest=parent[4] if original["schema"]!=ACCEPT_SCHEMA else original["root_accepted_digest"],
                active_evidence=active_evidence),"accepted_digest")
            row=(lifecycle.namespace,operation_id,canonical_digest(input_data),canonical_json(input_data),value["accepted_digest"],
                canonical_json(value),"accepted","accepted",None,None)
            db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?,?,?,?)",row)
            result=self.view_v1(row)
        self.workflow._start_worker_v1(operation_id)
        return result

    def view_v1(self,row):
        value=json.loads(row[5])
        return dict(schema=VIEW_SCHEMA,scope="/".join(self.lifecycle.namespace_id.as_tuple),
            installation_id=self.lifecycle.installation_id,operation_id=row[1],request_digest=row[2],state=row[6],phase=row[7],
            hold_code=row[8],effective_deadline_utc=value["effective_deadline_utc"],
            classification=None if row[9] is None else json.loads(row[9])["classification"],**value["input"])

    def run_v1(self,operation_id):
        from .source_inspection_workflow_v1 import TABLE
        from .source_inspection_migration_v1 import TABLE as SOURCE
        lifecycle=self.lifecycle;child_id=None
        try:
            while not self.workflow._closed.is_set() and not lifecycle._closed.is_set():
                with lifecycle.core._tx() as db:
                    original=json.loads(self.workflow._row_v1(db,operation_id)[5]);child_id=original["input"]["child_migration_operation_id"]
                active=self.source._active.get(child_id)
                if active is not None:
                    from ..runtime.source_inspection_metadata_read_v3 import resolve_pending_inspection_metadata_core_v3
                    resolve_pending_inspection_metadata_core_v3(active)
                with lifecycle.fences._frozen() as (db,deletion,execution,_):
                    row=self.workflow._row_v1(db,operation_id)
                    if row[6] in {"completed","held"}:return
                    self.workflow._phase_context=(db,deletion,execution,threading.get_ident())
                    accepted=_AcceptedHeldInspectionV1(_ISSUER,self,row)
                    context,storage=accepted.require_current_v1(db);value=accepted.original
                    if row[7]=="accepted":
                        db.execute(f"UPDATE {TABLE} SET state='running',phase='reconciling' WHERE namespace=? AND operation_id=?",
                            (lifecycle.namespace,operation_id))
                    elif row[7]=="reconciling":
                        if value["boundary"]["kind"]=="unknown":
                            raise AuthorityUnavailable("original observed boundary is unknown")
                        if value["input"]["disposition"]=="reconcile_active_completed":
                            self._link_v1(db,row,"resolution","recovered_active",value["active_evidence"]["completed_commitment"])
                            db.execute(f"UPDATE {TABLE} SET state='completed',phase='recovered_active' WHERE namespace=? AND operation_id=?",
                                (lifecycle.namespace,operation_id))
                            continue
                        parent=self.workflow._row_v1(db,value["input"]["parent_workflow_operation_id"])
                        boundary=self.workflow.recovery.read_child_boundary_v1(db,parent,context,storage,operation_id,value["effective_deadline_utc"])
                        if boundary!=value["boundary"]:raise AuthorityUnavailable("held durable boundary changed after fresh acceptance")
                        if boundary["kind"]=="completed":
                            self._link_v1(db,row,"resolution","recovered_complete_paused",boundary["completed_commitment"])
                            db.execute(f"UPDATE {TABLE} SET state='completed',phase='recovered_complete_paused' WHERE namespace=? AND operation_id=?",
                                (lifecycle.namespace,operation_id))
                        elif value["input"]["disposition"]=="terminate_paused":
                            if boundary["kind"]!="no_child":raise AuthorityUnavailable("published child cannot be silently terminated")
                            self._link_v1(db,row,"resolution","terminal_paused",None)
                            db.execute(f"UPDATE {TABLE} SET state='completed',phase='terminal_paused' WHERE namespace=? AND operation_id=?",
                                (lifecycle.namespace,operation_id))
                        elif value["input"]["disposition"]=="continue_remaining":
                            self._link_v1(db,row,"ownership","continuing_remaining",None)
                            db.execute(f"UPDATE {TABLE} SET state='running',phase='continuing_remaining' WHERE namespace=? AND operation_id=?",
                                (lifecycle.namespace,operation_id))
                        else:
                            db.execute(f"UPDATE {TABLE} SET state='completed',phase='reconciled_read_only' WHERE namespace=? AND operation_id=?",
                                (lifecycle.namespace,operation_id))
                    elif row[7]=="continuing_remaining":
                        phase=accepted.issue_migration_v1(db)
                        result=self.source.advance_accepted_workflow_phase_v1(phase)
                        if result["phase"]=="completed":
                            child=db.execute(f"SELECT * FROM {SOURCE} WHERE namespace=? AND operation_id=?",(lifecycle.namespace,child_id)).fetchone()
                            from .source_inspection_migration_v1 import COLUMNS as SOURCE_COLUMNS,validate_source_inspection_migration_core_row_v1
                            actual=validate_source_inspection_migration_core_row_v1(SOURCE_COLUMNS,child,authority_namespace=lifecycle.namespace)
                            commitment=dict(operation_id=child_id,request_digest=actual["request_digest"],
                                accepted_digest=actual["accepted_digest"],receipt_digest=canonical_digest(result),
                                producer_operation_id=result["producer_operation_id"],event_digest=result["event_digest"])
                            self._link_v1(db,row,"resolution","recovered_complete_paused",commitment)
                            db.execute(f"UPDATE {TABLE} SET state='completed',phase='recovered_complete_paused' WHERE namespace=? AND operation_id=?",
                                (lifecycle.namespace,operation_id))
                    else:raise AuthorityUnavailable("unregistered held reconciliation phase")
                self.workflow._phase_context=None
                self.workflow._closed.wait(0.05)
        except Exception:
            with lifecycle.core._tx() as db:
                db.execute(f"UPDATE {TABLE} SET state='held',phase='unknown_boundary',hold_code='unknown_boundary' WHERE namespace=? AND operation_id=? AND state IN ('accepted','running')",
                    (lifecycle.namespace,operation_id))
            work=self.source._active.pop(child_id,None)
            if work is not None:work.close_v1()
        finally:self.workflow._phase_context=None


def validate_resolution_v1(value,accepted):
    from .c09_storage_control_v1 import digest as control_digest
    fields={"schema","kind","authority_namespace","installation_id","recovery_operation_id","recovery_accepted_digest",
        "parent_workflow_operation_id","parent_accepted_digest","parent_hold_digest","parent_child_operation_id",
        "child_operation_id","classification","pause_operation_id","pause_receipt_digest","boundary_digest",
        "completed_commitment","active_evidence_digest","key_id","resolution_digest","signature"}
    if (type(value) is not dict or set(value)!=fields or value["schema"]!=LINK_SCHEMA or value["kind"] not in {"ownership","resolution"}
            or value["authority_namespace"]!=accepted["authority_namespace"] or value["installation_id"]!=accepted["installation_id"]
            or value["recovery_operation_id"]!=accepted["operation_id"] or value["recovery_accepted_digest"]!=accepted["accepted_digest"]
            or value["parent_workflow_operation_id"]!=accepted["input"]["parent_workflow_operation_id"]
            or value["parent_accepted_digest"]!=accepted["input"]["parent_accepted_digest"]
            or value["parent_hold_digest"]!=accepted["input"]["parent_hold_digest"]
            or value["parent_child_operation_id"]!=accepted["parent_child_operation_id"]
            or value["child_operation_id"]!=accepted["input"]["child_migration_operation_id"]
            or value["pause_operation_id"]!=accepted["pause_operation_id"]
            or value["pause_receipt_digest"]!=accepted["pause_receipt_digest"]
            or value["boundary_digest"]!=canonical_digest(accepted["boundary"])
            or value["active_evidence_digest"]!=(None if accepted["active_evidence"] is None else canonical_digest(accepted["active_evidence"]))
            or control_digest({k:v for k,v in value.items() if k not in {"resolution_digest","signature"}})!=value["resolution_digest"]):
        raise AuthorityUnavailable("held recovery signed parent-resolution grammar differs")
    if (value["kind"]=="ownership")!=(value["classification"]=="continuing_remaining"):
        raise AuthorityUnavailable("held recovery resolution classification differs")
    if value["classification"] not in {"continuing_remaining","recovered_complete_paused","terminal_paused","recovered_active"}:
        raise AuthorityUnavailable("held recovery resolution disposition differs")
    commitment=value["completed_commitment"]
    if value["classification"]=="recovered_complete_paused":
        validate_completed_commitment_v1(commitment)
        expected=accepted["input"]["child_migration_operation_id"] if accepted["boundary"]["kind"]!="completed" else accepted["parent_child_operation_id"]
        if commitment["operation_id"]!=expected:
            raise AuthorityUnavailable("held resolution completion names another actual child")
    elif value["classification"]=="recovered_active":
        if (accepted["input"]["disposition"]!="reconcile_active_completed" or accepted["active_evidence"] is None
                or commitment!=accepted["active_evidence"]["completed_commitment"]):
            raise AuthorityUnavailable("active resolution has no actual accepted Host completion evidence")
    elif commitment is not None:
        raise AuthorityUnavailable("held ownership/no-child resolution cannot carry a claimed completion")
    return value


def validate_completed_commitment_v1(value):
    from .source_inspection_migration_v1 import _uuid_v1,_sha_v1
    if type(value) is not dict or set(value)!={"operation_id","request_digest","accepted_digest","receipt_digest","producer_operation_id","event_digest"}:
        raise AuthorityUnavailable("actual completed child commitment fields differ")
    _uuid_v1(value["operation_id"])
    producer=UUID(value["producer_operation_id"])
    if producer.version!=5 or str(producer)!=value["producer_operation_id"]:
        raise AuthorityUnavailable("actual completed child producer differs")
    for name in ("request_digest","accepted_digest","receipt_digest","event_digest"):_sha_v1(value[name])
    return value


def validate_held_core_row_v1(columns,row,*,authority_namespace):
    from .source_inspection_workflow_v1 import COLUMNS
    from .source_inspection_migration_v1 import decode_source_inspection_migration_request_v1
    from .c09_storage_control_v1 import digest as control_digest
    fields={"schema","namespace","authority_namespace","installation_id","operation_id","input","input_digest","actor",
        "owner_head","public_session_request","owner_grant_digest","storage","selected_pointer","cohort_digest","catalogue_hash",
        "accepted_at_utc","owner_authorization_deadline_utc","resource_original","effective_deadline_utc","pause_operation_id",
        "pause_receipt_digest","boundary","source_request","active_evidence","parent_child_operation_id","root_workflow_operation_id","root_accepted_digest","key_id","accepted_digest","signature"}
    if columns!=COLUMNS or len(row)!=len(columns) or row[0]!=authority_namespace:
        raise AuthorityUnavailable("held reconciliation Core columns differ")
    value=json.loads(row[5]);submitted=json.loads(row[3])
    if (type(value) is not dict or set(value)!=fields or value["schema"]!=ACCEPT_SCHEMA or canonical_json(value)!=row[5]
            or canonical_json(submitted)!=row[3] or value["input"]!=submitted or canonical_digest(submitted)!=row[2]
            or value["input_digest"]!=row[2] or value["operation_id"]!=row[1] or value["authority_namespace"]!=row[0]
            or value["accepted_digest"]!=row[4]
            or control_digest({k:v for k,v in value.items() if k not in {"accepted_digest","signature"}})!=row[4]
            or row[6] not in {"accepted","running","completed","held"}
            or row[7] not in {"accepted","reconciling","continuing_remaining","recovered_complete_paused","terminal_paused",
                "reconciled_read_only","unknown_boundary","recovered_active"}):
        raise AuthorityUnavailable("held reconciliation signed accepted row differs")
    validate_held_input_v1(row[1],submitted)
    from .source_inspection_migration_v1 import _uuid_v1,_sha_v1
    from ..runtime_contracts import NamespaceId
    NamespaceId(**value["namespace"])
    for name in ("parent_child_operation_id","root_workflow_operation_id","pause_operation_id"):_uuid_v1(value[name])
    for name in ("accepted_digest","signature","root_accepted_digest","cohort_digest","catalogue_hash"):_sha_v1(value[name])
    boundary=value["boundary"]
    if type(boundary) is not dict or boundary.get("kind") not in {"unknown","no_child","incomplete","completed","active_completed"}:
        raise AuthorityUnavailable("held reconciliation actual boundary kind differs")
    if boundary["kind"]=="unknown":
        if set(boundary)!={"kind"}:raise AuthorityUnavailable("unknown boundary cannot claim evidence")
    elif boundary["kind"]=="active_completed":
        if (set(boundary)!={"kind","completed_commitment_digest","active_evidence_digest"}
                or submitted["disposition"]!="reconcile_active_completed" or value["active_evidence"] is None
                or boundary["completed_commitment_digest"]!=canonical_digest(value["active_evidence"]["completed_commitment"])
                or boundary["active_evidence_digest"]!=canonical_digest(value["active_evidence"])):
            raise AuthorityUnavailable("active boundary lacks its actual completion/birth commitments")
        evidence=value["active_evidence"]
        expected_evidence={"schema","resume_operation_id","active_receipt_digest","active_receipt_ref","bootstrap_original_ref",
            "bootstrap_original_digest","process_identity_digest","supervisor_observation_digest","invocation_id",
            "package_manifest_digest","completed_commitment"}
        if set(evidence)!=expected_evidence or evidence["schema"]!="sylanne.source-inspection-active-completion-evidence.v1":
            raise AuthorityUnavailable("active completion evidence closed fields differ")
        _uuid_v1(evidence["resume_operation_id"])
        for name in ("active_receipt_digest","bootstrap_original_digest","process_identity_digest","supervisor_observation_digest"):
            _sha_v1(evidence[name].removeprefix("sha256:"))
        _sha_v1(evidence["package_manifest_digest"])
        commitment=evidence["completed_commitment"]
        if type(commitment) is dict and commitment.get("schema")=="sylanne.source-inspection-terminal-no-child.v1":
            if set(commitment)!={"schema","parent_workflow_operation_id","parent_accepted_digest","resolution_digest"}:
                raise AuthorityUnavailable("active no-child terminal certificate differs")
            _uuid_v1(commitment["parent_workflow_operation_id"])
            _sha_v1(commitment["parent_accepted_digest"]);_sha_v1(commitment["resolution_digest"])
        else:validate_completed_commitment_v1(commitment)
    else:
        if value["active_evidence"] is not None:raise AuthorityUnavailable("paused recovery cannot carry active evidence")
        if (set(boundary)!={"kind","operation_id","core_row_digest","graph_row_digest","last_receipt_digest",
                "graph_stamp","published_batches","completed_commitment"}
                or boundary["operation_id"]!=value["parent_child_operation_id"]
                or type(boundary["published_batches"]) is not int or boundary["published_batches"]<0):
            raise AuthorityUnavailable("held durable boundary closed fields differ")
        for name in ("core_row_digest","graph_row_digest","last_receipt_digest"):
            if boundary[name] is not None:_sha_v1(boundary[name])
        if boundary["kind"]=="completed":validate_completed_commitment_v1(boundary["completed_commitment"])
        elif boundary["completed_commitment"] is not None:raise AuthorityUnavailable("unfinished boundary claims completion")
    if (row[6]=="held")!=(row[7]=="unknown_boundary"):
        raise AuthorityUnavailable("held recovery first-failure state differs")
    request=value["source_request"];refs=()
    if request is not None:
        decoded=decode_source_inspection_migration_request_v1(canonical_json(request),authority_namespace=authority_namespace)
        if decoded["operation_id"]!=submitted["child_migration_operation_id"] or decoded["deadline_utc"]!=value["effective_deadline_utc"]:
            raise AuthorityUnavailable("new remaining migration changed its own signed operation/deadline")
        refs=tuple(decoded["target_refs"])
    elif submitted["disposition"]=="continue_remaining":raise AuthorityUnavailable("remaining migration authorization is absent")
    link=None if row[9] is None else json.loads(row[9])
    if link is not None:
        if canonical_json(link)!=row[9]:raise AuthorityUnavailable("held resolution is not canonical")
        validate_resolution_v1(link,value)
    if row[6]=="completed" and row[7]!="reconciled_read_only" and (link is None or link["kind"]!="resolution" or link["classification"]!=row[7]):
        raise AuthorityUnavailable("held reconciliation terminal state lacks actual signed resolution")
    return dict(operation_id=row[1],state=row[6],phase=row[7],request_digest=row[2],accepted_digest=row[4],
        accepted_original=value,input=submitted,progress=link,graph_refs=refs)


def replacement_for_operation_v1(source,db,operation_id):
    """Locate one exact signed replacement by workflow ID or actual child ID."""
    from .source_inspection_workflow_v1 import TABLE
    direct=authenticated_recovery_links_v1(source,db,parent_operation_id=operation_id).get(operation_id)
    if direct is not None:return direct
    rows=tuple(db.execute(f"SELECT operation_id,progress_json FROM {TABLE} WHERE namespace=? AND json_extract(progress_json,'$.schema')=? AND json_extract(progress_json,'$.parent_child_operation_id')=? LIMIT 2",
        (source.lifecycle.namespace,LINK_SCHEMA,operation_id)))
    if len(rows)>1:raise AuthorityUnavailable("more than one signed recovery replaces the same child")
    if not rows:return None
    parent=json.loads(rows[0][1])["parent_workflow_operation_id"]
    actual=authenticated_recovery_links_v1(source,db,parent_operation_id=parent).get(parent)
    if actual is None or actual[0][1]!=rows[0][0]:
        raise AuthorityUnavailable("child replacement has no actual authenticated parent ownership")
    return actual


def read_terminal_inspection_resolution_v1(db,*,control,namespace,operation_id):
    """C09 consumes only real terminal replacement chains in its current Core TX."""
    from .source_inspection_migration_v1 import InstalledSourceInspectionMigrationV1
    source=getattr(control,"_source_inspection_migration_service_v1",None)
    if not db.in_transaction:raise AuthorityUnavailable("terminal resolution requires the actual Core transaction")
    if (type(source) is not InstalledSourceInspectionMigrationV1 or source.lifecycle.control is not control
            or source.lifecycle.namespace!=namespace or source.lifecycle.core._db is not db):
        return None
    current=operation_id;seen=set()
    while current not in seen:
        seen.add(current)
        actual=replacement_for_operation_v1(source,db,current)
        if actual is None:return None
        row,link=actual
        if link["kind"]=="resolution":
            if row[6]!="completed":raise AuthorityUnavailable("signed terminal resolution is not actually completed")
            return dict(replaced_operation_id=operation_id,terminal_recovery_operation_id=row[1],resolution=link)
        current=row[1]
    raise AuthorityUnavailable("inspection replacement chain contains a cycle")
