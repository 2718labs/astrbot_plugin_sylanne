"""Fresh Owner authorization to resume a completed native inspection pause."""
from dataclasses import asdict,dataclass
import json
import math
from pathlib import Path
import sqlite3
import threading
import time
from weakref import WeakKeyDictionary

from .contract import AuthorityUnavailable
from .d12_lifecycle_gate_v1 import read_lifecycle_head_in_tx_v1
from ..contracts import canonical_json
from ..runtime_contracts import canonical_digest

ACCEPT_SCHEMA="sylanne.source-inspection-recovery-accepted.v1"
CONTROL_SCHEMA="d12.source-inspection-recovery-control-original.v1"
VIEW_SCHEMA="d12.source-inspection-recovery-view.v1"
INPUT_FIELDS=frozenset({"parent_workflow_operation_id","pause_operation_id","expected_lifecycle_epoch",
    "expected_lifecycle_head_digest","deadline_utc"})
ACCEPT_FIELDS=frozenset({"schema","action","namespace","authority_namespace","installation_id","operation_id",
    "input","input_digest","actor","owner_head","public_session_request","owner_grant_digest","storage",
    "selected_pointer","cohort_digest","catalogue_hash","accepted_at_utc","owner_authorization_deadline_utc",
    "resource_original","effective_deadline_utc","parent_accepted_digest","pause_receipt_digest",
    "child_commitment","key_id","accepted_digest","signature"})
CONTROL_FIELDS=frozenset({"schema","authority_namespace","installation_id","workflow_operation_id",
    "parent_workflow_operation_id","parent_pause_operation_id","parent_accepted_digest","pause_receipt_digest",
    "child_commitment_digest","accepted_digest","operation_id","action","request_digest","owner_head","intent",
    "storage_identity_digest","key_id","original_digest","signature"})
_ISSUER=object()
_ACCEPTED=WeakKeyDictionary()
_PHASES=WeakKeyDictionary()


def validate_recovery_input_v1(operation_id,value):
    from .source_inspection_migration_v1 import _uuid_v1,_sha_v1
    _uuid_v1(operation_id)
    if type(value) is not dict or set(value)!=INPUT_FIELDS:
        raise ValueError("completed inspection recovery exact input fields required")
    _uuid_v1(value["parent_workflow_operation_id"]);_uuid_v1(value["pause_operation_id"])
    if len({operation_id,value["parent_workflow_operation_id"],value["pause_operation_id"]})!=3:
        raise ValueError("fresh recovery and original pause/workflow identities must differ")
    if (type(value["expected_lifecycle_epoch"]) is not int or value["expected_lifecycle_epoch"]<0
            or type(value["deadline_utc"]) not in (int,float) or not math.isfinite(value["deadline_utc"])):
        raise ValueError("fresh recovery lifecycle epoch/deadline differs")
    _sha_v1(value["expected_lifecycle_head_digest"].removeprefix("sha256:"))
    return value


@dataclass(frozen=True,eq=False)
class _InspectionRecoveryPhaseV1:
    accepted: object
    action: str
    operation_id: str
    expected_lifecycle_epoch: int
    db: object
    thread_id: int
    context: object
    anchor: object

    @property
    def original(self):return self.accepted.original

    def require_v1(self,lifecycle,action):
        if (_PHASES.get(self)!=(self.accepted,self.db,self.thread_id) or action!="resume" or self.action!=action
                or self.accepted.manager.lifecycle is not lifecycle or self.db is not lifecycle.core._db
                or not self.db.in_transaction or self.thread_id!=threading.get_ident()
                or self.accepted.manager.workflow._phase_context is not self.context):
            raise AuthorityUnavailable("actual fresh inspection recovery phase required")
        self.accepted.require_current_v1(self.db)
        head=read_lifecycle_head_in_tx_v1(self.db,lifecycle.namespace)
        value=self.original["input"]
        if (head.state!="paused" or head.epoch!=self.expected_lifecycle_epoch
                or head.operation_id!=value["pause_operation_id"]
                or head.head_digest!=value["expected_lifecycle_head_digest"]
                or not lifecycle.supervisor.read_current_host_state_v1().stopped_and_drained):
            raise AuthorityUnavailable("fresh recovery lost its exact original paused lifecycle head")
        return self


class _AcceptedInspectionRecoveryV1:
    def __init__(self,issuer,manager,row):
        if issuer is not _ISSUER:raise AuthorityUnavailable("actual fresh inspection acceptance required")
        self.manager,self.row=manager,row
        self.original=json.loads(row[5])
        _ACCEPTED[self]=(manager,row[1],row[4])

    def require_current_v1(self,db):
        manager=self.manager;lifecycle=manager.lifecycle
        row=manager.workflow._row_v1(db,self.row[1])
        if (_ACCEPTED.get(self)!=(manager,row[1],row[4]) or db is not lifecycle.core._db
                or not db.in_transaction or row[5]!=self.row[5] or row[6] not in {"accepted","running"}):
            raise AuthorityUnavailable("fresh inspection recovery no longer owns its durable authorization")
        value=self.original
        lifecycle.control.verify_original_v1(value,"accepted_digest")
        if time.time()>=value["effective_deadline_utc"]:
            raise AuthorityUnavailable("fresh inspection recovery original deadline expired")
        resource=manager.workflow.resources.qualify_current_v1(lifecycle=lifecycle)
        resource.require_current_v1(lifecycle=lifecycle)
        if resource.as_original_v1()!=value["resource_original"]:
            raise AuthorityUnavailable("fresh inspection recovery Root resources changed")
        context,storage=lifecycle._storage()
        selected,cohort,configuration=manager.source.files.read_selected_configuration_cohort_v2()
        if (storage!=value["storage"] or asdict(selected)!=value["selected_pointer"]
                or cohort.cohort_digest!=value["cohort_digest"]
                or manager.source.registry.catalogue_hash!=value["catalogue_hash"]
                or configuration["host_profile"]["installation_policy"]["catalogue_hash"]!=value["catalogue_hash"]):
            raise AuthorityUnavailable("fresh inspection recovery current storage/package changed")
        request=manager.workflow._session_request_v1(value)
        sessions=lifecycle.status_service.sessions
        sessions._current_key(db,request)
        sessions._current_pairing_source.require_current_actor_in_tx(db,authority_namespace=lifecycle.namespace,
            installation_id=lifecycle.installation_id,actor_id=value["actor"],principal=request.principal)
        guard=lifecycle.status_service.tickets._checked_current_head(db,lifecycle.namespace)
        if (guard is None or guard.authorization_head!=value["owner_head"] or guard.pending_revoke_operation_id is not None
                or guard.minimum_revocation_revision or guard.minimum_revocation_epoch):
            raise AuthorityUnavailable("fresh inspection recovery current Owner changed")
        manager.source._actual_owner_grant_v1(db,context,storage,actor=value["actor"],session_request=request,
            required={"workbench.read","workbench.maintain","workbench.control"})
        return context,storage

    def issue_phase_v1(self,db):
        context,storage=self.require_current_v1(db)
        manager=self.manager
        frozen=manager.workflow._phase_context
        if frozen is None or frozen[0] is not db or frozen[3]!=threading.get_ident():
            raise AuthorityUnavailable("fresh recovery needs the real frozen journals")
        if any(manager.lifecycle._counts(db)):
            raise AuthorityUnavailable("fresh inspection recovery has undrained Core admissions")
        manager.lifecycle._constraints_in_tx(db,frozen[1],frozen[2],storage,qualified_context=context)
        anchor=manager.lifecycle.fences._current_locked(db,frozen[1],frozen[2],require_no_pending=False)
        phase=_InspectionRecoveryPhaseV1(self,"resume",self.row[1],self.original["input"]["expected_lifecycle_epoch"],
            db,threading.get_ident(),frozen,anchor)
        _PHASES[phase]=(self,db,phase.thread_id)
        phase.require_v1(manager.lifecycle,"resume")
        return phase


class InstalledInspectionRecoveryV1:
    def __init__(self,workflow):
        self.workflow,self.source,self.lifecycle=workflow,workflow.source,workflow.lifecycle

    def _unconsumed_v1(self,db,operation_id,pause_id):
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_c09_consumed_execution_v1'").fetchone():
            if db.execute("SELECT 1 FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND "
                    "((kind IN ('source_inspection_workflow_operation','source_inspection_migration_operation','d12_lifecycle_operation') AND item_id=?) "
                    "OR (kind='d12_lifecycle_operation' AND item_id=?))",
                    (self.lifecycle.namespace,operation_id,pause_id)).fetchone():
                raise AuthorityUnavailable("retired native recovery or original pause cannot be replayed")

    def _completed_child_v1(self,db,parent,context,storage,operation_id,deadline):
        from .source_inspection_migration_v1 import TABLE as SOURCE,COLUMNS as SOURCE_COLUMNS,validate_source_inspection_migration_core_row_v1
        from ..runtime.source_inspection_migration_v1 import (
            OPERATIONS,MEMBERS,COLUMNS,SESSION,validate_source_inspection_migration_row_v1,_fixed)
        from ..runtime_storage_v3 import (
            runtime_storage_operation_v3,runtime_storage_quantum_v3)
        from ..runtime.source_inspection_migration_v1 import install_source_inspection_runtime_v1
        child=db.execute(f"SELECT * FROM {SOURCE} WHERE namespace=? AND operation_id=?",
            (self.lifecycle.namespace,parent[1])).fetchone()
        if child is None:raise AuthorityUnavailable("original completed inspection child is absent")
        parsed=validate_source_inspection_migration_core_row_v1(SOURCE_COLUMNS,child,authority_namespace=self.lifecycle.namespace)
        self.lifecycle.control.verify_original_v1(parsed["accepted_original"],"accepted_digest")
        parent_original=json.loads(parent[5])
        if (parsed["request"]!=parent_original["source_request"]
                or parsed["accepted_original"]["workflow_accepted_digest"]!=parent[4]):
            raise AuthorityUnavailable("completed inspection child has another signed accepted parent")
        if parsed["state"]!="completed" or parsed["receipt"]["phase"]!="completed":
            raise AuthorityUnavailable("original inspection child has no completed Core receipt")
        path=next(member["resolved_path"] for member in storage["members"] if member["role"]=="graph")
        graph=sqlite3.connect(Path(path).as_uri()+"?mode=ro",uri=True,isolation_level=None)
        handle=None
        try:
            handle=install_source_inspection_runtime_v1(graph,control=self.lifecycle.control,context=context)
            with runtime_storage_operation_v3(graph,operation_id=operation_id,deadline_utc=deadline):
                with runtime_storage_quantum_v3(graph) as meter:
                    graph.execute("BEGIN")
                    row=_fixed(graph,meter,OPERATIONS,COLUMNS[OPERATIONS],"bot=? AND persona=? AND operation_id=?",
                        (*self.lifecycle.namespace_id.as_tuple,parent[1]))
                    if row is None:raise AuthorityUnavailable("original completed migration Graph cursor is absent")
                    decoded=validate_source_inspection_migration_row_v1(OPERATIONS,COLUMNS[OPERATIONS],row,
                        authority_namespace=self.lifecycle.namespace)
                    receipt=parsed["receipt"]
                    if (decoded["state"]!="completed" or decoded["receipt"]!=receipt
                            or decoded["request_digest"]!=parsed["request_digest"]
                            or decoded["accepted_digest"]!=parsed["accepted_digest"]
                            or decoded["request"]!=parsed["request"] or parsed["request"]["storage"]!=storage):
                        raise AuthorityUnavailable("completed Graph/Core inspection receipts differ")
                    member=_fixed(graph,meter,MEMBERS,COLUMNS[MEMBERS],"bot=? AND persona=? AND producer_operation_id=?",
                        (*self.lifecycle.namespace_id.as_tuple,receipt["producer_operation_id"]))
                    if member is None:raise AuthorityUnavailable("actual inspection completion member is absent")
                    completion=validate_source_inspection_migration_row_v1(MEMBERS,COLUMNS[MEMBERS],member,
                        authority_namespace=self.lifecycle.namespace)
                    event=_fixed(graph,meter,"graph_events",("digest","epoch_revision","reads","revisions","invalidated"),
                        "bot=? AND persona=? AND session=? AND event_id=?",
                        (*self.lifecycle.namespace_id.as_tuple,SESSION,receipt["producer_operation_id"]))
                    if (completion["outcome"]!="completed" or member[10]!=receipt["event_digest"]
                            or event!=(receipt["event_digest"],receipt["after_stamp"][2],"[]","[]","[]")):
                        raise AuthorityUnavailable("inspection completion has no actual committed Graph event/member")
                    return dict(operation_id=parent[1],request_digest=parsed["request_digest"],
                        accepted_digest=parsed["accepted_digest"],receipt_digest=canonical_digest(receipt),
                        producer_operation_id=receipt["producer_operation_id"],event_digest=receipt["event_digest"])
        finally:
            if graph.in_transaction:graph.execute("ROLLBACK")
            if handle is not None:handle.close()
            graph.close()


    def read_child_boundary_v1(self,db,parent,context,storage,operation_id,deadline):
        """Read actual technical receipts only; uncertainty never becomes replay permission."""
        from .source_inspection_migration_v1 import TABLE as SOURCE,COLUMNS as SOURCE_COLUMNS,validate_source_inspection_migration_core_row_v1
        from ..runtime.source_inspection_migration_v1 import (
            OPERATIONS,MEMBERS,COLUMNS,SESSION,validate_source_inspection_migration_row_v1,_fixed,_head,_stamp)
        from ..runtime_storage_v3 import (
            runtime_storage_operation_v3,runtime_storage_quantum_v3,begin_runtime_cell_read_v3)
        from ..graph_types import AtomKey
        from ..runtime.source_inspection_migration_v1 import install_source_inspection_runtime_v1
        parent_original=json.loads(parent[5])
        child_operation_id=parent_original["source_request"]["operation_id"]
        child=db.execute(f"SELECT * FROM {SOURCE} WHERE namespace=? AND operation_id=?",
            (self.lifecycle.namespace,child_operation_id)).fetchone()
        decoded_core=None
        if child is not None:
            decoded_core=validate_source_inspection_migration_core_row_v1(SOURCE_COLUMNS,child,authority_namespace=self.lifecycle.namespace)
            self.lifecycle.control.verify_original_v1(decoded_core["accepted_original"],"accepted_digest")
            if (decoded_core["request"]!=parent_original["source_request"]
                    or decoded_core["accepted_original"]["workflow_accepted_digest"]!=parent[4]):
                raise AuthorityUnavailable("held child has another actual signed parent")
        path=next(member["resolved_path"] for member in storage["members"] if member["role"]=="graph")
        graph=sqlite3.connect(Path(path).as_uri()+"?mode=ro",uri=True,isolation_level=None)
        handle=None
        try:
            handle=install_source_inspection_runtime_v1(graph,control=self.lifecycle.control,context=context)
            with runtime_storage_operation_v3(graph,operation_id=operation_id,deadline_utc=deadline):
                with runtime_storage_quantum_v3(graph) as meter:
                    graph.execute("BEGIN")
                    present=graph.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(OPERATIONS,)).fetchone()
                    row=None if present is None else _fixed(graph,meter,OPERATIONS,COLUMNS[OPERATIONS],
                        "bot=? AND persona=? AND operation_id=?",(*self.lifecycle.namespace_id.as_tuple,child_operation_id))
                    stamp=_stamp(graph,self.lifecycle.namespace_id,meter)
                    if row is None:
                        if (child is None and parent_original["schema"]=="sylanne.source-inspection-workflow-accepted.v1"
                                and parent[9] is not None):
                            raise AuthorityUnavailable("original recorded progress cannot become a no-child proof")
                        if decoded_core is not None and decoded_core["receipt"] is not None:
                            raise AuthorityUnavailable("held Core progress has no actual Graph boundary")
                        return dict(kind="no_child" if child is None else "incomplete",
                            operation_id=child_operation_id,core_row_digest=None if child is None else canonical_digest(child),
                            graph_row_digest=None,last_receipt_digest=None,graph_stamp=list(stamp),
                            published_batches=0,completed_commitment=None)
                    if decoded_core is None:
                        raise AuthorityUnavailable("held Graph original has no actual durable child Core original")
                    decoded=validate_source_inspection_migration_row_v1(OPERATIONS,COLUMNS[OPERATIONS],row,
                        authority_namespace=self.lifecycle.namespace)
                    if (decoded["request"]!=decoded_core["request"] or decoded["accepted_digest"]!=decoded_core["accepted_digest"]
                            or tuple(row[6:9])!=stamp):
                        raise AuthorityUnavailable("held child current Graph stamp/accepted binding changed")
                    receipt=decoded["receipt"]
                    previous=decoded_core["receipt"]
                    prior_batches=0 if previous is None else previous["batch_index"]+1
                    if row[10]-prior_batches not in {0,1}:
                        raise AuthorityUnavailable("held Core/Graph boundary exceeds its actual single commit gap")
                    if previous is not None and row[10]==prior_batches:
                        if (previous["cursor"]!=row[9] or previous["migrated"]!=row[11] or previous["retired"]!=row[12]
                                or previous["schema"]=="sylanne.source-inspection-migration-receipt.v1" and previous!=receipt):
                            raise AuthorityUnavailable("held Core cursor differs from its committed Graph boundary")
                    if receipt is not None:
                        member=_fixed(graph,meter,MEMBERS,COLUMNS[MEMBERS],"bot=? AND persona=? AND producer_operation_id=?",
                            (*self.lifecycle.namespace_id.as_tuple,receipt["producer_operation_id"]))
                        if member is None:raise AuthorityUnavailable("held committed cursor member is absent")
                        checked=validate_source_inspection_migration_row_v1(MEMBERS,COLUMNS[MEMBERS],member,
                            authority_namespace=self.lifecycle.namespace)
                        if checked["admission"] is not None:self.source.verify_member_admission_v1(checked["admission"])
                        event=_fixed(graph,meter,"graph_events",("digest","epoch_revision","reads","revisions","invalidated"),
                            "bot=? AND persona=? AND session=? AND event_id=?",
                            (*self.lifecycle.namespace_id.as_tuple,SESSION,receipt["producer_operation_id"]))
                        if (member[10]!=receipt["event_digest"] or event is None or event[:2]!=(member[10],receipt["after_stamp"][2])
                                or json.loads(event[2])!=checked["original"]["reads"]
                                or json.loads(event[3])!=checked["original"]["writes"] or event[4]!="[]"
                                or checked["receipt"]["before_stamp"]!=receipt["before_stamp"]
                                or checked["receipt"]["after_stamp"]!=receipt["after_stamp"]):
                            raise AuthorityUnavailable("held Graph cursor has no exact actual producer event/receipt")
                        if checked["outcome"]=="migrated":
                            target=AtomKey.from_token(member[6]);metadata=AtomKey.from_token(member[8])
                            target_head=_head(graph,self.lifecycle.namespace_id,target,meter)
                            metadata_head=_head(graph,self.lifecycle.namespace_id,metadata,meter)
                            if (target_head!=tuple(checked["original"]["target_original"]["target_head"])
                                    or metadata_head is None or metadata_head[:2]!=(1,1)
                                    or begin_runtime_cell_read_v3(graph,metadata_head[2],erasure_owner_ref=metadata.token).header[2]!=member[2]):
                                raise AuthorityUnavailable("held last producer target/output current commitments differ")
                    if decoded_core["state"]=="completed" and decoded["state"]!="completed":
                        raise AuthorityUnavailable("held child claims completion outside its actual Graph boundary")
                    completed=None
                    if decoded["state"]=="completed":
                        if receipt is None or checked["outcome"]!="completed":
                            raise AuthorityUnavailable("held child completion lacks its actual final member")
                        completed=dict(operation_id=child_operation_id,request_digest=decoded["request_digest"],
                            accepted_digest=decoded["accepted_digest"],receipt_digest=canonical_digest(receipt),
                            producer_operation_id=receipt["producer_operation_id"],event_digest=receipt["event_digest"])
                    return dict(kind="completed" if completed is not None else "incomplete",
                        operation_id=child_operation_id,core_row_digest=canonical_digest(child),graph_row_digest=canonical_digest(row),
                        last_receipt_digest=None if receipt is None else canonical_digest(receipt),
                        graph_stamp=list(stamp),published_batches=row[10],completed_commitment=completed)
        finally:
            if graph.in_transaction:graph.execute("ROLLBACK")
            if handle is not None:handle.close()
            graph.close()


    def read_options_current_v1(self,*,credential,actor,session_token,session_request,parent_workflow_operation_id):
        from .source_inspection_migration_v1 import _uuid_v1
        from .source_inspection_held_reconciliation_v1 import hold_snapshot_digest_v1
        from .v2_owner_session import _verifier,_time
        _uuid_v1(parent_workflow_operation_id)
        lifecycle=self.lifecycle
        lifecycle.core._require(credential,"d12_lifecycle_control",lifecycle.namespace)
        context,storage=lifecycle._storage()
        with lifecycle.fences._frozen() as (db,deletion,execution,_):
            guard=lifecycle.status_service.tickets._checked_current_head(db,lifecycle.namespace)
            if guard is None:raise AuthorityUnavailable("current recovery observer Owner is absent")
            lifecycle.status_service._current_session_in_tx(db,actor=actor,token=session_token,request=session_request,
                expected_head=guard.authorization_head)
            self.source._actual_owner_grant_v1(db,context,storage,actor=actor,session_request=session_request,
                required={"workbench.read"})
            parent=self.workflow._row_v1(db,parent_workflow_operation_id);value=json.loads(parent[5])
            lifecycle.control.verify_original_v1(value,"accepted_digest")
            resource=self.workflow.resources.qualify_current_v1(lifecycle=lifecycle)
            resource.require_current_v1(lifecycle=lifecycle)
            head=read_lifecycle_head_in_tx_v1(db,lifecycle.namespace)
            from .source_inspection_held_reconciliation_v1 import ACCEPT_SCHEMA as HELD_SCHEMA
            if value["schema"]=="sylanne.source-inspection-workflow-accepted.v1":
                pause_id=value["input"]["pause_operation_id"]
                eligible_held_parent=True
            elif value["schema"]==HELD_SCHEMA:
                pause_id=value["pause_operation_id"]
                eligible_held_parent=(value["source_request"] is not None and parent[9] is not None
                    and json.loads(parent[9])["kind"]=="ownership")
            elif value["schema"]==ACCEPT_SCHEMA:
                pause_id=value["input"]["pause_operation_id"]
                eligible_held_parent=False
            else:
                raise AuthorityUnavailable("operation has no inspection pause recovery options")
            kind="not_observed"
            if head.state=="paused" and head.operation_id==pause_id and lifecycle.supervisor.read_current_host_state_v1().stopped_and_drained:
                session=db.execute("SELECT expires_at_utc FROM authority_owner_sessions_v1 WHERE verifier=?",(_verifier(session_token),)).fetchone()
                deadline=min(_time(session[0]).timestamp(),resource.deadline_utc)
                try:
                    if (value["schema"]=="sylanne.source-inspection-workflow-accepted.v1"
                            or parent[6]=="held" and value.get("source_request") is not None):
                        kind=self.read_child_boundary_v1(db,parent,context,storage,"inspection-recovery-observation:"+parent[1],deadline)["kind"]
                    elif parent[6]=="completed" and parent[9] is not None:
                        from .source_inspection_held_reconciliation_v1 import validate_resolution_v1
                        resolution=validate_resolution_v1(json.loads(parent[9]),value)
                        lifecycle.control.verify_original_v1(resolution,"resolution_digest")
                        kind="completed" if resolution["classification"]=="recovered_complete_paused" else "no_child"
                except Exception:
                    kind="unknown"
            if parent[6]=="held" and head.state=="active":
                try:
                    selector=dict(parent_workflow_operation_id=parent[1],parent_accepted_digest=parent[4],
                        parent_hold_digest=hold_snapshot_digest_v1(parent),expected_lifecycle_epoch=head.epoch,
                        expected_lifecycle_head_digest=head.head_digest,disposition="reconcile_active_completed")
                    self.workflow.held_reconciliation.require_active_completed_v1(db,{"input":selector},storage)
                    kind="active_completed"
                except Exception:
                    kind="unknown"
            allowed=[]
            if parent[6]=="held" and eligible_held_parent and head.state=="paused" and head.operation_id==pause_id:
                allowed=["reconcile_only"]
                if kind=="no_child":allowed+=["terminate_paused","continue_remaining"]
                elif kind=="incomplete":allowed.append("continue_remaining")
            if parent[6]=="held" and kind=="active_completed":allowed=["reconcile_active_completed"]
            can_resume=(parent[6]=="completed" and parent[7] in {"paused","recovered_complete_paused","terminal_paused"}
                and kind in {"completed","no_child"})
            return dict(schema="d12.source-inspection-recovery-options.v1",scope="/".join(lifecycle.namespace_id.as_tuple),
                installation_id=lifecycle.installation_id,parent_workflow_operation_id=parent[1],parent_accepted_digest=parent[4],
                parent_state=parent[6],parent_phase=parent[7],parent_hold_digest=hold_snapshot_digest_v1(parent) if parent[6]=="held" else None,
                pause_operation_id=pause_id,lifecycle_state=head.state,lifecycle_epoch=head.epoch,lifecycle_head_digest=head.head_digest,
                storage_identity_digest=canonical_digest(storage),resource_binding_digest=resource.binding_digest,
                resource_deadline_utc=resource.deadline_utc,boundary_kind=kind,allowed_dispositions=allowed,can_resume_completed=can_resume)

    def accept_completed_v1(self,*,credential,actor,session_token,session_request,operation_id,input_data):
        from .source_inspection_workflow_v1 import TABLE
        from .source_inspection_workflow_v1 import validate_inspection_workflow_core_row_v1,COLUMNS
        from .source_inspection_migration_v1 import require_no_pending_source_inspection_migration_in_tx_v1
        from .d12_installation_lifecycle_v1 import OPS,RECEIPTS
        from .d12_lifecycle_contract_v1 import lifecycle_receipt_from_wire_v1
        from .v2_owner_session import _verifier,_time
        validate_recovery_input_v1(operation_id,input_data)
        lifecycle=self.lifecycle
        lifecycle.core._require(credential,"d12_lifecycle_control",lifecycle.namespace)
        context,storage=lifecycle._storage()
        with lifecycle.fences._frozen() as (db,deletion,execution,_):
            guard=lifecycle.status_service.tickets._checked_current_head(db,lifecycle.namespace)
            if guard is None:raise AuthorityUnavailable("fresh recovery current Owner head is absent")
            lifecycle.status_service._current_session_in_tx(db,actor=actor,token=session_token,
                request=session_request,expected_head=guard.authorization_head)
            grant,owner=self.source._actual_owner_grant_v1(db,context,storage,actor=actor,
                session_request=session_request,required={"workbench.read","workbench.maintain","workbench.control"})
            self._unconsumed_v1(db,operation_id,input_data["pause_operation_id"])
            prior=db.execute(f"SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=?",
                (lifecycle.namespace,operation_id)).fetchone()
            if prior is not None:
                value=json.loads(prior[5]);lifecycle.control.verify_original_v1(value,"accepted_digest")
                if (value["schema"]!=ACCEPT_SCHEMA or prior[2]!=canonical_digest(input_data)
                        or prior[3]!=canonical_json(input_data) or value["actor"]!=actor
                        or value["owner_head"]!=guard.authorization_head
                        or value["public_session_request"]["principal"]!=asdict(session_request.principal)):
                    raise AuthorityUnavailable("fresh recovery retry changes its accepted request/Owner")
                return self.view_v1(prior)
            require_no_pending_source_inspection_migration_in_tx_v1(db,lifecycle.namespace,lifecycle=lifecycle)
            parent=self.workflow._row_v1(db,input_data["parent_workflow_operation_id"])
            original=json.loads(parent[5])
            lifecycle.control.verify_original_v1(original,"accepted_digest")
            validate_inspection_workflow_core_row_v1(COLUMNS,parent,authority_namespace=lifecycle.namespace)
            resolved=None
            if original["schema"]=="sylanne.source-inspection-workflow-accepted.v1":
                if (parent[6:8]!=("completed","paused") or original["input"]["resume_on_complete"]
                        or original["input"]["pause_operation_id"]!=input_data["pause_operation_id"]):
                    raise AuthorityUnavailable("fresh recovery requires its original completed paused workflow")
                root_operation_id=parent[1];root_accepted_digest=parent[4]
            else:
                from .source_inspection_held_reconciliation_v1 import ACCEPT_SCHEMA as HELD_SCHEMA,validate_resolution_v1
                if (original["schema"]!=HELD_SCHEMA or parent[6]!="completed"
                        or parent[7] not in {"recovered_complete_paused","terminal_paused"}
                        or parent[9] is None or original["pause_operation_id"]!=input_data["pause_operation_id"]):
                    raise AuthorityUnavailable("fresh resume requires an actual signed terminal held resolution")
                resolved=validate_resolution_v1(json.loads(parent[9]),original)
                lifecycle.control.verify_original_v1(resolved,"resolution_digest")
                if resolved["kind"]!="resolution":raise AuthorityUnavailable("held parent is not resolved")
                root_operation_id=original["root_workflow_operation_id"];root_accepted_digest=original["root_accepted_digest"]
            head=read_lifecycle_head_in_tx_v1(db,lifecycle.namespace)
            pause=db.execute(f"SELECT * FROM {OPS} WHERE namespace=? AND operation_id=?",
                (lifecycle.namespace,input_data["pause_operation_id"])).fetchone()
            if (pause is None or pause[3]!="pause" or pause[13]!="paused" or pause[15] is not None
                    or head.state!="paused" or head.operation_id!=pause[1]
                    or head.epoch!=input_data["expected_lifecycle_epoch"]
                    or head.head_digest!=input_data["expected_lifecycle_head_digest"]
                    or not lifecycle.supervisor.read_current_host_state_v1().stopped_and_drained
                    or json.loads(pause[10])!=storage or any(lifecycle._counts(db))):
                raise AuthorityUnavailable("fresh recovery does not bind its actual stopped/drained original pause")
            from .source_inspection_workflow_v1 import validate_inspection_control_original_v1
            native=validate_inspection_control_original_v1(pause[5],authority_namespace=lifecycle.namespace)
            lifecycle.control.verify_original_v1(native,"original_digest")
            if (native["schema"]!="d12.source-inspection-control-original.v1"
                    or pause[4]!="d12inspectioncontrol:"+native["original_digest"]
                    or native["workflow_operation_id"]!=root_operation_id or native["accepted_digest"]!=root_accepted_digest
                    or native["operation_id"]!=pause[1] or native["request_digest"]!=pause[2] or native["action"]!="pause"
                    or native["owner_head"]!=pause[9] or native["storage_identity_digest"]!=canonical_digest(storage)):
                raise AuthorityUnavailable("fresh recovery native pause has another actual causal parent")
            paused_receipt=db.execute(f"SELECT original_json FROM {RECEIPTS} WHERE original_ref=?",(pause[14],)).fetchone()
            if paused_receipt is None:raise AuthorityUnavailable("original native paused receipt is absent")
            receipt=lifecycle_receipt_from_wire_v1(json.loads(paused_receipt[0]))
            from ..runtime.lifecycle_operations_v1 import digest
            if (receipt.stage!="paused" or receipt.action!="pause" or receipt.operation_id!=pause[1]
                    or receipt.original_ref!=pause[14] or receipt.request_digest!=pause[2]
                    or receipt.authority_namespace!=lifecycle.namespace or receipt.installation_id!=lifecycle.installation_id
                    or receipt.owner_head!=pause[9] or receipt.storage_identity_digest!=digest(storage)
                    or receipt.lifecycle_epoch!=head.epoch or db.execute("SELECT current_receipt_ref FROM authority_d12_lifecycle_heads_v1 WHERE namespace=?",(lifecycle.namespace,)).fetchone()!=(pause[14],)):
                raise AuthorityUnavailable("fresh recovery paused receipt/current lifecycle differs")
            resource=self.workflow.resources.qualify_current_v1(lifecycle=lifecycle)
            resource.require_current_v1(lifecycle=lifecycle)
            session=db.execute("SELECT expires_at_utc FROM authority_owner_sessions_v1 WHERE verifier=?",
                (_verifier(session_token),)).fetchone()
            effective=min(input_data["deadline_utc"],_time(session[0]).timestamp(),resource.deadline_utc,time.time()+3600)
            if effective<=time.time():raise AuthorityUnavailable("fresh recovery actual authorization deadline elapsed")
            if resolved is None:
                child=self._completed_child_v1(db,parent,context,storage,operation_id,effective)
            elif resolved["classification"]=="recovered_complete_paused":
                child=resolved["completed_commitment"]
                if child is None:raise AuthorityUnavailable("resolved migration completion commitment is absent")
            else:
                child=dict(schema="sylanne.source-inspection-terminal-no-child.v1",
                    parent_workflow_operation_id=parent[1],parent_accepted_digest=parent[4],
                    resolution_digest=resolved["resolution_digest"])
            lifecycle._constraints_in_tx(db,deletion,execution,storage,qualified_context=context)
            selected,cohort,configuration=self.source.files.read_selected_configuration_cohort_v2()
            if configuration["host_profile"]["installation_policy"]["catalogue_hash"]!=self.source.registry.catalogue_hash:
                raise AuthorityUnavailable("fresh recovery selected catalogue differs")
            value=lifecycle.control.sign_original_v1(ACCEPT_SCHEMA,dict(schema=ACCEPT_SCHEMA,
                action="completed_inspection_resume",namespace=asdict(lifecycle.namespace_id),
                authority_namespace=lifecycle.namespace,installation_id=lifecycle.installation_id,operation_id=operation_id,
                input=input_data,input_digest=canonical_digest(input_data),actor=actor,owner_head=guard.authorization_head,
                public_session_request=asdict(session_request),owner_grant_digest=owner.grant_digest,storage=storage,
                selected_pointer=asdict(selected),cohort_digest=cohort.cohort_digest,catalogue_hash=self.source.registry.catalogue_hash,
                accepted_at_utc=time.time(),owner_authorization_deadline_utc=_time(session[0]).timestamp(),
                resource_original=resource.as_original_v1(),effective_deadline_utc=effective,
                parent_accepted_digest=parent[4],pause_receipt_digest=receipt.original_digest,child_commitment=child),"accepted_digest")
            row=(lifecycle.namespace,operation_id,canonical_digest(input_data),canonical_json(input_data),
                value["accepted_digest"],canonical_json(value),"accepted","accepted",None,None)
            db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?,?,?,?)",row)
            result=self.view_v1(row)
        self.workflow._start_worker_v1(operation_id)
        return result

    def view_v1(self,row):
        value=json.loads(row[5])
        return dict(schema=VIEW_SCHEMA,scope="/".join(self.lifecycle.namespace_id.as_tuple),
            installation_id=self.lifecycle.installation_id,operation_id=row[1],request_digest=row[2],
            state=row[6],phase=row[7],hold_code=row[8],effective_deadline_utc=value["effective_deadline_utc"],**value["input"])

    def run_v1(self,operation_id):
        from .source_inspection_workflow_v1 import TABLE
        lifecycle=self.lifecycle
        try:
            while not self.workflow._closed.is_set() and not lifecycle._closed.is_set():
                start=False
                with lifecycle.fences._frozen() as (db,deletion,execution,_):
                    row=self.workflow._row_v1(db,operation_id)
                    if row[6] in {"completed","held"}:return
                    self.workflow._phase_context=(db,deletion,execution,threading.get_ident())
                    accepted=_AcceptedInspectionRecoveryV1(_ISSUER,self,row)
                    accepted.require_current_v1(db)
                    if row[7]=="accepted":
                        phase=accepted.issue_phase_v1(db)
                        lifecycle.submit_accepted_maintenance_resume_in_tx_v1(phase)
                        db.execute(f"UPDATE {TABLE} SET state='running',phase='resuming' WHERE namespace=? AND operation_id=?",
                            (lifecycle.namespace,operation_id))
                        start=True
                    elif row[7]=="resuming":
                        resumed=lifecycle._operation(db,operation_id)
                        head=read_lifecycle_head_in_tx_v1(db,lifecycle.namespace)
                        if resumed[15] is not None:raise AuthorityUnavailable("fresh native resume held")
                        if resumed[13]=="active" and head.state=="active" and head.operation_id==operation_id:
                            db.execute(f"UPDATE {TABLE} SET state='completed',phase='active' WHERE namespace=? AND operation_id=?",
                                (lifecycle.namespace,operation_id))
                            return
                    else:raise AuthorityUnavailable("unregistered fresh recovery phase")
                self.workflow._phase_context=None
                if start:lifecycle._start_worker(operation_id)
                self.workflow._closed.wait(0.1)
        except Exception:
            self.workflow._held_v1(operation_id,"fresh_recovery_original_reconciliation_required")
        finally:self.workflow._phase_context=None

    def require_continuation_v1(self,db,control_row):
        native=validate_recovery_control_original_v1(control_row[5],authority_namespace=self.lifecycle.namespace)
        self.lifecycle.control.verify_original_v1(native,"original_digest")
        row=self.workflow._row_v1(db,native["workflow_operation_id"])
        accepted=_AcceptedInspectionRecoveryV1(_ISSUER,self,row)
        accepted.require_current_v1(db)
        original=accepted.original
        if (row[7]!="resuming" or native["accepted_digest"]!=row[4] or native["operation_id"]!=row[1]
                or control_row[1]!=row[1] or control_row[3]!="resume" or control_row[15] is not None
                or control_row[4]!="d12inspectioncontrol:"+native["original_digest"]
                or control_row[2]!=native["request_digest"] or native["owner_head"]!=original["owner_head"]
                or native["storage_identity_digest"]!=canonical_digest(original["storage"])
                or native["parent_accepted_digest"]!=original["parent_accepted_digest"]
                or native["pause_receipt_digest"]!=original["pause_receipt_digest"]
                or native["parent_workflow_operation_id"]!=original["input"]["parent_workflow_operation_id"]
                or native["parent_pause_operation_id"]!=original["input"]["pause_operation_id"]
                or native["child_commitment_digest"]!=canonical_digest(original["child_commitment"])):
            raise AuthorityUnavailable("native recovery lost its actual new authorization/causal binding")

    def reconcile_restart_v1(self,db,row):
        from .source_inspection_workflow_v1 import TABLE
        from .d12_installation_lifecycle_v1 import OPS
        if row[7]=="resuming":
            control=db.execute(f"SELECT * FROM {OPS} WHERE namespace=? AND operation_id=?",
                (self.lifecycle.namespace,row[1])).fetchone()
            if control is None or control[13]!="active" or control[15] is not None:
                db.execute(f"UPDATE {TABLE} SET state='held',phase='held',hold_code='restart_unknown_fresh_resume' WHERE namespace=? AND operation_id=?",
                    (self.lifecycle.namespace,row[1]))
                return False
        return True


def native_recovery_control_original_v1(phase,intent):
    from ..runtime.lifecycle_operations_v1 import digest
    phase.require_v1(phase.accepted.manager.lifecycle,"resume")
    value=phase.original
    material=dict(workflow_operation_id=value["operation_id"],accepted_digest=value["accepted_digest"],
        operation_id=phase.operation_id,intent=asdict(intent))
    body=dict(schema=CONTROL_SCHEMA,authority_namespace=value["authority_namespace"],installation_id=value["installation_id"],
        workflow_operation_id=value["operation_id"],parent_workflow_operation_id=value["input"]["parent_workflow_operation_id"],
        parent_pause_operation_id=value["input"]["pause_operation_id"],parent_accepted_digest=value["parent_accepted_digest"],
        pause_receipt_digest=value["pause_receipt_digest"],child_commitment_digest=canonical_digest(value["child_commitment"]),
        accepted_digest=value["accepted_digest"],operation_id=phase.operation_id,action="resume",request_digest=digest(material),
        owner_head=value["owner_head"],intent=asdict(intent),storage_identity_digest=canonical_digest(value["storage"]))
    return phase.accepted.manager.lifecycle.control.sign_original_v1(CONTROL_SCHEMA,body,"original_digest")


def validate_recovery_control_original_v1(raw,*,authority_namespace):
    from .c09_storage_control_v1 import digest as control_digest
    from .d12_lifecycle_contract_v1 import D12InstallationControlIntentV1
    from ..runtime.lifecycle_operations_v1 import digest
    value=json.loads(raw)
    if (type(value) is not dict or set(value)!=CONTROL_FIELDS or value["schema"]!=CONTROL_SCHEMA
            or canonical_json(value)!=raw or value["authority_namespace"]!=authority_namespace or value["action"]!="resume"
            or value["operation_id"]!=value["workflow_operation_id"]
            or control_digest({k:v for k,v in value.items() if k not in {"original_digest","signature"}})!=value["original_digest"]):
        raise AuthorityUnavailable("fresh inspection native control closed schema differs")
    from .source_inspection_migration_v1 import _uuid_v1,_sha_v1
    for name in ("operation_id","workflow_operation_id","parent_workflow_operation_id","parent_pause_operation_id"):
        _uuid_v1(value[name])
    for name in ("accepted_digest","parent_accepted_digest","child_commitment_digest","original_digest","signature"):
        _sha_v1(value[name])
    for name in ("pause_receipt_digest","owner_head","request_digest"):
        _sha_v1(value[name].removeprefix("sha256:"))
    intent=D12InstallationControlIntentV1(**value["intent"])
    if (intent.action!="resume" or intent.installation_id!=value["installation_id"]
            or intent.prior_pause_operation_id!=value["parent_pause_operation_id"]
            or digest(dict(workflow_operation_id=value["workflow_operation_id"],accepted_digest=value["accepted_digest"],
                operation_id=value["operation_id"],intent=value["intent"]))!=value["request_digest"]):
        raise AuthorityUnavailable("fresh inspection native resume intent binding differs")
    return value


def validate_recovery_core_row_v1(columns,row,*,authority_namespace):
    from .source_inspection_workflow_v1 import COLUMNS
    from .c09_storage_control_v1 import digest as control_digest
    from .source_inspection_migration_v1 import _sha_v1,_uuid_v1
    from ..runtime_contracts import NamespaceId
    from uuid import UUID
    if columns!=COLUMNS or len(row)!=len(columns) or row[0]!=authority_namespace:
        raise AuthorityUnavailable("fresh recovery Core row columns differ")
    value=json.loads(row[5]);submitted=json.loads(row[3])
    if (type(value) is not dict or set(value)!=ACCEPT_FIELDS or value["schema"]!=ACCEPT_SCHEMA
            or value["action"]!="completed_inspection_resume" or canonical_json(value)!=row[5] or canonical_json(submitted)!=row[3]
            or value["input"]!=submitted or canonical_digest(submitted)!=row[2] or value["input_digest"]!=row[2]
            or value["operation_id"]!=row[1] or value["authority_namespace"]!=row[0] or value["accepted_digest"]!=row[4]
            or control_digest({k:v for k,v in value.items() if k not in {"accepted_digest","signature"}})!=row[4]
            or row[6] not in {"accepted","running","completed","held"} or row[7] not in {"accepted","resuming","active","held"}
            or row[9] is not None or (row[6]=="held")!=(row[7]=="held")
            or row[6]=="completed" and row[7]!="active"):
        raise AuthorityUnavailable("fresh recovery signed accepted row differs")
    validate_recovery_input_v1(row[1],submitted)
    NamespaceId(**value["namespace"])
    commitment=value["child_commitment"]
    if type(commitment) is not dict:raise AuthorityUnavailable("fresh recovery completion commitment is absent")
    if commitment.get("schema")=="sylanne.source-inspection-terminal-no-child.v1":
        if (set(commitment)!={"schema","parent_workflow_operation_id","parent_accepted_digest","resolution_digest"}
                or commitment["parent_workflow_operation_id"]!=submitted["parent_workflow_operation_id"]
                or commitment["parent_accepted_digest"]!=value["parent_accepted_digest"]):
            raise AuthorityUnavailable("fresh terminal-no-child certificate differs")
        _sha_v1(commitment["resolution_digest"])
    else:
        if set(commitment)!={"operation_id","request_digest","accepted_digest","receipt_digest","producer_operation_id","event_digest"}:
            raise AuthorityUnavailable("fresh recovery child completion fields differ")
        _uuid_v1(commitment["operation_id"])
        producer=UUID(commitment["producer_operation_id"])
        if producer.version!=5 or str(producer)!=commitment["producer_operation_id"]:
            raise AuthorityUnavailable("fresh recovery child producer identity differs")
        for name in ("request_digest","accepted_digest","receipt_digest","event_digest"):_sha_v1(commitment[name])
    if (type(value["effective_deadline_utc"]) not in (int,float) or not math.isfinite(value["effective_deadline_utc"])
            or value["effective_deadline_utc"]>submitted["deadline_utc"]):
        raise AuthorityUnavailable("fresh recovery actual effective deadline differs")
    for name in ("accepted_digest","signature","parent_accepted_digest","cohort_digest","catalogue_hash"):_sha_v1(value[name])
    _sha_v1(value["pause_receipt_digest"].removeprefix("sha256:"))
    return dict(operation_id=row[1],state=row[6],phase=row[7],request_digest=row[2],accepted_digest=row[4],
        accepted_original=value,input=submitted,progress=None,graph_refs=())

