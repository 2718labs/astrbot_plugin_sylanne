"""Independent durable whole-Host pause/resume; business generation is retained.

The Authority owns the state machine. W09 can stop with its Host without losing
this operation. New work is gated in existing Core admission transactions;
original claimed terminal/accounting work may drain. No killed permit, unknown
reservation, cost or journal record is deleted to manufacture quiescence.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, fields
import json
from pathlib import Path
import sqlite3
import threading
import time
from uuid import UUID

from ..domains.d12.backend_operation_contracts_v1 import D12BackendOperationOriginalV1, D12ControlPayloadV1, backend_original_digest_v1
from ..graph_store import GraphStore
from ..runtime.lifecycle_operations_v1 import decode_original, digest
from ..runtime_contracts import canonical_serialize
from .contract import AuthorityUnavailable
from .c09_process_identity_v1 import read_process_identity_v1, require_process_retired_v1
from .c09_storage_control_v1 import C09StorageControlV1
from .d12_installed_supervisor_v1 import InstalledD12SystemdSupervisorV1
from .d12_lifecycle_contract_v1 import D12InstallationControlIntentV1, D12InstallationLifecycleReceiptV1, lifecycle_receipt_from_wire_v1
from .d12_lifecycle_gate_v1 import HEAD_DDL, read_lifecycle_head_in_tx_v1
from .installed_migration_reconciliation_v1 import InstalledNamespaceExecutionReconciliationV1
from .v2_owner_session import from_wire as session_from_wire, _canonical as session_canonical

OPS = "authority_d12_lifecycle_operations_v1"
RECEIPTS = "authority_d12_lifecycle_receipts_v1"
BOOTS = "authority_d12_lifecycle_bootstraps_v1"


class InstalledD12InstallationLifecycleV1:
    def __init__(self, *, status_service, control, supervisor, package_root,
                 expected_manifest_digest, peer_certificate_sha256, peer_profile_id,
                 model_store=None, drain_timeout_seconds=300):
        if (type(control) is not C09StorageControlV1
                or type(supervisor) is not InstalledD12SystemdSupervisorV1
                or control.authority_id != status_service.fences.core._id(status_service.core._db)
                or control.installation_id not in status_service._source_graphs):
            raise TypeError("actual same-installation Authority/control/supervisor services required")
        if type(drain_timeout_seconds) is not int or not 1 <= drain_timeout_seconds <= 3600:
            raise ValueError("bounded installed whole-Host drain deadline required")
        self.status_service, self.core, self.fences = status_service, status_service.core, status_service.fences
        self.control, self.supervisor = control, supervisor
        self.namespace, self.namespace_id = status_service.namespace, status_service.namespace_id
        self.installation_id = control.installation_id
        self.package_root = Path(package_root).resolve(strict=True)
        self.expected_manifest_digest = expected_manifest_digest
        self.peer = (peer_certificate_sha256, peer_profile_id)
        self.constraints = InstalledNamespaceExecutionReconciliationV1(fences=self.fences, model_store=model_store)
        self.drain_timeout_seconds = drain_timeout_seconds
        self._condition = threading.Condition(threading.RLock())
        self._active_rpc = 0
        self._workers = {}
        self._closed = threading.Event()
        status_service.install_control_status_reader_v1(self)

    def install_schema(self, administrator_credential):
        self.core._require(administrator_credential, "d12_lifecycle_install", self.namespace)
        with self.core._tx() as db:
            db.execute(HEAD_DDL)
            db.execute(f"CREATE TABLE IF NOT EXISTS {OPS}(namespace TEXT NOT NULL,operation_id TEXT NOT NULL,"
                "request_digest TEXT NOT NULL,action TEXT NOT NULL,source_original_ref TEXT NOT NULL,source_original_json TEXT NOT NULL,"
                "intent_json TEXT NOT NULL,actor TEXT NOT NULL,session_request_json BLOB NOT NULL,owner_head TEXT NOT NULL,"
                "storage_json TEXT NOT NULL,initial_supervisor_json TEXT NOT NULL,initial_process_json TEXT NOT NULL,"
                "current_stage TEXT NOT NULL,current_receipt_ref TEXT,hold_code TEXT,PRIMARY KEY(namespace,operation_id))")
            db.execute(f"CREATE TABLE IF NOT EXISTS {RECEIPTS}(namespace TEXT NOT NULL,operation_id TEXT NOT NULL,"
                "stage TEXT NOT NULL,original_ref TEXT NOT NULL UNIQUE,original_digest TEXT NOT NULL,original_json TEXT NOT NULL,"
                "PRIMARY KEY(namespace,operation_id,stage))")
            db.execute(f"CREATE TABLE IF NOT EXISTS {BOOTS}(namespace TEXT NOT NULL,epoch INTEGER NOT NULL,operation_id TEXT NOT NULL,"
                "peer_certificate_sha256 TEXT NOT NULL,peer_profile_id TEXT NOT NULL,process_json TEXT NOT NULL,"
                "invocation_id TEXT NOT NULL,manifest_digest TEXT NOT NULL,graph_head_digest TEXT NOT NULL,constraint_digest TEXT NOT NULL,"
                "original_ref TEXT NOT NULL,original_digest TEXT NOT NULL,PRIMARY KEY(namespace,epoch,original_ref))")
            material = (self.namespace, self.installation_id, "active", 0, None)
            db.execute("INSERT OR IGNORE INTO authority_d12_lifecycle_heads_v1 VALUES(?,?,?,?,?,?,NULL)",
                       (*material, digest(material)))

    @contextmanager
    def rpc_activity_v1(self):
        """Count installed ordinary RPCs; management/status must be excluded."""
        with self._condition:
            self._active_rpc += 1
        try:
            yield
        finally:
            with self._condition:
                self._active_rpc -= 1
                self._condition.notify_all()

    def _rpc_count(self):
        with self._condition:
            return self._active_rpc

    def _storage(self):
        context = self.control.read_verified_current_storage_v1()
        context.require_current("business")
        # A one-Owner whole-Host control cannot silently claim other namespaces.
        if tuple(context.manifest["cohort_namespaces"]) != (self.namespace,):
            raise AuthorityUnavailable("whole-Host control requires the explicitly single-Owner installed cohort")
        value = {"pointer_version": context.pointer_version, "manifest_digest": context.manifest_digest,
            "storage_generation": context.storage_generation, "members": [
                {key: member[key] for key in ("role", "resolved_path", "device", "file_id", "incarnation_or_journal_id")}
                for member in context.manifest["members"]]}
        return context, value

    def _counts(self, db):
        live = db.execute("SELECT COUNT(*) FROM authority_v2_fences WHERE namespace=? AND state='active'", (self.namespace,)).fetchone()[0]
        pending = db.execute("SELECT COUNT(*) FROM authority_v2_mutations WHERE namespace=? AND state='pending'", (self.namespace,)).fetchone()[0]
        return live, pending, self._rpc_count()

    def _operation(self, db, operation_id):
        row = db.execute(f"SELECT * FROM {OPS} WHERE namespace=? AND operation_id=?", (self.namespace, operation_id)).fetchone()
        if row is None:
            raise AuthorityUnavailable("original installation control operation is absent")
        return row

    def _owner_still_current(self, db, row):
        request = session_from_wire({"kind": "owner_session_login_request_v1", **json.loads(row[8])})
        sessions = self.status_service.sessions
        # Durable command authorization is not a browser session extension.
        # Current key/pairing/actor/head must still exist at every new stage.
        sessions._current_key(db, request)
        sessions._current_pairing_source.require_current_actor_in_tx(db, authority_namespace=self.namespace,
            installation_id=request.installation_id, actor_id=row[7], principal=request.principal)
        guard = self.status_service.tickets._checked_current_head(db, self.namespace)
        if (guard is None or guard.authorization_head != row[9]
                or guard.pending_revoke_operation_id is not None
                or guard.minimum_revocation_revision or guard.minimum_revocation_epoch):
            raise AuthorityUnavailable("installation control initiating Owner has changed")
        return guard

    def _constraints_in_tx(self, db, deletion, execution, storage, *, require_current_graph=False, qualified_context=None):
        graph_path = next(item["resolved_path"] for item in storage["members"] if item["role"] == "graph")
        graph = sqlite3.connect(Path(graph_path).as_uri()+"?mode=ro", uri=True, isolation_level=None)
        try:
            graph.execute("BEGIN")
            metadata = GraphStore._decode_recovery(graph.execute("SELECT schema,requirements_json,graph_revision "
                "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", self.namespace_id.as_tuple).fetchone(), self.namespace_id)
            if metadata is None:
                raise AuthorityUnavailable("current paused/resuming Graph stamp absent")
            anchor = self.fences._current_locked(db, deletion, execution, require_no_pending=False)
            req = metadata.requirements
            if (req.authority_id, req.authority_namespace, req.activation_generation,
                    req.deletion_journal_id, req.deletion_seq, req.deletion_digest,
                    req.execution_journal_id, req.revocation_epoch) != (
                    anchor.authority_id, anchor.namespace, anchor.activation_generation,
                    anchor.deletion_journal_id, anchor.deletion_seq, anchor.deletion_digest,
                    anchor.execution_journal_id, anchor.revocation_epoch):
                raise AuthorityUnavailable("Host Graph namespace/deletion/activation lineage differs")
            if require_current_graph and (req.execution_seq,req.execution_digest)!=(anchor.execution_seq,anchor.execution_digest):
                raise AuthorityUnavailable("new Host has not reconciled its exact current execution head")
            if req.execution_seq>anchor.execution_seq:
                raise AuthorityUnavailable("Host Graph execution head is ahead of independent Authority")
            head,rows=self.fences.execution._scan_locked()
            prefix="genesis" if req.execution_seq==0 else next((item[6] for item in rows if item[0]==req.execution_seq),None)
            if head!=execution or prefix!=req.execution_digest:
                raise AuthorityUnavailable("Host Graph execution prefix is not in the actual independent journal")
            projection = self.constraints.read_namespace_constraints_in_authority_tx_v1(
                db=db, target_db=graph, namespace_id=self.namespace_id, deletion_head=deletion, execution_head=execution,qualified_context=qualified_context)
            return projection, digest(metadata)
        finally:
            graph.close()

    def _receipt(self, db, row, *, head, stage, anchor, constraints=None, supervisor=None, process=None, bootstrap_ref=None):
        prior = None
        if row[14] is not None:
            prior = db.execute(f"SELECT original_digest FROM {RECEIPTS} WHERE original_ref=?", (row[14],)).fetchone()[0]
        live, pending, rpc = self._counts(db)
        material = dict(authority_namespace=self.namespace, installation_id=self.installation_id,
            operation_id=row[1], request_digest=row[2], action=row[3], stage=stage,
            lifecycle_epoch=head.epoch, business_generation=anchor.activation_generation, owner_head=row[9],
            storage_identity_digest=digest(json.loads(row[10])), namespace_anchor_digest=digest(anchor),
            constraint_projection_digest=None if constraints is None else constraints.original_digest,
            supervisor_observation_digest=None if supervisor is None else supervisor.observation_digest,
            process_identity_digest=None if process is None else digest(process), bootstrap_original_ref=bootstrap_ref,
            live_fence_count=live, pending_mutation_count=pending, active_rpc_count=rpc,
            prior_receipt_digest=prior, scope="whole_host", schema="d12.installation_lifecycle_receipt.v1")
        material["original_ref"] = "d12lifecycle:" + digest(material)[7:]
        material["original_digest"] = digest(material)
        receipt = D12InstallationLifecycleReceiptV1(**material)
        values = (self.namespace, row[1], stage, receipt.original_ref, receipt.original_digest, canonical_serialize(asdict(receipt)))
        db.execute(f"INSERT INTO {RECEIPTS} VALUES(?,?,?,?,?,?)", values)
        db.execute(f"UPDATE {OPS} SET current_stage=?,current_receipt_ref=?,hold_code=NULL WHERE namespace=? AND operation_id=?", (stage,receipt.original_ref,self.namespace,row[1]))
        state = "drained" if stage in {"drained", "stop_intent"} else "resuming" if stage in {"resuming", "start_intent", "ready"} else stage
        head_material = (self.namespace,self.installation_id,state,head.epoch,row[1],receipt.original_ref)
        changed = db.execute("UPDATE authority_d12_lifecycle_heads_v1 SET state=?,operation_id=?,head_digest=?,current_receipt_ref=? "
            "WHERE namespace=? AND epoch=? AND head_digest=?", (state,row[1],digest(head_material),receipt.original_ref,
                self.namespace,head.epoch,head.head_digest)).rowcount
        if changed != 1:
            raise AuthorityUnavailable("lifecycle stage head CAS changed")
        return receipt

    def inspect_current_lifecycle_v1(self, *, credential, actor, session_token, session_request):
        self.core._require(credential,"d12_lifecycle_control",self.namespace)
        with self.core._tx() as db:
            guard=self.status_service.tickets._checked_current_head(db,self.namespace)
            if guard is None:
                raise AuthorityUnavailable("current installation Owner head absent")
            self.status_service._current_session_in_tx(db,actor=actor,token=session_token,
                request=session_request,expected_head=guard.authorization_head)
            head=read_lifecycle_head_in_tx_v1(db,self.namespace)
            if head is None or head.installation_id!=self.installation_id:
                raise AuthorityUnavailable("current installed lifecycle controller identity differs")
            return head

    def submit_current_control_v1(self, *, credential, actor, session_token, session_request, original_ref):
        self.core._require(credential, "d12_lifecycle_control", self.namespace)
        context, storage = self._storage()
        observed = self.supervisor.read_current_host_state_v1()
        process = None if observed.main_pid == 0 else read_process_identity_v1(observed.main_pid)
        with self.fences._frozen() as (db, deletion, execution, _):
            source = db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE authority_namespace=? AND original_ref=?",
                                (self.namespace, original_ref)).fetchone()
            if source is None:
                raise AuthorityUnavailable("whole-Host control original not registered")
            original = self.status_service._authenticate_original_row_in_tx(db, source, actor=actor,
                token=session_token, request=session_request)
            plan = json.loads(source[7])
            if original.kind != "control" or plan.get("schema") != "d12.registered_installation_control.v1":
                raise AuthorityUnavailable("explicit whole-Host control original required")
            intent = D12InstallationControlIntentV1(**plan["intent"])
            if intent.installation_id != self.installation_id:
                raise AuthorityUnavailable("whole-Host control installation differs")
            prior = db.execute(f"SELECT source_original_ref FROM {OPS} WHERE namespace=? AND operation_id=?",
                               (self.namespace,original.operation_id)).fetchone()
            if prior is None:
                head = read_lifecycle_head_in_tx_v1(db,self.namespace)
                required_state = "active" if intent.action == "pause" else "paused"
                if head is None or head.installation_id != self.installation_id or head.epoch != intent.expected_lifecycle_epoch or head.state != required_state:
                    raise AuthorityUnavailable("current lifecycle state/epoch differs")
                if intent.action == "resume" and head.operation_id != intent.prior_pause_operation_id:
                    raise AuthorityUnavailable("resume does not name the current original pause")
                if intent.action == "pause" and (observed.active_state != "active" or process is None):
                    raise AuthorityUnavailable("pause requires the actual current installed Host")
                if intent.action == "resume" and not observed.stopped_and_drained:
                    raise AuthorityUnavailable("resume requires actual original Host retirement")
                anchor = self.fences._current_locked(db,deletion,execution,require_no_pending=False)
                context.require_current("business")
                stage = "quiescing" if intent.action == "pause" else "resuming"
                values = (self.namespace,original.operation_id,original.request_digest,intent.action,original_ref,
                    canonical_serialize(asdict(original)),canonical_serialize(asdict(intent)),actor,source[5],source[6],
                    canonical_serialize(storage),canonical_serialize(asdict(observed)),canonical_serialize(process),stage,None,None)
                db.execute(f"INSERT INTO {OPS} VALUES({','.join('?' for _ in values)})",values)
                material=(self.namespace,self.installation_id,stage,head.epoch+1,original.operation_id)
                changed=db.execute("UPDATE authority_d12_lifecycle_heads_v1 SET state=?,epoch=?,operation_id=?,head_digest=? "
                    "WHERE namespace=? AND epoch=? AND head_digest=?",(stage,head.epoch+1,original.operation_id,digest(material),self.namespace,head.epoch,head.head_digest)).rowcount
                if changed != 1:
                    raise AuthorityUnavailable("lifecycle accepted head CAS changed")
                head=read_lifecycle_head_in_tx_v1(db,self.namespace)
                self._receipt(db,values,head=head,stage=stage,anchor=anchor,supervisor=observed,process=process)
            elif prior[0] != original_ref:
                # Registration/ref refresh may yield a new immutable status; it
                # never changes the original command or accepted operation ID.
                row=self._operation(db,original.operation_id)
                if row[2] != original.request_digest:
                    raise AuthorityUnavailable("lifecycle original operation request differs")
        self._start_worker(original.operation_id)
        return self.status_service.read_current_operation_original_v1(credential=credential,actor=actor,
            session_token=session_token,session_request=session_request,original_ref=original_ref,refresh=True)

    def _start_worker(self, operation_id):
        with self._condition:
            prior=self._workers.get(operation_id)
            if prior is not None and prior.is_alive():
                return
            thread=threading.Thread(target=self._run, args=(operation_id,),name="sylanne-lifecycle-"+operation_id[:8],daemon=True)
            self._workers[operation_id]=thread
            thread.start()

    def _run(self, operation_id):
        deadline=time.monotonic()+self.drain_timeout_seconds
        try:
            while not self._closed.is_set() and time.monotonic()<deadline:
                context,storage=self._storage()
                with self.fences._frozen() as (db,deletion,execution,_):
                    row=self._operation(db,operation_id); head=read_lifecycle_head_in_tx_v1(db,self.namespace)
                    if head.operation_id != operation_id or row[13] in {"paused","active"}:
                        return
                    self._owner_still_current(db,row)
                    if canonical_serialize(storage)!=row[10]:
                        raise AuthorityUnavailable("lifecycle current four-file storage changed")
                    anchor=self.fences._current_locked(db,deletion,execution,require_no_pending=False)
                    stage=row[13]
                    if stage=="quiescing":
                        # RPC entry/exit is independent of Core SQL. Hold its
                        # same condition lock across the actual zero check and
                        # settled receipt so a just-arriving RPC cannot race it.
                        with self._condition:
                            if any(self._counts(db)):
                                wait=True
                            else:
                                projection,_=self._constraints_in_tx(db,deletion,execution,storage,qualified_context=context)
                                self._receipt(db,row,head=head,stage="drained",anchor=anchor,constraints=projection)
                                wait=False
                    else:
                        wait=False
                if wait:
                    self._closed.wait(0.25)
                    continue
                if stage=="quiescing":
                    continue
                if stage in {"drained","stop_intent"}:
                    initial=json.loads(row[11]); identity=json.loads(row[12])
                    if stage=="drained":
                        with self.fences._frozen() as (db,deletion,execution,_):
                            row=self._operation(db,operation_id);head=read_lifecycle_head_in_tx_v1(db,self.namespace)
                            self._owner_still_current(db,row)
                            self._receipt(db,row,head=head,stage="stop_intent",anchor=self.fences._current_locked(db,deletion,execution,require_no_pending=False))
                    after=self.supervisor.stop_original_host_v1(expected_invocation_id=initial["invocation_id"])
                    if identity is not None:
                        require_process_retired_v1(identity)
                    context,current=self._storage()
                    wait_after_stop=False
                    with self.fences._frozen() as (db,deletion,execution,_):
                        with self._condition:
                            row=self._operation(db,operation_id);head=read_lifecycle_head_in_tx_v1(db,self.namespace)
                            self._owner_still_current(db,row)
                            if canonical_serialize(current)!=row[10]:
                                raise AuthorityUnavailable("post-stop current storage changed")
                            if any(self._counts(db)):
                                wait_after_stop=True
                            else:
                                projection,_=self._constraints_in_tx(db,deletion,execution,current,qualified_context=context)
                                self._receipt(db,row,head=head,stage="paused",anchor=self.fences._current_locked(db,deletion,execution),
                                    constraints=projection,supervisor=after,process=identity)
                    if wait_after_stop:
                        self._closed.wait(0.05)
                        continue
                    return
                if stage=="resuming":
                    with self.fences._frozen() as (db,deletion,execution,_):
                        row=self._operation(db,operation_id);head=read_lifecycle_head_in_tx_v1(db,self.namespace)
                        self._owner_still_current(db,row)
                        if any(self._counts(db)):
                            raise AuthorityUnavailable("resume original admissions have not drained")
                        projection,_=self._constraints_in_tx(db,deletion,execution,storage,qualified_context=context)
                        self._receipt(db,row,head=head,stage="start_intent",anchor=self.fences._current_locked(db,deletion,execution),
                            constraints=projection)
                    self.supervisor.start_stopped_host_v1(expected_prior_invocation_id=json.loads(row[11])["invocation_id"])
                    continue
                if stage in {"start_intent","ready"}:
                    # Once start_intent exists, never issue another start. A
                    # crash/timeout is resolved only by actual current bootstrap.
                    if self._finish_resume_if_ready(operation_id):
                        return
                    self._closed.wait(0.25)
                    continue
                raise AuthorityUnavailable("unsupported installed lifecycle stage")
            if not self._closed.is_set():
                self._record_hold(operation_id, "original_stage_drain_or_bootstrap_incomplete")
        except Exception:
            # Do not persist exception text, paths, tokens or provider bodies.
            self._record_hold(operation_id, "original_stage_reconciliation_required")
            return

    def _record_hold(self, operation_id, code):
        with self.core._tx() as db:
            row=db.execute(f"SELECT current_stage FROM {OPS} WHERE namespace=? AND operation_id=?",
                           (self.namespace,operation_id)).fetchone()
            if row is not None and row[0] not in {"paused","active"}:
                db.execute(f"UPDATE {OPS} SET hold_code=? WHERE namespace=? AND operation_id=?",
                           (code,self.namespace,operation_id))

    def read_current_control_v1(self, *, credential, actor, session_token, session_request, operation_id, continue_original=False):
        self.core._require(credential,"d12_lifecycle_control",self.namespace)
        with self.core._tx() as db:
            row=self._operation(db,operation_id)
            original_ref=row[4]
        result=self.status_service.read_current_operation_original_v1(credential=credential,actor=actor,
            session_token=session_token,session_request=session_request,original_ref=original_ref,refresh=True)
        if continue_original:
            self._start_worker(operation_id)
        return result

    def resume_paused_installation_v1(self, *, credential, actor, session_token, session_request,
                                     pause_operation_id, operation_id, expected_lifecycle_epoch):
        self.core._require(credential,"d12_lifecycle_control",self.namespace)
        if str(UUID(operation_id))!=operation_id or UUID(operation_id).version!=4:
            raise ValueError("resume operation must be a canonical UUID4")
        with self.fences._frozen() as (db,deletion,execution,_):
            paused=self._operation(db,pause_operation_id)
            source=db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE original_ref=?",(paused[4],)).fetchone()
            original=self.status_service._authenticate_original_row_in_tx(db,source,actor=actor,token=session_token,request=session_request)
            head=read_lifecycle_head_in_tx_v1(db,self.namespace)
            if (paused[3]!="pause" or paused[13]!="paused" or head.state!="paused"
                    or head.operation_id!=pause_operation_id or head.epoch!=expected_lifecycle_epoch):
                existing=db.execute(f"SELECT source_original_ref,request_digest FROM {OPS} WHERE namespace=? AND operation_id=?",(self.namespace,operation_id)).fetchone()
                expected_intent=D12InstallationControlIntentV1(self.installation_id,"resume",expected_lifecycle_epoch,pause_operation_id)
                expected_digest=digest({"schema":"d12.independent_resume_request.v1","operation_id":operation_id,
                    "pause_operation_id":pause_operation_id,"intent":asdict(expected_intent)})
                if existing is None or existing[1]!=expected_digest:
                    raise AuthorityUnavailable("resume original pause/current lifecycle epoch differs")
                registered_ref=existing[0]
            else:
                intent=D12InstallationControlIntentV1(self.installation_id,"resume",expected_lifecycle_epoch,pause_operation_id)
                command={"object_ref":"installation:"+self.installation_id,"control":"resume","test_intent":None,
                    "config_diff":{"schema":intent.schema,"scope":intent.scope,"expected_lifecycle_epoch":expected_lifecycle_epoch,
                        "prior_pause_operation_id":pause_operation_id}}
                request_digest=digest({"schema":"d12.independent_resume_request.v1","operation_id":operation_id,
                    "pause_operation_id":pause_operation_id,"intent":asdict(intent)})
                material={field.name:getattr(original,field.name) for field in fields(original)}
                payload=D12ControlPayloadV1(command["object_ref"],"resume",expected_lifecycle_epoch,(),False)
                material.update(operation_id=operation_id,request_digest=request_digest,result=payload,result_digest=digest(payload),
                    state="accepted",coverage=("independent_signed_owner_resume",),missing_inputs=())
                material["original_digest"]=backend_original_digest_v1(material)
                registered=self.status_service._readdress(D12BackendOperationOriginalV1(**material))
                plan=json.loads(source[7]);plan.update(input=command,intent=asdict(intent))
                values=(self.namespace,operation_id,registered.original_ref,canonical_serialize(asdict(registered)),
                    actor,session_canonical(session_request),source[6],canonical_serialize(plan),"d12controlrequest:"+request_digest[7:])
                db.execute("INSERT OR IGNORE INTO authority_d12_operation_originals_v1 VALUES(?,?,?,?,?,?,?,?,?)",values)
                if db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE original_ref=?",(registered.original_ref,)).fetchone()!=values:
                    raise AuthorityUnavailable("resume original registration conflict")
                registered_ref=registered.original_ref
        return self.submit_current_control_v1(credential=credential,actor=actor,session_token=session_token,
            session_request=session_request,original_ref=registered_ref)

    def _verify_package_in_host(self, observation):
        from ..host.installed_package import verify_installed_backend_runtime_v1
        verified=verify_installed_backend_runtime_v1(self.package_root,self.expected_manifest_digest)
        if not verified.verified:
            raise AuthorityUnavailable("current Host backend package is not qualified")
        manifest=json.loads((self.package_root/"release-manifest.json").read_bytes())
        native=(self.package_root/manifest["native"]["path"]).resolve(strict=True)
        inode=native.stat().st_ino
        mappings=Path(f"/proc/{observation.main_pid}/maps").read_text()
        if not any(len(parts:=line.split(maxsplit=5))==6 and parts[4]==str(inode)
                   and Path(parts[5]).resolve(strict=False)==native for line in mappings.splitlines()):
            raise AuthorityUnavailable("actual new Host does not map the qualified native library")
        return verified

    def register_current_host_bootstrap_v1(self, *, credential, peer_certificate_sha256, peer_profile_id,
                                          operation_id, expected_epoch, process_id, invocation_id,
                                          catalogue_hash, ready_domains):
        self.core._require(credential,"d12_lifecycle_bootstrap",self.namespace)
        if (peer_certificate_sha256,peer_profile_id)!=self.peer or ready_domains!=tuple(f"d{i:02}" for i in range(1,14)):
            raise AuthorityUnavailable("exact installed peer and thirteen ready domains required")
        observed=self.supervisor.read_current_host_state_v1()
        if (observed.active_state!="active" or observed.main_pid!=process_id or observed.invocation_id!=invocation_id
                or process_id not in observed.process_ids):
            raise AuthorityUnavailable("bootstrap is not the actual new supervised Host")
        identity=read_process_identity_v1(process_id)
        verified=self._verify_package_in_host(observed)
        if identity is None or catalogue_hash!=verified.catalogue_hash:
            raise AuthorityUnavailable("actual new Host birth/catalogue differs")
        context,storage=self._storage()
        with self.fences._frozen() as (db,deletion,execution,_):
            head=read_lifecycle_head_in_tx_v1(db,self.namespace);row=self._operation(db,operation_id)
            if (head.epoch!=expected_epoch or head.operation_id!=operation_id
                    or canonical_serialize(storage)!=row[10] or json.loads(row[11])["invocation_id"]==invocation_id):
                raise AuthorityUnavailable("bootstrap does not bind the original resume stage")
            self._owner_still_current(db,row)
            if head.state=="active" and row[13]=="active":
                # An ACK-lost Host replays the same bootstrap identity. It does
                # not manufacture a fresh readiness receipt after activation.
                prior=db.execute(f"SELECT * FROM {BOOTS} WHERE namespace=? AND epoch=? AND operation_id=? ORDER BY rowid DESC LIMIT 1",
                    (self.namespace,expected_epoch,operation_id)).fetchone()
                if (prior is None or prior[3:5]!=self.peer or prior[5]!=canonical_serialize(identity)
                        or prior[6]!=invocation_id or prior[7]!=self.expected_manifest_digest):
                    raise AuthorityUnavailable("active bootstrap replay differs from its original Host birth")
                return prior[10]
            if head.state!="resuming" or row[13] not in {"start_intent","ready"}:
                raise AuthorityUnavailable("bootstrap does not belong to a resuming installation")
            projection,graph_digest=self._constraints_in_tx(db,deletion,execution,storage,require_current_graph=True,qualified_context=context)
            material=(self.namespace,head.epoch,operation_id,*self.peer,canonical_serialize(identity),
                invocation_id,self.expected_manifest_digest,graph_digest,projection.original_digest)
            ref="d12bootstrap:"+digest(material)[7:]
            values=(*material,ref,digest((*material,ref)))
            prior=tuple(db.execute(f"SELECT process_json,invocation_id,peer_certificate_sha256,peer_profile_id FROM {BOOTS} WHERE namespace=? AND epoch=?",
                                   (self.namespace,head.epoch)))
            if any(item!=(canonical_serialize(identity),invocation_id,*self.peer) for item in prior):
                raise AuthorityUnavailable("resume epoch already belongs to a different actual Host birth")
            db.execute(f"INSERT OR IGNORE INTO {BOOTS} VALUES({','.join('?' for _ in values)})",values)
            if db.execute(f"SELECT * FROM {BOOTS} WHERE namespace=? AND epoch=? AND original_ref=?",(self.namespace,head.epoch,ref)).fetchone()!=values:
                raise AuthorityUnavailable("original Host bootstrap identity conflict")
        return ref

    def read_current_host_bootstrap_progress_v1(self, original_ref):
        """Only the just-authenticated exact bootstrap's actual lifecycle head."""
        with self.core._tx() as db:
            boot=db.execute(f"SELECT namespace,epoch,operation_id FROM {BOOTS} WHERE original_ref=?",(original_ref,)).fetchone()
            head=read_lifecycle_head_in_tx_v1(db,self.namespace)
            if (boot is None or boot!=(self.namespace,head.epoch,head.operation_id)
                    or head.state not in {"resuming","active"}):
                raise AuthorityUnavailable("original bootstrap no longer owns the current resume epoch")
            self._owner_still_current(db,self._operation(db,head.operation_id))
            return {"bootstrap_original_ref":original_ref,"lifecycle_state":head.state,"lifecycle_epoch":head.epoch}

    def _finish_resume_if_ready(self, operation_id):
        observed=self.supervisor.read_current_host_state_v1()
        context,storage=self._storage()
        identity=read_process_identity_v1(observed.main_pid) if observed.main_pid else None
        if observed.active_state!="active" or identity is None:
            return False
        # Package traversal and /proc observations precede the short Core CAS.
        # The exact observed birth/invocation must still equal the independently
        # registered bootstrap original below; no process start is issued here.
        try:
            self._verify_package_in_host(observed)
        except (AuthorityUnavailable,ValueError,OSError):
            return False
        with self.fences._frozen() as (db,deletion,execution,_):
            with self._condition:
                head=read_lifecycle_head_in_tx_v1(db,self.namespace);row=self._operation(db,operation_id)
                boot=db.execute(f"SELECT * FROM {BOOTS} WHERE namespace=? AND epoch=? ORDER BY rowid DESC LIMIT 1",(self.namespace,head.epoch)).fetchone()
                if boot is None:
                    return False
                if (head.operation_id!=operation_id or head.state!="resuming" or boot[2]!=operation_id
                        or boot[3:5]!=self.peer or boot[5]!=canonical_serialize(identity)
                        or boot[6]!=observed.invocation_id or observed.active_state!="active"
                        or canonical_serialize(storage)!=row[10]):
                    raise AuthorityUnavailable("current resume bootstrap/storage/drain differs")
                if any(self._counts(db)):
                    return False
                self._owner_still_current(db,row)
                projection,graph_digest=self._constraints_in_tx(db,deletion,execution,storage,require_current_graph=True,qualified_context=context)
                if (graph_digest,projection.original_digest)!=(boot[8],boot[9]):
                    raise AuthorityUnavailable("Host readiness Graph or retained constraints changed")
                anchor=self.fences._current_locked(db,deletion,execution)
                if row[13]!="ready":
                    self._receipt(db,row,head=head,stage="ready",anchor=anchor,constraints=projection,
                        supervisor=observed,process=json.loads(boot[5]),bootstrap_ref=boot[10])
                    row=self._operation(db,operation_id);head=read_lifecycle_head_in_tx_v1(db,self.namespace)
                self._receipt(db,row,head=head,stage="active",anchor=anchor,constraints=projection,
                    supervisor=observed,process=json.loads(boot[5]),bootstrap_ref=boot[10])
                return True

    def read_status_original_in_tx_v1(self, db, *, original):
        row=db.execute(f"SELECT * FROM {OPS} WHERE namespace=? AND operation_id=?",(self.namespace,original.operation_id)).fetchone()
        if row is None:
            return original
        if row[2]!=original.request_digest:
            raise AuthorityUnavailable("control status request identity differs")
        receipts=tuple(lifecycle_receipt_from_wire_v1(json.loads(item[0])) for item in db.execute(
            f"SELECT original_json FROM {RECEIPTS} WHERE namespace=? AND operation_id=? ORDER BY rowid",(self.namespace,original.operation_id)))
        latest=receipts[-1]
        material={field.name:getattr(original,field.name) for field in fields(original)}
        payload=D12ControlPayloadV1(original.result.object_ref,original.result.control,latest.lifecycle_epoch,
            tuple(item.original_ref for item in receipts),False)
        material.update(result=payload,result_digest=digest(payload),state="completed" if latest.stage in {"paused","active"} else "running",
            authority_refs=(*original.authority_refs[:1],*(('lifecycle_stage',item.original_ref,item.original_digest) for item in receipts)),
            coverage=("whole_host_scope","original_owner_command","durable_lifecycle_epoch","unknown_constraints_preserved",
                "stage:"+latest.stage),missing_inputs=(() if row[15] is None else (row[15],)))
        if row[15] is not None and latest.stage not in {"paused","active"}:
            material["state"]="pending_confirmation"
        material["original_digest"]=backend_original_digest_v1(material)
        return D12BackendOperationOriginalV1(**material)

    def resume_pending_operations_v1(self):
        with self.core._tx() as db:
            head=read_lifecycle_head_in_tx_v1(db,self.namespace)
            owned=(head is not None and head.operation_id is not None and db.execute(
                f"SELECT 1 FROM {OPS} WHERE namespace=? AND operation_id=?",(self.namespace,head.operation_id)).fetchone() is not None)
        # Package maintenance owns this shared exclusion through its separate
        # external supervisor; a lifecycle worker cannot finish that operation.
        if owned and head.state not in {"active","paused"}:
            self._start_worker(head.operation_id)

    def close(self):
        self._closed.set()
        with self._condition:
            workers=tuple(self._workers.values())
        timeout=getattr(getattr(self.supervisor,"config",None),"timeout_seconds",60)+5
        for worker in workers:
            if worker is not threading.current_thread():
                worker.join(timeout=timeout)
                if worker.is_alive():
                    raise AuthorityUnavailable("original supervisor action must settle before Authority closes")


__all__=("InstalledD12InstallationLifecycleV1","OPS","RECEIPTS","BOOTS")
