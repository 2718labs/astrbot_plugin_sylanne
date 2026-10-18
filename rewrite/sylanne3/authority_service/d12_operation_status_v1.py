"""Exact D12 operation originals that remain queryable after source freeze.

This service never reads user content through a revoked source API. Registration
copies a typed original from the administrator-pinned Graph under a current
Owner fence. Later queries authenticate the original Owner's still-current key,
login session and authorization head, then disclose only that exact operation.
"""
from __future__ import annotations

from dataclasses import asdict, fields
import json
from pathlib import Path
import sqlite3

from ..domains.d12.backend_operation_contracts_v1 import (
    D12BackendOperationOriginalV1, D12TransferExecutionPayloadV1, backend_original_digest_v1,
)
from ..graph_types import owner_grant_key
from ..runtime.lifecycle_operations_v1 import ControlCommandV1, decode_original, digest
from ..runtime_contracts import canonical_serialize
from .contract import AuthorityUnavailable
from .v2_fence_store import AuthorityV2FenceStore
from .v2_owner_session import (
    AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1,
    _canonical, _principal, _time, _verifier,
)
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore

_TABLE = """CREATE TABLE IF NOT EXISTS authority_d12_operation_originals_v1(
 authority_namespace TEXT NOT NULL, operation_id TEXT NOT NULL,
 original_ref TEXT NOT NULL PRIMARY KEY, original_json TEXT NOT NULL,
 actor TEXT NOT NULL, session_request_json BLOB NOT NULL,
 owner_head TEXT NOT NULL, plan_json TEXT NOT NULL,
 source_original_ref TEXT NOT NULL)"""


class InstalledD12OperationStatusServiceV1:
    def __init__(self, *, fences, owner_tickets, source_graph_db: Path,
                 namespace_id, installation_id: str, migration=None):
        if (type(owner_tickets) is not AuthorityV2OwnerTicketStore
                or owner_tickets._core is not fences.core
                or type(owner_tickets._owner_sessions) is not AuthorityV2OwnerSessionStore):
            raise TypeError("D12 status requires same-Core signed Owner services")
        path = Path(source_graph_db)
        if not path.is_absolute() or not path.is_file() or path.is_symlink():
            raise ValueError("administrator-pinned source Graph file required")
        if migration is not None and migration.fences is not fences:
            raise TypeError("migration must use the same installed fence service")
        self.fences, self.core, self.tickets = fences, fences.core, owner_tickets
        self.sessions = owner_tickets._owner_sessions
        self.namespace, self.namespace_id = fences.namespace, namespace_id
        self.installation_id, self.source = installation_id, path.resolve(strict=True)
        self.migration = migration
        self._target_owner_readers = {}
        self._source_graphs = {installation_id: self.source}
        self._control_status_readers = {}
        self._stop_reply_status_readers = {}

    def install_schema(self, administrator_credential):
        self.core._require(administrator_credential, "d12_operation_install", self.namespace)
        with self.core._tx() as db:
            db.execute(_TABLE)

    def _current_session_in_tx(self, db, *, actor, token, request, expected_head):
        """Current authentication without an ordinary content-active predicate."""
        if (type(request) is not OwnerSessionLoginRequestV1 or request.audience != "owner"
                or request.authority_namespace != self.namespace
                or request.installation_id not in self._source_graphs
                or request.authority_id != self.core._id(db)):
            raise AuthorityUnavailable("D12 operation session identity differs")
        sessions = self.sessions
        sessions._require_mode(db)
        key = db.execute("SELECT credential_id,credential_epoch,public_key FROM authority_owner_credentials_v1 "
            "WHERE authority_namespace=? AND installation_id=? AND principal_json=?",
            (self.namespace, request.installation_id, _principal(request.principal))).fetchone()
        if key is None or key[:2] != (request.credential_id, request.credential_epoch):
            raise AuthorityUnavailable("D12 operation Owner key is no longer current")
        if db.execute("SELECT 1 FROM authority_owner_session_revoked_keys_v1 WHERE authority_namespace=? "
            "AND installation_id=? AND principal_json=? AND credential_id=? AND credential_epoch=?",
            (self.namespace, request.installation_id, _principal(request.principal),
             request.credential_id, request.credential_epoch)).fetchone() is not None:
            raise AuthorityUnavailable("D12 operation Owner key is revoked")
        source = sessions._current_pairing_source
        if source is None:
            raise AuthorityUnavailable("D12 operation Owner pairing reader unavailable")
        source.require_current_owner_key_in_tx(db, request, key[2])
        source.require_current_actor_in_tx(db, authority_namespace=self.namespace,
            installation_id=request.installation_id, actor_id=actor, principal=request.principal)
        row = db.execute("SELECT request_json,principal_epoch,boot_id,expires_at_utc,revoked_at_utc "
            "FROM authority_owner_sessions_v1 WHERE verifier=?", (_verifier(token),)).fetchone()
        boot = db.execute("SELECT value FROM authority_meta WHERE key='owner_session_boot_id'").fetchone()
        if (row is None or row[0] != _canonical(request)
                or row[1] != sessions._principal_epoch(db, request)
                or row[2] != sessions._boot_id or boot != (sessions._boot_id,)
                or sessions._now() >= _time(row[3]) or row[4] is not None):
            raise AuthorityUnavailable("D12 operation login session is not current")
        guard = self.tickets._checked_current_head(db, self.namespace)
        if (guard is None or guard.authorization_head != expected_head
                or guard.minimum_revocation_revision or guard.minimum_revocation_epoch
                or guard.pending_revoke_operation_id is not None):
            raise AuthorityUnavailable("D12 operation Owner authorization changed")
        return guard

    def install_target_owner_status_reader_v1(self, service):
        from .d12_target_owner_admission_v1 import InstalledD12TargetOwnerAdmissionServiceV1
        if (type(service) is not InstalledD12TargetOwnerAdmissionServiceV1
                or service.core is not self.core or service.namespace != self.namespace
                or service.operation_status_service is not self):
            raise AuthorityUnavailable("target status admission authority differs")
        existing = self._target_owner_readers.get(service.installation_id)
        if existing is not None and existing is not service:
            raise AuthorityUnavailable("target status reader already installed")
        self._target_owner_readers[service.installation_id] = service
        self._source_graphs[service.installation_id] = service.target_graph

    def install_owner_storage_reader_v1(self,service):
        from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
        if (type(service) is not InstalledD12OwnerStorageAdmissionServiceV1 or service.core is not self.core
                or service.namespace!=self.namespace or service.installation_id not in self._source_graphs):
            raise AuthorityUnavailable("source storage Owner status reader differs")
        readers=getattr(self,"_storage_owner_readers",None)
        if readers is None:readers={};self._storage_owner_readers=readers
        prior=readers.get(service.installation_id)
        if prior is not None and prior is not service:raise AuthorityUnavailable("source storage status reader already installed")
        readers[service.installation_id]=service
        self._source_graphs[service.installation_id]=service.graph_path

    def _authenticate_original_row_in_tx(self, db, row, *, actor, token, request):
        original = decode_original(json.loads(row[3]))
        raw=json.loads(row[5])
        from .v2_owner_contract import OwnerPrincipalV1
        raw["principal"]=OwnerPrincipalV1(**raw["principal"])
        source_request=OwnerSessionLoginRequestV1(**raw)
        same_installation=(type(request) is OwnerSessionLoginRequestV1 and all(
            getattr(source_request,name)==getattr(request,name) for name in
            ("authority_id","authority_namespace","installation_id","principal","audience")))
        if same_installation:
            if row[4] != actor:
                raise AuthorityUnavailable("exact D12 operation is not owned by this actor")
            # A fresh current key/session may inspect this exact old operation.
            # The initiating request remains immutable; current pairing, actor,
            # key revocation, principal epoch and unchanged Owner head are all
            # checked again here, including while the Host is stopped.
            self._current_session_in_tx(db, actor=actor, token=token, request=request, expected_head=row[6])
        else:
            reader = self._target_owner_readers.get(request.installation_id)
            if reader is None:
                raise AuthorityUnavailable("current target status admission unavailable")
            reader.require_exact_operation_status_in_tx_v1(db, original=original,
                source_request=source_request, expected_owner_head=row[6], actor=actor,
                token=token, request=request)
        return original

    def _read_source_original(self, original_ref, installation_id):
        source = self._source_graphs.get(installation_id)
        if source is None:
            raise AuthorityUnavailable("current operation installation has no pinned graph")
        db = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        try:
            db.execute("BEGIN")
            row = db.execute("SELECT original_json FROM graph_d12_backend_originals_v1 WHERE "
                "bot=? AND persona=? AND original_ref=?", (*self.namespace_id.as_tuple, original_ref)).fetchone()
            if row is None:
                raise AuthorityUnavailable("exact D12 source operation is absent")
            original = decode_original(json.loads(row[0]))
            operation = db.execute("SELECT owner_json,current_original_ref,request_digest,kind,input_json FROM graph_d12_backend_operations_v1 "
                "WHERE bot=? AND persona=? AND operation_id=?", (*self.namespace_id.as_tuple, original.operation_id)).fetchone()
            grant = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (owner_grant_key(*self.namespace_id.as_tuple).token,)).fetchone()
            if (original.namespace != self.namespace_id or original.kind not in {"transfer_execution", "control"}
                    or operation is None or operation[1] != original_ref
                    or operation[2:4] != (original.request_digest, original.kind)
                    or grant is None or grant[2] != 1 or grant[0] != original.owner_grant_revision
                    or digest(json.loads(grant[1])) != original.owner_grant_digest):
                raise AuthorityUnavailable("D12 source original or current grant differs")
            owner, intent, grant_value = json.loads(operation[0]), json.loads(operation[4]), json.loads(grant[1])
            if (owner["namespace"] != asdict(self.namespace_id)
                    or (owner["grant_ref"], owner["grant_revision"], owner["grant_digest"], owner["activation_generation"]) != (
                        original.owner_grant_ref, original.owner_grant_revision,
                        original.owner_grant_digest, original.activation_generation)):
                raise AuthorityUnavailable("D12 initiating operation identity differs")
            if original.kind == "transfer_execution":
                plan = db.execute("SELECT plan_digest,plan_json FROM graph_d12_lifecycle_plans_v1 WHERE "
                    "bot=? AND persona=? AND plan_ref=?", (*self.namespace_id.as_tuple, original.plan_ref)).fetchone()
                if (plan is None or plan[0] != original.plan_digest or digest(json.loads(plan[1])) != plan[0]
                        or intent["plan_ref"] != original.plan_ref
                        or intent["current_epochs"]["plan_digest"] != original.plan_digest
                        or "workbench.transfer" not in grant_value["capabilities"]):
                    raise AuthorityUnavailable("D12 original transfer plan/capability differs")
                plan_json = plan[1]
            else:
                from .d12_lifecycle_contract_v1 import D12InstallationControlIntentV1
                command = ControlCommandV1.from_wire(intent)
                lifecycle = D12InstallationControlIntentV1.from_command(command)
                if (lifecycle.installation_id != installation_id
                        or (command.object_ref, command.control) != (original.result.object_ref, original.result.control)
                        or not {"workbench.control", "workbench.maintain"}.issubset(grant_value["capabilities"])):
                    raise AuthorityUnavailable("whole-Host control requires current maintain/control capabilities")
                plan_json = canonical_serialize({"schema": "d12.registered_installation_control.v1",
                    "owner": owner, "input": intent, "intent": asdict(lifecycle)})
            return original, owner, plan_json, grant_value["principal"]
        finally:
            db.close()

    def install_control_status_reader_v1(self, reader):
        if (reader.installation_id in self._control_status_readers or reader.core is not self.core
                or reader.status_service is not self or not callable(getattr(reader, "read_status_original_in_tx_v1", None))):
            raise AuthorityUnavailable("lifecycle status reader installation differs")
        self._control_status_readers[reader.installation_id] = reader

    def install_owner_stop_reply_status_reader_v1(self, reader):
        from .owner_stop_reply_v1 import InstalledOwnerStopReplyServiceV1
        if (type(reader) is not InstalledOwnerStopReplyServiceV1
                or reader.core is not self.core or reader.status_service is not self
                or reader.namespace != self.namespace
                or reader.installation_id in self._stop_reply_status_readers):
            raise AuthorityUnavailable("reply stop status reader installation differs")
        self._stop_reply_status_readers[reader.installation_id] = reader

    def persist_derived_original_in_tx_v1(self, db, *, source_row, original):
        if db is not self.core._db or not db.in_transaction:
            raise AuthorityUnavailable("derived D12 original requires its existing Core transaction")
        source = decode_original(json.loads(source_row[3]))
        if ((original.namespace, original.operation_id, original.request_digest, original.owner_grant_digest) != (
                source.namespace, source.operation_id, source.request_digest, source.owner_grant_digest)):
            raise AuthorityUnavailable("derived D12 original changed initiating identity")
        result = self._readdress(original)
        values = (*source_row[:2], result.original_ref, canonical_serialize(asdict(result)), *source_row[4:])
        db.execute("INSERT OR IGNORE INTO authority_d12_operation_originals_v1 VALUES(?,?,?,?,?,?,?,?,?)", values)
        if db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE original_ref=?", (result.original_ref,)).fetchone() != values:
            raise AuthorityUnavailable("derived D12 original identity conflict")
        return result

    @staticmethod
    def _readdress(original):
        material = {field.name: getattr(original, field.name) for field in fields(original)}
        material["original_ref"] = "d12authority:" + digest({
            key: value for key, value in material.items()
            if key not in {"original_ref", "original_digest"}})[7:]
        material["original_digest"] = backend_original_digest_v1(material)
        return D12BackendOperationOriginalV1(**material)

    def register_current_operation_v1(self, *, credential, subject, permit,
                                      actor, session_token, session_request, original_ref):
        self.fences.validate_fence(credential=credential, subject=subject, permit=permit)
        target_owner = (self._target_owner_readers.get(session_request.installation_id)
            or getattr(self,"_storage_owner_readers",{}).get(session_request.installation_id))
        if target_owner is not None:
            current, _ = target_owner.get_current_owner_authority_for_fence_v1(
                credential=credential, subject=subject, permit=permit, actor=actor,
                session_token=session_token, session_request=session_request)
            guard = current.guard
        else:
            guard = self.tickets.get_current_guard(credential=credential,
                authority_namespace=self.namespace, installation_id=self.installation_id,
                subject=subject, permit=permit, owner_actor_id=actor,
                owner_session_token=session_token, owner_session_request=session_request)
        original, owner, plan_json, principal = self._read_source_original(original_ref, session_request.installation_id)
        if (principal != asdict(session_request.principal) or owner["actor"] != actor or original.activation_generation != permit.generation
                or owner["authority_ref"] != "owner-authority:" + guard.authorization_head):
            raise AuthorityUnavailable("D12 original initiating Owner differs")
        result = self._readdress(original)
        with self.core._tx() as db:
            self._current_session_in_tx(db, actor=actor, token=session_token,
                request=session_request, expected_head=guard.authorization_head)
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_c09_consumed_execution_v1'").fetchone() is not None and db.execute(
                    "SELECT 1 FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind='d12_source_original' AND item_id=?",
                    (self.namespace,original_ref)).fetchone() is not None:
                raise AuthorityUnavailable("original D12 operation was retired by storage rebase")
            row = AuthorityV2FenceStore._row(db, permit.operation_id)
            current = self.core._row(db, self.namespace)
            if (row is None or row[6] != "active" or AuthorityV2FenceStore._permit(row) != permit
                    or self.core._anchor(db, self.namespace, current) != permit.pinned_anchor
                    or current[2] != "active"):
                raise AuthorityUnavailable("D12 registration fence is no longer current")
            values = (self.namespace, result.operation_id, result.original_ref,
                canonical_serialize(asdict(result)), actor, _canonical(session_request),
                guard.authorization_head, plan_json, original_ref)
            db.execute("INSERT OR IGNORE INTO authority_d12_operation_originals_v1 VALUES(?,?,?,?,?,?,?,?,?)", values)
            if db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE original_ref=?",
                          (result.original_ref,)).fetchone() != values:
                raise AuthorityUnavailable("D12 exact operation registration conflict")
        return result

    def find_registered_current_operation_v1(self, *, credential, actor, session_token,
                                             session_request, original_ref):
        self.core._require(credential, "d12_operation_status", self.namespace)
        with self.core._tx() as db:
            row = db.execute("SELECT original_ref,owner_head,actor,session_request_json FROM "
                "authority_d12_operation_originals_v1 WHERE authority_namespace=? "
                "AND source_original_ref=? ORDER BY rowid LIMIT 1",
                (self.namespace, original_ref)).fetchone()
            if row is None:
                # Absence is visible only while ordinary current signed Owner
                # authentication is valid. It grants no post-freeze registration.
                self.sessions.require_current_in_tx(db, token=session_token, request=session_request)
                guard = self.tickets._checked_current_head(db, self.namespace)
                if guard is None:
                    raise AuthorityUnavailable("current D12 initiating Owner unavailable")
                self._current_session_in_tx(db, actor=actor, token=session_token,
                    request=session_request, expected_head=guard.authorization_head)
                return None
            full = db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE original_ref=?", (row[0],)).fetchone()
            return self._authenticate_original_row_in_tx(db, full, actor=actor,
                token=session_token, request=session_request)

    def read_current_operation_original_v1(self, *, credential, actor, session_token,
                                           session_request, original_ref, refresh=False):
        if refresh:
            self.core._require(credential,"d12_operation_status",self.namespace)
            with self.core._tx()as db:
                row=db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE "
                    "authority_namespace=? AND original_ref=?",(self.namespace,original_ref)).fetchone()
                if row is None:raise AuthorityUnavailable("exact D12 operation is not owned by this session")
                original=self._authenticate_original_row_in_tx(db,row,actor=actor,
                    token=session_token,request=session_request)
                stop=(original.kind=="control"and json.loads(row[7]).get("schema")=="d12.registered_owner_stop_reply.v1")
            if stop:
                reader=self._stop_reply_status_readers.get(session_request.installation_id)
                if reader is None:raise AuthorityUnavailable("reply stop status reader is unavailable")
                with reader.prepare_owner_stop_status_metadata_v1(credential=credential,actor=actor,
                        session_token=session_token,session_request=session_request,original_ref=original_ref):
                    return self._read_current_operation_original_with_prepared_metadata_v1(
                        credential=credential,actor=actor,session_token=session_token,
                        session_request=session_request,original_ref=original_ref,refresh=True)
        return self._read_current_operation_original_with_prepared_metadata_v1(
            credential=credential,actor=actor,session_token=session_token,
            session_request=session_request,original_ref=original_ref,refresh=refresh)

    def _read_current_operation_original_with_prepared_metadata_v1(self, *, credential, actor, session_token,
                                           session_request, original_ref, refresh=False):
        self.core._require(credential, "d12_operation_status", self.namespace)
        # A status read holds the same frozen current heads as migration. It
        # never opens source/target content or permits a new transfer identity.
        with self.fences._frozen() as (db, deletion, execution, history):
            row = db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE "
                "authority_namespace=? AND original_ref=?", (self.namespace, original_ref)).fetchone()
            if row is None:
                raise AuthorityUnavailable("exact D12 operation is not owned by this session")
            original = self._authenticate_original_row_in_tx(db, row, actor=actor,
                token=session_token, request=session_request)
            if refresh and original.kind == "control":
                plan = json.loads(row[7])
                if plan.get("schema") == "d12.registered_owner_stop_reply.v1":
                    reader = self._stop_reply_status_readers.get(session_request.installation_id)
                    if reader is None:
                        raise AuthorityUnavailable("reply stop status reader is unavailable")
                    projected = reader.read_status_original_in_tx_v1(db, source_row=row, original=original)
                    return self.persist_derived_original_in_tx_v1(db, source_row=row, original=projected)
                reader=self._control_status_readers.get(original.result.object_ref.removeprefix("installation:"))
                if reader is not None:
                    projected = reader.read_status_original_in_tx_v1(db, original=original)
                    return self.persist_derived_original_in_tx_v1(db, source_row=row, original=projected)
            if not refresh or original.kind != "transfer_execution" or self.migration is None:
                return original
            status = self.migration.store.status_locked(db, original.result.transfer_id)
            if status is None:
                return original
            if asdict(status.plan) != json.loads(row[7])["migration_plan"]:
                raise AuthorityUnavailable("D12 migration original plan differs")
            current = self.migration._current_namespace_locked(db, deletion, execution, history)
            active = (status.phase == "activated" and current.phase == "active"
                and current.holder == status.plan.target_holder and current.anchor == status.current_anchor)
            payload = D12TransferExecutionPayloadV1(status.plan.transfer_id, status.phase,
                self.namespace, digest(status.current_anchor), original.result.target_lease_digest,
                status.phase != "begun", active)
            material = {field.name: getattr(original, field.name) for field in fields(original)}
            material.update(result=payload, result_digest=digest(payload),
                state="completed" if active else "running",
                authority_refs=(*material["authority_refs"][:1], *(
                    ("migration_stage", receipt.request_id, digest(receipt)) for receipt in status.receipts)),
                coverage=("exact_original_operation", "current_owner_identity", "independent_authority_heads",
                          *(("current_unique_target_activation",) if active else ())))
            material["original_digest"] = backend_original_digest_v1(material)
            result = self._readdress(D12BackendOperationOriginalV1(**material))
            values = (*row[:2], result.original_ref, canonical_serialize(asdict(result)), *row[4:])
            db.execute("INSERT OR IGNORE INTO authority_d12_operation_originals_v1 VALUES(?,?,?,?,?,?,?,?,?)", values)
            return result


__all__ = ("InstalledD12OperationStatusServiceV1",)
