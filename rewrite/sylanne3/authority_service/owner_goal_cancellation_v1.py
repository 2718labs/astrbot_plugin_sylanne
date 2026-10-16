"""Actual same-Core user Goal stop requests and fixed metadata barrier producer."""
from contextlib import closing
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
import sqlite3
from threading import get_ident
from weakref import WeakSet
from .contract import AuthorityUnavailable
from .owner_goal_cancellation_contract_v1 import (
    GOAL_CANCEL_SIGN_KIND_V1, GOAL_CANCEL_TABLE_V1, GOAL_CANCEL_COLUMNS_V1, GOAL_CANCEL_DDL_V1,
    OwnerGoalCancellationRequestV1, OwnerGoalCancellationOriginalV1,
    GoalCancellationMetadataV1, owner_goal_cancellation_from_wire_v1)
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import (
    bind_runtime_database_from_control_v3, runtime_storage_v3, begin_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3, bind_runtime_storage_operation_v3)
from .v2_owner_session import _verifier

_INVOCATION_ISSUER_V1 = object()
_GOAL_MANAGEMENT_INVOCATIONS_V1 = WeakSet()


@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True)
class GoalManagementInvocationV1:
    service: object
    owner_service: object
    status_service: object
    core: object
    fences: object
    control: object
    issuer: object
    bundle: object
    credential: object
    subject: str
    actor: str
    session_token: str
    session_request: object
    principal: object
    current_owner_guard: object
    current_owner_head: object
    original_request: object
    request_digest: str
    namespace: object
    authority_namespace: str
    installation_id: str
    manifest_digest: str
    holder: str
    current_anchor: object
    active_originals_commitment: str
    storage_context: object
    selected_graph_member: object
    selection_digest: str
    actual_db: object
    retained_operation: object
    registered_deadline_utc: float
    registered_deadline_text: str
    metadata_operation_id: str
    thread_id: int
    _issuer: object

    def __post_init__(self):
        if self._issuer is not _INVOCATION_ISSUER_V1:
            raise AuthorityUnavailable("actual authenticated Goal management call issuer required")
        _GOAL_MANAGEMENT_INVOCATIONS_V1.add(self)
        self.retained_operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        import sys
        from ..runtime.artifact_no_dispatch_metadata_invocation_v1 import _actual_metadata_heap_v1
        seen={id(self)}
        amount=sys.getsizeof(self)
        for name in ("subject","actor","session_token","session_request","principal","current_owner_guard",
                "current_owner_head","original_request","request_digest","namespace","authority_namespace",
                "installation_id","manifest_digest","holder","current_anchor","active_originals_commitment",
                "selected_graph_member","selection_digest","registered_deadline_utc","registered_deadline_text",
                "metadata_operation_id","thread_id"):
            amount+=_actual_metadata_heap_v1(getattr(self,name),seen)
        return amount

    @property
    def graph_path(self):
        return self.selected_graph_member["resolved_path"]

    @property
    def original_permit(self):
        return None

    @property
    def scope(self):
        return None

    @property
    def kind(self):
        return "goal_management_metadata"

    @property
    def operation_id(self):
        return self.original_request.cancel_operation_id

    def require_current_v1(self, *, phase, graph_stamp=None):
        from threading import get_ident
        from ..runtime_storage_v3 import RuntimeStorageOperationV3, runtime_storage_v3
        if (self not in _GOAL_MANAGEMENT_INVOCATIONS_V1 or self._issuer is not _INVOCATION_ISSUER_V1
                or type(self.service) is not InstalledOwnerGoalCancellationServiceV1
                or self.service.owner_service is not self.owner_service
                or self.service.status_service is not self.status_service
                or self.service.core is not self.core or self.service.fences is not self.fences
                or self.service.control is not self.control or self.service.issuer is not self.issuer
                or self.service.bundle is not self.bundle or phase not in {"before","after"}
                or self.thread_id != get_ident() or type(self.original_request) is not OwnerGoalCancellationRequestV1
                or self.request_digest != self.original_request.digest
                or self.principal != self.session_request.principal
                or self.namespace != self.original_request.namespace
                or (self.installation_id,self.authority_namespace) !=
                    (self.original_request.installation_id,self.original_request.authority_namespace)
                or type(self.retained_operation) is not RuntimeStorageOperationV3 or self.retained_operation.closed
                or self.retained_operation.operation_id != self.metadata_operation_id
                or self.retained_operation.deadline_utc != self.registered_deadline_utc
                or runtime_storage_v3(self.actual_db).selection_digest != self.selection_digest):
            raise AuthorityUnavailable("Goal management invocation left its actual registered call/operation")
        if self.actual_db.in_transaction:
            if graph_stamp is not None:
                self.service.require_current_goal_metadata_stamp_v1(self, graph_stamp)
            return self
        self.storage_context.require_current("business")
        self.core._require(self.credential, "d12_operation_status", self.authority_namespace)
        with self.fences._frozen() as (db, deletion, execution, _):
            guard = self.owner_service._auth(db, actor=self.actor, session_token=self.session_token,
                session_request=self.session_request)
            anchor = self.fences._current_locked(db, deletion, execution, holder=self.holder,
                require_clear=False, require_no_pending=False)
            head = self.status_service.tickets.current_migration_head_in_tx(db, authority_namespace=self.authority_namespace)
            active = self.service._active_originals_commitment_v1(db)
            if (guard != self.current_owner_guard or head != self.current_owner_head
                    or anchor != self.current_anchor or active != self.active_originals_commitment):
                raise AuthorityUnavailable("Goal management current Owner/anchor/active originals changed")
            from .v2_owner_session import _verifier
            row = db.execute("SELECT expires_at_utc FROM authority_owner_sessions_v1 WHERE verifier=?",
                (_verifier(self.session_token),)).fetchone()
            if row != (self.registered_deadline_text,) or self.status_service.sessions._now().timestamp() >= self.registered_deadline_utc:
                raise AuthorityUnavailable("Goal management original registered session deadline expired/changed")
        if graph_stamp is not None:
            self.service.require_current_goal_metadata_stamp_v1(self, graph_stamp)
        return self

    def release_v1(self):
        self.retained_operation.unregister_retained_state_v3(self)
        _GOAL_MANAGEMENT_INVOCATIONS_V1.discard(self)


def require_goal_management_invocation_v1(invocation, *, phase, graph_stamp=None):
    if type(invocation) is not GoalManagementInvocationV1:
        raise AuthorityUnavailable("actual live private Goal management invocation required")
    return invocation.require_current_v1(phase=phase, graph_stamp=graph_stamp)


class InstalledOwnerGoalCancellationServiceV1:
    def __init__(self, *, owner_service, bundle):
        from .owner_stop_reply_v1 import InstalledOwnerStopReplyServiceV1
        from ..host.authority_profile import AdminInstallationBundle
        if (type(owner_service) is not InstalledOwnerStopReplyServiceV1 or type(bundle) is not AdminInstallationBundle
                or owner_service.namespace_id != bundle.installation_policy.namespace
                or owner_service.namespace != bundle.installation_policy.authority_namespace
                or owner_service.installation_id != bundle.installation_policy.installation_id):
            raise AuthorityUnavailable("Goal management needs its actual installed Owner/D12/Core/bundle")
        self.owner_service, self.bundle = owner_service, bundle
        self.status_service, self.core, self.fences = owner_service.status_service, owner_service.core, owner_service.fences
        self.control, self.issuer = owner_service.control, owner_service.issuer
        self.namespace, self.namespace_id, self.installation_id = owner_service.namespace, owner_service.namespace_id, owner_service.installation_id
        self.holder = bundle.installation_policy.administrator_holder
        self.manifest_digest = bundle.installation_policy.manifest_digest
        with self.core._tx() as db:
            row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (GOAL_CANCEL_TABLE_V1,)).fetchone()
            if row is None: db.execute(GOAL_CANCEL_DDL_V1)
            elif row != (GOAL_CANCEL_DDL_V1,): raise AuthorityUnavailable("Goal cancellation Core schema differs")

    def _active_originals_commitment_v1(self, db):
        rows = tuple(db.execute("SELECT operation_id,namespace,subject,token,fence_epoch,revision,state,"
            "finish_request_id,finish_request_digest,pending IS NOT NULL FROM authority_v2_fences "
            "WHERE namespace=? AND state='active' ORDER BY operation_id", (self.namespace,)))
        if len(rows) > 1: raise AuthorityUnavailable("actual namespace active fence set differs from its unique-index contract")
        return canonical_digest(rows)

    def _require_peer_v1(self, credential, subject):
        from .mtls_server import MtlsPeerCredential
        if type(credential) is not MtlsPeerCredential or subject != "mtls:sha256:" + credential.certificate_sha256:
            raise AuthorityUnavailable("Goal management requires its actual original mTLS credential/subject")
        self.core._require(credential, "d12_operation_status", self.namespace)

    def _read_original_in_tx_v1(self, db, *, operation_id):
        row = db.execute("SELECT original_json,original_digest,signature FROM " + GOAL_CANCEL_TABLE_V1 +
            " WHERE authority_namespace=? AND installation_id=? AND cancel_operation_id=?",
            (self.namespace,self.installation_id,operation_id)).fetchone()
        if row is None: return None
        raw = json.loads(row[0])
        original = owner_goal_cancellation_from_wire_v1(raw, OwnerGoalCancellationOriginalV1)
        original.require_signature_v1(self.issuer)
        if (canonical_serialize(raw),original.digest,original.signature) != row:
            raise AuthorityUnavailable("actual signed Goal cancellation Core original changed")
        return original

    def begin_invocation_v1(self, *, credential, subject, actor, session_token, session_request, request):
        self._require_peer_v1(credential, subject)
        if type(request) is not OwnerGoalCancellationRequestV1 or (
                request.namespace,request.authority_namespace,request.installation_id) != (
                self.namespace_id,self.namespace,self.installation_id):
            raise AuthorityUnavailable("Goal management request crossed its actual installation")
        with self.fences._frozen() as (db,deletion,execution,_):
            guard = self.owner_service._auth(db, actor=actor, session_token=session_token, session_request=session_request)
            head = self.status_service.tickets.current_migration_head_in_tx(db, authority_namespace=self.namespace)
            anchor = self.fences._current_locked(db,deletion,execution,holder=self.holder,
                require_clear=False,require_no_pending=False)
            active = self._active_originals_commitment_v1(db)
            session = db.execute("SELECT expires_at_utc FROM authority_owner_sessions_v1 WHERE verifier=?",
                (_verifier(session_token),)).fetchone()
            if head is None or head.state != "active" or head.guard != guard or session is None:
                raise AuthorityUnavailable("actual live signed Owner/session metadata is missing")
        context, storage, graph_member = self.owner_service._storage()
        context.require_current("business")
        db = sqlite3.connect(Path(storage["graph_path"]).as_uri()+"?mode=ro",uri=True,isolation_level=None)
        operation = None
        invocation = None
        try:
            db.execute("PRAGMA query_only=ON")
            handle = bind_runtime_database_from_control_v3(db,control=self.control,role="graph")
            if handle is None: raise AuthorityUnavailable("Goal management needs its actual installed bounded metadata role")
            from ..runtime.d11_offline_originals_v1 import _utc
            deadline = _utc(session[0]).timestamp()
            operation_id = request.cancel_operation_id + ":metadata"
            operation = begin_runtime_storage_operation_v3(db,operation_id,deadline)
            invocation = GoalManagementInvocationV1(self,self.owner_service,self.status_service,self.core,
                self.fences,self.control,self.issuer,self.bundle,credential,subject,actor,session_token,session_request,
                session_request.principal,guard,head,request,request.digest,self.namespace_id,self.namespace,
                self.installation_id,self.manifest_digest,self.holder,anchor,active,context,graph_member,
                handle.selection_digest,db,operation,deadline,session[0],operation_id,get_ident(),_INVOCATION_ISSUER_V1)
            invocation.require_current_v1(phase="before")
            return invocation
        except BaseException:
            if invocation is not None: invocation.release_v1()
            if operation is not None: finish_runtime_storage_operation_v3(operation)
            db.close()
            raise

    def require_current_goal_metadata_stamp_v1(self, invocation, graph_stamp):
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .goal_projection_metadata_invocation_v1 import GoalProjectionMetadataInvocationV1,require_goal_projection_metadata_invocation_v1
        if type(invocation) is GoalManagementInvocationV1:
            require_goal_management_invocation_v1(invocation,phase="before")
        elif type(invocation) is GoalProjectionMetadataInvocationV1:
            require_goal_projection_metadata_invocation_v1(invocation,phase="before")
        else:
            raise AuthorityUnavailable("actual private Goal metadata invocation required")
        if invocation.service is not self:raise AuthorityUnavailable("Goal metadata belongs to another installed service")
        db = invocation.actual_db
        if not db.in_transaction: return invocation
        meter = current_c09_sql_meter_v2()
        metadata, epoch = graph_stamp
        revision = _runtime_bounded_fixed_row_v3(db,meter,"graph_recovery_metadata_v2",("graph_revision",),
            "bot=? AND persona=?",self.namespace_id.as_tuple)
        actual_epoch = _runtime_bounded_fixed_row_v3(db,meter,"graph_epochs",("revision",),
            "bot=? AND persona=?",self.namespace_id.as_tuple)
        if revision != (metadata.graph_revision,) or actual_epoch != (epoch.revision,):
            raise AuthorityUnavailable("Goal management same-SQL graph metadata stamp changed")
        runtime_storage_v3(db).require_current(meter)
        return invocation

    def close_invocation_v1(self, invocation, *, work=None, proof=None):
        if type(invocation) is not GoalManagementInvocationV1 or invocation.service is not self:
            raise AuthorityUnavailable("actual Goal management call cleanup required")
        try:
            if work is not None: work.close_v3()
        finally:
            try:
                if proof is not None: proof.release_v3()
            finally:
                invocation.release_v1()
                finish_runtime_storage_operation_v3(invocation.retained_operation)
                invocation.actual_db.close()

    def _observe_metadata_v1(self, invocation):
        from .owner_location_read_v3 import (create_goal_management_owner_caller_proof_v3,
            prepare_owner_location_read_work_v3, owner_location_read_quantum_v3)
        from .goal_cancellation_metadata_read_v1 import GoalCancellationMetadataReadWorkV1
        proof = None
        owner_work = None
        goal_work = None
        try:
            proof = create_goal_management_owner_caller_proof_v3(invocation)
            owner_work = prepare_owner_location_read_work_v3(proof)
            while True:
                with owner_location_read_quantum_v3(proof) as meter:
                    result = owner_work.advance(meter=meter)
                if type(result) is dict and result.get("phase") == "owner_location_quantum_commit":
                    result = owner_work.complete_reserved_quantum_v3(proof)
                if type(result) is not dict: break
            facts = result.require_for_v3(proof)
            goal_work = GoalCancellationMetadataReadWorkV1(invocation,owner_proof=proof,owner_work=owner_work,owner_facts=facts)
            while not goal_work.complete:
                with owner_location_read_quantum_v3(proof) as meter:
                    with bind_runtime_storage_operation_v3(invocation.retained_operation,invocation.actual_db):
                        invocation.actual_db.execute("BEGIN")
                        try:
                            goal_work.advance_v1(meter)
                        finally:
                            invocation.actual_db.rollback()
                goal_work.complete_quantum_v1()
            invocation.require_current_v1(phase="after")
            return goal_work.require_result_v1(), goal_work.require_owner_grant_v1()
        finally:
            if goal_work is not None: goal_work.close_v1()
            self.close_invocation_v1(invocation,work=owner_work,proof=proof)

    def submit_v1(self, *, credential, subject, actor, session_token, session_request, request):
        self._require_peer_v1(credential, subject)
        if type(request) is not OwnerGoalCancellationRequestV1:
            raise AuthorityUnavailable("actual typed Goal cancellation request required")
        with self.core._tx() as db:
            self.owner_service._auth(db,actor=actor,session_token=session_token,session_request=session_request)
            prior = self._read_original_in_tx_v1(db,operation_id=request.cancel_operation_id)
            if prior is not None:
                if prior.request != request: raise AuthorityUnavailable("Goal cancellation UUID reused with another request")
                return prior
        invocation = self.begin_invocation_v1(credential=credential,subject=subject,actor=actor,
            session_token=session_token,session_request=session_request,request=request)
        observed, grant = self._observe_metadata_v1(invocation)
        # Accept only the observed version. This second qualified observation does
        # not claim atomicity between the independent Graph and Core databases.
        repeated = self.begin_invocation_v1(credential=credential,subject=subject,actor=actor,
            session_token=session_token,session_request=session_request,request=request)
        current, current_grant = self._observe_metadata_v1(repeated)
        if current != observed or current_grant != grant:
            raise AuthorityUnavailable("Goal/Owner metadata changed before actual cancellation acceptance")
        with self.fences._frozen() as (db,deletion,execution,_):
            guard = self.owner_service._auth(db,actor=actor,session_token=session_token,session_request=session_request)
            anchor = self.fences._current_locked(db,deletion,execution,holder=self.holder,
                require_clear=False,require_no_pending=False)
            head = self.status_service.tickets.current_migration_head_in_tx(db,authority_namespace=self.namespace)
            if guard != invocation.current_owner_guard or head != invocation.current_owner_head or (
                    anchor,self._active_originals_commitment_v1(db)) != (
                    invocation.current_anchor,invocation.active_originals_commitment):
                raise AuthorityUnavailable("Goal management current Owner/active originals changed at acceptance")
            observed.require_request_v1(request)
            old = self._read_original_in_tx_v1(db,operation_id=request.cancel_operation_id)
            if old is not None:
                if old.request != request: raise AuthorityUnavailable("Goal cancellation UUID conflict")
                return old
            session = db.execute("SELECT principal_epoch,boot_id FROM authority_owner_sessions_v1 WHERE verifier=?",
                (_verifier(session_token),)).fetchone()
            from .v2_owner_session import _canonical
            unsigned = dict(request=asdict(request),metadata=asdict(observed),authority_id=anchor.authority_id,
                actor_id=actor,principal_json=canonical_serialize(asdict(session_request.principal)),
                credential_id=session_request.credential_id,credential_epoch=session_request.credential_epoch,
                session_request_digest=canonical_digest(asdict(session_request)),
                session_request_json=canonical_serialize(asdict(session_request)),
                session_principal_epoch=session[0],session_boot_id=session[1],owner_guard=asdict(guard),
                owner_grant_ref=grant[0],owner_grant_revision=grant[1],owner_grant_digest=grant[2],
                metadata_operation_id=invocation.metadata_operation_id,metadata_deadline_utc=invocation.registered_deadline_text,
                anchor=asdict(anchor),active_originals_commitment=invocation.active_originals_commitment,
                storage_pointer_version=invocation.storage_context.pointer_version,
                storage_manifest_digest=invocation.storage_context.manifest_digest,
                storage_generation=invocation.storage_context.storage_generation,
                source_graph_incarnation=invocation.selected_graph_member["incarnation_or_journal_id"],
                cancel_scope="artifact_task_goal",state="cancel_requested",original_ref="owner-goal-cancellation:"+canonical_digest((
                    request.namespace,request.installation_id,request.cancel_operation_id)),
                schema="d08.owner-goal-cancellation-original.v1")
            signature = self.issuer._signer.sign(GOAL_CANCEL_SIGN_KIND_V1,canonical_serialize(unsigned))
            original = owner_goal_cancellation_from_wire_v1({**unsigned,"signature":signature},OwnerGoalCancellationOriginalV1)
            db.execute("INSERT INTO "+GOAL_CANCEL_TABLE_V1+"("+",".join(GOAL_CANCEL_COLUMNS_V1)+") VALUES(?,?,?,?,?,?,?,?,?)",
                (self.namespace,self.installation_id,request.cancel_operation_id,request.goal_ref,
                 request.root_registration_ref,request.digest,canonical_serialize(asdict(original)),original.digest,original.signature))
            return original

    def read_status_v1(self, *, credential, subject, actor, session_token, session_request, operation_id):
        self._require_peer_v1(credential,subject)
        with self.core._tx() as db:
            guard=self.owner_service._auth(db,actor=actor,session_token=session_token,session_request=session_request)
            original=self._read_original_in_tx_v1(db,operation_id=operation_id)
            if (original is None or original.actor_id!=actor
                    or original.principal_json!=canonical_serialize(asdict(session_request.principal))
                    or original.owner_guard.authorization_head!=guard.authorization_head):
                raise AuthorityUnavailable("Goal cancellation original lacks the actual current initiating Owner")
            return original

    def _current_projection_owner_in_tx_v1(self,db,original):
        from .v2_owner_session import from_wire
        if db is not self.core._db or not db.in_transaction:
            raise AuthorityUnavailable("Goal projection requires its actual same-Core current Owner")
        original.require_signature_v1(self.issuer)
        session=from_wire({"kind":"owner_session_login_request_v1",**json.loads(original.session_request_json)})
        self.status_service.sessions._current_key(db,session)
        source=self.status_service.sessions._current_pairing_source
        if source is None:raise AuthorityUnavailable("actual current Goal projection Owner pairing absent")
        source.require_current_actor_in_tx(db,authority_namespace=self.namespace,installation_id=self.installation_id,
            actor_id=original.actor_id,principal=session.principal)
        head=self.status_service.tickets.current_migration_head_in_tx(db,authority_namespace=self.namespace)
        guard=self.status_service.tickets._checked_current_head(db,self.namespace)
        if (head is None or guard is None or head.guard!=guard or guard.pending_revoke_operation_id is not None
                or guard.minimum_revocation_revision or guard.minimum_revocation_epoch
                or head.issue_operation.principal!=session.principal):
            raise AuthorityUnavailable("actual current Goal projection Owner/key/authorization is unavailable")
        return session,head

    def require_projection_metadata_permission_v1(self,invocation):
        from .goal_projection_metadata_invocation_v1 import GoalProjectionMetadataInvocationV1
        if type(invocation) is not GoalProjectionMetadataInvocationV1 or invocation.service is not self:
            raise AuthorityUnavailable("actual installed Goal projection call required")
        self._require_peer_v1(invocation.credential,invocation.subject)
        permit=invocation.original_permit
        self.fences._require_permit(credential=invocation.credential,subject=invocation.subject,permit=permit)
        self.fences.validate_fence(credential=invocation.credential,subject=invocation.subject,permit=permit)
        with self.fences._frozen() as (db,deletion,execution,_):
            original=self._read_original_in_tx_v1(db,operation_id=invocation.original.request.cancel_operation_id)
            if original!=invocation.original:raise AuthorityUnavailable("cold Goal cancellation cause changed")
            from .owner_goal_projection_contract_v1 import require_goal_projection_operation_v1
            if require_goal_projection_operation_v1(original,permit)!=invocation.scope_kind:
                raise AuthorityUnavailable("Goal metadata call changed its fixed projection/lookup identity")
            from .owner_goal_projection_contract_v1 import require_goal_projection_operation_v1
            require_goal_projection_operation_v1(original,permit)
            session,head=self._current_projection_owner_in_tx_v1(db,original)
            anchor=self.fences._current_locked(db,deletion,execution,holder=permit.holder,generation=permit.generation)
            self.fences.fences.validate_fence_locked(db,permit,subject=invocation.subject,current_anchor=anchor)
            if (session!=invocation.session_request or head!=invocation.current_owner_head
                    or anchor!=invocation.current_anchor
                    or self._active_originals_commitment_v1(db)!=invocation.active_originals_commitment):
                raise AuthorityUnavailable("Goal projection current key/Owner/WRITE/current originals changed")
        self.control.verify_member_v1(invocation.selected_graph_member,prepared=False)

    def begin_projection_metadata_invocation_v1(self,*,credential,subject,permit,cancel_operation_id,original_ref):
        from .v2_contract import FencePermitV2
        from .goal_projection_metadata_invocation_v1 import issue_goal_projection_metadata_invocation_v1,_ISSUER
        if type(permit) is not FencePermitV2 or permit.operation not in {"read","write"}:
            raise AuthorityUnavailable("actual independent Goal metadata WRITE permit required")
        self._require_peer_v1(credential,subject)
        self.fences._require_permit(credential=credential,subject=subject,permit=permit)
        self.fences.validate_fence(credential=credential,subject=subject,permit=permit)
        with self.fences._frozen() as (db,deletion,execution,_):
            original=self._read_original_in_tx_v1(db,operation_id=cancel_operation_id)
            if original is None or original.original_ref!=original_ref or original.state!="cancel_requested":
                raise AuthorityUnavailable("actual immutable Goal cancel cause is absent")
            session,head=self._current_projection_owner_in_tx_v1(db,original)
            anchor=self.fences._current_locked(db,deletion,execution,holder=permit.holder,generation=permit.generation)
            self.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
            active=self._active_originals_commitment_v1(db)
        context,storage,member=self.owner_service._storage()
        context.require_current("business");self.control.verify_member_v1(member,prepared=False)
        # This is the new metadata WRITE's actual operation registration. It
        # carries no execution TTL and never changes the original C4 deadline.
        db=sqlite3.connect(Path(storage["graph_path"]).as_uri()+"?mode=ro",uri=True)
        db.execute("PRAGMA query_only=ON")
        bind_runtime_database_from_control_v3(db,context,role="graph")
        operation=begin_runtime_storage_operation_v3(db,permit.operation_id,None)
        invocation=issue_goal_projection_metadata_invocation_v1(_ISSUER,service=self,original=original,
            credential=credential,subject=subject,original_permit=permit,session_request=session,
            principal=session.principal,current_owner_guard=head.guard,current_owner_head=head,current_anchor=anchor,
            active_originals_commitment=active,storage_context=context,selected_graph_member=member,
            selection_digest=runtime_storage_v3(db).selection_digest,actual_db=db,retained_operation=operation,
            thread_id=get_ident())
        try:invocation.require_current_v1(phase="before");return invocation
        except BaseException:
            invocation.release_v1();finish_runtime_storage_operation_v3(operation);db.close();raise

    def observe_projection_metadata_v1(self,*,credential,subject,permit,cancel_operation_id,original_ref):
        from .owner_goal_projection_contract_v1 import SIGN_KIND,goal_projection_from_wire_v1
        from .v2_contract import to_wire as fence_to_wire
        from .v2_owner_contract import to_wire as owner_to_wire
        from .owner_location_read_v3 import (create_goal_projection_owner_caller_proof_v3,
            prepare_owner_location_read_work_v3,owner_location_read_quantum_v3)
        from .goal_cancellation_metadata_read_v1 import GoalCancellationMetadataReadWorkV1
        invocation=self.begin_projection_metadata_invocation_v1(credential=credential,subject=subject,permit=permit,
            cancel_operation_id=cancel_operation_id,original_ref=original_ref)
        proof=owner_work=goal_work=receipt_work=None
        committed_bridge=None
        try:
            proof=create_goal_projection_owner_caller_proof_v3(invocation)
            owner_work=prepare_owner_location_read_work_v3(proof)
            while True:
                with owner_location_read_quantum_v3(proof) as meter:progress=owner_work.advance(meter=meter)
                if type(progress) is dict and progress.get("phase")=="owner_location_quantum_commit":
                    progress=owner_work.complete_reserved_quantum_v3(proof)
                if type(progress) is not dict:break
            facts=progress.require_for_v3(proof)
            original=invocation.original
            if invocation.scope_kind=="projection_lookup":
                from .owner_location_read_v3 import _owner_wire_digest_v3
                from ..graph_types import owner_grant_key
                head=invocation.current_owner_head;grant_value=json.loads(facts.atom[1])
                if (facts.atom[0:3:2]!=(1,1) or _owner_wire_digest_v3(grant_value)!=head.grant_digest
                        or grant_value["principal"]!=asdict(invocation.principal)
                        or grant_value["principal"]!=asdict(head.issue_operation.principal)
                        or "workbench.control" not in grant_value["capabilities"]
                        or "workbench_user_action" not in grant_value["purposes"]
                        or "owner" not in grant_value["audiences"]
                        or json.loads(facts.proof_row[8])!=asdict(head.issue_proof)):
                    raise AuthorityUnavailable("Goal lookup lacks actual current management Owner grant/issue EOF")
                metadata=original.metadata
                grant=(owner_grant_key(*invocation.namespace.as_tuple).token,1,head.grant_digest.removeprefix("sha256:"))
                invocation.require_current_v1(phase="after")
            else:
                goal_work=GoalCancellationMetadataReadWorkV1(invocation,owner_proof=proof,owner_work=owner_work,owner_facts=facts)
                while not goal_work.complete:
                    with owner_location_read_quantum_v3(proof) as meter:
                        with bind_runtime_storage_operation_v3(invocation.retained_operation,invocation.actual_db):
                            invocation.actual_db.execute("BEGIN")
                            try:goal_work.advance_v1(meter)
                            finally:invocation.actual_db.rollback()
                    goal_work.complete_quantum_v1()
                invocation.require_current_v1(phase="after")
                metadata=goal_work.require_result_v1()
                original=invocation.original
                if (metadata.goal_ref,metadata.goal_atom_revision,metadata.goal_semantic_revision,
                        metadata.goal_payload_digest,metadata.goal_producing_digest,metadata.root_registration_digest)!=(
                        original.metadata.goal_ref,original.metadata.goal_atom_revision,original.metadata.goal_semantic_revision,
                        original.metadata.goal_payload_digest,original.metadata.goal_producing_digest,original.metadata.root_registration_digest):
                    raise AuthorityUnavailable("cold Goal metadata changed after its accepted cancellation cause")
                grant=goal_work.require_owner_grant_v1()
            if invocation.scope_kind=="projection_write":
                from ..runtime.owner_goal_projection_receipt_read_v1 import GoalProjectionReceiptReadWorkV1
                from .owner_goal_projection_contract_v1 import GoalProjectionCommittedBridgeV1
                from .goal_projection_metadata_invocation_v1 import issue_goal_projection_committed_bridge_v1
                receipt_work=GoalProjectionReceiptReadWorkV1.from_actual_core_projection_v1(
                    invocation,owner_proof=proof,owner_facts=facts)
                while not receipt_work.complete:
                    with owner_location_read_quantum_v3(proof) as meter:
                        with bind_runtime_storage_operation_v3(invocation.retained_operation,invocation.actual_db):
                            invocation.actual_db.execute("BEGIN")
                            try:receipt_work.advance(meter)
                            finally:invocation.actual_db.rollback()
                if type(receipt_work.result) is GoalProjectionCommittedBridgeV1:
                    committed_bridge=issue_goal_projection_committed_bridge_v1(invocation,receipt_work)
            unsigned=dict(scope_kind=invocation.scope_kind,committed_bridge=None if committed_bridge is None else asdict(committed_bridge),
                original=asdict(original),metadata=asdict(metadata),
                permit=fence_to_wire(permit),
                owner_head=owner_to_wire(invocation.current_owner_head),
                owner_grant_ref=grant[0],owner_grant_revision=grant[1],owner_grant_digest=grant[2],
                current_anchor=asdict(invocation.current_anchor),storage_manifest_digest=invocation.storage_context.manifest_digest,
                storage_pointer_version=invocation.storage_context.pointer_version,
                storage_generation=invocation.storage_context.storage_generation,
                graph_incarnation=invocation.selected_graph_member["incarnation_or_journal_id"],
                registered_deadline_utc=invocation.retained_operation.deadline_utc,schema="d08.owner-goal-projection-observed.v1")
            signature=self.issuer._signer.sign(SIGN_KIND,canonical_serialize(unsigned))
            return goal_projection_from_wire_v1({**unsigned,"signature":signature})
        finally:
            try:
                if receipt_work is not None:receipt_work.close_v1()
                if goal_work is not None:goal_work.close_v1()
                if owner_work is not None:owner_work.close_v3()
            finally:
                try:
                    if proof is not None:proof.release_v3()
                finally:
                    invocation.release_v1();finish_runtime_storage_operation_v3(invocation.retained_operation)
                    invocation.actual_db.close()

    def read_next_projection_cause_v1(self,*,credential,subject,after_cancel_operation_id):
        self._require_peer_v1(credential,subject)
        from uuid import uuid4
        operation=begin_runtime_storage_operation_v3(self.core._db,str(uuid4()),None)
        try:
            from ..runtime_storage_v3 import runtime_storage_quantum_v3
            with bind_runtime_storage_operation_v3(operation,self.core._db):
                with runtime_storage_quantum_v3(self.core._db):
                    with self.core._tx() as db:
                        row=db.execute("SELECT "+",".join(GOAL_CANCEL_COLUMNS_V1)+" FROM "+GOAL_CANCEL_TABLE_V1+
                            " WHERE authority_namespace=? AND installation_id=? AND cancel_operation_id COLLATE BINARY>? "
                            "ORDER BY cancel_operation_id COLLATE BINARY LIMIT 1",
                            (self.namespace,self.installation_id,after_cancel_operation_id)).fetchone()
                        if row is None:return None
                        from .owner_goal_cancellation_contract_v1 import validate_goal_cancellation_core_row_v1
                        original=validate_goal_cancellation_core_row_v1(GOAL_CANCEL_COLUMNS_V1,row,issuer=self.issuer)
                        self._current_projection_owner_in_tx_v1(db,original)
                        return original
        finally:finish_runtime_storage_operation_v3(operation)

