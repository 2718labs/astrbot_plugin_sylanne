"""Authority-owned, revocable administrator persona/self mapping.

The head and operation ledger live in the existing Authority Core database.
Graph checks run outside Authority and journal locks.  A current read is valid
only while its independently issued read/write fence remains active.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import sqlite3
from typing import Callable

from ..contracts import canonical_json
from ..runtime_contracts import NamespaceId, canonical_digest
from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .current_self_identity_graph_verifier import PinnedCurrentSelfIdentityGraphVerifier
from .v2_contract import FencePermitV2, canonical_bytes
from .v2_fence_service import AuthorityV2FenceService
from .v2_fence_store import AuthorityV2FenceStore
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from .v2_self_identity_contract import (
    AuthorityCurrentSelfIdentityV1, SelfIdentityCurrentRequestV1,
    SelfIdentityMutationV1,
)


_HEAD = """CREATE TABLE authority_self_identity_heads_v1 (
    authority_namespace TEXT PRIMARY KEY,
    namespace_json TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    mapping_id TEXT NOT NULL,
    self_entity_ref TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    revocation_epoch INTEGER NOT NULL CHECK(revocation_epoch >= 0),
    state TEXT NOT NULL CHECK(state IN ('active','revoked')),
    registration_operation_id TEXT NOT NULL,
    registration_digest TEXT NOT NULL,
    registration_subject TEXT NOT NULL
) STRICT"""
_OPERATIONS = """CREATE TABLE authority_self_identity_operations_v1 (
    operation_id TEXT PRIMARY KEY,
    authority_namespace TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    administrator_subject TEXT NOT NULL,
    receipt_json TEXT NOT NULL
) STRICT"""


@dataclass(frozen=True, slots=True)
class SelfIdentityMutationReceiptV1:
    operation_id: str
    request_digest: str
    authority_namespace: str
    mapping_id: str
    revision: int
    revocation_epoch: int
    state: str
    schema: str = "sylanne3.authority.self-identity-mutation.v1"

    def __post_init__(self) -> None:
        for name in ("operation_id", "authority_namespace", "mapping_id"):
            identifier(getattr(self, name), name)
        if (self.schema != "sylanne3.authority.self-identity-mutation.v1"
                or len(self.request_digest) != 64
                or any(ch not in "0123456789abcdef" for ch in self.request_digest)
                or type(self.revision) is not int or self.revision < 1
                or type(self.revocation_epoch) is not int or self.revocation_epoch < 0
                or self.state not in {"active", "revoked"}):
            raise ValueError("self identity mutation receipt differs")


class AuthorityV2SelfIdentityService:
    def __init__(self, *, core: AuthorityServiceCore,
                 fences: AuthorityV2FenceService,
                 owner_tickets: AuthorityV2OwnerTicketStore,
                 graph: PinnedCurrentSelfIdentityGraphVerifier,
                 namespace_id: NamespaceId,
                 installation_id: str, manifest_digest: str,
                 read_subject: str, holder: str,
                 administrator_authorizer: Callable[[object, str, str, str], bool],
                 create: bool = False):
        if (type(core) is not AuthorityServiceCore
                or type(fences) is not AuthorityV2FenceService
                or type(owner_tickets) is not AuthorityV2OwnerTicketStore
                or type(graph) is not PinnedCurrentSelfIdentityGraphVerifier
                or owner_tickets._core is not core
                or fences.core is not core or fences.fences._db is not core._db
                or fences.fences._lock is not core._lock
                or not callable(administrator_authorizer)):
            raise AuthorityUnavailable("self identity needs the installed Authority composition")
        if type(namespace_id) is not NamespaceId:
            raise AuthorityUnavailable("installed self identity namespace is required")
        for name, value in (("installation_id", installation_id),
                            ("read_subject", read_subject), ("holder", holder)):
            identifier(value, name)
        if (type(manifest_digest) is not str or len(manifest_digest) != 64
                or any(ch not in "0123456789abcdef" for ch in manifest_digest)):
            raise AuthorityUnavailable("installed manifest digest differs")
        self._core, self._fences, self._tickets = core, fences, owner_tickets
        self._graph = graph
        self._namespace_id = namespace_id
        self._installation_id, self._manifest_digest = installation_id, manifest_digest
        self._read_subject, self._holder = read_subject, holder
        self._admin_authorizer = administrator_authorizer
        self._source_location = None
        self._owner_storage = None
        with core._tx() as db:
            fences._require_mode(db)
            present = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND "
                "name IN ('authority_self_identity_heads_v1',"
                "'authority_self_identity_operations_v1')")}
            if not present and create:
                db.execute(_HEAD)
                db.execute(_OPERATIONS)
            elif present != {"authority_self_identity_heads_v1",
                             "authority_self_identity_operations_v1"}:
                raise AuthorityUnavailable("self identity schema is absent or partial")
            self._check_schema(db)

    def install_current_source_location_v1(self, qualifier, owner_storage):
        from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
        from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
        if (type(qualifier) is not InstalledCurrentSourceLocationQualifierV1
                or type(owner_storage) is not InstalledD12OwnerStorageAdmissionServiceV1
                or qualifier._fences is not self._fences or qualifier.core is not self._core
                or qualifier._graph_db_path != self._graph._path
                or qualifier.namespace_id != self._namespace_id or qualifier.installation_id != self._installation_id
                or owner_storage.fences is not self._fences or owner_storage.tickets is not self._tickets
                or owner_storage.graph_path != self._graph._path
                or owner_storage.control is not qualifier._control
                or self._source_location not in (None, qualifier)
                or self._owner_storage not in (None, owner_storage)):
            raise AuthorityUnavailable("self identity needs the actual shared source-location composition")
        self._source_location, self._owner_storage = qualifier, owner_storage

    @staticmethod
    def _check_schema(db) -> None:
        for name, ddl in (("authority_self_identity_heads_v1", _HEAD),
                          ("authority_self_identity_operations_v1", _OPERATIONS)):
            if db.execute("SELECT sql FROM sqlite_master WHERE type='table' "
                          "AND name=?", (name,)).fetchone() != (ddl,):
                raise AuthorityUnavailable("self identity schema differs")

    @staticmethod
    def _head(db, namespace: str):
        return db.execute(
            "SELECT namespace_json,installation_id,manifest_digest,mapping_id,"
            "self_entity_ref,revision,revocation_epoch,state,"
            "registration_operation_id,registration_digest,registration_subject "
            "FROM authority_self_identity_heads_v1 WHERE authority_namespace=?",
            (namespace,)).fetchone()

    def _current_namespace(self, db, deletion_head, execution_head):
        return self._fences._current_locked(db, deletion_head, execution_head,
                                             holder=self._holder)

    def mutate(self, *, credential: object, subject: str,
               mutation: SelfIdentityMutationV1) -> SelfIdentityMutationReceiptV1:
        """Administrator-only CAS; an operation ID can never mean new bytes."""
        identifier(subject, "subject")
        if (type(mutation) is not SelfIdentityMutationV1
                or mutation.authority_namespace != self._fences.namespace
                or mutation.namespace != self._namespace_id
                or mutation.installation_id != self._installation_id
                or mutation.manifest_digest != self._manifest_digest):
            raise AuthorityUnavailable("self identity mutation installation differs")
        try:
            allowed = self._admin_authorizer(
                credential, "self_identity_mutate", mutation.authority_namespace,
                self._installation_id)
        except Exception as exc:
            raise AuthorityUnavailable("administrator self identity authorization unavailable") from exc
        if allowed is not True:
            raise AuthorityUnavailable("administrator self identity authorization denied")
        with self._fences._frozen() as (db, deletion_head, execution_head, history):
            self._check_schema(db)
            anchor = self._current_namespace(db, deletion_head, execution_head)
            if (history or mutation.authority_id != anchor.authority_id):
                raise AuthorityUnavailable("self identity namespace is not current")
            prior = db.execute(
                "SELECT authority_namespace,request_digest,administrator_subject,receipt_json FROM "
                "authority_self_identity_operations_v1 WHERE operation_id=?",
                (mutation.operation_id,)).fetchone()
            if prior is not None:
                if prior[:3] != (mutation.authority_namespace,
                                 mutation.request_digest, subject):
                    raise AuthorityUnavailable("self identity operation ID replay differs")
                receipt = SelfIdentityMutationReceiptV1(**json.loads(prior[3]))
                if canonical_json(asdict(receipt)) != prior[3]:
                    raise AuthorityUnavailable("stored self identity operation differs")
                return receipt
            # Recovery of an exact original operation is read-only and must
            # work even if a later read fence is active. New mutations wait.
            AuthorityV2FenceStore.require_idle_owner_write_in_tx(
                db, mutation.authority_namespace)
            head = self._head(db, mutation.authority_namespace)
            current_revision = 0 if head is None else head[5]
            if current_revision != mutation.expected_revision:
                raise AuthorityUnavailable("self identity revision changed")
            if head is not None and head[0] != canonical_json(asdict(mutation.namespace)):
                raise AuthorityUnavailable("self identity namespace changed")
            if mutation.action == "revoke":
                if head is None or head[7] != "active" or head[4] != mutation.self_entity_ref:
                    raise AuthorityUnavailable("active self identity is absent")
                mapping_id = head[3]
                revocation_epoch = head[6] + 1
                registration_operation_id, registration_digest = head[8:10]
                registration_subject = head[10]
                state = "revoked"
            else:
                mapping_id = "self-map:" + canonical_digest({
                    "namespace": list(mutation.namespace.as_tuple),
                    "installation_id": mutation.installation_id,
                    "operation_id": mutation.operation_id,
                    "request_digest": mutation.request_digest,
                })
                revocation_epoch = 0 if head is None else head[6] + 1
                registration_operation_id = mutation.operation_id
                registration_digest = mutation.request_digest
                registration_subject = subject
                state = "active"
            revision = current_revision + 1
            new_head = (canonical_json(asdict(mutation.namespace)),
                        mutation.installation_id, mutation.manifest_digest,
                        mapping_id, mutation.self_entity_ref, revision,
                        revocation_epoch, state, registration_operation_id,
                        registration_digest, registration_subject)
            if head is None:
                db.execute(
                    "INSERT INTO authority_self_identity_heads_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (mutation.authority_namespace, *new_head))
            else:
                changed = db.execute(
                    "UPDATE authority_self_identity_heads_v1 SET namespace_json=?,"
                    "installation_id=?,manifest_digest=?,mapping_id=?,self_entity_ref=?,"
                    "revision=?,revocation_epoch=?,state=?,registration_operation_id=?,"
                    "registration_digest=?,registration_subject=? "
                    "WHERE authority_namespace=? AND revision=?",
                    (*new_head, mutation.authority_namespace, current_revision),
                ).rowcount
                if changed != 1:
                    raise AuthorityUnavailable("self identity head CAS failed")
            receipt = SelfIdentityMutationReceiptV1(
                mutation.operation_id, mutation.request_digest,
                mutation.authority_namespace, mapping_id, revision,
                revocation_epoch, state)
            db.execute(
                "INSERT INTO authority_self_identity_operations_v1 VALUES(?,?,?,?,?)",
                (mutation.operation_id, mutation.authority_namespace,
                 mutation.request_digest, subject, canonical_json(asdict(receipt))))
            return receipt

    def _read_locked(self, db, deletion_head, execution_head, history,
                     credential, subject, request, location=None, *, _mesh_work=None, _original_work=None):
        self._check_schema(db)
        anchor = self._current_namespace(db, deletion_head, execution_head)
        permit = request.permit
        if history and (location is None or self._source_location is None):
            raise AuthorityUnavailable("self identity needs actual current storage continuation")
        if _original_work is not None:
            from .original_foreground_source_read_v3 import require_original_foreground_source_anchor_in_tx_v3
            if _mesh_work is not None or _original_work.service.self_identity is not self:
                raise AuthorityUnavailable('Original current Self changed its actual installed service')
            require_original_foreground_source_anchor_in_tx_v3(_original_work,db,location)
        elif _mesh_work is not None:
            from .foreground_mesh_source_read_v3 import require_foreground_mesh_source_anchor_in_tx_v3
            if _mesh_work.service.self_identity is not self:
                raise AuthorityUnavailable("Personal mesh current Self reader changed its actual installation")
            require_foreground_mesh_source_anchor_in_tx_v3(_mesh_work,db,location)
        elif location is not None:
            self._source_location.require_current_in_tx_v1(db, location)
        if (request.authority_id != anchor.authority_id
                or permit.pinned_anchor != anchor or permit.subject != subject
                or permit.holder != self._holder
                or permit.generation != anchor.activation_generation):
            raise AuthorityUnavailable("current self identity anchor differs")
        AuthorityV2FenceStore._check_schema(db)
        AuthorityV2FenceStore._require_no_migration(db)
        fence = AuthorityV2FenceStore._row(db, permit.operation_id)
        if (fence is None or fence[1:4] != (
                permit.namespace, subject, permit.token)
                or fence[6] != "active" or fence[7] != canonical_bytes(permit)
                or fence[10] is not None
                or AuthorityV2FenceStore._permit(fence) != permit
                or db.execute(
                    "SELECT 1 FROM authority_v2_mutations WHERE namespace=? "
                    "AND state='pending' LIMIT 1",
                    (request.authority_namespace,)).fetchone() is not None):
            raise AuthorityUnavailable("self identity read fence is no longer current")
        head = self._head(db, request.authority_namespace)
        if (head is None or head[7] != "active"
                or head[0] != canonical_json(asdict(request.namespace))
                or head[1:3] != (request.installation_id,
                                  request.manifest_digest)):
            return None
        guard = self._tickets._checked_current_head(db, request.authority_namespace)
        if (guard is None or guard.namespace != request.namespace
                or guard.authority_id != anchor.authority_id
                or guard.installation_id != request.installation_id
                or guard.pending_revoke_operation_id is not None
                or guard.minimum_revocation_revision >= guard.authorization_revision
                or guard.minimum_revocation_epoch > 0):
            raise AuthorityUnavailable("current Owner head is unavailable")
        epoch = db.execute(
            "SELECT last_epoch FROM authority_v2_epochs WHERE namespace=?",
            (request.authority_namespace,)).fetchone()
        return head, guard, anchor, epoch

    def current(self, *, credential: object, subject: str,
                request: SelfIdentityCurrentRequestV1,
                ) -> AuthorityCurrentSelfIdentityV1 | None:
        identifier(subject, "subject")
        if (type(request) is not SelfIdentityCurrentRequestV1
                or request.authority_namespace != self._fences.namespace
                or request.namespace != self._namespace_id
                or request.installation_id != self._installation_id
                or request.manifest_digest != self._manifest_digest
                or subject != self._read_subject):
            raise AuthorityUnavailable("self identity reader installation differs")
        return self._current_for_installed_permit(
            credential=credential, subject=subject, request=request)

    def current_for_c04_v4(self,*,credential,reader,binding,permit):
        from .owner_location_read_v3 import (prepare_owner_location_for_c04_self_v3,
            _owner_location_service_invocation_v3)
        with _owner_location_service_invocation_v3(self):
            return prepare_owner_location_for_c04_self_v3(self,credential=credential,reader=reader,
                binding=binding,permit=permit)

    def _current_for_installed_permit(self, *, credential, subject, request):
        self._core._require(credential, "self_identity_read",
                            request.authority_namespace, self._holder)
        location = current_owner = None
        if self._source_location is not None:
            location = self._source_location.observe_business_for_fence_v1(
                credential=credential, subject=subject, permit=request.permit)
            current_owner, observed = self._owner_storage.get_current_background_owner_authority_for_fence_v1(
                credential=credential, subject=subject, permit=request.permit)
            if observed != request.permit or current_owner.target_admission is not None:
                raise AuthorityUnavailable("self identity source Owner observation differs")
        with self._fences._frozen() as (db, deletion_head, execution_head, history):
            before = self._read_locked(db, deletion_head, execution_head,
                                       history, credential, subject, request, location)
        if before is None:
            return None
        head, guard, anchor, epoch = before
        if current_owner is not None and current_owner.guard != guard:
            raise AuthorityUnavailable("self identity Owner changed after storage observation")
        if location is None:
            current_graph = self._graph.current(request.namespace, anchor, request.installation_id, guard)
        else:
            current_graph = self._graph.current(
                request.namespace, anchor, request.installation_id, guard,
                source_location=self._source_location, location_observation=location,
                storage_admission=current_owner.storage_admission, holder=self._holder)
        if current_graph is None:
            raise AuthorityUnavailable("current D01 self identity role is unavailable")
        with self._fences._frozen() as (db, deletion_head, execution_head, history):
            after = self._read_locked(db, deletion_head, execution_head,
                                      history, credential, subject, request, location)
            if after != before:
                raise AuthorityUnavailable("self identity changed during graph read")
        admission = None if current_owner is None else current_owner.storage_admission
        return self._current_value(request, head, guard, anchor, current_graph, admission)

    @staticmethod
    def _current_value(request, head, guard, anchor, current_graph, admission):
        graph_incarnation, role_head_id, graph_revision, graph_epoch = current_graph
        return AuthorityCurrentSelfIdentityV1(
            namespace=request.namespace,
            authority_namespace=request.authority_namespace,
            authority_id=anchor.authority_id,
            installation_id=request.installation_id,
            manifest_digest=request.manifest_digest,
            activation_generation=anchor.activation_generation,
            graph_incarnation=graph_incarnation,
            role_head_id=role_head_id,
            graph_revision=graph_revision, graph_epoch=graph_epoch,
            persona_ref="persona:" + request.namespace.persona_id,
            self_entity_ref=head[4], mapping_id=head[3],
            mapping_revision=head[5], mapping_revocation_epoch=head[6],
            registration_operation_id=head[8], registration_digest=head[9],
            owner_authorization_revision=guard.authorization_revision,
            owner_authorization_head=guard.authorization_head,
            owner_minimum_revocation_revision=guard.minimum_revocation_revision,
            owner_revocation_epoch=guard.minimum_revocation_epoch,
            request_operation_id=request.request_operation_id,
            permit=request.permit,
            origin_graph_incarnation=None if admission is None else admission.source_graph_incarnation,
            storage_admission_digest=None if admission is None else admission.original_digest)


__all__ = ("AuthorityV2SelfIdentityService", "SelfIdentityMutationReceiptV1")

