"""Independent target Owner admission derived from actual migration originals.

The immutable source grant and Authority Owner head are never rewritten. A
freshly paired target Owner key/session authenticates the same principal; the
current target fence and imported Graph independently qualify its new location.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
from pathlib import Path
import re
import sqlite3

from ..graph_store import GraphStore, _assert_migration_owner_head_in_transaction
from ..graph_types import owner_grant_key, validate_owner_grant_v1
from ..runtime.graph_migration_snapshot_v1 import _read_import_receipt_locked
from ..runtime.lifecycle_operations_v1 import digest
from ..runtime_contracts import NamespaceId, canonical_serialize
from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2
from .v2_owner_contract import (OwnerAuthorizationGuardV1, OwnerPrincipalV1,
    canonical_digest as owner_contract_digest)
from .v2_owner_session import AuthorityV2OwnerSessionStore, OwnerSessionLoginRequestV1
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore

SCHEMA = "d12.target_owner_admission.v1"


def _material(value):
    return {field.name: getattr(value, field.name) for field in fields(value)
            if field.name != "original_digest"}


@dataclass(frozen=True, slots=True)
class D12TargetOwnerAdmissionV1:
    namespace: NamespaceId
    authority_namespace: str
    transfer_id: str
    source_installation_id: str
    target_installation_id: str
    target_holder: str
    source_grant_ref: str
    source_grant_revision: int
    source_grant_digest: str
    source_owner_guard: OwnerAuthorizationGuardV1
    principal: OwnerPrincipalV1
    target_actor_id: str
    target_actor_revision: int
    target_credential_id: str
    target_credential_epoch: int
    activation_generation: int
    revocation_epoch: int
    graph_incarnation: str
    source_snapshot_digest: str
    target_import_digest: str
    activation_receipt_digest: str
    policy_ref: str
    policy_digest: str
    original_ref: str
    original_digest: str
    storage_continuation_ref: str | None = None
    storage_continuation_digest: str | None = None
    source_lifecycle_head_digest: str | None = None
    source_lifecycle_epoch: int | None = None
    target_lifecycle_epoch: int | None = None
    schema: str = SCHEMA

    def __post_init__(self):
        if (self.schema != SCHEMA or type(self.namespace) is not NamespaceId
                or type(self.source_owner_guard) is not OwnerAuthorizationGuardV1
                or type(self.principal) is not OwnerPrincipalV1
                or self.source_owner_guard.namespace != self.namespace):
            raise ValueError("typed target Owner admission identities required")
        for name in ("authority_namespace", "transfer_id", "source_installation_id",
                     "target_installation_id", "target_holder", "source_grant_ref",
                     "target_actor_id", "target_credential_id", "graph_incarnation", "policy_ref", "original_ref"):
            value = getattr(self, name)
            if type(value) is not str or not value or len(value) > 4096:
                raise ValueError("bounded target Owner admission reference required")
        for name in ("source_grant_revision", "target_actor_revision", "target_credential_epoch", "activation_generation"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError("positive target Owner admission versions required")
        if type(self.revocation_epoch) is not int or self.revocation_epoch < 0:
            raise ValueError("target revocation epoch required")
        for name in ("source_grant_digest", "source_snapshot_digest", "target_import_digest",
                     "activation_receipt_digest", "policy_digest", "original_digest"):
            if type(getattr(self, name)) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", getattr(self, name)) is None:
                raise ValueError("target Owner admission digest required")
        if (self.storage_continuation_ref is None) != (self.storage_continuation_digest is None):
            raise ValueError("target storage continuation identity must be paired")
        if self.storage_continuation_digest is not None and (
                type(self.storage_continuation_ref) is not str or not self.storage_continuation_ref.startswith("d12c09location:")
                or re.fullmatch(r"sha256:[0-9a-f]{64}", self.storage_continuation_digest) is None):
            raise ValueError("target storage continuation identity differs")
        lifecycle = (self.source_lifecycle_head_digest, self.source_lifecycle_epoch, self.target_lifecycle_epoch)
        if any(value is not None for value in lifecycle) and (
                not all(value is not None for value in lifecycle)
                or type(self.source_lifecycle_head_digest) is not str
                or re.fullmatch(r"sha256:[0-9a-f]{64}", self.source_lifecycle_head_digest) is None
                or type(self.source_lifecycle_epoch) is not int or self.source_lifecycle_epoch < 0
                or type(self.target_lifecycle_epoch) is not int
                or self.target_lifecycle_epoch != self.source_lifecycle_epoch + 1):
            raise ValueError("target lifecycle relocation commitment differs")
        if digest(_material(self)) != self.original_digest:
            raise ValueError("target Owner admission original digest differs")

    def to_wire(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class D12CurrentOwnerAuthorityV1:
    """Current server-read guard, optionally located by a target admission."""
    guard: OwnerAuthorizationGuardV1
    target_admission: D12TargetOwnerAdmissionV1 | None
    storage_admission: object | None = None

    def __post_init__(self):
        if type(self.guard) is not OwnerAuthorizationGuardV1:
            raise TypeError("unchanged current Authority Owner guard required")
        if self.target_admission is not None and (
                type(self.target_admission) is not D12TargetOwnerAdmissionV1
                or self.target_admission.source_owner_guard != self.guard):
            raise ValueError("target admission differs from original Owner guard")
        if self.storage_admission is not None:
            from .d12_owner_storage_admission_v1 import D12OwnerStorageAdmissionV1
            if (self.target_admission is not None or type(self.storage_admission) is not D12OwnerStorageAdmissionV1
                    or self.storage_admission.source_owner_guard!=self.guard):
                raise ValueError("source storage admission differs from original Owner guard")


def current_owner_authority_material_v1(value):
    """Preserve original two-field commitments when no storage extension exists."""
    if type(value) is not D12CurrentOwnerAuthorityV1:raise TypeError("actual Owner authority value required")
    body={"guard":asdict(value.guard),"target_admission":None if value.target_admission is None else asdict(value.target_admission)}
    if value.storage_admission is not None:body["storage_admission"]=value.storage_admission.to_wire()
    return body


def current_owner_authority_to_wire_v1(value):
    from .v2_owner_contract import to_wire
    body={"guard":to_wire(value.guard),"target_admission":None if value.target_admission is None else value.target_admission.to_wire()}
    if value.storage_admission is not None:body["storage_admission"]=value.storage_admission.to_wire()
    return body


def current_owner_authority_from_wire_v1(raw):
    from .v2_owner_contract import from_wire
    from .d12_owner_storage_admission_v1 import owner_storage_admission_from_wire_v1
    if type(raw) is not dict or set(raw) not in ({"guard","target_admission"},{"guard","target_admission","storage_admission"}):raise ValueError("Owner authority wire fields differ")
    value=D12CurrentOwnerAuthorityV1(from_wire(raw["guard"]),None if raw["target_admission"] is None else target_admission_from_wire_v1(raw["target_admission"]),
        None if "storage_admission" not in raw else owner_storage_admission_from_wire_v1(raw["storage_admission"]))
    if json.loads(canonical_serialize(current_owner_authority_to_wire_v1(value)))!=raw:raise ValueError("Owner authority wire noncanonical")
    return value


def target_admission_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != set(D12TargetOwnerAdmissionV1.__dataclass_fields__):
        raise ValueError("target Owner admission wire fields differ")
    value = dict(raw)
    value["namespace"] = NamespaceId(**value["namespace"])
    guard = dict(value["source_owner_guard"])
    guard["namespace"] = NamespaceId(**guard["namespace"])
    value["source_owner_guard"] = OwnerAuthorizationGuardV1(**guard)
    value["principal"] = OwnerPrincipalV1(**value["principal"])
    return D12TargetOwnerAdmissionV1(**value)


class InstalledD12TargetOwnerAdmissionServiceV1:
    def __init__(self, *, migration, owner_tickets, target_graph_db, namespace_id,
                 target_installation_id, target_holder, policy_ref, policy_digest,
                 operation_status_service=None, storage_continuation_reader=None):
        if (type(owner_tickets) is not AuthorityV2OwnerTicketStore
                or owner_tickets._core is not migration.core
                or type(owner_tickets._owner_sessions) is not AuthorityV2OwnerSessionStore):
            raise TypeError("same-Core target Owner/session/migration authorities required")
        path = Path(target_graph_db)
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("administrator-pinned target Graph required")
        self.migration, self.core, self.fences = migration, migration.core, migration.fences
        self.tickets, self.sessions = owner_tickets, owner_tickets._owner_sessions
        self.namespace, self.namespace_id = migration.namespace, namespace_id
        self.target_graph = path.resolve(strict=False)
        self.installation_id, self.holder = target_installation_id, target_holder
        self.policy_ref, self.policy_digest = policy_ref, policy_digest
        if operation_status_service is not None and (
                operation_status_service.core is not self.core
                or operation_status_service.namespace != self.namespace):
            raise TypeError("target status reader must share the original migration Authority")
        self.operation_status_service = operation_status_service
        if storage_continuation_reader is not None:
            from .d12_c09_target_continuation_v1 import InstalledD12C09TargetContinuationReaderV1
            if (type(storage_continuation_reader) is not InstalledD12C09TargetContinuationReaderV1
                    or storage_continuation_reader.close_apply.service.core is not self.core):
                raise TypeError("target continuation must use actual same-Core C09 release reader")
        self.storage_continuation_reader = storage_continuation_reader

    def install_schema(self, administrator_credential):
        self.core._require(administrator_credential, "d12_target_owner_install", self.namespace)
        with self.core._tx() as db:
            db.execute("CREATE TABLE IF NOT EXISTS authority_d12_target_owner_admissions_v1("
                "authority_namespace TEXT NOT NULL,target_installation_id TEXT NOT NULL,"
                "original_ref TEXT PRIMARY KEY,original_digest TEXT NOT NULL,original_json TEXT NOT NULL)")

    def _current_session(self, db, *, actor, token, request):
        if (type(request) is not OwnerSessionLoginRequestV1 or request.audience != "owner"
                or request.authority_namespace != self.namespace
                or request.installation_id != self.installation_id
                or request.authority_id != self.core._id(db)):
            raise AuthorityUnavailable("fresh target Owner session identity differs")
        self.sessions.require_current_in_tx(db, token=token, request=request)
        source = self.sessions._current_pairing_source
        if source is None:
            raise AuthorityUnavailable("current target Owner actor pairing unavailable")
        return source.require_current_actor_in_tx(db, authority_namespace=self.namespace,
            installation_id=self.installation_id, actor_id=actor, principal=request.principal)

    def _current_transfer(self, db, *, generation):
        candidates = []
        for (transfer_id,) in db.execute("SELECT transfer_id FROM authority_migration_v2_plans "
                                        "WHERE namespace=? AND phase='activated'", (self.namespace,)):
            history = self.migration.store.status_locked(db, transfer_id)
            if (history.plan.target_installation_id == self.installation_id
                    and history.plan.target_holder == self.holder
                    and history.target_permit.generation == generation):
                candidates.append(history)
        if len(candidates) != 1:
            raise AuthorityUnavailable("current target has no unique activated migration original")
        return candidates[0]

    def _read_graph(self, *, history, owner_head, anchor):
        if not self.target_graph.is_file() or self.target_graph.is_symlink():
            raise AuthorityUnavailable("actual target Graph is unavailable")
        graph = sqlite3.connect(self.target_graph.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        try:
            graph.execute("BEGIN")
            _assert_migration_owner_head_in_transaction(graph, self.namespace_id, owner_head)
            imported = _read_import_receipt_locked(graph, self.namespace_id, history.plan.transfer_id)
            row = graph.execute("SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
                "WHERE bot=? AND persona=?", self.namespace_id.as_tuple).fetchone()
            metadata = GraphStore._decode_recovery(row, self.namespace_id)
            grant_row = graph.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (owner_grant_key(*self.namespace_id.as_tuple).token,)).fetchone()
            if metadata is None or imported is None or grant_row is None or grant_row[2] != 1:
                raise AuthorityUnavailable("target graph lacks current import/Owner originals")
            grant = json.loads(grant_row[1])
            validate_owner_grant_v1(grant)
            req = metadata.requirements
            expected = history.target_recovery
            continuation = None
            if (req.graph_incarnation != expected.new_graph_incarnation
                    or req.revocation_epoch != expected.current_requirements.revocation_epoch):
                if self.storage_continuation_reader is None:
                    raise AuthorityUnavailable("current target C09 location continuation reader unavailable")
                continuation = self.storage_continuation_reader.require_current_target_continuation_v1(
                    graph_db=graph, history=history, metadata=metadata)
            if (req.namespace != self.namespace_id or req.authority_id != anchor.authority_id
                    or req.authority_namespace != self.namespace
                    or req.activation_generation != anchor.activation_generation
                    or req.revocation_epoch != anchor.revocation_epoch
                    or (req.deletion_journal_id, req.deletion_seq, req.deletion_digest,
                        req.execution_journal_id, req.execution_seq, req.execution_digest) != (
                        anchor.deletion_journal_id, anchor.deletion_seq, anchor.deletion_digest,
                        anchor.execution_journal_id, anchor.execution_seq, anchor.execution_digest)
                    or continuation is None and req.graph_incarnation != expected.new_graph_incarnation
                    or imported.target_graph_incarnation != expected.new_graph_incarnation
                    or imported.target_activation_generation != anchor.activation_generation
                    or imported.graph_commit_digest != expected.graph_commit_digest
                    or imported.snapshot_digest != history.source_snapshot.snapshot_digest
                    or metadata.graph_revision < imported.target_graph_revision
                    or digest(grant) != owner_head.grant_digest
                    or grant_row[0] != owner_head.grant_revision
                    or grant["principal"] != asdict(owner_head.issue_operation.principal)):
                raise AuthorityUnavailable("target admission differs from actual imported/current graph originals")
            return metadata, grant_row[0], digest(grant), imported, continuation
        finally:
            graph.close()

    def _lifecycle_relocation_material(self, db, history):
        from .d12_lifecycle_gate_v1 import read_lifecycle_head_in_tx_v1
        head = read_lifecycle_head_in_tx_v1(db, self.namespace)
        material = dict(source_lifecycle_head_digest=None, source_lifecycle_epoch=None, target_lifecycle_epoch=None)
        if head is None:
            return head, material
        if head.installation_id == self.installation_id:
            # Preserve the first relocation commitment when a new signed
            # session rereads the same immutable admission basis. A later C09
            # may retire it; no relocation is needed for an already target head.
            for (encoded,) in db.execute("SELECT original_json FROM authority_d12_target_owner_admissions_v1 "
                    "WHERE authority_namespace=? AND target_installation_id=?", (self.namespace,self.installation_id)):
                original = target_admission_from_wire_v1(json.loads(encoded))
                if original.transfer_id == history.plan.transfer_id and original.source_lifecycle_epoch is not None:
                    material = {key:getattr(original,key) for key in material}
                    break
            return head, material
        if head.installation_id != history.plan.source_installation_id or head.state != "active":
            raise AuthorityUnavailable("target cannot adopt an unrelated or unfinished lifecycle head")
        material.update(source_lifecycle_head_digest=head.head_digest,
                        source_lifecycle_epoch=head.epoch, target_lifecycle_epoch=head.epoch+1)
        return head, material

    def _commit_lifecycle_relocation(self, db, head, original):
        if head is None or head.installation_id == self.installation_id:
            return
        material = (self.namespace,self.installation_id,"active",original.target_lifecycle_epoch,None,original.original_ref)
        changed = db.execute("UPDATE authority_d12_lifecycle_heads_v1 SET installation_id=?,state='active',epoch=?,"
            "operation_id=NULL,head_digest=?,current_receipt_ref=? WHERE namespace=? AND installation_id=? "
            "AND state='active' AND epoch=? AND head_digest=?", (self.installation_id,original.target_lifecycle_epoch,
                digest(material),original.original_ref,self.namespace,head.installation_id,head.epoch,head.head_digest)).rowcount
        if changed != 1:
            raise AuthorityUnavailable("target lifecycle relocation head CAS changed")

    def get_current_owner_authority_for_fence_v1(self, *, credential, subject, permit,
            actor, session_token, session_request):
        if (type(permit) is not FencePermitV2 or permit.operation not in {"read", "write"}
                or permit.holder != self.holder or permit.namespace != self.namespace
                or permit.subject != subject):
            raise AuthorityUnavailable("current target content fence required")
        self.fences._require_permit(credential=credential, subject=subject, permit=permit)
        with self.fences._frozen() as (db, deletion, execution, _):
            anchor = self.fences._current_locked(db, deletion, execution,
                holder=self.holder, generation=permit.generation)
            if anchor != permit.pinned_anchor:
                raise AuthorityUnavailable("target Owner fence anchor changed")
            self.fences.fences.validate_fence_locked(db, permit=permit, subject=subject, current_anchor=anchor)
            actor_binding = self._current_session(db, actor=actor, token=session_token, request=session_request)
            owner_head = self.tickets.current_migration_head_in_tx(db, authority_namespace=self.namespace)
            if (owner_head is None or owner_head.state != "active"
                    or owner_head.issue_operation.principal != session_request.principal):
                raise AuthorityUnavailable("target session is not the original migration Owner")
            history = self._current_transfer(db, generation=permit.generation)
            metadata, grant_revision, grant_digest, imported, continuation = self._read_graph(
                history=history, owner_head=owner_head, anchor=anchor)
            lifecycle_head, lifecycle_material = self._lifecycle_relocation_material(db, history)
            material = dict(namespace=self.namespace_id, authority_namespace=self.namespace,
                transfer_id=history.plan.transfer_id, source_installation_id=history.plan.source_installation_id,
                target_installation_id=self.installation_id, target_holder=self.holder,
                source_grant_ref=owner_grant_key(*self.namespace_id.as_tuple).token,
                source_grant_revision=grant_revision, source_grant_digest=grant_digest,
                source_owner_guard=owner_head.guard, principal=session_request.principal,
                target_actor_id=actor, target_actor_revision=actor_binding.revision,
                target_credential_id=session_request.credential_id,
                target_credential_epoch=session_request.credential_epoch,
                activation_generation=anchor.activation_generation, revocation_epoch=anchor.revocation_epoch,
                graph_incarnation=metadata.requirements.graph_incarnation,
                source_snapshot_digest=history.source_snapshot.snapshot_digest,
                target_import_digest=imported.graph_commit_digest,
                activation_receipt_digest=digest(history.receipts[-1]),
                policy_ref=self.policy_ref, policy_digest=self.policy_digest,
                storage_continuation_ref=None if continuation is None else continuation.original_ref,
                storage_continuation_digest=None if continuation is None else continuation.original_digest,
                schema=SCHEMA, **lifecycle_material)
            material["original_ref"] = "d12targetowner:" + digest(material)[7:]
            material["original_digest"] = digest(material)
            original = D12TargetOwnerAdmissionV1(**material)
            values = (self.namespace, self.installation_id, original.original_ref,
                      original.original_digest, canonical_serialize(asdict(original)))
            db.execute("INSERT OR IGNORE INTO authority_d12_target_owner_admissions_v1 VALUES(?,?,?,?,?)", values)
            if db.execute("SELECT * FROM authority_d12_target_owner_admissions_v1 WHERE original_ref=?",
                          (original.original_ref,)).fetchone() != values:
                raise AuthorityUnavailable("target Owner admission original identity conflict")
            self._commit_lifecycle_relocation(db, lifecycle_head, original)
            return D12CurrentOwnerAuthorityV1(owner_head.guard, original), permit

    def get_current_background_owner_authority_for_fence_v1(self, *, credential, subject, permit):
        """Read installed background authority after a genuine target admission.

        No browser token is consumed or extended. Revoked/replaced Owner head,
        actor, key pairing, credential epoch or target namespace invalidates it.
        Missing a prior freshly signed target admission is an explicit HOLD.
        """
        if (type(permit) is not FencePermitV2 or permit.operation not in {"read", "write"}
                or permit.holder != self.holder or permit.namespace != self.namespace
                or permit.subject != subject):
            raise AuthorityUnavailable("current installed target background fence required")
        self.fences._require_permit(credential=credential, subject=subject, permit=permit)
        with self.fences._frozen() as (db, deletion, execution, _):
            anchor = self.fences._current_locked(db, deletion, execution,
                holder=self.holder, generation=permit.generation)
            if anchor != permit.pinned_anchor:
                raise AuthorityUnavailable("target background fence anchor changed")
            self.fences.fences.validate_fence_locked(db, permit=permit, subject=subject, current_anchor=anchor)
            head = self.tickets.current_migration_head_in_tx(db, authority_namespace=self.namespace)
            if head is None or head.state != "active":
                raise AuthorityUnavailable("original background Owner head is not active")
            history = self._current_transfer(db, generation=permit.generation)
            metadata, revision, grant_digest, imported, continuation = self._read_graph(history=history, owner_head=head, anchor=anchor)
            current = self._current_background_identity_for_verified_location_in_tx_v1(
                db, head=head, history=history, metadata=metadata, revision=revision,
                grant_digest=grant_digest, imported=imported, continuation=continuation, anchor=anchor)
            return current, permit

    def _current_background_identity_for_verified_location_in_tx_v1(self, db, *, head,
            history, metadata, revision, grant_digest, imported, continuation, anchor):
        """Internal identity projection after an actual installed location read.

        Numeric own-journal reconciliation may reuse this key/head check only
        after independently proving its exact claim/terminal transition and
        rereading this service's real target Graph/import/migration location.
        It is not an RPC and accepts no browser-created location evidence.
        """
        if db is not self.core._db or not db.in_transaction:
            raise AuthorityUnavailable("current target identity requires its Core transaction")
        candidates = []
        for (encoded,) in db.execute("SELECT original_json FROM authority_d12_target_owner_admissions_v1 "
                "WHERE authority_namespace=? AND target_installation_id=?", (self.namespace, self.installation_id)):
            admission = target_admission_from_wire_v1(json.loads(encoded))
            if (admission.transfer_id == history.plan.transfer_id
                    and admission.source_owner_guard == head.guard
                    and admission.source_grant_digest == grant_digest
                    and admission.source_grant_revision == revision
                    and admission.activation_generation == anchor.activation_generation
                    and admission.revocation_epoch == anchor.revocation_epoch
                    and admission.graph_incarnation == metadata.requirements.graph_incarnation
                    and admission.target_import_digest == imported.graph_commit_digest
                    and admission.storage_continuation_ref == (None if continuation is None else continuation.original_ref)
                    and admission.storage_continuation_digest == (None if continuation is None else continuation.original_digest)):
                candidates.append(admission)
        current = []
        source = self.sessions._current_pairing_source
        if source is None:
            raise AuthorityUnavailable("target background Owner pairing reader unavailable")
        from .v2_owner_proof import from_wire as proof_from_wire, OwnerCredentialRegistrationV1
        from .v2_owner_contract import canonical_bytes
        from .v2_owner_session import _principal, _time
        for admission in candidates:
            paired = db.execute("SELECT registration_bytes,valid_until_utc FROM authority_owner_credential_pairings_v1 "
                "WHERE authority_namespace=? AND principal_bytes=?",
                (self.namespace, canonical_bytes(admission.principal))).fetchone()
            if paired is None or self.sessions._now() >= _time(paired[1]):
                continue
            registration = proof_from_wire(json.loads(paired[0]))
            key = db.execute("SELECT credential_id,credential_epoch,public_key FROM authority_owner_credentials_v1 "
                "WHERE authority_namespace=? AND installation_id=? AND principal_json=?",
                (self.namespace, self.installation_id, _principal(admission.principal))).fetchone()
            if (type(registration) is not OwnerCredentialRegistrationV1
                    or registration.installation_id != self.installation_id
                    or (registration.credential_id, registration.credential_epoch) != (
                        admission.target_credential_id, admission.target_credential_epoch)
                    or key != (registration.credential_id, registration.credential_epoch, registration.public_key)
                    or db.execute("SELECT 1 FROM authority_owner_session_revoked_keys_v1 WHERE authority_namespace=? "
                        "AND installation_id=? AND principal_json=? AND credential_id=? AND credential_epoch=?",
                        (self.namespace, self.installation_id, _principal(admission.principal),
                         registration.credential_id, registration.credential_epoch)).fetchone() is not None):
                continue
            actor_binding = source.require_current_actor_in_tx(db, authority_namespace=self.namespace,
                installation_id=self.installation_id, actor_id=admission.target_actor_id,
                principal=admission.principal)
            if actor_binding.revision != admission.target_actor_revision:
                continue
            current.append(admission)
        if len(current) != 1:
            raise AuthorityUnavailable("background target requires one current signed-admission original")
        return D12CurrentOwnerAuthorityV1(head.guard, current[0])

    def require_exact_operation_status_in_tx_v1(self, db, *, original, source_request,
            expected_owner_head, actor, token, request):
        """A freshly admitted target Owner may read only its exact migration."""
        if db is not self.core._db or not db.in_transaction:
            raise AuthorityUnavailable("target status needs the existing Core transaction")
        actor_binding = self._current_session(db, actor=actor, token=token, request=request)
        if request.principal != source_request.principal:
            raise AuthorityUnavailable("target status principal differs from original Owner")
        row = self.core._row(db, self.namespace)
        if row[0] != self.holder or row[2] != "active" or row[3] is not None:
            raise AuthorityUnavailable("target status installation is no longer current")
        history = self._current_transfer(db, generation=row[1])
        head = self.tickets.current_migration_head_in_tx(db, authority_namespace=self.namespace)
        if (original.kind != "transfer_execution" or original.namespace != self.namespace_id
                or original.result.transfer_id != history.plan.transfer_id
                or head is None or head.state != "active"
                or head.guard.authorization_head != expected_owner_head
                or head.grant_digest != original.owner_grant_digest
                or head.issue_operation.principal != request.principal):
            raise AuthorityUnavailable("exact target migration status identity changed")
        matches = []
        for (encoded,) in db.execute("SELECT original_json FROM authority_d12_target_owner_admissions_v1 "
                "WHERE authority_namespace=? AND target_installation_id=?", (self.namespace, self.installation_id)):
            admission = target_admission_from_wire_v1(json.loads(encoded))
            if (admission.transfer_id == original.result.transfer_id
                    and admission.source_owner_guard == head.guard
                    and admission.target_actor_id == actor
                    and admission.target_actor_revision == actor_binding.revision
                    and admission.principal == request.principal
                    and admission.target_credential_id == request.credential_id
                    and admission.target_credential_epoch == request.credential_epoch
                    and admission.activation_generation == row[1]
                    and admission.revocation_epoch == row[5]):
                matches.append(admission)
        if len(matches) != 1:
            raise AuthorityUnavailable("target session lacks its current durable admission original")
        return matches[0]


def require_target_owner_graph_binding_v1(admission, *, authority, principal, grant,
        proof, metadata, installation_id, holder, guard=None):
    """Pure W01 comparison, only after its installed current Authority RPC.

    This helper does not independently authorize an arbitrary DTO. W01 must
    obtain it from get_current_owner_authority_for_fence_v1 for this exact permit
    and revalidate that same current admission at the normal final boundary.
    """
    if (type(admission) is not D12TargetOwnerAdmissionV1
            or admission.namespace != authority.namespace or admission.principal != principal
            or admission.target_actor_id != authority.actor
            or admission.target_installation_id != installation_id or admission.target_holder != holder
            or admission.activation_generation != authority.activation_generation
            or admission.activation_generation != metadata.requirements.activation_generation
            or admission.graph_incarnation != metadata.requirements.graph_incarnation
            or admission.revocation_epoch != metadata.requirements.revocation_epoch
            or admission.authority_namespace != metadata.requirements.authority_namespace
            or admission.source_grant_ref != owner_grant_key(*authority.namespace.as_tuple).token
            or admission.source_grant_digest != digest(grant)
            or admission.source_grant_revision != proof.grant_revision
            or admission.source_grant_digest != proof.grant_digest
            or admission.principal != principal or grant["principal"] != asdict(principal)
            or admission.source_owner_guard.authorization_head != owner_contract_digest(proof)
            or guard is not None and admission.source_owner_guard != guard):
        raise AuthorityUnavailable("current target Owner admission does not qualify this graph binding")
    return admission


__all__ = ("D12TargetOwnerAdmissionV1", "D12CurrentOwnerAuthorityV1",
           "InstalledD12TargetOwnerAdmissionServiceV1", "target_admission_from_wire_v1",
           "require_target_owner_graph_binding_v1")
