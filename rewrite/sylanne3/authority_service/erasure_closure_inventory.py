"""Installer-owned C09 closure originals and one execution-payload inventory.

These records are observations, never cleanup-complete receipts. In particular
the v2 execution journal is immutable and its chain commits to the full pending
bytes; this module cannot redact those bytes or authorize a closed transition.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import re
import sqlite3

from ..runtime_contracts import canonical_digest, canonical_serialize
from .contract import AuthorityUnavailable, identifier
from .current_erasure_service import REQUIRED_CLEANUP_SURFACES
from .v2_contract import DeletionMutationReceiptV1, deletion_scope_digest
from .v2_scoped_erasure_store import AuthorityV2ScopedErasureStore


_HEX = re.compile(r"[0-9a-f]{64}\Z")
SURFACES_V1 = tuple(sorted(REQUIRED_CLEANUP_SURFACES))
_REGISTRY_SCHEMA = "sylanne3.authority.erasure_surface_registry.v1"
_RUN_SCHEMA = "sylanne3.authority.erasure_cleanup_run.v2"
_INVENTORY_SCHEMA = "sylanne3.authority.execution_payload_inventory.v1"
_DDL = (
    "CREATE TABLE authority_erasure_surface_registry_v1(namespace TEXT PRIMARY KEY, registry_json TEXT NOT NULL) STRICT",
    "CREATE TABLE authority_erasure_cleanup_runs_v1(operation_id TEXT PRIMARY KEY, namespace TEXT NOT NULL, run_json TEXT NOT NULL) STRICT",
    "CREATE TABLE authority_erasure_execution_inventory_v1(operation_id TEXT PRIMARY KEY, namespace TEXT NOT NULL, receipt_json TEXT NOT NULL) STRICT",
)
_TABLES = tuple(item.split("(", 1)[0].split()[2] for item in _DDL)


def _digest(value: str, name: str) -> None:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


@dataclass(frozen=True, slots=True)
class SurfaceTargetV1:
    surface: str
    resource_kind: str
    target_ref: str
    cleaner_version: str
    generation_ref: str
    inventory_state: str

    def __post_init__(self) -> None:
        if self.surface not in SURFACES_V1:
            raise ValueError("unknown C09 cleanup surface")
        for name in ("resource_kind", "cleaner_version", "generation_ref"):
            identifier(getattr(self, name), name)
        if (type(self.target_ref) is not str or not self.target_ref
                or len(self.target_ref) > 1024 or "\x00" in self.target_ref):
            raise ValueError("surface target reference is invalid")
        if self.inventory_state not in {"installed", "unresolved_hold"}:
            raise ValueError("surface inventory state cannot imply N/A")


@dataclass(frozen=True, slots=True)
class SurfaceRegistryV1:
    authority_id: str
    namespace: str
    installation_id: str
    surfaces: tuple[str, ...]
    targets: tuple[SurfaceTargetV1, ...]
    registry_digest: str
    schema: str = _REGISTRY_SCHEMA

    def __post_init__(self) -> None:
        for name in ("authority_id", "namespace", "installation_id"):
            identifier(getattr(self, name), name)
        if (self.schema != _REGISTRY_SCHEMA or self.surfaces != SURFACES_V1
                or type(self.targets) is not tuple
                or tuple(item.surface for item in self.targets) != SURFACES_V1
                or any(type(item) is not SurfaceTargetV1
                       for item in self.targets)):
            raise ValueError("C09 surface registry is not the fixed installed set")
        _digest(self.registry_digest, "registry_digest")
        if self.registry_digest != canonical_digest((
                self.schema, self.authority_id, self.namespace,
                self.installation_id, self.surfaces, self.targets)):
            raise ValueError("C09 registry digest differs")


@dataclass(frozen=True, slots=True)
class CleanupRunV2:
    authority_id: str
    namespace: str
    operation_id: str
    accepted_mutation_id: str
    accepted_receipt_digest: str
    scope_digest: str
    graph_barrier_receipt_digest: str
    barrier_scope_digest: str
    registry_digest: str
    execution_journal_id: str
    execution_seq: int
    execution_digest: str
    run_digest: str
    status: str = "inventory_open_hold"
    schema: str = _RUN_SCHEMA

    def __post_init__(self) -> None:
        for name in ("authority_id", "namespace", "operation_id",
                     "accepted_mutation_id", "execution_journal_id"):
            identifier(getattr(self, name), name)
        for name in ("accepted_receipt_digest", "scope_digest",
                     "graph_barrier_receipt_digest", "barrier_scope_digest",
                     "registry_digest", "run_digest"):
            _digest(getattr(self, name), name)
        if (self.schema != _RUN_SCHEMA or self.status != "inventory_open_hold"
                or type(self.execution_seq) is not int
                or self.execution_seq < 0):
            raise ValueError("C09 cleanup run shape differs")
        if self.execution_digest != "genesis":
            identifier(self.execution_digest, "execution_digest")
        if self.run_digest != canonical_digest((
                self.schema, self.authority_id, self.namespace,
                self.operation_id, self.accepted_mutation_id,
                self.accepted_receipt_digest, self.scope_digest,
                self.graph_barrier_receipt_digest, self.barrier_scope_digest,
                self.registry_digest, self.execution_journal_id,
                self.execution_seq, self.execution_digest, self.status)):
            raise ValueError("C09 cleanup run digest differs")


@dataclass(frozen=True, slots=True)
class ExecutionPayloadInventoryV1:
    namespace: str
    operation_id: str
    run_digest: str
    execution_journal_id: str
    execution_seq: int
    execution_digest: str
    entry_count: int
    entries_digest: str
    receipt_digest: str
    status: str = "inventory_only_hold"
    schema: str = _INVENTORY_SCHEMA

    def __post_init__(self) -> None:
        identifier(self.namespace, "namespace")
        identifier(self.operation_id, "operation_id")
        identifier(self.execution_journal_id, "execution_journal_id")
        for name in ("run_digest", "entries_digest", "receipt_digest"):
            _digest(getattr(self, name), name)
        if (self.schema != _INVENTORY_SCHEMA or self.status != "inventory_only_hold"
                or type(self.execution_seq) is not int or self.execution_seq < 0
                or type(self.entry_count) is not int or self.entry_count < 0):
            raise ValueError("execution payload inventory cannot claim cleanup")
        if self.execution_digest != "genesis":
            identifier(self.execution_digest, "execution_digest")
        if self.entry_count != self.execution_seq:
            raise ValueError("execution payload inventory misses journal entries")
        if self.receipt_digest != canonical_digest((
                self.schema, self.namespace, self.operation_id,
                self.run_digest, self.execution_journal_id,
                self.execution_seq, self.execution_digest,
                self.entry_count, self.entries_digest, self.status)):
            raise ValueError("execution payload inventory receipt digest differs")


class AuthorityErasureClosureInventory:
    """Paired Core/independent-journal writer; no public close capability."""

    def __init__(self, *, scoped: AuthorityV2ScopedErasureStore,
                 installation_id: str):
        if type(scoped) is not AuthorityV2ScopedErasureStore:
            raise AuthorityUnavailable("paired scoped erasure service required")
        identifier(installation_id, "installation_id")
        self.scoped = scoped
        self.core = scoped.core
        self.execution = scoped.execution
        self.deletion = scoped.deletion
        self.namespace = scoped.namespace
        self.installation_id = installation_id
        import threading
        self.current_source_location = None
        self._registry_location = threading.local()

    def install_current_source_location_v1(self, qualifier):
        from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
        if (type(qualifier) is not InstalledCurrentSourceLocationQualifierV1
                or qualifier._scoped is not self.scoped or qualifier.core is not self.core
                or qualifier.installation_id != self.installation_id
                or self.current_source_location is not None):
            raise AuthorityUnavailable("one exact installed registry location qualifier required")
        self.current_source_location = qualifier

    def qualify_current_registry_location_v1(self, *, credential, subject,
                                             operation_id=None, accepted_mutation_id=None):
        """Observe before caller SQL/freezes; the immutable registry is retained."""
        qualifier = self.current_source_location
        if qualifier is None:
            return None  # The original exact path/JID check still applies.
        with self.core._tx() as db:
            original = self._read_record(db, _TABLES[0], self.namespace, SurfaceRegistryV1)
            if original is not None:
                target = original.targets[SURFACES_V1.index("execution_journal_payloads")]
                if (target.target_ref, target.generation_ref) == (str(self.execution.path.resolve()), self.execution.journal_id):
                    return None  # Preserve existing exact-location sealed replay.
        if accepted_mutation_id is None:
            if operation_id is None:raise AuthorityUnavailable("exact accepted cleanup selector required")
            with self.core._tx() as db:
                run = self._read_record(db, _TABLES[1], operation_id, CleanupRunV2)
                if run is None:raise AuthorityUnavailable("actual cleanup run absent")
                accepted_mutation_id = run.accepted_mutation_id
        value = qualifier.observe_accepted_erasure_location_v1(credential=credential,
            subject=subject, accepted_mutation_id=accepted_mutation_id)
        if operation_id is not None and value.accepted_receipt.pending.deletion_operation_id != operation_id:
            raise AuthorityUnavailable("registry location belongs to another cleanup operation")
        self._registry_location.observation = value
        return value

    @staticmethod
    def _install_schema(db) -> None:
        for ddl in _DDL:
            db.execute(ddl.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
        for table in _TABLES:
            for action in ("UPDATE", "DELETE"):
                db.execute(
                    f"CREATE TRIGGER IF NOT EXISTS {table}_{action.lower()}_immutable "
                    f"BEFORE {action} ON {table} "
                    "BEGIN SELECT RAISE(ABORT,'C09 closure original immutable'); END")

    @staticmethod
    def _require_schema(db) -> None:
        for table in _TABLES:
            cols = tuple(row[1] for row in db.execute(f"PRAGMA table_info({table})"))
            expected = (("namespace", "registry_json") if table == _TABLES[0]
                        else ("operation_id", "namespace", "run_json")
                        if table == _TABLES[1]
                        else ("operation_id", "namespace", "receipt_json"))
            triggers = {row[0]: row[1] for row in db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                "AND tbl_name=?", (table,))}
            if (cols != expected or set(triggers) != {
                    f"{table}_update_immutable", f"{table}_delete_immutable"}
                    or any("RAISE(ABORT,'C09 closure original immutable')"
                           not in sql for sql in triggers.values())):
                raise AuthorityUnavailable("C09 closure immutable schema differs")

    @staticmethod
    def _read_record(db, table: str, key: str, cls):
        if table not in _TABLES:
            raise AuthorityUnavailable("unknown C09 closure original table")
        column = "namespace" if cls is SurfaceRegistryV1 else "operation_id"
        try:
            row = db.execute(
                f"SELECT namespace,{('registry_json' if cls is SurfaceRegistryV1 else 'run_json' if cls is CleanupRunV2 else 'receipt_json')} "
                f"FROM {table} WHERE {column}=?", (key,)).fetchone()
        except sqlite3.Error as exc:
            raise AuthorityUnavailable("C09 closure original schema unavailable") from exc
        if row is None:
            return None
        import json
        try:
            raw = json.loads(row[1])
            if cls is SurfaceRegistryV1:
                raw["surfaces"] = tuple(raw["surfaces"])
                raw["targets"] = tuple(SurfaceTargetV1(**item)
                                       for item in raw["targets"])
            record = cls(**raw)
        except (TypeError, ValueError, KeyError) as exc:
            raise AuthorityUnavailable("C09 closure original is malformed") from exc
        if row[0] != record.namespace or canonical_serialize(asdict(record)) != row[1]:
            raise AuthorityUnavailable("C09 closure original bytes differ")
        return record

    def _registry_locked(self, db) -> SurfaceRegistryV1:
        self._require_schema(db)
        record = self._read_record(
            db, _TABLES[0], self.namespace, SurfaceRegistryV1)
        if (record is None or record.installation_id != self.installation_id
                or record.authority_id != self.core._id(db)):
            raise AuthorityUnavailable("installed C09 surface registry unavailable")
        target = record.targets[SURFACES_V1.index("execution_journal_payloads")]
        if target.resource_kind != "sqlite_execution_journal" or target.inventory_state != "installed":
            raise AuthorityUnavailable("execution journal installation changed")
        if (target.target_ref, target.generation_ref) != (str(self.execution.path.resolve()), self.execution.journal_id):
            qualifier = self.current_source_location
            observation = getattr(self._registry_location, "observation", None)
            if qualifier is None or observation is None:
                raise AuthorityUnavailable("execution journal successor has no installed observation")
            qualifier.require_registry_target_in_tx_v1(db, observation,
                target_ref=target.target_ref, generation_ref=target.generation_ref)
        return record

    def install_registry(self, *, credential,
                         targets: tuple[SurfaceTargetV1, ...]) -> SurfaceRegistryV1:
        """Install the fixed twelve-surface manifest under installer authority."""
        self.core._require(credential, "erasure_closure_install", self.namespace)
        if (type(targets) is not tuple or len(targets) != len(SURFACES_V1)
                or any(type(item) is not SurfaceTargetV1 for item in targets)
                or tuple(item.surface for item in targets) != SURFACES_V1):
            raise AuthorityUnavailable("installer must inventory all C09 surfaces")
        execution_target = targets[SURFACES_V1.index("execution_journal_payloads")]
        if (execution_target.resource_kind != "sqlite_execution_journal"
                or execution_target.target_ref != str(self.execution.path.resolve())
                or execution_target.generation_ref != self.execution.journal_id
                or execution_target.inventory_state != "installed"):
            raise AuthorityUnavailable("installed execution journal target differs")
        with self.core._tx() as db:
            self._install_schema(db)
            self._require_schema(db)
            authority_id = self.core._id(db)
            digest = canonical_digest((
                _REGISTRY_SCHEMA, authority_id, self.namespace,
                self.installation_id, SURFACES_V1, targets))
            record = SurfaceRegistryV1(
                authority_id, self.namespace, self.installation_id,
                SURFACES_V1, targets, digest)
            prior = self._read_record(
                db, _TABLES[0], self.namespace, SurfaceRegistryV1)
            if prior is not None:
                if prior != record:
                    raise AuthorityUnavailable("installed C09 registry differs")
                return prior
            db.execute(
                f"INSERT INTO {_TABLES[0]} VALUES(?,?)",
                (self.namespace, canonical_serialize(asdict(record))))
            return record

    def _accepted_locked(self, db, run: CleanupRunV2,
                         subject: str) -> DeletionMutationReceiptV1:
        state = self.scoped.state_locked(db)
        row = self.scoped.fences.mutation_locked(db, run.accepted_mutation_id)
        if row is None or row[1:3] != (self.namespace, subject):
            raise AuthorityUnavailable("accepted deletion original is absent")
        kind, pending, receipt, original_permit = self.scoped.fences._decode_mutation_row(row)
        current = self.core._row(db, self.namespace)
        if (kind != "deletion" or type(receipt) is not DeletionMutationReceiptV1
                or receipt.pending != pending
                or (pending.source_phase, pending.target_phase) !=
                   ("pending", "accepted")
                or pending.evidence.issuer_id not in {"authority-pinned-graph-barrier-v1","authority-pinned-graph-barrier-v2"}
                or pending.deletion_operation_id != run.operation_id
                or canonical_digest(receipt) != run.accepted_receipt_digest
                or pending.evidence.scope_digest.removeprefix("sha256:")
                   != run.scope_digest
                or pending.evidence.proof_digest.removeprefix("sha256:")
                   != run.graph_barrier_receipt_digest
                or pending.evidence.barrier_scope_digest is None
                or pending.evidence.barrier_scope_digest.removeprefix("sha256:")
                   != run.barrier_scope_digest
                or state.active_operation_id != run.operation_id
                or state.aggregate_phase != "accepted" or state.closed_seq is not None
                or current[9] != "accepted"):
            raise AuthorityUnavailable("current accepted C09 cleanup run differs")
        current_anchor = self.core._anchor(db, self.namespace, current)
        if current_anchor != receipt.after_anchor:
            fence = self.scoped.fences._row(db, pending.permit.operation_id)
            if fence is None or fence[6] != "active":
                raise AuthorityUnavailable("current accepted deletion fence is absent")
            self.scoped.fences.verify_current_deletion_bridge_locked(
                db, core=self.core, receipt=receipt, original_permit=original_permit,
                current_anchor=current_anchor,
                current_permit=self.scoped.fences._permit(fence))
        return receipt

    def begin_run(self, *, credential, subject: str,
                  accepted_mutation_id: str) -> CleanupRunV2:
        """Persist one content-free original from the live accepted phase."""
        identifier(subject, "subject")
        identifier(accepted_mutation_id, "accepted_mutation_id")
        self.core._require(credential, "deletion", self.namespace)
        self.qualify_current_registry_location_v1(credential=credential, subject=subject,
            accepted_mutation_id=accepted_mutation_id)
        receipt = self.scoped.read_ancestor_receipt(
            credential=credential, subject=subject,
            mutation_id=accepted_mutation_id)
        pending = receipt.pending
        if (pending.source_phase, pending.target_phase) != ("pending", "accepted"):
            raise AuthorityUnavailable("accepted deletion receipt required")
        with self.deletion.freeze_writes():
            with self.execution.freeze_writes():
                head = self.execution.verified_head()
                with self.core._tx() as db:
                    registry = self._registry_locked(db)
                    scope = deletion_scope_digest(
                        pending.closure_roots, pending.deletion_epoch,
                        pending.policy_ref).removeprefix("sha256:")
                    shape = (receipt.after_anchor.authority_id, self.namespace,
                             pending.deletion_operation_id, accepted_mutation_id,
                             canonical_digest(receipt), scope,
                             pending.evidence.proof_digest.removeprefix("sha256:"),
                             pending.evidence.barrier_scope_digest.removeprefix("sha256:"),
                             registry.registry_digest, head.journal_id,
                             head.seq, head.digest)
                    run = CleanupRunV2(
                        *shape, canonical_digest((
                            _RUN_SCHEMA, *shape, "inventory_open_hold")))
                    self._accepted_locked(db, run, subject)
                    if (receipt.after_anchor.execution_journal_id,
                            receipt.after_anchor.execution_seq,
                            receipt.after_anchor.execution_digest) != (
                            head.journal_id, head.seq, head.digest):
                        raise AuthorityUnavailable("execution journal differs from accepted head")
                    prior = self._read_record(
                        db, _TABLES[1], run.operation_id, CleanupRunV2)
                    if prior is not None:
                        if prior != run:
                            raise AuthorityUnavailable("cleanup run replay differs")
                        return prior
                    db.execute(
                        f"INSERT INTO {_TABLES[1]} VALUES(?,?,?)",
                        (run.operation_id, self.namespace,
                         canonical_serialize(asdict(run))))
                    return run

    def _inventory_locked(self, db, run: CleanupRunV2,
                          subject: str) -> ExecutionPayloadInventoryV1:
        self._accepted_locked(db, run, subject)
        head, rows = self.execution._scan_locked()
        if (head.journal_id, head.seq, head.digest) != (
                run.execution_journal_id, run.execution_seq,
                run.execution_digest):
            raise AuthorityUnavailable("execution payload inventory became stale")
        entries = tuple((row[0], row[1], row[2], row[3], row[5], row[6],
                         len(row[4]), hashlib.sha256(row[4]).hexdigest())
                        for row in rows)
        entries_digest = canonical_digest(entries)
        shape = (self.namespace, run.operation_id, run.run_digest,
                 head.journal_id, head.seq, head.digest, len(rows), entries_digest)
        return ExecutionPayloadInventoryV1(
            *shape, canonical_digest((
                _INVENTORY_SCHEMA, *shape, "inventory_only_hold")))

    def issue_execution_payload_inventory(
            self, *, credential, subject: str, operation_id: str,
    ) -> ExecutionPayloadInventoryV1:
        """Read the real immutable journal and persist a non-success receipt."""
        identifier(subject, "subject")
        identifier(operation_id, "operation_id")
        self.core._require(credential, "deletion", self.namespace)
        self.qualify_current_registry_location_v1(credential=credential, subject=subject,
            operation_id=operation_id)
        with self.deletion.freeze_writes():
            with self.execution.freeze_writes():
                with self.core._tx() as db:
                    self._registry_locked(db)
                    run = self._read_record(
                        db, _TABLES[1], operation_id, CleanupRunV2)
                    if run is None:
                        raise AuthorityUnavailable("cleanup run original absent")
                    receipt = self._inventory_locked(db, run, subject)
                    prior = self._read_record(
                        db, _TABLES[2], operation_id,
                        ExecutionPayloadInventoryV1)
                    if prior is not None:
                        if prior != receipt:
                            raise AuthorityUnavailable("execution inventory replay differs")
                        return prior
                    db.execute(
                        f"INSERT INTO {_TABLES[2]} VALUES(?,?,?)",
                        (operation_id, self.namespace,
                         canonical_serialize(asdict(receipt))))
                    return receipt

    def read_execution_payload_inventory(
            self, *, credential, subject: str, operation_id: str,
    ) -> ExecutionPayloadInventoryV1:
        """Independently recompute the journal inventory from durable originals."""
        identifier(subject, "subject")
        identifier(operation_id, "operation_id")
        self.core._require(credential, "deletion", self.namespace)
        self.qualify_current_registry_location_v1(credential=credential, subject=subject,
            operation_id=operation_id)
        with self.deletion.freeze_writes():
            with self.execution.freeze_writes():
                with self.core._tx() as db:
                    self._registry_locked(db)
                    run = self._read_record(
                        db, _TABLES[1], operation_id, CleanupRunV2)
                    receipt = self._read_record(
                        db, _TABLES[2], operation_id,
                        ExecutionPayloadInventoryV1)
                    if run is None or receipt is None:
                        raise AuthorityUnavailable("durable execution inventory absent")
                    if receipt != self._inventory_locked(db, run, subject):
                        raise AuthorityUnavailable("execution inventory differs from journal")
                    return receipt


__all__ = ["SURFACES_V1", "SurfaceTargetV1", "SurfaceRegistryV1", "CleanupRunV2",
           "ExecutionPayloadInventoryV1", "AuthorityErasureClosureInventory"]
