"""Service-owned, single-namespace v2 execution append substrate.

Only an installer-owned service may construct this object or call append_once.
PendingMutationV2 is a shape and identity record, not authorization: this
module cannot authenticate a subject, verify a footprint, or commit an
Authority head. The service must first persist the matching pending fence.

One SQLite file is one v2 journal and one namespace. Legacy/mixed schemas are
rejected. With WAL and synchronous=FULL, a successful SQLite commit syncs the
append before append_once returns. The chain detects accidental alteration;
freshness against a fully rewritten file still requires the external Authority.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
import threading

from .contract import AuthorityUnavailable, JournalHead, identifier
from .v2_contract import (
    PendingMutationV2, canonical_bytes, decode_bytes, to_wire,
)
from .internal_work_contract import (
    InternalWorkBindingV1, InternalWorkClaimV1, InternalWorkTerminalV1,
    InternalWorkTerminalV2,
    claim_internal_work_v1, terminal_internal_work_v1,
)
from .erasure_closure_redaction_v3 import (
    execution_row_commitment_v3, read_execution_redaction_seal_at_path,
    require_no_execution_redaction_at_path,
)


_VERSION = "2"
_INTERNAL_SCHEMA = "sylanne3.internal_work.journal_entry.v1"
_INTERNAL_V2_SCHEMA = "sylanne3.internal_work.journal_entry.v2"
_CORE_SEAL_SOURCE_SCHEMA = "sylanne3.execution.core_redaction_source.v1"
_CORE_SEAL_SOURCE_KEY = "core_redaction_source"
_META_DDL = "CREATE TABLE authority_v2_execution_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT"
_ENTRY_DDL = """CREATE TABLE authority_v2_execution_entries(
    seq INTEGER PRIMARY KEY CHECK(seq > 0),
    mutation_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL,
    append_id TEXT NOT NULL UNIQUE,
    pending BLOB NOT NULL,
    previous_digest TEXT NOT NULL,
    chain_digest TEXT NOT NULL
) STRICT"""
_UPDATE_DDL = """CREATE TRIGGER authority_v2_execution_no_update
BEFORE UPDATE ON authority_v2_execution_entries
BEGIN SELECT RAISE(ABORT,'append-only'); END"""
_DELETE_DDL = """CREATE TRIGGER authority_v2_execution_no_delete
BEFORE DELETE ON authority_v2_execution_entries
BEGIN SELECT RAISE(ABORT,'append-only'); END"""
_PREFIX_DDL_V4_LEGACY = """CREATE TABLE authority_v2_execution_redacted_prefix_v4(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    authority_id TEXT NOT NULL, namespace TEXT NOT NULL,
    operation_id TEXT NOT NULL, old_journal_id TEXT NOT NULL,
    old_seq INTEGER NOT NULL CHECK(old_seq>0), old_digest TEXT NOT NULL,
    facts_pin_digest TEXT NOT NULL, graph_issue_digest TEXT NOT NULL,
    new_journal_id TEXT NOT NULL
) STRICT"""
_PREFIX_DDL_V4 = _PREFIX_DDL_V4_LEGACY.replace("CHECK(old_seq>0)", "CHECK(old_seq>=0)")
_PREFIX_UPDATE_DDL_V4 = """CREATE TRIGGER authority_v2_execution_redacted_prefix_v4_no_update
BEFORE UPDATE ON authority_v2_execution_redacted_prefix_v4
BEGIN SELECT RAISE(ABORT,'redacted prefix immutable'); END"""
_PREFIX_DELETE_DDL_V4 = """CREATE TRIGGER authority_v2_execution_redacted_prefix_v4_no_delete
BEFORE DELETE ON authority_v2_execution_redacted_prefix_v4
BEGIN SELECT RAISE(ABORT,'redacted prefix immutable'); END"""
_OBJECTS = {
    ("table", "authority_v2_execution_meta"): _META_DDL,
    ("table", "authority_v2_execution_entries"): _ENTRY_DDL,
    ("trigger", "authority_v2_execution_no_update"): _UPDATE_DDL,
    ("trigger", "authority_v2_execution_no_delete"): _DELETE_DDL,
}
_OBJECTS_V4 = {**_OBJECTS,
    ("table", "authority_v2_execution_redacted_prefix_v4"): _PREFIX_DDL_V4,
    ("trigger", "authority_v2_execution_redacted_prefix_v4_no_update"):
        _PREFIX_UPDATE_DDL_V4,
    ("trigger", "authority_v2_execution_redacted_prefix_v4_no_delete"):
        _PREFIX_DELETE_DDL_V4,
}
_OBJECTS_V4_LEGACY = {**_OBJECTS_V4,
    ("table", "authority_v2_execution_redacted_prefix_v4"): _PREFIX_DDL_V4_LEGACY}


@dataclass(frozen=True, slots=True)
class VerifiedAppendV2:
    journal_id: str
    namespace: str
    seq: int
    mutation_id: str
    request_digest: str
    append_id: str
    chain_digest: str


@dataclass(frozen=True, slots=True)
class ExpectedAppendInspectionV2:
    """0, 1, or >1 rows after the pending before-head; never a commit decision."""

    following_count: int
    first_append: VerifiedAppendV2 | None
    verified_head: JournalHead


class AuthorityV2ExecutionJournal:
    def __init__(self, path, *, namespace: str, journal_id: str, create: bool = False,
                 _redaction_core=None, _redaction_credential=None,
                 installed_storage_reader=None, selected_storage=None, storage_context=None, maintenance_basis=None):
        identifier(namespace, "namespace")
        identifier(journal_id, "journal_id")
        self._maintenance_seal_digest: str | None = None
        self._maintenance_depth = 0
        self._installed_storage_reader = installed_storage_reader
        self._storage_context = None
        if installed_storage_reader is not None:
            from .c09_storage_control_v1 import InstalledC09StorageReaderV1
            if not isinstance(installed_storage_reader, InstalledC09StorageReaderV1) or create:
                raise AuthorityUnavailable("installed C09 journal reader required")
            context = (storage_context if selected_storage is not None or maintenance_basis is not None
                else installed_storage_reader.read_verified_current_storage_v1())
            member = next(m for m in context.manifest["members"] if m["role"] == "execution")
            if (member["resolved_path"], member["incarnation_or_journal_id"], member["namespace"]) != (str(Path(path).resolve()), journal_id, namespace):
                raise AuthorityUnavailable("journal outside current C09 manifest")
            self._storage_context = context
        if _redaction_core is not None:
            from .core import AuthorityServiceCore
            from .erasure_closure_redaction_v3 import (
                read_execution_redaction_seal_locked,
            )

            if (type(_redaction_core) is not AuthorityServiceCore or create):
                raise AuthorityUnavailable("installer Core required for redaction cold open")
            _redaction_core._require(
                _redaction_credential, "execution_redaction_install", namespace)
            with _redaction_core._tx() as db:
                seal = read_execution_redaction_seal_locked(db, namespace)
                if (seal is None or seal.authority_id != _redaction_core._id(db)
                        or seal.execution_journal_id != journal_id):
                    raise AuthorityUnavailable("current PREPARED Core seal required")
                self._maintenance_seal_digest = seal.seal_digest
                self._maintenance_core_path = _redaction_core.path.resolve()
                self._maintenance_authority_id = seal.authority_id
                self._maintenance_depth = 1
        elif _redaction_credential is not None:
            raise AuthorityUnavailable("redaction credential needs installed Core")
        self.path = Path(path)
        if not create and not self.path.is_file():
            raise AuthorityUnavailable("v2 execution journal is absent")
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.namespace = namespace
        self.journal_id = journal_id
        self._lock = threading.RLock()
        self._guard_owner: int | None = None
        self._db = sqlite3.connect(self.path, isolation_level=None,
                                   check_same_thread=False, timeout=5)
        try:
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA busy_timeout=5000")
            mode = self._db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            self._db.execute("PRAGMA synchronous=FULL")
            if (mode.lower() != "wal"
                    or self._db.execute("PRAGMA synchronous").fetchone()[0] < 2):
                raise AuthorityUnavailable("v2 execution journal lacks FULL WAL durability")
            self._runtime_storage_v3 = None
            if selected_storage is not None and maintenance_basis is not None:
                raise AuthorityUnavailable("business selection and maintenance basis are mutually exclusive")
            if maintenance_basis is not None:
                from ..runtime_storage_v3 import install_selected_maintenance_storage_v3
                from .daemon import _bootstrap_control_quantum_v3
                with _bootstrap_control_quantum_v3(maintenance_basis.basis.control):
                    self._runtime_storage_v3 = install_selected_maintenance_storage_v3(
                        self._db,role="execution",basis=maintenance_basis)
                return
            elif selected_storage is not None:
                from ..runtime_storage_v3 import install_selected_runtime_storage_v3
                self._runtime_storage_v3 = install_selected_runtime_storage_v3(
                    self._db,role="execution",selected=selected_storage,context=storage_context)
                return
            with self._transaction():
                existing = self._objects()
                if not existing:
                    if not create:
                        raise AuthorityUnavailable("v2 execution schema is absent")
                    for ddl in _OBJECTS.values():
                        self._db.execute(ddl)
                    self._db.executemany(
                        "INSERT INTO authority_v2_execution_meta(key,value) VALUES(?,?)",
                        (("schema_version", _VERSION), ("namespace", namespace),
                         ("journal_id", journal_id)),
                    )
                self._check_schema()
                head, rows = self._scan_locked()
                if self._maintenance_seal_digest is not None:
                    self._check_prepared_rows(head, rows)
        except BaseException:
            self._db.close()
            self._db = None
            raise
        finally:
            self._maintenance_depth = 0

    @classmethod
    def open_prepared_redaction_v3(
            cls, path, *, namespace: str, journal_id: str, core, credential):
        """Installer-only cold open for building/verifying a sanitized sidecar."""
        return cls(
            path, namespace=namespace, journal_id=journal_id,
            _redaction_core=core, _redaction_credential=credential)

    def _objects(self) -> dict[tuple[str, str], str]:
        return {(kind, name): ddl for kind, name, ddl in self._db.execute(
            "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}

    def _check_schema(self) -> None:
        selected = getattr(self,'_c09_selected_journal_proof_v3',None)
        if selected is not None:
            from .c09_graph_application_v1 import SelectedC09JournalProofV3
            from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
            if type(selected) is not SelectedC09JournalProofV3:
                raise AuthorityUnavailable('actual private selected execution schema proof required')
            return selected.require_schema_locked(self,'execution',meter=current_c09_sql_meter_v2())
        objects = self._objects()
        if objects not in (_OBJECTS, _OBJECTS_V4, _OBJECTS_V4_LEGACY):
            raise AuthorityUnavailable("legacy, mixed or malformed v2 execution schema")
        meta = dict(self._db.execute("SELECT key,value FROM authority_v2_execution_meta"))
        expected = {"schema_version": meta.get("schema_version"),
                    "namespace": self.namespace,
                    "journal_id": self.journal_id}
        if _CORE_SEAL_SOURCE_KEY in meta:
            expected[_CORE_SEAL_SOURCE_KEY] = meta[_CORE_SEAL_SOURCE_KEY]
        if (meta.get("schema_version") not in ("1", _VERSION, "4")
                or (meta["schema_version"] == "4") != (objects in (_OBJECTS_V4, _OBJECTS_V4_LEGACY))
                or meta != expected):
            raise AuthorityUnavailable("v2 execution schema/version/namespace mismatch")
        if meta["schema_version"] == "4":
            prefix = self._db.execute(
                "SELECT authority_id,namespace,operation_id,old_journal_id,"
                "old_seq,old_digest,facts_pin_digest,graph_issue_digest,new_journal_id "
                "FROM authority_v2_execution_redacted_prefix_v4 WHERE singleton=1"
            ).fetchone()
            if (prefix is None or self._db.execute(
                    "SELECT COUNT(*) FROM authority_v2_execution_redacted_prefix_v4"
                    ).fetchone() != (1,)
                    or prefix[1] != self.namespace or prefix[8] != self.journal_id
                    or prefix[3] == self.journal_id
                    or type(prefix[4]) is not int or prefix[4] < 0):
                raise AuthorityUnavailable("V4 redacted execution prefix differs")
            for index in (0, 2, 3, 8):
                identifier(prefix[index], "redacted_prefix_identity")
            for index in (5, 6, 7):
                value = prefix[index]
                if index == 5 and prefix[4] == 0 and value == "genesis":
                    continue
                if (type(value) is not str or len(value) != 64 + (7 if index == 5 else 0)
                        or (index == 5 and not value.startswith("sha256:"))
                        or any(ch not in "0123456789abcdef" for ch in
                               value.removeprefix("sha256:"))):
                    raise AuthorityUnavailable("V4 redacted execution digest differs")
            if self._installed_storage_reader is None:
                raise AuthorityUnavailable("V4 execution cold open requires installed storage transition")
            self._require_current_storage_v1(action="maintenance")
            original = self._storage_context.prepared_original
            head = None if original is None else original["old_execution_head_original"]
            pin = None if original is None else original["facts_pin_original"]
            if (original is None or original["authority_id"] != prefix[0]
                    or original["namespace"] != prefix[1] or original["operation_id"] != prefix[2]
                    or (head["journal_id"],head["seq"],head["digest"]) != tuple(prefix[3:6])
                    or pin["pin_digest"] != prefix[6]
                    or original["graph_issue_original"]["issue_digest"] != prefix[7]):
                raise AuthorityUnavailable("V4 prefix differs from authenticated current transition")
        if _CORE_SEAL_SOURCE_KEY in meta:
            source = self._decode_core_seal_source(meta[_CORE_SEAL_SOURCE_KEY])
            if self._maintenance_depth:
                if (self._maintenance_seal_digest is None
                        or Path(source["core_path"]) != self._maintenance_core_path):
                    raise AuthorityUnavailable("execution maintenance Core source differs")
                seal = read_execution_redaction_seal_at_path(
                    self._maintenance_core_path, namespace=self.namespace,
                    authority_id=source["authority_id"])
                if (seal.seal_digest != self._maintenance_seal_digest
                        or seal.execution_journal_id != self.journal_id):
                    raise AuthorityUnavailable("execution maintenance seal differs")
            elif self._installed_storage_reader is not None:
                self._require_current_storage_v1(action="maintenance")
                core_member = next(m for m in self._storage_context.manifest["members"] if m["role"] == "core")
                if source["core_path"] != core_member["resolved_path"] or source["authority_id"] != self._storage_context.manifest["authority_id"]:
                    raise AuthorityUnavailable("V4 current Core seal bridge differs")
            else:
                require_no_execution_redaction_at_path(
                    Path(source["core_path"]), namespace=self.namespace,
                    authority_id=source["authority_id"])
        elif self._maintenance_depth:
            raise AuthorityUnavailable("execution maintenance Core link absent")
        self._schema_version = meta["schema_version"]

    def _require_current_storage_v1(self, *, action):
        reader = self._installed_storage_reader
        if reader is None or self._storage_context is None:
            raise AuthorityUnavailable("installed execution generation verifier unavailable")
        context = reader.read_verified_current_storage_v1(verify_files=False)
        if (context.pointer_version,context.manifest_digest) != (self._storage_context.pointer_version,self._storage_context.manifest_digest):
            raise AuthorityUnavailable("old execution process generation revoked")
        context.require_current(action)
        member = next(m for m in context.manifest["members"] if m["role"] == "execution")
        reader.verify_member_v1(member,prepared=False)
        self._storage_context = context

    def _check_prepared_rows(self, head: JournalHead, rows: list[tuple]) -> None:
        if self._maintenance_seal_digest is None:
            raise AuthorityUnavailable("installer maintenance seal is absent")
        seal = read_execution_redaction_seal_at_path(
            self._maintenance_core_path, namespace=self.namespace,
            authority_id=self._maintenance_authority_id)
        if (seal.seal_digest != self._maintenance_seal_digest
                or (seal.execution_journal_id, seal.execution_seq,
                    seal.execution_digest) != (
                        head.journal_id, head.seq, head.digest)
                or tuple(execution_row_commitment_v3(self, row)
                         for row in rows) != seal.rows):
            raise AuthorityUnavailable("PREPARED execution rows differ from Core seal")

    @contextmanager
    def freeze_prepared_redaction_v3(self):
        """Return full old rows only to the installer maintenance path."""
        if self._maintenance_seal_digest is None:
            raise AuthorityUnavailable("installer maintenance journal required")
        with self._transaction():
            self._maintenance_depth = 1
            try:
                self._check_schema()
                head, rows = self._scan_locked()
                self._check_prepared_rows(head, rows)
                yield tuple(rows)
            finally:
                self._maintenance_depth = 0

    def _decode_core_seal_source(self, encoded: str) -> dict[str, str]:
        try:
            source = json.loads(encoded)
            if (type(source) is not dict or set(source) != {
                    "schema", "core_path", "authority_id",
                    "namespace", "journal_id"}
                    or source["schema"] != _CORE_SEAL_SOURCE_SCHEMA
                    or source["namespace"] != self.namespace
                    or source["journal_id"] != self.journal_id
                    or type(source["core_path"]) is not str
                    or not Path(source["core_path"]).is_absolute()
                    or str(Path(source["core_path"]).resolve()) != source["core_path"]
                    or type(source["authority_id"]) is not str
                    or json.dumps(source, sort_keys=True, separators=(",", ":"))
                       != encoded):
                raise ValueError("Core seal source differs")
            identifier(source["authority_id"], "authority_id")
            return source
        except (TypeError, ValueError, KeyError) as exc:
            raise AuthorityUnavailable("execution Core seal source malformed") from exc

    def install_core_redaction_source(
            self, *, core_path: Path, authority_id: str) -> None:
        """Persist the Core lookup before any Core PREPARED seal can commit.

        This adds only a metadata link. It does not change any journal entry
        or chain head. A crash after this step leaves an ordinary linked v2
        journal; a crash after the Core seal blocks all old v2 entrances.
        """
        identifier(authority_id, "authority_id")
        resolved = Path(core_path).resolve()
        source = {
            "schema": _CORE_SEAL_SOURCE_SCHEMA, "core_path": str(resolved),
            "authority_id": authority_id, "namespace": self.namespace,
            "journal_id": self.journal_id,
        }
        encoded = json.dumps(source, sort_keys=True, separators=(",", ":"))
        with self._transaction():
            self._check_schema()
            self._scan_locked()
            require_no_execution_redaction_at_path(
                resolved, namespace=self.namespace, authority_id=authority_id)
            previous = self._db.execute(
                "SELECT value FROM authority_v2_execution_meta WHERE key=?",
                (_CORE_SEAL_SOURCE_KEY,)).fetchone()
            if previous is None:
                self._db.execute(
                    "INSERT INTO authority_v2_execution_meta(key,value) VALUES(?,?)",
                    (_CORE_SEAL_SOURCE_KEY, encoded))
            elif previous != (encoded,):
                raise AuthorityUnavailable("execution Core seal source conflicts")

    def require_core_redaction_source(
            self, *, core_path: Path, authority_id: str) -> None:
        """Check the durable link while the service holds the writer guard."""
        if self._guard_owner != threading.get_ident():
            raise AuthorityUnavailable("execution Core seal check requires frozen writer")
        row = self._db.execute(
            "SELECT value FROM authority_v2_execution_meta WHERE key=?",
            (_CORE_SEAL_SOURCE_KEY,)).fetchone()
        if row is None:
            raise AuthorityUnavailable("execution Core seal source is absent")
        source = self._decode_core_seal_source(row[0])
        if (source["core_path"] != str(Path(core_path).resolve())
                or source["authority_id"] != authority_id):
            raise AuthorityUnavailable("execution Core seal source differs")

    @contextmanager
    def _transaction(self):
        with self._lock:
            if self._db is None or self._db.in_transaction:
                raise AuthorityUnavailable("v2 execution journal transaction unavailable")
            try:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    yield
                    self._db.execute("COMMIT")
                except BaseException:
                    self._db.execute("ROLLBACK")
                    raise
            except sqlite3.Error as exc:
                raise AuthorityUnavailable("v2 execution journal SQLite failure") from exc

    @contextmanager
    def freeze_writes(self):
        """Hold the sole writer across inspect_expected and an Authority CAS.

        The caller must release this guard before waiting for a graph lock or
        invoking any business callback. No append may run inside this guard.
        """
        with self._transaction():
            self._guard_owner = threading.get_ident()
            try:
                self._check_schema()
                yield self
            finally:
                self._guard_owner = None

    @staticmethod
    def _material(pending: PendingMutationV2, seq: int, previous: str,
                  journal_id: str) -> bytes:
        shape = to_wire(pending)
        shape.pop("expected_append_digest")  # The digest cannot contain itself.
        return json.dumps({
            "journal_id": journal_id, "seq": seq,
            "previous_digest": previous, "pending": shape,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8")

    @classmethod
    def expected_digest(cls, pending: PendingMutationV2) -> str:
        """Preview a chain digest; this neither authorizes nor appends."""
        if type(pending) is not PendingMutationV2:
            raise TypeError("PendingMutationV2 required")
        return "sha256:" + hashlib.sha256(cls._material(
            pending, pending.expected_execution_seq,
            pending.before_anchor.execution_digest,
            pending.expected_execution_journal_id,
        )).hexdigest()

    def _require_pending(self, pending: PendingMutationV2) -> None:
        if self._installed_storage_reader is not None:
            self._require_current_storage_v1(action="business")
            self._installed_storage_reader.require_unconsumed_identity_v1(
                namespace=self.namespace,identities=(("execution_id",pending.permit.effect_id),
                    ("journal_mutation",pending.mutation_id),("journal_append",pending.expected_append_id)))
        if type(pending) is not PendingMutationV2:
            raise AuthorityUnavailable("PendingMutationV2 required")
        if pending.phase not in ("prepared", "claimed", "observed"):
            raise AuthorityUnavailable("execution journal phase is not implemented")
        if (pending.permit.namespace != self.namespace
                or pending.expected_execution_journal_id != self.journal_id):
            raise AuthorityUnavailable("pending namespace or journal mismatch")
        if pending.expected_append_digest != self.expected_digest(pending):
            raise AuthorityUnavailable("pending expected digest does not match canonical append")

    @staticmethod
    def _append_from_row(row, journal_id: str, namespace: str) -> VerifiedAppendV2:
        return VerifiedAppendV2(journal_id, namespace, row[0], row[1], row[2],
                                row[3], row[6])

    def _internal_bytes(self, *, phase: str, binding: InternalWorkBindingV1,
                        claim: InternalWorkClaimV1,
                        terminal: InternalWorkTerminalV1 | InternalWorkTerminalV2 | None,
                        sequence: int, previous_digest: str) -> bytes:
        return encode_internal_original_bytes_v1(self.journal_id, phase=phase, binding=binding, claim=claim, terminal=terminal, sequence=sequence, previous_digest=previous_digest)

    def _decode_internal_row(self, row):
        return decode_internal_original_row_v1(self, row)

    def _scan_locked(self) -> tuple[JournalHead, list[tuple]]:
        return scan_execution_original_rows_v1(self)

    def verified_head(self) -> JournalHead:
        """Recompute the full chain; a current Authority anchor remains required."""
        if self._guard_owner == threading.get_ident():
            self._check_schema()
            return self._scan_locked()[0]
        with self._transaction():
            self._check_schema()
            return self._scan_locked()[0]

    def inspect_expected(self, pending: PendingMutationV2) -> ExpectedAppendInspectionV2:
        """Inspect while freeze_writes is held; never repair or append here."""
        if self._guard_owner != threading.get_ident():
            raise AuthorityUnavailable("inspect_expected requires frozen journal writer")
        self._check_schema()
        self._require_pending(pending)
        head, rows = self._scan_locked()
        before = pending.before_anchor
        if (before.execution_seq > head.seq
                or (before.execution_seq and rows[before.execution_seq - 1][6]
                    != before.execution_digest)
                or (before.execution_seq == 0 and before.execution_digest != "genesis")):
            raise AuthorityUnavailable("pending before-head is absent or differs")
        following = head.seq - before.execution_seq
        first = None
        if following:
            row = rows[before.execution_seq]
            if row[4] != canonical_bytes(pending):
                raise AuthorityUnavailable("first append differs from pending mutation")
            first = self._append_from_row(row, self.journal_id, self.namespace)
        return ExpectedAppendInspectionV2(following, first, head)

    def _internal_append_receipt(self, row, binding: InternalWorkBindingV1,
                                 phase: str):
        return internal_original_append_receipt_v1(self.journal_id, row, binding, phase)

    def _append_internal_work_locked(
        self, *, phase: str, binding: InternalWorkBindingV1,
        claim: InternalWorkClaimV1,
        terminal: InternalWorkTerminalV1 | InternalWorkTerminalV2 | None,
        before_head: JournalHead,
    ):
        if self._installed_storage_reader is not None:
            self._require_current_storage_v1(action="business")
            self._installed_storage_reader.require_unconsumed_identity_v1(
                namespace=self.namespace,identities=(("execution_id",binding.execution_id),
                    ("internal_operation",binding.operation_id)))
        if self._guard_owner != threading.get_ident():
            raise AuthorityUnavailable("internal work append requires frozen journal writer")
        self._check_schema()
        if self._schema_version not in ("2", "4"):
            raise AuthorityUnavailable("internal work requires explicit execution schema v2")
        if (type(binding) is not InternalWorkBindingV1 or
                binding.namespace != self.namespace or
                claim != claim_internal_work_v1(binding) or
                (phase == "claim") != (terminal is None) or
                type(before_head) is not JournalHead or
                before_head.journal_id != self.journal_id):
            raise AuthorityUnavailable("internal work append identity differs")
        if terminal is not None and (
                type(terminal) not in (InternalWorkTerminalV1, InternalWorkTerminalV2) or
                terminal.binding_digest != binding.binding_digest or
                terminal.claim_mutation_id != claim.mutation_id):
            raise AuthorityUnavailable("internal work terminal differs from claim")
        head, rows = self._scan_locked()
        mutation = claim.mutation_id if terminal is None else terminal.mutation_id
        existing = next((row for row in rows if row[1] == mutation), None)
        if existing is not None:
            encoded = self._internal_bytes(
                phase=phase, binding=binding, claim=claim, terminal=terminal,
                sequence=existing[0], previous_digest=existing[5])
            if (existing[4] != encoded or before_head !=
                    JournalHead(self.journal_id, existing[0] - 1, existing[5])):
                raise AuthorityUnavailable("internal work mutation ID was reused")
            return self._internal_append_receipt(existing, binding, phase)
        if head != before_head:
            raise AuthorityUnavailable("internal work execution before-head differs")
        if phase == "terminal":
            original = next((row for row in rows if row[1] == claim.mutation_id), None)
            if original is None or self._decode_internal_row(original)[:2] != (binding, claim):
                raise AuthorityUnavailable("internal work terminal lacks durable claim")
        encoded = self._internal_bytes(
            phase=phase, binding=binding, claim=claim, terminal=terminal,
            sequence=head.seq + 1, previous_digest=head.digest)
        content = claim if terminal is None else terminal
        content_digest = hashlib.sha256(json.dumps(
            asdict(content), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
        try:
            self._db.execute(
                "INSERT INTO authority_v2_execution_entries "
                "(seq,mutation_id,request_digest,append_id,pending,previous_digest,chain_digest) "
                "VALUES(?,?,?,?,?,?,?)",
                (head.seq + 1, mutation, content_digest, mutation,
                 encoded, head.digest, digest),
            )
        except sqlite3.IntegrityError as exc:
            raise AuthorityUnavailable("internal work append identity already bound") from exc
        row = (head.seq + 1, mutation, content_digest, mutation,
               encoded, head.digest, digest)
        return self._internal_append_receipt(row, binding, phase)

    def append_internal_work_claim_v1(
        self, binding: InternalWorkBindingV1, claim: InternalWorkClaimV1,
        before_head: JournalHead,
    ):
        """Append only under the service's frozen-writer and Core pending check."""
        return self._append_internal_work_locked(
            phase="claim", binding=binding, claim=claim, terminal=None,
            before_head=before_head)

    def append_internal_work_terminal_v1(
        self, binding: InternalWorkBindingV1, claim: InternalWorkClaimV1,
        terminal: InternalWorkTerminalV1 | InternalWorkTerminalV2,
        before_head: JournalHead,
    ):
        """Append one observed or explicit unknown terminal after durable claim."""
        return self._append_internal_work_locked(
            phase="terminal", binding=binding, claim=claim, terminal=terminal,
            before_head=before_head)

    def read_internal_work_v1(self, binding: InternalWorkBindingV1):
        """Full-chain same-file reread, including claim-only unknown recovery."""
        from .internal_work_service import InternalWorkJournalInspectionV1

        if type(binding) is not InternalWorkBindingV1 or binding.namespace != self.namespace:
            raise AuthorityUnavailable("internal work read namespace differs")

        def read_locked():
            self._check_schema()
            head, rows = self._scan_locked()
            claim = terminal = claim_append = terminal_append = None
            expected_claim = claim_internal_work_v1(binding)
            expected_ids = {
                expected_claim.mutation_id,
                terminal_internal_work_v1(
                    binding, expected_claim, status="unknown").mutation_id,
            }
            for row in rows:
                if row[1] not in expected_ids:
                    continue
                observed_binding, observed_claim, observed_terminal = (
                    self._decode_internal_row(row))
                if observed_binding != binding:
                    raise AuthorityUnavailable("internal work original binding differs")
                if observed_terminal is None:
                    claim = observed_claim
                    claim_append = self._internal_append_receipt(row, binding, "claim")
                else:
                    terminal = observed_terminal
                    terminal_append = self._internal_append_receipt(row, binding, "terminal")
            return InternalWorkJournalInspectionV1(
                binding, claim, terminal, claim_append, terminal_append, head)

        if self._guard_owner == threading.get_ident():
            return read_locked()
        with self.freeze_writes():
            return read_locked()

    def verified_predecessor_head(self, sequence: int) -> JournalHead:
        """Return an exact historical head from the fully verified current chain."""
        if type(sequence) is not int or sequence < 1:
            raise AuthorityUnavailable("execution predecessor sequence is invalid")

        def read_locked():
            self._check_schema()
            head, rows = self._scan_locked()
            if sequence > head.seq:
                raise AuthorityUnavailable("execution predecessor is absent")
            return JournalHead(
                self.journal_id, sequence - 1,
                "genesis" if sequence == 1 else rows[sequence - 2][6])

        if self._guard_owner == threading.get_ident():
            return read_locked()
        with self.freeze_writes():
            return read_locked()

    def _append_locked(self, pending: PendingMutationV2) -> VerifiedAppendV2:
        self._require_pending(pending)
        self._check_schema()
        head, _ = self._scan_locked()
        existing = self._db.execute(
            "SELECT seq,mutation_id,request_digest,append_id,pending,previous_digest,chain_digest "
            "FROM authority_v2_execution_entries WHERE mutation_id=?",
            (pending.mutation_id,),
        ).fetchone()
        if existing is not None:
            if (existing[4] != canonical_bytes(pending) or existing[0] != head.seq
                    or existing[5] != pending.before_anchor.execution_digest):
                raise AuthorityUnavailable("mutation ID reused or append no longer current")
            return self._append_from_row(existing, self.journal_id, self.namespace)
        if (head.seq != pending.before_anchor.execution_seq
                or head.digest != pending.before_anchor.execution_digest):
            raise AuthorityUnavailable("execution before-head differs")
        try:
            self._db.execute(
                "INSERT INTO authority_v2_execution_entries "
                "(seq,mutation_id,request_digest,append_id,pending,previous_digest,chain_digest) "
                "VALUES(?,?,?,?,?,?,?)",
                (pending.expected_execution_seq, pending.mutation_id,
                 pending.request_digest, pending.expected_append_id,
                 canonical_bytes(pending), head.digest,
                 pending.expected_append_digest),
            )
        except sqlite3.IntegrityError as exc:
            raise AuthorityUnavailable("append ID or sequence already bound") from exc
        return VerifiedAppendV2(
            self.journal_id, self.namespace, pending.expected_execution_seq,
            pending.mutation_id, pending.request_digest,
            pending.expected_append_id, pending.expected_append_digest,
        )

    def append_once_guarded(self, pending: PendingMutationV2) -> VerifiedAppendV2:
        """Service-internal append after Authority pending check under freeze_writes."""
        if self._guard_owner != threading.get_ident():
            raise AuthorityUnavailable("guarded append requires frozen journal writer")
        return self._append_locked(pending)

    def append_once(self, pending: PendingMutationV2) -> VerifiedAppendV2:
        """Journal-only append; callers must have persisted Authority pending."""
        with self._transaction():
            return self._append_locked(pending)

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                runtime=getattr(self,"_runtime_storage_v3",None)
                if runtime is not None:runtime.close()
                self._db.close()
                self._db = None


__all__ = ["AuthorityV2ExecutionJournal", "ExpectedAppendInspectionV2",
           "VerifiedAppendV2"]


def scan_execution_original_rows_v1(reader):
    """Shared full structural walk over an actual journal or qualified SQL reader."""
    from .c09_execution_connection_v1 import C09ExecutionOriginalsConnectionV1
    if (type(reader) not in {AuthorityV2ExecutionJournal, C09ExecutionOriginalsConnectionV1}
            or not reader._db.in_transaction):
        raise AuthorityUnavailable("execution scan requires actual pinned journal connection")
    previous = "genesis"
    claims: dict[str, InternalWorkBindingV1] = {}
    terminals: set[str] = set()
    numeric_claims = {}
    numeric_terminals = set()
    series_claims = {}
    series_terminals = set()
    root_claims = {}
    root_terminals = set()
    life_claims = {}
    life_terminals = set()
    offline_claims = {}
    offline_terminals = set()
    rows = list(reader._db.execute(
        "SELECT seq,mutation_id,request_digest,append_id,pending,previous_digest,chain_digest "
        "FROM authority_v2_execution_entries ORDER BY seq"))
    for expected_seq, row in enumerate(rows, 1):
        seq, mutation_id, request_digest, append_id, encoded, prev, digest = row
        from .d04_series_journal_v1 import ENTRY_PREFIX as SERIES_PREFIX, decode_series_row_v1
        if reader._schema_version in ("2", "4") and encoded.startswith(SERIES_PREFIX):
            if seq != expected_seq or prev != previous:
                raise AuthorityUnavailable("D04 series execution chain is discontinuous")
            binding, claim, measurement = decode_series_row_v1(reader, row)
            key = claim.claim_id
            if measurement is None:
                if key in series_claims:
                    raise AuthorityUnavailable("duplicate D04 series execution claim")
                series_claims[key] = (binding, claim)
            elif series_claims.get(key) != (binding, claim) or key in series_terminals:
                raise AuthorityUnavailable("D04 series terminal lacks its exact original claim")
            else:
                series_terminals.add(key)
            previous = digest
            continue
        from .d11_life_journal_v1 import ENTRY_PREFIX as LIFE_PREFIX, decode_life_row_v1
        if reader._schema_version in ("2", "4") and encoded.startswith(LIFE_PREFIX):
            if seq != expected_seq or prev != previous:
                raise AuthorityUnavailable("life execution chain is discontinuous")
            binding, claim, terminal = decode_life_row_v1(reader, row)
            key = claim.claim_id
            if terminal is None:
                if key in life_claims:
                    raise AuthorityUnavailable("duplicate life execution claim")
                life_claims[key] = (binding, claim)
            elif life_claims.get(key) != (binding, claim) or key in life_terminals:
                raise AuthorityUnavailable("life terminal lacks its exact unique claim")
            else:
                life_terminals.add(key)
            previous = digest
            continue
        from .d11_offline_tick_journal_v1 import ENTRY_PREFIX as OFFLINE_PREFIX, decode_offline_tick_row_v1
        if reader._schema_version in ("2", "4") and encoded.startswith(OFFLINE_PREFIX):
            if seq != expected_seq or prev != previous:
                raise AuthorityUnavailable("offline tick execution chain is discontinuous")
            binding, claim, terminal = decode_offline_tick_row_v1(reader, row)
            key = claim.claim_id
            if terminal is None:
                if key in offline_claims:
                    raise AuthorityUnavailable("duplicate offline tick claim")
                offline_claims[key] = (binding, claim)
            elif offline_claims.get(key) != (binding, claim) or key in offline_terminals:
                raise AuthorityUnavailable("offline terminal lacks its exact unique claim")
            else:
                offline_terminals.add(key)
            previous = digest
            continue
        from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3, decode_root_execution_row_v3
        if reader._schema_version in ("2", "4") and encoded.startswith(ROOT_ENTRY_PREFIX_V3):
            if seq != expected_seq or prev != previous:
                raise AuthorityUnavailable("D04 authored-root execution chain is discontinuous")
            binding, claim, measurement = decode_root_execution_row_v3(reader, row)
            key = claim.claim_id
            if measurement is None:
                if key in root_claims:
                    raise AuthorityUnavailable("duplicate authored-root execution claim")
                root_claims[key] = (binding, claim)
            elif root_claims.get(key) != (binding, claim) or key in root_terminals:
                raise AuthorityUnavailable("authored-root terminal lacks its exact original claim")
            else:
                root_terminals.add(key)
            previous = digest
            continue
        from .d04_numeric_journal_v3 import ENTRY_PREFIX, decode_numeric_row_v3
        if reader._schema_version in ("2", "4") and encoded.startswith(ENTRY_PREFIX):
            if seq != expected_seq or prev != previous:
                raise AuthorityUnavailable("D04 numeric execution chain is discontinuous")
            binding, claim, measurement = decode_numeric_row_v3(reader, row)
            key = claim.claim_id
            if measurement is None:
                if key in numeric_claims:
                    raise AuthorityUnavailable("duplicate D04 numeric execution claim")
                numeric_claims[key] = (binding, claim)
            elif numeric_claims.get(key) != (binding, claim) or key in numeric_terminals:
                raise AuthorityUnavailable("D04 numeric terminal lacks its original claim")
            else:
                numeric_terminals.add(key)
            previous = digest
            continue
        if (reader._schema_version in ("2", "4") and
                encoded.startswith(b'{"binding":')):
            if seq != expected_seq or prev != previous:
                raise AuthorityUnavailable("internal work execution chain is discontinuous")
            binding, _claim, terminal = reader._decode_internal_row(row)
            key = binding.binding_digest
            if terminal is None:
                if key in claims:
                    raise AuthorityUnavailable("duplicate internal work claim")
                claims[key] = binding
            elif claims.get(key) != binding or key in terminals:
                raise AuthorityUnavailable("internal work terminal lacks original claim")
            else:
                terminals.add(key)
            previous = digest
            continue
        try:
            pending = decode_bytes(encoded)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise AuthorityUnavailable("malformed persisted execution pending") from exc
        if (type(pending) is not PendingMutationV2
                or pending.phase not in ("prepared", "claimed", "observed")
                or encoded != canonical_bytes(pending)
                or seq != expected_seq or prev != previous
                or (mutation_id, request_digest, append_id) != (
                    pending.mutation_id, pending.request_digest,
                    pending.expected_append_id)
                or pending.permit.namespace != reader.namespace
                or pending.expected_execution_journal_id != reader.journal_id
                or pending.before_anchor.execution_seq != seq - 1
                or pending.before_anchor.execution_digest != previous
                or pending.expected_append_digest != digest
                or reader.expected_digest(pending) != digest):
            raise AuthorityUnavailable("v2 execution chain or entry identity is invalid")
        previous = digest
    return JournalHead(reader.journal_id, len(rows), previous), rows


def encode_internal_original_bytes_v1(journal_id, *, phase, binding, claim, terminal, sequence, previous_digest):
    binding_shape = asdict(binding)
    if binding_shape["algorithm_build_digest"] is None:
        binding_shape.pop("algorithm_build_digest")
    return json.dumps({
        "schema": (_INTERNAL_V2_SCHEMA if type(terminal) is InternalWorkTerminalV2
                   else _INTERNAL_SCHEMA), "phase": phase,
        "journal_id": journal_id, "sequence": sequence,
        "previous_digest": previous_digest,
        "binding": binding_shape, "claim": asdict(claim),
        "terminal": asdict(terminal) if terminal is not None else None,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def decode_internal_original_row_v1(reader, row):
    try:
        body = json.loads(row[4])
        if (type(body) is not dict or set(body) != {
                "schema", "phase", "journal_id", "sequence", "previous_digest",
                "binding", "claim", "terminal"}
                or body["schema"] not in (_INTERNAL_SCHEMA, _INTERNAL_V2_SCHEMA)
                or body["phase"] not in ("claim", "terminal")
                or type(body["binding"]) is not dict
                or type(body["claim"]) is not dict):
            raise ValueError("internal work journal entry shape differs")
        binding = InternalWorkBindingV1(**body["binding"])
        claim = InternalWorkClaimV1(**body["claim"])
        terminal = (None if body["terminal"] is None else
                    (InternalWorkTerminalV2 if body["schema"] == _INTERNAL_V2_SCHEMA
                     else InternalWorkTerminalV1)(**body["terminal"]))
        if body["schema"] == _INTERNAL_V2_SCHEMA and type(terminal) is not InternalWorkTerminalV2:
            raise ValueError("v2 internal work entry needs v2 terminal")
        if (binding.namespace != reader.namespace or
                claim != claim_internal_work_v1(binding) or
                (body["phase"] == "claim") != (terminal is None) or
                (terminal is not None and (
                    terminal.binding_digest != binding.binding_digest or
                    terminal.claim_mutation_id != claim.mutation_id)) or
                body["journal_id"] != reader.journal_id or
                body["sequence"] != row[0] or
                body["previous_digest"] != row[5]):
            raise ValueError("internal work journal binding differs")
        mutation = claim.mutation_id if terminal is None else terminal.mutation_id
        content_digest = (hashlib.sha256(json.dumps(
            asdict(claim if terminal is None else terminal),
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode()).hexdigest())
        encoded = encode_internal_original_bytes_v1(reader.journal_id, 
            phase=body["phase"], binding=binding, claim=claim,
            terminal=terminal, sequence=row[0], previous_digest=row[5])
        digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
        if (row[1] != mutation or row[2] != content_digest or
                row[3] != mutation or row[4] != encoded or row[6] != digest):
            raise ValueError("internal work journal chain differs")
        return binding, claim, terminal
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise AuthorityUnavailable("malformed internal work execution entry") from exc


def internal_original_append_receipt_v1(journal_id, row, binding, phase):
    from .internal_work_service import InternalWorkJournalAppendV1

    return InternalWorkJournalAppendV1(
        binding.namespace, journal_id, row[0], row[1],
        binding.binding_digest, row[2], row[6],
        f"internal-work:{phase}:{binding.binding_digest}")
