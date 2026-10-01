"""Installed, signed, single-pointer C09 storage control journal.

Only this installation journal selects the four running files. Every mutation
requires the live OS lease, and every durable row is independently authenticated
against the installed key. No business backup may contain this journal or key.
"""
from __future__ import annotations

from contextlib import contextmanager, closing
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import threading

from .contract import AuthorityUnavailable, identifier

SURFACES = frozenset({"graph_current_history", "graph_dependency_history",
    "source_derived_caches", "retrieval_indexes", "process_local_caches",
    "model_prompt_caches", "jobs_drafts", "experiments_diagnostics",
    "imports_exports", "execution_journal_payloads", "sqlite_wal_free_pages",
    "controlled_backups"})
ROLES = ("core", "deletion", "execution", "graph")
STAGES = ("INTENT", "PREPARED", "SWITCHED", "CLEANED", "RELEASED")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _hex(value, name):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise AuthorityUnavailable("invalid C09 " + name)


def _installed_path(path, *, exists=True):
    candidate = Path(path)
    if not candidate.is_absolute():
        raise AuthorityUnavailable("C09 path must be absolute")
    for part in (candidate, *candidate.parents):
        if part.exists() and (part.is_symlink() or getattr(part, "is_junction", lambda: False)()):
            raise AuthorityUnavailable("C09 reparse path refused: " + str(part))
    resolved = candidate.resolve(strict=exists)
    if str(resolved) != str(candidate):
        raise AuthorityUnavailable("C09 unresolved path")
    return resolved


def _regular_path(path, *, exists=True):
    resolved = _installed_path(path, exists=exists)
    if exists and not resolved.is_file():
        raise AuthorityUnavailable("C09 regular file required")
    return resolved


def _directory_path(path):
    resolved = _installed_path(path)
    if not resolved.is_dir():
        raise AuthorityUnavailable("C09 registered directory required")
    return resolved


def file_identity_v1(path):
    return file_observation_v1(path, fingerprint=False)


def file_observation_v1(path, *, exclusive=False, fingerprint=True):
    """Read identity, final path and hash from the same OS file handle."""
    path = _regular_path(path)
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        import msvcrt
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        class Info(ctypes.Structure):
            _fields_ = [("attributes", wintypes.DWORD), ("creation", wintypes.FILETIME),
                ("access", wintypes.FILETIME), ("write", wintypes.FILETIME),
                ("volume", wintypes.DWORD), ("size_hi", wintypes.DWORD),
                ("size_lo", wintypes.DWORD), ("links", wintypes.DWORD),
                ("id_hi", wintypes.DWORD), ("id_lo", wintypes.DWORD)]
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(Info)]
        kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR,
                                                   wintypes.DWORD, wintypes.DWORD]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.CreateFileW(str(path), 0x80000000, 0 if exclusive else 3,
                                    None, 3, 0x00200000, None)
        if handle == wintypes.HANDLE(-1).value:
            raise AuthorityUnavailable("C09 file handle unavailable: " + str(path))
        info, final = Info(), ctypes.create_unicode_buffer(32768)
        if (not kernel.GetFileInformationByHandle(handle, ctypes.byref(info))
                or not kernel.GetFinalPathNameByHandleW(handle, final, len(final), 0)):
            kernel.CloseHandle(handle)
            raise AuthorityUnavailable("C09 file identity unavailable")
        normalized = final.value
        if normalized.startswith("\\\\?\\UNC\\"):
            normalized = "\\\\" + normalized[8:]
        elif normalized.startswith("\\\\?\\"):
            normalized = normalized[4:]
        if os.path.normcase(normalized) != os.path.normcase(str(path)) or info.attributes & 0x400:
            kernel.CloseHandle(handle)
            raise AuthorityUnavailable("C09 opened file final path changed")
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        device, file_id = info.volume, (info.id_hi << 32) | info.id_lo
    else:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        if exclusive:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stat = os.fstat(descriptor)
        device, file_id = stat.st_dev, stat.st_ino
    with os.fdopen(descriptor, "rb") as stream:
        if not fingerprint:
            return dict(resolved_path=str(path), device=device, file_id=file_id)
        before = os.fstat(stream.fileno())
        hasher = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise AuthorityUnavailable("C09 file changed during fingerprint")
    return dict(resolved_path=str(path), device=device, file_id=file_id,
                prepared_size=before.st_size, prepared_mtime_ns=before.st_mtime_ns,
                prepared_sha256=hasher.hexdigest())


class InstalledC09InstanceLeaseV1:
    """A held lock handle, never evidence inferred from a lock filename."""
    def __init__(self, path):
        self.path = _regular_path(path, exists=False)
        self._continuation_lock=threading.RLock()
        self._continuation_thread=None
        self._owner = os.getpid()
        self._stream = self.path.open("a+b")
        self._stream.seek(0)
        if self._stream.read(1) == b"":
            self._stream.write(b"\0")
            self._stream.flush()
        self._stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self._stream.close()
            raise AuthorityUnavailable("C09 installation OS lock unavailable")

    def require_held(self):
        if self._owner != os.getpid() or self._stream.closed:
            raise AuthorityUnavailable("C09 installation OS lease expired")
        held = os.fstat(self._stream.fileno())
        current = _regular_path(self.path).stat()
        if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
            raise AuthorityUnavailable("C09 installation lock inode replaced")

    def __enter__(self):
        self.require_held()
        return self

    def __exit__(self, *exc):
        self.close()

    @contextmanager
    def hold_continuation_v3(self):
        with self._continuation_lock:
            self.require_held()
            if self._continuation_thread is not None:
                raise AuthorityUnavailable("C09 lease continuation is already active")
            self._continuation_thread=threading.get_ident()
            try:yield self
            finally:self._continuation_thread=None

    def close(self):
        with self._continuation_lock:
            if self._continuation_thread is not None:
                raise AuthorityUnavailable("C09 lease cannot close during final continuation")
            if not self._stream.closed:
                if os.name == "nt":
                    import msvcrt
                    self._stream.seek(0)
                    msvcrt.locking(self._stream.fileno(), msvcrt.LK_UNLCK, 1)
                self._stream.close()


_DDL = {
"c09_storage_meta_v1": """CREATE TABLE c09_storage_meta_v1(key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT""",
"c09_storage_manifests_v1": """CREATE TABLE c09_storage_manifests_v1(
 manifest_digest TEXT PRIMARY KEY, installation_id TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>=0),
 manifest_json TEXT NOT NULL, issuer_id TEXT NOT NULL, key_id TEXT NOT NULL, signature TEXT NOT NULL,
 UNIQUE(installation_id,generation)) STRICT""",
"c09_storage_operations_v1": """CREATE TABLE c09_storage_operations_v1(
 operation_id TEXT PRIMARY KEY, installation_id TEXT NOT NULL, namespace TEXT NOT NULL,
 generation INTEGER NOT NULL CHECK(generation>0), expected_pointer_version INTEGER NOT NULL CHECK(expected_pointer_version>=0),
 old_manifest_digest TEXT NOT NULL REFERENCES c09_storage_manifests_v1(manifest_digest),
 new_manifest_digest TEXT NOT NULL REFERENCES c09_storage_manifests_v1(manifest_digest),
 prepared_original_json TEXT NOT NULL, prepared_digest TEXT NOT NULL UNIQUE, key_id TEXT NOT NULL, signature TEXT NOT NULL) STRICT""",
"c09_storage_events_v1": """CREATE TABLE c09_storage_events_v1(
 installation_id TEXT NOT NULL, event_seq INTEGER NOT NULL CHECK(event_seq>0), operation_id TEXT NOT NULL,
 stage TEXT NOT NULL CHECK(stage IN ('INTENT','PREPARED','SWITCHED','CLEANED','RELEASED')),
 prior_event_digest TEXT NOT NULL, event_json TEXT NOT NULL, event_digest TEXT NOT NULL UNIQUE,
 key_id TEXT NOT NULL, signature TEXT NOT NULL, PRIMARY KEY(installation_id,event_seq), UNIQUE(operation_id,stage)) STRICT""",
"c09_storage_current_v1": """CREATE TABLE c09_storage_current_v1(
 installation_id TEXT PRIMARY KEY, pointer_version INTEGER NOT NULL CHECK(pointer_version>=0),
 current_manifest_digest TEXT NOT NULL REFERENCES c09_storage_manifests_v1(manifest_digest),
 active_operation_id TEXT, stage TEXT NOT NULL CHECK(stage IN ('READY','INTENT','PREPARED','SWITCHED','CLEANED','RELEASED')),
 last_event_seq INTEGER NOT NULL CHECK(last_event_seq>=0), last_event_digest TEXT NOT NULL,
 deletion_watermark INTEGER NOT NULL CHECK(deletion_watermark>=0), cumulative_tombstone_root TEXT NOT NULL) STRICT""",
"c09_storage_surface_evidence_v1": """CREATE TABLE c09_storage_surface_evidence_v1(
 operation_id TEXT NOT NULL REFERENCES c09_storage_operations_v1(operation_id), surface TEXT NOT NULL,
 evidence_json TEXT NOT NULL, evidence_digest TEXT NOT NULL UNIQUE, issuer_id TEXT NOT NULL,
 key_id TEXT NOT NULL, signature TEXT NOT NULL, PRIMARY KEY(operation_id,surface)) STRICT""",
"c09_storage_retired_files_v1": """CREATE TABLE c09_storage_retired_files_v1(
 installation_id TEXT NOT NULL, resource_id TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>=0),
 resolved_path TEXT NOT NULL, file_identity_json TEXT NOT NULL, content_sha256 TEXT NOT NULL,
 retirement_event_digest TEXT NOT NULL REFERENCES c09_storage_events_v1(event_digest),
 PRIMARY KEY(installation_id,resource_id,generation,resolved_path)) STRICT"""}

_MANIFEST_FIELDS = frozenset("schema authority_id installation_id cohort_namespaces generation prior_manifest_digest members inventory_manifest_digest certificate_digest graph_issue_digest recovery_pin_digest cumulative_tombstone_root deletion_watermark manifest_digest".split())
_MEMBER_FIELDS = frozenset("role resolved_path store_id schema_version namespace storage_generation incarnation_or_journal_id device file_id prepared_size prepared_mtime_ns prepared_sha256 logical_data_root schema_objects_digest cold_read_digest wal_policy companion_resource_ids".split())
_PREPARED_FIELDS = frozenset("schema authority_id installation_id namespace operation_id maintenance_generation expected_pointer_version old_manifest_digest new_manifest_digest prior_prepared_digest accepted_receipt_original barrier_receipt_original accepted_receipt_digest barrier_receipt_digest old_core_anchor_original new_core_anchor_original anchor_transition_original old_deletion_head_original old_execution_head_original old_graph_head_original facts_pin_original facts_digest recovery_bindings_digest graph_certificate_original graph_issue_original frozen_inventory_original frozen_scan_digest writer_quiescence_original source_final_fingerprints four_candidate_disposition_roots four_candidate_cold_reads cumulative_tombstone_root deletion_watermark component_verifier_hashes prepared_digest key_id signature".split())
_BUILD_TABLE = "c09_storage_build_originals_v1"
_BUILD_DDL = """CREATE TABLE c09_storage_build_originals_v1(
 installation_id TEXT NOT NULL, operation_id TEXT NOT NULL, original_kind TEXT NOT NULL,
 original_json TEXT NOT NULL, original_digest TEXT NOT NULL UNIQUE,
 PRIMARY KEY(installation_id,operation_id,original_kind)) STRICT"""


@dataclass(frozen=True, slots=True)
class VerifiedStorageOpenContextV1:
    control_path: str
    pointer_version: int
    manifest_digest: str
    storage_generation: int
    stage: str
    manifest: dict
    prepared_original: dict | None
    _reader: object
    _capability: object

    def require_current(self, action="maintenance"):
        self._reader.require_context_v1(self, action=action)


class InstalledC09StorageReaderV1:
    def __init__(self, *, control_path, key_path, installation_id, authority_id,
                 control_store_id, key_id, lease, resource_roots):
        if type(lease) is not InstalledC09InstanceLeaseV1:
            raise AuthorityUnavailable("installed C09 OS lease required")
        for value, name in ((installation_id, "installation_id"), (authority_id, "authority_id"),
                            (control_store_id, "control_store_id"), (key_id, "key_id")):
            identifier(value, name)
        self.path = _regular_path(control_path, exists=False)
        self.key_path = _regular_path(key_path)
        self._key = self.key_path.read_bytes()
        if len(self._key) < 32:
            raise AuthorityUnavailable("installed C09 key unavailable")
        self.installation_id, self.authority_id = installation_id, authority_id
        self.control_store_id, self.key_id, self.lease = control_store_id, key_id, lease
        self._roots = tuple(Path(p).resolve(strict=True) for p in resource_roots)
        if not self._roots or any(self.path.is_relative_to(p) or self.key_path.is_relative_to(p) for p in self._roots):
            raise AuthorityUnavailable("protected control/key must be outside business resources")
        self._capability, self._lock = object(), threading.RLock()
        self._applied_reader = None

    def install_applied_reader_v1(self, reader):
        if self._applied_reader is not None or not callable(getattr(reader, "read_storage_applied_original_v1", None)):
            raise AuthorityUnavailable("installed applied reader unavailable/already bound")
        self._applied_reader = reader

    def sign_original_v1(self, schema, body, digest_field):
        if body.get("schema") != schema:
            raise AuthorityUnavailable("C09 signing domain differs")
        unsigned = {k: v for k, v in body.items() if k not in {digest_field, "signature"}}
        unsigned["key_id"] = self.key_id
        committed = digest(unsigned)
        return {**unsigned, digest_field: committed, "signature": hmac.new(
            self._key, (schema + "\n" + committed).encode(), hashlib.sha256).hexdigest()}

    def verify_original_v1(self, original, digest_field):
        body = {k: v for k, v in original.items() if k not in {digest_field, "signature"}}
        committed = digest(body)
        if original.get("key_id") != self.key_id or original.get(digest_field) != committed:
            raise AuthorityUnavailable("C09 original digest/key differs")
        expected = hmac.new(self._key, (original["schema"] + "\n" + committed).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, original.get("signature", "")):
            raise AuthorityUnavailable("C09 installed signature differs")

    def _manifest(self, manifest):
        if set(manifest) != _MANIFEST_FIELDS or manifest["schema"] != "sylanne3.c09.storage_manifest.v1":
            raise AuthorityUnavailable("C09 manifest fields/schema differ")
        if (manifest["authority_id"], manifest["installation_id"]) != (self.authority_id, self.installation_id):
            raise AuthorityUnavailable("C09 manifest installation differs")
        if len(manifest["cohort_namespaces"]) != 1:
            raise AuthorityUnavailable("unsupported_storage_cohort")
        if manifest["manifest_digest"] != digest({k:v for k,v in manifest.items() if k != "manifest_digest"}):
            raise AuthorityUnavailable("C09 manifest digest differs")
        members = manifest["members"]
        if tuple(m["role"] for m in members) != ROLES or any(set(m) != _MEMBER_FIELDS for m in members):
            raise AuthorityUnavailable("C09 exact four member roles/fields required")
        paths, identities = set(), set()
        for m in members:
            path = _regular_path(m["resolved_path"], exists=False)
            if not any(path.is_relative_to(root) for root in self._roots):
                raise AuthorityUnavailable("C09 file outside installed resources")
            if str(path) in paths or (m["device"], m["file_id"]) in identities:
                raise AuthorityUnavailable("C09 member paths/file identities overlap")
            paths.add(str(path)); identities.add((m["device"], m["file_id"]))
            if m["storage_generation"] != manifest["generation"] or m["namespace"] != manifest["cohort_namespaces"][0]:
                raise AuthorityUnavailable("C09 member generation/namespace differs")
            for name in ("prepared_sha256", "logical_data_root", "schema_objects_digest", "cold_read_digest"):
                _hex(m[name], name)

    @contextmanager
    def _db(self, *, write=False, create=False):
        self.lease.require_held()
        if not create and not self.path.is_file():
            raise AuthorityUnavailable("installed C09 control log absent; no static fallback")
        with self._lock, closing(sqlite3.connect(self.path, isolation_level=None)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            if write or create:
                if db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal":
                    raise AuthorityUnavailable("C09 control WAL unavailable")
                db.execute("PRAGMA synchronous=FULL")
            else:
                db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield db
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def _validate(self, db):
        for name, ddl in _DDL.items():
            row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
            if row is None or row[0] != ddl:
                raise AuthorityUnavailable("C09 control schema differs: " + name)
            if name != "c09_storage_current_v1":
                for action in ("UPDATE", "DELETE"):
                    expected = self._immutable_ddl(name, action)
                    row = db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name + "_no_" + action.lower(),)).fetchone()
                    if row is None or row[0] != expected:
                        raise AuthorityUnavailable("C09 control immutable trigger differs")
        meta = dict(db.execute("SELECT key,value FROM c09_storage_meta_v1"))
        if meta != {"schema_version":"1", "installation_id":self.installation_id,
                    "authority_id":self.authority_id, "control_store_id":self.control_store_id, "key_id":self.key_id}:
            raise AuthorityUnavailable("C09 control identity differs")

    @staticmethod
    def _immutable_ddl(name, action):
        return f"CREATE TRIGGER {name}_no_{action.lower()} BEFORE {action} ON {name} BEGIN SELECT RAISE(ABORT,'C09 immutable original'); END"

    def _current(self, db):
        self._validate(db)
        row = db.execute("SELECT * FROM c09_storage_current_v1 WHERE installation_id=?", (self.installation_id,)).fetchone()
        if row is None:
            raise AuthorityUnavailable("C09 current pointer absent")
        current = dict(row)
        prior, last, pointer, selected, active, stage, water, tomb = "genesis", 0, 0, None, None, "READY", None, None
        for item in db.execute("SELECT * FROM c09_storage_events_v1 WHERE installation_id=? ORDER BY event_seq", (self.installation_id,)):
            original = json.loads(item["event_json"])
            self.verify_original_v1(original, "event_digest")
            if (item["event_seq"] != last+1 or item["prior_event_digest"] != prior
                    or original["prior_event_digest"] != prior or original["event_seq"] != item["event_seq"]
                    or original["operation_id"] != item["operation_id"] or original["stage"] != item["stage"]
                    or original["event_digest"] != item["event_digest"] or original["signature"] != item["signature"]
                    or original["key_id"] != item["key_id"] or original["installation_id"] != self.installation_id):
                raise AuthorityUnavailable("C09 signed event chain differs")
            if item["stage"] == "INTENT":
                if stage not in {"READY", "RELEASED"} or (selected is not None and original["current_manifest_digest"] != selected):
                    raise AuthorityUnavailable("C09 INTENT prior stage/pointer differs")
                active = item["operation_id"]
            elif item["operation_id"] != active or STAGES.index(item["stage"]) != STAGES.index(stage)+1:
                raise AuthorityUnavailable("C09 illegal event stage transition")
            next_pointer = pointer + (item["stage"] == "SWITCHED")
            if original["pointer_version"] != next_pointer or (selected is not None and item["stage"] != "SWITCHED" and original["current_manifest_digest"] != selected):
                raise AuthorityUnavailable("C09 pointer did not change atomically")
            pointer, selected, stage = next_pointer, original["current_manifest_digest"], item["stage"]
            water, tomb = original["deletion_watermark"], original["cumulative_tombstone_root"]
            last, prior = item["event_seq"], item["event_digest"]
        if (last, prior, pointer, stage) != (current["last_event_seq"], current["last_event_digest"], current["pointer_version"], current["stage"]):
            raise AuthorityUnavailable("C09 current pointer/event differs")
        if last and (selected, active, water, tomb) != (current["current_manifest_digest"], current["active_operation_id"], current["deletion_watermark"], current["cumulative_tombstone_root"]):
            raise AuthorityUnavailable("C09 current materialization differs")
        return current

    def _read_manifest(self, db, manifest_digest):
        row = db.execute("SELECT * FROM c09_storage_manifests_v1 WHERE manifest_digest=?", (manifest_digest,)).fetchone()
        if row is None:
            raise AuthorityUnavailable("C09 selected manifest absent")
        manifest = json.loads(row["manifest_json"])
        self._manifest(manifest)
        signed = self.sign_original_v1("sylanne3.c09.manifest_signature.v1", dict(
            schema="sylanne3.c09.manifest_signature.v1", manifest=manifest,
            issuer_id=self.authority_id), "digest")
        if (row["signature"] != signed["signature"] or row["key_id"] != self.key_id
                or row["issuer_id"] != self.authority_id or row["manifest_digest"] != manifest["manifest_digest"]
                or row["installation_id"] != manifest["installation_id"] or row["generation"] != manifest["generation"]):
            raise AuthorityUnavailable("C09 manifest installed signature differs")
        return manifest

    def read_verified_current_storage_v1(self, *, verify_files=True):
        with self._db() as db:
            current = self._current(db)
            manifest = self._read_manifest(db, current["current_manifest_digest"])
            prepared = None
            if manifest["generation"] > 0:
                row = db.execute("SELECT * FROM c09_storage_operations_v1 WHERE new_manifest_digest=?", (manifest["manifest_digest"],)).fetchone()
                if row is None:
                    raise AuthorityUnavailable("C09 current PREPARED original absent")
                prepared = json.loads(row["prepared_original_json"])
                self.verify_original_v1(prepared, "prepared_digest")
                if set(prepared) != _PREPARED_FIELDS or prepared["prepared_digest"] != row["prepared_digest"] or prepared["signature"] != row["signature"]:
                    raise AuthorityUnavailable("C09 prepared original fields/row differ")
                if prepared["new_manifest_digest"] != manifest["manifest_digest"]:
                    raise AuthorityUnavailable("C09 selected transition differs")
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='c09_storage_build_originals_v1'").fetchone():
                    from .current_filesystem_inventory_v3 import require_prepared_inventory_evidence_v3
                    require_prepared_inventory_evidence_v3(self,db,prepared)
        if verify_files:
            for member in manifest["members"]:
                self.verify_member_v1(member, prepared=False)
        return VerifiedStorageOpenContextV1(str(self.path), current["pointer_version"],
            manifest["manifest_digest"], manifest["generation"], current["stage"],
            manifest, prepared, self, self._capability)

    def verify_member_v1(self, member, *, prepared):
        observed = (file_observation_v1(member["resolved_path"], exclusive=True)
                    if prepared else file_identity_v1(member["resolved_path"]))
        names = ("device", "file_id", "resolved_path") + (("prepared_size", "prepared_mtime_ns", "prepared_sha256") if prepared else ())
        if any(observed[k] != member[k] for k in names):
            raise AuthorityUnavailable("C09 member fingerprint differs: " + member["role"])
        return observed

    def require_context_v1(self, context, *, action="maintenance"):
        if action not in {"business", "accounting", "recovery", "maintenance"}:
            raise AuthorityUnavailable("unknown C09 storage admission action")
        if (type(context) is not VerifiedStorageOpenContextV1 or context._reader is not self
                or context._capability is not self._capability or context.control_path != str(self.path)):
            raise AuthorityUnavailable("installed C09 open context required")
        current = self.read_verified_current_storage_v1(verify_files=False)
        if (current.pointer_version, current.manifest_digest, current.stage) != (context.pointer_version, context.manifest_digest, context.stage):
            raise AuthorityUnavailable("C09 open context expired")
        if action in {"business", "accounting", "recovery"}:
            if context.stage not in {"READY", "RELEASED"}:
                raise AuthorityUnavailable("C09 maintenance admission closed")
            if context.stage == "RELEASED":
                if self._applied_reader is None:
                    raise AuthorityUnavailable("C09 installed scoped-applied reader absent")
                proof = self._applied_reader.read_storage_applied_original_v1(context=context)
                if type(proof) is not dict or proof.get("manifest_digest") != context.manifest_digest or proof.get("state") != "applied" or not proof.get("graph_ack_digest"):
                    raise AuthorityUnavailable("C09 current scoped-applied proof differs")

    def read_consumed_identity_v1(self, *, namespace, kind, item_id):
        context = self.read_verified_current_storage_v1()
        member = next(m for m in context.manifest["members"] if m["role"] == "core")
        with closing(sqlite3.connect(Path(member["resolved_path"]).as_uri()+"?mode=ro",uri=True)) as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_c09_consumed_execution_v1'").fetchone():
                return None
            row = db.execute("SELECT operation_id,original_commitment,facts_pin_digest FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind=? AND item_id=?", (namespace,kind,item_id)).fetchone()
        context.require_current("maintenance")
        return None if row is None else dict(operation_id=row[0],original_commitment=row[1],facts_pin_digest=row[2])

    def require_unconsumed_identity_v1(self, *, namespace, identities):
        for kind,item_id in identities:
            if self.read_consumed_identity_v1(namespace=namespace,kind=kind,item_id=item_id) is not None:
                raise AuthorityUnavailable("already_consumed:" + kind + ":" + item_id)


class C09StorageControlV1(InstalledC09StorageReaderV1):
    def install_build_originals_schema_v1(self):
        """Explicit installer extension; it never changes a stage or pointer."""
        with self._db(write=True) as db:
            self._current(db)
            row = db.execute("SELECT sql FROM sqlite_master WHERE name=?", (_BUILD_TABLE,)).fetchone()
            if row is None:
                db.execute(_BUILD_DDL)
                for action in ("UPDATE", "DELETE"):
                    db.execute(self._immutable_ddl(_BUILD_TABLE, action))
            elif row[0] != _BUILD_DDL:
                raise AuthorityUnavailable("C09 build-original schema differs")
            for action in ("UPDATE", "DELETE"):
                row = db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",
                    (_BUILD_TABLE + "_no_" + action.lower(),)).fetchone()
                if row is None or row[0] != self._immutable_ddl(_BUILD_TABLE, action):
                    raise AuthorityUnavailable("C09 build-original trigger differs")

    def _build_original_locked(self, db, operation_id, kind):
        row = db.execute("SELECT original_json,original_digest FROM c09_storage_build_originals_v1 "
            "WHERE installation_id=? AND operation_id=? AND original_kind=?",
            (self.installation_id, operation_id, kind)).fetchone()
        if row is None:
            return None
        original = json.loads(row[0])
        self.verify_original_v1(original, "original_digest")
        if (original.get("installation_id") != self.installation_id
                or original.get("operation_id") != operation_id or original.get("original_kind") != kind
                or original.get("original_digest") != row[1]):
            raise AuthorityUnavailable("C09 build-original row identity differs")
        return original

    def read_build_original_v1(self, *, operation_id, kind):
        with self._db() as db:
            self._current(db)
            return self._build_original_locked(db, operation_id, kind)

    def record_build_original_v1(self, *, operation_id, kind, details):
        identifier(operation_id, "operation_id")
        identifier(kind, "original_kind")
        with self._db(write=True) as db:
            current = self._current(db)
            preopen = kind.startswith("preopen_switch_quiescence:")
            if preopen:
                from .c09_process_identity_v1 import read_process_identity_v1
                from ..runtime_contracts import canonical_digest
                quiescence = details.get("quiescence_original")
                if type(quiescence) is not dict:
                    raise AuthorityUnavailable("C09 actual preopen quiescence required")
                self.verify_original_v1(quiescence, "quiescence_digest")
                identity = read_process_identity_v1(os.getpid())
                if (quiescence.get("authority_process_original") != identity
                        or quiescence.get("operation_id") != operation_id
                        or quiescence.get("active_writers") != 0
                        or kind != "preopen_switch_quiescence:" + canonical_digest(identity)):
                    raise AuthorityUnavailable("C09 preopen actual process registration differs")
            allowed_stage = "PREPARED" if preopen else "INTENT"
            if current["stage"] != allowed_stage or current["active_operation_id"] != operation_id:
                raise AuthorityUnavailable("C09 build original requires this current INTENT")
            prior = self._build_original_locked(db, operation_id, kind)
            if prior is not None:
                if prior["details"] != json.loads(canonical(details)):
                    raise AuthorityUnavailable("C09 build original replay differs")
                return prior
            original = self.sign_original_v1("sylanne3.c09.storage-build-original.v1", {
                "schema": "sylanne3.c09.storage-build-original.v1", "installation_id": self.installation_id,
                "operation_id": operation_id, "original_kind": kind,
                "old_manifest_digest": current["current_manifest_digest"],
                "expected_pointer_version": current["pointer_version"], "details": details}, "original_digest")
            db.execute("INSERT INTO c09_storage_build_originals_v1 VALUES(?,?,?,?,?)", (
                self.installation_id, operation_id, kind, canonical(original), original["original_digest"]))
            return original

    def record_cleanup_plan_v1(self, *, operation_id, surface, details):
        if surface not in SURFACES:
            raise AuthorityUnavailable("C09 cleanup surface differs")
        kind = "purge_" + surface
        with self._db(write=True) as db:
            current = self._current(db)
            if current["stage"] != "SWITCHED" or current["active_operation_id"] != operation_id:
                raise AuthorityUnavailable("C09 cleanup plan requires this SWITCHED")
            prior = self._build_original_locked(db, operation_id, kind)
            if prior is not None:
                if prior["details"] != json.loads(canonical(details)):
                    raise AuthorityUnavailable("C09 cleanup plan replay differs")
                return prior
            original = self.sign_original_v1("sylanne3.c09.storage-cleanup-plan.v1", {
                "schema": "sylanne3.c09.storage-cleanup-plan.v1", "installation_id": self.installation_id,
                "operation_id": operation_id, "original_kind": kind,
                "manifest_digest": current["current_manifest_digest"], "surface": surface,
                "pointer_version": current["pointer_version"], "details": details}, "original_digest")
            db.execute("INSERT INTO c09_storage_build_originals_v1 VALUES(?,?,?,?,?)", (
                self.installation_id, operation_id, kind, canonical(original), original["original_digest"]))
            return original

    def _store_manifest(self, db, manifest):
        self._manifest(manifest)
        signed = self.sign_original_v1("sylanne3.c09.manifest_signature.v1", dict(
            schema="sylanne3.c09.manifest_signature.v1", manifest=manifest,
            issuer_id=self.authority_id), "digest")
        row = db.execute("SELECT manifest_json FROM c09_storage_manifests_v1 WHERE manifest_digest=?", (manifest["manifest_digest"],)).fetchone()
        if row is not None:
            if row[0] != canonical(manifest):
                raise AuthorityUnavailable("C09 manifest replay differs")
            return
        db.execute("INSERT INTO c09_storage_manifests_v1 VALUES(?,?,?,?,?,?,?)", (
            manifest["manifest_digest"], self.installation_id, manifest["generation"],
            canonical(manifest), self.authority_id, self.key_id, signed["signature"]))

    def bootstrap_installed_storage_v1(self, *, manifest):
        if self.path.exists():
            raise AuthorityUnavailable("C09 bootstrap refuses existing control log")
        self._manifest(manifest)
        if manifest["generation"] != 0 or manifest["prior_manifest_digest"] is not None:
            raise AuthorityUnavailable("C09 bootstrap generation differs")
        for member in manifest["members"]:
            self.verify_member_v1(member, prepared=True)
        descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(descriptor)
        with self._db(write=True, create=True) as db:
            for ddl in _DDL.values():
                db.execute(ddl)
            db.executemany("INSERT INTO c09_storage_meta_v1 VALUES(?,?)", (
                ("schema_version", "1"), ("installation_id", self.installation_id),
                ("authority_id", self.authority_id), ("control_store_id", self.control_store_id), ("key_id", self.key_id)))
            self._store_manifest(db, manifest)
            db.execute("INSERT INTO c09_storage_current_v1 VALUES(?,0,?,NULL,'READY',0,'genesis',?,?)", (
                self.installation_id, manifest["manifest_digest"], manifest["deletion_watermark"], manifest["cumulative_tombstone_root"]))
            for name in _DDL:
                if name != "c09_storage_current_v1":
                    for action in ("UPDATE", "DELETE"):
                        db.execute(self._immutable_ddl(name, action))
        return self.read_verified_current_storage_v1()

    def _event(self, db, current, *, operation_id, stage, details, manifest=None):
        prior = db.execute("SELECT event_json FROM c09_storage_events_v1 WHERE operation_id=? AND stage=?", (operation_id, stage)).fetchone()
        if prior is not None:
            original = json.loads(prior[0])
            self.verify_original_v1(original, "event_digest")
            if original["details"] != details:
                raise AuthorityUnavailable("C09 same operation/stage digest conflict")
            return original
        if stage == "INTENT":
            if current["stage"] not in {"READY", "RELEASED"}:
                raise AuthorityUnavailable("C09 maintenance already active")
        elif current["active_operation_id"] != operation_id or STAGES.index(stage) != STAGES.index(current["stage"])+1:
            raise AuthorityUnavailable("C09 invalid current stage")
        selected = current["current_manifest_digest"] if stage != "SWITCHED" else manifest["manifest_digest"]
        water = current["deletion_watermark"] if stage != "SWITCHED" else manifest["deletion_watermark"]
        tomb = current["cumulative_tombstone_root"] if stage != "SWITCHED" else manifest["cumulative_tombstone_root"]
        if water < current["deletion_watermark"]:
            raise AuthorityUnavailable("C09 deletion watermark rollback")
        original = self.sign_original_v1("sylanne3.c09.storage_event.v1", dict(
            schema="sylanne3.c09.storage_event.v1", installation_id=self.installation_id,
            event_seq=current["last_event_seq"]+1, operation_id=operation_id,
            stage=stage, prior_event_digest=current["last_event_digest"],
            pointer_version=current["pointer_version"]+(stage == "SWITCHED"),
            current_manifest_digest=selected, deletion_watermark=water,
            cumulative_tombstone_root=tomb, details=details), "event_digest")
        db.execute("INSERT INTO c09_storage_events_v1 VALUES(?,?,?,?,?,?,?,?,?)", (
            self.installation_id, original["event_seq"], operation_id, stage,
            original["prior_event_digest"], canonical(original), original["event_digest"], self.key_id, original["signature"]))
        changed = db.execute("UPDATE c09_storage_current_v1 SET pointer_version=?,current_manifest_digest=?,active_operation_id=?,stage=?,last_event_seq=?,last_event_digest=?,deletion_watermark=?,cumulative_tombstone_root=? WHERE installation_id=? AND pointer_version=? AND current_manifest_digest=? AND last_event_digest=?", (
            original["pointer_version"], selected, operation_id, stage, original["event_seq"],
            original["event_digest"], water, tomb, self.installation_id,
            current["pointer_version"], current["current_manifest_digest"], current["last_event_digest"]))
        if changed.rowcount != 1:
            raise AuthorityUnavailable("C09 pointer CAS conflict")
        return original

    def record_maintenance_intent_v1(self, *, operation_id, namespace, installed_intent):
        identifier(operation_id, "operation_id")
        with self._db(write=True) as db:
            current = self._current(db)
            old = self._read_manifest(db, current["current_manifest_digest"])
            if old["cohort_namespaces"] != [namespace]:
                raise AuthorityUnavailable("unsupported_storage_cohort")
            if installed_intent.get("expected_pointer_version") != current["pointer_version"] or installed_intent.get("old_manifest_digest") != old["manifest_digest"]:
                raise AuthorityUnavailable("C09 intent expected pointer differs")
            targets = installed_intent.get("targets", {})
            if tuple(sorted(targets)) != ROLES or len(set(targets.values())) != 4:
                raise AuthorityUnavailable("C09 intent requires four distinct targets")
            for target in targets.values():
                path = _regular_path(target, exists=False)
                if not any(path.is_relative_to(root) for root in self._roots) or str(path) in {m["resolved_path"] for m in old["members"]}:
                    raise AuthorityUnavailable("C09 target outside registered resources/overlaps source")
            return self._event(db, current, operation_id=operation_id, stage="INTENT", details=installed_intent)

    def read_operation_event_v1(self, operation_id, stage):
        with self._db() as db:
            self._current(db)
            row = db.execute("SELECT event_json FROM c09_storage_events_v1 WHERE operation_id=? AND stage=?", (operation_id, stage)).fetchone()
            if row is None:
                raise AuthorityUnavailable("C09 operation event absent: " + stage)
            original = json.loads(row[0]); self.verify_original_v1(original, "event_digest")
            return original

    def record_prepared_storage_v1(self, *, manifest, prepared_original,closing_continuation=None):
        self._manifest(manifest)
        self.verify_original_v1(prepared_original, "prepared_digest")
        if set(prepared_original) != _PREPARED_FIELDS or prepared_original["schema"] != "sylanne3.c09.storage_prepared_original.v1":
            raise AuthorityUnavailable("C09 exact PREPARED fields required")
        operation_id = prepared_original["operation_id"]
        intent = self.read_operation_event_v1(operation_id, "INTENT")
        for member in manifest["members"]:
            if member["resolved_path"] != intent["details"]["targets"][member["role"]]:
                raise AuthorityUnavailable("C09 candidate differs from registered INTENT")
            self.verify_member_v1(member, prepared=True)
        with self._db(write=True) as db:
            current = self._current(db)
            prior = db.execute("SELECT prepared_original_json FROM c09_storage_operations_v1 WHERE operation_id=?", (operation_id,)).fetchone()
            if prior is not None and prior[0]!=canonical(prepared_original):
                raise AuthorityUnavailable("C09 PREPARED original conflict")
            intent_row=db.execute("SELECT event_json FROM c09_storage_events_v1 WHERE operation_id=? AND stage='INTENT'",(operation_id,)).fetchone()
            if intent_row is None:raise AuthorityUnavailable("actual signed INTENT absent")
            actual_intent=json.loads(intent_row[0]);self.verify_original_v1(actual_intent,"event_digest")
            if (actual_intent!=intent or actual_intent["operation_id"]!=operation_id
                    or actual_intent["stage"]!="INTENT"
                    or actual_intent["current_manifest_digest"]!=prepared_original["old_manifest_digest"]
                    or actual_intent["details"]["old_manifest_digest"]!=prepared_original["old_manifest_digest"]
                    or actual_intent["details"]["expected_pointer_version"]!=prepared_original["expected_pointer_version"]
                    or actual_intent["pointer_version"]!=prepared_original["expected_pointer_version"]
                    or actual_intent["details"]["accepted_receipt_digest"]!=prepared_original["accepted_receipt_digest"]):
                raise AuthorityUnavailable("PREPARED/bridge differs from actual signed INTENT")
            old = self._read_manifest(db, prepared_original["old_manifest_digest"])
            if (manifest["generation"] != old["generation"]+1 or manifest["prior_manifest_digest"] != old["manifest_digest"]
                    or prepared_original["new_manifest_digest"] != manifest["manifest_digest"]
                    or prepared_original["maintenance_generation"] != manifest["generation"]):
                raise AuthorityUnavailable("C09 PREPARED lineage differs")
            if prior is None and (current["stage"]!="INTENT" or current["active_operation_id"]!=operation_id
                    or current["pointer_version"]!=prepared_original["expected_pointer_version"]
                    or current["current_manifest_digest"]!=prepared_original["old_manifest_digest"]):
                raise AuthorityUnavailable("C09 PREPARED exact INTENT predecessor changed")
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='c09_storage_build_originals_v1'").fetchone():
                from .current_filesystem_inventory_v3 import require_prepared_inventory_evidence_v3
                require_prepared_inventory_evidence_v3(self,db,prepared_original,require_present=prior is None)
            elif prior is None:
                raise AuthorityUnavailable("new C09 PREPARED has no durable current inventory evidence")
            if prior is None:
                gate=getattr(self,'_final_gate_v3',None)
                if gate is None:raise AuthorityUnavailable("actual continuous close gate absent")
                gate.require_final_continuation_v3(closing_continuation,operation_id=operation_id,observe=False)
                from .c09_retired_final_scan_v1 import require_retired_qualification_in_tx_v1
                require_retired_qualification_in_tx_v1(self, db, prepared_original, gate)
            self._store_manifest(db, manifest)
            prior = db.execute("SELECT prepared_original_json FROM c09_storage_operations_v1 WHERE operation_id=?", (operation_id,)).fetchone()
            if prior is not None:
                if prior[0] != canonical(prepared_original):
                    raise AuthorityUnavailable("C09 PREPARED original conflict")
            else:
                db.execute("INSERT INTO c09_storage_operations_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)", (
                    operation_id, self.installation_id, prepared_original["namespace"], manifest["generation"],
                    prepared_original["expected_pointer_version"], old["manifest_digest"], manifest["manifest_digest"],
                    canonical(prepared_original), prepared_original["prepared_digest"], self.key_id, prepared_original["signature"]))
            return self._event(db, current, operation_id=operation_id, stage="PREPARED", details={"prepared_digest":prepared_original["prepared_digest"], "new_manifest_digest":manifest["manifest_digest"]})

    def switch_prepared_storage_v1(self, *, operation_id, quiescence_original):
        self.verify_original_v1(quiescence_original, "quiescence_digest")
        with self._db(write=True) as db:
            current = self._current(db)
            row = db.execute("SELECT prepared_original_json FROM c09_storage_operations_v1 WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None:
                raise AuthorityUnavailable("C09 switch PREPARED absent")
            prepared = json.loads(row[0]); self.verify_original_v1(prepared, "prepared_digest")
            new = self._read_manifest(db, prepared["new_manifest_digest"])
            old = self._read_manifest(db, prepared["old_manifest_digest"])
            details = {"prepared_digest":prepared["prepared_digest"],
                "quiescence_digest":quiescence_original["quiescence_digest"],
                "quiescence_original":quiescence_original}
            prior = db.execute("SELECT event_json FROM c09_storage_events_v1 WHERE operation_id=? AND stage='SWITCHED'", (operation_id,)).fetchone()
            if prior is not None:
                existing = json.loads(prior[0])
                if existing["details"]["prepared_digest"] != details["prepared_digest"]:
                    raise AuthorityUnavailable("C09 SWITCHED replay conflict")
                return existing
            if (current["pointer_version"], current["current_manifest_digest"]) != (prepared["expected_pointer_version"], old["manifest_digest"]):
                raise AuthorityUnavailable("C09 four-file switch CAS differs")
            if quiescence_original.get("operation_id") != operation_id or quiescence_original.get("pointer_version") != current["pointer_version"]:
                raise AuthorityUnavailable("C09 current quiescence differs")
            for member in new["members"]:
                self.verify_member_v1(member, prepared=True)
            for source in prepared["source_final_fingerprints"]:
                if file_observation_v1(source["resolved_path"], exclusive=True) != source:
                    raise AuthorityUnavailable("C09 source final fingerprint differs")
            event = self._event(db, current, operation_id=operation_id, stage="SWITCHED", details=details, manifest=new)
            for member in old["members"]:
                observation = next((s for s in prepared["source_final_fingerprints"] if s["resolved_path"] == member["resolved_path"]), None)
                if observation is None:
                    raise AuthorityUnavailable("C09 old file retirement observation absent")
                db.execute("INSERT INTO c09_storage_retired_files_v1 VALUES(?,?,?,?,?,?,?)", (
                    self.installation_id, member["role"], old["generation"], member["resolved_path"],
                    canonical(observation), observation["prepared_sha256"], event["event_digest"]))
            return event

    def record_surface_evidence_v1(self, original):
        self.verify_original_v1(original, "evidence_digest")
        if original.get("surface") not in SURFACES or original.get("action") not in {"purged", "sanitized", "reset"}:
            raise AuthorityUnavailable("C09 real surface action required")
        with self._db(write=True) as db:
            current = self._current(db)
            if current["stage"] not in {"SWITCHED", "CLEANED"} or original["operation_id"] != current["active_operation_id"]:
                raise AuthorityUnavailable("C09 surface evidence current operation differs")
            row = db.execute("SELECT evidence_json FROM c09_storage_surface_evidence_v1 WHERE operation_id=? AND surface=?", (original["operation_id"], original["surface"])).fetchone()
            if row is not None:
                if row[0] != canonical(original):
                    raise AuthorityUnavailable("C09 surface original conflict")
                return original
            db.execute("INSERT INTO c09_storage_surface_evidence_v1 VALUES(?,?,?,?,?,?,?)", (
                original["operation_id"], original["surface"], canonical(original), original["evidence_digest"],
                original["issuer_id"], self.key_id, original["signature"]))
            return original

    def read_surface_evidence_v1(self, operation_id):
        with self._db() as db:
            self._current(db)
            originals = tuple(json.loads(r[0]) for r in db.execute("SELECT evidence_json FROM c09_storage_surface_evidence_v1 WHERE operation_id=? ORDER BY surface", (operation_id,)))
            for original in originals:
                self.verify_original_v1(original, "evidence_digest")
            return originals

    def record_cleaned_storage_v1(self, *, operation_id, independently_verified_root):
        originals = self.read_surface_evidence_v1(operation_id)
        if {item["surface"] for item in originals} != SURFACES or digest([item["evidence_digest"] for item in originals]) != independently_verified_root:
            raise AuthorityUnavailable("C09 twelve independently verified surfaces required")
        with self._db(write=True) as db:
            return self._event(db, self._current(db), operation_id=operation_id, stage="CLEANED", details={"surface_receipt_root":independently_verified_root})

    def release_cleaned_storage_v1(self, *, operation_id, release_original):
        self.verify_original_v1(release_original, "release_digest")
        if release_original.get("operation_id") != operation_id or release_original.get("state") != "applied" or not release_original.get("graph_ack_digest") or not release_original.get("closed_digest"):
            raise AuthorityUnavailable("C09 closed/applied/ACK release original required")
        with self._db(write=True) as db:
            current = self._current(db)
            if release_original.get("manifest_digest") != current["current_manifest_digest"]:
                raise AuthorityUnavailable("C09 RELEASED manifest differs")
            return self._event(db, current, operation_id=operation_id, stage="RELEASED", details={"release_original":release_original})


def read_verified_current_storage_v1(*, reader):
    if not isinstance(reader, InstalledC09StorageReaderV1):
        raise AuthorityUnavailable("installed C09 storage reader required")
    return reader.read_verified_current_storage_v1()
