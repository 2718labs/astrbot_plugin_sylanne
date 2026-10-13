"""Explicit ordinary-runtime access to installed immutable segmented SQL cells.

A selected storage binding proves physical storage identity. It never replaces
the caller's Owner, Source, W01, scope, epoch or effect admission.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import threading
from time import monotonic_ns

from .authority_service.contract import AuthorityUnavailable
from .runtime_contracts import canonical_digest, meter_canonical_outputs
from .runtime.c09_paged_sql_v2 import (
    C09BatchBudgetV2, C09SqlByteMeterV2, c09_sql_meter_quantum_v2,
)
from .segmented_sql_cell_v1 import MAX_SEGMENT_BYTES, CODECS

_INSTALLED = object()
_BINDINGS = {}
_BINDINGS_LOCK = threading.RLock()
_POOLS = {}
_OPERATION = ContextVar('sylanne_runtime_storage_operation_v3', default=None)
_QUANTUM = ContextVar('sylanne_runtime_storage_quantum_v3', default=None)
_HEAD_COLUMNS = frozenset(("token", "bot", "persona", "owner_kind", "subject",
    "type_name", "name", "revision", "value", "valid", "value_cell_id"))
_HISTORY_COLUMNS = frozenset(("token", "revision", "value", "valid",
    "dependencies", "event_bot", "event_persona", "event_session", "event_id",
    "value_cell_id"))
_PROJECTIONS = {
    "d09.turn-slot-origin.v3": (("origin_ref",),),
    "d13.counter-generation-call.v3": (("generation_call_id",),),
    "d13.standby-metadata.v3": (("conversation_ref",), ("status",), ("expires_at_utc",), ("schema",)),
}


@dataclass(frozen=True, slots=True)
class RuntimeGraphMetadataV3:
    token: str
    revision: int
    valid: bool
    cell_id: str | None



class _RuntimeResourcePoolV3:
    def __init__(self):
        self.capacity = 8388608
        self.slab = bytearray(262144)
        self.lock = threading.RLock()
        self.used = len(self.slab)

    def reserve(self, amount):
        with self.lock:
            if amount < 0 or self.used + amount > self.capacity:
                raise AuthorityUnavailable("ordinary storage actual retention pool is exhausted")
            self.used += amount

    def release(self, amount):
        with self.lock:
            self.used -= amount


class RuntimeStorageOperationV3:
    """Retention lease owned by the actual enclosing business operation."""
    def __init__(self, issuer, handle, operation_id, deadline_utc):
        if issuer is not _INSTALLED:
            raise AuthorityUnavailable("actual installed runtime operation required")
        self.handle, self.pool = handle, handle.pool
        self.operation_id, self.deadline_utc = operation_id, deadline_utc
        self.selection_digest = handle.selection_digest
        self.kind = "business"
        self.retained = 0
        self.closed = False
        self._release_lock = threading.Lock()
        self._payload_release = None

    def transfer_payload_release_v3(self, callback):
        """Move the actual result cleanup to this same retained operation."""
        with self._release_lock:
            if self.closed or self._payload_release is not None:
                raise AuthorityUnavailable("runtime result cleanup ownership already ended or moved")
            self._payload_release = callback

    def retain(self, size):
        if self.closed:
            raise AuthorityUnavailable("ordinary runtime retention operation ended")
        self.pool.reserve(size)
        self.retained += size

    def release(self):
        with self._release_lock:
            if self.closed:
                return
            self.closed = True
            size, self.retained = self.retained, 0
            cleanup, self._payload_release = self._payload_release, None
        try:
            if cleanup is not None:
                cleanup()
        finally:
            self.pool.release(size)


def begin_runtime_storage_operation_v3(db,operation_id,deadline_utc):
    """Issue one retained operation lease for synchronous or queued consumers."""
    handle=runtime_storage_v3(db)
    if handle is None:
        return None
    if handle.purpose != "business":
        raise AuthorityUnavailable("physical maintenance handle cannot issue ordinary operation")
    return RuntimeStorageOperationV3(_INSTALLED,handle,operation_id,deadline_utc)


@contextmanager
def bind_runtime_storage_operation_v3(lease,db):
    """Bind the same retained operation on a worker tick; exit never releases it."""
    handle=runtime_storage_v3(db)
    if handle is None:
        if lease is not None:
            raise AuthorityUnavailable("runtime operation crossed its explicit storage layout")
        yield None
        return
    if (type(lease) is not RuntimeStorageOperationV3 or lease.closed
            or lease.pool is not handle.pool or lease.selection_digest!=handle.selection_digest):
        raise AuthorityUnavailable("actual same selected runtime operation retention lease required")
    prior=_OPERATION.get()
    if prior is not None and prior is not lease:
        raise AuthorityUnavailable("another ordinary retained operation is already bound")
    token=_OPERATION.set(lease)
    try:
        yield lease
    finally:
        _OPERATION.reset(token)


def finish_runtime_storage_operation_v3(lease):
    """Release only at actual work completion, failure or cancellation."""
    if lease is not None:
        if type(lease) not in (RuntimeStorageOperationV3,MaintenanceRuntimeOperationV3):
            raise AuthorityUnavailable("actual runtime retention lease required")
        lease.release()


@contextmanager
def runtime_storage_operation_v3(db,*,operation_id=None,deadline_utc=None):
    """Synchronous convenience over the same persistent retention lease protocol."""
    handle=runtime_storage_v3(db)
    prior=_OPERATION.get()
    if prior is not None:
        if handle is None or prior.closed or prior.pool is not handle.pool or prior.selection_digest!=handle.selection_digest:
            raise AuthorityUnavailable("ordinary runtime operation crossed its selected binding")
        yield prior
        return
    lease=begin_runtime_storage_operation_v3(db,operation_id,deadline_utc)
    try:
        with bind_runtime_storage_operation_v3(lease,db):
            yield lease
    finally:
        finish_runtime_storage_operation_v3(lease)


def _operation(handle):
    operation = _OPERATION.get()
    if operation is None or operation.closed or operation.pool is not handle.pool or operation.selection_digest!=handle.selection_digest:
        raise AuthorityUnavailable("ordinary storage requires its actual business retention operation")
    if (handle.purpose == "business" and operation.kind != "business"
            or handle.purpose == "physical_maintenance" and operation.kind != "maintenance"):
        raise AuthorityUnavailable("actual runtime operation purpose differs from physical composition")
    return operation


@dataclass(frozen=True, slots=True)
class RuntimeStorageProgressV3:
    selection_digest: str
    cell_id: str
    next_ordinal: int
    next_byte_offset: int
    payload_sha256: str
    operation_id: str | None = None
    deadline_utc: float | None = None
    state: str = "needs_continuation"


class RuntimeStorageNeedsContinuationV3(RuntimeError):
    def __init__(self, progress, *, continuation=None):
        self.progress = progress
        self.continuation = continuation
        super().__init__("actual runtime cell requires its existing operation continuation")


class InstalledRuntimeStorageV3:
    """Exact selected SQLite handle plus independently allocated local resources."""
    def __init__(self, issuer, db, role, selected, context):
        if issuer is not _INSTALLED:
            raise AuthorityUnavailable("installed runtime storage factory required")
        self.db, self.role, self.selected, self.context = db, role, selected, context
        self.member = selected.basis.member(role)
        self.instance = selected.basis.manifest["segmented_layouts"][role]["storage_instance_id"]
        self.selection_digest = selected.basis.selection_digest
        self.purpose = "business"
        pool_key = (selected.basis.control.authority_id, selected.basis.control.installation_id)
        if pool_key not in _POOLS:
            _POOLS[pool_key] = _RuntimeResourcePoolV3()
        self.pool = _POOLS[pool_key]
        self._closed = False

    @contextmanager
    def quantum(self):
        if self._closed:
            raise AuthorityUnavailable("runtime storage handle is closed")
        prior = _QUANTUM.get()
        if prior is not None:
            pool, selection_digest, meter = prior
            if pool is not self.pool or selection_digest != self.selection_digest:
                raise AuthorityUnavailable("ordinary quantum crossed its installed pool or selection")
            self.require_current(meter)
            yield meter
            return
        if not self.pool.lock.acquire(blocking=False):
            raise AuthorityUnavailable("actual ordinary runtime resource pool is occupied")
        try:
            budget = C09BatchBudgetV2(100,262144,25000000,250000000,self.pool.capacity)
            meter = C09SqlByteMeterV2(budget)
            started = monotonic_ns()
            token = _QUANTUM.set((self.pool,self.selection_digest,meter))
            try:
                with c09_sql_meter_quantum_v2(meter), meter_canonical_outputs(meter):
                    self.require_current(meter)
                    yield meter
                    self.require_current(meter)
                if monotonic_ns() - started > budget.max_local_ns:
                    raise AuthorityUnavailable("runtime storage quantum exceeded its local duration")
            finally:
                _QUANTUM.reset(token)
        finally:
            self.pool.lock.release()

    def require_current(self, meter):
        if self._closed or type(self.db) is not sqlite3.Connection:
            raise AuthorityUnavailable("actual installed runtime database required")
        current = self.selected.basis.require_current(meter=meter)
        if current["stage"] != "RELEASED":
            raise AuthorityUnavailable("ordinary runtime storage requires actual RELEASED")
        stat = Path(self.member["resolved_path"]).stat()
        if (stat.st_dev, stat.st_ino) != (self.member["device"], self.member["file_id"]):
            raise AuthorityUnavailable("ordinary runtime selected file identity changed")
        return current

    def close(self):
        with _BINDINGS_LOCK:
            if _BINDINGS.get(self.db) is self:
                del _BINDINGS[self.db]
        self._closed = True
        self.db = None


def install_selected_runtime_storage_v3(db, *, role, selected, context):
    """Bind an actual selected connection after existing business open admission."""
    from .authority_service.c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
    from .authority_service.c09_storage_control_v1 import VerifiedStorageOpenContextV1
    if (type(db) is not sqlite3.Connection or type(selected) is not VerifiedSelectedHistoryReadV3
            or type(context) is not VerifiedStorageOpenContextV1
            or context._reader is not selected.basis.control
            or context.manifest_digest != selected.basis.manifest["manifest_digest"]
            or role not in ("graph", "core", "deletion", "execution")):
        raise AuthorityUnavailable("exact selected history, open context and SQLite role required")
    context.require_current("business")
    member = selected.basis.member(role)
    databases = db.execute("PRAGMA database_list").fetchall()
    if (len(databases) != 1 or databases[0][1] != "main"
            or Path(databases[0][2]).resolve(strict=True) != Path(member["resolved_path"]).resolve(strict=True)):
        raise AuthorityUnavailable("runtime connection differs from actual selected role file")
    with _BINDINGS_LOCK:
        prior = _BINDINGS.get(db)
        if prior is not None:
            if prior.selected is not selected or prior.role != role:
                raise AuthorityUnavailable("runtime connection cannot change its selected scope")
            return prior
        handle = InstalledRuntimeStorageV3(_INSTALLED, db, role, selected, context)
        with handle.quantum() as meter:
            selected.basis.require_layout(db, role, meter=meter)
        _BINDINGS[db] = handle
        return handle


def runtime_storage_v3(db):
    """Return only the actual registered connection binding; no path-based issuer."""
    if type(db) is not sqlite3.Connection:
        raise TypeError("actual SQLite connection required")
    with _BINDINGS_LOCK:
        handle = _BINDINGS.get(db)
    if handle is None and db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='segmented_storage_layout_v1'").fetchone():
        raise AuthorityUnavailable("segmented ordinary read requires installed selected runtime storage")
    return handle


def graph_value_column_v3(db):
    return "value_cell_id" if runtime_storage_v3(db) is not None else "value"


class RuntimeCellReadV3:
    """Resumable integrity reader; partial fragments never constitute a value."""
    def __init__(self, handle, cell_id, *, erasure_owner_ref=None, meter=None):
        self.handle, self.cell_id = handle, cell_id
        if meter is None:
            with handle.quantum() as actual:
                self._read_header(handle, cell_id, erasure_owner_ref, actual)
        else:
            self._read_header(handle, cell_id, erasure_owner_ref, meter)
        self.ordinal, self.offset = 0, 0
        self.hash = sha256()
        self.root = canonical_digest(('sylanne3.segmented-cell-genesis.v1', cell_id))
        self.complete = False

    def _read_header(self, handle, cell_id, erasure_owner_ref, meter):
            meter.require_available(32768)
            row = meter.read_fixed_row(handle.db, 'segmented_cells_v1',
                ('codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
                 'payload_sha256','ordered_segment_root','origin_scope_digest'), 'cell_id=?', (cell_id,))
            if (row is None or row[0] not in CODECS or row[3] < 0 or row[4] < 0
                    or erasure_owner_ref is not None and row[1] != erasure_owner_ref):
                raise AuthorityUnavailable("actual sealed runtime cell or erasure owner differs")

            self.header = row
            read_runtime_cell_origin_v3(handle.db,cell_id,header=row,meter=meter)

    def read_fragment(self, *, meter=None):
        if self.complete:
            raise AuthorityUnavailable("runtime cell EOF was already consumed")
        if self.ordinal == self.header[4]:
            return None
        if meter is None:
            with self.handle.quantum() as actual:
                return self.read_fragment(meter=actual)
        _operation(self.handle)
        meter.require_available(MAX_SEGMENT_BYTES * 4)
        row = meter.read_fixed_row(self.handle.db, 'segmented_cell_segments_v1',
            ('byte_offset','payload','payload_sha256'), 'cell_id=? AND ordinal=?', (self.cell_id, self.ordinal))
        if row is None or row[0] != self.offset or type(row[1]) is not bytes:
            raise AuthorityUnavailable('runtime cell segment is absent or out of order')
        chunk = row[1]
        if not 0 < len(chunk) <= MAX_SEGMENT_BYTES or sha256(chunk).hexdigest() != row[2]:
            raise AuthorityUnavailable('runtime cell segment SHA or byte bound differs')

        self.root = canonical_digest(("sylanne3.segmented-cell-link.v1",
            self.root, self.cell_id, self.ordinal, self.offset, len(chunk), row[2]))
        self.hash.update(chunk)
        self.ordinal += 1
        self.offset += len(chunk)
        if self.offset > self.header[3]:
            raise AuthorityUnavailable("runtime cell exceeds its sealed byte count")
        return chunk

    def finish(self, *, meter=None):
        if meter is None:
            with self.handle.quantum() as actual:
                return self.finish(meter=actual)
        meter.require_available(256)
        extra = self.handle.db.execute(
            'SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? LIMIT 1',
            (self.cell_id, self.ordinal)).fetchone()
        meter.charge_read(8 if extra else 0)
        if (self.ordinal != self.header[4] or self.offset != self.header[3]
                or self.hash.hexdigest() != self.header[5] or self.root != self.header[6] or extra is not None):
            raise AuthorityUnavailable("runtime cell complete EOF, payload SHA or ordered root differs")
        self.complete = True
        return self.header[5]


def begin_runtime_cell_read_v3(db, cell_id, *, erasure_owner_ref=None):
    handle = runtime_storage_v3(db)
    if handle is None:
        raise AuthorityUnavailable("runtime cell reads require explicit selected segmented layout")
    return RuntimeCellReadV3(handle, cell_id, erasure_owner_ref=erasure_owner_ref)


def materialize_runtime_cell_v3(db, cell_id, *, erasure_owner_ref=None):
    """One actual quantum; larger values expose an explicit continuation."""
    handle = runtime_storage_v3(db)
    operation = _operation(handle)
    with handle.quantum() as meter:
        reader = RuntimeCellReadV3(handle, cell_id, erasure_owner_ref=erasure_owner_ref, meter=meter)
        size = reader.header[3]
        reservation = size * 8 + 8192
        if size * 3 + 32768 > meter.available_bytes:
            raise RuntimeStorageNeedsContinuationV3(RuntimeStorageProgressV3(
                handle.selection_digest, cell_id, 0, 0, reader.header[5],
                operation.operation_id, operation.deadline_utc))
        operation.retain(reservation)
        value = bytearray(size)
        offset = 0
        while reader.ordinal < reader.header[4]:
            chunk = reader.read_fragment(meter=meter)
            value[offset:offset + len(chunk)] = chunk
            offset += len(chunk)
        reader.finish(meter=meter)
        if reader.header[0] not in ("canonical-json.ascii.v1", "canonical-json.utf8.v1"):
            raise AuthorityUnavailable("JSON runtime value requires its registered canonical codec")
        meter.charge_encode(size)
        return value.decode("utf-8")


def materialize_graph_value_v3(db, value, *, token=None):
    if runtime_storage_v3(db) is None:
        return value
    return materialize_runtime_cell_v3(db, value, erasure_owner_ref=token)


def read_graph_rows_v3(db,columns,*,where,parameters=(),history=False,order_by=(),limit=None):
    """Explicit bounded metadata/body collection; large queries retain a cursor."""
    handle=runtime_storage_v3(db)
    allowed=_HISTORY_COLUMNS if history else _HEAD_COLUMNS
    if type(columns) is not tuple or not columns or any(c not in allowed for c in columns):
        raise ValueError('registered Graph projection columns required')
    predicate=_registered_graph_predicate_v3(where,allowed-{'value','value_cell_id'})
    if type(order_by) is not tuple or any(c not in allowed-{'value','value_cell_id'} for c in order_by):
        raise ValueError('registered Graph metadata ordering required')
    if handle is None:
        sql='SELECT '+','.join(columns)+' FROM '+('graph_history' if history else 'graph_atoms')+' WHERE '+predicate
        if order_by:sql+=' ORDER BY '+','.join(order_by)
        if limit is not None:sql+=' LIMIT '+str(limit)
        return tuple(db.execute(sql,parameters))
    # These fixed selectors consume only the originating Method Work's
    # privately prepared heads/history and complete typed family coverage.
    from .runtime.current_method_learning_read_v3 import (
        read_bound_method_graph_point_v3, read_bound_method_type_rows_v3)
    compact = "".join(predicate.split())
    point_keys = None
    if not history and compact in {"token=?", "token=?ANDbot=?ANDpersona=?"}:
        point_keys = ("token",) if compact == "token=?" else ("token", "bot", "persona")
    elif history and compact in {"token=?ANDrevision=?", "token=?ANDrevision=?ANDevent_bot=?ANDevent_persona=?"}:
        point_keys = (("token", "revision") if compact == "token=?ANDrevision=?"
            else ("token", "revision", "event_bot", "event_persona"))
    if point_keys is not None and not order_by and limit in (None, 1):
        handled, row = read_bound_method_graph_point_v3(db, columns=columns,
            key_columns=point_keys, key=tuple(parameters), history=history)
        if handled:
            return () if row is None else (row,)
    if not history and order_by in ((), ("token",)) and compact.startswith("bot=?ANDpersona=?ANDtype_name="):
        from .runtime_contracts import NamespaceId
        selector = compact[len("bot=?ANDpersona=?ANDtype_name="):]
        valid_only = selector.endswith("ANDvalid=1")
        if valid_only:
            selector = selector[:-len("ANDvalid=1")]
        type_id = (parameters[2] if selector == "?" and len(parameters) == 3
            else selector[1:-1] if selector.startswith("'") and selector.endswith("'")
                and selector.count("'") == 2 and len(parameters) == 2 else None)
        if type_id is not None:
            handled, rows = read_bound_method_type_rows_v3(db,
                NamespaceId(*parameters[:2]), type_id, columns, valid_only=valid_only)
            if not handled:
                from .runtime.domain_background_read_v3 import read_bound_background_graph_type_rows_v3
                handled, rows = read_bound_background_graph_type_rows_v3(db,
                    NamespaceId(*parameters[:2]), type_id, columns, valid_only=valid_only)
            if handled:
                return rows if limit is None else rows[:limit]
    reader=begin_graph_rows_read_v3(db,columns,where=predicate,parameters=parameters,
        history=history,order_by=order_by,limit=limit)
    from .runtime.c09_paged_sql_v2 import C09PagedCaptureHold
    with handle.quantum() as meter:
        reader._require_stamp(meter)
        started=monotonic_ns()
        steps=0
        while not reader.complete and steps<meter.budget.max_records:
            if monotonic_ns()-started>=meter.budget.max_local_ns//2:
                break
            try:
                reader._advance_value(meter)
            except C09PagedCaptureHold:
                break
            steps+=1
        if reader.complete:
            reader._require_stamp(meter)
    if not reader.complete:
        raise RuntimeStorageNeedsContinuationV3(reader._progress(),continuation=reader)
    return tuple(reader.values)


def read_graph_head_v3(db, token, *, columns=("revision", "value", "valid"), namespace=None):
    where, parameters = "token=?", (token,)
    if namespace is not None:
        where += " AND bot=? AND persona=?"
        parameters += tuple(namespace)
    rows = read_graph_rows_v3(db, columns, where=where, parameters=parameters, limit=1)
    return rows[0] if rows else None


def read_graph_history_v3(db, token, revision, *,
                          columns=("value", "valid"), namespace=None):
    where, parameters = "token=? AND revision=?", (token, revision)
    if namespace is not None:
        where += " AND event_bot=? AND event_persona=?"
        parameters += tuple(namespace)
    rows = read_graph_rows_v3(db, columns, where=where, parameters=parameters, history=True, limit=1)
    return rows[0] if rows else None


class RuntimeJSONProjectionReadV3:
    """One fragment per advance; the existing operation owns continuation."""
    def __init__(self, db, cell_id, *, projection_id):
        from .runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.paths = _PROJECTIONS[projection_id]
        self.reader = begin_runtime_cell_read_v3(db, cell_id)
        self.operation = _operation(self.reader.handle)
        self.operation.retain(65536)
        self.parser = C09CanonicalJSONStreamV2(
            ensure_ascii=self.reader.header[0] == 'canonical-json.ascii.v1')
        self.chunks, self.result = {}, {}
        self.complete = False

    def next_cell_v3(self, db, cell_id):
        """Reuse this completed scalar reader's reserved workspace in the same Work."""
        from .runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        if (not self.complete or not self.reader.complete or self.operation.closed
                or runtime_storage_v3(db) is not self.reader.handle
                or _operation(self.reader.handle) is not self.operation):
            raise AuthorityUnavailable("next projection cell requires actual EOF and the same retained Work")
        self.reader = begin_runtime_cell_read_v3(db, cell_id)
        self.parser = C09CanonicalJSONStreamV2(
            ensure_ascii=self.reader.header[0] == 'canonical-json.ascii.v1')
        self.chunks, self.result = {}, {}
        self.complete = False
        return self

    def _emit(self, event):
        if event.path not in self.paths:
            return
        if event.kind == 'scalar_start':
            self.chunks[event.path] = bytearray()
        elif event.kind == 'scalar_chunk':
            target = self.chunks[event.path]
            if len(target) + len(event.raw) > 8192:
                raise AuthorityUnavailable('registered runtime projection exceeds its scalar reservation')
            target.extend(event.raw)
        elif event.kind == 'scalar_end':
            self.result[event.path] = json.loads(self.chunks.pop(event.path))

    def advance(self):
        if self.complete:
            return self.result
        with self.reader.handle.quantum() as meter:
            if self.reader.ordinal < self.reader.header[4]:
                self.parser.feed(self.reader.read_fragment(meter=meter), self._emit)
                return RuntimeStorageProgressV3(self.reader.handle.selection_digest,
                    self.reader.cell_id, self.reader.ordinal, self.reader.offset, self.reader.header[5],
                    _operation(self.reader.handle).operation_id, _operation(self.reader.handle).deadline_utc)
            complete = self.parser.finish()
            self.reader.finish(meter=meter)
            if complete.sha256 != self.reader.header[5] or complete.byte_count != self.reader.header[3]:
                raise AuthorityUnavailable('runtime JSON projection EOF differs from sealed payload')
            self.complete = True
            return self.result


def begin_runtime_json_projection_v3(db, cell_id, *, projection_id):
    return RuntimeJSONProjectionReadV3(db, cell_id, projection_id=projection_id)


def read_runtime_json_projection_v3(db, cell_id, *, projection_id):
    """Small fixed projection in one quantum; large consumers resume the reader."""
    value = json.loads(materialize_runtime_cell_v3(db, cell_id))
    result = {}
    for path in _PROJECTIONS[projection_id]:
        current = value
        for part in path:
            if type(current) is not dict or part not in current:
                break
            current = current[part]
        else:
            if type(current) not in (str,int,float,bool,type(None)):
                raise AuthorityUnavailable('registered runtime projection requires a scalar')
            if type(current) is str and len(current.encode('utf-8')) > 8192:
                raise AuthorityUnavailable('registered runtime projection exceeds its scalar reservation')
            result[path] = current
    return result

_RUNTIME_ORIGIN_DDL = """CREATE TABLE IF NOT EXISTS runtime_cell_origins_v3 (
    origin_digest TEXT PRIMARY KEY,selection_digest TEXT NOT NULL,role TEXT NOT NULL,
    authority_id TEXT NOT NULL,installation_id TEXT NOT NULL,namespace_json TEXT NOT NULL,
    operation_id TEXT NOT NULL,event_digest TEXT NOT NULL,locator_json TEXT NOT NULL,
    read_proof_json TEXT NOT NULL) STRICT"""


def reserve_runtime_payload_v3(db, value):
    """Reserve encoding/DTO copies before canonical serialization in the writer."""
    handle = runtime_storage_v3(db)
    if handle is None:
        return
    from .runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
    size = c09_canonical_json_size_v3(value, ascii=True, exact=True)
    _operation(handle).retain(size * 8 + 8192)


def seal_runtime_cell_in_transaction_v3(db, *, locator, erasure_owner_ref,
                                        operation_id, event_digest, namespace,
                                        read_proof, payload):
    """Trusted writer primitive after its existing business guard and exact CAS.

    Header, complete segments and producer original are committed by the same
    existing transaction as the actual business original/event reference.
    """
    from .runtime_contracts import canonical_serialize
    handle = runtime_storage_v3(db)
    operation = _operation(handle)
    if not db.in_transaction or type(payload) is not str:
        raise AuthorityUnavailable('runtime sealing requires the actual writer transaction and canonical bytes')
    encoded_size = len(payload.encode('utf-8'))
    if encoded_size * 4 + 32768 > 262144:
        raise RuntimeStorageNeedsContinuationV3(RuntimeStorageProgressV3(
            handle.selection_digest, canonical_digest(locator), 0, 0,
            sha256(payload.encode('utf-8')).hexdigest(), operation.operation_id, operation.deadline_utc))
    authority = handle.selected.basis.control
    origin = dict(schema='sylanne3.runtime-cell-origin.v3', selection_digest=handle.selection_digest,
        role=handle.role, authority_id=authority.authority_id, installation_id=authority.installation_id,
        namespace=namespace, operation_id=operation_id, event_digest=event_digest,
        locator=locator, read_proof=read_proof)
    origin_digest = canonical_digest(origin)
    cell_id = canonical_digest(dict(schema='sylanne3.runtime-cell-identity.v3',
        instance=handle.instance, origin_digest=origin_digest, locator=locator,
        payload_sha256=sha256(payload.encode('utf-8')).hexdigest()))
    encoded = payload.encode('utf-8')
    digest = sha256(encoded).hexdigest()
    root = canonical_digest(('sylanne3.segmented-cell-genesis.v1', cell_id))
    count = (len(encoded) + MAX_SEGMENT_BYTES - 1) // MAX_SEGMENT_BYTES
    with handle.quantum() as meter:
        meter.require_available(encoded_size * 4 + 32768)
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_cell_origins_v3'").fetchone() is None:
            raise AuthorityUnavailable("actual runtime origin schema was not installed at bootstrap")
        original = (origin_digest, handle.selection_digest, handle.role, authority.authority_id,
            authority.installation_id, canonical_serialize(namespace), operation_id, event_digest,
            canonical_serialize(locator), canonical_serialize(read_proof))
        prior = db.execute('SELECT * FROM runtime_cell_origins_v3 WHERE origin_digest=?',
            (origin_digest,)).fetchone()
        if prior is None:
            meter.charge_write(sum(len(v.encode('utf-8')) for v in original))
            db.execute('INSERT INTO runtime_cell_origins_v3 VALUES(?,?,?,?,?,?,?,?,?,?)', original)
        elif prior != original:
            raise AuthorityUnavailable('runtime immutable producer original replay differs')
        for ordinal, offset in enumerate(range(0, len(encoded), MAX_SEGMENT_BYTES)):
            chunk = encoded[offset:offset + MAX_SEGMENT_BYTES]
            segment_sha = sha256(chunk).hexdigest()
            root = canonical_digest(('sylanne3.segmented-cell-link.v1',
                root, cell_id, ordinal, offset, len(chunk), segment_sha))
            prior = db.execute('SELECT byte_offset,payload,payload_sha256 FROM segmented_cell_segments_v1 '
                'WHERE cell_id=? AND ordinal=?', (cell_id, ordinal)).fetchone()
            if prior is None:
                meter.charge_write(len(chunk) + 128)
                db.execute('INSERT INTO segmented_cell_segments_v1 VALUES(?,?,?,?,?)',
                    (cell_id, ordinal, offset, chunk, segment_sha))
            elif prior != (offset, chunk, segment_sha):
                raise AuthorityUnavailable('runtime immutable segment replay differs')
        header = (cell_id, 'canonical-json.ascii.v1', erasure_owner_ref, operation_id,
            len(encoded), count, digest, root, origin_digest)
        prior = db.execute('SELECT * FROM segmented_cells_v1 WHERE cell_id=?', (cell_id,)).fetchone()
        if prior is None:
            meter.charge_write(sum(len(v.encode('utf-8')) if type(v) is str else 8 for v in header))
            db.execute('INSERT INTO segmented_cells_v1 VALUES(?,?,?,?,?,?,?,?,?)', header)
        elif prior != header:
            raise AuthorityUnavailable('runtime immutable seal replay differs')
    return cell_id


def read_graph_row_v3(db, columns, *, where, parameters=(), history=False, order_by=()):
    rows = read_graph_rows_v3(db, columns, where=where, parameters=parameters,
        history=history, order_by=order_by, limit=1)
    return rows[0] if rows else None

@contextmanager
def runtime_storage_quantum_v3(db):
    """One enclosing actual runtime quantum; nested helpers share its meter."""
    handle = runtime_storage_v3(db)
    if handle is None:
        yield None
    else:
        _operation(handle)
        with handle.quantum() as meter:
            yield meter


def runtime_storage_quantum_method_v3(function):
    from functools import wraps
    @wraps(function)
    def run(self, *args, **kwargs):
        with runtime_storage_quantum_v3(self._db):
            return function(self, *args, **kwargs)
    return run


_CORE_PAYLOAD_KEYS = {
    'authority_d13_counter_originals_v1': ('namespace','counter_operation_id','phase'),
    'authority_d13_provider_http_bindings_v1': ('namespace','call_id','phase'),
}


def core_payload_schema_v3(db, table, legacy_schema):
    handle = runtime_storage_v3(db)
    if handle is None:
        return legacy_schema
    if handle.role != 'core' or table not in _CORE_PAYLOAD_KEYS:
        raise AuthorityUnavailable('actual registered Core payload role required')
    from .segmented_sql_cell_v1 import CORE_REF_DDLS_V2
    return CORE_REF_DDLS_V2[table]


def _core_payload_owner_v3(table, key):
    from .runtime_contracts import canonical_serialize
    family = ('d13-counter-source' if key[2]=='draft' else 'd13-counter-history'
        ) if table=='authority_d13_counter_originals_v1' else 'd13-provider-http-history'
    return canonical_serialize((family,key[0],key[1]))


_CORE_STREAM_ISSUER_V3=object()
from weakref import WeakSet,WeakKeyDictionary
_CORE_PAYLOAD_READERS_V3=WeakSet()
_CORE_PAYLOAD_EOFS_V3=WeakKeyDictionary()


def _core_payload_freeze_v3(value):
    from types import MappingProxyType
    if type(value)is dict:return MappingProxyType({key:_core_payload_freeze_v3(part)for key,part in value.items()})
    if type(value)in(tuple,list):return tuple(_core_payload_freeze_v3(part)for part in value)
    return value


def _core_payload_copy_v3(value):
    from collections.abc import Mapping
    if isinstance(value,Mapping):return {key:_core_payload_copy_v3(part)for key,part in value.items()}
    if type(value)is tuple:return [_core_payload_copy_v3(part)for part in value]
    return value


def _core_payload_matches_v3(value,sealed):
    from collections.abc import Mapping
    if isinstance(sealed,Mapping):
        return(type(value)is dict and value.keys()==sealed.keys()
            and all(_core_payload_matches_v3(value[key],part)for key,part in sealed.items()))
    if type(sealed)is tuple:
        return(type(value)in(tuple,list)and len(value)==len(sealed)
            and all(_core_payload_matches_v3(left,right)for left,right in zip(value,sealed)))
    if type(sealed)is str:return value is sealed
    return type(value)is type(sealed)and value==sealed


class PreparedCorePayloadEOFV3:
    def __init__(self,issuer,reader):
        if issuer is not _CORE_STREAM_ISSUER_V3 or not reader.complete or reader.row is None:
            raise AuthorityUnavailable('actual Core payload parser/cell complete EOF required')
        self.reader,self.db,self.table,self.key=reader,reader.db,reader.table,reader.key
        self.operation,self.handle,self.cell_id,self.digest=reader.operation,reader.handle,reader.row[0],reader.row[1]
        self.header=reader.cell.header
        from .runtime.natural_frozen_original_read_v3 import _canonical_container_bytes_v3
        self.operation.retain(_canonical_container_bytes_v3(reader.value)*2+1024)
        self._value=_core_payload_freeze_v3(reader.value);self._decoded=None
        _CORE_PAYLOAD_EOFS_V3[self]=(reader,self.db,self.table,self.key,self.operation,self.handle,
            self.cell_id,self.digest,self.header,self._value)
    def require_current_v3(self,db,table,key):
        reader=self.reader
        if (reader is None or _CORE_PAYLOAD_EOFS_V3.get(self)!=(reader,self.db,self.table,self.key,
                    self.operation,self.handle,self.cell_id,self.digest,self.header,self._value)
                or reader.result is not self or not reader.complete
                or reader.db is not db or reader.table!=table or reader.key!=tuple(key)
                or self.operation is not reader.operation or self.handle is not reader.handle
                or self.cell_id!=reader.row[0]or self.digest!=reader.row[1]or self.header!=reader.cell.header):
            raise AuthorityUnavailable('Core EOF proof lost its actual reader/PK/original lifetime')
        reader._require_current_v3()
        if reader._row_v3()!=reader.row:
            raise AuthorityUnavailable('Core immutable payload PK changed after complete EOF')
        return self
    def decoded_v3(self,db,table,key):
        self.require_current_v3(db,table,key)
        if self._decoded is None:
            from .runtime.natural_frozen_original_read_v3 import _canonical_container_bytes_v3
            self.operation.retain(_canonical_container_bytes_v3(self._value)*2+1024)
            self._decoded=_core_payload_copy_v3(self._value)
        elif not _core_payload_matches_v3(self._decoded,self._value):
            raise AuthorityUnavailable('Core decoded original changed its immutable EOF snapshot')
        return self._decoded
    def matches_v3(self,value):
        self.require_current_v3(self.db,self.table,self.key)
        return _core_payload_matches_v3(value,self._value)
    def release_payload_v3(self):
        _CORE_PAYLOAD_EOFS_V3.pop(self,None)
        self.reader=self._value=self._decoded=None


class _CorePayloadDecodedJSONV3:
    def __init__(self,reader,*,ensure_ascii):
        from .runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        owner=self
        class _Parser(C09CanonicalJSONStreamV2):
            def _append_decoded_codepoint(self,codepoint):
                if self._string is not None and self._string['mode']!='key':
                    owner._codepoint_v3(codepoint)
                else:super()._append_decoded_codepoint(codepoint)
        self.reader=reader;self.parser=_Parser(ensure_ascii=ensure_ascii)
        self.nodes={};self.value=None;self.scalar=bytearray();self.characters=[];self.string_parts=[];self.high=None
        self.reserved=0
    def _reserve_v3(self,extra=0):
        from .runtime.source_correction_read_v3 import _heap
        size=_heap((self.nodes,self.scalar,self.characters,self.string_parts,self.value))+extra+65536
        if size>self.reserved:self.reader.operation.retain(size-self.reserved);self.reserved=size
    def _put_v3(self,path,value):
        if not path:self.value=value
        else:
            parent=self.nodes[path[:-1]]
            if type(parent)is list:parent.append(value)
            else:parent[path[-1]]=value
    def _flush_v3(self):
        if self.characters:
            self._reserve_v3(len(self.characters)*4+1024)
            self.string_parts.append(''.join(self.characters));self.characters=[]
    def _codepoint_v3(self,codepoint):
        if self.high is not None:
            if 0xDC00<=codepoint<=0xDFFF:
                codepoint=0x10000+((self.high-0xD800)<<10)+(codepoint-0xDC00);self.high=None
            else:self.characters.append(chr(self.high));self.high=None
        if 0xD800<=codepoint<=0xDBFF:self.high=codepoint
        else:self.characters.append(chr(codepoint))
        if len(self.characters)>=1024:self._flush_v3()
    def _emit_v3(self,event):
        if event.kind in('object_start','array_start'):
            self._reserve_v3(1024);value={}if event.kind=='object_start'else[]
            self.nodes[event.path]=value;self._put_v3(event.path,value)
        elif event.kind=='scalar_start':
            self.scalar=bytearray();self.characters=[];self.string_parts=[];self.high=None
        elif event.kind=='scalar_chunk'and event.scalar_kind!='string':
            self._reserve_v3(len(event.raw)*4+1024);self.scalar.extend(event.raw)
        elif event.kind=='scalar_end':
            if event.scalar_kind=='string':
                if self.high is not None:self.characters.append(chr(self.high));self.high=None
                self._flush_v3();self._reserve_v3(sum(len(part)for part in self.string_parts)*4+1024)
                value=''.join(self.string_parts);self.string_parts=[]
            else:value=json.loads(self.scalar);self.scalar=bytearray()
            self._put_v3(event.path,value)
    def feed_v3(self,fragment):
        self._reserve_v3(65536);self.parser.feed(fragment,self._emit_v3)
    def finish_v3(self):return self.parser.finish()
    def release_payload_v3(self):
        self.nodes.clear();self.value=self.parser=None;self.scalar=self.characters=self.string_parts=None


class _CorePayloadReadV3:
    def __init__(self,issuer,db,table,key,*,expected_value=None):
        if issuer is not _CORE_STREAM_ISSUER_V3 or table not in _CORE_PAYLOAD_KEYS or type(key)is not tuple or len(key)!=3:
            raise AuthorityUnavailable('actual fixed Core original reader required')
        handle=runtime_storage_v3(db)
        if handle is None or handle.role!='core'or key[0]!=handle.selected.basis.prepared['namespace']:
            raise AuthorityUnavailable('Core original reader requires its actual selected Core namespace')
        self.db,self.table,self.key,self.handle=db,table,key,handle
        self.operation=_operation(handle);self.where=' AND '.join(column+'=?'for column in _CORE_PAYLOAD_KEYS[table])
        self.phase='row';self.complete=False;self.result=None;self.row=None;self.cell=self.decoder=None
        self.fragment=b'';self.fragment_offset=0;self.value=None
        self.expected_value=expected_value;self.expected=None;self.expected_fragment=b'';self.expected_offset=0
        _CORE_PAYLOAD_READERS_V3.add(self)
        if expected_value is not None:
            from .runtime.owner_material_source_storage_v3 import CanonicalValueStreamV3
            self.expected=CanonicalValueStreamV3(expected_value)
    def _require_current_v3(self,meter=None):
        if (self not in _CORE_PAYLOAD_READERS_V3 or runtime_storage_v3(self.db)is not self.handle
                or _operation(self.handle)is not self.operation):
            raise AuthorityUnavailable('Core original reader changed operation or selected handle')
        if meter is None:
            with self.handle.quantum()as actual:self.handle.require_current(actual)
        else:self.handle.require_current(meter)
    def _row_v3(self):
        with self.handle.quantum()as meter:
            return meter.read_fixed_row(self.db,self.table,('payload_cell_id','payload_digest'),self.where,self.key)
    def advance(self,*,meter):
        self._require_current_v3(meter)
        if self.complete:return self
        if self.phase=='row':
            self.row=meter.read_fixed_row(self.db,self.table,('payload_cell_id','payload_digest'),self.where,self.key)
            if self.row is None:self.complete=True;return self
            self.cell=RuntimeCellReadV3(self.handle,self.row[0],erasure_owner_ref=_core_payload_owner_v3(self.table,self.key),meter=meter)
            if self.cell.header[0]not in('canonical-json.ascii.v1','canonical-json.utf8.v1')or self.cell.header[5]!=self.row[1]:
                raise AuthorityUnavailable('actual Core canonical codec/payload digest differs')
            self.decoder=_CorePayloadDecodedJSONV3(self,ensure_ascii=True)
            self.phase='fragment';return self
        if self.fragment_offset<len(self.fragment):
            if self.expected is not None and self.expected_offset==len(self.expected_fragment):
                if self.expected.complete:raise AuthorityUnavailable('Core prior payload exceeds actual expected canonical EOF')
                if meter.available_bytes<196608:return self
                self.expected_fragment=self.expected.read_fragment(meter)or b'';self.expected_offset=0;return self
            amount=min(1024,len(self.fragment)-self.fragment_offset)
            if self.expected is not None:amount=min(amount,len(self.expected_fragment)-self.expected_offset)
            if not amount:raise AuthorityUnavailable('Core expected canonical stream ended before actual payload')
            chunk=self.fragment[self.fragment_offset:self.fragment_offset+amount]
            if self.expected is not None:
                if chunk!=self.expected_fragment[self.expected_offset:self.expected_offset+amount]:
                    raise AuthorityUnavailable('Core immutable original differs from actual expected canonical fragment')
                self.expected_offset+=amount
            meter.charge_encode(len(chunk));self.decoder.feed_v3(chunk);self.fragment_offset+=amount;return self
        if self.cell.ordinal<self.cell.header[4]:
            self.fragment=self.cell.read_fragment(meter=meter);self.fragment_offset=0;return self
        if self.expected is not None and not self.expected.complete:
            if meter.available_bytes<196608:return self
            chunk=self.expected.read_fragment(meter)
            if chunk:raise AuthorityUnavailable('Core actual payload ended before expected canonical EOF')
            return self
        if self.expected is not None and self.expected_offset!=len(self.expected_fragment):
            raise AuthorityUnavailable('Core actual payload ended before expected canonical bytes')
        parsed=self.decoder.finish_v3();digest=self.cell.finish(meter=meter)
        if (parsed.sha256,parsed.byte_count)!=(digest,self.cell.header[3])or self._row_v3()!=self.row:
            raise AuthorityUnavailable('Core payload parser/cell/PK complete EOF differs')
        self.value=self.decoder.value;self.complete=True
        self.result=PreparedCorePayloadEOFV3(_CORE_STREAM_ISSUER_V3,self)
        self.decoder.release_payload_v3();self.decoder=None;self.value=None
        self.expected=self.expected_value=None;self.fragment=self.expected_fragment=b''
        return self
    def require_v3(self,db,table,key):
        if not self.complete or self.db is not db or self.table!=table or self.key!=tuple(key):
            raise AuthorityUnavailable('Core original requires its actual complete fixed PK reader')
        self._require_current_v3()
        if self.result is None:
            if self._row_v3()is not None:raise AuthorityUnavailable('Core absent original changed after complete point read')
            return None
        return self.result.require_current_v3(db,table,key)
    def release_payload_v3(self):
        _CORE_PAYLOAD_READERS_V3.discard(self)
        if self.result is not None:self.result.release_payload_v3()
        if self.decoder is not None:self.decoder.release_payload_v3()
        self.result=self.decoder=self.cell=self.value=self.expected=self.expected_value=None
        self.fragment=self.expected_fragment=b''


def begin_core_payload_read_v3(db,table,key):
    return _CorePayloadReadV3(_CORE_STREAM_ISSUER_V3,db,table,tuple(key))


class _CorePayloadWriteV3:
    def __init__(self,issuer,db,table,key,payload):
        if issuer is not _CORE_STREAM_ISSUER_V3 or table not in _CORE_PAYLOAD_KEYS or type(key)is not tuple or len(key)!=3:
            raise AuthorityUnavailable('actual fixed Core payload writer required')
        self.db,self.table,self.key=db,table,key;self.handle=runtime_storage_v3(db)
        if self.handle is None or self.handle.role!='core'or key[0]!=self.handle.selected.basis.prepared['namespace']:
            raise AuthorityUnavailable('Core original writer requires actual selected namespace')
        self.operation=_operation(self.handle)
        from .runtime.natural_frozen_original_read_v3 import _canonical_container_bytes_v3
        from .runtime_contracts import _canonical_value
        from .runtime.owner_material_source_storage_v3 import CanonicalValueStreamV3
        self.operation.retain(_canonical_container_bytes_v3(payload)*2+65536)
        self.value=_canonical_value(payload,set());self.stream=CanonicalValueStreamV3(self.value)
        self.phase='canonical';self.complete=False;self.result=None;self.prior_reader=self.verify_reader=None
        self.read_proof=None;self.transaction_started=False
    def _require_current_v3(self,meter=None):
        if(runtime_storage_v3(self.db)is not self.handle or _operation(self.handle)is not self.operation
                or self.transaction_started and not self.db.in_transaction):
            raise AuthorityUnavailable('Core payload writer lost its actual operation/transaction')
        if meter is not None:self.handle.require_current(meter)
    def attach_read_proof_v3(self,read_proof):
        self._require_current_v3()
        if self.phase!='ready'or not self.db.in_transaction:
            raise AuthorityUnavailable('Core payload must complete canonical EOF before actual writer transaction')
        from .runtime_contracts import _canonical_value
        self.read_proof=_canonical_value(read_proof,set());self.transaction_started=True;self.phase='prior'
    def advance(self,*,meter):
        self._require_current_v3(meter)
        if self.complete:return self
        if self.phase=='canonical':
            if meter.available_bytes<196608:return self
            self.stream.read_fragment(meter)
            if self.stream.complete:
                self.digest,self.byte_count=self.stream.hash.hexdigest(),self.stream.offset
                self.stream=None;self.phase='ready'
            return self
        if self.phase=='prior':
            if self.prior_reader is None:
                self.prior_reader=_CorePayloadReadV3(_CORE_STREAM_ISSUER_V3,self.db,self.table,self.key,expected_value=self.value)
            self.prior_reader.advance(meter=meter)
            if self.prior_reader.complete:
                if self.prior_reader.result is not None:
                    if self.prior_reader.result.digest!=self.digest:raise AuthorityUnavailable('Core prior canonical commitment differs')
                    self.result=self.prior_reader.result;self.verify_reader=self.prior_reader;self.complete=True;self.value=None
                else:self.phase='origin'
            return self
        if self.phase=='origin':
            from .runtime_contracts import canonical_serialize
            authority=self.handle.selected.basis.control
            locator=dict(table=self.table,primary_key=self.key,column='payload_json')
            origin=dict(schema='sylanne3.runtime-cell-origin.v3',selection_digest=self.handle.selection_digest,
                role=self.handle.role,authority_id=authority.authority_id,installation_id=authority.installation_id,
                namespace=self.key[0],operation_id=self.key[1],event_digest=self.digest,locator=locator,read_proof=self.read_proof)
            self.origin_digest=canonical_digest(origin)
            self.cell_id=canonical_digest(dict(schema='sylanne3.runtime-cell-identity.v3',instance=self.handle.instance,
                origin_digest=self.origin_digest,locator=locator,payload_sha256=self.digest))
            original=(self.origin_digest,self.handle.selection_digest,self.handle.role,authority.authority_id,
                authority.installation_id,canonical_serialize(self.key[0]),self.key[1],self.digest,
                canonical_serialize(locator),canonical_serialize(self.read_proof))
            prior=self.db.execute('SELECT * FROM runtime_cell_origins_v3 WHERE origin_digest=?',(self.origin_digest,)).fetchone()
            if prior is None:
                meter.charge_write(sum(len(part.encode('utf-8'))for part in original))
                self.db.execute('INSERT INTO runtime_cell_origins_v3 VALUES(?,?,?,?,?,?,?,?,?,?)',original)
            elif prior!=original:raise AuthorityUnavailable('Core runtime origin immutable replay differs')
            from .runtime.owner_material_source_storage_v3 import CanonicalValueStreamV3
            self.stream=CanonicalValueStreamV3(self.value);self.ordinal=self.offset=0
            self.root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',self.cell_id));self.phase='segments';return self
        if self.phase=='segments':
            if meter.available_bytes<196608:return self
            chunk=self.stream.read_fragment(meter)
            if chunk:
                segment_sha=sha256(chunk).hexdigest()
                prior=meter.read_fixed_row(self.db,'segmented_cell_segments_v1',('byte_offset','payload','payload_sha256'),
                    'cell_id=? AND ordinal=?',(self.cell_id,self.ordinal))
                if prior is None:
                    meter.charge_write(len(chunk)+128)
                    self.db.execute('INSERT INTO segmented_cell_segments_v1 VALUES(?,?,?,?,?)',
                        (self.cell_id,self.ordinal,self.offset,chunk,segment_sha))
                elif prior!=(self.offset,chunk,segment_sha):raise AuthorityUnavailable('Core runtime segment immutable replay differs')
                self.root=canonical_digest(('sylanne3.segmented-cell-link.v1',self.root,self.cell_id,
                    self.ordinal,self.offset,len(chunk),segment_sha));self.ordinal+=1;self.offset+=len(chunk)
            if self.stream.complete:
                if(self.stream.hash.hexdigest(),self.offset)!=(self.digest,self.byte_count):
                    raise AuthorityUnavailable('Core canonical second-pass SHA/size differs')
                self.stream=None;self.phase='attach'
            return self
        if self.phase=='attach':
            if self.ordinal!=(self.byte_count+MAX_SEGMENT_BYTES-1)//MAX_SEGMENT_BYTES:
                raise AuthorityUnavailable('Core canonical segment count differs')
            header=(self.cell_id,'canonical-json.ascii.v1',_core_payload_owner_v3(self.table,self.key),self.key[1],
                self.byte_count,self.ordinal,self.digest,self.root,self.origin_digest)
            prior=self.db.execute('SELECT * FROM segmented_cells_v1 WHERE cell_id=?',(self.cell_id,)).fetchone()
            if prior is None:
                meter.charge_write(sum(len(part.encode('utf-8'))if type(part)is str else 8 for part in header))
                self.db.execute('INSERT INTO segmented_cells_v1 VALUES(?,?,?,?,?,?,?,?,?)',header)
            elif prior!=header:raise AuthorityUnavailable('Core runtime sealed header immutable replay differs')
            meter.charge_write(sum(len(part.encode('utf-8'))for part in self.key)+128)
            self.db.execute('INSERT INTO '+self.table+' VALUES(?,?,?,?,?)',(*self.key,self.cell_id,self.digest))
            self.verify_reader=_CorePayloadReadV3(_CORE_STREAM_ISSUER_V3,self.db,self.table,self.key,expected_value=self.value)
            self.phase='verify';return self
        if self.phase=='verify':
            self.verify_reader.advance(meter=meter)
            if self.verify_reader.complete:
                self.result=self.verify_reader.result
                if self.result is None or self.result.digest!=self.digest:
                    raise AuthorityUnavailable('Core written original lacks actual read-back dual EOF')
                self.complete=True;self.value=None
            return self
        raise AuthorityUnavailable('Core payload writer requires its original transaction admission')
    def require_v3(self,db,table,key):
        self._require_current_v3()
        if not self.complete or self.db is not db or self.table!=table or self.key!=tuple(key):
            raise AuthorityUnavailable('Core payload requires complete write/read-back EOF')
        return self.result.require_current_v3(db,table,key)
    def release_payload_v3(self):
        for reader in(self.prior_reader,self.verify_reader):
            if reader is not None:reader.release_payload_v3()
        self.result=self.value=self.stream=self.prior_reader=self.verify_reader=self.read_proof=None


def begin_core_payload_write_v3(db,table,key,payload):
    return _CorePayloadWriteV3(_CORE_STREAM_ISSUER_V3,db,table,tuple(key),payload)


def read_core_payload_row_v3(db, table, key):
    columns = _CORE_PAYLOAD_KEYS[table]
    handle = runtime_storage_v3(db)
    if handle is not None and (handle.role != 'core' or key[0] != handle.selected.basis.prepared['namespace']):
        raise AuthorityUnavailable('Core original crosses its actual selected namespace')
    where = ' AND '.join(column+'=?' for column in columns)
    field = 'payload_json' if handle is None else 'payload_cell_id'
    row = db.execute('SELECT '+field+',payload_digest FROM '+table+' WHERE '+where, key).fetchone()
    if row is None:
        return None
    encoded = row[0] if handle is None else materialize_runtime_cell_v3(
        db,row[0],erasure_owner_ref=_core_payload_owner_v3(table,key))
    if sha256(encoded.encode('utf-8')).hexdigest() != row[1]:
        raise AuthorityUnavailable('actual immutable Core payload digest differs')
    return encoded,row[1]


def insert_core_payload_row_v3(db, table, key, encoded, digest, *, read_proof):
    handle = runtime_storage_v3(db)
    if handle is None:
        db.execute('INSERT INTO '+table+' VALUES(?,?,?,?,?)',(*key,encoded,digest))
        return
    if not db.in_transaction or handle.role != 'core' or key[0] != handle.selected.basis.prepared['namespace']:
        raise AuthorityUnavailable('Core payload requires its actual selected writer transaction')
    cell_id = seal_runtime_cell_in_transaction_v3(db,
        locator=dict(table=table,primary_key=key,column='payload_json'),
        erasure_owner_ref=_core_payload_owner_v3(table,key), operation_id=key[1],
        event_digest=digest, namespace=key[0], read_proof=read_proof, payload=encoded)
    db.execute('INSERT INTO '+table+' VALUES(?,?,?,?,?)',(*key,cell_id,digest))


def read_runtime_cell_origin_v3(db,cell_id,*,header=None,meter=None):
    """Ordinary producer verification after the separate installed business gate."""
    handle=runtime_storage_v3(db)
    _operation(handle)
    if meter is None:
        with handle.quantum() as actual:
            return read_runtime_cell_origin_v3(db,cell_id,header=header,meter=actual)
    original=read_selected_runtime_cell_origin_v3(db,selected_basis=handle.selected,role=handle.role,
        cell_id=cell_id,header=header,meter=meter)
    if (original is not None and original.get('producer_kind')=='owner_material_source_prepared_v3'
            and original['phase']!='committed'):
        raise AuthorityUnavailable('unattached prepared Source cells are not ordinary business values')
    return original


def _runtime_bounded_fixed_row_v3(db,meter,table,columns,where,parameters):
    """Observe byte lengths and reserve the actual decode peak before transfer."""
    from .runtime.c09_paged_sql_v2 import _quote
    lengths=db.execute('SELECT '+','.join('length(CAST('+_quote(column)+' AS BLOB))' for column in columns)
        +' FROM '+_quote(table)+' WHERE '+where+' LIMIT 1',parameters).fetchone()
    if lengths is None:
        return None
    amount=sum(size or 0 for size in lengths)
    meter.require_available(amount+256)
    if amount*8+4096>meter.budget.reserved_arena_bytes:
        raise AuthorityUnavailable('actual runtime producer decode requires its registered fragment consumer')
    operation=_OPERATION.get()
    if operation is not None:
        operation.retain(amount*8+4096)
    return meter.read_fixed_row(db,table,columns,where,parameters)


def read_selected_runtime_cell_origin_v3(db,*,selected_basis,role,cell_id,header,meter):
    """Pure installed cold read: no business handle, mutation or fresh budget."""
    from .authority_service.c09_selected_history_v3 import (
        _InstalledSelectedStorageBasisV3,VerifiedSelectedHistoryReadV3)
    from .runtime_contracts import canonical_digest
    if type(selected_basis) is VerifiedSelectedHistoryReadV3:
        basis=selected_basis.basis
        selected_scope_digest=selected_basis.scope.scope_digest
    elif type(selected_basis) is _InstalledSelectedStorageBasisV3:
        basis=selected_basis
        selected_scope_digest=basis.prepared['capture_scope_digest']
    else:
        raise AuthorityUnavailable('actual private installed selected cold basis required')
    if type(db) is not sqlite3.Connection or role not in ('graph','core'):
        raise AuthorityUnavailable('actual selected cold SQLite Graph/Core role required')
    basis.require_current(meter=meter)
    member=basis.member(role)
    databases=db.execute('PRAGMA database_list').fetchall()
    if len(databases)!=1 or Path(databases[0][2]).resolve(strict=True)!=Path(member['resolved_path']).resolve(strict=True):
        raise AuthorityUnavailable('cold producer database differs from its actual selected role')
    instance=basis.manifest['segmented_layouts'][role]['storage_instance_id']
    if header is None:
        full = _runtime_bounded_fixed_row_v3(db,meter,'segmented_cells_v1',
            ('codec_id','erasure_owner_ref','producer_operation_id','total_bytes','segment_count',
             'payload_sha256','ordered_segment_root','origin_scope_digest'),'cell_id=?',(cell_id,))
        if full is None:
            raise AuthorityUnavailable('runtime producer cell is absent')
        header = full
    exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_cell_origins_v3'").fetchone()
    if exists is None:
        if header[7] != selected_scope_digest:
            raise AuthorityUnavailable('cell has neither selected capture nor actual runtime producer')
        return None
    row = _runtime_bounded_fixed_row_v3(db,meter,'runtime_cell_origins_v3',
        ('origin_digest','selection_digest','role','authority_id','installation_id','namespace_json',
         'operation_id','event_digest','locator_json','read_proof_json'),'origin_digest=?',(header[7],))
    if row is None:
        if role=='graph':
            from .runtime.owner_material_source_storage_v3 import read_selected_owner_source_cell_v3
            owner_source=read_selected_owner_source_cell_v3(db,basis=basis,cell_id=cell_id,header=header,meter=meter)
            if owner_source is not None:return owner_source
        if header[7] != selected_scope_digest:
            raise AuthorityUnavailable('cell runtime producer original is absent')
        return None
    namespace,locator,proof = json.loads(row[5]),json.loads(row[8]),json.loads(row[9])
    original = dict(schema='sylanne3.runtime-cell-origin.v3',selection_digest=row[1],
        role=row[2],authority_id=row[3],installation_id=row[4],namespace=namespace,
        operation_id=row[6],event_digest=row[7],locator=locator,read_proof=proof)
    if (canonical_digest(original) != row[0] or row[0] != header[7]
            or row[2] != role or row[3] != basis.control.authority_id
            or row[4] != basis.control.installation_id or row[6] != header[2]):
        raise AuthorityUnavailable('actual immutable runtime producer identity or digest differs')
    expected_cell = canonical_digest(dict(schema='sylanne3.runtime-cell-identity.v3',
        instance=instance,origin_digest=row[0],locator=locator,payload_sha256=header[5]))
    if expected_cell != cell_id:
        raise AuthorityUnavailable('runtime cell is not bound to its actual producer and layout')
    if role == 'graph':
        from .graph_types import AtomKey
        from .runtime_contracts import canonical_serialize,NamespaceId,namespace_ref
        key = AtomKey.from_token(locator['token'])
        if (locator['table'] != 'graph_atoms' or header[1] != key.token
                or namespace != [key.owner.bot,key.owner.persona]
                or namespace_ref(NamespaceId(*namespace)) != basis.prepared['namespace']
                or proof['event_scope'][:2] != namespace or proof['event_scope'][3] != row[6]):
            raise AuthorityUnavailable('runtime Graph producer locator or namespace differs')
        event = _runtime_bounded_fixed_row_v3(db,meter,'graph_events',('digest','reads','epoch_reads'),
            'bot=? AND persona=? AND session=? AND event_id=?',tuple(proof['event_scope']))
        history = _runtime_bounded_fixed_row_v3(db,meter,'graph_history',
            ('value_cell_id','dependencies','event_bot','event_persona','event_session','event_id'),
            'token=? AND revision=?',(key.token,locator['revision']))
        if (event != (row[7],canonical_serialize(proof['reads']),canonical_serialize(proof['epochs']))
                or history is None or history[0] != cell_id or list(history[2:]) != proof['event_scope']
                or sorted(item[0] for item in json.loads(history[1])) != sorted(proof['dependencies'])):
            raise AuthorityUnavailable('runtime Graph cell lacks its exact committed event/history producer')
    elif role == 'core':
        key = tuple(locator['primary_key'])
        table = locator['table']
        if (table not in _CORE_PAYLOAD_KEYS or locator['column'] != 'payload_json'
                or namespace != key[0] or namespace != basis.prepared['namespace']
                or key[1] != row[6] or header[1] != _core_payload_owner_v3(table,key)):
            raise AuthorityUnavailable('runtime Core producer original locator differs')
        where = ' AND '.join(column+'=?' for column in _CORE_PAYLOAD_KEYS[table])
        actual = _runtime_bounded_fixed_row_v3(db,meter,table,('payload_cell_id','payload_digest'),where,key)
        if actual != (cell_id,header[5]) or row[7] != header[5]:
            raise AuthorityUnavailable('runtime Core cell lacks its actual immutable phase producer')
    else:
        raise AuthorityUnavailable('ordinary runtime cell producer role is not registered')
    return original


def bind_runtime_database_from_control_v3(db, *, control, role):
    """Installed composition seam for independently opened real role readers."""
    if type(db) is not sqlite3.Connection:
        raise TypeError('actual SQLite role connection required')
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='segmented_storage_layout_v1'").fetchone() is None:
        return None
    context = control.read_verified_current_storage_v3()
    selected = control._selected_history_read_v3
    return install_selected_runtime_storage_v3(db,role=role,selected=selected,context=context)


def _registered_graph_predicate_v3(where, allowed):
    """Finite metadata predicate grammar; no SQL functions, expressions or queries."""
    import re
    if type(where) is not str or len(where.encode('utf-8')) > 8192:
        raise ValueError('registered Graph metadata predicate exceeds its descriptor bound')
    pattern=re.compile(r"\s*(?:(?P<string>'(?:[^']|'')*')|(?P<integer>-?\d+)|(?P<word>[A-Za-z_][A-Za-z_0-9]*)|(?P<punct><=|>=|!=|<>|[=<>?(),]))")
    tokens=[];offset=0
    while offset<len(where):
        if not where[offset:].strip():break
        match=pattern.match(where,offset)
        if match is None:raise ValueError('unregistered Graph metadata SQL token')
        tokens.append((match.lastgroup,match.group(match.lastgroup)))
        offset=match.end()
    if not tokens or len(tokens)>2048:
        raise ValueError('registered Graph metadata token bound exceeded')
    index=0
    def peek(value):
        return index<len(tokens) and tokens[index][1].upper()==value
    def take(value):
        nonlocal index
        if not peek(value):raise ValueError('registered Graph predicate syntax differs')
        index+=1
    def operand(*,column=True):
        nonlocal index
        if index>=len(tokens):raise ValueError('Graph metadata predicate lacks operand')
        kind,value=tokens[index]
        if kind in ('string','integer') or value=='?':
            index+=1;return
        if column and kind=='word' and value.lower() in allowed:
            index+=1;return
        raise ValueError('Graph predicate operand is not a registered metadata column or scalar')
    def relation(depth):
        nonlocal index
        if depth>32:raise ValueError('registered Graph predicate nesting exceeded')
        if peek('('):
            take('(');boolean(depth+1);take(')');return
        operand()
        if peek('COLLATE'):take('COLLATE');take('BINARY')
        if peek('IS'):
            take('IS')
            if peek('NOT'):take('NOT')
            take('NULL');return
        if peek('NOT'):take('NOT');take('IN');in_values();return
        if peek('IN'):take('IN');in_values();return
        if index>=len(tokens) or tokens[index][1] not in ('=','!=','<>','<','>','<=','>='):
            raise ValueError('registered Graph metadata comparison required')
        index+=1;operand()
        if peek('COLLATE'):take('COLLATE');take('BINARY')
    def in_values():
        take('(');operand(column=False)
        while peek(','):take(',');operand(column=False)
        take(')')
    def conjunction(depth):
        if peek('NOT'):take('NOT')
        relation(depth)
        while peek('AND'):
            take('AND')
            if peek('NOT'):take('NOT')
            relation(depth)
    def boolean(depth):
        conjunction(depth)
        while peek('OR'):take('OR');conjunction(depth)
    boolean(0)
    if index!=len(tokens):raise ValueError('Graph predicate contains an unregistered SQL continuation')
    return ' '.join(value for kind,value in tokens)


class RuntimeGraphRowsReadV3:
    """Explicit metadata keyset and retained body continuation for one operation."""
    def __init__(self,db,columns,*,where,parameters=(),history=False,order_by=(),limit=None):
        self.db,self.handle=db,runtime_storage_v3(db)
        self.operation=_operation(self.handle)
        self.operation.retain(65536)
        self.columns,self.parameters,self.history=columns,tuple(parameters),history
        self.allowed=_HISTORY_COLUMNS if history else _HEAD_COLUMNS
        if type(columns) is not tuple or not columns or any(c not in self.allowed for c in columns):
            raise ValueError('registered Graph projection columns required')
        self.where=_registered_graph_predicate_v3(where,self.allowed-{'value','value_cell_id'})
        if order_by not in ((),('token',),('token','revision')):
            raise ValueError('Graph continuation requires its registered token/revision keyset')
        if limit is not None and (type(limit) is not int or not 1<=limit<=513):
            raise ValueError('Graph projection limit must be 1..513')
        self.limit=limit
        self.after=None
        self.values=[]
        self.pending=None
        self.complete=False
        self.table='graph_history' if history else 'graph_atoms'
        self.keys=('token','revision') if history else ('token',)
        self.stored=tuple('value_cell_id' if c=='value' else c for c in columns)
        self.projected=self.keys+self.stored
        self.cell_reader,self.buffer,self.buffer_offset=None,None,0
        self.namespace=tuple(json.loads(self.handle.selected.scope.graph_namespace))
        self.expected_stamp=None

    def _require_stamp(self,meter):
        from .contracts import StaleRead
        recovery=_runtime_bounded_fixed_row_v3(self.db,meter,'graph_recovery_metadata_v2',
            ('schema','requirements_json','graph_revision'),'bot=? AND persona=?',self.namespace)
        epoch=_runtime_bounded_fixed_row_v3(self.db,meter,'graph_epochs',
            ('revision',),'bot=? AND persona=?',self.namespace)
        authority=_runtime_bounded_fixed_row_v3(self.db,meter,'graph_authority_epochs',
            ('access_epoch','delete_epoch'),'bot=? AND persona=?',self.namespace)
        if recovery is None or epoch is None or authority is None:
            raise AuthorityUnavailable('actual current Graph traversal stamps are absent')
        stamp=(recovery,epoch,authority)
        if self.expected_stamp is None:
            self.expected_stamp=stamp
        elif self.expected_stamp!=stamp:
            raise StaleRead('Graph traversal identity, epoch, access or deletion changed between actual quanta')

    def _next(self,meter):
        where,parameters=self.where,self.parameters
        if self.after is not None:
            if self.history:
                where='('+where+') AND (token>? OR (token=? AND revision>?))'
                parameters+= (self.after[0],self.after[0],self.after[1])
            else:
                where='('+where+') AND token>?';parameters+=(self.after[0],)
        order='token,revision' if self.history else 'token'
        return _runtime_bounded_fixed_row_v3(self.db,meter,self.table,self.projected,
            where+' ORDER BY '+order,parameters)

    def _progress(self):
        reader=self.cell_reader
        return RuntimeStorageProgressV3(self.handle.selection_digest,
            '' if reader is None else reader.cell_id,
            0 if reader is None else reader.ordinal,0 if reader is None else reader.offset,
            '' if reader is None else reader.header[5],self.operation.operation_id,self.operation.deadline_utc)

    def _advance_value(self,meter):
        if self.pending is None:
            raw=self._next(meter)
            if raw is None:
                self.complete=True
                return
            self.after=raw[:len(self.keys)]
            self.pending=list(raw[len(self.keys):])
            self.value_indices=[i for i,c in enumerate(self.columns) if c=='value']
            self.value_cursor=0
        if self.value_cursor < len(self.value_indices):
            index=self.value_indices[self.value_cursor]
            if self.cell_reader is None:
                self.cell_reader=RuntimeCellReadV3(self.handle,self.pending[index],meter=meter)
                amount=self.cell_reader.header[3]
                self.operation.retain(amount*8+8192)
                self.buffer=bytearray(amount);self.buffer_offset=0
            reader=self.cell_reader
            if reader.ordinal<reader.header[4]:
                fragment=reader.read_fragment(meter=meter)
                self.buffer[self.buffer_offset:self.buffer_offset+len(fragment)]=fragment
                self.buffer_offset+=len(fragment)
                return
            reader.finish(meter=meter)
            if reader.header[0] not in ('canonical-json.ascii.v1','canonical-json.utf8.v1'):
                raise AuthorityUnavailable('registered Graph JSON projection requires its canonical codec')
            self.pending[index]=self.buffer.decode('utf-8')
            self.cell_reader,self.buffer=None,None
            self.value_cursor+=1
            return
        self.values.append(tuple(self.pending));self.pending=None
        if self.limit is not None and len(self.values)==self.limit:
            self.complete=True

    def advance(self):
        """One row/fragment step, always using the retained original operation."""
        with bind_runtime_storage_operation_v3(self.operation,self.db),runtime_storage_quantum_v3(self.db) as meter:
            self._require_stamp(meter)
            if not self.complete:
                self._advance_value(meter)
            if self.complete:
                self._require_stamp(meter)
        return tuple(self.values) if self.complete else self._progress()


def begin_graph_rows_read_v3(db,columns,*,where,parameters=(),history=False,order_by=(),limit=None):
    return RuntimeGraphRowsReadV3(db,columns,where=where,parameters=parameters,
        history=history,order_by=order_by,limit=limit)

def selected_runtime_catalogue_v3(role):
    """Fixed exact schema descriptors, shared by installed bootstrap and census."""
    if role not in ('graph','core'):return
    definitions={'runtime_cell_origins_v3':_RUNTIME_ORIGIN_DDL}
    immutable=['runtime_cell_origins_v3']
    if role=='graph':
        from .runtime.owner_material_source_storage_v3 import PREPARED_DDL,DISPOSITION_DDL,COMMAND_SEED_DDL
        from .runtime.domain_production_originals_v1 import PHYSICAL_DDL
        definitions.update(graph_owner_source_command_seeds_v3=COMMAND_SEED_DDL,graph_owner_source_prepared_v3=PREPARED_DDL,
            graph_owner_source_dispositions_v3=DISPOSITION_DDL,graph_domain_production_originals_v3=PHYSICAL_DDL)
        immutable+=['graph_owner_source_command_seeds_v3','graph_owner_source_dispositions_v3','graph_domain_production_originals_v3']
    else:
        from .authority_service.d13_provider_http_admission_v1 import _INDEX_DDL,_CURSOR_DDL,_SEAL_DDL
        definitions.update(runtime_d13_counter_calls_v3=_INDEX_DDL,
            runtime_d13_counter_index_cursor_v3=_CURSOR_DDL,runtime_d13_counter_index_seals_v3=_SEAL_DDL)
        immutable+=['runtime_d13_counter_calls_v3','runtime_d13_counter_index_seals_v3']
    for name,ddl in definitions.items():yield ('table',name,ddl.replace('IF NOT EXISTS ',''))
    for table in immutable:
        for action in ('UPDATE','DELETE'):
            name=table+'_no_'+action.lower()+'_v3'
            ddl="CREATE TRIGGER "+name+" BEFORE "+action+" ON "+table+" BEGIN SELECT RAISE(ABORT,'runtime metadata original is immutable'); END"
            yield ('trigger',name,ddl)
    yield ('index','segmented_runtime_cell_origin_lookup_v3',
        'CREATE INDEX segmented_runtime_cell_origin_lookup_v3 ON segmented_cells_v1(origin_scope_digest,cell_id)')
    if role=='graph':
        columns=('prepared_digest','bot','persona','operation_id','attempt_id','request_claim_digest','metadata_json',
            'input_sha256','input_bytes','original_digest','original_bytes','source_sha256','source_bytes')
        condition=' OR '.join('NEW.'+name+' IS NOT OLD.'+name for name in columns)
        name='graph_owner_source_prepared_immutable_content_v3'
        ddl=('CREATE TRIGGER '+name+' BEFORE UPDATE ON graph_owner_source_prepared_v3 WHEN '+condition+
            " BEGIN SELECT RAISE(ABORT,'Owner Source prepared content is immutable'); END")
        yield ('trigger',name,ddl)
        yield ('index','graph_owner_source_prepared_operation_v3',
            'CREATE INDEX graph_owner_source_prepared_operation_v3 ON graph_owner_source_prepared_v3(bot,persona,operation_id)')
        yield ('index','graph_owner_source_prepared_attempt_unique_v3',
            'CREATE UNIQUE INDEX graph_owner_source_prepared_attempt_unique_v3 ON graph_owner_source_prepared_v3(bot,persona,operation_id,attempt_id)')
        yield ('index','graph_domain_production_lookup_v3',
            'CREATE INDEX graph_domain_production_lookup_v3 ON graph_domain_production_originals_v3(bot,persona,domain,operation_kind,operation_id)')
    else:
        yield ('index','runtime_d13_counter_call_lookup_v3',
            'CREATE INDEX runtime_d13_counter_call_lookup_v3 ON runtime_d13_counter_calls_v3(selection_digest,namespace,generation_call_id)')


def install_runtime_storage_schema_v3(db,*,handle):
    """One installed bootstrap registration of the exact census catalogue."""
    if type(db) is not sqlite3.Connection or handle is not runtime_storage_v3(db):
        raise AuthorityUnavailable('actual installed runtime role handle required for schema registration')
    if db.in_transaction:
        raise AuthorityUnavailable('runtime schema bootstrap cannot run inside a business write transaction')
    if handle.role not in ('graph','core'):return
    with handle.quantum():
        db.execute('BEGIN IMMEDIATE')
        try:
            for kind,name,ddl in selected_runtime_catalogue_v3(handle.role):
                row=db.execute('SELECT sql FROM sqlite_master WHERE type=? AND name=?',(kind,name)).fetchone()
                if row is None:db.execute(ddl)
                elif row!=(ddl,):raise AuthorityUnavailable('actual fixed runtime schema descriptor differs: '+name)
            db.execute('COMMIT')
        except BaseException:
            db.execute('ROLLBACK');raise


_PHYSICAL = object()
_MAINTENANCE_OPERATION = object()


class PhysicalRuntimeHandleV3(InstalledRuntimeStorageV3):
    """Physical role composition only; an operation is a separate private issuer."""
    def __init__(self,issuer,db,role,capability):
        if issuer is not _PHYSICAL:
            raise AuthorityUnavailable('private selected physical factory required')
        super().__init__(_INSTALLED,db,role,capability.selected,capability.context)
        self.capability=capability
        self.purpose='physical_maintenance'

    @contextmanager
    def quantum(self):
        from .runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2,require_c09_reserved_meter_v3
        current=current_c09_sql_meter_v2()
        meter=require_c09_reserved_meter_v3(current.budget)
        prior=_QUANTUM.get()
        if prior is not None and (prior[0] is not self.pool or prior[1]!=self.selection_digest or prior[2] is not meter):
            raise AuthorityUnavailable("maintenance codec crossed its existing actual reservation")
        token=_QUANTUM.set((self.pool,self.selection_digest,meter))
        try:
            self.require_current(meter)
            with meter_canonical_outputs(meter):
                yield meter
            self.require_current(meter)
        finally:
            _QUANTUM.reset(token)

    def require_current(self,meter):
        current=self.capability.require_current(meter=meter)
        stat=Path(self.member['resolved_path']).stat()
        if self._closed or (stat.st_dev,stat.st_ino)!=(self.member['device'],self.member['file_id']):
            raise AuthorityUnavailable('actual selected maintenance role identity changed')
        operation=_OPERATION.get()
        if operation is not None:
            if type(operation) is not MaintenanceRuntimeOperationV3:
                raise AuthorityUnavailable('physical maintenance handle refuses ordinary business operation')
            operation.require_current(self)
        return current


class MaintenanceRuntimeOperationV3(RuntimeStorageOperationV3):
    def __init__(self,issuer,handle,actor,core,credential):
        if issuer is not _MAINTENANCE_OPERATION:
            raise AuthorityUnavailable('actual maintenance runtime operation issuer required')
        super().__init__(_INSTALLED,handle,actor.operation_id,None)
        self.actor,self.core,self.credential=actor,core,credential
        self.kind='maintenance'

    def require_current(self,handle):
        from .authority_service.c09_maintenance_actor_v3 import InstalledC09MaintenanceActorV3
        from .authority_service.c09_selected_history_v3 import MaintenanceSelectedBasisV3
        if (self.closed or type(self.actor) is not InstalledC09MaintenanceActorV3
                or type(handle.capability) is not MaintenanceSelectedBasisV3
                or self.actor.maintenance.core is not self.core
                or self.credential is not self.actor.maintenance.credential
                or self.actor.maintenance.control is not handle.capability.physical.control
                or self.actor.operation_id!=handle.capability.operation_id):
            raise AuthorityUnavailable('actual same-actor installed maintenance scope required')
        self.core._require(self.credential,'delete',self.actor.maintenance.closure.namespace)


def install_selected_maintenance_storage_v3(db,*,role,basis):
    """Open only identity/schema metadata before actual actor/Core composition."""
    from .authority_service.c09_selected_history_v3 import SelectedPhysicalCompositionV3,MaintenanceSelectedBasisV3
    if type(db) is not sqlite3.Connection or type(basis) not in (SelectedPhysicalCompositionV3,MaintenanceSelectedBasisV3):
        raise AuthorityUnavailable('actual private selected physical composition required')
    if role not in ('graph','core','deletion','execution'):
        raise AuthorityUnavailable('registered physical role required')
    member=basis.basis.member(role)
    databases=db.execute('PRAGMA database_list').fetchall()
    if len(databases)!=1 or Path(databases[0][2]).resolve(strict=True)!=Path(member['resolved_path']).resolve(strict=True):
        raise AuthorityUnavailable('physical maintenance database differs from its selected role')
    with _BINDINGS_LOCK:
        if db in _BINDINGS:
            raise AuthorityUnavailable('actual runtime connection is already composed')
        handle=PhysicalRuntimeHandleV3(_PHYSICAL,db,role,basis)
        with handle.quantum() as meter:
            basis.require_current(meter=meter)
            basis.basis.require_layout(db,role,meter=meter)
        _BINDINGS[db]=handle
        return handle


def begin_maintenance_runtime_operation_v3(handle,*,actor,core,credential):
    if type(handle) is not PhysicalRuntimeHandleV3:
        raise AuthorityUnavailable('actual private maintenance physical handle required')
    lease=MaintenanceRuntimeOperationV3(_MAINTENANCE_OPERATION,handle,actor,core,credential)
    lease.require_current(handle)
    with handle.quantum():
        pass
    return lease


@contextmanager
def bind_maintenance_runtime_operation_v3(lease,db):
    handle=runtime_storage_v3(db)
    if (type(lease) is not MaintenanceRuntimeOperationV3 or type(handle) is not PhysicalRuntimeHandleV3
            or lease.closed or lease.pool is not handle.pool or lease.selection_digest!=handle.selection_digest):
        raise AuthorityUnavailable('actual same selected maintenance operation required')
    lease.require_current(handle)
    token=_OPERATION.set(lease)
    try:
        yield lease
    finally:
        _OPERATION.reset(token)


def require_maintenance_runtime_operation_v3(db):
    """Require the actual same-actor maintenance lease before scoped body recovery."""
    handle=runtime_storage_v3(db)
    if type(handle) is not PhysicalRuntimeHandleV3:
        raise AuthorityUnavailable('actual private maintenance physical role required')
    lease=_operation(handle)
    if type(lease) is not MaintenanceRuntimeOperationV3:
        raise AuthorityUnavailable('actual bound maintenance operation required')
    lease.require_current(handle)
    return lease
