"""Discover committed pending IDs without generated history or Source Body.

The result only schedules the existing P2/dispatch consumer. It grants no
execution, budget, content read or replay permission.
"""
from sys import getsizeof
from weakref import WeakKeyDictionary
import json
import secrets
from ..authority_service.contract import AuthorityUnavailable
from ..graph_worker import (GraphStorageStepV3, create_graph_storage_work_v3,
    require_graph_storage_work_admission_v3)
from ..runtime_storage_v3 import (runtime_storage_v3, begin_runtime_storage_operation_v3,
    bind_runtime_storage_operation_v3, finish_runtime_storage_operation_v3,
    runtime_storage_quantum_v3, begin_runtime_cell_read_v3)
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2

KIND = "natural_pending_dispatch_metadata_read_v3"
_READERS = WeakKeyDictionary()
_PATHS = frozenset({("commit_seq",), ("natural_dispatch_candidate", "schema"),
    ("natural_dispatch_candidate", "digest")})


class _ReceiptMetadataV3:
    def __init__(self, reader, cell_id):
        self.cell = begin_runtime_cell_read_v3(reader.db, cell_id)
        codec = self.cell.header[0]
        if codec not in {"canonical-json.ascii.v1", "canonical-json.utf8.v1"}:
            raise AuthorityUnavailable("pending receipt canonical codec differs")
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=codec == "canonical-json.ascii.v1")
        self.metadata, self.scalar = {}, bytearray()
        self.fragment, self.offset, self.complete = b"", 0, False

    def emit(self, event):
        if event.path not in _PATHS:
            return
        if event.kind == "scalar_start":
            self.scalar.clear()
        elif event.kind == "scalar_chunk":
            if len(self.scalar) + len(event.raw) > 4096:
                raise AuthorityUnavailable("pending receipt fixed identifier exceeds its bound")
            self.scalar.extend(event.raw)
        elif event.kind == "scalar_end":
            self.metadata[event.path] = json.loads(self.scalar)
            self.scalar.clear()

    def advance(self, meter):
        if self.offset < len(self.fragment):
            end = min(self.offset + 1024, len(self.fragment))
            self.parser.feed(self.fragment[self.offset:end], self.emit)
            self.offset = end
            return
        fragment = self.cell.read_fragment(meter=meter)
        if fragment is not None:
            self.fragment, self.offset = fragment, 0
            return
        parsed = self.parser.finish()
        digest = self.cell.finish(meter=meter)
        if (parsed.sha256, parsed.byte_count) != (digest, self.cell.header[3]):
            raise AuthorityUnavailable("pending receipt canonical whole EOF differs from its selected cell")
        self.complete, self.fragment, self.parser = True, b"", None


class _PendingDispatchReadV3:
    def __init__(self, graph, authority, lease, after, limit):
        require_graph_storage_work_admission_v3(graph)
        graph._authorize(lease, authority, frozenset({"d08", "d09", "d11"}), owner_read=True)
        self.graph, self.authority, self.lease = graph, authority, lease
        self.namespace, self.after, self.limit = authority.namespace, after, limit
        self.store, self.db = graph._GraphCoordinator__store, graph._GraphCoordinator__store._db
        self.operation = begin_runtime_storage_operation_v3(self.db, KIND + ":" + secrets.token_hex(20), None)
        self.fence = self.work = self.column = self.current = None
        self.items, self.scanned, self.cursor = [], 0, after or ""
        self.complete, self.closed, self.result = False, False, None
        try:
            with bind_runtime_storage_operation_v3(self.operation, self.db):
                self.fence = graph._begin_read_fence_v3(authority,
                    operation_id=self.operation.operation_id,
                    owner_binding=graph._GraphCoordinator__owner_leases.get(lease),
                    owner_session_proof=graph._GraphCoordinator__owner_session_proofs.get(lease))
            self.stamp = self.fence.metadata, self.fence.epoch
            self.operation.register_retained_state_v3(self)
        except BaseException:
            try:
                if self.fence is not None:
                    with bind_runtime_storage_operation_v3(self.operation, self.db):
                        graph._finish_read_fence_v3(self.fence)
            finally:
                finish_runtime_storage_operation_v3(self.operation)
            raise

    def _runtime_retained_heap_bytes_v3(self):
        size = 131072 + sum(getsizeof(item) + sum(getsizeof(v) for v in (
            item.operation_id, item.effect_id, item.outbox_ref)) for item in self.items)
        if self.column is not None:
            size += len(self.column.fragment) + len(self.column.scalar) + getsizeof(self.column.metadata)
        return size

    def require_current(self):
        if (_READERS.get(self) != (self.graph, self.authority, self.lease, self.operation,
                self.fence, self.after, self.limit) or self.closed or self.operation.closed
                or self.work.state is not self or self.work.operation is not self.operation
                or self.work.coordinator is not self.graph or self.work.kind != KIND
                or runtime_storage_v3(self.db) is not self.operation.handle):
            raise AuthorityUnavailable("pending dispatch metadata lost its actual same Work")
        self.work._require_invocation(self.graph)
        self.graph._authorize(self.lease, self.authority, frozenset({"d08", "d09", "d11"}), owner_read=True)
        if self.graph._v2_graph_stamp(self.namespace) != self.stamp:
            raise AuthorityUnavailable("pending dispatch Graph changed during discovery")

    def page(self, eof):
        from ..graph_coordinator import NaturalPendingDispatchPageV2
        self.result = NaturalPendingDispatchPageV2(self.namespace, tuple(self.items),
            None if eof else self.cursor, self.stamp[0].graph_revision, self.stamp[1].revision)
        self.complete = True

    def advance(self, meter):
        from ..graph_coordinator import NaturalPendingDispatchItemV2
        ns = self.namespace.as_tuple
        if self.column is None:
            if self.scanned == self.limit:
                self.page(False)
                return
            row = meter.read_fixed_row(self.db, "graph_bundle_outbox", ("operation_id", "outbox_ref"),
                "bot=? AND persona=? AND operation_id>? AND phase='pending' ORDER BY operation_id,outbox_ref",
                (*ns, self.cursor))
            if row is None:
                self.page(True)
                return
            operation, outbox = row
            bundle = meter.read_fixed_row(self.db, "graph_bundle_operations",
                ("effect_id", "commit_seq", "receipt_json_cell_id"),
                "bot=? AND persona=? AND operation_id=?", (*ns, operation))
            if bundle is None or type(bundle[1]) is not int or bundle[1] < 1 or bundle[2] is None:
                raise AuthorityUnavailable("pending outbox lacks its committed selected receipt")
            self.current = operation, outbox, bundle[0], bundle[1]
            self.column = _ReceiptMetadataV3(self, bundle[2])
            return
        self.column.advance(meter)
        if not self.column.complete:
            return
        operation, outbox, effect, commit_seq = self.current
        data = self.column.metadata
        if data.get(("commit_seq",)) != commit_seq:
            raise AuthorityUnavailable("pending receipt differs from actual bundle commit metadata")
        if data.get(("natural_dispatch_candidate", "schema")) == "sylanne.d11.natural_dispatch_candidate.v2":
            digest = data.get(("natural_dispatch_candidate", "digest"))
            if (type(digest) is not str or len(digest) != 64
                    or any(c not in "0123456789abcdef" for c in digest) or not effect):
                raise AuthorityUnavailable("pending natural candidate identity commitments differ")
            admission = meter.read_fixed_row(self.db, "graph_dispatch_admissions",
                ("admission_ref", "admission_digest", "receipt_digest"),
                "bot=? AND persona=? AND operation_id=? AND effect_id=?", (*ns, operation, effect))
            other = meter.read_fixed_row(self.db, "graph_bundle_outbox", ("outbox_ref",),
                "bot=? AND persona=? AND operation_id=? AND outbox_ref<>? ORDER BY outbox_ref",
                (*ns, operation, outbox))
            if admission is None or other is not None:
                raise AuthorityUnavailable("pending natural outbox lacks its unique admission/outbox")
            self.items.append(NaturalPendingDispatchItemV2(operation, effect, outbox))
        self.cursor, self.scanned = operation, self.scanned + 1
        self.column = self.current = None

    def release(self):
        if self.closed:
            return
        _READERS.pop(self, None)
        self.column = self.current = None
        self.items.clear()
        self.operation.unregister_retained_state_v3(self)
        self.closed = True


def begin_natural_pending_dispatch_metadata_v3(graph, authority, lease, *, after, limit):
    reader = _PendingDispatchReadV3(graph, authority, lease, after, limit)
    try:
        reader.work = create_graph_storage_work_v3(graph, kind=KIND,
            operation_id=reader.operation.operation_id, selection_digest=reader.operation.selection_digest,
            deadline_utc=None, state=reader, operation=reader.operation)
        _READERS[reader] = (graph, authority, lease, reader.operation, reader.fence, after, limit)
        return reader.work
    except BaseException:
        try:
            with bind_runtime_storage_operation_v3(reader.operation, reader.db):
                graph._finish_read_fence_v3(reader.fence)
        finally:
            reader.release()
            finish_runtime_storage_operation_v3(reader.operation)
        raise


def advance_natural_pending_dispatch_metadata_v3(graph, work):
    reader = work.state
    if type(reader) is not _PendingDispatchReadV3 or reader.graph is not graph:
        raise AuthorityUnavailable("actual pending-dispatch metadata Work required")
    with bind_runtime_storage_operation_v3(reader.operation, reader.db):
        graph._validate_read_fence_v3(reader.fence)
        with reader.store._lock, runtime_storage_quantum_v3(reader.db) as meter:
            if reader.db.in_transaction:
                raise AuthorityUnavailable("pending metadata must own its READ quantum")
            reader.db.execute("BEGIN")
            try:
                reader.require_current()
                reader.advance(meter)
                reader.require_current()
            finally:
                reader.db.rollback()
    return GraphStorageStepV3("complete", reader.result) if reader.complete else GraphStorageStepV3("progress")


def finish_natural_pending_dispatch_metadata_v3(graph, work, error):
    reader = work.state
    if type(reader) is not _PendingDispatchReadV3 or reader.graph is not graph:
        raise AuthorityUnavailable("pending metadata finish crossed its actual Work")
    failure = error
    try:
        with bind_runtime_storage_operation_v3(reader.operation, reader.db):
            graph._finish_read_fence_v3(reader.fence)
        if failure is None and not reader.complete:
            raise AuthorityUnavailable("pending metadata cannot publish a partial receipt")
    except BaseException as exc:
        if failure is None:
            failure = exc
        else:
            failure.add_note("pending metadata READ finish also failed: " + type(exc).__name__)
    finally:
        reader.release()
        finish_runtime_storage_operation_v3(reader.operation)
    if failure is not None:
        raise failure
