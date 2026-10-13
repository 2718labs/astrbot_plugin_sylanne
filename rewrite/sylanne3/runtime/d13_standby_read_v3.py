"""D13's fixed standby metadata census on one actual worker read operation."""
from contextlib import contextmanager
from contextvars import ContextVar
from weakref import WeakKeyDictionary
import math
import secrets

from ..authority_service.contract import AuthorityUnavailable
from ..graph_worker import GraphStorageStepV3, create_graph_storage_work_v3, require_graph_storage_work_admission_v3
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3, bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3, runtime_storage_quantum_v3, runtime_storage_v3,
    begin_runtime_json_projection_v3)

KIND = "d13_standby_read_v3"
_TYPE = "d13.compressed_turn_block.v2"
_ISSUER = object()
_READS = WeakKeyDictionary()
_BOUND = ContextVar("d13_standby_read_v3", default=None)


class _StandbyReadV3:
    def __init__(self, issuer, graph, authority, lease, operation, fence, scene_ref):
        if issuer is not _ISSUER:
            raise AuthorityUnavailable("actual D13 standby read issuer required")
        self.graph, self.authority, self.lease = graph, authority, lease
        self.operation, self.fence, self.scene_ref = operation, fence, scene_ref
        self.db = graph._GraphCoordinator__store._db
        self.work = None
        self.cursor, self.row, self.body = "", None, None
        self.max_expiry = None
        self.complete, self.proof = False, None

    def require_current(self):
        from .d13_paid_product_v1 import _authorize
        from .first_ingress_v2 import trusted_upper
        _, port, _, _, _ = _authorize(self.graph, self.authority, self.lease)
        now = trusted_upper(port.read_ingress_clock(self.graph._GraphCoordinator__scene_clock_policy))
        if now >= self.operation.deadline_utc:
            raise AuthorityUnavailable("D13 standby original preparation deadline expired")
        if (self.work is None or self.work.state is not self
                or self.work.operation is not self.operation or self.operation.closed
                or runtime_storage_v3(self.db) is not self.operation.handle):
            raise AuthorityUnavailable("D13 standby lost its actual Work or selected storage")
        self.graph._validate_read_fence_v3(self.fence)


class PreparedD13StandbyReadV3:
    def __init__(self, issuer, reader):
        if issuer is not _ISSUER or not reader.complete:
            raise AuthorityUnavailable("actual complete D13 standby EOF required")
        self.reader, self.max_expiry = reader, reader.max_expiry
        _READS[self] = (reader, self.max_expiry)

    def require_for(self, graph, db, authority, scene_ref, window):
        reader = self.reader
        if (_READS.get(self) != (reader, self.max_expiry) or reader.operation.closed
                or graph is not reader.graph or db is not reader.db or authority != reader.authority
                or scene_ref != reader.scene_ref or not reader.complete
                or window.namespace != authority.namespace or window.conversation_ref != authority.audience[0]):
            raise AuthorityUnavailable("actual D13 standby scope/window/EOF differs")
        # The read permit has ended; current scheduling still performs its own
        # original authority/write admission. This proof supplies only read facts.
        if graph._v2_graph_stamp(authority.namespace) != (reader.fence.metadata, reader.fence.epoch):
            raise AuthorityUnavailable("D13 standby namespace changed after its EOF")
        if window.trusted_utc >= reader.operation.deadline_utc:
            raise AuthorityUnavailable("D13 standby original preparation deadline expired")
        return self.max_expiry is not None and self.max_expiry > window.trusted_utc

    def release_payload_v3(self):
        if _READS.pop(self, None) is None:
            return
        self.max_expiry = None
        self.reader.max_expiry = None
        self.reader.body = self.reader.row = self.reader.proof = None


def prepare_d13_standby_read_v3(graph, authority, lease, *, scene_ref):
    from .d13_paid_product_v1 import _authorize
    from .first_ingress_v2 import trusted_upper
    require_graph_storage_work_admission_v3(graph)
    store, port, policy, _, _ = _authorize(graph, authority, lease)
    now = trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    deadline = now + policy.deadline_after_seconds
    operation_id = "d13-standby:" + secrets.token_hex(24)
    operation = begin_runtime_storage_operation_v3(store._db, operation_id, deadline)
    fence = None
    try:
        with bind_runtime_storage_operation_v3(operation, store._db):
            fence = graph._begin_read_fence_v3(authority, operation_id=operation_id)
            reader = _StandbyReadV3(_ISSUER, graph, authority, lease, operation, fence, scene_ref)
        work = create_graph_storage_work_v3(graph, kind=KIND, operation_id=operation_id,
            selection_digest=operation.selection_digest, deadline_utc=deadline,
            state=reader, operation=operation)
        reader.work = work
        operation.retain(65536)
        return work
    except BaseException:
        try:
            if fence is not None:
                graph._finish_read_fence_v3(fence)
        finally:
            finish_runtime_storage_operation_v3(operation)
        raise


def advance_d13_standby_read_v3(graph, work):
    reader = work.state
    with bind_runtime_storage_operation_v3(work.operation, reader.db):
        reader.require_current()
        with graph._GraphCoordinator__store._lock:
            db = reader.db
            db.execute("BEGIN")
            try:
                with runtime_storage_quantum_v3(db) as meter:
                    if reader.row is None:
                        row = meter.read_fixed_row(db, "graph_atoms",
                            ("token", "revision", "valid", "value_cell_id"),
                            "bot=? AND persona=? AND type_name=? AND valid=1 AND token>? ORDER BY token",
                            (*reader.authority.namespace.as_tuple, _TYPE, reader.cursor))
                        if row is None:
                            reader.complete = True
                            reader.proof = PreparedD13StandbyReadV3(_ISSUER, reader)
                        else:
                            reader.row = tuple(row)
                            reader.body = (begin_runtime_json_projection_v3(
                                db, row[3], projection_id="d13.standby-metadata.v3")
                                if reader.body is None else reader.body.next_cell_v3(db, row[3]))
                            if reader.body.reader.header[1] != row[0]:
                                raise AuthorityUnavailable("D13 standby cell has another erasure owner")
                    else:
                        head = meter.read_fixed_row(db, "graph_atoms",
                            ("token", "revision", "valid", "value_cell_id"),
                            "token=?", (reader.row[0],))
                        if head is None or tuple(head) != reader.row:
                            raise AuthorityUnavailable("D13 standby cell lost its actual current head")
                        reader.body.advance()
                        if reader.body.complete:
                            value = reader.body.result
                            expected = {("conversation_ref",), ("status",), ("expires_at_utc",), ("schema",)}
                            if (set(value) != expected or value[("schema",)] != _TYPE
                                    or type(value[("conversation_ref",)]) is not str
                                    or value[("status",)] not in {"standby", "active", "retired"}
                                    or type(value[("expires_at_utc",)]) not in (int, float)
                                    or not math.isfinite(value[("expires_at_utc",)])):
                                raise AuthorityUnavailable("D13 standby metadata has another registered shape")
                            if (value[("conversation_ref",)] == reader.authority.audience[0]
                                    and value[("status",)] == "standby"):
                                expiry = value[("expires_at_utc",)]
                                reader.max_expiry = expiry if reader.max_expiry is None else max(reader.max_expiry, expiry)
                            reader.cursor, reader.row = reader.row[0], None
            finally:
                db.rollback()
        reader.require_current()
    return GraphStorageStepV3("complete", reader.proof) if reader.complete else GraphStorageStepV3("progress")


def finish_d13_standby_read_v3(graph, work, error):
    reader = work.state
    try:
        graph._finish_read_fence_v3(reader.fence)
        if error is None:
            work.result_lease = work.operation
    finally:
        if error is not None or work.result_lease is None:
            if reader.proof is not None:
                reader.proof.release_payload_v3()
            reader.body = reader.row = None
            reader.max_expiry = None
            finish_runtime_storage_operation_v3(work.operation)


@contextmanager
def bind_prepared_d13_standby_v3(proof):
    if type(proof) is not PreparedD13StandbyReadV3 or _READS.get(proof) != (proof.reader, proof.max_expiry):
        raise AuthorityUnavailable("actual issued D13 standby read proof required")
    token = _BOUND.set(proof)
    try:
        yield proof
    finally:
        _BOUND.reset(token)


def current_d13_standby_v3(graph, db, authority, *, scene_ref, window):
    proof = _BOUND.get()
    if type(proof) is not PreparedD13StandbyReadV3:
        raise AuthorityUnavailable("D13 scheduling requires its actual prepared standby census")
    return proof.require_for(graph, db, authority, scene_ref, window), proof.reader.operation.deadline_utc
