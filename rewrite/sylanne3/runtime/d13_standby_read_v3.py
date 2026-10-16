"""D13's fixed standby metadata census on one actual worker read operation."""
from contextlib import contextmanager
from contextvars import ContextVar
from weakref import WeakKeyDictionary
from ..graph_types import AtomKey, Owner
from ..runtime_contracts import canonical_digest
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
        self.scene_token = None
        self.ledger_cursor, self.ledger_rows, self.ledger_blocks = "", {}, {}
        self.phase, self.ledger_row, self.ledger_job = "scene", None, None
        self.ledger_head, self.ledger_body, self.ledger_eof = None, None, False
        self.complete, self.proof = False, None
        self.read_finished, self.paid_original_read = False, None

    def require_current(self):
        from .d13_paid_product_v1 import _authorize
        from .first_ingress_v2 import trusted_upper
        _, port, _, _, _ = _authorize(self.graph, self.authority, self.lease)
        now = trusted_upper(port.read_ingress_clock(self.graph._GraphCoordinator__scene_clock_policy))
        self.now_utc = now
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
        self.ledger_rows = dict(reader.ledger_rows)
        self.ledger_blocks = dict(reader.ledger_blocks)
        self.ledger_root = canonical_digest(("d13.scene-ledger-metadata-eof.v3", reader.scene_token,
            tuple(sorted(self.ledger_rows.items())), tuple(sorted(self.ledger_blocks.items()))))
        self.current_ledger_rows = dict(self.ledger_rows)
        _READS[self] = (reader, self.max_expiry, self.ledger_root, self.ledger_rows, self.ledger_blocks)

    def require_for(self, graph, db, authority, scene_ref, window):
        reader = self.reader
        if (_READS.get(self) != (reader, self.max_expiry, self.ledger_root, self.ledger_rows, self.ledger_blocks) or reader.operation.closed
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

    def require_scene_ledger_v3(self, db, namespace, scene_token, now_utc):
        reader = self.reader
        if (_READS.get(self) != (reader, self.max_expiry, self.ledger_root, self.ledger_rows, self.ledger_blocks)
                or db is not reader.db or namespace != reader.authority.namespace
                or scene_token != reader.scene_token or not reader.ledger_eof
                or reader.operation.closed or now_utc >= reader.operation.deadline_utc
                or runtime_storage_v3(db) is not reader.operation.handle
                or reader.work.state is not reader or reader.work.operation is not reader.operation
                or reader.work.selection_digest != reader.operation.selection_digest
                or reader.graph._v2_graph_stamp(namespace) != (reader.fence.metadata, reader.fence.epoch)):
            raise AuthorityUnavailable("D13 ledger requires its exact current same-Work metadata EOF")
        reader.work._require_invocation(reader.graph)
        with runtime_storage_quantum_v3(db) as meter:
            cursor = ""
            for job_ref, expected in sorted(self.current_ledger_rows.items()):
                row = meter.read_fixed_row(db, "graph_d13_paid_scene_jobs_v1",
                    ("job_ref", "input_digest", "state", "expires_at_utc"),
                    "bot=? AND persona=? AND scene_ref=? AND job_ref>? ORDER BY job_ref",
                    (*namespace.as_tuple, scene_token, cursor))
                if row != expected:
                    raise AuthorityUnavailable("D13 paid scene ledger metadata coverage changed")
                cursor = job_ref
                if job_ref in self.ledger_blocks:
                    job, token, head, metadata = self.ledger_blocks[job_ref]
                    actual_job = meter.read_fixed_row(db, "runtime_jobs",
                        ("bot_id", "persona_id", "work_kind", "result_ref"), "job_id=?", (job_ref,))
                    actual_head = (meter.read_fixed_row(db, "graph_atoms",
                        ("token", "revision", "valid", "value_cell_id"), "token=?", (token,)) if token else None)
                    if actual_job != job or actual_head != head:
                        raise AuthorityUnavailable("D13 ledger job/result/block current head changed")
            if meter.read_fixed_row(db, "graph_d13_paid_scene_jobs_v1", ("job_ref",),
                    "bot=? AND persona=? AND scene_ref=? AND job_ref>? ORDER BY job_ref",
                    (*namespace.as_tuple, scene_token, cursor)) is not None:
                raise AuthorityUnavailable("D13 ledger lacks complete exact scene-job coverage")
        return tuple(self.current_ledger_rows.values()), self.ledger_blocks

    def record_scene_ledger_state_v3(self, job_ref, state):
        prior = self.current_ledger_rows[job_ref]
        if prior[2] != "standby" or state not in {"active", "retired"}:
            raise AuthorityUnavailable("D13 ledger proof requires its original standby transition")
        self.current_ledger_rows[job_ref] = (*prior[:2], state, prior[3])

    def release_payload_v3(self):
        if _READS.pop(self, None) is None:
            return
        self.max_expiry = None
        self.reader.max_expiry = None
        if self.reader.paid_original_read is not None and self.reader.paid_original_read.proof is not None:
            self.reader.paid_original_read.proof.release_payload_v3()
        self.reader.paid_original_read = None
        self.reader.body = self.reader.row = self.reader.proof = None
        self.current_ledger_rows.clear(); self.ledger_rows.clear(); self.ledger_blocks.clear()
        self.reader.ledger_rows.clear(); self.reader.ledger_blocks.clear()
        self.reader.ledger_row = self.reader.ledger_job = self.reader.ledger_head = self.reader.ledger_body = None


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
            from .d13_paid_original_read_v3 import observe_d13_paid_owner_guard_v3
            fence = graph._begin_read_fence_v3(authority, operation_id=operation_id,
                fence_observer=lambda scope: observe_d13_paid_owner_guard_v3(graph, authority, scope))
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
                    if reader.phase != "census":
                        _advance_d13_scene_ledger_metadata_v3(reader, meter)
                    elif reader.row is None:
                        row = meter.read_fixed_row(db, "graph_atoms",
                            ("token", "revision", "valid", "value_cell_id"),
                            "bot=? AND persona=? AND type_name=? AND valid=1 AND token>? ORDER BY token",
                            (*reader.authority.namespace.as_tuple, _TYPE, reader.cursor))
                        if row is None:
                            from .d13_paid_original_read_v3 import begin_d13_paid_original_reader_in_work_v3
                            reader.phase = "paid"
                            begin_d13_paid_original_reader_in_work_v3(reader,job_id=None,
                                method="schedule_d13_paid_precompression_v1",args={"scene_ref":reader.scene_ref})
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
        reader.read_finished = True
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
    if type(proof) is not PreparedD13StandbyReadV3 or _READS.get(proof) != (proof.reader, proof.max_expiry, proof.ledger_root, proof.ledger_rows, proof.ledger_blocks):
        raise AuthorityUnavailable("actual issued D13 standby read proof required")
    from .d13_paid_original_read_v3 import bind_prepared_d13_paid_original_v3
    token = _BOUND.set(proof)
    try:
        with bind_prepared_d13_paid_original_v3(proof.reader.paid_original_read.proof):
            yield proof
    finally:
        _BOUND.reset(token)


def current_d13_standby_v3(graph, db, authority, *, scene_ref, window):
    proof = _BOUND.get()
    if type(proof) is not PreparedD13StandbyReadV3:
        raise AuthorityUnavailable("D13 scheduling requires its actual prepared standby census")
    return proof.require_for(graph, db, authority, scene_ref, window), proof.reader.operation.deadline_utc

def _advance_d13_scene_ledger_metadata_v3(reader, meter):
    db, ns = reader.db, reader.authority.namespace
    if reader.phase == "paid":
        reader.paid_original_read.advance_v3(meter)
        if reader.paid_original_read.complete:
            reader.complete = True
            reader.proof = PreparedD13StandbyReadV3(_ISSUER, reader)
        return
    if reader.phase == "scene":
        where = "bot=? AND persona=? AND owner_kind='scene' AND subject=? AND type_name='d03.role_binding' AND valid=1"
        row = meter.read_fixed_row(db, "graph_atoms", ("token",), where+" ORDER BY token", (*ns.as_tuple, reader.scene_ref))
        if row is None or meter.read_fixed_row(db, "graph_atoms", ("token",), where+" AND token>? ORDER BY token",
                (*ns.as_tuple, reader.scene_ref, row[0])) is not None:
            raise AuthorityUnavailable("D13 ledger needs its exact unique current scene binding")
        reader.scene_token, reader.phase = row[0], "ledger"
        return
    if reader.phase == "ledger":
        row = meter.read_fixed_row(db, "graph_d13_paid_scene_jobs_v1",
            ("job_ref", "input_digest", "state", "expires_at_utc"),
            "bot=? AND persona=? AND scene_ref=? AND job_ref>? ORDER BY job_ref",
            (*ns.as_tuple, reader.scene_token, reader.ledger_cursor))
        if row is None:
            reader.ledger_eof, reader.phase = True, "census"
            return
        reader.operation.retain(1024 + sum(len(x.encode("utf8")) for x in row if type(x) is str))
        reader.ledger_rows[row[0]] = tuple(row); reader.ledger_cursor = row[0]
        if row[2] == "standby":reader.ledger_row, reader.phase = tuple(row), "ledger_job"
        return
    if reader.phase == "ledger_job":
        job = meter.read_fixed_row(db, "runtime_jobs",
            ("bot_id", "persona_id", "work_kind", "result_ref"), "job_id=?", (reader.ledger_row[0],))
        if job is None or job[:3] != (*ns.as_tuple, "d13.precompress.paid.v1"):
            raise AuthorityUnavailable("D13 ledger lost its exact namespace paid job")
        reader.ledger_job = tuple(job)
        token = AtomKey(Owner("persona", *ns.as_tuple), _TYPE, job[3]).token if job[3] else None
        head = meter.read_fixed_row(db, "graph_atoms", ("token", "revision", "valid", "value_cell_id"),
            "token=?", (token,)) if token else None
        if head is None or head[2] != 1:
            reader.ledger_blocks[reader.ledger_row[0]] = (tuple(job), token, head, None)
            reader.ledger_row = reader.ledger_job = None; reader.phase = "ledger"
            return
        reader.ledger_head = tuple(head)
        reader.ledger_body = (begin_runtime_json_projection_v3(db, head[3], projection_id="d13.standby-metadata.v3")
            if reader.ledger_body is None else reader.ledger_body.next_cell_v3(db, head[3]))
        if reader.ledger_body.reader.header[1] != token:
            raise AuthorityUnavailable("D13 ledger cell has another erasure owner")
        reader.phase = "ledger_body"
        return
    head = meter.read_fixed_row(db, "graph_atoms", ("token", "revision", "valid", "value_cell_id"),
        "token=?", (reader.ledger_head[0],))
    if head != reader.ledger_head:
        raise AuthorityUnavailable("D13 ledger physical block head changed before metadata EOF")
    reader.ledger_body.advance()
    if reader.ledger_body.complete:
        value = reader.ledger_body.result
        expected = {("conversation_ref",), ("status",), ("expires_at_utc",), ("schema",)}
        if (set(value) != expected or value[("schema",)] != _TYPE
                or value[("conversation_ref",)] != reader.authority.audience[0]
                or value[("status",)] not in {"standby", "active", "retired"}
                or type(value[("expires_at_utc",)]) not in (int,float)
                or not math.isfinite(value[("expires_at_utc",)])):
            raise AuthorityUnavailable("D13 ledger metadata has another registered shape/conversation")
        metadata = tuple(value[path] for path in (("conversation_ref",),("status",),("expires_at_utc",),("schema",)))
        reader.operation.retain(2048)
        reader.ledger_blocks[reader.ledger_row[0]] = (
            reader.ledger_job, reader.ledger_head[0], reader.ledger_head, metadata)
        reader.ledger_row = reader.ledger_job = reader.ledger_head = None; reader.phase = "ledger"


def current_d13_scene_ledger_metadata_v3(db, namespace, scene_token, now_utc):
    proof = _BOUND.get()
    if type(proof) is not PreparedD13StandbyReadV3:
        raise AuthorityUnavailable("D13 paid ledger requires its actual prepared metadata Work")
    return proof, *proof.require_scene_ledger_v3(db, namespace, scene_token, now_utc)

