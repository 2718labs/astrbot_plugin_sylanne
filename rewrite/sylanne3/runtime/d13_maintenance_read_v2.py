"""Private metadata-only namespace census and exact fresh-WRITE maintenance proof."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import secrets
import time
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..domains.d13.derived_block_metadata_v2 import (METADATA_TYPE, decode_derived_block_metadata_v2,
    derived_block_metadata_key_v2)
from ..domains.d13.logical_payload_identity_v2 import initial_logical_payload_identity_v2
from ..domains.d13.maintenance_intent_v2 import (INTENT_TYPE, WORK_KIND, D13MaintenanceVictimV2,
    D13DerivedCacheMaintenanceIntentV2, decode_maintenance_intent_v2, maintenance_intent_key_v2, victim_operation_v2)
from ..graph_types import AtomKey, Owner, owner_grant_key
from ..graph_worker import (GraphStorageStepV3, GraphStorageWorkV3, create_graph_storage_work_v3,
    require_graph_storage_work_admission_v3)
from ..runtime_contracts import canonical_digest, canonical_serialize, NamespaceId, namespace_ref, VersionedRef
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3, bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3, runtime_storage_v3, runtime_storage_quantum_v3,
    RuntimeCellReadV3)
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .dispatch_current_inventory_v3 import _heap
from .first_ingress_v2 import trusted_upper
from .jobs import get_job
from .d13_derived_cache_maintenance_v2 import (authorize_d13_maintenance_v2,
    require_d13_maintenance_grant_v2, require_pending_d13_payload_v2, require_d13_pending_trigger_metadata_v2)

KIND = "d13_maintenance_read_v2"
_READERS = WeakKeyDictionary()
_PROOFS = WeakKeyDictionary()
_BOUND = ContextVar("d13_maintenance_exact_write_v2", default=None)

class _Metadata:
    """Fixed metadata slots; each decode peak ends at the actual retained heap."""
    def __init__(self, operation):
        self.operation = operation
        self.rows, self.origin = {}, None
        operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        return _heap((self.rows, self.origin)) + 65536

    def fixed(self, db, meter, table, columns, where, parameters):
        from .c09_paged_sql_v2 import _quote
        lengths = db.execute("SELECT " + ",".join("length(CAST(" + _quote(column) + " AS BLOB))"
            for column in columns) + " FROM " + _quote(table) + " WHERE " + where + " LIMIT 1",
            parameters).fetchone()
        if lengths is None:
            self.rows.pop(table, None)
            self.operation.refresh_retained_state_v3(self)
            return None
        amount = sum(size or 0 for size in lengths)
        meter.require_available(amount + 256)
        if amount * 8 + 4096 > meter.budget.reserved_arena_bytes:
            raise AuthorityUnavailable("maintenance metadata exceeds its registered decode arena")
        self.operation.reserve_retained_state_growth_v3(self, amount * 8 + 4096)
        try:
            row = meter.read_fixed_row(db, table, columns, where, parameters)
            self.rows[table] = row
            return row
        finally:
            self.operation.finish_retained_state_growth_v3(self)

    def read_origin(self, db, handle, cell_id, header, meter):
        from ..runtime_storage_v3 import runtime_source_identity_v4
        identity = runtime_source_identity_v4(handle, meter=meter)
        if type(db) is not sqlite3.Connection or handle.role != "graph" or db is not handle.db:
            raise AuthorityUnavailable("maintenance requires its actual installed Graph database")
        selected_scope_digest = identity.capture_scope_digest
        databases = db.execute("PRAGMA database_list").fetchall()
        if (len(databases) != 1 or Path(databases[0][2]).resolve(strict=True)
                != Path(identity.member["resolved_path"]).resolve(strict=True)):
            raise AuthorityUnavailable("maintenance metadata database differs from its actual selected role")
        instance = identity.instance
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_cell_origins_v3'").fetchone()
        row = None if exists is None else self.fixed(db, meter, "runtime_cell_origins_v3",
            ("origin_digest", "selection_digest", "role", "authority_id", "installation_id", "namespace_json",
                "operation_id", "event_digest", "locator_json", "read_proof_json"), "origin_digest=?", (header[7],))
        if row is None:
            if selected_scope_digest is None or header[7] != selected_scope_digest:
                raise AuthorityUnavailable("maintenance cell has no selected capture or actual runtime metadata producer")
            self.origin = None
            self.operation.refresh_retained_state_v3(self)
            return None
        self.operation.reserve_retained_state_growth_v3(self, sum(len(value.encode("utf-8"))
            for value in (row[5], row[8], row[9])) * 8 + 4096)
        try:
            namespace, locator, proof = json.loads(row[5]), json.loads(row[8]), json.loads(row[9])
            original = dict(schema="sylanne3.runtime-cell-origin.v3", selection_digest=row[1],
                role=row[2], authority_id=row[3], installation_id=row[4], namespace=namespace,
                operation_id=row[6], event_digest=row[7], locator=locator, read_proof=proof)
            self.origin = original
        finally:
            self.operation.finish_retained_state_growth_v3(self)
        if (canonical_digest(original) != row[0] or row[0] != header[7] or row[2] != "graph"
                or row[3] != identity.authority_id or row[4] != identity.installation_id
                or row[6] != header[2]):
            raise AuthorityUnavailable("maintenance runtime metadata producer identity or digest differs")
        expected_cell = canonical_digest(dict(schema="sylanne3.runtime-cell-identity.v3",
            instance=instance, origin_digest=row[0], locator=locator, payload_sha256=header[5]))
        if expected_cell != cell_id:
            raise AuthorityUnavailable("maintenance cell differs from its actual producer and selected layout")
        key = AtomKey.from_token(locator["token"])
        if (locator["table"] != "graph_atoms" or header[1] != key.token
                or key.type_name not in {METADATA_TYPE, INTENT_TYPE}
                or namespace != [key.owner.bot, key.owner.persona]
                or namespace_ref(NamespaceId(*namespace)) != identity.authority_namespace
                or proof["event_scope"][:2] != namespace or proof["event_scope"][3] != row[6]):
            raise AuthorityUnavailable("maintenance runtime cell crossed its exact metadata locator or namespace")
        event = self.fixed(db, meter, "graph_events", ("digest", "reads", "epoch_reads"),
            "bot=? AND persona=? AND session=? AND event_id=?", tuple(proof["event_scope"]))
        history = self.fixed(db, meter, "graph_history",
            ("value_cell_id", "dependencies", "event_bot", "event_persona", "event_session", "event_id"),
            "token=? AND revision=?", (key.token, locator["revision"]))
        if (event != (row[7], canonical_serialize(proof["reads"]), canonical_serialize(proof["epochs"]))
                or history is None or history[0] != cell_id or list(history[2:]) != proof["event_scope"]
                or sorted(item[0] for item in json.loads(history[1])) != sorted(proof["dependencies"])):
            raise AuthorityUnavailable("maintenance metadata lacks its exact committed event/history producer")
        return original


class _MetadataCellRead(RuntimeCellReadV3):
    def __init__(self, metadata, handle, cell_id, *, token, meter):
        self.metadata = metadata
        super().__init__(handle, cell_id, erasure_owner_ref=token, meter=meter)

    def _read_header(self, handle, cell_id, erasure_owner_ref, meter):
        meter.require_available(32768)
        row = self.metadata.fixed(handle.db, meter, "segmented_cells_v1",
            ("codec_id", "erasure_owner_ref", "producer_operation_id", "total_bytes", "segment_count",
                "payload_sha256", "ordered_segment_root", "origin_scope_digest"), "cell_id=?", (cell_id,))
        if (row is None or row[0] not in {"canonical-json.ascii.v1", "canonical-json.utf8.v1"}
                or not 0 < row[3] <= 65536 or row[4] < 0
                or erasure_owner_ref is not None and row[1] != erasure_owner_ref):
            raise AuthorityUnavailable("maintenance needs its sealed bounded canonical metadata and exact erasure owner")
        self.header = row
        self.origin = self.metadata.read_origin(handle.db, handle, cell_id, row, meter)


class _Cell:
    def __init__(self, reader, cell_id, token, decoder):
        self.reader, self.decoder = reader, decoder
        with runtime_storage_quantum_v3(reader.db) as meter:
            self.cell = _MetadataCellRead(reader.metadata, reader.operation.handle, cell_id, token=token, meter=meter)
        header = self.cell.header
        self.origin = self.cell.origin
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=header[0] == "canonical-json.ascii.v1")
        self.body = bytearray()
        self.complete = False
        self.value = None
        reader.reserve(header[3] * 10 + 65536)

    def advance(self, meter):
        chunk = self.cell.read_fragment(meter=meter)
        if chunk is not None:
            meter.charge_encode(len(chunk) * 2)
            self.parser.feed(chunk, lambda event: None)
            self.body.extend(chunk)
            return
        parsed = self.parser.finish()
        if (parsed.sha256, parsed.byte_count) != (self.cell.finish(meter=meter), self.cell.header[3]):
            raise AuthorityUnavailable("maintenance metadata canonical EOF changed")
        self.value = self.decoder(json.loads(self.body))
        self.body.clear()
        self.complete = True

class _Reader:
    def __init__(self, graph, authority, lease, policy, operation, now, job_id, pending):
        self.graph, self.authority, self.lease, self.policy = graph, authority, lease, policy
        self.operation, self.namespace = operation, authority.namespace
        self.store, self.db = graph._GraphCoordinator__store, graph._GraphCoordinator__store._db
        self.selection_digest = operation.selection_digest
        self.initial_now = self.now = now
        self.deadline_mono = time.monotonic() + operation.deadline_utc - now
        self.work = self.fence = self.guard = None
        self.borrowed = False
        self.graph_stamp = None
        self.owner_head = self.epochs = None
        self.job_id, self.pending = job_id, pending
        self.intent = self.job = None
        self.terminal_result = self.replayed_receipt = None
        self.ordinal = 0
        self.phase = "recovery_head"
        self.recovery_cursor = "d13-maint-"
        self.receipt_column = None
        self.recovery_row = self.recovery_result = None
        self.cursor = ""
        self.row = self.head = self.history = self.event = None
        self.cell = None
        self.current_metadata = self.initial_metadata = None
        self.victim_metadata = self.current_victim = None
        self.candidate = None
        self.expired, self.fifo, self.selected = [], [], ()
        self.retained_bytes = self.retained_count = 0
        self.skipped_pinned = self.skipped_unknown = 0
        self.use_control_revision = None
        self.inventory, self.classification = sha256(), sha256()
        self.complete = self.read_finished = False
        self.proof = None
        self.reserved = 0
        self.metadata = _Metadata(operation)
        self.grant = None
        self.new_operation = "d13-maint-pass:" + secrets.token_hex(24)
        self.additional_bytes = self.additional_count = 0
        _READERS[self] = (graph, authority, lease, policy, operation, self.selection_digest)
        self.reserve(262144)

    def reserve(self, extra=0):
        values = (self.expired, self.fifo, self.selected, self.intent, self.job,
            self.current_metadata, self.initial_metadata, self.victim_metadata, self.row, self.head, self.history,
            self.event, self.candidate, self.current_victim, self.recovery_row, self.recovery_result)
        amount = _heap(values) + extra + 262144
        if self.cell is not None:
            amount += _heap((self.cell.body, self.cell.value, self.cell.cell.header, self.cell.origin)) + 131072
        if amount > self.reserved:
            self.operation.retain(amount - self.reserved)
            self.reserved = amount

    def current(self, *, in_tx_now=None):
        if (_READERS.get(self) != (self.graph, self.authority, self.lease, self.policy, self.operation, self.selection_digest)
                or self.operation.closed or type(self.work) is not GraphStorageWorkV3 or self.work.kind != KIND
                or self.work.state is not self or self.work.operation is not self.operation
                or runtime_storage_v3(self.db) is not self.operation.handle
                or self.selection_digest != self.operation.handle.selection_digest):
            raise AuthorityUnavailable("maintenance lost its actual private Work/selection/retention")
        self.work._require_invocation(self.graph)
        if authorize_d13_maintenance_v2(self.graph, self.authority, self.lease) is not self.policy:
            raise AuthorityUnavailable("maintenance installation changed")
        if in_tx_now is None:
            self.now = trusted_upper(self.graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
                self.graph._GraphCoordinator__scene_clock_policy))
        else:
            self.now = in_tx_now
        if self.now >= self.operation.deadline_utc or time.monotonic() >= self.deadline_mono:
            raise AuthorityUnavailable("maintenance cannot renew its original deadline")
        if self.fence is not None:
            if not self.read_finished and not self.borrowed:
                self.graph._validate_read_fence_v3(self.fence)
            if self.graph._v2_graph_stamp(self.namespace) != self.graph_stamp:
                raise AuthorityUnavailable("namespace changed after the complete FIFO census")

    def heads(self, meter):
        epochs = meter.read_fixed_row(self.db, "graph_authority_epochs", ("access_epoch", "delete_epoch"),
            "bot=? AND persona=?", self.namespace.as_tuple)
        owner = meter.read_fixed_row(self.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
            "token=?", (owner_grant_key(*self.namespace.as_tuple).token,))
        if owner is None or owner[1] != 1 or epochs is None:
            raise AuthorityUnavailable("maintenance current Owner/rights metadata is absent")
        if self.epochs is None:
            self.epochs, self.owner_head = epochs, owner
        elif (epochs, owner) != (self.epochs, self.owner_head):
            raise AuthorityUnavailable("maintenance Owner/SourceAccess/Delete heads changed")

    def advance(self, meter):
        if self.phase == "recovery_head":
            if self.receipt_column is None:
                columns = self.db.execute("PRAGMA table_info(graph_d13_worker_attempts_v2)").fetchall()
                meter.charge_read(sum(len(column[1]) + 16 for column in columns))
                self.receipt_column = "receipt_json_cell_id" if any(column[1] == "receipt_json_cell_id" for column in columns) else "receipt_json"
            self.recovery_row = self.metadata.fixed(self.db, meter, "graph_d13_worker_attempts_v2",
                ("operation_id", "request_digest", "attempt_id", "anchor_json", "pre_graph_revision",
                    "pre_graph_epoch", "permit_json", "finish_request_id", "finish_request_digest", self.receipt_column),
                "bot=? AND persona=? AND operation_id>? AND operation_id<'d13-maint.' ORDER BY operation_id",
                (*self.namespace.as_tuple, self.recovery_cursor))
            if self.recovery_row is None:
                self.phase = "open_scope"
                return
            self.recovery_cursor = self.recovery_row[0]
            self.recovery_result = None
            if self.recovery_row[9] is None:
                self.phase = "recovery_inspect"
            elif self.receipt_column == "receipt_json":
                self.recovery_result = json.loads(self.recovery_row[9])
                self.phase = "recovery_inspect"
            else:
                self.cell = _Cell(self, self.recovery_row[9], None, lambda value: value)
                self.phase = "recovery_receipt"
            return
        if self.phase == "recovery_receipt":
            if not self.cell.complete:
                self.cell.advance(meter)
                return
            self.recovery_result = self.cell.value
            self.cell = None
            self.phase = "recovery_inspect"
            return
        self.heads(meter)
        if self.phase == "job":
            if self.job_id is None:
                rows = self.db.execute("SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
                    "AND work_kind=? AND phase NOT IN ('completed','failed','cancelled') ORDER BY job_id LIMIT 2",
                    (*self.namespace.as_tuple, WORK_KIND)).fetchall()
                meter.charge_read(sum(len(row[0]) + 32 for row in rows))
                if len(rows) > 1:
                    raise AuthorityUnavailable("multiple unresolved maintenance passes require original recovery")
                self.job_id = None if not rows else rows[0][0]
            if self.job_id is not None:
                self.job = get_job(self.db, self.job_id)
                continuation = dict(self.job.continuation)
                if (self.job.work_kind != WORK_KIND or set(continuation) !=
                        {"schema", "intent_ref", "intent_digest", "completed_victim_ordinal"}
                        or continuation["schema"] != "d13.maintenance-job.v2"
                        or self.job.cancel_epoch or self.job.budget_ref != self.policy.lease_id):
                    raise AuthorityUnavailable("maintenance job has another original continuation")
                self.ordinal = continuation["completed_victim_ordinal"]
                token = continuation["intent_ref"]
                key = AtomKey.from_token(token)
                if key.type_name != INTENT_TYPE or NamespaceId.from_key(key) != self.namespace:
                    raise AuthorityUnavailable("maintenance job crossed its namespace intent")
                head = meter.read_fixed_row(self.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
                    "token=?", (token,))
                if head is None or head[:2] != (1, 1):
                    raise AuthorityUnavailable("immutable maintenance intent is absent or was rewritten")
                self.cell = _Cell(self, head[2], token, decode_maintenance_intent_v2)
                self.phase = "intent"
                return
            if self.pending is not None:
                pending = require_pending_d13_payload_v2(self.pending, self.graph, self.selection_digest, self.now)
                require_d13_pending_trigger_metadata_v2(self.graph, pending, meter=meter)
                self.additional_bytes, self.additional_count = pending.additional_bytes, 1
                self.operation.deadline_utc = min(self.operation.deadline_utc, pending.deadline_utc)
                self.deadline_mono = min(self.deadline_mono, time.monotonic() + pending.deadline_utc - self.now)
            elif not self.policy.cold_maintenance_enabled:
                raise AuthorityUnavailable("cold maintenance is explicitly disabled")
            self.phase = "payload"
            return
        if self.phase == "intent":
            if not self.cell.complete:
                self.cell.advance(meter)
                return
            intent = self.cell.value
            if (intent.operation_id != self.job_id or maintenance_intent_key_v2(intent).token != self.job.continuation["intent_ref"]
                    or intent.digest != self.job.continuation["intent_digest"] or intent.policy_digest != self.policy.digest
                    or intent.coverage_ref != self.policy.coverage_ref or intent.coverage_digest != self.policy.coverage_digest
                    or intent.grant_digest != canonical_digest(asdict(self.grant))
                    or type(self.ordinal) is not int or not 0 <= self.ordinal <= len(intent.victims)):
                raise AuthorityUnavailable("maintenance job lost its exact immutable original/ordinal")
            self.intent = intent
            if self.job.phase == "completed":
                result = self.replayed_receipt
                if (self.ordinal != len(intent.victims) or result is None
                        or result.get("job_id") != self.job_id or result.get("intent_digest") != intent.digest
                        or result.get("ordinal") != self.ordinal or result.get("status") != "completed"):
                    raise AuthorityUnavailable("completed maintenance job lacks its original final worker result")
                last = intent.victims[-1]
                operation_id, digest = victim_operation_v2(intent, self.ordinal - 1)
                history = meter.read_fixed_row(self.db, "graph_history", ("valid", "event_bot", "event_persona", "event_session", "event_id"),
                    "token=? AND revision=?", (last.metadata_ref, last.metadata_revision + 1))
                payload = self.db.execute("SELECT 1 FROM graph_d11_derived_cache_payloads_v1 WHERE bot=? AND persona=? AND block_ref=?",
                    (*self.namespace.as_tuple, last.block_ref)).fetchone()
                meter.charge_read(8)
                if (result.get("operation_id") != operation_id or history !=
                        (1, *self.namespace.as_tuple, "d13-derived-cache-v6", operation_id) or payload is not None):
                    raise AuthorityUnavailable("completed maintenance result lost its actual retired CAS/payload absence")
                self.terminal_result = result
                self.complete = True
                self.phase = "complete"
                self.cell = None
                self.proof = _Prepared(self)
                self.reserve()
                return
            if self.ordinal == len(intent.victims):
                raise AuthorityUnavailable("unterminated maintenance job cannot fabricate a final result")
            self.additional_bytes, self.additional_count = intent.additional_bytes, intent.additional_count
            self.operation.deadline_utc = min(self.operation.deadline_utc, intent.original_deadline_utc)
            self.deadline_mono = min(self.deadline_mono, time.monotonic() + intent.original_deadline_utc - self.now)
            if intent.trigger_kind == "pending_paid_payload":
                require_d13_pending_trigger_metadata_v2(self.graph, intent, meter=meter)
                pending_job = get_job(self.db, intent.trigger_original_ref)
                if (pending_job.phase != "running" or pending_job.fence != intent.trigger_worker_fence
                        or pending_job.cancel_epoch or pending_job.lease_expires_utc is None
                        or self.now >= datetime.fromisoformat(pending_job.lease_expires_utc.replace("Z", "+00:00")).timestamp()):
                    raise AuthorityUnavailable("original paid payload is no longer awaiting its first cache admission")
            self.work.deadline_utc = self.operation.deadline_utc
            if self.job.lease_expires_utc is not None:
                worker_deadline = datetime.fromisoformat(self.job.lease_expires_utc.replace("Z", "+00:00")).timestamp()
                self.operation.deadline_utc = self.work.deadline_utc = min(self.operation.deadline_utc, worker_deadline)
                self.deadline_mono = min(self.deadline_mono, time.monotonic() + worker_deadline - self.now)
            self.cell = None
            self.phase = "payload"
            return
        if self.phase == "payload":
            row = self.db.execute("SELECT block_ref,payload_digest,length(payload_bytes) FROM graph_d11_derived_cache_payloads_v1 "
                "WHERE bot=? AND persona=? AND block_ref>? ORDER BY block_ref LIMIT 1",
                (*self.namespace.as_tuple, self.cursor)).fetchone()
            meter.charge_read(0 if row is None else len(row[0].encode()) + len(row[1]) + 32)
            if row is None:
                self.seal()
                return
            self.row = tuple(row)
            self.cursor = row[0]
            self.retained_count += 1
            self.retained_bytes += row[2]
            self.inventory.update(canonical_digest(tuple(row)).encode())
            token = AtomKey(Owner("persona", *self.namespace.as_tuple), METADATA_TYPE, row[0]).token
            head = meter.read_fixed_row(self.db, "graph_atoms", ("token", "revision", "valid", "value_cell_id"),
                "token=? AND bot=? AND persona=?", (token, *self.namespace.as_tuple))
            if head is None or head[2] != 1:
                self.unknown("missing_or_invalid_metadata")
                return
            self.head = tuple(head)
            self.cell = _Cell(self, head[3], token, decode_derived_block_metadata_v2)
            self.phase = "metadata"
            return
        if self.phase == "metadata":
            if not self.cell.complete:
                self.cell.advance(meter)
                return
            value = self.cell.value
            if (derived_block_metadata_key_v2(value).token != self.head[0] or value.namespace != self.namespace
                    or (value.block_ref, value.payload_digest, value.payload_length_bytes) != self.row
                    or value.status not in self.policy.eligible_statuses):
                self.unknown("retired_or_unmatched_metadata")
                return
            self.current_metadata = value
            history = meter.read_fixed_row(self.db, "graph_history",
                ("revision", "valid", "value_cell_id", "event_bot", "event_persona", "event_session", "event_id"),
                "token=? ORDER BY revision", (self.head[0],))
            if history is None or history[:2] != (1, 1) or history[3:5] != self.namespace.as_tuple:
                self.unknown("unproved_initial_history")
                return
            self.history = tuple(history)
            self.cell = _Cell(self, history[2], self.head[0], decode_derived_block_metadata_v2)
            self.phase = "initial"
            return
        if self.phase == "initial":
            if not self.cell.complete:
                self.cell.advance(meter)
                return
            initial = self.cell.value
            from dataclasses import replace
            if initial != replace(self.current_metadata, status="standby"):
                self.unknown("ambiguous_initial_payload_identity")
                return
            self.initial_metadata = initial
            event = meter.read_fixed_row(self.db, "graph_events", ("digest", "revisions", "epoch_revision"),
                "bot=? AND persona=? AND session=? AND event_id=?", tuple(self.history[3:]))
            producer = self.history[6]
            attempt = meter.read_fixed_row(self.db, "graph_d13_worker_attempts_v2",
                ("request_digest", "pre_graph_epoch"),
                "bot=? AND persona=? AND operation_id=?", (*self.namespace.as_tuple, producer))
            columns = self.db.execute("PRAGMA table_info(graph_d13_worker_attempts_v2)").fetchall()
            meter.charge_read(sum(len(column[1]) + 16 for column in columns))
            receipt_column = "receipt_json_cell_id" if any(column[1] == "receipt_json_cell_id" for column in columns) else "receipt_json"
            committed = self.db.execute("SELECT " + receipt_column + " IS NOT NULL FROM graph_d13_worker_attempts_v2 "
                "WHERE bot=? AND persona=? AND operation_id=?", (*self.namespace.as_tuple, producer)).fetchone()
            meter.charge_read(8)
            if (event is None or attempt is None or committed != (1,)
                    or self.history[5] != "d13-derived-cache-v6" or not producer.startswith("d13-paid-derived-complete:")
                    or [self.head[0], 1] not in json.loads(event[1]) or event[2] != attempt[1] + 1
                    or self.cell.origin is not None and
                        (self.cell.origin["operation_id"] != producer or self.cell.cell.header[2] != producer)):
                self.unknown("unproved_first_committed_producer")
                return
            identity = initial_logical_payload_identity_v2(self.current_metadata,
                metadata_ref=VersionedRef(self.head[0], self.head[1]), initial_metadata=initial,
                initial_history=self.history, producer_attempt=tuple(attempt), event=tuple(event))
            origin = identity[2]
            reason = "expired" if self.current_metadata.expires_at_utc <= self.now else "capacity_fifo"
            self.candidate = D13MaintenanceVictimV2(self.head[0], self.head[1],
                canonical_digest(self.current_metadata), self.row[0], self.row[1], self.row[2],
                origin, event[2], self.current_metadata.expires_at_utc, reason)
            self.phase = "use"
            return
        raise AuthorityUnavailable("unregistered maintenance metadata phase")

    def inspect_recovery(self):
        from ..authority_service.v2_contract import from_wire
        from .restore_anchor import RestoreAnchor
        from ..runtime_contracts import FenceScope
        from ..graph_types import NamespaceEpoch
        from types import SimpleNamespace
        from .d13_paid_original_read_v3 import observe_d13_paid_owner_guard_v3
        row = self.recovery_row
        port = self.graph._GraphCoordinator__content_fence_v2
        expected = "d13-worker-" + canonical_digest({"operation_id": row[0], "request_digest": row[1],
            "namespace": self.namespace.as_tuple})[:48]
        if row[2] != expected:
            raise AuthorityUnavailable("maintenance original worker attempt identity differs")
        anchor = RestoreAnchor(**json.loads(row[3]))
        if self.recovery_result is None and row[6] is None:
            # GET admits only existing permits. The paired typed observation is
            # the formal negative lookup; a transport exception is not absence.
            from ..authority_service.v2_contract import ContentWriteAttemptObservationV1
            observation = port.observe_content_write_attempt_v1(namespace=self.namespace,
                authority_namespace=anchor.namespace, operation_id=row[2], expected_anchor=anchor)
            if (type(observation) is not ContentWriteAttemptObservationV1
                    or observation.current_anchor != anchor or observation.operation_id != row[2]
                    or observation.namespace != anchor.namespace
                    or observation.subject != port.installation_grant.subject
                    or observation.authority_id != port.installation_grant.authority_id
                    or observation.holder != self.graph._GraphCoordinator__holder):
                raise AuthorityUnavailable("maintenance original attempt observation identity differs")
            observed, state = observation.permit, observation.state
        else:
            observed, state = port.get_fence_operation(namespace=self.namespace,
                authority_namespace=anchor.namespace, operation_id=row[2])
        if self.recovery_result is not None:
            result = self.recovery_result
            if (type(result) is not dict or result.get("schema") not in
                    {"d13.maintenance-pass-result.v2", "d13.maintenance-victim-result.v2"}
                    or result.get("intent_digest") is None or result.get("job_id") is None
                    or result.get("graph_receipt", {}).get("status") != "committed"
                    or result["graph_receipt"]["epoch"]["revision"] != row[5] + 1 or row[6] is None):
                raise AuthorityUnavailable("committed maintenance receipt changed its actual producer")
            permit = from_wire(json.loads(row[6]))
            finish = "sha256:" + canonical_digest({"action": "finish_d13_worker",
                "operation_id": row[0], "permit_token": permit.token})
            if (observed != permit or state not in {"active", "finished"} or permit.pinned_anchor != anchor
                    or row[7:9] != ("finish:" + expected, finish)):
                raise AuthorityUnavailable("maintenance committed original permit/finish changed")
            if state == "active":
                scope = FenceScope(self.namespace, anchor.namespace, self.authority.activation_generation,
                    "write", expected, permit, anchor, NamespaceEpoch(*self.namespace.as_tuple, row[5]), row[4])
                if port.validate_fence(scope) != permit:
                    raise AuthorityUnavailable("maintenance committed original WRITE is unavailable")
                port.finish_fence(scope, request_id=row[7], request_digest=row[8])
                actual, finished = port.get_fence_operation(namespace=self.namespace,
                    authority_namespace=anchor.namespace, operation_id=expected)
                if actual != permit or finished != "finished":
                    raise AuthorityUnavailable("maintenance original WRITE finish is still unresolved")
            if result.get("job_id") == self.job_id and (self.replayed_receipt is None
                    or result.get("ordinal", -1) > self.replayed_receipt.get("ordinal", -1)):
                self.replayed_receipt = result
            self.recovery_row = self.recovery_result = None
            self.phase = "recovery_head"
            return
        if not row[0].startswith("d13-maint-victim:"):
            raise AuthorityUnavailable("uncommitted schedule retains its original attempt; HOLD")
        if state == "absent" and observed is None and row[6] is None:
            self.recovery_row = None
            self.phase = "recovery_head"
            return
        if row[6] is None or state != "active" or observed != from_wire(json.loads(row[6])):
            raise AuthorityUnavailable("unknown victim WRITE cannot be replaced")
        permit = observed
        with self.store._lock, runtime_storage_quantum_v3(self.db):
            metadata, epoch = self.graph._v2_graph_stamp(self.namespace)
        finish = "sha256:" + canonical_digest({"action": "finish_d13_worker",
            "operation_id": row[0], "permit_token": permit.token})
        if (self.borrowed or row[7:9] != ("finish:" + expected, finish)
                or permit.pinned_anchor != anchor or permit.operation != "write"
                or permit.holder != self.graph._GraphCoordinator__holder
                or (metadata.graph_revision, epoch.revision) != row[4:6]
                or not self.graph._anchor_matches(metadata.requirements, anchor)):
            raise AuthorityUnavailable("unknown WRITE lost its same original stamp")
        scope = FenceScope(self.namespace, anchor.namespace, self.authority.activation_generation,
            "write", expected, permit, anchor, NamespaceEpoch(*self.namespace.as_tuple, row[5]), row[4])
        if port.validate_fence(scope) != permit:
            raise AuthorityUnavailable("original unknown victim WRITE is unavailable")
        guard = observe_d13_paid_owner_guard_v3(self.graph, self.authority, scope)
        self.fence = SimpleNamespace(scope=scope, metadata=metadata, epoch=epoch,
            fence_observation=guard, operation_id=row[0], request_digest=row[1])
        self.borrowed = True
        self.graph_stamp, self.guard = (metadata, epoch), guard
        self.recovery_row = None
        self.phase = "recovery_head"

    def open_scope(self):
        if self.fence is None:
            from .d13_paid_original_read_v3 import observe_d13_paid_owner_guard_v3
            self.fence = self.graph._begin_read_fence_v3(self.authority, operation_id=self.operation.operation_id,
                fence_observer=lambda scope: observe_d13_paid_owner_guard_v3(self.graph, self.authority, scope))
            self.graph_stamp, self.guard = (self.fence.metadata, self.fence.epoch), self.fence.fence_observation
        self.phase = "job"

    def unknown(self, reason):
        self.skipped_unknown += 1
        self.classification.update(canonical_digest((self.row, "unknown", reason)).encode())
        self.next_payload()

    def next_payload(self):
        self.cell = self.current_metadata = self.initial_metadata = None
        self.row = self.head = self.history = self.event = self.candidate = None
        self.phase = "payload"
        self.reserve()

    def observe_use(self):
        v = self.candidate
        selected = (v.payload_identity,)
        port = self.graph._GraphCoordinator__d13_cache_use_control_v2
        observed = port.observe_for_fence_v2(namespace=self.namespace,
            authority_namespace=self.fence.scope.authority_namespace, permit=self.fence.scope.permit,
            policy_digest=self.policy.digest, expected_coverage=(self.policy.coverage_ref, self.policy.coverage_digest),
            selected_payloads=selected)
        if (observed.namespace != self.namespace or observed.policy_digest != self.policy.digest
                or observed.permit_token != self.fence.scope.permit.token or observed.selection_digest != self.selection_digest
                or (observed.coverage_ref, observed.coverage_digest) != (self.policy.coverage_ref, self.policy.coverage_digest)
                or len(observed.entries) != 1 or observed.entries[0].identity != v.payload_identity):
            raise AuthorityUnavailable("actual Core use observation crossed its installed scope/payload/fence")
        if self.use_control_revision is None:
            self.use_control_revision = observed.control_revision
        elif observed.control_revision != self.use_control_revision:
            raise AuthorityUnavailable("namespace use changed during FIFO census; retain and take a new READ")
        entry = observed.entries[0]
        if observed.coverage_state != "complete" or not entry.query_complete or entry.coverage != "complete" or entry.unknown_count:
            self.skipped_unknown += 1
            classification = "unknown"
        elif entry.active_count:
            self.skipped_pinned += 1
            classification = "pinned"
        elif v.reason == "capacity_fifo" and not self.policy.capacity_eviction_enabled:
            classification = "capacity_disabled"
        else:
            target = self.expired if v.reason == "expired" else self.fifo
            target.append(v)
            target.sort(key=lambda item: item.fifo_key)
            del target[self.policy.max_victims_per_pass:]
            classification = "eligible"
            if self.intent is not None and v.metadata_ref == self.intent.victims[self.ordinal].metadata_ref:
                self.victim_metadata, self.current_victim = self.current_metadata, v
        self.classification.update(canonical_digest((v.payload_identity, classification, observed.observation_digest)).encode())
        self.next_payload()

    def seal(self):
        needed_bytes = max(0, self.retained_bytes + self.additional_bytes - self.policy.max_retained_payload_bytes)
        needed_count = max(0, self.retained_count + self.additional_count - self.policy.max_retained_blocks)
        selected = []
        freed_bytes = 0
        for victim in self.expired:
            if len(selected) == self.policy.max_victims_per_pass:
                break
            selected.append(victim)
            freed_bytes += victim.payload_length_bytes
        for victim in self.fifo:
            if len(selected) == self.policy.max_victims_per_pass or (
                    freed_bytes >= needed_bytes and len(selected) >= needed_count):
                break
            selected.append(victim)
            freed_bytes += victim.payload_length_bytes
        self.selected = tuple(selected)
        if self.intent is not None:
            original = self.intent.victims[self.ordinal]
            if self.current_victim != original or not self.selected or self.selected[0] != original:
                raise AuthorityUnavailable("original next victim is no longer the first eligible current FIFO member")
        self.complete = True
        self.phase = "complete"
        self.proof = _Prepared(self)
        self.reserve()

    def new_intent_v2(self):
        pending = self.pending
        return D13DerivedCacheMaintenanceIntentV2(self.namespace, self.new_operation,
            "cold" if pending is None else "pending_paid_payload",
            self.policy.coverage_ref if pending is None else pending.job_id,
            self.policy.coverage_digest if pending is None else pending.original_digest,
            None if pending is None else pending.worker_fence,
            () if pending is None else pending.source_heads, () if pending is None else pending.authority_epochs,
            self.policy.digest, canonical_digest(asdict(self.grant)),
            self.operation.deadline_utc, self.additional_bytes, self.additional_count,
            self.retained_bytes, self.retained_count, self.inventory.hexdigest(), self.classification.hexdigest(),
            self.policy.coverage_ref, self.policy.coverage_digest, self.selected, self.skipped_pinned, self.skipped_unknown)

class _Prepared:
    def __init__(self, reader):
        self.reader = reader
        self.write_identity = self.write_scope = self.write_guard = self.write_observation = None
        self.write_now = None
        self.used = False
        _PROOFS[self] = (reader, reader.work, reader.operation, reader.fence, reader.selection_digest)

    def require_v2(self, graph, authority, lease):
        r = self.reader
        if (_PROOFS.get(self) != (r, r.work, r.operation, r.fence, r.selection_digest)
                or graph is not r.graph or authority is not r.authority or lease is not r.lease
                or not r.complete or not r.read_finished):
            raise AuthorityUnavailable("maintenance needs its exact privately completed metadata Work")
        if r.db.in_transaction:
            if self.write_now is None:
                raise AuthorityUnavailable("maintenance transaction has no actual fresh WRITE clock")
            r.current(in_tx_now=self.write_now)
        else:
            r.current()
        return r

    @property
    def scope(self):
        return self.write_scope

    def bind_write_identity_v2(self, operation_id, digest):
        r = self.require_v2(self.reader.graph, self.reader.authority, self.reader.lease)
        expected = (r.new_operation, r.new_intent_v2().digest) if r.intent is None else victim_operation_v2(r.intent, r.ordinal)
        if r.borrowed and expected != (r.fence.operation_id, r.fence.request_digest):
            raise AuthorityUnavailable("unknown WRITE recovery cannot select another original victim")
        if self.write_identity is not None or (operation_id, digest) != expected:
            raise AuthorityUnavailable("maintenance changed its immutable WRITE identity")
        self.write_identity = expected

    def release_payload_v3(self):
        r = self.reader
        _PROOFS.pop(self, None)
        _READERS.pop(r, None)
        r.expired.clear()
        r.fifo.clear()
        r.selected = ()
        r.cell = r.current_metadata = r.initial_metadata = r.victim_metadata = r.pending = None
        r.terminal_result = r.replayed_receipt = None
        self.write_guard = self.write_scope = None

@contextmanager
def bind_d13_maintenance_v2(proof):
    proof.require_v2(proof.reader.graph, proof.reader.authority, proof.reader.lease)
    token = _BOUND.set(proof)
    try:
        yield proof
    finally:
        _BOUND.reset(token)


def prepare_d13_maintenance_read_v2(graph, authority, lease, *, job_id=None, pending=None):
    require_graph_storage_work_admission_v3(graph)
    policy = authorize_d13_maintenance_v2(graph, authority, lease)
    db = graph._GraphCoordinator__store._db
    now = trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
        graph._GraphCoordinator__scene_clock_policy))
    operation = begin_runtime_storage_operation_v3(db, "d13-maint-read:" + secrets.token_hex(24),
        now + policy.deadline_after_seconds)
    if operation is None:
        raise AuthorityUnavailable("maintenance requires the actual current segmented storage layout")
    fence = borrowed = None
    try:
        with bind_runtime_storage_operation_v3(operation, db), graph._GraphCoordinator__store._lock:
            with runtime_storage_quantum_v3(db):
                grant = require_d13_maintenance_grant_v2(graph, policy, now)
            operation.deadline_utc = min(operation.deadline_utc, grant.valid_until_utc)
            r = _Reader(graph, authority, lease, policy, operation, now, job_id, pending)
            r.grant = grant
        work = create_graph_storage_work_v3(graph, kind=KIND, operation_id=operation.operation_id,
            selection_digest=operation.selection_digest, deadline_utc=operation.deadline_utc, state=r, operation=operation)
        r.work = work
        def completed(proof):
            from .d13_derived_cache_maintenance_v2 import commit_d13_maintenance_step_v2
            with bind_runtime_storage_operation_v3(operation, db):
                if proof.reader.terminal_result is not None:
                    return proof.reader.terminal_result
                return commit_d13_maintenance_step_v2(graph, authority, lease, proof)
        return work.map_terminal_v3("issuer", completed, lambda error: (_ for _ in ()).throw(error))
    except BaseException:
        try:
            if fence is not None and borrowed is None:
                graph._finish_read_fence_v3(fence)
        finally:
            finish_runtime_storage_operation_v3(operation)
        raise

def advance_d13_maintenance_read_v2(graph, work):
    r = work.state
    with bind_runtime_storage_operation_v3(r.operation, r.db):
        r.current()
        if r.phase == "use":
            r.observe_use()
        elif r.phase == "recovery_inspect":
            r.inspect_recovery()
        elif r.phase == "open_scope":
            r.open_scope()
        else:
            with r.store._lock:
                r.db.execute("BEGIN")
                try:
                    with runtime_storage_quantum_v3(r.db) as meter:
                        r.advance(meter)
                finally:
                    r.db.rollback()
        r.current()
    return GraphStorageStepV3("complete", r.proof) if r.complete else GraphStorageStepV3("progress")

def finish_d13_maintenance_read_v2(graph, work, error):
    r = work.state
    try:
        if r.fence is not None and not r.borrowed:
            graph._finish_read_fence_v3(r.fence)
        r.read_finished = True
        if error is None:
            work.result_lease = r.operation
    finally:
        if error is not None:
            if r.proof is not None:
                r.proof.release_payload_v3()
            else:
                _READERS.pop(r, None)
            finish_runtime_storage_operation_v3(r.operation)

def require_d13_maintenance_producer_v2(graph, authority, proof, operation_id, digest):
    r = proof.require_v2(graph, authority, proof.reader.lease)
    if _BOUND.get() is not proof or proof.write_identity != (operation_id, digest):
        raise AuthorityUnavailable("maintenance WRITE is outside its named private producer")
    return r

def observe_d13_maintenance_write_v2(graph, authority, scope, proof, operation_id, digest):
    r = require_d13_maintenance_producer_v2(graph, authority, proof, operation_id, digest)
    if scope.operation != "write" or proof.write_scope is not None:
        raise AuthorityUnavailable("maintenance requires one actual fresh WRITE")
    proof.write_scope = scope
    port = graph._GraphCoordinator__d13_cache_use_control_v2
    victims = r.selected if r.intent is None else (r.intent.victims[r.ordinal],)
    selected = tuple(v.payload_identity for v in victims)
    observed = port.observe_for_fence_v2(namespace=r.namespace,
        authority_namespace=scope.authority_namespace, permit=scope.permit,
        policy_digest=r.policy.digest, expected_coverage=(r.policy.coverage_ref, r.policy.coverage_digest),
        selected_payloads=selected)
    if observed.control_revision != r.use_control_revision:
        raise AuthorityUnavailable("namespace use changed after FIFO EOF; the original ordering is stale")
    proof.write_observation = observed
    if r.intent is not None:
        proof.write_guard = port.require_reclaim_for_fence_v2(observed, maintenance_admission=proof)
    elif (observed.coverage_state != "complete" or tuple(entry.identity for entry in observed.entries) != selected
            or any(not entry.query_complete or entry.coverage != "complete" or entry.active_count or entry.unknown_count
                for entry in observed.entries)):
        raise AuthorityUnavailable("maintenance intent planning lost actual complete unpinned observations")

def require_d13_maintenance_control_admission_v2(admission, *, namespace, policy_digest, permit,
        selection_digest, selected_payloads):
    if type(admission) is not _Prepared or admission not in _PROOFS:
        raise AuthorityUnavailable("named private maintenance admission required")
    r = admission.reader
    admission.require_v2(r.graph, r.authority, r.lease)
    victims = r.selected if r.intent is None else (r.intent.victims[r.ordinal],)
    if (r.intent is None or admission.write_scope is None or admission.write_scope.permit != permit or permit.operation != "write"
            or namespace != r.namespace or policy_digest != r.policy.digest or selection_digest != r.selection_digest
            or selected_payloads != tuple(v.payload_identity for v in victims) or _BOUND.get() is not admission):
        raise AuthorityUnavailable("control reclaim admission crossed its actual named maintenance WRITE")
    return r

def require_d13_maintenance_write_in_tx_v2(graph, db, authority, scope, proof, metadata, epoch, now):
    proof.write_now = now
    r = require_d13_maintenance_producer_v2(graph, authority, proof, *proof.write_identity)
    r.current(in_tx_now=now)
    if (proof.used or proof.write_scope is not scope or proof.write_observation is None
            or r.intent is not None and proof.write_guard is None
            or db is not r.db or not db.in_transaction or (metadata, epoch) != r.graph_stamp):
        raise AuthorityUnavailable("maintenance fresh WRITE lost its exact census/permit/deadline")
    victims = r.selected if r.intent is None else (r.intent.victims[r.ordinal],)
    selected = tuple(v.payload_identity for v in victims)
    if r.intent is not None:
        proof.write_guard.require_v2(namespace=r.namespace, policy_digest=r.policy.digest,
            permit=scope.permit, selection_digest=r.selection_digest, selected_payloads=selected,
            coverage_ref=r.policy.coverage_ref, coverage_digest=r.policy.coverage_digest, maintenance_admission=proof)
    elif (proof.write_observation.permit_token != scope.permit.token
            or proof.write_observation.selection_digest != r.selection_digest
            or proof.write_observation.policy_digest != r.policy.digest):
        raise AuthorityUnavailable("intent planning observation changed its exact actual WRITE")
    with runtime_storage_quantum_v3(db) as meter:
        r.heads(meter)
        trigger = r.pending if r.intent is None else r.intent
        if (r.pending is not None if r.intent is None else r.intent.trigger_kind == "pending_paid_payload"):
            require_d13_pending_trigger_metadata_v2(graph, trigger, meter=meter)
        for victim in victims:
            current = meter.read_fixed_row(db, "graph_atoms", ("revision", "valid"), "token=?", (victim.metadata_ref,))
            payload = db.execute("SELECT payload_digest,length(payload_bytes) FROM graph_d11_derived_cache_payloads_v1 "
                "WHERE bot=? AND persona=? AND block_ref=?", (*r.namespace.as_tuple, victim.block_ref)).fetchone()
            meter.charge_read(96)
            if current != (victim.metadata_revision, 1) or payload != (victim.payload_digest, victim.payload_length_bytes):
                raise AuthorityUnavailable("maintenance victim exact metadata/payload CAS changed")
            if victim.reason == "expired" and now < victim.expires_at_utc:
                raise AuthorityUnavailable("expiry maintenance cannot shorten the original lifetime")
    proof.used = True
