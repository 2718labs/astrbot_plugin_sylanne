"""Read-only D13 priority metadata; these selections never authorize Source bodies."""
from dataclasses import dataclass
from datetime import datetime, timedelta
import math
from hashlib import sha256

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest
from ..runtime_storage_v3 import runtime_storage_v3
from .d13_paid_original_read_v3 import _ColumnV3, _IntentDigestMetadataV3, _JOB_COLUMNS
from .dispatch_current_inventory_v3 import _heap


@dataclass(frozen=True, slots=True)
class D13PrecompressionPriorityV1:
    status: str
    namespace: NamespaceId
    scene_ref: str
    conversation_ref: str
    job_ref: str | None
    original_operation_id: str | None
    original_digest: str | None
    deadline_utc: float | None
    observation_digest: str
    reason: str


def _finite_time_v1(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise AuthorityUnavailable("D13 priority original time is not finite UTC seconds")
    return value


def _job_deadline_v1(value):
    if type(value) is not str:
        raise AuthorityUnavailable("D13 priority original job deadline is not UTC text")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise AuthorityUnavailable("D13 priority original job deadline is not UTC")
    return parsed.timestamp()


class D13PriorityMetadataReadV1:
    """One namespace census and full original metadata EOF in the owning READ."""
    def __init__(self, parent):
        self.parent = parent
        self.graph, self.db = parent.graph, parent.db
        self.namespace = parent.authority.namespace
        self.operation = parent.operation
        self.phase, self.cursor = "jobs", ""
        self.jobs, self.intents, self.schedules, self.ledgers = {}, {}, {}, {}
        self.paid_headers = {}
        self.column = self.intent_digest_task = None
        self.job_id = None
        self.job = self.intent_head = self.selected_row = None
        self.complete, self.result, self.reserved = False, None, 0
        self.epochs = None
        self.owner_head = None
        self.root = sha256()
        self.selection_iterator = None
        self.choices = []
        self.recovery_items = []
        self.recovery_scenes = set()

    def require_current_v3(self, *, meter=None):
        p = self.parent
        if (p.priority_read is not self or p.mode not in {"priority", "discovery"} or p.phase != "priority"
                or p.work.state is not p or p.work.operation is not self.operation
                or self.operation.closed or runtime_storage_v3(self.db) is not self.operation.handle
                or p.graph._v2_graph_stamp(self.namespace) != (p.fence.metadata, p.fence.epoch)
                or p.now_utc >= self.operation.deadline_utc):
            raise AuthorityUnavailable("D13 priority metadata lost its actual READ")
        p.work._require_invocation(self.graph)
        if meter is not None:
            epochs = meter.read_fixed_row(self.db, "graph_authority_epochs", ("access_epoch", "delete_epoch"),
                "bot=? AND persona=?", self.namespace.as_tuple)
            owner = meter.read_fixed_row(self.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
                "token=?", (owner_grant_key(*self.namespace.as_tuple).token,))
            if self.epochs is None:
                self.epochs, self.owner_head = epochs, owner
            elif (epochs, owner) != (self.epochs, self.owner_head):
                raise AuthorityUnavailable("D13 priority Owner or rights changed")
        return self

    def reserve_v3(self, extra=0):
        values = (self.jobs, self.intents, self.schedules, self.ledgers, self.paid_headers,
                  self.selected_row, self.job, self.intent_head, self.choices, self.recovery_items, self.recovery_scenes)
        size = _heap(values) + extra
        if self.column is not None:
            c = self.column
            size += _heap((c.key, c.fragment, c.body, vars(c.parser)))
            size += _heap((c.parser.frozen.values, c.parser.frozen.buffers))
            if hasattr(c.parser, "decoder"):
                size += _heap(vars(c.parser.decoder)) + _heap(vars(c.parser.frozen_parser))
        if self.intent_digest_task is not None:
            size += _heap(self.intent_digest_task.actions)
        if size > self.reserved:
            self.operation.retain(size - self.reserved)
            self.reserved = size

    def _observe(self, table, row, meter):
        # Fixed headers only. Canonical commitment is never a Body permission.
        raw = canonical_digest((table, row)).encode("ascii")
        meter.charge_encode(len(raw))
        self.root.update(raw)

    def _next(self, phase):
        self.phase, self.cursor, self.selected_row = phase, "", None

    def _intent_finished(self):
        c, job = self.column, self.job
        outer, frozen = c.parser.scalars, c.parser.frozen.values
        ns = self.namespace.as_tuple
        if ((outer.get(("namespace", "bot_id")), outer.get(("namespace", "persona_id"))) != ns
                or (frozen.get(("window", "namespace", "bot_id")), frozen.get(("window", "namespace", "persona_id"))) != ns
                or outer.get(("binding", "job_ref")) != job[0]
                or outer.get(("binding", "original_operation_id")) != job[1]
                or self.intent_head[0] != job[1] or frozen.get(("plan", "job_ref")) != job[0]
                or outer.get(("binding", "installation_id")) != self.graph._GraphCoordinator__content_fence_v2.installation_grant.installation_id):
            raise AuthorityUnavailable("D13 priority original job/namespace join mismatch")
        scene = frozen.get(("window", "scene_ref", "ref"))
        key = AtomKey.from_token(scene)
        if NamespaceId.from_key(key) != self.namespace or key.owner.kind != "scene":
            raise AuthorityUnavailable("D13 priority original scene differs")
        policy = self.graph._GraphCoordinator__d13_paid_precompression_policy
        selected = policy.selected_main
        if (job[8] != policy.lease_id
                or tuple(outer.get(("binding", field)) for field in
                         ("installation_id", "provider_id", "model_id", "provider_config_digest")) !=
                   (selected.installation_id, selected.provider_id, selected.model_id, selected.provider_config_digest)):
            raise AuthorityUnavailable("D13 priority original installation/model/lease identity differs")
        expiry = min(_finite_time_v1(outer[("binding", "expires_at_utc")]),
                     _finite_time_v1(frozen[("plan", "expires_at_utc")]),
                     _job_deadline_v1(job[7]))
        self.intents[job[0]] = (key.owner.subject, scene, frozen[("window", "conversation_ref")],
                               job[1], self.intent_head[1], expiry, c.sha256)
        self.intent_digest_task = _IntentDigestMetadataV3(self, c)
        self.phase = "intent_digest"

    def advance_v3(self, meter):
        self.require_current_v3(meter=meter)
        ns = self.namespace.as_tuple
        if self.phase == "jobs":
            row = meter.read_fixed_row(self.db, "runtime_jobs", _JOB_COLUMNS,
                "bot_id=? AND persona_id=? AND work_kind='d13.precompress.paid.v1' AND job_id>? ORDER BY job_id",
                (*ns, self.cursor))
            if row is None: self._next("intents")
            else:
                self.jobs[row[0]] = tuple(row); self.cursor = row[0]
                self._observe("runtime_jobs", row, meter)
        elif self.phase == "intents":
            row = meter.read_fixed_row(self.db, "graph_d13_paid_intent_originals_v1",
                ("job_ref", "operation_id", "original_digest"),
                "bot=? AND persona=? AND job_ref>? ORDER BY job_ref", (*ns, self.cursor))
            if row is None:
                if self.jobs.keys() != self.intents.keys():
                    raise AuthorityUnavailable("D13 priority namespace has orphan paid job/original")
                self._next("schedules")
            else:
                self.job = self.jobs.get(row[0])
                if self.job is None or self.job[1] != row[1]:
                    raise AuthorityUnavailable("D13 priority immutable original has no exact paid job")
                self.job_id = row[0]
                self.cursor, self.intent_head = row[0], tuple(row[1:])
                self._observe("graph_d13_paid_intent_originals_v1", row, meter)
                self.column = _ColumnV3(self, table="graph_d13_paid_intent_originals_v1", column="original_json",
                    key_columns=("bot", "persona", "job_ref"), key=(*ns, row[0]), metadata=True)
                self.phase = "intent_column"
        elif self.phase == "intent_column":
            self.column.advance(meter)
            if self.column.complete: self._intent_finished()
        elif self.phase == "intent_digest":
            self.intent_digest_task.advance_v3(meter)
            if self.intent_digest_task.complete:
                job = self.job
                call = meter.read_fixed_row(self.db, "graph_d13_paid_call_originals_v1", ("call_id", "original_digest"),
                    "bot=? AND persona=? AND job_ref=?", (*ns, job[0]))
                read = meter.read_fixed_row(self.db, "graph_d13_paid_result_reads_v1", ("read_attempt_id", "payload_digest"),
                    "bot=? AND persona=? AND job_ref=?", (*ns, job[0]))
                cost = meter.read_fixed_row(self.db, "graph_d13_paid_cost_receipts_v1", ("payload_digest",),
                    "bot=? AND persona=? AND job_ref=?", (*ns, job[0]))
                if (read is not None and call is None) or (cost is not None and read is None):
                    raise AuthorityUnavailable("D13 priority paid call/read/cost original join mismatch")
                if call is not None and call[0] != self.column.parser.scalars[("binding", "call_id")]:
                    raise AuthorityUnavailable("D13 priority paid call identity differs")
                self.paid_headers[job[0]] = (call, read, cost)
                self._observe("paid-call-read-cost", (job[0], call, read, cost), meter)
                self.job_id = None
                self.column = self.intent_digest_task = self.job = self.intent_head = None
                self.phase = "intents"
        elif self.phase == "schedules":
            row = meter.read_fixed_row(self.db, "graph_d13_paid_schedule_inputs_v1",
                ("job_ref", "scene_ref", "pending", "payload_digest"),
                "bot=? AND persona=? AND job_ref>? ORDER BY job_ref", (*ns, self.cursor))
            if row is None: self._next("ledgers")
            else:
                self.cursor, self.selected_row = row[0], tuple(row)
                self._observe("graph_d13_paid_schedule_inputs_v1", row, meter)
                self.column = _ColumnV3(self, table="graph_d13_paid_schedule_inputs_v1", column="payload_json",
                    key_columns=("bot", "persona", "job_ref"), key=(*ns, row[0]), metadata="schedule")
                self.phase = "schedule_column"
        elif self.phase == "schedule_column":
            self.column.advance(meter)
            if self.column.complete:
                row, c = self.selected_row, self.column
                values, outer = c.parser.frozen.values, c.parser.scalars
                scene = AtomKey.from_token(values[("window", "scene_ref", "ref")])
                if (c.sha256 != row[3] or outer.get(("binding", "job_ref")) != row[0]
                        or values.get(("plan", "job_ref")) != row[0]
                        or (values.get(("window", "namespace", "bot_id")), values.get(("window", "namespace", "persona_id"))) != ns
                        or NamespaceId.from_key(scene) != self.namespace or scene.owner.kind != "scene"
                        or scene.owner.subject != row[1] or row[2] not in (0, 1)
                        or row[2] == 0 and row[0] not in self.intents):
                    raise AuthorityUnavailable("D13 priority pending schedule metadata/committed original mismatch")
                policy = self.graph._GraphCoordinator__d13_paid_precompression_policy
                if ((outer.get(("job", "bot_id")), outer.get(("job", "persona_id"))) != ns
                        or outer.get(("job", "job_id")) != row[0]
                        or outer.get(("job", "operation_id")) != outer.get(("binding", "original_operation_id"))
                        or outer.get(("job", "budget_ref")) != policy.lease_id
                        or outer.get(("job", "work_kind")) != "d13.precompress.paid.v1"):
                    raise AuthorityUnavailable("D13 priority pending original job/lease differs")
                self.schedules[row[0]] = (row, values[("window", "conversation_ref")],
                    outer[("binding", "original_operation_id")],
                    min(_finite_time_v1(values[("plan", "expires_at_utc")]), _finite_time_v1(outer[("binding", "expires_at_utc")]),
                        _job_deadline_v1(outer[("job", "deadline_utc")])))
                self.column = self.selected_row = None; self.phase = "schedules"
        elif self.phase == "ledgers":
            row = meter.read_fixed_row(self.db, "graph_d13_paid_scene_jobs_v1",
                ("job_ref", "scene_ref", "input_digest", "state", "expires_at_utc"),
                "bot=? AND persona=? AND job_ref>? ORDER BY job_ref", (*ns, self.cursor))
            if row is None:
                if self.ledgers.keys() != self.intents.keys():
                    raise AuthorityUnavailable("D13 priority namespace has orphan scene ledger/original")
                self._next("select")
                self.selection_iterator = iter(self.intents.items())
            else:
                original = self.intents.get(row[0])
                if (original is None or row[1] != original[1]
                        or row[3] not in {"queued", "running", "standby", "active", "finished", "retired"}):
                    raise AuthorityUnavailable("D13 priority scene ledger original mismatch")
                if row[3] == "finished":
                    job = self.jobs[row[0]]
                    if (job[5] != "failed" or job[13] is not None
                            or any(header is None for header in self.paid_headers[row[0]])):
                        raise AuthorityUnavailable("D13 finished paid original lacks its actual terminal/read/cost metadata")
                self.ledgers[row[0]] = tuple(row); self.cursor = row[0]
                self._observe("graph_d13_paid_scene_jobs_v1", row, meter)
        elif self.phase == "select":
            self._select(meter)
        elif self.phase == "select_pending":
            self._select_pending()
        else:
            raise AuthorityUnavailable("D13 priority has another metadata phase")
        self.reserve_v3()

    def _select(self, meter):
        p = self.parent
        item = next(self.selection_iterator, None)
        if item is None:
            self.phase = "select_pending"
            self.selection_iterator = iter(self.schedules.items())
            return
        ref, original = item
        if p.mode == "discovery":
            job, ledger = self.jobs[ref], self.ledgers[ref]
            if ledger[3] in {"queued", "running", "standby"}:
                self._append_recovery_v1("existing_paid", ref, original[0], original[2],
                    original[3], original[4], min(original[5], _finite_time_v1(ledger[4])), "paid_original_unresolved")
            return
        if original[0] != p.scene_ref: return
        if original[2] != p.authority.audience[0] or original[1] != p.scene_token:
            raise AuthorityUnavailable("D13 priority selected scene/conversation differs")
        job, ledger = self.jobs[ref], self.ledgers[ref]
        state = ledger[3]
        if state in {"queued", "running"}:
            if job[5] not in {"queued", "running", "waiting", "deferred"} or job[12]:
                raise AuthorityUnavailable("D13 priority unresolved paid job state differs")
            self.choices.append(("existing_paid", ref, original[3], original[4], original[5], "paid_original_unresolved"))
        elif state == "standby":
            block = p.ledger_blocks.get(ref)
            if block is None or block[2] is None or block[2][2] != 1 or block[3] is None:
                raise AuthorityUnavailable("D13 priority standby needs its actual metadata original")
            self._observe("standby-block", (ref, block), meter)
            if block[3][1] == "standby":
                self.choices.append(("existing_paid", ref, original[3], original[4],
                    min(original[5], ledger[4]), "paid_standby_unadopted"))
            elif block[3][1] not in {"active", "retired"}:
                raise AuthorityUnavailable("D13 priority standby state is unresolved")
        if len(self.choices) > 1:
            raise AuthorityUnavailable("D13 priority multiple outstanding paid originals; HOLD")

    def _select_pending(self):
        p = self.parent
        item = next(self.selection_iterator, None)
        if item is not None:
            ref, (row, conversation, operation, expiry) = item
            if p.mode == "discovery":
                if row[2] == 1:
                    self._append_recovery_v1("pending_paid_schedule", ref, row[1], conversation,
                        operation, row[3], expiry, "paid_schedule_pending")
                return
            if row[1] == p.scene_ref and row[2] == 1:
                if conversation != p.authority.audience[0]:
                    raise AuthorityUnavailable("D13 priority pending conversation differs")
                self.choices.append(("pending_paid_schedule", ref, operation, row[3], expiry, "paid_schedule_pending"))
            if len(self.choices) > 1:
                raise AuthorityUnavailable("D13 priority multiple outstanding paid originals; HOLD")
            return
        if p.mode == "discovery":
            self.result = tuple(self.recovery_items)
            self.complete = True
            return
        if self.choices:
            status, ref, operation, digest, expiry, reason = self.choices[0]
        else:
            ref = operation = digest = expiry = None
            reason, status = "paid_metadata_complete_absence", "no_outstanding_paid"
        if expiry is not None and p.now_utc >= expiry:
            status, reason = "hold", "paid_original_expired"
        self.result = D13PrecompressionPriorityV1(status, self.namespace, p.scene_ref,
            p.authority.audience[0], ref, operation, digest, expiry, self.root.hexdigest(), reason)
        self.complete = True

    def _append_recovery_v1(self, status, ref, scene, conversation, operation, digest, expiry, reason):
        if len(self.recovery_items) >= 64 or scene in self.recovery_scenes:
            raise AuthorityUnavailable("D13 paid recovery identities exceed bound or have competing scene originals")
        if self.parent.now_utc >= expiry:
            status, reason = "hold", "paid_original_expired"
        self.recovery_scenes.add(scene)
        self.recovery_items.append(D13PrecompressionPriorityV1(status, self.namespace, scene,
            conversation, ref, operation, digest, expiry, self.root.hexdigest(), reason))

    def release_payload_v3(self):
        self.jobs.clear(); self.intents.clear(); self.schedules.clear(); self.ledgers.clear(); self.paid_headers.clear()
        self.job_id = None
        self.column = self.intent_digest_task = self.job = self.intent_head = self.selected_row = None
        self.result = None
        self.choices.clear(); self.recovery_items.clear(); self.recovery_scenes.clear(); self.selection_iterator = None


def require_no_outstanding_paid_for_deterministic_v1(db, namespace, window):
    """Repeat exact scene absence in the original deterministic WRITE view."""
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    if not db.in_transaction:
        raise RuntimeError("D13 competing-original check needs the actual business transaction")
    with runtime_storage_quantum_v3(db) as meter:
        pending = meter.read_fixed_row(db, "graph_d13_paid_schedule_inputs_v1", ("job_ref",),
            "bot=? AND persona=? AND scene_ref=? AND pending=1", (*namespace.as_tuple, AtomKey.from_token(window.scene_ref.ref).owner.subject))
        ledger = meter.read_fixed_row(db, "graph_d13_paid_scene_jobs_v1", ("job_ref", "state"),
            "bot=? AND persona=? AND scene_ref=? AND state IN ('queued','running','standby') ORDER BY job_ref",
            (*namespace.as_tuple, window.scene_ref.ref))
        if pending is not None or ledger is not None:
            raise AuthorityUnavailable("D13 competing paid original changed before deterministic WRITE")
