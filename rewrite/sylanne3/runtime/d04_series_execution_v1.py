"""Real per-chunk D02/D11 work and Graph progression for one frozen series."""
from dataclasses import asdict, dataclass, replace
import json
import os
from time import thread_time_ns
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

from ..authority_service.d04_series_contract_v1 import (D04SeriesChunkBindingV1, D04SeriesClaimV1,
    D04SeriesMeasurementV1, D04SeriesTerminalV1, D04SeriesGateV1, to_wire, from_wire)
from ..graph_types import AtomKey, GraphWrite, GraphVersion, GraphCandidate
from ..graph_store import GraphStore
from ..contracts import Event, Scope
from ..runtime_contracts import canonical_digest, canonical_serialize
from .d04_appraisal_driver_v3 import read_d04_original_v3, record_d04_original_in_transaction_v3
from .d04_series_store_v1 import (read_d04_series_root_v1, freeze_post_c02_d04_series_v1,
    read_d04_series_chunk_prepared_v1, read_d04_series_chunk_math_v1,
    require_d04_series_own_progress_v1, record_d04_series_progress_v1)
from .d04_series_codec_v1 import encode_series_dto_v1, decode_series_dto_v1
from .d04_installed_stage_fence_v3 import run_installed_d04_stage_v3
from .d11_types import job_graph_write, cost_settlement_from_runtime, cost_settlement_graph_write, reconcile_runtime_write
from .jobs import get_job, checkpoint_job, transition_job, acquire_job, _save_job
from .budget import reserve_budget, settle_budget, get_budget_lease, require_budget_family_admissible
from .issuers import ResourceQuote
from ..native_runtime.d04_series_math_v1 import run_d04_series_chunk_math_v1, verify_d04_series_chunk_math_v1, D04SeriesChunkMathV1


def chunk_operation_v1(root, start):
    return (root.prepared.binding.operation_id if start == 0 else
        "d04-series-chunk:" + canonical_digest((root.digest, start))[:48])


def _reads(db, writes):
    return tuple(GraphVersion(write.key, (db.execute("SELECT revision FROM graph_atoms WHERE token=?",
        (write.key.token,)).fetchone() or (0,))[0]) for write in writes)


def commit_series_writes_v1(graph, db, metadata, epoch, root, *, event_id, now, writes,
        reads=None, target=None, operation_digest=None, ledger_refs=()):
    store = graph._GraphCoordinator__store
    for write in writes:
        if write.key.type_name.startswith("runtime."):
            reconcile_runtime_write(db, write)
    candidate = GraphCandidate(Event(Scope(*root.prepared.binding.namespace.as_tuple,
        root.prepared.binding.activity_id), event_id, now, "d04.series-graph.v1",
        {"root_digest": root.digest, "writes_digest": canonical_digest(writes)}),
        tuple(reads) if reads is not None else _reads(db, writes), tuple(writes), (epoch,))
    receipt = GraphStore._graph_commit_in_transaction(store, candidate,
        _capability=graph._GraphCoordinator__graph_capability)
    if receipt.status != "committed":
        raise ValueError("series exact Graph event CAS changed")
    store.cas_graph_recovery_metadata(metadata, target or metadata.requirements,
        _capability=graph._GraphCoordinator__graph_capability)
    namespace = root.prepared.binding.namespace
    row = db.execute("SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    seq = (0 if row is None else row[0]) + 1
    db.execute("INSERT INTO graph_bundle_sequence VALUES(?,?,?) ON CONFLICT(bot,persona) DO UPDATE SET last_seq=excluded.last_seq",
        (*namespace.as_tuple, seq))
    db.execute("INSERT INTO graph_bundle_operations(bot,persona,operation_id,digest,activity_id,effect_id,commit_seq,receipt_json) "
        "VALUES(?,?,?,?,?,NULL,?,?)", (*namespace.as_tuple, event_id, operation_digest or canonical_digest(candidate),
        root.prepared.binding.activity_id, seq, canonical_serialize({"ledger_refs": list(ledger_refs), "outbox_refs": [],
            "root_digest": root.digest, "graph_receipt_digest": canonical_digest(receipt)})))
    return receipt


def _require_d04_series_cpu_deadline_v1(*, grant, lease, policy, base, now):
    """The existing fixed-root/parent guard, separated for permanent boundaries."""
    if (grant.grant_id != policy.grant_id or grant.version != policy.grant_version
            or grant.valid_until_utc <= now or lease.state != "active"
            or base.cpu_ceiling_ms > grant.max_ceiling.get("cpu_ms", 0)
            or now >= __import__("datetime").datetime.fromisoformat(base.deadline_utc.replace("Z", "+00:00")).timestamp()):
        raise ValueError("series fixed deadline/current parent CPU authority expired")


def prepare_d04_series_chunk_v1(graph, bootstrap, bundle, root, *, predecessor=None):
    graph._admin(bootstrap)
    start = 0 if predecessor is None else predecessor.end_step_index
    steps = root.frozen.plan.chunk(start)
    operation = chunk_operation_v1(root, start)
    store = graph._GraphCoordinator__store
    with store._lock:
        prior = read_d04_series_chunk_prepared_v1(store._db, root.prepared.binding.namespace, operation)
    if prior is not None:
        return prior[0]
    def prepare(db, metadata, epoch, now, guard, role, current):
        require_d04_series_own_progress_v1(graph, db, root)
        base = root.prepared.binding
        policy = bundle.d04_joint_numeric
        grant = graph._GraphCoordinator__d11_issuer.current_budget_grant(db, policy.lease_id)
        lease = get_budget_lease(db, policy.lease_id)
        _require_d04_series_cpu_deadline_v1(grant=grant, lease=lease, policy=policy, base=base, now=now)
        require_budget_family_admissible(db, lease.lease_id)
        job = get_job(db, base.job_id)
        if job.phase != "running" or job.cancel_epoch:
            raise ValueError("series original worker is not runnable")
        from .d04_installed_numeric_v3 import _utc
        job = acquire_job(db, job.job_id, job.lease_holder, now_utc=_utc(now),
            lease_seconds=max(1, int(__import__("datetime").datetime.fromisoformat(base.deadline_utc.replace("Z", "+00:00")).timestamp() - now)))
        continuation = {**job.continuation, "series_root_ref": root.root_ref, "series_root_digest": root.digest,
            "series_start_step_index": start, "series_end_step_index": start + len(steps),
            "series_predecessor_digest": None if predecessor is None else predecessor.digest}
        updated = checkpoint_job(db, job.job_id, job.lease_holder, job.fence,
            continuation=continuation, usage=job.usage)
        if start == 0:
            numeric = base
            quote_json = root.prepared.quote_payload_json
            reserve_json = root.prepared.reserve_receipt_json
        else:
            predecessor_operation = chunk_operation_v1(root, predecessor.start_step_index)
            paid = read_d04_original_v3(db, base.namespace, "series_chunk_cost", predecessor_operation)
            if (paid is None or paid[0]["math_digest"] != predecessor.digest or not paid[0]["authority_ack"]):
                raise ValueError("series next CPU reservation requires prior durable terminal ACK")
            quote_id = "d04-series-quote:" + canonical_digest((root.digest, start))[:48]
            deadline = __import__("datetime").datetime.fromisoformat(base.deadline_utc.replace("Z", "+00:00")).timestamp()
            quote = ResourceQuote(quote_id, 1, *base.namespace.as_tuple, base.activity_id, operation, None,
                base.parent_budget_lease_ref, job.work_kind, root.root_ref, deadline, base.algorithm_id,
                job_graph_write(updated).key.token, (), (), {"cpu_ms": base.cpu_ceiling_ms}, None, deadline)
            resource = graph._GraphCoordinator__d02_issuer
            resource.issue_quote(db, quote)
            if resource.original_signed_quote(db, quote_id, 1) != quote:
                raise ValueError("series actual signed chunk quote changed")
            reservation = "d04-series-reserve:" + canonical_digest((root.digest, start))[:48]
            reserve_digest = canonical_digest((root.digest, start, canonical_digest(quote), continuation))
            reserved = reserve_budget(db, lease.lease_id, reservation, reserve_digest, quote.ceiling)
            if reserved.status != "reserved":
                raise ValueError("series parent CPU cannot reserve the next chunk")
            reserve_json = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
                "AND operation_id=? AND phase='reserve'", (*base.namespace.as_tuple, reservation)).fetchone()[0]
            quote_json = canonical_serialize(quote)
            numeric = replace(base, operation_id=operation, execution_id="d04-series-execution:" + canonical_digest((root.digest, start))[:48],
                input_original_ref="d04-series-input:" + canonical_digest((root.digest, start))[:48],
                input_digest=canonical_digest((root.digest, root.frozen.plan.digest, start, predecessor.digest)),
                quote_id=quote_id, quote_version=1, quote_digest=canonical_digest(quote),
                reservation_operation_id=reservation, reservation_digest=reserve_digest)
        binding = D04SeriesChunkBindingV1(numeric, root.root_ref, root.digest, root.frozen.plan.digest,
            start, start + len(steps), None if predecessor is None else chunk_operation_v1(root, predecessor.start_step_index),
            None if predecessor is None else predecessor.digest)
        value = {"schema": "d04.series-chunk-prepared.v1", "binding": to_wire(binding), "job": asdict(updated),
            "quote_payload_json": quote_json, "reserve_receipt_json": reserve_json,
            "graph_revision": metadata.graph_revision + 1, "graph_epoch": epoch.revision + 1,
            "requirements_json": canonical_serialize(asdict(metadata.requirements))}
        record_d04_original_in_transaction_v3(db, base.namespace, "series_chunk_prepared", operation, value)
        from .d04_numeric_accounting_prepared_v3 import JOB_IDENTITY_FIELDS
        record_d04_original_in_transaction_v3(db, base.namespace, "series_chunk_accounting", operation,
            {"schema": "d04.series-chunk-accounting.v1", "binding": to_wire(binding),
                "quote_payload_json": quote_json, "reserve_receipt_json": reserve_json,
                "job_identity_json": canonical_serialize({name: asdict(updated)[name] for name in JOB_IDENTITY_FIELDS})})
        writes = (job_graph_write(updated),)
        event_id = "d04-series-prepare:" + operation
        receipt = commit_series_writes_v1(graph, db, metadata, epoch, root, event_id=event_id, now=now, writes=writes)
        record_d04_series_progress_v1(graph, db, root, before=metadata, before_epoch=epoch,
            receipt=receipt, event_id=event_id, writes=writes)
        return {"status": "series_chunk_prepared", "binding": to_wire(binding)}
    value = run_installed_d04_stage_v3(graph, bootstrap, bundle,
        c02_operation_id=root.payload["c02_operation_id"], source_ref=root.payload["source_ref"],
        operation_id="d04-series-stage:" + operation, stage="numeric_prepare",
        request_digest=canonical_digest((root.digest, start)), commit=prepare, semantic=True)
    return from_wire(value["binding"], D04SeriesChunkBindingV1)


@dataclass(frozen=True, slots=True)
class _SeriesTicketV1:
    root: object
    binding: D04SeriesChunkBindingV1
    claim: D04SeriesClaimV1
    predecessor: D04SeriesChunkMathV1 | None
    installation: object


@dataclass(frozen=True, slots=True)
class _SeriesReturnV1:
    ticket: _SeriesTicketV1
    math: D04SeriesChunkMathV1 | None
    measurement: D04SeriesMeasurementV1


@dataclass(frozen=True, slots=True)
class _SeriesHandoffV1:
    returned: _SeriesReturnV1
    terminal: D04SeriesTerminalV1
    cost_digest: str

    @property
    def math(self):
        return self.returned.math


class InstalledD04SeriesQueueV1:
    def __init__(self, graph, bootstrap):
        graph._admin(bootstrap)
        self.graph_id = id(graph)
        self._lock = Lock()
        self._ticket = self._return = None
        self._accepted = None
        self._active = False
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sylanne-d04-series")

    def issue(self, graph, root, binding, predecessor):
        if id(graph) != self.graph_id or graph._GraphCoordinator__d04_series_queue_v1 is not self:
            raise ValueError("actual installed series queue issuer required")
        from ..authority_service.c09_process_identity_v1 import read_process_identity_v1
        from .d04_series_initial_original_v1 import require_d04_series_initial_original_v1
        store = graph._GraphCoordinator__store
        with store._lock:
            store._db.execute("BEGIN")
            try:
                require_d04_series_initial_original_v1(store._db, root)
            finally:
                store._db.rollback()
        with self._lock:
            if self._active:
                raise ValueError("series executor already occupied")
            port = graph._GraphCoordinator__c04_authority_port_v3
            claim = port.series(binding, "claim", executor_incarnation="d04-series-executor:" + canonical_digest(read_process_identity_v1(os.getpid())))
            self._ticket = _SeriesTicketV1(root, binding, claim, predecessor, graph._GraphCoordinator__d04_installed_joint_assembly)
            self._active = True
            return self._ticket

    def submit(self, ticket):
        with self._lock:
            if type(ticket) is not _SeriesTicketV1 or self._ticket is not ticket:
                raise ValueError("series native execution requires actual new claim object")
            self._ticket = None
        return self._pool.submit(self._measure, ticket)

    def _measure(self, ticket):
        from ..native_runtime.loader import load_production_native
        from ..native_runtime.d04_fixed_trajectory_v2 import bounded_d04_native_cpu_v2
        start = thread_time_ns()
        math = None
        failure = None
        try:
            handle = load_production_native(ticket.installation.package_root,
                trusted_manifest_sha256=ticket.binding.numeric.native_manifest_sha256)
            with bounded_d04_native_cpu_v2(ticket.binding.numeric.cpu_ceiling_ms):
                math = run_d04_series_chunk_math_v1(handle, ticket.root.frozen,
                    root_digest=ticket.root.digest, predecessor=ticket.predecessor)
                if math.invariant_domain is not None:
                    from ..native_runtime.d04_invariant_domain_v1 import require_installed_d04_invariant_verifier_v1
                    require_installed_d04_invariant_verifier_v1(math.invariant_domain, ticket.binding.numeric.native_manifest_sha256)
                from ..domains.d04.joint_state_output_v1 import JointStateOutputPolicyV1
                from ..native_runtime.d04_series_math_v1 import read_d04_series_certified_box_v1
                policy_values = dict(ticket.root.payload["output_policy"])
                policy_values["axis_ids"] = tuple(policy_values["axis_ids"])
                policy = JointStateOutputPolicyV1(**policy_values)
                for endpoint in math.endpoints:
                    read_d04_series_certified_box_v1(math, endpoint.output, endpoint.trajectory_error, policy)
                # Serialize within the measured thread; the transcript becomes
                # the genuine observed artifact before a terminal is requested.
                encode_series_dto_v1(math)
        except Exception as exc:
            failure = type(exc).__name__
        measured = D04SeriesMeasurementV1(ticket.binding.digest, ticket.claim.claim_id,
            "chunk_completed" if failure is None else "failed", thread_time_ns() - start,
            None if failure is not None else math.digest,
            None if failure is not None else canonical_digest(math.endpoints), failure)
        value = _SeriesReturnV1(ticket, math if failure is None else None, measured)
        with self._lock:
            self._return = value
        return value

    def accept(self, graph, returned):
        with self._lock:
            if id(graph) != self.graph_id or returned is not self._return:
                raise ValueError("series returned measurement is not this actual native execution")
        terminal = persist_d04_series_measurement_v1(graph, returned)
        with self._lock:
            self._return = None
            self._accepted = (returned, terminal)
            self._active = False
        return terminal

    def handoff(self, graph, returned, terminal, paid):
        """Continue this exact execution only after its independent cost ACK."""
        with self._lock:
            if (id(graph) != self.graph_id or graph._GraphCoordinator__d04_series_queue_v1 is not self
                    or self._accepted is None or self._accepted[0] is not returned
                    or self._accepted[1] is not terminal):
                raise ValueError("series hot handoff requires this actual accepted execution")
            root, binding, claim = returned.ticket.root, returned.ticket.binding, returned.ticket.claim
            math = returned.math
            if (math is None or terminal.binding != binding or terminal.claim != claim
                    or terminal.measurement != returned.measurement
                    or terminal.measurement.status != "chunk_completed"
                    or terminal.measurement.actual_cpu_ms > binding.numeric.cpu_ceiling_ms
                    or (math.root_digest, math.plan_digest, math.start_step_index,
                        math.end_step_index, math.predecessor_digest) != (root.digest, binding.plan_digest,
                        binding.start_step_index, binding.end_step_index, binding.predecessor_digest)
                    or math.digest != terminal.measurement.chunk_math_digest
                    or canonical_digest(math.endpoints) != terminal.measurement.endpoint_digest):
                raise ValueError("series hot handoff actual root/claim/math/endpoints differ")
            store = graph._GraphCoordinator__store
            with store._lock:
                original = read_d04_original_v3(store._db, binding.numeric.namespace,
                    "series_chunk_cost", binding.numeric.operation_id)
            if (original is None or original[0] != paid or paid["authority_ack"] is not True
                    or paid["budget_status"] != "settled" or paid["root_digest"] != root.digest
                    or paid["binding_digest"] != binding.digest or paid["terminal_digest"] != terminal.digest
                    or paid["math_digest"] != math.digest or paid["actual_cpu_ns"] != terminal.measurement.actual_cpu_ns):
                raise ValueError("series hot handoff lacks its exact durable independent CPU ACK")
            value = _SeriesHandoffV1(returned, terminal, original[1])
            self._accepted = None
            return value

    def close(self):
        self._pool.shutdown(wait=True, cancel_futures=False)
        with self._lock:
            return self._return


def persist_d04_series_measurement_v1(graph, returned):
    root, binding, claim = returned.ticket.root, returned.ticket.binding, returned.ticket.claim
    port = graph._GraphCoordinator__c04_authority_port_v3
    actual, terminal = port.series(binding, "inspect")
    if actual != claim:
        raise ValueError("series actual measurement lost its independent claim")
    if terminal is not None:
        if terminal.measurement != returned.measurement:
            raise ValueError("series measurement conflicts with durable terminal")
        return terminal
    gate = port.series(binding, "gate", phase="measurement")
    port.series(binding, "validate", gate=gate)
    store = graph._GraphCoordinator__store
    with store._lock:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        try:
            metadata, epoch = graph._v2_graph_stamp(binding.numeric.namespace)
            if metadata.graph_revision != gate.before_graph_revision or canonical_serialize(asdict(metadata.requirements)) != gate.before_requirements_json:
                raise ValueError("series technical original must use exact Graph snapshot")
            record_d04_original_in_transaction_v3(db, binding.numeric.namespace, "series_chunk_measurement_gate", binding.numeric.operation_id, to_wire(gate))
            payload = None if returned.math is None or not gate.retain_math else encode_series_dto_v1(returned.math)
            if payload is not None:
                verify_d04_series_chunk_math_v1(root.frozen, returned.math, root_digest=root.digest,
                    predecessor=returned.ticket.predecessor)
                record_d04_original_in_transaction_v3(db, binding.numeric.namespace, "series_chunk_math", binding.numeric.operation_id, payload)
            record_d04_original_in_transaction_v3(db, binding.numeric.namespace, "series_chunk_measurement", binding.numeric.operation_id,
                {"claim": to_wire(claim), "measurement": to_wire(returned.measurement),
                    "artifact_payload_digest": None if payload is None else canonical_digest(payload)})
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return port.series(binding, "terminal", claim=claim, measurement=returned.measurement)


def stage_series_cpu_settlement_v1(graph, db, root, binding, terminal, gate, *, complete=False):
    numeric = binding.numeric
    prepared = read_d04_series_chunk_prepared_v1(db, numeric.namespace, numeric.operation_id)
    if prepared is None or prepared[0] != binding or terminal.binding != binding:
        raise ValueError("series exact prepared/terminal CPU originals differ")
    resource = graph._GraphCoordinator__d02_issuer
    quote = resource.original_signed_quote(db, numeric.quote_id, numeric.quote_version)
    if canonical_digest(quote) != numeric.quote_digest:
        raise ValueError("series signed CPU quote changed")
    record_d04_original_in_transaction_v3(db, numeric.namespace, "series_chunk_terminal", numeric.operation_id, to_wire(terminal))
    receipt = settle_budget(db, numeric.parent_budget_lease_ref, numeric.reservation_operation_id,
        numeric.reservation_digest, {"cpu_ms": terminal.measurement.actual_cpu_ms}, execution_revoked=True)
    cost_id = "d04-series-cost:" + canonical_digest((root.digest, binding.start_step_index))[:48]
    cost = cost_settlement_graph_write(cost_settlement_from_runtime(db, bot_id=numeric.namespace.bot_id,
        persona_id=numeric.namespace.persona_id, activity_id=numeric.activity_id, bundle_operation_id=numeric.operation_id,
        effect_id=None, settlement_id=cost_id, lease_id=numeric.parent_budget_lease_ref,
        cost_operation_id=numeric.reservation_operation_id, budget_operation_id=numeric.reservation_operation_id,
        budget_phase="settle", prior_unknown_ref=None, execution_revoked=True))
    job = get_job(db, numeric.job_id)
    continuation = {**job.continuation, "series_committed_step_index": binding.end_step_index,
        "series_last_terminal_digest": terminal.digest}
    usage = {"cpu_ms": job.usage.get("cpu_ms", 0) + terminal.measurement.actual_cpu_ms}
    if job.phase == "running" and not job.cancel_epoch:
        updated = checkpoint_job(db, job.job_id, job.lease_holder, job.fence, continuation=continuation, usage=usage)
    else:
        if complete:
            raise ValueError("cancelled series worker cannot adopt business output")
        updated = replace(job, usage=usage)
        _save_job(db, updated)
    if updated.phase == "running" and (complete or terminal.measurement.status == "failed" or receipt.status == "overrun"):
        updated = transition_job(db, job.job_id, job.lease_holder, job.fence,
            target_phase="completed" if complete else "failed", result_ref=root.root_ref if complete else terminal.terminal_ref)
    value = {"schema": "d04.series-chunk-cost.v1", "root_digest": root.digest, "binding_digest": binding.digest,
        "terminal_digest": terminal.digest, "actual_cpu_ns": terminal.measurement.actual_cpu_ns,
        "actual_cpu_ms": terminal.measurement.actual_cpu_ms, "status": terminal.measurement.status,
        "math_digest": terminal.measurement.chunk_math_digest, "budget_status": receipt.status,
        "gate_digest": gate.digest, "authority_ack": False}
    record_d04_original_in_transaction_v3(db, numeric.namespace, "series_chunk_cost_pending", numeric.operation_id, value)
    return value, (cost, job_graph_write(updated))


def settle_d04_series_chunk_v1(graph, bootstrap, bundle, root, binding, terminal):
    graph._admin(bootstrap)
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__c04_authority_port_v3
    with store._lock:
        prior = read_d04_original_v3(store._db, binding.numeric.namespace, "series_chunk_cost", binding.numeric.operation_id)
        saved_gate = read_d04_original_v3(store._db, binding.numeric.namespace, "series_chunk_cost_gate", binding.numeric.operation_id)
        committed = read_d04_original_v3(store._db, binding.numeric.namespace, "series_chunk_cost_commit", binding.numeric.operation_id)
    if prior is not None:
        return prior[0]
    gate = (from_wire(saved_gate[0], D04SeriesGateV1) if saved_gate is not None
        else port.series(binding, "gate", phase="settlement"))
    if committed is None:
        port.series(binding, "validate", gate=gate)
    if port.series(binding, "inspect")[1] != terminal:
        raise ValueError("series CPU settlement requires independently reread terminal")
    with store._lock:
        db = store._db
        pending = read_d04_original_v3(db, binding.numeric.namespace, "series_chunk_cost_pending", binding.numeric.operation_id)
        if pending is None:
            db.execute("BEGIN IMMEDIATE")
            try:
                metadata, epoch = graph._v2_graph_stamp(binding.numeric.namespace)
                if metadata.graph_revision != gate.before_graph_revision or canonical_serialize(asdict(metadata.requirements)) != gate.before_requirements_json:
                    raise ValueError("series accounting Graph snapshot changed")
                # Cost survives another-domain mutation. It never qualifies that
                # mutation as series own progress or business adoption.
                own = True
                try:
                    require_d04_series_own_progress_v1(graph, db, root)
                except ValueError:
                    own = False
                value, writes = stage_series_cpu_settlement_v1(graph, db, root, binding, terminal, gate)
                anchor = gate.permit.pinned_anchor
                target = replace(metadata.requirements, execution_seq=anchor.execution_seq,
                    execution_digest=anchor.execution_digest, deletion_seq=anchor.deletion_seq,
                    deletion_digest=anchor.deletion_digest, revocation_epoch=anchor.revocation_epoch)
                event = "d04-series-settle:" + binding.numeric.operation_id
                receipt = commit_series_writes_v1(graph, db, metadata, epoch, root, event_id=event,
                    now=__import__("time").time(), writes=writes, target=target)
                if own:
                    record_d04_series_progress_v1(graph, db, root, before=metadata, before_epoch=epoch,
                        receipt=receipt, event_id=event, writes=writes)
                record_d04_original_in_transaction_v3(db, binding.numeric.namespace, "series_chunk_cost_gate", binding.numeric.operation_id, to_wire(gate))
                # Authority authenticates this exact committed cost before ACK.
                record_d04_original_in_transaction_v3(db, binding.numeric.namespace, "series_chunk_cost_commit", binding.numeric.operation_id,
                    {**value, "event_id": event, "graph_receipt_digest": canonical_digest(receipt)})
                db.commit()
            except BaseException:
                db.rollback()
                raise
    port.series(binding, "finish", gate=gate)
    with store._lock:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        try:
            value = read_d04_original_v3(db, binding.numeric.namespace, "series_chunk_cost_commit", binding.numeric.operation_id)[0]
            value = {**value, "authority_ack": True}
            record_d04_original_in_transaction_v3(db, binding.numeric.namespace, "series_chunk_cost", binding.numeric.operation_id, value)
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return value
