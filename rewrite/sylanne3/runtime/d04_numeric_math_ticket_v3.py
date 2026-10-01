"""One bounded private math handoff, issued only from a new actual claim ACK."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
import os
from threading import Lock

from ..authority_service.c09_process_identity_v1 import read_process_identity_v1
from ..runtime_contracts import canonical_digest
from .c04_authority_port_v3 import InstalledC04AuthorityPortV3
from .d04_appraisal_driver_v3 import read_d04_original_v3
from .d04_installed_numeric_v3 import (
    D04ExecutedNumericV3, _MeasuredNumericV3, _ready_from_original_v3,
    _pending_measured, _flush_actual_measurement_v3, numeric_ids_v3,
    prepare_post_c02_joint_numeric_v3,
)
from .d04_numeric_cost_v3 import read_d04_numeric_prepared_v3, measure_installed_d04_numeric_v3


@dataclass(frozen=True, slots=True)
class _MathTicketV3:
    ready: object
    claim: object
    installation: object
    output_policy: object


@dataclass(frozen=True, slots=True)
class _MathReturnV3:
    ticket: _MathTicketV3
    measured: _MeasuredNumericV3


class InstalledD04MathQueueV3:
    """No Graph access/RPC occurs on the one actual synchronous math thread."""
    def __init__(self, graph, bootstrap):
        graph._admin(bootstrap)
        self._graph_id = id(graph)
        self._lock = Lock()
        self._busy = None
        self._issued = None
        self._returned = None
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sylanne-d04-native")

    def reserve(self, graph, operation_id):
        if id(graph) != self._graph_id:
            raise ValueError("D04 math queue belongs to another installed coordinator")
        with self._lock:
            if self._busy is not None:
                return False
            self._busy = operation_id
            return True

    def abandon_unissued(self, operation_id):
        with self._lock:
            if self._busy == operation_id and self._issued is None and self._returned is None:
                self._busy = None

    def claim_and_issue(self, graph, bootstrap, ready, installation, output_policy):
        graph._admin(bootstrap)
        port = graph._GraphCoordinator__c04_authority_port_v3
        if (id(graph) != self._graph_id
                or getattr(graph, "_GraphCoordinator__d04_math_queue_v3", None) is not self
                or type(port) is not InstalledC04AuthorityPortV3
                or graph._GraphCoordinator__d04_installed_joint_assembly is not installation
                or port._bundle is not installation.admin_bundle
                or graph._GraphCoordinator__d04_installed_joint_output_policy is not output_policy):
            raise ValueError("D04 math ticket issuer is not this exact installed composition")
        with self._lock:
            if self._busy != ready.prepared.binding.operation_id or self._issued is not None or self._returned is not None:
                raise ValueError("D04 actual claim lacks its reserved private math slot")
            # Claim creation is inside the concrete issuer. A supplied claim
            # DTO, recovered ACK or imported ticket cannot reach this branch.
            incarnation = "d04-executor:" + canonical_digest(read_process_identity_v1(os.getpid()))
            claim = port.numeric_claim(ready.prepared.binding, incarnation)
            if claim.binding_digest != ready.prepared.binding.digest:
                raise ValueError("D04 math ticket actual claim differs")
            self._issued = _MathTicketV3(ready, claim, installation, output_policy)
            return self._issued

    def submit(self, ticket):
        with self._lock:
            if type(ticket) is not _MathTicketV3 or self._issued is not ticket:
                raise ValueError("D04 math ticket is not the actual newly issued object")
            # Consume before placing it in the sole executor. No DTO, retry or
            # second submit can reconstruct this process-local start right.
            self._issued = None
        return self._pool.submit(self._measure, ticket)

    def _measure(self, ticket):
        from .d04_joint_product_assembly_v3 import run_installed_d04_joint_product_v3
        from .d04_numeric_artifact_v3 import encode_d04_numeric_artifact_v3
        ready, policy = ticket.ready, ticket.installation.admin_bundle.d04_joint_numeric
        product, measurement, error = measure_installed_d04_numeric_v3(ready.prepared, ticket.claim,
            lambda _: run_installed_d04_joint_product_v3(ready.preparation, installation=ticket.installation,
                output_policy=ticket.output_policy, max_iterations=policy.max_iterations, tolerance=policy.tolerance))
        artifact = None
        if error is None:
            try:
                artifact = encode_d04_numeric_artifact_v3(ready.prepared, ticket.claim, product)
            except (ValueError, TypeError, OverflowError):
                pass  # Completed CPU remains completed; missing proof closes cost only.
        measured = _MeasuredNumericV3(ready, ticket.claim, measurement, artifact)
        returned = _MathReturnV3(ticket, measured)
        with self._lock:
            if self._busy != ready.prepared.binding.operation_id or self._returned is not None:
                raise RuntimeError("D04 actual measured slot identity changed")
            self._returned = returned
        return returned

    def accept(self, graph, returned):
        with self._lock:
            if id(graph) != self._graph_id or self._returned is not returned or type(returned) is not _MathReturnV3:
                raise ValueError("D04 measured return was not produced by this installed queue")
            measured = returned.measured
            _pending_measured(graph)[measured.ready.prepared.binding.digest] = measured
            self._returned = None
            self._busy = None
        return _flush_actual_measurement_v3(graph, measured)

    def completed(self, graph, operation_id):
        if id(graph) != self._graph_id:
            raise ValueError("D04 completed math belongs to another coordinator")
        with self._lock:
            return self._returned if self._busy == operation_id else None

    def close(self):
        # Shutdown never pretends that Future cancellation stops native work.
        self._pool.shutdown(wait=True, cancel_futures=False)
        with self._lock:
            return self._returned


def issue_current_numeric_math_ticket_v3(graph, bootstrap, bundle, queue, *, c02_operation_id, source_ref):
    graph._admin(bootstrap)
    if (type(queue) is not InstalledD04MathQueueV3
            or getattr(graph, "_GraphCoordinator__d04_math_queue_v3", None) is not queue):
        raise ValueError("D04 math queue is not installed on this coordinator")
    port, store = graph._GraphCoordinator__c04_authority_port_v3, graph._GraphCoordinator__store
    if type(port) is not InstalledC04AuthorityPortV3 or port._bundle is not bundle:
        raise ValueError("D04 queue needs the current actual paired installation")
    identity = numeric_ids_v3(bundle.installation_policy.namespace, c02_operation_id)
    if not queue.reserve(graph, identity["operation"]):
        returned = queue.completed(graph, identity["operation"])
        if returned is not None:
            return queue.accept(graph, returned)
        return {"status": "numeric_executor_busy", "operation_id": identity["operation"]}
    try:
        with store._lock:
            prepared = read_d04_numeric_prepared_v3(store._db, bundle.installation_policy.namespace, identity["operation"])
        ready = (prepare_post_c02_joint_numeric_v3(graph, bootstrap, bundle,
            c02_operation_id=c02_operation_id, source_ref=source_ref) if prepared is None else _ready_from_original_v3(prepared))
        prepared, binding = ready.prepared, ready.prepared.binding
        job = json.loads(prepared.job_payload_json)
        if (job["continuation"].get("c02_operation_id") != c02_operation_id
                or job["continuation"].get("source_ref") != source_ref):
            raise ValueError("D04 queued numeric input changed its original C02 source")
        closure = port.numeric_cost_inspect(binding)
        if closure is not None:
            return D04ExecutedNumericV3(prepared, closure, "execution_completed_adoption_not_adopted")
        claim, terminal = port.numeric_inspect(binding)
        if terminal is not None:
            return D04ExecutedNumericV3(prepared, terminal, "execution_terminal")
        if claim is not None:
            pending = _pending_measured(graph).get(binding.digest)
            if pending is not None:
                return _flush_actual_measurement_v3(graph, pending)
            from ..authority_service.d04_numeric_contract_v3 import D04NumericMeasurementV3, from_wire
            with store._lock:
                measured = read_d04_original_v3(store._db, binding.namespace, "numeric_measurement", binding.operation_id)
                artifact = read_d04_original_v3(store._db, binding.namespace, "numeric_artifact", binding.operation_id)
            if measured is None:
                return D04ExecutedNumericV3(prepared, None, "claimed_execution_unknown")
            pending = _MeasuredNumericV3(ready, claim, from_wire(measured[0]["measurement"], D04NumericMeasurementV3),
                None if artifact is None else artifact[0])
            _pending_measured(graph)[binding.digest] = pending
            return _flush_actual_measurement_v3(graph, pending)
        if _ready_from_original_v3(prepared) != ready or _pending_measured(graph):
            raise ValueError("D04 original codec or prior measured pending slot blocks a new claim")
        return queue.claim_and_issue(graph, bootstrap, ready, graph._GraphCoordinator__d04_installed_joint_assembly,
            graph._GraphCoordinator__d04_installed_joint_output_policy)
    finally:
        queue.abandon_unissued(identity["operation"])
