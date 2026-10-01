"""Installed asynchronous complete series; one genuine claim per bounded CPU chunk."""
import asyncio
import logging
import time
from ..runtime.d04_series_execution_v1 import (InstalledD04SeriesQueueV1, prepare_d04_series_chunk_v1,
    settle_d04_series_chunk_v1, chunk_operation_v1, persist_d04_series_measurement_v1, _SeriesTicketV1, _SeriesReturnV1)
from ..runtime.d04_series_store_v1 import freeze_post_c02_d04_series_v1, read_d04_series_chunk_prepared_v1
from ..runtime.d04_series_adoption_v1 import adopt_d04_series_v1, abandon_d04_series_adoption_v1
from ..runtime.d04_series_codec_v1 import decode_series_dto_v1
from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
from ..native_runtime.d04_series_math_v1 import D04SeriesChunkMathV1, verify_d04_series_chunk_math_v1
from ..authority_service.d04_series_contract_v1 import D04SeriesMeasurementV1, from_wire
from ..authority_service.contract import AuthorityUnavailable


def _prepare_next(graph, bootstrap, bundle, root, predecessor):
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__c04_authority_port_v3
    binding = prepare_d04_series_chunk_v1(graph, bootstrap, bundle, root, predecessor=predecessor)
    claim, terminal = port.series(binding, "inspect")
    if claim is not None and terminal is None:
        with store._lock:
            measured = read_d04_original_v3(store._db, binding.numeric.namespace, "series_chunk_measurement", binding.numeric.operation_id)
            math = read_d04_original_v3(store._db, binding.numeric.namespace, "series_chunk_math", binding.numeric.operation_id)
        if measured is None:
            return {"status": "claimed_execution_unknown", "operation_id": binding.numeric.operation_id}
        returned = _SeriesReturnV1(_SeriesTicketV1(root, binding, claim, predecessor,
            graph._GraphCoordinator__d04_installed_joint_assembly),
            None if math is None else decode_series_dto_v1(D04SeriesChunkMathV1, math[0]),
            from_wire(measured[0]["measurement"], D04SeriesMeasurementV1))
        terminal = persist_d04_series_measurement_v1(graph, returned)
    if terminal is not None:
        with store._lock:
            paid = read_d04_original_v3(store._db, binding.numeric.namespace, "series_chunk_cost", binding.numeric.operation_id)
        if paid is not None and binding.end_step_index == root.frozen.plan.total_step_count:
            return {**paid[0], "status": "actual_cpu_accounted", "adoption_status": "not_adopted"}
        return binding, terminal
    queue = getattr(graph, "_GraphCoordinator__d04_series_queue_v1", None)
    if queue is None:
        queue = InstalledD04SeriesQueueV1(graph, bootstrap)
        graph._GraphCoordinator__d04_series_queue_v1 = queue
    return queue, queue.issue(graph, root, binding, predecessor)


def _read_completed_chunk(graph, root, binding, predecessor):
    from ..runtime.d04_series_restore_v1 import read_installed_d04_series_packet_v1
    terminal, payload = read_installed_d04_series_packet_v1(graph, binding)
    chunk = decode_series_dto_v1(D04SeriesChunkMathV1, payload)
    verify_d04_series_chunk_math_v1(root.frozen, chunk, root_digest=root.digest, predecessor=predecessor)
    if terminal.measurement.chunk_math_digest != chunk.digest:
        raise ValueError("series completed terminal/native prefix differs")
    return chunk


async def run_installed_d04_series_v1(runtime, installation, *, c02_operation_id, source_ref):
    from .v2_installation import V2InstallationAssembly
    if type(installation) is not V2InstallationAssembly or installation is not getattr(runtime._v2_natural_readiness_receipt, "installation", None):
        return {"status": "not_ready", "missing_inputs": ["installed_numeric_authority"]}
    bundle, worker, bootstrap = installation.admin_bundle, runtime._worker, runtime._v2_bootstrap
    if bundle.d04_joint_numeric is None or bundle.d04_semantic_drive is None:
        return {"status": "not_configured", "missing_inputs": ["d04_semantic_drive", "d04_joint_numeric"]}
    arguments = {"c02_operation_id": c02_operation_id, "source_ref": source_ref}
    drive = await worker.call(lambda graph: graph.commit_post_c02_semantic_drive_v3(bootstrap, bundle, **arguments))
    if drive.get("status") != "drive_adopted":
        return drive
    root = await worker.call(lambda graph: freeze_post_c02_d04_series_v1(graph, bootstrap, bundle, **arguments))
    def prior_adoption(graph):
        saved = read_d04_original_v3(graph._GraphCoordinator__store._db, root.prepared.binding.namespace, "series_adoption", root.root_ref)
        return None if saved is None else adopt_d04_series_v1(graph, bootstrap, bundle, root)
    adopted = await worker.call(prior_adoption)
    predecessor = None
    while adopted is None:
        issued = await worker.call(lambda graph: _prepare_next(graph, bootstrap, bundle, root, predecessor))
        if type(issued) is dict:
            return issued
        hot_return = None
        if type(issued[0]) is InstalledD04SeriesQueueV1:
            queue, ticket = issued
            measured = await asyncio.shield(asyncio.wrap_future(queue.submit(ticket)))
            terminal = await worker.call(lambda graph: queue.accept(graph, measured))
            hot_return = measured
            binding = ticket.binding
        else:
            binding, terminal = issued
        successful = terminal.measurement.status == "chunk_completed" and terminal.measurement.actual_cpu_ms <= binding.numeric.cpu_ceiling_ms
        final = binding.end_step_index == root.frozen.plan.total_step_count
        if successful and final:
            try:
                adopted = await worker.call(lambda graph: adopt_d04_series_v1(graph, bootstrap, bundle, root))
            except (ValueError, TypeError, AuthorityUnavailable) as failure:
                failure_time = time.time()
                logging.getLogger(__name__).exception("D04 final adoption failed; measured cost retained")
                await worker.call(lambda graph: abandon_d04_series_adoption_v1(graph, root))
                paid = await worker.call(lambda graph: settle_d04_series_chunk_v1(graph, bootstrap, bundle, root, binding, terminal))
                return {**paid, "status": "actual_cpu_accounted", "adoption_status": "not_adopted",
                    "failure_stage": "series_final_adoption", "failure_type": type(failure).__name__,
                    "failure_reason": str(failure), "failure_observed_at_utc": failure_time}
        else:
            paid = await worker.call(lambda graph: settle_d04_series_chunk_v1(graph, bootstrap, bundle, root, binding, terminal))
            if not successful or paid["budget_status"] != "settled":
                return {**paid, "status": "actual_cpu_accounted", "adoption_status": "not_adopted"}
            try:
                if hot_return is not None:
                    handoff = await worker.call(lambda graph: queue.handoff(graph, hot_return, terminal, paid))
                    predecessor = handoff.math
                else:
                    predecessor = await worker.call(lambda graph: _read_completed_chunk(graph, root, binding, predecessor))
            except (ValueError, TypeError, AuthorityUnavailable) as failure:
                failure_time = time.time()
                logging.getLogger(__name__).exception("D04 completed chunk original read failed; measured cost retained")
                return {**paid, "status": "actual_cpu_accounted", "adoption_status": "not_adopted",
                    "failure_stage": "completed_chunk_original_read", "failure_type": type(failure).__name__,
                    "failure_reason": str(failure), "failure_observed_at_utc": failure_time}
    try:
        encoding = await worker.call(lambda graph: graph.commit_post_joint_c04_encoding_v3(bootstrap, bundle,
            **arguments, joint_operation_id=root.prepared.binding.operation_id))
    except (ValueError, TypeError, RuntimeError):
        return {**adopted, "encoding_baseline_status": "held"}
    return {**adopted, "encoding_baseline": encoding}


async def close_installed_d04_series_v1(runtime):
    if runtime._worker is None:
        return
    queue = await runtime._worker.call(lambda graph: getattr(graph, "_GraphCoordinator__d04_series_queue_v1", None))
    if queue is not None:
        returned = await asyncio.to_thread(queue.close)
        if returned is not None:
            terminal = await runtime._worker.call(lambda graph: queue.accept(graph, returned))
            await runtime._worker.call(lambda graph: settle_d04_series_chunk_v1(graph, runtime._v2_bootstrap,
                returned.ticket.installation.admin_bundle, returned.ticket.root, returned.ticket.binding, terminal))
