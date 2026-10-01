"""Installed asynchronous D04 math: short W01 work around one CPU thread."""
import asyncio

from .v2_installation import V2InstallationAssembly
from ..runtime.d04_installed_numeric_v3 import D04ExecutedNumericV3
from ..runtime.d04_numeric_math_ticket_v3 import (
    InstalledD04MathQueueV3, _MathTicketV3, issue_current_numeric_math_ticket_v3,
)


async def run_installed_post_c02_numeric_v3(runtime, installation, *, c02_operation_id, source_ref):
    from .installed_d04_series_driver_v1 import run_installed_d04_series_v1
    return await run_installed_d04_series_v1(runtime, installation,
        c02_operation_id=c02_operation_id, source_ref=source_ref)


async def _run_short_numeric_v3(runtime, installation, *, c02_operation_id, source_ref):
    if (type(installation) is not V2InstallationAssembly
            or installation is not getattr(runtime._v2_natural_readiness_receipt, "installation", None)):
        return {"status": "not_ready", "missing_inputs": ["installed_numeric_authority"]}
    bundle, worker, bootstrap = installation.admin_bundle, runtime._worker, runtime._v2_bootstrap
    if bundle.d04_joint_numeric is None or bundle.d04_semantic_drive is None:
        return {"status": "not_configured", "missing_inputs": ["d04_semantic_drive", "d04_joint_numeric"]}
    arguments = {"c02_operation_id": c02_operation_id, "source_ref": source_ref}
    drive = await worker.call(lambda graph: graph.commit_post_c02_semantic_drive_v3(bootstrap, bundle, **arguments))
    if drive.get("status") != "drive_adopted":
        return drive
    def prepare(graph):
        queue = getattr(graph, "_GraphCoordinator__d04_math_queue_v3", None)
        if queue is None:
            queue = InstalledD04MathQueueV3(graph, bootstrap)
            graph._GraphCoordinator__d04_math_queue_v3 = queue
        issued = issue_current_numeric_math_ticket_v3(graph, bootstrap, bundle, queue, **arguments)
        return queue, issued
    queue, issued = await worker.call(prepare)
    if type(issued) is _MathTicketV3:
        # The math executor sees only an immutable recipe and a private actual
        # new-claim ticket. GraphWorker remains available to other requests.
        future = asyncio.wrap_future(queue.submit(issued))
        measured = await asyncio.shield(future)
        executed = await worker.call(lambda graph: queue.accept(graph, measured))
    elif type(issued) is D04ExecutedNumericV3:
        executed = issued
    else:
        return issued
    if executed.terminal is None:
        return {"status": executed.status, "operation_id": executed.prepared.binding.operation_id}
    binding, measurement = executed.prepared.binding, executed.terminal.measurement
    can_adopt = (executed.status == "execution_terminal" and measurement.status == "completed"
        and measurement.actual_cpu_ms <= binding.cpu_ceiling_ms
        and getattr(executed.terminal, "adoption_allowed", True) is True)
    if can_adopt:
        try:
            adopted = await worker.call(lambda graph: graph.adopt_post_c02_joint_numeric_v3(
                bootstrap, bundle, operation_id=binding.operation_id))
        except (ValueError, TypeError, RuntimeError):
            # Actual CPU survives failed current source/job/clock adoption.
            # The accounting port independently authenticates the terminal;
            # it cannot turn this result into a new execution or content read.
            pass
        else:
            try:
                encoding = await worker.call(lambda graph: graph.commit_post_joint_c04_encoding_v3(
                    bootstrap, bundle, c02_operation_id=c02_operation_id, source_ref=source_ref,
                    joint_operation_id=binding.operation_id))
            except (ValueError, TypeError, RuntimeError):
                return {**adopted, "encoding_baseline_status": "held"}
            return {**adopted, "encoding_baseline": encoding}
    from ..runtime.d04_numeric_historical_cost_v3 import reconcile_historical_d04_numeric_cost_v3
    return await worker.call(lambda graph: reconcile_historical_d04_numeric_cost_v3(
        graph, bootstrap, bundle, operation_id=binding.operation_id))


async def close_installed_d04_math_v3(runtime):
    from .installed_d04_series_driver_v1 import close_installed_d04_series_v1
    await close_installed_d04_series_v1(runtime)
    worker = runtime._worker
    if worker is None:
        return
    queue = await worker.call(lambda graph: getattr(graph, "_GraphCoordinator__d04_math_queue_v3", None))
    if queue is not None:
        returned = await asyncio.to_thread(queue.close)
        if returned is not None:
            executed = await worker.call(lambda graph: queue.accept(graph, returned))
            if executed.terminal is not None:
                from ..runtime.d04_numeric_historical_cost_v3 import reconcile_historical_d04_numeric_cost_v3
                await worker.call(lambda graph: reconcile_historical_d04_numeric_cost_v3(
                    graph, runtime._v2_bootstrap, returned.ticket.installation.admin_bundle,
                    operation_id=executed.prepared.binding.operation_id))
