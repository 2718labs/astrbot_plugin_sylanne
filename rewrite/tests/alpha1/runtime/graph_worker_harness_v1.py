"""Drive production GraphStorageWorkV3 in tests with the worker's quantum contract.

Installed coordinator operations now return ``GraphStorageWorkV3`` and expect the
ordinary GraphWorker to (a) accept the work on a real ticket, (b) advance one
quantum per queue turn, (c) finish and map the terminal value. This helper
reproduces exactly that contract in the test thread, because the SQLite fixtures
are created on the test thread and a real worker thread may not touch them.

It is test-only infrastructure (never shipped in the runtime ZIP). It does not
mint a ticket, grant, lease or capacity slot: it only provides the invocation
context and runs the same public ``advance``/``_finish_and_map`` sequence the
worker runs. Handoff-capable kinds are not used by the migrated tests; the
helper refuses a non-step advance result instead of guessing.
"""
from __future__ import annotations


def run_graph_call_v1(store, coordinator, callback):
    """Run ``callback(coordinator)`` under an ordinary worker invocation and drive its Work."""
    from sylanne3.graph_worker import (
        GraphStorageStepV3, GraphStorageWorkV3, _GraphStorageInvocationV3,
        _STORAGE_INVOCATION_V3,
    )
    del store  # the fixture store is already bound to the coordinator
    ticket = 1
    token = _STORAGE_INVOCATION_V3.set(
        _GraphStorageInvocationV3(coordinator, ticket, "ordinary", True))
    try:
        value = callback(coordinator)
        if type(value) is GraphStorageWorkV3:
            value._accept(coordinator, ticket)
            while True:
                step = value.advance(coordinator)
                if type(step) is not GraphStorageStepV3:
                    raise TypeError("graph storage producer must return a GraphStorageStepV3")
                if step.status == "complete":
                    break
            value = value._finish_and_map(coordinator, step.result, None)
        return value
    finally:
        _STORAGE_INVOCATION_V3.reset(token)
