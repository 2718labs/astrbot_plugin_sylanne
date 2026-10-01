"""The installed V2 dispatch check stays separate from sealed legacy Core."""

from sylanne3.authority_service.local_bridge import constraint_keys_from_footprint
from sylanne3.authority_service.v2_execution_bridge import AuthorityV2ExecutionBridge
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.runtime_journal import RecoveryConstraintFootprint
from rewrite.tests.alpha1.runtime.test_authority_v2_fence_service import installed


def test_v2_dispatch_begin_and_prepare_use_one_installed_read_before_locks(tmp_path):
    _, core, fences, deletion, guard, execution, _ = installed(tmp_path)
    core._dispatch_verifier = lambda *_: False
    footprint = RecoveryConstraintFootprint(
        namespace="ns-a", activity_id="activity-a", effect_id="effect-a",
        conflict_keys=("resource-a",))
    keys = constraint_keys_from_footprint(footprint)
    seen = []

    def current_graph(namespace, effect_id, current_keys):
        assert not core._db.in_transaction
        assert execution._guard_owner is None
        assert not guard._db.in_transaction
        seen.append((namespace, effect_id, current_keys))
        return (namespace, effect_id, current_keys) == ("ns-a", "effect-a", keys)

    try:
        service = AuthorityV2FenceService(
            core=core, fences=fences, deletion=guard, execution=execution,
            namespace="ns-a", v2_dispatch_verifier=current_graph)
        bridge = AuthorityV2ExecutionBridge(
            core=core, fences=fences, journal=execution, deletion=guard,
            namespace="ns-a", v2_dispatch_verifier=current_graph)
        anchor = service.current_anchor(credential="ok", subject="subject-a")
        permit = service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="dispatch", operation_id="operation-a",
            expected_anchor=anchor, effect_id="effect-a",
            command_digest="sha256:" + "a" * 64, footprint=footprint)
        assert permit.operation == "dispatch"
        prepared, _ = bridge.execution_prepare(
            credential="ok", subject="subject-a", permit=permit,
            mutation_id="mutation-a", footprint=footprint)
        assert prepared.pending.phase == "prepared"
        assert seen == [("ns-a", "effect-a", keys)] * 2
        assert core._dispatch_verifier("ns-a", "effect-a", keys) is False
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()
