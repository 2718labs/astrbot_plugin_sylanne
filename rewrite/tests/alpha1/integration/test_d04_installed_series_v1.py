"""Permanent installed multichunk D04 acceptance, including current D06 input.

Run against an immutable installed package through SYLANNE_D04_INSTALLED_ROOT.
Inputs, quotes, claims, terminals, CPU costs and Graph receipts all originate
from the paired product fixture. Only loss of a returned ACK is injected.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import replace
from fractions import Fraction
import json
from pathlib import Path
import sqlite3
import sys
import time
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_d04_owner_semantic_initialization_v3 import (  # noqa: E402
    installed_d04_root, real_owner_case, current_owner,
)
from test_d04_installed_semantic_drive_v3 import (  # noqa: E402
    appraisal_workflows, compose_installed_appraisal, explicit_subjective_reply,
)
from d04_http_initialization_acceptance_v3 import initialize_via_actual_workbench_v3  # noqa: E402
from d04_numeric_authority_acceptance_support_v3 import install_actual_numeric_authority_case_v3  # noqa: E402

from sylanne3.host.installed_d04_appraisal_driver_v3 import run_installed_post_c02_appraisal_v3
from sylanne3.host.installed_d04_series_driver_v1 import (
    _prepare_next, _read_completed_chunk, run_installed_d04_series_v1,
)
from sylanne3.native_runtime import d04_series_math_v1, d04_fixed_trajectory_v2, loader
from sylanne3.domains.d04.projection_issuer_v2 import load_installed_d04_projection_assets_v2
from sylanne3.runtime.c04_authority_port_v3 import InstalledC04AuthorityPortV3
from sylanne3.runtime.c04_current_projection_service_v3 import issue_current_c04_target_v3
from sylanne3.runtime.c04_encoding_baseline_store_v3 import read_c04_encoding_baseline_v3
from sylanne3.runtime.c04_v3_contracts import AssociationTargetAuthoredV3
from sylanne3.runtime.d04_appraisal_driver_v3 import (
    read_current_d04_appraisal_original_v3, read_d04_original_v3,
)
from sylanne3.runtime.d04_numeric_policy_v3 import AdminD04JointNumericPolicyV3
from sylanne3.runtime.d04_series_adoption_v1 import (
    adopt_d04_series_v1, restore_d04_series_prefix_v1,
)
from sylanne3.runtime.d04_series_execution_v1 import (
    InstalledD04SeriesQueueV1, prepare_d04_series_chunk_v1, settle_d04_series_chunk_v1,
)
from sylanne3.runtime.d04_series_original_v1 import require_series_adopted_original_v1
from sylanne3.runtime.d04_series_store_v1 import (
    freeze_post_c02_d04_series_v1, read_d04_series_root_v1,
)
from sylanne3.runtime.jobs import get_job


class _ReturnedAckLost(Exception):
    """The actual Authority operation finished; its caller received no ACK."""


@contextmanager
def _without_native_execution():
    def forbidden(*_args, **_kwargs):
        raise AssertionError("cold restore or committed retry attempted FFI")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(loader, "load_production_native", forbidden)
        patch.setattr(d04_series_math_v1, "run_d04_series_chunk_math_v1", forbidden)
        patch.setattr(d04_series_math_v1, "_native_initial_radius", forbidden)
        patch.setattr(d04_series_math_v1, "run_d04_fixed_trajectory_v2", forbidden)
        patch.setattr(d04_fixed_trajectory_v2, "run_fixed_block_math", forbidden)
        yield


def _business_heads(store, refs):
    with store._lock:
        return tuple((ref, *store._db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?", (ref,)
        ).fetchone()) for ref in refs)


def _cold_root(store, namespace, root):
    with store._lock:
        path = Path(store._db.execute("PRAGMA database_list").fetchone()[2])
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        db.execute("BEGIN")
        restored = read_d04_series_root_v1(db, namespace, root.root_ref)
        assert restored == root and restored is not root
        return restored
    finally:
        db.rollback()
        db.close()


def _assert_exact_branches(root, chunks):
    families = tuple(family for family, _ in root.frozen.family_drives)
    assert families
    assert len(chunks) > 1
    assert chunks[0].start_step_index == 0
    assert chunks[-1].end_step_index == root.frozen.plan.total_step_count
    total = Fraction()
    previous = None
    for chunk in chunks:
        assert tuple(family for family, _ in chunk.family_loo) == families
        assert len(chunk.full.steps) <= root.frozen.plan.chunk_step_limit <= 512
        assert len(chunk.full.output) == 72
        assert chunk.predecessor_digest == (None if previous is None else previous.digest)
        branches = (chunk.full, *(branch for _, branch in chunk.family_loo))
        plan = root.frozen.plan.chunk(chunk.start_step_index)
        total += sum((Fraction.from_float(step) for step in plan), Fraction())
        for position, branch in enumerate(branches):
            assert tuple(step.input.h for step in branch.steps) == plan
            assert branch.production_binding.abi_version == 2
            assert chunk.endpoints[position].output == branch.output
            assert chunk.endpoints[position].trajectory_error == branch.final_error
            if previous is not None:
                assert branch.steps[0].input.previous == previous.endpoints[position].output
                assert branch.steps[0].input.previous_error == previous.endpoints[position].trajectory_error
        previous = chunk
    assert total == (Fraction.from_float(root.frozen.plan.role_end)
                     - Fraction.from_float(root.frozen.plan.role_start))


@pytest.mark.asyncio
async def test_installed_multichunk_series_cold_adoption_and_successor_d06_read(
        tmp_path, installed_d04_root):
    initialized, supports, queues = {}, [], []

    async def after_role(case):
        try:
            await initialize_via_actual_workbench_v3(case, role_clock_rate="1")
        finally:
            initialized.update(case)
        # Genuine elapsed time yields more than one 512-step h=1/64 chunk.
        # Neither the accepted role clock nor any checkpoint is rewritten.
        await asyncio.sleep(9.0)

    async def after_c02(case):
        graph, store, ns = case["graph"], case["store"], case["namespace"]
        bootstrap, worker = case["bootstrap"], initialized["http_worker"]
        bundle, assembly, runtime = compose_installed_appraisal(case, initialized)
        grant = case["policy"].root_grant
        numeric_policy = AdminD04JointNumericPolicyV3(ns, case["policy"].installation_id,
            grant.grant_id, grant.version, grant.lease_id, 100000, 256, 1e-8, 600)
        bundle = replace(bundle, d04_joint_numeric=numeric_policy)
        assembly = replace(assembly, admin_bundle=bundle)
        graph._GraphCoordinator__d04_installed_joint_assembly = assembly
        runtime._worker = worker
        runtime._v2_natural_readiness_receipt.installation = assembly
        support = await asyncio.to_thread(install_actual_numeric_authority_case_v3,
            {**initialized, **case, "installed_bundle": bundle, "assembly": assembly},
            owner_loop=asyncio.get_running_loop())
        supports.append(support)

        async def appraisal(args):
            prepared = await worker.call(lambda current: current.prepare_post_c02_appraisal_v3(
                bootstrap, bundle, **args))
            with store._lock:
                original = read_current_d04_appraisal_original_v3(store._db, ns, prepared["job_id"])
                frozen = json.loads(original.frozen_json)
            case["model_reply_mode"]["content"] = explicit_subjective_reply(frozen, 0.5)
            result = await run_installed_post_c02_appraisal_v3(runtime, assembly,
                context=case["model_context"], trusted_umo="platform-1:FriendMessage:123456", **args)
            assert result["status"] == "adopted", result

        args = {"c02_operation_id": case["c02"].operation_id, "source_ref": case["source_ref"]}
        await appraisal(args)
        drive = await worker.call(lambda current: current.commit_post_c02_semantic_drive_v3(
            bootstrap, bundle, **args))
        assert drive["status"] == "drive_adopted"
        root = await worker.call(lambda current: freeze_post_c02_d04_series_v1(
            current, bootstrap, bundle, **args))
        assert root.frozen.plan.total_step_count > 512
        assert root.frozen.plan.role_start == 0.0
        refs = tuple(root.frozen.member_refs)
        with store._lock:
            from sylanne3.runtime.d04_numeric_artifact_v3 import decode_d04_numeric_prepared_input_v3
            decoded = decode_d04_numeric_prepared_input_v3(root.prepared)
        state_refs = tuple(member.state_ref for member in decoded.preparation.predecessors.members)
        before_heads = _business_heads(store, (*refs, *state_refs))
        assert all(row[1] == 1 and row[3] == 1 for row in before_heads)

        def issue_first(current):
            queue = InstalledD04SeriesQueueV1(current, bootstrap)
            current._GraphCoordinator__d04_series_queue_v1 = queue
            binding = prepare_d04_series_chunk_v1(current, bootstrap, bundle, root)
            return queue, queue.issue(current, root, binding, None)

        queue, ticket = await worker.call(issue_first)
        queues.append(queue)
        first_claim = ticket.claim
        with _without_native_execution():
            unknown = await worker.call(lambda current: _prepare_next(current, bootstrap, bundle, root, None))
            assert unknown == {"status": "claimed_execution_unknown", "operation_id": ticket.binding.numeric.operation_id}
            assert await worker.call(lambda current: support.port.series(ticket.binding, "inspect")) == (first_claim, None)
        assert _business_heads(store, (*refs, *state_refs)) == before_heads
        with store._lock:
            assert read_d04_original_v3(store._db, ns, "series_chunk_cost", ticket.binding.numeric.operation_id) is None

        chunks, bindings, terminals = [], [], []
        predecessor = None
        while True:
            returned = await asyncio.shield(asyncio.wrap_future(queue.submit(ticket)))
            terminal = await worker.call(lambda current: queue.accept(current, returned))
            binding = ticket.binding
            assert terminal.measurement.status == "chunk_completed", terminal.measurement
            assert terminal.measurement.actual_cpu_ns > 0
            assert terminal.measurement.actual_cpu_ms <= binding.numeric.cpu_ceiling_ms
            chunk = await worker.call(lambda current: _read_completed_chunk(current, root, binding, predecessor))
            chunks.append(chunk)
            bindings.append(binding)
            terminals.append(terminal)
            assert _business_heads(store, (*refs, *state_refs)) == before_heads
            if binding.end_step_index == root.frozen.plan.total_step_count:
                break
            paid = await worker.call(lambda current: settle_d04_series_chunk_v1(
                current, bootstrap, bundle, root, binding, terminal))
            assert paid["budget_status"] == "settled" and paid["authority_ack"] is True
            assert paid["actual_cpu_ns"] == terminal.measurement.actual_cpu_ns
            predecessor = chunk
            queue, ticket = await worker.call(lambda current: _prepare_next(
                current, bootstrap, bundle, root, predecessor))
            assert ticket.claim.claim_id != first_claim.claim_id

        assert await asyncio.to_thread(queue.close) is None
        queues.remove(queue)
        graph._GraphCoordinator__d04_series_queue_v1 = None
        chunks, bindings, terminals = tuple(chunks), tuple(bindings), tuple(terminals)
        _assert_exact_branches(root, chunks)
        # Replace the transport-facing port and reconstruct the root from a
        # fresh read-only SQLite snapshot after the native executor is closed.
        port = InstalledC04AuthorityPortV3(client=case["authority_client"], bundle=bundle,
            grant=case["client_grant"], owner_loop=asyncio.get_running_loop())
        graph._GraphCoordinator__c04_authority_port_v3 = port
        root = await asyncio.to_thread(_cold_root, store, ns, root)
        with _without_native_execution():
            stamp = await worker.call(lambda current: current._v2_graph_stamp(ns))
            restored = await worker.call(lambda current: restore_d04_series_prefix_v1(current, root))
            assert restored == (chunks, bindings, terminals)
            assert await worker.call(lambda current: current._v2_graph_stamp(ns)) == stamp
            assert _business_heads(store, (*refs, *state_refs)) == before_heads

            # The real final Graph transaction and Authority finish both run.
            # Losing only the returned finish ACK leaves an actual recoverable
            # committed adoption, never an invented terminal or receipt.
            real_series = port.series
            def lose_returned_final_ack(binding, method, **values):
                result = real_series(binding, method, **values)
                if method == "finish" and values["gate"].phase == "restore":
                    raise _ReturnedAckLost("final Authority finish returned no ACK")
                return result

            with pytest.MonkeyPatch.context() as patch:
                patch.setattr(port, "series", lose_returned_final_ack)
                with pytest.raises(_ReturnedAckLost, match="no ACK"):
                    await worker.call(lambda current: adopt_d04_series_v1(current, bootstrap, bundle, root))
            committed_stamp = await worker.call(lambda current: current._v2_graph_stamp(ns))
            assert committed_stamp[0].graph_revision == stamp[0].graph_revision + 1
            with store._lock:
                committed = read_d04_original_v3(store._db, ns, "series_adoption", root.root_ref)[0]
                assert read_d04_original_v3(store._db, ns, "series_chunk_cost_commit", bindings[-1].numeric.operation_id) is not None
                assert read_d04_original_v3(store._db, ns, "series_chunk_cost", bindings[-1].numeric.operation_id) is None
            adopted = await worker.call(lambda current: adopt_d04_series_v1(current, bootstrap, bundle, root))
            assert adopted == committed
            assert await worker.call(lambda current: current._v2_graph_stamp(ns)) == committed_stamp
            assert adopted["actual_cpu_ns"] == sum(item.measurement.actual_cpu_ns for item in terminals)
            assert adopted["chunk_count"] == len(chunks)
            with store._lock:
                job = get_job(store._db, root.prepared.binding.job_id)
                assert job.phase == "completed"
                assert job.usage["cpu_ms"] == adopted["actual_cpu_ms"]
                for binding, terminal in zip(bindings, terminals):
                    paid = read_d04_original_v3(store._db, ns, "series_chunk_cost", binding.numeric.operation_id)[0]
                    assert paid["authority_ack"] is True and paid["actual_cpu_ns"] == terminal.measurement.actual_cpu_ns
                verified = require_series_adopted_original_v1(store._db, ns, adopted["operation_id"])
                output = verified[3]
            assert all(row[1] == 2 and row[3] == 1 for row in _business_heads(store, (*refs, *state_refs)))
            first_encoding = await worker.call(lambda current: current.commit_post_joint_c04_encoding_v3(
                bootstrap, bundle, **args, joint_operation_id=adopted["operation_id"]))
            assert first_encoding["status"] == "encoding_baseline_committed", first_encoding

        # A second real observed C02 and paid appraisal exercise the strict
        # series predecessor reader; wait for the actual first focus to expire.
        with store._lock:
            focus = json.loads(store._db.execute("SELECT value FROM graph_atoms "
                "WHERE type_name='d07.focus.v1' AND valid=1").fetchone()[0])
            attention = json.loads(store._db.execute("SELECT value FROM graph_atoms WHERE token=?",
                (focus["primary_ticket_ref"],)).fetchone()[0])
        await asyncio.sleep(max(0.0, attention["valid_until"] - time.time() + 0.05))
        ingress, second_c02 = await case["commit_second_c02"](
            "observed-d04-series-successor", "hello again", commit_attention=True)
        second_source = next(version.key.token for version in ingress.write_versions
                             if version.key.type_name == "memory.source")
        second_args = {"c02_operation_id": second_c02.operation_id, "source_ref": second_source}
        await appraisal(second_args)
        successor = await run_installed_d04_series_v1(runtime, assembly, **second_args)
        assert successor["status"] == "joint_advance_committed", successor
        assert successor["encoding_baseline"]["status"] == "encoding_baseline_committed", successor
        assert successor["operation_id"] != adopted["operation_id"]
        successor_queue = graph._GraphCoordinator__d04_series_queue_v1
        assert await asyncio.to_thread(successor_queue.close) is None
        graph._GraphCoordinator__d04_series_queue_v1 = None

        def read_current_d06_input(current):
            with current_owner(case) as (authority, lease):
                reading = current.read_current_d04_joint_output_original_v1(
                    authority, lease, operation_id=successor["operation_id"])
                assert reading.original.operation_id == successor["operation_id"]
                assert all(member.next_checkpoint.cursor > output.members[index].next_checkpoint.cursor
                    for index, member in enumerate(reading.original.members))
                owner = current._GraphCoordinator__owner_leases.get(lease)
                proof = current._GraphCoordinator__owner_session_proofs.get(lease)
                policy, asset = load_installed_d04_projection_assets_v2(
                    assembly.package_root, assembly.installation_policy.manifest_digest,
                    available_cpu_features=assembly.available_cpu_features)
                mood = next(member for member in reading.original.members if member.kind == "mood")
                def reader():
                    db = store._db
                    db.execute("BEGIN")
                    try:
                        rights = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
                            "WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
                        baseline = read_c04_encoding_baseline_v3(db, namespace=ns,
                            encoding_operation_id=first_encoding["operation_id"], source_ref=case["source_ref"])
                        assert baseline.joint_operation_id == adopted["operation_id"]
                        target = issue_current_c04_target_v3(db, namespace=ns,
                            operation_id="d04-series-current-d06:" + str(uuid4()),
                            encoding_operation_id=first_encoding["operation_id"], source_ref=case["source_ref"],
                            mood_joint_operation_id=successor["operation_id"], mood_ref=mood.predecessor_state_ref,
                            audience=owner.audience, purpose=owner.purpose, owner_epoch=owner.revocation_epoch,
                            access_epoch=rights[0], delete_epoch=rights[1], asset=asset, policy=policy)
                        assert type(target) is AssociationTargetAuthoredV3
                        assert target.baseline.encoding_operation_id == first_encoding["operation_id"]
                        assert target.condition.current_joint_output_original_digest == reading.original.original_digest
                        assert target.condition.current_mood.revision == 3
                        assert target.condition.current_checkpoint.revision == 3
                        return target
                    finally:
                        db.rollback()
                return current._read_v2(authority, reader, owner_binding=owner, owner_session_proof=proof)

        with _without_native_execution():
            target = await worker.call(read_current_d06_input)
            assert target.source_ref == case["source_ref"]

    try:
        await real_owner_case(tmp_path, "owned", installed_package_root=installed_d04_root,
            after_role_initialization=after_role, continue_to_ingress=True, after_c02=after_c02,
            enable_d09_workbench=True, enable_d04_root_cpu=True, enable_d04_semantic_drive=True,
            enable_d04_joint_numeric=True, d04_numeric_budget_cpu_ms=600000, register_c04_domains=True,
            extra_owner_purposes=("context", "consolidation"), natural_workflow_builder=appraisal_workflows)
    finally:
        for queue in queues:
            await asyncio.to_thread(queue.close)
        if initialized.get("http_worker") is not None:
            await initialized["http_worker"].close()
        for support in supports:
            support.close()
