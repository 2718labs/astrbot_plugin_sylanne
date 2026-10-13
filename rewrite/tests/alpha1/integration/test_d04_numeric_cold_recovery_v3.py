"""Permanent cold-recovery assertions for actual installed full/LOO execution.

The product fixture supplies a genuine claim, measured artifact and independent
terminal. No fake terminal or locally seeded authority can satisfy this helper.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_d04_owner_semantic_initialization_v3 import installed_d04_root  # noqa: E402,F401
from test_d04_installed_semantic_drive_v3 import test_installed_owner_c02_appraisal_semantic_drive as actual_drive_case  # noqa: E402
from d04_numeric_authority_acceptance_support_v3 import install_actual_numeric_authority_case_v3  # noqa: E402

from sylanne3.authority_service.d04_numeric_contract_v3 import to_wire
from sylanne3.authority_service.d04_numeric_service_v3 import AuthorityD04NumericServiceV3
from sylanne3.domains.d04 import trusted_joint_replay
from sylanne3.domains.d04.trusted_joint_replay import (
    D04TrustedJointReplayHold, is_package_bound_joint_numeric_replay_v1,
    restore_installed_d04_numeric_product_v3,
)
from sylanne3.native_runtime import fixed_block_transcript, initial_box_trajectory, loader, d04_joint_product_math, d04_fixed_trajectory_v2
from sylanne3.native_runtime.d04_joint_replay_validation_v3 import revalidate_d04_numeric_artifact_v3
from sylanne3.runtime.c04_authority_port_v3 import InstalledC04AuthorityPortV3
from sylanne3.runtime.d04_numeric_artifact_v3 import (
    D04NumericArtifactHold, decode_d04_numeric_prepared_input_v3,
    verify_d04_numeric_artifact_commitments_v3,
)
from sylanne3.runtime.d04_semantic_mapping_v3 import evidence_payload_v3
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize


_COLD_SCRIPT = r'''
import ctypes, json, sys
from pathlib import Path
from sylanne3.authority_service.d04_numeric_contract_v3 import D04NumericBindingV3,D04NumericTerminalV3,from_wire
from sylanne3.runtime.d04_numeric_cost_v3 import D04NumericPreparedV3
from sylanne3.native_runtime.d04_joint_replay_validation_v3 import D04PinnedReplayAssetsV3,revalidate_d04_numeric_artifact_v3
from sylanne3.domains.d04.trusted_joint_replay import is_package_bound_joint_numeric_replay_v1
from sylanne3.native_runtime import fixed_block_transcript,initial_box_trajectory,loader,d04_joint_product_math,d04_fixed_trajectory_v2
packet=json.loads(Path(sys.argv[1]).read_text())
raw=dict(packet['prepared']);raw['binding']=from_wire(raw['binding'],D04NumericBindingV3)
prepared=D04NumericPreparedV3(**raw)
terminal=from_wire(packet['terminal'],D04NumericTerminalV3)
def forbidden(*args,**kwargs): raise AssertionError('cold restoration attempted FFI')
fixed_block_transcript.run_fixed_block_math=forbidden
initial_box_trajectory._native_initial_radius=forbidden
d04_joint_product_math.run_fixed_block_math=forbidden
d04_fixed_trajectory_v2.run_fixed_block_math=forbidden
loader.load_production_native=forbidden
ctypes.CDLL=forbidden
assets=D04PinnedReplayAssetsV3(Path(packet['package_root']),prepared.binding.namespace,
    prepared.binding.installation_id,prepared.binding.native_manifest_sha256)
product=revalidate_d04_numeric_artifact_v3(prepared,terminal,packet['artifact'],assets)
assert not is_package_bound_joint_numeric_replay_v1(product.replay), 'pure math must never mint Authority trust'
assert product.output.original_digest==terminal.measurement.output_original_digest
print(json.dumps({'output':product.output.original_digest,'full':product.replay.math_result.full_transcript_sha256,
    'loo':product.replay.math_result.family_transcripts,'trusted':False},sort_keys=True))
'''


def assert_actual_numeric_cold_recovery_v3(*, authority, execution, installation, tmp_path,
                                         product=None, claim=None, terminal=None):
    """Call after the terminal/append gate is closed and before adoption begins.

    Return the newly authenticated restored product for the actual final CAS.
    """
    prepared = execution.prepared
    terminal = execution.terminal if terminal is None else terminal
    claim = terminal.claim if claim is None else claim
    assert type(authority) in {AuthorityD04NumericServiceV3, InstalledC04AuthorityPortV3}
    read = (authority.read_d04_numeric_restore_original_v3(prepared.binding)
            if type(authority) is AuthorityD04NumericServiceV3 else authority.numeric_restore_original(prepared.binding))
    assert read.prepared == prepared and read.terminal == terminal and terminal.claim == claim
    assert terminal.measurement.status == "completed"
    assert terminal.measurement.actual_cpu_ns >= 0
    decoded = decode_d04_numeric_prepared_input_v3(prepared)
    if hasattr(execution, "preparation"):
        assert decoded.preparation == execution.preparation
        assert decoded.evidence_inputs == execution.evidence_inputs
        assert (decoded.holder, decoded.worker_fence) == (execution.holder, execution.worker_fence)
    artifact = read.artifact_payload
    assert verify_d04_numeric_artifact_commitments_v3(prepared, claim, terminal.measurement, artifact)
    if product is None:
        product = revalidate_d04_numeric_artifact_v3(prepared, terminal, artifact, installation)
        assert not is_package_bound_joint_numeric_replay_v1(product.replay)
    else:
        assert is_package_bound_joint_numeric_replay_v1(product.replay)
    assert len(product.replay.math_result.full_transcript.output) == 72
    assert product.replay.component.role_end - product.replay.component.role_start > 1.0
    assert len(product.replay.math_result.full_transcript.steps) > 64
    from fractions import Fraction
    for chain in (product.replay.math_result.full_transcript,
                  *(item[1] for item in product.replay.math_result.family_transcript_originals)):
        assert sum((Fraction.from_float(step.input.h) for step in chain.steps), Fraction()) == (
            Fraction.from_float(product.replay.component.role_end) - Fraction.from_float(product.replay.component.role_start))
    assert product.replay.math_result.family_transcript_originals
    assert len(product.replay.math_result.family_transcript_originals) == len(prepared.binding.family_roots)

    # A brand-new interpreter owns no old Python objects, weak dictionary or
    # native handle. It validates actual terminal-bound math but gains no trust.
    packet = Path(tmp_path) / "actual-d04-cold-artifact.json"
    packet.write_text(canonical_serialize({"prepared": asdict(prepared), "terminal": to_wire(terminal),
        "artifact": artifact, "package_root": str(installation.package_root)}), encoding="utf-8")
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(installation.package_root / "rewrite") + os.pathsep + environment.get("PYTHONPATH", "")
    cold = subprocess.run([sys.executable, "-c", _COLD_SCRIPT, str(packet)],
        check=True, capture_output=True, text=True, env=environment, timeout=120)
    result = json.loads(cold.stdout.strip().splitlines()[-1])
    assert result == {"output": terminal.measurement.output_original_digest,
        "full": terminal.measurement.full_transcript_digest,
        "loo": [list(pair) for pair in terminal.measurement.family_loo_transcripts], "trusted": False}

    def forbidden(*_args, **_kwargs):
        raise AssertionError("cold restoration attempted native execution")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(fixed_block_transcript, "run_fixed_block_math", forbidden)
        patch.setattr(initial_box_trajectory, "_native_initial_radius", forbidden)
        patch.setattr(d04_joint_product_math, "run_fixed_block_math", forbidden)
        patch.setattr(d04_fixed_trajectory_v2, "run_fixed_block_math", forbidden)
        patch.setattr(loader, "load_production_native", forbidden)
        patch.setattr(trusted_joint_replay, "_replay_package_bound_joint_numeric", forbidden)
        trusted_joint_replay._ISSUED_REPLAYS.clear()
        trusted_joint_replay._ISSUED_DIGESTS.clear()
        assert not is_package_bound_joint_numeric_replay_v1(product.replay)
        with pytest.raises(D04TrustedJointReplayHold, match="concrete paired"):
            restore_installed_d04_numeric_product_v3(terminal, prepared.binding, installation)
        restored = restore_installed_d04_numeric_product_v3(authority, prepared.binding, installation)
        assert restored is not product and restored.replay is not product.replay
        assert is_package_bound_joint_numeric_replay_v1(restored.replay)
        assert evidence_payload_v3(restored.output) == evidence_payload_v3(product.output)
        assert evidence_payload_v3(restored.replay.math_result) == evidence_payload_v3(product.replay.math_result)
        assert restored.replay.candidate == product.replay.candidate
        assert restored.replay.numeric_error == product.replay.numeric_error

        # Rehashing an outer DTO never changes the independent native/output
        # commitments. These are tampered copies, not seeded successful results.
        corruptions = []
        changed = deepcopy(artifact)
        changed["math_result"]["full_transcript"]["steps"][0]["output"][0] = {"binary64_be": "3fe0000000000000"}
        if changed == artifact:
            changed["math_result"]["full_transcript"]["steps"][0]["output"][0] = {"binary64_be": "3fd0000000000000"}
        corruptions.append(changed)
        changed = deepcopy(artifact)
        changed["math_result"]["family_transcript_originals"] = []
        corruptions.append(changed)
        changed = deepcopy(artifact)
        changed["math_result"]["full_transcript"]["steps"][0]["bounds"]["q_upper"] = {"binary64_be": "3ff0000000000000"}
        corruptions.append(changed)
        changed = deepcopy(artifact)
        changed["math_result"]["full_transcript"]["steps"].pop(len(changed["math_result"]["full_transcript"]["steps"]) // 2)
        corruptions.append(changed)
        changed = deepcopy(artifact)
        changed["output"]["members"][0]["axes"][0]["representative"] = {"binary64_be": "0000000000000000"}
        corruptions.append(changed)
        changed = deepcopy(artifact)
        changed["math_result"]["$type"] = "untrusted.constructor"
        corruptions.append(changed)
        for changed in corruptions:
            changed["artifact_digest"] = canonical_digest({key: value for key, value in changed.items()
                                                           if key != "artifact_digest"})
            with pytest.raises((D04NumericArtifactHold, ValueError, TypeError)):
                revalidate_d04_numeric_artifact_v3(prepared, terminal, changed, installation)
    current = (authority.read_d04_numeric_terminal_v3(prepared.binding)
               if type(authority) is AuthorityD04NumericServiceV3 else authority.numeric_inspect(prepared.binding)[1])
    assert current == terminal  # Recovery neither reruns nor rewrites actual CPU.
    return restored


@pytest.mark.asyncio
async def test_actual_full_loo_cold_restore_and_atomic_adoption(tmp_path, installed_d04_root):
    """Owner→C02→paid appraisal→three drives→actual ABI2→cold restore→CAS."""
    from sylanne3.runtime.d04_numeric_policy_v3 import AdminD04JointNumericPolicyV3
    from sylanne3.runtime.d04_numeric_cost_v3 import read_d04_numeric_cost_original_v3
    from sylanne3.runtime.jobs import get_job
    from sylanne3.domains.d04.contribution_ledger_v3 import TYPE_NAME as LEDGER_TYPE
    resources = []
    math_queues = []

    async def after_drive(case):
        graph, store, ns = case["graph"], case["store"], case["namespace"]
        grant = case["policy"].root_grant
        policy = AdminD04JointNumericPolicyV3(ns, case["policy"].installation_id,
            grant.grant_id, grant.version, grant.lease_id, 100000, 256, 1e-8, 600)
        bundle = replace(case["installed_bundle"], d04_joint_numeric=policy)
        assembly = replace(case["assembly"], admin_bundle=bundle)
        graph._GraphCoordinator__d04_installed_joint_assembly = assembly
        current = {**case, "installed_bundle": bundle, "assembly": assembly}
        support = await asyncio.to_thread(install_actual_numeric_authority_case_v3, current,
            owner_loop=asyncio.get_running_loop())
        resources.append(support)
        arguments = {"c02_operation_id": case["c02"].operation_id, "source_ref": case["source_ref"]}
        from sylanne3.runtime.d04_numeric_math_ticket_v3 import (
            InstalledD04MathQueueV3, _MathTicketV3, issue_current_numeric_math_ticket_v3,
        )
        worker = case["http_worker"]
        def prepare_on_graph(current_graph):
            assert current_graph is graph
            queue = InstalledD04MathQueueV3(current_graph, case["bootstrap"])
            current_graph._GraphCoordinator__d04_math_queue_v3 = queue
            return queue, issue_current_numeric_math_ticket_v3(current_graph, case["bootstrap"], bundle, queue, **arguments)
        queue, ticket = await worker.call(prepare_on_graph)
        math_queues.append(queue)
        assert type(ticket) is _MathTicketV3
        with pytest.raises(ValueError, match="actual newly issued object"):
            queue.submit(replace(ticket))
        future = queue.submit(ticket)
        with pytest.raises(ValueError, match="actual newly issued object"):
            queue.submit(ticket)
        assert not future.done()
        # An actual read completes on the sole GraphWorker while the complete
        # 72D native full/LOO recipe is running on the separate math thread.
        stamp = await asyncio.wait_for(worker.call(lambda current_graph: current_graph._v2_graph_stamp(ns)), timeout=10)
        assert stamp[0].graph_revision == ticket.ready.preparation.current.component.graph_revision
        assert not future.done()
        returned = await asyncio.shield(asyncio.wrap_future(future))
        executed = await worker.call(lambda current_graph: queue.accept(current_graph, returned))
        assert executed.status == "execution_terminal"
        assert executed.terminal.measurement.status == "completed", executed.terminal.measurement
        assert executed.terminal.measurement.actual_cpu_ns > 0
        restored = await asyncio.to_thread(assert_actual_numeric_cold_recovery_v3,
            authority=support.port, execution=executed, installation=assembly, tmp_path=tmp_path)

        def forbidden(*_args, **_kwargs):
            raise AssertionError("terminal retry/adoption attempted another native execution")
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(fixed_block_transcript, "run_fixed_block_math", forbidden)
            patch.setattr(initial_box_trajectory, "_native_initial_radius", forbidden)
            patch.setattr(d04_joint_product_math, "run_fixed_block_math", forbidden)
            patch.setattr(d04_fixed_trajectory_v2, "run_fixed_block_math", forbidden)
            patch.setattr(loader, "load_production_native", forbidden)
            patch.setattr(trusted_joint_replay, "_replay_package_bound_joint_numeric", forbidden)
            assert await worker.call(lambda current_graph: issue_current_numeric_math_ticket_v3(
                current_graph, case["bootstrap"], bundle, queue, **arguments)) == executed
            receipt = await asyncio.to_thread(graph.adopt_post_c02_joint_numeric_v3,
                case["bootstrap"], bundle, operation_id=executed.prepared.binding.operation_id)
            assert receipt["status"] == "joint_advance_committed"
            assert receipt["output_original_digest"] == restored.output.original_digest
            assert receipt["actual_cpu_ns"] == executed.terminal.measurement.actual_cpu_ns
            assert await asyncio.to_thread(graph.adopt_post_c02_joint_numeric_v3,
                case["bootstrap"], bundle, operation_id=executed.prepared.binding.operation_id) == receipt
        with store._lock:
            cost = read_d04_numeric_cost_original_v3(store._db, ns, executed.prepared.binding.operation_id)
            assert cost is not None and cost.actual_cpu_ns == executed.terminal.measurement.actual_cpu_ns
            assert get_job(store._db, executed.prepared.binding.job_id).phase == "completed"
            for member in restored.output.members:
                for ref in (member.checkpoint_ref, member.predecessor_state_ref):
                    assert store._db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?", (ref,)).fetchone() == (2, 1)
            assert store._db.execute("SELECT COUNT(*) FROM graph_atoms WHERE bot=? AND persona=? AND type_name=?",
                (*ns.as_tuple, LEDGER_TYPE)).fetchone()[0] > 0
            assert store._db.execute("SELECT COUNT(*) FROM graph_d04_originals_v3 "
                "WHERE bot=? AND persona=? AND kind='numeric_cost' AND original_ref=?",
                (*ns.as_tuple, executed.prepared.binding.operation_id)).fetchone() == (1,)
        # A separate real encoding read freezes the newly adopted state at its
        # actual current time. The C02 perspective only identifies the observer.
        encoding = await worker.call(lambda current_graph: current_graph.commit_post_joint_c04_encoding_v3(
            case["bootstrap"], bundle, **arguments, joint_operation_id=executed.prepared.binding.operation_id))
        assert encoding["status"] == "encoding_baseline_committed"
        assert await worker.call(lambda current_graph: current_graph.commit_post_joint_c04_encoding_v3(
            case["bootstrap"], bundle, **arguments, joint_operation_id=executed.prepared.binding.operation_id)) == encoding
        from sylanne3.runtime.c04_encoding_baseline_store_v3 import read_c04_encoding_baseline_v3
        with store._lock:
            store._db.execute("BEGIN")
            try:
                baseline = read_c04_encoding_baseline_v3(store._db, namespace=ns,
                    encoding_operation_id=encoding["operation_id"], source_ref=case["source_ref"])
                assert baseline.record_digest == encoding["record_digest"]
                assert baseline.joint_operation_id == executed.prepared.binding.operation_id
                assert baseline.encoding_receipt.write_versions == ()
                assert baseline.original.as_known_at >= ticket.ready.preparation.current.component.role_end
            finally:
                store._db.rollback()
        from c09_d04_original_inventory_acceptance_v3 import assert_actual_d04_original_erasure_inventory_v3
        assert_actual_d04_original_erasure_inventory_v3(case, executed)
    try:
        await actual_drive_case(tmp_path, installed_d04_root, 0.5, after_drive=after_drive, role_clock_rate="1")
    finally:
        for queue in reversed(math_queues):
            await asyncio.to_thread(queue.close)
        for resource in reversed(resources):
            resource.close()


@pytest.mark.parametrize('failure', ('truncated', 'trailing', 'overrun', 'wrong_digest', 'wrong_length'))
def test_numeric_restore_codec_rejects_incomplete_or_changed_bytes(failure):
    import hashlib
    import zlib
    from sylanne3.authority_service.d04_numeric_restore_stream_v3 import _decode_packet
    raw = b'{"original":"bounded exact bytes"}'
    encoded = zlib.compress(raw, level=1)
    digest = hashlib.sha256(raw).hexdigest()
    assert _decode_packet(encoded, decoded_bytes=len(raw), decoded_digest=digest) == raw
    length = len(raw)
    if failure == 'truncated':
        encoded = encoded[:-1]
    elif failure == 'trailing':
        encoded += b'additional-data'
    elif failure == 'overrun':
        length -= 1
    elif failure == 'wrong_digest':
        digest = '0' * 64
    else:
        length += 1
    with pytest.raises(RuntimeError, match='numeric restoration'):
        _decode_packet(encoded, decoded_bytes=length, decoded_digest=digest)
