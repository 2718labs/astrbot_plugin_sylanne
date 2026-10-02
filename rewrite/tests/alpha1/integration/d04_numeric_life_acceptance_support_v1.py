"""Permanent actual-installation Life numeric acceptance support.

No fake native result, prepared DTO, signature or clock is introduced. The
unchanged installed policy may reject a long actual role interval; that is a
real HOLD/failure and must not be repaired by shortening time or tolerance.
"""
import asyncio
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3

import pytest


@contextmanager
def numeric_owner(case, *, purpose="workbench_user_action", audience="owner"):
    graph = case['graph']
    authority, lease, _ = graph.grant_current_owner(case['bootstrap'], actor='owner-actor-reply',
        namespace=case['namespace'], domains=tuple(domain for domain in
            ('d01', 'd02', 'd03', 'd04', 'd05', 'd06', 'd07', 'd08', 'd10', 'd11', 'd12')
            if domain in graph._GraphCoordinator__providers),
        purpose=purpose, audience=audience, activation_generation=1,
        owner_session_token=case['owner_session_token'], owner_session_request=case['owner_session_request'])
    try:
        yield authority, lease
    finally:
        graph.release_current_owner_lease(case['bootstrap'], lease)


def _command(case, kind, request, operation_id):
    with numeric_owner(case) as (authority, lease):
        result = case['graph'].run_current_domain_operation_v1(authority, lease,
            operation_kind=kind, request=request, operation_id=operation_id,
            activity_id=case['life_activity_id'], audience_ref=case['life_audience'],
            parent_budget_lease_ref=case['policy'].root_grant.lease_id)
    runtime = case['graph']._GraphCoordinator__domain_production_runtime_v1
    if kind == 'prepare_internal_life_numeric_joint':
        assert type(result) is dict and set(result) == {
            'status', 'operation_id', 'joint_operation_id', 'prepared_digest',
            'binding_digest', 'job_id', 'worker_fence'}, repr(
                getattr(runtime, '_last_refusal_exception_v1', result))
        assert result['status'] == 'numeric_prepared'
        assert result['operation_id'] == operation_id
        assert type(result['worker_fence']) is int and result['worker_fence'] > 0
    else:
        assert result.get('schema') == 'sylanne.domain-production-receipt.v1', repr(
            getattr(runtime, '_last_refusal_exception_v1', result))
        assert result['receipt']['status'] == 'committed'
        assert result['operation_id'] == operation_id
    return result


async def run_life_numeric_interval_acceptance_v1(case, *, tmp_path, installed_d04_root, appraisal_ref):
    from d04_numeric_authority_acceptance_support_v3 import install_actual_numeric_authority_case_v3
    from sylanne3.runtime.d06_life_numeric_drive_v1 import (
        PrepareLifeNumericDriveRequestV1, life_numeric_drive_ids_v1, OPERATION as DRIVE_OPERATION,
        KIND as DRIVE_KIND, decode_life_numeric_drive_original_v1)
    from sylanne3.runtime.d06_life_numeric_joint_v1 import (
        PrepareLifeNumericJointRequestV1, life_numeric_joint_ids_v1, OPERATION as JOINT_OPERATION,
        read_life_numeric_joint_prepared_v1, issue_current_life_numeric_math_ticket_v1)
    from sylanne3.runtime.d04_life_encoding_baseline_v1 import (
        PrepareLifeEncodingBaselineRequestV1, life_encoding_baseline_ids_v1, OPERATION as BASELINE_OPERATION,
        KIND as BASELINE_KIND, decode_life_encoding_baseline_v1)
    from sylanne3.runtime.d06_life_numeric_trace_v1 import (
        AdoptLifeNumericTraceRequestV1, life_numeric_trace_operation_v1, life_numeric_trace_keys_v1,
        OPERATION as TRACE_OPERATION, SIGNED_KIND, PROVENANCE, decode_life_numeric_trace_value_v1,
        require_installed_life_numeric_trace_reader_v1, InstalledInternalLifeNumericReaderV1)
    from sylanne3.runtime.d04_numeric_math_ticket_v3 import InstalledD04MathQueueV3, _MathTicketV3
    from sylanne3.runtime.d04_numeric_adoption_v3 import adopt_post_c02_joint_numeric_v3
    from sylanne3.runtime.c04_encoding_baseline_store_v3 import read_c04_encoding_baseline_v3
    from sylanne3.runtime.d04_joint_output_original_store_v1 import read_d04_joint_output_original_v1
    from sylanne3.runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    from sylanne3.runtime.d11_life_preparation_v1 import _read
    from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.graph_types import AtomKey
    graph, worker, namespace = case['graph'], case['http_worker'], case['namespace']
    bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    assert bundle.d04_joint_numeric is not None and bundle.d04_semantic_drive is not None
    assert Path(installed_d04_root).resolve() == Path(case['package_root']).resolve()
    episode, causal = case['episode_ref'], case['life_causal_operation_id']
    original_policy = bundle.d04_joint_numeric
    original_mapping_policy = bundle.d04_semantic_drive
    original_before = case['numeric_before']
    drive_request = PrepareLifeNumericDriveRequestV1(episode, causal, appraisal_ref)
    drive_ids = life_numeric_drive_ids_v1(namespace, episode, appraisal_ref)
    drive_receipt = await asyncio.to_thread(_command, case, DRIVE_OPERATION, drive_request, drive_ids['operation'])
    assert drive_receipt['coverage'] == 'complete'
    support = await asyncio.to_thread(install_actual_numeric_authority_case_v3, case, owner_loop=asyncio.get_running_loop())
    assert support.port is graph._GraphCoordinator__c04_authority_port_v3
    joint_request = PrepareLifeNumericJointRequestV1(episode, causal, appraisal_ref)
    joint_ids = life_numeric_joint_ids_v1(namespace, episode, appraisal_ref)
    preparation_receipt = await asyncio.to_thread(_command, case, JOINT_OPERATION, joint_request, joint_ids['prepare'])
    def read_prepared(current):
        with current._GraphCoordinator__store._lock:
            return read_life_numeric_joint_prepared_v1(current._GraphCoordinator__store._db,
                namespace=namespace, request=joint_request)
    prepared = await worker.call(read_prepared)
    assert prepared is not None and prepared.binding.operation_id == joint_ids['operation']
    assert prepared.binding.quote_id == joint_ids['quote'] and prepared.binding.job_id == joint_ids['job']
    from sylanne3.runtime.d04_installed_numeric_v3 import _ready_from_original_v3
    actual_ready = _ready_from_original_v3(prepared)
    assert preparation_receipt == {
        'status': 'numeric_prepared', 'operation_id': joint_ids['prepare'],
        'joint_operation_id': joint_ids['operation'], 'prepared_digest': prepared.digest,
        'binding_digest': prepared.binding.digest, 'job_id': prepared.binding.job_id,
        'worker_fence': actual_ready.worker_fence}
    request = json.loads(prepared.input_payload_json)['numeric_request']
    assert set(request['component']['checkpoint_refs']) == {m.checkpoint.ref for m in original_before.members}
    assert request['max_iterations'] == original_policy.max_iterations
    from sylanne3.runtime.d04_semantic_mapping_v3 import evidence_payload_v3
    assert request['tolerance'] == evidence_payload_v3(original_policy.tolerance)
    assert prepared.binding.cpu_ceiling_ms == original_policy.cpu_ceiling_ms
    before_native = json.loads(prepared.job_payload_json)
    assert before_native['work_kind'] == 'd04.joint_numeric_cpu.v3'
    assert before_native['continuation']['before_digest'] == original_before.digest
    def issue(current):
        assert getattr(current, '_GraphCoordinator__d04_math_queue_v3', None) is None
        queue = InstalledD04MathQueueV3(current, case['bootstrap'])
        current._GraphCoordinator__d04_math_queue_v3 = queue
        ticket = issue_current_life_numeric_math_ticket_v1(current, case['bootstrap'], bundle, queue, request=joint_request)
        return queue, ticket
    queue, ticket = await worker.call(issue)
    try:
        assert type(ticket) is _MathTicketV3, repr(ticket)
        returned = await asyncio.shield(asyncio.wrap_future(queue.submit(ticket)))
        execution = await worker.call(lambda current: queue.accept(current, returned))
        assert execution.prepared == prepared
        assert execution.terminal.measurement.status == 'completed', execution.status
        assert execution.terminal.measurement.actual_cpu_ms >= 0
        adoption = await worker.call(lambda current: adopt_post_c02_joint_numeric_v3(
            current, case['bootstrap'], bundle, operation_id=joint_ids['operation']))
        assert adoption['status'] == 'joint_advance_committed', adoption
        baseline_request = PrepareLifeEncodingBaselineRequestV1(episode, causal, joint_ids['operation'])
        baseline_ids = life_encoding_baseline_ids_v1(namespace, episode, joint_ids['operation'])
        baseline_receipt = await asyncio.to_thread(_command, case, BASELINE_OPERATION, baseline_request, baseline_ids['operation'])
        assert baseline_receipt['coverage'] == 'complete' and not baseline_receipt['receipt']['write_versions']
        trace_request = AdoptLifeNumericTraceRequestV1(episode, causal, joint_ids['operation'])
        trace_operation = life_numeric_trace_operation_v1(namespace, episode, joint_ids['operation'])
        trace_keys = life_numeric_trace_keys_v1(namespace, episode, joint_ids['operation'])
        trace_receipt = await asyncio.to_thread(_command, case, TRACE_OPERATION, trace_request, trace_operation)
        assert trace_receipt['coverage'] == 'complete' and len(trace_receipt['receipt']['write_versions']) == 3

        def cold_read():
            store = case['store']
            with store._lock:
                path = Path(store._db.execute('PRAGMA database_list').fetchone()[2])
            with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
                db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
                drive_saved = _read(db, issuer=case['d11_issuer'], namespace=namespace, kind=DRIVE_KIND, ref=drive_ids['original'])
                drive = decode_life_numeric_drive_original_v1(drive_saved[0])
                baseline_saved = _read(db, issuer=case['d11_issuer'], namespace=namespace, kind=BASELINE_KIND, ref=baseline_ids['original'])
                baseline = decode_life_encoding_baseline_v1(baseline_saved[0])
                trace_saved = _read(db, issuer=case['d11_issuer'], namespace=namespace, kind=SIGNED_KIND, ref=trace_keys[0].token)
                provenance = decode_life_numeric_trace_value_v1(PROVENANCE, trace_saved[0])
                trace = provenance.trace
                actual = read_c04_encoding_baseline_v3(db, namespace=namespace,
                    encoding_operation_id=baseline.encoding_operation_id, source_ref=baseline.source_ref)
                output = read_d04_joint_output_original_v1(db, namespace, joint_ids['operation'])
                proof = actual.proof
                assert drive.before_digest == baseline.before_digest == trace.baseline.before_digest == original_before.digest
                assert evidence_payload_v3(drive.clock.role_start) == request['component']['role_start']
                assert evidence_payload_v3(drive.clock.role_end) == request['component']['role_end']
                assert baseline.context_digest == drive.context_digest
                assert baseline.c04_record_digest == actual.record_digest and baseline.proof_digest == proof.proof_digest
                assert proof.output_original_digest == output.original_digest
                assert baseline.native_sha256 == proof.native_sha256 == prepared.binding.native_sha256
                assert baseline.native_manifest_sha256 == proof.native_manifest_sha256 == prepared.binding.native_manifest_sha256
                assert baseline.numeric_error_digest == trace.numeric_error_digest == canonical_digest(plain_v1(proof.numeric_error))
                assert trace.baseline == baseline and trace.axis_intervals == proof.projection.normalized_axes
                assert trace.salience_interval == baseline.salience_interval == proof.projection.salience_interval
                assert trace.tone_interval == baseline.tone_interval == proof.projection.tone_interval
                assert trace.then_feeling_versions == tuple((m.feeling_ref, m.feeling_revision) for m in proof.feeling_bindings)
                assert trace.interpretation_versions == tuple((m.ref, m.revision) for m in proof.interpretation_versions)
                assert trace.causal_effect == baseline.causal_effect == 'not_identified'
                assert trace.semantic_calibration == baseline.semantic_calibration == 'unvalidated'
                assert baseline.appraisal_acceptance_digests and all(ref == appraisal_ref for ref, _ in baseline.appraisal_acceptance_digests)
                assert trace.meaning_facets and all(ref == appraisal_ref for ref, _, _ in trace.meaning_facets)
                for key in trace_keys:
                    row = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?', (key.token,)).fetchone()
                    assert row is not None and row[0] == 1 and row[2] == 1
                    assert db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1',
                        (key.token,)).fetchone() == (row[1], 1, trace_operation)
                assert json.loads(db.execute('SELECT value FROM graph_atoms WHERE token=?', (trace_keys[0].token,)).fetchone()[0]) == plain_v1(trace)
                shared = read_adopted_domain_operation_v1(db, namespace, trace_operation)
                assert shared['operation_kind'] == TRACE_OPERATION
                assert shared['payload']['provenance']['numeric_trace_provenance'] == plain_v1(provenance)
                assert db.execute("SELECT count(*) FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind=? AND original_ref=?",
                    (*namespace.as_tuple, SIGNED_KIND, trace_keys[0].token)).fetchone() == (1,)
                assert db.total_changes == 0
                return baseline, trace, provenance, actual.record_digest
        cold_before = await asyncio.to_thread(cold_read)
        from sylanne3.runtime.d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
        installed_readers = InstalledD06StructuredExperienceReadersV1(issuer=case['d11_issuer'],
            resource_issuer=graph._GraphCoordinator__d02_issuer,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority)
        current_reader = InstalledInternalLifeNumericReaderV1(graph=graph, installed_readers=installed_readers)
        def current_read():
            with numeric_owner(case, purpose='consolidation', audience=case['life_audience']) as (authority, lease):
                return current_reader.read(authority=authority, lease=lease, request=trace_request,
                    activity_id=case['life_activity_id'])
        current_trace = await asyncio.to_thread(current_read)
        assert current_trace == cold_before[1]
        with pytest.raises(ValueError):
            require_installed_life_numeric_trace_reader_v1()
        # Exact replay is read-only recovery of these real consumed originals.
        assert await asyncio.to_thread(_command, case, BASELINE_OPERATION, baseline_request, baseline_ids['operation']) == baseline_receipt
        assert await asyncio.to_thread(_command, case, TRACE_OPERATION, trace_request, trace_operation) == trace_receipt
        replay = await worker.call(lambda current: issue_current_life_numeric_math_ticket_v1(
            current, case['bootstrap'], bundle, queue, request=joint_request))
        assert replay.prepared == prepared and replay.terminal is not None
        assert await asyncio.to_thread(cold_read) == cold_before
        def reject_logged_out_owner():
            from sylanne3.graph_coordinator import UnavailableGuard
            with numeric_owner(case, purpose='consolidation', audience=case['life_audience']) as (authority, lease):
                port = case['port']
                assert port.current_owner_session(namespace=namespace, authority_namespace=case['policy'].authority_namespace,
                    request=case['owner_session_request'], token=case['owner_session_token']) is True
                port.logout_owner_session(namespace=namespace, authority_namespace=case['policy'].authority_namespace,
                    request=case['owner_session_request'], token=case['owner_session_token'])
                with pytest.raises(UnavailableGuard):
                    current_reader.read(authority=authority, lease=lease, request=trace_request,
                        activity_id=case['life_activity_id'])
        await asyncio.to_thread(reject_logged_out_owner)
        assert await asyncio.to_thread(cold_read) == cold_before
        assert bundle.d04_joint_numeric is original_policy and bundle.d04_semantic_drive is original_mapping_policy
        return {'drive': drive_receipt, 'prepare': preparation_receipt, 'adoption': adoption,
            'baseline': baseline_receipt, 'trace': trace_receipt, 'current_trace_digest': current_trace.digest, 'joint_operation_id': joint_ids['operation'],
            'prepared_digest': prepared.digest, 'baseline_digest': cold_before[0].digest,
            'trace_digest': cold_before[1].digest, 'c04_record_digest': cold_before[3]}
    finally:
        await asyncio.to_thread(queue.close)
        # The outer actual root/Life fixture owns and closes the reused storage
        # selection and Authority support after its real writers are closed.
