"""Permanent actual-installation Life numeric acceptance support.

No fake native result, prepared DTO, signature or clock is introduced. The
unchanged installed policy may reject a long actual role interval; that is a
real HOLD/failure and must not be repaired by shortening time or tolerance.
"""
import asyncio
from contextlib import contextmanager, AsyncExitStack
import json
from pathlib import Path
import time
import traceback

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
    from sylanne3.runtime_storage_v3 import runtime_storage_v3
    if runtime_storage_v3(case['store']._db)is not None:
        from beta1_fixture_phase_controller_v1 import call_current_beta1_numeric_v3
        result=asyncio.run_coroutine_threadsafe(call_current_beta1_numeric_v3(case,
            'run_current_domain_operation_v1',operation_kind=kind,request=request,operation_id=operation_id,
            activity_id=case['life_activity_id'],audience_ref=case['life_audience'],
            parent_budget_lease_ref=case['policy'].root_grant.lease_id),case['owner_loop']).result()
    else:
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


@contextmanager
def _observe_numeric_rpc_wait_v1(case, evidence_path):
    """Observe actual RPC work and stacks; never retain arguments or locals."""
    import threading
    import sys
    server = case['server']
    actual_dispatch = server.dispatch
    actual_enqueue = server._dispatch_on_worker
    actual_run = case['graph']._GraphCoordinator__c04_authority_port_v3._run
    stream = evidence_path.open('x', encoding='utf-8')
    lock = threading.Lock()
    started = time.monotonic()
    sequence = 0
    def record(stage, **values):
        with lock:
            stream.write(json.dumps({'stage': stage,
                'elapsed_seconds': time.monotonic() - started,
                'wall_utc_observation': time.time(),
                'thread_name': threading.current_thread().name, **values}) + '\n')
            stream.flush()
    def stacks():
        frames = sys._current_frames()
        return [{'thread_name': thread.name, 'frames': [
            {'file': frame.filename, 'line': frame.lineno, 'function': frame.name}
            for frame in traceback.extract_stack(frames[thread.ident])[-24:]]}
            for thread in threading.enumerate() if thread.ident in frames]
    def dispatch(method, *args, **kwargs):
        record('dispatch:begin', method=method)
        try:
            result = actual_dispatch(method, *args, **kwargs)
        except BaseException as exc:
            record('dispatch:error', method=method, category=type(exc).__name__)
            raise
        record('dispatch:end', method=method)
        return result
    async def enqueue(method, *args, **kwargs):
        nonlocal sequence
        sequence += 1
        invocation = sequence
        record('enqueue:begin', method=method, invocation=invocation)
        try:
            result = await actual_enqueue(method, *args, **kwargs)
        except BaseException as exc:
            record('enqueue:error', method=method, invocation=invocation,
                category=type(exc).__name__, stacks=stacks())
            raise
        record('enqueue:end', method=method, invocation=invocation)
        return result
    def run(coroutine, **kwargs):
        code = coroutine.cr_code
        client_started = time.monotonic()
        original_timeout = case['installed_bundle'].tls_profile.timeout_seconds
        deadline_observation = client_started + original_timeout
        record('client:begin', function=code.co_name, client_started_monotonic=client_started,
            original_tls_timeout_seconds=original_timeout)
        probe = threading.Timer(original_timeout,
            lambda: record('client:first_transport_deadline', function=code.co_name,
                client_started_monotonic=client_started,
                client_elapsed_seconds=time.monotonic() - client_started,
                original_tls_timeout_seconds=original_timeout,
                timer_lateness_seconds=time.monotonic() - deadline_observation,
                observation_scope='elapsed from actual port._run entry; HTTP handshake phase is not identified',
                stacks=stacks()))
        probe.daemon = True
        probe.start()
        try:
            result = actual_run(coroutine, **kwargs)
        except BaseException as exc:
            record('client:error', function=code.co_name,
                client_started_monotonic=client_started,
                client_elapsed_seconds=time.monotonic() - client_started,
                category=type(exc).__name__, frames=[
                    {'file': frame.filename, 'line': frame.lineno, 'function': frame.name}
                    for frame in traceback.extract_tb(exc.__traceback__)], stacks=stacks())
            raise
        finally:
            probe.cancel()
            probe.join()
        record('client:end', function=code.co_name, client_started_monotonic=client_started,
            client_elapsed_seconds=time.monotonic() - client_started)
        return result
    port = case['graph']._GraphCoordinator__c04_authority_port_v3
    server.dispatch = dispatch
    server._dispatch_on_worker = enqueue
    port._run = run
    try:
        yield
    finally:
        port._run = actual_run
        server._dispatch_on_worker = actual_enqueue
        server.dispatch = actual_dispatch
        stream.close()


async def run_life_numeric_interval_acceptance_v1(case, *, tmp_path, installed_d04_root, appraisal_ref, native_wait_diagnostic=False):
    async with AsyncExitStack() as read_lifetimes:
        from d04_numeric_authority_acceptance_support_v3 import install_actual_numeric_authority_case_v3
        from sylanne3.runtime.d06_life_numeric_drive_v1 import PrepareLifeNumericDriveRequestV1, life_numeric_drive_ids_v1, OPERATION as DRIVE_OPERATION
        from sylanne3.runtime.d06_life_numeric_joint_v1 import PrepareLifeNumericJointRequestV1, life_numeric_joint_ids_v1, OPERATION as JOINT_OPERATION, issue_current_life_numeric_math_ticket_v1
        from sylanne3.runtime.d04_life_encoding_baseline_v1 import PrepareLifeEncodingBaselineRequestV1, life_encoding_baseline_ids_v1, OPERATION as BASELINE_OPERATION
        from sylanne3.runtime.d06_life_numeric_trace_v1 import AdoptLifeNumericTraceRequestV1, life_numeric_trace_operation_v1, life_numeric_trace_keys_v1, OPERATION as TRACE_OPERATION, require_installed_life_numeric_trace_reader_v1, InstalledInternalLifeNumericReaderV1
        from sylanne3.runtime.d04_numeric_math_ticket_v3 import InstalledD04MathQueueV3, _MathTicketV3
        from sylanne3.runtime.d04_numeric_adoption_v3 import adopt_post_c02_joint_numeric_v3
        from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
        from sylanne3.domains.d01.production_operations_v1 import plain_v1
        graph, namespace = (case['graph'], case['namespace'])
        worker = await case['get_http_worker']()
        bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
        assert bundle.d04_joint_numeric is not None and bundle.d04_semantic_drive is not None
        assert Path(installed_d04_root).resolve() == Path(case['package_root']).resolve()
        episode, causal = (case['episode_ref'], case['life_causal_operation_id'])
        original_policy = bundle.d04_joint_numeric
        original_mapping_policy = bundle.d04_semantic_drive
        from sylanne3.runtime_storage_v3 import runtime_storage_v3
        if runtime_storage_v3(case['store']._db) is None:
            raise ValueError('current Beta1 Life interval consumer requires actual selected V3; frozen Alpha2 owns its historical native entry')
        from beta1_fixture_phase_controller_v1 import numeric_before_digest_v3, current_beta1_native_original_read_v3
        before_digest = numeric_before_digest_v3(case)
        checkpoint_refs = set(case['beta1_numeric_selectors']['before_checkpoint_refs'])
        drive_request = PrepareLifeNumericDriveRequestV1(episode, causal, appraisal_ref)
        drive_ids = life_numeric_drive_ids_v1(namespace, episode, appraisal_ref)
        drive_receipt = await asyncio.to_thread(_command, case, DRIVE_OPERATION, drive_request, drive_ids['operation'])
        assert drive_receipt['coverage'] == 'complete'
        support = await asyncio.to_thread(install_actual_numeric_authority_case_v3, case, owner_loop=asyncio.get_running_loop())
        assert support.port is graph._GraphCoordinator__c04_authority_port_v3
        joint_request = PrepareLifeNumericJointRequestV1(episode, causal, appraisal_ref)
        joint_ids = life_numeric_joint_ids_v1(namespace, episode, appraisal_ref)
        preparation_receipt = await asyncio.to_thread(_command, case, JOINT_OPERATION, joint_request, joint_ids['prepare'])
        prepared = await read_lifetimes.enter_async_context(current_beta1_native_original_read_v3(case, request=joint_request))
        assert prepared is not None and prepared.binding.operation_id == joint_ids['operation']
        assert prepared.binding.quote_id == joint_ids['quote'] and prepared.binding.job_id == joint_ids['job']
        from sylanne3.runtime.d04_installed_numeric_v3 import _ready_from_original_v3
        actual_ready = _ready_from_original_v3(prepared)
        assert preparation_receipt == {'status': 'numeric_prepared', 'operation_id': joint_ids['prepare'], 'joint_operation_id': joint_ids['operation'], 'prepared_digest': prepared.digest, 'binding_digest': prepared.binding.digest, 'job_id': prepared.binding.job_id, 'worker_fence': actual_ready.worker_fence}
        request = json.loads(prepared.input_payload_json)['numeric_request']
        assert set(request['component']['checkpoint_refs']) == checkpoint_refs
        assert request['max_iterations'] == original_policy.max_iterations
        from sylanne3.runtime.d04_semantic_mapping_v3 import evidence_payload_v3
        assert request['tolerance'] == evidence_payload_v3(original_policy.tolerance)
        assert prepared.binding.cpu_ceiling_ms == original_policy.cpu_ceiling_ms
        before_native = json.loads(prepared.job_payload_json)
        assert before_native['work_kind'] == 'd04.joint_numeric_cpu.v3'
        assert before_native['continuation']['before_digest'] == before_digest

        def issue(current):
            assert getattr(current, '_GraphCoordinator__d04_math_queue_v3', None) is None
            queue = InstalledD04MathQueueV3(current, case['bootstrap'])
            current._GraphCoordinator__d04_math_queue_v3 = queue
            ticket = issue_current_life_numeric_math_ticket_v1(current, case['bootstrap'], bundle, queue, request=joint_request, prepared_read=prepared)
            return (queue, ticket)
        queue, ticket = await worker.call(issue)
        diagnostic_started = time.monotonic()

        def native_stage(label, **values):
            if native_wait_diagnostic:
                row = {'stage': label, 'elapsed_seconds': time.monotonic() - diagnostic_started, 'wall_utc_observation': time.time(), **values}
                with (tmp_path / 'native-post-terminal-diagnostic.jsonl').open('a') as stream:
                    stream.write(json.dumps(row) + '\n')
                    stream.flush()

        async def observed(label, action):
            native_stage(label + ':begin')
            try:
                value = await action()
            except BaseException as exc:
                native_stage(label + ':error', category=type(exc).__name__, frames=[{'file': frame.filename, 'line': frame.lineno, 'function': frame.name} for frame in traceback.extract_tb(exc.__traceback__)])
                raise
            native_stage(label + ':end')
            return value
        try:
            assert type(ticket) is _MathTicketV3, repr(ticket)
            returned = await observed('native_future', lambda: asyncio.shield(asyncio.wrap_future(queue.submit(ticket))))
            with _observe_numeric_rpc_wait_v1(case, tmp_path / 'numeric-adoption-rpc-first.jsonl'):
                execution = await observed('accept_terminal', lambda: worker.call(lambda current: queue.accept(current, returned)))
                assert execution.prepared == prepared
                assert execution.terminal.measurement.status == 'completed', execution.status
                assert execution.terminal.measurement.actual_cpu_ms >= 0
                adoption = await observed('restore_and_adopt', lambda: worker.call(lambda current: adopt_post_c02_joint_numeric_v3(current, case['bootstrap'], bundle, operation_id=joint_ids['operation'])))
            assert adoption['status'] == 'joint_advance_committed', adoption
            if native_wait_diagnostic:
                native_stage('DIAGNOSTIC_NOT_FULL_NUMERIC_PASS', actual_adoption_status=adoption['status'])
                return
            baseline_request = PrepareLifeEncodingBaselineRequestV1(episode, causal, joint_ids['operation'])
            baseline_ids = life_encoding_baseline_ids_v1(namespace, episode, joint_ids['operation'])
            baseline_receipt = await asyncio.to_thread(_command, case, BASELINE_OPERATION, baseline_request, baseline_ids['operation'])
            assert baseline_receipt['coverage'] == 'complete' and (not baseline_receipt['receipt']['write_versions'])
            trace_request = AdoptLifeNumericTraceRequestV1(episode, causal, joint_ids['operation'])
            trace_operation = life_numeric_trace_operation_v1(namespace, episode, joint_ids['operation'])
            trace_keys = life_numeric_trace_keys_v1(namespace, episode, joint_ids['operation'])
            trace_receipt = await asyncio.to_thread(_command, case, TRACE_OPERATION, trace_request, trace_operation)
            assert trace_receipt['coverage'] == 'complete' and len(trace_receipt['receipt']['write_versions']) == 3

            def qualified_companion(originals):
                drive, baseline, trace, provenance, actual = (originals.drive, originals.baseline, originals.trace, originals.provenance, originals.c04_record)
                proof = actual.proof
                assert drive.before_digest == baseline.before_digest == trace.baseline.before_digest == before_digest
                assert evidence_payload_v3(drive.clock.role_start) == request['component']['role_start']
                assert evidence_payload_v3(drive.clock.role_end) == request['component']['role_end']
                assert baseline.context_digest == drive.context_digest
                assert baseline.c04_record_digest == actual.record_digest and baseline.proof_digest == proof.proof_digest
                assert proof.output_original_digest == originals.output_original_digest
                assert baseline.native_sha256 == proof.native_sha256 == prepared.binding.native_sha256
                assert baseline.native_manifest_sha256 == proof.native_manifest_sha256 == prepared.binding.native_manifest_sha256
                assert baseline.numeric_error_digest == trace.numeric_error_digest == canonical_digest(plain_v1(proof.numeric_error))
                assert trace.baseline == baseline and trace.axis_intervals == proof.projection.normalized_axes
                assert trace.salience_interval == baseline.salience_interval == proof.projection.salience_interval
                assert trace.tone_interval == baseline.tone_interval == proof.projection.tone_interval
                assert trace.then_feeling_versions == tuple(((m.feeling_ref, m.feeling_revision) for m in proof.feeling_bindings))
                assert trace.interpretation_versions == tuple(((m.ref, m.revision) for m in proof.interpretation_versions))
                assert trace.causal_effect == baseline.causal_effect == 'not_identified'
                assert trace.semantic_calibration == baseline.semantic_calibration == 'unvalidated'
                assert baseline.appraisal_acceptance_digests and all((ref == appraisal_ref for ref, _ in baseline.appraisal_acceptance_digests))
                assert trace.meaning_facets and all((ref == appraisal_ref for ref, _, _ in trace.meaning_facets))
                assert len(originals.heads) == len(originals.histories) == len(trace_keys) == 3
                for key, head, history in zip(trace_keys, originals.heads, originals.histories):
                    assert head.key == key and head.revision == 1 and head.valid
                    assert history == (canonical_serialize(head.value), 1, trace_operation)
                assert originals.heads[0].value == plain_v1(trace) and provenance.trace == trace
                return (baseline, trace, provenance, actual.record_digest)
            cold_before = None
            from sylanne3.runtime.d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
            installed_readers = InstalledD06StructuredExperienceReadersV1(issuer=case['d11_issuer'], resource_issuer=graph._GraphCoordinator__d02_issuer, body_quote_authority=graph._GraphCoordinator__body_quote_authority)
            current_reader = InstalledInternalLifeNumericReaderV1(graph=graph, installed_readers=installed_readers)

            async def retained_trace():
                return await read_lifetimes.enter_async_context(current_beta1_native_original_read_v3(case, request=trace_request, installed_trace_reader=current_reader))
            cold_before = qualified_companion(await retained_trace())
            current_trace = qualified_companion(await retained_trace())[1]
            assert current_trace == cold_before[1]
            with pytest.raises(ValueError):
                require_installed_life_numeric_trace_reader_v1()
            assert await asyncio.to_thread(_command, case, BASELINE_OPERATION, baseline_request, baseline_ids['operation']) == baseline_receipt
            assert await asyncio.to_thread(_command, case, TRACE_OPERATION, trace_request, trace_operation) == trace_receipt
            replay_prepared = await read_lifetimes.enter_async_context(current_beta1_native_original_read_v3(case, request=joint_request))
            replay = await worker.call(lambda current: issue_current_life_numeric_math_ticket_v1(current, case['bootstrap'], bundle, queue, request=joint_request, prepared_read=replay_prepared))
            assert replay.prepared == prepared and replay.terminal is not None
            assert qualified_companion(await retained_trace()) == cold_before
            from sylanne3.graph_coordinator import UnavailableGuard
            port = case['port']
            await asyncio.to_thread(port.logout_owner_session, namespace=namespace, authority_namespace=case['policy'].authority_namespace, request=case['owner_session_request'], token=case['owner_session_token'])
            with pytest.raises(UnavailableGuard):
                await retained_trace()
            assert bundle.d04_joint_numeric is original_policy and bundle.d04_semantic_drive is original_mapping_policy
            return {'drive': drive_receipt, 'prepare': preparation_receipt, 'adoption': adoption, 'baseline': baseline_receipt, 'trace': trace_receipt, 'current_trace_digest': current_trace.digest, 'joint_operation_id': joint_ids['operation'], 'prepared_digest': prepared.digest, 'baseline_digest': cold_before[0].digest, 'trace_digest': cold_before[1].digest, 'c04_record_digest': cold_before[3]}
        finally:
            native_stage('queue_close:begin')
            await asyncio.to_thread(queue.close)
            native_stage('queue_close:end')
            # The outer actual root/Life fixture owns and closes the reused storage
            # selection and Authority support after its real writers are closed.
