"""Permanent installed numerical Life chain with one finite model provider call.

Real before capture, Source/Owner qualification, independent paid task, native
CPU and interval readers are exercised through installed product entrypoints.
The finite HTTP transport supplies a candidate, never numeric evidence.
"""
import asyncio,json,sqlite3,traceback
from dataclasses import fields
from pathlib import Path
import pytest
import time
import sys
import hashlib
import inspect
from contextlib import contextmanager, nullcontext
from test_installed_life_numeric_before_v1 import installed_d04_root,run_installed_life_before_case
from test_d04_installed_semantic_drive_v3 import explicit_subjective_reply
from d04_numeric_life_acceptance_support_v1 import numeric_owner
from sylanne3.host.authority_profile import AdminModelWorkflowV2
from sylanne3.host.model_workflows_v3 import AdminModelWorkflowsV3
from sylanne3.authority_service.current_life_numeric_v1 import InstalledLifeNumericModelGraphReaderV1
from sylanne3.authority_service.d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
from sylanne3.runtime.d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
from sylanne3.runtime.d06_life_numeric_paid_v1 import life_numeric_model_draft_v1,seal_life_numeric_call_v1
from sylanne3.runtime.d06_life_numeric_task_v1 import read_life_numeric_prepared_v1
from sylanne3.model_broker.internal_life_numeric_v1 import WORK_KIND,TEMPLATE_VERSION,internal_life_numeric_ids_v1
from sylanne3.runtime_contracts import AuthorityContext
from sylanne3.host.authority_client import AuthorityClient,AuthoritySelection
from sylanne3.host.mtls_transport import MtlsAuthorityTransport
from sylanne3.host.astrbot_model_call import AstrBotModelProvider
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.model_broker.broker import ModelProviderDescriptor
from sylanne3.runtime.model_cost_settlement import read_original_model_cost,OriginalModelCostCommitV1
from sylanne3.authority_service.v2_model_egress_contract import ModelTerminalReceiptV2


def life_numeric_workflows(base,shared):
    common={f.name:getattr(base,f.name) for f in fields(base) if f.name not in {'version','life_numeric'}}
    return AdminModelWorkflowsV3(3,**common,life_numeric=AdminModelWorkflowV2(
        work_kind=WORK_KIND,purpose='consolidation',template_version=TEMPLATE_VERSION,
        max_output_tokens=2048,quote_ceiling={'input_tokens':16384,'output_tokens':2048},**shared))


@contextmanager
def _observe_numeric_issuance_times(record):
    """Observe original producer inputs/outputs without changing its clock."""
    from datetime import datetime
    from sylanne3.runtime import d06_life_numeric_task_v1 as task, d06_life_numeric_worker_v1 as worker
    originals = [(task, 'stage_prepare_life_numeric_in_transaction_v1'),
                 (worker, 'stage_acquire_life_numeric_in_transaction_v1')]
    saved = []
    def observed(actual, name):
        def call(*args, **kwargs):
            frame = kwargs['frame']
            started = time.monotonic()
            caller = inspect.currentframe().f_back
            clock_age = None
            while caller is not None:
                if caller.f_code.co_name == '_owner_domain_write_v3':
                    clock = caller.f_locals.get('clock')
                    if clock is not None:
                        clock_age = started - clock.monotonic_after_seconds
                    break
                caller = caller.f_back
            del caller
            record(name + ':begin', authoritative_frame_utc=frame.now_utc,
                frame_deadline_utc=frame.envelope.deadline_utc,
                wall_utc_observation=time.time(), monotonic_observation=started,
                owner_clock_sample_age_seconds=clock_age)
            result = actual(*args, **kwargs)
            record(name + ':end', duration_seconds=time.monotonic() - started,
                job_deadline_utc=datetime.fromisoformat(result.job.deadline_utc.replace('Z', '+00:00')).timestamp(),
                job_phase=result.job.phase, job_fence=result.job.fence,
                worker_deadline_utc=getattr(getattr(result, 'binding', None), 'deadline_utc', None))
            return result
        return call
    try:
        for module, name in originals:
            actual = getattr(module, name)
            saved.append((module, name, actual))
            setattr(module, name, observed(actual, name))
        yield
    finally:
        for module, name, actual in saved:
            setattr(module, name, actual)



@contextmanager
def _observe_numeric_preparation_costs(record):
    """One declared diagnostic; aggregate only labels/counts/wall/thread CPU."""
    import threading
    from sylanne3.runtime import d06_life_numeric_context_v1 as context
    from sylanne3.runtime import d06_life_numeric_task_v1 as task
    from sylanne3.runtime import d06_life_numeric_worker_v1 as worker
    from sylanne3.runtime.d01_production_operations_v1 import CurrentDomainReadV1
    from sylanne3.graph_coordinator import GraphCoordinator
    targets = [(context, 'stage_life_numeric_context_in_transaction_v1'),
        (context, 'verify_life_numeric_context_stage_v1'),
        (task, '_current'), (worker, '_current'),
        (task, 'stage_prepare_life_numeric_in_transaction_v1'),
        (task, 'verify_life_numeric_preparation_in_transaction_v1'),
        (worker, 'stage_acquire_life_numeric_in_transaction_v1'),
        (worker, 'verify_life_numeric_acquisition_in_transaction_v1'),
        (CurrentDomainReadV1, 'check'), (GraphCoordinator, '_owner_domain_write_v3')]
    totals = {}; lock = threading.Lock(); saved = []
    def measured(actual, label):
        def call(*args, **kwargs):
            wall = time.monotonic(); cpu = time.thread_time()
            try:
                return actual(*args, **kwargs)
            finally:
                wall_elapsed = time.monotonic() - wall
                cpu_elapsed = time.thread_time() - cpu
                with lock:
                    row = totals.setdefault(label, {'calls': 0, 'wall_seconds': 0.0,
                        'thread_cpu_seconds': 0.0, 'max_wall_seconds': 0.0})
                    row['calls'] += 1; row['wall_seconds'] += wall_elapsed
                    row['thread_cpu_seconds'] += cpu_elapsed
                    row['max_wall_seconds'] = max(row['max_wall_seconds'], wall_elapsed)
        return call
    try:
        for owner, name in targets:
            actual = getattr(owner, name)
            label = owner.__name__ + '.' + name
            saved.append((owner, name, actual)); setattr(owner, name, measured(actual, label))
        yield
    finally:
        for owner, name, actual in saved:
            setattr(owner, name, actual)
        record('numeric_preparation_cost_diagnostic', methods=totals,
            measurement='inclusive overlapping wall/thread CPU, no payloads or secrets; instrumentation overhead exists')


def _observe_numeric_current_decision(actual, args, kwargs, record, installed_root):
    """Capture the first propagated exception before _current swallows it."""
    code = actual.__func__.__code__
    started = time.monotonic()
    previous = sys.gettrace()
    captured = []
    def trace(frame, event, value):
        if frame.f_code is not code:
            return None
        if event == 'exception' and not captured:
            category, error, tb = value
            chain, evidence = [], {}
            while tb is not None:
                current = tb.tb_frame
                filename = current.f_code.co_filename
                path = Path(filename)
                if path.is_relative_to(installed_root):
                    chain.append({'file': path.relative_to(installed_root).as_posix(),
                                  'line': tb.tb_lineno, 'function': current.f_code.co_name})
                locals_ = current.f_locals
                model_request = locals_.get('request')
                if type(model_request).__name__ == 'ModelCallRequest':
                    evidence['request_deadline_utc'] = model_request.envelope.deadline_utc
                    evidence['request_monotonic_deadline_identity_only'] = model_request.envelope.monotonic_deadline
                current_frame = locals_.get('self')
                job = locals_.get('job')
                if type(job).__name__ == 'PersistentJob':
                    from datetime import datetime
                    evidence['job_deadline_utc'] = datetime.fromisoformat(job.deadline_utc.replace('Z', '+00:00')).timestamp()
                    evidence['worker_lease_expires_utc'] = datetime.fromisoformat(job.lease_expires_utc.replace('Z', '+00:00')).timestamp() if job.lease_expires_utc else None
                binding = locals_.get('binding')
                if type(binding).__name__ == 'LifeNumericWorkerBindingV1':
                    evidence['binding_deadline_utc'] = binding.deadline_utc
                if type(current_frame).__name__ == 'CurrentOperationFrameV1':
                    evidence['rejected_frame_now_utc'] = current_frame.now_utc
                    evidence['rejected_frame_deadline_utc'] = current_frame.envelope.deadline_utc
                    evidence['remaining_seconds'] = current_frame.envelope.deadline_utc - current_frame.now_utc
                tb = tb.tb_next
            captured.append(True)
            record('first_internal_numeric_refusal', error_category=category.__name__,
                reason=str(error) if category in (ValueError, TypeError) else 'see category and source location',
                include_binding=frame.f_locals.get('include_binding'),
                authoritative_verifier_now_utc=frame.f_locals.get('now'), source_chain=chain, **evidence)
        elif event == 'return':
            intent = args[0]
            record('authority_numeric_current_decision', accepted=value is True,
                include_binding=frame.f_locals.get('include_binding'),
                authoritative_verifier_now_utc=frame.f_locals.get('now'),
                duration_seconds=time.monotonic() - started, return_line=frame.f_lineno,
                call_link=hashlib.sha256(intent.call_id.encode()).hexdigest())
        return trace
    sys.settrace(trace)
    try:
        return actual(*args, **kwargs)
    finally:
        sys.settrace(previous)


def _numeric_state(case, job_id):
    """Read durable job, preparation, projection and accounting effects."""
    db, ns = case['store']._db, case['namespace']
    from sylanne3.runtime.d11_types import job_graph_write
    from sylanne3.runtime.jobs import get_job
    job = get_job(db, job_id)
    ref = job_graph_write(job).key.token
    return {
        'job': job,
        'accounting_inventory': {table: db.execute('SELECT * FROM ' + table + ' ORDER BY rowid').fetchall()
            for table in ('runtime_budget_leases', 'runtime_budget_grants',
                'runtime_budget_operations', 'runtime_budget_reservations')},
        'job_operations': db.execute('SELECT * FROM runtime_job_operations WHERE job_id=? ORDER BY phase', (job_id,)).fetchall(),
        'registrations': db.execute('SELECT * FROM graph_bundle_refs WHERE bot=? AND persona=? AND ref=? ORDER BY ref_kind', (*ns.as_tuple, ref)).fetchall(),
        'originals': db.execute('SELECT * FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND original_ref=? ORDER BY kind', (*ns.as_tuple, job_id)).fetchall(),
        'budget': db.execute('SELECT * FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? ORDER BY phase', (*ns.as_tuple, job.operation_id)).fetchall(),
        'reservation': db.execute('SELECT * FROM runtime_budget_reservations WHERE operation_id=?', (job.operation_id,)).fetchall(),
        'projection': db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?', (ref,)).fetchall(),
        'history': db.execute('SELECT revision,value,valid,event_id FROM graph_history WHERE token=? ORDER BY revision', (ref,)).fetchall(),
    }


def prepare_and_acquire(case, *, registration_checks=False):
    from sylanne3.runtime.d06_life_numeric_context_v1 import (PrepareLifeNumericContextRequestV1,
        life_numeric_context_ids_v1,decode_life_numeric_context_original_v1,KIND)
    from sylanne3.runtime.d06_life_numeric_task_v1 import PrepareInternalLifeNumericRequestV1,_identity
    from sylanne3.runtime.d06_life_numeric_worker_v1 import AcquireInternalLifeNumericRequestV1,read_committed_life_numeric_request_v1
    from sylanne3.runtime.d11_life_preparation_v1 import _read
    ns,store=case['namespace'],case['store']
    ep,causal=case['episode_ref'],case['life_causal_operation_id']
    context_ids=life_numeric_context_ids_v1(ns,ep)
    def run(kind,request,op):
        graph=case['graph']
        with numeric_owner(case) as (authority,lease):
            result=graph.run_current_domain_operation_v1(authority,lease,operation_kind=kind,
                request=request,operation_id=op,activity_id=case['life_activity_id'],
                audience_ref=case['life_audience'],parent_budget_lease_ref=case['policy'].root_grant.lease_id)
        if result.get('schema')!='sylanne.domain-production-receipt.v1':
            error=graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1
            if error is not None:traceback.print_exception(type(error),error,error.__traceback__)
        assert result['schema']=='sylanne.domain-production-receipt.v1'
        return result
    result=run('prepare_internal_life_numeric_context',PrepareLifeNumericContextRequestV1(ep,causal),context_ids['operation'])
    assert result['schema']=='sylanne.domain-production-receipt.v1'
    path=Path(store._db.execute('PRAGMA database_list').fetchone()[2])
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        saved=_read(db,namespace=ns,issuer=case['d11_issuer'],kind=KIND,ref=context_ids['original'])
        original=decode_life_numeric_context_original_v1(saved[0])
        ids=internal_life_numeric_ids_v1(_identity(original))
        assert db.total_changes==0
    request=PrepareInternalLifeNumericRequestV1(ep,causal)
    prepared=run('prepare_internal_life_numeric',request,ids['prepare'])
    assert prepared['job_states']==[[ids['job'],'queued']]
    if registration_checks:
        before = _numeric_state(case, ids['job'])
        assert run('prepare_internal_life_numeric',request,ids['prepare'])==prepared
        assert _numeric_state(case, ids['job']) == before
    from sylanne3.runtime import d06_life_numeric_commit_v1 as commit
    actual_registration = commit.require_life_numeric_job_registration_v1
    rejected = []
    def inspect_registration(witness, db):
        # Only copies of this fresh fixture's reference table are corrupted.
        # The actual active W01 witness, job and signed preparation are used.
        actual = _numeric_state(case, ids['job'])
        columns = db.execute('PRAGMA table_info(graph_bundle_refs)').fetchall()
        rows = db.execute('SELECT * FROM graph_bundle_refs').fetchall()
        ref, = witness.bundle.persistent_job_refs
        for field, value in (('ref_kind', 'persistent_job_refs'), ('ref', 'wrong-ref'),
                ('operation_id', case['numeric_life_prepared'].prepare_operation_id), ('bot', 'other-bot')):
            with sqlite3.connect(':memory:') as copied:
                copied.execute('CREATE TABLE graph_bundle_refs (' + ','.join(c[1] + ' ' + c[2] for c in columns) + ')')
                copied.executemany('INSERT INTO graph_bundle_refs VALUES(?,?,?,?,?)', rows)
                copied.execute('UPDATE graph_bundle_refs SET ' + field + '=? WHERE bot=? AND persona=? AND ref=?',
                    (value, *ns.as_tuple, ref))
                changes = copied.total_changes
                with pytest.raises(ValueError):
                    actual_registration(witness, copied)
                assert copied.total_changes == changes
            assert _numeric_state(case, ids['job']) == actual
            rejected.append(field)
        changes = db.total_changes
        assert actual_registration(witness, db) == (ref,)
        assert db.total_changes == changes
        return (ref,)
    if registration_checks:
        commit.require_life_numeric_job_registration_v1 = inspect_registration
    acquire_request = AcquireInternalLifeNumericRequestV1(ep,causal)
    try:
        acquired=run('acquire_internal_life_numeric',acquire_request,ids['acquire'])
    finally:
        commit.require_life_numeric_job_registration_v1 = actual_registration
    assert acquired['job_states']==[[ids['job'],'running']]
    if registration_checks:
        acquired_state = _numeric_state(case, ids['job'])
        assert run('acquire_internal_life_numeric',acquire_request,ids['acquire']) == acquired
        assert _numeric_state(case, ids['job']) == acquired_state
    if registration_checks:
        with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
            db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            p,b,model=read_committed_life_numeric_request_v1(db,namespace=ns,issuer=case['d11_issuer'],job_id=ids['job'])
            assert b.worker_subject==model.envelope.authority.actor and model.identity.phase=='internal_life_numeric_v1'
            assert p.frozen.identity.before_digest==case['numeric_before'].digest and db.total_changes==0
    case['numeric_job_id']=ids['job']
    if registration_checks:
        from sylanne3.runtime.jobs import cancel_job, get_job
        from sylanne3.runtime_contracts import canonical_digest
        # Drive the real cancellation operator in the new fixture. No old
        # database or ledger is repaired or copied back into the product.
        with store._lock:
            store._db.execute('BEGIN IMMEDIATE')
            try:
                cancelled = cancel_job(store._db, ids['job'], 'numeric-regression-cancel',
                    canonical_digest({'job_id': ids['job'], 'action': 'cancel'}))
                store._db.commit()
            except BaseException:
                store._db.rollback(); raise
        assert cancelled.phase == 'draining' and cancelled.cancel_epoch == 1 and cancelled.fence == 2
        cancelled_state = _numeric_state(case, ids['job'])
        run('prepare_internal_life_numeric',request,ids['prepare'])
        run('acquire_internal_life_numeric',acquire_request,ids['acquire'])
        assert _numeric_state(case, ids['job']) == cancelled_state
        assert get_job(store._db, ids['job']) == cancelled
        with store._lock:
            store._db.execute('BEGIN')
            try:
                metadata, epoch = case['graph']._v2_graph_stamp(ns)
                with pytest.raises(ValueError):
                    life_numeric_model_draft_v1(store._db, namespace=ns, issuer=case['d11_issuer'],
                        job_id=ids['job'], metadata=metadata, epoch=epoch)
                assert _numeric_state(case, ids['job']) == cancelled_state
            finally:
                store._db.rollback()
        assert rejected == ['ref_kind', 'ref', 'operation_id', 'bot']
        assert len(cancelled_state['registrations']) == 1
        assert len(cancelled_state['history']) == 2
        assert store._db.execute('SELECT phase FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=?',
            (*ns.as_tuple, cancelled.operation_id)).fetchall() == [('reserve',)]


async def _numeric_egress_authorization_regression(case, executor, prepared, intent, request, anchor, reader, calls, tmp_path, group):
    """Fresh signed inputs; real-clock rights negatives and explicit clock units."""
    from dataclasses import replace
    from sylanne3.runtime.jobs import cancel_job
    from sylanne3.runtime_contracts import canonical_digest
    from sylanne3.host.authority_profile import installed_model_config_ref
    import math
    store, model = case['store'], case['model_store']
    verifier = case['model_service']._graph_verifier
    results = []; donor = None; time_bounds = None
    def read(candidate=intent, *, controlled_now=None):
        now = verifier._paired_clock()[0] if controlled_now is None else controlled_now
        with store._lock:
            store._db.execute('BEGIN')
            try:
                value = reader.read(store._db, candidate, now)
                assert value.prepared == prepared and value.request == request
                assert value.valid_until_utc > now, 'positive Numeric read lost its actual common lifetime'
                return value, now
            finally:
                store._db.rollback()
    def counts():
        with model._lock:
            db = model._db
            return {table: db.execute('SELECT count(*) FROM ' + table + ' WHERE call_id=?', (intent.call_id,)).fetchone()[0]
                for table in ('authority_model_admissions_v2', 'authority_model_egress_observations_v1')}
    def save(name, error, valid_now, before, *, clock='production'):
        assert not calls and not any(counts().values())
        assert _numeric_state(case, prepared.job_id) == before
        results.append({'case': name, 'clock': clock, 'positive_precondition_utc': valid_now,
            'positive_remaining_seconds': request.envelope.deadline_utc - valid_now,
            'positive_common_deadline_utc': _valid.valid_until_utc,
            'positive_common_remaining_seconds': _valid.valid_until_utc - valid_now,
            'reason_code': type(error).__name__, 'reason': str(error),
            'admissions': 0, 'observations': 0, 'mock_http_calls': 0, 'accounting_unchanged': True,
            'actual_donor_original': donor, **({'time_bounds': time_bounds} if time_bounds is not None else {})})
        (tmp_path / ('life-numeric-authorization-' + group + '.json')).write_text(json.dumps(results, indent=2) + '\n')
    if group == 'installation':
        _valid, valid_now = read()
        before = _numeric_state(case, prepared.job_id)
        foreign = case['numeric_foreign_installation_grant']
        handshake = case['numeric_foreign_installation_client']._v2_handshake
        assert handshake.valid_pairing()
        assert foreign.installation_id == 'installation-admin' != executor._grant.installation_id
        assert foreign.authority_id == executor._grant.authority_id
        assert foreign.manifest_digest == executor._grant.manifest_digest
        assert foreign.subject == handshake.installation_identity_ref
        assert foreign.channel_binding_sha256 == handshake.channel_binding_sha256
        donor = {'producer': 'actual mTLS installation_grant_v2', 'installation_id': foreign.installation_id,
            'manifest_digest': foreign.manifest_digest, 'paired': True}
        await executor._authority._model_installation_context(executor._bundle, executor._grant)
        with pytest.raises(RuntimeError, match='authority model installation binding is invalid') as denied:
            await executor._authority._model_installation_context(executor._bundle, foreign)
        save('cross_installation_grant', denied.value, valid_now, before)
    elif group == 'lease':
        from sylanne3.runtime.budget import get_budget_lease, require_budget_family_admissible
        with store._lock:
            store._db.execute('BEGIN')
            try:
                alternatives = store._db.execute('SELECT lease_id FROM runtime_budget_leases '
                    "WHERE lease_id<>? AND state='active' ORDER BY lease_id", (intent.budget_lease_id,)).fetchall()
                assert len(alternatives) == 1
                foreign = get_budget_lease(store._db, alternatives[0][0])
                signed = case['d11_issuer'].current_budget_grant(store._db, foreign.lease_id)
                now = verifier._paired_clock()[0]
                assert (foreign.bot_id, foreign.persona_id, foreign.currency) == (
                    signed.bot_id, signed.persona_id, signed.currency)
                assert signed.valid_until_utc > now and signed.allowed_work_kinds
                require_budget_family_admissible(store._db, foreign.lease_id)
                donor = {'lease_id': foreign.lease_id, 'active_signed_grant_id': signed.grant_id,
                    'allowed_work_kinds': list(signed.allowed_work_kinds),
                    'valid_until_utc': signed.valid_until_utc, 'state': foreign.state}
            finally:
                store._db.rollback()
        _valid, valid_now = read()
        before = _numeric_state(case, prepared.job_id)
        with pytest.raises(ValueError, match='actual signed quote/once reserve/settlement ledger changed') as denied:
            read(replace(intent, budget_lease_id=foreign.lease_id))
        save('cross_budget_lease', denied.value, valid_now, before)
    elif group == 'reservation':
        from sylanne3.runtime.budget import reserve_budget, get_budget_lease
        from sylanne3.domains.d01.production_operations_v1 import plain_v1
        operation = 'numeric-other-reserve:' + prepared.digest[:40]
        with store._lock:
            store._db.execute('BEGIN IMMEDIATE')
            try:
                issuer = case['d02_issuer']
                actual = issuer.original_signed_quote(store._db, prepared.quote_id, prepared.quote_version)
                foreign = replace(actual, quote_id='numeric-other-quote:' + prepared.digest[:40],
                    operation_id=operation, graph_job_ref=None, required_worker_fence=None,
                    ceiling={'output_tokens': 1})
                lease = get_budget_lease(store._db, foreign.parent_budget_lease_ref)
                assert lease.available('output_tokens') >= 1
                issuer.issue_quote(store._db, foreign)
                digest = canonical_digest({'quote': plain_v1(foreign), 'operation_id': operation})
                reserved = reserve_budget(store._db, foreign.parent_budget_lease_ref, operation,
                    digest, foreign.ceiling)
                assert reserved.status == 'reserved'
                assert issuer.original_signed_quote(store._db, foreign.quote_id, foreign.version) == foreign
                assert store._db.execute('SELECT digest,ceiling_json,state FROM runtime_budget_reservations '
                    'WHERE lease_id=? AND operation_id=?', (foreign.parent_budget_lease_ref, operation)).fetchone() == (
                        digest, '{"output_tokens":1}', 'reserved')
                store._db.commit()
            except BaseException:
                store._db.rollback(); raise
        _valid, valid_now = read()
        assert foreign.valid_until_utc > valid_now and foreign.deadline_utc > valid_now
        donor = {'signed_quote_id': foreign.quote_id, 'lease_id': foreign.parent_budget_lease_ref,
            'reservation_operation_id': operation, 'reservation_digest': digest, 'state': 'reserved',
            'ceiling': dict(foreign.ceiling), 'deadline_utc': foreign.deadline_utc}
        before = _numeric_state(case, prepared.job_id)
        with pytest.raises(ValueError, match='actual signed quote/once reserve/settlement ledger changed') as denied:
            read(replace(intent, budget_reservation_operation_id=operation,
                budget_reservation_digest=digest, budget_ceiling=tuple(sorted(foreign.ceiling.items()))))
        save('cross_reservation', denied.value, valid_now, before)
    elif group == 'configuration':
        _valid, valid_now = read()
        before = _numeric_state(case, prepared.job_id)
        workflow = executor._adapter._admin_model
        wrong = replace(workflow, provider_config_digest='f' * 64,
            provider_config_ref=installed_model_config_ref(workflow.provider_id, workflow.model_id, 'f' * 64))
        adapter = executor._adapter
        with pytest.raises(ValueError, match='model selection is absent from installed administrator snapshot') as denied:
            AstrBotModelProvider(context=adapter._context, host_loop=adapter._host_loop,
                trusted_umo=adapter._trusted_umo, descriptor=adapter._descriptor,
                admin_model=wrong, installation_bundle=executor._bundle)
        save('wrong_configuration_object', denied.value, valid_now, before)
    elif group == 'time':
        from datetime import datetime
        from sylanne3.runtime.jobs import get_job
        from sylanne3.runtime.d06_life_numeric_worker_v1 import read_committed_life_numeric_request_v1
        with store._lock:
            store._db.execute('BEGIN')
            try:
                quote = case['d02_issuer'].original_signed_quote(store._db, prepared.quote_id, prepared.quote_version)
                parent = case['d11_issuer'].current_budget_grant(store._db, quote.parent_budget_lease_ref)
                _prepared, binding, original_request = read_committed_life_numeric_request_v1(
                    store._db, namespace=case['namespace'], issuer=case['d11_issuer'], job_id=prepared.job_id)
                job = get_job(store._db, prepared.job_id)
                assert _prepared == prepared and original_request == request
            finally:
                store._db.rollback()
        job_deadline = datetime.fromisoformat(job.deadline_utc.replace('Z', '+00:00')).timestamp()
        worker_lease_expiry = datetime.fromisoformat(job.lease_expires_utc.replace('Z', '+00:00')).timestamp()
        common_deadline = min(request.envelope.deadline_utc, binding.deadline_utc,
            job_deadline, worker_lease_expiry, quote.valid_until_utc, quote.deadline_utc, parent.valid_until_utc)
        unit_now = math.nextafter(common_deadline, -math.inf)
        time_bounds = {'frame_deadline_utc': request.envelope.deadline_utc,
            'binding_deadline_utc': binding.deadline_utc, 'job_deadline_utc': job_deadline,
            'worker_lease_expires_utc': worker_lease_expiry, 'parent_grant_valid_until_utc': parent.valid_until_utc,
            'quote_valid_until_utc': quote.valid_until_utc, 'quote_deadline_utc': quote.deadline_utc,
            'common_deadline_utc': common_deadline, 'positive_control_utc': unit_now,
            'positive_quote_remaining_seconds': quote.valid_until_utc - unit_now}
        cases = (
            ('expiry_equal', request.envelope.deadline_utc, 'production frame time is invalid or expired'),
            ('expiry_after', request.envelope.deadline_utc + 1.0, 'production frame time is invalid or expired'),
            ('future_occurrence_frame', min(case['numeric_occurrence'].event.activity.completed_at,
                prepared.frozen.appraisal.input.sources[0].record.recorded_at) - 1.0,
                'Life context cannot precede its actual occurrence'),
        )
        if quote.valid_until_utc < request.envelope.deadline_utc:
            cases = (('signed_quote_expiry_equal', quote.valid_until_utc,
                'actual signed quote/once reserve/settlement ledger changed'), *cases)
        for name, invalid_now, reason in cases:
            _valid, valid_now = read(controlled_now=unit_now)
            before = _numeric_state(case, prepared.job_id)
            with pytest.raises(ValueError, match=reason) as denied:
                read(controlled_now=invalid_now)
            save(name, denied.value, valid_now, before, clock='explicit controlled boundary unit')
    else:
        assert group == 'worker'
        for name, candidate in (
            ('wrong_worker_subject', replace(intent, subject=intent.subject + ':other-worker')),
            ('wrong_worker_fence', replace(intent, worker_fence=intent.worker_fence + 1)),
        ):
            _valid, valid_now = read()
            before = _numeric_state(case, prepared.job_id)
            with pytest.raises(ValueError, match='installed workflow/current worker/input identity changed') as denied:
                read(candidate)
            save(name, denied.value, valid_now, before)
        _valid, valid_now = read()
        with store._lock:
            store._db.execute('BEGIN IMMEDIATE')
            try:
                cancelled = cancel_job(store._db, prepared.job_id, 'numeric-egress-regression-cancel',
                    canonical_digest({'job_id': prepared.job_id, 'action': 'cancel'}))
                store._db.commit()
            except BaseException:
                store._db.rollback(); raise
        assert cancelled.phase == 'draining' and cancelled.cancel_epoch == 1
        cancelled_state = _numeric_state(case, prepared.job_id)
        target_now = verifier._paired_clock()[0]
        assert target_now < request.envelope.deadline_utc, 'cancellation negative target lost its other valid time precondition'
        with pytest.raises(ValueError, match='installed workflow/current worker/input identity changed') as denied:
            read(controlled_now=target_now)
        save('cancelled_job', denied.value, valid_now, cancelled_state)



async def run_installed_life_numeric_fullchain_v1(tmp_path,installed_d04_root, *, authorization_group=None, time_diagnostic=False, native_wait_diagnostic=False):
    stages = []
    started = time.monotonic()
    def record_stage(stage, **evidence):
        evidence.update(monotonic_elapsed_seconds=time.monotonic() - started,
                        wall_utc_observation=time.time())
        stages.append({'stage': stage, **evidence})
        (tmp_path / 'life-numeric-stages.json').write_text(json.dumps(stages, indent=2) + '\n')
    async def after(case):
        graph,store,server=(case[k] for k in ('graph','store','server'))
        ns=case['namespace'];policy=case['policy'];port=case['port'];issuer=case['d11_issuer']
        bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
        fences=server._v2_fences[case['authority_namespace']]
        control=graph._actual_d04_authority_acceptance_v3.storage_control
        path=Path(store._db.execute('PRAGMA database_list').fetchone()[2]).resolve()
        owner=InstalledD12OwnerStorageAdmissionServiceV1(fences=fences,owner_tickets=server._v2_owner_tickets,
            graph_db_path=path,namespace_id=ns,installation_id=policy.installation_id,
            holder=policy.administrator_holder,control=control,close_apply=control._applied_reader)
        readers=InstalledD06StructuredExperienceReadersV1(issuer=issuer,resource_issuer=issuer.resource_issuer,
            body_quote_authority=graph._GraphCoordinator__body_quote_authority)
        reader=InstalledLifeNumericModelGraphReaderV1(owner_storage=owner,structured_readers=readers,
            bundle=bundle,read_subject=case['client_grant'].subject)
        model=case['model_service'];verifier=model._graph_verifier
        from sylanne3.authority_service.current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
        location=InstalledCurrentSourceLocationQualifierV1(fences=fences,scoped=control._applied_reader.scoped,
            control=control,graph_db_path=path,namespace_id=ns,installation_id=policy.installation_id)
        model.install_current_source_location_v1(location)
        verifier.install_life_numeric_reader_v1(reader)
        original_current=verifier._current
        def diagnose(*args,**kwargs):
            # Preserve the actual first internal decision in every permanent
            # node; a later read can encounter expiry for a different reason.
            return _observe_numeric_current_decision(
                original_current, args, kwargs, record_stage, installed_d04_root)
        verifier._current=diagnose
        def draft_read():
            with store._lock:
                store._db.execute('BEGIN')
                try:
                    job=case['numeric_job_id']
                    prepared=read_life_numeric_prepared_v1(store._db,namespace=ns,issuer=issuer,job_id=job)
                    metadata,_=graph._v2_graph_stamp(ns)
                finally:store._db.rollback()
            authority=AuthorityContext(port.installation_grant.subject,'d11','life-numeric-read:'+prepared.digest,
                ns,('activity','event','persona','scene'),'consolidation',(case['life_audience'],),
                prepared.provider_config_ref,metadata.requirements.activation_generation)
            def observe(scope):
                actual,permit=port.get_current_owner_guard_for_fence(namespace=ns,
                    authority_namespace=policy.authority_namespace,permit=scope.permit)
                assert permit==scope.permit
                return actual,permit
            def read():
                changes=store._db.total_changes
                store._db.execute('BEGIN')
                try:
                    metadata,epoch=graph._v2_graph_stamp(ns)
                    value=life_numeric_model_draft_v1(store._db,namespace=ns,issuer=issuer,job_id=job,
                        metadata=metadata,epoch=epoch)
                    p,b,model,_=value
                    assert b.worker_subject==model.envelope.authority.actor and model.identity.phase=='internal_life_numeric_v1'
                    assert p.frozen.identity.before_digest==case['numeric_before'].digest and store._db.total_changes==changes
                    return value
                finally:store._db.rollback()
            value,anchor,_,_=graph._read_v2(authority,read,fence_observer=observe,return_recovery_context=True)
            return (*value,anchor)
        transport=MtlsAuthorityTransport({bundle.tls_profile.profile_id:bundle.tls_profile})
        client=AuthorityClient(AuthoritySelection(bundle.tls_profile.profile_id),package_root=installed_d04_root,
            data_dir=tmp_path,transport=transport)
        workflow=bundle.model_workflows.life_numeric
        descriptor=ModelProviderDescriptor(workflow.provider_id,'astrbot-openai-official-v1',workflow.model_id,
            frozenset({'text'}),frozenset({workflow.purpose}),frozenset({workflow.privacy_tier}),
            workflow.provider_config_ref,'unknown',False,False)
        adapter=AstrBotModelProvider(context=case['model_context'],host_loop=asyncio.get_running_loop(),
            trusted_umo=json.loads(case['life_audience'])[0],descriptor=descriptor,admin_model=workflow,installation_bundle=bundle)
        mock=case['model_http_client']._transport;actual_handler=mock.handler;calls=[]
        def counted(req):calls.append(req.url.host);return actual_handler(req)
        mock.handler=counted
        foreign_transport = None
        try:
            record_stage('separate_host_pairing_begin')
            assert (await client.status_v2()).state=='paired'
            actual_grant=await client.installation_grant_v2()
            record_stage('separate_host_pairing_end')
            from sylanne3.host.installation_grant_identity import same_installed_grant_identity_v2
            assert same_installed_grant_identity_v2(case['client_grant'],actual_grant)
            executor=HostModelEgressExecutor(authority=client,bundle=bundle,grant=actual_grant,adapter=adapter)
            record_stage('installed_executor_constructed', exact_workflow_slot=adapter._admin_model is bundle.model_workflows.life_numeric)
            if authorization_group == 'installation':
                from dataclasses import replace
                admin_profile = replace(bundle.tls_profile,
                    client_certificate=case['files']['second.pem'],
                    client_private_key=case['files']['second.key'])
                foreign_transport = MtlsAuthorityTransport({admin_profile.profile_id: admin_profile})
                foreign_client = AuthorityClient(AuthoritySelection(admin_profile.profile_id),
                    package_root=installed_d04_root, data_dir=tmp_path, transport=foreign_transport)
                assert (await foreign_client.status_v2()).state == 'paired'
                foreign_grant = await foreign_client.installation_grant_v2()
                assert foreign_grant.installation_id == 'installation-admin'
                case['numeric_foreign_installation_client'] = foreign_client
                case['numeric_foreign_installation_grant'] = foreign_grant
            with _observe_numeric_preparation_costs(record_stage) if time_diagnostic else nullcontext():
                with _observe_numeric_issuance_times(record_stage) if time_diagnostic else nullcontext():
                    await asyncio.to_thread(prepare_and_acquire, case)
            record_stage('numeric_prepare_and_acquire_committed')
            prepared,binding,request,draft,anchor=await asyncio.to_thread(draft_read)
            record_stage('numeric_draft', request_digest=request.digest, prepared_digest=prepared.digest,
                         binding_digest=binding.digest, ceiling=dict(draft.budget_ceiling))
            frozen=prepared.frozen
            from sylanne3.domains.d01.production_operations_v1 import plain_v1
            candidate=json.loads(explicit_subjective_reply(plain_v1(frozen.appraisal),0.5))
            candidate['facets'][0]['facet_id']='facet:internal-activity'
            candidate['facets'][0]['relation_meaning']='Possible subjective significance of the internal activity'
            for signal in candidate['mechanism_signals']:signal['facet_id']='facet:internal-activity'
            candidate['unknown_fields']=['identified_causal_affect']
            case['model_reply_mode']['content']=json.dumps(candidate)
            record_stage('numeric_model_prepare_begin')
            record,permit=await executor.prepare_once(draft=draft,expected_anchor=anchor,request=request)
            intent=record.intent
            assert record.state=='prepared'
            def seal():
                actual,state=port.get_fence_operation(namespace=ns,authority_namespace=policy.authority_namespace,
                    operation_id=intent.operation_id)
                assert actual==permit and state=='active'
                with store._lock:
                    db=store._db;db.execute('BEGIN IMMEDIATE')
                    try:
                        metadata,epoch=graph._v2_graph_stamp(ns)
                        seal_life_numeric_call_v1(db,namespace=ns,issuer=issuer,
                            intent=intent,permit=permit,metadata=metadata,epoch=epoch)
                        db.commit()
                    except BaseException:db.rollback();raise
            await asyncio.to_thread(seal)
            record_stage('numeric_model_prepared_and_sealed', state=record.state, request_digest=intent.request_digest)
            if time_diagnostic:
                with store._lock:
                    store._db.execute('BEGIN')
                    try:
                        quote = issuer.resource_issuer.original_signed_quote(store._db, prepared.quote_id, 1)
                        parent = issuer.current_budget_grant(store._db, quote.parent_budget_lease_ref)
                        from sylanne3.runtime.budget import get_budget_lease
                        lease = get_budget_lease(store._db, quote.parent_budget_lease_ref)
                        reservation = store._db.execute('SELECT state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
                            (quote.parent_budget_lease_ref, prepared.prepare_operation_id)).fetchone()
                        record_stage('numeric_signed_time_bounds', quote_deadline_utc=quote.deadline_utc,
                            quote_valid_until_utc=quote.valid_until_utc, grant_valid_until_utc=parent.valid_until_utc,
                            request_deadline_utc=request.envelope.deadline_utc, binding_deadline_utc=binding.deadline_utc,
                            lease_state=lease.state, reservation_state=reservation[0])
                    finally:
                        store._db.rollback()
            if authorization_group is not None:
                await _numeric_egress_authorization_regression(case, executor, prepared, intent, request, anchor, reader, calls, tmp_path, authorization_group)
                record_stage('numeric_authorization_regressions_passed', admissions=0, mock_http_calls=0)
                # Successful refusal cases may retire only their actual Core
                # prepared/no-admission original. Failure paths retain first DB.
                before_closure = _numeric_state(case, prepared.job_id)
                current_anchor = await transport.v2_current_anchor(client._v2_request, client._v2_handshake,
                    policy.authority_namespace)
                from sylanne3.authority_service.v2_model_egress_contract import ModelEgressDraftV1
                closure = await executor.reconcile_capacity_current_v1(expected_anchor=current_anchor,
                    draft=ModelEgressDraftV1.from_intent(intent), close_prepared=True)
                assert closure['status'] == 'not_dispatched' and not calls
                assert _numeric_state(case, prepared.job_id) == before_closure
                from sylanne3.host import astrbot_model_call as local_registry
                assert intent.call_id not in local_registry._calls
                with case['model_store']._lock:
                    assert case['model_store']._db.execute('SELECT count(*) FROM authority_model_admissions_v2 WHERE call_id=?', (intent.call_id,)).fetchone()[0] == 0
                    assert case['model_store']._db.execute('SELECT count(*) FROM authority_model_egress_observations_v1 WHERE call_id=?', (intent.call_id,)).fetchone()[0] == 0
                (tmp_path / 'life-numeric-not-dispatched-closure.json').write_text(json.dumps(closure, indent=2) + '\n')
                record_stage('numeric_successful_negative_actual_unadmitted_closure',
                    status=closure['status'], mock_http_calls=0, domain_accounting_modified=False)
                return
            record_stage('numeric_execute_begin')
            terminal=await executor.execute_once(intent=intent,expected_anchor=anchor,request=request)
            record_stage('numeric_execute_returned', terminal_returned=type(terminal) is ModelTerminalReceiptV2,
                         mock_http_calls=len(calls))
            assert type(terminal) is ModelTerminalReceiptV2 and len(calls)==1
            assert (terminal.call_id,terminal.request_digest,terminal.installation_id)==(
                prepared.call_id,request.digest,prepared.installation_id)
            if time_diagnostic:
                return
            record_stage('numeric_model_terminal', mock_http_calls=len(calls), request_digest=terminal.request_digest,
                         observation_digest=terminal.observation_digest, report_digest=terminal.report_digest)
            # The donor's original channel may have retired while actual Life
            # execution ran. Re-authenticate that client through the installed
            # APIs and bind its cost port to the newly issued channel grant.
            from sylanne3.host.model_terminal_cost_port import InstalledModelTerminalCostPort
            from sylanne3.host.accounting_maintenance_port import InstalledAccountingMaintenancePort
            donor=case['authority_client']
            assert (await donor.status_v2()).state=='paired'
            donor_grant=await donor.installation_grant_v2()
            assert same_installed_grant_identity_v2(case['client_grant'],donor_grant)
            graph._GraphCoordinator__model_terminal_cost_port=InstalledModelTerminalCostPort(
                client=donor,bundle=case['installed_bundle'],grant=donor_grant,
                owner_loop=asyncio.get_running_loop())
            graph._GraphCoordinator__accounting_maintenance_port=InstalledAccountingMaintenancePort(
                client=donor,bundle=case['installed_bundle'],grant=donor_grant,
                owner_loop=asyncio.get_running_loop())
            def settle():
                fact=read_original_model_cost(graph._GraphCoordinator__model_terminal_cost_port,intent)
                result=graph._commit_original_model_cost_v1(case['bootstrap'],ns,intent,
                    quote_id=prepared.quote_id,quote_version=prepared.quote_version,work_kind=WORK_KIND)
                assert type(result) is OriginalModelCostCommitV1
                return result
            cost=await asyncio.to_thread(settle)
            assert cost.call_id==prepared.call_id
            def ledger():
                return tuple(store._db.execute('SELECT phase,digest,receipt_json FROM runtime_budget_operations '
                    'WHERE bot_id=? AND persona_id=? AND operation_id=? ORDER BY phase',(*ns.as_tuple,prepared.prepare_operation_id)))
            before=await asyncio.to_thread(ledger)
            assert [r[0] for r in before]==['reserve','settle']
            record_stage('numeric_cost_settled', commit_seq=cost.commit_seq, budget_phases=[r[0] for r in before])
            assert await executor.recover_original_terminal(intent)==terminal and len(calls)==1
            again=await asyncio.to_thread(settle)
            assert again.commit_seq==cost.commit_seq and await asyncio.to_thread(ledger)==before
            assert len(calls)==1
            from sylanne3.authority_service.life_numeric_model_result_service_v1 import InstalledLifeNumericModelResultServiceV1
            from sylanne3.runtime.d06_life_numeric_paid_v1 import (prepare_life_numeric_result_selector_v1,
                record_life_numeric_paid_result_v1,read_life_numeric_cost_commit_v1)
            from sylanne3.runtime.d06_life_numeric_task_v1 import (AdoptInternalLifeNumericRequestV1,
                ADOPT_OPERATION,read_life_numeric_appraisal_acceptance_v1)
            from sylanne3.runtime.jobs import get_job
            service=InstalledLifeNumericModelResultServiceV1(store=model._store,fences=fences,
                graph_db_path=path,d11_issuer=issuer,installation_id=policy.installation_id,
                read_subject=actual_grant.subject,holder=policy.administrator_holder,
                trusted_now_utc=verifier._clock,source_location=model._source_location,graph_reader=reader)
            server.install_life_numeric_model_result_reader_v1(case['authority_namespace'],service)
            original_prepare=service.prepare
            def diagnose_result(**kwargs):
                try:return original_prepare(**kwargs)
                except Exception:traceback.print_exc();raise
            service.prepare=diagnose_result
            def fenced_sql(action):
                def observe(scope):
                    guard,actual=port.get_current_owner_guard_for_fence(namespace=ns,
                        authority_namespace=policy.authority_namespace,permit=scope.permit)
                    assert actual==scope.permit
                    return guard,actual
                authority=AuthorityContext(actual_grant.subject,'d11','life-numeric-read:'+prepared.digest,
                    ns,('activity','event','persona','scene'),'consolidation',(case['life_audience'],),
                    prepared.provider_config_ref,prepared.activation_generation)
                def transaction():
                    db=store._db;db.execute('BEGIN IMMEDIATE')
                    try:
                        value=action(db);db.commit();return value
                    except BaseException:db.rollback();raise
                return graph._read_v2(authority,transaction,fence_observer=observe)
            selector=await asyncio.to_thread(fenced_sql,lambda db:prepare_life_numeric_result_selector_v1(db,
                namespace=ns,issuer=issuer,job_id=prepared.job_id,authority_id=actual_grant.authority_id,
                authority_namespace=policy.authority_namespace))
            delivered=await client.life_numeric_model_result_read_v1(bundle,actual_grant,read_request=selector)
            delivered.require_original(intent,prepared,frozen,binding)
            record_stage('numeric_result_original_read', observation_digest=delivered.observation.digest,
                         read_attempt_digest=delivered.request.digest)
            _,read_state=await asyncio.to_thread(port.get_fence_operation,namespace=ns,
                authority_namespace=policy.authority_namespace,operation_id=selector.read_attempt_id)
            assert read_state=='finished' and not service._inflight_deliveries
            fact=await asyncio.to_thread(read_original_model_cost,graph._GraphCoordinator__model_terminal_cost_port,intent)
            def save_result(db):
                current=reader.read(db,intent,verifier._clock(),allow_accounted_result=True)
                assert (current.prepared,current.binding,current.frozen)==(prepared,binding,frozen)
                assert delivered.terminal_receipt==fact.receipt and delivered.observation.digest==fact.recovery.observation_digest
                read_life_numeric_cost_commit_v1(db,namespace=ns,issuer=issuer,prepared=prepared,intent=intent,terminal=terminal,fact=fact)
                return record_life_numeric_paid_result_v1(db,namespace=ns,issuer=issuer,job_id=prepared.job_id,result_read=delivered,fact=fact)
            await asyncio.to_thread(fenced_sql,save_result)
            paid_refusals = await asyncio.to_thread(_assert_numeric_paid_original_binding_refusals_v1,
                case, prepared, binding)
            assert len(calls) == 1
            record_stage('numeric_paid_original_binding_refusals', cases=paid_refusals)
            operation='life-numeric-adopt:'+prepared.job_id.removeprefix('life-numeric-job:')
            locator=AdoptInternalLifeNumericRequestV1(prepared.episode_ref,
                prepared.causal_operation_id)
            def adopt():
                with numeric_owner(case) as (authority,lease):
                    result=graph.run_current_domain_operation_v1(authority,lease,operation_kind=ADOPT_OPERATION,
                        request=locator,operation_id=operation,activity_id=prepared.activity_id,
                        audience_ref=case['life_audience'],parent_budget_lease_ref=policy.root_grant.lease_id)
                runtime=graph._GraphCoordinator__domain_production_runtime_v1
                if result.get('schema')!='sylanne.domain-production-receipt.v1':
                    error=runtime._last_refusal_exception_v1
                    if error is not None:traceback.print_exception(type(error),error,error.__traceback__)
                assert result['schema']=='sylanne.domain-production-receipt.v1'
                assert len(result['receipt']['write_versions'])==2 and not store._db.in_transaction
                return result
            adopted=await asyncio.to_thread(adopt)
            def cold_appraisal():
                with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
                    db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
                    rows=db.execute("SELECT original_ref FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind='numeric_appraisal_acceptance_v1'",ns.as_tuple).fetchall()
                    assert len(rows)==1
                    acceptance=read_life_numeric_appraisal_acceptance_v1(db,namespace=ns,appraisal_ref=rows[0][0],issuer=issuer)
                    assert acceptance.job_id==prepared.job_id and acceptance.before_digest==case['numeric_before'].digest
                    assert acceptance.operation_id==operation and db.total_changes==0
                    from sylanne3.runtime.jobs import get_job
                    from sylanne3.runtime.d11_types import job_graph_write
                    completed = get_job(db, prepared.job_id)
                    assert (completed.phase,completed.result_ref,completed.lease_holder,
                        completed.lease_expires_utc,completed.fence,completed.cancel_epoch) == (
                        'completed',prepared.call_id,None,None,intent.worker_fence,0)
                    projection = job_graph_write(completed)
                    from sylanne3.runtime_contracts import canonical_serialize
                    assert db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',
                        (projection.key.token,)).fetchone() == (3,canonical_serialize(projection.value),1)
                    assert tuple(row[0] for row in db.execute('SELECT phase FROM runtime_budget_operations '
                        'WHERE operation_id=? ORDER BY phase',(prepared.operation_id,))) == ('reserve','settle')
                    return acceptance
            acceptance=await asyncio.to_thread(cold_appraisal)
            record_stage('numeric_appraisal_adopted', appraisal_ref=acceptance.appraisal_ref, before_digest=acceptance.before_digest)
            assert await asyncio.to_thread(adopt)==adopted and len(calls)==1
            from d04_numeric_life_acceptance_support_v1 import run_life_numeric_interval_acceptance_v1
            record_stage('numeric_native_interval_entered')
            await run_life_numeric_interval_acceptance_v1(case,tmp_path=tmp_path,
                installed_d04_root=installed_d04_root,appraisal_ref=acceptance.appraisal_ref,
                native_wait_diagnostic=native_wait_diagnostic)
            assert len(calls)==1
            record_stage('native_wait_diagnostic_ended_not_full_pass' if native_wait_diagnostic else
                'numeric_native_interval_and_trace_originals_verified', mock_http_calls=len(calls))
        finally:
            record_stage('numeric_mock_http_counter_final', mock_http_calls=len(calls))
            mock.handler=actual_handler
            verifier._current=original_current
            await transport.close()
            if foreign_transport is not None:
                await foreign_transport.close()
    await run_installed_life_before_case(tmp_path,installed_d04_root,
        natural_workflow_builder=life_numeric_workflows,after_before_async=after,
        enable_d04_semantic_drive=True,enable_d04_joint_numeric=True)


@pytest.mark.asyncio
async def test_installed_life_numeric_original_paid_native_interval_and_trace(tmp_path,installed_d04_root):
    await run_installed_life_numeric_fullchain_v1(tmp_path,installed_d04_root)


@pytest.mark.asyncio
async def test_installed_life_numeric_registration_replay_and_cancelled_job(tmp_path, installed_d04_root):
    async def after(case):
        await asyncio.to_thread(prepare_and_acquire, case, registration_checks=True)
    await run_installed_life_before_case(tmp_path, installed_d04_root,
        natural_workflow_builder=life_numeric_workflows, after_before_async=after)


@pytest.mark.asyncio
@pytest.mark.parametrize('group', ('installation', 'lease', 'reservation', 'configuration', 'worker', 'time'))
async def test_installed_life_numeric_egress_authorization_refusals(tmp_path, installed_d04_root, group):
    await run_installed_life_numeric_fullchain_v1(tmp_path, installed_d04_root, authorization_group=group)


@pytest.mark.asyncio
async def test_installed_life_numeric_first_decision_time_probe(tmp_path, installed_d04_root):
    # A bounded diagnostic entrant: no settlement/native/trace pipeline, no
    # altered clock/TTL, and at most the original finite MockTransport call.
    await run_installed_life_numeric_fullchain_v1(tmp_path, installed_d04_root, time_diagnostic=True)


@pytest.mark.asyncio
async def test_installed_life_numeric_native_post_terminal_wait_probe(tmp_path, installed_d04_root):
    # One declared wait diagnosis using current production clocks and originals.
    # Stops after adoption; no full qualification or trace PASS is implied.
    await run_installed_life_numeric_fullchain_v1(tmp_path, installed_d04_root,
        native_wait_diagnostic=True)


def _assert_numeric_paid_original_binding_refusals_v1(case, prepared, binding):
    """Actual signed accounting read; tamper only a private in-memory DB copy."""
    from sylanne3.runtime.d06_life_numeric_paid_v1 import read_life_numeric_paid_result_v1
    from sylanne3.runtime.d11_life_preparation_v1 import TABLE, SIGN_KIND, _read
    from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
    from copy import deepcopy
    ns, issuer, live = case['namespace'], case['d11_issuer'], case['store']._db
    tables = ('runtime_budget_leases', 'runtime_budget_operations', 'runtime_budget_reservations')
    before = {name:tuple(live.execute('SELECT * FROM '+name)) for name in tables}
    changes = live.total_changes
    path = Path(live.execute('PRAGMA database_list').fetchone()[2])
    with sqlite3.connect(path.as_uri()+'?mode=ro', uri=True) as source, sqlite3.connect(':memory:') as db:
        source.execute('PRAGMA query_only=ON'); source.backup(db)
        db.execute('BEGIN')
        original = _read(db, issuer=issuer, namespace=ns, kind='numeric_paid_v1', ref=prepared.job_id)
        paid = read_life_numeric_paid_result_v1(db, namespace=ns, issuer=issuer, job_id=prepared.job_id)
        assert paid[0] == prepared and paid[1] == binding
        assert original[1] == paid[3].operation_id
        ordinary = db.execute('SELECT receipt_json,commit_seq FROM graph_bundle_operations '
            'WHERE bot=? AND persona=? AND operation_id=?', (*ns.as_tuple,binding.acquire_operation_id)).fetchone()
        assert ordinary is not None and json.loads(ordinary[0])['commit_seq'] == ordinary[1]
        db.rollback()
        evidence = []
        for failure in ('ordinary_commit_substitution', 'signed_cost_digest_mismatch'):
            db.execute('BEGIN')
            # Other originals, quote, reservation, terminal and true paid read stay valid.
            assert read_life_numeric_paid_result_v1(db, namespace=ns, issuer=issuer,
                job_id=prepared.job_id)[4] == paid[4]
            if failure == 'ordinary_commit_substitution':
                db.execute('UPDATE '+TABLE+' SET producing_operation_id=? '
                    'WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
                    (binding.acquire_operation_id,*ns.as_tuple,'numeric_paid_v1',prepared.job_id))
            else:
                raw = deepcopy(original[0]); raw['cost_digest'] = 'f'*64
                digest = canonical_digest(raw)
                signature = issuer._signer.sign(SIGN_KIND, canonical_serialize(
                    (ns,'numeric_paid_v1',prepared.job_id,digest)))
                db.execute('UPDATE '+TABLE+' SET payload_json=?,payload_digest=?,signature=? '
                    'WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
                    (canonical_serialize(raw),digest,signature,*ns.as_tuple,'numeric_paid_v1',prepared.job_id))
            with pytest.raises(ValueError, match='paid original lost exact cost/worker membership') as denied:
                _read(db, issuer=issuer, namespace=ns, kind='numeric_paid_v1', ref=prepared.job_id)
            evidence.append({'case':failure,'specific_refusal':str(denied.value),
                'provider_delta':0,'live_accounting_changes':0})
            db.rollback()
    assert live.total_changes == changes
    assert before == {name:tuple(live.execute('SELECT * FROM '+name)) for name in tables}
    return evidence


@pytest.mark.asyncio
@pytest.mark.parametrize('phase', ('prepare', 'acquire'))
async def test_installed_life_numeric_stage_original_mutation_refused(tmp_path, installed_d04_root, phase):
    """Actual valid W01 stage; changing a signed original must prevent its CAS."""
    async def after(case):
        def exercise():
            from sylanne3.runtime import d06_life_numeric_task_v1 as task
            from sylanne3.runtime import d06_life_numeric_worker_v1 as worker
            from sylanne3.runtime.d06_life_numeric_context_v1 import (
                PrepareLifeNumericContextRequestV1, life_numeric_context_ids_v1,
                decode_life_numeric_context_original_v1, KIND)
            from sylanne3.runtime.jobs import get_job
            from sylanne3.runtime.d11_life_preparation_v1 import _read
            from sylanne3.runtime.d06_life_numeric_task_v1 import _identity
            graph, store, ns = case['graph'], case['store'], case['namespace']
            episode, cause = case['episode_ref'], case['life_causal_operation_id']
            context_ids = life_numeric_context_ids_v1(ns, episode)
            def run(kind, request, operation):
                with numeric_owner(case) as (authority, lease):
                    return graph.run_current_domain_operation_v1(authority, lease,
                        operation_kind=kind, request=request, operation_id=operation,
                        activity_id=case['life_activity_id'], audience_ref=case['life_audience'],
                        parent_budget_lease_ref=case['policy'].root_grant.lease_id)
            result = run('prepare_internal_life_numeric_context',
                PrepareLifeNumericContextRequestV1(episode, cause), context_ids['operation'])
            assert result['schema'] == 'sylanne.domain-production-receipt.v1'
            with store._lock:
                store._db.execute('BEGIN')
                try:
                    saved = _read(store._db, namespace=ns, issuer=case['d11_issuer'],
                        kind=KIND, ref=context_ids['original'])
                    original = decode_life_numeric_context_original_v1(saved[0])
                finally:
                    store._db.rollback()
            ids = internal_life_numeric_ids_v1(_identity(original))
            if phase == 'acquire':
                result = run('prepare_internal_life_numeric',
                    task.PrepareInternalLifeNumericRequestV1(episode, cause), ids['prepare'])
                assert result['schema'] == 'sylanne.domain-production-receipt.v1'
            tables = ('runtime_budget_leases', 'runtime_budget_grants',
                'runtime_budget_operations', 'runtime_budget_reservations', 'runtime_jobs')
            def accounting():
                return {name: store._db.execute('SELECT * FROM ' + name + ' ORDER BY rowid').fetchall()
                    for name in tables}
            before = accounting()
            signature_before = store._db.execute('SELECT signature FROM graph_d11_life_originals_v1 '
                'WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
                (*ns.as_tuple, KIND, context_ids['original'])).fetchone()
            module = task if phase == 'prepare' else worker
            name = 'verify_life_numeric_' + ('preparation' if phase == 'prepare' else 'acquisition') + '_in_transaction_v1'
            actual = getattr(module, name); observed = []
            def changing_original(db, stage, readers, *args):
                assert actual(db, stage, readers, *args) is stage
                assert db.in_transaction
                changed = db.execute('UPDATE graph_d11_life_originals_v1 SET signature=? '
                    'WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
                    ('invalid-fixture-signature', *ns.as_tuple, KIND, context_ids['original']))
                assert changed.rowcount == 1
                reason = 'Life numeric ' + ('preparation' if phase == 'prepare' else 'acquisition') + ' qualification changed before CAS'
                with pytest.raises(ValueError, match=reason) as denied:
                    actual(db, stage, readers, *args)
                observed.append(str(denied.value))
                raise denied.value
            setattr(module, name, changing_original)
            try:
                if phase == 'prepare':
                    result = run('prepare_internal_life_numeric',
                        task.PrepareInternalLifeNumericRequestV1(episode, cause), ids['prepare'])
                else:
                    result = run('acquire_internal_life_numeric',
                        worker.AcquireInternalLifeNumericRequestV1(episode, cause), ids['acquire'])
            finally:
                setattr(module, name, actual)
            assert result.get('schema') != 'sylanne.domain-production-receipt.v1'
            assert len(observed) == 1
            assert accounting() == before
            assert store._db.execute('SELECT signature FROM graph_d11_life_originals_v1 '
                'WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
                (*ns.as_tuple, KIND, context_ids['original'])).fetchone() == signature_before
            if phase == 'prepare':
                assert store._db.execute('SELECT 1 FROM runtime_jobs WHERE job_id=?', (ids['job'],)).fetchone() is None
            else:
                job = get_job(store._db, ids['job'])
                assert job.phase == 'queued' and job.fence == 0
            return {'phase': phase, 'valid_actual_stage_verified': True,
                'reason': observed[0], 'accounting_unchanged_after_rollback': True,
                'original_signature_restored_by_transaction_rollback': True}
        transport = case['model_http_client']._transport
        actual_handler = transport.handler; calls = []
        def counted(request):
            calls.append(request.url.host); return actual_handler(request)
        transport.handler = counted
        try:
            result = await asyncio.to_thread(exercise)
            assert not calls
            result['mock_http_calls'] = 0
            (tmp_path / ('life-numeric-stage-mutation-' + phase + '.json')).write_text(
                json.dumps(result, indent=2) + '\n')
        finally:
            transport.handler = actual_handler
    await run_installed_life_before_case(tmp_path, installed_d04_root,
        natural_workflow_builder=life_numeric_workflows, after_before_async=after)
