"""Installed completed content Life enters genuine C09 source maintenance.

Fresh synthetic installation only. This node is deliberately fail-closed until
its real registered Host can satisfy the maintenance lifecycle. It neither
substitutes an empty writer gate nor fabricates a private archive capability.
The Host actor driver owns its terminal cleanup; the original one-process
Life logout/cold-business tail is not covered. Physical completion requires all
independent Authority phases and the final nonempty factual read to pass.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
from uuid import uuid4

import pytest
from test_installed_internal_life_content_fullchain_v1 import (
    installed_d04_root, run_installed_life_content_fullchain_v1,
)


def _prepare_actual_maintenance(case):
    from sylanne3.authority_service.current_erasure_service import CurrentErasureAuthority
    from sylanne3.authority_service.current_accepted_erasure_read import CurrentAcceptedErasureReadService
    from sylanne3.authority_service.v2_deletion_graph_read import AuthorityV2DeletionGraphReadService
    from sylanne3.authority_service.erasure_closure_inventory import AuthorityErasureClosureInventory, SurfaceTargetV1
    from sylanne3.authority_service.c09_storage_control_v1 import SURFACES
    from sylanne3.authority_service.c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
    from sylanne3.authority_service.c09_surface_cleanup_v1 import InstalledC09SurfaceCleanupV1
    from sylanne3.authority_service.linux_bootstrap_v1 import build_initial_inventory_v1

    graph, store, core, server = (case[name] for name in ('graph', 'store', 'core', 'server'))
    ns, auth_ns, policy = (case[name] for name in ('namespace', 'authority_namespace', 'policy'))
    peer, subject = case['peer'], case['client_grant'].subject
    gate = case['c09_writer_gate']
    control = gate.control
    close_apply = control._applied_reader
    assert gate.control is control and gate._peers, 'actual previously registered writer gate required'
    assert case['d11_issuer'].resource_issuer is case['d02_issuer']
    context = control.read_verified_current_storage_v1()
    context.require_current('business')
    graph_path = Path(store._db.execute('PRAGMA database_list').fetchone()[2]).resolve(strict=True)
    files = {member['role']: Path(member['resolved_path']) for member in context.manifest['members']}
    assert files['graph'] == graph_path
    managed = graph_path.parent / 'offline-managed-artifacts'
    directories = {name: managed / name for name in ('controlled_backup', 'export', 'rebuild_temp', 'cache')}
    inventory = build_initial_inventory_v1(authority_id=control.authority_id,
        installation_id=control.installation_id, namespace=auth_ns, files=files, directories=directories)
    assert inventory.manifest_digest == context.manifest['inventory_manifest_digest']
    provider = case['c09_provider_cache']
    assert provider.recorded_request_count() > 0, 'actual request cache must begin before the first model call'
    provider.bind(authority_id=control.authority_id, installation_id=control.installation_id, namespace=auth_ns)
    provider_cleaner = provider.installed_disposition()

    scoped, recovery = close_apply.scoped, close_apply.recovery
    fences = server._v2_fences[auth_ns]
    pending = AuthorityV2DeletionGraphReadService(fence_service=fences, owner_tickets=server._v2_owner_tickets)
    erasure = CurrentErasureAuthority(recovery, graph_coordinator=graph,
        graph_bootstrap=case['bootstrap'], namespace_id=ns, pending_graph_reader=pending,
        installation_id=policy.installation_id, fence_service=fences,
        owner_sessions=server._v2_owner_sessions, owner_tickets=server._v2_owner_tickets,
        scoped_store=scoped, plan_graph_coordinator=graph, graph_db_path=graph_path)
    accepted_reader = CurrentAcceptedErasureReadService(fence_service=fences,
        owner_tickets=server._v2_owner_tickets, scoped_store=scoped)
    server.install_current_erasure_prepare(auth_ns, policy.installation_id, erasure)
    server.install_current_accepted_erasure_read(auth_ns, policy.installation_id, accepted_reader)
    authority, lease, _ = graph.grant_current_owner(case['bootstrap'], actor='owner-actor-reply',
        namespace=ns, domains=('d06',), purpose='context', audience=case['life_audience'],
        activation_generation=1, owner_session_token=case['owner_session_token'],
        owner_session_request=case['owner_session_request'])
    operation = str(uuid4())
    try:
        plan = graph.issue_current_c09_erasure_plan_v1(authority, lease,
            operation_id=operation, source_ref=case['source_ref'])
        receipt, permit = erasure.prepare_request(credential=peer, subject=subject,
            holder=policy.administrator_holder, installation_id=policy.installation_id,
            owner_actor_id='owner-actor-reply', owner_session_token=case['owner_session_token'],
            owner_session_request=case['owner_session_request'], deletion_operation_id=operation,
            source_id=plan.source_id)
        graph.commit_current_c09_source_barrier_v1(case['bootstrap'], namespace=ns,
            deletion_operation_id=operation, permit=permit)
        accepted, _ = erasure.accept_verified_graph_barrier(credential=peer, subject=subject,
            pending_mutation_id=receipt.pending.mutation_id)
    finally:
        graph.release_current_owner_lease(case['bootstrap'], lease)
    closure = AuthorityErasureClosureInventory(scoped=scoped, installation_id=policy.installation_id)
    core.install_current_c09_recovery_readers_v4(closure=closure, graph=store, namespace_id=ns,
        resource_issuer=case['d02_issuer'], budget_job_issuer=case['d11_issuer'],
        body_authority=graph._GraphCoordinator__body_quote_authority,
        internal_services=dict(core._execution_redaction_c04_services.get(auth_ns, {})))
    cleaners = {name: InstalledC09SurfaceCleanupV1(control=control, gate=gate,
        inventory_manifest=inventory, surface=name, registry=store._registry)
        for name in SURFACES - {'model_prompt_caches'}}
    cleaners['model_prompt_caches'] = provider_cleaner
    maintenance = InstalledC09MaintenanceV1(control=control, gate=gate, core=core, closure=closure,
        graph=store, namespace_id=ns, accepted_service=accepted_reader,
        inventory_manifest=inventory, target_directory=directories['rebuild_temp'],
        subject=subject, credential=peer,
        service_handles=tuple(dict.fromkeys((store, case['c09_authority_graph_store']))), surface_services=cleaners,
        close_apply_service=close_apply)
    targets = tuple(SurfaceTargetV1(name,
        'sqlite_execution_journal' if name == 'execution_journal_payloads' else 'installed_current_four_store',
        str(files['execution']) if name == 'execution_journal_payloads' else str(graph_path.parent),
        'c09.installed.v1', closure.execution.journal_id if name == 'execution_journal_payloads' else 'generation:0',
        'installed') for name in sorted(SURFACES))
    closure.install_registry(credential=peer, targets=targets)
    closure.begin_run(credential=peer, subject=subject, accepted_mutation_id=accepted.pending.mutation_id)
    # Actual configured provider coverage is checked before any INTENT. Unknown
    # configurations or unclosed carrier families remain product refusals.
    maintenance._require_historical_provider_cache_coverage_v1()
    result = maintenance.prepare_storage_rebase_v1(operation_id=operation)
    current = control.read_verified_current_storage_v1()
    assert current.stage == 'PREPARED'
    control.verify_original_v1(result, 'prepared_digest')
    # The actual final scan closed the stores under this held gate/lease.
    # Use the product's bounded, reobserved immutable connection helper; an
    # ordinary mode=ro connection may itself change WAL sidecar metadata.
    from sylanne3.authority_service.c09_sanitized_history_v2 import (
        _factual_member_observation_v2, _history_member_connection_v2,
    )
    from sylanne3.authority_service.c09_life_completed_archive_v1 import (
        validate_life_archive_frame_v1, validate_selected_life_carriers_v1,
    )
    from sylanne3.authority_service.erasure_recovery_pin_v4 import read_execution_recovery_facts_v4_locked
    from sylanne3.runtime_contracts import canonical_digest
    gate.read_quiescence_original_v1(operation_id=operation)
    with control._db() as protected:
        target_manifest = control._read_manifest(protected, result['new_manifest_digest'])
    source_core = next(member for member in current.manifest['members'] if member['role'] == 'core')
    target_core = next(member for member in target_manifest['members'] if member['role'] == 'core')
    archives = []
    for member in (source_core, target_core):
        observation = _factual_member_observation_v2(control, member)
        with _history_member_connection_v2(control, member, closed_observation=observation) as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            facts = read_execution_recovery_facts_v4_locked(db, auth_ns, operation_id=operation)
            assert facts is not None and facts.facts_digest == result['facts_digest']
            archives.append(validate_life_archive_frame_v1(db, control, facts, required=True))
            db.rollback()
    assert archives[0] == archives[1]
    original = archives[0]
    job = canonical_digest(case['content_prepared'].job_id)
    selected = [item for item in original['completed_jobs'] if item['job_commitment'] == job]
    assert len(selected) == 1 and selected[0]['disposition'] == 'derived_removed'
    assert len(original['tables']) == 3 and all(family['present'] and family['rows'] for family in original['tables'])
    target_graph = next(member for member in target_manifest['members'] if member['role'] == 'graph')
    observation = _factual_member_observation_v2(control, target_graph)
    with _history_member_connection_v2(control, target_graph, closed_observation=observation) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        validate_selected_life_carriers_v1(db, original)
        db.rollback()
    assert core._execution_recovery_facts_ports_v4[auth_ns]._life_completed_scope is None
    return result


async def _run_live_prepare(root, installed_root):
    from c09_life_host_process_support_v1 import run_life_host_process_v1
    result = None
    async def after_exit(case, retirement):
        nonlocal result
        import os, hashlib
        import sylanne3.authority_service.c09_life_completed_archive_v1 as archive
        assert Path(archive.__file__).resolve().is_relative_to(installed_root)
        assert retirement is not None
        prepared = await asyncio.to_thread(_prepare_actual_maintenance, case)
        descriptor = case['c09_cold_fixture']
        assert set(descriptor) == {'path', 'fixture_digest'}
        result = {'phase': 'prepare', 'pid': os.getpid(),
            'prepared_digest': prepared['prepared_digest'],
            'operation_id': prepared['operation_id'], 'cold_fixture': descriptor,
            'source_execution_commitment': hashlib.sha256(case['content_source_execution_id'].encode()).hexdigest()}
        return result
    async def host_process_runner(installation, parent):
        return await run_life_host_process_v1(installation=installation, parent=parent,
            after_exit=after_exit)
    state = root / 'state'
    state.mkdir()
    await run_installed_life_content_fullchain_v1(state, installed_root,
        host_process_runner=host_process_runner, enable_c09_maintenance=True,
        c09_protected_root=root / 'protected')
    assert result is not None
    return result


def test_installed_completed_life_authenticates_maintenance_archive(tmp_path, installed_d04_root):
    import json, os, subprocess, sys
    from test_c09_daemon_factual_process_v2 import _installed_phase_environment
    here = Path(__file__).resolve()
    environment, fixture, installed, guard = _installed_phase_environment(tmp_path, here)
    assert installed == Path(installed_d04_root).resolve()
    environment['SYLANNE_D04_INSTALLED_ROOT'] = str(installed)
    script = fixture / 'rewrite/tests/alpha1/integration' / here.name
    outcomes = []
    descriptor = None
    source_execution_commitment = None
    for phase in ('prepare', 'switch', 'release', 'build', 'dispose', 'factual'):
        command = [sys.executable, str(script), phase, str(tmp_path)]
        if descriptor is not None:
            command.extend((descriptor['path'], descriptor['fixture_digest'], source_execution_commitment))
        run, process_receipt = _run_observed_life_phase_v1(command, environment, guard, phase)
        assert run.returncode == 0, f'{phase} failed\n{run.stdout}\n{run.stderr}'
        result = json.loads(run.stdout.strip().splitlines()[-1])
        assert result['phase'] == phase
        assert result['pid'] == run.pid == process_receipt['process_identity']['pid']
        pin = json.loads((guard / ('pin-' + str(result['pid']) + '.json')).read_text())
        assert pin['installed_root'] == str(installed)
        assert pin['manifest_sha256'] == environment['SYLANNE_C09_MANIFEST_SHA256']
        assert pin['engineering_inventory_sha256'] == environment['SYLANNE_C09_ENGINEERING_INVENTORY_SHA256']
        assert pin['process_identity'] == process_receipt['process_identity']
        assert process_receipt['actual_exit_code'] == 0
        assert process_receipt['retirement'] == {
            'original_process': pin['process_identity'], 'state': 'retired'}
        if phase == 'prepare':
            hosts = [json.loads(path.read_text()) for path in guard.glob('host-*-parent-retired.json')]
            assert len(hosts) == 1 and hosts[0]['observer_process_id'] == result['pid']
            host = hosts[0]
            assert host['actual_exit_code'] == 0 and host['retirement'] == {
                'original_process': host['process_identity'], 'state': 'retired'}
            assert host['process_id'] == host['process_identity']['pid'] != result['pid']
            inner_path = Path(host['import_pin']['path']).resolve(strict=True)
            assert inner_path.parent == guard.resolve(strict=True)
            assert hashlib.sha256(inner_path.read_bytes()).hexdigest() == host['import_pin']['sha256']
            inner = json.loads(inner_path.read_text())
            assert inner['process_identity'] == host['process_identity']
            assert inner['installed_root'] == str(installed)
            assert inner['manifest_sha256'] == environment['SYLANNE_C09_MANIFEST_SHA256']
            assert inner['engineering_inventory_sha256'] == environment['SYLANNE_C09_ENGINEERING_INVENTORY_SHA256']
            descriptor = result['cold_fixture']
            source_execution_commitment = result['source_execution_commitment']
        outcomes.append(result)
    assert len({row['pid'] for row in outcomes}) == len(outcomes)
    assert outcomes[-1]['execution_count'] > 0 and outcomes[-1]['files_unchanged'] > 0
    (tmp_path / 'life-c09-phase-outcomes.json').write_text(json.dumps(outcomes, sort_keys=True))


def _run_observed_life_phase_v1(command, environment, guard, phase):
    """Observe this Popen child, its OS birth, actual exit and retirement."""
    from types import SimpleNamespace
    from sylanne3.authority_service.c09_process_identity_v1 import (
        read_process_identity_v1, require_process_retired_v1,
    )
    process = subprocess.Popen(command, env=environment, cwd=guard,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    identity = None
    receipt = dict(schema='sylanne.test.c09.life-phase-process.v1', phase=phase,
        process_id=process.pid, observer_process_id=os.getpid(), process_identity=None,
        actual_exit_code=None, retirement=None)
    try:
        identity = read_process_identity_v1(process.pid)
        receipt['process_identity'] = identity
        (guard / ('life-phase-' + phase + '-started.json')).write_text(
            json.dumps(receipt, sort_keys=True, indent=2) + '\n')
        assert identity is not None and process.poll() is None, 'phase child birth admission unavailable'
        stdout, stderr = process.communicate(timeout=600)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        receipt['actual_exit_code'] = process.returncode
        if identity is not None:
            receipt['retirement'] = require_process_retired_v1(identity)
        (guard / ('life-phase-' + phase + '-process.json')).write_text(
            json.dumps(receipt, sort_keys=True, indent=2) + '\n')
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    return SimpleNamespace(pid=process.pid, returncode=process.returncode, stdout=stdout, stderr=stderr), receipt


if __name__ == '__main__':
    import json, os, sys
    phase, root = sys.argv[1], Path(sys.argv[2]).resolve(strict=True)
    installed = Path(os.environ['SYLANNE_C09_INSTALLED_ROOT']).resolve(strict=True)
    try:
        if phase == 'prepare':
            outcome = asyncio.run(_run_live_prepare(root, installed))
        else:
            from c09_life_authority_phase_support_v1 import run_life_cold_phase_v1
            outcome = run_life_cold_phase_v1(sys.argv[3], phase, expected_fixture_digest=sys.argv[4], source_execution_commitment=sys.argv[5])
    finally:
        import sitecustomize
        sitecustomize.audit(phase='life-' + phase)
    print(json.dumps(outcome, sort_keys=True))
