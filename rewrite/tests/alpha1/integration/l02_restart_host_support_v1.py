"""Real Linux Host restart around unchanged installed foreground originals.

Fixture locators carry no authority. Every actor opens fresh official Host
connections and reconstructs the installed Runtime/D07 consumer. The parent
keeps Core alive and the existing C09 gate authenticates process retirement.
"""
from contextlib import asynccontextmanager
from dataclasses import dataclass, asdict, replace
import asyncio
import hashlib
import json
import multiprocessing
import os
from datetime import datetime, timezone
from pathlib import Path
import traceback


@dataclass(frozen=True)
class L02RestartLocatorsV1:
    c02_operation_id: str
    source_ref: str
    namespace_creation_operation_id: str
    parent_job_id: str
    c3_job_id: str
    prepared_digest: str


@dataclass(frozen=True)
class L02OfflineLocatorsV1:
    namespace_creation_operation_id: str
    schedule_ref: str
    schedule_original_digest: str


def _l02_initial_configuration_wire_v1(initial):
    from cryptography.hazmat.primitives import serialization
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    if type(initial) is not M1PhaseFixtureInstallationV2:
        raise TypeError('actual protected initial fixture configuration required')
    names = ('profile_id', 'profile_root', 'package_root', 'data_dir', 'authority_store',
        'server_certificate', 'server_private_key', 'administrator_certificate', 'administrator_private_key',
        'initial_bundle', 'counter_policy')
    raw = {name: getattr(initial, name) for name in names}
    # This is the finite provider's original synthetic billing key, never an
    # Authority/Core key or a live SDK/issuer/connection object.
    raw['simulated_provider_key'] = initial.simulated_provider_key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return raw


def _l02_initial_configuration_from_wire_v1(raw):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    names = {'profile_id', 'profile_root', 'package_root', 'data_dir', 'authority_store',
        'server_certificate', 'server_private_key', 'administrator_certificate', 'administrator_private_key',
        'initial_bundle', 'counter_policy', 'simulated_provider_key'}
    if type(raw) is not dict or set(raw) != names:
        raise ValueError('closed initial L02 fixture material required')
    fields = dict(raw)
    fields['simulated_provider_key'] = Ed25519PrivateKey.from_private_bytes(raw['simulated_provider_key'])
    return M1PhaseFixtureInstallationV2(**fields)


@asynccontextmanager
async def open_l02_restarted_runtime_v1(material, *, initial_configuration, namespace_creation_operation_id):
    from c09_life_host_bootstrap_v1 import open_life_host_bootstrap_v1
    from sylanne3.graph_worker import GraphWorker
    from sylanne3.runtime_context import RuntimeContext
    from sylanne3.runtime.d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
    from sylanne3.runtime.d11_host_lifecycle_v1 import InstalledHostLifecycleObserverV1
    async with open_life_host_bootstrap_v1(material, l02_initial_issuers_v1=True) as case:
        from d11_life_host_actor_support_v1 import _install_model_context
        from m1_artifact_draft_acceptance_support_v1 import build_m1_phase_mock_client_v2
        from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
        if type(initial_configuration) is not M1PhaseFixtureInstallationV2:
            raise TypeError('original closed initial M1 fixture configuration required')
        graph, bundle = case['graph'], case['installed_bundle']
        if (initial_configuration.package_root != Path(material.package_root)
                or initial_configuration.initial_bundle.installation_policy != bundle.installation_policy
                or initial_configuration.workflows != bundle.model_workflows):
            raise ValueError('fresh Host initial provider/installation differs')
        original_http = _install_model_context(case, material)
        await case['model_provider'].client.close()
        await original_http.aclose()
        sdk, http_client, mode, calls = build_m1_phase_mock_client_v2(initial_configuration,
            '请确认这条独立任务已收到。', provider_cache=case['c09_provider_cache'])
        case['model_provider'].client = sdk
        case['model_http_client'] = http_client
        case['model_reply_mode'] = mode
        case['l02_provider_calls'] = calls
        model_context = case['model_context']
        worker = await GraphWorker.start(lambda: case['store'], lambda store: graph)
        runtime = RuntimeContext(material.data_dir, package_root=material.package_root, dependencies=None)
        service = None
        try:
            runtime._worker, runtime._v2_coordinator = worker, graph
            runtime._v2_bootstrap, runtime._v2_port = case['bootstrap'], case['port']
            runtime._v2_namespace, runtime._v2_policy = material.namespace, bundle.installation_policy
            runtime._v2_installation_grant, runtime._v2_model_bundle = case['client_grant'], bundle
            runtime._v2_provision = lambda current_graph, operation_id: current_graph.provision_namespace_v2(
                case['bootstrap'], bundle.installation_policy, operation_id=operation_id)
            await runtime.provision_installed_namespace(namespace_creation_operation_id)
            installation = graph._GraphCoordinator__d04_installed_joint_assembly
            owner_loop = asyncio.get_running_loop()
            service = await worker.call(lambda current_graph: InstalledD07ExecutionServiceV1(
                graph=current_graph, bootstrap=case['bootstrap'], bundle=bundle, installation=installation,
                worker=worker, authority_client=case['authority_client'], client_grant=case['client_grant'],
                context=model_context, owner_loop=owner_loop))
            runtime._v2_d07_execution_service = service
            await worker.call(lambda current_graph: setattr(current_graph,
                '_GraphCoordinator__d07_execution_service_v1', service))
            runtime._host_lifecycle_observer = InstalledHostLifecycleObserverV1(runtime)
            yield runtime, installation, case
        finally:
            await runtime.stop()
            await sdk.close()
            await http_client.aclose()


async def resume_l02_original_c3_v1(runtime, installation, locators):
    from sylanne3.runtime.d07_execution_v1 import read_prepared_d07_execution_v1, D07IngressRecallPreparedV1
    from sylanne3.runtime.jobs import get_job
    from sylanne3.runtime.d07_execution_v1 import read_d07_original_v1
    from sylanne3.runtime_contracts import canonical_digest
    def read(graph):
        current = graph.read_current_ingress_recall_resume_v1(runtime._v2_bootstrap,
            runtime._v2_model_bundle, c02_operation_id=locators.c02_operation_id, source_ref=locators.source_ref)
        anchor = runtime._v2_port.current_anchor(namespace=runtime._v2_namespace,
            authority_namespace=runtime._v2_policy.authority_namespace)
        store = graph._GraphCoordinator__store
        with store._lock:
            prepared = read_prepared_d07_execution_v1(store._db, graph._GraphCoordinator__d11_issuer,
                runtime._v2_namespace, locators.c3_job_id)
            if (type(prepared) is not D07IngressRecallPreparedV1 or prepared.digest != locators.prepared_digest
                    or prepared.c02_operation_id != locators.c02_operation_id):
                raise ValueError('cold C3 locator differs from signed original preparation')
            parent, child = get_job(store._db, locators.parent_job_id), get_job(store._db, locators.c3_job_id)
            if current['c3_job'] != child or current['prepared'] != prepared:
                raise ValueError('current parent maps to another C3 child')
            reservations = tuple(store._db.execute('SELECT operation_id,digest,state FROM runtime_budget_reservations '
                'WHERE operation_id=? ORDER BY operation_id', (prepared.operation_id,)))
            prepare_commit = read_d07_original_v1(store._db, graph._GraphCoordinator__d11_issuer,
                runtime._v2_namespace, 'prepare_commit', prepared.job_id)
            inventory = json.loads(prepare_commit[0]['post_query_inventory_json'])
            query_types = sorted({row['type_id'] for row in inventory})
            originals = {}
            for kind, ref in (('paid_cost', prepared.job_id), ('body_cost', prepared.job_id),
                    ('execution', 'd07-terminal:' + prepared.call_id)):
                actual = read_d07_original_v1(store._db, graph._GraphCoordinator__d11_issuer,
                    runtime._v2_namespace, kind, ref)
                originals[kind] = None if actual is None else actual[1]
            return dict(parent_phase=parent.phase, parent_fence=parent.fence, child_phase=child.phase,
                child_fence=child.fence, reservation_rows=reservations, routing=current['routing'],
                signed_original_digests=originals, original_query_type_ids=query_types,
                original_access_epoch=prepared.access_epoch, original_delete_epoch=prepared.delete_epoch,
                actual_current_anchor_digest=canonical_digest(asdict(anchor)))
    before = await runtime._worker.call(read)
    result = await runtime.resume_original_post_c02_recall_v1(installation,
        c02_operation_id=locators.c02_operation_id, source_ref=locators.source_ref)
    after = await runtime._worker.call(read)
    if (result['status'] != 'no_history_needed' or after['child_phase'] != 'completed'
            or any(value is None for value in after['signed_original_digests'].values())):
        raise AssertionError('original C3 did not actually adopt and wake its parent')
    repeat = await runtime.resume_original_post_c02_recall_v1(installation,
        c02_operation_id=locators.c02_operation_id, source_ref=locators.source_ref)
    replay = await runtime._worker.call(read)
    if (repeat['status'] != result['status'] or replay['child_fence'] != after['child_fence']
            or replay['reservation_rows'] != after['reservation_rows'] or replay['routing'] != after['routing']
            or replay['signed_original_digests'] != after['signed_original_digests']):
        raise AssertionError('cold continuation replay replaced actual child or reservation originals')
    return dict(before=before, after=after, replay=replay)



async def run_l02_prepare_waiting_actor_v1(material, packet):
    """Initial actual Host produces C1/C02 and the durable C3 wait, without C3 dispatch."""
    from d11_life_host_actor_support_v1 import (_claim_and_initialize_owner, _bind_scene_and_ingress,
        _run_first_ingress, _register_installed_domains)
    from d11_offline_authority_acceptance_support_v1 import install_phase_fixture_recall_owner_policies_v1
    from m1_artifact_draft_acceptance_support_v1 import install_m1_owner_body_and_catalogue_v1
    from sylanne3.runtime.d07_ingress_recall_preparation_v1 import OPERATION, ingress_recall_model_ids_v1
    from sylanne3.runtime.d07_execution_v1 import read_prepared_d07_execution_v1
    from sylanne3.runtime.foreground_cycle_v1 import foreground_cycle_ids_v1, foreground_cycle_from_wire_v1
    from sylanne3.runtime.jobs import get_job
    from sylanne3.memory_types import source_key
    if (type(packet) is not dict or set(packet) != {'schema', 'initial_configuration', 'namespace_creation_operation_id'}
            or packet['schema'] != 'sylanne.l02.prepare-waiting.v1'):
        raise ValueError('closed L02 initial preparation packet required')
    async with open_l02_restarted_runtime_v1(material, initial_configuration=_l02_initial_configuration_from_wire_v1(packet['initial_configuration']),
            namespace_creation_operation_id=packet['namespace_creation_operation_id']) as (runtime, installation, case):
        case['data_dir'] = material.data_dir
        case['m1_initial_configuration'] = _l02_initial_configuration_from_wire_v1(packet['initial_configuration'])
        await _claim_and_initialize_owner(case, material.host_driver_configuration['owner_claim'])
        _register_installed_domains(case, ('d01', 'd03', 'd05', 'd06', 'd07', 'd08'))
        await runtime._worker.call(lambda graph: install_m1_owner_body_and_catalogue_v1(case))
        await runtime._worker.call(lambda graph: install_phase_fixture_recall_owner_policies_v1(case))
        runtime.resume_host_lifecycle_observation_v1()
        startup = runtime._host_lifecycle_startup_task
        if startup is None:
            raise AssertionError('initial actual Host startup was not scheduled')
        await startup
        if runtime._host_lifecycle_startup_receipt is None:
            raise AssertionError(runtime._host_lifecycle_last_status)
        if runtime._offline_recovery_task is not None:
            await runtime._offline_recovery_task
        await _bind_scene_and_ingress(case)
        # A fresh finite input is constructed before its first Source admission.
        # This never edits an already admitted Source or backdates its fact time.
        text = '请确认这条独立任务已收到。'
        case['ingress'] = replace(case['ingress'], message_id='message:l02', text=text)
        case['host'] = replace(case['host'], message_id='message:l02', text=text)
        first, c02 = await _run_first_ingress(case)
        source_ref = source_key(*case['namespace'].as_tuple, case['host'].lineage.source_ref).token
        args = dict(c02_operation_id=c02.operation_id, source_ref=source_ref)
        await runtime._worker.call(lambda graph: graph.prepare_post_c02_foreground_cycle_v1(
            case['bootstrap'], case['installed_bundle'], **args))
        await runtime._worker.call(lambda graph: graph.acquire_post_c02_foreground_cycle_v1(
            case['bootstrap'], case['installed_bundle'], **args))
        need = await runtime.prepare_post_c02_recall_need_v1(installation, **args)
        if need['status'] != 'semantic_route_required':
            raise AssertionError('actual initial C3 need is not a semantic route')
        await runtime._worker.call(lambda graph: graph.run_current_post_c02_ingress_recall_model_operation_v1(
            case['bootstrap'], case['installed_bundle'], operation_kind=OPERATION, **args))
        def original(graph):
            ns, store, issuer = case['namespace'], case['store'], case['d11_issuer']
            with store._lock:
                parent_id = foreground_cycle_ids_v1(ns, c02.operation_id)[1]
                child_id = ingress_recall_model_ids_v1(ns, c02.operation_id)['job']
                prepared = read_prepared_d07_execution_v1(store._db, issuer, ns, child_id)
                parent, child = get_job(store._db, parent_id), get_job(store._db, child_id)
                wait = foreground_cycle_from_wire_v1(parent.continuation).wait
                if (parent.phase != 'waiting' or parent.lease_holder is not None or child.phase != 'queued'
                        or child.fence != 0 or wait is None or wait.producer_domain != 'd07'
                        or wait.event_kind != 'ingress_recall_model_terminal'):
                    raise AssertionError('actual producer did not durably register its C3 waiting state')
                return L02RestartLocatorsV1(c02.operation_id, source_ref,
                    packet['namespace_creation_operation_id'], parent_id, child_id, prepared.digest)
        locators = await runtime._worker.call(original)
        if len(case['l02_provider_calls']) != 1:
            raise AssertionError('waiting preparation must have only its actual C1 provider call')
        return dict(locators=asdict(locators), provider_call_count=1)


async def run_l02_prepare_offline_actor_v1(material, packet):
    """Actual initial Owner registers only approved role-clock downtime arithmetic."""
    from d11_life_host_actor_support_v1 import _claim_and_initialize_owner, _register_installed_domains
    from test_current_domain_production_v1 import command
    from sylanne3.runtime.d10_offline_inputs_v1 import RegisterCurrentOfflineScheduleInputRequestV1
    from sylanne3.runtime.d11_offline_originals_v1 import read_current_d11_offline_original_ref_v1
    if (type(packet) is not dict or set(packet) != {'schema', 'initial_configuration', 'namespace_creation_operation_id'}
            or packet['schema'] != 'sylanne.l02.prepare-offline.v1'):
        raise ValueError('closed L02 initial offline packet required')
    async with open_l02_restarted_runtime_v1(material, initial_configuration=_l02_initial_configuration_from_wire_v1(packet['initial_configuration']),
            namespace_creation_operation_id=packet['namespace_creation_operation_id']) as (runtime, installation, case):
        case['data_dir'] = material.data_dir
        await _claim_and_initialize_owner(case, material.host_driver_configuration['owner_claim'])
        _register_installed_domains(case, ('d01', 'd03', 'd06', 'd10'))
        request = RegisterCurrentOfflineScheduleInputRequestV1('offline-schedule:l02', 0,
            60, 4, 100, datetime.fromtimestamp(case['policy'].root_grant.valid_until_utc, timezone.utc).isoformat().replace(
                '+00:00', 'Z'), ('consolidation', 'context'))
        registered = await runtime._worker.call(lambda graph: command(case, 'register_offline_schedule', request, producer=True))
        if registered['coverage'] != 'complete':
            raise AssertionError('actual Owner schedule did not commit')
        def locate(graph):
            store = case['store']
            with store._lock:
                rows = store._db.execute("SELECT original_ref FROM graph_d11_offline_originals_v1 WHERE bot=? AND persona=? "
                    "AND kind='registered_schedule' AND producing_operation_id=?", (*case['namespace'].as_tuple,
                    registered['operation_id'])).fetchall()
                if len(rows) != 1:
                    raise AssertionError('actual registered schedule original is unavailable')
                original = read_current_d11_offline_original_ref_v1(store._db, namespace=case['namespace'],
                    original_ref=rows[0][0], issuer=case['d11_issuer'])
                return L02OfflineLocatorsV1(packet['namespace_creation_operation_id'],
                    original.original_ref, original.original_digest)
        locators = await runtime._worker.call(locate)
        runtime.resume_host_lifecycle_observation_v1()
        startup = runtime._host_lifecycle_startup_task
        if startup is None:
            raise AssertionError('actual registered-schedule Host startup was not scheduled')
        await startup
        if runtime._host_lifecycle_startup_receipt is None:
            raise AssertionError(runtime._host_lifecycle_last_status)
        if runtime._offline_recovery_task is not None:
            await runtime._offline_recovery_task
        if case['l02_provider_calls']:
            raise AssertionError('offline initial scope made a model call')
        return dict(locators=asdict(locators), provider_call_count=0)


async def run_l02_c3_reopen_actor_v1(material, packet):
    """New actual process uses only the initial configuration and old locators."""
    if (type(packet) is not dict or set(packet) != {'schema', 'initial_configuration', 'locators'}
            or packet['schema'] != 'sylanne.l02.c3-reopen.v1'
            or type(packet['locators']) is not dict
            or set(packet['locators']) != {'c02_operation_id', 'source_ref', 'namespace_creation_operation_id',
                'parent_job_id', 'c3_job_id', 'prepared_digest'}):
        raise ValueError('closed L02 C3 reopen locator packet required')
    locators = L02RestartLocatorsV1(**packet['locators'])
    async with open_l02_restarted_runtime_v1(material,
            initial_configuration=_l02_initial_configuration_from_wire_v1(packet['initial_configuration']),
            namespace_creation_operation_id=locators.namespace_creation_operation_id) as (runtime, installation, case):
        outcome = await resume_l02_original_c3_v1(runtime, installation, locators)
        outcome['provider_call_count'] = len(case['l02_provider_calls'])
        if outcome['provider_call_count'] > 1:
            raise AssertionError('same original C3 continuation called provider twice')
        return outcome


def _actual_offline_adoptions_v1(graph, namespace):
    from sylanne3.runtime.d11_offline_originals_v1 import TABLE
    from sylanne3.runtime.d11_offline_adoption_v1 import _read_signed, verify_offline_adoption_commit_v1
    from sylanne3.authority_service.d11_offline_tick_bridge_v1 import offline_bridge_from_wire_v1
    from sylanne3.runtime_contracts import canonical_digest
    store, issuer = graph._GraphCoordinator__store, graph._GraphCoordinator__d11_issuer
    with store._lock:
        refs = tuple(row[0] for row in store._db.execute('SELECT original_ref FROM ' + TABLE +
            " WHERE bot=? AND persona=? AND kind='adoption_receipt' ORDER BY original_ref", namespace.as_tuple))
        verified = {}
        for ref in refs:
            original = _read_signed(store._db, namespace, 'adoption_receipt', ref, issuer)
            bridge = _read_signed(store._db, namespace, 'adoption_bridge', ref, issuer)
            actual = offline_bridge_from_wire_v1(bridge[1])
            verify_offline_adoption_commit_v1(store._db, gate=actual, issuer=issuer,
                resource_issuer=issuer.resource_issuer, require_current_metadata=False)
            if actual.terminal.status != 'completed' or original[1]['status'] != 'completed':
                raise AssertionError('actual offline tick has no completed simulated adoption')
            verified[ref] = dict(receipt_digest=canonical_digest(original[1]),
                terminal_digest=canonical_digest(actual.terminal), actual_cpu_ms=original[1]['actual_cpu_ms'])
        return verified


async def run_l02_offline_reopen_actor_v1(material, packet):
    """Actual registered Host reconnect and product offline recovery only."""
    if (type(packet) is not dict or set(packet) != {'schema', 'initial_configuration', 'locators'}
            or packet['schema'] != 'sylanne.l02.offline-reopen.v1'):
        raise ValueError('closed L02 offline reopen packet required')
    locators = L02OfflineLocatorsV1(**packet['locators'])
    async with open_l02_restarted_runtime_v1(material,
            initial_configuration=_l02_initial_configuration_from_wire_v1(packet['initial_configuration']),
            namespace_creation_operation_id=locators.namespace_creation_operation_id) as (runtime, installation, case):
        def verify_schedule(graph):
            from sylanne3.runtime.d11_offline_originals_v1 import read_current_d11_offline_original_ref_v1
            with case['store']._lock:
                actual = read_current_d11_offline_original_ref_v1(case['store']._db, namespace=runtime._v2_namespace,
                    original_ref=locators.schedule_ref, issuer=case['d11_issuer'])
                if actual.original_digest != locators.schedule_original_digest:
                    raise AssertionError('offline cold locator differs from actual signed schedule')
        await runtime._worker.call(verify_schedule)
        before = await runtime._worker.call(lambda graph: _actual_offline_adoptions_v1(graph, runtime._v2_namespace))
        runtime.resume_host_lifecycle_observation_v1()
        startup = runtime._host_lifecycle_startup_task
        if startup is None:
            raise AssertionError('actual Host lifecycle startup was not scheduled')
        await startup
        if runtime._host_lifecycle_startup_receipt is None:
            raise AssertionError(runtime._host_lifecycle_last_status)
        recovery = runtime._offline_recovery_task
        if recovery is not None:
            await recovery
        first = runtime._offline_recovery_last_status
        adopted = await runtime._worker.call(lambda graph: _actual_offline_adoptions_v1(graph, runtime._v2_namespace))
        if not set(adopted) - set(before):
            raise AssertionError('actual downtime produced no newly adopted signed offline tick')
        runtime.resume_offline_recovery_v1()
        replay = runtime._offline_recovery_task
        if replay is not None:
            await replay
        second = runtime._offline_recovery_last_status
        repeated = await runtime._worker.call(lambda graph: _actual_offline_adoptions_v1(graph, runtime._v2_namespace))
        if repeated != adopted:
            raise AssertionError('offline replay duplicated its original execution/adoption/cost')
        if first is None or first['status'] == 'held' or second is None or second['status'] != 'idle':
            raise AssertionError({'first': first, 'replay': second})
        if case['l02_provider_calls']:
            raise AssertionError('role-clock recovery made a model call')
        return dict(startup_operation_id=runtime._host_lifecycle_startup_receipt['operation_id'],
            first_status=first['status'], replay_status=second['status'], provider_call_count=0,
            signed_adoptions=adopted, signed_replay_adoptions=repeated)


@dataclass(frozen=True)
class L02ParentAuthorityServicesV1:
    control: object
    gate: object
    close_host_handles: object
    authenticate_phase: object
    namespace_creation_operation_id: str


async def run_l02_restart_host_sequence_v1(material, parent, *, initial_configuration, scenario):
    """Initial parent owns only Authority; each business Host has a real lifetime."""
    if type(parent) is not L02ParentAuthorityServicesV1 or scenario not in {'c3_restart', 'offline_restart'}:
        raise TypeError('named L02 initial parent/scenario required')
    if parent.gate.control is not parent.control or parent.gate._peers or parent.gate._active:
        raise ValueError('L02 initial supervisor must precede its first real Host admission')
    await parent.close_host_handles()
    source = Path(__file__)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    initial = dict(schema='sylanne.l02.prepare-waiting.v1' if scenario == 'c3_restart' else
        'sylanne.l02.prepare-offline.v1', initial_configuration=_l02_initial_configuration_wire_v1(initial_configuration),
        namespace_creation_operation_id=parent.namespace_creation_operation_id)
    first = await run_l02_actual_host_process_v1(material, control=parent.control, gate=parent.gate,
        driver_module=source.stem, driver_function='run_l02_prepare_waiting_actor_v1' if scenario == 'c3_restart' else
        'run_l02_prepare_offline_actor_v1', driver_digest=digest, packet=initial)
    # Only after actual kernel retirement may the original parent authenticate
    # the returned locator against its real Core/D11/Graph signed originals.
    await parent.authenticate_phase(first, phase='waiting' if scenario == 'c3_restart' else 'offline_registered')
    if scenario == 'offline_restart':
        # The actual schedule's original minimum 60-second cadence is retained.
        # Two finite non-busy waits happen only after observed Host process exit.
        await asyncio.sleep(30)
        await asyncio.sleep(30)
    cold = dict(schema='sylanne.l02.c3-reopen.v1' if scenario == 'c3_restart' else
        'sylanne.l02.offline-reopen.v1', initial_configuration=_l02_initial_configuration_wire_v1(initial_configuration),
        locators=first['outcome']['locators'])
    second = await run_l02_actual_host_process_v1(material, control=parent.control, gate=parent.gate,
        driver_module=source.stem, driver_function='run_l02_c3_reopen_actor_v1' if scenario == 'c3_restart' else
        'run_l02_offline_reopen_actor_v1', driver_digest=digest, packet=cold)
    proof = await parent.authenticate_phase(second, phase='adopted' if scenario == 'c3_restart' else 'offline_adopted')
    if first['process_identity'] == second['process_identity']:
        raise AssertionError('L02 did not actually restart a distinct Host process')
    return dict(first=first, restarted=second, original_proof=proof,
        scope='actual C1/C3 original process recovery' if scenario == 'c3_restart' else
        'actual registered role-clock offline arithmetic only')


async def run_installed_l02_case_v1(initial_configuration, *, scenario):
    """New donor branch retains the original protected initial policy bytes."""
    from test_d04_owner_semantic_initialization_v3 import real_owner_case
    captured = []
    async def runner(material, parent):
        result = await run_l02_restart_host_sequence_v1(material, parent,
            initial_configuration=initial_configuration, scenario=scenario)
        captured.append(result)
        return result
    await real_owner_case(initial_configuration.data_dir, 'owned', installed_package_root=initial_configuration.package_root,
        initial_phase_fixture_installation=initial_configuration, l02_restart_runner=runner,
        enable_c09_maintenance=True, enable_d10_offline_ticks=True, enable_d04_root_cpu=True,
        enable_c04_body_work=True, enable_d12_package_maintenance=True,
        extra_owner_purposes=('context', 'consolidation'))
    if len(captured) != 1:
        raise AssertionError('named L02 initial fixture did not run its actual Host supervisor')
    return captured[0]


def _l02_child(material, driver_module, driver_function, driver_digest, packet, connection):
    import importlib
    from c09_life_host_process_support_v1 import _require_product_origins, _write_host_import_evidence_v1
    try:
        asyncio.events._set_running_loop(None)
        _require_product_origins(material.package_root)
        module = importlib.import_module(driver_module)
        if hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest() != driver_digest:
            raise ValueError('L02 actual driver source pin differs')
        driver = getattr(module, driver_function)
        if driver.__module__ != module.__name__ or driver.__closure__ is not None:
            raise TypeError('L02 driver must be explicit top-level source')
        connection.send({'phase': 'ready', 'pid': os.getpid()})
        if connection.recv() != {'phase': 'start', 'pid': os.getpid()}:
            raise ValueError('L02 Host has not been admitted by actual C09 supervisor')
        outcome = asyncio.run(driver(material, packet))
        _write_host_import_evidence_v1(material.package_root, 'host-pre-exit')
        connection.send({'phase': 'completed', 'pid': os.getpid(), 'outcome': outcome})
    except BaseException as exc:
        connection.send({'phase': 'failed', 'pid': os.getpid(), 'exception': type(exc).__name__,
            'frames': [{'file': Path(f.filename).name, 'line': f.lineno, 'function': f.name}
                for f in traceback.extract_tb(exc.__traceback__)[-24:]]})
        raise SystemExit(1)
    finally:
        connection.close()


async def run_l02_actual_host_process_v1(material, *, control, gate, driver_module, driver_function,
        driver_digest, packet):
    from c09_life_host_process_support_v1 import _safe_installation_value, _require_product_origins
    from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1, require_process_retired_v1
    _safe_installation_value(packet)
    _require_product_origins(material.package_root)
    if gate.control is not control:
        raise ValueError('same installed C09 supervisor required')
    current = control.read_verified_current_storage_v1()
    current.require_current('business')
    fork = multiprocessing.get_context('fork')
    parent_pipe, child_pipe = fork.Pipe(duplex=True)
    process = fork.Process(target=_l02_child, args=(material, driver_module, driver_function,
        driver_digest, packet, child_pipe), name='sylanne-l02-host')
    process.start()
    child_pipe.close()
    identity = read_process_identity_v1(process.pid)
    try:
        if not await asyncio.to_thread(parent_pipe.poll, 30):
            raise AssertionError('L02 fresh Host did not reach admission barrier')
        if parent_pipe.recv() != {'phase': 'ready', 'pid': process.pid} or identity is None:
            raise AssertionError('L02 fresh Host kernel identity unavailable')
        if read_process_identity_v1(process.pid) != identity or not process.is_alive():
            raise AssertionError('L02 Host kernel identity changed before actual admission')
        latest = control.read_verified_current_storage_v1()
        latest.require_current('business')
        if (latest.pointer_version, latest.storage_generation, latest.manifest_digest) != (
                current.pointer_version, current.storage_generation, current.manifest_digest):
            raise ValueError('L02 selected current C09 generation changed before admission')
        gate.register_peer_process_v1(peer=(material.peer.certificate_sha256, material.request.profile_id),
            process_id=process.pid, process_incarnation='l02-host:' + identity['birth'],
            pointer_version=current.pointer_version, storage_generation=current.storage_generation)
        parent_pipe.send({'phase': 'start', 'pid': process.pid})
        if not await asyncio.to_thread(parent_pipe.poll, 600):
            raise AssertionError('L02 actual Host exceeded finite fixture window')
        result = parent_pipe.recv()
        await asyncio.to_thread(process.join, 10)
        retirement = require_process_retired_v1(identity)
        if process.is_alive() or process.exitcode != 0 or result['phase'] != 'completed':
            raise AssertionError(result)
        return dict(process_identity=identity, actual_exit_code=process.exitcode, retirement=retirement,
            outcome=result['outcome'])
    finally:
        if process.is_alive():
            process.terminate()
            await asyncio.to_thread(process.join, 5)
        if process.is_alive():
            process.kill()
            await asyncio.to_thread(process.join, 5)
        parent_pipe.close()
