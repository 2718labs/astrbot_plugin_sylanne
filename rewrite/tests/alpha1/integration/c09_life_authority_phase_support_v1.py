"""Cold phases for one fresh, test-owned Life/C09 installation.

Initial configuration is signed and persisted before the first Host model
request. Later processes use that original installation, never keys or issuer
claims reconstructed from business records. No normal Host is reopened here.
"""
from contextlib import contextmanager
from dataclasses import asdict
import base64
import hashlib
import json
import os
from pathlib import Path

SCHEMA = 'sylanne.test.c09.life-cold-installation.v1'
_ACTIONS = ('accounting', 'current', 'delete', 'deletion', 'erasure_closure_install',
    'execution', 'execution_redaction_install', 'read', 'write')
_FIELDS = {'schema', 'control', 'namespace', 'authority_namespace', 'peer_certificate',
    'subject', 'holder', 'actions', 'package_root', 'manifest_digest', 'inventory',
    'target_directory', 'runtime_issuer_key', 'admin_d02_key', 'provider_cache',
    'initial_manifest_digest', 'initial_process', 'key_id', 'fixture_digest', 'signature'}


def persist_life_cold_fixture_v1(path, *, core, control, namespace, peer, subject, holder,
        package_root, manifest_digest, inventory, target_directory,
        runtime_issuer_signing_key, admin_d02_signing_key, provider_cache):
    from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1
    from sylanne3.authority_service.c09_storage_control_v1 import canonical
    from sylanne3.graph_coordinator import namespace_ref
    from c09_life_provider_cache_acceptance_v1 import _write_new
    control.lease.require_held()
    current = control.read_verified_current_storage_v1()
    current.require_current('business')
    auth_ns = namespace_ref(namespace)
    if (current.stage != 'READY' or current.pointer_version != 0
            or inventory.manifest_digest != current.manifest['inventory_manifest_digest']
            or Path(core.path).resolve() != Path(next(m['resolved_path'] for m in current.manifest['members'] if m['role'] == 'core')).resolve()
            or subject != 'mtls:sha256:' + peer.certificate_sha256):
        raise ValueError('original first-installation configuration required')
    for action in _ACTIONS:
        core._require(peer, action, auth_ns, holder)
        core._require(peer, action, auth_ns, None)
    with core._tx() as db:
        if db.execute('SELECT COUNT(*) FROM authority_model_egress_v1 WHERE namespace=?', (auth_ns,)).fetchone()[0]:
            raise ValueError('cold configuration must predate the first model request')
    if any(type(key) is not bytes or len(key) < 32 for key in (runtime_issuer_signing_key, admin_d02_signing_key)):
        raise ValueError('original initial fixture key configuration required')
    target = Path(path).absolute()
    if target.parent != control.key_path.parent or any(target.is_relative_to(root) for root in control._roots):
        raise ValueError('test installation configuration must stay in original protected directory')
    cache = provider_cache.installation_material()
    body = dict(schema=SCHEMA, control=dict(control_path=str(control.path), key_path=str(control.key_path),
        lease_path=str(control.lease.path), installation_id=control.installation_id, authority_id=control.authority_id,
        control_store_id=control.control_store_id, key_id=control.key_id, resource_roots=[str(p) for p in control._roots]),
        namespace=list(namespace.as_tuple), authority_namespace=auth_ns, peer_certificate=peer.certificate_sha256,
        subject=subject, holder=holder, actions=list(_ACTIONS), package_root=str(Path(package_root).resolve(strict=True)),
        manifest_digest=manifest_digest, inventory=asdict(inventory), target_directory=str(Path(target_directory).resolve(strict=True)),
        runtime_issuer_key=base64.b64encode(runtime_issuer_signing_key).decode(),
        admin_d02_key=base64.b64encode(admin_d02_signing_key).decode(), provider_cache=cache,
        initial_manifest_digest=current.manifest_digest, initial_process=read_process_identity_v1(os.getpid()))
    original = control.sign_original_v1(SCHEMA, body, 'fixture_digest')
    _write_new(target, canonical(original).encode())
    return {'path': str(target), 'fixture_digest': original['fixture_digest']}


@contextmanager
def open_life_cold_fixture_v1(path, *, expected_fixture_digest):
    from sylanne3.authority_service.c09_storage_control_v1 import C09StorageControlV1, InstalledC09InstanceLeaseV1
    from sylanne3.authority_service.linux_installation_security_v1 import read_installed_bytes_v1
    raw = json.loads(read_installed_bytes_v1(Path(path), limit=262144))
    if type(raw) is not dict or set(raw) != _FIELDS or raw['schema'] != SCHEMA or raw['actions'] != list(_ACTIONS):
        raise ValueError('closed original test installation required')
    if type(expected_fixture_digest) is not str or raw['fixture_digest'] != expected_fixture_digest:
        raise ValueError('initial fixture descriptor differs')
    values = raw['control']
    if type(values) is not dict or set(values) != {'control_path','key_path','lease_path','installation_id',
            'authority_id','control_store_id','key_id','resource_roots'}:
        raise ValueError('closed original Control installation differs')
    if Path(path).resolve(strict=True).parent != Path(values['key_path']).resolve(strict=True).parent:
        raise ValueError('original protected configuration location differs')
    lease = InstalledC09InstanceLeaseV1(values['lease_path'])
    try:
        control = C09StorageControlV1(**{k:v for k,v in values.items() if k != 'lease_path'}, lease=lease)
        control.verify_original_v1(raw, 'fixture_digest')
        yield raw, control
    finally:
        lease.close()


def _inventory(raw):
    from sylanne3.runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2, InstalledResourceV2
    values = dict(raw)
    values['resources'] = tuple(InstalledResourceV2(**{**row, 'content_coverage': tuple(row['content_coverage'])})
        for row in values['resources'])
    return InstallationFilesystemManifestV2(**values)


@contextmanager
def _maintenance(raw, control):
    """Open the selected generation for actual cleanup, with original policy."""
    from sylanne3.runtime_contracts import NamespaceId
    from sylanne3.graph_coordinator import GraphCoordinator
    from sylanne3.graph_store import ProductionGraphStore
    from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
    from sylanne3.authority_service.mtls_server import MtlsPeerCredential
    from sylanne3.authority_service.core import AuthorityServiceCore
    from sylanne3.authority_service.installed_core_verifiers import installed_core_verifier_factory
    from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
    from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
    from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
    from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
    from sylanne3.authority_service.v2_scoped_erasure_store import AuthorityV2ScopedErasureStore
    from sylanne3.authority_service.v2_deletion_recovery_service import AuthorityV2DeletionPendingRecovery
    from sylanne3.authority_service.c09_installed_factory_v1 import _LocalInstalledFencePortV1
    from sylanne3.authority_service.c09_storage_control_v1 import SURFACES
    from sylanne3.authority_service.c09_storage_maintenance_v1 import InstalledC09WriterGateV1, InstalledC09MaintenanceV1
    from sylanne3.authority_service.c09_surface_cleanup_v1 import InstalledC09SurfaceCleanupV1
    from sylanne3.authority_service.c09_close_apply_v1 import InstalledC09CloseApplyV1
    from sylanne3.authority_service.c09_graph_application_v1 import InstalledC09GraphApplicationV1
    from sylanne3.authority_service.erasure_closure_inventory import AuthorityErasureClosureInventory
    from c09_life_provider_cache_acceptance_v1 import ControlledLifeProviderCacheV1

    ns = NamespaceId(*raw['namespace']); ans = raw['authority_namespace']
    peer = MtlsPeerCredential(raw['peer_certificate'])
    def authorizer(credential, action, namespace, holder):
        return (credential == peer and action in _ACTIONS and namespace == ans
            and holder in {None, raw['holder']})
    context = control.read_verified_current_storage_v1()
    if context.stage not in {'PREPARED', 'SWITCHED', 'CLEANED', 'RELEASED'}:
        raise ValueError('cold cleanup requires an existing actual prepared chain')
    members = {member['role']: member for member in context.manifest['members']}
    handles = []
    try:
        deletion = AuthorityV2DeletionGuard(members['deletion']['resolved_path']); handles.append(deletion)
        execution = AuthorityV2ExecutionJournal(members['execution']['resolved_path'], namespace=ans,
            journal_id=members['execution']['incarnation_or_journal_id'], installed_storage_reader=control); handles.append(execution)
        verifiers = installed_core_verifier_factory(deletion, {ans: execution})
        core = AuthorityServiceCore(members['core']['resolved_path'], authorizer=authorizer,
            deletion_verifier=verifiers.deletion, execution_verifier=verifiers.execution,
            effect_verifier=verifiers.effect, dispatch_verifier=verifiers.dispatch); handles.append(core)
        core.install_current_c09_storage_reader_v1(reader=control)
        fences = AuthorityV2FenceStore(core._db, lock=core._lock)
        service = AuthorityV2FenceService(core=core, fences=fences, deletion=deletion, execution=execution, namespace=ans)
        scoped = AuthorityV2ScopedErasureStore(core=core, fences=fences, deletion=deletion, execution=execution, namespace=ans)
        recovery = AuthorityV2DeletionPendingRecovery(core=core, fences=fences, deletion=deletion, execution=execution,
            namespace=ans, scoped_store=scoped)
        registry = load_verified_affect_scheme(Path(raw['package_root']), raw['manifest_digest']).registry.type_registry
        store = ProductionGraphStore(members['graph']['resolved_path'], registry); handles.append(store)
        bootstrap = object()
        graph = GraphCoordinator(store, bootstrap, holder=raw['holder'],
            content_fence_v2=_LocalInstalledFencePortV1(service, peer, raw['subject'], ns))
        app = InstalledC09GraphApplicationV1(control=control, core=core, scoped=scoped, coordinator=graph,
            bootstrap=bootstrap, namespace=ns, subject=raw['subject'], credential=peer)
        close_apply = InstalledC09CloseApplyV1(control=control, service=service, recovery=recovery,
            graph_application=app, subject=raw['subject'], credential=peer)
        control.install_applied_reader_v1(close_apply)
        gate = InstalledC09WriterGateV1(control=control)
        closure = AuthorityErasureClosureInventory(scoped=scoped, installation_id=control.installation_id)
        # These phases consume only the signed PREPARED transition and retained
        # facts. They do not install a live original producer or recreate C04 rights.
        inventory = _inventory(raw['inventory'])
        cache = raw['provider_cache']
        provider = ControlledLifeProviderCacheV1.attach_installed(cache['root'],
            {'id': cache['provider_id'], 'type': 'openai_chat_completion', 'model': 'model-1'},
            authority_id=cache['authority_id'], installation_id=cache['installation_id'], namespace=cache['namespace'],
            executable_sha256=cache['executable_sha256'], public_key_sha256=cache['public_key_sha256'])
        cleaners = {surface: InstalledC09SurfaceCleanupV1(control=control, gate=gate, inventory_manifest=inventory,
            surface=surface, registry=registry) for surface in SURFACES - {'model_prompt_caches'}}
        cleaners['model_prompt_caches'] = provider.installed_disposition()
        maintenance = InstalledC09MaintenanceV1(control=control, gate=gate, core=core, closure=closure, graph=store,
            namespace_id=ns, accepted_service=None, inventory_manifest=inventory, target_directory=raw['target_directory'],
            subject=raw['subject'], credential=peer, service_handles=(store,), surface_services=cleaners,
            close_apply_service=close_apply)
        yield maintenance
    finally:
        errors = []
        for handle in reversed(handles):
            try:handle.close()
            except Exception as error:errors.append(error)
        if errors:raise ExceptionGroup('cold fixture handles did not close', errors)


def run_life_cold_phase_v1(path, phase, *, expected_fixture_digest, source_execution_commitment=None):
    from sylanne3.authority_service.c09_process_identity_v1 import require_process_retired_v1
    from sylanne3.authority_service.c09_control_selector_v2 import InstalledC09ControlSelectorV2
    from sylanne3.authority_service.c09_sanitized_history_v2 import build_sanitized_history_v2, InstalledC09StorageReaderV2
    from sylanne3.authority_service.c09_storage_maintenance_v1 import InstalledC09WriterGateV1
    with open_life_cold_fixture_v1(path, expected_fixture_digest=expected_fixture_digest) as (raw, control):
        require_process_retired_v1(raw['initial_process'])
        if phase in {'switch', 'release'}:
            context = control.read_verified_current_storage_v1()
            operation = context.prepared_original['operation_id']
            with _maintenance(raw, control) as maintenance:
                if phase == 'switch':
                    maintenance.switch_prepared_storage_v1(operation_id=operation)
                else:
                    maintenance.resume_storage_maintenance_v1(operation_id=operation)
            return {'phase': phase, 'pid': os.getpid(), 'stage': control.read_verified_current_storage_v1().stage}
        selector = InstalledC09ControlSelectorV2(control, str(control.path)+'.selector-v2', str(control.path)+'.selector-v2.journal')
        history_path = control.path.parent / 'sanitized-history-v2.json'
        if phase == 'build':
            history = build_sanitized_history_v2(control, history_path, gate=InstalledC09WriterGateV1(control=control))
            assert history['frames'] and history['storage_stage'] == 'RELEASED'
            selector.prepare(history_path)
            return {'phase': phase, 'pid': os.getpid(), 'frames': len(history['frames'])}
        if phase == 'factual':
            return _read_actual_factual_v1(raw, control, selector, source_execution_commitment)
        if phase != 'dispose':
            raise ValueError('unknown exact Life cold phase')
        selector.switch(); selector.dispose()
        reader = InstalledC09StorageReaderV2(control=control, selector=selector)
        context, frames = reader.read_verified_frames_v2()
        context.require_current('recovery')
        assert frames and not control.path.exists()
        return {'phase': phase, 'pid': os.getpid(), 'frames': len(frames), 'history_digest': context.history_digest}


def _closed_file_observations_v1(control, selector, manifest):
    import stat
    paths = {control.key_path, control.lease.path, Path(str(control.path)+'.selector-v2'),
        Path(str(control.path)+'.selector-v2.journal'),
        Path(str(control.path)+'.selector-v2.pending'),
        Path(selector.current()['candidate_path'])}
    for base in [control.path, *(Path(m['resolved_path']) for m in manifest['members'])]:
        paths.update(Path(str(base)+suffix) for suffix in ('', '-wal', '-shm', '-journal'))
    result = {}
    for path in sorted(paths):
        if not os.path.lexists(path):
            result[str(path)] = None
            continue
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('closed factual file must be a single regular inode')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        after = path.lstat()
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
                  'st_mode', 'st_uid', 'st_gid', 'st_nlink')
        if tuple(getattr(before, name) for name in fields) != tuple(getattr(after, name) for name in fields):
            raise ValueError('factual file changed while observed')
        result[str(path)] = dict(device=before.st_dev, inode=before.st_ino, size=before.st_size,
            mtime_ns=before.st_mtime_ns, ctime_ns=before.st_ctime_ns, mode=before.st_mode,
            uid=before.st_uid, gid=before.st_gid, links=before.st_nlink, sha256=digest)
    return result


def _record_factual_observation_v1(control, phase, observations, previous=None):
    """Persist only safe stat/hash summaries, before checking each transition."""
    directory = control.key_path.parent / 'factual-file-observation-evidence'
    directory.mkdir(exist_ok=True)
    with (directory / (phase + '.json')).open('x') as stream:
        json.dump(dict(phase=phase, files=observations), stream, sort_keys=True, indent=2)
        stream.write('\n')
    if previous is None:
        return
    changes = []
    for path in sorted(set(previous) | set(observations)):
        left, right = previous.get(path), observations.get(path)
        if left != right:
            fields = ['existence'] if left is None or right is None else [
                name for name in left if left[name] != right[name]]
            changes.append(dict(path=path, changed_fields=fields, before=left, after=right))
    report = dict(phase=phase, changes=changes)
    with (directory / (phase + '-diff.json')).open('x') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    assert not changes, json.dumps(report, sort_keys=True)


def _read_actual_factual_v1(raw, control, selector, source_execution_commitment):
    from dataclasses import replace
    from sylanne3.authority_service.core import AuthorityFactualReadCoreV2
    from sylanne3.authority_service.mtls_server import MtlsPeerCredential
    from sylanne3.authority_service.contract import AuthorityUnavailable
    from sylanne3.authority_service.c09_sanitized_history_v2 import (
        InstalledC09StorageReaderV2, read_sanitized_history_v2)
    # Authenticate the signed JSON without opening any selected SQLite file.
    history = read_sanitized_history_v2(control, selector.current()['candidate_path'])
    before = _closed_file_observations_v1(control, selector, history['current_manifest'])
    _record_factual_observation_v1(control, 'before', before)
    reader = InstalledC09StorageReaderV2(control=control, selector=selector)
    peer = MtlsPeerCredential(raw['peer_certificate'])
    def authorize(credential, action, namespace, holder):
        return (credential == peer and action in _ACTIONS
            and namespace == raw['authority_namespace'] and holder in {None, raw['holder']})
    core = None
    previous = before
    opened_recorded = False
    read_started = False
    try:
        context, frames = reader.read_verified_frames_v2()
        executions = {item.execution_id for _, facts, _ in frames for item in facts.executions}
        assert executions, 'actual Life fixture must retain nonempty execution facts'
        assert type(source_execution_commitment) is str and any(
            hashlib.sha256(value.encode()).hexdigest() == source_execution_commitment for value in executions), \
            'authenticated Life donor execution absent from sanitized facts'
        core = AuthorityFactualReadCoreV2(reader=reader, authorizer=authorize)
        opened = _closed_file_observations_v1(control, selector, history['current_manifest'])
        opened_recorded = True
        _record_factual_observation_v1(control, 'open', opened, previous)
        previous = opened
        read_started = True
        for execution_id in sorted(executions):
            evidence = core.read_current_sanitized_execution_v2(credential=peer,
                namespace=raw['authority_namespace'], execution_id=execution_id)
            assert evidence is not None and evidence.fact.execution_id == execution_id
            assert evidence.history_digest == context.history_digest
            reader.require_execution_evidence_v2(evidence)
            try:
                reader.require_execution_evidence_v2(replace(evidence))
            except AuthorityUnavailable:
                pass
            else:
                raise AssertionError('copied factual DTO acquired evidence authority')
        try:
            core.read_current_sanitized_execution_v2(credential=object(),
                namespace=raw['authority_namespace'], execution_id=next(iter(executions)))
        except AuthorityUnavailable:
            pass
        else:
            raise AssertionError('uninstalled credential read factual evidence')
        for action in ('business', 'accounting'):
            try:
                context.require_current(action)
            except AuthorityUnavailable:
                pass
            else:
                raise AssertionError('factual context admitted business/accounting')
    finally:
        try:
            try:
                if not opened_recorded:
                    opened = _closed_file_observations_v1(control, selector, history['current_manifest'])
                    _record_factual_observation_v1(control, 'open', opened, previous)
                    previous = opened
                if read_started:
                    read = _closed_file_observations_v1(control, selector, history['current_manifest'])
                    _record_factual_observation_v1(control, 'read', read, previous)
                    previous = read
            finally:
                if core is not None:
                    core.close()
        finally:
            closed = _closed_file_observations_v1(control, selector, history['current_manifest'])
            _record_factual_observation_v1(control, 'close', closed, previous)
    assert not control.path.exists()
    return {'phase': 'factual', 'pid': os.getpid(), 'execution_count': len(executions),
        'history_digest': context.history_digest, 'files_unchanged': len(before)}
