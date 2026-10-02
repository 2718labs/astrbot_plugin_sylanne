"""Cold public V2 daemon over actual nonempty PREPARED history, synthetic only.

Every case creates an independent new installation through the existing Owner
prepare/switch/release and real V2 build/dispose processes. The source fixture
has no executions: the positive credential read proves authenticated absence,
not a nonempty SanitizedExecutionEvidenceV2 or business/accounting admission.
No listening daemon, native model, paid provider, or platform send is started.
"""
import asyncio
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest


CASES = ('factual', 'v1_v2_conflict', 'missing_selector', 'missing_journal',
         'partial_journal', 'wrong_history_inode', 'old_control_revived', 'double_current',
         'nonempty_wal', 'rollback_journal')


def _forbidden_business_composition(*args, **kwargs):
    raise AssertionError('factual daemon invoked an executable business composition callback')


def _config(root):
    from c09_four_store_process_acceptance_support_v1 import _authorize, AUTH_NS, ROLE
    from sylanne3.authority_service.deployment_config import (
        AuthorityDeploymentConfig, ExecutionJournalInstallation, InstalledC09AuthorityV2,
    )
    from sylanne3.authority_service.mtls_server import AdministratorInstallationV2, AuthorityServerTlsConfig
    from sylanne3.authority_service.reverse_handoff import AdministratorReverseHandoffProfile

    packet = json.loads((root / 'packet.json').read_text())
    history_path = root / 'protected' / 'sanitized-history-v2.json'
    history = json.loads(history_path.read_bytes())
    members = {member['role']: member for member in history['current_manifest']['members']}
    installed = InstalledC09AuthorityV2(control_path=root / 'protected' / 'control.db',
        key_path=root / 'protected' / 'control.key', installation_id='installation',
        authority_id=packet['authority_id'], control_store_id='controlled-c09-test',
        key_id='controlled-c09-key', resource_roots=(root / 'state',))
    # Typed installation requires paths, but this factual route must not read
    # TLS material or construct a reverse client/listener. Invalid PEM makes
    # accidentally entering those paths a real failure, without network use.
    tls_path = root / 'factual-only-unused-tls.pem'
    tls_path.write_bytes(b'synthetic unused TLS material; factual route never opens TLS\n')
    peer = ('a' * 64, 'factual-fixture')
    config = AuthorityDeploymentConfig(
        authority_db=Path(members['core']['resolved_path']),
        deletion_db=Path(members['deletion']['resolved_path']),
        graph_db=Path(members['graph']['resolved_path']),
        instance_lock=root / 'protected' / 'instance.lock',
        execution_journals={AUTH_NS: ExecutionJournalInstallation(
            Path(members['execution']['resolved_path']), members['execution']['incarnation_or_journal_id'])},
        tls=AuthorityServerTlsConfig(str(tls_path), str(tls_path), str(tls_path)),
        bind_host='127.0.0.1', bind_port=19783,
        installations_v2={peer: AdministratorInstallationV2('installation', 'administrator',
            'fixture-policy', '2', 'b' * 64)},
        namespace_bindings_v2={(*peer, ROLE): AUTH_NS},
        reverse_handoff_profiles={AUTH_NS: AdministratorReverseHandoffProfile(
            AUTH_NS, peer[1], 'installation', '127.0.0.1', 19784, 'localhost',
            'c' * 64, tls_path, tls_path, tls_path)},
        reverse_handoff_issuers={AUTH_NS: 'fixture-graph-issuer'},
        core_authorizer=_authorize,
        core_verifier_factory=_forbidden_business_composition,
        administrator_authorizer=_forbidden_business_composition,
        publisher_manifest_verifier=_forbidden_business_composition,
        utc_clock=lambda: datetime.now(timezone.utc),
        local_administrator_credential=_forbidden_business_composition,
        c09_storage_v2=installed)
    return config, history, history_path


def _observations(config, history, history_path):
    """Exact named files and absent SQLite companions, including byte contents."""
    selected = [Path(member['resolved_path']) for member in history['current_manifest']['members']]
    installed = config.c09_storage_v2
    paths = {history_path, installed.selector_path, installed.selector_journal_path,
             installed.key_path, config.instance_lock,
             Path(str(installed.selector_path) + '.pending')}
    for path in (*selected, installed.control_path):
        paths.update(Path(str(path) + suffix) for suffix in ('', '-wal', '-shm', '-journal'))
    observed = {}
    for path in sorted(paths):
        if not os.path.lexists(path):
            observed[str(path)] = None
            continue
        before = path.lstat()
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1, path
        content = path.read_bytes()
        after = path.lstat()
        fields = ('st_dev', 'st_ino', 'st_mtime_ns', 'st_ctime_ns', 'st_size',
                  'st_mode', 'st_uid', 'st_gid', 'st_nlink')
        assert tuple(getattr(before, name) for name in fields) == tuple(
            getattr(after, name) for name in fields)
        observed[str(path)] = tuple(getattr(after, name) for name in fields) + (content,)
    return observed


def _observation_summaries(observations):
    """No file contents escape the byte comparison, including keys and TLS."""
    return {path: None if value is None else dict(device=value[0], inode=value[1],
        mtime_ns=value[2], ctime_ns=value[3], size=value[4], mode=value[5], uid=value[6],
        gid=value[7], links=value[8], sha256=hashlib.sha256(value[9]).hexdigest())
        for path, value in observations.items()}


def _record_observations(root, phase, observations):
    directory = root / 'file-observation-evidence'
    directory.mkdir(exist_ok=True)
    value = dict(phase=phase, files=_observation_summaries(observations))
    (directory / (phase + '.json')).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def _assert_observations_unchanged(root, phase, before, after):
    # Compare full bytes/dev/inode/mtime/size in memory; only safe hashes and
    # metadata reach assertion messages, pytest output, or durable evidence.
    _record_observations(root, phase, after)
    safe_before, safe_after = _observation_summaries(before), _observation_summaries(after)
    changes = []
    for path in sorted(set(before) | set(after)):
        if before.get(path) != after.get(path):
            left, right = safe_before.get(path), safe_after.get(path)
            fields = ['existence'] if left is None or right is None else [
                name for name in left if left[name] != right[name]]
            changes.append(dict(path=path, changed_fields=fields, before=left, after=right))
    report = dict(phase=phase, changes=changes)
    (root / 'file-observation-evidence' / (phase + '-diff.json')).write_text(
        json.dumps(report, sort_keys=True, indent=2) + '\n')
    assert not changes, json.dumps(report, sort_keys=True)


def _mutate_fixture(case, config, history_path):
    """Only this case's new temporary fixture; never a copied installed path."""
    installed = config.c09_storage_v2
    if case == 'missing_selector':
        installed.selector_path.unlink()
    elif case == 'missing_journal':
        installed.selector_journal_path.unlink()
    elif case == 'partial_journal':
        journal = installed.selector_journal_path.read_bytes()
        installed.selector_journal_path.write_bytes(journal.splitlines(keepends=True)[0])
    elif case == 'wrong_history_inode':
        replacement = history_path.with_suffix('.new-inode')
        replacement.write_bytes(history_path.read_bytes())
        os.replace(replacement, history_path)
    elif case == 'old_control_revived':
        assert not installed.control_path.exists()
        installed.control_path.write_bytes(b'synthetic reappearance of retired Control name')
    elif case == 'double_current':
        Path(str(installed.selector_path) + '.pending').write_bytes(installed.selector_path.read_bytes())
    elif case == 'nonempty_wal':
        sidecar = Path(str(config.authority_db) + '-wal')
        assert not sidecar.exists() or sidecar.stat().st_size == 0
        sidecar.write_bytes(b'controlled synthetic pending WAL bytes')
    elif case == 'rollback_journal':
        sidecar = Path(str(config.authority_db) + '-journal')
        assert not sidecar.exists()
        sidecar.write_bytes(b'controlled synthetic rollback journal bytes')
    else:
        raise AssertionError('unrecognized negative fixture mutation')


def _daemon_phase(root, case):
    from c09_four_store_process_acceptance_support_v1 import AUTH_NS, ADMIN
    from sylanne3.authority_service.contract import AuthorityUnavailable
    from sylanne3.authority_service.core import AuthorityFactualReadCoreV2
    from sylanne3.authority_service.daemon import open_authority_daemon, AuthorityFactualDaemonV2
    from sylanne3.authority_service.deployment_config import InstalledC09AuthorityV1
    from sylanne3.authority_service.c09_sanitized_history_v2 import (
        SanitizedExecutionEvidenceV2,
    )
    from sylanne3.runtime_contracts import canonical_digest

    config, history, history_path = _config(root)
    assert case in CASES
    assert len(history['frames']) >= 1 and history['storage_stage'] == 'RELEASED'
    assert not config.c09_storage_v2.control_path.exists()
    if case == 'v1_v2_conflict':
        before = _observations(config, history, history_path)
        _record_observations(root, 'before-v1-v2-conflict', before)
        installed = config.c09_storage_v2
        v1 = InstalledC09AuthorityV1(**{field: getattr(installed, field) for field in (
            'control_path', 'key_path', 'installation_id', 'authority_id',
            'control_store_id', 'key_id', 'resource_roots')})
        with pytest.raises(AuthorityUnavailable, match='exclusive'):
            replace(config, c09_storage_v1=v1)
        _assert_observations_unchanged(root, 'after-v1-v2-conflict', before,
            _observations(config, history, history_path))
        return dict(case=case, state='refused', process_id=os.getpid())
    if case != 'factual':
        _mutate_fixture(case, config, history_path)
        before = _observations(config, history, history_path)
        _record_observations(root, 'before-refused-open', before)
        unexpected = None
        expected_message = {'nonempty_wal': 'nonempty WAL',
                            'rollback_journal': 'rollback journal'}.get(case)
        try:
            with pytest.raises(AuthorityUnavailable, match=expected_message):
                unexpected = open_authority_daemon(config)
        finally:
            if unexpected is not None:
                asyncio.run(unexpected.aclose())
        _assert_observations_unchanged(root, 'after-refused-open', before,
            _observations(config, history, history_path))
        assert config.c09_storage_v2.control_path.exists() == (case == 'old_control_revived')
        # Failure cleanup releases the real installation lock, without opening
        # any database or normal V1 initializer.
        from sylanne3.authority_service.c09_storage_control_v1 import InstalledC09InstanceLeaseV1
        with InstalledC09InstanceLeaseV1(config.instance_lock):
            pass
        return dict(case=case, state='refused', process_id=os.getpid())

    before = _observations(config, history, history_path)
    _record_observations(root, 'before-open', before)
    daemon = None
    previous = before
    try:
        daemon = open_authority_daemon(config)
        assert type(daemon) is AuthorityFactualDaemonV2
        assert type(daemon.core) is AuthorityFactualReadCoreV2
        assert not daemon.is_listening
        opened = _observations(config, history, history_path)
        _assert_observations_unchanged(root, 'after-open', previous, opened)
        previous = opened
        context, frames = daemon.reader.read_verified_frames_v2()
        assert len(frames) >= 1 and context.storage_generation >= 1
        # Existing Owner fixture authenticator recognizes ADMIN; no patched
        # auth reader, callback allowing all credentials, or fabricated facts.
        assert daemon.read_current_sanitized_execution_v2(credential=ADMIN,
            namespace=AUTH_NS, execution_id='fixture-absent-execution') is None
        assert all(not facts.executions for _association, facts, _bindings in frames)
        with pytest.raises(AuthorityUnavailable, match='authentication denied'):
            daemon.read_current_sanitized_execution_v2(credential='unregistered-credential',
                namespace=AUTH_NS, execution_id='fixture-absent-execution')
        with pytest.raises(AuthorityUnavailable, match='HOLD'):
            asyncio.run(daemon.start())
        for action in ('business', 'accounting'):
            with pytest.raises(AuthorityUnavailable, match='HOLD'):
                context.require_current(action)
        with pytest.raises(AuthorityUnavailable):
            daemon.core.begin_content_operation(ADMIN, namespace=AUTH_NS,
                holder='administrator', generation=context.storage_generation, operation='dispatch')
        reconstructed = replace(context, _capability=object())
        with pytest.raises(AuthorityUnavailable, match='actual context'):
            daemon.reader.require_context_v2(reconstructed)
        # Dataclass construction alone cannot mint registered factual evidence.
        caller_dto = SanitizedExecutionEvidenceV2(AUTH_NS, context.history_digest,
            tuple(association for association, _facts, _bindings in frames),
            None, None, (), (), None, context)
        with pytest.raises(AuthorityUnavailable, match='caller DTO'):
            daemon.reader.require_execution_evidence_v2(caller_dto)
        # The actual installed reader authenticates the selected history and
        # re-enumerates every retained carrier family under its factual closed
        # member contract. Calling the generic maintenance capture here would
        # itself open SQLite in mode=ro and mutate SHM, defeating this check.
        after_context = daemon.reader.read_verified_current_storage_v2()
        assert after_context.history_digest == context.history_digest == history['history_digest']
        assert after_context.manifest == history['current_manifest']
        assert after_context.storage_generation == context.storage_generation
        read = _observations(config, history, history_path)
        _assert_observations_unchanged(root, 'after-factual-read', previous, read)
        previous = read
        assert not config.c09_storage_v2.control_path.exists()
        result = dict(case=case, state='factual-absence-verified', process_id=os.getpid(),
            frames=len(frames), history_digest=context.history_digest,
            carrier_inventory_digest=canonical_digest(history['carrier_inventory']),
            carrier_inventory_revalidated_by='InstalledC09StorageReaderV2.read_verified_current_storage_v2',
            selected_file_sha256={path: hashlib.sha256(value[-1]).hexdigest()
                for path, value in before.items() if value is not None},
            exact_files_unchanged=True, nonempty_execution_evidence=False)
    finally:
        try:
            if daemon is not None:
                asyncio.run(daemon.aclose())
        finally:
            _assert_observations_unchanged(root, 'after-close', previous,
                _observations(config, history, history_path))
    with pytest.raises(AuthorityUnavailable, match='closed'):
        daemon.read_current_sanitized_execution_v2(credential=ADMIN,
            namespace=AUTH_NS, execution_id='fixture-absent-execution')
    return result


# This startup guard runs in every child, including the old fixture's nested
# provider children. A PYTHONPATH order assertion in the parent would not pin
# subprocess imports. No installed-root or manifest pin has a source fallback.
_PRODUCT_IMPORT_GUARD = r"""
import atexit
import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sys


def fail(message):
    os.write(2, ('C09 installed-product import pin failed: ' + str(message) + '\n').encode())
    os._exit(86)


try:
    installed = Path(os.environ['SYLANNE_C09_INSTALLED_ROOT']).resolve(strict=True)
    expected_manifest = os.environ['SYLANNE_C09_MANIFEST_SHA256']
    fixture = Path(os.environ['SYLANNE_C09_TEST_ROOT']).resolve(strict=True)
    expected_engineering = os.environ['SYLANNE_C09_ENGINEERING_INVENTORY_SHA256']
    output = Path(os.environ['SYLANNE_C09_IMPORT_EVIDENCE']).resolve(strict=True)
    guard_path = output / 'sitecustomize.py'
    if (Path(__file__).resolve(strict=True) != guard_path
            or hashlib.sha256(guard_path.read_bytes()).hexdigest() != os.environ['SYLANNE_C09_GUARD_SHA256']):
        fail('startup guard path or hash differs')
    raw_manifest = (installed / 'release-manifest.json').read_bytes()
    if hashlib.sha256(raw_manifest).hexdigest() != expected_manifest:
        fail('release manifest digest differs')
    file_pins = {row['path']: row for row in json.loads(raw_manifest)['files']}
    engineering_path = fixture.parent / 'frozen-engineering-inventory.json'
    engineering = json.loads(engineering_path.read_text())
    actual_engineering = hashlib.sha256(json.dumps(engineering['files'], sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()
    if (engineering['schema'] != 'sylanne.engineering-source-inventory.v1'
            or engineering['sha256'] != actual_engineering or actual_engineering != expected_engineering):
        fail('explicit frozen engineering inventory differs')
    test_pins = {row['path']: row for row in engineering['files']
        if row['path'].startswith(('rewrite/tests/', 'rewrite/host_tests/'))}
    test_roots = (fixture / 'rewrite/tests', fixture / 'rewrite/host_tests')
    checked = {}

    def closed_test(name):
        return any(name == 'rewrite.' + leaf or name.startswith('rewrite.' + leaf + '.')
            for leaf in ('tests', 'host_tests'))

    def product(name):
        return (name == 'sylanne3' or name.startswith('sylanne3.') or name == 'rewrite'
            or name.startswith('rewrite.') and not closed_test(name))

    def verify_test_origin(name, origin):
        path = Path(origin).resolve(strict=True)
        if not any(path.is_relative_to(root) for root in test_roots):
            fail('engineering test namespace escaped closed roots: ' + name)
        relative = path.relative_to(fixture).as_posix()
        pin = test_pins.get(relative)
        data = path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        if pin is None or pin['sha256'] != sha or pin['bytes'] != len(data):
            fail('engineering test differs from frozen inventory: ' + relative)
        return dict(path=str(path), sha256=sha)

    # Validate both complete engineering test families before any fixture use.
    for relative in test_pins:
        verify_test_origin(relative, fixture / relative)

    def verify_origin(name, origin, locations):
        base = installed / ('rewrite' if name.startswith('sylanne3') else '')
        stem = base.joinpath(*name.split('.'))
        if origin is None:
            if tuple(Path(p).resolve(strict=True) for p in locations or ()) != (stem,):
                fail('namespace origin differs: ' + name)
            return dict(path=None, namespace_path=str(stem))
        path = Path(origin).resolve(strict=True)
        if path not in (stem.with_suffix('.py'), stem / '__init__.py'):
            fail('module __file__ or product alias differs: ' + name + ' -> ' + str(path))
        relative = path.relative_to(installed).as_posix()
        pin = file_pins.get(relative)
        data = path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        if pin is None or pin['sha256'] != sha or pin['bytes'] != len(data):
            fail('module differs from pinned extracted manifest: ' + relative)
        value = dict(path=str(path), sha256=sha)
        checked[name] = value
        return value

    def verify_module(name, origin, locations):
        if product(name):
            return 'product', verify_origin(name, origin, locations)
        if origin is None:
            if closed_test(name):
                expected = fixture.joinpath(*name.split('.'))
                prefix = expected.relative_to(fixture).as_posix() + '/'
                if (not any(relative.startswith(prefix) for relative in test_pins)
                        or tuple(Path(p).resolve(strict=True) for p in locations or ()) != (expected,)):
                    fail('closed test namespace path differs: ' + name)
            return None, None
        path = Path(origin).resolve(strict=True)
        if 'sylanne3' in path.parts:
            fail('product file imported under an unrecognized alias: ' + name)
        if path.is_relative_to(fixture):
            return 'test', verify_test_origin(name, path)
        if closed_test(name):
            fail('closed test module came from outside frozen fixture: ' + name)
        return None, None

    class PinnedProductFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            spec = importlib.machinery.PathFinder.find_spec(fullname, path)
            if spec is None:
                if product(fullname) or closed_test(fullname):
                    fail('installed product or frozen test module absent: ' + fullname)
                return None
            if spec.origin not in ('built-in', 'frozen'):
                verify_module(fullname, spec.origin, spec.submodule_search_locations)
            return spec if product(fullname) or closed_test(fullname) else None

    sys.meta_path.insert(0, PinnedProductFinder())
    import rewrite
    import sylanne3
    # ZIPs omit engineering tests. Bridge only these two pinned families,
    # without appending source/rewrite to any product package search path.
    for leaf in ('tests', 'host_tests'):
        name = 'rewrite.' + leaf
        spec = importlib.machinery.ModuleSpec(name, loader=None, is_package=True)
        spec.submodule_search_locations = [str(fixture / 'rewrite' / leaf)]
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        setattr(rewrite, leaf, module)
    sys.path.append(str(fixture / 'rewrite' / 'tests' / 'alpha1' / 'integration'))

    def audit(phase='atexit'):
        try:
            if (type(phase) is not str or not phase or len(phase) > 64
                    or any(not (char.isascii() and (char.isalnum() or char in '-_')) for char in phase)):
                fail('closed import observation phase required')
            from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1
            identity = read_process_identity_v1(os.getpid())
            if identity is None:
                fail('actual current process birth identity unavailable')
            modules, fixtures, namespaces = {}, {}, {}
            for name, module in tuple(sys.modules.items()):
                origin = getattr(module, '__file__', None)
                if origin in ('built-in', 'frozen'):
                    continue
                kind, value = verify_module(name, origin, getattr(module, '__path__', None))
                if kind == 'product':
                    modules[name] = value
                elif kind == 'test':
                    fixtures[value['path']] = value['sha256']
                elif closed_test(name) and origin is None:
                    namespaces[name] = list(module.__path__)
            main = getattr(sys.modules.get('__main__'), '__file__', None)
            entrypoint = None
            if main:
                path = Path(main).resolve(strict=True)
                if path.is_relative_to(fixture):
                    verify_test_origin('__main__', path)
                entrypoint = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            value = dict(process_id=os.getpid(), process_identity=identity, observation_phase=phase,
                installed_root=str(installed), manifest_sha256=expected_manifest,
                engineering_inventory_sha256=expected_engineering, guard_sha256=os.environ['SYLANNE_C09_GUARD_SHA256'],
                product_modules=modules, test_sources=fixtures, test_namespaces=namespaces, entrypoint=entrypoint)
            encoded = json.dumps(value, sort_keys=True) + '\n'
            (output / ('pin-' + str(os.getpid()) + '.json')).write_text(encoded)
            (output / ('pin-' + str(os.getpid()) + '-' + phase + '.json')).write_text(encoded)
            return value
        except BaseException as exc:
            fail(exc)
    atexit.register(audit)
except BaseException as exc:
    fail(exc)
"""


def _installed_phase_environment(tmp_path, here):
    # The caller must explicitly choose the extracted product and authenticate
    # its release manifest. Running this test against engineering source is not
    # an implicit alternate mode.
    raw_root = os.environ.get('SYLANNE_C09_INSTALLED_ROOT')
    expected = os.environ.get('SYLANNE_C09_MANIFEST_SHA256')
    engineering_pin = os.environ.get('SYLANNE_C09_ENGINEERING_INVENTORY_SHA256')
    assert raw_root and expected, 'explicit extracted product root and release-manifest SHA256 required'
    assert engineering_pin and len(engineering_pin) == 64 and all(c in '0123456789abcdef'
        for c in engineering_pin), 'explicit frozen canonical engineering inventory SHA256 required'
    installed = Path(raw_root).resolve(strict=True)
    assert len(expected) == 64 and all(c in '0123456789abcdef' for c in expected)
    assert hashlib.sha256((installed / 'release-manifest.json').read_bytes()).hexdigest() == expected
    fixture = Path(os.environ.get('SYLANNE_C09_TEST_ROOT', str(here.parents[4]))).resolve(strict=True)
    guard = tmp_path / 'import-origin-evidence'
    guard.mkdir()
    (guard / 'sitecustomize.py').write_text(_PRODUCT_IMPORT_GUARD)
    guard_pin = hashlib.sha256((guard / 'sitecustomize.py').read_bytes()).hexdigest()
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join(
        (str(guard), str(installed / 'rewrite'), str(installed))),
        PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1',
        SYLANNE_C09_INSTALLED_ROOT=str(installed), SYLANNE_C09_MANIFEST_SHA256=expected,
        SYLANNE_C09_TEST_ROOT=str(fixture), SYLANNE_C09_IMPORT_EVIDENCE=str(guard),
        SYLANNE_C09_ENGINEERING_INVENTORY_SHA256=engineering_pin, SYLANNE_C09_GUARD_SHA256=guard_pin)
    environment.pop('PYTHONHOME', None)
    return environment, fixture, installed, guard


@pytest.mark.parametrize('case', CASES)
def test_public_daemon_cold_factual_v2(tmp_path, case):
    here = Path(__file__).resolve()
    environment, fixture, installed, guard = _installed_phase_environment(tmp_path, here)
    helpers = fixture / 'rewrite' / 'tests' / 'alpha1' / 'integration'
    old = helpers / 'c09_four_store_process_acceptance_support_v1.py'
    conversion = helpers / 'test_c09_nonempty_history_process_v2.py'
    outcomes = []
    # Fresh tmp_path per parameter: signatures and inode-bound paths are never
    # rewritten to reuse a copied installation or share a mutated case.
    for script, phase in ((old, 'prepare'), (old, 'switch'), (old, 'release'),
            (conversion, 'build'), (conversion, 'dispose'), (here, case)):
        run = subprocess.run([sys.executable, str(script), phase, str(tmp_path)],
            env=environment, cwd=guard, capture_output=True, text=True, timeout=180)
        assert run.returncode == 0, f'{script.name}:{phase}\n{run.stdout}\n{run.stderr}'
        result = json.loads(run.stdout.strip().splitlines()[-1])
        pin = json.loads((guard / ('pin-' + str(result['process_id']) + '.json')).read_text())
        assert pin['installed_root'] == str(installed)
        assert pin['manifest_sha256'] == environment['SYLANNE_C09_MANIFEST_SHA256']
        assert pin['product_modules']['sylanne3']['path'] == str(installed / 'rewrite/sylanne3/__init__.py')
        if script == here and case == 'factual':
            for name in ('daemon', 'core', 'deployment_config', 'c09_control_selector_v2', 'c09_sanitized_history_v2'):
                assert pin['product_modules']['sylanne3.authority_service.' + name]['path'] == str(
                    installed / 'rewrite' / 'sylanne3' / 'authority_service' / (name + '.py'))
        outcomes.append(result)
    # Nested controlled-provider helpers inherit the same startup guard and
    # produce their own module-origin evidence, independently of main phases.
    reports = [json.loads(path.read_text()) for path in guard.glob('pin-*.json')]
    assert len(reports) >= len(outcomes)
    assert all(report['installed_root'] == str(installed)
        and report['manifest_sha256'] == environment['SYLANNE_C09_MANIFEST_SHA256'] for report in reports)
    assert len({item['process_id'] for item in outcomes}) == len(outcomes)
    assert outcomes[-2]['old_control_exists'] is False
    if case == 'factual':
        assert outcomes[-1]['history_digest'] == outcomes[-2]['history_digest']
        assert outcomes[-1]['exact_files_unchanged'] is True
        assert outcomes[-1]['nonempty_execution_evidence'] is False
    else:
        assert outcomes[-1]['state'] == 'refused'


if __name__ == '__main__':
    print(json.dumps(_daemon_phase(Path(sys.argv[2]), sys.argv[1]), sort_keys=True))
