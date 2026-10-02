"""Explicit test-only Host actor; Authority and original issuers stay in parent.

Linux fork, not spawn or an Authority restart. Only allowlisted immutable
installation material is passed to the child target. No parent Core/server,
SQL connection, event loop, callback closure or old Host handle is consumed.
The child waits for the actual parent's process admission before first use.
"""
from __future__ import annotations

import asyncio
import dataclasses
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import importlib
import inspect
import json
import multiprocessing
import os
from pathlib import Path
import sys
import traceback
from types import MappingProxyType


@dataclasses.dataclass(frozen=True)
class HostInstallationCaseV1:
    package_root: Path
    data_dir: Path
    graph_path: Path
    namespace: object
    authority_namespace: str
    bundle: object
    request: object
    grant: object
    peer: object
    reverse_profile: object
    reverse_bind_host: str
    reverse_bind_port: int
    owner_fixture_private_key: bytes
    provider_config: dict
    host_driver_module: str
    host_driver_function: str
    host_driver_sha256: str
    host_driver_configuration: dict


@dataclasses.dataclass(frozen=True)
class ParentAuthorityServicesV1:
    control: object
    gate: object
    close_host_handles: object
    authenticate_completed: object


@dataclasses.dataclass(frozen=True)
class CompletedLifeLocatorsV1:
    job_id: str
    prepared_digest: str
    adoption_operation_id: str
    receipt_digest: str


def _safe_installation_value(value, active=None, *, depth=0):
    """Closed material algebra, excluding live handles and executable values."""
    if depth > 32:
        raise ValueError('Host installation material nesting exceeded')
    if value is None or type(value) in {bool, int, float, str, bytes}:
        if isinstance(value, (str, bytes)) and len(value) > 1048576:
            raise ValueError('Host installation material length exceeded')
        return
    if isinstance(value, (Path, datetime, timedelta, Enum)):
        return
    if callable(value):
        raise TypeError('Host installation cannot carry a callable or closure')
    active = set() if active is None else active
    if id(value) in active:
        raise ValueError('Host installation material cannot contain cycles')
    active.add(id(value))
    try:
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            for field in dataclasses.fields(value):
                _safe_installation_value(getattr(value, field.name), active, depth=depth + 1)
        elif type(value) in {dict, MappingProxyType}:
            if len(value) > 4096 or any(type(key) is not str for key in value):
                raise ValueError('Host installation mapping differs')
            for name, child in value.items():
                if name in {'core', 'server', 'store', 'db', 'connection', 'port', 'loop', 'control', 'gate'}:
                    raise ValueError('live Authority or Host object field forbidden')
                _safe_installation_value(child, active, depth=depth + 1)
        elif type(value) in {tuple, list, set, frozenset}:
            if len(value) > 4096:
                raise ValueError('Host installation sequence exceeded')
            for child in value:
                _safe_installation_value(child, active, depth=depth + 1)
        else:
            raise TypeError('Host installation has unsupported live material type: ' + type(value).__name__)
    finally:
        active.remove(id(value))


def _validate_installation(material):
    if type(material) is not HostInstallationCaseV1:
        raise TypeError('exact HostInstallationCaseV1 required')
    _safe_installation_value(material)
    root = Path(material.package_root).resolve(strict=True)
    if not root.is_dir() or not Path(material.graph_path).resolve(strict=True).is_relative_to(
            Path(material.data_dir).resolve(strict=True)):
        raise ValueError('actual installed Host paths differ')
    if (type(material.owner_fixture_private_key) is not bytes or len(material.owner_fixture_private_key) != 32
            or type(material.reverse_bind_port) is not int or not 0 < material.reverse_bind_port < 65536
            or material.reverse_bind_host != '127.0.0.1'
            or material.host_driver_module != 'd11_life_host_actor_support_v1'
            or material.host_driver_function != 'run_installed_life_host_actor_v1'
            or len(material.host_driver_sha256) != 64):
        raise ValueError('closed Host driver installation differs')


def _require_product_origins(root):
    root = Path(root).resolve(strict=True)
    expected = os.environ.get('SYLANNE_C09_MANIFEST_SHA256')
    if (root != Path(os.environ['SYLANNE_C09_INSTALLED_ROOT']).resolve(strict=True)
            or hashlib.sha256((root / 'release-manifest.json').read_bytes()).hexdigest() != expected):
        raise AssertionError('Host actor actual installed manifest differs')
    pins = {row['path']: row for row in json.loads((root / 'release-manifest.json').read_text())['files']}
    observed = {}
    for name, module in tuple(sys.modules.items()):
        origin = getattr(module, '__file__', None)
        product = (name == 'sylanne3' or name.startswith('sylanne3.')
            or name == 'rewrite.sylanne3' or name.startswith('rewrite.sylanne3.'))
        if not product and not (origin and 'sylanne3' in Path(origin).parts):
            continue
        if not product:
            raise AssertionError('Host actor imported a product file under an alias: ' + name)
        stem = root.joinpath(*(('rewrite.' + name) if name.startswith('sylanne3') else name).split('.'))
        if origin is None:
            if tuple(Path(path).resolve(strict=True) for path in getattr(module, '__path__', ())) != (stem,):
                raise AssertionError('Host actor product namespace differs: ' + name)
        else:
            path = Path(origin).resolve(strict=True)
            if path not in (stem.with_suffix('.py'), stem / '__init__.py'):
                raise AssertionError('Host actor imported product outside installed package: ' + name)
            relative = path.relative_to(root).as_posix()
            pin = pins.get(relative)
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if pin is None or actual != pin['sha256'] or path.stat().st_size != pin['bytes']:
                raise AssertionError('Host actor product differs from installed manifest: ' + name)
            observed[name] = {'path': str(path), 'sha256': actual}
    return observed


def _write_host_import_evidence_v1(root, phase):
    """Explicit fork-safe audit; multiprocessing's os._exit skips atexit."""
    _require_product_origins(root)
    import sitecustomize
    output = Path(os.environ['SYLANNE_C09_IMPORT_EVIDENCE']).resolve(strict=True)
    guard = output / 'sitecustomize.py'
    if (Path(sitecustomize.__file__).resolve(strict=True) != guard
            or hashlib.sha256(guard.read_bytes()).hexdigest() != os.environ['SYLANNE_C09_GUARD_SHA256']):
        raise AssertionError('Host actor explicit installed import guard differs')
    value = sitecustomize.audit(phase=phase)
    path = output / ('pin-' + str(os.getpid()) + '-' + phase + '.json')
    assert value['process_id'] == os.getpid()
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def _record_host_process_evidence_v1(pid, phase, **facts):
    output = Path(os.environ['SYLANNE_C09_IMPORT_EVIDENCE']).resolve(strict=True)
    value = dict(schema='sylanne.test.c09.life-host-process.v1', phase=phase,
        process_id=pid, observer_process_id=os.getpid(), **facts)
    with (output / ('host-' + str(pid) + '-' + phase + '.json')).open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')
    return value


def _send(pipe, payload):
    encoded = json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if len(encoded) > 65536:
        raise ValueError('Host actor message exceeded finite bound')
    pipe.send_bytes(encoded)


def _receive(pipe):
    value = json.loads(pipe.recv_bytes(65536))
    if type(value) is not dict:
        raise ValueError('closed Host actor message required')
    return value


def _decode_locators(raw):
    if type(raw) is not dict or set(raw) != {field.name for field in dataclasses.fields(CompletedLifeLocatorsV1)}:
        raise ValueError('closed completed Life locators required')
    if any(type(value) is not str or not 0 < len(value) <= 4096 for value in raw.values()):
        raise ValueError('completed Life locator shape differs')
    for name in ('prepared_digest', 'receipt_digest'):
        value = raw[name].removeprefix('sha256:')
        if len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('completed Life locator commitment differs')
    return CompletedLifeLocatorsV1(**raw)


def _host_child(material, pipe):
    requested_exit_code = 1
    try:
        asyncio.events._set_running_loop(None)
        _validate_installation(material)
        _require_product_origins(material.package_root)
        module = importlib.import_module(material.host_driver_module)
        if hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest() != material.host_driver_sha256:
            raise ValueError('Host driver source pin differs')
        driver = getattr(module, material.host_driver_function)
        if (not inspect.iscoroutinefunction(driver) or driver.__module__ != module.__name__
                or driver.__closure__ is not None):
            raise ValueError('Host driver must be an explicit top-level async function')
        _write_host_import_evidence_v1(material.package_root, 'host-ready')
        _send(pipe, {'phase': 'ready', 'pid': os.getpid()})
        command = _receive(pipe)
        if set(command) != {'phase', 'pid'} or command != {'phase': 'start', 'pid': os.getpid()}:
            raise ValueError('parent has not admitted this Host process')
        # This entry point must create and finally close its new Graph, TLS,
        # Owner session, provider transport and fixed-port reverse listener.
        result = asyncio.run(driver(material))
        raw = dataclasses.asdict(result) if type(result) is CompletedLifeLocatorsV1 else result
        locators = _decode_locators(raw)
        _require_product_origins(material.package_root)
        _send(pipe, {'phase': 'completed', 'pid': os.getpid(), 'locators': dataclasses.asdict(locators)})
        requested_exit_code = 0
    except BaseException as exc:
        # No values, exception text, locals, request body or credentials cross
        # the diagnostic pipe. Parent keeps failure as failure, never success.
        frames = traceback.extract_tb(exc.__traceback__)[-24:]
        _send(pipe, {'phase': 'failed', 'pid': os.getpid(), 'exception': type(exc).__name__,
            'frames': [{'file': Path(f.filename).name, 'line': f.lineno, 'function': f.name} for f in frames]})
        raise SystemExit(1)
    finally:
        try:
            from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1
            pin = _write_host_import_evidence_v1(material.package_root, 'host-pre-exit')
            identity = read_process_identity_v1(os.getpid())
            assert identity is not None
            _record_host_process_evidence_v1(os.getpid(), 'child-pre-exit',
                process_identity=identity, requested_exit_code=requested_exit_code, import_pin=pin)
        finally:
            pipe.close()


async def run_life_host_process_v1(*, installation, parent, after_exit):
    """Run one actual Host; authenticate its locators only after observed exit.

    Parent callbacks are never sent to the child. authenticate_completed must
    reread actual signed originals with the same live Core/D11; a returned DTO
    does not issue a scope, mark a job complete, or authorize maintenance.
    """
    from sylanne3.authority_service.c09_storage_maintenance_v1 import InstalledC09WriterGateV1
    from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1, require_process_retired_v1
    _validate_installation(installation)
    _require_product_origins(installation.package_root)
    if (type(parent) is not ParentAuthorityServicesV1 or type(parent.gate) is not InstalledC09WriterGateV1
            or parent.gate.control is not parent.control or not callable(after_exit)
            or not callable(parent.close_host_handles) or not callable(parent.authenticate_completed)):
        raise ValueError('same actual parent Authority/gate and callbacks required')
    parent.control.lease.require_held()
    current = parent.control.read_verified_current_storage_v1()
    current.require_current('business')
    # Existing live peer admissions may not disappear merely because a new
    # child is being created. The fixture must split actors before admitting
    # its first Host; no replacement empty gate is accepted here.
    if parent.gate._peers or parent.gate._workers or parent.gate._active:
        raise ValueError('Host actor split must precede original writer admission')
    await parent.close_host_handles()
    context = multiprocessing.get_context('fork')
    parent_pipe, child_pipe = context.Pipe(duplex=True)
    process = context.Process(target=_host_child, args=(installation, child_pipe), name='c09-life-host')
    process.start()
    child_pipe.close()
    identity = None
    try:
        identity = read_process_identity_v1(process.pid)
        _record_host_process_evidence_v1(process.pid, 'parent-started', process_identity=identity)
        if not await asyncio.to_thread(parent_pipe.poll, 30):
            raise AssertionError('Host actor did not reach startup barrier')
        ready = _receive(parent_pipe)
        assert ready == {'phase': 'ready', 'pid': process.pid}, ready
        assert identity is not None and read_process_identity_v1(process.pid) == identity and process.is_alive()
        _record_host_process_evidence_v1(process.pid, 'parent-admitted', process_identity=identity)
        latest = parent.control.read_verified_current_storage_v1()
        assert (latest.pointer_version, latest.manifest_digest) == (current.pointer_version, current.manifest_digest)
        peer = (installation.peer.certificate_sha256, installation.request.profile_id)
        parent.gate.register_peer_process_v1(peer=peer, process_id=process.pid,
            process_incarnation='c09-life-host:' + identity['birth'],
            pointer_version=current.pointer_version, storage_generation=current.storage_generation)
        _send(parent_pipe, {'phase': 'start', 'pid': process.pid})
        if not await asyncio.to_thread(parent_pipe.poll, 600):
            raise AssertionError('Host actor exceeded the existing finite scenario deadline')
        result = _receive(parent_pipe)
        await asyncio.to_thread(process.join, 10)
        assert not process.is_alive() and process.exitcode == 0, result
        assert set(result) == {'phase', 'pid', 'locators'} and result['phase'] == 'completed' and result['pid'] == process.pid
        locators = _decode_locators(result['locators'])
        retirement = require_process_retired_v1(identity)
        pin_path = Path(os.environ['SYLANNE_C09_IMPORT_EVIDENCE']) / ('pin-' + str(process.pid) + '-host-pre-exit.json')
        pin = json.loads(pin_path.read_text())
        assert pin['process_id'] == process.pid and pin['process_identity'] == identity
        assert pin['installed_root'] == str(Path(installation.package_root).resolve(strict=True))
        assert pin['manifest_sha256'] == os.environ['SYLANNE_C09_MANIFEST_SHA256']
        assert pin['engineering_inventory_sha256'] == os.environ['SYLANNE_C09_ENGINEERING_INVENTORY_SHA256']
        _record_host_process_evidence_v1(process.pid, 'parent-retired', process_identity=identity,
            actual_exit_code=process.exitcode, retirement=retirement,
            import_pin={'path': str(pin_path), 'sha256': hashlib.sha256(pin_path.read_bytes()).hexdigest()})
        # No parent loop blocking: Authority TLS remains responsive throughout.
        authenticated = await parent.authenticate_completed(locators)
        return await after_exit(authenticated, retirement)
    finally:
        if process.is_alive():
            process.terminate()
            await asyncio.to_thread(process.join, 5)
            if process.is_alive():
                process.kill()
                await asyncio.to_thread(process.join, 5)
        if not process.is_alive():
            _record_host_process_evidence_v1(process.pid, 'parent-final', process_identity=identity,
                actual_exit_code=process.exitcode,
                retirement=None if identity is None else require_process_retired_v1(identity))
        parent_pipe.close()
