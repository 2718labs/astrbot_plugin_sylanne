"""Real, finite request cache owned by the synthetic installed MockTransport.

Never install this adapter for a real provider. Only fresh test directories and
actual mock request bodies are touched; headers and credentials are not cached.
The product InstalledProviderCacheDispositionV1 verifies independent signed
subprocess purge/read observations. This helper grants no C09 authority.
"""
from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import uuid


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def _sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    _sync_dir(path.parent)


@contextlib.contextmanager
def _locked(root):
    fd = os.open(root / 'lock', os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _read(root, name):
    fd = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1048576:
            raise ValueError('synthetic adapter owned file differs')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            return stream.read(1048577)
    finally:
        os.close(fd)


class ControlledLifeProviderCacheV1:
    def __init__(self, root, provider_config):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
        if (type(provider_config) is not dict or set(provider_config) != {'id', 'type', 'model'}
                or provider_config != {'id': 'provider-1', 'type': 'openai_chat_completion', 'model': 'model-1'}):
            raise ValueError('mock provider installed configuration differs')
        self.root = Path(root).absolute()
        self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        (self.root / 'cache').mkdir(mode=0o700)
        _write_new(self.root / 'lock', b'')
        self.config_digest = hashlib.sha256(_canonical(provider_config).encode()).hexdigest()
        self.provider_id = provider_config['id']
        key = Ed25519PrivateKey.generate()
        _write_new(self.root / 'signing-key', key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        _write_new(self.root / 'verification-key', key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        # A standalone pinned script; no product/source import or network path.
        body = Path(__file__).read_text()
        executable = '#!' + sys.executable + '\n' + body + '\n_adapter_main(' + repr(str(self.root)) + ')\n'
        _write_new(self.root / 'adapter', executable.encode())
        os.chmod(self.root / 'adapter', 0o700)
        _sync_dir(self.root)
        self.recorded_requests = 0

    @classmethod
    def attach_installed(cls, root, provider_config, *, authority_id, installation_id,
                         namespace, executable_sha256, public_key_sha256):
        """Child attaches to the original fixture provider, never installs anew."""
        path = Path(root).absolute()
        if path.is_symlink() or not path.is_dir():
            raise ValueError('installed mock cache directory differs')
        if provider_config != {'id': 'provider-1', 'type': 'openai_chat_completion', 'model': 'model-1'}:
            raise ValueError('installed mock provider configuration differs')
        instance = object.__new__(cls)
        instance.root = path
        instance.provider_id = provider_config['id']
        instance.config_digest = hashlib.sha256(_canonical(provider_config).encode()).hexdigest()
        instance.recorded_requests = 0
        binding = dict(authority_id=authority_id, installation_id=installation_id,
            namespace=namespace, provider_id=instance.provider_id, config_digest=instance.config_digest)
        if json.loads(_read(path, 'binding.json')) != binding:
            raise ValueError('installed mock cache binding differs')
        if (hashlib.sha256(_read(path, 'adapter')).hexdigest() != executable_sha256
                or hashlib.sha256(_read(path, 'verification-key')).hexdigest() != public_key_sha256):
            raise ValueError('original installed mock adapter pins differ')
        return instance

    def installation_material(self):
        """Only original pinned public configuration; no private key export."""
        return dict(root=str(self.root), **json.loads(_read(self.root, 'binding.json')),
            executable_sha256=hashlib.sha256(_read(self.root, 'adapter')).hexdigest(),
            public_key_sha256=hashlib.sha256(_read(self.root, 'verification-key')).hexdigest())

    def recorded_request_count(self):
        with _locked(self.root):
            members = tuple((self.root / 'cache').iterdir())
            if len(members) > 256 or any(not path.is_file() or path.is_symlink() for path in members):
                raise ValueError('owned mock cache inventory differs')
            return len(members)

    def wrap(self, handler):
        def cached(request):
            if request.url.host != 'mock.invalid' or request.method != 'POST':
                raise ValueError('non-mock provider request refused')
            body = request.content
            if len(body) > 8 * 1024 * 1024 or json.loads(body).get('model') != 'model-1':
                raise ValueError('mock provider body differs')
            with _locked(self.root):
                if not (self.root / 'binding.json').is_file():
                    raise ValueError('mock cache installation not bound before request')
                if (self.root / 'purged').exists():
                    raise ValueError('retired mock cache cannot accept a new request')
                members = tuple((self.root / 'cache').iterdir())
                if len(members) >= 256 or sum(path.lstat().st_size for path in members) + len(body) > 32 * 1024 * 1024:
                    raise ValueError('finite mock cache exhausted')
                _write_new(self.root / 'cache' / (uuid.uuid4().hex + '.request'), body)
                self.recorded_requests += 1
            return handler(request)
        return cached

    def bind(self, *, authority_id, installation_id, namespace):
        document = dict(authority_id=authority_id, installation_id=installation_id,
            namespace=namespace, provider_id=self.provider_id, config_digest=self.config_digest)
        if any(type(value) is not str or not value for value in document.values()):
            raise ValueError('actual installation binding required')
        with _locked(self.root):
            if (self.root / 'binding.json').exists():
                if json.loads(_read(self.root, 'binding.json')) != document:
                    raise ValueError('mock cache installation rebinding refused')
                return
            if self.recorded_requests:
                raise ValueError('mock cache must bind installation before the first request')
            _write_new(self.root / 'binding.json', _canonical(document).encode())

    def installed_disposition(self):
        from sylanne3.authority_service.c09_provider_cache_v1 import InstalledProviderCacheDispositionV1
        if not (self.root / 'binding.json').is_file():
            raise ValueError('mock cache installation not bound')
        return InstalledProviderCacheDispositionV1(provider_id=self.provider_id,
            executable=self.root / 'adapter', executable_sha256=hashlib.sha256(_read(self.root, 'adapter')).hexdigest(),
            public_key_path=self.root / 'verification-key',
            public_key_sha256=hashlib.sha256(_read(self.root, 'verification-key')).hexdigest(),
            provider_config_digests=(self.config_digest,))


def _adapter_main(root_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    root = Path(root_path)
    request = json.loads(sys.stdin.buffer.read(1048577))
    fields = {'schema', 'action', 'provider_id', 'installation_id', 'authority_id', 'namespace',
        'operation_id', 'manifest_digest', 'scope', 'receipt_id', 'provider_config_scopes',
        'scope_inventory_digest', 'request_digest'}
    if set(request) != fields or request['schema'] != 'sylanne3.c09.provider-cache-request.v2':
        raise ValueError('closed exact-scope request required')
    unsigned = {key: value for key, value in request.items() if key != 'request_digest'}
    if request['request_digest'] != hashlib.sha256(_canonical(unsigned).encode()).hexdigest():
        raise ValueError('request commitment differs')
    binding = json.loads(_read(root, 'binding.json'))
    if (any(request[name] != binding[name] for name in ('provider_id', 'authority_id', 'installation_id', 'namespace'))
            or request['provider_config_scopes'] != [[binding['provider_id'], binding['config_digest']]]
            or request['scope'] != 'installation_namespace_exact_provider_config_prompt_caches'
            or request['action'] not in {'purge', 'read'}):
        raise ValueError('actual installed mock cache scope differs')
    with _locked(root):
        prior = json.loads(_read(root, 'purged')) if (root / 'purged').exists() else None
        scope = {name: request[name] for name in ('operation_id', 'manifest_digest', 'scope_inventory_digest')}
        if prior is not None and prior['scope'] != scope:
            raise ValueError('cache disposition belongs to another operation')
        if request['action'] == 'purge':
            members = sorted((root / 'cache').iterdir())
            if len(members) > 256 or sum(path.lstat().st_size for path in members) > 32 * 1024 * 1024:
                raise ValueError('finite mock cache inventory exceeded')
            for path in members:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    before = os.fstat(fd)
                    named = path.lstat()
                    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                            or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)):
                        raise ValueError('cache member ownership changed')
                    path.unlink()
                    _sync_dir(path.parent)
                    if os.fstat(fd).st_nlink != 0:
                        raise ValueError('cache member survived unlink')
                finally:
                    os.close(fd)
            if prior is None:
                prior = {'scope': scope, 'receipt_id': uuid.uuid4().hex}
                _write_new(root / 'purged', _canonical(prior).encode())
        if prior is None or any((root / 'cache').iterdir()):
            raise ValueError('cache is not independently absent')
        if request['receipt_id'] is not None and request['receipt_id'] != prior['receipt_id']:
            raise ValueError('purge receipt differs')
        payload = dict(schema='sylanne3.c09.provider-cache-original.v2',
            request_digest=request['request_digest'], provider_id=binding['provider_id'],
            receipt_id=prior['receipt_id'], state='absent', scope=request['scope'],
            provider_config_scopes=request['provider_config_scopes'],
            scope_inventory_digest=request['scope_inventory_digest'])
        signature = Ed25519PrivateKey.from_private_bytes(_read(root, 'signing-key')).sign(
            payload['schema'].encode() + b'\0' + _canonical(payload).encode())
        sys.stdout.write(_canonical({'payload': payload, 'signature': base64.b64encode(signature).decode()}))
