"""Private installation provenance for current D13 pressure policy."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from weakref import ref

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest, canonical_serialize

class D13PressurePolicyNotMigratedV1(AuthorityUnavailable):
    pass


_ISSUER = object()
_BUNDLES = {}


def _policy(bundle):
    from ..runtime.d13_technical_policy import (
        AdminD13PrecompressionPolicyV1, AdminD13PaidPrecompressionPolicyV1)
    technical, paid = bundle.d13_precompression, bundle.d13_paid_precompression
    if technical is not None and type(technical) is not AdminD13PrecompressionPolicyV1:
        raise AuthorityUnavailable('installed technical pressure policy type differs')
    if paid is not None and type(paid) is not AdminD13PaidPrecompressionPolicyV1:
        raise AuthorityUnavailable('installed paid pressure policy type differs')
    if technical is not None and paid is not None:
        if any(getattr(technical, name) != getattr(paid, name) for name in
               ('namespace', 'installation_id', 'max_slots', 'history_token_budget')):
            raise AuthorityUnavailable('technical and paid pressure selection differ')
    return technical if technical is not None else paid


class VerifiedInstalledD13PressurePolicyV1:
    __slots__ = ('_bundle', '_policy', '_policy_digest', '_origin')

    def __init__(self, issuer, bundle, policy, origin):
        if issuer is not _ISSUER:
            raise TypeError('actual descriptor-pinned installation loader required')
        self._bundle = ref(bundle)
        self._policy, self._policy_digest = policy, canonical_digest(policy)
        self._origin = canonical_serialize(origin)

    def require_current(self, *, observer, bundle, work):
        from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
        registered = _BUNDLES.get(id(bundle))
        if (registered is None or registered[0]() is not bundle or registered[1] is not self
                or self._bundle() is not bundle or observer.installed_bundle is not bundle
                or type(work) is not AuthorityGraphReadWorkV3 or work.controller.kind != 'counter'
                or work.service.observer is not observer or not work.complete
                or work.counter_material_scope is None):
            raise AuthorityUnavailable('pressure policy lost its actual installation/Source Work')
        work._actual()
        work.controller.require_installed_v3()
        if (_policy(bundle) is not self._policy
                or canonical_digest(self._policy) != self._policy_digest
                or self._policy.namespace != work.namespace
                or self._policy.installation_id != bundle.installation_policy.installation_id):
            raise AuthorityUnavailable('installed pressure policy changed')
        return self._policy, json.loads(self._origin)


def _retain_loaded_d13_pressure_policy_v1(bundle, *, files, profile_id,
                                          profile_dir, system, payload):
    from ..host import authority_profile as loader
    caller = sys._getframe(1)
    if (caller.f_code is not loader._load_installation_bundle_from_root.__code__
            or caller.f_locals.get('files') is not files
            or caller.f_locals.get('bundle') is not bundle
            or type(files) is not loader._OpenedProfileFilesV2):
        raise AuthorityUnavailable('pressure provenance requires the actual pinned loader')
    policy = _policy(bundle)
    if policy is None:
        return
    fd = files['profile.json']
    before = os.fstat(fd)
    raw = loader._read_fd_bounded(fd, loader._MAX_PROFILE_BYTES)
    after = os.fstat(fd)
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    if (identity(before) != identity(after) or loader._read_profile_json(fd) != payload
            or bundle.tls_profile.profile_id != profile_id
            or bundle.installation_policy.installation_id != policy.installation_id):
        raise AuthorityUnavailable('pressure profile changed during descriptor-pinned loading')
    profile_original = {
        'profile_id': profile_id, 'profile_directory': str(profile_dir),
        'system': system, 'device': before.st_dev, 'file_id': before.st_ino,
        'size': before.st_size, 'mtime_ns': before.st_mtime_ns,
        'profile_sha256': hashlib.sha256(raw).hexdigest(),
        'installation_id': policy.installation_id,
        'installation_policy_digest': canonical_digest(bundle.installation_policy),
    }
    selection = files.selected_package
    if selection is None:
        origin = {'schema': 'sylanne3.d13.pressure-policy.protected-profile.v1',
                  'kind': 'protected_profile_v1', 'profile': profile_original}
    else:
        from dataclasses import asdict
        if selection is not bundle.package_selection:
            raise AuthorityUnavailable('pressure policy selected package identity differs')
        origin = {'schema': 'sylanne3.d13.pressure-policy.selected-configuration.v2',
                  'kind': 'selected_configuration_v2', 'selection': asdict(selection),
                  'profile': profile_original}
    proof = VerifiedInstalledD13PressurePolicyV1(_ISSUER, bundle, policy, validate_d13_pressure_policy_origin_v1(origin))
    key = id(bundle)
    def discard(actual):
        current = _BUNDLES.get(key)
        if current is not None and current[0] is actual:
            del _BUNDLES[key]
    _BUNDLES[key] = (ref(bundle, discard), proof)



def validate_d13_pressure_policy_origin_v1(original):
    """Decode the two historical loader domains; this issues no live policy proof."""
    from pathlib import PurePosixPath
    from uuid import UUID
    from .d13_core_counter_contract_v1 import _sha, _text, _uint
    protected = original.get('schema') if type(original) is dict else None
    shapes = {
        'sylanne3.d13.pressure-policy.protected-profile.v1':
            ('protected_profile_v1', {'schema', 'kind', 'profile'}),
        'sylanne3.d13.pressure-policy.selected-configuration.v2':
            ('selected_configuration_v2', {'schema', 'kind', 'selection', 'profile'}),
    }
    if protected not in shapes:
        raise ValueError('unknown pressure policy provenance schema')
    kind, keys = shapes[protected]
    if set(original) != keys or original['kind'] != kind:
        raise ValueError('exact closed pressure policy provenance required')
    profile = original['profile']
    if type(profile) is not dict or set(profile) != {
            'profile_id', 'profile_directory', 'system', 'device', 'file_id', 'size', 'mtime_ns',
            'profile_sha256', 'installation_id', 'installation_policy_digest'}:
        raise ValueError('exact descriptor-pinned pressure profile original required')
    for name in ('profile_id', 'profile_directory', 'installation_id'):
        _text(profile[name], name)
    for name in ('device', 'file_id', 'size', 'mtime_ns'):
        _uint(profile[name], name)
    for name in ('profile_sha256', 'installation_policy_digest'):
        _sha(profile[name], name)
    path = PurePosixPath(profile['profile_directory'])
    if (profile['system'] not in ('Linux', 'Darwin') or not path.is_absolute()
            or '..' in path.parts or path.name != profile['profile_id']
            or not 1 <= profile['size'] <= 32768):
        raise ValueError('protected pressure profile domain/path/bound differs')
    if kind == 'selected_configuration_v2':
        selection = original['selection']
        if type(selection) is not dict or set(selection) != {
                'installation_id', 'revision', 'package_epoch', 'operation_id', 'release_ref',
                'manifest_sha256', 'cohort_ref', 'cohort_digest', 'prior_selection_digest',
                'selection_digest', 'schema'}:
            raise ValueError('exact selected configuration pressure pointer required')
        if (selection['schema'] != 'sylanne3.d12.package-selection.v2'
                or selection['installation_id'] != profile['installation_id']):
            raise ValueError('pressure selected configuration installation differs')
        for name in ('revision', 'package_epoch'):
            _uint(selection[name], name)
        for name in ('operation_id', 'release_ref', 'cohort_ref'):
            _text(selection[name], name)
        for name in ('manifest_sha256', 'cohort_digest', 'selection_digest'):
            _sha(selection[name], name)
        operation = UUID(selection['operation_id'])
        if operation.version != 4 or str(operation) != selection['operation_id']:
            raise ValueError('pressure selected pointer operation is not canonical UUID4')
        prior = selection['prior_selection_digest']
        if (selection['revision'] == 0) != (prior is None):
            raise ValueError('pressure selected pointer lineage differs')
        if prior is not None:
            _sha(prior, 'prior_selection_digest')
        body = dict(selection)
        body.pop('selection_digest')
        if canonical_digest(body) != selection['selection_digest']:
            raise ValueError('pressure selected pointer commitment differs')
    return original


def require_verified_installed_d13_pressure_policy_v1(*, observer, bundle, work):
    registered = _BUNDLES.get(id(bundle))
    if registered is None or registered[0]() is not bundle:
        raise D13PressurePolicyNotMigratedV1('pressure policy installation has no migrated loader provenance')
    proof = registered[1]
    proof.require_current(observer=observer, bundle=bundle, work=work)
    return proof
