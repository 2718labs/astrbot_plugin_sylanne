"""Current installed Root resources for an explicitly accepted inspection workflow."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from weakref import WeakKeyDictionary

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest, canonical_serialize

_ISSUER = object()
_PROOFS = WeakKeyDictionary()


@dataclass(frozen=True, eq=False)
class VerifiedInspectionWorkflowResourceV1:
    _issuer: object
    _provider: object
    _lifecycle: object
    _original_json: str
    deadline_utc: float
    approval_digest: str
    spec_digest: str
    binding_digest: str

    def __post_init__(self):
        if self._issuer is not _ISSUER:
            raise AuthorityUnavailable("installed inspection resource private issuer required")
        _PROOFS[self] = (id(self._provider), id(self._lifecycle), self._original_json)

    def require_current_v1(self, *, lifecycle):
        if (_PROOFS.get(self) != (id(self._provider), id(lifecycle), self._original_json)
                or lifecycle is not self._lifecycle):
            raise AuthorityUnavailable("inspection workflow resource belongs to another lifecycle")
        current = self._provider._read_current_v1(lifecycle)
        if canonical_serialize(current) != self._original_json:
            raise AuthorityUnavailable("inspection workflow Root resource original changed")
        return self

    def as_original_v1(self):
        self.require_current_v1(lifecycle=self._lifecycle)
        return json.loads(self._original_json)


class InstalledInspectionWorkflowResourceV1:
    def __init__(self):
        self._sdk_daemon = None

    @classmethod
    def from_controlled_sdk_v4(cls, *, daemon):
        from ..host.c09_controlled_sdk_bootstrap_v3 import read_actual_controlled_sdk_root_resource_v4
        read_actual_controlled_sdk_root_resource_v4(daemon=daemon).require_current_v4(daemon=daemon)
        result = cls()
        result._sdk_daemon = daemon
        return result

    def _read_current_v1(self, lifecycle):
        from .d12_installation_lifecycle_v1 import InstalledD12InstallationLifecycleV1
        if type(lifecycle) is not InstalledD12InstallationLifecycleV1:
            raise AuthorityUnavailable("actual installed lifecycle resource consumer required")
        control = lifecycle.control
        control.lease.require_held()
        if self._sdk_daemon is None:
            from .installed_root_lifetime_observer_v3 import (
                read_installed_root_lifetime_spec_v3, read_root_lifetime_resource_approval_v3)
            spec = read_installed_root_lifetime_spec_v3()
            approval = read_root_lifetime_resource_approval_v3(spec)
            if ((spec['authority_id'], spec['installation_id'], spec['profile_id'], tuple(spec['namespace_cohort']))
                    != (control.authority_id, lifecycle.installation_id, lifecycle.peer[1], (lifecycle.namespace,))):
                raise AuthorityUnavailable("installed Root resource crosses the current lifecycle identity")
            deadline = datetime.fromisoformat(approval['deadline_utc'].replace('Z', '+00:00')).timestamp()
            original = dict(schema='sylanne.source-inspection-workflow-resource.v1',
                profile='installed_root', authority_id=control.authority_id,
                installation_id=lifecycle.installation_id, authority_namespace=lifecycle.namespace,
                namespace=dict(bot_id=lifecycle.namespace_id.bot_id, persona_id=lifecycle.namespace_id.persona_id),
                control_store_id=control.control_store_id, deadline_utc=float(deadline),
                approval_digest=approval['approval_original_digest'], spec_digest=spec['spec_digest'],
                root_spec=spec, resource_approval=approval)
        else:
            from ..host.c09_controlled_sdk_bootstrap_v3 import read_actual_controlled_sdk_root_resource_v4
            daemon = self._sdk_daemon
            if daemon.core is not lifecycle.core or daemon.c09_control is not control:
                raise AuthorityUnavailable("SDK resource crosses the actual lifecycle Core/Control")
            resource = read_actual_controlled_sdk_root_resource_v4(daemon=daemon)
            resource.require_current_v4(daemon=daemon)
            sdk = resource.as_original_v4()
            if (sdk['authority_id'], sdk['installation_id'], sdk['control_store_id'], sdk['namespace']) != (
                    control.authority_id, lifecycle.installation_id, control.control_store_id, lifecycle.namespace):
                raise AuthorityUnavailable("SDK Root resource crosses the current installation namespace")
            original = dict(schema='sylanne.source-inspection-workflow-resource.v1', profile='controlled_sdk',
                authority_id=control.authority_id, installation_id=lifecycle.installation_id,
                authority_namespace=lifecycle.namespace,
                namespace=dict(bot_id=lifecycle.namespace_id.bot_id, persona_id=lifecycle.namespace_id.persona_id),
                control_store_id=control.control_store_id, deadline_utc=resource.deadline_utc,
                approval_digest=resource.approval_digest, spec_digest=resource.spec_digest, resource_original=sdk)
        original['binding_digest'] = canonical_digest(original)
        return original

    def qualify_current_v1(self, *, lifecycle):
        original = self._read_current_v1(lifecycle)
        return VerifiedInspectionWorkflowResourceV1(_ISSUER, self, lifecycle, canonical_serialize(original),
            original['deadline_utc'], original['approval_digest'], original['spec_digest'], original['binding_digest'])
