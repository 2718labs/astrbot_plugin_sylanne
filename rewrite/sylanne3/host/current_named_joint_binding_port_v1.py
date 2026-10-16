"""Installed named Joint port; only private same-Scope current facts authorize WRITE."""
from weakref import WeakKeyDictionary
from dataclasses import replace
from ..runtime_contracts import FenceScope, canonical_digest
from ..authority_service.current_named_joint_binding_v1 import (NamedJointBindingSelectorV1,
    named_joint_selector_to_wire_v1, named_joint_current_from_wire_v1)
from .v2_fence_port import V2FencePort

_PORTS = WeakKeyDictionary()


class InstalledCurrentNamedJointBindingPortV1:
    def __init__(self, context):
        from ..runtime_context import RuntimeContext
        from ..graph_coordinator import GraphCoordinator
        from .authority_profile import AdminInstallationBundle
        if (type(context) is not RuntimeContext or type(context._v2_coordinator) is not GraphCoordinator
                or type(context._v2_port) is not V2FencePort or type(context._v2_model_bundle) is not AdminInstallationBundle
                or context._v2_coordinator._GraphCoordinator__content_fence_v2 is not context._v2_port):
            raise TypeError('Named Joint requires the actual installed Context/Graph/paired fence')
        if context in _PORTS:
            raise ValueError('Named Joint port is already installed on this Context')
        self.context, self.graph, self.base, self.bundle = context, context._v2_coordinator, context._v2_port, context._v2_model_bundle
        self._observations = {}
        _PORTS[context] = self

    def require_installed_v1(self):
        if (_PORTS.get(self.context) is not self or self.context._v2_coordinator is not self.graph
                or self.context._v2_port is not self.base or self.context._v2_model_bundle is not self.bundle):
            raise ValueError('Named Joint actual installation changed')
        return self

    def current_for_fence_v1(self, *, scope, request):
        self.require_installed_v1()
        from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1,source_note_scope_operation_id_v1
        note=type(request)is NamedJointSourceNoteSelectorV1
        expected_id=source_note_scope_operation_id_v1(request)if note else request.operation_id
        if (type(scope) is not FenceScope or type(request) not in {NamedJointBindingSelectorV1,NamedJointSourceNoteSelectorV1}
                or scope.operation not in {'read', 'write'} or scope.namespace != request.namespace
                or request.installation_id != self.bundle.installation_policy.installation_id
                or scope.namespace != self.bundle.installation_policy.namespace
                or scope.operation == 'write' and scope.operation_id != expected_id
                or self.graph._GraphCoordinator__store._db.in_transaction
                or self.base.validate_fence(scope) != scope.permit):
            raise ValueError('Named Joint exact current observation must precede Graph SQL')
        evidence, permit = self.base._submit(self.base._with_session_repair(
            lambda: self._rpc_v1(scope=scope, request=request)))
        if scope.operation == 'write':
            previous = self._observations.get(id(scope))
            if previous is not None and (previous[0] is not scope or previous[1] != request
                    or _same_observed_time_v1(evidence,previous[2]) != previous[2]):
                raise ValueError('Named Joint repeated same-Scope observation changed its original facts')
            self._observations[id(scope)] = (scope, request, evidence, canonical_digest(evidence))
        return evidence, permit

    async def _rpc_v1(self, *, scope, request):
        from ..authority_service.v2_contract import SCHEMA, to_wire, from_wire
        await self.base._mapped(scope.namespace, scope.authority_namespace)
        handshake, grant = self.base._identity()
        from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteSelectorV1,note_selector_to_wire_v1,note_current_from_wire_v1
        note=type(request)is NamedJointSourceNoteSelectorV1
        encode=note_selector_to_wire_v1 if note else named_joint_selector_to_wire_v1
        decode=note_current_from_wire_v1 if note else named_joint_current_from_wire_v1
        response = await self.base._transport._content_rpc(self.base._request, handshake,
            'named_joint_source_note_current_v1'if note else'named_joint_binding_current_v1', {'namespace': scope.authority_namespace,
                'permit': to_wire(scope.permit), 'request': encode(request)}, protocol=SCHEMA)
        if (type(response) is not dict or response.pop('channel_binding_sha256', None) != handshake.channel_binding_sha256
                or set(response) != {'evidence', 'permit'}):
            raise ValueError('Named Joint paired channel/response fields differ')
        evidence, permit = decode(response['evidence']), from_wire(response['permit'])
        evidence.require_for_v3(request=request, permit=scope.permit,
            installation_id=grant.installation_id, authority_namespace=scope.authority_namespace)
        if permit != scope.permit:
            raise ValueError('Named Joint response changed the actual paired permit')
        return evidence, permit

    def require_issued_write_v1(self, *, scope, request, evidence):
        self.require_installed_v1()
        value = self._observations.get(id(scope))
        if (scope.operation != 'write' or value is None or value[0] is not scope
                or value[1:] != (request, evidence, canonical_digest(evidence))):
            raise ValueError('Named Joint WRITE requires this installed port actual same-Scope observation')
        return evidence

    def release_write_v1(self, scope):
        value = self._observations.get(id(scope))
        if value is not None and value[0] is scope:
            self._observations.pop(id(scope), None)


def installed_named_joint_binding_port_v1(context):
    previous = _PORTS.get(context)
    return previous.require_installed_v1() if previous is not None else InstalledCurrentNamedJointBindingPortV1(context)


def _same_observed_time_v1(current,previous):
    from ..authority_service.current_named_joint_source_note_v1 import NamedJointSourceNoteCurrentV1
    if type(current)is NamedJointSourceNoteCurrentV1:
        evidence=current.original_evidence;before=previous.original_evidence
        from ..authority_service.current_owner_source_note_task_v1 import OwnerTaskActivityEvidenceV1
        if type(evidence)is OwnerTaskActivityEvidenceV1 and type(before)is OwnerTaskActivityEvidenceV1:
            evidence=replace(evidence,observed_at_utc=before.observed_at_utc)
        current=replace(current,original_evidence=evidence)
    return replace(current,observed_at_utc=previous.observed_at_utc)
