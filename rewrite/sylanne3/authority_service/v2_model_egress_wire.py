"""Exact JSON shapes for passive model identity and an admission candidate.

The request is caller data. Only the Authority's independent graph verifier,
installed policy, and fenced CAS can grant a dispatch admission.
"""

from __future__ import annotations

from dataclasses import fields, is_dataclass
import json
from typing import Mapping

from ..graph_types import AtomKey, GraphVersion, Owner
from ..model_broker.broker import ModelCallRequest
from ..runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    QueryEpoch, SourceQualification, VersionGuard, VersionedRef,
)
from .v2_model_egress_contract import (
    ModelNoDispatchClosureRequestV1, ModelNoDispatchWitnessV1,
    ModelEgressDraftV1, ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelAdmissionV2, HostObservedModelCompletionV2, ModelTerminalReceiptV2,
    ModelEgressObservationV1, model_observation_to_wire_v1, model_observation_from_wire_v1,
    host_model_completion_to_wire_v2, host_model_completion_from_wire_v2,
)


def _plain(value):
    if type(value) is ModelEgressObservationV1:
        return model_observation_to_wire_v1(value)
    if type(value) is HostObservedModelCompletionV2:
        return host_model_completion_to_wire_v2(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if type(value) is frozenset:
        return sorted(_plain(item) for item in value)
    if type(value) in {tuple, list}:
        return [_plain(item) for item in value]
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ValueError("model wire object keys must be strings")
        return {key: _plain(item) for key, item in value.items()}
    if value is None or type(value) in {str, bool, int, float}:
        return value
    raise ValueError("unsupported model wire value")


def to_wire(value):
    if type(value) is ModelNoDispatchWitnessV1:
        from .v2_contract import to_wire as permit_to_wire
        result = _plain(value)
        result["original_permit"] = permit_to_wire(value.original_permit)
        json.dumps(result, allow_nan=False)
        return result
    if type(value) not in {ModelNoDispatchClosureRequestV1, ModelEgressDraftV1, ModelEgressIntentV1,
                           ModelEgressRecoveryV1, ModelCallRequest,
                           ModelAdmissionV2, HostObservedModelCompletionV2,
                           ModelTerminalReceiptV2, ModelEgressObservationV1}:
        raise ValueError("unsupported model wire type")
    plain = _plain(value)
    # Reject NaN and other values that cannot cross the stdlib JSON transport.
    json.dumps(plain, allow_nan=False)
    return plain


def _shape(value, kind):
    if type(value) is not dict or set(value) != {field.name for field in fields(kind)}:
        raise ValueError("model wire fields differ")
    return dict(value)


def _list(value):
    if type(value) is not list:
        raise ValueError("model wire sequence required")
    return value


def _pairs(value):
    return tuple(tuple(_list(item)) for item in _list(value))


def command_envelope_from_wire_v2(value):
    """Decode the existing exact formal envelope without fabricating a model body."""
    envelope = _shape(value, CommandEnvelope)
    authority = _shape(envelope["authority"], AuthorityContext)
    authority["namespace"] = NamespaceId(**_shape(authority["namespace"], NamespaceId))
    for name in ("owner_scope", "audience"):
        authority[name] = tuple(_list(authority[name]))
    guard = _shape(envelope["version_guard"], VersionGuard)
    reads = []
    for item in _list(guard["read_versions"]):
        version = _shape(item, GraphVersion)
        key = _shape(version["key"], AtomKey)
        key["owner"] = Owner(**_shape(key["owner"], Owner))
        version["key"] = AtomKey(**key)
        reads.append(GraphVersion(**version))
    guard["read_versions"] = tuple(reads)
    queries = []
    for item in _list(guard["query_epochs"]):
        query = _shape(item, QueryEpoch)
        query["namespace"] = NamespaceId(**_shape(query["namespace"], NamespaceId))
        queries.append(QueryEpoch(**query))
    guard["query_epochs"] = tuple(queries)
    for name in ("source_grant_refs", "focus_lease_versions", "resource_lease_versions"):
        guard[name] = tuple(VersionedRef(**_shape(item, VersionedRef))
                            for item in _list(guard[name]))
    qualification = _shape(envelope["source_qualification"], SourceQualification)
    qualification["source_refs"] = tuple(_list(qualification["source_refs"]))
    envelope["identity"] = OperationIdentity(**_shape(envelope["identity"], OperationIdentity))
    envelope["authority"] = AuthorityContext(**authority)
    envelope["version_guard"] = VersionGuard(**guard)
    envelope["source_qualification"] = SourceQualification(**qualification)
    for name in ("input_refs", "causation"):
        envelope[name] = tuple(_list(envelope[name]))
    result = CommandEnvelope(**envelope)
    if _plain(result) != value:
        raise ValueError("noncanonical command envelope wire value")
    return result


def from_wire(value, kind):
    if kind is ModelNoDispatchClosureRequestV1:
        from ..runtime.restore_anchor import RestoreAnchor
        shaped = _shape(value, kind)
        shaped["intent"] = from_wire(shaped["intent"], ModelEgressIntentV1)
        shaped["expected_anchor"] = RestoreAnchor(**_shape(shaped["expected_anchor"], RestoreAnchor))
        result = kind(**shaped)
        if _plain(result) != value: raise ValueError("noncanonical exact no-dispatch closure wire")
        return result
    if kind is ModelNoDispatchWitnessV1:
        from ..runtime.restore_anchor import RestoreAnchor
        from .v2_contract import from_wire as permit_from_wire, FencePermitV2
        shaped = _shape(value, kind)
        shaped["request"] = from_wire(shaped["request"], ModelNoDispatchClosureRequestV1)
        shaped["original_permit"] = permit_from_wire(shaped["original_permit"])
        if type(shaped["original_permit"]) is not FencePermitV2:
            raise ValueError("no-dispatch original permit wire differs")
        for name in ("before_anchor", "after_anchor"):
            shaped[name] = RestoreAnchor(**_shape(shaped[name], RestoreAnchor))
        result = kind(**shaped)
        if to_wire(result) != value: raise ValueError("noncanonical Authority no-dispatch witness wire")
        return result
    if kind in {ModelEgressDraftV1, ModelEgressIntentV1}:
        shaped = _shape(value, kind)
        shaped["source_refs"] = tuple(_list(shaped["source_refs"]))
        for name in ("source_revisions", "access_revisions", "budget_ceiling"):
            shaped[name] = _pairs(shaped[name])
        result = kind(**shaped)
    elif kind is ModelEgressRecoveryV1:
        shaped = _shape(value, kind)
        shaped["intent"] = from_wire(shaped["intent"], ModelEgressIntentV1)
        shaped["usage"] = _pairs(shaped["usage"])
        shaped["cost"] = _pairs(shaped["cost"])
        result = kind(**shaped)
    elif kind in {ModelAdmissionV2, ModelTerminalReceiptV2}:
        result = kind(**_shape(value, kind))
    elif kind is HostObservedModelCompletionV2:
        result = host_model_completion_from_wire_v2(value)
    elif kind is ModelEgressObservationV1:
        result = model_observation_from_wire_v1(value)
    elif kind is ModelCallRequest:
        shaped = _shape(value, ModelCallRequest)
        shaped["envelope"] = command_envelope_from_wire_v2(shaped["envelope"])
        shaped["required_capabilities"] = frozenset(_list(shaped["required_capabilities"]))
        result = ModelCallRequest(**shaped)
    else:
        raise ValueError("unsupported model wire type")
    if to_wire(result) != value:
        raise ValueError("noncanonical model wire value")
    return result


__all__ = ["from_wire", "to_wire", "command_envelope_from_wire_v2"]
