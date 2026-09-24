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
    ModelEgressDraftV1, ModelEgressIntentV1, ModelEgressRecoveryV1,
)


def _plain(value):
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
    if type(value) not in {ModelEgressDraftV1, ModelEgressIntentV1,
                           ModelEgressRecoveryV1, ModelCallRequest}:
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


def from_wire(value, kind):
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
    elif kind is ModelCallRequest:
        shaped = _shape(value, ModelCallRequest)
        envelope = _shape(shaped["envelope"], CommandEnvelope)
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
        shaped["envelope"] = CommandEnvelope(**envelope)
        shaped["required_capabilities"] = frozenset(_list(shaped["required_capabilities"]))
        result = ModelCallRequest(**shaped)
    else:
        raise ValueError("unsupported model wire type")
    if to_wire(result) != value:
        raise ValueError("noncanonical model wire value")
    return result


__all__ = ["from_wire", "to_wire"]
