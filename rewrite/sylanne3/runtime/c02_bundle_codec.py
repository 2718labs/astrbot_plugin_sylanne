"""Strict, data-only codec for a frozen first-ingress C02 domain bundle."""

from __future__ import annotations

from dataclasses import fields
import json

from ..graph_types import AtomKey, GraphVersion, GraphWrite
from ..runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, DomainBundle,
    DomainProposal, NamespaceId, OperationIdentity, QueryEpoch,
    SourceQualification, VersionGuard, VersionedRef, canonical_serialize,
)


_LIST = "list"
_OPTIONAL = "optional"
_JSON = "json"

# This is the complete set of DTO classes the C02 bundle may contain. Wire
# names are checked against these exact classes; no name is ever imported.
_FIELDS: dict[type, dict[str, object]] = {
    NamespaceId: {"bot_id": str, "persona_id": str},
    GraphVersion: {"key": AtomKey, "revision": int},
    GraphWrite: {"key": AtomKey, "value": _JSON,
                 "dependencies": (_LIST, AtomKey)},
    VersionedRef: {"ref": str, "version": int},
    QueryEpoch: {"namespace": NamespaceId, "scope_ref": str,
                 "revision": int},
    OperationIdentity: {
        "activity_id": str, "effect_id": (_OPTIONAL, str), "attempt_id": str,
        "phase": str, "operation_id": str, "canonical_input_digest": str,
    },
    AuthorityContext: {
        "actor": str, "issuer_domain": str, "capability_ref": str,
        "namespace": NamespaceId, "owner_scope": (_LIST, str),
        "purpose": str, "audience": (_LIST, str),
        "provider_policy_ref": str, "activation_generation": int,
        "worker_fence": (_OPTIONAL, int),
    },
    VersionGuard: {
        "read_versions": (_LIST, GraphVersion),
        "query_epochs": (_LIST, QueryEpoch),
        "access_epoch": int, "delete_epoch": int,
        "catalogue_version": str, "scheme_version": str,
        "operator_version": str, "policy_version": str,
        "source_grant_refs": (_LIST, VersionedRef),
        "focus_lease_versions": (_LIST, VersionedRef),
        "resource_lease_versions": (_LIST, VersionedRef),
    },
    SourceQualification: {
        "source_refs": (_LIST, str), "source_family": str,
        "occurred_at": (_OPTIONAL, float), "learned_at": float,
        "content_reality": str, "evidence_eligibility": str,
        "subjective_confidence": (_OPTIONAL, float),
        "internal_activity_actuality": str,
    },
    DependencySet: {
        "current_invalidation": (_LIST, GraphVersion),
        "historical_provenance": (_LIST, GraphVersion),
        "associations": (_LIST, GraphVersion),
        "numeric_coupling": (_LIST, GraphVersion),
    },
    CommandEnvelope: {
        "schema": str, "identity": OperationIdentity,
        "authority": AuthorityContext, "version_guard": VersionGuard,
        "source_qualification": SourceQualification,
        "input_refs": (_LIST, str), "parent_budget_lease_ref": str,
        "deadline_utc": float, "monotonic_deadline": float,
        "character_interval_ref": str, "causation": (_LIST, str),
    },
    DomainProposal: {
        "domain": str, "proposal_schema": str, "proposal_schema_hash": str,
        "envelope": CommandEnvelope, "typed_writes": (_LIST, GraphWrite),
        "dependencies": DependencySet,
        "contribution_keys": (_LIST, str),
        "required_bundle_parts": (_LIST, str),
    },
    DomainBundle: {
        "envelope": CommandEnvelope,
        "proposals": (_LIST, DomainProposal),
        "experience_refs": (_LIST, str), "choice_refs": (_LIST, str),
        "d02_settlement_refs": (_LIST, str),
        "d11_cost_settlement_refs": (_LIST, str),
        "idempotency_keys": (_LIST, str),
        "persistent_job_refs": (_LIST, str), "outbox_refs": (_LIST, str),
        "product_advance": (_OPTIONAL, type(None)),
    },
}


def _plain_json(value: object) -> object:
    """Accept JSON data without interpreting any embedded marker as a DTO."""
    if value is None or type(value) in (str, bool, int, float):
        return value
    if type(value) is list:
        return [_plain_json(item) for item in value]
    if type(value) is dict and all(type(key) is str for key in value):
        return {key: _plain_json(item) for key, item in value.items()}
    raise ValueError("GraphWrite.value must be plain JSON data")


def _decode(raw: object, kind: object) -> object:
    if kind == _JSON:
        if type(raw) is not dict:
            raise ValueError("GraphWrite.value must be a JSON object")
        return _plain_json(raw)
    if type(kind) is tuple:
        mode, inner = kind
        if mode == _OPTIONAL:
            return None if raw is None else _decode(raw, inner)
        if mode == _LIST and type(raw) is list:
            return tuple(_decode(item, inner) for item in raw)
        raise ValueError("C02 bundle collection shape differs")
    if kind is type(None):
        if raw is not None:
            raise ValueError("C02 bundle optional field must be null")
        return None
    if kind in (str, int, float):
        if type(raw) is not kind:
            raise ValueError("C02 bundle scalar type differs")
        return raw
    if kind is AtomKey:
        if type(raw) is not dict or set(raw) != {"$type", "token"}:
            raise ValueError("C02 atom key fields differ")
        if raw["$type"] != "AtomKey" or type(raw["token"]) is not str:
            raise ValueError("C02 atom key type differs")
        return AtomKey.from_token(raw["token"])
    allowed = _FIELDS.get(kind)
    if allowed is None or type(raw) is not dict:
        raise ValueError("unsupported C02 bundle DTO")
    expected_type = f"{kind.__module__}.{kind.__qualname__}"
    if (set(raw) != {"$type", *allowed}
            or raw.get("$type") != expected_type
            or set(allowed) != {field.name for field in fields(kind)}):
        raise ValueError("C02 bundle DTO fields or type differ")
    return kind(**{name: _decode(raw[name], spec)
                   for name, spec in allowed.items()})


def _require_c02(bundle: DomainBundle) -> None:
    if (type(bundle) is not DomainBundle
            or bundle.envelope.identity.phase != "first_ingress_c02"
            or len(bundle.proposals) != 2
            or tuple(item.domain for item in bundle.proposals) != ("d06", "d11")
            or any((bundle.experience_refs, bundle.choice_refs,
                    bundle.d02_settlement_refs, bundle.d11_cost_settlement_refs,
                    bundle.idempotency_keys, bundle.persistent_job_refs,
                    bundle.outbox_refs))
            or bundle.product_advance is not None):
        raise ValueError("only a two-proposal C02 bundle is supported")


def c02_bundle_to_wire(bundle: DomainBundle) -> str:
    """Save the existing canonical DomainBundle wire representation unchanged."""
    _require_c02(bundle)
    text = canonical_serialize(bundle)
    if c02_bundle_from_wire(text) != bundle:
        raise ValueError("C02 bundle contains an unsupported DTO")
    return text


def c02_bundle_from_wire(text: str) -> DomainBundle:
    """Decode only the explicit C02 DTO tree and reject noncanonical input."""
    if type(text) is not str:
        raise TypeError("C02 bundle wire text required")
    try:
        raw = json.loads(text, parse_constant=lambda _value: (
            _reject_constant()))
        bundle = _decode(raw, DomainBundle)
        _require_c02(bundle)
        if canonical_serialize(bundle) != text:
            raise ValueError("noncanonical C02 bundle wire value")
        # Recompute through the model property, including its legacy digest
        # rule for product_advance=None.
        if type(bundle.digest) is not str or len(bundle.digest) != 64:
            raise ValueError("C02 bundle digest unavailable")
        return bundle
    except (TypeError, KeyError, AttributeError) as exc:
        raise ValueError("invalid C02 bundle wire value") from exc


def _reject_constant() -> object:
    raise ValueError("nonfinite C02 bundle JSON number")


__all__ = ("c02_bundle_to_wire", "c02_bundle_from_wire")
