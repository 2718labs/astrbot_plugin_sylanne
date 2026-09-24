"""Exact JSON encoding for versioned Owner-qualified model result reads."""

from __future__ import annotations

from dataclasses import asdict, fields
import json

from ..runtime_contracts import NamespaceId, canonical_serialize
from .v2_model_egress_contract import ModelEgressObservationV1, ModelTerminalReceiptV2
from .v2_model_result_read_contract import ModelResultReadRequestV1, ModelResultReadV1
from .v2_owner_session import (
    OwnerSessionLoginRequestV1, from_wire as session_from_wire,
    to_wire as session_to_wire,
)


def _shape(raw, kind):
    if type(raw) is not dict or set(raw) != {field.name for field in fields(kind)}:
        raise ValueError("model result read wire fields differ")
    return dict(raw)


def _pairs(raw):
    if type(raw) is not list or any(type(item) is not list for item in raw):
        raise ValueError("model result amount pairs differ")
    return tuple(tuple(item) for item in raw)


def to_wire(value: ModelResultReadRequestV1 | ModelResultReadV1) -> dict:
    if type(value) not in {ModelResultReadRequestV1, ModelResultReadV1}:
        raise TypeError("typed model result read wire value required")
    plain = json.loads(canonical_serialize(asdict(value)))
    if type(value) is ModelResultReadRequestV1:
        plain["owner_session_request"] = session_to_wire(value.owner_session_request)
    return plain


def from_wire(raw: object, kind):
    if kind is ModelResultReadRequestV1:
        shaped = _shape(raw, kind)
        shaped["namespace"] = NamespaceId(**_shape(shaped["namespace"], NamespaceId))
        session = session_from_wire(shaped["owner_session_request"])
        if type(session) is not OwnerSessionLoginRequestV1:
            raise ValueError("Owner session request required")
        shaped["owner_session_request"] = session
        audience = shaped["audience"]
        if type(audience) is not list:
            raise ValueError("result read audience must be a wire list")
        shaped["audience"] = tuple(audience)
        result = ModelResultReadRequestV1(**shaped)
    elif kind is ModelResultReadV1:
        shaped = _shape(raw, kind)
        observation = _shape(shaped["observation"], ModelEgressObservationV1)
        for name in ("usage", "cost"):
            observation[name] = _pairs(observation[name])
        shaped["observation"] = ModelEgressObservationV1(**observation)
        shaped["terminal_receipt"] = ModelTerminalReceiptV2(
            **_shape(shaped["terminal_receipt"], ModelTerminalReceiptV2))
        result = ModelResultReadV1(**shaped)
    else:
        raise ValueError("unsupported model result read wire type")
    if to_wire(result) != raw:
        raise ValueError("noncanonical model result read wire value")
    return result


__all__ = ("from_wire", "to_wire")
