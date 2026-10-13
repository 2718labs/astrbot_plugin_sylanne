"""Exact JSON encoding for versioned Owner-qualified model result reads."""

from __future__ import annotations

from dataclasses import asdict, fields
import json

from ..runtime_contracts import NamespaceId, canonical_serialize
from .v2_model_egress_contract import ModelTerminalReceiptV2
from .v2_model_result_read_contract import ModelResultReadRequestV1, ModelResultReadV1
from .v2_owner_session import (
    OwnerSessionLoginRequestV1, from_wire as session_from_wire,
    to_wire as session_to_wire,
)


def _shape(raw, kind):
    if type(raw) is not dict or set(raw) != {field.name for field in fields(kind)}:
        raise ValueError("model result read wire fields differ")
    return dict(raw)


def to_wire(value: ModelResultReadRequestV1 | ModelResultReadV1) -> dict:
    if type(value) not in {ModelResultReadRequestV1, ModelResultReadV1}:
        raise TypeError("typed model result read wire value required")
    plain = json.loads(canonical_serialize(asdict(value)))
    if type(value) is ModelResultReadRequestV1:
        plain["owner_session_request"] = session_to_wire(value.owner_session_request)
    else:
        from .v2_model_egress_contract import model_observation_to_wire_v1
        plain["observation"] = model_observation_to_wire_v1(value.observation)
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
        from .v2_model_egress_contract import model_observation_from_wire_v1
        shaped["observation"] = model_observation_from_wire_v1(shaped["observation"])
        shaped["terminal_receipt"] = ModelTerminalReceiptV2(
            **_shape(shaped["terminal_receipt"], ModelTerminalReceiptV2))
        result = ModelResultReadV1(**shaped)
    else:
        raise ValueError("unsupported model result read wire type")
    if to_wire(result) != raw:
        raise ValueError("noncanonical model result read wire value")
    return result


__all__ = ("from_wire", "to_wire")
