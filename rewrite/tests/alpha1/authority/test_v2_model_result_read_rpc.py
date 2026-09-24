"""Versioned result read and content-free terminal RPC boundaries."""

import pytest

from rewrite.tests.alpha1.authority.test_v2_model_result_read import _request
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressObservationV1, ModelTerminalReceiptV2,
)


def test_result_read_wire_rejects_changed_owner_session_identity():
    from sylanne3.authority_service.v2_model_result_read_wire import from_wire, to_wire
    from sylanne3.authority_service.v2_model_result_read_contract import ModelResultReadRequestV1

    request = _request()
    encoded = to_wire(request)
    assert from_wire(encoded, ModelResultReadRequestV1) == request
    changed = {**encoded, "owner_session_request": {
        **encoded["owner_session_request"], "installation_id": "other-installation"}}
    with pytest.raises((ValueError, TypeError)):
        from_wire(changed, ModelResultReadRequestV1)


def test_result_wire_keeps_original_terminal_binding():
    from sylanne3.authority_service.v2_model_result_read_wire import from_wire, to_wire
    from sylanne3.authority_service.v2_model_result_read_contract import ModelResultReadV1

    observation = ModelEgressObservationV1(
        "authority-1", "namespace-1", "worker-1", "operation-1",
        "call-1", "a" * 64, "completed", '{"answer":"ok"}',
        (("input_tokens", 1),), (("micro_usd", 2),), None)
    receipt = ModelTerminalReceiptV2(
        "b" * 64, "call-1", "a" * 64, "c" * 64,
        observation.digest, "sha256:" + "d" * 64,
        "installation-1", "e" * 64)
    result = ModelResultReadV1("call-1", observation, receipt)
    encoded = to_wire(result)
    assert from_wire(encoded, ModelResultReadV1) == result
    with pytest.raises((ValueError, TypeError)):
        from_wire({**encoded, "terminal_receipt": {
            **encoded["terminal_receipt"], "observation_digest": "f" * 64}},
            ModelResultReadV1)
