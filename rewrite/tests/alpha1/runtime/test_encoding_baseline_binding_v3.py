"""A new model binding freezes its pre-acquire D04 graph revision."""

from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.runtime.encoding_call_binding import (
    CommittedEncodingBaselineV1, EncodingCallConflict, binding_from_json,
    binding_to_json, prepare_binding,
)
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize

from test_encoding_call_binding import NAMESPACE, SOURCE, _request
from sylanne3.model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
)


BASELINE_KEY = AtomKey(Owner("event", "bot", "persona", "arrival-event"),
                       "d04.encoding_baseline.v1", "record")
BASELINE = CommittedEncodingBaselineV1(
    BASELINE_KEY.token, 1, "d04-op", "a" * 64, "graph-incarnation", 12)


def _production():
    return SimpleNamespace(
        acquire_operation_id="operation-1",
        job=SimpleNamespace(work_kind="d06.encode_source",
                            operation_id="operation-1", budget_ref="budget-1",
                            fence=1, lease_expires_utc="2030-01-01T00:00:00Z"),
        monotonic_deadline=100.0, character_interval_ref="interval-1",
        deadline_utc=100.0, clock_epoch="clock-1",
    )


def _v3_request(*, guard_baseline=True):
    request = _request()
    versions = request.envelope.version_guard.read_versions
    if guard_baseline:
        versions += (GraphVersion(BASELINE_KEY, 1),)
    envelope = replace(request.envelope,
                       version_guard=replace(request.envelope.version_guard,
                                             read_versions=versions))
    return replace(request, envelope=envelope)


def _bind(request, baseline=BASELINE):
    return prepare_binding(
        NAMESPACE, "job-1", SOURCE, 1, 1, "budget-1", "operation-1", request,
        prompt_template_version=FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
        provider_config_ref="admin-config-1", provider_config_digest="b" * 64,
        production_context=_production(), baseline=baseline)


def test_v3_freezes_committed_baseline_in_request_and_binding_digest():
    bound = _bind(_v3_request())
    assert bound.request["schema"] == "sylanne.first-ingress-encoding-call.v3"
    assert bound.request["baseline"] == {
        "baseline_ref": BASELINE_KEY.token, "baseline_revision": 1,
        "operation_id": "d04-op", "bundle_digest": "a" * 64,
        "graph_incarnation": "graph-incarnation", "graph_epoch": 12,
    }
    assert binding_from_json(binding_to_json(bound)) == bound


def test_v3_rejects_late_or_different_baseline_claim():
    with pytest.raises(ValueError, match="guard the committed D04 baseline"):
        _bind(_v3_request(guard_baseline=False))
    bound = _bind(_v3_request())
    forged = dict(bound.request)
    forged["baseline"] = {**forged["baseline"], "baseline_revision": 2}
    with pytest.raises(EncodingCallConflict, match="V3 committed baseline"):
        binding_to_json(replace(
            bound, request_json=canonical_serialize(forged),
            binding_digest=canonical_digest(forged)))


def test_v2_cannot_claim_a_baseline_after_the_call():
    bound = _bind(_v3_request(), baseline=None)
    assert bound.request["schema"] == "sylanne.first-ingress-encoding-call.v2"
    forged = dict(bound.request)
    forged["baseline"] = json.loads(canonical_serialize(BASELINE))
    with pytest.raises(EncodingCallConflict, match="legacy binding"):
        binding_to_json(replace(
            bound, request_json=canonical_serialize(forged),
            binding_digest=canonical_digest(forged)))
