from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import pytest

from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.model_broker import (EgressFinishReceipt, EgressStartReceipt, ModelBroker, ModelCallRequest, ModelProviderDescriptor, ProviderResponse,
                                   ProviderUnavailable, VerifiedHttpConfiguration, VerifiedHttpProvider)
from sylanne3.model_broker.broker import AuthorityExecutionResult, CallReceipt
from sylanne3.runtime_contracts import (AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
                                        QueryEpoch, SourceQualification, VersionGuard, canonical_digest)


def envelope():
    namespace = NamespaceId("bot", "persona")
    key = AtomKey(Owner("persona", "bot", "persona"), "state", "model")
    return CommandEnvelope("sylanne.runtime.v1", OperationIdentity("activity", None, "attempt", "propose", "operation", canonical_digest({"input_refs": ["input"]})),
        AuthorityContext("actor", "d07", "cap", namespace, ("persona",), "proposal", ("owner",), "policy", 1),
        VersionGuard((GraphVersion(key, 0),), (QueryEpoch(namespace, "all", 0),), 0, 0, "catalogue", "scheme", "operator", "policy", (), (), ()),
        SourceQualification(("source",), "reported", None, 1.0, "external_report", "qualified", None, "actual"),
        ("input",), "budget", 2.0, 1.0, "clock", ())


def request(**changes):
    values = dict(envelope=envelope(), call_id="call", provider_id="provider", model_id="model",
                  required_capabilities=frozenset({"structured"}), privacy_tier="private",
                  prompt_template_digest="a" * 64, payload={"input_ref": "input"},
                  timeout_seconds=0.05, max_output_tokens=128)
    values.update(changes); return ModelCallRequest(**values)


def test_call_digest_binds_timeout_and_required_capabilities():
    original = request()
    shorter_timeout = request(timeout_seconds=0.01)
    changed_capabilities = request(
        required_capabilities=frozenset({"structured", "tool"}))
    changed_output_limit = request(max_output_tokens=64)
    assert original.digest != shorter_timeout.digest
    assert original.digest != changed_capabilities.digest
    assert shorter_timeout.digest != changed_capabilities.digest
    assert original.digest != changed_output_limit.digest
    assert request(timeout_seconds=0.05).digest == original.digest
    assert request(required_capabilities=frozenset({"structured"})).digest == original.digest
    with pytest.raises(ValueError, match="max_output_tokens"):
        request(max_output_tokens=0)


class Provider:
    def __init__(self, response=None, delay=0, test=False): self.response, self.delay, self.cancelled, self.invoked = response, delay, False, False; self._descriptor = ModelProviderDescriptor("provider", "v1", "model", frozenset({"structured"}), frozenset({"proposal"}), frozenset({"private"}), "credential:provider", "reported", True, True, test)
    @property
    def descriptor(self): return self._descriptor
    async def invoke(self, request, cancellation):
        self.invoked = True
        if self.delay: await asyncio.sleep(self.delay)
        return self.response or ProviderResponse("completed", {"candidate": True}, {"input_tokens": 1}, {"model_microusd": 2}, "remote-call")
    async def cancel(self, request): self.cancelled = True; return True


def run(coro): return asyncio.run(coro)


class LegacyStartAuthority:
    def __init__(self):
        self.started = False

    async def begin_handoff(self, req, digest):
        self.started = True
        return EgressStartReceipt(
            "started", req.identity.operation_id, req.call_id, digest,
            req.envelope.source_qualification.source_refs,
            req.envelope.version_guard.access_epoch,
            req.envelope.version_guard.delete_epoch,
            req.envelope.authority.activation_generation, "legacy-start",
        )


class FixtureExecutor:
    def __init__(self, *, receipt_changes=None, finish_changes=None, result=None, raises=False):
        self.receipt_changes = receipt_changes or {}
        self.finish_changes = finish_changes or {}
        self.result = {"candidate": True} if result is None else result
        self.raises = raises
        self.calls = []

    async def execute_call(self, req, digest):
        self.calls.append((req, digest))
        if self.raises:
            raise TimeoutError("authority response lost")
        usage = {"input_tokens": 1}
        cost = {"model_microusd": 2}
        result_digest = canonical_digest(self.result)
        outcome_digest = canonical_digest({
            "request_digest": digest,
            "status": "completed",
            "provider_call_ref": "remote-call",
            "usage": usage,
            "cost": cost,
            "result_digest": result_digest,
        })
        receipt = CallReceipt(
            "completed", req.identity.operation_id, req.identity.attempt_id,
            req.call_id, digest, req.provider_id, req.model_id, "remote-call",
            usage, cost, "confirmed", "eligible", False,
            "durable-start", "durable-finish",
        )
        finish = EgressFinishReceipt(
            "finished", req.identity.operation_id, req.call_id, digest,
            "durable-start", outcome_digest, "durable-finish",
        )
        return AuthorityExecutionResult(
            replace(receipt, **self.receipt_changes), self.result,
            replace(finish, **self.finish_changes),
        )


def test_production_uses_authority_executor_without_host_provider():
    executor = FixtureExecutor()
    receipt, result = run(ModelBroker({}, egress_authority=executor).call(request()))
    assert receipt.status == "completed" and receipt.result_qualification == "eligible"
    assert receipt.operation_id == "operation" and receipt.attempt_id == "attempt"
    assert receipt.cost == {"model_microusd": 2} and result == {"candidate": True}
    assert executor.calls == [(request(), request().digest)]


def test_legacy_started_receipt_cannot_trigger_local_provider():
    provider, legacy = Provider(), LegacyStartAuthority()
    receipt, result = run(ModelBroker({"provider": provider}, egress_authority=legacy).call(request()))
    assert receipt.status == "unavailable" and result is None
    assert not legacy.started and not provider.invoked


def test_missing_executor_holds_production_even_with_local_provider():
    provider = Provider()
    receipt, result = run(ModelBroker({"provider": provider}).call(request()))
    assert receipt.status == "unavailable" and result is None and not provider.invoked


@pytest.mark.parametrize(("receipt_changes", "finish_changes"), [
    ({"call_id": "other-call"}, {}),
    ({"call_digest": "f" * 64}, {}),
    ({"attempt_id": "other-attempt"}, {}),
    ({"egress_start_ref": None}, {}),
    ({"egress_finish_ref": None}, {}),
    ({"egress_finish_ref": "other-finish"}, {}),
    ({}, {"start_ref": "other-start"}),
    ({}, {"outcome_digest": "f" * 64}),
])
def test_production_rejects_inexact_or_missing_durable_identity(receipt_changes, finish_changes):
    provider = Provider()
    executor = FixtureExecutor(receipt_changes=receipt_changes, finish_changes=finish_changes)
    receipt, result = run(ModelBroker({"provider": provider}, egress_authority=executor).call(request()))
    assert receipt.status == "unknown" and receipt.result_qualification == "unknown"
    assert receipt.cost_status == "unconfirmed" and result is None and not provider.invoked


def test_authority_timeout_is_unknown_and_does_not_fall_back():
    provider = Provider()
    receipt, result = run(ModelBroker({"provider": provider}, egress_authority=FixtureExecutor(raises=True)).call(request()))
    assert receipt.status == "unknown" and receipt.cost_status == "unconfirmed"
    assert result is None and not provider.invoked


def test_noneligible_authority_result_cannot_expose_content():
    class PoisonedExecutor(FixtureExecutor):
        async def execute_call(self, req, digest):
            execution = await super().execute_call(req, digest)
            return replace(execution, receipt=replace(execution.receipt, result_qualification="unknown"))

    receipt, result = run(ModelBroker({}, egress_authority=PoisonedExecutor()).call(request()))
    assert receipt.status == "unknown" and result is None


def test_development_provider_receipt_and_timeout():
    provider = Provider()
    completed, result = run(ModelBroker({"provider": provider}, production=False).call(request()))
    assert provider.invoked and completed.status == "completed" and result == {"candidate": True}
    slow = Provider(delay=.2)
    timed, result = run(ModelBroker({"provider": slow}, production=False).call(request(timeout_seconds=.01)))
    assert timed.status == "timed_out" and timed.cost_status == "unconfirmed"
    assert result is None and slow.cancelled


def test_development_missing_capability_is_denied():
    receipt, result = run(ModelBroker({"provider": Provider()}, production=False).call(
        request(required_capabilities=frozenset({"tool"}))
    ))
    assert receipt.status == "denied" and result is None


def test_production_requires_executor_even_with_test_double():
    provider = Provider(test=True)
    production, _ = run(ModelBroker({"provider": provider}).call(request()))
    development, _ = run(ModelBroker({"provider": provider}, production=False).call(request()))
    assert production.status == "unavailable" and development.status == "completed"


def test_http_adapter_requires_host_attestation_and_never_borrows_a_credential():
    descriptor = replace(Provider().descriptor, timeout_cancellable=False)
    adapter = VerifiedHttpProvider(descriptor, VerifiedHttpConfiguration("https://provider.invalid/v1", "credential:provider", False), lambda _: "secret")
    try:
        adapter._credential()
    except ProviderUnavailable:
        pass
    else:
        raise AssertionError("unattested configuration must fail before HTTP")


def test_generic_http_request_carries_output_limit_without_claiming_enforcement():
    descriptor = replace(Provider().descriptor, timeout_cancellable=False)
    adapter = VerifiedHttpProvider(
        descriptor,
        VerifiedHttpConfiguration("https://provider.invalid/v1", "credential:provider", True),
        lambda _: "test-secret",
    )
    sent = []

    def capture(body, secret, timeout):
        sent.append((body, secret, timeout))
        return '{"status":"completed","result":{"text":"ok"}}'

    adapter._post = capture
    response = run(adapter.invoke(request(max_output_tokens=73), asyncio.Event()))
    assert response.status == "completed"
    assert len(sent) == 1
    assert json.loads(sent[0][0])["max_output_tokens"] == 73


def test_provider_receipt_cannot_claim_non_dispatch_after_usage_or_false_cancellation():
    with pytest.raises(ValueError, match="not_dispatched"):
        ProviderResponse("not_dispatched", None, {"input_tokens": 1}, {}, None)
    with pytest.raises(ValueError, match="cancellation"):
        VerifiedHttpProvider(Provider().descriptor, None)


def test_missing_reported_cost_remains_unconfirmed():
    provider = Provider(response=ProviderResponse("completed", {"candidate": True}, {"input_tokens": 1}, {}, "remote-call"))
    receipt, _ = run(ModelBroker({"provider": provider}, production=False).call(request()))
    assert receipt.cost_status == "unconfirmed"
