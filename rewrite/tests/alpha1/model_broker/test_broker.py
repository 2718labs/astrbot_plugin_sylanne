from __future__ import annotations

import asyncio
from dataclasses import replace
import pytest

from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.model_broker import (EgressFinishReceipt, EgressStartReceipt, ModelBroker, ModelCallRequest, ModelProviderDescriptor, ProviderResponse,
                                   ProviderUnavailable, VerifiedHttpConfiguration, VerifiedHttpProvider)
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
                  prompt_template_digest="a" * 64, payload={"input_ref": "input"}, timeout_seconds=0.05)
    values.update(changes); return ModelCallRequest(**values)


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


class FixtureEgressAuthority:
    """Synthetic authority contract test; no source or deletion proof is implied."""

    def __init__(self, status="started", wrong_digest=False, finish_status="finished", wrong_finish=False):
        self.status, self.wrong_digest = status, wrong_digest
        self.finish_status, self.wrong_finish = finish_status, wrong_finish
        self.calls = []
        self.finishes = []

    async def begin_handoff(self, req, digest):
        self.calls.append((req, digest))
        return EgressStartReceipt(
            self.status, req.identity.operation_id, req.call_id,
            "f" * 64 if self.wrong_digest else digest,
            req.envelope.source_qualification.source_refs,
            req.envelope.version_guard.access_epoch,
            req.envelope.version_guard.delete_epoch,
            req.envelope.authority.activation_generation,
            "fixture-start" if self.status == "started" else None,
        )

    async def finish_handoff(self, start, outcome_digest):
        self.finishes.append((start, outcome_digest))
        if self.finish_status == "raises":
            raise TimeoutError("finish response lost")
        return EgressFinishReceipt(
            self.finish_status, start.operation_id, start.call_id,
            start.request_digest, start.start_ref,
            "f" * 64 if self.wrong_finish else outcome_digest,
            "fixture-finish" if self.finish_status == "finished" else None,
        )


def production_broker(provider):
    return ModelBroker({"provider": provider}, egress_authority=FixtureEgressAuthority())


def test_completed_call_binds_operation_attempt_usage_and_cost():
    receipt, result = run(production_broker(Provider()).call(request()))
    assert receipt.status == "completed" and receipt.operation_id == "operation" and receipt.attempt_id == "attempt"
    assert receipt.cost == {"model_microusd": 2} and receipt.cost_status == "confirmed" and result == {"candidate": True}
    assert receipt.egress_start_ref == "fixture-start"
    assert receipt.egress_finish_ref == "fixture-finish"


def test_missing_capability_or_unconfigured_provider_fails_closed():
    denied, _ = run(production_broker(Provider()).call(request(required_capabilities=frozenset({"tool"}))))
    absent, _ = run(ModelBroker({}).call(request()))
    assert denied.status == "denied" and absent.status == "unavailable"


def test_timeout_is_unknown_cost_and_requests_cancellation():
    provider = Provider(delay=.2)
    receipt, result = run(production_broker(provider).call(request(timeout_seconds=.01)))
    assert receipt.status == "timed_out" and receipt.cost_status == "unconfirmed" and receipt.result_qualification == "unknown"
    assert result is None and provider.cancelled


def test_production_requires_atomic_egress_authority_before_provider_call():
    provider = Provider()
    receipt, result = run(ModelBroker({"provider": provider}).call(request()))
    assert receipt.status == "unavailable" and result is None and not provider.invoked


def test_egress_denial_and_forged_binding_never_invoke_provider():
    for gate in (FixtureEgressAuthority("denied"), FixtureEgressAuthority(wrong_digest=True)):
        provider = Provider()
        receipt, result = run(ModelBroker({"provider": provider}, egress_authority=gate).call(request()))
        assert receipt.status in {"denied", "unknown"}
        assert result is None and not provider.invoked


def test_production_requires_a_durable_finish_contract_before_starting_provider():
    class StartOnlyAuthority:
        begin_handoff = FixtureEgressAuthority().begin_handoff

    provider = Provider()
    receipt, result = run(ModelBroker({"provider": provider}, egress_authority=StartOnlyAuthority()).call(request()))
    assert receipt.status == "unavailable" and result is None and not provider.invoked


@pytest.mark.parametrize("finish_status", ["unknown", "unavailable", "raises"])
def test_unconfirmed_finish_keeps_result_ineligible_and_never_claims_lease_release(finish_status):
    gate = FixtureEgressAuthority(finish_status=finish_status)
    provider = Provider()
    receipt, result = run(ModelBroker({"provider": provider}, egress_authority=gate).call(request()))
    assert provider.invoked and gate.finishes
    assert receipt.status == "unknown" and receipt.result_qualification == "unknown"
    assert receipt.cost_status == "unconfirmed" and receipt.egress_start_ref == "fixture-start"
    assert receipt.egress_finish_ref is None and result is None


def test_bad_finish_binding_keeps_completed_provider_content_ineligible():
    gate = FixtureEgressAuthority(wrong_finish=True)
    provider = Provider()
    receipt, result = run(ModelBroker({"provider": provider}, egress_authority=gate).call(request()))
    assert provider.invoked and gate.finishes
    assert receipt.status == "unknown" and receipt.result_qualification == "unknown" and result is None


def test_untyped_provider_return_is_unknown_and_never_releases_handoff_permit():
    class UntypedProvider(Provider):
        async def invoke(self, req, cancellation):
            self.invoked = True
            return {"status": "completed", "result": {"candidate": True}}

    gate, provider = FixtureEgressAuthority(), UntypedProvider()
    receipt, result = run(ModelBroker({"provider": provider}, egress_authority=gate).call(request()))
    assert provider.invoked and gate.calls and not gate.finishes
    assert receipt.status == "unknown" and receipt.cost_status == "unconfirmed"
    assert receipt.egress_start_ref == "fixture-start" and result is None


def test_uncanonical_provider_content_is_unknown_and_never_releases_handoff_permit():
    class PoisonedProvider(Provider):
        async def invoke(self, req, cancellation):
            self.invoked = True
            response = ProviderResponse("completed", {"candidate": True}, {}, {}, "remote-call")
            # Simulates an untrusted adapter bypassing the dataclass constructor.
            object.__setattr__(response, "result", {"candidate": object()})
            return response

    gate, provider = FixtureEgressAuthority(), PoisonedProvider()
    receipt, result = run(ModelBroker({"provider": provider}, egress_authority=gate).call(request()))
    assert provider.invoked and gate.calls and not gate.finishes
    assert receipt.status == "unknown" and receipt.result_qualification == "unknown"
    assert receipt.egress_start_ref == "fixture-start" and result is None


def test_timeout_and_provider_unknown_are_finished_as_noneligible_outcomes():
    timed_gate, unknown_gate = FixtureEgressAuthority(), FixtureEgressAuthority()
    timed = Provider(delay=.2)
    timed_receipt, _ = run(ModelBroker({"provider": timed}, egress_authority=timed_gate).call(request(timeout_seconds=.01)))
    unknown = Provider(response=ProviderResponse("unknown", None, {}, {}, "remote-call"))
    unknown_receipt, _ = run(ModelBroker({"provider": unknown}, egress_authority=unknown_gate).call(request()))
    assert timed_receipt.status == "timed_out" and timed_gate.finishes
    assert unknown_receipt.status == "unknown" and unknown_gate.finishes


def test_cancellation_after_handoff_is_finished_before_the_result_is_returned():
    class CancellingProvider(Provider):
        async def invoke(self, req, cancellation):
            self.invoked = True
            cancellation.set()
            return ProviderResponse("completed", {"candidate": True}, {}, {}, "remote-call")

    async def scenario():
        gate, provider, cancelled = FixtureEgressAuthority(), CancellingProvider(), asyncio.Event()
        receipt, result = await ModelBroker({"provider": provider}, egress_authority=gate).call(request(), cancellation=cancelled)
        return gate, provider, receipt, result

    gate, provider, receipt, result = run(scenario())
    assert provider.invoked and gate.calls and gate.finishes and provider.cancelled
    assert receipt.status == "cancelled" and receipt.egress_finish_ref == "fixture-finish" and result is None


def test_production_rejects_test_double_but_dev_can_exercise_it():
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


def test_provider_receipt_cannot_claim_non_dispatch_after_usage_or_false_cancellation():
    with pytest.raises(ValueError, match="not_dispatched"):
        ProviderResponse("not_dispatched", None, {"input_tokens": 1}, {}, None)
    with pytest.raises(ValueError, match="cancellation"):
        VerifiedHttpProvider(Provider().descriptor, None)


def test_missing_reported_cost_remains_unconfirmed():
    provider = Provider(response=ProviderResponse("completed", {"candidate": True}, {"input_tokens": 1}, {}, "remote-call"))
    receipt, _ = run(production_broker(provider).call(request()))
    assert receipt.cost_status == "unconfirmed"
