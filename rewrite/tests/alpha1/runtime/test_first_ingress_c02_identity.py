"""Host and D11 must derive the same fixed C02 consumer operation."""

from dataclasses import asdict

from sylanne3.runtime.first_ingress_c02_identity import (
    first_ingress_c02_consumer_operation_id_v1,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


def test_consumer_identity_matches_original_host_formula_and_changes_with_call():
    fields = dict(
        namespace=NamespaceId("bot", "persona"), authority_id="authority",
        authority_namespace="authority-namespace", installation_id="installation",
        job_id="job", acquire_operation_id="acquire",
        original_operation_id="ingress", call_id="call",
        binding_digest="a" * 64, model_request_digest="b" * 64,
    )
    expected = "first-ingress-c02-" + canonical_digest({
        "schema": "sylanne3.first-ingress-c02-consumer.v1",
        "original": {**fields, "namespace": asdict(fields["namespace"])},
    })[:48]
    assert first_ingress_c02_consumer_operation_id_v1(**fields) == expected
    assert first_ingress_c02_consumer_operation_id_v1(
        **{**fields, "call_id": "other-call"}) != expected
