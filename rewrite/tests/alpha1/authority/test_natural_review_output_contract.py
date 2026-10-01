"""Review output identity is distinct from generation and bounded by attempt."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_natural_review_output_contract import (
    NaturalReviewOriginalOutputV2, NaturalReviewOutputReadRequestV2,
    from_wire, natural_review_output_attempt_id_v2, to_wire,
)
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, MtlsPeerCredential,
)
from sylanne3.runtime_contracts import NamespaceId


def test_natural_review_output_wire_and_attempt_identity():
    request = NaturalReviewOutputReadRequestV2(
        "authority", "opaque:persona", NamespaceId("bot", "persona"),
        "parent", "generation-origin", "generation-call", "a" * 64,
        "review-installation", "review-job", "review-origin",
        "review-acquire", "review-call", "b" * 64,
        natural_review_output_attempt_id_v2("review-origin", 1),
    )
    output = NaturalReviewOriginalOutputV2(
        request, "c" * 64, "b" * 64, "d" * 64,
        "e" * 64, "f" * 64, "0" * 64, "pass",
    )
    assert from_wire(to_wire(request), NaturalReviewOutputReadRequestV2) == request
    assert from_wire(to_wire(output), NaturalReviewOriginalOutputV2) == output
    assert not hasattr(output, "body")
    with pytest.raises(ValueError):
        replace(request, read_attempt_id=natural_review_output_attempt_id_v2(
            "generation-origin", 1))
    with pytest.raises(ValueError):
        replace(output, typed_model_request_digest="1" * 64)


def test_review_output_rpc_uses_paired_installed_peer():
    namespace = NamespaceId("bot", "persona")
    peer, other = MtlsPeerCredential("a" * 64), MtlsPeerCredential("b" * 64)
    request = NaturalReviewOutputReadRequestV2(
        "authority", "ns-a", namespace, "parent", "generation-origin",
        "generation-call", "a" * 64, "review-installation",
        "review-job", "review-origin", "review-acquire", "review-call",
        "b" * 64, natural_review_output_attempt_id_v2("review-origin", 1),
    )
    output = NaturalReviewOriginalOutputV2(
        request, "c" * 64, "b" * 64, "d" * 64,
        "e" * 64, "f" * 64, "0" * 64, "pass",
    )
    seen = []
    service = SimpleNamespace(
        _read_subject="mtls:sha256:" + peer.certificate_sha256,
        prepare=lambda **kwargs: (
            seen.append(kwargs["request"]), SimpleNamespace(result=output))[1],
    )
    server = object.__new__(AuthorityRpcServer)
    server._v2_natural_review_output_reads = {"ns-a": service}
    server._worker_result_readers_v2 = {
        "ns-a": (peer.certificate_sha256, "profile-a")}
    server._installations_v2 = {
        (peer.certificate_sha256, "profile-a"):
            AdministratorInstallationV2(
                request.installation_id, "holder", "policy", "v2", "f" * 64),
        (other.certificate_sha256, "profile-a"):
            AdministratorInstallationV2(
                "other-installation", "holder", "policy", "v2", "f" * 64),
    }
    server._namespace_bindings_v2 = {
        (peer.certificate_sha256, "profile-a", namespace): "ns-a"}
    server._authority_id = lambda: "authority"
    server._bound_v2_service = lambda *_: None
    command = {"namespace": "ns-a", "read_request": to_wire(request)}
    delivery = server._v2_command(
        "natural_review_output_select_v2", peer,
        "profile-a", "f" * 64, command)
    assert delivery.payload == {"result": to_wire(output)}
    assert seen == [request]
    with pytest.raises(RuntimeError, match="authority unavailable"):
        server._v2_command(
            "natural_review_output_select_v2", other,
            "profile-a", "f" * 64, command)
