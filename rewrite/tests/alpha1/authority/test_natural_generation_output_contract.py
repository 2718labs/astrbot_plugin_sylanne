"""Identity-only natural output request never carries a model body."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_natural_generation_output_contract import (
    NaturalGenerationOriginalOutputV2, NaturalGenerationOutputReadRequestV2,
    from_wire, natural_generation_output_attempt_id_v2, to_wire,
)
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, MtlsPeerCredential,
)
from sylanne3.memory_types import source_key
from sylanne3.runtime_contracts import NamespaceId


def test_natural_original_output_wire_is_content_free_and_versioned():
    namespace = NamespaceId("bot", "persona")
    original = "natural-original"
    request = NaturalGenerationOutputReadRequestV2(
        "authority", "authority:namespace", namespace, "c02-original",
        source_key(*namespace.as_tuple, "source").token, "installation",
        "job", original, "acquire", "call", "a" * 64,
        natural_generation_output_attempt_id_v2(original, 1),
    )
    output = NaturalGenerationOriginalOutputV2(
        request, "b" * 64, "a" * 64, "c" * 64, "d" * 64,
        "e" * 64, "f" * 64, "untrusted_content_candidate")
    assert from_wire(to_wire(request), type(request)) == request
    assert from_wire(to_wire(output), type(output)) == output
    assert "text" not in str(to_wire(output))
    with pytest.raises(ValueError, match="original natural generation read attempt"):
        replace(request, read_attempt_id="other")
    with pytest.raises(ValueError, match="identity differs"):
        replace(output, typed_model_request_digest="0" * 64)


def test_natural_output_recovery_rpc_requires_installed_peer():
    namespace = NamespaceId("bot", "persona")
    original = "natural-original"
    peer, other = MtlsPeerCredential("a" * 64), MtlsPeerCredential("b" * 64)
    request = NaturalGenerationOutputReadRequestV2(
        "authority", "ns-a", namespace, "c02-original",
        source_key(*namespace.as_tuple, "source").token, "installation",
        "job", original, "acquire", "call", "a" * 64,
        natural_generation_output_attempt_id_v2(original, 1),
    )
    observed = []
    service = SimpleNamespace(
        _read_subject="mtls:sha256:" + peer.certificate_sha256,
        recover_finish=lambda **kwargs: observed.append(kwargs["request"]))
    server = object.__new__(AuthorityRpcServer)
    server._v2_natural_generation_output_reads = {"ns-a": service}
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
    assert server._v2_command(
        "natural_generation_output_recover_finish_v2", peer,
        "profile-a", "f" * 64, command) == {"finished": True}
    assert observed == [request]
    with pytest.raises(RuntimeError, match="authority unavailable"):
        server._v2_command(
            "natural_generation_output_recover_finish_v2", other,
            "profile-a", "f" * 64, command)
