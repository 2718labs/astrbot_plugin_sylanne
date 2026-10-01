"""Natural review content uses a separate original read identity."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_natural_generation_content_contract import (
    NaturalGenerationContentReadRequestV2, NaturalGenerationCurrentContentV2,
    from_wire, natural_generation_content_attempt_id_v2, to_wire,
)
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, MtlsPeerCredential,
)
from sylanne3.authority_service.v2_natural_generation_output_contract import (
    natural_generation_output_attempt_id_v2,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.memory_types import source_key
from sylanne3.runtime_contracts import NamespaceId


def test_review_content_has_independent_attempt_and_roundtrip():
    namespace = NamespaceId("bot", "persona")
    original = "natural-original"
    request = NaturalGenerationContentReadRequestV2(
        "authority", "authority-namespace", namespace, "c02",
        source_key(*namespace.as_tuple, "source").token, "installation",
        "job", original, "acquire", "call", "a" * 64, "b" * 64,
        "c" * 64, "d" * 64, "scene:private", "conversation:private",
        "review", natural_generation_content_attempt_id_v2(original, 1))
    assert request.read_attempt_id != natural_generation_output_attempt_id_v2(
        original, 1)
    assert from_wire(to_wire(request), NaturalGenerationContentReadRequestV2) == request
    with pytest.raises(ValueError, match="attempt"):
        replace(request, read_attempt_id=natural_generation_output_attempt_id_v2(
            original, 1))
    key = AtomKey(Owner("persona", *namespace.as_tuple), "d07.focus.v1", "focus")
    current = NaturalGenerationCurrentContentV2(
        request, '{"schema":"review"}', "e" * 64, "d" * 64,
        "f" * 64, (GraphVersion(key, 1),), 5, 2, 1, 10.0)
    assert from_wire(to_wire(current), NaturalGenerationCurrentContentV2) == current


def test_review_content_rpc_requires_paired_installed_peer():
    namespace = NamespaceId("bot", "persona")
    peer, other = MtlsPeerCredential("a" * 64), MtlsPeerCredential("b" * 64)
    request = NaturalGenerationContentReadRequestV2(
        "authority", "ns-a", namespace, "c02",
        source_key(*namespace.as_tuple, "source").token, "installation",
        "job", "natural-original", "acquire", "call", "a" * 64,
        "b" * 64, "c" * 64, "d" * 64, "scene:private",
        '["private","conversation"]', "review",
        natural_generation_content_attempt_id_v2("natural-original", 1))
    key = AtomKey(Owner("persona", *namespace.as_tuple), "d07.focus.v1", "focus")
    content = NaturalGenerationCurrentContentV2(
        request, '{"schema":"review"}', "e" * 64, "d" * 64,
        "f" * 64, (GraphVersion(key, 1),), 5, 2, 1, 10.0)
    seen = []
    service = SimpleNamespace(
        _original=SimpleNamespace(_read_subject="mtls:sha256:" + peer.certificate_sha256),
        read_current_natural_generation_content_v2=lambda **kwargs:
            (seen.append(kwargs["request"]), content)[1])
    server = object.__new__(AuthorityRpcServer)
    server._v2_natural_generation_content_reads = {"ns-a": service}
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
        "natural_generation_content_read_v2", peer,
        "profile-a", "f" * 64, command) == {"result": to_wire(content)}
    assert seen == [request]
    with pytest.raises(RuntimeError, match="authority unavailable"):
        server._v2_command(
            "natural_generation_content_read_v2", other,
            "profile-a", "f" * 64, command)
