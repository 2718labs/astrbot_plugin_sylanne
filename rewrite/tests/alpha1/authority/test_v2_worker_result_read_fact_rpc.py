"""Only the configured installed C02 committer can query a content-free fact."""

from types import SimpleNamespace

import pytest

from rewrite.tests.alpha1.authority.test_v2_worker_result_read_fact_service import _finished
from sylanne3.authority_service.mtls_server import (
    AuthorityRpcServer, MtlsPeerCredential,
)
from sylanne3.authority_service.v2_worker_result_read_fact_contract import (
    from_wire, to_wire,
)
from sylanne3.runtime_contracts import NamespaceId


def test_fact_rpc_requires_designated_installed_namespace_bound_committer(
        tmp_path, monkeypatch):
    service, request, _, core, deletion, guard, execution = _finished(
        tmp_path, monkeypatch)
    try:
        fact = service.current(credential="ok", request=request)
        peer = MtlsPeerCredential("a" * 64)
        other = MtlsPeerCredential("b" * 64)
        namespace = NamespaceId("bot-a", "persona-a")
        seen = []
        rpc_service = SimpleNamespace(
            _committer_subject="mtls:sha256:" + peer.certificate_sha256,
            current=lambda **kwargs: (seen.append(kwargs["request"]), fact)[1])
        server = object.__new__(AuthorityRpcServer)
        server._v2_worker_result_read_facts = {"ns-a": rpc_service}
        server._worker_result_fact_committers_v2 = {
            "ns-a": (peer.certificate_sha256, "profile-a")}
        server._namespace_bindings_v2 = {
            (peer.certificate_sha256, "profile-a", namespace): "ns-a"}
        server._authority_id = lambda: request.read_request.authority_id
        server._bound_v2_service = lambda *_: None
        command = {"namespace": "ns-a", "fact_request": to_wire(request)}
        response = server._v2_command(
            "worker_result_read_fact_v1", peer, "profile-a", "f" * 64,
            command)
        assert from_wire(response["fact"], type(fact)) == fact
        assert seen == [request]
        with pytest.raises(RuntimeError, match="authority unavailable"):
            server._v2_command(
                "worker_result_read_fact_v1", other, "profile-a", "f" * 64,
                command)
        server._v2_worker_result_read_facts = {}
        with pytest.raises(RuntimeError, match="authority unavailable"):
            server._v2_command(
                "worker_result_read_fact_v1", peer, "profile-a", "f" * 64,
                command)
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()
