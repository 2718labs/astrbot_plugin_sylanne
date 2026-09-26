"""Only the configured installed C02 committer can query a content-free fact."""

from dataclasses import asdict, fields, replace
from types import SimpleNamespace

import pytest

from rewrite.tests.alpha1.authority.test_v2_worker_result_read_fact_service import _finished
from sylanne3.authority_service.mtls_server import (
    AuthorityRpcServer, MtlsPeerCredential,
)
from sylanne3.authority_service.v2_worker_result_read_fact_contract import (
    WorkerResultReadFactRequestV2, WorkerResultReadFactV2,
    from_wire, to_wire,
)
from sylanne3.runtime.graph_write_attempt import domain_bundle_write_attempt_id_v1
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


def test_fact_rpc_requires_designated_installed_namespace_bound_committer(
        tmp_path, monkeypatch):
    service, request, _, core, deletion, guard, execution = _finished(
        tmp_path, monkeypatch)
    try:
        fact = service.current(credential="ok", request=request)
        bundle_digest = "9" * 64
        write = replace(
            request.write_permit,
            operation_id=domain_bundle_write_attempt_id_v1(
                request.read_request.namespace,
                request.read_request.consumer_operation_id, bundle_digest),
        )
        request_v2 = WorkerResultReadFactRequestV2(
            read_request=request.read_request, write_permit=write,
            bundle_digest=bundle_digest)
        fact_v2 = WorkerResultReadFactV2(**{
            **{field.name: getattr(fact, field.name)
               for field in fields(type(fact)) if field.name != "schema"},
            "write_permit": write,
            "write_permit_digest": canonical_digest(asdict(write)),
            "bundle_digest": bundle_digest,
        })
        peer = MtlsPeerCredential("a" * 64)
        other = MtlsPeerCredential("b" * 64)
        namespace = NamespaceId("bot-a", "persona-a")
        seen = []
        rpc_service = SimpleNamespace(
            _committer_subject="mtls:sha256:" + peer.certificate_sha256,
            current=lambda **kwargs: (seen.append(kwargs["request"]), fact)[1],
            current_v2=lambda **kwargs: (seen.append(kwargs["request"]), fact_v2)[1])
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
        command_v2 = {"namespace": "ns-a", "fact_request": to_wire(request_v2)}
        response_v2 = server._v2_command(
            "worker_result_read_fact_v2", peer, "profile-a", "f" * 64,
            command_v2)
        assert from_wire(response_v2["fact"], type(fact_v2)) == fact_v2
        assert seen == [request, request_v2]
        wrong_bundle = {"namespace": "ns-a", "fact_request": {
            **to_wire(request_v2), "bundle_digest": "8" * 64}}
        with pytest.raises((RuntimeError, ValueError)):
            server._v2_command(
                "worker_result_read_fact_v2", peer, "profile-a", "f" * 64,
                wrong_bundle)
        with pytest.raises(RuntimeError, match="authority unavailable"):
            server._v2_command(
                "worker_result_read_fact_v1", other, "profile-a", "f" * 64,
                command)
        with pytest.raises(RuntimeError, match="authority unavailable"):
            server._v2_command(
                "worker_result_read_fact_v2", other, "profile-a", "f" * 64,
                command_v2)
        server._v2_worker_result_read_facts = {}
        with pytest.raises(RuntimeError, match="authority unavailable"):
            server._v2_command(
                "worker_result_read_fact_v1", peer, "profile-a", "f" * 64,
                command)
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()
