"""The V2 paid-result RPC is bound to the installed mTLS reader."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from rewrite.tests.alpha1.authority.test_context_reply_original_verifier import (
    _prepared_graph,
)
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, MtlsPeerCredential,
)
from sylanne3.authority_service.v2_context_reply_result_contract import to_wire


def test_context_reply_recovery_rpc_checks_peer_and_original_namespace(tmp_path):
    request = _prepared_graph(tmp_path / "graph.sqlite")
    peer = MtlsPeerCredential("a" * 64)
    other = MtlsPeerCredential("b" * 64)
    request = replace(request, authority_id="authority-1",
                      authority_namespace="ns-a")
    observed = []
    service = SimpleNamespace(
        _read_subject="mtls:sha256:" + peer.certificate_sha256,
        recover_finish=lambda **kwargs: observed.append(kwargs["request"]))
    server = object.__new__(AuthorityRpcServer)
    server._v2_context_reply_result_reads = {"ns-a": service}
    server._worker_result_readers_v2 = {
        "ns-a": (peer.certificate_sha256, "profile-a")}
    server._installations_v2 = {
        (peer.certificate_sha256, "profile-a"): AdministratorInstallationV2(
            request.installation_id, "holder-1", "policy", "v2", "f" * 64),
        (other.certificate_sha256, "profile-a"): AdministratorInstallationV2(
            "other-installation", "holder-1", "policy", "v2", "f" * 64),
    }
    server._namespace_bindings_v2 = {
        (peer.certificate_sha256, "profile-a", request.namespace): "ns-a"}
    server._authority_id = lambda: "authority-1"
    server._bound_v2_service = lambda *_: None
    command = {"namespace": "ns-a", "read_request": to_wire(request)}
    assert server._v2_command(
        "context_reply_result_recover_finish_v2", peer,
        "profile-a", "f" * 64, command) == {"finished": True}
    assert observed == [request]
    with pytest.raises(RuntimeError, match="authority unavailable"):
        server._v2_command(
            "context_reply_result_recover_finish_v2", other,
            "profile-a", "f" * 64, command)
