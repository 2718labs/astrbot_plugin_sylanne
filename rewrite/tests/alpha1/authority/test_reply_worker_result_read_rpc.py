"""Reply worker result RPC keeps its own typed purpose and installed peer."""

from types import SimpleNamespace

import pytest

from sylanne3.authority_service.current_reply_worker_model_result_graph_verifier import (
    PinnedCurrentReplyWorkerModelResultGraphVerifier,
)
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, MtlsPeerCredential,
)
from sylanne3.authority_service.v2_reply_worker_model_result_contract import (
    ReplyWorkerModelResultReadRequestV1, to_wire,
    reply_worker_read_attempt_id_v1,
)
from sylanne3.memory_types import source_key
from sylanne3.runtime_contracts import NamespaceId


def test_reply_select_rpc_requires_exact_installed_reader_and_purpose():
    peer = MtlsPeerCredential("a" * 64)
    other = MtlsPeerCredential("b" * 64)
    namespace = NamespaceId("bot-a", "persona-a")
    request = ReplyWorkerModelResultReadRequestV1(
        "authority-1", "ns-a", namespace, "installation-1", "job-a",
        "acquire-a", "original-a", "call-a", "c" * 64, "d" * 64,
        "reply-consumer-a", reply_worker_read_attempt_id_v1("reply-consumer-a", 1),
        "c02-a", source_key("bot-a", "persona-a", "source-a").token,
        1, 1, "ticket-a", 1, ("conversation-a",),
    )
    observed = []
    service = SimpleNamespace(
        _read_subject="mtls:sha256:" + peer.certificate_sha256,
        _reply_graph=object.__new__(PinnedCurrentReplyWorkerModelResultGraphVerifier),
        select_attempt=lambda **kwargs: kwargs["first_request"],
        recover_finish=lambda **kwargs: observed.append(kwargs["request"]),
    )
    server = object.__new__(AuthorityRpcServer)
    server._v2_worker_model_result_reads = {"ns-a": service}
    server._worker_result_readers_v2 = {
        "ns-a": (peer.certificate_sha256, "profile-a")}
    server._installations_v2 = {
        (peer.certificate_sha256, "profile-a"): AdministratorInstallationV2(
            "installation-1", "holder-1", "policy", "v2", "f" * 64),
        (other.certificate_sha256, "profile-a"): AdministratorInstallationV2(
            "other-installation", "holder-1", "policy", "v2", "f" * 64),
    }
    server._namespace_bindings_v2 = {
        (peer.certificate_sha256, "profile-a", namespace): "ns-a"}
    server._authority_id = lambda: "authority-1"
    server._bound_v2_service = lambda *_: None
    command = {"namespace": "ns-a", "read_request": to_wire(request)}
    assert server._v2_command(
        "reply_worker_model_result_select_attempt_v1", peer,
        "profile-a", "f" * 64, command,
    ) == {"selected_request": to_wire(request)}
    assert server._v2_command(
        "reply_worker_model_result_recover_finish_v1", peer,
        "profile-a", "f" * 64, command,
    ) == {"finished": True}
    assert observed == [request]
    with pytest.raises(RuntimeError, match="authority unavailable"):
        server._v2_command(
            "reply_worker_model_result_select_attempt_v1", other,
            "profile-a", "f" * 64, command)
    with pytest.raises(RuntimeError, match="authority unavailable"):
        server._v2_command(
            "worker_model_result_select_attempt_v1", peer,
            "profile-a", "f" * 64, command)
