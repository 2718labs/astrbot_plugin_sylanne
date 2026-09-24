"""A worker body stays fenced until its mTLS response is drained."""

import asyncio
import hashlib
import json
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, MtlsPeerCredential,
    _DeferredWorkerDelivery,
)
from sylanne3.authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, to_wire,
)
from sylanne3.runtime_contracts import NamespaceId


class _Ssl:
    def getpeercert(self, *, binary_form):
        assert binary_form is True
        return b"verified-test-client-certificate"

    def get_channel_binding(self, kind):
        assert kind == "tls-unique"
        return b"verified-test-channel"


class _Reader:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode() + b"\n"
        self._used = False

    async def readuntil(self, separator):
        if not self._used:
            self._used = True
            return self._payload
        raise asyncio.IncompleteReadError(b"", None)


class _Writer:
    def __init__(self, events, *, fail_drain=False):
        self.events = events
        self.fail_drain = fail_drain
        self.written = None

    def get_extra_info(self, name):
        assert name == "ssl_object"
        return _Ssl()

    def write(self, value):
        self.events.append("write")
        self.written = value

    async def drain(self):
        self.events.append("drain")
        if self.fail_drain:
            raise ConnectionResetError("peer disconnected")

    def close(self):
        self.events.append("close")

    async def wait_closed(self):
        return None


def _payload():
    return {
        "protocol": "sylanne3.authority.v2", "request_id": "rpc-read-1",
        "method": "worker_model_result_read_v1",
        "request": {"protocol": "sylanne3.authority.v2"},
        "handshake_binding_sha256": "a" * 64,
        "command": {"namespace": "ns-a", "read_request": {}},
    }


def test_worker_recover_rpc_requires_installed_namespace_bound_mtls_peer():
    peer = MtlsPeerCredential("a" * 64)
    other = MtlsPeerCredential("b" * 64)
    namespace = NamespaceId("bot-a", "persona-a")
    request = WorkerModelResultReadRequestV1(
        "authority-1", "ns-a", namespace, "installation-1",
        "job-1", "acquire-1", "original-1", "call-1", "c" * 64,
        "d" * 64, "consumer-1", "attempt-1")
    observed = []
    service = SimpleNamespace(
        _read_subject="mtls:sha256:" + peer.certificate_sha256,
        recover_finish=lambda **kwargs: observed.append(kwargs["request"]))
    server = object.__new__(AuthorityRpcServer)
    server._v2_worker_model_result_reads = {"ns-a": service}
    server._worker_result_readers_v2 = {"ns-a": (peer.certificate_sha256, "profile-a")}
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
        "worker_model_result_recover_finish_v1", peer,
        "profile-a", "f" * 64, command) == {"finished": True}
    assert observed == [request]
    with pytest.raises(RuntimeError, match="authority unavailable"):
        server._v2_command(
            "worker_model_result_recover_finish_v1", other,
            "profile-a", "f" * 64, command)


def test_worker_result_finishes_only_after_local_drain():
    events = []
    server = object.__new__(AuthorityRpcServer)
    delivery = _DeferredWorkerDelivery(
        {"result": {"body": "original-observation"}},
        SimpleNamespace(finish_delivery=lambda **_: events.append("finish"),
                        abandon_delivery=lambda **_: events.append("abandon")),
        SimpleNamespace(certificate_sha256=hashlib.sha256(b"peer").hexdigest()),
        object())

    async def dispatch(*_args):
        return delivery

    server._dispatch_on_worker = dispatch
    writer = _Writer(events)
    asyncio.run(server.serve_connection(
        _Reader(_payload()), writer, timeout_seconds=1.0,
        max_message_bytes=65536))
    assert events == ["write", "drain", "finish", "close"]
    assert b"original-observation" in writer.written


def test_failed_worker_result_drain_retains_original_attempt():
    events = []
    server = object.__new__(AuthorityRpcServer)
    delivery = _DeferredWorkerDelivery(
        {"result": {"body": "original-observation"}},
        SimpleNamespace(finish_delivery=lambda **_: events.append("finish"),
                        abandon_delivery=lambda **_: events.append("abandon")),
        SimpleNamespace(certificate_sha256=hashlib.sha256(b"peer").hexdigest()),
        object())

    async def dispatch(*_args):
        return delivery

    server._dispatch_on_worker = dispatch
    writer = _Writer(events, fail_drain=True)
    asyncio.run(server.serve_connection(
        _Reader(_payload()), writer, timeout_seconds=1.0,
        max_message_bytes=65536))
    assert events == ["write", "drain", "abandon", "close"]


def test_oversize_worker_result_abandons_local_handoff_without_finishing():
    events = []
    server = object.__new__(AuthorityRpcServer)
    delivery = _DeferredWorkerDelivery(
        {"result": {"body": "x" * 4096}},
        SimpleNamespace(finish_delivery=lambda **_: events.append("finish"),
                        abandon_delivery=lambda **_: events.append("abandon")),
        SimpleNamespace(certificate_sha256=hashlib.sha256(b"peer").hexdigest()),
        object())

    async def dispatch(*_args):
        return delivery

    server._dispatch_on_worker = dispatch
    writer = _Writer(events)
    asyncio.run(server.serve_connection(
        _Reader(_payload()), writer, timeout_seconds=1.0,
        max_message_bytes=512))
    assert events == ["abandon", "close"]
    assert writer.written is None


def test_unserializable_worker_result_abandons_local_handoff():
    events = []
    server = object.__new__(AuthorityRpcServer)
    delivery = _DeferredWorkerDelivery(
        {"result": {"body": object()}},
        SimpleNamespace(finish_delivery=lambda **_: events.append("finish"),
                        abandon_delivery=lambda **_: events.append("abandon")),
        SimpleNamespace(certificate_sha256=hashlib.sha256(b"peer").hexdigest()),
        object())

    async def dispatch(*_args):
        return delivery

    server._dispatch_on_worker = dispatch
    writer = _Writer(events)
    asyncio.run(server.serve_connection(
        _Reader(_payload()), writer, timeout_seconds=1.0,
        max_message_bytes=65536))
    assert events == ["abandon", "close"]
