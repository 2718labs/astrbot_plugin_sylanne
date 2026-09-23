"""Network RPC dispatch stays off the event loop and has bounded occupancy."""

import asyncio
import json
import threading

import pytest

from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.mtls_server import AUTHORITY_PROTOCOL, AuthorityRpcServer


REQUEST = {
    "protocol": AUTHORITY_PROTOCOL,
    "profile_id": "profile-a",
    "plugin_name": "astrbot_plugin_sylanne",
    "host_api_version": "4.28.1",
    "manifest_sha256": "a" * 64,
}


class _Tls:
    def getpeercert(self, *, binary_form):
        assert binary_form
        return b"certificate"

    def get_channel_binding(self, kind):
        assert kind == "tls-unique"
        return b"binding"


class _Writer:
    def __init__(self):
        self.responses = []

    def get_extra_info(self, name):
        return _Tls() if name == "ssl_object" else None

    def write(self, data):
        self.responses.append(json.loads(data))

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


def _reader(request_id):
    reader = asyncio.StreamReader()
    reader.feed_data(json.dumps({
        "protocol": AUTHORITY_PROTOCOL,
        "request_id": request_id,
        "method": "handshake",
        "request": REQUEST,
    }).encode() + b"\n")
    reader.feed_eof()
    return reader


@pytest.fixture
def core(tmp_path):
    service = AuthorityServiceCore(
        tmp_path / "authority.db", create=True,
        authorizer=lambda *args: True,
        deletion_verifier=lambda *args: True,
        execution_verifier=lambda *args: True,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True,
    )
    yield service
    service.close()


def test_blocking_dispatch_keeps_loop_timer_running(core):
    started = threading.Event()
    release = threading.Event()
    order = []

    def authorize(*args):
        started.set()
        assert release.wait(1)
        order.append("dispatch finished")
        return True

    rpc = AuthorityRpcServer(
        core, administrator_authorizer=authorize,
        publisher_manifest_verifier=lambda *args: True,
    )

    async def scenario():
        writer = _Writer()
        task = asyncio.create_task(rpc.serve_connection(
            _reader("first"), writer, timeout_seconds=1, max_message_bytes=4096,
        ))
        fallback = threading.Timer(0.3, release.set)
        fallback.start()
        try:
            assert await asyncio.to_thread(started.wait, 1)
            loop = asyncio.get_running_loop()
            loop.call_later(0.01, lambda: (order.append("timer"), release.set()))
            await asyncio.wait_for(task, 1)
            assert order == ["timer", "dispatch finished"]
            assert writer.responses[0]["ok"] is True
        finally:
            release.set()
            fallback.cancel()
            await rpc.aclose()

    asyncio.run(scenario())


def test_cancelled_request_keeps_worker_capacity_until_dispatch_finishes(core):
    started = threading.Event()
    release = threading.Event()

    def authorize(*args):
        started.set()
        assert release.wait(1)
        return True

    rpc = AuthorityRpcServer(
        core, administrator_authorizer=authorize,
        publisher_manifest_verifier=lambda *args: True,
        max_inflight_dispatches=1,
    )

    async def scenario():
        first = asyncio.create_task(rpc.serve_connection(
            _reader("first"), _Writer(), timeout_seconds=1, max_message_bytes=4096,
        ))
        try:
            assert await asyncio.to_thread(started.wait, 1)
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            second_writer = _Writer()
            await asyncio.wait_for(rpc.serve_connection(
                _reader("second"), second_writer, timeout_seconds=1,
                max_message_bytes=4096,
            ), 0.2)
            assert second_writer.responses == [{
                "request_id": "second", "ok": False, "error": "authority_unavailable",
            }]
            closing = asyncio.create_task(rpc.aclose())
            await asyncio.sleep(0)
            assert not closing.done()
        finally:
            release.set()
            await rpc.aclose()

    asyncio.run(scenario())
