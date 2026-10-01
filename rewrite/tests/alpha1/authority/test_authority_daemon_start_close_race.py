"""Closing a daemon during listener startup must not leave a live listener."""

import asyncio
import threading
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.daemon import AuthorityDaemon


@pytest.mark.asyncio
async def test_close_during_start_rejects_late_listener():
    entered = asyncio.Event()
    release = asyncio.Event()

    class Listener:
        closed = False

        def close(self):
            self.closed = True

        async def wait_closed(self):
            assert self.closed

    class Server:
        def __init__(self):
            self.listener = Listener()
            self.closed = False

        async def start(self, *_):
            entered.set()
            await release.wait()
            return self.listener

        async def aclose(self):
            self.closed = True

    daemon = AuthorityDaemon.__new__(AuthorityDaemon)
    daemon.config = SimpleNamespace(bind_host="127.0.0.1", bind_port=1, tls=object())
    daemon.server = Server()
    daemon.core = SimpleNamespace(close=lambda: None)
    daemon.execution = {}
    daemon.deletion = SimpleNamespace(close=lambda: None)
    daemon._lock_handle = None
    daemon._maintenance_lock = threading.RLock()
    daemon._listener = None
    daemon._starting = False
    daemon._closed = False

    starting = asyncio.create_task(daemon.start())
    await entered.wait()
    await daemon.aclose()
    release.set()
    with pytest.raises(AuthorityUnavailable, match="closed during startup"):
        await starting
    assert daemon.server.closed
    assert daemon.server.listener.closed
    assert daemon._listener is None
