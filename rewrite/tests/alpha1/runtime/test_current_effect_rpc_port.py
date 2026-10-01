"""Current effect reads retain exact identity and fail closed across the RPC."""

import asyncio
from dataclasses import asdict, replace
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

import pytest

host_package = ModuleType("sylanne3.host")
host_package.__path__ = [str(Path(__file__).resolve().parents[3] / "sylanne3" / "host")]
installed_stub = "sylanne3.host" not in sys.modules
if installed_stub:
    sys.modules["sylanne3.host"] = host_package

from sylanne3.authority_service.v2_execution_bridge import CurrentEffectReadV2
from sylanne3.authority_service.mtls_server import AuthorityRpcServer
from sylanne3.host.mtls_transport import MtlsAuthorityTransport
from sylanne3.host.v2_fence_port import V2FencePort

if installed_stub:
    del sys.modules["sylanne3.host"]


READING = CurrentEffectReadV2(
    "authority-a", "ns-a", "effect-a", 1, "absent", 0, "genesis")
HANDSHAKE = SimpleNamespace(
    channel_binding_sha256="a" * 64, installation_authority_id="authority-a")


@pytest.mark.parametrize("change", [
    {"effect_id": "effect-b"},
    {"authority_id": "authority-b"},
    {"state": "settled"},
    {"effect_seq": 1},
    {"observation_id": "observation-a"},
    {"observation_outcome": "accepted"},
    {"channel_binding_sha256": "b" * 64},
    {"content": "secret"},
])
def test_transport_rejects_unbound_or_extra_effect_response(change):
    transport = object.__new__(MtlsAuthorityTransport)

    async def rpc(request, handshake, method, command, *, protocol):
        assert method == "execution_read_current_effect"
        assert command == {"namespace": "ns-a", "effect_id": "effect-a"}
        return {**asdict(READING), "channel_binding_sha256": "a" * 64, **change}

    transport._content_rpc = rpc
    with pytest.raises(RuntimeError, match="current effect"):
        asyncio.run(transport.v2_execution_read_current_effect(
            None, HANDSHAKE, namespace="ns-a", effect_id="effect-a"))


def test_transport_returns_only_typed_current_effect_evidence():
    transport = object.__new__(MtlsAuthorityTransport)

    async def rpc(request, handshake, method, command, *, protocol):
        return {**asdict(READING), "channel_binding_sha256": "a" * 64}

    transport._content_rpc = rpc
    assert asyncio.run(transport.v2_execution_read_current_effect(
        None, HANDSHAKE, namespace="ns-a", effect_id="effect-a")) == READING


def test_server_requires_exact_command_and_installed_namespace():
    server = object.__new__(AuthorityRpcServer)
    seen = []

    def bound(credential, profile_id, manifest_digest, namespace):
        seen.append(namespace)
        if namespace != "ns-a":
            raise ValueError("namespace unavailable")
        return object()

    class Bridge:
        def read_current_effect(self, **kwargs):
            assert kwargs["effect_id"] == "effect-a"
            return READING

    server._bound_v2_service = bound
    server._v2_execution = {"ns-a": Bridge()}
    peer = SimpleNamespace(certificate_sha256="a" * 64)
    call = lambda command: server._v2_command(
        "execution_read_current_effect", peer, "profile-a", "c" * 64, command)
    assert call({"namespace": "ns-a", "effect_id": "effect-a"}) == asdict(READING)
    assert seen == ["ns-a"]
    with pytest.raises(RuntimeError, match="authority unavailable"):
        call({"namespace": "ns-a", "effect_id": "effect-a", "content": "secret"})
    with pytest.raises(RuntimeError, match="authority unavailable"):
        call({"namespace": "ns-b", "effect_id": "effect-a"})


def test_port_rejects_generation_change_and_lost_response():
    port = object.__new__(V2FencePort)
    port._request = object()
    port._identity = lambda: (HANDSHAKE, SimpleNamespace(authority_id="authority-a"))

    async def mapped(namespace, authority_namespace):
        assert authority_namespace == "ns-a"
        return SimpleNamespace(generation=1)

    port._mapped = mapped

    class Transport:
        async def v2_execution_read_current_effect(self, *args, **kwargs):
            return replace(READING, activation_generation=2)

    port._transport = Transport()
    with pytest.raises(RuntimeError, match="identity changed"):
        asyncio.run(port._read_current_effect(object(), "ns-a", "effect-a"))

    async def lost(*args, **kwargs):
        raise RuntimeError("authority transport unavailable")

    port._transport.v2_execution_read_current_effect = lost
    with pytest.raises(RuntimeError, match="transport unavailable"):
        asyncio.run(port._read_current_effect(object(), "ns-a", "effect-a"))
