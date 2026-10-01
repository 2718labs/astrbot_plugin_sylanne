"""A paired write fence is the only host path to the complete effect index."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_contract import (
    AuthorityCurrentEffectSnapshotV2, FencePermitV2, canonical_digest, to_wire,
)
from sylanne3.host.mtls_transport import MtlsAuthorityTransport
from sylanne3.host.v2_fence_port import V2FencePort
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    ContentEffectSnapshotPortV2, ContentFencePortV2, NamespaceId,
)


def test_effect_snapshot_extension_preserves_base_fence_port():
    class BasePort:
        def current_anchor(self):
            pass

        def begin_fence(self):
            pass

        def validate_fence(self):
            pass

        def finish_fence(self):
            pass

    assert isinstance(BasePort(), ContentFencePortV2)
    assert not isinstance(BasePort(), ContentEffectSnapshotPortV2)


@pytest.mark.asyncio
async def test_current_effect_snapshot_port_binds_original_write_permit():
    anchor = RestoreAnchor(
        "authority-a", "ns:role", 1, "deletion", 0, "genesis",
        "execution", 0, "genesis", 0, "proof")
    permit = FencePermitV2(
        "authority-a", "ns:role", "subject-a", "holder-a", 1,
        "write", "operation-a", "t" * 32, 0, 0, anchor)
    snapshot = AuthorityCurrentEffectSnapshotV2(
        "authority-a", "ns:role", anchor, canonical_digest(permit),
        0, "genesis", "complete", ())
    handshake = SimpleNamespace(
        installation_authority_id="authority-a",
        installation_identity_ref="subject-a",
        channel_binding_sha256="b" * 64)
    response = {
        "snapshot": to_wire(snapshot),
        "channel_binding_sha256": handshake.channel_binding_sha256,
    }
    calls = []
    transport = object.__new__(MtlsAuthorityTransport)

    async def rpc(request, observed_handshake, method, command, *, protocol):
        calls.append((method, command, protocol))
        assert request is request_identity and observed_handshake is handshake
        return response

    transport._content_rpc = rpc
    namespace = NamespaceId("bot", "persona")
    request_identity = object()
    port = object.__new__(V2FencePort)
    port._request = request_identity
    port._transport = transport

    async def mapped(observed_namespace, authority_namespace):
        assert (observed_namespace, authority_namespace) == (namespace, "ns:role")
        return SimpleNamespace(
            holder="holder-a", generation=1, anchor=anchor)

    port._mapped = mapped
    port._identity = lambda: (handshake, SimpleNamespace(
        authority_id="authority-a", subject="subject-a"))
    assert await port._read_current_effect_snapshot_for_write_fence(
        namespace, "ns:role", permit) == snapshot
    assert calls == [(
        "execution_read_current_effect_snapshot_for_write_fence",
        {"permit": to_wire(permit)}, "sylanne3.authority.v2")]

    response["channel_binding_sha256"] = "c" * 64
    with pytest.raises(RuntimeError, match="response is invalid"):
        await port._read_current_effect_snapshot_for_write_fence(
            namespace, "ns:role", permit)
    response["channel_binding_sha256"] = handshake.channel_binding_sha256
    changed_digest = "sha256:" + "a" * 64
    changed_anchor = replace(anchor, execution_seq=1,
                             execution_digest=changed_digest)
    response["snapshot"] = to_wire(AuthorityCurrentEffectSnapshotV2(
        "authority-a", "ns:role", changed_anchor,
        canonical_digest(permit), 1, changed_digest, "complete", ()))
    with pytest.raises(RuntimeError, match="binding is invalid"):
        await port._read_current_effect_snapshot_for_write_fence(
            namespace, "ns:role", permit)

    before = len(calls)
    with pytest.raises(ValueError, match="ordinary write fence"):
        await port._read_current_effect_snapshot_for_write_fence(
            namespace, "ns:role", replace(permit, operation="read"))
    assert len(calls) == before


@pytest.mark.asyncio
async def test_current_effect_snapshot_missing_transport_fails_closed():
    anchor = RestoreAnchor(
        "authority-a", "ns:role", 1, "deletion", 0, "genesis",
        "execution", 0, "genesis", 0, "proof")
    permit = FencePermitV2(
        "authority-a", "ns:role", "subject-a", "holder-a", 1,
        "write", "operation-a", "t" * 32, 0, 0, anchor)
    port = object.__new__(V2FencePort)
    port._transport = object()
    port._request = object()
    async def mapped(*_):
        return SimpleNamespace(holder="holder-a", generation=1, anchor=anchor)
    port._mapped = mapped
    port._identity = lambda: (object(), SimpleNamespace(
        authority_id="authority-a", subject="subject-a"))
    with pytest.raises(RuntimeError, match="transport is unavailable"):
        await port._read_current_effect_snapshot_for_write_fence(
            NamespaceId("bot", "persona"), "ns:role", permit)
