"""The graph worker's synchronous bridge stays bound to one Authority loop."""

import asyncio
from dataclasses import replace
from pathlib import Path
import sys
from threading import get_ident
from types import ModuleType

import pytest

# The host package's AstrBot entry point is unavailable in the standalone
# rewrite test environment. Load its pure transport modules without that entry.
host_package = ModuleType("sylanne3.host")
host_package.__path__ = [str(Path(__file__).resolve().parents[3] / "sylanne3" / "host")]
installed_stub = "sylanne3.host" not in sys.modules
if installed_stub:
    sys.modules["sylanne3.host"] = host_package

from sylanne3.authority_service.v2_contract import (
    FencePermitV2, MutationReceiptV2, PendingMutationV2,
)
from sylanne3.graph_types import NamespaceEpoch
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityHandshake, AuthorityProvisioningRequest,
    PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile
from sylanne3.host.v2_fence_port import V2FenceOutcomeUnknown, V2FencePort
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_journal import RecoveryConstraintFootprint
from sylanne3.runtime_contracts import (
    FenceScope, InstallationGrantV2, NamespaceBootstrapV2, NamespaceId,
    NamespaceRuntimeState,
)

if installed_stub:
    del sys.modules["sylanne3.host"]


NAMESPACE = NamespaceId("bot-a", "persona-a")
BINDING = "a" * 64
ANCHOR = RestoreAnchor("authority-a", "ns-a", 1, "deletion-a", 0, "genesis",
                       "execution-a", 0, "genesis", 0, "proof-a")
HANDSHAKE = AuthorityHandshake("paired", "authority-a", "subject-a", BINDING, True)
GRANT = InstallationGrantV2("authority-a", "subject-a", "holder-a", "installation-a",
                            "c" * 64, "policy-a", "capabilities-v2", BINDING)


class ControlledMtlsTransport:
    """Controlled Authority responses with the same async ownership surface."""

    def __init__(self, profiles):
        self.loop = None
        self.thread_id = None
        self.closed = False
        self.permit = None
        self.fail_next = False
        self.expire_begin_once = False
        self.lose_begin_response_once = False
        self.lose_begin_transport_after_commit_once = False
        self.expire_finish_once = False
        self.lose_finish_before_once = False
        self.lose_finish_after_once = False
        self.fail_finish_always = False
        self.slow_anchor_once = False
        self.expire_genesis_once = False
        self.genesis_response = None
        self.genesis_requests = []
        self.grant = GRANT
        self.mapping = "ns-a"
        self.handshakes = 0
        self.bootstrap_calls = 0
        self.begin_ids = []
        self.finish_requests = []
        self.finished = None
        self.prepare_calls = []
        self.lose_prepare_once = False

    def _on_owner_loop(self):
        loop = asyncio.get_running_loop()
        if self.loop is None:
            self.loop = loop
            self.thread_id = get_ident()
        assert self.loop is loop

    async def handshake(self, request, *, protocol):
        self._on_owner_loop()
        assert protocol == "sylanne3.authority.v2"
        self.handshakes += 1
        return HANDSHAKE

    async def installation_grant_v2(self, request, handshake):
        self._on_owner_loop()
        return self.grant

    async def v2_namespace_bootstrap(self, request, handshake, namespace):
        self._on_owner_loop()
        assert namespace == NAMESPACE
        self.bootstrap_calls += 1
        return NamespaceBootstrapV2("authority-a", NAMESPACE, self.mapping, "holder-a",
                                    1, "active", NamespaceRuntimeState.ACTIVE,
                                    replace(ANCHOR, namespace=self.mapping), ())

    async def v2_namespace_genesis(self, request, handshake, namespace, request_id):
        self._on_owner_loop()
        self.genesis_requests.append((namespace, request_id))
        if self.expire_genesis_once:
            self.expire_genesis_once = False
            raise RuntimeError("authority service unavailable")
        if self.genesis_response is not None:
            return self.genesis_response
        return NamespaceBootstrapV2("authority-a", namespace, self.mapping, "holder-a",
                                    1, "active", NamespaceRuntimeState.ACTIVE,
                                    replace(ANCHOR, namespace=self.mapping), ())

    async def v2_current_anchor(self, request, handshake, namespace):
        self._on_owner_loop()
        if self.slow_anchor_once:
            self.slow_anchor_once = False
            await asyncio.sleep(0.2)
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("authority v2 anchor identity mismatch")
        return ANCHOR

    async def v2_begin_content_fence(self, request, handshake, *, namespace, holder,
                                     operation, operation_id, expected_anchor):
        self._on_owner_loop()
        self.begin_ids.append(operation_id)
        if self.expire_begin_once:
            self.expire_begin_once = False
            raise RuntimeError("authority service unavailable")
        if self.permit is not None:
            assert self.permit.operation_id == operation_id
            return self.permit
        self.permit = FencePermitV2("authority-a", namespace, "subject-a", holder, 1,
                                    operation, operation_id, "a" * 32, 1, 0, expected_anchor)
        if self.lose_begin_transport_after_commit_once:
            self.lose_begin_transport_after_commit_once = False
            raise RuntimeError("authority transport unavailable")
        if self.lose_begin_response_once:
            self.lose_begin_response_once = False
            await asyncio.sleep(0.2)
        return self.permit

    async def v2_validate_fence(self, request, handshake, permit):
        self._on_owner_loop()
        assert permit == self.permit
        return permit

    async def v2_begin_dispatch_fence(self, request, handshake, *, namespace, holder,
                                      operation_id, expected_anchor, effect_id,
                                      command_digest, footprint):
        self._on_owner_loop()
        import hashlib
        return FencePermitV2(
            "authority-a", namespace, "subject-a", holder, 1, "dispatch",
            operation_id, "a" * 32, 1, 0, expected_anchor, effect_id,
            command_digest, "sha256:" + hashlib.sha256(footprint._json().encode()).hexdigest(),
        )

    async def v2_execution_prepare(self, request, handshake, *, permit,
                                   mutation_id, footprint):
        self._on_owner_loop()
        self.prepare_calls.append((permit, mutation_id, footprint))
        pending = PendingMutationV2(
            permit, mutation_id, "sha256:" + "a" * 64, "prepared",
            permit.pinned_anchor, "append-a", "sha256:" + "e" * 64,
        )
        after = replace(permit.pinned_anchor, execution_seq=1,
                        execution_digest=pending.expected_append_digest, proof="proof-next")
        result = (MutationReceiptV2(pending, after, 1, "committed"),
                  replace(permit, revision=1, pinned_anchor=after))
        if self.lose_prepare_once:
            self.lose_prepare_once = False
            raise RuntimeError("authority transport unavailable")
        return result

    async def v2_finish_fence(self, request, handshake, permit, *, request_id, request_digest):
        self._on_owner_loop()
        self.finish_requests.append((request_id, request_digest))
        if self.fail_finish_always:
            raise RuntimeError("authority service unavailable")
        if self.expire_finish_once:
            self.expire_finish_once = False
            raise RuntimeError("authority service unavailable")
        if self.lose_finish_before_once:
            self.lose_finish_before_once = False
            await asyncio.sleep(0.2)
        if self.permit is None:
            assert self.finished == (permit, request_id, request_digest)
            return
        assert permit == self.permit
        self.permit = None
        self.finished = (permit, request_id, request_digest)
        if self.lose_finish_after_once:
            self.lose_finish_after_once = False
            await asyncio.sleep(0.2)

    async def close(self):
        self._on_owner_loop()
        self.closed = True


@pytest.fixture
def port(tmp_path):
    request = AuthorityProvisioningRequest(
        AUTHORITY_PROTOCOL, "profile-a", "astrbot_plugin_sylanne", "4.28.1",
        tmp_path, tmp_path, PublisherPackageIdentity("c" * 64),
    )
    profile = AuthorityTlsProfile("profile-a", "localhost", 443, "localhost",
                                  "authority-a", Path(tmp_path / "ca.pem"),
                                  Path(tmp_path / "client.pem"), Path(tmp_path / "key.pem"))
    transport = ControlledMtlsTransport({"profile-a": profile})
    adapter = V2FencePort(request, {"profile-a": profile}, GRANT,
                          transport_factory=lambda _: transport)
    try:
        yield adapter, transport
    finally:
        adapter.close()


def test_content_fence_round_trip_and_mapping(port):
    adapter, transport = port
    assert transport.thread_id != get_ident()
    assert adapter.current_anchor(namespace=NAMESPACE, authority_namespace="ns-a") == ANCHOR
    permit = adapter.begin_fence(
        namespace=NAMESPACE, authority_namespace="ns-a", holder="holder-a", generation=1,
        operation="write", operation_id="write-a", expected_anchor=ANCHOR,
    )
    scope = FenceScope(NAMESPACE, "ns-a", 1, "write", "write-a", permit, ANCHOR,
                       NamespaceEpoch("bot-a", "persona-a", 0), 0)
    assert adapter.validate_fence(scope) == permit
    adapter.finish_fence(scope, request_id="finish-a", request_digest="sha256:" + "d" * 64)
    assert transport.permit is None
    assert transport.bootstrap_calls == 2  # validate/finish use the verified session mapping
    transport.mapping = "ns-b"
    with pytest.raises(RuntimeError, match="not active or mapped"):
        adapter.current_anchor(namespace=NAMESPACE, authority_namespace="ns-a")
    with pytest.raises(ValueError, match="dispatch requires"):
        adapter.begin_fence(namespace=NAMESPACE, authority_namespace="ns-a",
                            holder="holder-a", generation=1, operation="dispatch",
                            operation_id="dispatch-a", expected_anchor=ANCHOR)


def test_dispatch_worker_replays_only_original_prepared_request(port):
    adapter, transport = port
    footprint = RecoveryConstraintFootprint(
        "ns-a", "activity-a", "effect-a", conflict_keys=("resource-a",))
    permit = adapter.begin_dispatch_fence(
        namespace=NAMESPACE, authority_namespace="ns-a", holder="holder-a",
        generation=1, operation_id="dispatch-a", expected_anchor=ANCHOR,
        effect_id="effect-a", command_digest="sha256:" + "d" * 64,
        footprint=footprint)
    transport.lose_prepare_once = True
    receipt, updated = adapter.execution_prepare(
        namespace=NAMESPACE, authority_namespace="ns-a", permit=permit,
        mutation_id="mutation-a", footprint=footprint)
    assert receipt.durable_state == "committed" and updated.revision == 1
    assert transport.prepare_calls == [(permit, "mutation-a", footprint)] * 2
    assert transport.handshakes == 2
    assert transport.thread_id != get_ident()


def test_namespace_genesis_retries_same_request_id_after_session_expiry(port):
    adapter, transport = port
    assert adapter.installation_grant == GRANT
    transport.expire_genesis_once = True
    observed = adapter.provision_namespace(namespace=NAMESPACE, request_id="genesis-stable")
    assert observed.namespace == NAMESPACE
    assert observed.authority_namespace == "ns-a"
    assert observed.anchor == ANCHOR
    assert transport.genesis_requests == [(NAMESPACE, "genesis-stable")] * 2
    assert transport.handshakes == 2


@pytest.mark.parametrize("invalid_response", [
    NamespaceBootstrapV2("authority-a", NAMESPACE, "ns-a", "other-holder", 1,
                         "active", NamespaceRuntimeState.ACTIVE, ANCHOR, ()),
    NamespaceBootstrapV2("authority-a", NAMESPACE, "ns-a", "holder-a", 2,
                         "active", NamespaceRuntimeState.ACTIVE,
                         replace(ANCHOR, activation_generation=2), ()),
    NamespaceBootstrapV2("authority-a", NAMESPACE, "ns-a", "holder-a", 1,
                         "active", NamespaceRuntimeState.ACTIVE,
                         replace(ANCHOR, deletion_seq=1,
                                 deletion_digest="sha256:" + "d" * 64), ()),
    NamespaceBootstrapV2("authority-a", NamespaceId("other", "persona-a"),
                         "ns-a", "holder-a", 1, "active", NamespaceRuntimeState.ACTIVE,
                         ANCHOR, ()),
])
def test_namespace_genesis_rejects_untrusted_activation_facts(port, invalid_response):
    adapter, transport = port
    transport.genesis_response = invalid_response
    with pytest.raises(RuntimeError, match="genesis response"):
        adapter.provision_namespace(namespace=NAMESPACE, request_id="genesis-check")


def test_error_isolation_event_loop_rejection_and_close(port):
    adapter, transport = port
    transport.fail_next = True
    with pytest.raises(RuntimeError, match="anchor identity mismatch"):
        adapter.current_anchor(namespace=NAMESPACE, authority_namespace="ns-a")
    assert adapter.current_anchor(namespace=NAMESPACE, authority_namespace="ns-a") == ANCHOR

    async def forbidden():
        with pytest.raises(RuntimeError, match="event loop thread"):
            adapter.current_anchor(namespace=NAMESPACE, authority_namespace="ns-a")

    asyncio.run(forbidden())
    adapter.close()
    assert transport.closed and not adapter._thread.is_alive()
    with pytest.raises(RuntimeError, match="closed"):
        adapter.current_anchor(namespace=NAMESPACE, authority_namespace="ns-a")


def test_expired_session_repairs_once_and_replays_original_request(port):
    adapter, transport = port
    transport.expire_begin_once = True
    permit = adapter.begin_fence(
        namespace=NAMESPACE, authority_namespace="ns-a", holder="holder-a", generation=1,
        operation="write", operation_id="write-stable", expected_anchor=ANCHOR,
    )
    assert transport.begin_ids == ["write-stable", "write-stable"]
    assert transport.handshakes == 2
    scope = FenceScope(NAMESPACE, "ns-a", 1, "write", "write-stable", permit, ANCHOR,
                       NamespaceEpoch("bot-a", "persona-a", 0), 0)
    transport.expire_finish_once = True
    digest = "sha256:" + "d" * 64
    adapter.finish_fence(scope, request_id="finish-stable", request_digest=digest)
    assert transport.finish_requests == [("finish-stable", digest)] * 2
    assert transport.handshakes == 3
    assert transport.permit is None


def test_timeout_reports_unknown_outcome(port):
    adapter, transport = port
    adapter._timeout = 0.05
    transport.slow_anchor_once = True
    with pytest.raises(V2FenceOutcomeUnknown, match="result unknown"):
        adapter.current_anchor(namespace=NAMESPACE, authority_namespace="ns-a")


def test_repair_fails_closed_if_installation_identity_drifts(port):
    adapter, transport = port
    transport.expire_begin_once = True
    transport.grant = replace(GRANT, installation_id="different-installation")
    with pytest.raises(RuntimeError, match="installation identity changed"):
        adapter.begin_fence(
            namespace=NAMESPACE, authority_namespace="ns-a", holder="holder-a", generation=1,
            operation="write", operation_id="write-stable", expected_anchor=ANCHOR,
        )
    assert transport.begin_ids == ["write-stable"]
    assert transport.handshakes == 2


def test_lost_begin_response_is_reclaimed_before_new_operation_id(port):
    adapter, transport = port
    adapter._timeout = 0.05
    transport.lose_begin_response_once = True
    with pytest.raises(V2FenceOutcomeUnknown, match="result unknown"):
        adapter.begin_fence(
            namespace=NAMESPACE, authority_namespace="ns-a", holder="holder-a", generation=1,
            operation="read", operation_id="lost-read", expected_anchor=ANCHOR,
        )
    assert adapter._pending_begin is not None
    adapter._timeout = 21
    next_permit = adapter.begin_fence(
        namespace=NAMESPACE, authority_namespace="ns-a", holder="holder-a", generation=1,
        operation="read", operation_id="next-read", expected_anchor=ANCHOR,
    )
    assert transport.begin_ids == ["lost-read", "lost-read", "next-read"]
    assert transport.finish_requests[0][0].startswith("abandoned-")
    assert transport.permit == next_permit
    assert adapter._pending_begin is None
    scope = FenceScope(NAMESPACE, "ns-a", 1, "read", "next-read", next_permit, ANCHOR,
                       NamespaceEpoch("bot-a", "persona-a", 0), 0)
    adapter.finish_fence(scope, request_id="finish-next", request_digest="sha256:" + "d" * 64)


def test_retained_unknown_begin_retries_same_operation_without_auto_finish(port):
    adapter, transport = port
    adapter._timeout = 0.05
    transport.lose_begin_response_once = True
    with pytest.raises(V2FenceOutcomeUnknown, match="result unknown"):
        adapter.begin_fence(
            namespace=NAMESPACE, authority_namespace="ns-a", holder="holder-a", generation=1,
            operation="read", operation_id="retained-read", expected_anchor=ANCHOR,
            retain_on_unknown=True,
        )
    assert adapter._pending_begin is None
    adapter._timeout = 21
    adapter.recover_pending_begin()
    assert transport.finish_requests == []

    permit = adapter.begin_fence(
        namespace=NAMESPACE, authority_namespace="ns-a", holder="holder-a", generation=1,
        operation="read", operation_id="retained-read", expected_anchor=ANCHOR,
        retain_on_unknown=True,
    )
    assert transport.begin_ids == ["retained-read", "retained-read"]
    assert transport.permit == permit
    assert transport.finish_requests == []
    scope = FenceScope(NAMESPACE, "ns-a", 1, "read", "retained-read", permit, ANCHOR,
                       NamespaceEpoch("bot-a", "persona-a", 0), 0)
    adapter.finish_fence(scope, request_id="finish-retained", request_digest="sha256:" + "d" * 64)


def test_retained_unknown_begin_is_not_finished_on_close(port):
    adapter, transport = port
    adapter._timeout = 0.05
    transport.lose_begin_response_once = True
    with pytest.raises(V2FenceOutcomeUnknown, match="result unknown"):
        adapter.begin_fence(
            namespace=NAMESPACE, authority_namespace="ns-a", holder="holder-a", generation=1,
            operation="read", operation_id="retained-on-close", expected_anchor=ANCHOR,
            retain_on_unknown=True,
        )
    adapter._timeout = 21
    adapter.close()
    assert transport.closed
    assert transport.finish_requests == []
    assert transport.permit is not None


def test_second_transport_loss_after_begin_commit_blocks_new_id_until_recovered(port):
    adapter, transport = port
    transport.expire_begin_once = True
    transport.lose_begin_transport_after_commit_once = True
    with pytest.raises(V2FenceOutcomeUnknown, match="result unknown after transport loss"):
        adapter.begin_fence(
            namespace=NAMESPACE, authority_namespace="ns-a", holder="holder-a", generation=1,
            operation="read", operation_id="uncertain-read", expected_anchor=ANCHOR,
        )
    assert transport.begin_ids == ["uncertain-read", "uncertain-read"]
    assert transport.permit is not None
    assert adapter._pending_begin is not None
    next_permit = adapter.begin_fence(
        namespace=NAMESPACE, authority_namespace="ns-a", holder="holder-a", generation=1,
        operation="read", operation_id="next-read", expected_anchor=ANCHOR,
    )
    assert transport.begin_ids == ["uncertain-read", "uncertain-read", "uncertain-read", "next-read"]
    assert transport.finish_requests[0][0].startswith("abandoned-")
    assert next_permit.operation_id == "next-read"
    scope = FenceScope(NAMESPACE, "ns-a", 1, "read", "next-read", next_permit, ANCHOR,
                       NamespaceEpoch("bot-a", "persona-a", 0), 0)
    adapter.finish_fence(scope, request_id="finish-next", request_digest="sha256:" + "d" * 64)


@pytest.mark.parametrize("lost_after_commit", [False, True])
def test_lost_finish_response_reuses_original_request_before_new_begin(port, lost_after_commit):
    adapter, transport = port
    permit = adapter.begin_fence(
        namespace=NAMESPACE, authority_namespace="ns-a", holder="holder-a", generation=1,
        operation="read", operation_id="first-read", expected_anchor=ANCHOR,
    )
    scope = FenceScope(NAMESPACE, "ns-a", 1, "read", "first-read", permit, ANCHOR,
                       NamespaceEpoch("bot-a", "persona-a", 0), 0)
    transport.lose_finish_after_once = lost_after_commit
    transport.lose_finish_before_once = not lost_after_commit
    adapter._timeout = 0.05
    digest = "sha256:" + "d" * 64
    with pytest.raises(V2FenceOutcomeUnknown, match="result unknown"):
        adapter.finish_fence(scope, request_id="finish-first", request_digest=digest)
    assert adapter._pending_finish is not None
    adapter._timeout = 21
    transport.fail_finish_always = True
    with pytest.raises(V2FenceOutcomeUnknown, match="new operation ID is blocked"):
        adapter.begin_fence(
            namespace=NAMESPACE, authority_namespace="ns-a", holder="holder-a", generation=1,
            operation="read", operation_id="second-read", expected_anchor=ANCHOR,
        )
    assert transport.begin_ids == ["first-read"]
    transport.fail_finish_always = False
    next_permit = adapter.begin_fence(
        namespace=NAMESPACE, authority_namespace="ns-a", holder="holder-a", generation=1,
        operation="read", operation_id="second-read", expected_anchor=ANCHOR,
    )
    assert transport.finish_requests[-1] == ("finish-first", digest)
    assert transport.begin_ids == ["first-read", "second-read"]
    assert adapter._pending_finish is None
    next_scope = FenceScope(NAMESPACE, "ns-a", 1, "read", "second-read", next_permit, ANCHOR,
                            NamespaceEpoch("bot-a", "persona-a", 0), 0)
    adapter.finish_fence(next_scope, request_id="finish-second", request_digest=digest)
