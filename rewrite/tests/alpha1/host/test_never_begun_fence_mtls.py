"""An installed write attempt can durably exclude a late Authority begin."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import ssl
from threading import Barrier
import time
from types import SimpleNamespace

import pytest

from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as loopback
from sylanne3.authority_service import AuthorityServiceCore, JournalHead
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, AuthorityServerTlsConfig,
    MtlsPeerCredential,
)
from sylanne3.authority_service.v2_contract import FenceNeverBegunReceiptV2
from sylanne3.authority_service.v2_clock import AuthorityClockReadingV2
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.local_composition import compose_local_owner_authority
from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard, namespace_ref
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import TypeRegistry, owner_grant_spec
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityProvisioningRequest, PublisherPackageIdentity,
)
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.host.authority_profile import AdminIngressClockPolicy
from sylanne3.host.post_c02_reply_driver import post_c02_reply_operation_id
from sylanne3.host.v2_fence_port import V2FencePort
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.memory_types import source_key
from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime.issuers import BudgetLeaseGrant, build_runtime_issuers
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId


@dataclass(frozen=True)
class _Progress:
    run: object


@dataclass(frozen=True)
class _Run:
    preparation: object


@dataclass(frozen=True)
class _Preparation:
    c02_receipt: object
    source: object


@dataclass(frozen=True)
class _C02Receipt:
    operation_id: str


@dataclass(frozen=True)
class _Source:
    source_ref: str


@pytest.mark.asyncio
async def test_mtls_reject_unbegun_is_durable_and_late_begin_cannot_win(tmp_path):
    files = loopback.AuthorityMtlsLoopbackTests._certificates(tmp_path)
    peer = MtlsPeerCredential(hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        files["client.pem"].read_text(encoding="ascii"))).hexdigest())
    namespace = NamespaceId("bot-never-begun", "persona-never-begun")
    authority_namespace = "ns:never-begun"
    holder = "host:never-begun"
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=authority_namespace,
        journal_id="execution-never-begun", create=True)
    head = deletion.latest_head()
    deletion_head = JournalHead(head.journal_id, head.seq, head.chain_digest)

    def authorizer(candidate, action, selected, requested_holder):
        return (candidate == peer and selected == authority_namespace
                and action in {"install", "seal_v2_only", "current", "write"}
                and (requested_holder is None or requested_holder == holder))

    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True, authorizer=authorizer,
        deletion_verifier=lambda ns, before, current, phase:
            current == deletion_head and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            current == execution.verified_head(),
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True)
    listener = transport = port = None
    try:
        core.register_namespace(peer, authority_namespace, holder,
                                deletion_head, execution.verified_head())
        core.seal_v2_only(peer)
        fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
        service = AuthorityV2FenceService(
            core=core, fences=fences, deletion=guard, execution=execution,
            namespace=authority_namespace)
        server = AuthorityRpcServer(
            core, administrator_authorizer=lambda candidate, action, target, profile:
                candidate == peer and action == "pair",
            publisher_manifest_verifier=lambda *args: True,
            v2_fences=service,
            installations_v2={
                (peer.certificate_sha256, "never-begun"):
                    AdministratorInstallationV2(
                        "installation-never-begun", holder, "policy-never-begun",
                        "v2", "a" * 64),
            },
            namespace_bindings_v2={
                (peer.certificate_sha256, "never-begun", namespace): authority_namespace,
            })
        listener = await server.start(
            "127.0.0.1", 0,
            AuthorityServerTlsConfig(str(files["server.pem"]), str(files["server.key"]),
                                     str(files["ca.pem"]), timeout_seconds=1,
                                     max_message_bytes=16_384))
        profile = AuthorityTlsProfile(
            "never-begun", "127.0.0.1", listener.sockets[0].getsockname()[1],
            "localhost", server._authority_id(), files["ca.pem"], files["client.pem"],
            files["client.key"], timeout_seconds=1, max_message_bytes=16_384)
        request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, "never-begun", "astrbot_plugin_sylanne", "4.28.1",
            tmp_path, tmp_path, PublisherPackageIdentity("a" * 64))
        transport = MtlsAuthorityTransport({"never-begun": profile})
        handshake = await transport.handshake(request, protocol="sylanne3.authority.v2")
        grant = await transport.installation_grant_v2(request, handshake)
        port = await asyncio.to_thread(
            V2FencePort, request, {"never-begun": profile}, grant)
        anchor = await asyncio.to_thread(
            port.current_anchor, namespace=namespace,
            authority_namespace=authority_namespace)
        kwargs = dict(
            holder=holder, generation=anchor.activation_generation,
            operation_id="write-never-begun", expected_anchor=anchor,
            request_id="reject-never-begun", request_digest="sha256:" + "b" * 64)

        def reject(**changes):
            return port.reject_unbegun_content_fence_v2(
                namespace, authority_namespace, **(kwargs | changes))

        receipt = await asyncio.to_thread(reject)
        assert type(receipt) is FenceNeverBegunReceiptV2
        assert receipt.state == "rejected_before_begin"
        assert receipt.installation_id == grant.installation_id
        assert await asyncio.to_thread(reject) == receipt
        with pytest.raises(RuntimeError):
            await asyncio.to_thread(reject, request_id="different-rejection")
        with pytest.raises(RuntimeError):
            await asyncio.to_thread(
                port.begin_fence, namespace=namespace,
                authority_namespace=authority_namespace, holder=holder,
                generation=anchor.activation_generation, operation="write",
                operation_id=kwargs["operation_id"], expected_anchor=anchor,
                retain_on_unknown=True)
        assert core._db.execute(
            "SELECT count(*) FROM authority_v2_fences WHERE operation_id=?",
            (kwargs["operation_id"],)).fetchone() == (0,)
        assert core._db.execute(
            "SELECT count(*) FROM authority_v2_never_begun WHERE operation_id=?",
            (kwargs["operation_id"],)).fetchone() == (1,)

        # Reverse ordering: once begin has won, no absent proof can be minted.
        permit = await asyncio.to_thread(
            port.begin_fence, namespace=namespace,
            authority_namespace=authority_namespace, holder=holder,
            generation=anchor.activation_generation, operation="write",
            operation_id="write-already-begun", expected_anchor=anchor)
        with pytest.raises(RuntimeError):
            await asyncio.to_thread(reject, operation_id=permit.operation_id,
                                    request_id="reject-existing")
        # A different pending operation is not evidence that this operation
        # began; it must not prevent an atomic rejection of this ID.
        core._db.execute(
            "UPDATE authority_v2_fences SET pending=? WHERE operation_id=?",
            (b"pending-other-operation", permit.operation_id))
        unrelated = service.reject_unbegun_content_fence_v2(
            credential=peer, subject="mtls:sha256:" + peer.certificate_sha256,
            installation_id=grant.installation_id, holder=holder,
            generation=anchor.activation_generation,
            operation_id="write-unrelated-pending", expected_anchor=anchor,
            request_id="reject-unrelated-pending",
            request_digest="sha256:" + "e" * 64)
        assert unrelated.state == "rejected_before_begin"
        core._db.execute(
            "UPDATE authority_v2_fences SET pending=NULL WHERE operation_id=?",
            (permit.operation_id,))
        with core._tx() as db:
            for changed in (
                {"subject": "mtls:sha256:" + "0" * 64},
                {"current_anchor": replace(anchor, namespace="ns:foreign")},
            ):
                with pytest.raises(AuthorityUnavailable):
                    arguments = dict(
                        subject="mtls:sha256:" + peer.certificate_sha256,
                        installation_id=grant.installation_id, holder=holder,
                        generation=anchor.activation_generation,
                        operation_id=kwargs["operation_id"], current_anchor=anchor,
                        request_id=kwargs["request_id"],
                        request_digest=kwargs["request_digest"])
                    fences.reject_unbegun_content_fence_locked(db, **(arguments | changed))
        service.finish_fence(
            credential=peer, subject="mtls:sha256:" + peer.certificate_sha256,
            permit=permit, request_id="finish-existing",
            request_digest="sha256:" + "c" * 64)

        # Both calls use the real Authority store and race for its DB lock.
        gate = Barrier(3)
        subject = "mtls:sha256:" + peer.certificate_sha256

        def begin_race():
            gate.wait()
            return service.begin_fence(
                credential=peer, subject=subject, holder=holder,
                operation="write", operation_id="write-race",
                expected_anchor=anchor)

        def reject_race():
            gate.wait()
            return service.reject_unbegun_content_fence_v2(
                credential=peer, subject=subject,
                installation_id=grant.installation_id, holder=holder,
                generation=anchor.activation_generation,
                operation_id="write-race", expected_anchor=anchor,
                request_id="reject-race", request_digest="sha256:" + "d" * 64)

        with ThreadPoolExecutor(max_workers=2) as pool:
            begun = pool.submit(begin_race)
            rejected = pool.submit(reject_race)
            gate.wait()
            outcomes = []
            for future in (begun, rejected):
                try:
                    outcomes.append(future.result())
                except AuthorityUnavailable:
                    outcomes.append(None)
        assert sum(item is not None for item in outcomes) == 1
        assert sum((
            core._db.execute("SELECT count(*) FROM authority_v2_fences "
                             "WHERE operation_id='write-race'").fetchone()[0],
            core._db.execute("SELECT count(*) FROM authority_v2_never_begun "
                             "WHERE operation_id='write-race'").fetchone()[0],
        )) == 1
    finally:
        if port is not None:
            await asyncio.to_thread(port.close)
        if transport is not None:
            await transport.close()
        if listener is not None:
            listener.close()
            await listener.wait_closed()
        core.close()
        execution.close()
        guard.close()
        deletion.close()


@pytest.mark.asyncio
async def test_graph_terminal_close_uses_real_mtls_never_begun_proof(tmp_path, monkeypatch):
    namespace = NamespaceId("bot-abort-cas", "persona-abort-cas")
    authority_namespace = namespace_ref(namespace)
    holder = "host:abort-cas"
    files = loopback.AuthorityMtlsLoopbackTests._certificates(tmp_path)
    peer = MtlsPeerCredential(hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        files["client.pem"].read_text(encoding="ascii"))).hexdigest())
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=authority_namespace,
        journal_id="execution-abort-cas", create=True)
    bootstrap_deletion = DeletionJournal(tmp_path / "bootstrap-deletion.db", create=True)
    bootstrap_execution = AuthorityV2ExecutionJournal(
        tmp_path / "bootstrap-execution.db", namespace="ns:bootstrap",
        journal_id="bootstrap-execution", create=True)
    head = deletion.latest_head()
    deletion_head = JournalHead(head.journal_id, head.seq, head.chain_digest)
    bootstrap_head = bootstrap_deletion.latest_head()
    bootstrap_deletion_head = JournalHead(
        bootstrap_head.journal_id, bootstrap_head.seq, bootstrap_head.chain_digest)

    def authorizer(candidate, action, selected, requested_holder):
        return (candidate == peer and selected in {authority_namespace, "ns:bootstrap"}
                and action in {"install", "seal_v2_only", "namespace_genesis",
                               "current", "read", "write", "dispatch", "execution",
                               "owner_guard_read"}
                and (requested_holder is None or requested_holder == holder))

    core = AuthorityServiceCore(
        tmp_path / "authority.db", create=True, authorizer=authorizer,
        deletion_verifier=lambda ns, before, current, phase:
            current == (bootstrap_deletion_head if ns == "ns:bootstrap" else deletion_head)
            and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            (bootstrap_execution.verified_head() if ns == "ns:bootstrap"
             else execution.verified_head()) == current,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True)
    registry = TypeRegistry()
    registry.register(owner_grant_spec())
    graph_store = ProductionGraphStore(tmp_path / "business.db", registry)
    listener = transport = port = None
    try:
        core.register_namespace(peer, "ns:bootstrap", holder,
                                bootstrap_deletion_head,
                                bootstrap_execution.verified_head())
        core.seal_v2_only(peer)
        fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
        protected = AuthorityV2FenceService(
            core=core, fences=fences, deletion=guard, execution=execution,
            namespace=authority_namespace)
        clock_offset = [0.0]
        server = compose_local_owner_authority(
            core=core, v2_fences={authority_namespace: protected},
            graph_db_path=tmp_path / "business.db",
            utc_clock=lambda: datetime.now(timezone.utc),
            first_claim_verifier=lambda *args: False,
            claimant_verifier=lambda *args: False,
            administrator_authorizer=lambda candidate, action, selected, profile:
                candidate == peer and action == "pair"
                and selected == "authority:enrollment",
            publisher_manifest_verifier=lambda *args: True,
            installations_v2={
                (peer.certificate_sha256, "abort-cas"):
                    AdministratorInstallationV2(
                        "installation-abort-cas", holder, "policy-abort-cas", "v2",
                        "a" * 64, "clock:abort-cas", 0.5),
            },
            namespace_bindings_v2={
                (peer.certificate_sha256, "abort-cas", namespace): authority_namespace,
            },
            clock_provider=lambda: AuthorityClockReadingV2(
                "clock:abort-cas", time.time() + clock_offset[0],
                time.monotonic(), "epoch:abort-cas", True, 0.1),
            create_owner_schema=True)
        listener = await server.start(
            "127.0.0.1", 0,
            AuthorityServerTlsConfig(str(files["server.pem"]), str(files["server.key"]),
                                     str(files["ca.pem"]), timeout_seconds=1,
                                     max_message_bytes=16_384))
        profile = AuthorityTlsProfile(
            "abort-cas", "127.0.0.1", listener.sockets[0].getsockname()[1],
            "localhost", server._authority_id(), files["ca.pem"], files["client.pem"],
            files["client.key"], timeout_seconds=1, max_message_bytes=16_384)
        request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, "abort-cas", "astrbot_plugin_sylanne", "4.28.1",
            tmp_path, tmp_path, PublisherPackageIdentity("a" * 64))
        transport = MtlsAuthorityTransport({"abort-cas": profile})
        handshake = await transport.handshake(request, protocol="sylanne3.authority.v2")
        grant = await transport.installation_grant_v2(request, handshake)
        port = await asyncio.to_thread(V2FencePort, request, {"abort-cas": profile}, grant)
        root_lease = BudgetLease(
            "lease-abort-cas", None, *namespace.as_tuple, "USD",
            {"cpu_ms": 200}, {}, {}, {}, 1, "active")
        root_grant = BudgetLeaseGrant(
            "grant-abort-cas", 1, *namespace.as_tuple, root_lease.lease_id,
            "USD", {"cpu_ms": 100}, ("encode",), time.time() + 3600, "d11-policy")
        policy = AdminInstallationPolicy(
            namespace, authority_namespace, grant.installation_id, "a" * 64,
            holder, grant.authority_id, graph_store._registry.catalogue_hash,
            "scheme-1", "operator-1", "policy-1", root_lease, root_grant)
        d02, d11 = build_runtime_issuers(b"abort-cas-key-" * 3)
        bootstrap = object()
        graph = GraphCoordinator(
            graph_store, bootstrap, holder=holder, content_fence_v2=port,
            d02_issuer=d02, d11_issuer=d11)
        await asyncio.to_thread(graph.provision_namespace_v2, bootstrap, policy,
                                operation_id="abort-cas-owner-creation")
        for domain in ("d08", "d09", "d11"):
            provider = type("NoWriteProvider", (),
                            {"validate": lambda self, *args: True})()
            graph.register_provider(bootstrap, domain, provider,
                                    f"{domain}.proposal.v1", "b" * 64)
        lease, capability = graph.grant(
            bootstrap, actor=holder, issuer_domain="d11", namespace=namespace,
            domains=("d08", "d09", "d11"), activation_generation=1,
            operation_id="abort-cas-attempt")
        authority = AuthorityContext(
            holder, "d11", capability, namespace, (), "expression", ("private",),
            "policy-1", 1)
        clock_policy = AdminIngressClockPolicy("clock:abort-cas", 0.5, 2.0)
        graph._GraphCoordinator__dispatch_clock_policy = clock_policy
        installed = SimpleNamespace(ingress_clock=clock_policy,
                                    installation_policy=policy)
        source_ref = source_key(*namespace.as_tuple, "inbound").token
        progress = _Progress(_Run(_Preparation(
            _C02Receipt("c02:abort-cas"), _Source(source_ref))))
        operation_id = post_c02_reply_operation_id("c02:abort-cas", source_ref)
        deadline = time.time() + 100.0
        digest = graph._post_c02_reply_dispatch_request_digest_v2(
            installed_bundle=installed, handler_invocation_id="handler:abort-cas",
            handler_deadline_utc=deadline, progress=progress)
        anchor = await asyncio.to_thread(
            port.current_anchor, namespace=namespace,
            authority_namespace=authority_namespace)
        with graph_store._lock:
            metadata, epoch = graph._v2_graph_stamp(namespace)
            attempt_id = graph._open_post_c02_reply_dispatch_attempt_locked(
                namespace=namespace, operation_id=operation_id,
                handler_invocation_id="handler:abort-cas", request_digest=digest,
                input_digest="a" * 64, handler_deadline_utc=deadline,
                frozen_deadline_utc=deadline - 1,
                metadata=metadata, epoch=epoch, anchor=anchor)
        clock_offset[0] = 200.0

        def close():
            return graph.close_expired_post_c02_reply_dispatch_attempt_v2(
                authority, lease, progress, installed,
                handler_invocation_id="handler:abort-cas",
                handler_deadline_utc=deadline)

        original_reject = port.reject_unbegun_content_fence_v2

        def lost_ack(*args, **kwargs):
            original_reject(*args, **kwargs)
            raise RuntimeError("simulated CAS response loss")

        monkeypatch.setattr(port, "reject_unbegun_content_fence_v2", lost_ack)
        with pytest.raises(RuntimeError, match="response loss"):
            await asyncio.to_thread(close)
        assert graph_store._db.execute(
            "SELECT state FROM graph_post_c02_reply_dispatch_attempts_v2 "
            "WHERE operation_id=?", (operation_id,)).fetchone() == ("open",)

        def forged_receipt(*args, **kwargs):
            return replace(original_reject(*args, **kwargs),
                           installation_id="installation:other")

        monkeypatch.setattr(port, "reject_unbegun_content_fence_v2", forged_receipt)
        with pytest.raises(UnavailableGuard, match="receipt differs"):
            await asyncio.to_thread(close)
        assert graph_store._db.execute(
            "SELECT state FROM graph_post_c02_reply_dispatch_attempts_v2 "
            "WHERE operation_id=?", (operation_id,)).fetchone() == ("open",)
        monkeypatch.setattr(port, "reject_unbegun_content_fence_v2", original_reject)
        assert await asyncio.to_thread(close) == "rejected_no_commit"
        assert await asyncio.to_thread(close) == "rejected_no_commit"
        with pytest.raises(RuntimeError):
            await asyncio.to_thread(
                port.begin_fence, namespace=namespace,
                authority_namespace=authority_namespace, holder=holder,
                generation=anchor.activation_generation, operation="write",
                operation_id=attempt_id, expected_anchor=anchor,
                retain_on_unknown=True)
        assert graph_store._db.execute(
            "SELECT state FROM graph_post_c02_reply_dispatch_attempts_v2 "
            "WHERE operation_id=?", (operation_id,)).fetchone() == (
                "rejected_no_commit",)
    finally:
        if port is not None:
            await asyncio.to_thread(port.close)
        if transport is not None:
            await transport.close()
        if listener is not None:
            listener.close()
            await listener.wait_closed()
        graph_store.close()
        core.close()
        execution.close()
        guard.close()
        deletion.close()
        bootstrap_execution.close()
        bootstrap_deletion.close()
