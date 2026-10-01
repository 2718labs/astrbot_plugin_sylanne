"""Expired post-C02 attempts close through a real local Authority fence port."""

import asyncio
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import ssl
import time
from types import SimpleNamespace

import pytest

from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as loopback
from sylanne3.authority_service import AuthorityServiceCore, JournalHead
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityServerTlsConfig, MtlsPeerCredential,
)
from sylanne3.authority_service.v2_clock import AuthorityClockReadingV2
from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.local_composition import compose_local_owner_authority
from sylanne3.contracts import canonical_json
from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard, namespace_ref
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.graph_types import TypeRegistry, owner_grant_spec
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityProvisioningRequest, PublisherPackageIdentity,
)
from sylanne3.host.authority_profile import AdminIngressClockPolicy
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.host.post_c02_reply_driver import post_c02_reply_operation_id
from sylanne3.host.v2_fence_port import V2FencePort
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.memory_types import source_key
from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime.issuers import BudgetLeaseGrant, build_runtime_issuers
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId, canonical_digest


@dataclass(frozen=True)
class _C02Receipt:
    operation_id: str


@dataclass(frozen=True)
class _Source:
    source_ref: str


@dataclass(frozen=True)
class _Preparation:
    c02_receipt: _C02Receipt
    source: _Source


@dataclass(frozen=True)
class _Run:
    preparation: _Preparation


@dataclass(frozen=True)
class _Progress:
    run: _Run


@pytest.mark.asyncio
async def test_expired_attempt_closes_once_with_original_permit_and_no_business_fact(
        tmp_path, monkeypatch):
    namespace = NamespaceId("bot-reply-close", "persona-reply-close")
    authority_namespace = namespace_ref(namespace)
    installation_id = "installation-reply-close"
    clock_source = "clock:reply-close"
    clock_offset = [0.0]
    files = loopback.AuthorityMtlsLoopbackTests._certificates(tmp_path)
    peer = MtlsPeerCredential(hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        files["client.pem"].read_text(encoding="ascii"))).hexdigest())
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=authority_namespace,
        journal_id="execution", create=True)
    head = deletion.latest_head()
    deletion_head = JournalHead(head.journal_id, head.seq, head.chain_digest)
    bootstrap_deletion = DeletionJournal(tmp_path / "bootstrap-deletion.db", create=True)
    bootstrap_execution = AuthorityV2ExecutionJournal(
        tmp_path / "bootstrap-execution.db", namespace="ns:bootstrap",
        journal_id="bootstrap-execution", create=True)
    bootstrap_head = bootstrap_deletion.latest_head()
    bootstrap_deletion_head = JournalHead(
        bootstrap_head.journal_id, bootstrap_head.seq, bootstrap_head.chain_digest)

    def authorizer(candidate, action, selected, holder):
        return (candidate == peer and selected in {authority_namespace, "ns:bootstrap"}
                and action in {"install", "seal_v2_only", "namespace_genesis",
                               "current", "read", "write", "dispatch", "execution",
                               "owner_guard_read"}
                and (holder is None or holder == "host:reply-close"))

    core = AuthorityServiceCore(
        tmp_path / "authority.db", authorizer=authorizer,
        deletion_verifier=lambda ns, before, current, phase:
            current == (bootstrap_deletion_head if ns == "ns:bootstrap" else deletion_head)
            and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            (bootstrap_execution.verified_head() if ns == "ns:bootstrap"
             else execution.verified_head()) == current,
        effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True, create=True)
    listener = transport = port = None
    registry = TypeRegistry()
    registry.register(owner_grant_spec())
    store = ProductionGraphStore(tmp_path / "business.db", registry)
    try:
        core.register_namespace(peer, "ns:bootstrap", "host:reply-close",
                                bootstrap_deletion_head, bootstrap_execution.verified_head())
        core.seal_v2_only(peer)
        fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
        protected = AuthorityV2FenceService(
            core=core, fences=fences, deletion=deletion_guard,
            execution=execution, namespace=authority_namespace)
        server = compose_local_owner_authority(
            core=core, v2_fences={authority_namespace: protected},
            graph_db_path=tmp_path / "business.db",
            utc_clock=lambda: datetime.now(timezone.utc),
            first_claim_verifier=lambda *args: False,
            claimant_verifier=lambda *args: False,
            administrator_authorizer=lambda candidate, action, selected, holder:
                candidate == peer and action == "pair" and selected == "authority:enrollment",
            publisher_manifest_verifier=lambda *args: True,
            installations_v2={
                (peer.certificate_sha256, "reply-close"): AdministratorInstallationV2(
                    installation_id, "host:reply-close", "policy:reply-close", "v2",
                    "a" * 64, clock_source, 0.5),
            },
            namespace_bindings_v2={
                (peer.certificate_sha256, "reply-close", namespace): authority_namespace,
            },
            clock_provider=lambda: AuthorityClockReadingV2(
                clock_source, time.time() + clock_offset[0], time.monotonic(),
                "epoch:reply-close", True, 0.1),
            create_owner_schema=True,
        )
        listener = await server.start(
            "127.0.0.1", 0,
            AuthorityServerTlsConfig(str(files["server.pem"]), str(files["server.key"]),
                                     str(files["ca.pem"]), timeout_seconds=1,
                                     max_message_bytes=16_384))
        profile = AuthorityTlsProfile(
            "reply-close", "127.0.0.1", listener.sockets[0].getsockname()[1],
            "localhost", server._authority_id(), files["ca.pem"], files["client.pem"],
            files["client.key"], timeout_seconds=1, max_message_bytes=16_384)
        request = AuthorityProvisioningRequest(
            AUTHORITY_PROTOCOL, "reply-close", "astrbot_plugin_sylanne", "4.28.1",
            tmp_path, tmp_path, PublisherPackageIdentity("a" * 64))
        transport = MtlsAuthorityTransport({"reply-close": profile})
        handshake = await transport.handshake(request, protocol=AUTHORITY_V2_PROTOCOL)
        grant = await transport.installation_grant_v2(request, handshake)
        port = await asyncio.to_thread(V2FencePort, request, {"reply-close": profile}, grant)
        root_lease = BudgetLease(
            "lease-reply-close", None, *namespace.as_tuple, "USD",
            {"cpu_ms": 200}, {}, {}, {}, 1, "active")
        root_grant = BudgetLeaseGrant(
            "grant-reply-close", 1, *namespace.as_tuple, root_lease.lease_id,
            "USD", {"cpu_ms": 100}, ("encode",), time.time() + 3600, "d11-policy")
        policy = AdminInstallationPolicy(
            namespace, authority_namespace, installation_id, "a" * 64,
            "host:reply-close", grant.authority_id, store._registry.catalogue_hash,
            "scheme-1", "operator-1", "policy-1", root_lease, root_grant)
        d02, d11 = build_runtime_issuers(b"reply-close-key-" * 2)
        bootstrap = object()
        graph = GraphCoordinator(store, bootstrap, holder="host:reply-close",
                                 content_fence_v2=port, d02_issuer=d02, d11_issuer=d11)
        await asyncio.to_thread(graph.provision_namespace_v2, bootstrap, policy,
                                operation_id="reply-close-owner-creation")
        for domain in ("d08", "d09", "d11"):
            provider = type("NoWriteProvider", (), {"validate": lambda self, *args: True})()
            graph.register_provider(bootstrap, domain, provider, f"{domain}.proposal.v1", "b" * 64)
        lease, capability = graph.grant(
            bootstrap, actor="host:reply-close", issuer_domain="d11",
            namespace=namespace, domains=("d08", "d09", "d11"),
            activation_generation=1, operation_id="reply-close-attempt")
        authority = AuthorityContext(
            "host:reply-close", "d11", capability, namespace, (), "expression",
            ("private",), "policy-1", 1)
        clock_policy = AdminIngressClockPolicy(clock_source, 0.5, 2.0)
        graph._GraphCoordinator__dispatch_clock_policy = clock_policy
        installed = SimpleNamespace(ingress_clock=clock_policy,
                                    installation_policy=policy)
        source_ref = source_key(*namespace.as_tuple, "inbound").token
        progress = _Progress(_Run(_Preparation(_C02Receipt("c02:original"),
                                               _Source(source_ref))))
        operation_id = post_c02_reply_operation_id("c02:original", source_ref)
        handler = "handler:original"
        deadline = time.time() + 100.0
        digest = graph._post_c02_reply_dispatch_request_digest_v2(
            installed_bundle=installed, handler_invocation_id=handler,
            handler_deadline_utc=deadline, progress=progress)
        anchor = await asyncio.to_thread(
            port.current_anchor, namespace=namespace,
            authority_namespace=authority_namespace)
        # This fixture isolates expired-attempt closure. Stage only its frozen
        # pre-P2 row; the production opener requires a real original ingress.
        with store._lock:
            metadata, epoch = graph._v2_graph_stamp(namespace)
            attempt_id = "post-c02-dispatch-write:" + canonical_digest({
                "namespace": list(namespace.as_tuple),
                "operation_id": operation_id,
                "input_digest": "a" * 64,
            })[:48]
            store._db.execute("""CREATE TABLE IF NOT EXISTS graph_post_c02_reply_dispatch_attempts_v2(
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, handler_invocation_id TEXT NOT NULL,
                request_digest TEXT NOT NULL, input_digest TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                handler_deadline_utc REAL NOT NULL,
                frozen_deadline_utc REAL NOT NULL, anchor_json TEXT NOT NULL,
                pre_graph_revision INTEGER NOT NULL, pre_graph_epoch INTEGER NOT NULL,
                state TEXT NOT NULL, bundle_digest TEXT,
                permit_json TEXT, finish_request_id TEXT,
                finish_request_digest TEXT,
                PRIMARY KEY(bot,persona,operation_id))""")
            store._db.execute(
                "INSERT INTO graph_post_c02_reply_dispatch_attempts_v2"
                "(bot,persona,operation_id,handler_invocation_id,request_digest,"
                "input_digest,attempt_id,handler_deadline_utc,frozen_deadline_utc,"
                "anchor_json,pre_graph_revision,pre_graph_epoch,state,bundle_digest) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'open',NULL)",
                namespace.as_tuple + (
                    operation_id, handler, digest, "a" * 64, attempt_id,
                    deadline, deadline - 1, canonical_json(asdict(anchor)),
                    metadata.graph_revision, epoch.revision),
            )
        permit = await asyncio.to_thread(
            port.begin_fence, namespace=namespace,
            authority_namespace=authority_namespace, holder="host:reply-close",
            generation=anchor.activation_generation, operation="write",
            operation_id=attempt_id, expected_anchor=anchor)

        def close():
            return graph.close_expired_post_c02_reply_dispatch_attempt_v2(
                authority, lease, progress, installed,
                handler_invocation_id=handler, handler_deadline_utc=deadline)

        with pytest.raises(UnavailableGuard, match="window remains active"):
            await asyncio.to_thread(close)
        assert store._db.execute(
            "SELECT state FROM graph_post_c02_reply_dispatch_attempts_v2 WHERE operation_id=?",
            (operation_id,)).fetchone() == ("open",)

        clock_offset[0] = 200.0
        store._db.execute(
            "INSERT INTO graph_bundle_operations(bot,persona,operation_id,digest,activity_id,"
            "effect_id,commit_seq,receipt_json) VALUES(?,?,?,?,?,?,?,?)",
            (*namespace.as_tuple, operation_id, "residue", "activity", None, 1, "{}"))
        with pytest.raises(UnavailableGuard, match="business side effect"):
            await asyncio.to_thread(close)
        assert store._db.execute(
            "SELECT state FROM graph_post_c02_reply_dispatch_attempts_v2 WHERE operation_id=?",
            (operation_id,)).fetchone() == ("open",)
        store._db.execute("DELETE FROM graph_bundle_operations WHERE operation_id=?", (operation_id,))
        store._db.execute(
            "INSERT INTO graph_events(bot,persona,session,event_id,digest,reads,"
            "epoch_reads,revisions,invalidated,epoch_revision) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (*namespace.as_tuple, "attempt-test", operation_id, "residue",
             "[]", "[]", "[]", "[]", epoch.revision))
        with pytest.raises(UnavailableGuard, match="graph event"):
            await asyncio.to_thread(close)
        store._db.execute("DELETE FROM graph_events WHERE event_id=?", (operation_id,))

        original_finish = port.finish_fence
        calls = []

        def lost_ack(scope, *, request_id, request_digest):
            calls.append((scope.permit.token, request_id, request_digest))
            original_finish(scope, request_id=request_id, request_digest=request_digest)
            raise RuntimeError("finish ACK lost after Authority committed")

        monkeypatch.setattr(port, "finish_fence", lost_ack)
        with pytest.raises(RuntimeError, match="ACK lost"):
            await asyncio.to_thread(close)
        row = store._db.execute(
            "SELECT state,permit_json,finish_request_id,finish_request_digest "
            "FROM graph_post_c02_reply_dispatch_attempts_v2 WHERE operation_id=?",
            (operation_id,)).fetchone()
        assert row[0] == "rejected_no_commit"
        assert row[2:] == calls[0][1:]
        replay_calls = []

        def record_replay(scope, *, request_id, request_digest):
            replay_calls.append((scope.permit.token, request_id, request_digest))
            return original_finish(scope, request_id=request_id,
                                   request_digest=request_digest)

        monkeypatch.setattr(port, "finish_fence", record_replay)
        assert await asyncio.to_thread(close) == "rejected_no_commit"
        assert len(calls) == 1
        assert replay_calls == calls
        observed, state = await asyncio.to_thread(
            port.get_fence_operation, namespace=namespace,
            authority_namespace=authority_namespace, operation_id=attempt_id)
        assert observed == permit and state == "finished"
        assert store._db.execute(
            "SELECT state,permit_json,finish_request_id,finish_request_digest "
            "FROM graph_post_c02_reply_dispatch_attempts_v2 WHERE operation_id=?",
            (operation_id,)).fetchone() == row
    finally:
        if port is not None:
            await asyncio.to_thread(port.close)
        if transport is not None:
            await transport.close()
        if listener is not None:
            listener.close()
            await listener.wait_closed()
        store.close()
        core.close()
