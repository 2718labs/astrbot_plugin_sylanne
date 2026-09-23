from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace
import unittest

from sylanne3.contracts import EventConflict, StaleRead
from sylanne3.domain_registry import discover_domain_registry
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.runtime.ingress_contracts import (
    IngressAuthoritySession, IngressObservationContext,
)
from sylanne3.runtime.ingress_observation import GraphIngressObservationAuthority
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId


class ObservationStoreTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.path = Path(self.temp.name) / "business.sqlite3"
        self.namespace = NamespaceId("bot", "persona")
        self.gate_entries = []
        self.block_writes = False
        self.deny_writes = False
        self.deny_reads = False
        self.write_entered = Event()
        self.write_release = Event()
        self._open(7)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _open(self, generation: int) -> None:
        registry = discover_domain_registry()
        self.store = ProductionGraphStore(self.path, registry.type_registry)
        bootstrap = object()
        self.bootstrap = bootstrap

        @contextmanager
        def content_fence(namespace, holder, selected_generation, operation):
            self.gate_entries.append((selected_generation, operation))
            if operation == "read" and self.deny_reads:
                raise PermissionError("trusted content fence denied read")
            if operation == "write":
                if self.deny_writes:
                    raise PermissionError("trusted content fence denied write")
                self.write_entered.set()
                if self.block_writes and not self.write_release.wait(timeout=5):
                    raise TimeoutError("test content fence was not released")
            yield

        self.coordinator = GraphCoordinator(
            self.store, bootstrap, deletion_journal=object(),
            migration_authority=SimpleNamespace(),
            restore_authority=object(),
            execution_journal_port=SimpleNamespace(
                verify_current_chain=lambda *args: True),
            snapshot_requirements=lambda namespace: None,
            holder="holder", content_fence=content_fence,
            closure_verifier=lambda *args: None,
            d02_issuer=SimpleNamespace(authorize_resources=lambda *args: None),
            d11_issuer=SimpleNamespace(admit_runtime=lambda *args: None),
        )
        # These tests isolate observation persistence and call order. Full
        # migration, deletion, and restore admission belongs to coordinator tests.
        self.coordinator._admit_content = lambda *args: None
        for domain in ("d06", "d11"):
            registration = registry.registrations[domain]
            self.coordinator.register_provider(
                bootstrap, domain, registration.provider,
                registration.proposal_schema, registration.proposal_schema_hash,
            )
        lease, ref = self.coordinator.grant(
            bootstrap, actor="host", issuer_domain="d06",
            namespace=self.namespace, domains=("d06", "d11"),
            activation_generation=generation,
            operation_id="operation-1",
        )
        authority = AuthorityContext(
            "host", "d06", ref, self.namespace, (), "context", ("conversation",),
            "policy", generation,
        )
        self.session = IngressAuthoritySession(authority, lease)
        self.context = IngressObservationContext(
            self.namespace, generation, "host", ref, "operation-1")
        with self.store._lock:
            self.store._db.execute(
                "INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) "
                "VALUES(?,?,?,?,?) ON CONFLICT(bot,persona,kind,ref) "
                "DO UPDATE SET version=excluded.version",
                self.namespace.as_tuple + ("activation", "current", str(generation)),
            )

    def _observation_table_exists(self) -> bool:
        with self.store._lock:
            return self.store._db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='ingress_first_observations'"
            ).fetchone() is not None

    def _record_commit(self, digest: str) -> None:
        with self.store._lock:
            self.store._db.execute(
                "INSERT INTO graph_bundle_operations "
                "(bot,persona,operation_id,digest,activity_id,effect_id,commit_seq,receipt_json) "
                "VALUES(?,?,?,?,?,?,?,?)",
                self.namespace.as_tuple + (
                    "operation-1", digest, "activity", None, 1,
                    '{"commit_seq":1,"ledger_refs":[],"outbox_refs":[]}',
                ),
            )
            self.store._db.execute(
                "INSERT INTO graph_events "
                "(bot,persona,session,event_id,digest,reads,epoch_reads,revisions,"
                "invalidated,epoch_revision) VALUES(?,?,?,?,?,?,?,?,?,?)",
                self.namespace.as_tuple + (
                    "activity", "operation-1", "e" * 64, "[]", "[]", "[]", "[]", 0,
                ),
            )

    async def test_first_clock_fingerprint_and_bundle_survive_new_generation(self) -> None:
        clock_calls = []

        def clock():
            clock_calls.append(42.5)
            return 42.5

        ledger = GraphIngressObservationAuthority(self.coordinator, self.store, clock)
        fingerprint = "a" * 64
        digest = "b" * 64
        first = await ledger.observe_first(
            self.context, self.session, fingerprint, 99999.0)
        self.assertEqual(first.learned_at, 42.5)
        self.assertEqual(clock_calls, [42.5])
        self.assertEqual(await ledger.seal_bundle(
            self.context, self.session, first, digest), digest)
        self.store.close()

        self._open(8)
        ledger = GraphIngressObservationAuthority(
            self.coordinator, self.store, lambda: 500.0)
        replay = await ledger.observe_first(
            self.context, self.session, fingerprint, 1.0)
        self.assertEqual(replay, first)
        self.assertEqual(await ledger.seal_bundle(
            self.context, self.session, replay, "c" * 64), digest)
        self.assertTrue(any(operation == "write" for _, operation in self.gate_entries))
        with self.assertRaisesRegex(EventConflict, "fingerprint changed"):
            await ledger.observe_first(
                self.context, self.session, "d" * 64, 1.0)

    async def test_old_generation_and_foreign_lease_fail_closed(self) -> None:
        ledger = GraphIngressObservationAuthority(
            self.coordinator, self.store, lambda: 42.5)
        first = await ledger.observe_first(
            self.context, self.session, "a" * 64, 1.0)
        foreign = IngressAuthoritySession(self.session.authority, object())
        with self.assertRaises(PermissionError):
            await ledger.seal_bundle(
                self.context, foreign, first, "b" * 64)
        with self.store._lock:
            self.store._db.execute(
                "UPDATE graph_guard_versions SET version=? WHERE bot=? AND persona=? "
                "AND kind='activation' AND ref='current'",
                ("8",) + self.namespace.as_tuple,
            )
        with self.assertRaises(StaleRead):
            await ledger.observe_first(
                self.context, self.session, "a" * 64, 1.0)

    async def test_committed_ledger_without_first_record_is_rejected(self) -> None:
        ledger = GraphIngressObservationAuthority(
            self.coordinator, self.store, lambda: 42.5)
        self._record_commit("b" * 64)
        with self.assertRaisesRegex(EventConflict, "lacks first observation"):
            await ledger.observe_first(
                self.context, self.session, "a" * 64, 1.0)

    async def test_committed_lookup_survives_restart_and_activation_change(self) -> None:
        ledger = GraphIngressObservationAuthority(
            self.coordinator, self.store, lambda: 42.5)
        fingerprint = "a" * 64
        digest = "b" * 64
        self.assertIsNone(await ledger.lookup_committed(
            self.context, self.session, fingerprint))
        first = await ledger.observe_first(
            self.context, self.session, fingerprint, 1.0)
        await ledger.seal_bundle(self.context, self.session, first, digest)
        self._record_commit(digest)
        self.store.close()

        self._open(8)
        ledger = GraphIngressObservationAuthority(
            self.coordinator, self.store, lambda: 999.0)
        replay = await ledger.lookup_committed(
            self.context, self.session, fingerprint)
        self.assertIsNotNone(replay)
        self.assertEqual(replay.observation, first)
        self.assertEqual(replay.receipt.operation_digest, digest)
        self.assertIs(replay.session, self.session)
        with self.assertRaisesRegex(EventConflict, "fingerprint changed"):
            await ledger.lookup_committed(
                self.context, self.session, "c" * 64)
        with self.assertRaises(PermissionError):
            await ledger.lookup_committed(
                self.context,
                IngressAuthoritySession(self.session.authority, object()),
                fingerprint,
            )
        broad_lease, broad_ref = self.coordinator.grant(
            self.bootstrap, actor="host", issuer_domain="d06",
            namespace=self.namespace, domains=("d06", "d11"),
            activation_generation=8,
        )
        broad_authority = replace(
            self.session.authority, capability_ref=broad_ref)
        broad_context = replace(self.context, capability_ref=broad_ref)
        with self.assertRaisesRegex(PermissionError, "not scoped"):
            await ledger.lookup_committed(
                broad_context,
                IngressAuthoritySession(broad_authority, broad_lease),
                fingerprint,
            )
        self.deny_reads = True
        with self.assertRaisesRegex(PermissionError, "fence denied read"):
            await ledger.lookup_committed(
                self.context, self.session, fingerprint)

    async def test_committed_lookup_rejects_unsealed_digest(self) -> None:
        ledger = GraphIngressObservationAuthority(
            self.coordinator, self.store, lambda: 42.5)
        first = await ledger.observe_first(
            self.context, self.session, "a" * 64, 1.0)
        await ledger.seal_bundle(
            self.context, self.session, first, "b" * 64)
        self._record_commit("c" * 64)
        with self.assertRaisesRegex(EventConflict, "sealed bundle"):
            await ledger.lookup_committed(
                self.context, self.session, "a" * 64)

    async def test_cancelled_observation_drains_worker_and_returns_durable_result(self) -> None:
        ledger = GraphIngressObservationAuthority(
            self.coordinator, self.store, lambda: 42.5)
        self.block_writes = True
        task = asyncio.create_task(ledger.observe_first(
            self.context, self.session, "a" * 64, 999.0))
        try:
            self.assertTrue(await asyncio.wait_for(
                asyncio.to_thread(self.write_entered.wait, 2), 2.5))
            # The worker is held inside the trusted fence; the event loop must
            # still schedule other coroutines while it waits.
            await asyncio.wait_for(asyncio.sleep(0.01), 0.2)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
        finally:
            self.write_release.set()
        observation = await asyncio.wait_for(task, 2)
        self.assertEqual(observation.learned_at, 42.5)
        self.assertEqual((await ledger.observe_first(
            self.context, self.session, "a" * 64, 1.0)), observation)

    async def test_cancelled_seal_drains_worker_and_returns_sealed_digest(self) -> None:
        ledger = GraphIngressObservationAuthority(
            self.coordinator, self.store, lambda: 42.5)
        observation = await ledger.observe_first(
            self.context, self.session, "a" * 64, 1.0)
        self.block_writes = True
        self.write_entered.clear()
        task = asyncio.create_task(ledger.seal_bundle(
            self.context, self.session, observation, "b" * 64))
        try:
            self.assertTrue(await asyncio.wait_for(
                asyncio.to_thread(self.write_entered.wait, 2), 2.5))
            await asyncio.wait_for(asyncio.sleep(0.01), 0.2)
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
        finally:
            self.write_release.set()
        self.assertEqual(await asyncio.wait_for(task, 2), "b" * 64)
        self.assertEqual(await ledger.seal_bundle(
            self.context, self.session, observation, "c" * 64), "b" * 64)

    async def test_cancelled_worker_failure_reports_failure_after_rollback(self) -> None:
        ledger = GraphIngressObservationAuthority(
            self.coordinator, self.store, lambda: float("nan"))
        self.block_writes = True
        task = asyncio.create_task(ledger.observe_first(
            self.context, self.session, "a" * 64, 1.0))
        try:
            self.assertTrue(await asyncio.wait_for(
                asyncio.to_thread(self.write_entered.wait, 2), 2.5))
            task.cancel()
            await asyncio.sleep(0)
            self.assertFalse(task.done())
        finally:
            self.write_release.set()
        with self.assertRaisesRegex(ValueError, "trusted host clock"):
            await asyncio.wait_for(task, 2)
        self.assertFalse(self._observation_table_exists())

    async def test_denied_content_fence_cannot_create_observation_table(self) -> None:
        ledger = GraphIngressObservationAuthority(
            self.coordinator, self.store, lambda: 42.5)
        self.assertFalse(self._observation_table_exists())
        self.deny_writes = True
        with self.assertRaisesRegex(PermissionError, "fence denied"):
            await ledger.observe_first(
                self.context, self.session, "a" * 64, 1.0)
        self.assertFalse(self._observation_table_exists())


if __name__ == "__main__":
    unittest.main()
