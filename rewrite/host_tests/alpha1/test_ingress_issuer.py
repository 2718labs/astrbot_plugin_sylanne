from __future__ import annotations

from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
import tempfile
import time
import unittest

from sylanne3.domain_registry import discover_domain_registry
from sylanne3.domains.d06 import D06DomainAdapter
from sylanne3.graph_coordinator import (
    AuthorityDenied, GraphCoordinator, IngressAuthorizationResult,
    IngressClockSample, IngressIssuancePolicy,
    IngressHostFacts, IngressIssuanceRequest, IngressLineage, UnavailableGuard,
    ingress_host_fingerprint,
)
from sylanne3.graph_store import GraphStore, ProductionGraphStore
from sylanne3.host.d06_ingress import (
    build_d06_ingress_handler, source_admission_from_host,
)
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.host.ingress_assembler import (
    IngressAssemblyRequest, IngressRuntimeAuthorization, LocalIngressAssembler,
    ingress_content_fingerprint,
)
from sylanne3.host.ingress_issuer import CoordinatorIngressIssuer, TrustedIngressIdentity
from sylanne3.runtime.budget import BudgetLease, create_budget_lease
from sylanne3.runtime.ingress_observation import GraphIngressObservationAuthority
from sylanne3.runtime.issuers import build_runtime_issuers
from sylanne3.runtime.jobs import PersistentJob
from sylanne3.runtime_contracts import (
    CommandEnvelope, NamespaceId, OperationIdentity, RUNTIME_SCHEMA,
    VersionGuard, canonical_digest,
)


def host_envelope(namespace: NamespaceId | None = None) -> HostIngressEnvelope:
    return HostIngressEnvelope(
        namespace or NamespaceId("bot-1", "persona-1"),
        "platform-1", "conversation-1", "sender-1", "message-1",
        "hello", 10.0, 11.0, "private",
        SourceLineage("a" * 64, "reported", "platform-1", "external_report", "reported_claim"),
    )


def request_for(host: HostIngressEnvelope) -> IngressAssemblyRequest:
    admission = source_admission_from_host(host)
    candidate = D06DomainAdapter(host.namespace).admit_source(admission)
    return IngressAssemblyRequest(
        host, admission, candidate, "ingress-1", "host-ingress-1",
        "encode-1", "job-ref", "outbox-1", "outbox-ref",
        host.lineage.source_ref, "host-ingress:key-1",
    )


def authorized_result(request, session, *, lease=None, authority=None):
    qualification = request.candidate.qualification
    command = CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity(
            request.activity_id, None, "first", "ingress", request.operation_id,
            canonical_digest({"input_refs": list(qualification.source_refs)}),
        ),
        authority or session.authority,
        VersionGuard((), (), 0, 0, "catalogue", "scheme", "operator", "policy", (), (), ()),
        qualification, qualification.source_refs, "budget-1", 4_000_000_000.0,
        4_000_000_000.0, "interval-1", (request.host.message_id,),
    )
    job = PersistentJob(
        request.job_id, request.operation_id, request.activity_id, None,
        *request.host.namespace.as_tuple, "snapshot-1", "queued",
        "d06.encode_source", {}, None, "2099-01-01T00:00:00Z",
        "budget-1", "resource-1", {}, None, None, 0, 0, {}, None,
    )
    return IngressAuthorizationResult(command, session.lease if lease is None else lease, job)


class _UnavailableExternalExecutionJournal:
    def verify_current_chain(self, *args, **kwargs):
        raise RuntimeError("external Authority is outside the controlled graph test")


class IngressIssuerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        catalogue = discover_domain_registry()
        self.store = GraphStore(
            Path(self.directory.name) / "graph.sqlite3", catalogue.type_registry
        )
        self.bootstrap = object()
        self.coordinator = GraphCoordinator(self.store, self.bootstrap)
        for name in ("d06", "d11"):
            registration = catalogue.registrations[name]
            self.coordinator.register_provider(
                self.bootstrap, name, registration.provider,
                registration.proposal_schema, registration.proposal_schema_hash,
            )
        self.coordinator.set_guard_version(
            self.bootstrap, NamespaceId("bot-1", "persona-1"),
            "activation", "current", 7,
        )
        self.issuer = CoordinatorIngressIssuer(
            TrustedIngressIdentity("host-actor", "provider-policy-1", 7)
        )

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    async def test_bootstrap_grant_binds_namespace_actor_and_conversation(self) -> None:
        host = host_envelope()
        session = await self.issuer.begin_authority(
            host, "host-ingress-1", self.coordinator, self.bootstrap
        )
        authority = session.authority
        self.assertEqual(authority.namespace, host.namespace)
        self.assertEqual(authority.actor, "host-actor")
        self.assertEqual(authority.issuer_domain, "d06")
        self.assertEqual(authority.owner_scope, ("event", "activity"))
        self.assertEqual(authority.purpose, "context")
        self.assertEqual(authority.audience, (host.conversation_ref,))
        self.assertEqual(authority.provider_policy_ref, "provider-policy-1")
        self.assertEqual(authority.activation_generation, 7)
        self.assertIsNone(
            self.coordinator.get_operation(authority, session.lease, "host-ingress-1")
        )

        other = replace(authority, namespace=NamespaceId("other", "persona-1"))
        with self.assertRaises(AuthorityDenied):
            self.coordinator.get_operation(other, session.lease, "host-ingress-1")

    async def test_wrong_bootstrap_cannot_obtain_ingress_lease(self) -> None:
        with self.assertRaises(AuthorityDenied):
            await self.issuer.begin_authority(
                host_envelope(), "host-ingress-1", self.coordinator, object()
            )

    async def test_missing_real_issuers_fail_before_quote_or_grant(self) -> None:
        host = host_envelope()
        session = await self.issuer.begin_authority(
            host, "host-ingress-1", self.coordinator, self.bootstrap
        )
        with self.assertRaisesRegex(UnavailableGuard, "real D02/D11 issuers"):
            await self.issuer.authorize(
                request_for(host), session, self.coordinator, self.bootstrap
            )
        with self.store._lock:
            issuer_tables = self.store._db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                "('runtime_resource_quotes','runtime_budget_grants')"
            ).fetchall()
            counts = tuple(self.store._db.execute(
                f"SELECT count(*) FROM {name}"
            ).fetchone()[0] for (name,) in issuer_tables)
        self.assertTrue(all(count == 0 for count in counts))

    async def test_session_cannot_be_reused_for_another_conversation(self) -> None:
        host = host_envelope()
        session = await self.issuer.begin_authority(
            host, "host-ingress-1", self.coordinator, self.bootstrap
        )
        changed = replace(host, conversation_ref="conversation-2")
        with self.assertRaisesRegex(ValueError, "trusted host scope"):
            await self.issuer.authorize(
                request_for(changed), session, self.coordinator, self.bootstrap
            )

    async def test_w01_must_return_typed_authorization(self) -> None:
        host = host_envelope()
        session = await self.issuer.begin_authority(
            host, "host-ingress-1", self.coordinator, self.bootstrap
        )
        self.coordinator.issue_ingress_authorization = lambda *args: object()
        with self.assertRaisesRegex(TypeError, "invalid ingress authorization"):
            await self.issuer.authorize(
                request_for(host), session, self.coordinator, self.bootstrap
            )

    async def test_w01_receives_pure_dto_with_exact_host_facts(self) -> None:
        host = host_envelope()
        session = await self.issuer.begin_authority(
            host, "host-ingress-1", self.coordinator, self.bootstrap
        )
        request = request_for(host)
        captured = []

        class ReachedW01(Exception):
            pass

        def capture(bootstrap, issued, issued_session):
            captured.append((bootstrap, issued, issued_session))
            raise ReachedW01

        self.coordinator.issue_ingress_authorization = capture
        with self.assertRaises(ReachedW01):
            await self.issuer.authorize(
                request, session, self.coordinator, self.bootstrap
            )
        supplied_bootstrap, issued, supplied_session = captured[0]
        self.assertIs(supplied_bootstrap, self.bootstrap)
        self.assertIs(supplied_session, session)
        self.assertIs(type(issued), IngressIssuanceRequest)
        self.assertIs(type(issued.host), IngressHostFacts)
        self.assertIs(type(issued.host.lineage), IngressLineage)
        self.assertEqual(issued.host.namespace, host.namespace)
        self.assertEqual(issued.host.conversation_ref, host.conversation_ref)
        self.assertEqual(issued.host.message_id, host.message_id)
        self.assertEqual(issued.host.text, host.text)
        self.assertEqual(issued.host.lineage.source_ref, host.lineage.source_ref)
        self.assertEqual(
            ingress_host_fingerprint(issued.host), ingress_content_fingerprint(host)
        )
        self.assertEqual(issued.admission, request.admission)
        self.assertEqual(issued.candidate, request.candidate)
        self.assertEqual(issued.operation_id, request.operation_id)
        self.assertEqual(issued.job_ref, request.job_ref)
        self.assertEqual(issued.outbox_ref, request.outbox_ref)

    async def test_typed_w01_result_is_wrapped_without_changing_authority(self) -> None:
        host = host_envelope()
        session = await self.issuer.begin_authority(
            host, "host-ingress-1", self.coordinator, self.bootstrap
        )
        request = request_for(host)
        result = authorized_result(request, session)
        self.coordinator.issue_ingress_authorization = lambda *args: result
        wrapped = await self.issuer.authorize(
            request, session, self.coordinator, self.bootstrap
        )
        self.assertIs(type(wrapped), IngressRuntimeAuthorization)
        self.assertIs(wrapped.envelope, result.envelope)
        self.assertIs(wrapped.lease, session.lease)
        self.assertIs(wrapped.job, result.job)

    async def test_w01_result_cannot_swap_lease_or_authority(self) -> None:
        host = host_envelope()
        session = await self.issuer.begin_authority(
            host, "host-ingress-1", self.coordinator, self.bootstrap
        )
        request = request_for(host)
        for result in (
            authorized_result(request, session, lease=object()),
            authorized_result(
                request, session,
                authority=replace(session.authority, audience=("conversation-2",)),
            ),
        ):
            self.coordinator.issue_ingress_authorization = lambda *args: result
            with self.assertRaisesRegex(ValueError, "changed the ingress authority or lease"):
                await self.issuer.authorize(
                    request, session, self.coordinator, self.bootstrap
                )


class ControlledGraphIngressIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Exercise the real graph/issuer path without claiming Authority service admission."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        catalogue = discover_domain_registry()
        self.store = ProductionGraphStore(
            Path(self.directory.name) / "graph.sqlite3", catalogue.type_registry
        )
        self.bootstrap = object()
        self.namespace = NamespaceId("bot-1", "persona-1")
        self.d02, self.d11 = build_runtime_issuers(b"controlled-signing-key-for-tests-32")
        now = time.time()
        self.policy = IngressIssuancePolicy(
            "parent-1", {"cpu_ms": 20}, {"cpu_ms": 40},
            now + 3600, now + 86400, time.monotonic() + 3600,
            "snapshot-1", "resource-1", "character-1",
        )
        self.coordinator = GraphCoordinator(
            self.store, self.bootstrap,
            deletion_journal=object(), migration_authority=object(),
            restore_authority=object(),
            execution_journal_port=_UnavailableExternalExecutionJournal(),
            snapshot_requirements=lambda namespace: None,
            holder="controlled-graph-test",
            content_fence=lambda *args: nullcontext(),
            d02_issuer=self.d02, d11_issuer=self.d11,
            ingress_policy=lambda namespace, ref: self.policy,
            ingress_clock=lambda: IngressClockSample(
                time.time(), time.monotonic(), "controlled-process", True),
        )
        # The external Authority deployment is outside this graph-layer test.
        # Its admission gate is bypassed explicitly; D02/D11 remain real.
        self.coordinator._admit_content = lambda *args: None
        for name in ("d06", "d11"):
            registration = catalogue.registrations[name]
            self.coordinator.register_provider(
                self.bootstrap, name, registration.provider,
                registration.proposal_schema, registration.proposal_schema_hash,
            )
        with self.store._lock:
            db = self.store._db
            db.execute("BEGIN IMMEDIATE")
            for kind, version in (
                ("scheme", "scheme-1"), ("operator", "operator-1"),
                ("policy", "policy-1"), ("activation", "7"),
            ):
                db.execute(
                    "INSERT INTO graph_guard_versions "
                    "(bot,persona,kind,ref,version) VALUES(?,?,?,?,?)",
                    self.namespace.as_tuple + (kind, "current", version),
                )
            create_budget_lease(
                db,
                BudgetLease(
                    "parent-1", None, *self.namespace.as_tuple, "USD",
                    {"cpu_ms": 100}, {}, {}, {}, 1, "active",
                ),
                "install-parent-1", "a" * 64,
            )
            db.execute("COMMIT")
        self.observations = GraphIngressObservationAuthority(
            self.coordinator, self.store, time.time
        )
        self.issuer = CoordinatorIngressIssuer(
            TrustedIngressIdentity("host-actor", "provider-policy-1", 7)
        )
        self.handler = build_d06_ingress_handler(
            LocalIngressAssembler(self.bootstrap, self.issuer, self.observations)
        )

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    async def test_real_issuers_commit_atomic_graph_and_deduplicate(self) -> None:
        host = host_envelope(self.namespace)
        issued = []
        actual_issue = self.coordinator.issue_ingress_authorization

        def capture_real_issuance(*args):
            result = actual_issue(*args)
            issued.append(result)
            return result

        self.coordinator.issue_ingress_authorization = capture_real_issuance
        accepted = await self.handler(host, self.coordinator)
        self.assertEqual(accepted.status, "accepted")
        self.assertEqual(len(issued), 1)
        with self.store._lock:
            db = self.store._db
            quote = self.d02.qualified_quote(issued[0].envelope, db)
            grant = self.d11.current_budget_grant(db, "parent-1")
            counts = tuple(db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                           for table in (
                               "runtime_resource_quotes", "runtime_budget_grants",
                               "runtime_jobs", "runtime_budget_reservations",
                           ))
            graph_types = tuple(row[0] for row in db.execute(
                "SELECT type_name FROM graph_atoms ORDER BY type_name"
            ))
        self.assertEqual(quote.work_kind, "d06.encode_source")
        self.assertEqual(grant.allowed_work_kinds, ("d06.encode_source",))
        self.assertEqual(issued[0].job.work_kind, quote.work_kind)
        self.assertEqual(counts, (1, 1, 1, 1))
        self.assertEqual(len(graph_types), 4)
        self.assertIn("runtime.job", graph_types)
        self.assertIn("runtime.outbox", graph_types)
        duplicate = await self.handler(
            replace(host, learned_at=host.learned_at + 1), self.coordinator
        )
        self.assertEqual(duplicate.status, "duplicate")
        self.assertEqual(duplicate.operation_id, accepted.operation_id)
        self.assertEqual(len(issued), 1)
        with self.store._lock:
            db = self.store._db
            after = tuple(db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                          for table in (
                              "runtime_resource_quotes", "runtime_budget_grants",
                              "runtime_jobs", "runtime_budget_reservations",
                          ))
            graph_count = db.execute("SELECT count(*) FROM graph_atoms").fetchone()[0]
            event_count = db.execute("SELECT count(*) FROM graph_events").fetchone()[0]
        self.assertEqual(after, counts)
        self.assertEqual(graph_count, 4)
        self.assertEqual(event_count, 1)


if __name__ == "__main__":
    unittest.main()
