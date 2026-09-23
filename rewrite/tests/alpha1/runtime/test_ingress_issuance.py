from dataclasses import replace
import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from sylanne3.contracts import Event, EventConflict, Scope, StaleRead
from sylanne3.domains.d06 import D06DomainAdapter, D06DomainProvider, SourceAdmission
from sylanne3.graph_coordinator import (
    GraphCoordinator, IngressClockSample, IngressHostFacts, IngressIssuancePolicy,
    IngressIssuanceRequest, IngressLineage, UnavailableGuard,
    ingress_host_fingerprint,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (
    AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry,
    TypeSpec,
)
from sylanne3.memory_types import source_key
from sylanne3.runtime.budget import BudgetLease, create_budget_lease, reserve_budget
from sylanne3.runtime.d11_types import (
    D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH, D11RuntimeProvider,
    RuntimeOutboxValue, graph_type_specs, job_graph_write, outbox_graph_write,
    runtime_job_key, runtime_outbox_key,
)
from sylanne3.runtime.issuers import build_runtime_issuers
from sylanne3.runtime_contracts import (
    AuthorityContext, DependencySet, DomainBundle, DomainProposal, NamespaceId,
)


class _TestClock:
    def __init__(self):
        self.wall_now_utc = time.time()
        self.monotonic_now = time.monotonic()
        self.clock_epoch = "process-a"
        self.clock_trusted = True

    def sample(self):
        return IngressClockSample(
            self.wall_now_utc, self.monotonic_now,
            self.clock_epoch, self.clock_trusted)


class IngressIssuanceTests(unittest.TestCase):
    def test_policy_deserialization_does_not_read_current_clocks(self):
        policy = IngressIssuancePolicy(
            "parent", {"cpu_ms": 1}, {"cpu_ms": 2},
            1.0, 2.0, -1000.0, "snapshot-1", "resource-1", "character-1",
        )
        self.assertEqual(policy.monotonic_deadline, -1000.0)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        registry = TypeRegistry()
        for spec in D06DomainProvider.type_specs() + graph_type_specs():
            registry.register(spec)
        registry.register(TypeSpec(
            "test.unrelated", ("activity",), "state", lambda value: None,
            writer_domain="d11", schema_hash="f" * 64,
        ))
        self.registry = registry
        self.path = Path(self.tmp.name) / "business.db"
        self.store = GraphStore(self.path, registry)
        self.bootstrap = object()
        self.namespace = NamespaceId("bot", "persona")
        self.d02, self.d11 = build_runtime_issuers(b"s" * 32)
        self.clock = _TestClock()
        self.policy = IngressIssuancePolicy(
            "parent", {"cpu_ms": 20}, {"cpu_ms": 40},
            self.clock.wall_now_utc + 3600,
            self.clock.wall_now_utc + 86400,
            self.clock.monotonic_now + 3600,
            "snapshot-1", "resource-1",
            "character-1",
        )
        self.request = self.make_request()
        self.coordinator = self.make_coordinator()
        self.register_providers(self.coordinator)
        self.lease, ref = self.coordinator.grant(
            self.bootstrap, actor="trusted-host", issuer_domain="d06",
            namespace=self.namespace, domains=("d06", "d11"),
            activation_generation=1, operation_id=self.request.operation_id,
        )
        self.authority = AuthorityContext(
            "trusted-host", "d06", ref, self.namespace, ("event", "activity"),
            "context", ("conversation",), "ingress-policy", 1,
        )
        self.session = SimpleNamespace(authority=self.authority, lease=self.lease)
        for kind, value in (("scheme", "scheme-1"), ("operator", "operator-1"),
                            ("policy", "policy-1"), ("activation", "1")):
            self.coordinator.set_guard_version(
                self.bootstrap, self.namespace, kind, "current", value,
            )
        with self.store._lock:
            db = self.store._db
            db.execute("BEGIN IMMEDIATE")
            create_budget_lease(db, BudgetLease(
                "parent", None, "bot", "persona", "USD", {"cpu_ms": 100},
                {}, {}, {}, 1, "active",
            ), "create-parent", "a" * 64)
            db.execute("""CREATE TABLE ingress_first_observations(
                bot TEXT, persona TEXT, operation_id TEXT,
                content_fingerprint TEXT, learned_at REAL, bundle_digest TEXT,
                PRIMARY KEY(bot,persona,operation_id))""")
            db.execute("COMMIT")
        self.observe(self.request)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def make_coordinator(self, *, policy=True, issuers=True, clock=True):
        return GraphCoordinator(
            self.store, self.bootstrap,
            d02_issuer=self.d02 if issuers else None,
            d11_issuer=self.d11 if issuers else None,
            ingress_policy=(lambda namespace, ref: self.policy) if policy else None,
            ingress_clock=self.clock.sample if clock else None,
        )

    def register_providers(self, coordinator):
        d06 = D06DomainProvider()
        coordinator.register_provider(
            self.bootstrap, "d06", d06, "d06.contract.v1",
            d06.descriptor.request_schema_hash,
        )
        coordinator.register_provider(
            self.bootstrap, "d11", D11RuntimeProvider(),
            D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH,
        )

    def make_request(self, text="hello", source_ref="b" * 64,
                     message_id="message"):
        host = IngressHostFacts(
            self.namespace, "platform", "conversation", "sender", message_id,
            text, 10.0, 11.0, "private",
            IngressLineage(source_ref, "reported", "platform",
                           "external_report", "reported_claim", "not_applicable"),
        )
        admission = SourceAdmission(
            source_ref, text, "sender", "reported", "reported",
            "reported_claim", "not_applicable", 10.0, 11.0,
            "platform", ("conversation",), ("context", "consolidation"),
        )
        candidate = D06DomainAdapter(self.namespace).admit_source(admission)
        digest = hashlib.sha256(
            ("sylanne3.host-ingress.v1:" + host.lineage.source_ref).encode("ascii")
        ).hexdigest()
        activity = "ingress-" + digest[:24]
        job_id = "encode-" + digest[:24]
        outbox_id = "encode-outbox-" + digest[:24]
        return IngressIssuanceRequest(
            host, admission, candidate, activity, "host-ingress-" + digest[:32],
            job_id, runtime_job_key("bot", "persona", activity, job_id).token,
            outbox_id, runtime_outbox_key("bot", "persona", activity, outbox_id).token,
            host.lineage.source_ref, "host-ingress:" + digest,
        )

    def observe(self, request):
        with self.store._lock:
            self.store._db.execute(
                "INSERT INTO ingress_first_observations VALUES(?,?,?,?,?,NULL)",
                self.namespace.as_tuple + (request.operation_id,
                    ingress_host_fingerprint(request.host), request.host.learned_at),
            )

    def session_for(self, coordinator, request):
        lease, ref = coordinator.grant(
            self.bootstrap, actor="trusted-host", issuer_domain="d06",
            namespace=self.namespace, domains=("d06", "d11"),
            activation_generation=1, operation_id=request.operation_id,
        )
        return SimpleNamespace(
            authority=replace(self.authority, capability_ref=ref), lease=lease)

    def commit_atom(self, key, value, event_id):
        candidate = GraphCandidate(
            Event(Scope("bot", "persona", "other-activity"), event_id,
                  12.0, "test", {"event_id": event_id}),
            (GraphVersion(key, 0),), (GraphWrite(key, value),),
        )
        return self.store.graph_commit(candidate)

    def bundle_for(self, authorization):
        command = authorization.envelope
        request = self.request
        job_key = AtomKey.from_token(request.job_ref)
        outbox = RuntimeOutboxValue(
            "bot", "persona", request.activity_id, request.operation_id,
            None, request.outbox_id, request.job_id, request.job_ref,
            request.payload_ref, request.idempotency_key, "pending", 1,
        )
        job_proof = next(read for read in command.version_guard.read_versions
                         if read.key == job_key)
        d11 = DomainProposal(
            "d11", D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH,
            command, (job_graph_write(authorization.job),
                      outbox_graph_write(outbox, job_key)),
            DependencySet(current_invalidation=(job_proof,)),
            ("source-encoding:" + request.operation_id,), (),
        )
        d06 = D06DomainAdapter(self.namespace).compile_source_ingress(
            command, request.admission)
        return DomainBundle(
            command, (d06, d11), (), (), (), (),
            (request.idempotency_key,), (request.job_ref,),
            (request.outbox_ref,),
        )

    def test_public_issuance_contract_exists(self):
        self.assertTrue(callable(getattr(GraphCoordinator, "issue_ingress_authorization", None)))

    def test_signed_issuance_reuses_exact_refs_and_job(self):
        first = self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        second = self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        self.assertEqual(first.envelope, second.envelope)
        self.assertEqual(first.job, second.job)
        self.assertIs(first.lease, self.lease)
        self.assertEqual(first.job.work_kind, "d06.encode_source")
        self.assertEqual(len(first.envelope.version_guard.read_versions), 4)
        self.assertTrue(all(item.revision == 0 for item in
                            first.envelope.version_guard.read_versions))
        self.assertEqual(self.d02.qualified_quote(first.envelope, self.store._db).ceiling,
                         {"cpu_ms": 20})
        self.assertEqual(self.d11.job_for(first.envelope, self.store._db), first.job)

    def test_replay_content_drift_is_rejected(self):
        self.coordinator.issue_ingress_authorization(self.bootstrap, self.request, self.session)
        drift = self.make_request("changed")
        with self.assertRaises(EventConflict):
            self.coordinator.issue_ingress_authorization(self.bootstrap, drift, self.session)

    def test_second_message_reuses_parent_grant_with_new_quote_deadline(self):
        first = self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        second_request = self.make_request(
            "second", "c" * 64, "message-2")
        self.observe(second_request)
        self.policy = replace(
            self.policy, deadline_utc=time.time() + 3700,
            monotonic_deadline=time.monotonic() + 3700,
        )
        second = self.coordinator.issue_ingress_authorization(
            self.bootstrap, second_request,
            self.session_for(self.coordinator, second_request))
        self.assertNotEqual(first.envelope.deadline_utc,
                            second.envelope.deadline_utc)
        self.assertNotEqual(first.envelope.version_guard.resource_lease_versions,
                            second.envelope.version_guard.resource_lease_versions)
        self.assertEqual(self.d11.current_budget_grant(
            self.store._db, "parent").max_ceiling, {"cpu_ms": 40})

    def test_uncommitted_retry_survives_rebuilt_coordinator_and_issuers(self):
        first = self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        quote_before = self.store._db.execute(
            "SELECT quote_json,signature FROM runtime_resource_quotes"
        ).fetchone()
        self.store.close()
        self.store = GraphStore(self.path, self.registry)
        self.d02, self.d11 = build_runtime_issuers(b"s" * 32)
        self.clock.clock_epoch = "process-b"
        # A new process may have a completely different monotonic origin.
        # The persisted envelope value must not become the new deadline.
        self.clock.monotonic_now = first.envelope.monotonic_deadline + 1000.0
        self.clock.wall_now_utc += 10.0
        rebuilt = self.make_coordinator()
        self.register_providers(rebuilt)
        replay = rebuilt.issue_ingress_authorization(
            self.bootstrap, self.request, self.session_for(rebuilt, self.request))
        self.assertEqual(replay.envelope, first.envelope)
        self.assertEqual(replay.job, first.job)
        self.assertEqual(self.store._db.execute(
            "SELECT quote_json,signature FROM runtime_resource_quotes"
        ).fetchone(), quote_before)

    def test_expired_trusted_utc_rejects_uncommitted_retry_without_changing_quote(self):
        self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        quote_before = self.store._db.execute(
            "SELECT quote_json,signature FROM runtime_resource_quotes"
        ).fetchone()
        self.clock.wall_now_utc = self.policy.deadline_utc + 1.0
        self.clock.monotonic_now += 1.0
        with self.assertRaisesRegex(UnavailableGuard, "UTC deadline"):
            self.coordinator.issue_ingress_authorization(
                self.bootstrap, self.request, self.session)
        self.assertEqual(self.store._db.execute(
            "SELECT quote_json,signature FROM runtime_resource_quotes"
        ).fetchone(), quote_before)

    def test_expired_trusted_utc_rejects_first_issuance(self):
        self.policy = replace(
            self.policy, deadline_utc=self.clock.wall_now_utc - 1.0)
        with self.assertRaisesRegex(UnavailableGuard, "UTC deadline"):
            self.coordinator.issue_ingress_authorization(
                self.bootstrap, self.request, self.session)
        self.assertIsNone(self.store._db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='runtime_resource_quotes'"
        ).fetchone())

    def test_untrusted_or_missing_clock_rejects_new_issuance(self):
        self.clock.clock_trusted = False
        with self.assertRaisesRegex(UnavailableGuard, "clock"):
            self.coordinator.issue_ingress_authorization(
                self.bootstrap, self.request, self.session)
        self.clock.clock_trusted = True
        self.coordinator._GraphCoordinator__ingress_clock = None
        with self.assertRaisesRegex(UnavailableGuard, "clock"):
            self.coordinator.issue_ingress_authorization(
                self.bootstrap, self.request, self.session)
        self.assertIsNone(self.store._db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='runtime_resource_quotes'"
        ).fetchone())

    def test_same_process_monotonic_regression_rejects_retry(self):
        self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        self.clock.monotonic_now -= 100.0
        self.clock.wall_now_utc += 1.0
        with self.assertRaisesRegex(UnavailableGuard, "binding changed"):
            self.coordinator.issue_ingress_authorization(
                self.bootstrap, self.request, self.session)

    def test_unrelated_commit_keeps_exact_ingress_absence_proofs(self):
        first = self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        unrelated = AtomKey(
            Owner("activity", "bot", "persona", "other-activity"),
            "test.unrelated", "record-b")
        self.commit_atom(unrelated, {"value": 1}, "unrelated-b")
        replay = self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        self.assertEqual(replay.envelope, first.envelope)
        self.assertEqual(replay.job, first.job)
        bundle = self.bundle_for(replay)
        self.store._db.execute(
            "UPDATE ingress_first_observations SET bundle_digest=? "
            "WHERE bot=? AND persona=? AND operation_id=?",
            (bundle.digest,) + self.namespace.as_tuple + (self.request.operation_id,),
        )
        receipt = self.coordinator.commit_domain_bundle(bundle, replay.lease)
        self.assertEqual(receipt.status, "committed")

    def test_unsealed_ingress_cannot_use_the_narrow_guard_exception(self):
        authorization = self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        bundle = self.bundle_for(authorization)
        with self.assertRaisesRegex(UnavailableGuard, "query epoch"):
            self.coordinator.commit_domain_bundle(bundle, authorization.lease)

    def test_sealed_ingress_cannot_commit_after_trusted_utc_deadline(self):
        authorization = self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        bundle = self.bundle_for(authorization)
        self.store._db.execute(
            "UPDATE ingress_first_observations SET bundle_digest=? "
            "WHERE bot=? AND persona=? AND operation_id=?",
            (bundle.digest,) + self.namespace.as_tuple + (self.request.operation_id,),
        )
        self.clock.wall_now_utc = self.policy.deadline_utc + 1.0
        self.clock.monotonic_now += 1.0
        with self.assertRaisesRegex(UnavailableGuard, "UTC deadline"):
            self.coordinator.commit_domain_bundle(bundle, authorization.lease)

    def test_sealed_ingress_cannot_commit_after_clock_loses_trust(self):
        authorization = self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        bundle = self.bundle_for(authorization)
        self.store._db.execute(
            "UPDATE ingress_first_observations SET bundle_digest=? "
            "WHERE bot=? AND persona=? AND operation_id=?",
            (bundle.digest,) + self.namespace.as_tuple + (self.request.operation_id,),
        )
        self.clock.clock_trusted = False
        with self.assertRaisesRegex(UnavailableGuard, "clock"):
            self.coordinator.commit_domain_bundle(bundle, authorization.lease)

    def test_deadline_expiring_during_commit_rolls_back_all_graph_writes(self):
        authorization = self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        bundle = self.bundle_for(authorization)
        self.store._db.execute(
            "UPDATE ingress_first_observations SET bundle_digest=? "
            "WHERE bot=? AND persona=? AND operation_id=?",
            (bundle.digest,) + self.namespace.as_tuple + (self.request.operation_id,),
        )
        registration = self.coordinator._GraphCoordinator__providers["d06"]

        def expire_after_validation(proposal, snapshot):
            result = registration[0].validate(proposal, snapshot)
            self.clock.wall_now_utc = self.policy.deadline_utc + 1.0
            self.clock.monotonic_now += 1.0
            return result

        self.coordinator._GraphCoordinator__providers["d06"] = (
            SimpleNamespace(validate=expire_after_validation),
            registration[1], registration[2],
        )
        with self.assertRaisesRegex(UnavailableGuard, "UTC deadline"):
            self.coordinator.commit_domain_bundle(bundle, authorization.lease)
        self.assertIsNone(self.store._db.execute(
            "SELECT 1 FROM graph_atoms WHERE token=?",
            (self.request.job_ref,),
        ).fetchone())

    def test_own_absent_key_changed_rejects_uncommitted_retry(self):
        self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        source = source_key("bot", "persona", self.request.admission.source_id)
        self.commit_atom(source, self.request.candidate.source.to_dict(),
                         "own-key-changed")
        with self.assertRaises(StaleRead):
            self.coordinator.issue_ingress_authorization(
                self.bootstrap, self.request, self.session)

    def test_prior_issuance_cannot_cross_activation_generation(self):
        self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        self.coordinator.set_guard_version(
            self.bootstrap, self.namespace, "activation", "current", "2")
        lease, ref = self.coordinator.grant(
            self.bootstrap, actor="trusted-host", issuer_domain="d06",
            namespace=self.namespace, domains=("d06", "d11"),
            activation_generation=2, operation_id=self.request.operation_id)
        newer = SimpleNamespace(
            authority=replace(self.authority, capability_ref=ref,
                              activation_generation=2), lease=lease)
        with self.assertRaisesRegex(StaleRead, "generation"):
            self.coordinator.issue_ingress_authorization(
                self.bootstrap, self.request, newer)

    def test_committed_ingress_resolves_on_new_activation_without_reissuance(self):
        authorization = self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        bundle = self.bundle_for(authorization)
        self.store._db.execute(
            "UPDATE ingress_first_observations SET bundle_digest=? "
            "WHERE bot=? AND persona=? AND operation_id=?",
            (bundle.digest,) + self.namespace.as_tuple + (self.request.operation_id,),
        )
        committed = self.coordinator.commit_domain_bundle(bundle, authorization.lease)
        self.coordinator.set_guard_version(
            self.bootstrap, self.namespace, "activation", "current", "2")
        lease, ref = self.coordinator.grant(
            self.bootstrap, actor="trusted-host", issuer_domain="d06",
            namespace=self.namespace, domains=("d06", "d11"),
            activation_generation=2, operation_id=self.request.operation_id,
        )
        newer = replace(
            self.authority, capability_ref=ref, activation_generation=2)
        replay = self.coordinator.get_operation(newer, lease, self.request.operation_id)
        self.assertEqual(replay.operation_digest, committed.operation_digest)
        self.assertEqual(replay.operation_id, committed.operation_id)

    def test_stale_generation_is_rejected(self):
        self.coordinator.set_guard_version(
            self.bootstrap, self.namespace, "activation", "current", "2")
        with self.assertRaises(StaleRead):
            self.coordinator.issue_ingress_authorization(
                self.bootstrap, self.request, self.session)

    def test_missing_canonical_observation_is_rejected(self):
        self.store._db.execute(
            "DELETE FROM ingress_first_observations WHERE bot=? AND persona=?",
            self.namespace.as_tuple,
        )
        with self.assertRaisesRegex(UnavailableGuard, "observation"):
            self.coordinator.issue_ingress_authorization(
                self.bootstrap, self.request, self.session)

    def test_access_epoch_change_rejects_uncommitted_retry(self):
        self.coordinator.issue_ingress_authorization(
            self.bootstrap, self.request, self.session)
        self.coordinator.advance_authority_epoch(
            self.bootstrap, self.namespace, "access")
        with self.assertRaises(StaleRead):
            self.coordinator.issue_ingress_authorization(
                self.bootstrap, self.request, self.session)

    def test_insufficient_existing_parent_budget_is_rejected(self):
        with self.store._lock:
            reserve_budget(self.store._db, "parent", "existing", "c" * 64,
                           {"cpu_ms": 90})
        with self.assertRaisesRegex(UnavailableGuard, "insufficient"):
            self.coordinator.issue_ingress_authorization(
                self.bootstrap, self.request, self.session)
        self.assertIsNone(self.store._db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='runtime_ingress_issuance'").fetchone())

    def test_missing_policy_and_fixture_issuers_fail_closed(self):
        self.coordinator._GraphCoordinator__ingress_policy = None
        with self.assertRaises(UnavailableGuard):
            self.coordinator.issue_ingress_authorization(
                self.bootstrap, self.request, self.session)
        self.coordinator._GraphCoordinator__ingress_policy = lambda *_: self.policy
        self.coordinator._GraphCoordinator__d11_issuer = object()
        with self.assertRaises(UnavailableGuard):
            self.coordinator.issue_ingress_authorization(
                self.bootstrap, self.request, self.session)


if __name__ == "__main__":
    unittest.main()
