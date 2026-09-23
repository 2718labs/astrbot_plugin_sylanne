import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path

from sylanne3.contracts import EventConflict, StaleRead
from sylanne3.domains.d03.context import ContextProvider, EntityAnchor
from sylanne3.graph_coordinator import (
    AuthorityDenied, BudgetAdmission, GraphCoordinator, JobBinding,
    RuntimeAdmission, ScheduleAdmission,
)
from sylanne3.graph_coordinator import UnavailableGuard, namespace_ref
from sylanne3.graph_coordinator import budget_operation_digest
from sylanne3.graph_store import GraphStore, ProductionGraphStore
from sylanne3.graph_runtime import GraphRuntime
from sylanne3.graph_types import AtomKey, GraphWrite, Owner, TypeRegistry, TypeSpec
from sylanne3.memory_types import SourceRecord, access_key, source_key, validate_access
from sylanne3.runtime_contracts import (
    RUNTIME_SCHEMA, AuthorityContext, CommandEnvelope, DependencySet,
    DomainBundle, DomainProposal, NamespaceId, OperationIdentity, QueryEpoch,
    SourceQualification, VersionGuard, canonical_digest,
)
from sylanne3.runtime.activation import SqliteMigrationAuthority, TransferPlan
from sylanne3.runtime.deletion import DeletionBlocked, DeletionJournal
from sylanne3.runtime.restore_anchor import (
    RestoreAnchor, SnapshotRequirements, _execution_head_and_continuity,
)
from sylanne3.runtime_journal import ExecutionJournal
from sylanne3.runtime.budget import (
    BudgetLease, BudgetReceipt, BudgetUnavailable, create_budget_lease, get_budget_lease,
)
from sylanne3.runtime.jobs import PersistentJob
from sylanne3.runtime.d11_types import (
    D11RuntimeProvider, D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH,
    RuntimeCostSettlement, RuntimeOutboxValue, cost_settlement_graph_write,
    graph_type_specs, job_graph_write, outbox_graph_write,
    runtime_cost_settlement_key, runtime_job_key, runtime_outbox_key,
)


class StubRestoreAuthority:
    def __init__(self, anchor):
        self.anchor = anchor
        self.trusted = True

    def current_anchor(self, namespace):
        return self.anchor

    def verify_current(self, anchor):
        return self.trusted and anchor is self.anchor


class FixtureExecutionJournalPort:
    """Test-only stand-in for the service-owned execution journal."""

    def __init__(self, path, namespace):
        self.path = path
        self.namespace = namespace

    def verify_current_chain(self, namespace, expected_head):
        return (namespace == self.namespace
                and _execution_head_and_continuity(self.path) == expected_head)


class FixtureD02Issuer:
    """Local test double, not a product D02 receipt issuer."""

    def authorize_resources(self, bundle, db):
        return True

    def authorize_schedule(self, envelope, db):
        return True


class FixtureD11Issuer:
    """Local test double, not a product D11 budget/job issuer."""

    def __init__(self):
        self.ceiling = {"cpu_ms": 1}
        self.settle_now = False
        self.actual = None
        self.pre_reserved = False
        self.schedule_graph_job_ref = None

    @staticmethod
    def _job(envelope, lease_id, ref):
        job_id = AtomKey.from_token(ref).name
        return PersistentJob(
            job_id, envelope.identity.operation_id, envelope.identity.activity_id,
            envelope.identity.effect_id, envelope.authority.namespace.bot_id,
            envelope.authority.namespace.persona_id, "snapshot-1", "queued", "encode",
            {}, None, "2030-01-01T00:00:00Z", lease_id, "resource-1",
            {}, None, None, 0, 0, {}, None,
        )

    def admit_schedule(self, envelope, db):
        if self.schedule_graph_job_ref is None:
            raise UnavailableGuard("test schedule graph job ref missing")
        lease = get_budget_lease(db, envelope.parent_budget_lease_ref)
        return ScheduleAdmission(
            BudgetAdmission(lease.lease_id, lease.version, dict(self.ceiling)),
            self._job(envelope, lease.lease_id, self.schedule_graph_job_ref),
        )

    def admit_runtime(self, bundle, db):
        envelope = bundle.envelope
        lease = get_budget_lease(db, envelope.parent_budget_lease_ref)
        bindings = []
        for index, ref in enumerate(bundle.persistent_job_refs):
            bindings.append(JobBinding(
                ref, self._job(envelope, lease.lease_id, ref),
                bundle.outbox_refs if index == 0 else ()))
        return RuntimeAdmission(
            BudgetAdmission(lease.lease_id, lease.version, dict(self.ceiling),
                            pre_reserved=self.pre_reserved,
                            settle_now=self.settle_now, actual=self.actual),
            tuple(bindings),
        )


class Provider:
    def __init__(self):
        self.approve = True

    def validate(self, proposal, snapshot):
        return self.approve


def validate_entity_anchor(value):
    decoded = dict(value)
    decoded["creation_evidence_refs"] = tuple(decoded["creation_evidence_refs"])
    EntityAnchor(**decoded)


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "business.db"
        self.registry = TypeRegistry()
        self.registry.register(TypeSpec(
            "state", ("persona",), "state", lambda value: None,
            writer_domain="d06", schema_hash="a" * 64,
        ))
        self.registry.register(TypeSpec(
            "d03.entity_anchor", ("persona",), "state", validate_entity_anchor,
            writer_domain="d03", schema_hash="c" * 64,
        ))
        self.registry.register(TypeSpec(
            "memory.source", ("event",), "source", SourceRecord.from_dict,
            immutable=True, writer_domain="d06", schema_hash="e" * 64,
        ))
        self.registry.register(TypeSpec(
            "memory.access", ("event",), "state", validate_access,
            writer_domain="d06", schema_hash="f" * 64,
        ))
        for spec in graph_type_specs():
            self.registry.register(spec)
        self.store = ProductionGraphStore(self.path, self.registry)
        with self.store._lock:
            self.store._db.execute("BEGIN IMMEDIATE")
            create_budget_lease(self.store._db, BudgetLease(
                "parent", None, "bot", "persona", "USD",
                {"cpu_ms": 1000}, {}, {}, {}, 1, "active",
            ), "install-parent", "0" * 64)
            self.store._db.execute("COMMIT")
        self.bootstrap = object()
        self.namespace = NamespaceId("bot", "persona")
        self.namespace_key = namespace_ref(self.namespace)
        self.deletion = DeletionJournal(Path(self.temp.name) / "deletion.db", create=True)
        self.execution = ExecutionJournal(Path(self.temp.name) / "execution.db")
        with closing(sqlite3.connect(self.execution.path)) as db:
            execution_id = db.execute(
                "SELECT value FROM execution_metadata WHERE name='journal_id'").fetchone()[0]
        head = self.deletion.latest_head()
        self.restore = StubRestoreAuthority(RestoreAnchor(
            "installer", self.namespace_key, 1, head.journal_id, 0, head.chain_digest,
            execution_id, 0, "genesis", 0, "test-external-proof"))
        self.requirements = SnapshotRequirements(self.namespace_key, 1, 0, 0, 0)
        self.secret = object()
        self.migration = SqliteMigrationAuthority(
            Path(self.temp.name) / "migration.db", create=True,
            installer_verifier=lambda credential, *_: credential is self.secret,
            transfer_verifier=lambda credential, _: credential is self.secret,
            anchor_verifier=lambda anchor: anchor is self.restore.anchor)
        self.migration.bootstrap(self.namespace_key, "test-host",
                                 installer_credential=self.secret)
        self.d11_issuer = FixtureD11Issuer()
        self.coordinator = GraphCoordinator(
            self.store, self.bootstrap, deletion_journal=self.deletion,
            migration_authority=self.migration, restore_authority=self.restore,
            execution_journal_port=FixtureExecutionJournalPort(
                self.execution.path, self.namespace_key),
            snapshot_requirements=lambda _: self.requirements,
            holder="test-host", content_fence=lambda *_: self.migration._lock,
            d02_issuer=FixtureD02Issuer(), d11_issuer=self.d11_issuer)
        self.provider = Provider()
        self.coordinator.register_provider(self.bootstrap, "d06", self.provider,
                                           "d06.contract.v1", "b" * 64)
        self.coordinator.register_provider(self.bootstrap, "d03", ContextProvider(),
                                           "d03.proposal.v1", "d" * 64)
        self.coordinator.register_provider(self.bootstrap, "d11", D11RuntimeProvider(),
                                           D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH)
        self.lease, self.ref = self.coordinator.grant(
            self.bootstrap, actor="host", issuer_domain="d11",
            namespace=self.namespace, domains=("d06", "d11"), activation_generation=1,
        )
        for kind, ref, version in (
            ("scheme", "current", "scheme-v1"),
            ("operator", "current", "operator-v1"),
            ("policy", "current", "policy-v1"),
            ("activation", "current", 1),
        ):
            self.coordinator.set_guard_version(self.bootstrap, self.namespace,
                                               kind, ref, version)
        self.key = AtomKey(Owner("persona", "bot", "persona"), "state", "mood")
        self.entity = AtomKey(Owner("persona", "bot", "persona"),
                              "d03.entity_anchor", "person")
        self.read_authority = AuthorityContext("host", "d11", self.ref, self.namespace,
                                               ("persona",), "remember", ("internal",),
                                               "policy", 1)

    def tearDown(self):
        self.store.close()
        self.deletion.close()
        self.execution.close()
        self.migration.close()
        self.temp.cleanup()

    def read(self, keys, *, authority=None, lease=None):
        return self.coordinator.read_snapshot(
            authority or self.read_authority, lease or self.lease, keys)

    def refresh_deletion_anchor(self):
        head = self.deletion.latest_head()
        self.restore.anchor = replace(self.restore.anchor, deletion_seq=head.seq,
                                      deletion_digest=head.chain_digest)
        self.requirements = replace(self.requirements, deletion_seq=head.seq)

    def bundle(self, operation="op1", value=1, *, epoch=None, owner_scope=("persona",),
               read_revision=None, outbox=False):
        suffix = hashlib.sha256(operation.encode()).hexdigest()[:20]
        job_key = runtime_job_key("bot", "persona", "activity", "job-" + suffix)
        outbox_key = runtime_outbox_key("bot", "persona", "activity", "outbox-" + suffix)
        authority_scope = ("persona", "activity") if outbox else owner_scope
        read_authority = replace(self.read_authority, owner_scope=authority_scope)
        snapshot = self.read((self.key, job_key, outbox_key) if outbox else (self.key,),
                             authority=read_authority)
        read = snapshot.versions[0]
        if read_revision is not None:
            read = type(read)(self.key, read_revision)
        current_epoch = snapshot.epochs[0].revision if epoch is None else epoch
        identity = OperationIdentity(
            "activity", None, "attempt", "commit", operation,
            canonical_digest({"input_refs": []}),
        )
        authority = AuthorityContext("host", "d11", self.ref, self.namespace,
                                     authority_scope, "remember", ("internal",),
                                     "policy", 1)
        guard = VersionGuard(
            (read,) + snapshot.versions[1:],
            (QueryEpoch(self.namespace, "all", current_epoch),), 0, 0,
            self.registry.catalogue_hash, "scheme-v1", "operator-v1", "policy-v1",
            (), (), (),
        )
        qualification = SourceQualification(
            (), "reported", 1.0, 1.0, "external_report", "qualified", 0.5,
            "not_applicable",
        )
        envelope = CommandEnvelope(
            RUNTIME_SCHEMA, identity, authority, guard, qualification, (),
            "parent", 100.0, 100.0, "character-v1", (),
        )
        proposal = DomainProposal(
            "d06", "d06.contract.v1", "b" * 64, envelope,
            (GraphWrite(self.key, {"n": value}),), DependencySet(), (),
            ("outbox",) if outbox else (),
        )
        proposals = (proposal,)
        if outbox:
            job = self.d11_issuer._job(envelope, "parent", job_key.token)
            outbox_value = RuntimeOutboxValue(
                "bot", "persona", "activity", operation, None,
                outbox_key.name, job.job_id, job_key.token, "payload-1",
                "idem-" + suffix, "pending", 1)
            proposals += (DomainProposal(
                "d11", D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH, envelope,
                (job_graph_write(job), outbox_graph_write(outbox_value, job_key)),
                DependencySet(current_invalidation=(snapshot.versions[1],)), (), (),
            ),)
        return DomainBundle(envelope, proposals, (), (), (), (),
                            ("idem-" + suffix,) if outbox else (),
                            (job_key.token,) if outbox else (),
                            (outbox_key.token,) if outbox else ())

    def test_atomic_bundle_and_duplicate_after_newer_state(self):
        candidate = self.bundle(outbox=True)
        first = self.coordinator.commit_domain_bundle(candidate, self.lease)
        self.assertEqual(first.status, "committed")
        self.assertEqual(first.commit_seq, 1)
        self.assertEqual(first.outbox_refs, candidate.outbox_refs)
        self.assertEqual(self.coordinator.get_operation(
            candidate.envelope.authority, self.lease, "op1"), first)
        self.assertEqual(self.read((self.key,)).get(self.key).value, {"n": 1})
        self.coordinator.commit_domain_bundle(self.bundle(operation="op2", value=2), self.lease)
        duplicate = self.coordinator.commit_domain_bundle(candidate, self.lease)
        self.assertEqual(duplicate.status, "duplicate")
        self.assertEqual(duplicate.commit_seq, 1)
        with self.store._lock:
            self.assertEqual(get_budget_lease(self.store._db, "parent").reserved,
                             {"cpu_ms": 2})
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM graph_bundle_operations").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT count(*) FROM graph_bundle_refs").fetchone()[0], 3)
            self.assertEqual(db.execute("SELECT phase FROM graph_bundle_outbox").fetchone()[0], "pending")
            self.assertEqual(db.execute("SELECT count(*) FROM graph_outbox_jobs").fetchone()[0], 1)

    def test_legacy_writes_and_direct_graph_access_are_closed(self):
        for call in (lambda: self.store.snapshot(None),
                     lambda: self.store.commit(None),
                     lambda: self.store.graph_snapshot((self.key,)),
                     lambda: self.store.graph_commit(None),
                     lambda: GraphStore.graph_snapshot(self.store, (self.key,)),
                     lambda: GraphStore.graph_epoch(self.store, "bot", "persona")):
            with self.assertRaises(PermissionError):
                call()
        with self.assertRaises(PermissionError):
            GraphRuntime(self.store, object())

    def test_production_constructor_requires_independent_authorities(self):
        separate = ProductionGraphStore(Path(self.temp.name) / "other.db", self.registry)
        try:
            with self.assertRaises(UnavailableGuard):
                GraphCoordinator(separate, object())
        finally:
            separate.close()

    def test_production_constructor_rejects_missing_execution_port(self):
        separate = ProductionGraphStore(Path(self.temp.name) / "no-port.db", self.registry)
        try:
            with self.assertRaises(UnavailableGuard):
                GraphCoordinator(
                    separate, object(), deletion_journal=self.deletion,
                    migration_authority=self.migration,
                    restore_authority=self.restore,
                    snapshot_requirements=lambda _: self.requirements,
                    holder="test-host", content_fence=lambda *_: self.migration._lock,
                    d02_issuer=FixtureD02Issuer(), d11_issuer=self.d11_issuer,
                )
        finally:
            separate.close()

    def test_pending_and_accepted_deletion_block_reads_and_commits(self):
        candidate = self.bundle(operation="before-erasure")
        self.deletion.append_intent(
            namespace=self.namespace_key, operation_id="delete-1",
            closure_roots=("root-1",), epoch=1, policy_ref="policy-1")
        self.refresh_deletion_anchor()
        for attempt in (lambda: self.read((self.key,)),
                        lambda: self.coordinator.get_operation(
                            self.read_authority, self.lease, "before-erasure"),
                        lambda: self.coordinator.commit_domain_bundle(candidate, self.lease)):
            with self.assertRaises(UnavailableGuard) as caught:
                attempt()
            self.assertIsInstance(caught.exception.__cause__, DeletionBlocked)
        self.deletion.advance("delete-1", "accepted", business_barrier=lambda _: True)
        self.refresh_deletion_anchor()
        with self.assertRaises(UnavailableGuard):
            self.read((self.key,))
        with self.assertRaises(UnavailableGuard):
            self.coordinator.commit_domain_bundle(candidate, self.lease)

    def test_revoked_generation_blocks_read_query_and_commit(self):
        candidate = self.bundle(operation="before-move")
        plan = TransferPlan(self.namespace_key, "test-host", "new-host", "move-1")
        planned = self.migration.begin_transfer(plan, credential=self.secret)
        self.migration.revoke_source(planned, credential=self.secret)
        for attempt in (lambda: self.read((self.key,)),
                        lambda: self.coordinator.query(
                            self.read_authority, self.lease,
                            type_names=("state",), owner_kind="persona"),
                        lambda: self.coordinator.commit_domain_bundle(candidate, self.lease)):
            with self.assertRaises(UnavailableGuard):
                attempt()
        with self.assertRaises(UnavailableGuard):
            self.coordinator.set_guard_version(
                self.bootstrap, self.namespace, "policy", "current", "forged")
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute(
                "SELECT version FROM graph_guard_versions WHERE bot='bot' "
                "AND persona='persona' AND kind='policy' AND ref='current'"
            ).fetchone()[0], "policy-v1")

    def test_untrusted_current_restore_anchor_blocks_all_content(self):
        candidate = self.bundle(operation="before-anchor-loss")
        self.restore.trusted = False
        for attempt in (lambda: self.read((self.key,)),
                        lambda: self.coordinator.get_operation(
                            self.read_authority, self.lease, "before-anchor-loss"),
                        lambda: self.coordinator.commit_domain_bundle(candidate, self.lease)):
            with self.assertRaises(UnavailableGuard):
                attempt()

    def test_real_d03_provider_and_d06_commit_nonempty_two_domain_bundle(self):
        joint_lease, joint_ref = self.coordinator.grant(
            self.bootstrap, actor="host", issuer_domain="d11",
            namespace=self.namespace, domains=("d06", "d03"),
            activation_generation=1,
        )
        base = self.bundle(operation="joint")
        authority = replace(base.envelope.authority, capability_ref=joint_ref)
        reads = self.read((self.key, self.entity), authority=authority,
                          lease=joint_lease).versions
        guard = replace(base.envelope.version_guard, read_versions=reads)
        envelope = replace(base.envelope, authority=authority, version_guard=guard)
        d06 = replace(base.proposals[0], envelope=envelope,
                      required_bundle_parts=("experience",))
        d03 = DomainProposal(
            "d03", "d03.proposal.v1", "d" * 64, envelope,
            (GraphWrite(self.entity, {
                "entity_id": "entity:person", "kind": "person",
                "owner_scope": "persona", "creation_evidence_refs": ["source:1"],
                "status": "active",
            }),), DependencySet(), (), (),
        )
        with self.assertRaises(ValueError):
            DomainBundle(envelope, (d06, d03), (), (), (), (), (), (), ())
        joint = DomainBundle(envelope, (d06, d03), (self.entity.token,),
                             (), (), (), (), (), ())
        receipt = self.coordinator.commit_domain_bundle(joint, joint_lease)
        self.assertEqual(receipt.status, "committed")
        self.assertEqual({item.key for item in receipt.write_versions}, {self.key, self.entity})
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM graph_atoms").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT count(*) FROM graph_bundle_operations").fetchone()[0], 1)

    def test_same_operation_different_digest_conflicts(self):
        self.coordinator.commit_domain_bundle(self.bundle(), self.lease)
        with self.assertRaises(EventConflict):
            self.coordinator.commit_domain_bundle(self.bundle(value=2), self.lease)

    def test_cross_namespace_and_writer_domain_are_rejected(self):
        base = self.bundle()
        alien = AtomKey(Owner("persona", "bot", "someone-else"), "state", "mood")
        with self.assertRaises(ValueError):
            replace(base.proposals[0], typed_writes=(GraphWrite(alien, {"n": 1}),))
        joint_lease, joint_ref = self.coordinator.grant(
            self.bootstrap, actor="host", issuer_domain="d11",
            namespace=self.namespace, domains=("d06", "d03"),
            activation_generation=1,
        )
        envelope = replace(base.envelope,
                           authority=replace(base.envelope.authority,
                                             capability_ref=joint_ref))
        wrong = replace(base.proposals[0], envelope=envelope, domain="d03",
                        proposal_schema="d03.proposal.v1", proposal_schema_hash="d" * 64)
        candidate = replace(base, envelope=envelope, proposals=(wrong,))
        with self.assertRaises(AuthorityDenied):
            self.coordinator.commit_domain_bundle(candidate, joint_lease)

    def test_first_source_ingress_requires_closed_source_access_job_outbox(self):
        source = source_key("bot", "persona", "s1")
        access = access_key("bot", "persona", "s1")
        job = runtime_job_key("bot", "persona", "activity", "job-ingress-1")
        outbox = runtime_outbox_key("bot", "persona", "activity", "outbox-ingress-1")
        keys = (source, access, job, outbox)
        base = self.bundle(operation="first-ingress")
        guard = replace(base.envelope.version_guard,
                        read_versions=self.read(
                            keys, authority=replace(self.read_authority,
                                                    owner_scope=("event", "activity"),
                                                    purpose="context")).versions)
        authority = replace(base.envelope.authority,
                            owner_scope=("event", "activity"), purpose="context")
        qualification = replace(base.envelope.source_qualification,
                                source_refs=(source.token,))
        envelope = replace(base.envelope, authority=authority, version_guard=guard,
                           source_qualification=qualification)
        source_value = SourceRecord(
            "s1", "hello", "user", "reported", "reported", 1.0, 1.0,
            "root-1", ("internal",), ("context",), (), "unknown",
        ).to_dict()
        durable_job = self.d11_issuer._job(envelope, "parent", job.token)
        outbox_value = RuntimeOutboxValue(
            "bot", "persona", "activity", "first-ingress", None,
            outbox.name, durable_job.job_id, job.token, "payload-s1",
            "ingress:s1", "pending", 1)
        writes = (
            GraphWrite(source, source_value),
            GraphWrite(access, {"source_id": "s1", "audiences": ["internal"],
                                "purposes": ["context"], "status": "active",
                                "recorded_at": 1.0}, (source,)),
            job_graph_write(durable_job),
            outbox_graph_write(outbox_value, job),
        )
        proposal = DomainProposal(
            "d06", "d06.contract.v1", "b" * 64, envelope, writes[:2],
            DependencySet(current_invalidation=(guard.read_versions[0],)),
            (), (),
        )
        runtime_proposal = DomainProposal(
            "d11", D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH, envelope, writes[2:],
            DependencySet(current_invalidation=(guard.read_versions[2],)), (), (),
        )
        incomplete = DomainBundle(envelope, (proposal, runtime_proposal),
                                  (), (), (), (), (), (), ())
        with self.assertRaises(ValueError):
            self.coordinator.commit_domain_bundle(incomplete, self.lease)
        candidate = DomainBundle(envelope, (proposal, runtime_proposal),
                                 (), (), (), (), ("ingress:s1",),
                                 (job.token,), (outbox.token,))
        receipt = self.coordinator.commit_domain_bundle(candidate, self.lease)
        self.assertEqual(receipt.status, "committed")
        self.assertEqual(len(receipt.write_versions), 4)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM graph_atoms").fetchone()[0], 4)
            self.assertEqual(db.execute("SELECT phase FROM graph_bundle_outbox").fetchone()[0], "pending")

        # A later domain bundle must read both the source and its still-active
        # access record; the source token alone is insufficient authority.
        follow = self.bundle(operation="followup")
        reads = self.read((self.key, source, access), authority=replace(
            self.read_authority, owner_scope=("persona", "event"),
            purpose="context")).versions
        guard = replace(follow.envelope.version_guard, read_versions=reads,
                        query_epochs=(QueryEpoch(self.namespace, "all",
                                                 self.read((self.key,)).epochs[0].revision),))
        envelope = replace(follow.envelope, version_guard=guard,
                           authority=replace(follow.envelope.authority, purpose="context"),
                           source_qualification=replace(
                               follow.envelope.source_qualification,
                               source_refs=(source.token,)))
        later = replace(follow, envelope=envelope,
                        proposals=(replace(follow.proposals[0], envelope=envelope),))
        self.assertEqual(self.coordinator.commit_domain_bundle(later, self.lease).status,
                         "committed")

    def test_process_authority_and_writer_scope(self):
        candidate = self.bundle()
        with self.assertRaises(AuthorityDenied):
            self.coordinator.commit_domain_bundle(candidate, object())
        with self.assertRaises(AuthorityDenied):
            self.coordinator.commit_domain_bundle(
                self.bundle(owner_scope=("relation",)), self.lease)
        self.assertEqual(self.read((self.key,)).get(self.key).revision, 0)

    def test_negative_query_and_delete_epoch_recheck(self):
        stale_query = self.bundle(operation="stale-query")
        self.coordinator.commit_domain_bundle(self.bundle(operation="first"), self.lease)
        with self.assertRaises(StaleRead):
            self.coordinator.commit_domain_bundle(stale_query, self.lease)
        current = self.bundle(operation="stale-delete")
        self.coordinator.advance_authority_epoch(self.bootstrap, self.namespace, "delete")
        with self.assertRaises(StaleRead):
            self.coordinator.commit_domain_bundle(current, self.lease)

    def test_provider_failure_rolls_back_every_bundle_part(self):
        self.provider.approve = False
        candidate = self.bundle(outbox=True)
        with self.assertRaises(AuthorityDenied):
            self.coordinator.commit_domain_bundle(candidate, self.lease)
        self.assertEqual(self.read((self.key,)).get(self.key).revision, 0)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM graph_bundle_operations").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM graph_bundle_refs").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM graph_bundle_outbox").fetchone()[0], 0)

    def test_late_ledger_failure_rolls_back_graph_write(self):
        with self.store._lock:
            self.store._db.execute(
                "CREATE TRIGGER fail_bundle_ref BEFORE INSERT ON graph_bundle_refs "
                "BEGIN SELECT RAISE(ABORT, 'injected ledger failure'); END"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.coordinator.commit_domain_bundle(self.bundle(outbox=True), self.lease)
        self.assertEqual(self.read((self.key,)).get(self.key).revision, 0)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM graph_events").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM graph_bundle_operations").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM runtime_jobs").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM graph_outbox_jobs").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM runtime_budget_reservations").fetchone()[0], 0)
            self.assertEqual(get_budget_lease(db, "parent").reserved, {})

    def test_insufficient_budget_rejects_graph_job_and_outbox_atomically(self):
        self.d11_issuer.ceiling = {"cpu_ms": 1001}
        candidate = self.bundle(operation="too-expensive", outbox=True)
        with self.assertRaises(BudgetUnavailable):
            self.coordinator.commit_domain_bundle(candidate, self.lease)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM graph_atoms").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM runtime_jobs").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM graph_bundle_outbox").fetchone()[0], 0)
            self.assertEqual(get_budget_lease(db, "parent").reserved, {})

    def test_schedule_reserves_before_execution_and_replay_does_not_double_spend(self):
        candidate = self.bundle(operation="scheduled", outbox=True)
        self.d11_issuer.schedule_graph_job_ref = candidate.persistent_job_refs[0]
        receipt, job = self.coordinator.reserve_and_schedule(candidate.envelope, self.lease)
        self.assertEqual(receipt.status, "reserved")
        repeated_receipt, repeated_job = self.coordinator.reserve_and_schedule(
            candidate.envelope, self.lease)
        self.assertEqual((repeated_receipt, repeated_job), (receipt, job))
        self.d11_issuer.pre_reserved = True
        committed = self.coordinator.commit_domain_bundle(candidate, self.lease)
        self.assertEqual(committed.status, "committed")
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(get_budget_lease(db, "parent").reserved, {"cpu_ms": 1})
            self.assertEqual(db.execute("SELECT count(*) FROM runtime_jobs").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT count(*) FROM graph_outbox_jobs").fetchone()[0], 1)

    def test_schedule_insufficient_balance_creates_no_job(self):
        candidate = self.bundle(operation="schedule-too-expensive", outbox=True)
        self.d11_issuer.schedule_graph_job_ref = candidate.persistent_job_refs[0]
        self.d11_issuer.ceiling = {"cpu_ms": 1001}
        with self.assertRaises(BudgetUnavailable):
            self.coordinator.reserve_and_schedule(candidate.envelope, self.lease)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM runtime_jobs").fetchone()[0], 0)
            self.assertEqual(get_budget_lease(db, "parent").reserved, {})

    def test_schedule_job_insert_failure_rolls_back_budget_reservation(self):
        candidate = self.bundle(operation="schedule-fault", outbox=True)
        self.d11_issuer.schedule_graph_job_ref = candidate.persistent_job_refs[0]
        with self.store._lock:
            self.store._db.execute(
                "CREATE TRIGGER fail_schedule_job BEFORE INSERT ON runtime_jobs "
                "BEGIN SELECT RAISE(ABORT, 'injected job failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.coordinator.reserve_and_schedule(candidate.envelope, self.lease)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(get_budget_lease(db, "parent").reserved, {})
            self.assertEqual(db.execute(
                "SELECT count(*) FROM runtime_budget_reservations").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM runtime_jobs").fetchone()[0], 0)

    def test_forged_runtime_job_graph_projection_rejects_bundle(self):
        candidate = self.bundle(operation="forged-job", outbox=True)
        d11 = candidate.proposals[1]
        job_write = d11.typed_writes[0]
        forged = replace(job_write, value={**job_write.value,
                                           "snapshot_ref": "wrong-snapshot"})
        candidate = replace(candidate, proposals=(candidate.proposals[0],
            replace(d11, typed_writes=(forged, d11.typed_writes[1]))))
        with self.assertRaises(ValueError):
            self.coordinator.commit_domain_bundle(candidate, self.lease)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(get_budget_lease(db, "parent").reserved, {})
            self.assertEqual(db.execute("SELECT count(*) FROM runtime_jobs").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM graph_atoms").fetchone()[0], 0)

    def test_stale_outbox_dispatch_generation_rejects_bundle(self):
        candidate = self.bundle(operation="stale-dispatch", outbox=True)
        d11 = candidate.proposals[1]
        outbox_write = d11.typed_writes[1]
        stale = replace(outbox_write, value={**outbox_write.value,
                                             "dispatch_generation": 0})
        candidate = replace(candidate, proposals=(candidate.proposals[0],
            replace(d11, typed_writes=(d11.typed_writes[0], stale))))
        with self.assertRaises(StaleRead):
            self.coordinator.commit_domain_bundle(candidate, self.lease)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM runtime_jobs").fetchone()[0], 0)
            self.assertEqual(get_budget_lease(db, "parent").reserved, {})

    def test_cancelled_worker_result_cannot_publish_graph_or_outbox(self):
        candidate = self.bundle(operation="cancelled-worker", outbox=True)
        self.d11_issuer.schedule_graph_job_ref = candidate.persistent_job_refs[0]
        _, queued = self.coordinator.reserve_and_schedule(candidate.envelope, self.lease)
        self.d11_issuer.pre_reserved = True
        running = self.coordinator.acquire_persistent_job(
            candidate.envelope.authority, self.lease, queued.job_id,
            now_utc="2029-01-01T00:00:00Z", lease_seconds=60)
        worker_authority = replace(candidate.envelope.authority,
                                   worker_fence=running.fence)
        worker_envelope = replace(candidate.envelope, authority=worker_authority)
        worker_bundle = replace(
            candidate, envelope=worker_envelope,
            proposals=tuple(replace(proposal, envelope=worker_envelope)
                            for proposal in candidate.proposals))
        cancelled = self.coordinator.cancel_persistent_job(
            candidate.envelope.authority, self.lease, queued.job_id,
            "cancel-worker", "a" * 64)
        self.assertEqual(cancelled.phase, "draining")
        self.assertGreater(cancelled.fence, running.fence)
        with self.assertRaises(UnavailableGuard):
            self.coordinator.commit_domain_bundle(worker_bundle, self.lease)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM graph_atoms").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM graph_bundle_outbox").fetchone()[0], 0)
            self.assertEqual(get_budget_lease(db, "parent").reserved, {"cpu_ms": 1})

    def test_current_worker_fence_can_commit_matching_runtime_projection(self):
        candidate = self.bundle(operation="current-worker", outbox=True)
        self.d11_issuer.schedule_graph_job_ref = candidate.persistent_job_refs[0]
        _, queued = self.coordinator.reserve_and_schedule(candidate.envelope, self.lease)
        self.d11_issuer.pre_reserved = True
        running = self.coordinator.acquire_persistent_job(
            candidate.envelope.authority, self.lease, queued.job_id,
            now_utc="2029-01-01T00:00:00Z", lease_seconds=60)
        worker_authority = replace(candidate.envelope.authority,
                                   worker_fence=running.fence)
        worker_envelope = replace(candidate.envelope, authority=worker_authority)
        d11 = candidate.proposals[1]
        worker_bundle = replace(
            candidate, envelope=worker_envelope,
            proposals=(replace(candidate.proposals[0], envelope=worker_envelope),
                       replace(d11, envelope=worker_envelope,
                               typed_writes=(job_graph_write(running),
                                             d11.typed_writes[1]))))
        self.assertEqual(self.coordinator.commit_domain_bundle(
            worker_bundle, self.lease).status, "committed")
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute(
                "SELECT count(*) FROM graph_outbox_jobs").fetchone()[0], 1)

    def test_unknown_cost_keeps_full_ceiling_and_matches_d11_graph_receipt(self):
        base = self.bundle(operation="unknown-cost")
        cost_key = runtime_cost_settlement_key(
            "bot", "persona", "activity", "settlement-unknown")
        authority = replace(base.envelope.authority,
                            owner_scope=("persona", "activity"))
        cost_read = self.read((cost_key,), authority=authority).versions[0]
        guard = replace(base.envelope.version_guard,
                        read_versions=base.envelope.version_guard.read_versions +
                        (cost_read,))
        envelope = replace(base.envelope, authority=authority, version_guard=guard)
        digest = budget_operation_digest(envelope, "parent", {"cpu_ms": 1})
        expected_receipt = BudgetReceipt(
            "pending_confirmation", "unknown-cost", digest, "parent", 3,
            {}, {}, {"cpu_ms": 1})
        receipt_bytes = json.dumps(asdict(expected_receipt), sort_keys=True,
                                   separators=(",", ":"))
        cost = RuntimeCostSettlement(
            "bot", "persona", "activity", "unknown-cost", None,
            cost_key.name, "parent", "USD", "unknown-cost",
            "pending_confirmation", {"cpu_ms": 1}, None, {"cpu_ms": 1},
            "settle", "unknown-cost",
            hashlib.sha256(receipt_bytes.encode()).hexdigest(), None, False)
        d06 = replace(base.proposals[0], envelope=envelope)
        d11 = DomainProposal(
            "d11", D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH, envelope,
            (cost_settlement_graph_write(cost),), DependencySet(), (), ())
        candidate = DomainBundle(
            envelope, (d06, d11), (), (), (), (cost_key.token,), (), (), ())
        self.d11_issuer.settle_now = True
        self.d11_issuer.actual = None
        self.assertEqual(self.coordinator.commit_domain_bundle(
            candidate, self.lease).status, "committed")
        with closing(sqlite3.connect(self.path)) as db:
            lease = get_budget_lease(db, "parent")
            self.assertEqual(lease.reserved, {})
            self.assertEqual(lease.unconfirmed, {"cpu_ms": 1})
            self.assertEqual(db.execute(
                "SELECT state FROM runtime_budget_reservations WHERE operation_id=?",
                ("unknown-cost",)).fetchone()[0], "unknown")
            self.assertEqual(db.execute(
                "SELECT count(*) FROM graph_atoms WHERE token=?",
                (cost_key.token,)).fetchone()[0], 1)
        self.d11_issuer.ceiling = {"cpu_ms": 1000}
        with self.assertRaises(BudgetUnavailable):
            self.coordinator.commit_domain_bundle(
                self.bundle(operation="after-unknown"), self.lease)


if __name__ == "__main__":
    unittest.main()
