import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06 import (
    CandidateItem, CandidateSet, D06DomainAdapter, D06DomainProvider,
    RecollectionContext, SelectionTicket, source_correction_head_key,
)
from sylanne3.domains.d06.pipeline import D06MemoryPipeline
from sylanne3.graph_coordinator import BudgetAdmission, GraphCoordinator, RuntimeAdmission
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphWrite, Owner, TypeRegistry
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.budget import BudgetLease, create_budget_lease, get_budget_lease
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, DomainBundle, DomainProposal,
    NamespaceId, OperationIdentity, RUNTIME_SCHEMA, SourceQualification,
    QueryEpoch, VersionGuard, VersionedRef, canonical_digest, schema_hash,
)


class _D02Issuer:
    def authorize_resources(self, bundle, db):
        return True


class _D11Issuer:
    def admit_runtime(self, bundle, db):
        lease = get_budget_lease(db, bundle.envelope.parent_budget_lease_ref)
        return RuntimeAdmission(
            BudgetAdmission(lease.lease_id, lease.version, {"cpu_ms": 1}), (),
        )


class RecollectionCoordinatorCommitTests(unittest.TestCase):
    def test_d06_c04_immutable_write_commits_with_historical_provenance(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        try:
            namespace = NamespaceId("bot", "persona")
            provider = D06DomainProvider()
            registry = TypeRegistry()
            for spec in provider.type_specs():
                registry.register(spec)
            store = GraphStore(Path(temp.name) / "graph.db", registry)
            self.addCleanup(store.close)
            repository = MemoryRepository(store, "bot", "persona")
            repository.ingest(
                Event(Scope("bot", "persona", "session"), "ingress-1", 1.0, "ingress", {}),
                SourceRecord(
                    "source-1", "shared evening", "alice", "observed", "confirmed",
                    1.0, 2.0, "family-1", ("owner",), ("context",),
                ),
            )
            with store._lock:
                create_budget_lease(store._db, BudgetLease(
                    "parent", None, "bot", "persona", "USD",
                    {"cpu_ms": 1}, {}, {}, {},
                    1, "active",
                ), "install-parent", "0" * 64)

            bootstrap = object()
            coordinator = GraphCoordinator(
                store, bootstrap, d02_issuer=_D02Issuer(), d11_issuer=_D11Issuer(),
            )
            coordinator.register_provider(
                bootstrap, "d06", provider, "d06.contract.v1",
                provider.descriptor.request_schema_hash,
            )
            lease, capability = coordinator.grant(
                bootstrap, actor="host", issuer_domain="d06", namespace=namespace,
                domains=("d06",), activation_generation=1,
            )
            for kind, ref, version in (
                ("scheme", "current", "scheme-1"),
                ("operator", "current", "operator-1"),
                ("policy", "current", "policy-1"),
                ("activation", "current", 1),
                ("focus_lease", "focus-1", 4),
            ):
                coordinator.set_guard_version(bootstrap, namespace, kind, ref, version)

            source = source_key("bot", "persona", "source-1")
            access = access_key("bot", "persona", "source-1")
            correction_head = source_correction_head_key(namespace, "source-1")
            candidates = CandidateSet(
                "set-1",
                (CandidateItem(
                    "candidate-1", "source-1", "family-1", "association",
                    ("context",), 0.8, "observed",
                ),),
                "complete", access_epoch=0, delete_epoch=0,
            )
            ticket = SelectionTicket(
                "ticket-1", "activity-1", "set-1", ("candidate-1",), 4,
            )
            adapter = D06DomainAdapter(namespace)
            recollection = adapter.prepare_recollection(
                ticket, candidates, RecollectionContext((), (), ()),
            )
            recollection_key = AtomKey(
                Owner("activity", "bot", "persona", "activity-1"),
                "d06.recollection.v1", recollection.recollection_id,
            )
            projection_key = AtomKey(
                Owner("activity", "bot", "persona", "activity-1"),
                "d06.recollection_projection.v1", "projection-1",
            )
            authority = AuthorityContext(
                "host", "d06", capability, namespace, ("event", "activity"), "context",
                ("owner",), "policy-1", 1,
            )
            snapshot = coordinator.read_snapshot(
                authority, lease, (source, access, correction_head,
                                   recollection_key, projection_key),
            )
            input_refs = (ticket.ticket_id, candidates.candidate_set_id)
            envelope = CommandEnvelope(
                RUNTIME_SCHEMA,
                OperationIdentity(
                    "activity-1", None, "attempt-1", "realize-recollection",
                    "operation-1", canonical_digest({"input_refs": list(input_refs)}),
                ),
                authority,
                VersionGuard(
                    snapshot.versions,
                    (QueryEpoch(namespace, "all", snapshot.epochs[0].revision),),
                    0, 0, registry.catalogue_hash,
                    "scheme-1", "operator-1", "policy-1", (),
                    (VersionedRef("focus-1", 4),), (),
                ),
                SourceQualification(
                    (source.token,), "observed", 1.0, 2.0,
                    "external_observation", "eligible", 0.8, "not_applicable",
                ),
                input_refs, "parent", 100.0, 100.0, "character-1", ("trigger-1",),
            )
            proofs = tuple(
                version for version in snapshot.versions if version.key in {source, access}
            )
            choice = AtomKey(
                Owner("activity", "bot", "persona", "activity-1"),
                "d07.selection_ticket.v1", "ticket-1",
            )
            interpretation = AtomKey(
                Owner("activity", "bot", "persona", "activity-1"),
                "d07.current_interpretation.v1", "interpretation-1",
            )
            feeling = AtomKey(
                Owner("activity", "bot", "persona", "activity-1"),
                "d04.recollection_feeling.v1", "feeling-1",
            )
            settlement = AtomKey(
                Owner("activity", "bot", "persona", "activity-1"),
                "d02.settlement.v1", "settlement-1",
            )
            cost = AtomKey(
                Owner("activity", "bot", "persona", "activity-1"),
                "runtime.cost_settlement", "cost-1",
            )
            job = AtomKey(
                Owner("activity", "bot", "persona", "activity-1"),
                "runtime.job", "job-1",
            )
            outbox = AtomKey(
                Owner("activity", "bot", "persona", "activity-1"),
                "runtime.outbox", "outbox-1",
            )

            def supporting(domain, writes):
                return DomainProposal(
                    domain, f"{domain}.proposal.v1",
                    schema_hash({"domain": domain, "proposal": 1}), envelope,
                    writes, DependencySet(), (), (),
                )

            choice_value = {
                "ticket_id": "ticket-1", "activity_id": "activity-1",
                "candidate_set_id": "set-1",
                "selected_candidate_ids": ["candidate-1"], "focus_epoch": 4,
            }
            candidate_bundle = adapter.assemble_recollection_bundle(
                envelope, ticket, candidates,
                RecollectionContext((interpretation.token,), (feeling.token,), ()),
                supporting_proposals=(
                    supporting("d07", (
                        GraphWrite(choice, choice_value), GraphWrite(interpretation, {}),
                    )),
                    supporting("d04", (GraphWrite(feeling, {}),)),
                    supporting("d02", (GraphWrite(settlement, {}),)),
                    supporting("d11", (
                        GraphWrite(cost, {}), GraphWrite(job, {}), GraphWrite(outbox, {}),
                    )),
                ),
                choice_ref=choice.token,
                d02_settlement_ref=settlement.token,
                d11_cost_settlement_ref=cost.token,
                persistent_job_ref=job.token,
                outbox_ref=outbox.token,
            )
            proposal = next(item for item in candidate_bundle.proposals if item.domain == "d06")
            write = proposal.typed_writes[0]
            projection_value = {
                "projection_id": "projection-1", "activity_id": "activity-1",
                "recollection_ref": write.key.token, "experience_ref": feeling.token,
                "source_ref": source.token, "source_revision": 1,
                "mood_ref": AtomKey(
                    Owner("persona", "bot", "persona"), "d04.mood_field.v1", "mood-1",
                ).token,
                "mood_revision": 1, "coupling_version": "coupling-1",
                "projection_version": "d06.affective_projection.v1",
                "state": "committed_subjective_projection",
                "evidence_eligibility": "subjective_only", "details": [],
                "subjective_weight": [0.4, 0.6], "subjective_tone": [-0.1, 0.1],
                "duration_interval": None, "encoding_trace_ref": None,
                "baseline_status": "not_read",
            }
            projection_write = GraphWrite(projection_key, projection_value)
            proposal = replace(proposal, typed_writes=(*proposal.typed_writes, projection_write))
            provider.validate(proposal)
            invalid_value = {**projection_value,
                             "source_ref": source_key("bot", "persona", "other-source").token}
            invalid_proposal = replace(
                proposal,
                typed_writes=(*proposal.typed_writes[:-1], GraphWrite(projection_key, invalid_value)),
            )
            with self.assertRaisesRegex(ValueError, "differs from its persisted recollection"):
                provider.validate(invalid_proposal)
            self.assertEqual(write.dependencies, ())
            self.assertEqual(proposal.dependencies.current_invalidation, ())
            self.assertEqual(proposal.dependencies.historical_provenance, proofs)
            proposal = replace(proposal, required_bundle_parts=())
            bundle = DomainBundle(
                envelope, (proposal,), (write.key.token,), (), (), (),
                ("d06:c04:activity-1",), (), (),
            )

            receipt = coordinator.commit_domain_bundle(bundle, lease)

            self.assertEqual(receipt.status, "committed")
            self.assertEqual({item.key for item in receipt.write_versions},
                             {write.key, projection_write.key})
            reread = D06MemoryPipeline(adapter, repository).read_recollection_projection(
                store.graph_snapshot((projection_key,)), projection_key.token,
            )
            self.assertEqual(reread["read_status"],
                             "hold_unverified_access_and_d04_experience")
            self.assertEqual(reread["evidence_eligibility"], "subjective_only")
            self.assertNotIn("literal_text", str(reread))
            self.assertNotIn("recalled_text", str(reread))
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
