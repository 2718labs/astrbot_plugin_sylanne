import tempfile
import unittest
from pathlib import Path

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06 import (
    CandidateItem,
    CandidateSet,
    CorrectionRequest,
    D06DomainAdapter,
    EncodingContext,
    ErasureRequest,
    RecallIntent,
    RecollectionContext,
    RetrievalChannel,
    SelectionTicket,
    SourceAdmission,
    TransferRequest,
    TriggerKind,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import GraphCandidate, GraphVersion, NamespaceEpoch, TypeRegistry
from sylanne3.memory_retrieval import MemoryBatch, MemoryHit
from sylanne3.memory_types import SourceRecord, access_key, register_memory_types, source_key
from sylanne3.runtime_contracts import (
    AuthorityContext,
    CommandEnvelope,
    DependencySet,
    DomainProposal,
    NamespaceId,
    OperationIdentity,
    RUNTIME_SCHEMA,
    VersionGuard,
    canonical_digest,
)


class D06DomainAdapterTests(unittest.TestCase):
    def setUp(self):
        self.domain = D06DomainAdapter(NamespaceId("bot", "persona"))

    def test_pure_greeting_does_not_search_history_but_history_reference_is_mandatory(self):
        greeting = self.domain.qualify_recall(
            RecallIntent("r-greeting", greeting_only=True)
        )
        self.assertEqual(greeting.mode, "no_history_search")
        self.assertIsNone(greeting.trigger)

        referenced = self.domain.qualify_recall(
            RecallIntent(
                "r-history",
                trigger=TriggerKind.UNRESOLVED_REFERENCE,
                rationale="上次那个项目",
                greeting_only=True,
            )
        )
        self.assertEqual(referenced.mode, "mandatory")
        self.assertEqual(referenced.trigger, TriggerKind.UNRESOLVED_REFERENCE)

    def test_source_qualification_preserves_reality_evidence_and_actuality_as_separate_axes(self):
        proposal = self.domain.admit_source(
            SourceAdmission(
                source_id="source-1",
                text="我想起了一个虚构故事",
                speaker_id="persona",
                source_kind="simulated",
                content_reality="simulated",
                evidence_eligibility="subjective_only",
                internal_activity_actuality="committed",
                occurred_at=None,
                learned_at=10.0,
                provenance_family="family-1",
                audiences=("owner",),
                purposes=("context",),
            )
        )

        self.assertEqual(proposal.qualification.content_reality, "simulation")
        self.assertEqual(proposal.qualification.evidence_eligibility, "ineligible")
        self.assertEqual(proposal.qualification.internal_activity_actuality, "actual")
        self.assertEqual(
            proposal.qualification.source_refs,
            (source_key("bot", "persona", "source-1").token,),
        )
        self.assertEqual(proposal.source.assertion_status, "unknown")
        self.assertTrue(proposal.encoding_pending)

    def test_encoding_and_recollection_are_candidates_until_runtime_commits_bundle(self):
        encoding = self.domain.prepare_encoding(
            "source-1",
            EncodingContext(
                event_ref="event-1",
                perspective_ref="perspective@4",
                then_feeling_refs=("feeling@7",),
                interpretation_refs=("meaning@2",),
                detail_weights=(("promise", 0.9), ("weather", 0.2)),
                read_versions=(("source-1", 3), ("feeling", 7)),
            ),
        )
        self.assertEqual(encoding.episode.source_refs, ("source-1",))
        self.assertEqual(encoding.trace.then_feeling_refs, ("feeling@7",))
        self.assertEqual(encoding.status, "proposal")

        candidates = CandidateSet(
            "set-1",
            (
                CandidateItem(
                    "candidate-1",
                    "source-1",
                    "family-1",
                    "keyword",
                    ("context",),
                    0.8,
                    "observed",
                ),
            ),
            coverage="partial",
            continuation="frontier-2",
        )
        recollection = self.domain.prepare_recollection(
            SelectionTicket("ticket-1", "activity-1", "set-1", ("candidate-1",), 4),
            candidates,
            RecollectionContext(
                now_interpretation_refs=("now@4",),
                feeling_experience_refs=("feeling-now@9",),
                self_understanding_refs=("self@3",),
            ),
        )

        self.assertEqual(recollection.status, "proposal")
        self.assertEqual(recollection.activity_id, "activity-1")
        self.assertEqual(recollection.content_refs, ("source-1",))
        self.assertEqual(recollection.activity_basis_refs, ("ticket-1", "set-1"))
        self.assertEqual(recollection.provenance_eligibility, ("observed",))

    def test_retrieval_batches_become_deduplicated_candidates_with_honest_coverage(self):
        source = SourceRecord(
            "source-1",
            "共同项目的截止日是周五",
            "alice",
            "reported",
            "reported",
            3.0,
            4.0,
            "family-chat-1",
            ("owner",),
            ("context",),
        )
        key = source_key("bot", "persona", source.source_id)
        hit = MemoryHit(
            key,
            source,
            (GraphVersion(key, 2),),
            (source.provenance_root,),
            (source,),
        )
        complete = MemoryBatch((hit,), NamespaceEpoch("bot", "persona", 9), 1, 2, 1, True, None)
        partial = MemoryBatch((hit,), NamespaceEpoch("bot", "persona", 9), 1, 2, 1, False, key)

        candidates = self.domain.assemble_candidates(
            "set-from-retrieval",
            (
                RetrievalChannel("exact", complete, 1.0),
                RetrievalChannel("association", partial, 0.6),
            ),
            purpose="context",
        )

        self.assertEqual(len(candidates.items), 1)
        self.assertEqual(candidates.items[0].content_ref, "source-1")
        self.assertEqual(candidates.items[0].provenance_family, "family-chat-1")
        self.assertEqual(candidates.items[0].activation, 1.0)
        self.assertEqual(candidates.coverage, "partial")
        self.assertIsNotNone(candidates.continuation)

    def test_correction_erasure_and_transfer_are_fail_closed_runtime_plans(self):
        correction = self.domain.plan_correction(
            CorrectionRequest(
                "correction-1",
                target_refs=("interpretation@2",),
                basis_source_refs=("source-new",),
                replacement_claim="后来确认当时在急诊",
                access_epoch=7,
                deletion_epoch=11,
            )
        )
        self.assertEqual(correction.operation, "revise_or_consolidate")
        self.assertIn("invalidate_current_interpretation", correction.required_bundle_parts)

        erasure = self.domain.plan_erasure(
            ErasureRequest("erase-1", ("source-1",), "all_derived", 7, 11)
        )
        self.assertEqual(erasure.operation, "erase_memory")
        self.assertEqual(erasure.status, "pending_runtime_authority")
        self.assertIn("independent_deletion_intent", erasure.required_bundle_parts)

        transfer = self.domain.plan_transfer(
            TransferRequest(
                "transfer-1",
                ("source-1",),
                "bot/persona-b",
                "grant-4",
                7,
                11,
            )
        )
        self.assertEqual(transfer.operation, "inspect_or_transfer")
        self.assertEqual(transfer.status, "pending_runtime_authority")
        self.assertIn("synchronous_origin_authorization", transfer.required_bundle_parts)

    def test_runtime_proposal_uses_the_frozen_w00_envelope_and_proposal_types(self):
        admitted = self.domain.admit_source(
            SourceAdmission(
                "source-runtime",
                "尚不知道发生时间的转述",
                "alice",
                "reported",
                "unknown",
                "reported_claim",
                "not_applicable",
                None,
                12.0,
                "family-runtime",
                ("owner",),
                ("context",),
            )
        )
        input_refs = ("source-runtime",)
        envelope = CommandEnvelope(
            RUNTIME_SCHEMA,
            OperationIdentity(
                "activity-runtime",
                None,
                "attempt-1",
                "source-admission",
                "operation-runtime",
                canonical_digest({"input_refs": list(input_refs)}),
            ),
            AuthorityContext(
                "host",
                "d06",
                "capability-d06",
                NamespaceId("bot", "persona"),
                ("persona",),
                "context",
                ("owner",),
                "provider-policy-1",
                1,
            ),
            VersionGuard(
                (), (), 4, 7, "catalogue-1", "scheme-1", "operator-1", "d06.policy.v1", (), (), ()
            ),
            admitted.qualification,
            input_refs,
            "budget-root",
            100.0,
            10.0,
            "character-interval-1",
            ("ingress-1",),
        )

        proposal = self.domain.wrap_runtime_proposal(
            envelope,
            typed_writes=(),
            dependencies=DependencySet(),
            contribution_keys=("source:source-runtime",),
            required_bundle_parts=("persistent_job", "outbox"),
        )

        self.assertIsInstance(proposal, DomainProposal)
        self.assertIs(proposal.envelope, envelope)
        self.assertEqual(proposal.domain, "d06")
        self.assertEqual(len(proposal.proposal_schema_hash), 64)

    def test_first_ingress_compiles_source_and_access_writes_with_absence_proofs(self):
        request = SourceAdmission(
            "source-ingress",
            "第一次入库",
            "alice",
            "observed",
            "observed",
            "external_fact",
            "not_applicable",
            8.0,
            9.0,
            "family-ingress",
            ("owner",),
            ("context",),
            subjective_confidence=0.9,
        )
        admitted = self.domain.admit_source(request)
        source = source_key("bot", "persona", "source-ingress")
        access = access_key("bot", "persona", "source-ingress")
        input_refs = (source.token,)
        envelope = CommandEnvelope(
            RUNTIME_SCHEMA,
            OperationIdentity(
                "activity-ingress",
                None,
                "attempt-1",
                "source-admission",
                "operation-ingress",
                canonical_digest({"input_refs": list(input_refs)}),
            ),
            AuthorityContext(
                "host", "d06", "capability-d06", NamespaceId("bot", "persona"),
                ("persona",), "context", ("owner",), "provider-policy-1", 1,
            ),
            VersionGuard(
                (GraphVersion(source, 0), GraphVersion(access, 0)),
                (), 4, 7, "catalogue-1", "scheme-1", "operator-1", "d06.policy.v1", (), (), (),
            ),
            admitted.qualification,
            input_refs,
            "budget-root",
            100.0,
            10.0,
            "character-interval-1",
            ("host-ingress-1",),
        )

        proposal = self.domain.compile_source_ingress(envelope, request)

        self.assertEqual(tuple(write.key for write in proposal.typed_writes), (source, access))
        self.assertEqual(proposal.typed_writes[1].dependencies, (source,))
        self.assertEqual(
            proposal.dependencies.current_invalidation,
            (GraphVersion(source, 0),),
        )
        self.assertEqual(proposal.typed_writes[1].value["status"], "active")
        self.assertEqual(proposal.required_bundle_parts, ("persistent_job", "outbox"))
        registry = TypeRegistry()
        register_memory_types(registry)
        with tempfile.TemporaryDirectory() as directory:
            store = GraphStore(Path(directory) / "ingress.db", registry)
            try:
                receipt = store.graph_commit(GraphCandidate(
                    Event(Scope("bot", "persona", "session"), "ingress-1", 1.0, "ingress", {}),
                    envelope.version_guard.read_versions,
                    proposal.typed_writes,
                ))
                self.assertEqual(receipt.status, "committed")
                snapshot = store.graph_snapshot((source, access))
                self.assertTrue(all(atom.valid for atom in snapshot.atoms))
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
