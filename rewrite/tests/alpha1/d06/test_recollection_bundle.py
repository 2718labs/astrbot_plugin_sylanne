import unittest

from sylanne3.domains.d06 import (
    CandidateItem,
    CandidateSet,
    D06DomainAdapter,
    D06DomainProvider,
    RecollectionContext,
    SelectionTicket,
)
from sylanne3.graph_types import AtomKey, GraphVersion, GraphWrite, Owner, TypeRegistry
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime_contracts import (
    AuthorityContext,
    CommandEnvelope,
    DependencySet,
    DomainProposal,
    NamespaceId,
    OperationIdentity,
    RUNTIME_SCHEMA,
    SourceQualification,
    VersionGuard,
    VersionedRef,
    canonical_digest,
    schema_hash,
)


class RecollectionBundleTests(unittest.TestCase):
    def setUp(self):
        self.namespace = NamespaceId("bot", "persona")
        self.domain = D06DomainAdapter(self.namespace)
        self.source = source_key("bot", "persona", "source-1")
        self.access = access_key("bot", "persona", "source-1")
        self.ticket = SelectionTicket("ticket-1", "activity-1", "set-1", ("candidate-1",), 4)
        self.candidates = CandidateSet(
            "set-1",
            (CandidateItem(
                "candidate-1", "source-1", "family-1", "exact", ("context",), 0.9, "observed",
            ),),
            "complete",
            access_epoch=5,
            delete_epoch=6,
        )
        self.choice = self._key("activity", "activity-1", "d07.selection_ticket.v1", "ticket-1")
        self.interpretation = self._key("activity", "activity-1", "d07.belief_revision.v1", "now-1")
        self.feeling = self._key("activity", "activity-1", "d04.recollection_feeling.v1", "feeling-1")
        self.settlement = self._key("activity", "activity-1", "d02.settlement.v1", "settlement-1")
        self.cost = self._key("activity", "activity-1", "runtime.cost_settlement", "cost-1")
        self.outbox = self._key("activity", "activity-1", "runtime.outbox", "outbox-1")
        self.context = RecollectionContext(
            (self.interpretation.token,), (self.feeling.token,), (),
        )
        self.envelope = self._envelope(access_epoch=5, delete_epoch=6)

    def _key(self, kind, subject, type_name, name):
        return AtomKey(Owner(kind, "bot", "persona", subject), type_name, name)

    def _envelope(self, *, access_epoch, delete_epoch):
        input_refs = ("ticket-1", "set-1")
        return CommandEnvelope(
            RUNTIME_SCHEMA,
            OperationIdentity(
                "activity-1", None, "attempt-1", "realize-recollection", "operation-1",
                canonical_digest({"input_refs": list(input_refs)}),
            ),
            AuthorityContext(
                "host", "d06", "capability-d06", self.namespace, ("activity",),
                "context", ("owner",), "provider-policy-1", 1,
            ),
            VersionGuard(
                (GraphVersion(self.source, 3), GraphVersion(self.access, 2)), (),
                access_epoch, delete_epoch, "catalogue-1", "scheme-1", "operator-1",
                "d06.policy.v1", (), (VersionedRef("focus-lease", 4),), (),
            ),
            SourceQualification(
                (self.source.token,), "observed", 1.0, 2.0, "external_observation",
                "eligible", 0.9, "not_applicable",
            ),
            input_refs,
            "budget-root",
            100.0,
            10.0,
            "character-interval-1",
            ("trigger-1",),
        )

    def _proposal(self, domain, writes):
        return DomainProposal(
            domain,
            f"{domain}.proposal.v1",
            schema_hash({"domain": domain, "proposal": 1}),
            self.envelope,
            tuple(writes),
            DependencySet(),
            (),
            (),
        )

    def _supporting_proposals(self):
        choice_value = {
            "ticket_id": self.ticket.ticket_id,
            "activity_id": self.ticket.activity_id,
            "candidate_set_id": self.ticket.candidate_set_id,
            "selected_candidate_ids": list(self.ticket.selected_candidate_ids),
            "focus_epoch": self.ticket.focus_epoch,
        }
        return (
            self._proposal("d07", (
                GraphWrite(self.choice, choice_value),
                GraphWrite(self.interpretation, {"candidate": "current-interpretation"}),
            )),
            self._proposal("d04", (GraphWrite(self.feeling, {"candidate": "current-feeling"}),)),
            self._proposal("d02", (GraphWrite(self.settlement, {"candidate": "resource-settlement"}),)),
            self._proposal("d11", (
                GraphWrite(self.cost, {"candidate": "cost-settlement"}),
                GraphWrite(self.outbox, {"candidate": "outbox"}),
            )),
        )

    def test_complete_supporting_write_set_builds_candidate_bundle_without_commit_claim(self):
        bundle = self.domain.assemble_recollection_bundle(
            self.envelope,
            self.ticket,
            self.candidates,
            self.context,
            supporting_proposals=self._supporting_proposals(),
            choice_ref=self.choice.token,
            d02_settlement_ref=self.settlement.token,
            d11_cost_settlement_ref=self.cost.token,
            outbox_ref=self.outbox.token,
        )

        self.assertEqual({proposal.domain for proposal in bundle.proposals}, {"d02", "d04", "d06", "d07", "d11"})
        self.assertEqual(bundle.choice_refs, (self.choice.token,))
        self.assertEqual(bundle.d11_cost_settlement_refs, (self.cost.token,))
        self.assertEqual(bundle.outbox_refs, (self.outbox.token,))
        self.assertEqual(len(bundle.experience_refs), 1)
        recollection = bundle.proposals[0].typed_writes[0]
        self.assertEqual(recollection.value["activity_id"], "activity-1")
        self.assertNotIn("commit_seq", recollection.value)
        self.assertNotIn("committed", recollection.value)

    def test_retrieval_hit_without_selection_ticket_cannot_create_recollection(self):
        with self.assertRaises(TypeError):
            self.domain.prepare_recollection(None, self.candidates, self.context)

    def test_missing_supporting_domain_or_write_fails_closed(self):
        proposals = self._supporting_proposals()
        with self.assertRaisesRegex(ValueError, "supporting domains are incomplete"):
            self.domain.assemble_recollection_bundle(
                self.envelope, self.ticket, self.candidates, self.context,
                supporting_proposals=proposals[:-1],
                choice_ref=self.choice.token,
                d02_settlement_ref=self.settlement.token,
                d11_cost_settlement_ref=self.cost.token,
                outbox_ref=self.outbox.token,
            )

        broken = (*proposals[:-1], self._proposal("d11", (GraphWrite(self.cost, {}),)))
        with self.assertRaisesRegex(ValueError, "does not materialize required C04 refs"):
            self.domain.assemble_recollection_bundle(
                self.envelope, self.ticket, self.candidates, self.context,
                supporting_proposals=broken,
                choice_ref=self.choice.token,
                d02_settlement_ref=self.settlement.token,
                d11_cost_settlement_ref=self.cost.token,
                outbox_ref=self.outbox.token,
            )

    def test_d04_experience_must_reference_this_recollection(self):
        feeling = self._key(
            "activity", "activity-1", "d04.recollection_experience.v1", "feeling-1",
        )
        context = RecollectionContext((self.interpretation.token,), (feeling.token,), ())
        proposals = tuple(
            self._proposal("d04", (GraphWrite(feeling, {"recollection_ref": "other"}),))
            if proposal.domain == "d04" else proposal
            for proposal in self._supporting_proposals()
        )

        with self.assertRaisesRegex(ValueError, "does not reference this recollection"):
            self.domain.assemble_recollection_bundle(
                self.envelope, self.ticket, self.candidates, context,
                supporting_proposals=proposals,
                choice_ref=self.choice.token,
                d02_settlement_ref=self.settlement.token,
                d11_cost_settlement_ref=self.cost.token,
                outbox_ref=self.outbox.token,
            )

    def test_access_or_deletion_epoch_change_rejects_old_candidate_set(self):
        stale_envelope = self._envelope(access_epoch=6, delete_epoch=7)
        with self.assertRaisesRegex(ValueError, "authorization epochs are stale"):
            self.domain.assemble_recollection_bundle(
                stale_envelope, self.ticket, self.candidates, self.context,
                supporting_proposals=(),
                choice_ref=self.choice.token,
                d02_settlement_ref=self.settlement.token,
                d11_cost_settlement_ref=self.cost.token,
                outbox_ref=self.outbox.token,
            )

    def test_d06_provider_exports_strict_memory_and_recollection_specs(self):
        provider = D06DomainProvider()
        specs = provider.type_specs()
        self.assertEqual(provider.descriptor.provider_id, "d06.memory")
        self.assertEqual(
            {spec.name for spec in specs},
            {"memory.source", "memory.access", "memory.interpretation", "d06.recollection.v1"},
        )
        registry = TypeRegistry()
        for spec in specs:
            self.assertEqual(spec.writer_domain, "d06")
            registry.register(spec)
        invalid = self._key("activity", "activity-1", "d06.recollection.v1", "bad")
        with self.assertRaises(ValueError):
            registry.validate(invalid, {"recollection_id": "bad"})


if __name__ == "__main__":
    unittest.main()
