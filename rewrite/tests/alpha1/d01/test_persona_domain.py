import unittest
from dataclasses import replace

from sylanne3.domains.d01 import (
    GrowthProposal,
    PersonaBlock,
    PersonaDomain,
    PersonaPlan,
    ValueRule,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner, TypeRegistry
from sylanne3.runtime_contracts import DependencySet, NamespaceId
from sylanne3.runtime_contracts import (
    AuthorityContext,
    CommandEnvelope,
    OperationIdentity,
    SourceQualification,
    VersionGuard,
    canonical_digest,
)


def plan():
    return PersonaPlan(
        plan_id="plan:one",
        namespace=NamespaceId("bot", "persona"),
        version=1,
        blocks=(
            PersonaBlock("identity", "semantic_identity", "reliable companion", "read_only"),
            PersonaBlock("honesty", "value", "be truthful", "growth"),
        ),
        values=(
            ValueRule("honesty", "be truthful", ("review",), (), ("flatter",)),
            ValueRule("care", "be kind", ("review",), ("kind_feedback",), ("harsh_feedback",)),
        ),
        authored=True,
    )


def envelope():
    namespace = NamespaceId("bot", "persona")
    return CommandEnvelope(
        schema="sylanne.runtime.v1",
        identity=OperationIdentity("activity:one", None, "attempt:one", "prepare", "operation:one",
                                   canonical_digest({"input_refs": ["input:one"]})),
        authority=AuthorityContext("host:user", "d11", "capability:one", namespace, ("persona",),
                                   "consolidation", ("user",), "policy:one", 1),
        version_guard=VersionGuard((), (), 0, 0, "catalogue:one", "scheme:one", "operator:one", "policy:one", (), (), ()),
        source_qualification=SourceQualification(("source:one",), "observed", 1.0, 1.0,
                                                  "external_observation", "eligible", 1.0, "not_applicable"),
        input_refs=("input:one",), parent_budget_lease_ref="budget:one", deadline_utc=10.0,
        monotonic_deadline=10.0, character_interval_ref="interval:one", causation=(),
    )


class PersonaDomainTests(unittest.TestCase):
    def test_type_specs_and_nonempty_plan_candidate_are_graph_coordinator_ready(self):
        domain = PersonaDomain()
        specs = domain.type_specs()
        self.assertEqual(tuple(spec.name for spec in specs), domain.register_types())
        self.assertTrue(all(spec.writer_domain == "d01" for spec in specs))
        registry = TypeRegistry()
        for spec in specs:
            registry.register(spec)

        write = domain.plan_write(plan())
        growth = GrowthProposal(
            "growth:persist", "plan:one@1", "honesty", "be candid with consent",
            ("family:one", "family:two"), True, "core",
        )
        revision = domain.activate_revision(plan(), growth)
        revision_write = domain.revision_write(plan().namespace, revision)
        growth_write = domain.growth_contribution_write(plan().namespace, growth)
        for candidate_write in (write, revision_write, growth_write):
            with self.subTest(type_name=candidate_write.key.type_name):
                registry.validate(candidate_write.key, candidate_write.value)
                with self.assertRaises(ValueError):
                    registry.validate(
                        candidate_write.key,
                        {**candidate_write.value, "shadow_identity": "forbidden"},
                    )
        with self.assertRaises(ValueError):
            registry.validate(
                revision_write.key,
                {**revision_write.value, "previous_head": ""},
            )
        with self.assertRaises(ValueError):
            registry.validate(
                AtomKey(Owner("event", "bot", "persona", "world:1"),
                        "d01.persona_plan.v1", "plan:one"),
                write.value,
            )

        d03 = AtomKey(Owner("persona", "bot", "persona"), "d03.entity_anchor", "self")
        d06 = AtomKey(Owner("event", "bot", "persona", "source:missing"),
                      "memory.source", "record")
        target = GraphVersion(write.key, 0)
        env = envelope()
        env = replace(env, version_guard=replace(
            env.version_guard,
            read_versions=(target, GraphVersion(d03, 3), GraphVersion(d06, 0)),
        ))
        dependencies = DependencySet(
            current_invalidation=(GraphVersion(d03, 3),),
            historical_provenance=(GraphVersion(d06, 0),),
        )
        proposal = domain.proposal_for(
            env,
            ("persona-plan:one",),
            typed_writes=(write,),
            dependencies=dependencies,
        )
        self.assertEqual(proposal.typed_writes, (write,))
        self.assertIs(domain.validate(proposal), proposal)

    def test_authored_plan_preserves_running_identity_and_separates_growth_policy(self):
        domain = PersonaDomain()
        compiled = domain.compile_scheme(plan())
        self.assertEqual(compiled.head_id, "plan:one@1")
        self.assertEqual(compiled.blocks[0].plasticity, "read_only")
        with self.assertRaises(ValueError):
            PersonaBlock("identity", "semantic_identity", "changed", "growth")

    def test_value_evaluation_returns_partial_order_and_does_not_grant_action_permission(self):
        view = PersonaDomain().project(plan(), context_tags=("private",))
        result = PersonaDomain().evaluate_values(
            view, {"kind_feedback": ("review",), "flatter": ("review",)}
        )
        self.assertEqual(result.preferred, ("kind_feedback",))
        self.assertEqual(result.rejected, ("flatter",))
        self.assertFalse(result.action_authorized)

    def test_core_growth_requires_two_independent_families_and_checked_counterevidence(self):
        domain = PersonaDomain()
        proposal = GrowthProposal(
            proposal_id="growth:one",
            base_head="plan:one@1",
            target_block="honesty",
            replacement_claim="be candid with consent",
            source_families=("family:one",),
            counterevidence_checked=True,
            change_kind="core",
        )
        with self.assertRaises(ValueError):
            domain.validate_growth(plan(), proposal)
        approved = GrowthProposal(
            proposal_id="growth:two",
            base_head="plan:one@1",
            target_block="honesty",
            replacement_claim="be candid with consent",
            source_families=("family:one", "family:two"),
            counterevidence_checked=True,
            change_kind="core",
        )
        revision = domain.activate_revision(plan(), approved)
        self.assertEqual(revision.continuity.previous_head, "plan:one@1")
        self.assertEqual(revision.continuity.retained_blocks, ("identity",))

    def test_growth_contribution_cannot_be_consumed_twice_or_from_simulated_evidence(self):
        domain = PersonaDomain()
        proposal = GrowthProposal(
            proposal_id="growth:three",
            base_head="plan:one@1",
            target_block="honesty",
            replacement_claim="be candid with consent",
            source_families=("family:one", "family:two"),
            counterevidence_checked=True,
            change_kind="core",
            evidence_reality="simulated",
        )
        with self.assertRaises(ValueError):
            domain.validate_growth(plan(), proposal)
        key = domain.contribution_key("honesty", "family:one", "core")
        self.assertTrue(domain.consume_contribution(key))
        self.assertFalse(domain.consume_contribution(key))

    def test_domain_candidate_uses_the_shared_envelope_and_does_not_claim_write_authority(self):
        domain = PersonaDomain()
        proposal = domain.proposal_for(envelope(), ("honesty|family:one|core",))
        self.assertEqual(proposal.domain, "d01")
        self.assertEqual(proposal.typed_writes, ())
        self.assertIs(domain.validate(proposal), proposal)


if __name__ == "__main__":
    unittest.main()
