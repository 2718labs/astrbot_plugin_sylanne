import unittest

from sylanne3.domains.d05 import (
    BoundaryRule,
    RelationshipContribution,
    RelationshipProvider,
)
from sylanne3.graph_types import AtomKey, GraphVersion, GraphWrite, Owner, TypeRegistry
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, DomainProposal, NamespaceId,
    OperationIdentity, QueryEpoch, SourceQualification, VersionGuard, canonical_digest,
)


def _proposal(domain):
    key = AtomKey(Owner("relation", "bot", "persona", "entity:alice"), "state", "relationship")
    namespace = NamespaceId("bot", "persona")
    envelope = CommandEnvelope(
        "sylanne.runtime.v1", OperationIdentity("activity:1", None, "attempt:1", "prepare", "operation:1",
        canonical_digest({"input_refs": ["source:1"]})),
        AuthorityContext("host:user", "d11", "capability:1", namespace, ("relation",), "respond",
                         ("user:1",), "policy:1", 1),
        VersionGuard((GraphVersion(key, 0),), (QueryEpoch(namespace, "d05:scope", 0),), 0, 0,
                     "catalogue:1", "scheme:1", "operator:1", "policy:1", (), (), ()),
        SourceQualification(("source:1",), "observed", 1, 1, "external_observation", "eligible", .5,
                            "not_applicable"),
        ("source:1",), "budget:1", 10, 10, "clock:1", (),
    )
    return DomainProposal(domain, f"{domain}.proposal.v1", canonical_digest({"domain": domain}), envelope,
                          (), DependencySet(), (), ())


class RelationshipDomainTests(unittest.TestCase):
    def test_type_specs_are_authorized_and_reject_invalid_payload_or_owner(self):
        provider = RelationshipProvider()
        specs = provider.type_specs()
        self.assertEqual(tuple(spec.name for spec in specs), provider.register_types())
        self.assertTrue(all(spec.writer_domain == "d05" for spec in specs))
        self.assertTrue(all(spec.schema_hash and len(spec.schema_hash) == 64 for spec in specs))
        registry = TypeRegistry()
        for spec in specs:
            registry.register(spec)

        key = AtomKey(Owner("relation", "bot", "persona", "entity:alice"),
                      "d05.contribution", "contribution:1")
        value = {
            "owner_persona_ref": "persona:sylanne",
            "canonical_event_or_family_ref": "event:arrival-1",
            "subject_entity_ref": "entity:alice",
            "target_dimension": "reliability:project",
            "semantics": "external_observation",
            "contribution_revision": 1,
            "source_refs": ["source:1"],
        }
        registry.validate(key, value)
        with self.assertRaises(ValueError):
            registry.validate(key, {**value, "unexpected": "shadow-score"})
        with self.assertRaises(ValueError):
            registry.validate(
                AtomKey(Owner("event", "bot", "persona", "event:arrival-1"),
                        "d05.contribution", "contribution:1"),
                value,
            )

        cases = (
            (
                AtomKey(Owner("relation", "bot", "persona", "entity:alice"),
                        "d05.boundary_rule", "boundary:no-contact"),
                {
                    "rule_id": "boundary:no-contact", "subject_persona_ref": "persona:sylanne",
                    "target_entity_ref": "entity:alice", "action_kind": "contact",
                    "audience_scope": "direct", "scene_ref": None, "effect": "deny",
                    "basis": "counterparty_explicit", "source_refs": ["source:1"],
                    "communicated_refs": [], "acknowledged_refs": [], "valid_from": 1.0,
                    "valid_until": None, "scope_version": 1, "revision_actor": "entity:alice",
                    "exception_refs": [], "status": "active",
                },
            ),
            (
                AtomKey(Owner("relation", "bot", "persona", "entity:alice"),
                        "d05.relationship_projection", "current"),
                {"subject_entity_ref": "entity:alice", "dimension": "reliability:project",
                 "status": "unknown"},
            ),
        )
        for graph_key, payload in cases:
            with self.subTest(type_name=graph_key.type_name):
                registry.validate(graph_key, payload)
                with self.assertRaises(ValueError):
                    registry.validate(graph_key, {**payload, "unexpected": True})

    def test_contribution_key_is_directed_and_deduplicates_same_event_dimension(self):
        left = RelationshipContribution(
            owner_persona_ref="persona:sylanne",
            canonical_event_or_family_ref="event:arrival-1",
            subject_entity_ref="entity:alice",
            target_dimension="reliability:project",
            semantics="external_observation",
            contribution_revision=1,
            source_refs=("source:inbound-1",),
        )
        right = RelationshipContribution(
            owner_persona_ref="persona:sylanne",
            canonical_event_or_family_ref="event:arrival-1",
            subject_entity_ref="entity:bob",
            target_dimension="reliability:project",
            semantics="external_observation",
            contribution_revision=1,
            source_refs=("source:inbound-1",),
        )
        self.assertNotEqual(left.key, right.key)
        self.assertEqual(left.key, left.with_revision(2).key)

    def test_explicit_no_contact_boundary_denies_action_and_affinity_cannot_override_it(self):
        provider = RelationshipProvider()
        rule = BoundaryRule(
            rule_id="boundary:no-contact",
            subject_persona_ref="persona:sylanne",
            target_entity_ref="entity:alice",
            action_kind="contact",
            audience_scope="direct",
            scene_ref=None,
            effect="deny",
            basis="counterparty_explicit",
            source_refs=("source:alice-no-contact",),
            communicated_refs=("receipt:delivered",),
            acknowledged_refs=(),
            valid_from=1.0,
            valid_until=None,
            scope_version=3,
            revision_actor="entity:alice",
            exception_refs=(),
            status="active",
        )
        check = provider.provide_required_check(
            subject_persona_ref="persona:sylanne",
            target_entity_ref="entity:alice",
            action_kind="contact",
            audience_scope="direct",
            scene_ref=None,
            at_time=5.0,
            rules=(rule,),
            coverage_complete=True,
        )
        self.assertEqual(check.result, "deny")
        self.assertEqual(check.matched_rule_ids, ("boundary:no-contact",))

    def test_missing_boundary_coverage_is_unknown_not_pass(self):
        check = RelationshipProvider().provide_required_check(
            subject_persona_ref="persona:sylanne",
            target_entity_ref="entity:alice",
            action_kind="contact",
            audience_scope="direct",
            scene_ref=None,
            at_time=5.0,
            rules=(),
            coverage_complete=False,
        )
        self.assertEqual(check.result, "unknown")

    def test_scheme_rejects_unregistered_dimension_and_invalidation_preserves_history_reference(self):
        provider = RelationshipProvider()
        provider.compile_scheme(
            {
                "schema": "d05.relationship.scheme.v1",
                "dimensions": ("reliability:project", "comfort:direct"),
                "contribution_semantics": ("external_observation", "recollection", "simulation"),
            },
            snapshot=None,
        )
        with self.assertRaises(ValueError):
            provider.validate_dimension("reliability:medical")
        invalidation = provider.invalidate(("source:bad-1", "event:arrival-1"))
        self.assertEqual(invalidation.current_status, "blocked_rebuild")
        self.assertEqual(invalidation.historical_refs, ("event:arrival-1", "source:bad-1"))

    def test_provider_accepts_only_d05_typed_candidates(self):
        provider = RelationshipProvider()
        self.assertTrue(hasattr(provider, "descriptor"))
        self.assertEqual(provider.validate(_proposal("d05"), snapshot=None).domain, "d05")
        with self.assertRaises(ValueError):
            provider.validate(_proposal("d03"), snapshot=None)

    def test_provider_rejects_a_foreign_graph_write_type(self):
        proposal = _proposal("d05")
        bad_write = GraphWrite(
            AtomKey(Owner("scene", "bot", "persona", "scene:project"), "d03.role_binding", "current"),
            {"role_binding_id": "binding:project"},
        )
        proposal = DomainProposal(proposal.domain, proposal.proposal_schema, proposal.proposal_schema_hash,
                                  proposal.envelope, (bad_write,), proposal.dependencies, (), ())
        with self.assertRaises(ValueError):
            RelationshipProvider().validate(proposal, snapshot=None)

    def test_provider_rejects_malformed_own_graph_payload(self):
        proposal = _proposal("d05")
        write = GraphWrite(
            AtomKey(Owner("relation", "bot", "persona", "entity:alice"), "d05.boundary_rule", "current"),
            {"rule_id": "boundary:no-contact"},
        )
        proposal = DomainProposal(proposal.domain, proposal.proposal_schema, proposal.proposal_schema_hash,
                                  proposal.envelope, (write,), proposal.dependencies, (), ())
        with self.assertRaises(TypeError):
            RelationshipProvider().validate(proposal, snapshot=None)


if __name__ == "__main__":
    unittest.main()
