import unittest

from sylanne3.domains.d03 import (
    AccountBinding,
    ContextProvider,
    EntityAnchor,
    RoleBinding,
    RoleBindingRequest,
    WorldEvent,
)
from sylanne3.graph_types import AtomKey, GraphVersion, GraphWrite, Owner, TypeRegistry
from sylanne3.runtime_contracts import (
    AuthorityContext,
    CommandEnvelope,
    DependencySet,
    DomainProposal,
    NamespaceId,
    OperationIdentity,
    QueryEpoch,
    SourceQualification,
    VersionGuard,
    canonical_digest,
)


def _proposal(domain):
    key = AtomKey(Owner("persona", "bot", "persona"), "state", "context")
    namespace = NamespaceId("bot", "persona")
    envelope = CommandEnvelope(
        schema="sylanne.runtime.v1",
        identity=OperationIdentity("activity:1", None, "attempt:1", "prepare", "operation:1",
                                   canonical_digest({"input_refs": ["source:1"]})),
        authority=AuthorityContext("host:user", "d11", "capability:1", namespace, ("persona",),
                                   "respond", ("user:1",), "policy:1", 1),
        version_guard=VersionGuard((GraphVersion(key, 0),), (QueryEpoch(namespace, "d03:scope", 0),),
                                   0, 0, "catalogue:1", "scheme:1", "operator:1", "policy:1", (), (), ()),
        source_qualification=SourceQualification(("source:1",), "observed", 1, 1,
                                                  "external_observation", "eligible", .5, "not_applicable"),
        input_refs=("source:1",), parent_budget_lease_ref="budget:1", deadline_utc=10,
        monotonic_deadline=10, character_interval_ref="clock:1", causation=(),
    )
    return DomainProposal(domain, f"{domain}.proposal.v1", canonical_digest({"domain": domain}), envelope,
                          (), DependencySet(), (), ())


class ContextDomainTests(unittest.TestCase):
    def test_type_specs_are_authorized_strict_and_preserve_unknown_event_time(self):
        provider = ContextProvider()
        specs = provider.type_specs()
        self.assertEqual(tuple(spec.name for spec in specs), provider.register_types())
        self.assertTrue(all(spec.writer_domain == "d03" for spec in specs))
        self.assertTrue(all(spec.schema_hash and len(spec.schema_hash) == 64 for spec in specs))

        registry = TypeRegistry()
        for spec in specs:
            registry.register(spec)
        entity_key = AtomKey(Owner("persona", "bot", "persona"), "d03.entity_anchor", "entity:alice")
        entity = {
            "entity_id": "entity:alice", "kind": "person", "owner_scope": "private",
            "creation_evidence_refs": ["source:1"], "status": "active",
        }
        self.assertEqual(registry.validate(entity_key, entity), entity)
        with self.assertRaises(ValueError):
            registry.validate(entity_key, {**entity, "unexpected": True})
        with self.assertRaises(ValueError):
            registry.validate(
                AtomKey(Owner("relation", "bot", "persona", "entity:alice"),
                        "d03.entity_anchor", "entity:alice"),
                entity,
            )

        event_key = AtomKey(Owner("event", "bot", "persona", "world:unknown-time"),
                            "d03.world_event", "current")
        unknown_time = {
            "event_id": "world:unknown-time", "kind": "reported_event",
            "participant_roles": [["entity:alice", "reporter"]],
            "occurred_from": None, "occurred_until": None, "learned_at": 4.0,
            "scene_ref": "scene:private", "source_refs": ["source:1"], "reality": "reported",
        }
        registry.validate(event_key, unknown_time)

        cases = (
            (
                AtomKey(Owner("persona", "bot", "persona"),
                        "d03.account_binding", "account:alice"),
                {
                    "account_id": "account:alice", "platform_namespace": "chat.example",
                    "platform_identifier": "42", "entity_id": "entity:alice",
                    "verification_ref": "source:host", "valid_from": 1.0,
                    "valid_until": None,
                },
            ),
            (event_key, unknown_time),
            (
                AtomKey(Owner("scene", "bot", "persona", "scene:project"),
                        "d03.role_binding", "binding:project"),
                {
                    "role_binding_id": "binding:project",
                    "subject_persona_ref": "persona:sylanne", "social_role": "collaborator",
                    "target_entity_ref": "entity:alice", "group_ref": None,
                    "scene_ref": "scene:project", "scope_selector": "scene",
                    "visibility_scope": "project", "norm_refs": ["norm:project"],
                    "effective_from": 1.0, "effective_until": None, "precedence": 10,
                    "source_refs": ["source:role"], "binding_version": 1, "status": "active",
                },
            ),
        )
        for key, value in cases:
            with self.subTest(type_name=key.type_name):
                registry.validate(key, value)
                with self.assertRaises(ValueError):
                    registry.validate(key, {**value, "unexpected": True})

    def test_account_identity_and_social_role_are_separate(self):
        account = AccountBinding(
            account_id="account:alice",
            platform_namespace="chat.example",
            platform_identifier="42",
            entity_id="entity:alice",
            verification_ref="source:host-1",
            valid_from=1.0,
            valid_until=None,
        )
        self.assertEqual(account.entity_id, "entity:alice")
        with self.assertRaises(ValueError):
            RoleBinding(
                role_binding_id="binding:global",
                subject_persona_ref="persona:sylanne",
                social_role="friend",
                target_entity_ref=None,
                group_ref=None,
                scene_ref=None,
                scope_selector="all",
                visibility_scope="private",
                norm_refs=("norm:care:1",),
                effective_from=1.0,
                effective_until=None,
                precedence=1,
                source_refs=("source:role-1",),
                binding_version=1,
                status="active",
            )

    def test_world_event_is_not_an_execution_or_source_identity(self):
        event = WorldEvent(
            event_id="world:arrival-1",
            kind="message_arrival",
            participant_roles=(("entity:alice", "speaker"),),
            occurred_from=10.0,
            occurred_until=10.0,
            learned_at=11.0,
            scene_ref="scene:private-1",
            source_refs=("source:inbound-1",),
            reality="host_observed",
        )
        self.assertEqual(event.event_id, "world:arrival-1")
        with self.assertRaises(ValueError):
            WorldEvent(
                event_id="source:inbound-1",
                kind="message_arrival",
                participant_roles=(("entity:alice", "speaker"),),
                occurred_from=10.0,
                occurred_until=10.0,
                learned_at=11.0,
                scene_ref="scene:private-1",
                source_refs=("source:inbound-1",),
                reality="host_observed",
            )

    def test_role_resolution_requires_scope_and_returns_no_binding_only_for_complete_scope(self):
        provider = ContextProvider()
        provider.compile_scheme(
            {
                "schema": "d03.context.scheme.v1",
                "roles": ("friend", "collaborator"),
                "norms": ("norm:care:1", "norm:project:1"),
            },
            snapshot=None,
        )
        binding = RoleBinding(
            role_binding_id="binding:project",
            subject_persona_ref="persona:sylanne",
            social_role="collaborator",
            target_entity_ref="entity:alice",
            group_ref=None,
            scene_ref="scene:project",
            scope_selector="scene",
            visibility_scope="project",
            norm_refs=("norm:project:1",),
            effective_from=1.0,
            effective_until=None,
            precedence=10,
            source_refs=("source:role-1",),
            binding_version=2,
            status="active",
        )
        request = RoleBindingRequest(
            subject_persona_ref="persona:sylanne",
            target_entity_ref="entity:alice",
            group_ref=None,
            scene_ref="scene:project",
            requested_action_kind="coordinate",
            purpose="respond",
            at_time=5.0,
            scope_complete=True,
        )
        result = provider.resolve_role_binding(request, (binding,))
        self.assertEqual(result.status, "complete")
        self.assertEqual(result.matched_bindings, ("binding:project",))
        self.assertEqual(result.applicable_norm_refs, ("norm:project:1",))
        incomplete = provider.resolve_role_binding(
            RoleBindingRequest(**{**request.__dict__, "scope_complete": False}),
            (),
        )
        self.assertEqual(incomplete.status, "partial")
        self.assertNotEqual(incomplete.status, "no_applicable_binding")

    def test_scheme_rejects_unknown_roles_and_entity_requires_stable_evidence(self):
        provider = ContextProvider()
        with self.assertRaises(ValueError):
            provider.compile_scheme(
                {"schema": "d03.context.scheme.v1", "roles": ("friend", "friend"), "norms": ()},
                snapshot=None,
            )
        with self.assertRaises(ValueError):
            EntityAnchor(
                entity_id="entity:alice",
                kind="person",
                owner_scope="public",
                creation_evidence_refs=(),
                status="active",
            )

    def test_provider_accepts_only_d03_typed_candidates(self):
        provider = ContextProvider()
        self.assertTrue(hasattr(provider, "descriptor"))
        self.assertEqual(provider.validate(_proposal("d03"), snapshot=None).domain, "d03")
        with self.assertRaises(ValueError):
            provider.validate(_proposal("d05"), snapshot=None)

    def test_provider_rejects_a_foreign_graph_write_type(self):
        proposal = _proposal("d03")
        bad_write = GraphWrite(
            AtomKey(Owner("relation", "bot", "persona", "entity:alice"), "d05.boundary_rule", "current"),
            {"rule_id": "boundary:no-contact"},
        )
        proposal = DomainProposal(proposal.domain, proposal.proposal_schema, proposal.proposal_schema_hash,
                                  proposal.envelope, (bad_write,), proposal.dependencies, (), ())
        with self.assertRaises(ValueError):
            ContextProvider().validate(proposal, snapshot=None)

    def test_provider_rejects_malformed_own_graph_payload(self):
        proposal = _proposal("d03")
        write = GraphWrite(
            AtomKey(Owner("persona", "bot", "persona"), "d03.entity_anchor", "entity:alice"),
            {"entity_id": "entity:alice"},
        )
        proposal = DomainProposal(proposal.domain, proposal.proposal_schema, proposal.proposal_schema_hash,
                                  proposal.envelope, (write,), proposal.dependencies, (), ())
        with self.assertRaises(TypeError):
            ContextProvider().validate(proposal, snapshot=None)


if __name__ == "__main__":
    unittest.main()
