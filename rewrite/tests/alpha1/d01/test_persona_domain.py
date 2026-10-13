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
        self.assertTrue(domain.consume_contribution(key, ()))
        self.assertFalse(domain.consume_contribution(key, (key,)))

    def test_domain_candidate_uses_the_shared_envelope_and_does_not_claim_write_authority(self):
        domain = PersonaDomain()
        proposal = domain.proposal_for(envelope(), ("honesty|family:one|core",))
        self.assertEqual(proposal.domain, "d01")
        self.assertEqual(proposal.typed_writes, ())
        self.assertIs(domain.validate(proposal), proposal)


if __name__ == "__main__":
    unittest.main()


def test_registered_method_policy_changes_choice_without_changing_values_or_hard_eligibility():
    from sylanne3.domains.d01 import (method_policy_state_v1, method_preference_edges_v1,
        FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1)
    from sylanne3.domains.d07 import METHOD_CONDITION_IDS_V1
    from sylanne3.domains.d08.personal_plan_v1 import QualifiedPersonalCandidateV1, select_personal_step_v2
    from sylanne3.memory_types import source_key
    mapping = (("candidate:full", FULL_DRAFT_METHOD_V1), ("candidate:sample", TONE_SAMPLE_METHOD_V1))
    conditions = tuple((name, index < 6) for index, name in enumerate(METHOD_CONDITION_IDS_V1))
    full = QualifiedPersonalCandidateV1("candidate:full", "action:full", "task:full", "a" * 64,
        "eligible", 1, True, None, "quote:full")
    sample = replace(full, candidate_ref="candidate:sample", action_ref="action:sample", node_id="task:sample",
        semantic_digest="b" * 64, quote_ref="quote:sample")
    kwargs = dict(decision_id="decision:method", candidates=(sample, full),
        source_refs=(source_key("bot", "persona", "method-contract").token,), read_versions=())
    actual_plan = plan()
    view = PersonaDomain().project(actual_plan, context_tags=(), role_binding_complete=False)
    before = PersonaDomain().evaluate_values(view, {ref: () for ref, _ in mapping})
    for state, expected in (("ST0", "action:full"), ("ST2", "action:sample")):
        claim = '{"schema":"d01.method-policy.v1","policy_id":"CP-tone-order","strategy_state":"' + state + '"}'
        policy = method_policy_state_v1(claim)
        scope, edges = method_preference_edges_v1(policy, mapping, conditions, complete=True)
        assert scope == "applicable"
        assert select_personal_step_v2(preference_edges=edges, **kwargs).chosen_action_ref == expected
        assert PersonaDomain().evaluate_values(view, {ref: () for ref, _ in mapping}) == before
    assert before.action_authorized is False and not before.rejected
    _, edges = method_preference_edges_v1("ST2", mapping, conditions, complete=True)
    blocked = select_personal_step_v2(preference_edges=edges,
        **{**kwargs, "candidates": (replace(sample, hard_status="WAIT_BUDGET"), full)})
    assert blocked.chosen_action_ref == "action:full"


def test_method_policy_exclusions_missing_facts_and_conflict_do_not_manufacture_strategy():
    from sylanne3.domains.d01 import (method_policy_state_v1, method_preference_edges_v1,
        FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1)
    from sylanne3.domains.d07 import METHOD_CONDITION_IDS_V1
    mapping = (("candidate:full", FULL_DRAFT_METHOD_V1), ("candidate:sample", TONE_SAMPLE_METHOD_V1))
    values = {name: index < 6 for index, name in enumerate(METHOD_CONDITION_IDS_V1)}
    for excluded in ("short_draft", "immediate_full_draft"):
        conditions = tuple({**values, excluded: True}.items())
        for state in ("ST0", "ST2"):
            assert method_preference_edges_v1(state, mapping, conditions, complete=True) == (
                "excluded", (("candidate:full", "candidate:sample"),))
    for conditions, complete in ((tuple(values.items()), False),
            (tuple({**values, "fact_permission_gap": True}.items()), True),
            (tuple((key, value) for key, value in values.items() if key != "materials_complete"), True)):
        assert method_preference_edges_v1("ST2", mapping, conditions, complete=complete) == ("unknown", ())
    for claim in ("try a tone sample first", '{"schema":"old","policy_id":"CP-tone-order","strategy_state":"ST2"}',
            '{"schema":"d01.method-policy.v1","policy_id":"CP-tone-order","strategy_state":true}'):
        assert method_policy_state_v1(claim) is None


def test_method_condition_scope_is_canonical_goal_revision_not_free_text():
    import json
    from sylanne3.domains.d07 import method_condition_question_v1, decode_method_condition_question_v1
    key = AtomKey(Owner("activity", "bot", "persona", "activity:method"), "d08.goal.v1", "goal:method")
    question = method_condition_question_v1(key.token, 2, "tone_multiple_legal_readings")
    scope = decode_method_condition_question_v1(question)
    assert scope["goal_ref"] == key.token and scope["goal_revision"] == 2
    assert decode_method_condition_question_v1(json.dumps(scope, indent=2)) is None
    assert decode_method_condition_question_v1("tone has several readings") is None
    assert decode_method_condition_question_v1(question) != decode_method_condition_question_v1(
        method_condition_question_v1(key.token, 3, "tone_multiple_legal_readings"))


def _semantic_migration_fixture_v3():
    from sylanne3.domains.d01.identity_v3 import RuntimeIdentityRef, SemanticIdentityRevision
    from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    original=plan();guard=OwnerAuthorizationGuardV1("authority","installation",original.namespace,1,"sha256:"+"b"*64,0,0)
    stable=RuntimeIdentityRef.from_owner_guard(original.namespace,guard)
    head=GraphVersion(PersonaDomain.plan_write(original).key,1)
    value=SemanticIdentityRevision(stable,"identity",1,original.blocks[0].claim,None,head,head,
        canonical_digest(original.blocks[0].claim),(),None,None,(),None,None,(),(),(),1.0,None,"legacy_migration")
    return original,guard,value


def test_semantic_v3_legacy_migration_codec_preserves_runtime_id_claim_and_outer_schema():
    from sylanne3.domains.d01.identity_v3 import RuntimeIdentityRef, encode_semantic_identity_v3, decode_semantic_identity_v3
    from dataclasses import fields
    original,guard,payload=_semantic_migration_fixture_v3()
    encoded=encode_semantic_identity_v3(payload)
    assert decode_semantic_identity_v3(encoded)==payload
    block=PersonaBlock("identity","semantic_identity",encoded,"read_only")
    migrated=replace(original,version=2,blocks=(block,original.blocks[1]))
    assert RuntimeIdentityRef.from_owner_guard(migrated.namespace,replace(guard,authorization_revision=2,authorization_head="sha256:"+"c"*64))==payload.runtime_identity
    projected=PersonaDomain().project(migrated)
    assert projected.blocks[0].claim==original.blocks[0].claim and projected.blocks[0].plasticity=="read_only"
    assert tuple(field.name for field in fields(PersonaBlock))==("block_id","kind","claim","plasticity")
    assert PersonaDomain.plan_write(migrated).key==PersonaDomain.plan_write(original).key
    assert payload.support_original_refs==payload.trial_original_refs==() and payload.cumulative_diff==()


def test_semantic_v3_declared_invalid_claim_and_two_family_boolean_growth_are_rejected():
    from types import SimpleNamespace
    from sylanne3.domains.d01.identity_v3 import encode_semantic_identity_v3, decode_semantic_identity_v3
    original,_,payload=_semantic_migration_fixture_v3()
    with unittest.TestCase().assertRaises(ValueError):PersonaBlock("identity","semantic_identity","old claim","growth")
    with unittest.TestCase().assertRaises(ValueError):decode_semantic_identity_v3('{"schema":"d01.semantic-identity-revision.v3"')
    from sylanne3.runtime.domain_production_erasure_v1 import DomainProductionErasureHold
    with unittest.TestCase().assertRaises(DomainProductionErasureHold):decode_semantic_identity_v3('{"schema":"d01.semantic-identity-revision.v3"}')
    encoded=encode_semantic_identity_v3(replace(payload,plasticity_policy_ref="policy:explicit",plasticity_policy_digest="a"*64))
    grown_plan=replace(original,version=2,blocks=(PersonaBlock("identity","semantic_identity",encoded,"growth"),original.blocks[1]))
    proposal=GrowthProposal("growth:deep",grown_plan.head_id,"identity","new self claim",("family:one","family:two"),True,"core")
    with unittest.TestCase().assertRaises(ValueError):PersonaDomain().activate_revision(grown_plan,proposal)
    with unittest.TestCase().assertRaises(ValueError):PersonaDomain().activate_revision(grown_plan,proposal,semantic_qualification=SimpleNamespace(
        base_head=grown_plan.head_id,target_block="identity",replacement_claim=proposal.replacement_claim))
    with unittest.TestCase().assertRaises(ValueError):PersonaDomain().activate_revision(grown_plan,replace(proposal,change_kind="local"))


def test_semantic_v3_erasure_traces_references_inside_canonical_claim_and_bounds_bytes():
    from sylanne3.domains.d01.identity_v3 import encode_semantic_identity_v3, decode_semantic_identity_v3
    from sylanne3.runtime.domain_production_erasure_v1 import _references
    from sylanne3.memory_types import source_key
    original,_,payload=_semantic_migration_fixture_v3()
    ref=source_key(*original.namespace.as_tuple,"actual-support").token
    # Controlled codec fixture, not an adopted growth or authenticated Source.
    administrative=replace(payload,revision_kind="administrative",support_original_refs=(ref,))
    encoded=encode_semantic_identity_v3(administrative)
    assert ref in set(_references(encoded))
    with unittest.TestCase().assertRaises(ValueError):decode_semantic_identity_v3("x"*65537)
    with unittest.TestCase().assertRaises(ValueError):encode_semantic_identity_v3(replace(payload,claim="x"*65537))


def test_semantic_v3_initial_history_is_rejected_and_adoption_window_is_not_readout_ttl():
    from sylanne3.domains.d01.identity_v3 import encode_semantic_identity_v3
    from sylanne3.domains.d01.production_operations_v1 import SemanticCounterScopeV3
    from sylanne3.runtime.domain_production_contracts_v1 import ProductionQueryCoverageV1
    from sylanne3.runtime_contracts import QueryEpoch
    from sylanne3.runtime.d01_production_operations_v1 import semantic_counter_binding_v3
    original,_,payload=_semantic_migration_fixture_v3()
    block=PersonaBlock("identity","semantic_identity",encode_semantic_identity_v3(payload),"read_only")
    with unittest.TestCase().assertRaises(ValueError):replace(original,blocks=(block,original.blocks[1]))
    assert payload.valid_until is None and payload.adopt_before is None
    first=SemanticCounterScopeV3("d01.growth:identity:core",ProductionQueryCoverageV1(
        QueryEpoch(original.namespace,"namespace",1),"d07.current_interpretation.v1",(),True,None),(),(),(),"qualified")
    second=replace(first,coverage=replace(first.coverage,epoch=QueryEpoch(original.namespace,"namespace",2)))
    assert semantic_counter_binding_v3(first)==semantic_counter_binding_v3(second)
    assert not replace(first,qualification="unknown").complete
    assert not replace(first,qualification="opposition").complete
