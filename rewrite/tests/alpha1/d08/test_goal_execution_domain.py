from dataclasses import replace
import unittest

from sylanne3.domains.d08 import (
    ActionIntent,
    ActionOutcome,
    ActionSchema,
    Commitment,
    CommunicationGrantRequest,
    CommunicationIntentGrant,
    CommunicationSegmentSpec,
    CommitmentConflictSnapshot,
    Goal,
    GoalExecutionProvider,
    GoalPredicate,
    JointPlan,
    JointPlanAcceptance,
    OutcomeSettlement,
    PlanNode,
    RepairIntent,
    RequiredCheckRegistry,
    RequiredCheckSpec,
)
from sylanne3.graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from sylanne3.runtime_contracts import (
    AuthorityContext,
    CheckReceipt,
    CommandEnvelope,
    DependencySet,
    DomainProposal,
    NamespaceId,
    OperationIdentity,
    QueryEpoch,
    SourceQualification,
    VersionGuard,
    VersionedRef,
    canonical_digest,
    schema_hash,
)
from sylanne3.domains.d09 import (
    AdmissionReceipt,
    ClaimKind,
    ClaimUse,
    D09ExpressionProvider,
    ExpressionClaim,
    SegmentCandidate,
    segment_payload_digest,
)


def _identity(*, effect_id="effect:share-1", attempt_id="attempt:1"):
    return OperationIdentity(
        "activity:share", effect_id, attempt_id, "prepare", "operation:share-1",
        canonical_digest({"input_refs": ["source:request-1"]}),
    )


def _spec(kind, provider, *, version_ref=None, action_ref="action:share-1"):
    versions = (VersionedRef("criteria:1", 1),)
    if version_ref is not None:
        versions += (VersionedRef(version_ref, 1),)
    return RequiredCheckSpec(
        check_kind=kind,
        provider_id=provider,
        subject_ref="persona:sylanne",
        action_ref=action_ref,
        purpose="respond",
        criteria_version="criteria:1",
        required_input_versions=versions,
    )


def _receipt(spec, *, result="pass", coverage="full", valid_until=50.0, versions=None):
    return CheckReceipt(
        spec.check_kind,
        spec.subject_ref,
        spec.action_ref,
        spec.purpose,
        spec.required_input_versions if versions is None else versions,
        coverage,
        result,
        valid_until,
        spec.provider_id,
    )


def _schema(*, proactive=False, action_ref="action:share-1"):
    base = (
        _spec("role_binding", "d03.role_binding", version_ref="binding:1", action_ref=action_ref),
        _spec("boundary", "d05.boundary", version_ref="boundary:1", action_ref=action_ref),
        _spec("source_grant", "d06.source_grant", version_ref="grant:1", action_ref=action_ref),
        _spec("commitment_conflict", "d08.commitment_conflict", version_ref="commitments:1", action_ref=action_ref),
        _spec("dispatch_budget", "d11.dispatch_budget", version_ref="budget:1", action_ref=action_ref),
    )
    if proactive:
        base += (_spec("contact_policy", "d10.contact_policy", version_ref="contact-policy:1", action_ref=action_ref),)
    return ActionSchema("action.schema.message.v1", "message", proactive, base)


def _intent(schema=None, *, action_id="action:share-1", effect_id="effect:share-1", attempt_id="attempt:1"):
    schema = schema or _schema(action_ref=action_id)
    return ActionIntent(
        action_id=action_id,
        revision=1,
        goal_ref="goal:share-art",
        commitment_refs=("commitment:show-art",),
        target_ref="entity:alice",
        action_kind="message",
        purpose="respond",
        risk_class="reversible",
        parameters_digest=canonical_digest({"target": "entity:alice", "artifact": "artifact:sketch"}),
        identity=_identity(effect_id=effect_id, attempt_id=attempt_id),
        schema_id=schema.schema_id,
        required_checks=schema.required_checks,
        success_predicate=GoalPredicate(
            "communicated", "d11.delivery", (("effect", effect_id),), 0.0, None
        ),
        effect_scope=("message:entity:alice",),
        compensation_ref="repair:clarify",
        source_refs=("source:request-1",),
    )


def _proposal(domain="d08", writes=()):
    key = AtomKey(Owner("activity", "bot", "persona", "activity:share"), "state", "d08")
    namespace = NamespaceId("bot", "persona")
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        _identity(effect_id=None),
        AuthorityContext(
            "host:user", "d08", "capability:d08", namespace, ("activity",), "respond",
            ("entity:alice",), "policy:1", 1,
        ),
        VersionGuard(
            (GraphVersion(key, 0),), (QueryEpoch(namespace, "d08:commitments", 0),), 0, 0,
            "catalogue:1", "scheme:1", "operator:1", "policy:1", (), (), (),
        ),
        SourceQualification(
            ("source:request-1",), "observed", 1, 1, "external_observation", "eligible", 1.0,
            "not_applicable",
        ),
        ("source:request-1",), "budget:1", 10, 10, "clock:1", (),
    )
    return DomainProposal(
        domain, f"{domain}.proposal.v1", schema_hash({"domain": domain, "proposal": 1}), envelope,
        writes, DependencySet(), (), (),
    )


class GoalExecutionDomainTests(unittest.TestCase):
    def test_goal_commitment_and_joint_plan_keep_distinct_lifecycles(self):
        predicate = GoalPredicate(
            "artifact_verified", "d10.activity", (("artifact", "artifact:sketch"),), 0.0, None
        )
        goal = Goal(
            "goal:share-art", 1, "active", predicate, ("value:creativity",), (),
            "deadline:tomorrow", ("condition:no-consent",), (),
        )
        commitment = Commitment(
            "commitment:show-art", 1, "persona:sylanne", "entity:alice", "show artifact:sketch",
            "unilateral", "communicated", "pending", "deadline:tomorrow",
            ("receipt:message-1",), (), None, ("source:promise-1",),
        )
        plan = JointPlan(
            "plan:show-art", 2,
            (JointPlanAcceptance("persona:sylanne", 2, ("task:prepare",), ("source:self-accept",)),),
            (PlanNode("task:prepare", "persona:sylanne", (), "prepare_artifact", predicate, True,
                      "repair:restore-draft", "resource:creative"),),
            ("exit:renegotiate",), ("source:plan-2",),
        )
        self.assertEqual(goal.state, "active")
        self.assertEqual(commitment.fulfillment_state, "pending")
        self.assertEqual(plan.acceptances[0].accepted_scope, ("task:prepare",))
        with self.assertRaises(ValueError):
            Goal(**{**goal.__dict__, "state": "fulfilled"})

    def test_action_schema_cannot_remove_the_five_base_providers(self):
        registry = RequiredCheckRegistry()
        registry.register(_schema())
        incomplete = ActionSchema(
            "action.schema.bad.v1", "message", False,
            tuple(spec for spec in _schema().required_checks if spec.provider_id != "d05.boundary"),
        )
        with self.assertRaises(ValueError):
            registry.register(incomplete)
        with self.assertRaises(ValueError):
            RequiredCheckSpec(
                "boundary", "d05.boundary", "persona:sylanne", "action:share-1", "respond",
                "criteria:1", (VersionedRef("boundary:1", 1),),
            )

    def test_proactive_action_requires_contact_policy_in_addition_to_base_checks(self):
        registry = RequiredCheckRegistry()
        without_contact = ActionSchema("action.schema.proactive.bad.v1", "message", True, _schema().required_checks)
        with self.assertRaises(ValueError):
            registry.register(without_contact)
        registry.register(_schema(proactive=True))

    def test_missing_or_partial_required_check_fails_closed(self):
        registry = RequiredCheckRegistry()
        schema = _schema()
        registry.register(schema)
        receipts = tuple(_receipt(spec) for spec in schema.required_checks[:-1])
        decision = registry.qualify(_intent(schema), receipts, now=5.0)
        self.assertEqual(decision.status, "unavailable")
        self.assertEqual(decision.missing_check_kinds, ("dispatch_budget",))

        partial_spec = schema.required_checks[0]
        partial = _receipt(partial_spec, result="unknown", coverage="partial")
        receipts = (partial,) + tuple(_receipt(spec) for spec in schema.required_checks[1:])
        decision = registry.qualify(_intent(schema), receipts, now=5.0)
        self.assertEqual(decision.status, "unavailable")
        self.assertEqual(decision.incomplete_check_kinds, ("role_binding",))

    def test_d08_commitment_check_requires_a_complete_conflict_snapshot(self):
        provider = GoalExecutionProvider()
        intent = _intent()
        spec = next(item for item in intent.required_checks if item.provider_id == "d08.commitment_conflict")
        partial = provider.provide_required_check(
            intent,
            CommitmentConflictSnapshot(spec.required_input_versions, "partial", (), (), ("query:gap",)),
            valid_until=20.0,
        )
        self.assertEqual((partial.result, partial.coverage), ("unknown", "partial"))
        conflict = provider.provide_required_check(
            intent,
            CommitmentConflictSnapshot(
                spec.required_input_versions, "full", intent.commitment_refs,
                ("commitment:conflicting",), (),
            ),
            valid_until=20.0,
        )
        self.assertEqual(conflict.result, "fail")
        clear = provider.provide_required_check(
            intent,
            CommitmentConflictSnapshot(
                spec.required_input_versions, "full", intent.commitment_refs, (), (),
            ),
            valid_until=20.0,
        )
        self.assertEqual((clear.result, clear.coverage), ("pass", "full"))

    def test_version_mismatch_and_expiry_do_not_produce_qualification(self):
        registry = RequiredCheckRegistry()
        schema = _schema()
        registry.register(schema)
        stale_version = _receipt(
            schema.required_checks[0], versions=(VersionedRef("binding:1", 0),)
        )
        receipts = (stale_version,) + tuple(_receipt(spec) for spec in schema.required_checks[1:])
        self.assertEqual(registry.qualify(_intent(schema), receipts, now=5.0).status, "stale")

        expired = _receipt(schema.required_checks[0], valid_until=4.0)
        receipts = (expired,) + tuple(_receipt(spec) for spec in schema.required_checks[1:])
        self.assertEqual(registry.qualify(_intent(schema), receipts, now=5.0).status, "stale")

    def test_correction_invalidates_an_old_qualification_token(self):
        registry = RequiredCheckRegistry()
        schema = _schema()
        registry.register(schema)
        receipts = tuple(_receipt(spec) for spec in schema.required_checks)
        decision = registry.qualify(_intent(schema), receipts, now=5.0)
        self.assertEqual(decision.status, "qualified")
        self.assertTrue(registry.is_current(decision, now=6.0))
        registry.invalidate(("boundary:1",))
        self.assertFalse(registry.is_current(decision, now=6.0))

    def test_attempt_change_cannot_change_effect_or_frozen_parameters(self):
        original = _intent()
        followup = _intent(attempt_id="attempt:2")
        original.assert_retry_compatible(followup)
        with self.assertRaises(ValueError):
            original.assert_retry_compatible(_intent(effect_id="effect:other", attempt_id="attempt:2"))

    def test_outcome_settlement_does_not_upgrade_platform_acceptance(self):
        intent = _intent()
        outcome = ActionOutcome(
            "outcome:1", intent.action_id, intent.identity.effect_id, intent.identity.attempt_id,
            "accepted", "transport", ("receipt:accepted",), (), ("recipient_ack",),
            "settlement:effect:share-1", 8.0,
        )
        settlement = OutcomeSettlement.from_outcome(intent, outcome)
        self.assertEqual(settlement.goal_progress, "pending_verification")
        self.assertTrue(settlement.requires_verification)
        self.assertEqual(settlement.unresolved_effects, ("recipient_ack",))

        wrong_attempt = ActionOutcome(
            "outcome:wrong-attempt", intent.action_id, intent.identity.effect_id, "attempt:other",
            "unknown", "transport", ("receipt:timeout",), (), ("handoff",),
            "settlement:wrong-attempt", 9.0,
        )
        with self.assertRaises(ValueError):
            OutcomeSettlement.from_outcome(intent, wrong_attempt)

    def test_repair_is_a_new_qualified_action_not_a_reused_effect(self):
        original = _intent()
        repair = _intent(
            action_id="action:repair-1", effect_id="effect:repair-1", attempt_id="attempt:repair-1"
        )
        qualified = RequiredCheckRegistry()
        qualified.register(_schema())
        decision = qualified.qualify(repair, tuple(_receipt(s) for s in repair.required_checks), now=5.0)
        result = RepairIntent.create(
            "repair:1", original, repair, decision, ("outcome:failed-1",),
        )
        self.assertEqual(result.original_effect_id, "effect:share-1")
        with self.assertRaises(ValueError):
            RepairIntent.create(
                "repair:bad", original, original, decision, ("outcome:failed-1",),
            )
        same_action_new_effect = _intent(effect_id="effect:repair-2", attempt_id="attempt:repair-2")
        same_action_decision = qualified.qualify(
            same_action_new_effect,
            tuple(_receipt(s) for s in same_action_new_effect.required_checks),
            now=5.0,
        )
        with self.assertRaises(ValueError):
            RepairIntent.create(
                "repair:still-same-action", original, same_action_new_effect,
                same_action_decision, ("outcome:failed-1",),
            )

    def test_provider_validates_only_d08_graph_writes_and_never_dispatches(self):
        provider = GoalExecutionProvider()
        specs = provider.register_types()
        self.assertTrue(specs)
        self.assertTrue(all(spec.writer_domain == "d08" for spec in specs))
        self.assertTrue(all(spec.schema_hash and callable(spec.validator) for spec in specs))
        self.assertEqual(provider.validate(_proposal(), snapshot=None).domain, "d08")
        self.assertFalse(hasattr(provider, "dispatch"))
        with self.assertRaises(ValueError):
            provider.validate(_proposal("d05"), snapshot=None)
        with self.assertRaisesRegex(ValueError, "schema hash"):
            provider.validate(replace(_proposal(), proposal_schema_hash="0" * 64), snapshot=None)
        bad_write = GraphWrite(
            AtomKey(Owner("relation", "bot", "persona", "entity:alice"), "d05.boundary_rule", "current"),
            {"rule_id": "boundary:no-contact"},
        )
        with self.assertRaises(ValueError):
            provider.validate(_proposal(writes=(bad_write,)), snapshot=None)

    def test_qualified_action_freezes_a_finite_multi_segment_communication_grant(self):
        registry = RequiredCheckRegistry()
        schema = _schema()
        registry.register(schema)
        intent = _intent(schema)
        decision = registry.qualify(intent, tuple(_receipt(s) for s in intent.required_checks), now=5.0)
        request = CommunicationGrantRequest(
            "communication:share-1", "contact:alice-1", 1, ("entity:alice",),
            ("answer",), ("external_fact", "subjective_judgment", "rhetoric"), (),
            (
                CommunicationSegmentSpec(
                    "segment:1", "effect:segment-1", 0, "a" * 64, 200, (), None,
                ),
                CommunicationSegmentSpec(
                    "segment:2", "effect:segment-2", 1, "b" * 64, 200, (), "segment:1",
                ),
            ),
            2,
        )
        grant = registry.freeze_communication_grant(intent, decision, request, now=6.0)

        self.assertIsInstance(grant, CommunicationIntentGrant)
        self.assertEqual(grant.action_id, intent.action_id)
        self.assertEqual(grant.qualification_receipt_digest, decision.receipt_digest)
        self.assertEqual(grant.valid_until, decision.valid_until)
        self.assertTrue(grant.required_check_refs)
        self.assertEqual(
            tuple(segment.required_check_refs for segment in grant.segment_grants),
            (grant.required_check_refs, grant.required_check_refs),
        )
        self.assertEqual(grant.segment_manifest_digest, canonical_digest(grant.segment_grants))
        self.assertNotEqual(
            grant.segment_authorization_ref("segment:1"),
            grant.segment_authorization_ref("segment:2"),
        )
        self.assertIsNone(grant.contact_policy_check_ref)
        self.assertFalse(hasattr(grant, "admission_ref"))
        self.assertFalse(hasattr(registry, "dispatch"))

    def test_proactive_communication_grant_names_the_contact_policy_check_for_each_segment(self):
        registry = RequiredCheckRegistry()
        schema = _schema(proactive=True)
        registry.register(schema)
        intent = _intent(schema)
        decision = registry.qualify(
            intent, tuple(_receipt(spec) for spec in intent.required_checks), now=5.0,
        )
        request = CommunicationGrantRequest(
            "communication:share-1", "contact:alice-1", 1, ("entity:alice",), (),
            ("external_fact",), (),
            (CommunicationSegmentSpec(
                "segment:1", "effect:segment-1", 0, "a" * 64, 200, (), None,
            ),),
            2,
        )
        grant = registry.freeze_communication_grant(intent, decision, request, now=6.0)

        self.assertIsNotNone(grant.contact_policy_check_ref)
        self.assertIn(grant.contact_policy_check_ref, grant.required_check_refs)
        self.assertIn(grant.contact_policy_check_ref, grant.segment_grants[0].required_check_refs)

    def test_communication_grant_fails_closed_for_unqualified_partial_or_expired_decision(self):
        registry = RequiredCheckRegistry()
        schema = _schema()
        registry.register(schema)
        intent = _intent(schema)
        request = CommunicationGrantRequest(
            "communication:share-1", "contact:alice-1", 1, ("entity:alice",), (),
            ("external_fact",), (),
            (CommunicationSegmentSpec("segment:1", "effect:segment-1", 0, "a" * 64, 200, (), None),),
            0,
        )
        unavailable = registry.qualify(intent, (), now=5.0)
        with self.assertRaisesRegex(ValueError, "current qualified"):
            registry.freeze_communication_grant(intent, unavailable, request, now=5.0)

        partial_spec = schema.required_checks[0]
        partial_receipts = (_receipt(partial_spec, result="unknown", coverage="partial"),) + tuple(
            _receipt(spec) for spec in schema.required_checks[1:]
        )
        partial = registry.qualify(intent, partial_receipts, now=5.0)
        with self.assertRaisesRegex(ValueError, "current qualified"):
            registry.freeze_communication_grant(intent, partial, request, now=5.0)

        qualified = registry.qualify(intent, tuple(_receipt(s, valid_until=6.0) for s in intent.required_checks), now=5.0)
        forged = replace(qualified, receipt_digest="f" * 64, dependency_epochs=())
        with self.assertRaisesRegex(ValueError, "current qualified"):
            registry.freeze_communication_grant(intent, forged, request, now=5.0)
        with self.assertRaisesRegex(ValueError, "current qualified"):
            registry.freeze_communication_grant(intent, qualified, request, now=7.0)

    def test_communication_batch_rejects_unbounded_or_reused_segment_effects(self):
        segments = tuple(
            CommunicationSegmentSpec(f"segment:{index}", f"effect:{index}", index, f"{index}" * 64, 100, (), None)
            for index in range(4)
        )
        with self.assertRaises(ValueError):
            CommunicationGrantRequest(
                "communication:too-many", "contact:alice", 1, ("entity:alice",), (),
                ("rhetoric",), (), segments, 0,
            )
        with self.assertRaises(ValueError):
            CommunicationGrantRequest(
                "communication:duplicate", "contact:alice", 1, ("entity:alice",), (),
                ("rhetoric",), (),
                (
                    CommunicationSegmentSpec("segment:1", "effect:same", 0, "a" * 64, 100, (), None),
                    CommunicationSegmentSpec("segment:2", "effect:same", 1, "b" * 64, 100, (), "segment:1"),
                ),
                0,
            )

    def test_d09_consumes_the_frozen_grant_but_each_later_segment_needs_its_own_admission(self):
        registry = RequiredCheckRegistry()
        schema = _schema()
        registry.register(schema)
        intent = _intent(schema)
        decision = registry.qualify(intent, tuple(_receipt(s) for s in intent.required_checks), now=5.0)
        use_one = ClaimUse("claim:one", 0, 5, ClaimKind.EXTERNAL_FACT)
        use_two = ClaimUse("claim:two", 0, 6, ClaimKind.EXTERNAL_FACT)
        request = CommunicationGrantRequest(
            "communication:share-1", "contact:alice-1", 1, ("entity:alice",), ("answer",),
            ("external_fact",), (),
            (
                CommunicationSegmentSpec(
                    "segment:1", "effect:segment-1", 0,
                    segment_payload_digest("First", (), (use_one,)), 200, (), None,
                ),
                CommunicationSegmentSpec(
                    "segment:2", "effect:segment-2", 1,
                    segment_payload_digest("Second", (), (use_two,)), 200, (), "segment:1",
                ),
            ),
            2,
        )
        grant = registry.freeze_communication_grant(intent, decision, request, now=6.0)
        expression = D09ExpressionProvider()
        claims = (
            ExpressionClaim(
                "claim:one", "First", ClaimKind.EXTERNAL_FACT, ("source:request-1",),
                ("entity:alice",), ("expression",), "disclosure:1",
            ),
            ExpressionClaim(
                "claim:two", "Second", ClaimKind.EXTERNAL_FACT, ("source:request-1",),
                ("entity:alice",), ("expression",), "disclosure:1",
            ),
        )
        blueprint = expression.prepare_blueprint(grant, "scene:chat", 1, claims, now=6.0).blueprint
        self.assertIsNotNone(blueprint)
        staged = expression.verify_and_stage(blueprint, (
            SegmentCandidate(
                "segment:1", "effect:segment-1", "First", (use_one,), ("answer",), (), 0.0,
            ),
            SegmentCandidate(
                "segment:2", "effect:segment-2", "Second", (use_two,), (), (), 0.0,
            ),
        ))
        self.assertEqual(staged.status, "complete")
        first = AdmissionReceipt(
            "admission:1", "segment:1", "effect:segment-1",
            staged.segments[0].payload_digest, "accepted",
        )
        delivery = expression.prepare_delivery(staged, grant, (first,))
        self.assertEqual(delivery.status, "unavailable")
        self.assertEqual(delivery.admitted_segment_refs, ("segment:1",))
        self.assertEqual(delivery.missing, ("d11_admission:segment:2",))


if __name__ == "__main__":
    unittest.main()
