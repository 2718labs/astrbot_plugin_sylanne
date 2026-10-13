from dataclasses import replace
import unittest
import pytest
import json
from dataclasses import asdict

from sylanne3.domains.d08 import (
    ActionIntent,
    ActionSchemaRecord,
    ActionOutcome,
    ActionSchema,
    Commitment,
    CommunicationGrantRequest,
    CommunicationIntentGrant,
    CommunicationSegmentSpec,
    CommitmentConflictSnapshot,
    Goal,
    GoalExecutionProvider,
    NATURAL_PLAN_TYPE_V2,
    NaturalPlanPreparationEvidenceV2,
    natural_plan_key_v2,
    natural_plan_id_v2,
    natural_final_effect_id_v2,
    natural_route_semantic_digest_v2,
    prepare_coordinator_natural_plan_write_v2,
    verify_current_natural_plan_v2,
    GoalPredicate,
    JointPlan,
    JointPlanAcceptance,
    OutcomeSettlement,
    PlanNode,
    RepairIntent,
    RequiredCheckRegistry,
    RequiredCheckSpec,
    prepare_expression_plan,
)
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, GraphWrite,
    NamespaceEpoch, Owner,
)
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.domains.d06.qualified_expression import (
    QualifiedExpressionRequest, SourceTextSpan,
    prepare_qualified_expression_unit,
)
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
    canonical_serialize,
    schema_hash,
)
from sylanne3.domains.d09 import (
    AdmissionReceipt,
    ClaimKind,
    ClaimUse,
    D09ExpressionProvider,
    ExpressionClaim,
    NaturalExpressionPlanV2,
    QualifiedExpressionUnitV2,
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


def _commitment_spec(action_ref="action:share-1"):
    versions = (
        VersionedRef("criteria:1", 1),
        VersionedRef("goal:share-art", 1),
        VersionedRef("commitment:show-art", 1),
        VersionedRef("commitments-query:persona:sylanne", 4),
        VersionedRef(f"execution-epoch:{action_ref}", 3),
        VersionedRef(f"cancellation-epoch:{action_ref}", 2),
    )
    return RequiredCheckSpec(
        "commitment_conflict", "d08.commitment_conflict", "persona:sylanne",
        action_ref, "respond", "criteria:1", versions,
    )


def _schema(*, proactive=False, action_ref="action:share-1"):
    base = (
        _spec("role_binding", "d03.role_binding", version_ref="binding:1", action_ref=action_ref),
        _spec("boundary", "d05.boundary", version_ref="boundary:1", action_ref=action_ref),
        _spec("source_grant", "d06.source_grant", version_ref="grant:1", action_ref=action_ref),
        _commitment_spec(action_ref),
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
    def test_goal_adoption_stages_only_a_source_bound_active_candidate(self):
        source = source_key("bot", "persona", "request-1")
        base = _proposal()
        guard = replace(base.envelope.version_guard,
                        read_versions=base.envelope.version_guard.read_versions
                        + (GraphVersion(source, 1),))
        qualification = replace(base.envelope.source_qualification,
                                source_refs=(source.token,))
        identity = replace(base.envelope.identity,
                           canonical_input_digest=canonical_digest({
                               "input_refs": [source.token]}))
        envelope = replace(base.envelope, version_guard=guard,
                           source_qualification=qualification,
                           identity=identity,
                           input_refs=(source.token,))
        proposal = replace(base, envelope=envelope)
        goal = Goal(
            "goal:reply-1", 1, "active",
            GoalPredicate("communicated", "d11.delivery",
                          (("source", source.token),), 0.0, None),
            (source.token,), (), None, (), (),
        )
        provider = GoalExecutionProvider()
        staged = provider.prepare_goal_candidate(
            proposal, goal, source_ref=source.token)
        writes = tuple(write for write in staged.typed_writes
                       if write.key.type_name == "d08.goal.v1")
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0].value["state"], "active")
        self.assertEqual(staged.envelope.authority.owner_scope, ("activity",))
        self.assertEqual(writes[0].key.owner.kind, "activity")
        self.assertIn(GraphVersion(writes[0].key, 0),
                      staged.envelope.version_guard.read_versions)
        with self.assertRaisesRegex(ValueError, "current D06 read"):
            provider.prepare_goal_candidate(
                replace(proposal, envelope=replace(
                    envelope, version_guard=replace(
                        guard, read_versions=base.envelope.version_guard.read_versions))),
                goal, source_ref=source.token)
        with self.assertRaisesRegex(ValueError, "active at revision one"):
            provider.prepare_goal_candidate(
                proposal, replace(goal, state="satisfied"),
                source_ref=source.token)
        with self.assertRaisesRegex(ValueError, "absent graph head"):
            provider.prepare_goal_candidate(
                staged, goal, source_ref=source.token)

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
        schema = _schema()
        spec = next(item for item in intent.required_checks if item.provider_id == "d08.commitment_conflict")

        def snapshot(**changes):
            values = dict(
                input_versions=spec.required_input_versions,
                coverage="full",
                applicable_commitment_refs=intent.commitment_refs,
                conflicting_commitment_refs=(),
                pending_effect_refs=(),
                action_ref=intent.action_id,
                action_revision=intent.revision,
                intent_digest=canonical_digest(intent),
                schema_id=schema.schema_id,
                goal_ref=intent.goal_ref,
                target_ref=intent.target_ref,
                action_kind=intent.action_kind,
                purpose=intent.purpose,
                commitment_query_epoch_ref="commitments-query:persona:sylanne",
                commitment_query_epoch=4,
                execution_epoch_ref=f"execution-epoch:{intent.action_id}",
                execution_epoch=3,
                cancellation_epoch_ref=f"cancellation-epoch:{intent.action_id}",
                cancellation_epoch=2,
                current_read_confirmed=True,
                action_cancelled=False,
                conflicting_action_refs=(),
            )
            values.update(changes)
            return CommitmentConflictSnapshot(**values)

        partial = provider.provide_required_check(
            intent,
            schema,
            snapshot(coverage="partial", pending_effect_refs=("effect:unknown",)),
            valid_until=20.0,
        )
        self.assertEqual((partial.result, partial.coverage), ("unknown", "partial"))
        conflict = provider.provide_required_check(
            intent,
            schema,
            snapshot(
                applicable_commitment_refs=intent.commitment_refs + ("commitment:conflicting",),
                conflicting_commitment_refs=("commitment:conflicting",),
            ),
            valid_until=20.0,
        )
        self.assertEqual(conflict.result, "fail")
        clear = provider.provide_required_check(
            intent,
            schema,
            snapshot(),
            valid_until=20.0,
        )
        self.assertEqual((clear.result, clear.coverage), ("pass", "full"))

        missing_current_read = provider.provide_required_check(
            intent, schema, snapshot(current_read_confirmed=False), valid_until=20.0,
        )
        self.assertEqual((missing_current_read.result, missing_current_read.coverage), ("unknown", "partial"))
        changed_candidate = replace(intent, parameters_digest=canonical_digest({"target": "other"}))
        mismatched_candidate = provider.provide_required_check(
            changed_candidate, schema, snapshot(), valid_until=20.0,
        )
        self.assertEqual((mismatched_candidate.result, mismatched_candidate.coverage), ("unknown", "partial"))
        cancelled = provider.provide_required_check(
            intent, schema, snapshot(action_cancelled=True), valid_until=20.0,
        )
        self.assertEqual((cancelled.result, cancelled.coverage), ("fail", "full"))
        changed_cancel_epoch = provider.provide_required_check(
            intent,
            schema,
            snapshot(cancellation_epoch=3),
            valid_until=20.0,
        )
        self.assertEqual((changed_cancel_epoch.result, changed_cancel_epoch.coverage), ("unknown", "partial"))

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
        qualified.register(_schema(action_ref=repair.action_id))
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

    def test_action_schema_is_frozen_with_the_exact_intent_operation(self):
        provider = GoalExecutionProvider()
        schema = _schema()
        intent = _intent(schema)
        base = _proposal()
        envelope = replace(base.envelope, identity=intent.identity)
        candidate = provider.prepare_action_candidate(replace(base, envelope=envelope), intent, schema)
        action_writes = tuple(write for write in candidate.typed_writes
                              if write.key.type_name == "d08.action_intent.v1")
        schema_writes = tuple(write for write in candidate.typed_writes
                              if write.key.type_name == "d08.action_schema.v1")
        self.assertEqual(len(action_writes), 1)
        self.assertEqual(len(schema_writes), 1)
        self.assertEqual(action_writes[0].key.owner, schema_writes[0].key.owner)
        self.assertTrue(next(spec for spec in provider.register_types()
                             if spec.name == "d08.action_schema.v1").immutable)

        schema_type = next(spec for spec in provider.register_types()
                           if spec.name == "d08.action_schema.v1")
        decoded = schema_type.validator(schema_writes[0].value)
        self.assertIsInstance(decoded, ActionSchemaRecord)
        self.assertEqual(decoded.operation, intent.identity)
        self.assertEqual(decoded.intent_digest, canonical_digest(intent))
        self.assertEqual(decoded.required_checks, schema.required_checks)
        self.assertEqual(candidate.envelope.identity, decoded.operation)

        with self.assertRaisesRegex(ValueError, "exactly one intent and one frozen schema"):
            provider.validate(replace(candidate, typed_writes=action_writes), snapshot=None)
        with self.assertRaisesRegex(ValueError, "exact operation identity"):
            provider.prepare_action_candidate(base, intent, schema)

    def test_action_schema_candidate_rejects_removed_checks_or_tampered_versions(self):
        provider = GoalExecutionProvider()
        schema = _schema()
        intent = _intent(schema)
        base = _proposal()
        envelope = replace(base.envelope, identity=intent.identity)
        incomplete_schema = ActionSchema(
            schema.schema_id, schema.action_kind, schema.proactive,
            tuple(item for item in schema.required_checks if item.check_kind != "boundary"),
        )
        with self.assertRaisesRegex(ValueError, "removed required checks"):
            provider.prepare_action_candidate(replace(base, envelope=envelope), intent, incomplete_schema)

        candidate = provider.prepare_action_candidate(replace(base, envelope=envelope), intent, schema)
        schema_write = next(write for write in candidate.typed_writes
                            if write.key.type_name == "d08.action_schema.v1")
        tampered = dict(schema_write.value)
        tampered["schema_hash"] = "0" * 64
        tampered_proposal = replace(
            candidate,
            typed_writes=tuple(
                GraphWrite(write.key, tampered, write.dependencies) if write is schema_write else write
                for write in candidate.typed_writes
            ),
        )
        with self.assertRaises(ValueError):
            provider.validate(tampered_proposal, snapshot=None)

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

    def test_required_checks_to_finite_expression_plan_respects_cancel_and_unknown(self):
        registry = RequiredCheckRegistry()
        schema = _schema()
        registry.register(schema)
        intent = _intent(schema)
        receipts = tuple(_receipt(spec) for spec in schema.required_checks)
        use_one = ClaimUse("claim:one", 0, 5, ClaimKind.EXTERNAL_FACT)
        use_two = ClaimUse("claim:two", 0, 6, ClaimKind.EXTERNAL_FACT)
        request = CommunicationGrantRequest(
            "communication:share-1", "contact:alice-1", 1, ("entity:alice",),
            ("answer",), ("external_fact",), (),
            (
                CommunicationSegmentSpec("segment:1", "effect:segment-1", 0,
                    segment_payload_digest("First", (), (use_one,)), 200, (), None),
                CommunicationSegmentSpec("segment:2", "effect:segment-2", 1,
                    segment_payload_digest("Second", (), (use_two,)), 200, (), "segment:1"),
            ),
            2,
        )
        claims = (
            ExpressionClaim("claim:one", "First", ClaimKind.EXTERNAL_FACT,
                ("source:request-1",), ("entity:alice",), ("expression",), "disclosure:1"),
            ExpressionClaim("claim:two", "Second", ClaimKind.EXTERNAL_FACT,
                ("source:request-1",), ("entity:alice",), ("expression",), "disclosure:1"),
        )
        candidates = (
            SegmentCandidate("segment:1", "effect:segment-1", "First", (use_one,), ("answer",), (), 0.0),
            SegmentCandidate("segment:2", "effect:segment-2", "Second", (use_two,), (), (), 0.0),
        )
        args = (registry, intent, receipts, request, claims, candidates)
        result = prepare_expression_plan(*args, scene_ref="scene:chat", conversation_epoch=1,
            cancellation_epoch=2, now=5.0)
        self.assertEqual(result.status, "complete")
        self.assertIsNotNone(result.grant)
        self.assertEqual(result.grant.required_check_refs, result.grant.segment_grants[1].required_check_refs)
        self.assertEqual(tuple(segment.segment_id for segment in result.staging.segments),
            ("segment:1", "segment:2"))
        incomplete_plan = prepare_expression_plan(registry, intent, receipts, request, claims, candidates[:1],
            scene_ref="scene:chat", conversation_epoch=1, cancellation_epoch=2, now=5.0)
        self.assertEqual(incomplete_plan.status, "rejected")
        self.assertIn("segment_manifest", incomplete_plan.missing)
        unknown = AdmissionReceipt("admission:1", "segment:1", "effect:segment-1",
            result.staging.segments[0].payload_digest, "unknown")
        delivery = D09ExpressionProvider.prepare_delivery(result.staging, result.grant, (unknown,))
        self.assertEqual(delivery.status, "pending_confirmation")
        self.assertEqual(delivery.blocked_segment_refs, ("segment:2",))

        missing = prepare_expression_plan(registry, intent, receipts[:-1], request, claims, candidates,
            scene_ref="scene:chat", conversation_epoch=1, cancellation_epoch=2, now=5.0)
        self.assertEqual(missing.status, "unavailable")
        self.assertIsNone(missing.grant)
        self.assertIn("dispatch_budget", missing.missing)
        canceled = prepare_expression_plan(*args, scene_ref="scene:chat", conversation_epoch=1,
            cancellation_epoch=3, now=5.0)
        self.assertEqual(canceled.status, "stale")
        self.assertIsNone(canceled.grant)


if __name__ == "__main__":
    unittest.main()


def test_paid_multi_source_action_scope_rejects_missing_or_stale_secondary_head():
    namespace = NamespaceId("bot", "persona")
    first = source_key("bot", "persona", "first")
    second = source_key("bot", "persona", "second")
    refs = (first.token, second.token)
    intent = replace(_intent(), source_refs=refs)
    reads = (GraphVersion(first, 1), GraphVersion(second, 2))
    verify = GoalExecutionProvider.verify_paid_claim_source_scope_v2
    verify(intent, refs, reads, namespace=namespace, current_read_confirmed=True)
    with pytest.raises(ValueError, match="current D06 head"):
        verify(intent, refs, reads[:1], namespace=namespace,
               current_read_confirmed=True)
    with pytest.raises(ValueError, match="action sources"):
        verify(intent, refs[:1], reads, namespace=namespace,
               current_read_confirmed=True)


def _natural_preparation_case():
    from sylanne3.host.post_c02_reply_driver import post_c02_reply_operation_id

    namespace = NamespaceId("bot", "persona")
    c02_operation_id = "operation:c02"
    activity_id = "activity:natural"
    source = source_key(*namespace.as_tuple, "report")
    access = access_key(*namespace.as_tuple, "report")
    correction = source_correction_head_key(namespace, "report")
    scene_id = "scene:private"
    audience_id = "audience:private"
    scene_proof = AtomKey(Owner("scene", "bot", "persona", scene_id),
                          "d03.role_binding", "role:reply")
    audience_proof = AtomKey(Owner("persona", "bot", "persona"),
                             "d03.account_binding", "account:reply")
    focus = AtomKey(Owner("persona", "bot", "persona"), "d07.focus.v1", "persona")
    ticket = AtomKey(Owner("persona", "bot", "persona"),
                     "d07.attention_ticket.v1", "ticket:reply")
    text = "Alice said the payment was not sent."
    source_record = SourceRecord(
        "report", text, "alice", "reported", "reported", 3.0, 4.0,
        "family", (audience_id,), ("expression",), (),
    )
    plan_key = natural_plan_key_v2(
        namespace, activity_id,
        natural_plan_id_v2(namespace, c02_operation_id, source.token),
    )
    before = GraphSnapshot((
        GraphAtom(plan_key, 0, {}, False),
        GraphAtom(scene_proof, 1, {}), GraphAtom(audience_proof, 1, {}),
        GraphAtom(focus, 1, {}), GraphAtom(ticket, 1, {}),
        GraphAtom(source, 1, source_record.to_dict()),
        GraphAtom(access, 1, {"source_id": "report", "status": "active",
                              "audiences": [audience_id],
                              "purposes": ["expression"], "recorded_at": 4.0}),
        GraphAtom(correction, 0, {}, False),
    ), (NamespaceEpoch("bot", "persona", 5),))
    candidate = prepare_qualified_expression_unit(
        before, namespace=namespace,
        request=QualifiedExpressionRequest(
            source.token, "attributed_report", SourceTextSpan(0, len(text))),
        audiences=(audience_id,), access_epoch=2, deletion_epoch=0,
        valid_until=90.0,
    )
    versions = {row.key.token: row.revision for row in candidate.read_versions}
    unit = QualifiedExpressionUnitV2(
        "basis:report", ClaimKind.REPORTED_CLAIM, candidate.source_excerpt,
        None,
        tuple(VersionedRef(ref, versions[ref])
              for ref in candidate.lineage_source_refs),
        tuple(VersionedRef(row.key.token, row.revision)
              for row in candidate.read_versions if row.key.type_name == "memory.access"),
        tuple(VersionedRef(row.key.token, row.revision)
              for row in candidate.read_versions
              if row.key.type_name == "d06.source_correction_head.v1"),
        audience_id, "expression", candidate.valid_until,
        speaker_id=candidate.speaker_id, content_reality="external_report",
        qualification_digest=candidate.qualification_digest,
        occurred_at=candidate.occurred_at, learned_at=candidate.learned_at,
        source_kind=candidate.source_kind,
        assertion_status=candidate.assertion_status,
        d06_claim_kind=candidate.claim_kind,
        attribution_required=candidate.attribution_required,
        polarity_status=candidate.polarity_status,
        source_excerpt=candidate.source_excerpt,
        evidence_span=(candidate.evidence_span.start, candidate.evidence_span.end),
    )
    plan = NaturalExpressionPlanV2(
        namespace, VersionedRef(plan_key.token, 1),
        VersionedRef(scene_proof.token, 1),
        VersionedRef(audience_proof.token, 1),
        ("answer",), ("paraphrase",), (), (unit,), 80.0,
        activity_id, post_c02_reply_operation_id(c02_operation_id, source.token),
        natural_final_effect_id_v2(namespace, c02_operation_id, source.token),
        scene_id, audience_id,
    )
    evidence = NaturalPlanPreparationEvidenceV2(
        c02_operation_id, VersionedRef(source.token, 1),
        VersionedRef(focus.token, 1), VersionedRef(ticket.token, 1),
        "a" * 64, "b" * 64, "budget:root", 1, "c" * 64,
        (("tokens", 100),), (("tokens", 50),),
    )
    return plan, evidence, before, candidate, plan_key, access, correction


def test_preparation_plan_is_adopted_without_future_action_or_payload_grant():
    plan, evidence, before, candidate, plan_key, _, _ = _natural_preparation_case()
    write, reads = prepare_coordinator_natural_plan_write_v2(
        plan=plan, evidence=evidence, snapshot=before,
        d06_candidates=(candidate,), access_epoch=2,
        deletion_epoch=0, now_utc=10.0,
    )
    spec = next(item for item in GoalExecutionProvider().register_types()
                if item.name == NATURAL_PLAN_TYPE_V2)
    assert spec.schema_version == 2 and spec.immutable
    spec.validator(write.value)
    assert GraphVersion(plan_key, 0) in reads
    assert write.key == plan_key
    assert "action_ref" not in write.value
    assert "qualification_receipt_digest" not in write.value
    assert "payload_digest" not in write.value
    assert write.value["final_effect_id"] == plan.final_effect_id
    with pytest.raises(ValueError, match="coordinator current-read CAS"):
        GoalExecutionProvider().validate(replace(
            _proposal(), typed_writes=(write,)))
    old_action_claim = dict(write.value, action_ref={"ref": "forged", "version": 1})
    with pytest.raises(ValueError, match="graph fields differ"):
        spec.validator(old_action_claim)
    missing_qualification = replace(plan, units=(replace(
        plan.units[0], qualification_digest="d" * 64),))
    with pytest.raises(ValueError, match="qualification set is incomplete"):
        prepare_coordinator_natural_plan_write_v2(
            plan=missing_qualification, evidence=evidence, snapshot=before,
            d06_candidates=(candidate,), access_epoch=2,
            deletion_epoch=0, now_utc=10.0,
        )
    with pytest.raises(ValueError, match="final identity"):
        prepare_coordinator_natural_plan_write_v2(
            plan=replace(plan, final_effect_id="effect:forged"),
            evidence=evidence, snapshot=before,
            d06_candidates=(candidate,), access_epoch=2,
            deletion_epoch=0, now_utc=10.0,
        )


def test_preparation_plan_stable_across_unrelated_epochs_but_rejects_revocation():
    plan, evidence, before, candidate, plan_key, access, correction = (
        _natural_preparation_case())
    write, _ = prepare_coordinator_natural_plan_write_v2(
        plan=plan, evidence=evidence, snapshot=before,
        d06_candidates=(candidate,), access_epoch=2,
        deletion_epoch=0, now_utc=10.0,
    )
    adopted = replace(before, atoms=tuple(
        GraphAtom(plan_key, 1, write.value) if atom.key == plan_key else atom
        for atom in before.atoms
    ), epochs=(NamespaceEpoch("bot", "persona", 6),))
    later = replace(adopted, epochs=(NamespaceEpoch("bot", "persona", 7),),
                    atoms=adopted.atoms + (GraphAtom(
                        AtomKey(plan_key.owner, "d11.job.v1", "job:unrelated"), 1, {}),))
    for current in (adopted, later):
        record, reads = verify_current_natural_plan_v2(
            plan=plan, evidence=evidence, snapshot=current,
            d06_candidates=(candidate,), access_epoch=2,
            deletion_epoch=0, now_utc=11.0,
        )
        assert record.qualified_units_digest == canonical_digest(plan.units)
        assert GraphVersion(plan_key, 1) in reads
    revoked = replace(later, atoms=tuple(
        replace(atom, revision=2, value={**atom.value, "status": "withdrawn"})
        if atom.key == access else atom for atom in later.atoms
    ))
    with pytest.raises((ValueError, PermissionError)):
        verify_current_natural_plan_v2(
            plan=plan, evidence=evidence, snapshot=revoked,
            d06_candidates=(candidate,), access_epoch=2,
            deletion_epoch=0, now_utc=11.0,
        )
    corrected = replace(later, atoms=tuple(
        replace(atom, revision=1, valid=True, value={"correction_id": "new"})
        if atom.key == correction else atom for atom in later.atoms
    ))
    with pytest.raises(ValueError):
        verify_current_natural_plan_v2(
            plan=plan, evidence=evidence, snapshot=corrected,
            d06_candidates=(candidate,), access_epoch=2,
            deletion_epoch=0, now_utc=11.0,
        )


def test_natural_route_semantic_identity_ignores_query_epoch_only():
    from sylanne3.runtime.reply_entity_route_v2 import (
        CurrentReplyEntityRouteBindingV2,
    )

    namespace = NamespaceId("bot", "persona")
    version = GraphVersion(AtomKey(Owner("persona", "bot", "persona"),
                                   "d03.account_binding", "account:one"), 1)
    route = CurrentReplyEntityRouteBindingV2(
        namespace, "operation:c02", "source:one", "platform:one",
        "sender:one", "audience:one", "scene:one", "entity:one", "account:one",
        version, version, version, version, version, version, (version,),
        QueryEpoch(namespace, "all", 5), 100.0, "a" * 64,
    )
    assert natural_route_semantic_digest_v2(route) == (
        natural_route_semantic_digest_v2(replace(
            route, query=QueryEpoch(namespace, "all", 6),
            binding_scan_versions=(),
        )))
    assert natural_route_semantic_digest_v2(route) != (
        natural_route_semantic_digest_v2(replace(route, account_id="account:other")))


def test_natural_preparation_allows_rhetoric_without_using_c02_as_claim_source():
    plan, evidence, before, _, _, _, _ = _natural_preparation_case()
    greeting = QualifiedExpressionUnitV2(
        "basis:greeting", ClaimKind.RHETORIC, "Hello.",
        evidence.ticket_ref, (), (), (), plan.audience_id,
        "expression", 90.0,
    )
    greeting_plan = replace(plan, units=(greeting,))
    write, reads = prepare_coordinator_natural_plan_write_v2(
        plan=greeting_plan, evidence=evidence, snapshot=before,
        d06_candidates=(), access_epoch=2, deletion_epoch=0, now_utc=10.0,
    )
    assert write.value["d06_qualification_digests"] == []
    assert GraphVersion(AtomKey.from_token(evidence.source_ref.ref), 1) in reads
    missing_trigger = replace(before, atoms=tuple(
        atom for atom in before.atoms
        if atom.key.token != evidence.source_ref.ref
    ))
    with pytest.raises(ValueError, match="scope changed"):
        prepare_coordinator_natural_plan_write_v2(
            plan=greeting_plan, evidence=evidence, snapshot=missing_trigger,
            d06_candidates=(), access_epoch=2, deletion_epoch=0, now_utc=10.0,
        )


def test_personal_selection_scc_records_conflict_and_is_order_independent():
    from sylanne3.domains.d08.personal_plan_v1 import QualifiedPersonalCandidateV1, select_personal_step_v2
    from sylanne3.memory_types import source_key
    source = source_key("bot", "persona", "choice").token
    left = QualifiedPersonalCandidateV1("candidate:a", "action:a", "task:a", "a" * 64,
        "eligible", 3, True, None, "quote:a")
    right = replace(left, candidate_ref="candidate:b", action_ref="action:b", node_id="task:b",
        semantic_digest="b" * 64, irreversible_exposure=1, quote_ref="quote:b")
    kwargs = dict(decision_id="decision:scc", preference_edges=(("candidate:a", "candidate:b"),
        ("candidate:b", "candidate:a")), source_refs=(source,), read_versions=(VersionedRef(source, 1),))
    first = select_personal_step_v2(candidates=(left, right), **kwargs)
    second = select_personal_step_v2(candidates=(right, left), **kwargs)
    assert first == second
    assert first.chosen_action_ref == "action:b"
    assert first.sccs == (("candidate:a", "candidate:b"),)
    assert first.conflict_refs == ("candidate:a", "candidate:b")


def test_personal_selection_material_tie_waits_but_identical_semantics_use_stable_id():
    from sylanne3.domains.d08.personal_plan_v1 import QualifiedPersonalCandidateV1, select_personal_step_v2
    from sylanne3.memory_types import source_key
    source = source_key("bot", "persona", "tie").token
    left = QualifiedPersonalCandidateV1("candidate:a", "action:a", "task:a", "a" * 64,
        "eligible", 1, True, None, "quote:a")
    right = replace(left, candidate_ref="candidate:b", action_ref="action:b", node_id="task:b", semantic_digest="b" * 64)
    kwargs = dict(decision_id="decision:tie", preference_edges=(), source_refs=(source,), read_versions=())
    unresolved = select_personal_step_v2(candidates=(right, left), **kwargs)
    assert unresolved.chosen_action_ref is None
    assert unresolved.unknown_reason == "PREFERENCE_CONFLICT_UNRESOLVED"
    identical = select_personal_step_v2(candidates=(replace(right, semantic_digest=left.semantic_digest), left), **kwargs)
    assert identical.chosen_action_ref == "action:a"


def test_personal_selection_unknown_cost_and_original_effect_never_rank_as_zero():
    from sylanne3.domains.d08.personal_plan_v1 import QualifiedPersonalCandidateV1, select_personal_step_v2
    from sylanne3.memory_types import source_key
    source = source_key("bot", "persona", "unknown").token
    legal = QualifiedPersonalCandidateV1("candidate:legal", "action:legal", "task:legal", "c" * 64,
        "eligible", 3, True, None, "quote:legal")
    unknown_cost = replace(legal, candidate_ref="candidate:fee", action_ref="action:fee", hard_status="WAIT_COST_EVIDENCE",
        irreversible_exposure=0, quote_ref=None)
    unknown_effect = replace(unknown_cost, candidate_ref="candidate:effect", action_ref="action:effect",
        hard_status="WAIT_ORIGINAL_EFFECT", pending_original_effects=("effect:original",))
    decision = select_personal_step_v2(decision_id="decision:unknown", candidates=(unknown_effect, legal, unknown_cost),
        preference_edges=(("candidate:fee", "candidate:legal"),), source_refs=(source,), read_versions=())
    assert decision.chosen_action_ref == "action:legal"
    assert decision.unknown_refs == ("effect:original",)
    assert dict(decision.rejected_reasons)["candidate:fee"] == "WAIT_COST_EVIDENCE"


def test_personal_selection_actual_commitment_precedes_soft_preference_and_numeric_gap_is_preserved():
    from sylanne3.domains.d08.personal_plan_v1 import QualifiedPersonalCandidateV1, select_personal_step_v2
    from sylanne3.memory_types import source_key
    source = source_key("bot", "persona", "obligation").token
    obligation = QualifiedPersonalCandidateV1("candidate:owed", "action:owed", "task:owed", "a" * 64,
        "eligible", 2, True, None, "quote:owed", established_commitment=True)
    optional = replace(obligation, candidate_ref="candidate:optional", action_ref="action:optional", established_commitment=False)
    kwargs = dict(decision_id="decision:obligation", preference_edges=(("candidate:optional", "candidate:owed"),),
        source_refs=(source,), read_versions=())
    selected = select_personal_step_v2(candidates=(optional, obligation), **kwargs)
    assert selected.chosen_action_ref == "action:owed"
    gap = select_personal_step_v2(candidates=(replace(obligation, numeric_discriminator_unresolved=True),),
        **{**kwargs, "preference_edges": ()})
    assert gap.chosen_action_ref is None
    assert gap.unknown_reason == "NUMERIC_DISCRIMINATOR_UNRESOLVED"


def test_personal_plan_dependency_cycle_is_rejected_instead_of_collapsed_as_preference_scc():
    from sylanne3.domains.d08.personal_plan_v1 import PersonalPlanV1, PlanNodeV2
    from sylanne3.graph_types import AtomKey, Owner
    from sylanne3.memory_types import source_key
    source = source_key("bot", "persona", "plan").token
    goal_ref = AtomKey(Owner("activity", "bot", "persona", "activity:plan"), "d08.goal.v1", "goal:plan").token
    predicate = GoalPredicate("artifact_verified", "registered:postcondition", (), 0.0, None)
    first = PlanNodeV2("task:a", "persona:persona", ("task:b",), "artifact_draft_v1", predicate,
        True, None, "resource:cpu", observable_postconditions=(predicate,), cost_ceiling=(("thread_cpu_ms", 10),))
    second = replace(first, node_id="task:b", depends_on=("task:a",))
    with pytest.raises(ValueError, match="acyclic"):
        PersonalPlanV1("plan:cycle", 1, goal_ref, 1, "active", "persona:persona", (first, second), (), (), (),
            ("user_stop",), (source,), (VersionedRef(source, 1),), None)


def test_personal_method_mapping_is_owned_by_exact_plan_and_legacy_decode_is_narrow():
    from sylanne3.domains.d08.personal_plan_v1 import PersonalPlanV1, PlanNodeV2, PLAN_TYPE, decode_personal_plan_type_v1
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    from sylanne3.memory_types import source_key
    source = source_key("bot", "persona", "method-mapping").token
    goal_ref = AtomKey(Owner("activity", "bot", "persona", "activity:method"), "d08.goal.v1", "goal:method").token
    predicate = GoalPredicate("artifact_verified", "registered:postcondition", (), 0.0, None)
    node = PlanNodeV2("task:method", "persona:persona", (), "artifact_draft_v1", predicate, True, None,
        "resource:cpu", observable_postconditions=(predicate,), cost_ceiling=(("thread_cpu_ms", 10),))
    original = PersonalPlanV1("plan:method", 1, goal_ref, 1, "active", "persona:persona", (node,),
        ("candidate:a", "candidate:b"), (), (), ("user_stop",), (source,), (VersionedRef(source, 1),), None,
        method_candidates=(("candidate:b", "method:b"), ("candidate:a", "method:a")))
    assert original.method_candidates == (("candidate:a", "method:a"), ("candidate:b", "method:b"))
    for mapping in ((("candidate:other", "method:a"),), (("candidate:a", "method:a"), ("candidate:a", "method:b"))):
        with pytest.raises(ValueError, match="method identity"):
            replace(original, method_candidates=mapping)
    raw = plain_v1(original)
    assert decode_personal_plan_type_v1(PLAN_TYPE, raw) == original
    legacy = {name: value for name, value in raw.items() if name != "method_candidates"}
    assert decode_personal_plan_type_v1(PLAN_TYPE, legacy).method_candidates == ()
    assert decode_typed_production_value_v1(legacy, PersonalPlanV1).method_candidates == ()
    with pytest.raises(ValueError):
        decode_personal_plan_type_v1(PLAN_TYPE, {**legacy, "unregistered": []})
    with pytest.raises(ValueError):
        decode_typed_production_value_v1({**legacy, "unregistered": []}, PersonalPlanV1)
