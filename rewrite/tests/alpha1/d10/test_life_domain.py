import unittest
from dataclasses import replace

from sylanne3.domains.d10 import (
    ActivityOutcome,
    ActivityRecipe,
    CharacterClockMappingProposal,
    ContactPolicy,
    ContactPolicyReadSet,
    ContactClaim,
    ContactContinuation,
    LifeDomain,
    LifeProject,
    ProactiveOpportunity,
)
from sylanne3.domains.d08 import ActionIntent, GoalPredicate, RequiredCheckSpec
from sylanne3.runtime_contracts import (
    NamespaceId, OperationIdentity, QueryEpoch, VersionedRef, canonical_digest,
)


class LifeDomainTests(unittest.TestCase):
    def setUp(self):
        self.domain = LifeDomain()
        self.namespace = NamespaceId("bot", "persona")
        self.policy = ContactPolicy(
            policy_id="policy:one", namespace=self.namespace, version=1, subject_ref="user:one",
            channel="private", category="ordinary", consent=True, quiet=False,
            quota_limit=1, window_start=0.0, window_end=24.0,
        )

    def _proactive_intent(self):
        versions = (VersionedRef("criteria:contact", 1), VersionedRef("policy:one", 1),
                    VersionedRef("opportunity:one", 1),
                    VersionedRef("d10.contact_policy:user:one:private:ordinary", 5))
        spec = RequiredCheckSpec("contact_policy", "d10.contact_policy", "persona:persona",
                                 "action:one", "proactive_contact", "criteria:contact", versions)
        return ActionIntent(
            action_id="action:one", revision=1, goal_ref="goal:one", commitment_refs=(),
            target_ref="user:one", action_kind="message", purpose="proactive_contact",
            risk_class="limited", parameters_digest="a" * 64,
            identity=OperationIdentity("activity:one", "effect:one", "attempt:one", "prepare",
                                       "operation:one", canonical_digest({"input_refs": []})),
            schema_id="schema:one", required_checks=(spec,),
            success_predicate=GoalPredicate("communicated", "d11.observer", (), 0.0, None),
            effect_scope=("effect:one",), compensation_ref=None, source_refs=("source:one",),
        )

    def _read_set(self, opportunity, claims=(), *, coverage="full", versions=None):
        versions = versions or self._proactive_intent().required_checks[0].required_input_versions
        return ContactPolicyReadSet(
            self.namespace,
            QueryEpoch(self.namespace, "d10.contact_policy:user:one:private:ordinary", 5),
            self.policy, opportunity, claims, versions, coverage,
        )

    def test_life_project_cannot_adopt_planned_or_unknown_work_as_progress(self):
        project = LifeProject("project:one", self.namespace, "poetry", "role_simulation", "step:one")
        recipe = ActivityRecipe("recipe:one", 1, "role_simulation", ("draft",), True)
        planned = ActivityOutcome("activity:one", "effect:one", "planned", None, ())
        unknown = ActivityOutcome("activity:one", "effect:one", "unknown", None, ())
        with self.assertRaises(ValueError):
            self.domain.adopt_life_progress(project, recipe, planned)
        with self.assertRaises(ValueError):
            self.domain.adopt_life_progress(project, recipe, unknown)

    def test_clock_mapping_is_only_a_d10_proposal_and_never_an_executed_life_interval(self):
        mapping = CharacterClockMappingProposal(
            "clock:one", self.namespace, 1, 100.0, 0.0, 2.0, (100.0, 200.0), "policy:clock"
        )
        self.assertEqual(mapping.character_time(150.0), 100.0)
        self.assertFalse(mapping.execution_authorized)
        with self.assertRaises(ValueError):
            CharacterClockMappingProposal("clock:bad", self.namespace, 1, 0.0, 0.0, -1.0, (0.0, 1.0), "policy:clock")

    def test_contact_claim_rejects_quiet_or_missing_consent_without_sending(self):
        quiet = ContactPolicy(**{**self.policy.__dict__, "quiet": True})
        opportunity = ProactiveOpportunity("opportunity:one", self.namespace, "source:milestone", "user:one", "private", "ordinary", 0.0, 10.0)
        check = self.domain.contact_policy_check(quiet, opportunity, (), now=1.0)
        self.assertEqual(check.result, "fail")
        self.assertFalse(check.dispatch_authorized)

    def test_required_contact_check_passes_only_full_matching_current_graph_read(self):
        intent = self._proactive_intent()
        versions = intent.required_checks[0].required_input_versions
        opportunity = ProactiveOpportunity("opportunity:one", self.namespace, "source:milestone", "user:one",
                                           "private", "ordinary", 0.0, 10.0)
        read_set = self._read_set(opportunity)
        trusted = LifeDomain(contact_read_verifier=lambda candidate: candidate is read_set)
        receipt = trusted.contact_policy_required_check(
            intent, self.policy, opportunity, (), coverage="full", input_versions=versions,
            now=1.0, read_set=read_set,
        )
        self.assertEqual((receipt.result, receipt.coverage, receipt.issuer),
                         ("pass", "full", "d10.contact_policy"))
        forged = self.domain.contact_policy_required_check(
            intent, self.policy, opportunity, (), coverage="full", input_versions=versions,
            now=1.0, read_set=read_set,
        )
        self.assertEqual(forged.result, "unknown")
        partial = trusted.contact_policy_required_check(
            intent, self.policy, opportunity, (), coverage="partial", input_versions=versions,
            now=1.0, read_set=replace(read_set, coverage="partial"),
        )
        self.assertEqual((partial.result, partial.coverage), ("unknown", "partial"))
        stale = trusted.contact_policy_required_check(
            intent, self.policy, opportunity, (), coverage="full",
            input_versions=(VersionedRef("policy:one", 2),), now=1.0,
            read_set=replace(read_set, input_versions=(VersionedRef("policy:one", 2),)),
        )
        self.assertEqual(stale.result, "unknown")

        old_epoch = replace(read_set, query_epoch=replace(read_set.query_epoch, revision=4))
        old = trusted.contact_policy_required_check(
            intent, self.policy, opportunity, (), coverage="full", input_versions=versions,
            now=1.0, read_set=old_epoch,
        )
        self.assertEqual(old.result, "unknown")

    def test_required_contact_check_fails_closed_for_policy_gates(self):
        intent = self._proactive_intent()
        versions = intent.required_checks[0].required_input_versions
        opportunity = ProactiveOpportunity("opportunity:one", self.namespace, "source:milestone", "user:one",
                                           "private", "ordinary", 0.0, 10.0)
        policy = replace(self.policy, consent=False)
        read_set = replace(self._read_set(opportunity), policy=policy)
        trusted = LifeDomain(contact_read_verifier=lambda candidate: candidate is read_set)
        receipt = trusted.contact_policy_required_check(
            intent, policy, opportunity, (), coverage="full", input_versions=versions,
            now=1.0, read_set=read_set,
        )
        self.assertEqual((receipt.result, receipt.coverage), ("fail", "full"))

    def test_current_no_response_claim_blocks_a_forged_empty_read(self):
        opportunity = ProactiveOpportunity("opportunity:one", self.namespace, "source:milestone",
                                           "user:one", "private", "ordinary", 0.0, 10.0)
        claim = ContactClaim("contact:one", "action:old", "user:one", "private", "ordinary",
                             ("effect:old",), (("effect:old", "unknown"),),
                             "pending_confirmation", "policy:one", 1)
        base = self._proactive_intent()
        versions = (*base.required_checks[0].required_input_versions, VersionedRef("contact:one", 1))
        spec = replace(base.required_checks[0], required_input_versions=versions)
        intent = replace(base, required_checks=(spec,))
        current = self._read_set(opportunity, (claim,), versions=versions)
        trusted = LifeDomain(contact_read_verifier=lambda candidate: candidate is current)
        receipt = trusted.contact_policy_required_check(
            intent, self.policy, opportunity, (claim,), coverage="full",
            input_versions=versions, now=1.0, read_set=current,
        )
        self.assertEqual(receipt.result, "fail")
        forged_empty = replace(current, claims=())
        unknown = trusted.contact_policy_required_check(
            intent, self.policy, opportunity, (), coverage="full", input_versions=versions,
            now=1.0, read_set=forged_empty,
        )
        self.assertEqual(unknown.result, "unknown")

    def test_withdrawn_consent_cannot_be_overridden_by_old_policy_value(self):
        intent = self._proactive_intent()
        versions = intent.required_checks[0].required_input_versions
        opportunity = ProactiveOpportunity("opportunity:one", self.namespace, "source:milestone",
                                           "user:one", "private", "ordinary", 0.0, 10.0)
        current_policy = replace(self.policy, version=2, consent=False)
        current_versions = tuple(VersionedRef(item.ref, 2) if item.ref == "policy:one" else item
                                 for item in versions)
        current = replace(self._read_set(opportunity), policy=current_policy,
                          input_versions=current_versions)
        trusted = LifeDomain(contact_read_verifier=lambda candidate: candidate is current)
        old = trusted.contact_policy_required_check(
            intent, self.policy, opportunity, (), coverage="full", input_versions=versions,
            now=1.0, read_set=self._read_set(opportunity),
        )
        self.assertEqual(old.result, "unknown")
        current_intent = replace(intent, required_checks=(replace(
            intent.required_checks[0], required_input_versions=current_versions,
        ),))
        denied = trusted.contact_policy_required_check(
            current_intent, current_policy, opportunity, (), coverage="full",
            input_versions=current_versions, now=1.0, read_set=current,
        )
        self.assertEqual(denied.result, "fail")

    def test_unknown_segment_holds_contact_occupancy_and_new_contact_id_cannot_bypass_no_response_gate(self):
        opportunity = ProactiveOpportunity("opportunity:one", self.namespace, "source:milestone", "user:one", "private", "ordinary", 0.0, 10.0)
        claim = self.domain.claim_contact_window(self.policy, opportunity, "contact:one", "action:one", ("effect:one",), (), now=1.0)
        unknown = self.domain.observe_segment(claim, "effect:one", "unknown")
        self.assertEqual(unknown.status, "pending_confirmation")
        second = ProactiveOpportunity("opportunity:two", self.namespace, "source:other", "user:one", "private", "ordinary", 1.0, 10.0)
        check = self.domain.contact_policy_check(self.policy, second, (unknown,), now=2.0)
        self.assertEqual(check.result, "fail")
        self.assertIn("no_response_gate", check.reasons)

    def test_original_contact_continuation_uses_existing_quota_but_cannot_retry_unknown(self):
        opportunity = ProactiveOpportunity("opportunity:one", self.namespace, "source:milestone", "user:one",
                                           "private", "ordinary", 0.0, 10.0)
        original = self.domain.claim_contact_window(
            self.policy, opportunity, "contact:one", "communication:one",
            ("effect:first", "effect:second"), (), now=1.0,
        )
        unknown = self.domain.observe_segment(original, "effect:first", "unknown")
        continuation = ContactContinuation("contact:one", "communication:one", "effect:second")
        held = self.domain.contact_policy_check(self.policy, opportunity, (unknown,),
                                                 now=2.0, continuation=continuation)
        self.assertEqual(held.result, "fail")
        self.assertIn("prior_segment_unknown", held.reasons)
        self.assertFalse(held.dispatch_authorized)
        fresh = self.domain.contact_policy_check(self.policy, opportunity, (unknown,), now=2.0)
        self.assertIn("no_response_gate", fresh.reasons)
        self.assertIn("quota", fresh.reasons)

        retry_unknown = self.domain.contact_policy_check(
            self.policy, opportunity, (unknown,), now=2.0,
            continuation=ContactContinuation("contact:one", "communication:one", "effect:first"),
        )
        self.assertIn("segment_already_observed", retry_unknown.reasons)
        for forged in (
            ContactContinuation("contact:new", "communication:one", "effect:second"),
            ContactContinuation("contact:one", "communication:new", "effect:second"),
            ContactContinuation("contact:one", "communication:one", "effect:extra"),
        ):
            result = self.domain.contact_policy_check(self.policy, opportunity, (unknown,),
                                                      now=2.0, continuation=forged)
            self.assertEqual(result.result, "fail")

        quiet = replace(self.policy, quiet=True)
        self.assertIn("quiet_hours", self.domain.contact_policy_check(
            quiet, opportunity, (unknown,), now=2.0, continuation=continuation,
        ).reasons)

    def test_restart_uses_claim_representation_and_only_proven_zero_handoff_releases_it(self):
        opportunity = ProactiveOpportunity("opportunity:one", self.namespace, "source:milestone", "user:one", "private", "ordinary", 0.0, 10.0)
        claim = self.domain.claim_contact_window(self.policy, opportunity, "contact:one", "action:one", ("effect:one", "effect:two"), (), now=1.0)
        no_first = self.domain.observe_segment(claim, "effect:one", "not_handed_off")
        released = self.domain.release_contact(no_first)
        self.assertEqual(released.status, "claimed")
        none = self.domain.observe_segment(no_first, "effect:two", "not_handed_off")
        released = self.domain.release_contact(none)
        self.assertEqual(released.status, "released")

    def test_later_unhanded_segment_does_not_clear_prior_handoff_or_unknown(self):
        opportunity = ProactiveOpportunity("opportunity:one", self.namespace, "source:milestone", "user:one", "private", "ordinary", 0.0, 10.0)
        claim = self.domain.claim_contact_window(self.policy, opportunity, "contact:one", "action:one", ("effect:one", "effect:two"), (), now=1.0)
        for first_observation, held_status in (("handed_off", "handed_off"),
                                               ("unknown", "pending_confirmation")):
            first = self.domain.observe_segment(claim, "effect:one", first_observation)
            second = self.domain.observe_segment(first, "effect:two", "not_handed_off")
            self.assertEqual(second.status, held_status)
            later = ProactiveOpportunity("opportunity:two", self.namespace, "source:other", "user:one", "private", "ordinary", 1.0, 10.0)
            check = self.domain.contact_policy_check(self.policy, later, (second,), now=2.0)
            self.assertIn("no_response_gate", check.reasons)
            with self.assertRaises(ValueError):
                replace(second, status="released")

    def test_type_specs_bind_each_d10_type_to_its_writer_schema_owner_and_validator(self):
        specs = self.domain.type_specs()
        project = next(spec for spec in specs if spec.name == "d10.life_project.v1")
        self.assertEqual(project.writer_domain, "d10")
        self.assertEqual(project.owner_kinds, ("persona",))
        self.assertEqual(project.storage_role, "state")
        self.assertEqual(project.to_graph_spec().writer_domain, "d10")
        self.assertEqual(project.to_graph_spec().schema_hash, project.schema_hash)
        project.to_graph_spec().validator({
            "project_id": "project:one", "topic": "poetry", "reality": "role_simulation", "next_step": "step:one"
        })
        with self.assertRaises(ValueError):
            project.to_graph_spec().validator({"project_id": "project:one"})


class ProjectCheckpointContractTests(unittest.TestCase):
    def test_work_versions_are_effect_bound_and_do_not_mutate_initial_project_definition(self):
        from sylanne3.domains.d10.project_checkpoint_v1 import (ProjectCheckpointV1, ProjectWorkVersionV1,
            project_work_version_key_v1, project_checkpoint_key_v1, decode_project_checkpoint_type_v1, WORK_TYPE)
        from sylanne3.graph_types import AtomKey, Owner
        from sylanne3.memory_types import source_key
        from sylanne3.domains.d01.production_operations_v1 import plain_v1
        namespace = NamespaceId("bot", "persona")
        project = AtomKey(Owner("persona", "bot", "persona"), "d10.life_project.v1", "project:one").token
        owner = Owner("activity", "bot", "persona", "activity:one")
        plan = AtomKey(owner, "d08.personal_plan.v1", "plan:one").token
        progress = AtomKey(owner, "d10.life_progress.v1", "effect:one").token
        outcome = AtomKey(owner, "d08.action_outcome.v1", "outcome:one").token
        source = source_key("bot", "persona", "original").token
        work = ProjectWorkVersionV1(project, "registered-root:target-one", 1, progress, "artifact:one", "a" * 64,
            12, "terminal:one", outcome, (source,), (VersionedRef(source, 1),),
            "activity:one", "effect:one", "attempt:one", "task:draft")
        key = project_work_version_key_v1(namespace, project, work.effect_id)
        checkpoint = ProjectCheckpointV1(project, 2, plan, 1, ("task:draft",), (progress,), (key.token,),
            None, "completed", (VersionedRef(source, 1),))
        self.assertEqual(decode_project_checkpoint_type_v1(WORK_TYPE, plain_v1(work)), work)
        self.assertNotEqual(key, project_work_version_key_v1(namespace, project, "effect:two"))
        self.assertNotEqual(project_checkpoint_key_v1(namespace, project).token, project)
        self.assertIsNone(checkpoint.next_step)
        with self.assertRaises(ValueError):
            replace(checkpoint, state="active", next_step="task:draft")

    def test_waiting_requires_original_job_and_observed_watermark_in_checkpoint(self):
        from sylanne3.domains.d10.project_checkpoint_v1 import ProjectCheckpointV1, ProjectWaitConditionV1
        from sylanne3.graph_types import AtomKey, Owner
        from sylanne3.memory_types import source_key
        namespace = NamespaceId("bot", "persona")
        owner = Owner("activity", "bot", "persona", "activity:one")
        project = AtomKey(Owner("persona", "bot", "persona"), "d10.life_project.v1", "project:one").token
        plan = AtomKey(owner, "d08.personal_plan.v1", "plan:one").token
        source = source_key("bot", "persona", "original").token
        job = AtomKey(owner, "runtime.job", "job:original").token
        wake = ProjectWaitConditionV1("d11", "original_effect_observed", (VersionedRef(source, 1),),
            QueryEpoch(namespace, "namespace", 7), job, 4)
        checkpoint = ProjectCheckpointV1(project, 1, plan, 1, (), (), (), None, "waiting", (VersionedRef(source, 1),), wake)
        self.assertEqual(checkpoint.wait_condition.resume_job_ref, job)
        with self.assertRaises(ValueError):
            replace(checkpoint, wait_condition=None)


if __name__ == "__main__":
    unittest.main()
