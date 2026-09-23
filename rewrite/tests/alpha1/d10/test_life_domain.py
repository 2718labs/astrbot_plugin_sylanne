import unittest
from dataclasses import replace

from sylanne3.domains.d10 import (
    ActivityOutcome,
    ActivityRecipe,
    CharacterClockMappingProposal,
    ContactPolicy,
    LifeDomain,
    LifeProject,
    ProactiveOpportunity,
)
from sylanne3.runtime_contracts import NamespaceId


class LifeDomainTests(unittest.TestCase):
    def setUp(self):
        self.domain = LifeDomain()
        self.namespace = NamespaceId("bot", "persona")
        self.policy = ContactPolicy(
            policy_id="policy:one", namespace=self.namespace, version=1, subject_ref="user:one",
            channel="private", category="ordinary", consent=True, quiet=False,
            quota_limit=1, window_start=0.0, window_end=24.0,
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

    def test_unknown_segment_holds_contact_occupancy_and_new_contact_id_cannot_bypass_no_response_gate(self):
        opportunity = ProactiveOpportunity("opportunity:one", self.namespace, "source:milestone", "user:one", "private", "ordinary", 0.0, 10.0)
        claim = self.domain.claim_contact_window(self.policy, opportunity, "contact:one", "action:one", ("effect:one",), (), now=1.0)
        unknown = self.domain.observe_segment(claim, "effect:one", "unknown")
        self.assertEqual(unknown.status, "pending_confirmation")
        second = ProactiveOpportunity("opportunity:two", self.namespace, "source:other", "user:one", "private", "ordinary", 1.0, 10.0)
        check = self.domain.contact_policy_check(self.policy, second, (unknown,), now=2.0)
        self.assertEqual(check.result, "fail")
        self.assertIn("no_response_gate", check.reasons)

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


if __name__ == "__main__":
    unittest.main()
