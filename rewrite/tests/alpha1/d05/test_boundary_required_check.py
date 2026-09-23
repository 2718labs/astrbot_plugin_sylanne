import unittest

from sylanne3.domains.d05 import BoundaryRule, BoundaryRuleReadSet, RelationshipProvider
from sylanne3.domains.d08.execution import ActionIntent, ActionSchema, GoalPredicate, RequiredCheckSpec
from sylanne3.runtime_contracts import (
    NamespaceId, OperationIdentity, QueryEpoch, VersionedRef, canonical_digest,
)


class BoundaryRequiredCheckTests(unittest.TestCase):
    def setUp(self):
        self.namespace = NamespaceId("bot", "persona")
        self.rule = BoundaryRule(
            rule_id="boundary:no-contact", subject_persona_ref="persona:persona",
            target_entity_ref="entity:alice", action_kind="message", audience_scope="direct",
            scene_ref=None, effect="deny", basis="counterparty_explicit",
            source_refs=("source:no-contact",), communicated_refs=("receipt:delivered",),
            acknowledged_refs=(), valid_from=1.0, valid_until=None, scope_version=4,
            revision_actor="entity:alice", exception_refs=(), status="active",
        )
        self.required_versions = (
            VersionedRef("criteria:d05-boundary-v1", 1),
            VersionedRef("d05.boundary", 7),
            VersionedRef(self.rule.rule_id, self.rule.scope_version),
        )
        self.spec = RequiredCheckSpec(
            "boundary", "d05.boundary", "persona:persona", "action:send",
            "respond", "criteria:d05-boundary-v1", self.required_versions,
        )
        self.schema = ActionSchema("schema:send", "message", False, (self.spec,))
        self.intent = ActionIntent(
            action_id="action:send", revision=1, goal_ref="goal:reply", commitment_refs=(),
            target_ref="entity:alice", action_kind="message", purpose="respond",
            risk_class="reversible", parameters_digest="a" * 64,
            identity=OperationIdentity("activity:send", "effect:send", "attempt:send", "prepare",
                                       "operation:send", canonical_digest({"input_refs": ["source:request"]})),
            schema_id=self.schema.schema_id, required_checks=(self.spec,),
            success_predicate=GoalPredicate("communicated", "d11.delivery", (), 0.0, None),
            effect_scope=("message:entity:alice",), compensation_ref=None,
            source_refs=("source:request",),
        )
        self.read_set = BoundaryRuleReadSet(
            namespace=self.namespace,
            query_epoch=QueryEpoch(self.namespace, "d05.boundary", 7),
            rules=(self.rule,), input_versions=self.required_versions, coverage="full",
        )

    def check(self, *, verifier=lambda _read: True, read_set=None, valid_until=20.0):
        return RelationshipProvider(boundary_read_verifier=verifier).boundary_required_check(
            self.intent, self.schema, self.read_set if read_set is None else read_set,
            audience_scope="direct", scene_ref=None, at_time=5.0, valid_until=valid_until,
        )

    def test_current_complete_no_contact_boundary_fails_action_check(self):
        receipt = self.check()
        self.assertEqual((receipt.check_kind, receipt.issuer), ("boundary", "d05.boundary"))
        self.assertEqual((receipt.coverage, receipt.result), ("full", "fail"))
        self.assertEqual(receipt.input_versions, self.required_versions)

    def test_missing_current_graph_proof_is_unknown(self):
        receipt = self.check(verifier=lambda _read: False)
        self.assertEqual(receipt.result, "unknown")

    def test_revoked_boundary_is_not_treated_as_permission_without_requalification(self):
        revoked = BoundaryRule(**{**self.rule.__dict__, "status": "revoked"})
        versions = (VersionedRef("criteria:d05-boundary-v1", 1), VersionedRef("d05.boundary", 7),
                    VersionedRef(revoked.rule_id, revoked.scope_version))
        read_set = BoundaryRuleReadSet(self.namespace, self.read_set.query_epoch, (revoked,), versions, "full")
        self.assertEqual(self.check(read_set=read_set).result, "unknown")

    def test_partial_or_stale_boundary_read_is_unknown(self):
        partial = BoundaryRuleReadSet(
            self.namespace, self.read_set.query_epoch, self.read_set.rules,
            self.required_versions, "partial", ("boundary_query_incomplete",),
        )
        stale = BoundaryRuleReadSet(
            self.namespace, self.read_set.query_epoch, self.read_set.rules,
            (VersionedRef("criteria:d05-boundary-v1", 1), VersionedRef("d05.boundary", 6),
             VersionedRef(self.rule.rule_id, self.rule.scope_version)), "full",
        )
        self.assertEqual(self.check(read_set=partial).result, "unknown")
        self.assertEqual(self.check(read_set=stale).result, "unknown")

    def test_intent_target_is_bound_to_rule_query_and_full_pass_is_not_overlong(self):
        wrong_target_rule = BoundaryRule(
            **{**self.rule.__dict__, "target_entity_ref": "entity:bob"}
        )
        mismatch = BoundaryRuleReadSet(
            self.namespace, self.read_set.query_epoch, (wrong_target_rule,),
            self.required_versions, "full",
        )
        self.assertEqual(self.check(read_set=mismatch).result, "unknown")
        # A pass can never outlive a rule's explicit validity interval.
        allow_rule = BoundaryRule(
            **{**self.rule.__dict__, "effect": "allow", "basis": "self_internal", "valid_until": 8.0}
        )
        versions = (VersionedRef("criteria:d05-boundary-v1", 1), VersionedRef("d05.boundary", 7),
                    VersionedRef(allow_rule.rule_id, allow_rule.scope_version))
        allowed = BoundaryRuleReadSet(self.namespace, self.read_set.query_epoch, (allow_rule,), versions, "full")
        receipt = self.check(read_set=allowed, valid_until=15.0)
        self.assertEqual((receipt.result, receipt.valid_until), ("pass", 8.0))


if __name__ == "__main__":
    unittest.main()
