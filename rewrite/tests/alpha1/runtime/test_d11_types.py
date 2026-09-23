import sqlite3
import unittest
from dataclasses import replace

from sylanne3.graph_types import GraphWrite, TypeRegistry
from sylanne3.runtime import install_schema
from sylanne3.runtime.budget import (
    BudgetLease,
    create_budget_lease,
    reserve_budget,
    settle_budget,
)
from sylanne3.runtime.d11_types import (
    D11_PROPOSAL_SCHEMA,
    D11_PROPOSAL_SCHEMA_HASH,
    D11RuntimeProvider,
    RuntimeCostSettlement,
    RuntimeOutboxValue,
    cost_settlement_from_runtime,
    cost_settlement_graph_write,
    graph_type_specs,
    job_graph_write,
    outbox_graph_write,
    reconcile_runtime_write,
    runtime_cost_settlement_key,
    validate_d11_writes,
)
from sylanne3.runtime.jobs import PersistentJob, create_job
from sylanne3.runtime_contracts import NamespaceId


class D11RuntimeTypeTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        install_schema(self.db)
        self.namespace = NamespaceId("bot", "persona")
        self.digest = "a" * 64
        create_budget_lease(
            self.db,
            BudgetLease(
                "parent", None, "bot", "persona", "USD",
                {"model_microusd": 1_000}, {}, {}, {}, 1, "active",
            ),
            "create-parent", "b" * 64,
        )
        self.job = PersistentJob(
            "job-1", "op-1", "activity-1", None, "bot", "persona",
            "snapshot:1", "queued", "native_batch", {"offset": 0}, None,
            "2026-09-24T00:00:00Z", "parent", "resource:1", {"native": "2"},
            None, None, 0, 0, {}, None,
        )
        create_job(self.db, self.job, "create-job", "c" * 64)

    def tearDown(self):
        self.db.close()

    def settle_known(self):
        reserve_budget(
            self.db, "parent", "op-1", self.digest,
            {"model_microusd": 200},
        )
        settle_budget(
            self.db, "parent", "op-1", self.digest,
            {"model_microusd": 125}, execution_revoked=True,
        )

    def known_cost(self):
        return cost_settlement_from_runtime(
            self.db,
            bot_id="bot", persona_id="persona", activity_id="activity-1",
            bundle_operation_id="op-1", effect_id=None,
            settlement_id="cost-1", lease_id="parent",
            cost_operation_id="op-1", budget_operation_id="op-1",
            budget_phase="settle", prior_unknown_ref=None,
            execution_revoked=True,
        )

    def outbox(self, *, operation_id="op-1", outbox_id="outbox-1"):
        job_write = job_graph_write(self.job)
        value = RuntimeOutboxValue(
            "bot", "persona", "activity-1", operation_id, None,
            outbox_id, "job-1", job_write.key.token, "payload:1",
            "idempotency:1", "pending", 0,
        )
        return outbox_graph_write(value, job_write.key)

    def test_specs_are_stable_strict_and_owned_only_by_d11(self):
        specs = graph_type_specs()
        self.assertEqual(
            tuple(spec.name for spec in specs),
            ("runtime.cost_settlement", "runtime.job", "runtime.outbox"),
        )
        self.assertTrue(all(spec.writer_domain == "d11" for spec in specs))
        self.assertTrue(all(spec.owner_kinds == ("activity",) for spec in specs))
        self.assertTrue(all(len(spec.schema_hash) == 64 for spec in specs))
        self.assertEqual(D11_PROPOSAL_SCHEMA, "d11.runtime.proposal.v1")
        self.assertEqual(len(D11_PROPOSAL_SCHEMA_HASH), 64)
        provider = D11RuntimeProvider()
        self.assertEqual(provider.register_types(), tuple(spec.name for spec in specs))
        self.assertEqual(provider.descriptor.provider_id, "d11.runtime")
        registry = TypeRegistry()
        for spec in specs:
            registry.register(spec)
        job_write = job_graph_write(self.job)
        registry.validate(job_write.key, job_write.value)
        with self.assertRaises(ValueError):
            registry.validate(job_write.key, {**job_write.value, "extra": True})

    def test_job_outbox_and_known_cost_reconcile_with_runtime_authority(self):
        self.settle_known()
        job_write = job_graph_write(self.job)
        outbox_write = self.outbox()
        cost_write = cost_settlement_graph_write(self.known_cost())
        validate_d11_writes(
            (job_write, outbox_write, cost_write), self.namespace,
            operation_id="op-1", activity_id="activity-1", effect_id=None,
        )
        for write in (job_write, outbox_write, cost_write):
            self.assertTrue(reconcile_runtime_write(self.db, write))

    def test_forged_zero_cost_does_not_match_authoritative_receipt(self):
        self.settle_known()
        valid = self.known_cost()
        forged = RuntimeCostSettlement(
            **{**valid.__dict__, "actual": {},
               "budget_receipt_digest": "f" * 64}
        )
        with self.assertRaises(ValueError):
            reconcile_runtime_write(
                self.db, cost_settlement_graph_write(forged)
            )

    def test_cross_operation_and_duplicate_outbox_are_rejected(self):
        job_write = job_graph_write(self.job)
        with self.assertRaises(ValueError):
            validate_d11_writes(
                (job_write, self.outbox(operation_id="other")), self.namespace,
                operation_id="op-1", activity_id="activity-1", effect_id=None,
            )
        first = self.outbox()
        duplicate = GraphWrite(
            replace(first.key, name="another-key"), first.value,
            first.dependencies,
        )
        with self.assertRaises(ValueError):
            validate_d11_writes(
                (job_write, first, duplicate), self.namespace,
                operation_id="op-1", activity_id="activity-1", effect_id=None,
            )

    def test_unknown_cannot_become_settled_without_independent_resolution(self):
        reserve_budget(
            self.db, "parent", "op-unknown", "d" * 64,
            {"model_microusd": 300},
        )
        settle_budget(
            self.db, "parent", "op-unknown", "d" * 64, actual=None,
        )
        pending = cost_settlement_from_runtime(
            self.db,
            bot_id="bot", persona_id="persona", activity_id="activity-1",
            bundle_operation_id="op-unknown", effect_id=None,
            settlement_id="cost-unknown", lease_id="parent",
            cost_operation_id="op-unknown", budget_operation_id="op-unknown",
            budget_phase="settle", prior_unknown_ref=None,
            execution_revoked=False,
        )
        self.assertEqual(pending.status, "pending_confirmation")
        self.assertIsNone(pending.actual)
        self.assertEqual(pending.unconfirmed, pending.ceiling)
        prior_ref = runtime_cost_settlement_key(
            "bot", "persona", "activity-1", "cost-unknown"
        ).token
        with self.assertRaises(ValueError):
            RuntimeCostSettlement(
                **{**pending.__dict__, "status": "settled", "actual": {},
                   "unconfirmed": {}, "prior_unknown_ref": prior_ref,
                   "execution_revoked": True}
            )


if __name__ == "__main__":
    unittest.main()
