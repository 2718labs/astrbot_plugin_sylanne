import sqlite3
import time
import unittest

from sylanne3.graph_coordinator import budget_operation_digest
from sylanne3.runtime import install_schema as install_runtime_schema
from sylanne3.runtime.budget import BudgetLease, create_budget_lease, reserve_budget
from sylanne3.runtime.d11_types import runtime_job_key, runtime_outbox_key
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant,
    D02ResourceIssuer,
    D11BudgetJobIssuer,
    IssuerAuthorityDenied,
    ResourceOutcome,
    ResourceQuote,
    build_runtime_issuers,
    install_schema as install_issuer_schema,
)
from sylanne3.runtime.jobs import create_job
from sylanne3.runtime_contracts import (
    RUNTIME_SCHEMA,
    AuthorityContext,
    CommandEnvelope,
    DomainBundle,
    NamespaceId,
    OperationIdentity,
    SourceQualification,
    VersionGuard,
    VersionedRef,
    canonical_digest,
)


class ProductionIssuerTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        install_runtime_schema(self.db)
        install_issuer_schema(self.db)
        self.d02, self.d11 = build_runtime_issuers(
            b"k" * 32,
            outcome_verifier=lambda outcome, quote, db: (
                outcome.provider_receipt_ref == "provider-receipt-1"
                and outcome.operation_id == quote.operation_id
            ),
        )
        self.namespace = NamespaceId("bot", "persona")
        self.job_ref = runtime_job_key(
            "bot", "persona", "activity-1", "job-1"
        ).token
        self.outbox_ref = runtime_outbox_key(
            "bot", "persona", "activity-1", "outbox-1"
        ).token
        self.envelope = self.make_envelope()
        create_budget_lease(
            self.db,
            BudgetLease(
                "parent", None, "bot", "persona", "USD",
                {"cpu_ms": 10_000, "model_microusd": 5_000},
                {}, {}, {}, 1, "active",
            ),
            "create-parent", "a" * 64,
        )

    def make_envelope(self, *, worker_fence=None, deadline=4_102_444_800.0):
        identity = OperationIdentity(
            "activity-1", None, "attempt-1", "run", "op-1",
            canonical_digest({"input_refs": []}),
        )
        authority = AuthorityContext(
            "worker-1", "d11", "capability-1", self.namespace,
            ("activity",), "consolidation", ("internal",), "policy-1", 1,
            worker_fence,
        )
        guard = VersionGuard(
            (), (), 0, 0, "catalogue-1", "scheme-1", "operator-1", "policy-1",
            (), (), (VersionedRef("quote-1", 1),),
        )
        source = SourceQualification(
            (), "reported", 1.0, 1.0, "external_report", "qualified", 0.5,
            "not_applicable",
        )
        return CommandEnvelope(
            RUNTIME_SCHEMA, identity, authority, guard, source, (), "parent",
            deadline, 100.0, "character-1", (),
        )

    def quote(self, *, ceiling=None, worker_fence=None,
              deadline=4_102_444_800.0, valid_until=4_102_444_900.0):
        return ResourceQuote(
            "quote-1", 1, "bot", "persona", "activity-1", "op-1", None,
            "parent", "encode", "snapshot-1", deadline,
            "resource-1", self.job_ref, (self.outbox_ref,), (),
            ceiling or {"cpu_ms": 200, "model_microusd": 300},
            worker_fence, valid_until,
        )

    def grant(self, *, max_ceiling=None):
        return BudgetLeaseGrant(
            "grant-1", 1, "bot", "persona", "parent", "USD",
            max_ceiling or {"cpu_ms": 1_000, "model_microusd": 1_000},
            ("encode",), 4_102_445_000.0, "policy-1",
        )

    def bundle(self, *, settle=False):
        return DomainBundle(
            self.envelope, (), (), (), (),
            ("cost-token",) if settle else (), ("idempotency-1",),
            (self.job_ref,), (self.outbox_ref,),
        )

    def issue_authorities(self, *, quote=None, grant=None):
        self.d02.issue_quote(self.db, quote or self.quote())
        self.d11.issue_budget_grant(self.db, grant or self.grant())

    def test_missing_or_tampered_quote_fails_closed(self):
        with self.assertRaises(IssuerAuthorityDenied):
            self.d02.authorize_schedule(self.envelope, self.db)
        self.issue_authorities()
        self.assertTrue(self.d02.authorize_schedule(self.envelope, self.db))
        self.db.execute(
            "UPDATE runtime_resource_quotes SET quote_json=replace(quote_json,'200','1') "
            "WHERE quote_id='quote-1' AND version=1"
        )
        with self.assertRaises(IssuerAuthorityDenied):
            self.d02.authorize_schedule(self.envelope, self.db)

    def test_schedule_admission_uses_signed_quote_ceiling_and_lease(self):
        self.issue_authorities()
        admission = self.d11.admit_schedule(self.envelope, self.db)
        self.assertEqual(admission.budget.ceiling,
                         {"cpu_ms": 200, "model_microusd": 300})
        self.assertEqual(admission.budget.lease_id, "parent")
        self.assertEqual(admission.job.job_id, "job-1")
        self.assertEqual(admission.job.resource_ref, "resource-1")
        with self.assertRaises(IssuerAuthorityDenied):
            other_d02, other_d11 = build_runtime_issuers(b"x" * 32)
            other_d11.admit_schedule(self.envelope, self.db)

    def test_quote_cannot_exceed_signed_budget_grant(self):
        self.issue_authorities(
            quote=self.quote(ceiling={"cpu_ms": 200}),
            grant=self.grant(max_ceiling={"cpu_ms": 100}),
        )
        with self.assertRaises(IssuerAuthorityDenied):
            self.d11.admit_schedule(self.envelope, self.db)

    def test_past_command_quote_and_grant_are_rejected_against_current_utc(self):
        past = time.time() - 60.0
        self.envelope = self.make_envelope(deadline=past)
        self.issue_authorities(
            quote=self.quote(deadline=past, valid_until=past + 10.0),
            grant=BudgetLeaseGrant(
                "grant-1", 1, "bot", "persona", "parent", "USD",
                {"cpu_ms": 1_000, "model_microusd": 1_000},
                ("encode",), past + 20.0, "policy-1",
            ),
        )
        with self.assertRaises(IssuerAuthorityDenied):
            self.d02.authorize_schedule(self.envelope, self.db)
        with self.assertRaises(IssuerAuthorityDenied):
            self.d11.admit_schedule(self.envelope, self.db)

    def test_runtime_admission_uses_durable_reservation_job_and_signed_outcome(self):
        self.issue_authorities()
        schedule = self.d11.admit_schedule(self.envelope, self.db)
        digest = budget_operation_digest(
            self.envelope, "parent", schedule.budget.ceiling,
        )
        reserve_budget(self.db, "parent", "op-1", digest,
                       schedule.budget.ceiling)
        create_job(self.db, schedule.job, "create-job", digest)
        self.d02.issue_outcome(
            self.db,
            ResourceOutcome(
                "outcome-1", 1, "quote-1", "bot", "persona", "activity-1",
                "op-1", {"cpu_ms": 180, "model_microusd": 250}, True,
                "provider-receipt-1",
            ),
        )
        admission = self.d11.admit_runtime(self.bundle(settle=True), self.db)
        self.assertTrue(admission.budget.pre_reserved)
        self.assertTrue(admission.budget.settle_now)
        self.assertEqual(admission.budget.actual,
                         {"cpu_ms": 180, "model_microusd": 250})
        self.assertEqual(admission.budget.reservation_operation_id, "op-1")
        self.assertEqual(admission.jobs[0].job, schedule.job)
        self.assertEqual(admission.jobs[0].outbox_refs, (self.outbox_ref,))

    def test_settlement_without_signed_outcome_never_manufactures_zero_cost(self):
        self.issue_authorities()
        with self.assertRaises(IssuerAuthorityDenied):
            self.d11.admit_runtime(self.bundle(settle=True), self.db)

    def test_outcome_without_server_side_verifier_is_not_authority(self):
        unverified_d02, _ = build_runtime_issuers(b"z" * 32)
        unverified_d02.issue_quote(self.db, ResourceQuote(
            "quote-unverified", 1, "bot", "persona", "activity-1", "op-1", None,
            "parent", "encode", "snapshot-1", 4_102_444_800.0,
            "resource-1", self.job_ref, (), (), {"cpu_ms": 200}, None,
            4_102_444_900.0,
        ))
        with self.assertRaises(IssuerAuthorityDenied):
            unverified_d02.issue_outcome(
                self.db,
                ResourceOutcome(
                    "unverified", 1, "quote-unverified", "bot", "persona",
                    "activity-1", "op-1", {"cpu_ms": 1}, True,
                    "untrusted-receipt",
                ),
            )

    def test_worker_fence_is_bound_to_quote_and_durable_job(self):
        self.envelope = self.make_envelope(worker_fence=2)
        self.issue_authorities(quote=self.quote(worker_fence=1))
        with self.assertRaises(IssuerAuthorityDenied):
            self.d02.authorize_resources(self.bundle(), self.db)


if __name__ == "__main__":
    unittest.main()
