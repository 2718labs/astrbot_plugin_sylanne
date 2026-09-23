"""A supplied Authority UTC must survive every issuer admission layer."""

import sqlite3
import unittest
from unittest.mock import patch

from sylanne3.runtime import install_schema as install_runtime_schema
from sylanne3.runtime.budget import BudgetLease, create_budget_lease
from sylanne3.runtime.d11_types import runtime_job_key
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, IssuerAuthorityDenied, ResourceQuote,
    build_runtime_issuers, install_schema as install_issuer_schema,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DomainBundle, NamespaceId,
    OperationIdentity, RUNTIME_SCHEMA, SourceQualification, VersionGuard,
    VersionedRef, canonical_digest,
)


class ExplicitIssuerTimeTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        install_runtime_schema(self.db)
        install_issuer_schema(self.db)
        self.d02, self.d11 = build_runtime_issuers(b"k" * 32)
        self.deadline = 4_102_444_800.0
        self.envelope = CommandEnvelope(
            RUNTIME_SCHEMA,
            OperationIdentity("activity-1", None, "attempt-1", "run", "op-1",
                              canonical_digest({"input_refs": []})),
            AuthorityContext("worker-1", "d11", "capability-1",
                             NamespaceId("bot", "persona"), ("activity",),
                             "consolidation", ("internal",), "policy-1", 1, None),
            VersionGuard((), (), 0, 0, "catalogue-1", "scheme-1",
                         "operator-1", "policy-1", (), (),
                         (VersionedRef("quote-1", 1),)),
            SourceQualification((), "reported", 1.0, 1.0, "external_report",
                                "qualified", 0.5, "not_applicable"),
            (), "parent", self.deadline, 100.0, "character-1", (),
        )
        self.job_ref = runtime_job_key(
            "bot", "persona", "activity-1", "job-1"
        ).token
        self.bundle = DomainBundle(
            self.envelope, (), (), (), (), (), ("idempotency-1",),
            (self.job_ref,), (),
        )
        create_budget_lease(
            self.db,
            BudgetLease("parent", None, "bot", "persona", "USD",
                        {"cpu_ms": 1000}, {}, {}, {}, 1, "active"),
            "create-parent", "a" * 64,
        )
        self.d02.issue_quote(self.db, ResourceQuote(
            "quote-1", 1, "bot", "persona", "activity-1", "op-1", None,
            "parent", "encode", "snapshot-1", self.deadline,
            "resource-1", self.job_ref, (), (), {"cpu_ms": 200},
            None, self.deadline + 100,
        ))
        self.d11.issue_budget_grant(self.db, BudgetLeaseGrant(
            "grant-1", 1, "bot", "persona", "parent", "USD",
            {"cpu_ms": 1000}, ("encode",), self.deadline + 200, "policy-1",
        ))

    def tearDown(self):
        self.db.close()

    def test_explicit_time_reaches_all_nested_checks_without_reading_host_clock(self):
        now = self.deadline - 1
        with patch("sylanne3.runtime.issuers.time.time",
                   side_effect=AssertionError("host clock was read")):
            self.assertEqual(self.d02.qualified_quote(
                self.envelope, self.db, now_utc=now).quote_id, "quote-1")
            self.assertTrue(self.d02.authorize_schedule(
                self.envelope, self.db, now_utc=now))
            self.assertTrue(self.d02.authorize_resources(
                self.bundle, self.db, now_utc=now))
            self.assertEqual(self.d11.job_for(
                self.envelope, self.db, now_utc=now).job_id, "job-1")
            self.assertEqual(self.d11.admit_schedule(
                self.envelope, self.db, now_utc=now).job.job_id, "job-1")
            self.assertEqual(self.d11.admit_runtime(
                self.bundle, self.db, now_utc=now).jobs[0].job.job_id,
                "job-1")

    def test_explicit_expired_time_is_rejected_even_when_host_clock_is_earlier(self):
        with patch("sylanne3.runtime.issuers.time.time",
                   return_value=self.deadline - 1):
            for call, value in (
                (self.d02.qualified_quote, self.envelope),
                (self.d02.authorize_schedule, self.envelope),
                (self.d02.authorize_resources, self.bundle),
                (self.d11.job_for, self.envelope),
                (self.d11.admit_schedule, self.envelope),
                (self.d11.admit_runtime, self.bundle),
            ):
                with self.subTest(call=call.__name__):
                    with self.assertRaises(IssuerAuthorityDenied):
                        call(value, self.db, now_utc=self.deadline)

    def test_omitted_time_keeps_host_clock_and_nonfinite_time_is_invalid(self):
        with patch("sylanne3.runtime.issuers.time.time",
                   return_value=self.deadline - 1):
            self.assertEqual(self.d11.job_for(
                self.envelope, self.db).job_id, "job-1")
        with patch("sylanne3.runtime.issuers.time.time",
                   return_value=self.deadline):
            with self.assertRaises(IssuerAuthorityDenied):
                self.d11.job_for(self.envelope, self.db)
        for invalid in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    self.d11.admit_runtime(self.bundle, self.db, now_utc=invalid)


if __name__ == "__main__":
    unittest.main()
