"""The original model expense survives a failed or unusable content result."""

import sqlite3
import unittest

from sylanne3.authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelTerminalReceiptV2,
)
from sylanne3.runtime.budget import (
    BudgetLease, create_budget_lease, get_budget_lease, install_schema,
    reserve_budget, resolve_unconfirmed, settle_budget,
)
from sylanne3.runtime.d11_types import cost_settlement_from_runtime
from sylanne3.runtime.model_cost_settlement import (
    ModelCostUnavailable, OriginalModelCostFactV1,
    original_model_budget_actual, outcome_from_original_model_cost,
)
from sylanne3.runtime.issuers import (
    D02ResourceIssuer, IssuerAuthorityDenied, ResourceQuote,
    install_schema as install_issuer_schema,
)


class IndependentCostTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        install_schema(self.db)
        install_issuer_schema(self.db)
        create_budget_lease(
            self.db,
            BudgetLease("lease", None, "bot", "persona", "USD",
                        {"model_tokens": 100, "model_microusd": 100},
                        {}, {}, {}, 1, "active"),
            "create", "a" * 64,
        )
        self.ceiling = {"model_tokens": 80, "model_microusd": 80}
        reserve_budget(self.db, "lease", "original", "b" * 64, self.ceiling)

    def tearDown(self):
        self.db.close()

    def test_original_overrun_is_durable_debt_and_replay_is_idempotent(self):
        actual = {"model_tokens": 120, "model_microusd": 90}
        first = settle_budget(self.db, "lease", "original", "b" * 64,
                              actual, execution_revoked=True)
        self.assertEqual(first.status, "overrun")
        self.assertEqual(settle_budget(self.db, "lease", "original", "b" * 64,
                                       actual, execution_revoked=True), first)
        lease = get_budget_lease(self.db, "lease")
        self.assertEqual(lease.used, actual)
        self.assertEqual(lease.available("model_tokens"), 0)
        self.assertEqual(self.db.execute(
            "SELECT state,actual_json FROM runtime_budget_reservations "
            "WHERE lease_id='lease' AND operation_id='original'",
        ).fetchone()[0], "overrun")
        atom = cost_settlement_from_runtime(
            self.db, bot_id="bot", persona_id="persona", activity_id="activity",
            bundle_operation_id="accounting", effect_id=None,
            settlement_id="cost-call", lease_id="lease",
            cost_operation_id="original", budget_operation_id="original",
            budget_phase="settle", prior_unknown_ref=None,
            execution_revoked=True,
        )
        self.assertEqual(atom.status, "overrun")
        self.assertEqual(atom.actual, actual)

    def test_unknown_cost_holds_upper_bound_then_resolves_overrun(self):
        pending = settle_budget(self.db, "lease", "original", "b" * 64, None)
        self.assertEqual(pending.status, "pending_confirmation")
        self.assertEqual(get_budget_lease(self.db, "lease").unconfirmed, self.ceiling)
        resolved = resolve_unconfirmed(
            self.db, "lease", "original", "resolve", "c" * 64,
            {"model_tokens": 110, "model_microusd": 90},
            execution_revoked=True,
        )
        self.assertEqual(resolved.status, "overrun")
        self.assertEqual(get_budget_lease(self.db, "lease").unconfirmed, {})
        self.assertEqual(get_budget_lease(self.db, "lease").used["model_tokens"], 110)

    @staticmethod
    def original_fact(*, state="observed", usage=None, cost=None):
        intent = ModelEgressIntentV1(
            "authority", "authority-ns", "subject", "acquire", "call",
            "a" * 64, "job", 1, "a" * 32, 1, 0, "b" * 64,
            ("source",), (("source", 1),), (("access", 1),),
            1, 0, 1, 1, 1, 0, 0, 0,
            "lease", "original", "b" * 64,
            (("model_microusd", 80), ("model_tokens", 80)),
            "provider", "model", "c" * 64, 32,
        )
        record = ModelEgressRecoveryV1(
            intent, state, "d" * 64,
            tuple(sorted((usage or {}).items())), tuple(sorted((cost or {}).items())),
        )
        admission = ModelAdmissionV2(
            "e" * 64, "authority", "authority-ns", "subject", "acquire",
            "call", "a" * 64, "c" * 64, "install", "f" * 64,
            "observer", "1" * 64, "2" * 64,
        )
        receipt = ModelTerminalReceiptV2(
            "e" * 64, "call", "a" * 64, "3" * 64,
            "d" * 64, "sha256:" + "4" * 64, "install", "2" * 64,
        )
        return OriginalModelCostFactV1(intent, record, admission, receipt)

    def quote(self):
        return ResourceQuote(
            "quote", 1, "bot", "persona", "activity", "original", None,
            "lease", "d06.encode_source", "snapshot", 100.0, "resource",
            None, (), (), self.ceiling, None, 100.0,
        )

    def test_missing_price_keeps_entire_original_ceiling(self):
        fact = self.original_fact(usage={"input_tokens": 40, "output_tokens": 20})
        self.assertIsNone(original_model_budget_actual(fact, self.quote()))
        outcome = outcome_from_original_model_cost(fact, self.quote())
        self.assertIsNone(outcome.actual)
        self.assertTrue(outcome.execution_revoked)

    def test_full_terminal_cost_maps_without_double_counting_cached_tokens(self):
        fact = self.original_fact(
            usage={"input_tokens": 80, "output_tokens": 40,
                   "cached_input_tokens": 30},
            cost={"model_microusd": 90},
        )
        self.assertEqual(original_model_budget_actual(fact, self.quote()),
                         {"model_tokens": 120, "model_microusd": 90})

    def test_v2_output_token_quote_uses_original_output_counter(self):
        quote = ResourceQuote(
            "v2-quote", 1, "bot", "persona", "activity", "original", None,
            "lease", "d06.encode_source", "snapshot", 100.0, "resource",
            None, (), (), {"output_tokens": 80}, None, 100.0,
        )
        fact = self.original_fact(
            usage={"input_tokens": 40, "output_tokens": 72},
        )
        from dataclasses import replace
        intent = replace(fact.intent, budget_ceiling=(("output_tokens", 80),))
        fact = OriginalModelCostFactV1(
            intent, replace(fact.recovery, intent=intent),
            fact.admission, fact.receipt,
        )
        self.assertEqual(original_model_budget_actual(fact, quote),
                         {"output_tokens": 72})
        quote = replace(quote, ceiling={"input_tokens": 50, "output_tokens": 80})
        intent = replace(intent, budget_ceiling=(
            ("input_tokens", 50), ("output_tokens", 80)))
        fact = OriginalModelCostFactV1(
            intent, replace(fact.recovery, intent=intent),
            fact.admission, fact.receipt,
        )
        self.assertEqual(original_model_budget_actual(fact, quote),
                         {"input_tokens": 40, "output_tokens": 72})

    def test_wrong_terminal_receipt_cannot_form_cost_fact(self):
        fact = self.original_fact()
        wrong = ModelTerminalReceiptV2(
            fact.receipt.admission_id, "other-call", fact.receipt.request_digest,
            fact.receipt.report_digest, fact.receipt.observation_digest,
            fact.receipt.finish_digest, fact.receipt.installation_id,
            fact.receipt.host_incarnation,
        )
        with self.assertRaises(ModelCostUnavailable):
            OriginalModelCostFactV1(fact.intent, fact.recovery,
                                    fact.admission, wrong)

    def test_original_signed_quote_survives_loss_of_work_authority(self):
        issuer = D02ResourceIssuer(b"k" * 32)
        quote = self.quote()
        issuer.issue_quote(self.db, quote)
        self.db.execute(
            "UPDATE runtime_resource_quotes SET status='revoked' "
            "WHERE quote_id=? AND version=?", (quote.quote_id, quote.version),
        )
        self.assertEqual(
            issuer.original_signed_quote(self.db, quote.quote_id, quote.version),
            quote,
        )
        with self.assertRaises(IssuerAuthorityDenied):
            issuer._load_quote(self.db, quote.quote_id, quote.version)


if __name__ == "__main__":
    unittest.main()
