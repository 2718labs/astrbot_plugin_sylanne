from dataclasses import replace
from datetime import datetime, timezone
import json
import sqlite3
from types import SimpleNamespace

import pytest

from sylanne3.domains.d13.precompression import compile_deterministic_candidate
from sylanne3.runtime.d13_precompression_job import (
    D13CacheCommitReceiptV1, D13CallUsageV1, D13PrecompressionHold,
    D13ProviderUsageV2,
    account_d13_calls_v2, check_activation_v1, combine_usage_v1,
    prepare_activation_intent_v1, prepare_adoption_intent_v1,
    prepare_precompression_intent_v1, prepare_retirement_intent_v1,
    prepare_standby_v1, plan_from_precompression_job_v1, retirement_due_v1,
    submit_cache_transition_v1,
    submit_precompression_intent_v1,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, CompletedTurnV1,
    ConversationWindowProjectionV1, NamespaceId, OperationIdentity,
    RUNTIME_SCHEMA, SourceQualification, VersionGuard, VersionedRef,
    canonical_digest,
)
from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.d11_types import runtime_job_key
from sylanne3.runtime.issuers import (
    D02ResourceIssuer, D11BudgetJobIssuer, IssuerAuthorityDenied,
    ResourceQuote, install_schema as install_issuer_schema,
)


def ref(name):
    return VersionedRef(name, 1)


def window(now=100_000):
    scene, audience = ref("scene"), ref("audience")
    turns = tuple(CompletedTurnV1(
        "conversation", audience, i, ref(f"raw:{i}"), ref(f"source:{i}"),
        ref(f"access:{i}"), "speaker", "先前原文。后续内容。" + "x" * 100,
        now - 60 + i, "confirmed", "not_applicable",
    ) for i in range(6))
    deps = tuple(r for t in turns for r in (t.raw_ref, t.source_ref, t.access_ref))
    return ConversationWindowProjectionV1(
        NamespaceId("bot", "persona"), "owner", "conversation", scene, audience,
        turns, 5, now, deps, (scene, audience, *deps), 0, 0, 0,
    )


def intent(w=None, **changes):
    w = w or window()
    args = dict(history_token_budget=1000, background_capacity=True,
                outstanding_candidate=False, attempted_input_digests=frozenset(),
                parent_budget_lease_ref="lease:1", resource_ref="provider:1",
                ceiling={"input_tokens": 100, "output_tokens": 30,
                         "model_microusd": 1000}, deadline_utc=w.trusted_utc + 600)
    args.update(changes)
    return prepare_precompression_intent_v1(w, **args)


def utc(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat().replace("+00:00", "Z")


def test_original_intent_is_stable_and_skips_busy_or_attempted_work():
    w = window()
    first = intent(w)
    assert first is not None and first == intent(w)
    assert first.job.work_kind == "d13.precompress"
    assert first.job.continuation["input_digest"] == first.plan.input_digest
    assert first.job.continuation.get("raw_text") is None
    assert intent(w, background_capacity=False) is None
    assert intent(w, outstanding_candidate=True) is None
    assert intent(w, attempted_input_digests=frozenset({first.plan.input_digest})) is None


def test_durable_job_restores_exact_precompression_plan_after_json_round_trip():
    prepared = intent()
    restored = replace(prepared.job,
                       continuation=json.loads(json.dumps(prepared.job.continuation)))
    assert plan_from_precompression_job_v1(restored) == prepared.plan
    changed = dict(restored.continuation)
    changed["plan"] = {**changed["plan"], "delete_epoch": 1}
    with pytest.raises(ValueError, match="differs"):
        plan_from_precompression_job_v1(replace(restored, continuation=changed))


def test_signed_d13_quote_preserves_original_plan_and_rejects_wrong_job_binding():
    prepared = intent()
    w = window()
    db = sqlite3.connect(":memory:")
    install_issuer_schema(db)
    d02 = D02ResourceIssuer(b"k" * 32)
    issuer = D11BudgetJobIssuer(d02, b"k" * 32)
    quote = ResourceQuote(
        "d13-quote", 1, *w.namespace.as_tuple, prepared.job.activity_id,
        prepared.job.operation_id, None, prepared.job.budget_ref,
        "d13.precompress", prepared.job.snapshot_ref, w.trusted_utc + 600,
        prepared.job.resource_ref,
        runtime_job_key(*w.namespace.as_tuple, prepared.job.activity_id,
                        prepared.job.job_id).token,
        (), (), prepared.ceiling, None, w.trusted_utc + 700,
        prepared.job.continuation,
    )
    d02.issue_quote(db, quote)
    signed = d02._load_quote(db, quote.quote_id, quote.version)
    envelope = SimpleNamespace(
        authority=SimpleNamespace(namespace=w.namespace, issuer_domain="d13"),
        identity=SimpleNamespace(activity_id=prepared.job.activity_id,
                                 operation_id=prepared.job.operation_id,
                                 effect_id=None, phase="d13.precompress"),
        deadline_utc=w.trusted_utc + 600,
        version_guard=SimpleNamespace(read_versions=tuple(
            SimpleNamespace(key=SimpleNamespace(token=ref.ref), revision=ref.version)
            for ref in (w.scene_ref, w.audience_ref,
                        *prepared.plan.source_dependencies))),
    )
    lease = BudgetLease(prepared.job.budget_ref, None, *w.namespace.as_tuple,
                        "USD", prepared.ceiling, {}, {}, {}, 1, "active")
    persisted = issuer._job_from_quote(envelope, signed, lease)
    assert plan_from_precompression_job_v1(
        replace(persisted,
                continuation=json.loads(json.dumps(persisted.continuation)))) == prepared.plan
    assert persisted.continuation == prepared.job.continuation
    assert persisted.operator_versions == {
        "resource_quote": "d13-quote:1", "d13_compiler": "d13.deterministic.v1"}
    with pytest.raises(IssuerAuthorityDenied):
        issuer._job_from_quote(envelope, replace(signed,
            graph_job_ref=runtime_job_key(*w.namespace.as_tuple,
                                          prepared.job.activity_id, "other").token), lease)
    altered = dict(signed.job_continuation)
    altered["plan"] = {**altered["plan"], "delete_epoch": 1}
    with pytest.raises(IssuerAuthorityDenied):
        issuer._job_from_quote(envelope,
                               replace(signed, job_continuation=altered), lease)


def test_submit_requires_installed_fenced_coordinator():
    w = window()
    prepared = intent(w)
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity(prepared.job.activity_id, None, "attempt",
                          "d13.precompress", prepared.job.operation_id,
                          canonical_digest({"input_refs": []})),
        AuthorityContext("worker", "d13", "capability", w.namespace,
                         ("persona",), "technical", ("conversation",),
                         "policy", 1),
        VersionGuard((), (), 0, 0, "catalogue", "scheme", "operator", "policy",
                     (), (), ()),
        SourceQualification((), "derived", None, w.trusted_utc, "inference",
                            "ineligible", None, "not_applicable"),
        (), prepared.job.budget_ref, w.trusted_utc + 600, 600,
        "interval", (),
    )
    with pytest.raises(D13PrecompressionHold, match="installed GraphCoordinator"):
        submit_precompression_intent_v1(object(), envelope, object(), prepared)


def test_late_or_lost_fence_cannot_adopt_and_expiry_does_not_renew():
    w = window()
    prepared = intent(w)
    candidate = compile_deterministic_candidate(w, prepared.plan)
    running = replace(prepared.job, phase="running", lease_holder="worker",
                      lease_expires_utc=utc(w.trusted_utc + 100), fence=2)
    standby = prepare_standby_v1(
        running, holder="worker", fence=2, now_utc=w.trusted_utc,
        plan=prepared.plan, candidate=candidate, current_window=w)
    assert standby.status == "standby"
    with pytest.raises(D13PrecompressionHold):
        prepare_standby_v1(running, holder="worker", fence=1,
                           now_utc=w.trusted_utc, plan=prepared.plan,
                           candidate=candidate, current_window=w)
    with pytest.raises(D13PrecompressionHold):
        prepare_standby_v1(running, holder="worker", fence=2,
                           now_utc=w.trusted_utc + 100, plan=prepared.plan,
                           candidate=candidate,
                           current_window=replace(w, trusted_utc=w.trusted_utc + 100))
    assert not retirement_due_v1(standby, standby.expires_at_utc - 1)
    assert retirement_due_v1(standby, standby.expires_at_utc)


def test_activation_targets_and_two_usage_ledgers_preserve_unknown():
    w = window()
    prepared = intent(w)
    candidate = compile_deterministic_candidate(w, prepared.plan)
    standby = replace(candidate, status="standby")
    keep = check_activation_v1(
        standby, prepared.plan, w, history_token_budget=1000,
        raw_window_input_tokens=650, raw_tail_input_tokens=350,
        raw_window_fits=True,
        proven_future_saving=False)
    assert keep.decision == "keep_raw"
    assert not keep.reached_seventy_percent
    switch = check_activation_v1(
        standby, prepared.plan, w, history_token_budget=1000,
        raw_window_input_tokens=750, raw_tail_input_tokens=350,
        raw_window_fits=False,
        proven_future_saving=False)
    assert switch.decision == "activate"
    assert switch.reason == "window_pressure"
    assert switch.reached_seventy_percent
    stale = check_activation_v1(
        standby, prepared.plan, replace(w, delete_epoch=1),
        history_token_budget=1000, raw_window_input_tokens=750,
        raw_tail_input_tokens=350,
        raw_window_fits=False, proven_future_saving=False)
    assert stale.decision == "invalid"
    foreground = D13CallUsageV1(1000, 80, 700, 25)
    background = D13CallUsageV1(200, 20, None, 7)
    ledger = combine_usage_v1(foreground, background, candidate_used=False)
    assert ledger.foreground_window_tokens == 1000
    assert ledger.foreground_cached_tokens == 700
    assert ledger.total_billed_microusd == 32
    assert ledger.unused_candidate_cost_microusd == 7
    assert combine_usage_v1(foreground, replace(background, billed_microusd=None),
                            candidate_used=False).total_billed_microusd is None
    with pytest.raises(ValueError):
        D13CallUsageV1(10, 0, 11, 1)


def test_typed_cache_cas_intents_keep_epochs_fence_and_three_day_retirement():
    w = window()
    prepared = intent(w)
    candidate = compile_deterministic_candidate(w, prepared.plan)
    running = replace(prepared.job, phase="running", lease_holder="worker",
                      lease_expires_utc=utc(w.trusted_utc + 100), fence=2)
    adoption = prepare_adoption_intent_v1(
        running, holder="worker", fence=2, now_utc=w.trusted_utc,
        plan=prepared.plan, candidate=candidate, current_window=w)
    assert adoption.action == "adopt"
    assert adoption.expected_cache_revision is None
    assert adoption.worker_fence == 2
    assert set(prepared.plan.source_dependencies).issubset(adoption.read_set)
    assert adoption == prepare_adoption_intent_v1(
        running, holder="worker", fence=2, now_utc=w.trusted_utc,
        plan=prepared.plan, candidate=candidate, current_window=w)
    with pytest.raises(D13PrecompressionHold, match="installed GraphCoordinator"):
        submit_cache_transition_v1(object(), object(), adoption)

    activation = prepare_activation_intent_v1(
        adoption.block, prepared.plan, w, cache_revision=4,
        history_token_budget=1000, raw_window_input_tokens=750,
        raw_tail_input_tokens=350, raw_window_fits=False,
        proven_future_saving=False)
    assert activation.action == "activate"
    assert activation.expected_cache_revision == 4
    assert activation.block.status == "active"
    with pytest.raises(D13PrecompressionHold):
        prepare_activation_intent_v1(
            adoption.block, prepared.plan, replace(w, access_epoch=1),
            cache_revision=4, history_token_budget=1000,
            raw_window_input_tokens=750, raw_tail_input_tokens=350,
            raw_window_fits=False, proven_future_saving=False)
    with pytest.raises(D13PrecompressionHold):
        prepare_retirement_intent_v1(activation.block, w, cache_revision=5)
    expired = replace(w, trusted_utc=activation.block.expires_at_utc)
    retirement = prepare_retirement_intent_v1(
        activation.block, expired, cache_revision=5)
    assert retirement.action == "retire"
    assert retirement.block.status == "retired"
    assert retirement.reason == "72h_expired"
    assert retirement.expected_cache_revision == 5
    deleted_window = replace(
        w, turns=(), source_dependencies=(),
        read_set=(w.scene_ref, w.audience_ref), delete_epoch=1)
    invalidated = prepare_retirement_intent_v1(
        activation.block, deleted_window, cache_revision=5,
        source_invalidated=True)
    assert invalidated.reason == "source_invalidated"
    assert not set(invalidated.source_dependencies).issubset(invalidated.read_set)
    with pytest.raises(ValueError):
        D13CacheCommitReceiptV1(invalidated.operation_id, invalidated.input_digest,
                                invalidated.block.block_ref, "retire", 9, 6, 1,
                                False, False, None)


def test_actual_usage_contract_keeps_cache_subsets_and_unknown_cost():
    foreground = D13ProviderUsageV2("call:front", "a" * 64, "foreground",
                                    1000, 80, 700, 150, 25, 3)
    background = D13ProviderUsageV2("call:compress", "b" * 64,
                                    "precompression", 200, 20, None, None, 7, None)
    usage = account_d13_calls_v2(foreground, background, candidate_used=False)
    assert usage.foreground_window_tokens == 1000
    assert usage.foreground_cached_input_tokens == 700
    assert usage.foreground_cache_write_tokens == 150
    assert usage.total_billed_microusd == 32  # cache fees are within each reported total
    assert usage.unused_candidate_billed_microusd == 7
    assert usage.cost_status == "reported"
    unknown = account_d13_calls_v2(
        foreground, replace(background, total_billed_microusd=None),
        candidate_used=False)
    assert unknown.total_billed_microusd is None
    assert unknown.cost_status == "unknown"
    with pytest.raises(ValueError):
        account_d13_calls_v2(foreground, replace(foreground, role="precompression"),
                             candidate_used=True)
    with pytest.raises(ValueError):
        replace(foreground, cache_write_tokens=400)
