"""The host bridge binds paid original reply facts before using D09's issuer.

These constructed DTOs test identity checks; W01 must supply graph-verified
signed quote and current source in production.
"""

from dataclasses import asdict, replace
import time

import pytest
import pytest_asyncio

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.host_tests.alpha1.test_installed_reply_model_driver import _preparation
from rewrite.tests.alpha1.model.test_reply_language import _result
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressObservationV1, ModelTerminalReceiptV2,
)
from sylanne3.authority_service.v2_reply_worker_model_result_contract import (
    ReplyWorkerModelResultReadRequestV1, ReplyWorkerModelResultReadV1,
    reply_worker_read_attempt_id_v1,
)
from sylanne3.domains.d09 import ClaimKind
from sylanne3.host.installed_reply_model_driver import (
    InstalledReplyModelRunV1, InstalledReplyProgressV1,
    ReplyModelTerminalHoldV1, issue_installed_post_c02_source_expression_v1,
)
from sylanne3.host.post_c02_reply_driver import post_c02_reply_operation_id
from sylanne3.model_broker.reply_language import parse_reply_result_v1
from sylanne3.runtime.d11_types import runtime_job_key
from sylanne3.runtime.issuers import ResourceQuote
from sylanne3.runtime.jobs import PersistentJob
from sylanne3.runtime.model_cost_settlement import OriginalModelCostCommitV1
from sylanne3.runtime.reply_model_job import (
    ReplyModelQueuedPreparationV1, reply_job_id_v1,
    reply_job_original_operation_id_v1,
)
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize


def _case(bundle):
    prep = _preparation(bundle)
    c02_id = prep.c02_receipt.operation_id
    source_ref = prep.source.source_ref
    original_id = reply_job_original_operation_id_v1(c02_id, source_ref)
    job_id = reply_job_id_v1(c02_id, source_ref)
    intent = replace(
        prep.intent, job_id=job_id,
        budget_reservation_operation_id=original_id)
    prep = replace(prep, intent=intent)
    request = prep.installed.request
    result = _result()
    candidate = parse_reply_result_v1(result, request=request, snapshot=prep.source)
    observation = ModelEgressObservationV1(
        intent.authority_id, intent.namespace, intent.subject,
        intent.operation_id, intent.call_id, intent.request_digest,
        "completed", canonical_serialize(result), (), (), "provider-call")
    terminal = ModelTerminalReceiptV2(
        "a" * 64, intent.call_id, intent.request_digest,
        "b" * 64, observation.digest, "sha256:" + "d" * 64,
        bundle.installation_policy.installation_id, "e" * 64)
    consumer = post_c02_reply_operation_id(c02_id, source_ref)
    read_request = ReplyWorkerModelResultReadRequestV1(
        intent.authority_id, intent.namespace,
        prep.envelope.authority.namespace,
        bundle.installation_policy.installation_id, job_id,
        intent.operation_id, original_id, intent.call_id,
        intent.binding_digest, intent.request_digest, consumer,
        reply_worker_read_attempt_id_v1(consumer, 1),
        c02_id, source_ref, prep.source.source_revision,
        prep.source.access_revision, prep.attention.ticket_id,
        prep.focus_revision, prep.envelope.authority.audience)
    read = ReplyWorkerModelResultReadV1(read_request, observation, terminal)
    ns = prep.envelope.authority.namespace
    job_ref = runtime_job_key(*ns.as_tuple, "activity", job_id).token
    job = PersistentJob(
        job_id, original_id, "activity", None, *ns.as_tuple,
        "reply-snapshot", "queued", "reply", {}, None,
        "1970-01-01T00:01:40Z", intent.budget_lease_id,
        "reply-resource", {}, None, None, 0, 0, {}, None)
    quote = ResourceQuote(
        "reply-quote", 1, *ns.as_tuple, "activity", original_id, None,
        intent.budget_lease_id, "reply", "reply-snapshot", 9.0,
        "reply-resource", job_ref, (), (), dict(intent.budget_ceiling),
        None, 9.0)
    queued = ReplyModelQueuedPreparationV1(
        c02_id, source_ref, original_id, job, quote,
        intent.budget_reservation_digest, 1)
    cost_operation_id = "model-cost-" + canonical_digest({
        "namespace": list(ns.as_tuple), "call_id": intent.call_id,
    })[:48]
    cost = OriginalModelCostCommitV1(
        "committed", cost_operation_id, intent.call_id, quote.quote_id,
        quote.version, canonical_digest(asdict(terminal)), "cost-ref",
        "budget-receipt", 1, 1, 1)
    progress = InstalledReplyProgressV1(
        InstalledReplyModelRunV1(prep, ReplyModelTerminalHoldV1(
            intent.operation_id, intent.call_id, terminal,
            "observed_pending_result_read")), cost, candidate, read)
    current = replace(
        prep.envelope,
        identity=replace(prep.envelope.identity,
                         operation_id=consumer, effect_id="effect:reply"),
        authority=replace(prep.envelope.authority, purpose="expression"))
    return queued, progress, prep.source, current


def _issue(queued, progress, source, envelope, **changes):
    params = dict(current_source=source, current_envelope=envelope,
                  scene_ref="scene:private", covered_slots=("reply",),
                  max_chars=200)
    return issue_installed_post_c02_source_expression_v1(
        queued, progress, **(params | changes))


@pytest_asyncio.fixture
async def case():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, _ = host.v2_adapters()
        yield _case(bundle)
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_paid_result_becomes_one_source_quote_only(case):
    queued, progress, source, envelope = case
    assert progress.cost.operation_id != queued.original_operation_id
    expression = _issue(queued, progress, source, envelope)
    assert len(expression.claims) == len(expression.segments) == 1
    assert expression.claims[0].kind is ClaimKind.REPORTED_CLAIM
    assert expression.claims[0].source_refs == (queued.source_ref,)
    assert expression.segments[0].body == "你好"
    assert expression.result_read_request_digest == progress.result_read.request.digest


@pytest.mark.asyncio
async def test_paid_result_rejects_reply_reservation_as_cost_operation(case):
    queued, progress, source, envelope = case
    wrong_cost = replace(progress.cost,
                         operation_id=queued.original_operation_id)
    with pytest.raises(ValueError, match="durable model cost"):
        _issue(queued, replace(progress, cost=wrong_cost), source, envelope)


@pytest.mark.asyncio
async def test_unmapped_text_or_forged_claim_fails_closed(case):
    queued, progress, source, envelope = case
    with pytest.raises(ValueError, match="Authority result"):
        _issue(queued, replace(progress, candidate=replace(
            progress.candidate, body="自由文本")), source, envelope)
    forged = replace(progress.candidate, claims=(replace(
        progress.candidate.claims[0], kind=ClaimKind.EXTERNAL_FACT),))
    with pytest.raises(ValueError, match="Authority result"):
        _issue(queued, replace(progress, candidate=forged), source, envelope)


@pytest.mark.asyncio
async def test_audience_and_budget_fail_closed(case):
    queued, progress, source, envelope = case
    wrong_audience = replace(envelope, authority=replace(
        envelope.authority, audience=("stranger",)))
    with pytest.raises(ValueError, match="audience"):
        _issue(queued, progress, source, wrong_audience)
    with pytest.raises(ValueError, match="paid original"):
        _issue(queued, replace(progress, cost=None), source, envelope)
    with pytest.raises(ValueError, match="budget"):
        _issue(replace(queued, quote=replace(
            queued.quote, ceiling={"output_tokens": 1})), progress,
            source, envelope)


@pytest.mark.asyncio
async def test_expired_original_model_quote_does_not_erase_paid_result(case):
    queued, progress, source, envelope = case
    expired = replace(queued, quote=replace(
        queued.quote, deadline_utc=0.5, valid_until_utc=0.5))
    assert expired.quote.valid_until_utc < time.time()
    expression = _issue(expired, progress, source, envelope)
    assert expression.segments[0].body == "你好"
