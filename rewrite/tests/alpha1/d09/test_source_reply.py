"""A D09 reply candidate must retain the exact Authority and source closure."""

from dataclasses import replace
import json

import pytest

from rewrite.tests.alpha1.model.test_reply_language import _inputs, _result
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressIntentV1, ModelEgressObservationV1, ModelTerminalReceiptV2,
)
from sylanne3.authority_service.v2_reply_worker_model_result_contract import (
    ReplyWorkerModelResultReadRequestV1, ReplyWorkerModelResultReadV1,
    reply_worker_read_attempt_id_v1,
)
from sylanne3.domains.d09 import (
    ClaimKind, issue_source_reply_expression_v1, segment_payload_digest,
)
from sylanne3.model_broker.reply_language import parse_reply_result_v1
from sylanne3.runtime_contracts import canonical_serialize


def _case():
    source, model_request = _inputs()
    candidate = parse_reply_result_v1(
        _result(), request=model_request, snapshot=source)
    current = replace(
        model_request.envelope,
        identity=replace(model_request.envelope.identity,
                         operation_id="post-c02-reply-op", effect_id="effect:reply"),
        authority=replace(model_request.envelope.authority,
                          purpose="expression"),
    )
    intent = ModelEgressIntentV1(
        authority_id="authority", namespace="bot:persona", subject="actor",
        operation_id=model_request.identity.operation_id,
        call_id=model_request.call_id, request_digest=model_request.digest,
        job_id="job-1", worker_fence=1, fence_token="t" * 32,
        fence_epoch=1, fence_revision=0, anchor_digest="b" * 64,
        source_refs=(source.source.source_id,),
        source_revisions=((source.source.source_id, source.source_revision),),
        access_revisions=((source.source.source_id, source.access_revision),),
        access_epoch=1, delete_epoch=0, graph_epoch=1, graph_revision=1,
        authority_activation_generation=1, authority_revocation_epoch=0,
        authority_deletion_seq=0, authority_execution_seq=0,
        budget_lease_id="lease", budget_reservation_operation_id="reserve",
        budget_reservation_digest="c" * 64, budget_ceiling=(("USD", 1),),
        provider_id=model_request.provider_id, model_id=model_request.model_id,
        provider_config_digest="d" * 64,
        max_output_tokens=model_request.max_output_tokens,
        acquire_operation_id=model_request.identity.operation_id,
        binding_digest="e" * 64,
    )
    read_request = ReplyWorkerModelResultReadRequestV1(
        "authority", "bot:persona", current.authority.namespace,
        "installation", intent.job_id, intent.operation_id,
        intent.budget_reservation_operation_id, intent.call_id,
        intent.binding_digest, intent.request_digest,
        current.identity.operation_id,
        reply_worker_read_attempt_id_v1(current.identity.operation_id, 1),
        "c02", source.source_ref, source.source_revision,
        source.access_revision, "ticket", 1, current.authority.audience,
    )
    observation = ModelEgressObservationV1(
        intent.authority_id, intent.namespace, intent.subject,
        intent.operation_id, intent.call_id, intent.request_digest,
        "completed", canonical_serialize(_result()), (), (), None,
    )
    terminal = ModelTerminalReceiptV2(
        "a" * 64, intent.call_id, intent.request_digest,
        "b" * 64, observation.digest, "sha256:" + "c" * 64,
        "installation", "d" * 64,
    )
    read = ReplyWorkerModelResultReadV1(read_request, observation, terminal)
    return source, model_request, candidate, current, intent, read


def _issue(*, source=None, model_request=None, candidate=None, current=None,
           intent=None, read=None, scene_ref="scene:private"):
    values = _case()
    source, model_request, candidate, current, intent, read = (
        replacement if replacement is not None else original
        for original, replacement in zip(values, (
            source, model_request, candidate, current, intent, read))
    )
    return issue_source_reply_expression_v1(
        candidate, result_read=read, model_request=model_request,
        original_intent=intent, current_source=source,
        current_envelope=current, scene_ref=scene_ref,
        covered_slots=("answer",), max_chars=200,
    )


def test_quoted_reply_is_a_bounded_reported_claim_with_bound_provenance():
    source, request, candidate, current, intent, read = _case()
    result = _issue(source=source, model_request=request, candidate=candidate,
                    current=current, intent=intent, read=read)
    assert len(result.claims) == len(result.segments) == 1
    assert result.claims[0].kind is ClaimKind.REPORTED_CLAIM
    assert result.claims[0].source_refs == (source.source_ref,)
    assert result.claims[0].allowed_audiences == ("owner",)
    assert result.segments[0].body == "你好"
    assert result.segments[0].segment_id == "segment:" + result.provenance_digest
    assert result.payload_digest == segment_payload_digest(
        result.segments[0].body, (), result.segments[0].claim_uses)
    assert result.result_read_request_digest == read.request.digest
    assert result.observation_digest == read.observation.digest
    assert _issue(source=source, model_request=request, candidate=candidate,
                  current=current, intent=intent, read=read) == result


def test_result_or_audience_change_cannot_reuse_source_reply_candidate():
    source, request, candidate, current, intent, read = _case()
    with pytest.raises(ValueError, match="Authority result"):
        _issue(source=source, model_request=request,
               candidate=replace(candidate, body="别的"), current=current,
               intent=intent, read=read)
    with pytest.raises(ValueError, match="source, access, audience"):
        _issue(source=source, model_request=request, candidate=candidate,
               current=replace(current, authority=replace(
                   current.authority, audience=("stranger",))),
               intent=intent, read=read)
    with pytest.raises(ValueError, match="source, access, audience"):
        _issue(source=replace(source, access_revision=2), model_request=request,
               candidate=candidate, current=current, intent=intent, read=read)
    assert _issue(source=source, model_request=request, candidate=candidate,
                  current=current, intent=intent, read=read,
                  scene_ref="scene:changed").provenance_digest != _issue(
                      source=source, model_request=request, candidate=candidate,
                      current=current, intent=intent, read=read).provenance_digest


def test_free_text_cannot_be_promoted_to_a_claim():
    source, request, candidate, current, intent, read = _case()
    forged = replace(candidate, claims=(replace(
        candidate.claims[0], kind=ClaimKind.EXTERNAL_FACT),))
    with pytest.raises(ValueError, match="Authority result"):
        _issue(source=source, model_request=request, candidate=forged,
               current=current, intent=intent, read=read)
