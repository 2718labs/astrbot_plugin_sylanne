"""D09 only consumes a pinned paid/current Authority result service."""

from dataclasses import asdict, replace

import pytest

from sylanne3.authority_service.v2_context_reply_result_contract import (
    ContextReplyPaidResultReadV2, ContextReplyResultReadRequestV1,
    context_reply_read_attempt_id_v1,
)
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressObservationV1, ModelTerminalReceiptV2,
)
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.domains.d08 import CommunicationIntentGrant, SegmentGrant
from sylanne3.domains.d09 import (
    ClaimKind, D09ExpressionProvider, issue_paid_context_reply_expression_v2,
)
from sylanne3.graph_types import GraphVersion
from sylanne3.memory_types import access_key, source_key
from sylanne3.model_broker.context_reply import (
    CONTEXT_REPLY_TEMPLATE_VERSION,
    ContextReplyInputV1, ContextReplyInstallationV1, ContextReplyPartV1,
    freeze_context_reply_request_v1,
)
from sylanne3.runtime_contracts import (
    ContextReplyOriginalSealV2, NamespaceId, VersionedRef,
    canonical_digest, canonical_serialize,
)


class _AuthorityPort:
    def __init__(self, result):
        self.result = result

    def read_current_result_v2(self, request, *, now_utc):
        assert request == self.result_request
        assert now_utc == 110.0
        return self.result


def _case(*, no_reply=False):
    namespace = NamespaceId("bot", "persona")
    audience = VersionedRef("conversation:private", 1)
    source1 = source_key(*namespace.as_tuple, "door")
    source2 = source_key(*namespace.as_tuple, "window")
    access1 = access_key(*namespace.as_tuple, "door")
    access2 = access_key(*namespace.as_tuple, "window")
    kwargs = {"audience_ref": audience, "expires_at_utc": 150.0}
    input = ContextReplyInputV1(
        namespace, VersionedRef("scene:private", 1), audience,
        "conversation:private", 2, 3, 4, 100.0, 140.0,
        ContextReplyPartV1("question", VersionedRef("turn:question", 1),
                           text="What happened?", **kwargs),
        (
            ContextReplyPartV1(
                "d06_evidence", VersionedRef(source1.token, 1),
                text="The door opened.", access_ref=VersionedRef(access1.token, 1),
                **kwargs,
            ),
            ContextReplyPartV1(
                "d06_evidence", VersionedRef(source2.token, 2),
                text="The window stayed shut.",
                access_ref=VersionedRef(access2.token, 3), **kwargs,
            ),
        ),
    )
    frozen = freeze_context_reply_request_v1(
        input, ContextReplyInstallationV1(
            "installation", "a" * 64, "provider", "model", 128,
        ),
    )
    original_operation = "original-op"
    attempt_id = context_reply_read_attempt_id_v1(original_operation, 1)
    guard = "c" * 64
    seal = ContextReplyOriginalSealV2(
        namespace, "c02", source1.token, "installation", "a" * 64,
        "job", original_operation, "acquire", "call",
        CONTEXT_REPLY_TEMPLATE_VERSION,
        canonical_digest(asdict(input)), frozen.digest, guard,
    )
    request = ContextReplyResultReadRequestV1(
        "authority", "authority:namespace", namespace, "c02", source1.token,
        "installation", "job", "acquire", original_operation, "call",
        frozen.digest, canonical_digest(asdict(input)), attempt_id,
    )
    if no_reply:
        output = {"schema": "sylanne.d09.context_reply_output.v1", "body": "", "spans": []}
    else:
        output = {
            "schema": "sylanne.d09.context_reply_output.v1",
            "body": "The door opened. The window stayed shut.",
            "spans": [
                {"start": 0, "end": 16, "source_ref": source1.token,
                 "source_revision": 1, "access_ref": access1.token,
                 "access_revision": 1, "source_quote": "The door opened."},
                {"start": 17, "end": 40, "source_ref": source2.token,
                 "source_revision": 2, "access_ref": access2.token,
                 "access_revision": 3, "source_quote": "The window stayed shut."},
            ],
        }
    encoded = canonical_serialize(output)
    paid_digest = "b" * 64
    observed = ModelEgressObservationV1(
        "authority", "authority:namespace", "actor", original_operation,
        "call", paid_digest, "completed", canonical_serialize({"text": encoded}), (), (), None,
    )
    terminal = ModelTerminalReceiptV2(
        "1" * 64, "call", paid_digest, "2" * 64, observed.digest,
        "sha256:" + "3" * 64, "installation", "4" * 64,
    )
    versions = (
        GraphVersion(source1, 1), GraphVersion(access1, 1),
        GraphVersion(source_correction_head_key(namespace, "door"), 0),
        GraphVersion(source2, 2), GraphVersion(access2, 3),
        GraphVersion(source_correction_head_key(namespace, "window"), 0),
    )
    paid = ContextReplyPaidResultReadV2(
        seal, frozen, attempt_id, 1, attempt_id, "f" * 64,
        paid_digest, terminal, observed, versions, guard, encoded,
        canonical_digest(output),
        "no_reply_hold" if no_reply else "paid_current_source_verified_hold",
    )
    port = _AuthorityPort(paid)
    port.result_request = request
    return request, input, paid, port


def _issue(request, input, port):
    return issue_paid_context_reply_expression_v2(
        request, result_service=port, current_input=input,
        scene_ref=input.scene_ref, audience_ref=input.audience_ref,
        covered_slots=("answer",), max_chars=200, now_utc=110.0,
    )


def test_two_exact_d06_spans_from_paid_port_remain_finite_hold_candidate():
    request, input, paid, port = _case()
    result = _issue(request, input, port)
    assert result.status == "paid_current_source_verified_hold"
    assert len(result.claims) == 2
    assert all(claim.kind is ClaimKind.REPORTED_CLAIM for claim in result.claims)
    assert len(result.segments) == 1
    assert result.original_operation_id == paid.original_seal.original_operation_id
    assert result.read_fence_digest == paid.read_fence_digest
    assert result.segments[0].body == paid.body


def test_handmade_dto_without_service_and_no_reply_hold():
    request, input, paid, _ = _case()
    assert _issue(request, input, None).missing == ("authority_result_service_unavailable",)
    assert _issue(request, input, paid).status == "hold"
    request, input, _, port = _case(no_reply=True)
    assert _issue(request, input, port).status == "hold"


def test_changed_source_access_scope_or_service_revocation_holds():
    request, input, paid, port = _case()
    changed = replace(input, evidence=(replace(
        input.evidence[0], access_ref=VersionedRef(
            input.evidence[0].access_ref.ref, 2)), *input.evidence[1:]))
    assert _issue(request, changed, port).status == "hold"
    port.result = replace(paid, current_read_versions=tuple(
        replace(row, revision=4) if row.key.token == input.evidence[1].ref.ref else row
        for row in paid.current_read_versions))
    assert _issue(request, input, port).missing == ("current_source_versions_incomplete",)
    port.result = None
    assert _issue(request, input, port).status == "hold"


def test_result_service_authority_identity_must_match_request():
    request, input, _, port = _case()
    changed = replace(request, authority_id="other-authority")
    port.result_request = changed
    assert _issue(changed, input, port).status == "hold"


def test_tampered_paid_call_or_output_identity_cannot_construct_result():
    _, _, paid, _ = _case()
    with pytest.raises(ValueError, match="paid/current identity"):
        replace(paid, model_call_request_digest="9" * 64)
    with pytest.raises(ValueError, match="output state or digest"):
        replace(paid, canonical_output="{}")


def _paid_batch_case():
    request, input, result, port = _case()
    paid = _issue(request, input, port)
    segment = paid.segments[0]
    checks = ("check:source", "check:budget")
    grant = SegmentGrant(
        segment.segment_id, segment.effect_id, 0, paid.payload_digest,
        200, (), None, checks, 140.0, 0,
    )
    intent = CommunicationIntentGrant(
        "communication-grant:" + "1" * 64, "communication:paid", "contact:paid", 1,
        "intent:paid", "action:paid", 1, "conversation:private",
        (input.audience_ref.ref,), "expression", ("answer",),
        (ClaimKind.REPORTED_CLAIM.value,), (), (grant,), "2" * 64,
        checks, 140.0, 0,
    )
    provider = D09ExpressionProvider()
    blueprint = provider.prepare_blueprint(
        intent, input.scene_ref.ref, 1, paid.claims, now=110.0,
    ).blueprint
    assert blueprint is not None
    value = provider.build_paid_batch_v2(intent, blueprint, paid, now=110.0)
    return provider, intent, request, input, port, value


def test_paid_v2_batch_preserves_paid_identity_and_rechecks_current_sources():
    provider, intent, request, input, port, value = _paid_batch_case()
    spec = next(s for s in provider.register_types()
                if s.name == "d09.paid_verified_segment_batch.v2")
    assert spec.schema_version == 2
    spec.validator(value)
    assert value["original_operation_id"] == request.original_operation_id
    assert len(value["source_refs"]) == 2
    checked = provider.recheck_paid_batch_v2(
        value, intent=intent, request=request, result_service=port,
        current_input=input, scene_ref=input.scene_ref,
        audience_ref=input.audience_ref, covered_slots=("answer",),
        max_chars=200, now=110.0, conversation_epoch=1,
    )
    assert checked.status == "paid_current_source_verified_hold"
    assert "coordinator_source_and_access_cas" in checked.missing


def test_paid_v2_batch_rejects_missing_identity_and_revoked_secondary_source():
    provider, intent, request, input, port, value = _paid_batch_case()
    spec = next(s for s in provider.register_types()
                if s.name == "d09.paid_verified_segment_batch.v2")
    for field in ("original_operation_id", "paid_result_digest", "read_fence_digest"):
        altered = dict(value)
        altered.pop(field)
        with pytest.raises(ValueError):
            spec.validator(altered)
    original = port.result
    port.result = replace(original, current_read_versions=tuple(
        replace(row, revision=row.revision + 1)
        if row.key.token == input.evidence[1].ref.ref else row
        for row in original.current_read_versions
    ))
    checked = provider.recheck_paid_batch_v2(
        value, intent=intent, request=request, result_service=port,
        current_input=input, scene_ref=input.scene_ref,
        audience_ref=input.audience_ref, covered_slots=("answer",),
        max_chars=200, now=110.0, conversation_epoch=1,
    )
    assert checked.status == "hold"
    assert checked.missing == ("current_source_versions_incomplete",)
