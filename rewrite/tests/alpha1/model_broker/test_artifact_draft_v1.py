"""Pure artifact phase wire/identity tests; metadata fixtures confer no real adoption or execution permission."""
from dataclasses import replace
import hashlib
import json

import pytest

from sylanne3.domains.d01 import FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.memory_types import SourceRecord, source_key
from sylanne3.model_broker import artifact_draft_v1 as codec
from sylanne3.model_broker.broker import ModelCallRequest
from sylanne3.runtime.d11_artifact_draft_contract_v1 import DraftFileIdentityV1, DraftFileTargetV1, DraftFileReadbackV1
from sylanne3.runtime_contracts import (NamespaceId, VersionedRef, QueryEpoch, AuthorityContext, OperationIdentity,
    SourceQualification, VersionGuard, CommandEnvelope, RUNTIME_SCHEMA, canonical_digest)


def phase(method=TONE_SAMPLE_METHOD_V1, index=0):
    ns = NamespaceId("bot", "persona")
    task = codec.artifact_draft_task_selector_v1(ns, c02_operation_id="c02:codec", root_registration_ref="root:codec")
    owner = AtomKey.from_token(task.cycle_job_ref).owner
    return codec.ArtifactDraftPhaseSelectorV2(task,
        AtomKey(owner, "d08.decision_record.v2", "decision:codec").token, 1, "d" * 64,
        AtomKey(owner, "d08.personal_plan.v1", "plan:codec").token, 2, "e" * 64,
        method, index, codec.artifact_draft_phase_sequence_v2(method)[index],
        None if index == 0 else "phase:previous", None if index == 0 else "f" * 64)


def source(ns, source_id, text):
    record = SourceRecord(source_id, text, "persona:persona", "authored", "unknown", None, 100.0,
        "family:" + source_id, ("owner",), ("context", "consolidation"))
    return codec.ArtifactDraftSourceV1(source_key(*ns.as_tuple, source_id).token, 1,
        canonical_digest(record.to_dict()), record)


def frozen(selector=None):
    selector = selector or phase()
    task = source(selector.task.namespace, "task", "Explicit original task requirements.")
    sources = [task]
    identity = DraftFileIdentityV1(1, 2)
    target = DraftFileTargetV1("export", "root:codec", "a" * 64, identity, "draft.md", "create", 0,
        None, None, None, codec.MAX_TEXT_BYTES)
    prior = None
    if selector.phase_index:
        previous = source(selector.task.namespace, "previous", "样" * 150)
        sources.append(previous)
        readback = DraftFileReadbackV1("effect:previous", "execution:previous", "b" * 64, "c" * 64,
            "a" * 64, "draft.md", 1, hashlib.sha256(previous.record.text.encode()).hexdigest(),
            len(previous.record.text.encode()), identity, "9" * 64,
            "1970-01-01T00:01:40Z", "1970-01-01T00:01:41Z", 1)
        prior = codec.ArtifactDraftPriorContentCommitmentV2(VersionedRef(previous.ref, 1), previous.value_digest,
            "verified:readback", "8" * 64, readback)
        target = replace(target, mode="replace", expected_prior_version=1,
            expected_prior_digest=readback.content_digest, expected_prior_identity=identity,
            expected_prior_effect_marker=readback.effect_marker)
    versions = tuple(GraphVersion(AtomKey.from_token(row.ref), row.revision) for row in sources) + (
        GraphVersion(AtomKey.from_token(selector.plan_ref), selector.plan_revision),
        GraphVersion(AtomKey.from_token(selector.decision_ref), selector.decision_revision))
    extent = codec.ArtifactDraftTextExtentV2(120, 180) if selector.phase_kind in {"tone_sample", "sample_check"} else codec.ArtifactDraftTextExtentV2(600, 900)
    return codec.ArtifactDraftInputV2(selector, task.ref, "self:current", "1" * 64, "a" * 64,
        target, tuple(sources), versions, 7, 0, 0, 400.0, extent, prior)


def request(input):
    selector = input.selector
    ids = codec.artifact_draft_model_ids_v2(selector)
    identity = OperationIdentity(AtomKey.from_token(selector.task.cycle_job_ref).owner.subject, None,
        ids["acquire"], codec.WORK_KIND, ids["acquire"], canonical_digest({"input_refs": []}))
    authority = AuthorityContext("worker:codec", "d11", "capability:codec", selector.task.namespace,
        ("activity", "persona"), "consolidation", ("owner",), "policy:codec", 1)
    guard = VersionGuard(input.source_read_versions, (QueryEpoch(selector.task.namespace, "namespace", 7),),
        0, 0, "catalogue:codec", "scheme:codec", "operator:codec", "policy:codec", (), (), ())
    envelope = CommandEnvelope(RUNTIME_SCHEMA, identity, authority, guard,
        SourceQualification((), "derived", None, 100.0, "inference", "ineligible", None, "not_applicable"),
        (), "parent:codec", input.deadline_utc, 500.0, "interval:codec", ())
    return ModelCallRequest(envelope, ids["call"], "provider:codec", "model:codec", frozenset(), "private",
        codec.TEMPLATE_DIGEST_V2, input.wire, 10.0, codec.artifact_draft_phase_token_limits_v2(selector)["output_tokens"])


def reply(input, text):
    return json.dumps({"schema": codec.OUTPUT_SCHEMA_V2, "input_digest": input.digest,
        "draft_text": text, "source_refs": [input.task_source_ref], "needs_clarification": False, "gaps": []})


def test_v1_artifact_wire_and_template_pin_remain_unchanged():
    current = frozen()
    old = codec.ArtifactDraftInputV1(current.selector.task, current.task_source_ref, current.current_self_ref,
        current.current_self_digest, current.root_registration_digest, current.target, current.sources,
        current.source_read_versions, current.source_query_epoch, current.access_epoch, current.delete_epoch, current.deadline_utc)
    assert codec.TEMPLATE_DIGEST == "7a57c0cf973646044ba0580d8042296647975b9b55addf6f4b44c2eeb9c16c71"
    assert codec.TEMPLATE_VERSION == "sylanne.artifact_draft_template.v1"
    assert codec.artifact_draft_from_wire_v1(plain_v1(old), codec.ArtifactDraftInputV1) == old
    old_output = {"schema": codec.OUTPUT_SCHEMA, "input_digest": old.digest, "draft_text": "A short unchanged V1 draft.",
        "source_refs": [old.task_source_ref], "needs_clarification": False, "gaps": []}
    assert codec.parse_artifact_draft_output_v1(json.dumps(old_output), old).draft_text == old_output["draft_text"]
    assert codec.TEMPLATE_DIGEST_V2 != codec.TEMPLATE_DIGEST and current.digest != old.digest
    with pytest.raises(ValueError):
        codec.artifact_draft_from_wire_v1(plain_v1(current), codec.ArtifactDraftInputV1)


def test_phase_ids_are_distinct_but_retry_keeps_original_task_project_goal_and_activity():
    sample, full = phase(), phase(index=2)
    ids = codec.artifact_draft_model_ids_v2(sample)
    assert set(ids.values()).isdisjoint(codec.artifact_draft_model_ids_v2(full).values())
    assert set(ids.values()).isdisjoint(codec.artifact_draft_model_ids_v1(sample.task).values())
    observed_again = replace(sample, decision_revision=2, decision_digest="3" * 64)
    assert codec.artifact_draft_model_ids_v2(observed_again) == ids
    assert codec.artifact_draft_file_ids_v2(observed_again) == codec.artifact_draft_file_ids_v2(sample)
    assert codec.artifact_draft_model_ids_v2(replace(sample, plan_revision=3, plan_digest="4" * 64)) != ids
    files = codec.artifact_draft_file_ids_v2(sample)
    original = codec.artifact_draft_file_ids_v1(sample.task.namespace,
        c02_operation_id=sample.task.c02_operation_id, root_registration_ref=sample.task.root_registration_ref)
    for name in ("goal", "plan", "project", "activity_id", "recipe_ref"):
        assert files[name] == original[name]
    assert files["effect"] != codec.artifact_draft_file_ids_v2(full)["effect"]
    assert codec.artifact_draft_phase_token_limits_v2(sample) == {"input_tokens": 6000, "output_tokens": 1000}
    assert codec.artifact_draft_phase_token_limits_v2(full) == {"input_tokens": 10000, "output_tokens": 2000}


@pytest.mark.parametrize("changed", ({"phase_kind": "unknown"}, {"phase_index": 2}, {"method_ref": "unregistered"},
    {"prev_phase_original_ref": "unexpected", "prev_phase_original_digest": "f" * 64}))
def test_phase_rejects_unregistered_or_out_of_order_selector(changed):
    with pytest.raises(ValueError):
        replace(phase(), **changed)


def test_phase_rejects_other_plan_scope_and_stale_plan_source_or_prior_version():
    input = frozen(phase(index=2))
    assert codec.artifact_draft_from_wire_v2(plain_v1(input), codec.ArtifactDraftInputV2) == input
    other = AtomKey(Owner("activity", "bot", "other-persona", "activity:other"), "d08.personal_plan.v1", "plan:other")
    with pytest.raises(ValueError, match="task scope"):
        replace(input.selector, plan_ref=other.token)
    with pytest.raises(ValueError, match="versions"):
        replace(input, selector=replace(input.selector, plan_revision=3))
    with pytest.raises(ValueError, match="versions"):
        replace(input, sources=(replace(input.sources[0], revision=2), *input.sources[1:]))
    with pytest.raises(ValueError, match="Source head"):
        replace(input, prior_content=replace(input.prior_content,
            source_head=replace(input.prior_content.source_head, version=2)))
    with pytest.raises(ValueError, match="verified predecessor"):
        replace(input, target=replace(input.target, expected_prior_version=2))
    with pytest.raises(ValueError, match="verified prior"):
        replace(input, prior_content=None)
    with pytest.raises(ValueError):
        codec.artifact_draft_from_wire_v2({**plain_v1(input), "execution_grant": True}, codec.ArtifactDraftInputV2)


def test_cross_activity_plan_requires_actual_registered_amendment_binding():
    from sylanne3.runtime.d01_production_operations_v1 import MissingProductionOriginalV1
    from sylanne3.runtime.d11_artifact_draft_model_v1 import require_artifact_phase_plan_control_qualification_v2

    original = phase(index=2)
    # An actual same-task amendment can reuse its predecessor activity Plan.
    # The wire locator is not the signed amendment or execution permission.
    other = AtomKey(Owner("activity", "bot", "persona", "activity:previous"),
        "d08.personal_plan.v1", "plan:previous")
    selector = replace(original, plan_ref=other.token)
    assert codec.artifact_draft_from_wire_v2(plain_v1(selector), codec.ArtifactDraftPhaseSelectorV2) == selector
    for binding in (None, object()):
        with pytest.raises(MissingProductionOriginalV1,
                match="actual_registered_amendment_binding_for_cross_activity_Plan"):
            require_artifact_phase_plan_control_qualification_v2(None,
                selector=selector, binding=binding, issuer=None)
    # A Decision must still belong to the actual current task activity.
    with pytest.raises(ValueError, match="task scope"):
        replace(original, decision_ref=AtomKey(other.owner, "d08.decision_record.v2", "decision:other").token)


def test_phase_parser_counts_registered_characters_and_preserves_original_full_extent():
    sample = frozen()
    body = "调" * 119 + "。" + " \n\t" + "性" * 30
    parsed = codec.parse_artifact_draft_output_v2(reply(sample, body), sample)
    assert parsed.draft_text == body and codec.artifact_draft_character_count_v2(body) == 150
    for text in ("短" * 119, "长" * 181):
        with pytest.raises(ValueError, match="extent"):
            codec.parse_artifact_draft_output_v2(reply(sample, text), sample)
    with pytest.raises(ValueError, match="exactly 120"):
        replace(sample, extent=codec.ArtifactDraftTextExtentV2(1, 180))
    with pytest.raises(ValueError, match="extent"):
        replace(sample.extent, counting_schema="unregistered")
    full = frozen(phase(FULL_DRAFT_METHOD_V1))
    assert codec.parse_artifact_draft_output_v2(reply(full, "全" * 700), full).draft_text == "全" * 700
    with pytest.raises(ValueError, match="extent"):
        codec.parse_artifact_draft_output_v2(reply(full, "全" * 901), full)
    raw = json.loads(reply(sample, "调" * 150))
    for changed in ({"input_digest": full.digest}, {"source_refs": [source_key("bot", "persona", "outside").token]},
            {"schema": codec.OUTPUT_SCHEMA}):
        with pytest.raises(ValueError):
            codec.parse_artifact_draft_output_v2(json.dumps({**raw, **changed}), sample)
    duplicated = reply(sample, "调" * 150).replace('"needs_clarification": false', '"needs_clarification": false, "needs_clarification": false')
    with pytest.raises(ValueError, match="duplicate"):
        codec.parse_artifact_draft_output_v2(duplicated, sample)


def test_phase_provider_boundary_binds_call_template_original_deadline_and_output_ceiling():
    input = frozen()
    actual = request(input)
    messages = codec.artifact_draft_provider_messages_v2(actual)
    assert messages[0]["content"] == codec.SYSTEM_MESSAGE_V2
    assert json.loads(messages[1]["content"]) == input.wire
    for changed in ({"call_id": "call:wrong"}, {"prompt_template_digest": codec.TEMPLATE_DIGEST}, {"max_output_tokens": 1001}):
        with pytest.raises(ValueError):
            codec.artifact_draft_provider_messages_v2(replace(actual, **changed))
    with pytest.raises(ValueError, match="deadline"):
        codec.artifact_draft_provider_messages_v2(replace(actual, envelope=replace(actual.envelope, deadline_utc=401.0)))
    wrong_operation = replace(actual.envelope.identity, operation_id="operation:wrong")
    with pytest.raises(ValueError, match="identity"):
        codec.artifact_draft_provider_messages_v2(replace(actual, envelope=replace(actual.envelope, identity=wrong_operation)))


def test_check_phase_cannot_allocate_or_consume_a_model_generation():
    check = frozen(phase(index=1))
    sample = frozen()
    for ids in (codec.artifact_draft_model_ids_v2, codec.artifact_draft_file_ids_v2, codec.artifact_draft_phase_token_limits_v2):
        with pytest.raises(ValueError):
            ids(check.selector)
    with pytest.raises(ValueError, match="check"):
        codec.parse_artifact_draft_output_v2(reply(check, "调" * 150), check)
    with pytest.raises(ValueError, match="check"):
        codec.artifact_draft_provider_messages_v2(replace(request(sample), payload=check.wire))


def test_prospective_candidate_identity_joins_real_phase_identity_after_decision_without_fake_adoption():
    from sylanne3.domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV1, PrepareCurrentPersonalCandidatesRequestV1
    from sylanne3.graph_types import GraphAtom
    from sylanne3.runtime.d08_personal_candidate_v1 import prospective_personal_future_identity_v1, prospective_personal_decision_key_v1
    input = frozen()
    selector = input.selector
    binding = ArtifactPhaseCandidateBindingV1("candidate:sample", "task:sample", selector.task,
        selector.method_ref, 0, "tone_sample", input.extent, input.target, None, "scope:actual-locator")
    goal_ref = AtomKey(AtomKey.from_token(selector.plan_ref).owner, "d08.goal.v1", "goal:codec").token
    request = PrepareCurrentPersonalCandidatesRequestV1(selector.plan_ref, goal_ref, 2, 1,
        "selection:codec", "evaluation:codec", "need:actual-locator", (binding,))
    plan_value = {"plan_id": "plan:codec", "revision": 2}
    plan = GraphAtom(AtomKey.from_token(selector.plan_ref), 2, plan_value, True)
    future = prospective_personal_future_identity_v1(selector.task.namespace, request, binding, plan, 400.0, "parent:codec")
    decision = prospective_personal_decision_key_v1(selector.task.namespace, plan.key.owner.subject,
        request.selection_operation_id, request.plan_ref)
    adopted_selector = replace(selector, decision_ref=decision.token, plan_digest=canonical_digest(plan_value))
    model_ids = codec.artifact_draft_model_ids_v2(adopted_selector)
    file_ids = codec.artifact_draft_file_ids_v2(adopted_selector)
    assert future.model_call_id == model_ids["call"] and future.model_prepare_operation_id == model_ids["prepare"]
    assert future.action_ref == file_ids["action"] and future.effect_id == file_ids["effect"]
    assert future.attempt_id == file_ids["attempt"] and future.execution_call_id == file_ids["execution_call"]
    assert future.deadline_utc == 400.0 and future.parent_budget_lease_ref == "parent:codec"
    assert not hasattr(binding, "decision_revision") and not hasattr(binding, "decision_digest")
    with pytest.raises(ValueError, match="generation phase"):
        replace(binding, phase_index=1, phase_kind="sample_check", prev_phase_original_ref="phase:previous", prev_phase_original_digest="f" * 64)


def test_new_personal_selection_request_cannot_carry_actions_checks_callbacks_or_quotes():
    from sylanne3.domains.d08.personal_candidate_v1 import SelectCurrentPersonalStepRequestV2
    from sylanne3.runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    selector = phase()
    goal_ref = AtomKey(AtomKey.from_token(selector.plan_ref).owner, "d08.goal.v1", "goal:codec").token
    original = SelectCurrentPersonalStepRequestV2(selector.plan_ref, goal_ref, "preparation:actual-locator")
    raw = plain_v1(original)
    assert decode_typed_production_value_v1(raw, SelectCurrentPersonalStepRequestV2) == original
    for extra in ("candidates", "checks", "phase_price_reader", "quote_version", "effect_id"):
        with pytest.raises(ValueError):
            decode_typed_production_value_v1({**raw, extra: []}, SelectCurrentPersonalStepRequestV2)



def test_prospective_phase_price_preserves_money_and_sufficient_total_tokens_without_filling_unknown_dimensions():
    from sylanne3.domains.d08.personal_candidate_v1 import CurrentPersonalCandidatePriceV1
    from sylanne3.runtime.domain_production_contracts_v1 import ProductionOriginalRefV1, ProductionPolicyRefV1
    from sylanne3.runtime.d08_personal_candidate_v1 import actual_personal_phase_price_ceiling_v1, MissingProductionOriginalV1
    # Pure numeric-bound metadata only; installed originals are authenticated by
    # the W01 reader before this helper can influence a production candidate.
    evidence = CurrentPersonalCandidatePriceV1(ProductionOriginalRefV1("d02.price", "price:codec", "1" * 64),
        "candidate:sample", "2" * 64, ProductionPolicyRefV1("policy:codec", 1, "3" * 64), (), (),
        codec.WORK_KIND, codec.TEMPLATE_VERSION_V2, "provider:codec",
        (("input_tokens", 12000), ("output_tokens", 3000), ("model_tokens", 15000), ("model_microusd", 777)),
        "4" * 64, 1000, "counting-policy:codec", "v1")
    sample = actual_personal_phase_price_ceiling_v1(evidence, "tone_sample")
    full = actual_personal_phase_price_ceiling_v1(evidence, "full")
    assert sample == {"input_tokens": 6000, "output_tokens": 1000, "model_tokens": 7000, "model_microusd": 777}
    assert full == {"input_tokens": 10000, "output_tokens": 2000, "model_tokens": 12000, "model_microusd": 777}
    for dimension in ("model_tokens", "model_microusd"):
        incomplete = replace(evidence, quote_ceiling=tuple(row for row in evidence.quote_ceiling if row[0] != dimension))
        with pytest.raises(MissingProductionOriginalV1, match="four_dimension"):
            actual_personal_phase_price_ceiling_v1(incomplete, "tone_sample")
    insufficient = replace(evidence, quote_ceiling=tuple((dim, 1500 if dim == "model_tokens" else amount)
        for dim, amount in evidence.quote_ceiling))
    with pytest.raises(MissingProductionOriginalV1, match="total_token"):
        actual_personal_phase_price_ceiling_v1(insufficient, "tone_sample")
