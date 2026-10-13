"""Durable request identity only; no test invokes a model provider."""

from dataclasses import replace
import sqlite3

import pytest

from sylanne3.model_broker.broker import ModelCallRequest
from sylanne3.model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
    build_first_ingress_encoding_payload,
)
from sylanne3.memory_types import SourceRecord
from sylanne3.memory_types import access_key, source_key
from sylanne3.graph_types import GraphVersion
from sylanne3.runtime.encoding_call_binding import (
    EncodingCallConflict, insert_binding, install_schema, load_binding,
    prepare_binding,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    SourceQualification, VersionGuard, canonical_digest,
)


NAMESPACE = NamespaceId("bot", "persona")
SOURCE = SourceRecord("source-1", "source text", "speaker-1", "reported",
                      "reported", None, 1.0, "source-1",
                      ("internal",), ("consolidation",))


def _request(*, call_id="call-1", payload=None, max_output_tokens=128,
             source=SOURCE, template_version=FIRST_INGRESS_ENCODING_TEMPLATE_VERSION):
    source_id = source.source_id
    source_ref = source_key(*NAMESPACE.as_tuple, source_id).token
    expected_payload, template_digest = build_first_ingress_encoding_payload(source, template_version=template_version)
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity-1", None, "attempt-1", "encode",
                          "operation-1", canonical_digest({"input_refs": [source_ref]})),
        AuthorityContext("worker", "d06", "capability", NAMESPACE,
                         ("activity",), "consolidation", ("internal",), "policy", 1,
                         worker_fence=1),
        VersionGuard((
            GraphVersion(source_key(*NAMESPACE.as_tuple, source_id), 1),
            GraphVersion(access_key(*NAMESPACE.as_tuple, source_id), 1),
        ), (), 0, 0, "catalogue", "scheme", "operator",
                     "policy", (), (), ()),
        SourceQualification((source_ref,), "reported", None, 1.0,
                            "external_report", "qualified", None, "not_applicable"),
        (source_ref,), "budget-1", 100.0, 100.0, "interval-1", (),
    )
    return ModelCallRequest(
        envelope, call_id, "provider-1", "model-1",
        frozenset({"structured"}), "private", template_digest,
        payload if payload is not None else expected_payload,
        20.0, max_output_tokens,
    )


def _binding(request=None, *, job_id="job-1", source=SOURCE):
    return prepare_binding(
        NAMESPACE, job_id, source, 1, 1, "budget-1", "operation-1",
        request or _request(source=source),
        prompt_template_version=FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
        provider_config_ref="admin-config-1", provider_config_digest="b" * 64,
    )


def test_binding_survives_reopen_and_replays_only_identical_content(tmp_path):
    path = tmp_path / "graph.db"
    binding = _binding()
    with sqlite3.connect(path) as db:
        install_schema(db)
        assert insert_binding(db, binding) == binding
        assert insert_binding(db, binding) == binding
    with sqlite3.connect(path) as db:
        install_schema(db)
        loaded = load_binding(db, NAMESPACE, "job-1")
        assert loaded == binding
        assert "source text" in loaded.request["payload"]["prompt"]
        assert loaded.request["provider_config_ref"] == "admin-config-1"
        assert loaded.request["provider_config_digest"] == "b" * 64
        assert "provider_config" not in loaded.request
        assert loaded.model_request_digest == _request().digest
        assert loaded.binding_digest == canonical_digest(loaded.request)
        assert loaded.binding_digest != loaded.model_request_digest
        assert loaded.request["max_output_tokens"] == 128
        with pytest.raises(EncodingCallConflict, match="different request"):
            insert_binding(db, _binding(_request(max_output_tokens=256)))
        with pytest.raises(EncodingCallConflict, match="different request"):
            insert_binding(db, _binding(_request(call_id="call-2")))
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("UPDATE runtime_encoding_call_bindings_v1 SET source_id='bad'")


def test_call_id_cannot_move_to_another_job(tmp_path):
    with sqlite3.connect(tmp_path / "graph.db") as db:
        install_schema(db)
        insert_binding(db, _binding())
        other = _binding(job_id="job-2")
        with pytest.raises(EncodingCallConflict, match="another job"):
            insert_binding(db, other)


def test_erased_call_id_cannot_be_reused_by_another_source(tmp_path):
    with sqlite3.connect(tmp_path / "graph.db") as db:
        install_schema(db)
        original = insert_binding(db, _binding())
        db.execute("DELETE FROM runtime_encoding_call_bindings_v1 WHERE job_id=?",
                   (original.job_id,))
        db.execute(
            "INSERT INTO runtime_encoding_call_redactions_v1"
            "(bot,persona,acquire_operation_id,job_id,source_id,call_id,"
            "binding_digest,model_request_digest,deletion_operation_id) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            NAMESPACE.as_tuple + ("acquire-1", original.job_id,
                original.source_id, original.call_id, original.binding_digest,
                original.model_request_digest, "delete-1"),
        )
        other_source = replace(SOURCE, source_id="source-2")
        with pytest.raises(EncodingCallConflict, match="erased call ID"):
            insert_binding(db, _binding(job_id="job-2", source=other_source))


def test_wrong_source_or_budget_is_rejected_before_storage():
    with pytest.raises(ValueError, match="source or budget"):
        prepare_binding(
            NAMESPACE, "job-1", replace(SOURCE, source_id="different-source"),
            1, 1, "budget-1", "operation-1", _request(),
            prompt_template_version=FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
            provider_config_ref="admin-config-1", provider_config_digest="b" * 64,
        )
    with pytest.raises(ValueError, match="source or budget"):
        prepare_binding(
            NAMESPACE, "job-1", SOURCE, 1, 1, "different-budget",
            "operation-1", _request(),
            prompt_template_version=FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
            provider_config_ref="admin-config-1", provider_config_digest="b" * 64,
        )


def test_caller_prompt_cannot_substitute_for_current_source():
    forged = _request(payload={"system_prompt": "other", "prompt": "source text"})
    with pytest.raises(ValueError, match="fixed first-ingress template"):
        _binding(forged)


def test_bare_source_id_is_not_a_graph_source_ref():
    request = _request()
    envelope = replace(
        request.envelope,
        identity=replace(request.envelope.identity,
                         canonical_input_digest=canonical_digest(
                             {"input_refs": [SOURCE.source_id]})),
        source_qualification=replace(request.envelope.source_qualification,
                                     source_refs=(SOURCE.source_id,)),
        input_refs=(SOURCE.source_id,),
    )
    with pytest.raises(ValueError, match="source or budget identity"):
        _binding(replace(request, envelope=envelope))


def _v2_task_result(source):
    import json
    return {"text": json.dumps({
        "schema": "sylanne.d06.first_ingress_encoding_output.v2",
        "event_summary": "用户要求先存初稿，收到真实更正后存终稿。",
        "quoted_details": [], "possible_meanings": [], "possible_feelings": [],
        "task_intent": {"kind": "draft_then_corrected_revision", "filename": "draft.txt",
                        "source_quote": source.text},
    }, ensure_ascii=False)}


def test_v2_encoding_binding_retains_exact_version_through_sqlite_reopen(tmp_path):
    from sylanne3.model_broker.first_ingress_encoding import FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION
    source = replace(SOURCE, text="先保存 draft.txt 初稿，等我的更正后再保存终稿。")
    request = _request(source=source, template_version=FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION)
    binding = prepare_binding(NAMESPACE, "task-job", source, 1, 1, "budget-1", "operation-1", request,
        prompt_template_version=FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION,
        provider_config_ref="admin-config-1", provider_config_digest="b" * 64)
    path = tmp_path / "task-binding.db"
    with sqlite3.connect(path) as db:
        install_schema(db)
        assert insert_binding(db, binding) == binding
    with sqlite3.connect(path) as db:
        restored = load_binding(db, NAMESPACE, "task-job")
        assert restored == binding
        assert restored.request["prompt_template_version"] == FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION
        assert restored.model_request_digest == request.digest
        assert restored.request["payload"] != _request(source=source).payload
    with pytest.raises(ValueError, match="template"):
        _binding(request, source=source)  # V1 binding cannot consume a V2 request.


def test_v2_task_candidate_remains_non_authorizing_and_version_bound():
    from sylanne3.model_broker.first_ingress_encoding import (
        FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION, parse_artifact_task_intent_v1,
        parse_first_ingress_encoding_result,
    )
    source = replace(SOURCE, text="先保存 draft.txt 初稿，等我的更正后再保存终稿。")
    result = _v2_task_result(source)
    candidate = parse_artifact_task_intent_v1(result, source)
    assert (candidate.kind, candidate.filename, candidate.source_quote) == (
        "draft_then_corrected_revision", "draft.txt", source.text)
    memory = parse_first_ingress_encoding_result(result, source,
        template_version=FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION)
    assert memory.event_summary
    assert set(candidate.__dataclass_fields__) == {"kind", "filename", "source_quote", "schema"}
    with pytest.raises(ValueError, match="frozen template version"):
        parse_first_ingress_encoding_result(result, source,
            template_version=FIRST_INGRESS_ENCODING_TEMPLATE_VERSION)


@pytest.mark.parametrize("field,value", [
    ("kind", "execute_anything"), ("filename", "foreign.txt"),
    ("source_quote", "没有在原消息中出现的权限声明"),
])
def test_v2_task_candidate_rejects_unregistered_kind_or_unquoted_source(field, value):
    import json
    from sylanne3.model_broker.first_ingress_encoding import parse_artifact_task_intent_v1
    source = replace(SOURCE, text="先保存 draft.txt 初稿，等我的更正后再保存终稿。")
    result = _v2_task_result(source)
    assert parse_artifact_task_intent_v1(result, source).kind == "draft_then_corrected_revision"
    raw = json.loads(result["text"])
    raw["task_intent"][field] = value
    with pytest.raises(ValueError):
        parse_artifact_task_intent_v1({"text": json.dumps(raw, ensure_ascii=False)}, source)
