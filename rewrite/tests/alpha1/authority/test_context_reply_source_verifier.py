"""The V2 context reply source read remains a non-authorizing candidate."""

from dataclasses import replace
import json
import sqlite3

import pytest

from sylanne3.authority_service.current_context_reply_source_verifier import (
    read_current_context_reply_sources_v1,
)
from sylanne3.authority_service.v2_context_reply_result_contract import (
    ContextReplyResultReadRequestV1, context_reply_read_attempt_id_v1,
    from_wire, to_wire,
)
from sylanne3.contracts import canonical_json
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.model_broker.context_reply import (
    ContextReplyInputV1, ContextReplyInstallationV1, ContextReplyPartV1,
    freeze_context_reply_request_v1,
)
from sylanne3.runtime_contracts import NamespaceId, VersionedRef


NS = NamespaceId("bot", "persona")
AUDIENCE = VersionedRef("conversation:private", 1)
INSTALL = ContextReplyInstallationV1(
    "installation", "a" * 64, "provider", "model", 128)


def _frozen():
    source = source_key(*NS.as_tuple, "selected")
    access = access_key(*NS.as_tuple, "selected")
    part = ContextReplyPartV1(
        "d06_evidence", VersionedRef(source.token, 1), AUDIENCE,
        150.0, "The door opened.", access_ref=VersionedRef(access.token, 1))
    question = ContextReplyPartV1(
        "question", VersionedRef("turn:current", 1), AUDIENCE,
        150.0, "What happened?")
    input = ContextReplyInputV1(
        NS, VersionedRef("scene:private", 1), AUDIENCE,
        "conversation:private", 2, 3, 4, 100.0, 140.0,
        question, (part,))
    return freeze_context_reply_request_v1(input, INSTALL)


def _graph():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE graph_authority_epochs "
               "(bot TEXT, persona TEXT, access_epoch INTEGER, delete_epoch INTEGER)")
    db.execute("INSERT INTO graph_authority_epochs VALUES (?,?,?,?)",
               (*NS.as_tuple, 2, 3))
    db.execute("CREATE TABLE graph_recovery_metadata_v2 "
               "(bot TEXT, persona TEXT, requirements_json TEXT)")
    db.execute("INSERT INTO graph_recovery_metadata_v2 VALUES (?,?,?)",
               (*NS.as_tuple, canonical_json({
                   "namespace": {"bot_id": NS.bot_id, "persona_id": NS.persona_id},
                   "activation_generation": 4,
               })))
    db.execute("CREATE TABLE graph_atoms "
               "(token TEXT, revision INTEGER, value TEXT, valid INTEGER)")
    db.execute("CREATE TABLE graph_dependencies "
               "(dependent_token TEXT, dependency_token TEXT, dependency_revision INTEGER)")
    for source_id, parents, text in (
        ("selected", ("ancestor",), "The door opened."),
        ("ancestor", (), "Earlier account."),
    ):
        record = SourceRecord(
            source_id, text, "speaker", "reported", "reported", 1.0, 2.0,
            "family:one", (AUDIENCE.ref,), ("expression",), parents)
        source = source_key(*NS.as_tuple, source_id)
        access = access_key(*NS.as_tuple, source_id)
        head = source_correction_head_key(NS, source_id)
        db.execute("INSERT INTO graph_atoms VALUES (?,?,?,1)",
                   (source.token, 1, canonical_json(record.to_dict())))
        db.execute("INSERT INTO graph_atoms VALUES (?,?,?,1)",
                   (access.token, 1, canonical_json({
                       "source_id": source_id, "audiences": [AUDIENCE.ref],
                       "purposes": ["expression"], "status": "active",
                       "recorded_at": 2.0,
                   })))
        db.execute("INSERT INTO graph_atoms VALUES (?,?,?,0)",
                   (head.token, 0, "{}"))
        db.execute("INSERT INTO graph_dependencies VALUES (?,?,1)",
                   (access.token, source.token))
    db.commit()
    db.execute("BEGIN")
    return db


def test_current_multi_source_closure_is_content_free_and_not_authority():
    db = _graph()
    try:
        result = read_current_context_reply_sources_v1(db, _frozen(), now_utc=110.0)
        assert result is not None
        assert result.status == "candidate_requires_original_paid_v2_and_current_authority_fence"
        assert result.frozen_input_digest == _frozen().digest
        assert len(result.read_versions) == 6
        assert not hasattr(result, "model_result_body")
    finally:
        db.close()


@pytest.mark.parametrize("change", [
    "revoked_ancestor", "corrected_ancestor", "source_text_changed",
    "access_epoch_changed", "expired",
])
def test_current_source_change_or_expiry_holds(change):
    db = _graph()
    try:
        if change == "revoked_ancestor":
            token = access_key(*NS.as_tuple, "ancestor").token
            row = db.execute("SELECT value FROM graph_atoms WHERE token=?",
                             (token,)).fetchone()
            value = json.loads(row[0])
            value["status"] = "withdrawn"
            db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                       (canonical_json(value), token))
        elif change == "corrected_ancestor":
            token = source_correction_head_key(NS, "ancestor").token
            db.execute("UPDATE graph_atoms SET revision=1,valid=1 WHERE token=?",
                       (token,))
        elif change == "source_text_changed":
            token = source_key(*NS.as_tuple, "selected").token
            row = db.execute("SELECT value FROM graph_atoms WHERE token=?",
                             (token,)).fetchone()
            value = json.loads(row[0])
            value["text"] = "Different text."
            db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                       (canonical_json(value), token))
        elif change == "access_epoch_changed":
            db.execute("UPDATE graph_authority_epochs SET access_epoch=3")
        assert read_current_context_reply_sources_v1(
            db, _frozen(), now_utc=140.0 if change == "expired" else 110.0) is None
    finally:
        db.close()


def test_context_result_request_rejects_old_workflow_identity():
    request = ContextReplyResultReadRequestV1(
        "authority", "ns:one", NS, "c02",
        source_key(*NS.as_tuple, "selected").token,
        "installation", "job", "acquire",
        "original", "call", "a" * 64, "b" * 64,
        context_reply_read_attempt_id_v1("original", 1))
    assert request.template_version == "sylanne.d09.context_reply.v1"
    assert from_wire(to_wire(request), ContextReplyResultReadRequestV1) == request
    with pytest.raises(ValueError, match="workflow"):
        replace(request, template_version="sylanne.d09.source_reply.v1")
