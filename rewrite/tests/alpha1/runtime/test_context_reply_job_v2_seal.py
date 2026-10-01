"""A saved V2 original request survives an exact database round trip."""

from dataclasses import asdict
import json
import sqlite3
from types import SimpleNamespace

import pytest

from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.model_broker.context_reply import (
    CONTEXT_REPLY_TEMPLATE_DIGEST, CONTEXT_REPLY_TEMPLATE_VERSION, ContextReplyInputV1,
    ContextReplyInstallationV1, ContextReplyPartV1,
    freeze_context_reply_request_v1,
)
from sylanne3.model_broker.broker import ModelCallRequest
from sylanne3.runtime.context_reply_job_v2 import (
    ContextReplyJobHold, bind_original_context_reply_call_v2,
    context_reply_job_ids_v2, install_schema,
    read_original_context_reply_call_binding_v2,
    read_original_context_reply_preparation_v2,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, ContextReplyOriginalSealV2,
    NamespaceId, OperationIdentity, QueryEpoch, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, VersionedRef,
    canonical_digest, canonical_serialize, context_reply_graph_guard_digest_v2,
)


def test_saved_context_reply_seal_roundtrips_stable_history_and_rejects_tamper():
    namespace = NamespaceId("bot", "persona")
    source = AtomKey(Owner("event", "bot", "persona", "source"),
                     "memory.source", "original")
    block = AtomKey(Owner("activity", "bot", "persona", "history"),
                    "d13.compressed_turn_block.v2", "stable")
    audience = VersionedRef("private-conversation", 1)
    question = ContextReplyPartV1(
        "question", VersionedRef("question:c02", 1), audience,
        100.0, "What happened?",
    )
    evidence = ContextReplyPartV1(
        "d06_evidence", VersionedRef(source.token, 1), audience,
        100.0, "It happened.", (), VersionedRef("access", 1),
    )
    history = ContextReplyPartV1(
        "d13_history", VersionedRef(block.token, 1), audience,
        100.0, "Earlier chat.", (VersionedRef(source.token, 1),),
    )
    frozen = freeze_context_reply_request_v1(
        ContextReplyInputV1(
            namespace, VersionedRef("scene", 1), audience,
            audience.ref, 1, 0, 1, 10.0, 100.0, question,
            (evidence,), stable_history=(history,),
        ),
        ContextReplyInstallationV1("installation", "a" * 64,
                                   "provider", "model", 200),
    )
    ids = context_reply_job_ids_v2(namespace, "c02", source.token)
    versions = (GraphVersion(source, 1),)
    query = QueryEpoch(namespace, "private-conversation", 1)
    guard = context_reply_graph_guard_digest_v2(
        versions, query, graph_epoch=1, access_epoch=1,
        delete_epoch=0, activation_generation=1,
    )
    seal = ContextReplyOriginalSealV2(
        namespace, "c02", source.token, "installation", "a" * 64,
        *ids, CONTEXT_REPLY_TEMPLATE_VERSION,
        canonical_digest(asdict(frozen.input)), frozen.digest, guard,
    )
    db = sqlite3.connect(":memory:")
    install_schema(db)
    db.execute(
        "INSERT INTO graph_context_reply_preparations_v2"
        "(bot,persona,c02_operation_id,source_ref,job_id,original_operation_id,"
        "seal_json,frozen_request_json,read_versions_json,query_epoch_json,"
        "graph_epoch,access_epoch,delete_epoch,state)"
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        namespace.as_tuple + ("c02", source.token, ids[0], ids[1],
                              canonical_serialize(asdict(seal)),
                              canonical_serialize(asdict(frozen)),
                              canonical_serialize([{"key": source.token, "revision": 1}]),
                              canonical_serialize(asdict(query)), 1, 1, 0, "queued"),
    )
    saved = read_original_context_reply_preparation_v2(
        db, namespace, "c02", source.token)
    assert saved is not None
    assert saved.seal == seal
    assert saved.frozen_request == frozen
    assert saved.frozen_request.input.stable_history == (history,)
    assert saved.read_versions == versions
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity(
            "activity", None, "attempt", "context_reply", ids[2],
            canonical_digest({"input_refs": [source.token]}),
        ),
        AuthorityContext(
            "worker", "d11", "capability", namespace, ("activity",),
            "proposal", (audience.ref,), "policy", 1, 1,
        ),
        VersionGuard(versions, (query,), 1, 0, "catalogue", "scheme",
                     "operator", "policy", (), (), ()),
        SourceQualification(
            (source.token,), "reported", None, 10.0, "external_report",
            "qualified", None, "not_applicable",
        ),
        (source.token,), "lease", 100.0, 100.0, "interval", ("c02",),
    )
    call = ModelCallRequest(
        envelope, seal.call_id, "provider", "model", frozenset({"text"}),
        "private", CONTEXT_REPLY_TEMPLATE_DIGEST,
        json.loads(frozen.canonical_wire), 10.0, 200,
    )
    job = SimpleNamespace(job_id=seal.job_id,
                          operation_id=seal.original_operation_id,
                          phase="running", fence=1)
    assert bind_original_context_reply_call_v2(db, saved, job, call) == call.digest
    saved = read_original_context_reply_preparation_v2(
        db, namespace, "c02", source.token)
    assert saved.state == "acquired"
    bound = read_original_context_reply_call_binding_v2(db, saved)
    assert bound is not None
    assert bound.model_call_request == call
    assert bound.model_call_request_digest == call.digest
    assert call.digest != seal.model_request_digest
    assert bind_original_context_reply_call_v2(db, saved, job, call) == call.digest
    db.execute(
        "UPDATE graph_context_reply_call_bindings_v2 "
        "SET model_call_request_digest=? WHERE bot=? AND persona=?",
        (seal.model_request_digest, *namespace.as_tuple),
    )
    with pytest.raises(ContextReplyJobHold):
        read_original_context_reply_call_binding_v2(db, saved)
    db.execute(
        "UPDATE graph_context_reply_call_bindings_v2 "
        "SET model_call_request_digest=? WHERE bot=? AND persona=?",
        (call.digest, *namespace.as_tuple),
    )
    db.execute(
        "UPDATE graph_context_reply_preparations_v2 SET graph_epoch=2 "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    )
    with pytest.raises((ContextReplyJobHold, ValueError)):
        read_original_context_reply_preparation_v2(
            db, namespace, "c02", source.token)
