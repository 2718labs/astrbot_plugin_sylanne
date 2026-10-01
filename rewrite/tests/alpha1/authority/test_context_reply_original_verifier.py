"""A V2 original row and current multi-source graph only yield a HOLD preflight."""

from dataclasses import asdict, replace
import json
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from test_first_ingress_c02_commit import c02_case

from rewrite.tests.alpha1.authority.test_reply_qualified_egress_closure import (
    AUDIENCE, NAMESPACE, _graph,
)
from sylanne3.authority_service.current_context_reply_original_verifier import (
    PinnedCurrentContextReplyOriginalVerifier,
)
from sylanne3.authority_service.current_model_egress_graph_verifier import (
    PinnedCurrentModelEgressGraphVerifier,
)
from sylanne3.authority_service.v2_context_reply_result_contract import (
    ContextReplyResultReadRequestV1, context_reply_read_attempt_id_v1,
)
from sylanne3.contracts import canonical_json
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.model_broker.context_reply import (
    CONTEXT_REPLY_TEMPLATE_VERSION, ContextReplyInputV1,
    ContextReplyInstallationV1, ContextReplyPartV1,
    freeze_context_reply_request_v1,
)
from sylanne3.runtime.context_reply_job_v2 import (
    context_reply_job_ids_v2, install_schema,
)
from sylanne3.runtime_contracts import (
    ContextReplyOriginalSealV2, QueryEpoch, VersionedRef,
    canonical_digest, canonical_serialize, context_reply_graph_guard_digest_v2,
)
from test_context_reply_prepare_v2 import (
    context_reply_c02_case,
)


def _prepared_graph(path):
    db = _graph()
    root = source_key(*NAMESPACE.as_tuple, "selected")
    snapshot, attention = PinnedCurrentModelEgressGraphVerifier._reply_snapshot(
        db, NAMESPACE, root.token, 1, 10.0)
    db.execute("CREATE TABLE graph_epochs (bot TEXT, persona TEXT, revision INTEGER)")
    db.execute("INSERT INTO graph_epochs VALUES (?,?,1)", NAMESPACE.as_tuple)
    db.execute("CREATE TABLE graph_authority_epochs "
               "(bot TEXT, persona TEXT, access_epoch INTEGER, delete_epoch INTEGER)")
    db.execute("INSERT INTO graph_authority_epochs VALUES (?,?,1,0)", NAMESPACE.as_tuple)
    db.execute("CREATE TABLE graph_recovery_metadata_v2 "
               "(bot TEXT, persona TEXT, requirements_json TEXT)")
    db.execute("INSERT INTO graph_recovery_metadata_v2 VALUES (?,?,?)",
               NAMESPACE.as_tuple + (canonical_json({
                   "namespace": asdict(NAMESPACE), "activation_generation": 1,
               }),))
    db.execute("CREATE TABLE graph_dependencies "
               "(dependent_token TEXT, dependency_token TEXT, dependency_revision INTEGER)")
    for source_id in ("selected", "ancestor"):
        db.execute("INSERT INTO graph_dependencies VALUES (?,?,1)", (
            access_key(*NAMESPACE.as_tuple, source_id).token,
            source_key(*NAMESPACE.as_tuple, source_id).token))
    original = SourceRecord.from_dict(snapshot.get(root).value)
    evidence = ContextReplyPartV1(
        "d06_evidence", VersionedRef(root.token, 1),
        VersionedRef(AUDIENCE, 0), 100.0, original.text,
        (VersionedRef(source_key(*NAMESPACE.as_tuple, "ancestor").token, 1),),
        VersionedRef(access_key(*NAMESPACE.as_tuple, "selected").token, 1),
    )
    input = ContextReplyInputV1(
        NAMESPACE, VersionedRef("scene:private", 0), VersionedRef(AUDIENCE, 0),
        AUDIENCE, 1, 0, 1, 1.0, 100.0,
        ContextReplyPartV1("question", VersionedRef("c02-question:c02", 1),
                           VersionedRef(AUDIENCE, 0), 100.0, original.text),
        (evidence,),
    )
    frozen = freeze_context_reply_request_v1(
        input, ContextReplyInstallationV1(
            "installation", "a" * 64, "provider", "model", 128))
    ids = context_reply_job_ids_v2(NAMESPACE, "c02", root.token)
    query = QueryEpoch(NAMESPACE, input.scene_ref.ref, 1)
    guard = context_reply_graph_guard_digest_v2(
        snapshot.versions, query, graph_epoch=1, access_epoch=1,
        delete_epoch=0, activation_generation=1)
    seal = ContextReplyOriginalSealV2(
        NAMESPACE, "c02", root.token, "installation", "a" * 64,
        *ids, CONTEXT_REPLY_TEMPLATE_VERSION,
        canonical_digest(asdict(input)), frozen.digest, guard)
    install_schema(db)
    db.execute(
        "INSERT INTO graph_context_reply_preparations_v2"
        "(bot,persona,c02_operation_id,source_ref,job_id,original_operation_id,"
        "seal_json,frozen_request_json,read_versions_json,query_epoch_json,"
        "graph_epoch,access_epoch,delete_epoch,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        NAMESPACE.as_tuple + ("c02", root.token, ids[0], ids[1],
                              canonical_serialize(asdict(seal)),
                              canonical_serialize(asdict(frozen)),
                              canonical_serialize([{"key": v.key.token,
                                                    "revision": v.revision}
                                                   for v in snapshot.versions]),
                              canonical_serialize(asdict(query)), 1, 1, 0,
                              "queued"),
    )
    db.commit()
    saved = sqlite3.connect(path)
    db.backup(saved)
    saved.close()
    db.close()
    request = ContextReplyResultReadRequestV1(
        "authority", "authority:namespace", NAMESPACE, "c02", root.token,
        "installation", ids[0], ids[2], ids[1], ids[3], frozen.digest,
        canonical_digest(asdict(input)),
        context_reply_read_attempt_id_v1(ids[1], 1))
    return request


def test_original_current_read_is_content_free_and_revocation_holds(tmp_path):
    path = tmp_path / "graph.sqlite"
    request = _prepared_graph(path)
    verifier = PinnedCurrentContextReplyOriginalVerifier(path)
    candidate = verifier.current(request, now_utc=10.0)
    assert candidate is not None
    assert candidate.status == "original_preparation_current_hold"
    assert len(candidate.current_read_versions) == 8
    assert not hasattr(candidate, "body")
    with sqlite3.connect(path) as db:
        db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (
            access_key(*NAMESPACE.as_tuple, "ancestor").token,))
    assert verifier.current(request, now_utc=10.0) is None


def test_original_preparation_absent_or_tampered_holds(tmp_path):
    path = tmp_path / "graph.sqlite"
    request = _prepared_graph(path)
    verifier = PinnedCurrentContextReplyOriginalVerifier(path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE graph_context_reply_preparations_v2 "
                   "SET graph_epoch=2 WHERE job_id=?", (request.job_id,))
    assert verifier.current(request, now_utc=10.0) is None
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM graph_context_reply_preparations_v2 "
                   "WHERE job_id=?", (request.job_id,))
    assert verifier.current(request, now_utc=10.0) is None


def test_private_reply_original_conversation_must_match_frozen_audience(tmp_path):
    path = tmp_path / "graph.sqlite"
    request = _prepared_graph(path)
    verifier = PinnedCurrentContextReplyOriginalVerifier(path)
    assert verifier.current(request, now_utc=10.0) is not None
    with sqlite3.connect(path) as db:
        db.execute("UPDATE graph_first_ingress_identity_v1 "
                   "SET conversation_ref='conversation:other'")
    assert verifier.current(request, now_utc=10.0) is None


def test_acquire_epoch_advance_keeps_original_seal_and_rechecks_access(tmp_path):
    path = tmp_path / "graph.sqlite"
    request = _prepared_graph(path)
    verifier = PinnedCurrentContextReplyOriginalVerifier(path)
    original = verifier.current(request, now_utc=10.0)
    assert original is not None
    with sqlite3.connect(path) as db:
        # Acquiring the paid job advances the graph epoch without changing
        # the selected D06/D07 closure or the original E+1 seal.
        db.execute("UPDATE graph_epochs SET revision=2")
    advanced = verifier.current(request, now_utc=10.0)
    assert advanced is not None
    assert advanced.seal.graph_guard_digest == original.seal.graph_guard_digest
    assert advanced.current_guard_digest != original.current_guard_digest
    with sqlite3.connect(path) as db:
        db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (
            access_key(*NAMESPACE.as_tuple, "ancestor").token,))
    assert verifier.current(request, now_utc=10.0) is None


def test_original_paid_terminal_current_read_and_source_revocation(
        context_reply_c02_case, monkeypatch):
    """A settled original call is still rechecked against current D06."""
    from test_context_reply_prepare_v2 import (
        _context_reply_original_paid_lifecycle_case,
    )

    case = _context_reply_original_paid_lifecycle_case(
        context_reply_c02_case, monkeypatch)
    store, saved, intent = case["store"], case["saved"], case["intent"]
    seal = saved.seal
    path = store._db.execute("PRAGMA database_list").fetchone()[2]
    request = ContextReplyResultReadRequestV1(
        intent.authority_id, intent.namespace, case["namespace"],
        seal.c02_operation_id, seal.source_ref, seal.installation_id,
        seal.job_id, seal.acquire_operation_id, seal.original_operation_id,
        seal.call_id, seal.model_request_digest, seal.frozen_input_digest,
        context_reply_read_attempt_id_v1(seal.original_operation_id, 1),
    )
    verifier = PinnedCurrentContextReplyOriginalVerifier(path)
    now = saved.frozen_request.input.frozen_at_utc + 1.0
    assert verifier.current(request, now_utc=now) is not None
    result = verifier.paid_call_current(
        request, intent, case["terminal"], now_utc=now)
    assert result is not None
    assert result.model_call_request_digest == intent.request_digest
    assert result.original.current_guard_digest != seal.graph_guard_digest
    assert verifier.paid_call_current(
        request, intent,
        replace(case["terminal"], report_digest="0" * 64),
        now_utc=now) is None
    from sylanne3.runtime.model_cost_settlement import (
        original_model_cost_operation_id_v1,
    )
    cost_id = original_model_cost_operation_id_v1(case["namespace"], seal.call_id)
    receipt_json = store._db.execute(
        "SELECT receipt_json FROM graph_bundle_operations WHERE bot=? "
        "AND persona=? AND operation_id=?",
        case["namespace"].as_tuple + (cost_id,),
    ).fetchone()[0]
    altered = json.loads(receipt_json)
    altered["original_intent_digest"] = "0" * 64
    store._db.execute(
        "UPDATE graph_bundle_operations SET receipt_json=? WHERE bot=? "
        "AND persona=? AND operation_id=?",
        (canonical_json(altered), *case["namespace"].as_tuple, cost_id),
    )
    assert verifier.paid_call_current(
        request, intent, case["terminal"], now_utc=now) is None
    store._db.execute(
        "UPDATE graph_bundle_operations SET receipt_json=? WHERE bot=? "
        "AND persona=? AND operation_id=?",
        (receipt_json, *case["namespace"].as_tuple, cost_id),
    )
    assert verifier.paid_call_current(
        request, intent, case["terminal"],
        now_utc=saved.frozen_request.input.expires_at_utc) is None
    access_ref = saved.frozen_request.input.evidence[0].access_ref.ref
    store._db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (access_ref,))
    assert verifier.paid_call_current(
        request, intent, case["terminal"], now_utc=now) is None
