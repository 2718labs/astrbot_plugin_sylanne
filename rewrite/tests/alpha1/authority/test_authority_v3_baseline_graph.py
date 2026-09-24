"""A fresh V3 egress requires the independently committed D04 baseline."""

from dataclasses import asdict, replace
import json
from pathlib import Path
import sys

from sylanne3.authority_service.v2_contract import from_wire, to_wire
from sylanne3.authority_service.current_worker_model_result_graph_verifier import (
    PinnedCurrentWorkerModelResultGraphVerifier,
)
from sylanne3.authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1,
)
from sylanne3.contracts import canonical_json
from sylanne3.domains.d04.encoding_baseline import EncodingBaseline
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.memory_types import source_key
from sylanne3.runtime.d11_types import runtime_job_key
from sylanne3.runtime.encoding_call_binding import (
    CommittedEncodingBaselineV1, binding_to_json, load_binding,
)
from sylanne3.runtime.jobs import get_job
from sylanne3.runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from sylanne3.runtime_contracts import SnapshotRequirementsV2

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from test_current_model_egress_graph_verifier import _case, token_ingress_system
from test_current_d04_baseline_graph_proof import _seed_d03_stage, _stage_quote
import time


def _v3_case(system):
    db, verifier, intent = _case(system, production=True)
    ns = NamespaceId("bot", "persona")
    source = source_key(*ns.as_tuple, intent.source_refs[0])
    original = db.execute(
        "SELECT graph_revision,graph_epoch,anchor_json,requirements_json "
        "FROM graph_job_acquire_intents_v2 WHERE job_id=?",
        (intent.job_id,),
    ).fetchone()
    graph_revision, graph_epoch, anchor_json, requirements_json = original
    assert graph_revision >= 1 and graph_epoch >= 1
    bundle_digest, activity_id = "d" * 64, "d04-v3-activity"
    original_operation_id = db.execute(
        "SELECT operation_id FROM runtime_jobs WHERE job_id=?",
        (intent.job_id,),
    ).fetchone()[0]
    lease_id = db.execute(
        "SELECT lease_id FROM runtime_budget_leases WHERE parent_id IS NULL"
    ).fetchone()[0]
    issuer = system[1]._GraphCoordinator__d11_issuer
    anchor = from_wire(json.loads(db.execute(
        "SELECT permit_json FROM graph_job_acquire_receipts_v2 "
        "WHERE job_json LIKE ? LIMIT 1", ("%" + intent.job_id + "%",),
    ).fetchone()[0])).pinned_anchor
    frozen_requirements = json.loads(requirements_json)
    requirements = SnapshotRequirementsV2(**{
        **frozen_requirements,
        "namespace": NamespaceId(**frozen_requirements["namespace"]),
    })
    perspective, event, mapping = _seed_d03_stage(
        db, ns, source, requirements, anchor, issuer=issuer,
        pre_revision=graph_revision-1, pre_epoch=graph_epoch-1,
        source_revision=intent.source_revisions[0][1],
        original_operation_id=original_operation_id, lease_id=lease_id)
    operation_id = "d04-baseline-" + canonical_digest({
        "namespace": ns.as_tuple, "source": source.token,
        "event": event.token, "perspective": perspective.token,
        "perspective_revision": 1,
    })[:40]
    attempt = "graph-write-" + canonical_digest({
        "namespace": list(ns.as_tuple), "operation_id": operation_id,
        "bundle_digest": bundle_digest})[:48]
    permit = replace(
        from_wire(json.loads(db.execute(
            "SELECT permit_json FROM graph_job_acquire_receipts_v2 "
            "WHERE job_json LIKE ? LIMIT 1", ("%" + intent.job_id + "%",),
        ).fetchone()[0])), operation="write", operation_id=attempt,
        token="w" * 32, pinned_anchor=anchor)
    value = EncodingBaseline(
        "baseline:v3-fixture", (source.token,), perspective.token, (), (),
        1.0, "projection-policy", "1", "1", "1", None, None,
        ("salience_interval:unknown", "tone_interval:unknown"))
    key = AtomKey(source.owner, "d04.encoding_baseline.v1", value.baseline_id)
    baseline = CommittedEncodingBaselineV1(
        key.token, 1, operation_id, bundle_digest,
        frozen_requirements["graph_incarnation"], graph_epoch)
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d04_baseline_issuance_v1(
        bot TEXT,persona TEXT,operation_id TEXT,source_ref TEXT,event_ref TEXT,
        quote_id TEXT,bundle_digest TEXT)""")
    quote_id = _stage_quote(db, issuer, ns, operation_id, activity_id,
                            "d04", lease_id=lease_id)
    db.execute("INSERT INTO graph_d04_baseline_issuance_v1 VALUES(?,?,?,?,?,?,?)",
               (*ns.as_tuple, operation_id, source.token, event.token,
                quote_id, bundle_digest))
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d04_baseline_intents_v1(
        bot TEXT,persona TEXT,source_ref TEXT,original_operation_id TEXT,
        operation_id TEXT,bundle_digest TEXT)""")
    db.execute("INSERT INTO graph_d04_baseline_intents_v1 VALUES(?,?,?,?,?,?)",
               (*ns.as_tuple, source.token, original_operation_id,
                operation_id, bundle_digest))
    sequence = db.execute(
        "SELECT MAX(commit_seq) FROM graph_bundle_operations").fetchone()[0] + 1
    db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, operation_id, bundle_digest, activity_id,
                None, sequence, canonical_json({
                    "commit_seq": sequence, "ledger_refs": [], "outbox_refs": []})))
    db.execute("INSERT INTO graph_bundle_intents_v2 VALUES(?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, operation_id, bundle_digest, attempt,
                requirements_json, anchor_json, graph_revision - 1,
                graph_epoch - 1))
    db.execute("INSERT INTO graph_bundle_fences_v2 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, operation_id, bundle_digest,
                canonical_json(to_wire(permit)), graph_revision - 1,
                graph_epoch - 1, graph_revision, graph_epoch,
                "finish:" + attempt, "sha256:" + canonical_digest({
                    "operation_id": attempt, "permit_token": permit.token,
                    "action": "finish_domain_bundle",
                    "business_operation_id": operation_id,
                    "bundle_digest": bundle_digest})))
    reads = [[source.token, intent.source_revisions[0][1]],
             [perspective.token, 1], [key.token, 0]]
    db.execute("INSERT INTO graph_events VALUES(?,?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, activity_id, operation_id, "graph-event-digest",
                canonical_json(reads), "[]", canonical_json([[key.token, 1]]),
                "[]", graph_epoch))
    value_json = canonical_json({
        **asdict(value), "source_refs": [source.token],
        "then_feeling_versions": [], "interpretation_versions": [],
        "unknown_reasons": list(value.unknown_reasons)})
    for atom_key, atom_value in ((key, value_json),):
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,1)",
                   (atom_key.token, *ns.as_tuple, atom_key.owner.kind,
                    atom_key.owner.subject, atom_key.type_name, atom_key.name,
                    1, atom_value))
    db.execute("INSERT INTO graph_history VALUES(?,?,?,?,?,?,?,?,?)",
               (key.token, 1, value_json, 1, "[]", *ns.as_tuple,
                activity_id, operation_id))
    for ref, revision in ((source.token, intent.source_revisions[0][1]),
                          (perspective.token, 1)):
        db.execute("INSERT INTO graph_dependency_edges VALUES(?,?,?,?,?)",
                   (key.token, ref, revision, "historical_provenance", operation_id))
    binding = load_binding(db, ns, intent.job_id)
    frozen = json.loads(binding.request_json)
    frozen["schema"] = "sylanne.first-ingress-encoding-call.v3"
    frozen["baseline"] = asdict(baseline)
    frozen["envelope"]["version_guard"]["read_versions"].append(
        json.loads(canonical_serialize(GraphVersion(key, 1))))
    frozen["model_request_digest"] = canonical_digest({
        "envelope": frozen["envelope"], "call_id": frozen["call_id"],
        "provider_id": frozen["provider_id"], "model_id": frozen["model_id"],
        "purpose": frozen["envelope"]["authority"]["purpose"],
        "required_capabilities": frozen["required_capabilities"],
        "privacy_tier": frozen["privacy_tier"],
        "template": frozen["prompt_template_digest"],
        "payload": frozen["payload"],
        "timeout_seconds": frozen["timeout_seconds"],
        "max_output_tokens": frozen["max_output_tokens"],
    })
    binding = replace(
        binding, request_json=canonical_serialize(frozen),
        binding_digest=canonical_digest(frozen),
        model_request_digest=frozen["model_request_digest"])
    binding_to_json(binding)
    db.execute("DROP TRIGGER runtime_encoding_call_bindings_no_update_v1")
    db.execute("DROP TRIGGER graph_job_acquire_intent_no_update_v2")
    db.execute(
        "UPDATE runtime_encoding_call_bindings_v1 SET binding_digest=?,"
        "model_request_digest=?,request_json=? WHERE job_id=?",
        (binding.binding_digest, binding.model_request_digest,
         binding.request_json, intent.job_id))
    db.execute(
        "UPDATE graph_job_acquire_intents_v2 SET encoding_binding_json=? "
        "WHERE job_id=?", (binding_to_json(binding), intent.job_id))
    return db, verifier, replace(intent, request_digest=binding.model_request_digest), key


def test_v3_egress_requires_real_committed_baseline(token_ingress_system):
    db, verifier, intent, key = _v3_case(token_ingress_system)
    assert verifier.complete_graph_current(intent)
    baseline_operation, original_digest = db.execute(
        "SELECT operation_id,bundle_digest FROM graph_d04_baseline_issuance_v1"
    ).fetchone()
    db.execute("UPDATE graph_d04_baseline_issuance_v1 SET bundle_digest='wrong' "
               "WHERE operation_id=?", (baseline_operation,))
    assert not verifier.complete_graph_current(intent)
    db.execute("UPDATE graph_d04_baseline_issuance_v1 SET bundle_digest=? "
               "WHERE operation_id=?", (original_digest, baseline_operation))
    assert verifier.complete_graph_current(intent)
    db.execute("DELETE FROM graph_history WHERE token=?", (key.token,))
    assert not verifier.complete_graph_current(intent)


def test_v3_worker_result_rechecks_same_baseline_after_original_call(
        token_ingress_system):
    db, _, intent, key = _v3_case(token_ingress_system)
    namespace = NamespaceId("bot", "persona")
    binding = load_binding(db, namespace, intent.job_id)
    acquire_id = db.execute(
        "SELECT acquire_operation_id FROM graph_job_acquire_intents_v2 "
        "WHERE job_id=?", (intent.job_id,)).fetchone()[0]
    acquire_permit = from_wire(json.loads(db.execute(
        "SELECT permit_json FROM graph_job_acquire_receipts_v2 "
        "WHERE acquire_operation_id=?", (acquire_id,),
    ).fetchone()[0]))
    provision_installation = json.loads(db.execute(
        "SELECT receipt_json FROM graph_namespace_provisioning_v2 "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()[0])["installation_id"]
    request = WorkerModelResultReadRequestV1(
        intent.authority_id, intent.namespace, namespace,
        provision_installation, intent.job_id, acquire_id,
        intent.budget_reservation_operation_id, intent.call_id,
        binding.binding_digest, intent.request_digest,
        "c02-v3-commit", "worker-v3-read")
    read_permit = replace(
        acquire_permit, subject=intent.subject, operation="read",
        operation_id=request.read_attempt_id, token="r" * 32)
    verifier = PinnedCurrentWorkerModelResultGraphVerifier(
        db.execute("PRAGMA database_list").fetchone()[2],
        trusted_now_utc=time.time,
        d11_issuer=token_ingress_system[1]._GraphCoordinator__d11_issuer)
    worker_intent = replace(intent, operation_id=acquire_id)
    assert verifier.current(request, worker_intent, read_permit)
    job = get_job(db, intent.job_id)
    quote_id, quote_version = job.operator_versions["resource_quote"].rsplit(":", 1)
    signed = db.execute(
        "SELECT signature FROM runtime_resource_quotes WHERE quote_id=? "
        "AND version=?", (quote_id, int(quote_version)),
    ).fetchone()[0]
    db.execute("UPDATE runtime_resource_quotes SET signature='wrong' "
               "WHERE quote_id=? AND version=?", (quote_id, int(quote_version)))
    assert not verifier.current(request, worker_intent, read_permit)
    db.execute("UPDATE runtime_resource_quotes SET signature=? "
               "WHERE quote_id=? AND version=?",
               (signed, quote_id, int(quote_version)))
    job_key = runtime_job_key(*namespace.as_tuple, job.activity_id, job.job_id)
    historic = db.execute(
        "SELECT value FROM graph_history WHERE token=? AND event_id=?",
        (job_key.token, job.operation_id),
    ).fetchone()[0]
    forged = json.loads(historic)
    forged["phase"] = "running"
    db.execute("UPDATE graph_history SET value=? WHERE token=? AND event_id=?",
               (canonical_json(forged), job_key.token, job.operation_id))
    assert not verifier.current(request, worker_intent, read_permit)
    db.execute("UPDATE graph_history SET value=? WHERE token=? AND event_id=?",
               (historic, job_key.token, job.operation_id))
    db.execute("UPDATE runtime_jobs SET fence=2 WHERE job_id=?", (job.job_id,))
    assert not verifier.current(request, worker_intent, read_permit)
    db.execute("UPDATE runtime_jobs SET fence=? WHERE job_id=?",
               (job.fence, job.job_id))
    db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (key.token,))
    assert not verifier.current(request, worker_intent, read_permit)
