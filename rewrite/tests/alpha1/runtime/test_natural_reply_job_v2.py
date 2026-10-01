"""Natural generation/review original rows remain separate paid-call identities."""

from dataclasses import replace
import json
import sqlite3

import pytest

from sylanne3.domains.d09 import (
    ClaimKind, NaturalExpressionPlanV2, QualifiedExpressionUnitV2,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.model_broker.context_reply import ContextReplyPartV1
from sylanne3.model_broker.broker import ModelCallRequest
from sylanne3.model_broker.natural_reply import (
    NaturalReplyInputV2, NaturalReplyInstallationV2,
    freeze_natural_reply_request_v2,
)
from sylanne3.model_broker.natural_review import (
    NaturalReviewInstallationV1, freeze_natural_reply_review_v1,
)
from sylanne3.runtime.jobs import (
    PersistentJob, acquire_job, create_job, get_job,
    transition_job, install_schema as jobs_schema,
)
from sylanne3.runtime.natural_reply_job_v2 import (
    NaturalReplyJobHold, bind_original_call, install_schema,
    natural_graph_guard_digest_v2, natural_job_ids_v2,
    read_original_call_binding, read_original_preparation,
    record_terminal, save_original_preparation,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId,
    NaturalReplyGenerationOriginalSealV2, NaturalReplyReviewOriginalSealV2,
    OperationIdentity, QueryEpoch,
    RUNTIME_SCHEMA, SourceQualification, VersionGuard, VersionedRef,
    canonical_digest,
)
from sylanne3.model_broker.natural_reply import TEMPLATE_DIGEST


def _case():
    namespace = NamespaceId("bot", "persona")
    audience = VersionedRef("audience:private", 1)
    unit = QualifiedExpressionUnitV2(
        "basis:greeting", ClaimKind.RHETORIC, "Hello.",
        VersionedRef("qualification:greeting", 1), (), (), (),
        audience.ref, "expression", 30.0,
    )
    plan = NaturalExpressionPlanV2(
        namespace, VersionedRef("plan:one", 1),
        VersionedRef("scene:one", 1), audience, (), ("rhetoric",),
        (), (unit,), 30.0,
        "activity:reply", "operation:reply", "effect:reply",
        "scene:one", audience.ref,
    )
    frozen = freeze_natural_reply_request_v2(
        NaturalReplyInputV2(
            ContextReplyPartV1("question", VersionedRef("question:one", 1),
                               audience, 30.0, "Hi?"),
            plan, (), 1.0, 20.0,
        ),
        NaturalReplyInstallationV2(
            "installation", "a" * 64, "provider", "model", 256,
        ),
    )
    parent = "c02-original"
    ids = natural_job_ids_v2(namespace, parent, "generation")
    key = AtomKey(Owner("activity", "bot", "persona", "activity:one"),
                  "d08.action_intent.v1", "action:one")
    versions = (GraphVersion(key, 1),)
    queries = (QueryEpoch(namespace, "natural:one", 2),)
    guard = natural_graph_guard_digest_v2(
        namespace, versions, queries, graph_epoch=2,
        access_epoch=3, deletion_epoch=4,
    )
    seal = NaturalReplyGenerationOriginalSealV2(
        namespace=namespace, c02_operation_id=parent, source_ref="source:one",
        installation_id="installation", provider_config_digest="a" * 64,
        job_id=ids[0], original_operation_id=ids[1],
        acquire_operation_id=ids[2], call_id=ids[3],
        frozen_input_digest=frozen.frozen_input_digest,
        qualified_units_digest=frozen.qualified_units_digest,
        model_request_digest=frozen.model_request_digest,
        original_graph_guard_digest=guard, parent_budget_lease_id="budget:parent",
        reservation_operation_id=ids[4],
    )
    job = PersistentJob(
        ids[0], ids[1], "activity:one", None, "bot", "persona",
        "snapshot:one", "queued", "natural_generation", {}, None,
        "2026-10-01T00:00:00Z", "budget:parent", "resource:one", {},
        None, None, 0, 0, {}, None,
    )
    return namespace, parent, seal, frozen, versions, queries, job


def _generation_call(namespace, seal, frozen, versions, queries):
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity(
            "activity:one", None, "attempt:one", "natural_generation",
            seal.acquire_operation_id,
            canonical_digest({"input_refs": [seal.source_ref]}),
        ),
        AuthorityContext(
            "worker", "d11", "capability", namespace, ("activity",),
            "proposal", (frozen.input.plan.audience_ref.ref,), "policy", 1, 1,
        ),
        VersionGuard(versions, queries, 3, 4, "catalogue", "scheme",
                     "operator", "policy", (), (), ()),
        SourceQualification(
            (seal.source_ref,), "reported", None, 1.0,
            "external_report", "qualified", None, "not_applicable",
        ),
        (seal.source_ref,), "budget:parent", 20.0, 20.0, "interval",
        (seal.c02_operation_id,),
    )
    return ModelCallRequest(
        envelope, seal.call_id, "provider", "model", frozenset({"text"}),
        "private", TEMPLATE_DIGEST, json.loads(frozen.canonical_wire),
        10.0, 256,
    )


def test_original_generation_is_tx_only_and_recomputes_frozen_wire_and_guard():
    namespace, parent, seal, frozen, versions, queries, job = _case()
    db = sqlite3.connect(":memory:")
    jobs_schema(db)
    install_schema(db)
    with pytest.raises(NaturalReplyJobHold, match="graph write tx"):
        save_original_preparation(
            db, stage="generation", namespace=namespace,
            parent_original_id=parent, seal=seal, frozen=frozen,
            read_versions=versions, query_epochs=queries, graph_epoch=2,
            access_epoch=3, deletion_epoch=4, job=job,
        )
    db.execute("BEGIN")
    create_job(db, job, "create:one", "b" * 64)
    saved = save_original_preparation(
        db, stage="generation", namespace=namespace,
        parent_original_id=parent, seal=seal, frozen=frozen,
        read_versions=versions, query_epochs=queries, graph_epoch=2,
        access_epoch=3, deletion_epoch=4, job=job,
    )
    assert saved.state == "queued" and saved.frozen == frozen
    assert saved.seal.model_request_digest == frozen.model_request_digest
    assert read_original_preparation(db, namespace, parent, "generation") == saved
    db.execute("UPDATE runtime_jobs SET work_kind='context_reply' WHERE job_id=?",
               (job.job_id,))
    with pytest.raises(NaturalReplyJobHold, match="invalid"):
        read_original_preparation(db, namespace, parent, "generation")
    db.execute("UPDATE runtime_jobs SET work_kind='natural_generation' WHERE job_id=?",
               (job.job_id,))
    with pytest.raises(NaturalReplyJobHold):
        save_original_preparation(
            db, stage="review", namespace=namespace,
            parent_original_id=parent, seal=seal, frozen=frozen,
            read_versions=versions, query_epochs=queries, graph_epoch=2,
            access_epoch=3, deletion_epoch=4, job=job,
        )
    db.execute("UPDATE graph_natural_generation_preparations_v2 "
               "SET frozen_json='{}' WHERE original_operation_id=?",
               (seal.original_operation_id,))
    with pytest.raises(NaturalReplyJobHold, match="invalid"):
        read_original_preparation(db, namespace, parent, "generation")
    db.rollback()


def test_generation_and_review_ids_are_disjoint():
    namespace = NamespaceId("bot", "persona")
    generation = natural_job_ids_v2(namespace, "c02-original", "generation")
    review = natural_job_ids_v2(namespace, "c02-original", "review")
    assert len(set(generation + review)) == 10


def test_acquire_binds_real_typed_digest_then_terminal_requires_completed_job():
    namespace, parent, seal, frozen, versions, queries, job = _case()
    db = sqlite3.connect(":memory:")
    jobs_schema(db)
    install_schema(db)
    db.execute("BEGIN")
    create_job(db, job, "create:one", "b" * 64)
    saved = save_original_preparation(
        db, stage="generation", namespace=namespace,
        parent_original_id=parent, seal=seal, frozen=frozen,
        read_versions=versions, query_epochs=queries, graph_epoch=2,
        access_epoch=3, deletion_epoch=4, job=job,
    )
    running = acquire_job(db, job.job_id, "worker", now_utc="2026-09-28T00:00:00Z",
                          lease_seconds=30)
    call = _generation_call(namespace, seal, frozen, versions, queries)
    assert call.digest != frozen.model_request_digest
    assert bind_original_call(db, saved, running, call) == call.digest
    acquired = read_original_preparation(db, namespace, parent, "generation")
    assert acquired.state == "acquired"
    assert acquired.typed_request_digest == call.digest
    assert read_original_call_binding(db, acquired).request == call
    with pytest.raises(NaturalReplyJobHold, match="completed"):
        record_terminal(db, acquired, running,
                        terminal_receipt_digest="c" * 64,
                        output_digest="d" * 64)
    completed = transition_job(
        db, job.job_id, "worker", running.fence,
        target_phase="completed", result_ref="paid-result:one",
    )
    record_terminal(db, acquired, completed,
                    terminal_receipt_digest="c" * 64,
                    output_digest="d" * 64)
    terminal = read_original_preparation(db, namespace, parent, "generation")
    assert terminal.state == "terminal"
    assert terminal.terminal_output_digest == "d" * 64
    with pytest.raises(NaturalReplyJobHold, match="acquired"):
        record_terminal(db, terminal, completed,
                        terminal_receipt_digest="c" * 64,
                        output_digest="d" * 64)
    db.execute(
        "UPDATE graph_natural_generation_preparations_v2 "
        "SET typed_request_digest=? WHERE original_operation_id=?",
        (frozen.model_request_digest, seal.original_operation_id),
    )
    with pytest.raises(NaturalReplyJobHold, match="invalid"):
        read_original_preparation(db, namespace, parent, "generation")
    db.rollback()


def test_review_preparation_binds_terminal_generation_output_and_shared_parent_budget():
    namespace, parent, generation, frozen, versions, queries, job = _case()
    db = sqlite3.connect(":memory:")
    jobs_schema(db)
    install_schema(db)
    db.execute("BEGIN")
    create_job(db, job, "create:generation", "1" * 64)
    save_original_preparation(
        db, stage="generation", namespace=namespace,
        parent_original_id=parent, seal=generation, frozen=frozen,
        read_versions=versions, query_epochs=queries, graph_epoch=2,
        access_epoch=3, deletion_epoch=4, job=job,
    )
    output = {
        "schema": "sylanne.d09.context_reply_output.v2",
        "body": "Hello.",
        "units": [{"start": 0, "end": 6, "kind": "rhetoric",
                   "basis_ids": ["basis:greeting"], "speech_act": "rhetoric",
                   "promise_grant_id": None, "slot_ids": []}],
    }
    review_frozen = freeze_natural_reply_review_v1(
        generation, output, frozen.input.plan.units, (), "policy:review",
        NaturalReviewInstallationV1("review-installation", "review-provider",
                                    "e" * 64, "review-model"),
    )
    saved_generation = read_original_preparation(db, namespace, parent, "generation")
    running = acquire_job(db, job.job_id, "worker", now_utc="2026-09-28T00:00:00Z",
                          lease_seconds=30)
    bind_original_call(
        db, saved_generation, running,
        _generation_call(namespace, generation, frozen, versions, queries),
    )
    acquired = read_original_preparation(db, namespace, parent, "generation")
    completed = transition_job(
        db, job.job_id, "worker", running.fence,
        target_phase="completed", result_ref="paid-result:generation",
    )
    # The production caller must obtain this exact digest from W09's paid
    # original generation terminal and check costs before this CAS.
    record_terminal(
        db, acquired, completed, terminal_receipt_digest="2" * 64,
        output_digest=review_frozen.generation_output_digest,
    )
    ids = natural_job_ids_v2(namespace, parent, "review")
    guard = natural_graph_guard_digest_v2(
        namespace, versions, queries, graph_epoch=2,
        access_epoch=3, deletion_epoch=4,
    )
    seal = NaturalReplyReviewOriginalSealV2(
        namespace=namespace, installation_id="review-installation",
        provider_config_digest="e" * 64, job_id=ids[0],
        original_operation_id=ids[1], acquire_operation_id=ids[2],
        call_id=ids[3],
        generation_original_operation_id=generation.original_operation_id,
        generation_call_id=generation.call_id,
        generation_frozen_input_digest=generation.frozen_input_digest,
        generation_output_digest=review_frozen.generation_output_digest,
        qualified_units_digest=generation.qualified_units_digest,
        review_frozen_input_digest=review_frozen.digest,
        model_request_digest=review_frozen.wire_digest,
        original_graph_guard_digest=guard,
        parent_budget_lease_id="budget:parent",
        reservation_operation_id=ids[4],
        review_policy_version="policy:review",
    )
    review_job = replace(
        job, job_id=ids[0], operation_id=ids[1],
        work_kind="natural_review",
    )
    create_job(db, review_job, "create:review", "3" * 64)
    saved = save_original_preparation(
        db, stage="review", namespace=namespace,
        parent_original_id=parent, seal=seal, frozen=review_frozen,
        read_versions=versions, query_epochs=queries, graph_epoch=2,
        access_epoch=3, deletion_epoch=4, job=review_job,
    )
    assert saved.frozen == review_frozen
    assert saved.seal.parent_budget_lease_id == generation.parent_budget_lease_id
    assert read_original_preparation(db, namespace, parent, "review") == saved
    db.execute(
        "UPDATE graph_natural_generation_preparations_v2 "
        "SET terminal_output_digest=? WHERE original_operation_id=?",
        ("0" * 64, generation.original_operation_id),
    )
    with pytest.raises(NaturalReplyJobHold):
        read_original_preparation(db, namespace, parent, "review")
    db.rollback()
