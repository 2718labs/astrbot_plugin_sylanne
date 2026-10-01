"""A sealed natural call identity is readable, but never grants model egress."""

from dataclasses import replace
import sqlite3

from rewrite.tests.alpha1.runtime.test_natural_reply_job_v2 import (
    _case, _generation_call,
)

from sylanne3.authority_service.natural_original_binding_verifier import (
    PinnedNaturalOriginalCallIdentityVerifierV2,
)
from sylanne3.host.authority_profile import (
    AdminModelWorkflowV2, installed_model_config_ref,
)
from sylanne3.runtime.jobs import (
    acquire_job, create_job, install_schema as jobs_schema,
)
from sylanne3.runtime.natural_reply_job_v2 import (
    bind_original_call, install_schema, save_original_preparation,
)
from sylanne3.runtime_contracts import NATURAL_REPLY_GENERATION_WORKFLOW_V2


def test_original_typed_binding_reads_only_from_pinned_installation(tmp_path):
    namespace, parent, seal, frozen, versions, queries, job = _case()
    path = tmp_path / "graph.sqlite3"
    config_ref = installed_model_config_ref("provider", "model", "a" * 64)
    workflow = AdminModelWorkflowV2(
        "natural_generation", "provider", "model", config_ref,
        "a" * 64, "proposal", ("audience:private",), "private",
        NATURAL_REPLY_GENERATION_WORKFLOW_V2, ("text",), 10.0, 256,
        {"output_tokens": 256},
    )
    with sqlite3.connect(path) as db:
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
        running = acquire_job(
            db, job.job_id, "worker", now_utc="2026-09-28T00:00:00Z",
            lease_seconds=30)
        call = _generation_call(namespace, seal, frozen, versions, queries)
        call = replace(call, envelope=replace(
            call.envelope, authority=replace(
                call.envelope.authority, provider_policy_ref=config_ref)))
        bind_original_call(db, saved, running, call)
        db.commit()

    verifier = PinnedNaturalOriginalCallIdentityVerifierV2(
        path, installation_id="installation", generation=workflow,
        review=None,
    )
    read = verifier.read(namespace, parent, "generation")
    assert read is not None
    assert read.request == call
    assert read.typed_request_digest == call.digest
    assert read.typed_request_digest != seal.model_request_digest
    assert read.status == "original_call_binding_only_hold"
    assert verifier.read(namespace, parent, "review") is None
    wrong_installation = PinnedNaturalOriginalCallIdentityVerifierV2(
        path, installation_id="other", generation=workflow, review=None)
    assert wrong_installation.read(namespace, parent, "generation") is None
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE graph_natural_generation_preparations_v2 "
            "SET typed_request_digest=? WHERE original_operation_id=?",
            ("0" * 64, seal.original_operation_id),
        )
    assert verifier.read(namespace, parent, "generation") is None
