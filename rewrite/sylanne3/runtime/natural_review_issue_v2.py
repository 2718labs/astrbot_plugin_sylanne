"""Reserve the second paid natural job only after a trusted generation result.

GraphCoordinator supplies the current Authority write fence and the frozen
review request. This module only writes the original D02/D11 identities in
that caller-owned SQLite transaction.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import json

from ..graph_types import GraphVersion
from ..domains.d08.natural_plan import AdoptedNaturalPlanV2
from ..model_broker.natural_review import (
    FrozenNaturalReplyReviewV1, REVIEW_TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION_V2,
    INPUT_SCHEMA_V2,
)
from ..runtime_contracts import (
    NaturalReplyGenerationOriginalSealV2, NaturalReplyReviewOriginalSealV2, NamespaceId, QueryEpoch,
    canonical_digest,
)
from .natural_original_v3 import NaturalReplyGenerationOriginalSealV3, NaturalReplyReviewOriginalSealV3
from .natural_original_v4 import NaturalReplyGenerationOriginalSealV4, NaturalReplyReviewOriginalSealV4
from .natural_original_v6 import NaturalReplyGenerationOriginalSealV6,NaturalReplyReviewOriginalSealV6
from .natural_original_v7 import NaturalReplyGenerationOriginalSealV7, NaturalReplyReviewOriginalSealV7
from .budget import reserve_budget
from .d11_types import runtime_job_key
from .issuers import D02ResourceIssuer, D11BudgetJobIssuer, ResourceQuote
from .jobs import PersistentJob, create_job
from .natural_reply_job_v2 import (
    SavedNaturalPreparationV2, natural_graph_guard_digest_v2,
    natural_job_ids_v2, save_original_preparation,
)


class NaturalReviewIssueHold(RuntimeError):
    """The independent review paid call cannot be frozen safely."""


def install_review_attempt_schema(db) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS graph_natural_review_attempts_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        parent_original_id TEXT NOT NULL,
        input_digest TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE,
        anchor_json TEXT NOT NULL, graph_revision INTEGER NOT NULL,
        graph_epoch INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','closed','committed')),
        PRIMARY KEY(bot,persona,parent_original_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_natural_review_content_reads_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        parent_original_id TEXT NOT NULL,
        last_attempt INTEGER NOT NULL,
        PRIMARY KEY(bot,persona,parent_original_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_natural_review_acquires_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        acquire_operation_id TEXT NOT NULL,
        request_digest TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE,
        anchor_json TEXT NOT NULL, graph_revision INTEGER NOT NULL,
        graph_epoch INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','committed')),
        PRIMARY KEY(bot,persona,acquire_operation_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_natural_review_terminals_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        original_operation_id TEXT NOT NULL,
        request_digest TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE,
        anchor_json TEXT NOT NULL, graph_revision INTEGER NOT NULL,
        graph_epoch INTEGER NOT NULL,
        terminal_receipt_digest TEXT NOT NULL,
        output_digest TEXT NOT NULL, output_receipt_json TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','committed','rejected')),
        PRIMARY KEY(bot,persona,original_operation_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_natural_review_output_reads_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        original_operation_id TEXT NOT NULL,
        last_attempt INTEGER NOT NULL,
        PRIMARY KEY(bot,persona,original_operation_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_natural_paid_review_reads_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        original_operation_id TEXT NOT NULL,
        last_attempt INTEGER NOT NULL,
        PRIMARY KEY(bot,persona,original_operation_id))""")


def verify_current_generation_content_for_review_v2(
    db, *, generation: SavedNaturalPreparationV2, content,
    scoped_proof, adopted_plan, now_utc: float,
) -> dict[str, object]:
    """Bind Authority's paid text to the current graph before freezing review."""
    from ..authority_service.v2_natural_generation_content_contract import (
        NaturalGenerationCurrentContentV2,
        natural_generation_current_scope_digest_v2,
    )
    from ..model_broker.natural_reply_history_v3 import parse_natural_reply_output_current_v1 as parse_natural_reply_output_v2
    from .natural_reply_job_v2 import read_original_call_binding
    from .natural_scoped_query_proof_v2 import (
        assert_natural_scoped_query_current_v2,
    )

    if (not db.in_transaction or type(content) is not NaturalGenerationCurrentContentV2
            or generation.stage != "generation" or generation.state != "terminal"
            or content.request.original_operation_id
               != generation.seal.original_operation_id
            or content.request.output_digest != generation.terminal_output_digest
            or content.request.original_seal_digest
               != canonical_digest(asdict(generation.seal))
            or content.request.namespace != generation.seal.namespace
            or content.request.c02_operation_id != generation.parent_original_id
            or content.request.source_ref != generation.seal.source_ref
            or content.request.scene_id != generation.frozen.input.plan.scene_id
            or content.request.audience_id != generation.frozen.input.plan.audience_id
            or now_utc >= content.expires_at_utc):
        raise NaturalReviewIssueHold("trusted generation content identity differs")
    namespace = generation.seal.namespace
    binding = read_original_call_binding(db, generation)
    if (binding is None
            or content.request.typed_model_request_digest != binding.request.digest
            or content.request.terminal_receipt_digest
               != generation.terminal_receipt_digest):
        raise NaturalReviewIssueHold("generation paid call binding differs")
    from ..domains.d08.natural_plan import decode_natural_plan_v2
    import json
    plan_ref = generation.frozen.input.plan.plan_ref
    plan_row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (plan_ref.ref,),
    ).fetchone()
    if (plan_row is None or (plan_row[0], plan_row[2]) !=
            (plan_ref.version, 1)
            or decode_natural_plan_v2(json.loads(plan_row[1])) != adopted_plan):
        raise NaturalReviewIssueHold("generation adopted plan changed")
    epoch = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    barriers = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if (epoch != (content.current_graph_epoch,) or barriers != (
            content.current_access_epoch, content.current_delete_epoch)):
        raise NaturalReviewIssueHold("generation content graph epoch changed")
    assert_natural_scoped_query_current_v2(db, scoped_proof, now_utc=now_utc)
    for version in content.current_read_versions:
        row = db.execute(
            "SELECT revision,valid FROM graph_atoms WHERE token=?",
            (version.key.token,),
        ).fetchone()
        if ((version.revision == 0 and row is not None)
                or (version.revision > 0 and row != (version.revision, 1))):
            raise NaturalReviewIssueHold("generation content graph read changed")
    digest = natural_generation_current_scope_digest_v2(
        original_seal_digest=canonical_digest(asdict(generation.seal)),
        scoped_proof_digest=scoped_proof.semantic_digest,
        adopted_plan_digest=canonical_digest(asdict(adopted_plan)),
        read_versions=content.current_read_versions,
        graph_epoch=content.current_graph_epoch,
        access_epoch=content.current_access_epoch,
        delete_epoch=content.current_delete_epoch,
        scene_id=generation.frozen.input.plan.scene_id,
        audience_id=generation.frozen.input.plan.audience_id,
    )
    if digest != content.current_scope_digest:
        raise NaturalReviewIssueHold("generation content current scope differs")
    parsed = parse_natural_reply_output_v2(content.text, generation.frozen)
    if (parsed.status != "untrusted_content_candidate"
            or parsed.output_digest != content.output_digest
            or parsed.output_digest != generation.terminal_output_digest):
        raise NaturalReviewIssueHold("generation output digest differs")
    return parsed.d09_payload()


def issue_original_natural_review_in_transaction_v2(
    db, *, generation: SavedNaturalPreparationV2,
    adopted_plan: AdoptedNaturalPlanV2,
    frozen: FrozenNaturalReplyReviewV1,
    read_versions: tuple[GraphVersion, ...],
    query_epochs: tuple[QueryEpoch, ...], graph_epoch: int,
    access_epoch: int, deletion_epoch: int,
    installed_bundle, d02_issuer: D02ResourceIssuer,
    d11_issuer: D11BudgetJobIssuer, now_utc: float,
) -> tuple[PersistentJob, ResourceQuote, str, NaturalReplyReviewOriginalSealV2]:
    if not db.in_transaction:
        raise NaturalReviewIssueHold("natural review requires graph write tx")
    seal_class = {
        NaturalReplyGenerationOriginalSealV2: NaturalReplyReviewOriginalSealV2,
        NaturalReplyGenerationOriginalSealV3: NaturalReplyReviewOriginalSealV3,
        NaturalReplyGenerationOriginalSealV4: NaturalReplyReviewOriginalSealV4,
        NaturalReplyGenerationOriginalSealV6: NaturalReplyReviewOriginalSealV6,
        NaturalReplyGenerationOriginalSealV7: NaturalReplyReviewOriginalSealV7,
    }.get(type(generation.seal))
    if seal_class is None:
        raise NaturalReviewIssueHold("unknown natural generation original version")
    namespace: NamespaceId = generation.seal.namespace
    parent = generation.parent_original_id
    policy = installed_bundle.installation_policy
    workflow = installed_bundle.model_workflows.natural_review
    if workflow is None or generation.stage != "generation":
        raise NaturalReviewIssueHold("installed independent review is absent")
    from .natural_reply_budget_v3 import resolve_natural_reply_budget_for_original_admission_v3
    lease, grant = resolve_natural_reply_budget_for_original_admission_v3(db, namespace=namespace,
        c02_operation_id=parent, source_ref=generation.seal.source_ref, issuer=d11_issuer,
        installed_bundle=installed_bundle, now_utc=now_utc, original_preparation=generation)
    ceiling = dict(workflow.quote_ceiling)
    plan = generation.frozen.input.plan
    if (generation.state != "terminal"
            or generation.terminal_output_digest != frozen.generation_output_digest
            or generation.seal.frozen_input_digest
               != frozen.generation_frozen_input_digest
            or generation.seal.qualified_units_digest
               != frozen.qualified_units_digest
            or policy.namespace != namespace
            or grant.lease_id != generation.seal.parent_budget_lease_id
            or tuple(sorted(ceiling.items())) != adopted_plan.review_ceiling
            or workflow.work_kind != "natural_review"
            or workflow.purpose != "proposal"
            or workflow.template_version != (
                REVIEW_TEMPLATE_VERSION_V2 if json.loads(frozen.canonical_input).get("schema") == INPUT_SCHEMA_V2
                else REVIEW_TEMPLATE_VERSION)
            or plan.audience_id not in workflow.audiences
            or frozen.installation.installation_id != policy.installation_id
            or frozen.installation.provider_id != workflow.provider_id
            or frozen.installation.model_id != workflow.model_id
            or frozen.installation.provider_config_digest
               != workflow.provider_config_digest
            or frozen.installation.max_output_tokens != workflow.max_output_tokens
            or plan.valid_until_utc <= now_utc + workflow.timeout_seconds
            or "natural_review" not in grant.allowed_work_kinds
            or grant.valid_until_utc <= now_utc or lease.state != "active"
            or any(amount > grant.max_ceiling.get(name, 0)
                   or amount > lease.available(name)
                   for name, amount in ceiling.items())):
        raise NaturalReviewIssueHold("natural review scope or parent budget changed")
    ids = natural_job_ids_v2(namespace, parent, "review")
    job_id, original_id, acquire_id, call_id, reservation_id = ids
    identity = canonical_digest({
        "schema": "sylanne.d09.natural-review-identity.v2",
        "namespace": namespace, "parent_original_id": parent,
        "generation_output_digest": frozen.generation_output_digest,
    })[:48]
    activity_id = "natural-review-activity:" + identity
    quote_id = "natural-review-quote:" + identity
    deadline = plan.valid_until_utc
    snapshot_ref = "natural-review-snapshot:" + canonical_digest({
        "frozen_input_digest": frozen.digest,
        "read_versions": [(row.key.token, row.revision)
                          for row in read_versions],
    })[:48]
    quote = ResourceQuote(
        quote_id, 1, *namespace.as_tuple, activity_id, reservation_id, None,
        grant.lease_id, "natural_review", snapshot_ref, deadline,
        workflow.provider_config_ref,
        runtime_job_key(*namespace.as_tuple, activity_id, job_id).token,
        (), (), ceiling, None, deadline,
    )
    reservation_digest = canonical_digest({
        "schema": "sylanne.d09.natural-review-reservation.v2",
        "seal_original_operation_id": original_id,
        "generation_original_operation_id": generation.seal.original_operation_id,
        "quote": asdict(quote), "frozen_review_digest": frozen.digest,
    })
    job = PersistentJob(
        job_id, original_id, activity_id, None, *namespace.as_tuple,
        snapshot_ref, "queued", "natural_review", {
            "c02_operation_id": parent,
            "generation_original_operation_id":
                generation.seal.original_operation_id,
            "generation_output_digest": frozen.generation_output_digest,
            "frozen_review_digest": frozen.digest,
        }, None,
        datetime.fromtimestamp(deadline, timezone.utc).isoformat().replace(
            "+00:00", "Z"),
        grant.lease_id, workflow.provider_config_ref,
        {"resource_quote": f"{quote_id}:1"}, None, None, 0, 0, {}, None,
    )
    guard = natural_graph_guard_digest_v2(
        namespace, read_versions, query_epochs, graph_epoch=graph_epoch,
        access_epoch=access_epoch, deletion_epoch=deletion_epoch,
    )
    semantic_batch = generation.seal.schema in {"sylanne.d09.natural_generation_seal.v5", "sylanne.d09.natural_generation_seal.v6", "sylanne.d09.natural_generation_seal.v7"}
    if semantic_batch != (json.loads(frozen.canonical_input).get("schema") == INPUT_SCHEMA_V2):
        raise NaturalReviewIssueHold("generation and review semantic versions differ")
    seal = seal_class(
        namespace=namespace, installation_id=policy.installation_id,
        provider_config_digest=workflow.provider_config_digest,
        job_id=job_id, original_operation_id=original_id,
        acquire_operation_id=acquire_id, call_id=call_id,
        generation_original_operation_id=generation.seal.original_operation_id,
        generation_call_id=generation.seal.call_id,
        generation_frozen_input_digest=
            generation.seal.frozen_input_digest,
        generation_output_digest=frozen.generation_output_digest,
        qualified_units_digest=frozen.qualified_units_digest,
        review_frozen_input_digest=frozen.digest,
        model_request_digest=frozen.wire_digest,
        original_graph_guard_digest=guard,
        parent_budget_lease_id=grant.lease_id,
        reservation_operation_id=reservation_id,
        review_policy_version=frozen.review_policy_version,
        **({"schema": generation.seal.schema.replace("natural_generation_seal", "natural_review_seal"),
            "template_version": REVIEW_TEMPLATE_VERSION_V2} if semantic_batch else {}),
    )
    d02_issuer.issue_quote(db, quote)
    reserve_budget(db, grant.lease_id, reservation_id,
                   reservation_digest, ceiling)
    create_job(db, job, "create:" + original_id, reservation_digest)
    save_original_preparation(
        db, stage="review", namespace=namespace,
        parent_original_id=parent, seal=seal, frozen=frozen,
        read_versions=read_versions, query_epochs=query_epochs,
        graph_epoch=graph_epoch, access_epoch=access_epoch,
        deletion_epoch=deletion_epoch, job=job,
    )
    return job, quote, reservation_digest, seal
