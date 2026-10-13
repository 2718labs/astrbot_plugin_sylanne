"""One transactional D11 original generation reservation for an adopted plan.

GraphCoordinator owns the Authority fence and commits the plan and job graph
writes together. This helper only issues the signed quote, budget reservation,
durable queued job, and frozen original call identity inside that transaction.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import json

from ..domains.d08.natural_plan import AdoptedNaturalPlanV2
from ..model_broker.natural_reply import (
    FrozenNaturalReplyRequestV2, TEMPLATE_VERSION,
)
from ..runtime_contracts import (
    NaturalReplyGenerationOriginalSealV2, NamespaceId, QueryEpoch,
    canonical_digest, canonical_serialize,
)
from ..graph_types import GraphVersion
from ..model_broker.natural_reply_history_v3 import FrozenNaturalReplyRequestV3, TEMPLATE_VERSION as V3_TEMPLATE_VERSION
from .natural_original_v3 import NaturalReplyGenerationOriginalSealV3
from .natural_original_v4 import NaturalReplyGenerationOriginalSealV4
from .natural_original_v6 import NaturalReplyGenerationOriginalSealV6
from ..model_broker.natural_reply_history_v6 import FrozenNaturalReplyRequestV6,TEMPLATE_VERSION as V6_TEMPLATE_VERSION
from ..model_broker.natural_reply_history_v7 import FrozenNaturalReplyRequestV7,TEMPLATE_VERSION as V7_TEMPLATE_VERSION
from .natural_original_v7 import NaturalReplyGenerationOriginalSealV7
from ..model_broker.natural_reply_history_v4 import (
    FrozenNaturalReplyRequestV4, TEMPLATE_VERSION as V4_TEMPLATE_VERSION,
    TEMPLATE_VERSION_V5, FROZEN_SCHEMA_V5,
)
from .budget import reserve_budget
from .d11_types import runtime_job_key
from .issuers import D02ResourceIssuer, D11BudgetJobIssuer, ResourceQuote
from .jobs import PersistentJob, create_job
from .natural_reply_job_v2 import (
    natural_graph_guard_digest_v2, natural_job_ids_v2,
    save_original_preparation,
)


class NaturalGenerationIssueHold(RuntimeError):
    """The installed paid generation job cannot be frozen safely."""


def install_attempt_schema(db) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS graph_natural_generation_attempts_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        original_operation_id TEXT NOT NULL,
        input_digest TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE,
        anchor_json TEXT NOT NULL, graph_revision INTEGER NOT NULL,
        graph_epoch INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','closed','committed')),
        PRIMARY KEY(bot,persona,original_operation_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_natural_generation_acquires_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        acquire_operation_id TEXT NOT NULL,
        request_digest TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE,
        anchor_json TEXT NOT NULL, graph_revision INTEGER NOT NULL,
        graph_epoch INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','committed')),
        PRIMARY KEY(bot,persona,acquire_operation_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_natural_generation_terminals_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        original_operation_id TEXT NOT NULL,
        request_digest TEXT NOT NULL, attempt_id TEXT NOT NULL UNIQUE,
        anchor_json TEXT NOT NULL, graph_revision INTEGER NOT NULL,
        graph_epoch INTEGER NOT NULL,
        terminal_receipt_digest TEXT NOT NULL,
        output_digest TEXT NOT NULL,
        output_receipt_json TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','committed','rejected')),
        PRIMARY KEY(bot,persona,original_operation_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_natural_generation_scopes_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        parent_original_id TEXT NOT NULL,
        original_seal_digest TEXT NOT NULL,
        proof_json TEXT NOT NULL,
        PRIMARY KEY(bot,persona,parent_original_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_natural_generation_output_reads_v2 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        original_operation_id TEXT NOT NULL,
        last_attempt INTEGER NOT NULL,
        PRIMARY KEY(bot,persona,original_operation_id))""")


def save_original_scoped_query_proof_v2(db, saved, proof) -> None:
    """Seal one immutable D03/D05/D06 predicate result beside the original job."""
    from .natural_reply_job_v2 import SavedNaturalPreparationV2
    from .natural_scoped_query_proof_v2 import (
        NaturalScopedQueryProofV2, assert_original_scoped_d06_projection_v2,
    )

    if (not db.in_transaction or type(saved) is not SavedNaturalPreparationV2
            or saved.stage != "generation"
            or type(proof) is not NaturalScopedQueryProofV2):
        raise NaturalGenerationIssueHold("original natural scope requires graph tx")
    assert_original_scoped_d06_projection_v2(proof, saved.frozen)
    identity = saved.seal.namespace.as_tuple + (saved.parent_original_id,)
    value = (canonical_digest(asdict(saved.seal)),
             canonical_serialize(asdict(proof)))
    row = db.execute(
        "SELECT original_seal_digest,proof_json FROM "
        "graph_natural_generation_scopes_v2 WHERE bot=? AND persona=? "
        "AND parent_original_id=?", identity,
    ).fetchone()
    if row is None:
        db.execute(
            "INSERT INTO graph_natural_generation_scopes_v2"
            "(bot,persona,parent_original_id,original_seal_digest,proof_json) "
            "VALUES(?,?,?,?,?)", identity + value,
        )
    elif row != value:
        raise NaturalGenerationIssueHold("original natural scope identity differs")


def read_original_scoped_query_proof_v2(db, saved):
    """Rehydrate the exact query proof bound to the immutable original seal."""
    from .natural_reply_job_v2 import SavedNaturalPreparationV2
    from .natural_scoped_query_proof_v2 import (
        assert_original_scoped_d06_projection_v2,
        natural_scoped_query_proof_from_wire_v2,
    )

    if (not db.in_transaction or type(saved) is not SavedNaturalPreparationV2
            or saved.stage != "generation"):
        raise NaturalGenerationIssueHold("natural scope read requires graph tx")
    from ..authority_service.current_authority_graph_read_v3 import (
        read_bound_authority_graph_attachment_v3,
        require_authority_json_column_v3)
    namespace = saved.seal.namespace
    key = (*namespace.as_tuple, saved.parent_original_id)
    columns = ("original_seal_digest", "proof_json")
    key_columns = ("bot", "persona", "parent_original_id")
    handled, row = read_bound_authority_graph_attachment_v3(
        db, table="graph_natural_generation_scopes_v2", columns=columns,
        key_columns=key_columns, key=key)
    if not handled:
        row = db.execute(
            "SELECT original_seal_digest,proof_json FROM "
            "graph_natural_generation_scopes_v2 WHERE bot=? AND persona=? "
            "AND parent_original_id=?", key,
        ).fetchone()
    if row is None or row[0] != canonical_digest(asdict(saved.seal)):
        raise NaturalGenerationIssueHold("original natural scope seal differs")
    if handled:
        original = require_authority_json_column_v3(
            db, table="graph_natural_generation_scopes_v2", columns=columns,
            key_columns=key_columns, key=key, column="proof_json")
        if original is None:
            raise NaturalGenerationIssueHold("original natural scope EOF is absent")
        proof = natural_scoped_query_proof_from_wire_v2(
            original.require_v3(original.owner))
        if not original.matches_v3(asdict(proof)):
            raise NaturalGenerationIssueHold("original natural scope bytes differ")
    else:
        proof = natural_scoped_query_proof_from_wire_v2(json.loads(row[1]))
        if canonical_serialize(asdict(proof)) != row[1]:
            raise NaturalGenerationIssueHold("original natural scope bytes differ")
    assert_original_scoped_d06_projection_v2(proof, saved.frozen)
    return proof


def assert_natural_reply_identity_unused_v2(
    db, namespace: NamespaceId, c02_operation_id: str, source_ref: str,
) -> None:
    """One C02/source cannot prepare both old and natural paid replies."""
    from .context_reply_job_v2 import (
        context_reply_job_ids_v2, legacy_reply_identity_exists_v1,
    )

    if legacy_reply_identity_exists_v1(
            db, namespace, c02_operation_id, source_ref):
        raise NaturalGenerationIssueHold("source_reply.v1 identity already exists")
    original_id = context_reply_job_ids_v2(
        namespace, c02_operation_id, source_ref)[1]
    identity = namespace.as_tuple + (c02_operation_id, source_ref)
    for query, args in (
        ("SELECT 1 FROM graph_context_reply_preparations_v2 "
         "WHERE bot=? AND persona=? AND c02_operation_id=? AND source_ref=?",
         identity),
        ("SELECT 1 FROM graph_context_reply_attempts_v2 "
         "WHERE bot=? AND persona=? AND original_operation_id=?",
         namespace.as_tuple + (original_id,)),
        ("SELECT 1 FROM graph_context_reply_call_bindings_v2 "
         "WHERE bot=? AND persona=? AND original_operation_id=?",
         namespace.as_tuple + (original_id,)),
        ("SELECT 1 FROM graph_natural_generation_preparations_v2 "
         "WHERE bot=? AND persona=? AND parent_original_id=?",
         namespace.as_tuple + (c02_operation_id,)),
    ):
        if db.execute(query, args).fetchone() is not None:
            raise NaturalGenerationIssueHold("reply paid identity already exists")


def issue_original_natural_generation_in_transaction_v2(
    db, *, namespace: NamespaceId, plan: AdoptedNaturalPlanV2,
    frozen: FrozenNaturalReplyRequestV2,
    read_versions: tuple[GraphVersion, ...],
    query_epochs: tuple[QueryEpoch, ...], graph_epoch: int,
    access_epoch: int, deletion_epoch: int, installed_bundle,
    d02_issuer: D02ResourceIssuer, d11_issuer: D11BudgetJobIssuer,
    now_utc: float, history_decision=None, history_wire_port=None,
) -> tuple[PersistentJob, ResourceQuote, str, NaturalReplyGenerationOriginalSealV2]:
    if not db.in_transaction:
        raise NaturalGenerationIssueHold("natural generation requires graph write tx")
    from .context_reply_job_v2 import install_schema as install_context_schema
    from .reply_model_job import install_schema as install_legacy_schema
    from .natural_reply_job_v2 import install_schema as install_natural_schema
    install_legacy_schema(db)
    install_context_schema(db)
    install_natural_schema(db)
    assert_natural_reply_identity_unused_v2(
        db, namespace, plan.c02_operation_id, plan.source_ref.ref)
    policy = installed_bundle.installation_policy
    workflows = installed_bundle.model_workflows
    workflow = getattr(workflows, "natural_generation", None)
    if workflow is None:
        raise NaturalGenerationIssueHold("installed natural generation unavailable")
    from .natural_reply_budget_v3 import resolve_natural_reply_budget_for_new_admission_v3
    lease, grant = resolve_natural_reply_budget_for_new_admission_v3(db, namespace=namespace,
        c02_operation_id=plan.c02_operation_id, source_ref=plan.source_ref.ref,
        issuer=d11_issuer, installed_bundle=installed_bundle, now_utc=now_utc)
    ceiling = dict(workflow.quote_ceiling)
    ids = natural_job_ids_v2(namespace, plan.c02_operation_id, "generation")
    if (policy.namespace != namespace
            or grant.lease_id != plan.parent_budget_lease_id
            or grant.version != plan.budget_grant_version
            or canonical_digest(grant) != plan.budget_grant_digest
            or tuple(sorted(ceiling.items())) != plan.generation_ceiling
            or workflow.work_kind != "natural_generation"
            or workflow.purpose != "proposal"
            or workflow.template_version != (
                V7_TEMPLATE_VERSION if type(frozen) is FrozenNaturalReplyRequestV7 else
                V6_TEMPLATE_VERSION if type(frozen) is FrozenNaturalReplyRequestV6 else
                TEMPLATE_VERSION_V5 if type(frozen) is FrozenNaturalReplyRequestV4 and frozen.schema == FROZEN_SCHEMA_V5 else
                V4_TEMPLATE_VERSION if type(frozen) is FrozenNaturalReplyRequestV4 else
                V3_TEMPLATE_VERSION if type(frozen) is FrozenNaturalReplyRequestV3 else TEMPLATE_VERSION)
            or frozen.input.plan.namespace != namespace
            or frozen.input.question.ref != plan.source_ref
            or frozen.input.plan.plan_ref.ref != plan_ref(namespace, plan)
            or frozen.input.plan.final_activity_id != plan.final_activity_id
            or frozen.input.plan.final_operation_id != plan.final_operation_id
            or frozen.input.plan.final_effect_id != plan.final_effect_id
            or frozen.input.plan.scene_id != plan.scene_id
            or frozen.input.plan.audience_id != plan.audience_id
            or frozen.input.plan.scene_ref != plan.scene_ref
            or frozen.input.plan.audience_ref != plan.audience_ref
            or frozen.input.plan.required_slots != plan.required_slots
            or frozen.input.plan.allowed_speech_acts != plan.allowed_speech_acts
            or frozen.input.plan.promise_grants != plan.promise_grants
            or frozen.input.plan.audience_id not in workflow.audiences
            or frozen.input.plan.valid_until_utc != plan.valid_until_utc
            or frozen.qualified_units_digest != plan.qualified_units_digest
            or frozen.installation.installation_id != policy.installation_id
            or frozen.installation.provider_id != workflow.provider_id
            or frozen.installation.model_id != workflow.model_id
            or frozen.installation.provider_config_digest
               != workflow.provider_config_digest
            or frozen.installation.max_output_tokens != workflow.max_output_tokens
            or frozen.input.expires_at_utc <= now_utc + workflow.timeout_seconds
            or "natural_generation" not in grant.allowed_work_kinds
            or grant.valid_until_utc <= now_utc or lease.state != "active"
            or any(amount > grant.max_ceiling.get(name, 0)
                   or amount > lease.available(name)
                   for name, amount in ceiling.items())):
        raise NaturalGenerationIssueHold("current natural generation scope or budget differs")
    job_id, original_id, acquire_id, call_id, reservation_id = ids
    digest = canonical_digest({
        "schema": "sylanne.d09.natural-generation-identity.v2",
        "namespace": namespace, "c02_operation_id": plan.c02_operation_id,
        "source_ref": plan.source_ref.ref,
    })[:48]
    activity_id = "natural-generation-activity:" + digest
    quote_id = "natural-generation-quote:" + digest
    deadline = frozen.input.expires_at_utc
    snapshot_ref = "natural-generation-snapshot:" + canonical_digest({
        "frozen_input_digest": frozen.frozen_input_digest,
        "read_versions": [(row.key.token, row.revision) for row in read_versions],
    })[:48]
    quote = ResourceQuote(
        quote_id, 1, *namespace.as_tuple, activity_id, reservation_id, None,
        grant.lease_id, "natural_generation", snapshot_ref, deadline,
        workflow.provider_config_ref,
        runtime_job_key(*namespace.as_tuple, activity_id, job_id).token,
        (), (), ceiling, None, deadline,
    )
    reservation_digest = canonical_digest({
        "schema": "sylanne.d09.natural-generation-reservation.v2",
        "seal_original_operation_id": original_id, "quote": asdict(quote),
        "plan_id": plan.plan_id,
    })
    history_status = ({"history_selection": "raw", "token_evidence": "token_evidence_unverified",
                       "activation": "activation_not_attempted"}
                      if type(frozen) in (FrozenNaturalReplyRequestV3, FrozenNaturalReplyRequestV4,FrozenNaturalReplyRequestV6,FrozenNaturalReplyRequestV7) else {})
    if history_decision is not None:
        from .installed_d13_natural_frame_v4 import NaturalHistoryDecisionV4
        from .installed_d13_natural_frame_v6 import NaturalHistoryDecisionV6
        from .installed_d13_natural_frame_v7 import NaturalHistoryDecisionV7
        if (type(history_decision) is not (NaturalHistoryDecisionV7 if type(frozen) is FrozenNaturalReplyRequestV7 else NaturalHistoryDecisionV6 if type(frozen) is FrozenNaturalReplyRequestV6 else NaturalHistoryDecisionV4)
                or history_decision.wire_digest != frozen.model_request_digest
                or (history_decision.selected == "compressed") != bool(frozen.input.stable_history)):
            raise NaturalGenerationIssueHold("installed D13 decision differs from actual frozen wire")
        history_status = {"history_selection": history_decision.selected,
            "token_evidence": history_decision.token_evidence, "activation": history_decision.activation,
            "history_policy_digest": history_decision.policy_digest, "history_proof_digest": history_decision.proof_digest}
    job = PersistentJob(
        job_id, original_id, activity_id, None, *namespace.as_tuple,
        snapshot_ref, "queued", "natural_generation", {
            "c02_operation_id": plan.c02_operation_id,
            "source_ref": plan.source_ref.ref,
            "plan_id": plan.plan_id,
            "frozen_input_digest": frozen.frozen_input_digest,
            **history_status,
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
    seal_class = (NaturalReplyGenerationOriginalSealV7 if type(frozen) is FrozenNaturalReplyRequestV7 else NaturalReplyGenerationOriginalSealV6 if type(frozen) is FrozenNaturalReplyRequestV6 else NaturalReplyGenerationOriginalSealV4 if type(frozen) is FrozenNaturalReplyRequestV4 else NaturalReplyGenerationOriginalSealV3 if type(frozen) is FrozenNaturalReplyRequestV3 else NaturalReplyGenerationOriginalSealV2)
    seal_version = ({"schema": "sylanne.d09.natural_generation_seal.v5",
                     "template_version": TEMPLATE_VERSION_V5}
                    if type(frozen) is FrozenNaturalReplyRequestV4 and frozen.schema == FROZEN_SCHEMA_V5 else {})
    seal = seal_class(
        namespace=namespace, c02_operation_id=plan.c02_operation_id,
        source_ref=plan.source_ref.ref, installation_id=policy.installation_id,
        provider_config_digest=workflow.provider_config_digest,
        job_id=job_id, original_operation_id=original_id,
        acquire_operation_id=acquire_id, call_id=call_id,
        frozen_input_digest=frozen.frozen_input_digest,
        qualified_units_digest=frozen.qualified_units_digest,
        model_request_digest=frozen.model_request_digest,
        original_graph_guard_digest=guard,
        parent_budget_lease_id=grant.lease_id,
        reservation_operation_id=reservation_id,
        **seal_version,
    )
    d02_issuer.issue_quote(db, quote)
    reserve_budget(db, grant.lease_id, reservation_id, reservation_digest, ceiling)
    if history_decision is not None and history_decision.token_evidence != "token_evidence_unverified":
        from .installed_d13_wire_evidence_v1 import (
            D13ForegroundBudgetBindingV1, validate_reserved_d13_natural_selection_v1)
        from ..authority_service.d13_wire_evidence_v6 import validate_reserved_d13_natural_selection_v6
        if type(frozen) is FrozenNaturalReplyRequestV7:
            from ..authority_service.d13_wire_evidence_v7 import validate_reserved_d13_natural_selection_v7
            validator=validate_reserved_d13_natural_selection_v7
        else:
            validator = validate_reserved_d13_natural_selection_v6 if type(frozen) is FrozenNaturalReplyRequestV6 else validate_reserved_d13_natural_selection_v1
        admitted = validator(history_wire_port,
            selected=frozen, decision=history_decision,
            binding=D13ForegroundBudgetBindingV1(quote_id, 1, grant.lease_id, reservation_id, reservation_digest),
            read_versions=read_versions, now_utc=now_utc)
        from dataclasses import replace
        job = replace(job, continuation={**job.continuation,
            "history_preparation_proof_digest": history_decision.proof_digest,
            "history_proof_digest": admitted.proof_digest,
            "history_budget_state": admitted.budget_state})
    create_job(db, job, "create:" + original_id, reservation_digest)
    save_original_preparation(
        db, stage="generation", namespace=namespace,
        parent_original_id=plan.c02_operation_id, seal=seal, frozen=frozen,
        read_versions=read_versions, query_epochs=query_epochs,
        graph_epoch=graph_epoch, access_epoch=access_epoch,
        deletion_epoch=deletion_epoch, job=job,
    )
    return job, quote, reservation_digest, seal


def plan_ref(namespace: NamespaceId, plan: AdoptedNaturalPlanV2) -> str:
    from ..domains.d08.natural_plan import natural_plan_key_v2
    return natural_plan_key_v2(namespace, plan.final_activity_id, plan.plan_id).token
