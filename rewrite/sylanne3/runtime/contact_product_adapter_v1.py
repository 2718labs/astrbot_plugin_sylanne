"""Closed contact production stages for the actual common W01 witness."""
from dataclasses import dataclass, replace, asdict
import json
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d08.execution import GoalExecutionProvider
from ..graph_types import AtomKey, owner_grant_key
from ..runtime_contracts import canonical_digest, canonical_serialize
from .d01_production_operations_v1 import production_read_plan_v1, raw_head_value_v1, MissingProductionOriginalV1, waiting_stage_v1
from .contact_plan_adoption_v1 import (AdoptCurrentContactExpressionPlanRequestV1, ContactPlanStageV1,
    prepare_contact_plan_in_transaction_v1, record_contact_plan_after_cas_v1)
from .contact_model_job_v1 import prepare_contact_model_in_transaction_v1, record_contact_preparation_after_cas_v1

CONTACT_CURRENT_TYPES = ("d03.account_binding", "d03.entity_anchor", "d10.contact_policy.v1",
    "d10.proactive_opportunity.v1", "d10.contact_claim.v1", "d10.contact_claim.v2", "d05.boundary_rule")


@dataclass(frozen=True, slots=True)
class PrepareCurrentContactModelRequestV1:
    contact_id: str
    phase: str

    def __post_init__(self):
        if not self.contact_id.startswith("contact:") or self.phase not in {"contact_generation", "contact_review"}:
            raise ValueError("contact model request requires its stable adopted contact and fixed phase")


@dataclass(frozen=True, slots=True)
class ContactModelStageV1:
    stage: object
    prepared: object
    frozen: object
    job: object
    frame: object


def read_plan_contact_expression_v1(db, *, namespace, activity_id, operation_kind, request):
    from ..domains.d08.contact_plan_v1 import contact_ids_v1
    from .contact_route_binding_v1 import contact_route_read_inputs_v1
    if type(request) is not AdoptCurrentContactExpressionPlanRequestV1:
        raise TypeError("contact plan locator request required")
    keys = [owner_grant_key(*namespace.as_tuple)]
    keys.extend(AtomKey.from_token(ref) for ref in (request.opportunity_ref, request.contact_policy_ref, request.target_route_ref))
    route_keys, route_sources = contact_route_read_inputs_v1(db, namespace, request.target_route_ref)
    keys.extend(route_keys)
    roots, originals = list(route_sources), []
    for (wire,) in db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d05.boundary_rule' AND valid=1", namespace.as_tuple):
        roots.extend(json.loads(wire)["source_refs"])
    opportunity = raw_head_value_v1(db, namespace, AtomKey.from_token(request.opportunity_ref))
    if opportunity is not None:
        roots.append(opportunity["source_ref"])
        originals.append(opportunity["source_ref"])
        ids = contact_ids_v1(namespace, opportunity["source_ref"], opportunity["subject_ref"], "private_text")
        from ..graph_types import Owner
        keys.append(AtomKey(Owner("activity", *namespace.as_tuple, ids["activity"]), "d08.contact_expression_plan.v1", ids["plan"]))
    return production_read_plan_v1(CONTACT_CURRENT_TYPES, keys, roots, originals)


def stage_adopt_current_contact_expression_plan_in_transaction_v1(db, *, frame, request, installed_readers):
    graph = installed_readers.role_clock_reader.graph
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None:
        raise MissingProductionOriginalV1("actual_installed_contact_bundle")
    try:
        candidate = prepare_contact_plan_in_transaction_v1(db, frame=frame, request=request,
            installed_readers=installed_readers, installed_bundle=assembly.admin_bundle, issuer=installed_readers.issuer)
        if frame.envelope.identity.activity_id != candidate.plan.activity_id:
            raise ValueError("contact plan Owner command must use its actual stable cause activity")
        provider = GoalExecutionProvider()
        primary = stage_result_v1(frame, "d08", "adopt_contact_expression_plan", request, writes=(candidate.write,),
            provenance={"contact_plan": plain_v1(asdict(candidate.plan)), "expression": plain_v1(candidate.expression),
                "owner_policy_original": candidate.plan.policy_original_ref,
                "owner_policy_digest": candidate.plan.policy_original_digest},
            proposal_schema="d08.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
        result = replace(candidate, stage=primary)
        verify_contact_plan_stage_v1(result)
        provider.validate(primary.proposals[0], frame.snapshot)
        return result
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d08", "adopt_contact_expression_plan", request, missing)


def verify_contact_plan_stage_v1(staged):
    if type(staged) is not ContactPlanStageV1 or staged.stage is None:
        raise TypeError("closed actual contact plan stage required")
    stage = staged.stage
    payload = json.loads(stage.original_payload_json)
    if (stage.domain != "d08" or stage.operation_kind != "adopt_contact_expression_plan" or stage.coverage != "complete"
            or len(stage.proposals) != 1 or stage.proposals[0].typed_writes != (staged.write,)
            or stage.jobs or stage.outbox or payload["provenance"]["contact_plan"] != plain_v1(asdict(staged.plan))
            or payload["provenance"]["expression"] != plain_v1(staged.expression)
            or canonical_digest(staged.expression.units) != staged.plan.qualified_units_digest):
        raise ValueError("contact plan stage changed its fixed full typed expression proof")
    return staged


def stage_prepare_current_contact_model_in_transaction_v1(db, *, frame, request, installed_readers):
    from ..host.installed_contact_build_v1 import read_installed_contact_build_v1
    graph = installed_readers.role_clock_reader.graph
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if type(request) is not PrepareCurrentContactModelRequestV1 or assembly is None:
        raise MissingProductionOriginalV1("actual_installed_contact_model_preparation")
    build = read_installed_contact_build_v1(assembly.package_root, assembly.installation_policy.manifest_digest)
    prepared, frozen, job, writes = prepare_contact_model_in_transaction_v1(db, frame=frame,
        contact_id=request.contact_id, phase=request.phase, installed_bundle=assembly.admin_bundle,
        issuer=installed_readers.issuer, resource_issuer=graph._GraphCoordinator__d02_issuer, algorithm_build_digest=build)
    if not writes:
        raise MissingProductionOriginalV1("already_prepared_contact_exact_replay")
    from .d11_types import D11RuntimeProvider
    provider = D11RuntimeProvider()
    descriptor = provider.descriptor
    primary = stage_result_v1(frame, "d11", "prepare_contact_model", request, writes=writes,
        provenance={"prepared": plain_v1(prepared), "frozen": plain_v1(asdict(frozen)), "job": plain_v1(job)},
        proposal_schema="d11.proposal.v1", proposal_hash=descriptor.request_schema_hash)
    result = verify_contact_model_stage_v1(ContactModelStageV1(primary, prepared, frozen, job, frame))
    provider.validate(primary.proposals[0], frame.snapshot)
    return result


def verify_contact_model_stage_v1(staged):
    from .d11_types import job_graph_write
    if type(staged) is not ContactModelStageV1 or staged.stage.domain != "d11" or staged.stage.operation_kind != "prepare_contact_model":
        raise TypeError("closed contact model preparation stage required")
    stage, prepared = staged.stage, staged.prepared
    if (stage.coverage != "complete" or stage.operation_id != prepared.prepare_operation_id
            or stage.activity_id != prepared.activity_id or len(stage.proposals) != 1
            or stage.proposals[0].typed_writes != (job_graph_write(staged.job),) or stage.outbox
            or canonical_digest(plain_v1(asdict(staged.frozen))) != prepared.frozen_digest
            or staged.job.job_id != prepared.job_id or staged.job.phase != "queued"):
        raise ValueError("contact prepared stage changed actual fixed job/quote/frozen commitments")
    return staged


def verify_contact_model_preparation_in_transaction_v1(db, staged, *, issuer, resource_issuer, installed_bundle):
    from .contact_model_job_v1 import read_contact_prepared_v1
    from .contact_plan_adoption_v1 import read_adopted_contact_plan_v1, require_contact_inventory_current_v1
    from ..authority_service.contact_model_graph_v1 import require_contact_scope_current_v1
    from .jobs import get_job
    verify_contact_model_stage_v1(staged)
    prepared = staged.prepared
    actual, frozen = read_contact_prepared_v1(db, namespace=prepared.namespace, job_id=prepared.job_id, issuer=issuer)
    plan, expression, raw, plan_digest = read_adopted_contact_plan_v1(db, namespace=prepared.namespace, contact_id=prepared.contact_id, issuer=issuer)
    require_contact_inventory_current_v1(db, prepared.namespace, raw)
    require_contact_scope_current_v1(db, plan, expression, now=json.loads(staged.stage.original_payload_json)["now_utc"])
    quote = resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
    reservation = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (quote.parent_budget_lease_ref, prepared.prepare_operation_id)).fetchone()
    workflow = getattr(installed_bundle.model_workflows, prepared.phase)
    if (not db.in_transaction or actual != prepared or frozen != staged.frozen or get_job(db, prepared.job_id) != staged.job
            or prepared.plan_original_digest != plan_digest or canonical_digest(quote) != prepared.quote_digest
            or quote.operation_id != prepared.prepare_operation_id or quote.work_kind != prepared.phase
            or reservation != (prepared.reservation_digest, canonical_serialize(dict(quote.ceiling)), "reserved")
            or dict(quote.ceiling) != dict(workflow.quote_ceiling)
            or prepared.provider_config_ref != workflow.provider_config_ref
            or frozen.installation.provider_config_digest != workflow.provider_config_digest):
        raise ValueError("contact prepared stage differs from its real quoted/reserved installed job")
    return staged


def read_plan_contact_model_v1(db, *, namespace, activity_id, operation_kind, request):
    from ..domains.d08.contact_plan_v1 import contact_plan_key_v1, decode_contact_plan_v1
    from .contact_paid_original_v1 import TABLE
    from .contact_model_job_v1 import contact_model_ids_v1
    from .d11_types import runtime_job_key
    if type(request) is not PrepareCurrentContactModelRequestV1:
        raise TypeError("fixed contact model locator request required")
    saved = db.execute(f"SELECT payload_json FROM {TABLE} WHERE bot=? AND persona=? AND kind='plan' AND original_ref=?",
        (*namespace.as_tuple, request.contact_id)).fetchone()
    if saved is None:
        raise MissingProductionOriginalV1("actual_adopted_contact_plan")
    raw = json.loads(saved[0])
    plan = decode_contact_plan_v1(raw["plan"])
    ids = contact_model_ids_v1(plan, request.phase)
    keys = [owner_grant_key(*namespace.as_tuple), contact_plan_key_v1(plan),
        runtime_job_key(*namespace.as_tuple, plan.activity_id, ids["job"])]
    keys.extend(row.key for row in plan.qualified_read_versions)
    roots = tuple(row.key.token for row in plan.qualified_read_versions if row.key.type_name == "memory.source" and row.revision > 0)
    if request.phase == "contact_review":
        generation = contact_model_ids_v1(plan, "contact_generation")
        keys.append(runtime_job_key(*namespace.as_tuple, plan.activity_id, generation["job"]))
        paid = db.execute(f"SELECT payload_json FROM {TABLE} WHERE bot=? AND persona=? AND kind='paid_cost' AND original_ref=?",
            (*namespace.as_tuple, generation["job"])).fetchone()
        if paid is not None:
            keys.append(AtomKey.from_token(json.loads(paid[0])["cost_ref"]))
    return production_read_plan_v1(CONTACT_CURRENT_TYPES, keys, roots, (plan.source_ref.ref,))


def command_identity_contact_model_v1(db, *, namespace, request, operation_id, issuer):
    from .contact_plan_adoption_v1 import read_adopted_contact_plan_v1
    from .contact_model_job_v1 import contact_model_ids_v1
    if type(request) is not PrepareCurrentContactModelRequestV1:
        raise TypeError("fixed contact model request required")
    plan, _, _, _ = read_adopted_contact_plan_v1(db, namespace=namespace, contact_id=request.contact_id, issuer=issuer)
    if operation_id != contact_model_ids_v1(plan, request.phase)["prepare"]:
        raise ValueError("contact command cannot mint a second model reservation identity")
    return plan.activity_id, None, "expression"
