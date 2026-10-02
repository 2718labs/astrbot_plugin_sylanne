"""Contact Plan V2 paid preparation through the exact common W01 witness."""
from dataclasses import dataclass, replace, asdict
import json
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..graph_types import AtomKey, owner_grant_key
from ..runtime_contracts import canonical_digest, canonical_serialize
from .d01_production_operations_v1 import production_read_plan_v1, MissingProductionOriginalV1
from .contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
from .contact_model_job_v2 import prepare_contact_model_in_transaction_v2


@dataclass(frozen=True, slots=True)
class PrepareCurrentContactModelRequestV2:
    contact_id: str
    phase: str

    def __post_init__(self):
        from ..authority_service.contract import identifier
        identifier(self.contact_id, 'contact_id')
        if not self.contact_id.startswith("contact:") or type(self.phase) is not str or self.phase not in {"contact_generation", "contact_review"}:
            raise ValueError("contact model request requires its stable adopted contact and fixed phase")


@dataclass(frozen=True, slots=True)
class ContactModelStageV2:
    stage: object
    prepared: object
    frozen: object
    job: object
    frame: object


def stage_prepare_current_contact_model_in_transaction_v2(db, *, frame, request, installed_readers):
    from ..host.installed_contact_build_v1 import read_installed_contact_build_v1
    graph = installed_readers.role_clock_reader.graph
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if type(request) is not PrepareCurrentContactModelRequestV2 or assembly is None:
        raise MissingProductionOriginalV1("actual_installed_contact_model_preparation")
    build = read_installed_contact_build_v1(assembly.package_root, assembly.installation_policy.manifest_digest)
    prepared, frozen, job, writes = prepare_contact_model_in_transaction_v2(db, frame=frame,
        contact_id=request.contact_id, phase=request.phase, installed_bundle=assembly.admin_bundle,
        issuer=installed_readers.issuer, resource_issuer=graph._GraphCoordinator__d02_issuer, algorithm_build_digest=build)
    if not writes:
        raise MissingProductionOriginalV1("already_prepared_contact_exact_replay")
    from .d11_types import D11RuntimeProvider, D11_PROPOSAL_SCHEMA
    provider = D11RuntimeProvider()
    descriptor = provider.descriptor
    primary = stage_result_v1(frame, "d11", "prepare_contact_model_v2", request, writes=writes,
        provenance={"prepared": plain_v1(prepared), "frozen": plain_v1(frozen), "job": plain_v1(job)},
        proposal_schema=D11_PROPOSAL_SCHEMA, proposal_hash=descriptor.request_schema_hash)
    result = verify_contact_model_stage_v2(ContactModelStageV2(primary, prepared, frozen, job, frame))
    provider.validate(primary.proposals[0], frame.snapshot)
    return result


def verify_contact_model_preparation_in_transaction_v2(db, staged, *, issuer, resource_issuer, installed_bundle):
    from .contact_model_job_v2 import read_contact_prepared_v2
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2, require_contact_inventory_current_v2
    from ..authority_service.contact_model_graph_v2 import require_contact_scope_current_v2
    from .jobs import get_job
    verify_contact_model_stage_v2(staged)
    prepared = staged.prepared
    actual, frozen = read_contact_prepared_v2(db, namespace=prepared.namespace, job_id=prepared.job_id, issuer=issuer)
    plan, expression, raw, plan_digest = read_adopted_contact_plan_v2(db, namespace=prepared.namespace, contact_id=prepared.contact_id, issuer=issuer)
    require_contact_inventory_current_v2(db, prepared.namespace, raw)
    require_contact_scope_current_v2(db, plan, expression, now=json.loads(staged.stage.original_payload_json)["now_utc"])
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


def read_plan_contact_model_v2(db, *, namespace, activity_id, operation_kind, request):
    from ..domains.d08.contact_plan_v2 import contact_plan_keys_v2
    from .contact_plan_adoption_v2 import TABLE as PLAN_TABLE, validate_contact_plan_original_payload_v2
    from .contact_paid_original_v2 import TABLE
    from .contact_model_job_v2 import contact_model_ids_v2
    from .d11_types import runtime_job_key
    if type(request) is not PrepareCurrentContactModelRequestV2:
        raise TypeError("Contact V2 exact paid locator request required")
    saved = db.execute(f"SELECT payload_json FROM {PLAN_TABLE} WHERE bot=? AND persona=? AND contact_id=?",
        (*namespace.as_tuple, request.contact_id)).fetchone()
    if saved is None:
        raise MissingProductionOriginalV1("actual_adopted_contact_plan_v2")
    plan, expression, proof = validate_contact_plan_original_payload_v2(json.loads(saved[0]))
    ids = contact_model_ids_v2(plan, request.phase)
    keys = [owner_grant_key(*namespace.as_tuple), *contact_plan_keys_v2(plan),
        runtime_job_key(*namespace.as_tuple, plan.activity_id, ids["job"])]
    keys.extend(AtomKey.from_token(row.ref) for row in proof.historical_reads)
    roots = tuple(row.ref for row in proof.historical_reads
        if AtomKey.from_token(row.ref).type_name == "memory.source" and row.revision > 0)
    if request.phase == "contact_review":
        generation = contact_model_ids_v2(plan, "contact_generation")
        keys.append(runtime_job_key(*namespace.as_tuple, plan.activity_id, generation["job"]))
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone():
            paid = db.execute(f"SELECT payload_json FROM {TABLE} WHERE bot=? AND persona=? AND kind='paid_cost' AND original_ref=?",
                (*namespace.as_tuple, generation["job"])).fetchone()
            if paid is not None:
                keys.append(AtomKey.from_token(json.loads(paid[0])["cost_ref"]))
    return production_read_plan_v1(CONTACT_CURRENT_TYPES, keys, roots, (plan.source_ref.ref,))


def command_identity_contact_model_v2(db, *, namespace, request, operation_id, issuer):
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2
    from .contact_model_job_v2 import contact_model_ids_v2
    if type(request) is not PrepareCurrentContactModelRequestV2:
        raise TypeError("fixed contact model request required")
    plan, _, _, _ = read_adopted_contact_plan_v2(db, namespace=namespace, contact_id=request.contact_id, issuer=issuer)
    if operation_id != contact_model_ids_v2(plan, request.phase)["prepare"]:
        raise ValueError("contact command cannot mint a second model reservation identity")
    return plan.activity_id, None, "expression"


def verify_contact_model_stage_v2(staged):
    from .d11_types import job_graph_write
    if type(staged) is not ContactModelStageV2 or staged.stage.domain != "d11" or staged.stage.operation_kind != "prepare_contact_model_v2":
        raise TypeError("closed contact model preparation stage required")
    stage, prepared = staged.stage, staged.prepared
    if (stage.coverage != "complete" or stage.operation_id != prepared.prepare_operation_id
            or stage.activity_id != prepared.activity_id or len(stage.proposals) != 1
            or stage.proposals[0].typed_writes != (job_graph_write(staged.job),) or stage.outbox
            or canonical_digest(plain_v1(staged.frozen)) != prepared.frozen_digest
            or staged.job.job_id != prepared.job_id or staged.job.phase != "queued"):
        raise ValueError("contact prepared stage changed actual fixed job/quote/frozen commitments")
    return staged
