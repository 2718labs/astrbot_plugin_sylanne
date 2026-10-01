"""Two distinct finite model jobs, sharing the installed D02/D11 budget ledger."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
from ..domains.d01.production_operations_v1 import plain_v1
from ..model_broker.contact_expression_v1 import (ContactGenerationInputV1, FrozenContactModelRequestV1,
    freeze_contact_model_request_v1, GENERATION_TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION)
from ..model_broker.natural_reply import NaturalReplyInstallationV2
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .budget import get_budget_lease, reserve_budget, require_budget_family_admissible
from .issuers import ResourceQuote
from .jobs import PersistentJob, create_job, get_job
from .d11_types import runtime_job_key, job_graph_write
from .contact_paid_original_v1 import record_contact_original_v1, require_contact_original_v1, read_contact_original_v1
from .contact_plan_adoption_v1 import read_adopted_contact_plan_v1

PHASES = frozenset({"contact_generation", "contact_review"})


def contact_model_ids_v1(plan, phase):
    if phase not in PHASES:
        raise ValueError("contact model stage is outside the installed pair")
    digest = canonical_digest((plan.namespace, plan.contact_id, phase))[:48]
    reservation = plan.generation_reservation_id if phase == "contact_generation" else plan.review_reservation_id
    return {"job": "contact-model-job:" + digest, "prepare": reservation,
        "acquire": "contact-model-acquire:" + digest, "call": "contact-model-call:" + digest,
        "quote": "contact-model-quote:" + digest, "snapshot": "contact-model-snapshot:" + digest}


@dataclass(frozen=True, slots=True)
class ContactModelPreparedV1:
    namespace: NamespaceId
    contact_id: str
    phase: str
    activity_id: str
    installation_id: str
    job_id: str
    prepare_operation_id: str
    acquire_operation_id: str
    call_id: str
    plan_original_digest: str
    frozen_json: str
    frozen_digest: str
    quote_id: str
    quote_version: int
    quote_digest: str
    reservation_digest: str
    provider_config_ref: str
    algorithm_build_digest: str
    generation_terminal_digest: str | None
    generation_output_digest: str | None
    generation_cost_ref: str | None
    schema: str = "d10.contact-model-prepared.v1"

    def __post_init__(self):
        if self.schema != "d10.contact-model-prepared.v1" or self.phase not in PHASES or type(self.namespace) is not NamespaceId:
            raise ValueError("closed contact prepared stage required")
        proof = (self.generation_terminal_digest, self.generation_output_digest, self.generation_cost_ref)
        if (self.phase == "contact_review" and not all(v is not None for v in proof)
                or self.phase == "contact_generation" and any(v is not None for v in proof)):
            raise ValueError("independent review must bind the actual whole paid generation")

    @property
    def digest(self): return canonical_digest(plain_v1(self))


def decode_contact_prepared_v1(raw):
    from dataclasses import fields
    if type(raw) is not dict or set(raw) != {f.name for f in fields(ContactModelPreparedV1)}:
        raise ValueError("contact preparation fields differ")
    data = dict(raw)
    data["namespace"] = NamespaceId(**data["namespace"])
    result = ContactModelPreparedV1(**data)
    if plain_v1(result) != raw:
        raise ValueError("contact preparation wire is noncanonical")
    return result


def thaw_contact_request_v1(raw):
    from ..domains.d08.contact_plan_v1 import decode_contact_plan_v1
    from ..domains.d09.natural_reply import NaturalExpressionPlanV2
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..model_broker.contact_expression_v1 import parse_contact_generation_output_v1
    data = raw["input"]
    input = ContactGenerationInputV1(decode_contact_plan_v1(data["adopted_plan"]),
        decode_typed_production_value_v1(data["expression_plan"], NaturalExpressionPlanV2),
        data["frozen_at_utc"], data["expires_at_utc"])
    installation = NaturalReplyInstallationV2(**raw["installation"])
    generated = None
    if raw["phase"] == "contact_review":
        provider_data = json.loads(raw["messages"][1]["content"])
        generated = parse_contact_generation_output_v1(json.dumps(provider_data["generation_output"]),
            freeze_contact_model_request_v1(input, installation))
    rebuilt = freeze_contact_model_request_v1(input, installation, generation_output=generated)
    if plain_v1(asdict(rebuilt)) != raw:
        raise ValueError("contact frozen request differs from its exact template and typed input")
    return rebuilt


def read_contact_prepared_v1(db, *, namespace, job_id, issuer):
    raw, _ = require_contact_original_v1(db, issuer, namespace, "prepared", job_id)
    result = decode_contact_prepared_v1(raw)
    frozen = thaw_contact_request_v1(json.loads(result.frozen_json))
    if canonical_digest(plain_v1(asdict(frozen))) != result.frozen_digest or frozen.phase != result.phase:
        raise ValueError("contact prepared request commitment differs")
    return result, frozen


def prepare_contact_model_in_transaction_v1(db, *, frame, contact_id, phase, installed_bundle,
        issuer, resource_issuer, algorithm_build_digest, generation=None):
    from .d01_production_operations_v1 import CurrentDomainReadV1
    from ..authority_service.contact_model_graph_v1 import require_contact_scope_current_v1
    CurrentDomainReadV1(frame).check(db)
    ns, now = frame.envelope.authority.namespace, frame.now_utc
    plan, expression, plan_raw, plan_digest = read_adopted_contact_plan_v1(db, namespace=ns, contact_id=contact_id, issuer=issuer)
    require_contact_scope_current_v1(db, plan, expression, now=now)
    ids = contact_model_ids_v1(plan, phase)
    if frame.envelope.identity.operation_id != ids["prepare"] or frame.envelope.identity.activity_id != plan.activity_id:
        raise ValueError("contact preparation must commit its exact stable budget operation")
    prior = read_contact_original_v1(db, issuer, ns, "prepared", ids["job"])
    if prior is not None:
        prepared, frozen = read_contact_prepared_v1(db, namespace=ns, job_id=ids["job"], issuer=issuer)
        return prepared, frozen, get_job(db, ids["job"]), ()
    workflow = getattr(installed_bundle.model_workflows, phase)
    expected_template = GENERATION_TEMPLATE_VERSION if phase == "contact_generation" else REVIEW_TEMPLATE_VERSION
    ceiling = dict(plan.generation_ceiling if phase == "contact_generation" else plan.review_ceiling)
    grant = issuer.current_budget_grant(db, plan.parent_budget_lease_id)
    lease = get_budget_lease(db, plan.parent_budget_lease_id)
    require_budget_family_admissible(db, lease.lease_id)
    if (workflow is None or workflow.work_kind != phase or workflow.template_version != expected_template
            or workflow.purpose != "proposal" or workflow.quote_ceiling != ceiling
            or plan.audience_id not in workflow.audiences or grant.version != plan.budget_grant_version
            or canonical_digest(grant) != plan.budget_grant_digest or phase not in grant.allowed_work_kinds
            or lease.state != "active" or now + workflow.timeout_seconds >= min(grant.valid_until_utc, plan.valid_until_utc)):
        raise ValueError("contact current installed workflow or finite budget changed")
    installation = NaturalReplyInstallationV2(installed_bundle.installation_policy.installation_id,
        workflow.provider_config_digest, workflow.provider_id, workflow.model_id, workflow.max_output_tokens)
    # Both wires carry the exact originally frozen input, including its first time sample.
    generation_proof = (None, None, None)
    if phase == "contact_review":
        from .contact_model_preparation_v1 import read_paid_contact_result_v1
        generation_prepared, generation_frozen, generated, paid = read_paid_contact_result_v1(db,
            namespace=ns, contact_id=contact_id, phase="contact_generation", issuer=issuer, resource_issuer=resource_issuer)
        if generated.status != "untrusted_content_candidate":
            raise ValueError("zero-segment generation holds contact before review")
        input = generation_frozen.input
        generation = generated
        generation_proof = (paid["terminal_digest"], generated.output_digest, paid["cost_ref"])
    else:
        if generation is not None:
            raise ValueError("generation accepts no caller result")
        input = ContactGenerationInputV1(plan, expression, now, plan.valid_until_utc)
    frozen = freeze_contact_model_request_v1(input, installation, generation_output=generation)
    deadline = datetime.fromtimestamp(plan.valid_until_utc, timezone.utc).isoformat().replace("+00:00", "Z")
    quote = ResourceQuote(ids["quote"], 1, *ns.as_tuple, plan.activity_id, ids["prepare"], None,
        grant.lease_id, phase, ids["snapshot"], plan.valid_until_utc, workflow.provider_config_ref,
        runtime_job_key(*ns.as_tuple, plan.activity_id, ids["job"]).token, (), (), ceiling, None, plan.valid_until_utc)
    reservation_digest = canonical_digest({"schema": "d10.contact-model-reservation.v1", "plan_digest": plan_digest,
        "phase": phase, "quote": plain_v1(quote), "frozen_digest": canonical_digest(plain_v1(asdict(frozen)))})
    resource_issuer.issue_quote(db, quote)
    reserve_budget(db, grant.lease_id, ids["prepare"], reservation_digest, ceiling)
    job = PersistentJob(ids["job"], ids["prepare"], plan.activity_id, None, *ns.as_tuple, ids["snapshot"], "queued", phase,
        {"contact_id": contact_id, "plan_id": plan.plan_id}, None, deadline, grant.lease_id,
        workflow.provider_config_ref, {"resource_quote": ids["quote"] + ":1"}, None, None, 0, plan.cancellation_epoch, {}, None)
    prepared = ContactModelPreparedV1(ns, contact_id, phase, plan.activity_id, installation.installation_id,
        ids["job"], ids["prepare"], ids["acquire"], ids["call"], plan_digest,
        canonical_serialize(plain_v1(asdict(frozen))),
        canonical_digest(plain_v1(asdict(frozen))), quote.quote_id, quote.version, canonical_digest(quote), reservation_digest,
        workflow.provider_config_ref, algorithm_build_digest, *generation_proof)
    create_job(db, job, "create:" + ids["prepare"], reservation_digest)
    record_contact_original_v1(db, issuer, ns, "prepared", job.job_id, prepared)
    record_contact_original_v1(db, issuer, ns, "accounting_prepared", job.job_id,
        {"schema": "d10.contact-model-accounting-prepared.v1", "namespace": plain_v1(ns),
         "job_id": prepared.job_id, "call_id": prepared.call_id, "prepared_digest": prepared.digest,
         "prepare_operation_id": prepared.prepare_operation_id, "acquire_operation_id": prepared.acquire_operation_id,
         "quote_id": prepared.quote_id, "quote_version": prepared.quote_version, "quote_digest": prepared.quote_digest,
         "reservation_digest": prepared.reservation_digest, "work_kind": phase, "activity_id": prepared.activity_id,
         "parent_budget_lease_id": grant.lease_id})
    return prepared, frozen, job, (job_graph_write(job),)


def record_contact_preparation_after_cas_v1(db, *, prepared, issuer, receipt):
    from .d04_root_original_store_v1 import _receipt
    if receipt.status != "committed" or receipt.operation_id != prepared.prepare_operation_id:
        raise ValueError("contact preparation requires actual reserve/job Graph commit")
    actual = _receipt(db, prepared.namespace, prepared.prepare_operation_id)
    if actual != receipt:
        raise ValueError("contact preparation receipt is not its actual Graph original")
    return record_contact_original_v1(db, issuer, prepared.namespace, "prepare_commit", prepared.job_id,
        {"schema": "d10.contact-model-prepare-commit.v1", "prepared_digest": prepared.digest,
         "receipt_digest": canonical_digest(receipt), "operation_id": receipt.operation_id})
