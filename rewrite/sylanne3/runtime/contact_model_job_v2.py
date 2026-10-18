"""Two distinct finite model jobs, sharing the installed D02/D11 budget ledger."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
from ..domains.d01.production_operations_v1 import plain_v1
from ..model_broker.contact_expression_v2 import (ContactGenerationInputV2, FrozenContactModelRequestV2,
    freeze_contact_model_request_v2, GENERATION_TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION)
from ..model_broker.natural_reply import NaturalReplyInstallationV2
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .budget import get_budget_lease, reserve_budget, require_budget_family_admissible
from .issuers import ResourceQuote
from .jobs import PersistentJob, create_job, get_job
from .d11_types import runtime_job_key, job_graph_write
from .contact_paid_original_v2 import record_contact_original_v2, require_contact_original_v2, read_contact_original_v2
from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2

PHASES = frozenset({"contact_generation", "contact_review"})


def contact_model_ids_v2(plan, phase):
    from ..domains.d08.contact_plan_v2 import AdoptedContactExpressionPlanV2, contact_plan_key_v2
    if type(plan) is not AdoptedContactExpressionPlanV2 or phase not in PHASES:
        raise ValueError("Contact V2 model stage requires its exact adopted Plan V2")
    digest = canonical_digest({"schema": "d10.contact-model-identity.v2",
        "namespace": plan.namespace, "plan_ref": contact_plan_key_v2(plan).token,
        "plan_digest": canonical_digest(plain_v1(plan)), "phase": phase})[:48]
    identities = {name: prefix + digest for name, prefix in (
        ("job", "contact-model-job-v2:"),
        ("acquire", "contact-model-acquire-v2:"), ("call", "contact-model-call-v2:"),
        ("quote", "contact-model-quote-v2:"), ("snapshot", "contact-model-snapshot-v2:"))}
    identities["prepare"] = (plan.generation_reservation_id if phase == "contact_generation"
                             else plan.review_reservation_id)
    return identities


@dataclass(frozen=True, slots=True)
class ContactModelPreparedV2:
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
    schema: str = "d10.contact-model-prepared.v2"

    def __post_init__(self):
        if self.schema != "d10.contact-model-prepared.v2" or self.phase not in PHASES or type(self.namespace) is not NamespaceId:
            raise ValueError("closed contact prepared stage required")
        from ..authority_service.contract import identifier
        for name in ("contact_id", "phase", "activity_id", "installation_id", "job_id",
                     "prepare_operation_id", "acquire_operation_id", "call_id", "quote_id"):
            identifier(getattr(self, name), name)
        if type(self.quote_version) is not int or self.quote_version < 1:
            raise ValueError("Contact V2 signed quote version is invalid")
        for name in ("plan_original_digest", "frozen_digest", "quote_digest",
                     "reservation_digest", "algorithm_build_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("Contact V2 original digest is invalid")
        proof = (self.generation_terminal_digest, self.generation_output_digest, self.generation_cost_ref)
        if (self.phase == "contact_review" and not all(v is not None for v in proof)
                or self.phase == "contact_generation" and any(v is not None for v in proof)):
            raise ValueError("independent review must bind the actual whole paid generation")

    @property
    def digest(self): return canonical_digest(plain_v1(self))


def decode_contact_prepared_v2(raw):
    from dataclasses import fields
    if type(raw) is not dict or set(raw) != {f.name for f in fields(ContactModelPreparedV2)}:
        raise ValueError("contact preparation fields differ")
    data = dict(raw)
    data["namespace"] = NamespaceId(**data["namespace"])
    result = ContactModelPreparedV2(**data)
    if canonical_serialize(plain_v1(result)) != canonical_serialize(raw):
        raise ValueError("contact preparation wire is noncanonical")
    return result


def thaw_contact_request_v2(raw):
    from ..domains.d08.contact_plan_v2 import decode_contact_plan_v2
    from ..domains.d09.natural_reply import NaturalExpressionPlanV2
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..model_broker.contact_expression_v2 import parse_contact_generation_output_v2
    data = raw["input"]
    input = ContactGenerationInputV2(decode_contact_plan_v2(data["adopted_plan"]),
        decode_typed_production_value_v1(data["expression_plan"], NaturalExpressionPlanV2),
        data["frozen_at_utc"], data["expires_at_utc"])
    installation = NaturalReplyInstallationV2(**raw["installation"])
    generated = None
    if raw["phase"] == "contact_review":
        provider_data = json.loads(raw["messages"][1]["content"])
        generated = parse_contact_generation_output_v2(json.dumps(provider_data["generation_output"]),
            freeze_contact_model_request_v2(input, installation))
    rebuilt = freeze_contact_model_request_v2(input, installation, generation_output=generated)
    if canonical_serialize(plain_v1(rebuilt)) != canonical_serialize(raw):
        raise ValueError("contact frozen request differs from its exact template and typed input")
    return rebuilt


def read_contact_prepared_v2(db, *, namespace, job_id, issuer):
    raw, _ = require_contact_original_v2(db, issuer, namespace, "prepared", job_id)
    result = decode_contact_prepared_v2(raw)
    frozen = thaw_contact_request_v2(json.loads(result.frozen_json))
    if canonical_digest(plain_v1(frozen)) != result.frozen_digest or frozen.phase != result.phase:
        raise ValueError("contact prepared request commitment differs")
    return result, frozen


def prepare_contact_model_in_transaction_v2(db, *, frame, contact_id, phase, installed_bundle,
        issuer, resource_issuer, algorithm_build_digest, generation=None):
    from .d01_production_operations_v1 import CurrentDomainReadV1
    from ..authority_service.contact_model_graph_v2 import require_contact_scope_current_v2
    CurrentDomainReadV1(frame).check(db)
    from ..host.authority_profile import AdminInstallationBundle
    from ..host.model_workflows_v3 import AdminModelWorkflowsV3
    from ..host.model_workflows_v4 import AdminModelWorkflowsV4
    from ..host.model_workflows_v5 import AdminModelWorkflowsV5
    from ..host.model_workflows_v6 import AdminModelWorkflowsV6
    from ..host.model_workflows_v7 import AdminModelWorkflowsV7
    from ..host.model_workflows_v8 import AdminModelWorkflowsV8
    from ..host.model_workflows_v9 import AdminModelWorkflowsV9
    if (type(installed_bundle) is not AdminInstallationBundle
            or type(installed_bundle.model_workflows) not in (AdminModelWorkflowsV3, AdminModelWorkflowsV4,
                AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9)):
        raise ValueError("Contact V2 paid preparation requires an explicit installed workflow container V3-V7")
    ns, now = frame.envelope.authority.namespace, frame.now_utc
    plan, expression, plan_raw, plan_digest = read_adopted_contact_plan_v2(db, namespace=ns, contact_id=contact_id, issuer=issuer)
    require_contact_scope_current_v2(db, plan, expression, now=now)
    from .contact_plan_adoption_v2 import require_contact_inventory_current_v2
    require_contact_inventory_current_v2(db, ns, plan_raw)
    # Existing V1 paid execution cannot silently become a newly billed V2 call.
    from .contact_model_job_v1 import contact_model_ids_v1
    from .contact_paid_original_v1 import read_contact_original_v1
    old_job = contact_model_ids_v1(plan, phase)["job"]
    if read_contact_original_v1(db, issuer, ns, "prepared", old_job) is not None:
        raise ValueError("legacy Contact paid execution requires explicit migration; HOLD")
    ids = contact_model_ids_v2(plan, phase)
    if frame.envelope.identity.operation_id != ids["prepare"] or frame.envelope.identity.activity_id != plan.activity_id:
        raise ValueError("contact preparation must commit its exact stable budget operation")
    prior = read_contact_original_v2(db, issuer, ns, "prepared", ids["job"])
    if prior is not None:
        prepared, frozen = read_contact_prepared_v2(db, namespace=ns, job_id=ids["job"], issuer=issuer)
        return prepared, frozen, get_job(db, ids["job"]), ()
    occupied = db.execute('SELECT 1 FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
        (plan.parent_budget_lease_id, ids["prepare"])).fetchone()
    if occupied is not None:
        raise ValueError("Contact phase reservation exists without its exact V2 prepared original; HOLD")
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
        from .contact_model_preparation_v2 import read_paid_contact_result_v2
        generation_prepared, generation_frozen, generated, paid = read_paid_contact_result_v2(db,
            namespace=ns, contact_id=contact_id, phase="contact_generation", issuer=issuer, resource_issuer=resource_issuer)
        if generated.status != "untrusted_content_candidate":
            raise ValueError("zero-segment generation holds contact before review")
        input = generation_frozen.input
        generation = generated
        generation_proof = (paid["terminal_digest"], generated.output_digest, paid["cost_ref"])
    else:
        if generation is not None:
            raise ValueError("generation accepts no caller result")
        input = ContactGenerationInputV2(plan, expression, now, plan.valid_until_utc)
    frozen = freeze_contact_model_request_v2(input, installation, generation_output=generation)
    deadline = datetime.fromtimestamp(plan.valid_until_utc, timezone.utc).isoformat().replace("+00:00", "Z")
    quote = ResourceQuote(ids["quote"], 1, *ns.as_tuple, plan.activity_id, ids["prepare"], None,
        grant.lease_id, phase, ids["snapshot"], plan.valid_until_utc, workflow.provider_config_ref,
        runtime_job_key(*ns.as_tuple, plan.activity_id, ids["job"]).token, (), (), ceiling, None, plan.valid_until_utc)
    reservation_digest = canonical_digest({"schema": "d10.contact-model-reservation.v2", "plan_digest": plan_digest,
        "phase": phase, "quote": plain_v1(quote), "frozen_digest": canonical_digest(plain_v1(frozen))})
    resource_issuer.issue_quote(db, quote)
    reserve_budget(db, grant.lease_id, ids["prepare"], reservation_digest, ceiling)
    job = PersistentJob(ids["job"], ids["prepare"], plan.activity_id, None, *ns.as_tuple, ids["snapshot"], "queued", phase,
        {"contact_id": contact_id, "plan_id": plan.plan_id}, None, deadline, grant.lease_id,
        workflow.provider_config_ref, {"resource_quote": ids["quote"] + ":1"}, None, None, 0, plan.cancellation_epoch, {}, None)
    prepared = ContactModelPreparedV2(ns, contact_id, phase, plan.activity_id, installation.installation_id,
        ids["job"], ids["prepare"], ids["acquire"], ids["call"], plan_digest,
        canonical_serialize(plain_v1(frozen)),
        canonical_digest(plain_v1(frozen)), quote.quote_id, quote.version, canonical_digest(quote), reservation_digest,
        workflow.provider_config_ref, algorithm_build_digest, *generation_proof)
    create_job(db, job, "create:" + ids["prepare"], reservation_digest)
    record_contact_original_v2(db, issuer, ns, "prepared", job.job_id, prepared)
    record_contact_original_v2(db, issuer, ns, "accounting_prepared", job.job_id,
        {"schema": "d10.contact-model-accounting-prepared.v2", "namespace": plain_v1(ns),
         "contact_id": prepared.contact_id, "job_id": prepared.job_id, "call_id": prepared.call_id, "prepared_digest": prepared.digest,
         "prepare_operation_id": prepared.prepare_operation_id, "acquire_operation_id": prepared.acquire_operation_id,
         "quote_id": prepared.quote_id, "quote_version": prepared.quote_version, "quote_digest": prepared.quote_digest,
         "reservation_digest": prepared.reservation_digest, "work_kind": phase, "activity_id": prepared.activity_id,
         "parent_budget_lease_id": grant.lease_id})
    return prepared, frozen, job, (job_graph_write(job),)


def record_contact_preparation_after_cas_v2(db, *, prepared, issuer, receipt):
    from .d04_root_original_store_v1 import _receipt
    if receipt.status != "committed" or receipt.operation_id != prepared.prepare_operation_id:
        raise ValueError("contact preparation requires actual reserve/job Graph commit")
    actual = _receipt(db, prepared.namespace, prepared.prepare_operation_id)
    if actual != receipt:
        raise ValueError("contact preparation receipt is not its actual Graph original")
    return record_contact_original_v2(db, issuer, prepared.namespace, "prepare_commit", prepared.job_id,
        {"schema": "d10.contact-model-prepare-commit.v2", "prepared_digest": prepared.digest,
         "receipt_digest": canonical_digest(receipt), "operation_id": receipt.operation_id})
