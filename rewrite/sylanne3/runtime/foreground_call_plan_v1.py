"""Finite foreground call selection over the existing D11 budget family.

This continuation metadata counts attempts; it is not a money/token ledger.
The protected reply allocation is an actual child in runtime_budget_leases.
Every model dispatch still uses its original D02 quote and D11 reservation.
"""
from dataclasses import dataclass, replace
from ..graph_types import GraphVersion

from ..model_broker.artifact_draft_v1 import (
    ArtifactDraftPhaseSelectorV2, artifact_draft_phase_sequence_v2,
    artifact_draft_model_ids_v2, artifact_draft_phase_original_ref_v2,
    artifact_draft_phase_token_limits_v2, artifact_draft_from_wire_v2,
)

from ..runtime_contracts import NamespaceId, canonical_serialize, canonical_digest
from .budget import BudgetLease, get_budget_lease, require_budget_family_admissible, create_budget_lease
from .issuers import D11BudgetJobIssuer, BudgetLeaseGrant, MAX_DIMENSIONS, MAX_QUANTITY

SLOTS = {
    "C1": ("d06.encode_source", 6000, 800, False),
    "C2": ("d04.appraisal", 6000, 800, False),
    "C3": ("d07.cognition", 6000, 1000, True),
    "C4": ("artifact_draft_v1", 10000, 2000, True),
    "C5": ("natural_generation", 8000, 2000, False),
    "C6": ("natural_review", 12000, 1400, False),
}
SCHEMA = "d11.foreground-call-plan.v1"
ALLOCATION_SCHEMA = "d11.foreground-reply-allocation.v1"
ALLOCATION_POLICY = "policy:foreground-protected-reply.v1"
REPLY_KINDS = ("natural_generation", "natural_review", "message")
MODEL_DIMENSIONS = frozenset({"input_tokens", "output_tokens", "model_tokens", "model_microusd"})


def foreground_reply_budget_ids_v1(namespace, c02_operation_id):
    if type(namespace) is not NamespaceId or type(c02_operation_id) is not str or not c02_operation_id:
        raise TypeError("foreground reply identity requires its actual namespace and original C02")
    marker = canonical_digest((ALLOCATION_SCHEMA, namespace, c02_operation_id))[:40]
    return tuple(prefix + marker for prefix in ("foreground-reply-lease:", "foreground-reply-grant:", "foreground-reply-create:"))


def _amount_tuple_v1(values):
    result = tuple(sorted(values.items()))
    _validate_amount_tuple_v1(result)
    return result


def _validate_amount_tuple_v1(values):
    import re
    if (type(values) is not tuple or not 1 <= len(values) <= MAX_DIMENSIONS
            or any(type(row) is not tuple or len(row) != 2 or type(row[0]) is not str
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", row[0]) is None
                or type(row[1]) is not int or not 0 < row[1] <= MAX_QUANTITY for row in values)
            or len({row[0] for row in values}) != len(values) or values != tuple(sorted(values))):
        raise ValueError("foreground allocation amounts must retain every exact registered finite dimension")


@dataclass(frozen=True, slots=True)
class ForegroundReplyAllocationV1:
    namespace: NamespaceId
    c02_operation_id: str
    installation_id: str
    manifest_digest: str
    parent_lease_ref: str
    parent_version: int
    parent_state_digest: str
    parent_grant_digest: str
    generation_workflow_digest: str
    review_workflow_digest: str
    message_policy_digest: str
    child_lease_id: str
    child_grant_id: str
    allocation_operation_id: str
    currency: str
    policy_ref: str
    valid_until_utc: float
    generation_ceiling: tuple[tuple[str, int], ...]
    review_ceiling: tuple[tuple[str, int], ...]
    message_ceiling: tuple[tuple[str, int], ...]
    child_limits: tuple[tuple[str, int], ...]
    child_max_ceiling: tuple[tuple[str, int], ...]
    message_slots: int = 4
    allowed_work_kinds: tuple[str, ...] = REPLY_KINDS
    schema: str = ALLOCATION_SCHEMA

    def __post_init__(self):
        import math
        if (self.schema != ALLOCATION_SCHEMA or type(self.namespace) is not NamespaceId
                or type(self.parent_version) is not int or self.parent_version < 1
                or self.policy_ref != ALLOCATION_POLICY or self.message_slots != 4
                or self.allowed_work_kinds != REPLY_KINDS
                or type(self.valid_until_utc) not in (int, float) or not math.isfinite(self.valid_until_utc)):
            raise ValueError("foreground allocation exact versioned policy/counter/deadline differs")
        for name in ("manifest_digest", "parent_state_digest", "parent_grant_digest",
                "generation_workflow_digest", "review_workflow_digest", "message_policy_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError("foreground allocation actual original commitment is invalid")
        for values in (self.generation_ceiling, self.review_ceiling, self.message_ceiling,
                self.child_limits, self.child_max_ceiling):
            _validate_amount_tuple_v1(values)
        generation, review, message = map(dict, (self.generation_ceiling, self.review_ceiling, self.message_ceiling))
        if set(generation) != MODEL_DIMENSIONS or set(review) != MODEL_DIMENSIONS:
            raise ValueError("foreground model allocation lacks its complete four registered cost dimensions")
        if (generation["input_tokens"] > 8000 or generation["output_tokens"] > 2000
                or review["input_tokens"] > 12000 or review["output_tokens"] > 1400):
            raise ValueError("foreground allocation exceeds the actual C5/C6 slot bounds")
        dimensions = set(generation) | set(review) | set(message)
        total = {name: generation.get(name, 0) + review.get(name, 0) + 4 * message.get(name, 0) for name in dimensions}
        maximum = {name: max(generation.get(name, 0), review.get(name, 0), message.get(name, 0)) for name in dimensions}
        if dict(self.child_limits) != total or dict(self.child_max_ceiling) != maximum:
            raise ValueError("foreground allocation totals/max quote caps differ from its exact three installed quotes")
        if (self.child_lease_id, self.child_grant_id, self.allocation_operation_id) != foreground_reply_budget_ids_v1(
                self.namespace, self.c02_operation_id):
            raise ValueError("foreground allocation changed its original deterministic C02 identities")
        self.child_lease()
        self.child_grant()

    @property
    def digest(self):
        from ..domains.d01.production_operations_v1 import plain_v1
        return canonical_digest(plain_v1(self))

    def child_lease(self):
        return BudgetLease(self.child_lease_id, self.parent_lease_ref, *self.namespace.as_tuple,
            self.currency, dict(self.child_limits), {}, {}, {}, 1, "active")

    def child_grant(self):
        return BudgetLeaseGrant(self.child_grant_id, 1, *self.namespace.as_tuple, self.child_lease_id,
            self.currency, dict(self.child_max_ceiling), self.allowed_work_kinds, self.valid_until_utc, self.policy_ref)


def _require_absent_reply_allocation_v1(db, allocation):
    if (db.execute("SELECT 1 FROM runtime_budget_leases WHERE lease_id=?", (allocation.child_lease_id,)).fetchone()
            or db.execute("SELECT 1 FROM runtime_budget_grants WHERE lease_id=? OR json_extract(grant_json,'$.grant_id')=?",
                (allocation.child_lease_id, allocation.child_grant_id)).fetchone()
            or db.execute("SELECT 1 FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=?",
                (*allocation.namespace.as_tuple, allocation.allocation_operation_id)).fetchone()):
        raise ValueError("foreground reply allocation target already exists; original replay must use its saved receipt")


def prepare_foreground_reply_allocation_v1(db, *, namespace, c02_operation_id, source_ref,
        parent_budget_lease_ref, issuer, installed_bundle, now_utc, deadline_utc):
    from ..host.authority_profile import AdminInstallationBundle, AdminModelWorkflowV2, AdminPrivateReplyDispatchPolicy
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..memory_types import source_key
    from ..graph_types import AtomKey
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    if not db.in_transaction or type(issuer) is not D11BudgetJobIssuer or type(installed_bundle) is not AdminInstallationBundle:
        raise MissingProductionOriginalV1("actual_installed_foreground_reply_allocation_bundle")
    policy = installed_bundle.installation_policy
    generation, review = installed_bundle.model_workflows.natural_generation, installed_bundle.model_workflows.natural_review
    message = installed_bundle.private_reply_dispatch
    if (type(generation) is not AdminModelWorkflowV2 or type(review) is not AdminModelWorkflowV2
            or type(message) is not AdminPrivateReplyDispatchPolicy):
        raise MissingProductionOriginalV1("actual_installed_generation_review_and_message_quotes")
    root = issuer.current_budget_grant(db, parent_budget_lease_ref)
    parent = get_budget_lease(db, parent_budget_lease_ref)
    source = AtomKey.from_token(source_ref)
    if (namespace != policy.namespace or source != source_key(*namespace.as_tuple, source.owner.subject)
            or parent_budget_lease_ref != policy.root_lease.lease_id or root != policy.root_grant
            or (parent.parent_id, parent.bot_id, parent.persona_id, parent.currency, parent.limits) !=
                (policy.root_lease.parent_id, *namespace.as_tuple, policy.root_lease.currency, policy.root_lease.limits)
            or parent.state != "active" or "d11.foreground_cycle.v1" not in root.allowed_work_kinds
            or not set(REPLY_KINDS) <= set(root.allowed_work_kinds)
            or (generation.work_kind, review.work_kind) != REPLY_KINDS[:2]):
        raise ValueError("foreground reply allocation exceeds its actual installed root identity/permissions")
    require_budget_family_admissible(db, parent.lease_id)
    quotes = tuple(map(dict, (generation.quote_ceiling, review.quote_ceiling, message.quote_ceiling)))
    if any(set(quote) != MODEL_DIMENSIONS for quote in quotes[:2]):
        raise MissingProductionOriginalV1("complete_registered_foreground_model_cost_dimensions")
    dimensions = set().union(*quotes)
    if not dimensions <= set(parent.limits) or not dimensions <= set(root.max_ceiling):
        raise ValueError("installed foreground quotes contain a cost dimension outside the actual root grant")
    total = {name: quotes[0].get(name, 0) + quotes[1].get(name, 0) + 4 * quotes[2].get(name, 0) for name in dimensions}
    maximum = {name: max(quote.get(name, 0) for quote in quotes) for name in dimensions}
    if any(total[name] > parent.available(name) or maximum[name] > root.max_ceiling[name] for name in dimensions):
        raise MissingProductionOriginalV1("actual_parent_availability_and_original_per_quote_reply_caps")
    until = min(deadline_utc, root.valid_until_utc)
    if not now_utc < until:
        raise MissingProductionOriginalV1("unexpired_original_foreground_reply_deadline")
    child_id, grant_id, operation_id = foreground_reply_budget_ids_v1(namespace, c02_operation_id)
    allocation = ForegroundReplyAllocationV1(namespace, c02_operation_id, policy.installation_id, policy.manifest_digest,
        parent.lease_id, parent.version, canonical_digest(parent), canonical_digest(root),
        canonical_digest(plain_v1(generation)), canonical_digest(plain_v1(review)), canonical_digest(plain_v1(message)),
        child_id, grant_id, operation_id, parent.currency, ALLOCATION_POLICY, until,
        *(_amount_tuple_v1(quote) for quote in quotes), _amount_tuple_v1(total), _amount_tuple_v1(maximum))
    _require_absent_reply_allocation_v1(db, allocation)
    return allocation


def apply_foreground_reply_allocation_v1(db, *, allocation, issuer):
    if not db.in_transaction or type(allocation) is not ForegroundReplyAllocationV1 or type(issuer) is not D11BudgetJobIssuer:
        raise TypeError("foreground reply application requires its exact private W01 stage allocation and installed issuer")
    parent = get_budget_lease(db, allocation.parent_lease_ref)
    root = issuer.current_budget_grant(db, parent.lease_id)
    if parent.version != allocation.parent_version or canonical_digest(parent) != allocation.parent_state_digest or canonical_digest(root) != allocation.parent_grant_digest:
        raise ValueError("foreground reply allocation original parent/grant changed before actual atomic application")
    require_budget_family_admissible(db, parent.lease_id)
    _require_absent_reply_allocation_v1(db, allocation)
    receipt = create_budget_lease(db, allocation.child_lease(), allocation.allocation_operation_id, allocation.digest)
    issuer.issue_budget_grant(db, allocation.child_grant())
    actual = get_budget_lease(db, allocation.child_lease_id)
    after = get_budget_lease(db, parent.lease_id)
    expected_reserved = dict(parent.reserved)
    for name, amount in allocation.child_limits:
        expected_reserved[name] = expected_reserved.get(name, 0) + amount
    expected_parent = replace(parent, reserved=expected_reserved, version=parent.version + 1)
    if (receipt.status != "created" or receipt.lease_id != allocation.child_lease_id or receipt.digest != allocation.digest
            or actual != allocation.child_lease() or after != expected_parent
            or issuer.current_budget_grant(db, allocation.child_lease_id) != allocation.child_grant()):
        raise ValueError("foreground actual child/grant/creation receipt/ancestor encumbrance differs from its pure allocation")
    return actual, issuer.current_budget_grant(db, allocation.child_lease_id)


def _read_actual_reply_allocation_v1(db, *, namespace, c02_operation_id, source_ref, issuer):
    from .foreground_cycle_v1 import foreground_cycle_ids_v1, foreground_cycle_from_wire_v1
    from .d11_types import runtime_job_key, job_graph_write
    from .jobs import get_job
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    import json
    activity_id, job_id = foreground_cycle_ids_v1(namespace, c02_operation_id)
    job = get_job(db, job_id)
    continuation = foreground_cycle_from_wire_v1(job.continuation)
    key = runtime_job_key(*namespace.as_tuple, activity_id, job_id)
    atom = db.execute("SELECT value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
        (*namespace.as_tuple, key.token)).fetchone()
    if (atom is None or atom[1] != 1 or json.loads(atom[0]) != job_graph_write(job).value
            or (job.bot_id, job.persona_id, job.activity_id, job.work_kind) !=
                (*namespace.as_tuple, activity_id, "d11.foreground_cycle.v1")
            or continuation.c02_operation_id != c02_operation_id or continuation.source_ref != source_ref):
        raise ValueError("foreground protected budget lost its actual SQL/Graph C02/cycle/Source identity")
    original = read_adopted_domain_operation_v1(db, namespace, job.operation_id)
    if (original is None or original["domain"] != "d11" or original["operation_kind"] != "create_foreground_cycle"
            or original["payload"]["request"]["c02_operation_id"] != c02_operation_id
            or original["payload"]["request"]["source_ref"] != source_ref):
        raise ValueError("foreground reply budget has no actual Source-bound shared cycle creation original")
    provenance = original["payload"]["provenance"]
    if set(provenance) != {"before_job", "after_job", "reply_allocation"} or provenance["before_job"] is not None:
        raise ValueError("legacy/missing foreground reply allocation cannot authorize new protected work")
    allocation = decode_typed_production_value_v1(provenance["reply_allocation"], ForegroundReplyAllocationV1)
    if (allocation.namespace != namespace or allocation.c02_operation_id != c02_operation_id
            or allocation.parent_lease_ref != job.budget_ref
            or allocation.child_lease_id != continuation.call_plan.protected_reply_lease_ref
            or original["payload"]["request"]["protected_reply_lease_ref"] != allocation.child_lease_id
            or provenance["after_job"]["budget_ref"] != allocation.parent_lease_ref):
        raise ValueError("foreground allocation original borrowed another actual cycle/parent/child")
    row = db.execute("SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='create'",
        (*namespace.as_tuple, allocation.allocation_operation_id)).fetchone()
    if row is None or row[:2] != (allocation.digest, allocation.child_lease_id):
        raise ValueError("foreground reply allocation lost its actual existing budget creation receipt")
    from .budget import BudgetReceipt
    receipt = BudgetReceipt(**json.loads(row[2]))
    if (receipt.status, receipt.operation_id, receipt.digest, receipt.lease_id, receipt.version,
            dict(receipt.used), dict(receipt.reserved), dict(receipt.unconfirmed)) != (
            "created", allocation.allocation_operation_id, allocation.digest, allocation.child_lease_id, 1, {}, {}, {}):
        raise ValueError("foreground reply original creation receipt differs from the actual untouched child creation")
    child = get_budget_lease(db, allocation.child_lease_id)
    grant = issuer.current_budget_grant(db, child.lease_id)
    if ((child.parent_id, child.bot_id, child.persona_id, child.currency, child.limits) !=
            (allocation.parent_lease_ref, *namespace.as_tuple, allocation.currency, dict(allocation.child_limits))
            or grant != allocation.child_grant()):
        raise ValueError("foreground current actual child/grant differs from its immutable allocation original")
    return job, allocation, child, grant


def resolve_current_foreground_reply_budget_v1(db, *, namespace, c02_operation_id, source_ref,
        issuer, installed_bundle, now_utc):
    from ..host.authority_profile import AdminInstallationBundle
    from ..domains.d01.production_operations_v1 import plain_v1
    from .jobs import _utc
    if not db.in_transaction or type(namespace) is not NamespaceId or type(issuer) is not D11BudgetJobIssuer or type(installed_bundle) is not AdminInstallationBundle:
        raise TypeError("foreground reply resolver requires the actual current SQL/issuer/installed bundle")
    job, allocation, child, grant = _read_actual_reply_allocation_v1(db, namespace=namespace,
        c02_operation_id=c02_operation_id, source_ref=source_ref, issuer=issuer)
    policy = installed_bundle.installation_policy
    root = issuer.current_budget_grant(db, allocation.parent_lease_ref)
    parent = get_budget_lease(db, allocation.parent_lease_ref)
    if (root != policy.root_grant or allocation.parent_lease_ref != policy.root_lease.lease_id
            or canonical_digest(root) != allocation.parent_grant_digest
            or (parent.parent_id, parent.bot_id, parent.persona_id, parent.currency, parent.limits) !=
                (policy.root_lease.parent_id, *namespace.as_tuple, policy.root_lease.currency, policy.root_lease.limits)
            or (allocation.installation_id, allocation.manifest_digest) != (policy.installation_id, policy.manifest_digest)
            or allocation.generation_workflow_digest != canonical_digest(plain_v1(installed_bundle.model_workflows.natural_generation))
            or allocation.review_workflow_digest != canonical_digest(plain_v1(installed_bundle.model_workflows.natural_review))
            or allocation.message_policy_digest != canonical_digest(plain_v1(installed_bundle.private_reply_dispatch))
            or not set(grant.allowed_work_kinds) <= set(root.allowed_work_kinds)
            or "d11.foreground_cycle.v1" not in root.allowed_work_kinds
            or any(amount > root.max_ceiling.get(name, 0) for name, amount in grant.max_ceiling.items())):
        raise ValueError("foreground protected budget no longer matches its actual signed installed root and original quote policies")
    if (job.phase in {"completed", "failed", "cancelled", "draining", "pending_confirmation"} or job.cancel_epoch
            or parent.state != "active" or child.state != "active"
            or not now_utc < min(grant.valid_until_utc, root.valid_until_utc, _utc(job.deadline_utc, "deadline_utc").timestamp())):
        raise ValueError("foreground protected budget cannot authorize new work after its original control/deadline ends")
    require_budget_family_admissible(db, child.lease_id)
    return child, grant


@dataclass(frozen=True, slots=True)
class ForegroundModelAttemptV1:
    slot: str
    call_id: str
    original_call_id: str | None
    reservation_operation_id: str
    reservation_digest: str
    budget_lease_ref: str
    input_ceiling: int
    output_ceiling: int
    state: str
    terminal_ref: str | None = None

    def __post_init__(self):
        if self.slot not in SLOTS or self.state not in {"reserved", "dispatch_started", "completed", "unknown", "not_dispatched"}:
            raise ValueError("foreground attempt purpose/state is unregistered")
        if any(type(value) is not str or not value for value in
                (self.call_id, self.reservation_operation_id, self.reservation_digest, self.budget_lease_ref)):
            raise ValueError("foreground attempt requires its actual call/reservation identity")
        _, maximum_input, maximum_output, _ = SLOTS[self.slot]
        if (type(self.input_ceiling) is not int or not 0 <= self.input_ceiling <= maximum_input
                or type(self.output_ceiling) is not int or not 0 <= self.output_ceiling <= maximum_output):
            raise ValueError("foreground request exceeds its registered slot ceiling")
        if self.original_call_id == self.call_id:
            raise ValueError("a retry must retain a distinct original call identity")
        if self.state == "completed" and self.terminal_ref is None:
            raise ValueError("completed attempt needs its durable original terminal")


@dataclass(frozen=True, slots=True)
class ForegroundCallPlanV1:
    parent_budget_lease_ref: str
    protected_reply_lease_ref: str
    attempts: tuple[ForegroundModelAttemptV1, ...] = ()
    schema: str = SCHEMA

    def __post_init__(self):
        if (self.schema != SCHEMA or not self.parent_budget_lease_ref or not self.protected_reply_lease_ref
                or type(self.attempts) is not tuple or len(self.attempts) > 6
                or any(type(row) is not ForegroundModelAttemptV1 for row in self.attempts)
                or len({row.call_id for row in self.attempts}) != len(self.attempts)
                or sum(SLOTS[row.slot][3] for row in self.attempts) > 2
                or sum(row.original_call_id is not None for row in self.attempts) > 2
                or sum(row.input_ceiling for row in self.attempts) > 48000
                or sum(row.output_ceiling for row in self.attempts) > 8000):
            raise ValueError("foreground attempts exceed the original finite call plan")
        indexed = {row.call_id: row for row in self.attempts}
        for row in self.attempts:
            if row.original_call_id is not None:
                original = indexed.get(row.original_call_id)
                if original is None or original.slot != row.slot or original.state != "not_dispatched":
                    raise ValueError("retry requires its known unstarted original; UNKNOWN never authorizes retry")
        if len(canonical_serialize(self).encode("utf-8")) > 65536:
            raise ValueError("call plan exceeds its continuation metadata limit")


def foreground_call_plan_from_wire_v1(value):
    if type(value) is not dict or set(value) != set(ForegroundCallPlanV1.__dataclass_fields__):
        raise ValueError("foreground call plan fields differ")
    raw = dict(value)
    raw["attempts"] = tuple(ForegroundModelAttemptV1(**row) for row in raw["attempts"])
    return ForegroundCallPlanV1(**raw)



SCHEMA_V2 = "d11.foreground-call-plan.v2"
PHASE_GROUP_SCHEMA_V2 = "d11.foreground-artifact-phase-group.v2"


def foreground_artifact_phase_group_identity_v2(selector):
    if type(selector) is not ArtifactDraftPhaseSelectorV2:
        raise TypeError("phase group requires its exact adopted method selector")
    return (selector.task, selector.decision_ref, selector.decision_revision,
        selector.decision_digest, selector.plan_ref, selector.plan_revision,
        selector.plan_digest, selector.method_ref)


@dataclass(frozen=True, slots=True)
class ForegroundArtifactPhaseGroupV2:
    selector: ArtifactDraftPhaseSelectorV2
    completed_phase_originals: tuple[tuple[str, str], ...] = ()
    schema: str = PHASE_GROUP_SCHEMA_V2

    def __post_init__(self):
        if self.schema != PHASE_GROUP_SCHEMA_V2 or type(self.selector) is not ArtifactDraftPhaseSelectorV2:
            raise TypeError("phase group requires its exact current adopted selector")
        selector = self.selector
        phases = artifact_draft_phase_sequence_v2(selector.method_ref)
        completed = self.completed_phase_originals
        if (type(completed) is not tuple or len(completed) not in {selector.phase_index, selector.phase_index + 1}
                or len(completed) > len(phases)
                or any(type(row) is not tuple or len(row) != 2 or type(row[0]) is not str
                    or type(row[1]) is not str or len(row[1]) != 64
                    or any(ch not in "0123456789abcdef" for ch in row[1]) for row in completed)):
            raise ValueError("phase group requires its exact verified original prefix")
        previous = completed[selector.phase_index - 1] if selector.phase_index else (None, None)
        if (selector.prev_phase_original_ref, selector.prev_phase_original_digest) != previous:
            raise ValueError("phase selector lost its exact immediately preceding verification")
        for index, (ref, _digest) in enumerate(completed):
            prior = completed[index - 1] if index else (None, None)
            phase = replace(selector, phase_index=index, phase_kind=phases[index],
                prev_phase_original_ref=prior[0], prev_phase_original_digest=prior[1])
            if ref != artifact_draft_phase_original_ref_v2(phase) + ":verified":
                raise ValueError("phase group changed its fixed ordered verification identity")

    @property
    def identity_digest(self):
        return canonical_digest((PHASE_GROUP_SCHEMA_V2, foreground_artifact_phase_group_identity_v2(self.selector)))


@dataclass(frozen=True, slots=True, kw_only=True)
class ForegroundModelAttemptV2(ForegroundModelAttemptV1):
    phase_selector: ArtifactDraftPhaseSelectorV2

    def __post_init__(self):
        ForegroundModelAttemptV1.__post_init__(self)
        if self.slot != "C4" or type(self.phase_selector) is not ArtifactDraftPhaseSelectorV2:
            raise TypeError("phase model attempt requires its exact C4 generation selector")
        ids = artifact_draft_model_ids_v2(self.phase_selector)
        limits = artifact_draft_phase_token_limits_v2(self.phase_selector)
        if (self.call_id != ids["call"] or self.reservation_operation_id != ids["prepare"]
                or self.original_call_id is not None or self.input_ceiling > limits["input_tokens"]
                or self.output_ceiling > limits["output_tokens"]
                or self.terminal_ref is not None and self.terminal_ref != ids["result"]):
            raise ValueError("phase call changed its original identity or installed finite slot caps")


@dataclass(frozen=True, slots=True, kw_only=True)
class ForegroundCallPlanV2(ForegroundCallPlanV1):
    phase_group: ForegroundArtifactPhaseGroupV2
    schema: str = SCHEMA_V2

    def __post_init__(self):
        if (self.schema != SCHEMA_V2 or not self.parent_budget_lease_ref or not self.protected_reply_lease_ref
                or type(self.phase_group) is not ForegroundArtifactPhaseGroupV2
                or type(self.attempts) is not tuple or len(self.attempts) > 6
                or any(type(row) not in {ForegroundModelAttemptV1, ForegroundModelAttemptV2} for row in self.attempts)
                or len({row.call_id for row in self.attempts}) != len(self.attempts)
                or sum(SLOTS[row.slot][3] for row in self.attempts) > 2
                or sum(row.original_call_id is not None for row in self.attempts) > 2
                or sum(row.input_ceiling for row in self.attempts) > 48000
                or sum(row.output_ceiling for row in self.attempts) > 8000):
            raise ValueError("phase calls exceed the unchanged original physical call plan")
        selector = self.phase_group.selector
        phases = artifact_draft_phase_sequence_v2(selector.method_ref)
        if phases[0] == "tone_sample" and any(row.slot == "C3" for row in self.attempts):
            raise ValueError("tone sample route cannot add two C4 calls to an existing C3")
        indexed = {row.call_id: row for row in self.attempts}
        seen_phases = set()
        for row in self.attempts:
            if row.slot == "C4":
                if (type(row) is not ForegroundModelAttemptV2
                        or foreground_artifact_phase_group_identity_v2(row.phase_selector) !=
                            foreground_artifact_phase_group_identity_v2(selector)
                        or row.phase_selector.phase_index > selector.phase_index
                        or row.phase_selector.phase_index in seen_phases):
                    raise ValueError("C4 call does not belong to this unique ordered phase group")
                index = row.phase_selector.phase_index
                seen_phases.add(index)
                prior = self.phase_group.completed_phase_originals[index - 1] if index else (None, None)
                if (row.phase_selector.prev_phase_original_ref, row.phase_selector.prev_phase_original_digest) != prior:
                    raise ValueError("C4 phase call borrowed another prior verification")
                if index and not any(type(previous) is ForegroundModelAttemptV2
                        and previous.phase_selector.phase_index < index and previous.state == "completed"
                        for previous in self.attempts) and phases[0] == "tone_sample":
                    raise ValueError("full phase requires its actual completed sample call")
            elif type(row) is not ForegroundModelAttemptV1:
                raise TypeError("non-C4 slot retains its exact V1 attempt contract")
            if row.original_call_id is not None:
                original = indexed.get(row.original_call_id)
                if original is None or original.slot != row.slot or original.state != "not_dispatched":
                    raise ValueError("retry requires its known unstarted original; UNKNOWN never authorizes retry")
        for index in range(len(self.phase_group.completed_phase_originals)):
            if phases[index] in {"tone_sample", "full"} and not any(
                    type(row) is ForegroundModelAttemptV2 and row.phase_selector.phase_index == index
                    and row.state == "completed" for row in self.attempts):
                raise ValueError("verified generation cannot hide its actual completed physical call")
        if len(canonical_serialize(self).encode("utf-8")) > 65536:
            raise ValueError("phase call plan exceeds its original continuation bound")


def foreground_call_plan_from_wire_v2(value):
    from dataclasses import fields
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(value) is not dict or set(value) != {field.name for field in fields(ForegroundCallPlanV2)}:
        raise ValueError("phase call plan fields differ")
    raw = dict(value)
    group = dict(raw["phase_group"])
    if set(group) != {field.name for field in fields(ForegroundArtifactPhaseGroupV2)}:
        raise ValueError("phase group fields differ")
    group["selector"] = artifact_draft_from_wire_v2(group["selector"], ArtifactDraftPhaseSelectorV2)
    group["completed_phase_originals"] = tuple(tuple(row) for row in group["completed_phase_originals"])
    raw["phase_group"] = ForegroundArtifactPhaseGroupV2(**group)
    attempts = []
    for encoded in raw["attempts"]:
        row = dict(encoded)
        kind = ForegroundModelAttemptV2 if row.get("slot") == "C4" else ForegroundModelAttemptV1
        if set(row) != {field.name for field in fields(kind)}:
            raise ValueError("phase attempt fields differ")
        if kind is ForegroundModelAttemptV2:
            row["phase_selector"] = artifact_draft_from_wire_v2(row["phase_selector"], ArtifactDraftPhaseSelectorV2)
        attempts.append(kind(**row))
    raw["attempts"] = tuple(attempts)
    result = ForegroundCallPlanV2(**raw)
    if plain_v1(result) != value:
        raise ValueError("phase call plan wire is not canonical")
    return result


def require_foreground_phase_checkpoint_v2(before, after):
    if type(after) is not ForegroundCallPlanV2:
        if type(before) is ForegroundCallPlanV2:
            raise ValueError("checkpoint cannot erase its original phase group")
        return
    if type(before) is ForegroundCallPlanV1:
        if (any(row.slot == "C4" for row in before.attempts) or after.phase_group.selector.phase_index
                or after.phase_group.completed_phase_originals):
            raise ValueError("phase group must start at its original first phase without replacing a C4")
        return
    if type(before) is not ForegroundCallPlanV2:
        raise TypeError("unregistered foreground phase plan")
    old, current = before.phase_group, after.phase_group
    if (old.identity_digest != current.identity_digest
            or current.selector.phase_index not in {old.selector.phase_index, old.selector.phase_index + 1}
            or current.completed_phase_originals[:len(old.completed_phase_originals)] != old.completed_phase_originals
            or len(current.completed_phase_originals) > len(old.completed_phase_originals) + 1):
        raise ValueError("checkpoint cannot replace, regress or skip its verified phase prefix")
    previous = {row.call_id: row for row in after.attempts}
    for row in before.attempts:
        if type(row) is ForegroundModelAttemptV2:
            actual = previous.get(row.call_id)
            if type(actual) is not ForegroundModelAttemptV2 or actual.phase_selector != row.phase_selector:
                raise ValueError("checkpoint cannot replace an existing phase call identity")


def register_foreground_model_attempt_v2(db, *, namespace, plan, attempt, issuer, now_utc, installed_bundle=None, owner_guard=None):
    if type(plan) is not ForegroundCallPlanV2 or type(attempt) not in {ForegroundModelAttemptV1, ForegroundModelAttemptV2}:
        raise TypeError("registered phase plan and physical attempt required")
    if attempt.slot == "C4" and (type(attempt) is not ForegroundModelAttemptV2
            or attempt.phase_selector != plan.phase_group.selector):
        raise ValueError("only the exact current generation phase can reserve its original C4")
    previous = next((row for row in plan.attempts if row.call_id == attempt.call_id), None)
    if previous is not None:
        if previous != attempt:
            raise ValueError("call replay changed the original phase attempt")
        return plan
    projected = replace(plan, attempts=(*plan.attempts, attempt))
    require_protected_reply_budget_v1(db, namespace=namespace, plan=projected, issuer=issuer, now_utc=now_utc,
        installed_bundle=installed_bundle, owner_guard=owner_guard)
    if attempt.slot == "C6" and not any(row.slot == "C5" and row.state == "completed" for row in plan.attempts):
        raise ValueError("independent review requires the exact completed generation original")
    expected_lease = plan.protected_reply_lease_ref if attempt.slot in {"C5", "C6"} else plan.parent_budget_lease_ref
    if attempt.budget_lease_ref != expected_lease or attempt.state != "reserved":
        raise ValueError("phase call uses another bucket or pretends it already ran")
    reservation = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (attempt.budget_lease_ref, attempt.reservation_operation_id)).fetchone()
    if reservation is None or reservation[0] != attempt.reservation_digest or reservation[2] != "reserved":
        raise ValueError("phase call lacks its actual original D11 reservation")
    import json
    ceiling = json.loads(reservation[1])
    if ceiling.get("input_tokens", 0) < attempt.input_ceiling or ceiling.get("output_tokens", 0) < attempt.output_ceiling:
        raise ValueError("phase call ceiling exceeds its original reserved quantities")
    grant = issuer.current_budget_grant(db, attempt.budget_lease_ref)
    if SLOTS[attempt.slot][0] not in grant.allowed_work_kinds or now_utc >= grant.valid_until_utc:
        raise ValueError("phase call purpose is outside the original signed grant")
    return projected


def require_protected_reply_budget_v1(db, *, namespace, plan, issuer, now_utc, installed_bundle=None, owner_guard=None):
    """Read the real ancestor encumbrance; a planned cap is not an allocation."""
    if type(namespace) is not NamespaceId or type(issuer) is not D11BudgetJobIssuer or type(plan) not in {ForegroundCallPlanV1, ForegroundCallPlanV2}:
        raise TypeError("protected reply needs the actual installed budget reader")
    if type(plan) is ForegroundCallPlanV2:
        from .d11_artifact_draft_model_v1 import require_current_artifact_phase_group_v2
        if require_current_artifact_phase_group_v2(db, namespace=namespace, group=plan.phase_group, issuer=issuer,
                installed_bundle=installed_bundle, owner_guard=owner_guard) != plan.phase_group:
            raise ValueError("phase budget lost its actual current adopted group")
    parent = get_budget_lease(db, plan.parent_budget_lease_ref)
    protected = get_budget_lease(db, plan.protected_reply_lease_ref)
    grant = issuer.current_budget_grant(db, protected.lease_id)
    if (protected.parent_id != parent.lease_id or protected.state != "active"
            or (protected.bot_id, protected.persona_id) != namespace.as_tuple
            or grant.valid_until_utc <= now_utc
            or not {SLOTS["C5"][0], SLOTS["C6"][0]} <= set(grant.allowed_work_kinds)):
        raise ValueError("reply allocation is not an actual current child of this root budget")
    require_budget_family_admissible(db, protected.lease_id)
    from .jobs import get_job
    row = db.execute("SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? AND work_kind='d11.foreground_cycle.v1' "
        "AND json_extract(continuation_json,'$.call_plan.protected_reply_lease_ref')=? LIMIT 2",
        (*namespace.as_tuple, protected.lease_id)).fetchall()
    if len(row) != 1:
        raise ValueError("protected reply lease requires its unique actual registered foreground cycle")
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1, read_observed_foreground_call_plan_v1
    continuation = foreground_cycle_from_wire_v1(get_job(db, row[0][0]).continuation)
    _, allocation, actual_child, actual_grant = _read_actual_reply_allocation_v1(db, namespace=namespace,
        c02_operation_id=continuation.c02_operation_id, source_ref=continuation.source_ref, issuer=issuer)
    if (actual_child, actual_grant) != (protected, grant):
        raise ValueError("foreground protected budget differs from its actual original allocation")
    root_grant = issuer.current_budget_grant(db, parent.lease_id)
    if canonical_digest(root_grant) != allocation.parent_grant_digest:
        raise ValueError("foreground protected allocation original root grant is no longer current")
    observed = read_observed_foreground_call_plan_v1(db, namespace=namespace,
        continuation=replace(continuation, call_plan=plan), issuer=issuer,
        installed_bundle=installed_bundle, owner_guard=owner_guard)
    remaining = {slot for slot in ("C5", "C6") if not any(row.slot == slot and row.state in
        {"reserved", "dispatch_started", "completed", "unknown"} for row in observed.attempts)}
    quotes = {"C5": dict(allocation.generation_ceiling), "C6": dict(allocation.review_ceiling)}
    required = {name: sum(quotes[slot].get(name, 0) for slot in remaining)
        for name in set().union(*(set(quote) for quote in quotes.values()))}
    if any(protected.available(name) < amount for name, amount in required.items()):
        raise ValueError("optional work cannot consume required generation/review capacity")
    return protected, grant


def register_foreground_model_attempt_v1(db, *, namespace, plan, attempt, issuer, now_utc, installed_bundle=None, owner_guard=None):
    """Link a real reservation, once. This never reserves or settles a bucket."""
    if type(attempt) is not ForegroundModelAttemptV1:
        raise TypeError("actual typed model attempt required")
    previous = next((row for row in plan.attempts if row.call_id == attempt.call_id), None)
    if previous is not None:
        if previous != attempt:
            raise ValueError("call replay changed the original attempt")
        return plan
    projected = replace(plan, attempts=(*plan.attempts, attempt))
    require_protected_reply_budget_v1(db, namespace=namespace, plan=projected, issuer=issuer, now_utc=now_utc,
        installed_bundle=installed_bundle, owner_guard=owner_guard)
    if attempt.slot == "C6" and not any(row.slot == "C5" and row.state == "completed" for row in plan.attempts):
        raise ValueError("independent review requires the exact completed generation original")
    expected_lease = plan.protected_reply_lease_ref if attempt.slot in {"C5", "C6"} else plan.parent_budget_lease_ref
    if attempt.budget_lease_ref != expected_lease or attempt.state != "reserved":
        raise ValueError("foreground call uses another bucket or pretends it already ran")
    reservation = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (attempt.budget_lease_ref, attempt.reservation_operation_id)).fetchone()
    if reservation is None or reservation[0] != attempt.reservation_digest or reservation[2] != "reserved":
        raise ValueError("model attempt lacks its actual D11 reservation")
    import json
    ceiling = json.loads(reservation[1])
    if ceiling.get("input_tokens", 0) < attempt.input_ceiling or ceiling.get("output_tokens", 0) < attempt.output_ceiling:
        raise ValueError("call ceiling exceeds its existing reserved token quantities")
    grant = issuer.current_budget_grant(db, attempt.budget_lease_ref)
    if SLOTS[attempt.slot][0] not in grant.allowed_work_kinds or now_utc >= grant.valid_until_utc:
        raise ValueError("call purpose is outside the original signed budget grant")
    return projected


def observe_foreground_model_attempt_v1(plan, *, call_id, state, terminal_ref):
    """Pure continuation update after the installed caller verifies its original."""
    if state not in {"dispatch_started", "completed", "unknown", "not_dispatched"}:
        raise ValueError("unregistered model observation state")
    original = next(row for row in plan.attempts if row.call_id == call_id)
    transitions = {"reserved": {"dispatch_started", "not_dispatched", "unknown"},
        "dispatch_started": {"completed", "unknown"}, "unknown": {"unknown", "completed"},
        "completed": {"completed"}, "not_dispatched": {"not_dispatched"}}
    if state not in transitions[original.state] or original.terminal_ref is not None and terminal_ref != original.terminal_ref:
        raise ValueError("model observation cannot regress or replace its actual original")
    updated = replace(original, state=state, terminal_ref=terminal_ref)
    return replace(plan, attempts=tuple(updated if row.call_id == call_id else row for row in plan.attempts))


@dataclass(frozen=True, slots=True, kw_only=True, weakref_slot=True)
class NamedC3ParentageDescriptorV3:
    """Small relation data; its observer issuer supplies the actual authority."""
    namespace: NamespaceId
    kind: str
    operation_id: str
    job_id: str
    call_id: str
    semantic_question_ref: str
    semantic_question_digest: str
    cycle_ref: GraphVersion
    cycle_digest: str
    call_plan_digest: str
    c02_operation_id: str
    cancel_generation: int
    prepared_digest: str
    proposal_head: GraphVersion | None = None
    proposal_digest: str | None = None
    source_head: GraphVersion | None = None
    source_digest: str | None = None
    parent_budget_lease_ref: str | None = None
    original_deadline_utc: float | None = None
    reflection_request_ref: str | None = None
    reflection_request_digest: str | None = None
    reflection_continuation_ref: str | None = None
    reflection_continuation_digest: str | None = None
    parent_prepared_ref: str | None = None
    parent_prepared_digest: str | None = None
    parent_execution_ref: str | None = None
    parent_execution_digest: str | None = None
    checkpoint_ref: GraphVersion | None = None
    checkpoint_digest: str | None = None
    parent_grant_digest: str | None = None

    def __post_init__(self):
        from math import isfinite
        if (type(self.namespace) is not NamespaceId or self.kind not in ('relationship', 'growth', 'reflection')
                or type(self.cycle_ref) is not GraphVersion or self.cycle_ref.revision < 1
                or self.cycle_ref.key.type_name != 'runtime.job'
                or NamespaceId.from_key(self.cycle_ref.key) != self.namespace
                or type(self.cancel_generation) is not int or self.cancel_generation < 0):
            raise ValueError('named C3 relation requires its exact namespace/cycle/kind/cancel identity')
        for value in (self.operation_id, self.job_id, self.call_id,
                self.c02_operation_id):
            if type(value) is not str or not value:
                raise ValueError('named C3 relation lost an actual original identity')
        if self.kind!="reflection" and (type(self.semantic_question_ref) is not str or not self.semantic_question_ref):
            raise ValueError("named C3 retains its exact semantic original locator")
        digests = (self.semantic_question_digest, self.cycle_digest,
                   self.call_plan_digest, self.prepared_digest)
        extras = (self.proposal_head, self.proposal_digest, self.source_head,
                  self.source_digest, self.parent_budget_lease_ref, self.original_deadline_utc)
        reflection_fields=(self.reflection_request_ref,self.reflection_request_digest,self.reflection_continuation_ref,
            self.reflection_continuation_digest,self.parent_prepared_ref,self.parent_prepared_digest,
            self.parent_execution_ref,self.parent_execution_digest,self.checkpoint_ref,self.checkpoint_digest,self.parent_grant_digest)
        if self.kind == "reflection":
            if (any(value is None for value in reflection_fields) or self.semantic_question_ref is not None
                    or self.semantic_question_digest is not None or any(value is not None for value in extras[:4])
                    or type(self.checkpoint_ref) is not GraphVersion or self.checkpoint_ref.revision<1
                    or self.checkpoint_ref.key.type_name!="d07.reflection_checkpoint.v1"
                    or NamespaceId.from_key(self.checkpoint_ref.key)!=self.namespace
                    or not self.parent_budget_lease_ref or type(self.original_deadline_utc) not in (int,float)
                    or not isfinite(self.original_deadline_utc)):
                raise ValueError("reflection C3 requires only its exact original parentage fields")
            digests=(self.cycle_digest,self.call_plan_digest,self.prepared_digest,self.reflection_request_digest,
                self.reflection_continuation_digest,self.parent_prepared_digest,self.parent_execution_digest,
                self.checkpoint_digest,self.parent_grant_digest)
        elif self.kind == 'relationship':
            if any(value is not None for value in extras) or any(value is not None for value in reflection_fields):
                raise ValueError('Relationship C3 cannot borrow Growth provenance')
        else:
            if any(value is not None for value in reflection_fields):
                raise ValueError("growth C3 cannot borrow reflection provenance")
            from ..domains.d01.method_learning_v1 import TRIAL_PROPOSAL_TYPE_V2
            for head, type_name in ((self.proposal_head, TRIAL_PROPOSAL_TYPE_V2),
                                    (self.source_head, 'memory.source')):
                if (type(head) is not GraphVersion or head.revision < 1
                        or head.key.type_name != type_name
                        or NamespaceId.from_key(head.key) != self.namespace):
                    raise ValueError('growth C3 relation lost its actual proposal/Source head')
            if (type(self.parent_budget_lease_ref) is not str or not self.parent_budget_lease_ref
                    or type(self.original_deadline_utc) not in (int, float)
                    or not isfinite(self.original_deadline_utc)):
                raise ValueError('growth C3 relation lost its actual paying lease/original deadline')
            digests = (*digests, self.proposal_digest, self.source_digest)
        if any(type(value) is not str or len(value) != 64
                or any(ch not in '0123456789abcdef' for ch in value) for value in digests):
            raise ValueError('named C3 relation lost an exact original commitment')


def _named_c3_descriptor_from_prepared_v3(prepared, namespace):
    from .d07_execution_v1 import D07RelationshipPreparedV2, D07ReflectionPreparedV3
    from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
    if type(prepared) is D07ReflectionPreparedV3:
        if prepared.cycle_ref is None or prepared.namespace!=namespace:
            raise TypeError("ordinary reflection is not a Self C3 parent")
        names=("reflection_request_ref","reflection_request_digest","reflection_continuation_ref",
            "reflection_continuation_digest","parent_prepared_ref","parent_prepared_digest","parent_execution_ref",
            "parent_execution_digest","checkpoint_ref","checkpoint_digest","parent_grant_digest")
        return NamedC3ParentageDescriptorV3(namespace=namespace,kind="reflection",operation_id=prepared.operation_id,
            job_id=prepared.job_id,call_id=prepared.call_id,semantic_question_ref=None,semantic_question_digest=None,
            cycle_ref=prepared.cycle_ref,cycle_digest=prepared.cycle_digest,call_plan_digest=prepared.call_plan_digest,
            c02_operation_id=prepared.c02_operation_id,cancel_generation=prepared.cancel_generation,
            prepared_digest=prepared.digest,parent_budget_lease_ref=prepared.parent_budget_lease_ref,
            original_deadline_utc=prepared.original_deadline_utc,**{name:getattr(prepared,name) for name in names})
    if type(prepared) not in {D07RelationshipPreparedV2, D07MethodGrowthPreparedV2} or prepared.namespace != namespace:
        raise TypeError('actual signed Relationship C3 preparation required')
    growth = type(prepared) is D07MethodGrowthPreparedV2
    return NamedC3ParentageDescriptorV3(namespace=namespace, kind='growth' if growth else 'relationship',
        operation_id=prepared.operation_id, job_id=prepared.job_id, call_id=prepared.call_id,
        semantic_question_ref=prepared.semantic_question_ref,
        semantic_question_digest=prepared.semantic_question_digest, cycle_ref=prepared.cycle_ref,
        cycle_digest=prepared.cycle_digest, call_plan_digest=prepared.call_plan_digest,
        c02_operation_id=prepared.c02_operation_id, cancel_generation=prepared.cancel_generation,
        prepared_digest=prepared.digest,
        proposal_head=prepared.proposal_head if growth else None,
        proposal_digest=prepared.proposal_digest if growth else None,
        source_head=prepared.source_head if growth else None,
        source_digest=prepared.source_digest if growth else None,
        parent_budget_lease_ref=prepared.parent_budget_lease_ref if growth else None,
        original_deadline_utc=prepared.original_deadline_utc if growth else None)


def require_current_named_c3_cycle_v2(db, *, namespace, prepared, issuer):
    """Keep the original exact Prepared producer gate before shared relations."""
    descriptor = _named_c3_descriptor_from_prepared_v3(prepared, namespace)
    return _require_current_named_c3_descriptor_v3(db, namespace=namespace,
        descriptor=descriptor, issuer=issuer)


def require_current_named_c3_parentage_v3(db, *, namespace, parentage, issuer):
    """Accept only the installed observer's actual private D07 original proof."""
    from ..authority_service.model_reply_scope_observation_v3 import require_model_reply_d07_parentage_descriptor_v3
    descriptor = require_model_reply_d07_parentage_descriptor_v3(
        parentage, db=db, namespace=namespace, issuer=issuer)
    return _require_current_named_c3_descriptor_v3(db, namespace=namespace,
        descriptor=descriptor, issuer=issuer)


def _require_current_named_c3_descriptor_v3(db, *, namespace, descriptor, issuer):
    """The unchanged current C3 relation checks, independent of large input DTOs."""
    from .d07_execution_v1 import read_d07_original_v1
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1, _adopted_c02_v1
    from .jobs import get_job
    from .d11_types import job_graph_write
    from .natural_producer_qualification_v1 import _producer_original_point_v3, _producer_json_loads_v3
    from .domain_background_read_v3 import background_verify_signature_v3
    from ..authority_service.model_reply_scope_observation_v3 import (
        read_model_reply_latest_d05_policy_revision_v3, bind_model_reply_growth_question_v3,
        model_reply_scope_canonical_digest_v3)
    if type(descriptor) is not NamedC3ParentageDescriptorV3 or descriptor.namespace != namespace:
        raise TypeError('exact named C3 parentage descriptor required')
    head = _producer_original_point_v3(db, table='graph_atoms', columns=('revision', 'value', 'valid'),
        key_columns=('token',), key=(descriptor.cycle_ref.key.token,),
        legacy_reader=lambda: db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',
            (descriptor.cycle_ref.key.token,)).fetchone())
    job = get_job(db, descriptor.cycle_ref.key.name)
    cycle = foreground_cycle_from_wire_v1(job.continuation)
    head_value = None if head is None else _producer_json_loads_v3(head[1])
    if (head is None or head[2] != 1 or head_value != job_graph_write(job).value
            or cycle.c02_operation_id != descriptor.c02_operation_id or cycle.cancel_generation != descriptor.cancel_generation
            or job.cancel_epoch or cycle.call_plan.parent_budget_lease_ref != get_job(db, descriptor.job_id).budget_ref):
        raise ValueError('Relationship C3 lost its actual current parent/cancel/budget binding')
    _adopted_c02_v1(db, namespace, descriptor.c02_operation_id)
    if descriptor.kind=="reflection":
        from .d07_reflection_execution_v1 import require_reflection_c3_descriptor_v3
        _,lineage=require_reflection_c3_descriptor_v3(db,namespace=namespace,descriptor=descriptor,issuer=issuer)
        if lineage[0]=="birth" and (job.phase not in {"queued","running","waiting"} or cycle.stage=="completed"):
            raise ValueError("reflection cannot revive its closed Self cycle")
        if lineage[0]=="adopted_child" and not any(
                member.call_id==descriptor.call_id for member in cycle.call_plan.attempts):
            raise ValueError("completed reflection requires its original registered C3 member")
    else:
        question = read_d07_original_v1(db, issuer, namespace, 'semantic_question', descriptor.semantic_question_ref)
        if question is None or question[1] != descriptor.semantic_question_digest:
            raise ValueError('Relationship C3 lost its exact signed semantic question')
    from .d07_execution_v1 import read_current_d07_semantic_question_v1, D07RelationshipSemanticQuestionV2
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d05.relationship_revision_v2 import InstalledRelationshipPolicyV2
    semantic = None if descriptor.kind=="reflection" else read_current_d07_semantic_question_v1(db, issuer, namespace, descriptor.semantic_question_ref)
    if descriptor.kind == 'relationship':
        if type(semantic) is not D07RelationshipSemanticQuestionV2:
            raise ValueError('Relationship C3 has another actual prepared semantic kind')
        handled, latest_revision = read_model_reply_latest_d05_policy_revision_v3(db, namespace, semantic.policy_ref)
        if not handled:
            latest = db.execute('SELECT revision FROM graph_d05_production_policies_v1 '
                'WHERE bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC LIMIT 1',
                (*namespace.as_tuple, semantic.policy_ref)).fetchone()
            latest_revision = None if latest is None else latest[0]
        policy = None if latest_revision is None else _producer_original_point_v3(db,
            table='graph_d05_production_policies_v1', columns=('payload_json', 'payload_digest', 'signature', 'revision'),
            key_columns=('bot', 'persona', 'policy_ref', 'revision'),
            key=(*namespace.as_tuple, semantic.policy_ref, latest_revision),
            legacy_reader=lambda: db.execute('SELECT payload_json,payload_digest,signature,revision '
                'FROM graph_d05_production_policies_v1 WHERE bot=? AND persona=? AND policy_ref=? AND revision=?',
                (*namespace.as_tuple, semantic.policy_ref, latest_revision)).fetchone())
        if policy is None or (policy[1], policy[3]) != (semantic.policy_digest, semantic.policy_revision):
            raise ValueError('Relationship C3 installed policy changed since its actual preparation')
        background_verify_signature_v3(issuer._signer, 'd11.d05-production-policy.v2', policy[0], policy[2])
        typed_policy = decode_typed_production_value_v1(_producer_json_loads_v3(policy[0]), InstalledRelationshipPolicyV2)
        from dataclasses import asdict
        if canonical_digest(asdict(typed_policy)) != semantic.policy_digest:
            raise ValueError('Relationship C3 policy lost its canonical signed commitment')
        typed_policy.rule(semantic.scope)
    elif descriptor.kind=="growth":
        from .d07_method_growth_semantic_v2 import D07MethodGrowthSemanticQuestionV2
        from .d07_execution_v1 import require_current_method_growth_question_v2
        if type(semantic) is not D07MethodGrowthSemanticQuestionV2:
            raise ValueError('growth C3 has another actual signed semantic producer kind')
        if (descriptor.proposal_head, descriptor.proposal_digest, descriptor.source_head, descriptor.source_digest,
                descriptor.parent_budget_lease_ref, descriptor.original_deadline_utc) != (
                semantic.proposal_head, semantic.proposal_digest, semantic.source_head, semantic.source_digest,
                semantic.parent_budget_lease_ref, semantic.original_deadline_utc):
            raise ValueError('growth C3 changed its actual already registered proposal/cause/deadline')
        with bind_model_reply_growth_question_v3(db, namespace=namespace, question=semantic,
                original_ref=descriptor.semantic_question_ref, original_digest=descriptor.semantic_question_digest):
            require_current_method_growth_question_v2(db, namespace=namespace, question=semantic, issuer=issuer)
    member = next((row for row in cycle.call_plan.attempts if row.call_id == descriptor.call_id), None)
    if member is None:
        if (head[0] != descriptor.cycle_ref.revision or model_reply_scope_canonical_digest_v3(head[1], head_value) != descriptor.cycle_digest
                or canonical_digest(cycle.call_plan) != descriptor.call_plan_digest):
            raise ValueError('Relationship C3 parent changed before its original pre-call registration')
    else:
        acquire_id = 'd07-acquire:' + canonical_digest((namespace, descriptor.operation_id))[:48]
        row = _producer_original_point_v3(db, table='graph_bundle_operations', columns=('receipt_json',),
            key_columns=('bot', 'persona', 'operation_id'), key=(*namespace.as_tuple, acquire_id),
            legacy_reader=lambda: db.execute('SELECT receipt_json FROM graph_bundle_operations '
                'WHERE bot=? AND persona=? AND operation_id=?', (*namespace.as_tuple, acquire_id)).fetchone())
        if row is None:
            raise ValueError('Relationship C3 plan member lacks its actual pre-call Graph CAS')
        receipt = _producer_json_loads_v3(row[0])
        binding = receipt.get({'relationship':'relationship_c3','growth':'method_growth_c3','reflection':'reflection_c3'}[descriptor.kind])
        if (receipt.get('phase') != 'execution_acquired' or receipt.get('prepared_digest') != descriptor.prepared_digest
                or binding is None or binding != {'cycle_ref': descriptor.cycle_ref.key.token,
                    'before_cycle_digest': descriptor.cycle_digest, 'before_call_plan_digest': descriptor.call_plan_digest,
                    'call_id': descriptor.call_id,
                    ('reflection_request_digest' if descriptor.kind=='reflection' else 'semantic_question_digest'):
                        descriptor.reflection_request_digest if descriptor.kind=='reflection' else descriptor.semantic_question_digest}):
            raise ValueError('Relationship C3 pre-call checkpoint differs from its actual signed preparation')
    return job, cycle, head[0]



def register_current_named_c3_in_transaction_v2(db, *, prepared, issuer, now_utc, installed_bundle, owner_guard):
    from .foreground_cycle_v1 import read_observed_foreground_call_plan_v1
    from .d11_types import job_graph_write
    from ..domains.d01.production_operations_v1 import plain_v1
    job, cycle, revision = require_current_named_c3_cycle_v2(db, namespace=prepared.namespace,
        prepared=prepared, issuer=issuer)
    if any(row.call_id == prepared.call_id for row in cycle.call_plan.attempts):
        raise ValueError("Relationship C3 acquisition cannot register its call twice")
    observed = read_observed_foreground_call_plan_v1(db, namespace=prepared.namespace,
        continuation=cycle, issuer=issuer, installed_bundle=installed_bundle, owner_guard=owner_guard)
    quote = issuer.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
    attempt = ForegroundModelAttemptV1("C3", prepared.call_id, None, prepared.operation_id,
        prepared.reservation_digest, quote.parent_budget_lease_ref,
        quote.ceiling["input_tokens"], quote.ceiling["output_tokens"], "reserved")
    register = register_foreground_model_attempt_v2 if type(observed) is ForegroundCallPlanV2 else register_foreground_model_attempt_v1
    plan = register(db, namespace=prepared.namespace, plan=observed, attempt=attempt, issuer=issuer,
        now_utc=now_utc, installed_bundle=installed_bundle, owner_guard=owner_guard)
    return job_graph_write(replace(job, continuation=plain_v1(replace(cycle, call_plan=plan)))), revision


def read_current_named_c3_attempt_v2(db, *, namespace, continuation, attempt, issuer):
    """Read the actual D07 typed producer; never substitute an IngressRecall original."""
    import json
    from .d07_execution_v1 import (TABLE, D07RelationshipPreparedV2, D07ReflectionPreparedV3, read_prepared_d07_execution_v1,
        read_d07_original_v1, read_original_d07_request_v1, decode_d07_execution_original_v1)
    from .jobs import get_job
    rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='prepared' "
        "AND json_extract(payload_json,'$.call_id')=? LIMIT 2", (*namespace.as_tuple, attempt.call_id)).fetchall()
    if len(rows) != 1:
        raise ValueError("C3 attempt lacks one exact signed D07 preparation")
    prepared = read_prepared_d07_execution_v1(db, issuer, namespace, rows[0][0])
    from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
    if type(prepared) not in {D07RelationshipPreparedV2, D07MethodGrowthPreparedV2, D07ReflectionPreparedV3}:
        raise TypeError("C3 actual producer is not a registered named preparation")
    _, actual_cycle, _ = require_current_named_c3_cycle_v2(db, namespace=namespace, prepared=prepared, issuer=issuer)
    if actual_cycle.c02_operation_id != continuation.c02_operation_id:
        raise ValueError("Relationship C3 attempt belongs to another actual C02 cycle")
    committed = read_d07_original_v1(db, issuer, namespace, "prepare_commit", prepared.job_id)
    if committed is None or committed[0]["prepared_digest"] != prepared.digest:
        raise ValueError("Relationship C3 requires its actual committed preparation")
    quote = issuer.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
    reservation = db.execute("SELECT digest,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (quote.parent_budget_lease_ref, prepared.operation_id)).fetchone()
    base = ForegroundModelAttemptV1("C3", prepared.call_id, None, prepared.operation_id, prepared.reservation_digest,
        quote.parent_budget_lease_ref, quote.ceiling["input_tokens"], quote.ceiling["output_tokens"], "reserved")
    if (replace(attempt, state="reserved", terminal_ref=None) != base or quote.work_kind != "d07.cognition"
            or canonical_digest(quote) != prepared.quote_digest or reservation is None
            or reservation[0] != prepared.reservation_digest):
        raise ValueError("Relationship C3 differs from its actual quote/reservation")
    job = get_job(db, prepared.job_id)
    call = read_original_d07_request_v1(db, issuer, prepared)
    if (job.fence != call.envelope.authority.worker_fence or job.fence < 1
            or job.phase == "running" and job.lease_holder != call.envelope.authority.actor):
        raise ValueError("Relationship C3 worker differs from its actual acquired request")
    sealed = read_d07_original_v1(db, issuer, namespace, "call", job.job_id)
    paid = read_d07_original_v1(db, issuer, namespace, "paid_cost", job.job_id)
    execution = read_d07_original_v1(db, issuer, namespace, "execution", "d07-terminal:" + prepared.call_id)
    state, terminal = "reserved", None
    if sealed is not None:
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        from ..authority_service.v2_model_egress_wire import from_wire
        intent = from_wire(sealed[0], ModelEgressIntentV1)
        if (intent.job_id != job.job_id or intent.call_id != prepared.call_id
                or intent.budget_lease_id != quote.parent_budget_lease_ref or intent.request_digest != call.digest
                or intent.budget_reservation_operation_id != prepared.operation_id or intent.budget_reservation_digest != prepared.reservation_digest):
            raise ValueError("Relationship C3 sealed intent changed its actual call/reservation")
        state = "unknown"
    if execution is not None:
        actual = decode_d07_execution_original_v1(execution[0])
        body = read_d07_original_v1(db, issuer, namespace, "body_cost", job.job_id)
        if (job.phase != "completed" or job.result_ref != actual.terminal_ref or actual.input_digest != prepared.stage_input_digest
                or (actual.operation_id, actual.activity_id, actual.effect_id, actual.execution_id, actual.parent_budget_ref) !=
                   (prepared.operation_id, prepared.activity_id, prepared.effect_id, prepared.execution_id, quote.parent_budget_lease_ref)
                or paid is None or paid[0]["paid"] is not True or paid[0]["unknown_dimensions"]
                or body is None or body[0]["unpaid_cost"] or actual.cost_receipt_refs != (paid[0]["cost_ref"],)):
            raise ValueError("Relationship C3 completed attempt lacks its actual paid/body/terminal originals")
        state, terminal = "completed", actual.terminal_ref
    elif reservation[1] in {"unknown", "partial_unknown", "unconfirmed"} or paid is not None:
        state = "unknown"
    elif job.phase in {"cancelled", "failed"} and sealed is None:
        state = "not_dispatched"
    elif job.phase != "running":
        raise ValueError("Relationship C3 has no actual registered worker state")
    return replace(base, state=state, terminal_ref=terminal)


def require_current_relationship_c3_cycle_v2(db, *, namespace, prepared, issuer):
    from .d07_execution_v1 import D07RelationshipPreparedV2
    if type(prepared) is not D07RelationshipPreparedV2:
        raise TypeError("actual Relationship C3 producer required")
    return require_current_named_c3_cycle_v2(db, namespace=namespace, prepared=prepared, issuer=issuer)


def register_current_relationship_c3_in_transaction_v2(db, *, prepared, issuer, now_utc, installed_bundle, owner_guard):
    from .d07_execution_v1 import D07RelationshipPreparedV2
    if type(prepared) is not D07RelationshipPreparedV2:
        raise TypeError("actual Relationship C3 producer required")
    return register_current_named_c3_in_transaction_v2(db, prepared=prepared, issuer=issuer,
        now_utc=now_utc, installed_bundle=installed_bundle, owner_guard=owner_guard)


def read_current_relationship_c3_attempt_v2(db, *, namespace, continuation, attempt, issuer):
    from .d07_execution_v1 import TABLE, D07RelationshipPreparedV2, read_prepared_d07_execution_v1
    rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='prepared' "
        "AND json_extract(payload_json,'$.call_id')=? LIMIT 2", (*namespace.as_tuple, attempt.call_id)).fetchall()
    if len(rows) != 1 or type(read_prepared_d07_execution_v1(db, issuer, namespace, rows[0][0])) is not D07RelationshipPreparedV2:
        raise TypeError("actual Relationship C3 producer required")
    return read_current_named_c3_attempt_v2(db, namespace=namespace, continuation=continuation, attempt=attempt, issuer=issuer)
