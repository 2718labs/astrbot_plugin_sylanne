"""One installed message quote for an explicitly independent Artifact episode.

Preparation is pure. Only the existing W01 transaction may apply its new child.
The immutable allocation cannot authorize natural generation or review work.
"""
from dataclasses import dataclass, replace
import json
import math

from ..runtime_contracts import NamespaceId, canonical_digest
from ..domains.d01.production_operations_v1 import plain_v1
from .budget import BudgetLease, BudgetReceipt, get_budget_lease, create_budget_lease, require_budget_family_admissible
from .issuers import BudgetLeaseGrant, D11BudgetJobIssuer
from .foreground_call_plan_v1 import _amount_tuple_v1, _validate_amount_tuple_v1

SCHEMA = "d11.foreground-artifact-receipt-allocation.v3"
POLICY = "policy:foreground-artifact-receipt.v3"
WORK_KINDS = ("message",)


def foreground_artifact_receipt_budget_ids_v3(namespace, c02_operation_id):
    if type(namespace) is not NamespaceId or type(c02_operation_id) is not str or not c02_operation_id:
        raise TypeError("Artifact receipt requires its actual namespace and original C02")
    marker = canonical_digest((SCHEMA, namespace, c02_operation_id))[:40]
    return tuple(prefix + marker for prefix in (
        "artifact-receipt-lease:", "artifact-receipt-grant:", "artifact-receipt-create:"))


@dataclass(frozen=True, slots=True)
class ForegroundArtifactReceiptAllocationV3:
    namespace: NamespaceId
    c02_operation_id: str
    source_ref: str
    responsibility_digest: str
    installation_id: str
    manifest_digest: str
    observer_policy_ref: str
    observer_policy_digest: str
    parent_lease_ref: str
    parent_version: int
    parent_state_digest: str
    parent_grant_digest: str
    message_policy_digest: str
    child_lease_id: str
    child_grant_id: str
    allocation_operation_id: str
    currency: str
    valid_until_utc: float
    message_ceiling: tuple[tuple[str, int], ...]
    child_limits: tuple[tuple[str, int], ...]
    child_max_ceiling: tuple[tuple[str, int], ...]
    message_slots: int = 1
    allowed_work_kinds: tuple[str, ...] = WORK_KINDS
    policy_ref: str = POLICY
    schema: str = SCHEMA

    def __post_init__(self):
        from ..graph_types import AtomKey
        key = AtomKey.from_token(self.source_ref)
        if (self.schema != SCHEMA or type(self.namespace) is not NamespaceId
                or self.policy_ref != POLICY or self.allowed_work_kinds != WORK_KINDS
                or type(self.message_slots) is not int or self.message_slots != 1
                or type(self.parent_version) is not int or self.parent_version < 1
                or type(self.valid_until_utc) not in (int, float) or not math.isfinite(self.valid_until_utc)
                or key.type_name != "memory.source" or NamespaceId.from_key(key) != self.namespace
                or type(self.observer_policy_ref) is not str or not self.observer_policy_ref):
            raise ValueError("Artifact receipt allocation differs from its one-message original policy")
        for name in ("responsibility_digest", "manifest_digest", "observer_policy_digest",
                "parent_state_digest", "parent_grant_digest", "message_policy_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError("Artifact receipt requires exact original commitments")
        for values in (self.message_ceiling, self.child_limits, self.child_max_ceiling):
            _validate_amount_tuple_v1(values)
        if self.child_limits != self.message_ceiling or self.child_max_ceiling != self.message_ceiling:
            raise ValueError("Artifact receipt must retain every dimension of exactly one installed message quote")
        if (self.child_lease_id, self.child_grant_id, self.allocation_operation_id) != foreground_artifact_receipt_budget_ids_v3(
                self.namespace, self.c02_operation_id):
            raise ValueError("Artifact receipt cannot reuse a natural reply child or another original C02")
        self.child_lease()
        self.child_grant()

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))

    def child_lease(self):
        return BudgetLease(self.child_lease_id, self.parent_lease_ref, *self.namespace.as_tuple,
            self.currency, dict(self.child_limits), {}, {}, {}, 1, "active")

    def child_grant(self):
        return BudgetLeaseGrant(self.child_grant_id, 1, *self.namespace.as_tuple, self.child_lease_id,
            self.currency, dict(self.child_max_ceiling), self.allowed_work_kinds, self.valid_until_utc, self.policy_ref)


def _require_absent_artifact_receipt_v3(db, allocation):
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    if (_artifact_receipt_sql_v1(db,"SELECT 1 FROM runtime_budget_leases WHERE lease_id=?", (allocation.child_lease_id,)).fetchone()
            or _artifact_receipt_sql_v1(db,"SELECT 1 FROM runtime_budget_grants WHERE lease_id=? OR json_extract(grant_json,'$.grant_id')=?",
                (allocation.child_lease_id, allocation.child_grant_id)).fetchone()
            or _artifact_receipt_sql_v1(db,"SELECT 1 FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=?",
                (*allocation.namespace.as_tuple, allocation.allocation_operation_id)).fetchone()):
        raise ValueError("Artifact receipt child already exists; replay must read its saved creation original")


def _require_draft_responsibility_v3(responsibility, *, namespace, c02_operation_id, source_ref, parent_budget_lease_ref):
    from .foreground_cycle_v1 import ForegroundResponsibilityV1
    if (type(responsibility) is not ForegroundResponsibilityV1
            or responsibility.mode != "signed_scope_intersection_v1"
            or responsibility.root_registration_ref is None
            or (responsibility.namespace, responsibility.c02_operation_id, responsibility.source_ref,
                responsibility.parent_budget_lease_ref) != (namespace, c02_operation_id, source_ref, parent_budget_lease_ref)):
        raise ValueError("Artifact receipt requires its exact frozen signed draft responsibility")


def prepare_foreground_artifact_receipt_allocation_v3(db, *, namespace, c02_operation_id, source_ref,
        parent_budget_lease_ref, responsibility, purpose, audiences, issuer, installed_bundle, now_utc, deadline_utc):
    from ..host.authority_profile import AdminInstallationBundle, AdminPrivateReplyDispatchPolicy
    from ..host.artifact_phase_observer_policy_v2 import require_current_artifact_phase_observer_v2
    from .foreground_cycle_v1 import CreateForegroundCycleRequestV2, derive_current_foreground_responsibility_v1
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    if not db.in_transaction or type(issuer) is not D11BudgetJobIssuer or type(installed_bundle) is not AdminInstallationBundle:
        raise MissingProductionOriginalV1("actual_installed_artifact_receipt_bundle_and_W01_transaction")
    _require_draft_responsibility_v3(responsibility, namespace=namespace, c02_operation_id=c02_operation_id,
        source_ref=source_ref, parent_budget_lease_ref=parent_budget_lease_ref)
    observer = require_current_artifact_phase_observer_v2(installed_bundle)
    ids = foreground_artifact_receipt_budget_ids_v3(namespace, c02_operation_id)
    request = CreateForegroundCycleRequestV2(c02_operation_id, source_ref, ids[0],
        cause_original_ref=responsibility.cause_original_ref,
        draft_root_registration_ref=responsibility.root_registration_ref)
    current = derive_current_foreground_responsibility_v1(db, namespace=namespace, request=request,
        installed_bundle=installed_bundle, issuer=issuer, owner_guard=responsibility.owner_guard,
        parent_budget_lease_ref=parent_budget_lease_ref, purpose=purpose, audiences=audiences, now_utc=now_utc)
    if current != responsibility or deadline_utc != responsibility.deadline_utc:
        raise ValueError("Artifact receipt changed its actual standing/Source/Owner/root/deadline responsibility")
    policy = installed_bundle.installation_policy
    message = installed_bundle.private_reply_dispatch
    root = issuer.current_budget_grant(db, parent_budget_lease_ref)
    parent = get_budget_lease(db, parent_budget_lease_ref)
    if (type(message) is not AdminPrivateReplyDispatchPolicy or observer.completion_mode != "artifact_receipt_only"
            or namespace != policy.namespace or root != policy.root_grant
            or parent_budget_lease_ref != policy.root_lease.lease_id
            or (parent.parent_id, parent.bot_id, parent.persona_id, parent.currency, parent.limits) !=
                (None, *namespace.as_tuple, policy.root_lease.currency, policy.root_lease.limits)
            or parent.state != "active" or not {"d11.foreground_cycle.v1", "message"} <= set(root.allowed_work_kinds)
            or (responsibility.installation_id, responsibility.manifest_digest, responsibility.parent_grant_digest) !=
                (policy.installation_id, policy.manifest_digest, canonical_digest(root))):
        raise ValueError("Artifact receipt exceeds its actual signed installed root/message permission")
    require_budget_family_admissible(db, parent.lease_id)
    quote = _amount_tuple_v1(dict(message.quote_ceiling))
    if any(name not in parent.limits or amount > parent.available(name)
            or amount > root.max_ceiling.get(name, 0) for name, amount in quote):
        raise MissingProductionOriginalV1("actual_parent_availability_and_complete_message_quote")
    if not now_utc < deadline_utc <= root.valid_until_utc:
        raise MissingProductionOriginalV1("unexpired_original_artifact_receipt_deadline")
    allocation = ForegroundArtifactReceiptAllocationV3(
        namespace, c02_operation_id, source_ref, responsibility.digest,
        policy.installation_id, policy.manifest_digest, observer.asset_ref, observer.asset_digest,
        parent.lease_id, parent.version, canonical_digest(parent), canonical_digest(root),
        canonical_digest(plain_v1(message)), *ids, parent.currency, deadline_utc, quote, quote, quote)
    _require_absent_artifact_receipt_v3(db, allocation)
    return allocation


def apply_foreground_artifact_receipt_allocation_v3(db, *, allocation, issuer):
    if not db.in_transaction or type(allocation) is not ForegroundArtifactReceiptAllocationV3 or type(issuer) is not D11BudgetJobIssuer:
        raise TypeError("Artifact receipt application requires its exact private W01 allocation and installed issuer")
    parent = get_budget_lease(db, allocation.parent_lease_ref)
    root = issuer.current_budget_grant(db, parent.lease_id)
    if (parent.version != allocation.parent_version or canonical_digest(parent) != allocation.parent_state_digest
            or canonical_digest(root) != allocation.parent_grant_digest):
        raise ValueError("Artifact receipt original parent/grant changed before atomic application")
    require_budget_family_admissible(db, parent.lease_id)
    _require_absent_artifact_receipt_v3(db, allocation)
    receipt = create_budget_lease(db, allocation.child_lease(), allocation.allocation_operation_id, allocation.digest)
    issuer.issue_budget_grant(db, allocation.child_grant())
    actual = get_budget_lease(db, allocation.child_lease_id)
    expected_reserved = dict(parent.reserved)
    for name, amount in allocation.child_limits:
        expected_reserved[name] = expected_reserved.get(name, 0) + amount
    expected_parent = replace(parent, reserved=expected_reserved, version=parent.version + 1)
    grant = issuer.current_budget_grant(db, allocation.child_lease_id)
    if (receipt.status != "created" or receipt.lease_id != allocation.child_lease_id or receipt.digest != allocation.digest
            or actual != allocation.child_lease() or get_budget_lease(db, parent.lease_id) != expected_parent
            or grant != allocation.child_grant()):
        raise ValueError("Artifact actual child/grant/creation receipt/ancestor encumbrance differs from its allocation")
    return actual, grant


def _receipt_graph_head_v3(db, namespace, token):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from ..runtime_storage_v3 import read_graph_row_v3
    return _producer_original_point_v3(db, table='graph_atoms', columns=('revision','value','valid'),
        key_columns=('token','bot','persona'), key=(token,*namespace.as_tuple),
        legacy_reader=lambda:read_graph_row_v3(db,('revision','value','valid'),
            where='token=? AND bot=? AND persona=?',parameters=(token,*namespace.as_tuple)))


def read_actual_artifact_receipt_allocation_v3(db, *, namespace, c02_operation_id, source_ref, issuer):
    from .domain_background_read_v3 import background_json_loads_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .foreground_cycle_v1 import foreground_cycle_ids_v1, foreground_cycle_from_wire_v1, ForegroundResponsibilityV1
    from .d11_types import runtime_job_key, job_graph_write
    from .jobs import get_job
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    if not db.in_transaction or type(namespace) is not NamespaceId or type(issuer) is not D11BudgetJobIssuer:
        raise TypeError("Artifact receipt reader requires its actual Graph transaction/namespace/issuer")
    activity_id, job_id = foreground_cycle_ids_v1(namespace, c02_operation_id)
    job = get_job(db, job_id)
    continuation = foreground_cycle_from_wire_v1(job.continuation)
    key = runtime_job_key(*namespace.as_tuple, activity_id, job_id)
    from .domain_background_read_v3 import background_json_loads_v3
    atom = _receipt_graph_head_v3(db, namespace, key.token)
    if (atom is None or atom[2] != 1 or background_json_loads_v3(atom[1]) != job_graph_write(job).value
            or (job.bot_id, job.persona_id, job.activity_id, job.work_kind) !=
                (*namespace.as_tuple, activity_id, "d11.foreground_cycle.v1")
            or continuation.c02_operation_id != c02_operation_id or continuation.source_ref != source_ref):
        raise ValueError("Artifact receipt lost its actual SQL/Graph C02/cycle/Source identity")
    original = read_adopted_domain_operation_v1(db, namespace, job.operation_id)
    if (original is None or original["domain"] != "d11" or original["operation_kind"] != "create_foreground_cycle_v2"
            or original["payload"]["request"]["c02_operation_id"] != c02_operation_id
            or original["payload"]["request"]["source_ref"] != source_ref):
        raise ValueError("Artifact receipt has no actual Source-bound cycle creation original")
    proof = original["payload"]["provenance"]
    if set(proof) != {"before_job", "after_job", "reply_allocation", "foreground_responsibility"} or proof["before_job"] is not None:
        raise ValueError("Artifact receipt cannot upgrade or borrow an old natural allocation original")
    allocation = decode_typed_production_value_v1(proof["reply_allocation"], ForegroundArtifactReceiptAllocationV3)
    responsibility = read_original_foreground_responsibility_for_c09_v1(db, namespace=namespace, job=job, issuer=issuer)
    _require_draft_responsibility_v3(responsibility, namespace=namespace, c02_operation_id=c02_operation_id,
        source_ref=source_ref, parent_budget_lease_ref=job.budget_ref)
    if (allocation.namespace != namespace or allocation.c02_operation_id != c02_operation_id
            or allocation.source_ref != source_ref or allocation.parent_lease_ref != job.budget_ref
            or allocation.responsibility_digest != responsibility.digest
            or decode_typed_production_value_v1(proof["foreground_responsibility"], ForegroundResponsibilityV1) != responsibility
            or allocation.valid_until_utc != responsibility.deadline_utc
            or allocation.parent_grant_digest != responsibility.parent_grant_digest
            or allocation.child_lease_id != continuation.call_plan.protected_reply_lease_ref
            or original["payload"]["request"]["protected_reply_lease_ref"] != allocation.child_lease_id
            or proof["after_job"]["budget_ref"] != allocation.parent_lease_ref):
        raise ValueError("Artifact allocation original borrowed another actual responsibility/cycle/parent/child")
    row = _artifact_receipt_sql_v1(db,"SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='create'",
        (*namespace.as_tuple, allocation.allocation_operation_id)).fetchone()
    if row is None or row[:2] != (allocation.digest, allocation.child_lease_id):
        raise ValueError("Artifact receipt lost its actual existing budget creation receipt")
    receipt = BudgetReceipt(**background_json_loads_v3(row[2]))
    if (receipt.status, receipt.operation_id, receipt.digest, receipt.lease_id, receipt.version,
            dict(receipt.used), dict(receipt.reserved), dict(receipt.unconfirmed)) != (
            "created", allocation.allocation_operation_id, allocation.digest, allocation.child_lease_id, 1, {}, {}, {}):
        raise ValueError("Artifact receipt creation original differs from the untouched child creation")
    child = get_budget_lease(db, allocation.child_lease_id)
    grant = issuer.current_budget_grant(db, child.lease_id)
    if ((child.parent_id, child.bot_id, child.persona_id, child.currency, child.limits) !=
            (allocation.parent_lease_ref, *namespace.as_tuple, allocation.currency, dict(allocation.child_limits))
            or grant != allocation.child_grant()):
        raise ValueError("Artifact current child/grant differs from its immutable one-message allocation")
    return job, allocation, child, grant


def resolve_current_artifact_receipt_budget_v3(db, *, namespace, c02_operation_id, source_ref,
        issuer, installed_bundle, now_utc, owner_guard=None):
    from ..host.authority_profile import AdminInstallationBundle
    from ..host.artifact_phase_observer_policy_v2 import require_current_artifact_phase_observer_v2
    from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    from .jobs import _utc
    from ..graph_types import owner_grant_key
    if type(installed_bundle) is not AdminInstallationBundle:
        raise TypeError("Artifact receipt resolver requires its actual installed bundle")
    job, allocation, child, grant = read_actual_artifact_receipt_allocation_v3(db, namespace=namespace,
        c02_operation_id=c02_operation_id, source_ref=source_ref, issuer=issuer)
    policy = installed_bundle.installation_policy
    observer = require_current_artifact_phase_observer_v2(installed_bundle)
    root = issuer.current_budget_grant(db, allocation.parent_lease_ref)
    parent = get_budget_lease(db, allocation.parent_lease_ref)
    responsibility = read_original_foreground_responsibility_for_c09_v1(db, namespace=namespace, job=job, issuer=issuer)
    from .domain_background_read_v3 import background_json_loads_v3, background_json_digest_v3
    source = _receipt_graph_head_v3(db, namespace, source_ref)
    owner = _receipt_graph_head_v3(db, namespace, owner_grant_key(*namespace.as_tuple).token)
    if (namespace != policy.namespace or root != policy.root_grant
            or allocation.parent_lease_ref != policy.root_lease.lease_id
            or canonical_digest(root) != allocation.parent_grant_digest
            or (parent.parent_id, parent.bot_id, parent.persona_id, parent.currency, parent.limits) !=
                (None, *namespace.as_tuple, policy.root_lease.currency, policy.root_lease.limits)
            or (allocation.installation_id, allocation.manifest_digest) != (policy.installation_id, policy.manifest_digest)
            or (allocation.observer_policy_ref, allocation.observer_policy_digest) != (observer.asset_ref, observer.asset_digest)
            or allocation.message_policy_digest != canonical_digest(plain_v1(installed_bundle.private_reply_dispatch))
            or not {"d11.foreground_cycle.v1", "message"} <= set(root.allowed_work_kinds)
            or any(amount > root.max_ceiling.get(name, 0) for name, amount in grant.max_ceiling.items())
            or source is None or source[2] != 1
            or (source[0], background_json_digest_v3(source[1],background_json_loads_v3(source[1]))) != (responsibility.source_revision, responsibility.source_digest)
            or owner is None or owner[2] != 1
            or (owner[0], background_json_digest_v3(owner[1],background_json_loads_v3(owner[1]))) !=
                (responsibility.owner_guard.grant_revision, responsibility.owner_guard.grant_digest)
            or owner_guard is not None and owner_guard != responsibility.owner_guard):
        raise ValueError("Artifact receipt lost its current installed observer/Source/Owner/root/message quote")
    if (job.phase in {"completed", "failed", "cancelled", "draining", "pending_confirmation"} or job.cancel_epoch
            or parent.state != "active" or child.state != "active"
            or not now_utc < min(grant.valid_until_utc, root.valid_until_utc, _utc(job.deadline_utc, "deadline_utc").timestamp())):
        raise ValueError("Artifact receipt cannot authorize new work after its original control/deadline ends")
    require_budget_family_admissible(db, child.lease_id)
    return child, grant


def require_protected_artifact_receipt_budget_v3(db, *, namespace, plan, issuer, now_utc, installed_bundle, owner_guard=None):
    """Retain one full receipt quote; C5/C6 cannot use this child."""
    from .domain_background_read_v3 import background_json_loads_v3
    from .artifact_receipt_original_read_v1 import artifact_receipt_sql_v1 as _artifact_receipt_sql_v1
    from .jobs import get_job
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    rows = _artifact_receipt_sql_v1(db,"SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? AND work_kind='d11.foreground_cycle.v1' "
        "AND json_extract(continuation_json,'$.call_plan.protected_reply_lease_ref')=? LIMIT 2",
        (*namespace.as_tuple, plan.protected_reply_lease_ref)).fetchall()
    if len(rows) != 1:
        raise ValueError("Artifact receipt requires its unique actual registered cycle")
    continuation = foreground_cycle_from_wire_v1(get_job(db, rows[0][0]).continuation)
    _, allocation, _, _ = read_actual_artifact_receipt_allocation_v3(db, namespace=namespace,
        c02_operation_id=continuation.c02_operation_id, source_ref=continuation.source_ref, issuer=issuer)
    child, grant = resolve_current_artifact_receipt_budget_v3(db, namespace=namespace,
        c02_operation_id=continuation.c02_operation_id, source_ref=continuation.source_ref,
        issuer=issuer, installed_bundle=installed_bundle, now_utc=now_utc, owner_guard=owner_guard)
    if (plan.parent_budget_lease_ref != allocation.parent_lease_ref
            or plan.protected_reply_lease_ref != allocation.child_lease_id
            or any(row.slot in {"C5", "C6"} for row in plan.attempts)):
        raise ValueError("Artifact receipt allocation cannot become a natural generation/review budget")
    from .foreground_call_plan_v1 import ForegroundCallPlanV1, ForegroundCallPlanV2
    from .foreground_artifact_observation_plan_v3 import ForegroundCallPlanV3
    if type(plan) is ForegroundCallPlanV2 or type(plan) not in {ForegroundCallPlanV1, ForegroundCallPlanV3}:
        raise ValueError("an old phase group cannot adopt a new Artifact receipt allocation")
    if type(plan) is ForegroundCallPlanV3 and (plan.observer_policy_ref, plan.observer_policy_digest) != (
            allocation.observer_policy_ref, allocation.observer_policy_digest):
        raise ValueError("Artifact plan changed its original protected observer asset")
    reservations = _artifact_receipt_sql_v1(db,"SELECT ceiling_json FROM runtime_budget_reservations WHERE lease_id=?",
        (child.lease_id,)).fetchall()
    if len(reservations) > 1 or any(background_json_loads_v3(row[0]) != dict(allocation.message_ceiling) for row in reservations):
        raise ValueError("Artifact child permits exactly one actual full message reservation")
    if not reservations and any(child.available(name) < amount for name, amount in allocation.message_ceiling):
        raise ValueError("optional Artifact work consumed the protected receipt capacity")
    return child, grant


def select_initial_foreground_reply_budget_ids_v3(namespace, c02_operation_id, *, installed_bundle, draft_root_registration_ref):
    """Select prospective IDs only; creation must independently derive signed draft responsibility."""
    from .foreground_call_plan_v1 import foreground_reply_budget_ids_v1
    if draft_root_registration_ref is None or installed_bundle.artifact_phase_observer is None:
        return foreground_reply_budget_ids_v1(namespace, c02_operation_id)
    from ..host.artifact_phase_observer_policy_v2 import require_current_artifact_phase_observer_v2
    require_current_artifact_phase_observer_v2(installed_bundle)
    return foreground_artifact_receipt_budget_ids_v3(namespace, c02_operation_id)


def decode_foreground_reply_allocation_v3(raw):
    """Decode the exact retained schema; no existing natural original is upgraded."""
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .foreground_call_plan_v1 import ForegroundReplyAllocationV1
    selected = ForegroundArtifactReceiptAllocationV3 if type(raw) is dict and raw.get("schema") == SCHEMA else ForegroundReplyAllocationV1
    return decode_typed_production_value_v1(raw, selected)


def require_artifact_receipt_responsibility_binding_v3(allocation, responsibility):
    if type(allocation) is not ForegroundArtifactReceiptAllocationV3:
        raise TypeError("exact Artifact receipt allocation required")
    _require_draft_responsibility_v3(responsibility, namespace=allocation.namespace,
        c02_operation_id=allocation.c02_operation_id, source_ref=allocation.source_ref,
        parent_budget_lease_ref=allocation.parent_lease_ref)
    if (allocation.responsibility_digest != responsibility.digest
            or allocation.valid_until_utc != responsibility.deadline_utc
            or allocation.parent_grant_digest != responsibility.parent_grant_digest
            or (allocation.installation_id, allocation.manifest_digest) !=
                (responsibility.installation_id, responsibility.manifest_digest)):
        raise ValueError("Artifact allocation lost its actual signed responsibility/Source/root/deadline")
    return allocation
