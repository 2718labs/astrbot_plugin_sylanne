"""Immutable contact scope adopted before any model output or delivery claim."""
from dataclasses import dataclass, fields
import math

from ...graph_types import AtomKey, GraphVersion, Owner
from ...runtime_contracts import NamespaceId, VersionedRef, canonical_digest

CONTACT_PLAN_TYPE_V1 = "d08.contact_expression_plan.v1"


def contact_ids_v1(namespace, cause_original_ref, target_entity_ref, channel_category):
    """A policy renewal, clock tick or model retry cannot create a new contact."""
    if type(namespace) is not NamespaceId or channel_category != "private_text":
        raise ValueError("contact identity requires its actual private route scope")
    if not cause_original_ref or not target_entity_ref:
        raise ValueError("contact needs a substantive cause and actual recipient")
    identity = canonical_digest(("d10.contact-cause.v1", namespace,
        cause_original_ref, target_entity_ref, channel_category))
    return {name: prefix + identity[:48] for name, prefix in (
        ("contact", "contact:"), ("activity", "contact-activity:"),
        ("plan", "contact-plan:"), ("action", "action:"),
        ("generation", "contact-generation:"), ("review", "contact-review:"))}


def contact_segment_ids_v1(contact_id, index):
    if not contact_id.startswith("contact:") or type(index) is not int or not 0 <= index < 3:
        raise ValueError("contact segment needs its fixed manifest position")
    digest = canonical_digest((contact_id, index))[:48]
    return {"segment": "segment:" + digest,
            "effect": "effect:" + digest,
            "operation": "contact-dispatch:" + digest}


@dataclass(frozen=True, slots=True)
class AdoptedContactExpressionPlanV1:
    schema: str
    namespace: NamespaceId
    plan_id: str
    contact_id: str
    activity_id: str
    cause_original_ref: str
    cause_original_digest: str
    opportunity_ref: VersionedRef
    source_ref: VersionedRef
    target_entity_ref: str
    route_account_ref: VersionedRef
    route_binding_digest: str
    scene_id: str
    audience_id: str
    policy_original_ref: str
    policy_original_digest: str
    policy_version: int
    required_slots: tuple[str, ...]
    allowed_speech_acts: tuple[str, ...]
    qualified_units_digest: str
    d06_qualification_digests: tuple[str, ...]
    qualified_read_versions: tuple[GraphVersion, ...]
    parent_budget_lease_id: str
    budget_grant_version: int
    budget_grant_digest: str
    generation_reservation_id: str
    review_reservation_id: str
    generation_ceiling: tuple[tuple[str, int], ...]
    review_ceiling: tuple[tuple[str, int], ...]
    max_segments: int
    max_total_visible_chars: int
    cancellation_epoch: int
    valid_until_utc: float
    status: str = "scope_adopted_payload_pending"

    def __post_init__(self):
        ids = contact_ids_v1(self.namespace, self.cause_original_ref,
                            self.target_entity_ref, "private_text")
        if (self.schema != CONTACT_PLAN_TYPE_V1 or self.plan_id != ids["plan"]
                or self.contact_id != ids["contact"] or self.activity_id != ids["activity"]
                or self.status != "scope_adopted_payload_pending"
                or self.max_segments != 3 or type(self.max_total_visible_chars) is not int
                or not 1 <= self.max_total_visible_chars <= 2048
                or type(self.cancellation_epoch) is not int or self.cancellation_epoch < 0
                or type(self.policy_version) is not int or self.policy_version < 1
                or type(self.budget_grant_version) is not int or self.budget_grant_version < 1
                or not math.isfinite(self.valid_until_utc) or self.valid_until_utc <= 0):
            raise ValueError("contact scope identity, budget or finite limits differ")
        for name in ("cause_original_digest", "route_binding_digest", "policy_original_digest",
                     "qualified_units_digest", "budget_grant_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("contact scope commitment differs: " + name)
        for name in ("opportunity_ref", "source_ref", "route_account_ref"):
            ref = getattr(self, name)
            if type(ref) is not VersionedRef or ref.version < 1 or NamespaceId.from_key(AtomKey.from_token(ref.ref)) != self.namespace:
                raise ValueError("contact scope locator differs: " + name)
        if (not self.scene_id or not self.audience_id or not self.policy_original_ref
                or not self.parent_budget_lease_id or not self.generation_reservation_id
                or not self.review_reservation_id
                or self.generation_reservation_id == self.review_reservation_id
                or not self.qualified_read_versions or not self.d06_qualification_digests
                or any(type(row) is not GraphVersion or NamespaceId.from_key(row.key) != self.namespace
                       for row in self.qualified_read_versions)
                or len({row.key for row in self.qualified_read_versions}) != len(self.qualified_read_versions)
                or any(not ceiling or tuple(sorted(ceiling)) != ceiling
                       or any(type(k) is not str or not k or type(v) is not int or v <= 0 for k, v in ceiling)
                       for ceiling in (self.generation_ceiling, self.review_ceiling))
                or not self.allowed_speech_acts or "promise" in self.allowed_speech_acts
                or len(set(self.required_slots)) != len(self.required_slots)
                or len(set(self.allowed_speech_acts)) != len(self.allowed_speech_acts)):
            raise ValueError("contact scope lacks its original route, read closure or bounded model budget")


def contact_plan_key_v1(plan):
    return AtomKey(Owner("activity", *plan.namespace.as_tuple, plan.activity_id),
                   CONTACT_PLAN_TYPE_V1, plan.plan_id)


def decode_contact_plan_v1(value):
    if type(value) is not dict or set(value) != {f.name for f in fields(AdoptedContactExpressionPlanV1)}:
        raise ValueError("contact plan fields differ")
    data = dict(value)
    data["namespace"] = NamespaceId(**data["namespace"])
    for name in ("opportunity_ref", "source_ref", "route_account_ref"):
        data[name] = VersionedRef(**data[name])
    data["qualified_read_versions"] = tuple(GraphVersion(
        AtomKey(Owner(**row["key"]["owner"]), row["key"]["type_name"], row["key"]["name"]),
        row["revision"]) for row in data["qualified_read_versions"])
    for name in ("required_slots", "allowed_speech_acts", "d06_qualification_digests"):
        data[name] = tuple(data[name])
    for name in ("generation_ceiling", "review_ceiling"):
        data[name] = tuple(tuple(row) for row in data[name])
    return AdoptedContactExpressionPlanV1(**data)
