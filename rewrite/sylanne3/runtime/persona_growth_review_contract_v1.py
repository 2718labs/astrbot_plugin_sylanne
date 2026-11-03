"""Current-persona review metadata, without changing the reviewed obligation."""
from dataclasses import dataclass
from ..graph_types import AtomKey, GraphVersion, Owner, TypeSpec
from ..runtime_contracts import NamespaceId, canonical_digest, schema_hash

REVIEW_TYPES_V1 = {"d08": "d08.persona_growth_review.v1", "d10": "d10.persona_growth_review.v1"}
TARGET_TYPES_V1 = {
    "d08": ("d08.aspiration.v1", "d08.commitment_fulfillment_terms.v1", "d08.goal.v1", "d08.commitment.v1", "d08.personal_plan.v1", "d08.joint_plan.v1", "d08.long_term_plan.v1"),
    "d10": ("d10.life_project.v1", "d10.activity_recipe.v1", "d10.habit_policy.v1"),
}
GROWTH_EVENTS_V1 = {
    "d08": "persona_growth_requires_commitment_reevaluation",
    "d10": "persona_growth_requires_life_reevaluation",
}
MARK_OPERATIONS_V1 = {"d08": "mark_goal_growth_review_v1", "d10": "mark_life_growth_review_v1"}
CONFIRM_OPERATIONS_V1 = {"d08": "confirm_goal_growth_review_v1", "d10": "confirm_life_growth_review_v1"}
REVIEW_OPERATIONS_V1 = frozenset((*MARK_OPERATIONS_V1.values(), *CONFIRM_OPERATIONS_V1.values()))


def target_domain_v1(key):
    for domain, kinds in TARGET_TYPES_V1.items():
        if key.type_name in kinds:
            return domain
    raise ValueError("growth review target has no registered domain owner")


def growth_review_key_v1(namespace, target):
    key = AtomKey.from_token(target) if type(target) is str else target
    domain = target_domain_v1(key)
    if NamespaceId.from_key(key) != namespace:
        raise ValueError("growth review target crossed namespace")
    return AtomKey(Owner("persona", *namespace.as_tuple), REVIEW_TYPES_V1[domain],
        "target:" + canonical_digest(key.token)[:48])


@dataclass(frozen=True, slots=True)
class GrowthReviewRequestV1:
    target_ref: str
    expected_target_revision: int
    growth_operation_id: str
    expected_head_id: str
    expected_activation_revision: int
    expected_review_revision: int

    def __post_init__(self):
        target_domain_v1(AtomKey.from_token(self.target_ref))
        if (any(type(value) is not int or value < 1 for value in
                (self.expected_target_revision, self.expected_activation_revision))
                or type(self.expected_review_revision) is not int or self.expected_review_revision < 0
                or type(self.growth_operation_id) is not str or not self.growth_operation_id
                or type(self.expected_head_id) is not str or not self.expected_head_id):
            raise ValueError("growth review requires its exact current target, head and causal selectors")


@dataclass(frozen=True, slots=True)
class MarkCurrentGrowthReviewRequestV1(GrowthReviewRequestV1):
    pass


@dataclass(frozen=True, slots=True)
class ConfirmCurrentGrowthReviewRequestV1(GrowthReviewRequestV1):
    """An explicit Owner keep request; it contains no execution permission."""
    pass


@dataclass(frozen=True, slots=True)
class PersonaGrowthReviewV1:
    namespace: NamespaceId
    target_version: GraphVersion
    activation_version: GraphVersion
    persona_head_version: GraphVersion
    persona_head_id: str
    growth_operation_id: str
    growth_original_digest: str
    graph_incarnation: str
    state: str
    review_operation_id: str
    owner_grant: GraphVersion
    source_refs: tuple[str, ...]
    schema: str = "sylanne.persona-growth-review.v1"

    def __post_init__(self):
        if (self.schema != "sylanne.persona-growth-review.v1"
                or self.state not in {"pending", "owner_confirmed_keep"}
                or type(self.namespace) is not NamespaceId
                or type(self.source_refs) is not tuple or len(self.source_refs) > 128
                or len(set(self.source_refs)) != len(self.source_refs)):
            raise ValueError("growth review has another registered state or source contract")
        target_domain_v1(self.target_version.key)
        for version in (self.target_version, self.activation_version, self.persona_head_version, self.owner_grant):
            if (type(version) is not GraphVersion or version.revision < 1
                    or NamespaceId.from_key(version.key) != self.namespace):
                raise ValueError("growth review requires actual same-namespace versions")
        if (self.activation_version.key.type_name != "d01.persona_activation.v1"
                or self.persona_head_version.key.type_name != "d01.persona_plan.v1"
                or self.owner_grant.key.type_name != "d11.owner_grant.v1"
                or len(self.growth_original_digest) != 64
                or any(c not in "0123456789abcdef" for c in self.growth_original_digest)):
            raise ValueError("growth review changed its control or actual growth commitment")
        for value in (self.persona_head_id, self.growth_operation_id, self.graph_incarnation, self.review_operation_id):
            if type(value) is not str or not value:
                raise ValueError("growth review lacks an actual control or producing identity")
        for ref in self.source_refs:
            key = AtomKey.from_token(ref)
            if key.type_name != "memory.source" or NamespaceId.from_key(key) != self.namespace:
                raise ValueError("growth review sources crossed their actual namespace")


def decode_persona_growth_review_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw, PersonaGrowthReviewV1)


def growth_review_type_specs_v1(domain):
    kind = REVIEW_TYPES_V1[domain]
    return (TypeSpec(kind, ("persona",), "state", decode_persona_growth_review_v1,
        writer_domain=domain, schema_version=1,
        schema_hash=schema_hash({"type": kind, "fields": tuple(PersonaGrowthReviewV1.__dataclass_fields__)})),)
