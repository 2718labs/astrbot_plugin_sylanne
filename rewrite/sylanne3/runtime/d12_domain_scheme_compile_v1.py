"""Pure D12 draft-field compilation for supported whole-scheme fields.

This returns a typed candidate, not a D12 domain receipt or a stored scheme.
W01 must bind it to the current draft, persist the candidate, and issue any
receipt under its graph transaction before D12 can adopt it.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import math
import re

from ..domains.d01 import (
    PersonaBlock, PersonaDomain, PersonaPlan, PersonaScheme, ValueRule,
)
from ..domains.d02 import BodyDomain, BodyProfile
from ..domains.d03 import ContextProvider
from ..domains.d04 import AffectAxis, AffectProvider, AffectScheme
from ..domains.d04.authored_lineage_v3 import (
    AuthoredRootBlockInputV3, RootAuthoredFacetV3,
)
from ..domains.d05 import RelationshipProvider
from ..domains.d06 import D06DomainProvider
from ..domains.d06.encoding_projection import EncodingProjectionPolicyV1
from ..domains.d07 import AttentionPolicy, D07DomainProvider
from ..domains.d08 import ActionSchema, GoalExecutionProvider, RequiredCheckSpec
from ..domains.d09 import (
    D09ExpressionPolicyV1, D09ExpressionProvider, compile_expression_policy_v1,
)
from ..domains.d10 import ActivityRecipe, LifeDomain
from ..domains.d12.scheme_command import (
    D12DomainCompileRejectionV1, D12SchemeDiagnosticV1,
)
from ..runtime_contracts import (
    NamespaceId, VersionedRef, canonical_digest, canonical_serialize, schema_hash,
)


BODY_PROFILE_FIELD = "d02.body_profile"
PERSONA_PLAN_FIELD = "d01.persona_plan"
ACTIVITY_RECIPE_FIELD = "d10.activity_recipe"
CONTEXT_SCHEME_FIELD = "d03.context_scheme"
RELATIONSHIP_SCHEME_FIELD = "d05.relationship_scheme"
AFFECT_SCHEME_FIELD = "d04.affect_scheme"
AUTHORED_ROOT_FIELD = "d04.authored_root"
ACTION_SCHEMAS_FIELD = "d08.action_schemas"
ENCODING_PROJECTION_POLICY_FIELD = "d06.encoding_projection_policy"
ATTENTION_POLICY_FIELD = "d07.attention_policy"
EXPRESSION_POLICY_FIELD = "d09.expression_policy"
_BODY_PROFILE_KEYS = frozenset((
    "profile_id", "namespace", "version", "applicable_axes", "work_kinds",
))
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MISSING_OWNER_COMPILERS = {}


@dataclass(frozen=True, slots=True)
class D12BodyProfileCandidateV1:
    domain: str
    field_names: tuple[str, ...]
    field_input_digest: str
    proposal_schema_hash: str
    profile: BodyProfile
    candidate_digest: str
    status: str = "typed_candidate_not_persisted"


@dataclass(frozen=True, slots=True)
class D12PersonaPlanCandidateV1:
    domain: str
    field_names: tuple[str, ...]
    field_input_digest: str
    proposal_schema_hash: str
    plan: PersonaPlan
    scheme: PersonaScheme
    candidate_digest: str
    status: str = "typed_candidate_not_persisted"


@dataclass(frozen=True, slots=True)
class D12ActivityRecipeCandidateV1:
    namespace: NamespaceId
    domain: str
    field_names: tuple[str, ...]
    field_input_digest: str
    proposal_schema_hash: str
    recipe: ActivityRecipe
    candidate_digest: str
    status: str = "typed_candidate_not_persisted"


@dataclass(frozen=True, slots=True)
class D12ContextSchemeCandidateV1:
    namespace: NamespaceId
    domain: str
    field_names: tuple[str, ...]
    field_input_digest: str
    proposal_schema_hash: str
    schema: str
    roles: tuple[str, ...]
    norms: tuple[str, ...]
    candidate_digest: str
    status: str = "typed_candidate_not_persisted"


@dataclass(frozen=True, slots=True)
class D12RelationshipSchemeCandidateV1:
    namespace: NamespaceId
    domain: str
    field_names: tuple[str, ...]
    field_input_digest: str
    proposal_schema_hash: str
    schema: str
    dimensions: tuple[str, ...]
    contribution_semantics: tuple[str, ...]
    candidate_digest: str
    status: str = "typed_candidate_not_persisted"


@dataclass(frozen=True, slots=True)
class D12AffectSchemeCandidateV1:
    namespace: NamespaceId
    domain: str
    field_names: tuple[str, ...]
    field_input_digest: str
    proposal_schema_hash: str
    scheme: AffectScheme
    candidate_digest: str
    status: str = "typed_candidate_not_persisted"


@dataclass(frozen=True, slots=True)
class D12AuthoredRootSelectionCandidateV1:
    """Exact current-draft V3 selection, pending Owner and installed-asset replay."""

    namespace: NamespaceId
    domain: str
    field_names: tuple[str, ...]
    draft_digest: str
    field_input_digest: str
    proposal_schema_hash: str
    field_source: str
    field_value_json: str
    blocks: tuple[AuthoredRootBlockInputV3, ...]
    candidate_digest: str
    status: str = "typed_candidate_not_persisted"


def _authored_root_blocks_v3(value: object) -> tuple[AuthoredRootBlockInputV3, ...]:
    if (type(value) is not dict
            or set(value) != {"candidate_id", "cursor", "preset_digest",
                              "asset_digest", "blocks"}
            or type(value["candidate_id"]) is not str
            or not value["candidate_id"].strip()
            or type(value["cursor"]) not in (int, float)
            or not math.isfinite(value["cursor"])
            or type(value["preset_digest"]) is not str
            or _SHA256.fullmatch(value["preset_digest"]) is None
            or type(value["asset_digest"]) is not str
            or _SHA256.fullmatch(value["asset_digest"]) is None
            or type(value["blocks"]) is not list):
        raise ValueError("authored root requires exact V3 selection fields")
    blocks = []
    for item in value["blocks"]:
        if (type(item) is not dict
                or set(item) != {"facet", "axes", "latent_state",
                                     "ordered_box", "initial_error_ref"}
                or type(item["axes"]) is not list
                or type(item["latent_state"]) is not list
                or type(item["ordered_box"]) is not list):
            raise ValueError("authored root block requires exact V3 fields")
        facet = item["facet"]
        if (type(facet) is not dict
                or set(facet) != set(RootAuthoredFacetV3.__dataclass_fields__)):
            raise ValueError("authored root facet requires exact V3 fields")
        boxes = item["ordered_box"]
        if any(type(pair) is not list or len(pair) != 2 for pair in boxes):
            raise ValueError("authored root boxes require JSON pairs")
        blocks.append(AuthoredRootBlockInputV3(
            RootAuthoredFacetV3(**facet), tuple(item["axes"]),
            tuple(item["latent_state"]), tuple(tuple(pair) for pair in boxes),
            item["initial_error_ref"],
        ))
    if (len(blocks) < 3
            or sum(item.facet.kind == "feeling" for item in blocks) < 2
            or sum(item.facet.kind == "mood" for item in blocks) != 1
            or len({item.facet.block_id for item in blocks}) != len(blocks)
            or len({item.facet.facet_id for item in blocks}) != len(blocks)):
        raise ValueError("authored root needs unique facets, two Feelings and one Mood")
    return tuple(blocks)


@dataclass(frozen=True, slots=True)
class D12ActionSchemasCandidateV1:
    namespace: NamespaceId
    domain: str
    field_names: tuple[str, ...]
    field_input_digest: str
    proposal_schema_hash: str
    schemas: tuple[ActionSchema, ...]
    candidate_digest: str
    status: str = "typed_candidate_not_persisted"


@dataclass(frozen=True, slots=True)
class D12EncodingProjectionPolicyCandidateV1:
    namespace: NamespaceId
    domain: str
    field_names: tuple[str, ...]
    field_input_digest: str
    proposal_schema_hash: str
    policy: EncodingProjectionPolicyV1
    candidate_digest: str
    status: str = "typed_candidate_not_persisted"


@dataclass(frozen=True, slots=True)
class D12AttentionPolicyCandidateV1:
    namespace: NamespaceId
    domain: str
    field_names: tuple[str, ...]
    field_input_digest: str
    proposal_schema_hash: str
    policy: AttentionPolicy
    candidate_digest: str
    status: str = "typed_candidate_not_persisted"


@dataclass(frozen=True, slots=True)
class D12ExpressionPolicyCandidateV1:
    namespace: NamespaceId
    domain: str
    field_names: tuple[str, ...]
    field_input_digest: str
    proposal_schema_hash: str
    policy: D09ExpressionPolicyV1
    candidate_digest: str
    status: str = "typed_candidate_not_persisted"


def _reject(domain: str, fields: tuple[tuple[str, object, str], ...],
            digest: str, diagnostics: tuple[D12SchemeDiagnosticV1, ...]
            ) -> D12DomainCompileRejectionV1:
    return D12DomainCompileRejectionV1(
        domain, tuple(item[0] for item in fields), digest, diagnostics,
    )


def compile_d12_domain_scheme_candidate_v1(
    *, namespace: NamespaceId, draft_digest: str, domain: str,
    fields: tuple[tuple[str, object, str], ...], field_input_digest: str,
) -> (D12BodyProfileCandidateV1 | D12PersonaPlanCandidateV1 |
      D12ActivityRecipeCandidateV1 | D12ContextSchemeCandidateV1 |
      D12RelationshipSchemeCandidateV1 | D12AffectSchemeCandidateV1 |
      D12AuthoredRootSelectionCandidateV1 |
      D12ActionSchemasCandidateV1 | D12EncodingProjectionPolicyCandidateV1 |
      D12AttentionPolicyCandidateV1 | D12ExpressionPolicyCandidateV1 |
      D12DomainCompileRejectionV1):
    """Decode one complete supported scheme field from a frozen draft."""
    if type(namespace) is not NamespaceId or type(fields) is not tuple:
        raise TypeError("current namespace and frozen draft fields required")
    if (type(domain) is not str or not domain
            or type(draft_digest) is not str or len(draft_digest) != 64
            or type(field_input_digest) is not str or len(field_input_digest) != 64):
        raise ValueError("domain and complete draft digests required")
    if any(type(item) is not tuple or len(item) != 3
           or type(item[0]) is not str or not item[0]
           or type(item[2]) is not str or not item[2] for item in fields):
        raise ValueError("draft fields require path, value, and source")
    if not fields:
        raise ValueError("at least one draft field required")

    expected_digest = canonical_digest((draft_digest, domain, fields))
    if field_input_digest != expected_digest:
        return _reject(domain, fields, field_input_digest, tuple(
            D12SchemeDiagnosticV1(name, "field_input_changed",
                                  "Frozen draft field digest differs")
            for name, _, _ in fields
        ))
    unsupported = tuple(
        D12SchemeDiagnosticV1(name, "unsupported_scheme_field",
                              _MISSING_OWNER_COMPILERS.get(
                                  domain, "No installed D12 compiler mapping for this field"))
        for name, _, _ in fields
        if (domain, name) not in {
            ("d01", PERSONA_PLAN_FIELD), ("d02", BODY_PROFILE_FIELD),
            ("d03", CONTEXT_SCHEME_FIELD),
            ("d04", AFFECT_SCHEME_FIELD), ("d04", AUTHORED_ROOT_FIELD),
            ("d05", RELATIONSHIP_SCHEME_FIELD),
            ("d06", ENCODING_PROJECTION_POLICY_FIELD),
            ("d07", ATTENTION_POLICY_FIELD),
            ("d08", ACTION_SCHEMAS_FIELD),
            ("d09", EXPRESSION_POLICY_FIELD),
            ("d10", ACTIVITY_RECIPE_FIELD),
        }
    )
    if unsupported:
        return _reject(domain, fields, field_input_digest, unsupported)
    if len(fields) != 1:
        field_name = fields[0][0]
        return _reject(domain, fields, field_input_digest, (
            D12SchemeDiagnosticV1(field_name, "duplicate_scheme_field",
                                  "Scheme must be one complete field"),
        ))

    value = fields[0][1]
    if domain == "d04" and fields[0][0] == AUTHORED_ROOT_FIELD:
        try:
            blocks = _authored_root_blocks_v3(value)
            field_value_json = canonical_serialize(value)
        except (TypeError, ValueError) as exc:
            return _reject(domain, fields, field_input_digest, (
                D12SchemeDiagnosticV1(
                    AUTHORED_ROOT_FIELD, "invalid_authored_root_v3", str(exc)),
            ))
        proposal_hash = schema_hash({
            "schema": "d04.authored_root_input.v3",
            "selection_fields": ("candidate_id", "cursor", "preset_digest",
                                 "asset_digest", "blocks"),
            "block_fields": tuple(AuthoredRootBlockInputV3.__dataclass_fields__),
            "facet_fields": tuple(RootAuthoredFacetV3.__dataclass_fields__),
        })
        material = {
            "schema": "d12.authored-root-selection-candidate.v1",
            "namespace": namespace, "draft_digest": draft_digest,
            "field_input_digest": field_input_digest,
            "proposal_schema_hash": proposal_hash,
            "field_source": fields[0][2],
            "field_value_json": field_value_json,
            "blocks": blocks,
        }
        return D12AuthoredRootSelectionCandidateV1(
            namespace, "d04", (AUTHORED_ROOT_FIELD,), draft_digest,
            field_input_digest, proposal_hash, fields[0][2],
            field_value_json, blocks, canonical_digest(material),
        )
    if domain == "d09":
        try:
            if type(value) is not dict or set(value) != set(D09ExpressionPolicyV1.__dataclass_fields__):
                raise ValueError("expression policy requires exact JSON fields")
            compiled = compile_expression_policy_v1(D09ExpressionPolicyV1(**value))
        except (TypeError, ValueError) as exc:
            return _reject(domain, fields, field_input_digest, (
                D12SchemeDiagnosticV1(
                    EXPRESSION_POLICY_FIELD, "invalid_expression_policy", str(exc)),
            ))
        proposal_hash = D09ExpressionProvider().descriptor.request_schema_hash
        return D12ExpressionPolicyCandidateV1(
            namespace, "d09", (EXPRESSION_POLICY_FIELD,), field_input_digest,
            proposal_hash, compiled, canonical_digest({
                "schema": "d12.expression-policy-candidate.v1",
                "namespace": namespace, "field_input_digest": field_input_digest,
                "proposal_schema_hash": proposal_hash, "policy": asdict(compiled),
            }),
        )
    if domain == "d06":
        provider = D06DomainProvider()
        try:
            if type(value) is not dict or set(value) != set(EncodingProjectionPolicyV1.__dataclass_fields__):
                raise ValueError("encoding projection policy requires exact JSON fields")
            compiled = provider.compile_scheme(EncodingProjectionPolicyV1(**value))
        except (TypeError, ValueError) as exc:
            return _reject(domain, fields, field_input_digest, (
                D12SchemeDiagnosticV1(
                    ENCODING_PROJECTION_POLICY_FIELD, "invalid_encoding_projection_policy", str(exc)),
            ))
        proposal_hash = provider.descriptor.request_schema_hash
        return D12EncodingProjectionPolicyCandidateV1(
            namespace, "d06", (ENCODING_PROJECTION_POLICY_FIELD,), field_input_digest,
            proposal_hash, compiled, canonical_digest({
                "schema": "d12.encoding-projection-policy-candidate.v1",
                "namespace": namespace, "field_input_digest": field_input_digest,
                "proposal_schema_hash": proposal_hash, "policy": asdict(compiled),
            }),
        )

    if domain == "d07":
        provider = D07DomainProvider()
        try:
            if type(value) is not dict or set(value) != set(AttentionPolicy.__dataclass_fields__):
                raise ValueError("attention policy requires exact JSON fields")
            compiled = provider.compile_scheme(AttentionPolicy(**value))
        except (TypeError, ValueError) as exc:
            return _reject(domain, fields, field_input_digest, (
                D12SchemeDiagnosticV1(ATTENTION_POLICY_FIELD, "invalid_attention_policy", str(exc)),
            ))
        proposal_hash = provider.descriptor.request_schema_hash
        return D12AttentionPolicyCandidateV1(
            namespace, "d07", (ATTENTION_POLICY_FIELD,), field_input_digest,
            proposal_hash, compiled, canonical_digest({
                "schema": "d12.attention-policy-candidate.v1",
                "namespace": namespace, "field_input_digest": field_input_digest,
                "proposal_schema_hash": proposal_hash, "policy": asdict(compiled),
            }),
        )

    if domain == "d04":
        provider = AffectProvider()
        try:
            if (type(value) is not dict
                    or set(value) != {"schema", "scheme_version", "operator_version",
                                          "parameter_version", "coupling_version", "axes",
                                          "parameter_bounds"}
                    or type(value["axes"]) is not list
                    or type(value["parameter_bounds"]) is not list):
                raise ValueError("affect scheme requires exact JSON fields and arrays")
            axes = []
            for row in value["axes"]:
                if type(row) is not dict or set(row) != {"axis_id", "unit", "meaning"}:
                    raise ValueError("affect axis requires exact JSON fields")
                axes.append(AffectAxis(**row))
            bounds = []
            for row in value["parameter_bounds"]:
                if type(row) is not list or len(row) != 3:
                    raise ValueError("parameter bound requires a JSON triple")
                bounds.append(tuple(row))
            draft = AffectScheme(
                value["schema"], value["scheme_version"], value["operator_version"],
                value["parameter_version"], value["coupling_version"],
                tuple(axes), tuple(bounds),
            )
            compiled = provider.compile_scheme(draft)
        except (KeyError, TypeError, ValueError) as exc:
            return _reject(domain, fields, field_input_digest, (
                D12SchemeDiagnosticV1(AFFECT_SCHEME_FIELD, "invalid_affect_scheme", str(exc)),
            ))
        proposal_hash = provider.descriptor.request_schema_hash
        return D12AffectSchemeCandidateV1(
            namespace, "d04", (AFFECT_SCHEME_FIELD,), field_input_digest,
            proposal_hash, compiled, canonical_digest({
                "schema": "d12.affect-scheme-candidate.v1",
                "namespace": namespace, "field_input_digest": field_input_digest,
                "proposal_schema_hash": proposal_hash, "scheme": asdict(compiled),
            }),
        )

    if domain == "d08":
        provider = GoalExecutionProvider()
        try:
            if type(value) is not list or not value:
                raise ValueError("action schemas require a nonempty JSON array")
            schemas = []
            for row in value:
                if (type(row) is not dict
                        or set(row) != {"schema_id", "action_kind", "proactive",
                                            "required_checks"}
                        or type(row["required_checks"]) is not list):
                    raise ValueError("action schema requires exact JSON fields")
                checks = []
                for item in row["required_checks"]:
                    if (type(item) is not dict
                            or set(item) != {"check_kind", "provider_id", "subject_ref",
                                             "action_ref", "purpose", "criteria_version",
                                             "required_input_versions"}
                            or type(item["required_input_versions"]) is not list):
                        raise ValueError("required check requires exact JSON fields")
                    versions = []
                    for version in item["required_input_versions"]:
                        if type(version) is not dict or set(version) != {"ref", "version"}:
                            raise ValueError("required input version requires exact JSON fields")
                        versions.append(VersionedRef(**version))
                    checks.append(RequiredCheckSpec(
                        item["check_kind"], item["provider_id"], item["subject_ref"],
                        item["action_ref"], item["purpose"], item["criteria_version"],
                        tuple(versions),
                    ))
                schemas.append(ActionSchema(
                    row["schema_id"], row["action_kind"], row["proactive"],
                    tuple(checks),
                ))
            compiled = tuple(schemas)
            provider.compile_scheme(compiled)
        except (KeyError, TypeError, ValueError) as exc:
            return _reject(domain, fields, field_input_digest, (
                D12SchemeDiagnosticV1(ACTION_SCHEMAS_FIELD, "invalid_action_schemas", str(exc)),
            ))
        proposal_hash = provider.descriptor.request_schema_hash
        return D12ActionSchemasCandidateV1(
            namespace, "d08", (ACTION_SCHEMAS_FIELD,), field_input_digest,
            proposal_hash, compiled, canonical_digest({
                "schema": "d12.action-schemas-candidate.v1",
                "namespace": namespace, "field_input_digest": field_input_digest,
                "proposal_schema_hash": proposal_hash,
                "schemas": tuple(asdict(item) for item in compiled),
            }),
        )

    if domain == "d01":
        provider = PersonaDomain()
        try:
            spec = next(item for item in provider.type_specs()
                        if item.name == "d01.persona_plan.v1")
            spec.validator(value)
            plan = PersonaPlan(
                value["plan_id"], NamespaceId(**value["namespace"]),
                value["version"],
                tuple(PersonaBlock(**item) for item in value["blocks"]),
                tuple(ValueRule(
                    item["rule_id"], item["label"], tuple(item["applies_to"]),
                    tuple(item["supports_candidates"]),
                    tuple(item["rejects_candidates"]),
                ) for item in value["values"]),
                value["authored"],
            )
            if plan.namespace != namespace:
                raise ValueError("persona plan namespace differs from current creator")
            scheme = provider.compile_scheme(plan)
        except (KeyError, TypeError, ValueError) as exc:
            return _reject(domain, fields, field_input_digest, (
                D12SchemeDiagnosticV1(PERSONA_PLAN_FIELD, "invalid_persona_plan", str(exc)),
            ))
        proposal_hash = provider.descriptor.request_schema_hash
        return D12PersonaPlanCandidateV1(
            "d01", (PERSONA_PLAN_FIELD,), field_input_digest, proposal_hash,
            plan, scheme, canonical_digest({
                "schema": "d12.persona-plan-candidate.v1",
                "field_input_digest": field_input_digest,
                "proposal_schema_hash": proposal_hash,
                "plan": asdict(plan), "scheme": asdict(scheme),
            }),
        )

    if domain == "d03":
        provider = ContextProvider()  # A fresh compiler; never mutate the installed provider.
        try:
            if (type(value) is not dict
                    or set(value) != {"schema", "roles", "norms"}
                    or type(value["roles"]) is not list
                    or type(value["norms"]) is not list):
                raise ValueError("context scheme requires exact JSON fields and arrays")
            draft = deepcopy(value)
            draft["roles"] = tuple(draft["roles"])
            draft["norms"] = tuple(draft["norms"])
            compiled = provider.compile_scheme(draft, None)
        except (TypeError, ValueError) as exc:
            return _reject(domain, fields, field_input_digest, (
                D12SchemeDiagnosticV1(
                    CONTEXT_SCHEME_FIELD, "invalid_context_scheme", str(exc)),
            ))
        proposal_hash = provider.descriptor.request_schema_hash
        return D12ContextSchemeCandidateV1(
            namespace, "d03", (CONTEXT_SCHEME_FIELD,), field_input_digest,
            proposal_hash, compiled["schema"], compiled["roles"], compiled["norms"],
            canonical_digest({
                "schema": "d12.context-scheme-candidate.v1",
                "namespace": namespace, "field_input_digest": field_input_digest,
                "proposal_schema_hash": proposal_hash, "compiled": compiled,
            }),
        )

    if domain == "d05":
        provider = RelationshipProvider()  # An isolated compiler instance.
        try:
            if (type(value) is not dict
                    or set(value) != {"schema", "dimensions", "contribution_semantics"}
                    or type(value["dimensions"]) is not list
                    or type(value["contribution_semantics"]) is not list):
                raise ValueError("relationship scheme requires exact JSON fields and arrays")
            draft = deepcopy(value)
            draft["dimensions"] = tuple(draft["dimensions"])
            draft["contribution_semantics"] = tuple(draft["contribution_semantics"])
            compiled = provider.compile_scheme(draft, None)
        except (TypeError, ValueError) as exc:
            return _reject(domain, fields, field_input_digest, (
                D12SchemeDiagnosticV1(
                    RELATIONSHIP_SCHEME_FIELD, "invalid_relationship_scheme", str(exc)),
            ))
        proposal_hash = provider.descriptor.request_schema_hash
        return D12RelationshipSchemeCandidateV1(
            namespace, "d05", (RELATIONSHIP_SCHEME_FIELD,), field_input_digest,
            proposal_hash, compiled["schema"], compiled["dimensions"],
            compiled["contribution_semantics"], canonical_digest({
                "schema": "d12.relationship-scheme-candidate.v1",
                "namespace": namespace, "field_input_digest": field_input_digest,
                "proposal_schema_hash": proposal_hash, "compiled": compiled,
            }),
        )

    if domain == "d10":
        provider = LifeDomain()
        try:
            spec = next(item for item in provider.type_specs()
                        if item.name == "d10.activity_recipe.v1")
            spec.validator(value)
            if type(value["allowed_steps"]) is not list:
                raise ValueError("allowed_steps must be a JSON array")
            recipe = ActivityRecipe(
                value["recipe_id"], value["version"], value["reality"],
                tuple(value["allowed_steps"]), value["preemptible"],
            )
            compiled = provider.compile_scheme(recipe)
        except (KeyError, TypeError, ValueError) as exc:
            return _reject(domain, fields, field_input_digest, (
                D12SchemeDiagnosticV1(
                    ACTIVITY_RECIPE_FIELD, "invalid_activity_recipe", str(exc)),
            ))
        proposal_hash = provider.descriptor.request_schema_hash
        return D12ActivityRecipeCandidateV1(
            namespace, "d10", (ACTIVITY_RECIPE_FIELD,), field_input_digest,
            proposal_hash, compiled, canonical_digest({
                "schema": "d12.activity-recipe-candidate.v1",
                "namespace": namespace,
                "field_input_digest": field_input_digest,
                "proposal_schema_hash": proposal_hash,
                "recipe": asdict(compiled),
            }),
        )

    try:
        if type(value) is not dict or set(value) != _BODY_PROFILE_KEYS:
            raise ValueError("body profile requires exact graph JSON fields")
        scope = value["namespace"]
        if type(scope) is not dict or set(scope) != {"bot_id", "persona_id"}:
            raise ValueError("namespace requires bot_id and persona_id")
        if (type(value["applicable_axes"]) is not list
                or type(value["work_kinds"]) is not list):
            raise ValueError("applicable_axes and work_kinds must be JSON arrays")
        profile = BodyProfile(
            value["profile_id"], NamespaceId(**scope), value["version"],
            tuple(value["applicable_axes"]), tuple(value["work_kinds"]),
        )
        if profile.namespace != namespace:
            raise ValueError("body profile namespace differs from current creator")
        compiled = BodyDomain.compile_scheme(profile)
    except (TypeError, ValueError) as exc:
        return _reject(domain, fields, field_input_digest, (
            D12SchemeDiagnosticV1(BODY_PROFILE_FIELD, "invalid_body_profile", str(exc)),
        ))
    proposal_hash = BodyDomain().descriptor.request_schema_hash
    return D12BodyProfileCandidateV1(
        "d02", (BODY_PROFILE_FIELD,), field_input_digest, proposal_hash,
        compiled, canonical_digest({
            "schema": "d12.body-profile-candidate.v1",
            "field_input_digest": field_input_digest,
            "proposal_schema_hash": proposal_hash,
            "profile": asdict(compiled),
        }),
    )


__all__ = (
    "BODY_PROFILE_FIELD", "PERSONA_PLAN_FIELD", "ACTIVITY_RECIPE_FIELD",
    "CONTEXT_SCHEME_FIELD", "RELATIONSHIP_SCHEME_FIELD",
    "AFFECT_SCHEME_FIELD", "AUTHORED_ROOT_FIELD", "ACTION_SCHEMAS_FIELD",
    "ENCODING_PROJECTION_POLICY_FIELD", "ATTENTION_POLICY_FIELD",
    "EXPRESSION_POLICY_FIELD",
    "D12BodyProfileCandidateV1", "D12PersonaPlanCandidateV1",
    "D12ActivityRecipeCandidateV1", "D12ContextSchemeCandidateV1",
    "D12RelationshipSchemeCandidateV1",
    "D12AffectSchemeCandidateV1", "D12AuthoredRootSelectionCandidateV1",
    "D12ActionSchemasCandidateV1",
    "D12EncodingProjectionPolicyCandidateV1", "D12AttentionPolicyCandidateV1",
    "D12ExpressionPolicyCandidateV1",
    "compile_d12_domain_scheme_candidate_v1",
)
