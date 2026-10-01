"""D12 accepts only the real D02 body profile shape in this compiler slice."""

from copy import deepcopy

from sylanne3.domains.d01 import PersonaDomain, PersonaPlan, PersonaScheme
from sylanne3.domains.d02 import BodyDomain, BodyProfile
from sylanne3.domains.d03 import ContextProvider
from sylanne3.domains.d04 import AffectProvider, AffectScheme
from sylanne3.domains.d05 import RelationshipProvider
from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.domains.d06.encoding_projection import EncodingProjectionPolicyV1
from sylanne3.domains.d07 import AttentionPolicy, D07DomainProvider
from sylanne3.domains.d08 import BASE_REQUIRED_PROVIDERS, ActionSchema, GoalExecutionProvider
from sylanne3.domains.d10 import ActivityRecipe, LifeDomain
from sylanne3.domains.d12.scheme_command import D12DomainCompileRejectionV1
from sylanne3.runtime.d12_domain_scheme_compile_v1 import (
    D12ActivityRecipeCandidateV1, D12BodyProfileCandidateV1,
    D12ContextSchemeCandidateV1, D12PersonaPlanCandidateV1,
    D12RelationshipSchemeCandidateV1,
    D12AffectSchemeCandidateV1, D12ActionSchemasCandidateV1,
    D12EncodingProjectionPolicyCandidateV1, D12AttentionPolicyCandidateV1,
    compile_d12_domain_scheme_candidate_v1,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


NAMESPACE = NamespaceId("bot", "persona")
DRAFT_DIGEST = "a" * 64
PROFILE = {
    "profile_id": "body:default", "namespace": {"bot_id": "bot", "persona_id": "persona"},
    "version": 1, "applicable_axes": ["energy", "load"],
    "work_kinds": ["thinking"],
}
PERSONA_PLAN = {
    "plan_id": "plan:creator", "namespace": {"bot_id": "bot", "persona_id": "persona"},
    "version": 1, "authored": True,
    "blocks": [
        {"block_id": "identity", "kind": "semantic_identity",
         "claim": "reliable companion", "plasticity": "read_only"},
    ],
    "values": [
        {"rule_id": "truth", "label": "be truthful", "applies_to": ["reply"],
         "supports_candidates": ["honest"], "rejects_candidates": ["fabricated"]},
    ],
}
ACTIVITY_RECIPE = {
    "recipe_id": "recipe:one", "version": 1, "reality": "role_simulation",
    "allowed_steps": ["draft", "review"], "preemptible": True,
}
CONTEXT_SCHEME = {
    "schema": "d03.context.scheme.v1", "roles": ["friend", "assistant"],
    "norms": ["private"],
}
RELATIONSHIP_SCHEME = {
    "schema": "d05.relationship.scheme.v1", "dimensions": ["trust", "care"],
    "contribution_semantics": ["external_observation", "recollection"],
}
AFFECT_SCHEME = {
    "schema": "d04.affect.scheme.v1", "scheme_version": "scheme:1",
    "operator_version": "operator:1", "parameter_version": "parameters:1",
    "coupling_version": "coupling:1",
    "axes": [{"axis_id": "gain_engagement:fast", "unit": "normalized",
              "meaning": "engagement"}],
    "parameter_bounds": [["recovery_rate", 0.0, 1.0]],
}
ACTION_SCHEMAS = [{
    "schema_id": "schema:one", "action_kind": "reply", "proactive": False,
    "required_checks": [{
        "check_kind": kind, "provider_id": provider,
        "subject_ref": "persona:one", "action_ref": "action:one",
        "purpose": "reply", "criteria_version": f"criteria:{kind}",
        "required_input_versions": [{"ref": f"criteria:{kind}", "version": 1}],
    } for kind, provider in BASE_REQUIRED_PROVIDERS],
}]
ENCODING_POLICY = {
    "policy_ref": "policy:encoding:one", "policy_version": "version:one",
    "salience_gain": 0.4, "tone_magnitude_gain": 0.3,
    "neutral_salience": 0.5, "schema": "d06.encoding_projection_policy.v1",
}
ATTENTION_POLICY = {
    name: getattr(AttentionPolicy.default(), name)
    for name in AttentionPolicy.__dataclass_fields__
}


def _compile(domain="d02", fields=None, *, digest=None):
    fields = fields if fields is not None else (("d02.body_profile", deepcopy(PROFILE),
                                                 "administrative_edit"),)
    field_digest = digest or canonical_digest((DRAFT_DIGEST, domain, fields))
    return compile_d12_domain_scheme_candidate_v1(
        namespace=NAMESPACE, draft_digest=DRAFT_DIGEST, domain=domain,
        fields=fields, field_input_digest=field_digest,
    )


def test_canonical_d02_json_compiles_to_typed_unpersisted_candidate():
    fields = (("d02.body_profile", deepcopy(PROFILE), "administrative_edit"),)
    candidate = _compile(fields=fields)
    assert type(candidate) is D12BodyProfileCandidateV1
    assert candidate.profile == BodyProfile(
        "body:default", NAMESPACE, 1, ("energy", "load"), ("thinking",),
    )
    assert candidate.profile is BodyDomain.compile_scheme(candidate.profile)
    assert candidate.field_input_digest == canonical_digest((DRAFT_DIGEST, "d02", fields))
    assert candidate.proposal_schema_hash == BodyDomain().descriptor.request_schema_hash
    assert candidate.status == "typed_candidate_not_persisted"
    assert not hasattr(candidate, "candidate_ref")
    assert fields[0][1] == PROFILE


def test_canonical_d01_json_uses_existing_validator_and_typed_compiler():
    fields = (("d01.persona_plan", deepcopy(PERSONA_PLAN), "administrative_edit"),)
    candidate = _compile("d01", fields)
    assert type(candidate) is D12PersonaPlanCandidateV1
    assert type(candidate.plan) is PersonaPlan
    assert type(candidate.scheme) is PersonaScheme
    assert candidate.scheme == PersonaDomain().compile_scheme(candidate.plan)
    assert candidate.scheme.head_id == "plan:creator@1"
    assert candidate.field_input_digest == canonical_digest((DRAFT_DIGEST, "d01", fields))
    assert candidate.proposal_schema_hash == PersonaDomain().descriptor.request_schema_hash
    assert candidate.status == "typed_candidate_not_persisted"
    assert not hasattr(candidate, "candidate_ref")
    assert fields[0][1] == PERSONA_PLAN


def test_d01_rejects_malformed_nested_data_wrong_namespace_and_mixed_fields():
    wrong_block = deepcopy(PERSONA_PLAN)
    wrong_block["blocks"][0]["plasticity"] = "growth"
    wrong_namespace = deepcopy(PERSONA_PLAN)
    wrong_namespace["namespace"]["persona_id"] = "other"
    for payload in (wrong_block, wrong_namespace,
                    PERSONA_PLAN | {"unexpected": True}):
        result = _compile("d01", (("d01.persona_plan", payload,
                                    "administrative_edit"),))
        assert type(result) is D12DomainCompileRejectionV1
        assert result.diagnostics[0].field_path == "d01.persona_plan"
        assert result.diagnostics[0].code == "invalid_persona_plan"
    mixed = _compile("d01", (
        ("d01.persona_plan", deepcopy(PERSONA_PLAN), "administrative_edit"),
        ("d01.unknown", "value", "administrative_edit"),
    ))
    assert type(mixed) is D12DomainCompileRejectionV1
    assert mixed.diagnostics[0].field_path == "d01.unknown"


def test_canonical_d10_json_compiles_to_namespace_bound_unpersisted_recipe():
    fields = (("d10.activity_recipe", deepcopy(ACTIVITY_RECIPE),
               "administrative_edit"),)
    candidate = _compile("d10", fields)
    assert type(candidate) is D12ActivityRecipeCandidateV1
    assert candidate.namespace == NAMESPACE
    assert candidate.recipe == ActivityRecipe(
        "recipe:one", 1, "role_simulation", ("draft", "review"), True,
    )
    assert candidate.recipe is LifeDomain.compile_scheme(candidate.recipe)
    assert candidate.field_input_digest == canonical_digest((DRAFT_DIGEST, "d10", fields))
    assert candidate.proposal_schema_hash == LifeDomain().descriptor.request_schema_hash
    assert candidate.status == "typed_candidate_not_persisted"
    assert not hasattr(candidate, "candidate_ref")
    assert fields[0][1] == ACTIVITY_RECIPE


def test_d10_rejects_non_array_steps_extra_fields_and_mixed_fields():
    non_array = ACTIVITY_RECIPE | {"allowed_steps": "draft"}
    extra = ACTIVITY_RECIPE | {"effect": "completed"}
    for payload in (non_array, extra):
        result = _compile("d10", (("d10.activity_recipe", payload,
                                    "administrative_edit"),))
        assert type(result) is D12DomainCompileRejectionV1
        assert result.diagnostics[0].field_path == "d10.activity_recipe"
        assert result.diagnostics[0].code == "invalid_activity_recipe"
    mixed = _compile("d10", (
        ("d10.activity_recipe", deepcopy(ACTIVITY_RECIPE), "administrative_edit"),
        ("d10.unknown", "value", "administrative_edit"),
    ))
    assert type(mixed) is D12DomainCompileRejectionV1
    assert mixed.diagnostics[0].field_path == "d10.unknown"


def test_d03_d05_exact_schemes_compile_on_fresh_providers_only():
    installed_d03 = ContextProvider()
    installed_d05 = RelationshipProvider()
    assert installed_d03._roles == frozenset()
    assert installed_d05._dimensions == frozenset()
    for domain, path, payload, candidate_type, expected in (
        ("d03", "d03.context_scheme", CONTEXT_SCHEME,
         D12ContextSchemeCandidateV1, ("roles", ("friend", "assistant"))),
        ("d05", "d05.relationship_scheme", RELATIONSHIP_SCHEME,
         D12RelationshipSchemeCandidateV1, ("dimensions", ("trust", "care"))),
    ):
        fields = ((path, deepcopy(payload), "administrative_edit"),)
        candidate = _compile(domain, fields)
        assert type(candidate) is candidate_type
        assert candidate.namespace == NAMESPACE
        assert candidate.field_input_digest == canonical_digest((DRAFT_DIGEST, domain, fields))
        assert getattr(candidate, expected[0]) == expected[1]
        assert candidate.status == "typed_candidate_not_persisted"
        assert not hasattr(candidate, "candidate_ref")
        assert fields[0][1] == payload
    assert installed_d03._roles == frozenset()
    assert installed_d05._dimensions == frozenset()


def test_d03_d05_malformed_unknown_and_mixed_fields_reject():
    for domain, path, payload in (
        ("d03", "d03.context_scheme", CONTEXT_SCHEME),
        ("d05", "d05.relationship_scheme", RELATIONSHIP_SCHEME),
    ):
        invalid = payload | {"extra": True}
        rejected = _compile(domain, ((path, invalid, "administrative_edit"),))
        assert type(rejected) is D12DomainCompileRejectionV1
        assert rejected.diagnostics[0].field_path == path
        malformed = deepcopy(payload)
        array_name = "roles" if domain == "d03" else "dimensions"
        malformed[array_name] = "one"
        rejected = _compile(domain, ((path, malformed, "administrative_edit"),))
        assert type(rejected) is D12DomainCompileRejectionV1
        assert rejected.diagnostics[0].field_path == path
        mixed = _compile(domain, (
            (path, deepcopy(payload), "administrative_edit"),
            (f"{domain}.unknown", "value", "administrative_edit"),
        ))
        assert type(mixed) is D12DomainCompileRejectionV1
        assert mixed.diagnostics[0].field_path == f"{domain}.unknown"


def test_d04_exact_json_compiles_via_affect_owner_and_rejects_malformed():
    fields = (("d04.affect_scheme", deepcopy(AFFECT_SCHEME), "administrative_edit"),)
    result = _compile("d04", fields)
    assert type(result) is D12AffectSchemeCandidateV1
    assert type(result.scheme) is AffectScheme
    assert result.scheme == AffectProvider().compile_scheme(result.scheme)
    assert result.proposal_schema_hash == AffectProvider().descriptor.request_schema_hash
    assert result.status == "typed_candidate_not_persisted"
    assert fields[0][1] == AFFECT_SCHEME
    for bad in (AFFECT_SCHEME | {"extra": True},
                AFFECT_SCHEME | {"parameter_bounds": [["recovery_rate", 2.0, 1.0]]},
                AFFECT_SCHEME | {"axes": [AFFECT_SCHEME["axes"][0] | {"extra": True}]}):
        rejected = _compile("d04", (("d04.affect_scheme", bad, "administrative_edit"),))
        assert type(rejected) is D12DomainCompileRejectionV1
        assert rejected.diagnostics[0].code == "invalid_affect_scheme"


def test_d08_exact_action_schema_json_uses_owner_registry_validation():
    fields = (("d08.action_schemas", deepcopy(ACTION_SCHEMAS), "administrative_edit"),)
    result = _compile("d08", fields)
    assert type(result) is D12ActionSchemasCandidateV1
    assert len(result.schemas) == 1 and type(result.schemas[0]) is ActionSchema
    assert GoalExecutionProvider().compile_scheme(result.schemas) is not None
    assert result.proposal_schema_hash == GoalExecutionProvider().descriptor.request_schema_hash
    assert result.status == "typed_candidate_not_persisted"
    assert fields[0][1] == ACTION_SCHEMAS
    for bad in (ACTION_SCHEMAS + [deepcopy(ACTION_SCHEMAS[0])],
                [ACTION_SCHEMAS[0] | {"extra": True}],
                [ACTION_SCHEMAS[0] | {"required_checks":
                 ACTION_SCHEMAS[0]["required_checks"][:-1]}]):
        rejected = _compile("d08", (("d08.action_schemas", bad, "administrative_edit"),))
        assert type(rejected) is D12DomainCompileRejectionV1
        assert rejected.diagnostics[0].code == "invalid_action_schemas"


def test_d06_d07_owner_policy_compilers_accept_only_complete_typed_json():
    for domain, field, payload, candidate_type, owner in (
        ("d06", "d06.encoding_projection_policy", ENCODING_POLICY,
         D12EncodingProjectionPolicyCandidateV1, D06DomainProvider()),
        ("d07", "d07.attention_policy", ATTENTION_POLICY,
         D12AttentionPolicyCandidateV1, D07DomainProvider()),
    ):
        fields = ((field, deepcopy(payload), "administrative_edit"),)
        result = _compile(domain, fields)
        assert type(result) is candidate_type
        assert result.policy == owner.compile_scheme(result.policy)
        assert result.proposal_schema_hash == owner.descriptor.request_schema_hash
        assert result.status == "typed_candidate_not_persisted"
        assert fields[0][1] == payload
        rejected = _compile(domain, ((field, payload | {"extra": True},
                                      "administrative_edit"),))
        assert type(rejected) is D12DomainCompileRejectionV1
        bad = dict(payload)
        bad["salience_gain" if domain == "d06" else "primary_limit"] = 2
        rejected = _compile(domain, ((field, bad, "administrative_edit"),))
        assert type(rejected) is D12DomainCompileRejectionV1


def test_unmapped_policy_fields_stay_unsupported():
    for domain, field in (("d06", "d06.access_policy"),
                          ("d07", "d07.reflection_policy")):
        rejected = _compile(domain, ((field, {}, "administrative_edit"),))
        assert type(rejected) is D12DomainCompileRejectionV1
        assert rejected.diagnostics[0].code == "unsupported_scheme_field"


def test_unmapped_domain_fields_each_reject_without_success_receipts():
    for domain in ("d01", "d03", "d04", "d05", "d06", "d07", "d08", "d09", "d10"):
        fields = tuple((f"{domain}.{name}", "value", "administrative_edit")
                       for name in ("first", "second"))
        result = _compile(domain, fields)
        assert type(result) is D12DomainCompileRejectionV1
        assert tuple(item.field_path for item in result.diagnostics) == tuple(
            item[0] for item in fields
        )
        assert all(item.code == "unsupported_scheme_field" for item in result.diagnostics)


def test_wrong_json_shape_scope_and_frozen_digest_reject_at_field():
    malformed = deepcopy(PROFILE)
    malformed["work_kinds"] = "thinking"
    wrong_scope = deepcopy(PROFILE)
    wrong_scope["namespace"]["persona_id"] = "another"
    for payload in (malformed, wrong_scope, PROFILE | {"unexpected": True}):
        result = _compile(fields=(("d02.body_profile", payload, "administrative_edit"),))
        assert type(result) is D12DomainCompileRejectionV1
        assert result.diagnostics[0].field_path == "d02.body_profile"
        assert result.diagnostics[0].code == "invalid_body_profile"
    stale = _compile(digest="b" * 64)
    assert type(stale) is D12DomainCompileRejectionV1
    assert stale.diagnostics[0].code == "field_input_changed"
