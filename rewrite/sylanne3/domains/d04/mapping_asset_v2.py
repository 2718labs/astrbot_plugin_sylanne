"""Pure, locally calibrated D04 semantic mapping candidate.

Loading an asset and compiling a dose never installs it or adopts an appraisal.
W01 must authenticate the asset, current graph reads, and contribution consumption.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math

from ...native_runtime.d04_engineering_scheme import DIMENSION, LAYERS, MECHANISMS
from ...runtime_contracts import canonical_digest
from .affect import AppraisalBundle, MeaningFacet
from .drive_allocation import (
    CompiledDrivePolicy, CompiledMechanismRule,
    CompiledMeaningSignal, RoleCondition,
)


SCHEMA = "sylanne.d04.semantic_mapping_asset.v2"
REALITIES = frozenset({
    "external_observation", "external_report", "authored_content",
    "simulation", "inference",
})
INTERPRETATION_LEVELS = frozenset({"candidate", "contested", "adopted"})


@dataclass(frozen=True, slots=True)
class MappingRuleV2:
    mechanism_id: str
    magnitude_field: str
    required_known_fields: tuple[str, ...]
    layer_gains: tuple[float, float, float]


@dataclass(frozen=True, slots=True)
class DirectionFixtureV2:
    fixture_id: str
    source_ref: str
    facet: MeaningFacet
    signaled_mechanisms: tuple[str, ...]
    expected_positive_mechanisms: tuple[str, ...]
    provenance_note: str


@dataclass(frozen=True, slots=True)
class SemanticMappingAssetV2:
    asset_id: str
    role_ref: str
    persona_versions: tuple[str, ...]
    condition_version: str
    policy_version: str
    basis: tuple[str, ...]
    rules: tuple[MappingRuleV2, ...]
    max_family_dose: float
    allowed_realities: tuple[str, ...]
    allowed_interpretation_levels: tuple[str, ...]
    fixtures: tuple[DirectionFixtureV2, ...]
    content_digest: str
    schema: str = SCHEMA


@dataclass(frozen=True, slots=True)
class ExplicitMechanismSignalV2:
    facet_id: str
    mechanism_id: str
    source_ref: str
    rationale: str


@dataclass(frozen=True, slots=True)
class MappingCandidateV2:
    """Held semantic mapping result.

    ``signals`` are per-source evidence rows and must never be summed as
    product dose. W01 may construct numeric drives only from the deduplicated
    ``contribution_doses`` after authenticating each source and allocation.
    """
    policy: CompiledDrivePolicy | None
    signals: tuple[CompiledMeaningSignal, ...]
    family_dose_l1: float
    held_reasons: tuple[str, ...]
    status: str = "HOLD"
    missing_authority: tuple[str, ...] = (
        "owner_installed_mapping_receipt",
        "w01_current_graph_appraisal_and_role_verification",
        "w01_atomic_family_contribution_consumption",
    )
    contribution_doses: tuple["MappedContributionDoseV2", ...] = ()


@dataclass(frozen=True, slots=True)
class MappedContributionDoseV2:
    family_root: str
    event_ref: str
    contribution_key: str
    facet_id: str
    dose: tuple[float, ...]


def _body(asset: SemanticMappingAssetV2) -> dict:
    data = asdict(asset)
    data.pop("content_digest")
    return data


def seal_mapping_asset_v2(asset: SemanticMappingAssetV2) -> SemanticMappingAssetV2:
    """Return a content addressed local asset; sealing conveys no authority."""
    from dataclasses import replace
    return replace(asset, content_digest=canonical_digest(_body(asset)))


def load_mapping_asset_v2(asset: SemanticMappingAssetV2) -> SemanticMappingAssetV2:
    if type(asset) is not SemanticMappingAssetV2 or asset.schema != SCHEMA:
        raise ValueError("D04 mapping asset schema differs")
    if asset.content_digest != canonical_digest(_body(asset)):
        raise ValueError("D04 mapping asset content digest differs")
    if (not all((asset.asset_id, asset.role_ref, asset.condition_version,
                 asset.policy_version)) or not asset.persona_versions
            or len(set(asset.persona_versions)) != len(asset.persona_versions)
            or any(not value for value in asset.persona_versions)):
        raise ValueError("D04 mapping identity or role scope is incomplete")
    expected_basis = tuple(f"{m}:{layer}" for m in MECHANISMS for layer in LAYERS)
    if asset.basis != expected_basis or len(asset.basis) != DIMENSION:
        raise ValueError("D04 mapping must use the ordered 24D basis")
    if (len(asset.rules) != len(MECHANISMS)
            or {r.mechanism_id for r in asset.rules} != set(MECHANISMS)):
        raise ValueError("D04 mapping must cover each mechanism exactly once")
    for rule in asset.rules:
        CompiledMechanismRule(rule.mechanism_id, rule.layer_gains,
                              rule.required_known_fields)
        if (rule.magnitude_field not in {"controllability", "anticipated_impact"}
                or rule.magnitude_field not in rule.required_known_fields):
            raise ValueError("D04 magnitude needs an explicit known intensity field")
    if (type(asset.max_family_dose) not in (int, float)
            or not math.isfinite(asset.max_family_dose)
            or asset.max_family_dose <= 0):
        raise ValueError("D04 source family dose cap must be finite and positive")
    if (not asset.allowed_realities or not set(asset.allowed_realities) <= REALITIES
            or len(set(asset.allowed_realities)) != len(asset.allowed_realities)
            or not asset.allowed_interpretation_levels
            or not set(asset.allowed_interpretation_levels) <= INTERPRETATION_LEVELS
            or len(set(asset.allowed_interpretation_levels)) != len(asset.allowed_interpretation_levels)):
        raise ValueError("D04 reality or interpretation scope is invalid")
    if not asset.fixtures or len({f.fixture_id for f in asset.fixtures}) != len(asset.fixtures):
        raise ValueError("D04 sourced direction fixtures are required")
    for fixture in asset.fixtures:
        if (not fixture.fixture_id or not fixture.source_ref or not fixture.provenance_note
                or fixture.source_ref not in fixture.facet.source_refs
                or not fixture.signaled_mechanisms
                or not set(fixture.signaled_mechanisms) <= set(MECHANISMS)
                or not set(fixture.expected_positive_mechanisms) <= set(fixture.signaled_mechanisms)):
            raise ValueError("D04 direction fixture is untraceable or invalid")
    return asset


def compile_mapping_candidate_v2(
    asset: SemanticMappingAssetV2, role: RoleCondition,
    appraisals: tuple[AppraisalBundle, ...],
    signals: tuple[ExplicitMechanismSignalV2, ...],
    *, interpretation_level: str, source_family_by_ref: dict[str, str],
) -> MappingCandidateV2:
    """Compile subjective evidence rows and unique family contribution doses.

    A facet may cite multiple D06 records in one family. Those records remain
    separate in ``signals`` for provenance; only ``contribution_doses`` is a
    dose ledger for W01, and this pure candidate confers no adoption authority.
    """
    load_mapping_asset_v2(asset)
    if (type(role) is not RoleCondition or type(appraisals) is not tuple
            or type(signals) is not tuple or type(source_family_by_ref) is not dict):
        raise TypeError("typed D04 role, appraisals, signals and D06 family binding required")
    reasons: set[str] = set()
    if (role.role_ref != asset.role_ref or role.persona_version not in asset.persona_versions
            or role.condition_version != asset.condition_version
            or role.policy_version != asset.policy_version):
        reasons.add("role_scope_or_version_mismatch")
    if interpretation_level not in asset.allowed_interpretation_levels:
        reasons.add("interpretation_level_not_allowed")
    rules = {rule.mechanism_id: rule for rule in asset.rules}
    facets: dict[str, tuple[AppraisalBundle, MeaningFacet]] = {}
    for appraisal in appraisals:
        if type(appraisal) is not AppraisalBundle:
            raise TypeError("AppraisalBundle required")
        if appraisal.content_reality not in asset.allowed_realities:
            reasons.add("reality_level_not_allowed")
        for facet in appraisal.meaning_facets:
            if facet.facet_id in facets:
                reasons.add("ambiguous_facet_id")
            facets[facet.facet_id] = (appraisal, facet)
    compiled: list[CompiledMeaningSignal] = []
    seen: set[tuple[str, str, str]] = set()
    # A facet can cite several records from the same D06 family. They all
    # remain evidence dependencies, but they describe one causal dose.
    claim_signals: dict[tuple[str, str, str, str, str], float] = {}
    for signal in signals:
        if type(signal) is not ExplicitMechanismSignalV2:
            raise TypeError("ExplicitMechanismSignalV2 required")
        pair = facets.get(signal.facet_id)
        if pair is None or signal.mechanism_id not in rules or not signal.rationale:
            reasons.add("uncovered_or_unexplained_signal")
            continue
        appraisal, facet = pair
        if signal.source_ref not in facet.source_refs:
            reasons.add("signal_source_not_in_facet")
            continue
        family_root = source_family_by_ref.get(signal.source_ref)
        if type(family_root) is not str or not family_root:
            reasons.add("d06_source_family_root_missing")
            continue
        identity = (facet.facet_id, signal.mechanism_id, signal.source_ref)
        if identity in seen:
            reasons.add("duplicate_signal")
            continue
        seen.add(identity)
        rule = rules[signal.mechanism_id]
        if any(field in facet.unknown_fields or getattr(facet, field) is None
               or (field == "responsibility_hypothesis"
                   and facet.responsibility_hypothesis == "unknown")
               for field in rule.required_known_fields):
            reasons.add("required_semantic_field_unknown")
            continue
        magnitude = getattr(facet, rule.magnitude_field)
        if type(magnitude) not in (int, float) or not 0 <= magnitude <= 1:
            reasons.add("intensity_field_invalid")
            continue
        compiled.append(CompiledMeaningSignal(
            appraisal.appraisal_id, facet.facet_id,
            facet.interpretation_ref, signal.source_ref,
            signal.mechanism_id, float(magnitude),
        ))
        claim = (family_root, appraisal.event_ref, appraisal.contribution_key,
                 facet.facet_id, signal.mechanism_id)
        previous = claim_signals.get(claim)
        if previous is not None and previous != magnitude:
            reasons.add("conflicting_family_claim_signal")
        claim_signals[claim] = float(magnitude)
    if not signals:
        reasons.add("explicit_mechanism_signals_missing")
    for appraisal in appraisals:
        for facet in appraisal.meaning_facets:
            for source_ref in facet.source_refs:
                if any((facet.facet_id, mechanism, source_ref) not in seen
                       for mechanism in MECHANISMS):
                    reasons.add("incomplete_eight_mechanism_signal_coverage")
    claim_vectors: dict[tuple[str, str, str, str], list[float]] = {}
    for (*claim, mechanism_id), magnitude in claim_signals.items():
        vector = claim_vectors.setdefault(tuple(claim), [0.0] * DIMENSION)
        start = MECHANISMS.index(mechanism_id) * len(LAYERS)
        for layer, gain in enumerate(rules[mechanism_id].layer_gains):
            vector[start + layer] = gain * magnitude
    contribution_doses = tuple(MappedContributionDoseV2(
        *claim, tuple(vector),
    ) for claim, vector in sorted(claim_vectors.items()))
    family_doses: dict[str, float] = {}
    for item in contribution_doses:
        family_doses[item.family_root] = math.fsum((
            family_doses.get(item.family_root, 0.0),
            *(abs(value) for value in item.dose),
        ))
    if any(value > asset.max_family_dose for value in family_doses.values()):
        reasons.add("family_dose_cap_exceeded")
    policy = None
    if not reasons:
        policy = CompiledDrivePolicy(
            asset.asset_id + ":" + asset.content_digest,
            "d04.mapping_asset_v2:" + asset.content_digest,
            asset.condition_version, asset.policy_version,
            asset.max_family_dose,
            tuple(CompiledMechanismRule(r.mechanism_id, r.layer_gains,
                                        r.required_known_fields) for r in asset.rules),
        )
    return MappingCandidateV2(policy, tuple(compiled),
                              math.fsum(family_doses.values()), tuple(sorted(reasons)),
                              contribution_doses=contribution_doses)


def compile_untrusted_suggestion_candidate_v2(
    asset: SemanticMappingAssetV2, role: RoleCondition, suggestion: object,
    *, interpretation_level: str, source_family_by_ref: dict[str, str],
) -> MappingCandidateV2:
    """Adapt the actual broker wire without accepting its subjective claims."""
    from ...model_broker.d04_appraisal import UntrustedAppraisalSuggestionV1
    if type(suggestion) is not UntrustedAppraisalSuggestionV1:
        raise TypeError("untrusted D04 broker suggestion required")
    if suggestion.bundle is None:
        return MappingCandidateV2(None, (), 0.0,
                                  ("appraisal_bundle_missing",))
    qualified = set(suggestion.qualified_source_refs)
    if (suggestion.status != "untrusted_subjective_suggestion"
            or not set(suggestion.bundle.source_refs) <= qualified
            or any(not set(row.source_refs) <= qualified
                   for row in suggestion.mechanism_signals)):
        return MappingCandidateV2(None, (), 0.0,
                                  ("broker_source_or_status_unqualified",))
    signals = tuple(ExplicitMechanismSignalV2(
        row.facet_id, row.mechanism_id, source_ref, row.rationale,
    ) for row in suggestion.mechanism_signals for source_ref in row.source_refs)
    return compile_mapping_candidate_v2(asset, role, (suggestion.bundle,), signals,
                                        interpretation_level=interpretation_level,
                                        source_family_by_ref=source_family_by_ref)


def verify_direction_fixtures_v2(asset: SemanticMappingAssetV2) -> None:
    """Check local directional examples only; no psychological validity claim."""
    load_mapping_asset_v2(asset)
    rules = {r.mechanism_id: r for r in asset.rules}
    for fixture in asset.fixtures:
        for mechanism in fixture.expected_positive_mechanisms:
            rule = rules[mechanism]
            facet = fixture.facet
            if (any(field in facet.unknown_fields or getattr(facet, field) is None
                    for field in rule.required_known_fields)
                    or getattr(facet, rule.magnitude_field) <= 0
                    or not any(gain > 0 for gain in rule.layer_gains)):
                raise ValueError(f"D04 direction fixture failed: {fixture.fixture_id}")


__all__ = [
    "SCHEMA", "MappingRuleV2", "DirectionFixtureV2", "SemanticMappingAssetV2",
    "ExplicitMechanismSignalV2", "MappingCandidateV2", "MappedContributionDoseV2",
    "seal_mapping_asset_v2",
    "load_mapping_asset_v2", "compile_mapping_candidate_v2",
    "compile_untrusted_suggestion_candidate_v2",
    "verify_direction_fixtures_v2",
]
