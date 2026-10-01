"""Focused local checks for the uninstalled semantic mapping asset."""

from dataclasses import replace

import pytest

from sylanne3.domains.d04.affect import AppraisalBundle, MeaningFacet
from sylanne3.domains.d04.drive_allocation import RoleCondition
from sylanne3.domains.d04.mapping_asset_v2 import (
    DirectionFixtureV2, ExplicitMechanismSignalV2, MappingRuleV2,
    SemanticMappingAssetV2, compile_mapping_candidate_v2,
    compile_untrusted_suggestion_candidate_v2, load_mapping_asset_v2,
    seal_mapping_asset_v2, verify_direction_fixtures_v2,
)
from sylanne3.native_runtime.d04_engineering_scheme import LAYERS, MECHANISMS
from sylanne3.model_broker.d04_appraisal import (
    MechanismSignalSuggestionV1, UntrustedAppraisalSuggestionV1,
)


def _fixture():
    facet = MeaningFacet(
        "facet", "target", "interpretation", "value", "hypothesis",
        0.4, 0.5, "relationship concern", "self concern", 0.9, (), ("source",),
    )
    rules = tuple(MappingRuleV2(m, "anticipated_impact",
                                ("anticipated_impact",), (0.2, 0.1, 0.1))
                  for m in MECHANISMS)
    asset = SemanticMappingAssetV2(
        "local-calibration", "role", ("1",), "condition-1", "policy-1",
        tuple(f"{m}:{layer}" for m in MECHANISMS for layer in LAYERS),
        rules, 2.0, ("external_report",), ("candidate",),
        (DirectionFixtureV2("concern", "source", facet,
                            ("boundary_protection",), ("boundary_protection",),
                            "locally authored calibration example"),), "",
    )
    appraisal = AppraisalBundle(
        "appraisal", "event", "target", (facet,), ("interpretation",),
        ("source",), "reported", "external_report", "contribution", 1.0,
    )
    return seal_mapping_asset_v2(asset), appraisal


def test_mapping_asset_binds_digest_basis_role_and_direction():
    asset, appraisal = _fixture()
    assert load_mapping_asset_v2(asset) is asset
    verify_direction_fixtures_v2(asset)
    with pytest.raises(ValueError, match="digest"):
        load_mapping_asset_v2(replace(asset, max_family_dose=3.0))
    with pytest.raises(ValueError, match="24D"):
        load_mapping_asset_v2(seal_mapping_asset_v2(replace(asset, basis=asset.basis[::-1])))
    with pytest.raises(ValueError, match="exactly once"):
        load_mapping_asset_v2(seal_mapping_asset_v2(replace(asset, rules=asset.rules[:-1])))
    role = RoleCondition("role", "1", "condition-1", "policy-1")
    signals = tuple(ExplicitMechanismSignalV2("facet", m, "source", "concern")
                    for m in MECHANISMS)
    result = compile_mapping_candidate_v2(asset, role, (appraisal,), signals,
                                          interpretation_level="candidate",
                                          source_family_by_ref={"source": "family-1"})
    assert result.status == "HOLD"
    assert result.held_reasons == ()
    assert result.policy is not None
    assert result.signals[0].magnitude == 0.5
    assert result.family_dose_l1 == pytest.approx(1.6)
    assert "owner_installed_mapping_receipt" in result.missing_authority
    stale = compile_mapping_candidate_v2(asset, replace(role, persona_version="2"),
                                         (appraisal,), signals,
                                         interpretation_level="candidate",
                                         source_family_by_ref={"source": "family-1"})
    assert stale.policy is None
    assert "role_scope_or_version_mismatch" in stale.held_reasons


def test_unknown_external_claim_and_family_cap_hold():
    asset, appraisal = _fixture()
    role = RoleCondition("role", "1", "condition-1", "policy-1")
    signals = tuple(ExplicitMechanismSignalV2("facet", m, "source", "concern")
                    for m in MECHANISMS)
    unknown = replace(appraisal.meaning_facets[0], anticipated_impact=None,
                      unknown_fields=("anticipated_impact",))
    unknown_appraisal = replace(appraisal, meaning_facets=(unknown,))
    result = compile_mapping_candidate_v2(asset, role, (unknown_appraisal,), signals,
                                          interpretation_level="candidate",
                                          source_family_by_ref={"source": "family-1"})
    assert "required_semantic_field_unknown" in result.held_reasons
    assert result.policy is None
    disallowed = compile_mapping_candidate_v2(asset, role, (appraisal,), signals,
                                               interpretation_level="adopted",
                                               source_family_by_ref={"source": "family-1"})
    assert "interpretation_level_not_allowed" in disallowed.held_reasons
    tight_asset = seal_mapping_asset_v2(replace(asset, max_family_dose=0.1))
    capped = compile_mapping_candidate_v2(tight_asset, role, (appraisal,), signals,
                                          interpretation_level="candidate",
                                          source_family_by_ref={"source": "family-1"})
    assert "family_dose_cap_exceeded" in capped.held_reasons
    assert capped.policy is None
    bad_source = replace(signals[0], source_ref="other")
    mismatch = compile_mapping_candidate_v2(asset, role, (appraisal,), (bad_source,),
                                            interpretation_level="candidate",
                                            source_family_by_ref={"source": "family-1"})
    assert "signal_source_not_in_facet" in mismatch.held_reasons


def test_real_broker_suggestion_is_only_a_held_candidate():
    asset, appraisal = _fixture()
    role = RoleCondition("role", "1", "condition-1", "policy-1")
    broker = UntrustedAppraisalSuggestionV1(
        bundle=appraisal,
        mechanism_signals=tuple(MechanismSignalSuggestionV1(
            "facet", m, "subjective rationale", ("source",)) for m in MECHANISMS),
        possible_feelings=(), unknown_fields=(), source_refs=("source",),
        qualified_source_refs=("source",), basis_refs=(),
        frozen_input_digest="input-digest", provider_wire_digest="wire-digest",
        model_request_digest="request-digest", provider_id="provider",
        model_id="model", provider_config_ref="config",
        provider_config_digest="config-digest", output_digest="output-digest",
        canonical_output="{}",
    )
    result = compile_untrusted_suggestion_candidate_v2(
        asset, role, broker, interpretation_level="candidate",
        source_family_by_ref={"source": "family-1"})
    assert result.status == "HOLD"
    assert result.policy is not None
    assert result.signals[0].magnitude == 0.5
    sparse = replace(broker, mechanism_signals=broker.mechanism_signals[:1])
    result = compile_untrusted_suggestion_candidate_v2(
        asset, role, sparse, interpretation_level="candidate",
        source_family_by_ref={"source": "family-1"})
    assert result.policy is None
    assert "incomplete_eight_mechanism_signal_coverage" in result.held_reasons


def test_d06_family_roots_are_required_and_cap_spans_facets():
    asset, first = _fixture()
    role = RoleCondition("role", "1", "condition-1", "policy-1")
    second_facet = replace(first.meaning_facets[0], facet_id="facet-2",
                           source_refs=("source-2",))
    second = replace(first, appraisal_id="appraisal-2", event_ref="event-2",
                     meaning_facets=(second_facet,), source_refs=("source-2",),
                     contribution_key="contribution-2")
    signals = tuple(ExplicitMechanismSignalV2(facet, m, source, "concern")
                    for facet, source in (("facet", "source"),
                                          ("facet-2", "source-2"))
                    for m in MECHANISMS)
    independent = compile_mapping_candidate_v2(
        asset, role, (first, second), signals,
        interpretation_level="candidate",
        source_family_by_ref={"source": "root-1", "source-2": "root-2"})
    assert independent.policy is not None
    assert independent.family_dose_l1 == pytest.approx(3.2)
    shared = compile_mapping_candidate_v2(
        asset, role, (first, second), signals,
        interpretation_level="candidate",
        source_family_by_ref={"source": "root-1", "source-2": "root-1"})
    assert shared.policy is None
    assert "family_dose_cap_exceeded" in shared.held_reasons
    missing = compile_mapping_candidate_v2(
        asset, role, (first, second), signals,
        interpretation_level="candidate",
        source_family_by_ref={"source": "root-1"})
    assert missing.policy is None
    assert "d06_source_family_root_missing" in missing.held_reasons


def test_one_facet_with_two_source_records_in_family_counts_one_claim_dose():
    asset, appraisal = _fixture()
    role = RoleCondition("role", "1", "condition-1", "policy-1")
    facet = replace(appraisal.meaning_facets[0], source_refs=("source", "source-2"))
    appraisal = replace(appraisal, meaning_facets=(facet,),
                        source_refs=("source", "source-2"))
    signals = tuple(ExplicitMechanismSignalV2("facet", mechanism, source, "concern")
                    for source in facet.source_refs for mechanism in MECHANISMS)
    shared = compile_mapping_candidate_v2(
        asset, role, (appraisal,), signals, interpretation_level="candidate",
        source_family_by_ref={"source": "root", "source-2": "root"},
    )
    assert shared.policy is not None
    assert shared.family_dose_l1 == pytest.approx(1.6)
    assert len(shared.contribution_doses) == 1
    assert shared.contribution_doses[0].dose[0] == pytest.approx(0.1)
    assert len(shared.signals) == 16  # Both records remain provenance inputs.
    distinct = compile_mapping_candidate_v2(
        asset, role, (appraisal,), signals, interpretation_level="candidate",
        source_family_by_ref={"source": "root-1", "source-2": "root-2"},
    )
    assert distinct.family_dose_l1 == pytest.approx(3.2)
    assert len(distinct.contribution_doses) == 2
