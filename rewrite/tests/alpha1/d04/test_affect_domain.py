import importlib
import math
import tempfile
import unittest
from pathlib import Path

from sylanne3.domains.d04 import (
    AdvanceRequirements,
    AffectCandidate,
    AffectAxis,
    AffectCoupling,
    AffectProvider,
    AffectScheme,
    AppraisalBundle,
    CandidateRejection,
    FeelingState,
    MeaningFacet,
    MoodField,
    NumericCertificate,
    RegulationAttempt,
    RegulationObservation,
    SemanticDriveRule,
)
from sylanne3.contracts import Event, Scope
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry, TypeSpec
from sylanne3.runtime_contracts import (
    AuthorityContext,
    CommandEnvelope,
    DependencySet,
    DomainProposal,
    NamespaceId,
    OperationIdentity,
    QueryEpoch,
    SourceQualification,
    VersionGuard,
    canonical_digest,
)


def _scheme() -> AffectScheme:
    return AffectScheme(
        schema="d04.affect.scheme.v1",
        scheme_version="scheme:affect:1",
        operator_version="operator:affect:1",
        parameter_version="parameter:affect:1",
        coupling_version="coupling:affect:1",
        axes=(
            AffectAxis("care", "normalized", "wish to protect or approach"),
            AffectAxis("hurt", "normalized", "impact of disappointed expectation"),
            AffectAxis("guardedness", "normalized", "protective sensitivity"),
        ),
        parameter_bounds=(("recovery_rate", 0.01, 2.0),),
    )


def _appraisal(*, unknown: bool = False) -> AppraisalBundle:
    facet = MeaningFacet(
        facet_id="meaning:late-message:care-and-hurt",
        target_ref="entity:alice",
        interpretation_ref="interpretation:alice-was-delayed",
        value_ref="value:mutual-care",
        responsibility_hypothesis="unknown" if unknown else "circumstantial",
        controllability=None if unknown else 0.2,
        anticipated_impact=0.6,
        relation_meaning="wanted shared time",
        self_meaning=None,
        confidence=None if unknown else 0.7,
        unknown_fields=("controllability", "confidence") if unknown else (),
        source_refs=("source:message-delay",),
    )
    return AppraisalBundle(
        appraisal_id="appraisal:late-message:1",
        event_ref="world:late-message",
        target_ref="entity:alice",
        meaning_facets=(facet,),
        competing_interpretation_refs=("interpretation:alice-was-delayed", "interpretation:alice-did-not-care"),
        source_refs=("source:message-delay",),
        source_family="reported",
        content_reality="external_report",
        contribution_key="world:late-message|entity:alice|meaning:care-and-hurt|1",
        learned_at=10.0,
    )


def _feeling(*, cursor: float = 10.0, active_driver_refs=("world:late-message|entity:alice|meaning:care-and-hurt|1",)):
    return FeelingState(
        process_id="affect:late-message",
        target_ref="entity:alice",
        basis_version="scheme:affect:1",
        operator_version="operator:affect:1",
        coordinates=(("care", 0.75), ("hurt", 0.6)),
        meaning_refs=("meaning:late-message:care-and-hurt",),
        interpretation_refs=("interpretation:alice-was-delayed",),
        active_driver_refs=active_driver_refs,
        historical_source_refs=("source:message-delay",),
        parameter_version="parameter:affect:1",
        coupling_version="coupling:affect:1",
        cursor=cursor,
    )


def _proposal(domain: str) -> DomainProposal:
    key = AtomKey(Owner("persona", "bot", "persona"), "d04.feeling_state.v1", "affect:late-message")
    namespace = NamespaceId("bot", "persona")
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity(
            "activity:affect:1", None, "attempt:1", "prepare", "operation:affect:1",
            canonical_digest({"input_refs": ["source:message-delay"]}),
        ),
        AuthorityContext(
            "host:user", "d11", "capability:affect", namespace, ("persona",), "respond",
            ("entity:alice",), "policy:1", 1,
        ),
        VersionGuard(
            (GraphVersion(key, 0),), (QueryEpoch(namespace, "d04:affect", 0),), 0, 0,
            "catalogue:1", "scheme:affect:1", "operator:affect:1", "policy:1", (), (), (),
        ),
        SourceQualification(
            ("source:message-delay",), "reported", 9.0, 10.0, "external_report", "eligible", 0.7,
            "not_applicable",
        ),
        ("source:message-delay",), "budget:1", 20.0, 20.0, "clock:1", (),
    )
    return DomainProposal(
        domain, f"{domain}.proposal.v1", canonical_digest({"domain": domain, "proposal": 1}), envelope,
        (), DependencySet(), (), (),
    )


class AffectDomainImportTests(unittest.TestCase):
    def test_d04_public_contract_is_importable(self):
        try:
            module = importlib.import_module("sylanne3.domains.d04")
        except ModuleNotFoundError as exc:
            self.fail(f"D04 public contract is missing: {exc}")
        self.assertTrue(hasattr(module, "AffectProvider"))

    def test_d04_exposes_typed_continuous_affect_contracts(self):
        module = importlib.import_module("sylanne3.domains.d04")
        expected = (
            "AffectAxis",
            "AffectScheme",
            "MeaningFacet",
            "AppraisalBundle",
            "FeelingState",
            "MoodField",
            "AffectCoupling",
            "RecollectionInfluence",
            "InterpretationInfluence",
            "SelfUnderstanding",
            "RegulationAttempt",
            "RegulationObservation",
            "NumericCertificate",
            "AdvanceRequirements",
            "CorrectionResult",
            "AffectCandidate",
            "CandidateRejection",
            "SemanticDriveRule",
        )
        missing = tuple(name for name in expected if not hasattr(module, name))
        self.assertEqual(missing, ())

    def test_provider_exposes_domain_and_continuous_affect_operations(self):
        module = importlib.import_module("sylanne3.domains.d04")
        provider = module.AffectProvider()
        expected = (
            "descriptor",
            "register_types",
            "type_specs",
            "compile_scheme",
            "prepare_appraisal",
            "proposal_for",
            "build_feeling",
            "condition_interpretation",
            "condition_recollection",
            "interpret_feeling",
            "record_regulation",
            "correct_attribution",
            "adopt_advance",
            "propose_mixed_update",
            "reject_candidate",
            "adopt_candidate",
            "validate",
            "project",
            "invalidate",
            "cleanup",
        )
        missing = tuple(name for name in expected if not hasattr(provider, name))
        self.assertEqual(missing, ())


class ContinuousAffectTests(unittest.TestCase):
    def setUp(self):
        self.provider = AffectProvider()
        self.scheme = self.provider.compile_scheme(_scheme())

    def test_mixed_feelings_coexist_without_collapsing_to_one_label_or_score(self):
        appraisal = self.provider.prepare_appraisal(_appraisal())
        state = self.provider.build_feeling(
            appraisal,
            self.scheme,
            process_id="affect:late-message",
            coordinates=(("care", 0.75), ("hurt", 0.6)),
            cursor=10.0,
        )
        self.assertEqual(dict(state.coordinates), {"care": 0.75, "hurt": 0.6})
        self.assertEqual(state.target_ref, "entity:alice")
        self.assertEqual(state.active_driver_refs, (appraisal.contribution_key,))
        self.assertEqual(state.historical_source_refs, ("source:message-delay",))

    def test_unknown_appraisal_is_preserved_and_cannot_be_encoded_as_neutral(self):
        appraisal = self.provider.prepare_appraisal(_appraisal(unknown=True))
        self.assertEqual(appraisal.meaning_facets[0].unknown_fields, ("controllability", "confidence"))
        with self.assertRaisesRegex(ValueError, "unknown appraisal"):
            self.provider.build_feeling(
                appraisal,
                self.scheme,
                process_id="affect:unknown",
                coordinates=(),
                cursor=10.0,
            )

    def test_appraisal_rejects_source_or_unknown_upgrades(self):
        appraisal = _appraisal()
        with self.assertRaises(ValueError):
            AppraisalBundle(**{
                **appraisal.__dict__,
                "source_family": "simulated",
                "content_reality": "external_observation",
            })
        facet = appraisal.meaning_facets[0]
        with self.assertRaises(ValueError):
            AppraisalBundle(**{
                **appraisal.__dict__,
                "meaning_facets": (MeaningFacet(**{
                    **facet.__dict__, "source_refs": ("source:not-in-appraisal",),
                }),),
            })
        with self.assertRaises(ValueError):
            MeaningFacet(**{**facet.__dict__, "confidence": None, "unknown_fields": ()})

    def test_same_memory_has_different_mood_conditioned_feeling_without_new_evidence(self):
        coupling = AffectCoupling(
            "coupling:recall:1", "coupling:affect:1", "guardedness", "hurt",
            interpretation_gain=0.2, recall_salience_gain=0.3, recall_tone_gain=0.4,
        )
        guarded = MoodField(
            "mood:guarded", "scheme:affect:1", (("guardedness", 0.8),), ("source:prior-strain",),
            "parameter:affect:1", "coupling:affect:1", 10.0,
        )
        settled = MoodField(
            "mood:settled", "scheme:affect:1", (("guardedness", -0.4),), ("source:rest",),
            "parameter:affect:1", "coupling:affect:1", 10.0,
        )
        first = self.provider.condition_recollection(
            memory_ref="memory:shared-evening",
            memory_source_refs=("source:shared-evening",),
            base_salience_interval=(0.4, 0.5),
            base_tone_interval=(-0.05, 0.05),
            mood=guarded,
            coupling=coupling,
        )
        second = self.provider.condition_recollection(
            memory_ref="memory:shared-evening",
            memory_source_refs=("source:shared-evening",),
            base_salience_interval=(0.4, 0.5),
            base_tone_interval=(-0.05, 0.05),
            mood=settled,
            coupling=coupling,
        )
        self.assertNotEqual(first.tone_interval, second.tone_interval)
        self.assertNotEqual(first.salience_interval, second.salience_interval)
        self.assertEqual(first.source_refs, second.source_refs)
        self.assertEqual(first.evidence_weight_delta, 0.0)
        self.assertEqual(second.evidence_weight_delta, 0.0)

    def test_recollection_experience_is_activity_owned_and_keeps_evidence_separate(self):
        coupling = AffectCoupling("coupling:recall:1", "coupling:affect:1", "guardedness", "hurt", 0.2, 0.3, 0.4)
        mood = MoodField(
            "mood:guarded", "scheme:affect:1", (("guardedness", 0.8),),
            ("source:prior-strain",), "parameter:affect:1", "coupling:affect:1", 10.0,
        )
        influence = self.provider.condition_recollection(
            memory_ref="memory:shared-evening", memory_source_refs=("source:shared-evening",),
            base_salience_interval=(0.4, 0.5), base_tone_interval=(-0.05, 0.05),
            mood=mood, coupling=coupling,
        )
        envelope = _proposal("d04").envelope
        source_key = AtomKey(Owner("event", "bot", "persona", "shared-evening"), "d06.source.v1", "source:shared-evening")
        source_version = GraphVersion(source_key, 1)
        proposal = self.provider.propose_recollection_experience(
            envelope, experience_id="feeling:recall:1", recollection_ref="recollection:1",
            influence=influence, mood=mood, coupling=coupling,
            source_versions=(source_version,), dependencies=DependencySet(),
        )
        write = proposal.typed_writes[0]
        self.assertEqual(write.key.owner.kind, "activity")
        self.assertEqual(write.key.owner.subject, envelope.identity.activity_id)
        self.assertEqual(write.dependencies, ())
        self.assertEqual(proposal.dependencies.current_invalidation, ())
        self.assertEqual(proposal.dependencies.historical_provenance, (source_version,))
        self.assertEqual(write.value["salience_interval"], list(influence.salience_interval))
        self.assertEqual(write.value["tone_interval"], list(influence.tone_interval))
        self.assertEqual(write.value["mood_source_refs"], ["source:prior-strain"])
        self.assertEqual(write.value["evidence_weight_delta"], 0.0)
        self.assertEqual(proposal.required_bundle_parts, ("experience",))
        self.assertEqual(self.provider.validate(proposal, snapshot=self.scheme), proposal)

        registry = TypeRegistry()
        for registered in self.provider.type_specs():
            registry.register(registered)
        with tempfile.TemporaryDirectory() as directory:
            store = GraphStore(Path(directory) / "d04.db", registry)
            try:
                snapshot = store.graph_snapshot((write.key,))
                candidate = GraphCandidate(
                    Event(Scope("bot", "persona", "session"), "recollection-experience:1", 10.0,
                          "d04-recollection", {}),
                    snapshot.versions, proposal.typed_writes,
                )
                self.assertEqual(store.graph_commit(candidate).status, "committed")
                stored = store.graph_snapshot((write.key,)).atoms[0]
                self.assertEqual(stored.value["evidence_weight_delta"], 0.0)
                self.assertEqual(stored.value["memory_source_refs"], ["source:shared-evening"])
            finally:
                store.close()

        spec = next(spec for spec in self.provider.type_specs() if spec.name == "d04.recollection_experience.v1")
        self.assertEqual(spec.owner_kinds, ("activity",))
        self.assertTrue(spec.immutable)
        with self.assertRaisesRegex(ValueError, "evidence weight"):
            spec.validator({**write.value, "evidence_weight_delta": 0.1})
        with self.assertRaisesRegex(ValueError, "current invalidation"):
            self.provider.propose_recollection_experience(
                envelope, experience_id="feeling:recall:2", recollection_ref="recollection:1",
                influence=influence, mood=mood, coupling=coupling,
                source_versions=(source_version,),
                dependencies=DependencySet(current_invalidation=(source_version,)),
            )
        wrong_activity = GraphWrite(
            AtomKey(Owner("activity", "bot", "persona", "activity:other"), write.key.type_name, write.key.name),
            write.value, write.dependencies,
        )
        with self.assertRaisesRegex(ValueError, "identity"):
            self.provider.validate(DomainProposal(
                proposal.domain, proposal.proposal_schema, proposal.proposal_schema_hash,
                envelope, (wrong_activity,), proposal.dependencies,
                proposal.contribution_keys, proposal.required_bundle_parts,
            ), snapshot=self.scheme)

    def test_mood_changes_interpretation_sensitivity_without_becoming_evidence(self):
        coupling = AffectCoupling(
            "coupling:interpretation:1", "coupling:affect:1", "guardedness", "hurt",
            interpretation_gain=0.25, recall_salience_gain=0.0, recall_tone_gain=0.0,
        )
        guarded = MoodField(
            "mood:guarded", "scheme:affect:1", (("guardedness", 0.8),), ("source:prior-strain",),
            "parameter:affect:1", "coupling:affect:1", 10.0,
        )
        settled = MoodField(
            "mood:settled", "scheme:affect:1", (("guardedness", -0.4),), ("source:rest",),
            "parameter:affect:1", "coupling:affect:1", 10.0,
        )
        first = self.provider.condition_interpretation(
            interpretation_ref="interpretation:alice-did-not-care",
            interpretation_source_refs=("source:message-delay",),
            base_sensitivity_interval=(0.3, 0.4),
            mood=guarded,
            coupling=coupling,
        )
        second = self.provider.condition_interpretation(
            interpretation_ref="interpretation:alice-did-not-care",
            interpretation_source_refs=("source:message-delay",),
            base_sensitivity_interval=(0.3, 0.4),
            mood=settled,
            coupling=coupling,
        )
        self.assertNotEqual(first.sensitivity_interval, second.sensitivity_interval)
        self.assertEqual(first.source_refs, second.source_refs)
        self.assertEqual(first.evidence_weight_delta, 0.0)
        self.assertEqual(second.evidence_weight_delta, 0.0)

    def test_self_understanding_can_be_uncertain_and_need_not_rewrite_feeling(self):
        state = _feeling()
        understanding = self.provider.interpret_feeling(
            state,
            understanding_id="understanding:late-message:1",
            description_hypotheses=("I still care", "I also feel hurt"),
            reason_hypotheses=("I may have expected shared time",),
            unknown_parts=("how much is fatigue",),
            confidence=0.55,
            reflection_source_refs=("reflection:1",),
        )
        self.assertEqual(understanding.confidence, 0.55)
        self.assertTrue(understanding.unknown_parts)
        self.assertEqual(state, _feeling())

    def test_regulation_attempt_and_observed_effect_are_separate(self):
        attempt = RegulationAttempt(
            "regulation:walk:1", "strategy:walk:2", "affect:late-message", "goal:recover",
            ("source:strategy-history",), "reservation:walk:1", ("effect:less-rumination",), "planned",
        )
        observation = self.provider.record_regulation(
            attempt,
            execution_receipt_ref="execution:walk:1",
            observed_effects=(("hurt", -0.1),),
            unknown_effects=("long_term_recovery",),
            cost_settlement_ref="settlement:walk:1",
            status="partial",
        )
        self.assertEqual(observation.status, "partial")
        self.assertEqual(observation.unknown_effects, ("long_term_recovery",))
        self.assertNotEqual(attempt.status, observation.status)

    def test_sourced_mixed_update_is_replayable_and_stays_a_candidate(self):
        current = _feeling(cursor=10.0)
        mood = MoodField(
            "mood:background", "scheme:affect:1", (("care", 0.1), ("hurt", 0.2)),
            ("source:rest",), "parameter:affect:1", "coupling:affect:1", 10.0,
        )
        recall = self.provider.condition_recollection(
            memory_ref="memory:shared-evening", memory_source_refs=("source:shared-evening",),
            base_salience_interval=(0.3, 0.4), base_tone_interval=(-0.1, 0.0), mood=MoodField(
                "mood:guarded", "scheme:affect:1", (("guardedness", 0.5),),
                ("source:prior",), "parameter:affect:1", "coupling:affect:1", 10.0,
            ), coupling=AffectCoupling("coupling:1", "coupling:affect:1", "guardedness", "hurt", 0.0, 0.3, 0.2),
        )
        candidate = self.provider.propose_mixed_update(
            candidate_id="candidate:affect:1", replay_key="replay:event:1", committed_parent_ref="receipt:10",
            appraisal=_appraisal(), scheme=self.scheme, current_feeling=current, current_mood=mood,
            rules=(SemanticDriveRule("care", "anticipated_impact", 0.6), SemanticDriveRule("hurt", "anticipated_impact", 0.8)),
            recovery_rate=0.2, to_cursor=11.0, recollection=recall,
            reflection_source_refs=("reflection:committed-feeling:10",),
        )
        self.assertIsInstance(candidate, AffectCandidate)
        self.assertEqual(candidate.status, "candidate")
        self.assertEqual(candidate.feeling.revision, current.revision + 1)
        self.assertEqual(candidate.mood.revision, mood.revision + 1)
        self.assertIn("source:message-delay", candidate.source_refs)
        self.assertIn("source:shared-evening", candidate.source_refs)
        self.assertNotEqual(dict(candidate.feeling.coordinates), dict(current.coordinates))
        self.assertIsInstance(self.provider.reject_candidate(candidate, reason="stale source grant"), CandidateRejection)

    def test_unknown_semantics_and_unconfirmed_regulation_cannot_change_candidate(self):
        current = _feeling(cursor=10.0)
        mood = MoodField(
            "mood:background", "scheme:affect:1", (("care", 0.1),), ("source:rest",),
            "parameter:affect:1", "coupling:affect:1", 10.0,
        )
        with self.assertRaisesRegex(ValueError, "unknown semantic"):
            self.provider.propose_mixed_update(
                candidate_id="candidate:unknown", replay_key="replay:unknown", committed_parent_ref="receipt:10",
                appraisal=_appraisal(unknown=True), scheme=self.scheme, current_feeling=current, current_mood=mood,
                rules=(SemanticDriveRule("care", "controllability", 0.5),), recovery_rate=0.2, to_cursor=11.0,
            )
        pending = RegulationObservation(
            "regulation:1", "execution:unknown", (), ("effect:unknown",), "settlement:unknown", "pending_confirmation",
        )
        with self.assertRaisesRegex(ValueError, "unconfirmed"):
            self.provider.propose_mixed_update(
                candidate_id="candidate:pending", replay_key="replay:pending", committed_parent_ref="receipt:10",
                appraisal=_appraisal(), scheme=self.scheme, current_feeling=current, current_mood=mood,
                rules=(SemanticDriveRule("care", "anticipated_impact", 0.5),), recovery_rate=0.2, to_cursor=11.0,
                regulation=pending, regulation_observation_ref="regulation-observation:1",
            )

    def test_abi2_diagnostic_certificate_cannot_adopt_candidate(self):
        current = _feeling(cursor=10.0)
        mood = MoodField(
            "mood:background", "scheme:affect:1", (("care", 0.1),), ("source:rest",),
            "parameter:affect:1", "coupling:affect:1", 10.0,
        )
        candidate = self.provider.propose_mixed_update(
            candidate_id="candidate:diagnostic", replay_key="replay:diagnostic", committed_parent_ref="receipt:10",
            appraisal=_appraisal(), scheme=self.scheme, current_feeling=current, current_mood=mood,
            rules=(SemanticDriveRule("care", "anticipated_impact", 0.5),), recovery_rate=0.2, to_cursor=11.0,
        )
        diagnostic = NumericCertificate(
            2, 0, "operator:affect:1", "parameter:affect:1", "coupling:affect:1",
            10.0, 11.0, 0.0, 0.0, 0.0, True, "completed",
        )
        with self.assertRaisesRegex(ValueError, "certificate flags"):
            self.provider.adopt_candidate(current, candidate, diagnostic, AdvanceRequirements(1e-5, 1e-4, 1e-4, 0b11))

    def test_correction_stops_invalidated_driver_without_erasing_historical_feeling(self):
        state = _feeling()
        result = self.provider.correct_attribution(
            state,
            invalidated_driver_refs=(state.active_driver_refs[0],),
            replacement_appraisal_ref="appraisal:urgent-event:2",
            correction_source_ref="source:urgent-event",
            learned_at=12.0,
        )
        self.assertEqual(result.current_state.coordinates, state.coordinates)
        self.assertEqual(result.current_state.historical_source_refs, state.historical_source_refs)
        self.assertEqual(result.current_state.active_driver_refs, ())
        self.assertTrue(result.historical_feeling_preserved)

    def test_uncertified_or_abi1_numeric_advance_is_blocked(self):
        current = _feeling(cursor=10.0)
        candidate = FeelingState(**{**current.__dict__, "cursor": 11.0, "revision": 2})
        requirements = AdvanceRequirements(1e-5, 1e-4, 1e-4, required_flags=0b11)
        base = dict(
            abi_version=2,
            certificate_flags=0,
            operator_version="operator:affect:1",
            parameter_version="parameter:affect:1",
            coupling_version="coupling:affect:1",
            from_cursor=10.0,
            to_cursor=11.0,
            residual_error_bound=1e-6,
            time_error_bound=1e-5,
            truncation_error_bound=1e-5,
            assumptions_valid=True,
            stopping_reason="converged",
        )
        with self.assertRaisesRegex(ValueError, "certificate flags"):
            self.provider.adopt_advance(current, candidate, NumericCertificate(**base), requirements)
        with self.assertRaisesRegex(ValueError, "ABI 2"):
            self.provider.adopt_advance(
                current, candidate, NumericCertificate(**{**base, "abi_version": 1, "certificate_flags": 0b11}),
                requirements,
            )

    def test_certified_advance_requires_all_error_bounds_and_exact_versions(self):
        current = _feeling(cursor=10.0)
        candidate = FeelingState(**{**current.__dict__, "cursor": 11.0, "revision": 2})
        requirements = AdvanceRequirements(1e-5, 1e-4, 1e-4, required_flags=0b11)
        certificate = NumericCertificate(
            2, 0b11, "operator:affect:1", "parameter:affect:1", "coupling:affect:1",
            10.0, 11.0, 1e-6, 1e-5, 1e-5, True, "converged",
        )
        self.assertEqual(self.provider.adopt_advance(current, candidate, certificate, requirements), candidate)
        with self.assertRaisesRegex(ValueError, "time error"):
            self.provider.adopt_advance(
                current,
                candidate,
                NumericCertificate(**{**certificate.__dict__, "time_error_bound": 1e-2}),
                requirements,
            )

    def test_scheme_and_domain_proposal_are_versioned_and_fail_closed(self):
        self.assertEqual(self.scheme.parameter_version, "parameter:affect:1")
        with self.assertRaises(ValueError):
            self.provider.compile_scheme(AffectScheme(**{**_scheme().__dict__, "axes": (
                AffectAxis("hurt", "normalized", "a"), AffectAxis("hurt", "normalized", "b")
            )}))
        self.assertEqual(self.provider.validate(_proposal("d04")).domain, "d04")
        with self.assertRaises(ValueError):
            self.provider.validate(_proposal("d05"))

    def test_proposal_for_uses_frozen_runtime_envelope_and_schema_hash(self):
        template = _proposal("d04")
        proposal = self.provider.proposal_for(
            template.envelope,
            typed_writes=(),
            dependencies=DependencySet(),
            contribution_keys=("world:late-message|entity:alice|meaning:care-and-hurt|1",),
            required_bundle_parts=("experience",),
        )
        self.assertEqual(proposal.proposal_schema_hash, self.provider.descriptor.request_schema_hash)
        self.assertEqual(proposal.envelope, template.envelope)
        self.assertEqual(proposal.required_bundle_parts, ("experience",))

    def test_untyped_projection_fails_closed_instead_of_leaking_diagnostics(self):
        with self.assertRaisesRegex(ValueError, "typed D04 projection"):
            self.provider.project({"dump": "all internal affect"})

    def test_nonfinite_continuous_values_are_rejected(self):
        with self.assertRaises(ValueError):
            FeelingState(**{**_feeling().__dict__, "coordinates": (("hurt", math.nan),)})
        with self.assertRaises(ValueError):
            FeelingState(**{**_feeling().__dict__, "coordinates": (("hurt", 1.01),)})

    def test_type_specs_bind_real_d04_writers_hashes_owners_and_payload_validators(self):
        specs = self.provider.type_specs()
        self.assertTrue(specs)
        self.assertTrue(all(isinstance(spec, TypeSpec) for spec in specs))
        self.assertEqual({spec.name for spec in specs}, set(self.provider.register_types()))
        self.assertTrue(all(spec.writer_domain == "d04" for spec in specs))
        self.assertTrue(all(spec.schema_hash and len(spec.schema_hash) == 64 for spec in specs))
        feeling_spec = next(spec for spec in specs if spec.name == "d04.feeling_state.v1")
        payload = {
            **_feeling().__dict__,
            "coordinates": [["care", 0.75], ["hurt", 0.6]],
            "meaning_refs": ["meaning:late-message:care-and-hurt"],
            "interpretation_refs": ["interpretation:alice-was-delayed"],
            "active_driver_refs": ["world:late-message|entity:alice|meaning:care-and-hurt|1"],
            "historical_source_refs": ["source:message-delay"],
        }
        feeling_spec.validator(payload)
        with self.assertRaises((TypeError, ValueError)):
            feeling_spec.validator({"process_id": "affect:late-message"})
        with self.assertRaises((TypeError, ValueError)):
            feeling_spec.validator({**payload, "unregistered_field": "must fail closed"})

    def test_validate_decodes_own_typed_payload_instead_of_trusting_type_name(self):
        proposal = _proposal("d04")
        malformed = GraphWrite(
            AtomKey(Owner("persona", "bot", "persona"), "d04.feeling_state.v1", "affect:late-message"),
            {"process_id": "affect:late-message"},
        )
        malformed_proposal = DomainProposal(
            proposal.domain,
            proposal.proposal_schema,
            proposal.proposal_schema_hash,
            proposal.envelope,
            (malformed,),
            proposal.dependencies,
            (),
            (),
        )
        with self.assertRaises((TypeError, ValueError)):
            self.provider.validate(malformed_proposal)

    def test_typed_write_requires_active_scheme_and_exact_parameter_coupling_versions(self):
        proposal = _proposal("d04")
        payload = {
            **_feeling().__dict__,
            "coordinates": [["care", 0.75], ["hurt", 0.6]],
            "meaning_refs": ["meaning:late-message:care-and-hurt"],
            "interpretation_refs": ["interpretation:alice-was-delayed"],
            "active_driver_refs": ["world:late-message|entity:alice|meaning:care-and-hurt|1"],
            "historical_source_refs": ["source:message-delay"],
        }
        write = GraphWrite(
            AtomKey(Owner("persona", "bot", "persona"), "d04.feeling_state.v1", "affect:late-message"),
            payload,
        )
        typed = DomainProposal(
            proposal.domain, proposal.proposal_schema, proposal.proposal_schema_hash, proposal.envelope,
            (write,), proposal.dependencies, (), (),
        )
        with self.assertRaisesRegex(ValueError, "active D04 scheme"):
            self.provider.validate(typed)
        self.assertEqual(self.provider.validate(typed, snapshot=self.scheme), typed)
        mismatched = GraphWrite(write.key, {**payload, "coupling_version": "coupling:untrusted:99"})
        with self.assertRaisesRegex(ValueError, "versions"):
            self.provider.validate(
                DomainProposal(
                    proposal.domain, proposal.proposal_schema, proposal.proposal_schema_hash,
                    proposal.envelope, (mismatched,), proposal.dependencies, (), (),
                ),
                snapshot=self.scheme,
            )


if __name__ == "__main__":
    unittest.main()
