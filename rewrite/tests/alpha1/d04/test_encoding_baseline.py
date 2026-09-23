import unittest
from dataclasses import replace

from sylanne3.domains.d04 import AffectAxis, AffectProvider, AffectScheme, CommittedRef, EncodingBaseline
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, GraphWrite, Owner, TypeRegistry
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, NamespaceId, OperationIdentity,
    SourceQualification, VersionGuard, canonical_digest,
)


SOURCE = AtomKey(Owner("event", "bot", "persona", "event:1"), "memory.source", "record").token
FEELING = AtomKey(Owner("persona", "bot", "persona"), "d04.feeling_state.v1", "process:1").token
APPRAISAL = AtomKey(Owner("event", "bot", "persona", "event:1"), "d04.appraisal_bundle.v1", "appraisal:1").token
PERSPECTIVE = AtomKey(Owner("persona", "bot", "persona"), "d03.entity_anchor", "entity:1").token
INTERPRETATION = AtomKey(Owner("activity", "bot", "persona", "activity:1"),
                         "d07.current_interpretation.v1", "interpretation:1").token


def _scheme():
    return AffectScheme("d04.affect.scheme.v1", "scheme:1", "operator:1", "parameter:1",
                        "coupling:1", (AffectAxis("care", "normalized", "care"),), ())


def _proposal_and_snapshot():
    baseline = _baseline(then_feeling_versions=(CommittedRef(FEELING, 2),),
                         interpretation_versions=(CommittedRef(INTERPRETATION, 3),))
    keys = tuple(AtomKey.from_token(token) for token in (SOURCE, PERSPECTIVE, FEELING, INTERPRETATION))
    versions = tuple(GraphVersion(key, revision) for key, revision in zip(keys, (1, 1, 2, 3)))
    baseline_key = AtomKey(Owner("event", "bot", "persona", "event:1"),
                           "d04.encoding_baseline.v1", baseline.baseline_id)
    guard = VersionGuard((*versions, GraphVersion(baseline_key, 0)), (), 0, 0,
                         "catalogue:1", "scheme:1", "operator:1", "policy:1", (), (), ())
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity:1", None, "attempt:1", "prepare", "operation:1",
                          canonical_digest({"input_refs": [SOURCE]})),
        AuthorityContext("host:user", "d11", "capability:affect", NamespaceId("bot", "persona"),
                         ("persona",), "respond", (), "policy:1", 1),
        guard,
        SourceQualification((SOURCE,), "reported", 1.0, 1.0, "external_report", "eligible",
                            0.7, "not_applicable"),
        (SOURCE,), "budget:1", 10.0, 10.0, "clock:1", (),
    )
    value = {**baseline.__dict__, "source_refs": list(baseline.source_refs),
             "then_feeling_versions": [item.__dict__ for item in baseline.then_feeling_versions],
             "interpretation_versions": [item.__dict__ for item in baseline.interpretation_versions],
             "unknown_reasons": list(baseline.unknown_reasons)}
    write = GraphWrite(baseline_key, value, keys)
    provider = AffectProvider(active_scheme=_scheme())
    proposal = provider.proposal_for(envelope, typed_writes=(write,),
                                     dependencies=DependencySet(historical_provenance=versions),
                                     contribution_keys=(), required_bundle_parts=())
    snapshot = GraphSnapshot(tuple(GraphAtom(item.key, item.revision, {}) for item in versions), ())
    return provider, proposal, snapshot


def _baseline(**changes):
    values = dict(
        baseline_id="baseline:1",
        source_refs=(SOURCE,),
        perspective_ref=PERSPECTIVE,
        then_feeling_versions=(),
        interpretation_versions=(),
        as_known_at=None,
        projection_policy_ref="policy:unresolved",
        projection_policy_version="policy:v1",
        basis_version="basis:1",
        parameter_version="parameter:1",
        salience_interval=None,
        tone_interval=None,
        unknown_reasons=("salience_interval:projection_policy_unresolved", "tone_interval:polarity_unresolved"),
    )
    values.update(changes)
    return EncodingBaseline(**values)


class EncodingBaselineTests(unittest.TestCase):
    def test_unknown_record_is_typed_and_registered_immutable(self):
        value = _baseline()
        provider = AffectProvider()
        spec = next(spec for spec in provider.type_specs() if spec.name == "d04.encoding_baseline.v1")
        self.assertIn(spec.name, provider.register_types())
        self.assertEqual((spec.owner_kinds, spec.storage_role, spec.writer_domain), (("event",), "source", "d04"))
        self.assertTrue(spec.immutable)
        registry = TypeRegistry()
        registry.register(spec)
        payload = {**value.__dict__, "source_refs": list(value.source_refs),
                   "then_feeling_versions": [], "interpretation_versions": [],
                   "unknown_reasons": list(value.unknown_reasons)}
        self.assertEqual(spec.validator(payload), value)
        with self.assertRaisesRegex(ValueError, "fields differ"):
            spec.validator({**payload, "unsupported": True})

    def test_appraisal_is_not_committed_feeling_and_no_default_neutral(self):
        with self.assertRaisesRegex(ValueError, "d04.feeling_state.v1"):
            _baseline(then_feeling_versions=(CommittedRef(APPRAISAL, 1),))
        with self.assertRaisesRegex(ValueError, "verified projection issuer"):
            _baseline(salience_interval=(0.5, 0.5),
                      then_feeling_versions=(CommittedRef(FEELING, 1),),
                      unknown_reasons=("tone_interval:polarity_unresolved",))
        self.assertIsNone(_baseline().salience_interval)
        self.assertIsNone(_baseline().tone_interval)

    def test_strict_refs_intervals_and_unknown_reasons(self):
        feeling = CommittedRef(FEELING, 3)
        value = _baseline(then_feeling_versions=(feeling,),
                          interpretation_versions=(CommittedRef(INTERPRETATION, 2),))
        self.assertIsNone(value.salience_interval)
        for changes in (
            {"source_refs": ("source:1",)},
            {"tone_interval": (-1.1, 0.1), "unknown_reasons": ("salience_interval:unknown",)},
            {"unknown_reasons": ()},
            {"then_feeling_versions": (CommittedRef(FEELING, 1), CommittedRef(FEELING, 2))},
            {"perspective_ref": "perspective:1"},
            {"perspective_ref": AtomKey(Owner("event", "bot", "persona", "event:1"),
                                        "d03.world_event", "event:1").token},
            {"perspective_ref": AtomKey(Owner("persona", "other", "persona"),
                                        "d03.entity_anchor", "entity:1").token},
            {"interpretation_versions": (CommittedRef(APPRAISAL, 1),)},
            {"interpretation_versions": (CommittedRef(AtomKey(
                Owner("persona", "bot", "persona"), "d07.current_interpretation.v1", "x",
            ).token, 1),)},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                _baseline(**changes)
        with self.assertRaisesRegex(ValueError, "revision"):
            CommittedRef(FEELING, True)

    def test_graph_write_requires_exact_committed_read_and_provenance_proofs(self):
        provider, proposal, snapshot = _proposal_and_snapshot()
        self.assertEqual(provider.validate(proposal, snapshot=snapshot), proposal)
        with self.assertRaisesRegex(ValueError, "committed graph snapshot"):
            provider.validate(proposal, snapshot=_scheme())
        with self.assertRaisesRegex(ValueError, "committed guarded provenance"):
            provider.validate(replace(proposal, dependencies=DependencySet(
                historical_provenance=proposal.dependencies.historical_provenance[:-1],
            )), snapshot=snapshot)
        bad_guard = replace(proposal.envelope.version_guard, read_versions=tuple(
            GraphVersion(item.key, 4) if item.key.type_name == "d04.feeling_state.v1" else item
            for item in proposal.envelope.version_guard.read_versions
        ))
        with self.assertRaisesRegex(ValueError, "committed guarded provenance"):
            provider.validate(replace(proposal, envelope=replace(proposal.envelope,
                                                                  version_guard=bad_guard)), snapshot=snapshot)
        bad_write = replace(proposal.typed_writes[0], dependencies=())
        with self.assertRaisesRegex(ValueError, "graph dependencies"):
            provider.validate(replace(proposal, typed_writes=(bad_write,)), snapshot=snapshot)
        with self.assertRaisesRegex(ValueError, "committed graph revision"):
            provider.validate(proposal, snapshot=GraphSnapshot(snapshot.atoms[:-1], ()))
        changed_source = replace(snapshot.atoms[0], revision=2)
        with self.assertRaisesRegex(ValueError, "snapshot differs"):
            provider.validate(proposal, snapshot=GraphSnapshot((changed_source, *snapshot.atoms[1:]), ()))


if __name__ == "__main__":
    unittest.main()
