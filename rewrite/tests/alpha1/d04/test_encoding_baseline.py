import unittest
from dataclasses import asdict, replace
from pathlib import Path
import tempfile

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d04 import AffectAxis, AffectProvider, AffectScheme, CommittedRef, EncodingBaseline
from sylanne3.domains.d04.encoding_baseline import decode_encoding_baseline
from sylanne3.domains.d03.context import WorldEvent
from sylanne3.domains.d03.self_perspective import (
    SelfIdentityMapping, SelfPerspective, self_mapping_key,
    self_perspective_id, self_perspective_key,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (AtomKey, GraphAtom, GraphCandidate, GraphSnapshot,
                                  GraphVersion, GraphWrite, Owner, TypeRegistry, TypeSpec)
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
                         ("persona", "event"), "respond", (), "policy:1", 1),
        guard,
        SourceQualification((SOURCE,), "reported", 1.0, 1.0, "external_report", "eligible",
                            0.7, "not_applicable"),
        (SOURCE,), "budget:1", 10.0, 10.0, "clock:1", (),
    )
    value = {**baseline.__dict__, "source_refs": list(baseline.source_refs),
             "then_feeling_versions": [item.__dict__ for item in baseline.then_feeling_versions],
             "interpretation_versions": [item.__dict__ for item in baseline.interpretation_versions],
             "unknown_reasons": list(baseline.unknown_reasons)}
    write = GraphWrite(baseline_key, value)
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
    def test_self_perspective_requires_current_mapping_and_matching_arrival(self):
        provider, prior, _ = _proposal_and_snapshot()
        namespace = prior.envelope.authority.namespace
        event_key = AtomKey(Owner("event", "bot", "persona", "world:arrival"),
                            "d03.world_event", "current")
        event = WorldEvent("world:arrival", "message_received",
                           (("entity:account:sender", "sender_account"),),
                           1.0, 1.0, 1.0, "scene:one", (SOURCE,), "host_observed")
        mapping_key = self_mapping_key(namespace)
        mapping = SelfIdentityMapping(
            "self-map:one", "persona:persona", "entity:self",
            "d11:self-identity:one", "role:head", "incarnation:one", "active",
        )
        perspective = SelfPerspective(
            self_perspective_id(namespace, event.scene_ref, event_key.token),
            mapping.persona_ref, mapping.self_entity_ref, event.scene_ref,
            mapping_key.token, event_key.token, mapping.role_head_id,
        )
        perspective_key = self_perspective_key(namespace, perspective.perspective_id)
        atoms = (
            GraphAtom(AtomKey.from_token(SOURCE), 1, {}),
            GraphAtom(perspective_key, 1, asdict(perspective)),
            GraphAtom(mapping_key, 2, asdict(mapping)),
            GraphAtom(event_key, 3, {
                **asdict(event),
                "participant_roles": [list(item) for item in event.participant_roles],
                "source_refs": list(event.source_refs),
            }),
        )
        snapshot = GraphSnapshot(atoms, ())
        guards = tuple(GraphVersion(atom.key, atom.revision) for atom in atoms)
        envelope = replace(prior.envelope, version_guard=replace(
            prior.envelope.version_guard, read_versions=guards,
        ))
        args = dict(source_refs=(SOURCE,), perspective_ref=perspective_key.token,
                    projection_policy_ref="policy:unresolved")
        proposal = provider.propose_encoding_baseline(envelope, snapshot, **args)
        self.assertEqual(proposal.dependencies.historical_provenance, guards)
        self.assertEqual(decode_encoding_baseline(
            proposal.typed_writes[0].value).perspective_ref, perspective_key.token)
        stale = replace(envelope, version_guard=replace(
            envelope.version_guard, read_versions=guards[:-2] + (guards[-1],),
        ))
        with self.assertRaisesRegex(ValueError, "matching committed guarded revisions"):
            provider.propose_encoding_baseline(stale, snapshot, **args)
        unrelated = GraphSnapshot((*atoms[:-1], replace(
            atoms[-1], value={**atoms[-1].value, "source_refs": ["other"]},
        )), ())
        with self.assertRaisesRegex(ValueError, "unrelated to baseline source"):
            provider.propose_encoding_baseline(envelope, unrelated, **args)

    def test_unknown_baseline_proposal_is_committable_as_immutable_graph_source(self):
        provider, prior, _ = _proposal_and_snapshot()
        registry = TypeRegistry()
        # Parent validation belongs to D06/D03/D07; this checks GraphStore's
        # immutable-write rule using real revisions and a real graph commit.
        for name, owner in (("memory.source", "event"), ("d03.entity_anchor", "persona"),
                            ("d04.feeling_state.v1", "persona"),
                            ("d07.current_interpretation.v1", "activity")):
            registry.register(TypeSpec(name, (owner,), "state", lambda value: None))
        registry.register(next(spec for spec in provider.type_specs()
                               if spec.name == "d04.encoding_baseline.v1"))
        keys = tuple(AtomKey.from_token(ref) for ref in (SOURCE, PERSPECTIVE, FEELING, INTERPRETATION))
        with tempfile.TemporaryDirectory() as directory:
            store = GraphStore(Path(directory) / "baseline.db", registry)
            try:
                empty = store.graph_snapshot(keys)
                seeded = store.graph_commit(GraphCandidate(
                    Event(Scope("bot", "persona", "session"), "baseline-seed", 1.0,
                          "baseline-test-seed", {}),
                    tuple(GraphVersion(key, 0) for key in keys),
                    tuple(GraphWrite(key, {}) for key in keys), empty.epochs,
                ))
                self.assertEqual(seeded.status, "committed")
                snapshot = store.graph_snapshot(keys)
                envelope = replace(prior.envelope, version_guard=replace(
                    prior.envelope.version_guard, read_versions=snapshot.versions,
                ))
                proposal = provider.propose_encoding_baseline(
                    envelope, snapshot, source_refs=(SOURCE,), perspective_ref=PERSPECTIVE,
                    then_feeling_refs=(FEELING,), interpretation_refs=(INTERPRETATION,),
                    projection_policy_ref="policy:unresolved",
                )
                receipt = store.graph_commit(GraphCandidate(
                    Event(Scope("bot", "persona", "session"), "baseline-issue", 2.0,
                          "baseline-test-issue", {}),
                    proposal.envelope.version_guard.read_versions,
                    proposal.typed_writes, snapshot.epochs,
                ))
                self.assertEqual(receipt.status, "committed")
                key = proposal.typed_writes[0].key
                committed = store.graph_snapshot((key,)).get(key)
                self.assertEqual(committed.revision, 1)
                self.assertEqual(committed.value, proposal.typed_writes[0].value)
            finally:
                store.close()

    def test_issuer_proposes_deterministic_unknown_baseline_from_committed_versions(self):
        provider, prior, snapshot = _proposal_and_snapshot()
        kwargs = dict(source_refs=(SOURCE,), perspective_ref=PERSPECTIVE,
                      then_feeling_refs=(FEELING,), interpretation_refs=(INTERPRETATION,),
                      projection_policy_ref="policy:unresolved")
        proposal = provider.propose_encoding_baseline(prior.envelope, snapshot, **kwargs)
        replay = provider.propose_encoding_baseline(prior.envelope, snapshot, **kwargs)
        self.assertEqual(proposal, replay)
        self.assertEqual(provider.validate(proposal, snapshot=snapshot), proposal)
        write = proposal.typed_writes[0]
        baseline = decode_encoding_baseline(write.value)
        self.assertEqual(write.key.token, AtomKey(AtomKey.from_token(SOURCE).owner,
                         "d04.encoding_baseline.v1", baseline.baseline_id).token)
        self.assertEqual(baseline.source_refs, (SOURCE,))
        self.assertEqual(baseline.then_feeling_versions, (CommittedRef(FEELING, 2),))
        self.assertEqual(baseline.interpretation_versions, (CommittedRef(INTERPRETATION, 3),))
        self.assertIsNone(baseline.salience_interval)
        self.assertIsNone(baseline.tone_interval)
        self.assertEqual(write.dependencies, ())
        self.assertEqual(proposal.dependencies.historical_provenance, snapshot.versions)
        self.assertIn(GraphVersion(write.key, 0), proposal.envelope.version_guard.read_versions)
        absent_snapshot = GraphSnapshot(
            (*snapshot.atoms, GraphAtom(write.key, 0, {}, False)), snapshot.epochs,
        )
        self.assertEqual(provider.propose_encoding_baseline(
            prior.envelope, absent_snapshot, **kwargs,
        ), proposal)

        initial = provider.propose_encoding_baseline(
            prior.envelope, snapshot, source_refs=(SOURCE,), perspective_ref=PERSPECTIVE,
            projection_policy_ref="policy:unresolved",
        )
        initial_value = decode_encoding_baseline(initial.typed_writes[0].value)
        self.assertEqual(initial_value.then_feeling_versions, ())
        self.assertEqual(initial_value.interpretation_versions, ())
        self.assertEqual(initial.typed_writes[0].dependencies, ())
        self.assertEqual(initial.dependencies.historical_provenance,
                         snapshot.versions[:2])
        self.assertIsNone(initial_value.salience_interval)
        self.assertIsNone(initial_value.tone_interval)

        changed = GraphSnapshot((*snapshot.atoms[:-1], replace(snapshot.atoms[-1], revision=4)), ())
        with self.assertRaisesRegex(ValueError, "matching committed guarded revisions"):
            provider.propose_encoding_baseline(prior.envelope, changed, **kwargs)
        uncommitted = GraphSnapshot((replace(snapshot.atoms[0], revision=0), *snapshot.atoms[1:]), ())
        with self.assertRaisesRegex(ValueError, "matching committed guarded revisions"):
            provider.propose_encoding_baseline(prior.envelope, uncommitted, **kwargs)
        persona_only = replace(prior.envelope, authority=replace(
            prior.envelope.authority, owner_scope=("persona",),
        ))
        with self.assertRaisesRegex(ValueError, "event owner scope"):
            provider.propose_encoding_baseline(persona_only, snapshot, **kwargs)

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
        original = proposal.typed_writes[0]
        wrong_event = AtomKey(Owner("event", "bot", "persona", "event:other"),
                              original.key.type_name, original.key.name)
        wrong_guard = replace(proposal.envelope.version_guard, read_versions=tuple(
            GraphVersion(wrong_event, 0) if item.key == original.key else item
            for item in proposal.envelope.version_guard.read_versions
        ))
        with self.assertRaisesRegex(ValueError, "identity differs"):
            provider.validate(replace(
                proposal, envelope=replace(proposal.envelope, version_guard=wrong_guard),
                typed_writes=(replace(original, key=wrong_event),),
            ), snapshot=snapshot)
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
        bad_write = replace(proposal.typed_writes[0], dependencies=(AtomKey.from_token(SOURCE),))
        with self.assertRaisesRegex(ValueError, "invalidating dependencies"):
            provider.validate(replace(proposal, typed_writes=(bad_write,)), snapshot=snapshot)
        with self.assertRaisesRegex(ValueError, "committed graph revision"):
            provider.validate(proposal, snapshot=GraphSnapshot(snapshot.atoms[:-1], ()))
        changed_source = replace(snapshot.atoms[0], revision=2)
        with self.assertRaisesRegex(ValueError, "snapshot differs"):
            provider.validate(proposal, snapshot=GraphSnapshot((changed_source, *snapshot.atoms[1:]), ()))


if __name__ == "__main__":
    unittest.main()
