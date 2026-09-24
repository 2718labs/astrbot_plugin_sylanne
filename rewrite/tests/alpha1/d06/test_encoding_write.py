import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path

from sylanne3.contracts import Event, Scope, StaleRead
from sylanne3.domains.d06 import (
    D06DomainAdapter, D06DomainProvider, EncodingContext, SourceAdmission,
)
from sylanne3.domains.d06.pipeline import D06MemoryPipeline
from sylanne3.domains.d04.encoding_baseline import decode_encoding_baseline
from sylanne3.domains.d03.context import WorldEvent
from sylanne3.domains.d03.self_perspective import (
    SelfIdentityMapping, SelfPerspective, self_mapping_key,
    self_perspective_id, self_perspective_key,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (
    AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry, TypeSpec,
)
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import (
    SourceRecord, access_key, register_memory_types, source_key,
    subjective_trace_v2_key,
)
from sylanne3.model_broker.broker import CallReceipt
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    RUNTIME_SCHEMA, VersionGuard, canonical_digest,
)


class EncodingWriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.registry = TypeRegistry()
        register_memory_types(self.registry)
        for name, owner in (
            ("d03.world_event", "event"), ("d03.role_binding", "scene"),
            ("d03.self_identity_mapping.v1", "persona"),
            ("d03.self_perspective.v1", "persona"),
            ("d04.feeling_state.v1", "persona"), ("d07.belief_revision.v1", "persona"),
        ):
            self.registry.register(TypeSpec(name, (owner,), "state", lambda _: None))
        self.registry.register(TypeSpec(
            "d04.encoding_baseline.v1", ("event",), "source",
            decode_encoding_baseline, immutable=True, writer_domain="d04",
        ))
        self.store = GraphStore(Path(self.tmp.name) / "memory.db", self.registry)
        self.addCleanup(self.store.close)
        self.namespace = NamespaceId("bot", "persona")
        self.adapter = D06DomainAdapter(self.namespace)
        self.pipeline = D06MemoryPipeline(
            self.adapter, MemoryRepository(self.store, "bot", "persona")
        )
        self.sequence = 0
        self.scope = Scope("bot", "persona", "session")
        self.source = source_key("bot", "persona", "source-1")
        self.access = access_key("bot", "persona", "source-1")
        self.event_ref = AtomKey(Owner("event", "bot", "persona", "world-1"), "d03.world_event", "current")
        self.perspective = AtomKey(Owner("scene", "bot", "persona", "scene-1"), "d03.role_binding", "current")
        self.feeling = AtomKey(Owner("persona", "bot", "persona"), "d04.feeling_state.v1", "current")
        self.interpretation = AtomKey(Owner("persona", "bot", "persona"), "d07.belief_revision.v1", "current")
        self.baseline = AtomKey(Owner("event", "bot", "persona", "world-1"),
                                "d04.encoding_baseline.v1", "record")
        self.self_event = AtomKey(Owner("event", "bot", "persona", "world:1"),
                                  "d03.world_event", "current")
        self.self_mapping = self_mapping_key(self.namespace)
        self.self_perspective = self_perspective_key(
            self.namespace, self_perspective_id(
                self.namespace, "scene:1", self.self_event.token))

    def event(self, kind):
        self.sequence += 1
        return Event(self.scope, f"{self.sequence}-{kind}", self.sequence, kind, {})

    def seed(self):
        self.pipeline.repository.ingest(
            self.event("source"),
            SourceRecord("source-1", "A reported promise", "alice", "reported", "reported",
                         None, 2.0, "family-1", ("owner",), ("context",)),
        )
        refs = (self.event_ref, self.perspective, self.feeling, self.interpretation)
        self.store.graph_commit(GraphCandidate(
            self.event("context"), tuple(GraphVersion(key, 0) for key in refs),
            tuple(GraphWrite(key, {"committed": True}) for key in refs),
        ))
        context = EncodingContext(
            self.event_ref.token, self.perspective.token, (self.feeling.token,),
            (self.interpretation.token,), (("promise", 0.9), ("weather", 0.2)),
            tuple((key.token, 1) for key in (self.source, *refs)),
        )
        prepared = self.pipeline.prepare_encoding(
            "source-1", context, audience="owner", purpose="context",
        )
        return prepared

    def seed_self_graph(self):
        mapping = SelfIdentityMapping(
            "self-map:fixture", "persona:persona", "entity:self",
            "authority:self-identity:fixture", "head-1", "inc-1", "active",
        )
        event = WorldEvent(
            "world:1", "message_received", (("entity:account:1", "sender_account"),),
            None, None, 2.0, "scene:1", (self.source.token,), "host_observed",
        )
        perspective = SelfPerspective(
            self.self_perspective.name, "persona:persona", "entity:self", "scene:1",
            self.self_mapping.token, self.self_event.token, "head-1",
        )
        writes = (
            GraphWrite(self.self_mapping, asdict(mapping)),
            GraphWrite(self.self_event, {
                **asdict(event),
                "participant_roles": [list(item) for item in event.participant_roles],
                "source_refs": list(event.source_refs),
            }),
            GraphWrite(self.self_perspective, asdict(perspective)),
        )
        self.store.graph_commit(GraphCandidate(
            self.event("self-context"), tuple(GraphVersion(write.key, 0) for write in writes),
            writes,
        ))

    def seed_self(self):
        self.seed()
        self.seed_self_graph()
        context = EncodingContext(
            self.self_event.token, self.self_perspective.token,
            (self.feeling.token,), (self.interpretation.token,),
            (("promise", 0.9), ("weather", 0.2)),
            tuple((key.token, 1) for key in (
                self.source, self.self_event, self.self_perspective,
                self.self_mapping, self.feeling, self.interpretation)),
        )
        return self.pipeline.prepare_encoding(
            "source-1", context, audience="owner", purpose="context")

    def envelope(self, prepared, *, missing=(), baseline=False):
        episode = prepared.proposal.episode.episode_id
        trace = prepared.proposal.trace.trace_id
        from sylanne3.memory_types import episode_key, subjective_trace_key
        event_ref = AtomKey.from_token(prepared.proposal.episode.event_ref)
        perspective_ref = AtomKey.from_token(prepared.proposal.trace.perspective_ref)
        self_refs = ((self.self_mapping,) if perspective_ref.type_name == "d03.self_perspective.v1" else ())
        reads = tuple(version for version in (
            *prepared.proof_versions,
            *(GraphVersion(key, 1) for key in
              (event_ref, perspective_ref, *self_refs, self.feeling, self.interpretation)),
            GraphVersion(episode_key("bot", "persona", episode), 0),
            GraphVersion((subjective_trace_v2_key if baseline else subjective_trace_key)(
                "bot", "persona", trace), 0),
            *( (GraphVersion(self.baseline, 1),) if baseline else () ),
        ) if version.key not in missing)
        admission = self.adapter.admit_source(SourceAdmission(
            "source-1", "A reported promise", "alice", "reported", "reported",
            "reported_claim", "not_applicable", None, 2.0, "family-1",
            ("owner",), ("context",),
        ))
        input_refs = (self.source.token,)
        return CommandEnvelope(
            RUNTIME_SCHEMA,
            OperationIdentity("encoding-1", None, "attempt-1", "encode",
                              "operation-1", canonical_digest({"input_refs": list(input_refs)})),
            AuthorityContext("worker", "d06", "capability-1", self.namespace,
                             ("event",), "context", ("owner",), "policy-1", 1),
            VersionGuard(reads, (), 1, 1, "catalogue-1", "scheme-1", "operator-1",
                         "policy-1", (), (), ()),
            admission.qualification, input_refs, "budget-1", 100.0, 10.0,
            "interval-1", ("source-1",),
        )

    def test_committed_proofs_compile_separate_episode_and_subjective_trace(self):
        prepared = self.seed()
        envelope = self.envelope(prepared)
        proposal = self.adapter.compile_encoding(envelope, prepared)
        D06DomainProvider().validate(proposal)
        episode, trace = proposal.typed_writes
        self.assertEqual(episode.value["source_refs"], [self.source.token])
        self.assertEqual(episode.value["event_ref"], self.event_ref.token)
        self.assertEqual(trace.value["episode_ref"], episode.key.token)
        self.assertEqual(trace.value["then_feeling_refs"], [self.feeling.token])
        self.assertEqual(trace.value["interpretation_refs"], [self.interpretation.token])
        self.assertEqual(trace.value["detail_weights"], [["promise", 0.9], ["weather", 0.2]])
        self.assertEqual(episode.dependencies, ())
        self.assertIn(GraphVersion(self.access, 1), proposal.dependencies.historical_provenance)
        receipt = self.store.graph_commit(GraphCandidate(
            self.event("encoding"), envelope.version_guard.read_versions, proposal.typed_writes,
        ))
        self.assertEqual(receipt.status, "committed")

    def test_missing_committed_context_or_access_proof_is_rejected(self):
        prepared = self.seed()
        with self.assertRaisesRegex(ValueError, "committed read proof"):
            self.adapter.compile_encoding(
                self.envelope(prepared, missing=(self.feeling,)), prepared,
            )
        with self.assertRaisesRegex(ValueError, "source proof differs"):
            self.adapter.compile_encoding(
                self.envelope(prepared, missing=(self.access,)), prepared,
            )

    def test_candidate_is_not_written_by_preparation_or_compilation(self):
        prepared = self.seed()
        proposal = self.adapter.compile_encoding(self.envelope(prepared), prepared)
        snapshot = self.store.graph_snapshot(tuple(write.key for write in proposal.typed_writes))
        self.assertTrue(all(atom.revision == 0 and not atom.valid for atom in snapshot.atoms))

    def test_access_withdrawal_after_preparation_stales_the_write(self):
        prepared = self.seed()
        envelope = self.envelope(prepared)
        proposal = self.adapter.compile_encoding(envelope, prepared)
        self.pipeline.repository.set_access(
            self.event("withdraw"), "source-1", audiences=("owner",),
            purposes=("context",), status="withdrawn", recorded_at=3.0,
        )
        with self.assertRaises(StaleRead):
            self.store.graph_commit(GraphCandidate(
                self.event("stale-encoding"), envelope.version_guard.read_versions,
                proposal.typed_writes,
            ))

    def test_provider_rejects_a_trace_detached_from_its_episode(self):
        prepared = self.seed()
        proposal = self.adapter.compile_encoding(self.envelope(prepared), prepared)
        episode, trace = proposal.typed_writes
        detached = GraphWrite(
            trace.key, {**trace.value, "episode_ref": episode.value["event_ref"]},
        )
        with self.assertRaisesRegex(ValueError, "episode_ref"):
            D06DomainProvider().validate(replace(proposal, typed_writes=(episode, detached)))

    def test_v2_baseline_is_typed_and_bound_to_read_and_historical_proofs(self):
        prepared = self.seed_self()
        with_baseline = replace(prepared, proposal=replace(
            prepared.proposal,
            read_versions=(*prepared.proposal.read_versions, (self.baseline.token, 1)),
        ))
        envelope = self.envelope(with_baseline, baseline=True)
        proposal = self.adapter.compile_encoding_v2(
            envelope, with_baseline, encoding_baseline_ref=self.baseline.token,
        )
        self.assertEqual(proposal.typed_writes[1].key.type_name, "memory.subjective_trace.v2")
        self.assertEqual(proposal.typed_writes[1].value["encoding_baseline_ref"], self.baseline.token)
        self.assertIn(GraphVersion(self.baseline, 1), proposal.dependencies.historical_provenance)
        D06DomainProvider().validate(proposal)

        without_history = replace(proposal, dependencies=replace(
            proposal.dependencies, historical_provenance=tuple(
                version for version in proposal.dependencies.historical_provenance
                if version.key != self.baseline),
        ))
        with self.assertRaisesRegex(ValueError, "provenance"):
            D06DomainProvider().validate(without_history)
        with self.assertRaisesRegex(ValueError, "committed read proof"):
            self.adapter.compile_encoding_v2(
                self.envelope(prepared, baseline=False), prepared,
                encoding_baseline_ref=self.baseline.token,
            )
        wrong_namespace = AtomKey(Owner("event", "other", "persona", "world-1"),
                                  "d04.encoding_baseline.v1", "record")
        with self.assertRaisesRegex(ValueError, "same-namespace"):
            self.adapter.compile_encoding_v2(
                envelope, with_baseline, encoding_baseline_ref=wrong_namespace.token,
            )

    def test_v2_rejects_sender_scene_and_missing_self_mapping_proof(self):
        legacy = self.seed()
        legacy = replace(legacy, proposal=replace(
            legacy.proposal,
            read_versions=(*legacy.proposal.read_versions, (self.baseline.token, 1)),
        ))
        with self.assertRaisesRegex(ValueError, "perspective_ref"):
            self.adapter.compile_encoding_v2(
                self.envelope(legacy, baseline=True), legacy,
                encoding_baseline_ref=self.baseline.token,
            )
        self.seed_self_graph()
        context = EncodingContext(
            self.self_event.token, self.self_perspective.token,
            (self.feeling.token,), (self.interpretation.token,), (),
            tuple((key.token, 1) for key in (
                self.source, self.self_event, self.self_perspective,
                self.self_mapping, self.feeling, self.interpretation,
                self.baseline,
            )),
        )
        self_prepared = self.pipeline.prepare_encoding(
            "source-1", context, audience="owner", purpose="context")
        guarded = self.envelope(self_prepared, baseline=True)
        missing_mapping = replace(guarded.version_guard, read_versions=tuple(
            version for version in guarded.version_guard.read_versions
            if version.key != self.self_mapping))
        with self.assertRaisesRegex(ValueError, "self_mapping_ref"):
            self.adapter.compile_encoding_v2(
                replace(guarded, version_guard=missing_mapping), self_prepared,
                encoding_baseline_ref=self.baseline.token,
            )
        complete = self.adapter.compile_encoding_v2(
            guarded, self_prepared, encoding_baseline_ref=self.baseline.token)
        stripped = replace(complete, dependencies=replace(
            complete.dependencies, historical_provenance=tuple(
                version for version in complete.dependencies.historical_provenance
                if version.key != self.self_mapping)))
        with self.assertRaisesRegex(ValueError, "provenance"):
            D06DomainProvider().validate(stripped)

    def test_first_ingress_result_requires_committed_d04_baseline_and_keeps_feelings_hypothetical(self):
        self.seed_self()
        result = {"text": ('{"event_summary":"A promise was reported",'
                           '"quoted_details":[{"quote":"promise","salience":0.8}],'
                           '"possible_meanings":["trust"],"possible_feelings":["relief"]}')}
        receipt = CallReceipt("completed", "encoding-1", "attempt-1", "call-1",
                              "digest-1", "provider-1", "model-1", "provider-call-1",
                              {}, {}, "confirmed", "eligible", False, "start-1", "finish-1")
        context = EncodingContext(
            self.self_event.token, self.self_perspective.token, (self.feeling.token,),
            (self.interpretation.token,), (),
            tuple((key.token, 1) for key in
                  (self.source, self.self_event, self.self_perspective, self.self_mapping,
                   self.feeling,
                   self.interpretation, self.baseline)),
        )
        with self.assertRaisesRegex(ValueError, "D04 baseline"):
            self.pipeline.prepare_first_ingress_encoding(
                "source-1", result, receipt, context,
                encoding_baseline_ref=self.baseline.token,
                audience="owner", purpose="context",
            )
        baseline_value = {
            "baseline_id": "baseline-1", "source_refs": [self.source.token],
            "perspective_ref": self.self_perspective.token,
            "then_feeling_versions": [{"ref": self.feeling.token, "revision": 1}],
            "interpretation_versions": [{"ref": self.interpretation.token, "revision": 1}],
            "as_known_at": 2.0, "projection_policy_ref": "policy-1",
            "projection_policy_version": "v1", "basis_version": "scheme-1",
            "parameter_version": "params-1", "salience_interval": None,
            "tone_interval": None,
            "unknown_reasons": ["salience_interval:unknown", "tone_interval:unknown"],
        }
        self.store.graph_commit(GraphCandidate(
            self.event("baseline"), (GraphVersion(self.baseline, 0),),
            (GraphWrite(self.baseline, baseline_value),),
        ))
        with self.assertRaisesRegex(ValueError, "arrival"):
            self.pipeline.prepare_first_ingress_encoding(
                "source-1", result, receipt,
                replace(context, event_ref=self.event_ref.token),
                encoding_baseline_ref=self.baseline.token,
                audience="owner", purpose="context",
            )
        model_prepared = self.pipeline.prepare_first_ingress_encoding(
            "source-1", result, receipt, context,
            encoding_baseline_ref=self.baseline.token,
            audience="owner", purpose="context",
        )
        self.assertEqual(model_prepared.prepared.proposal.trace.detail_weights,
                         (("promise", 0.8),))
        self.assertEqual(model_prepared.prepared.proposal.trace.then_feeling_refs,
                         (self.feeling.token,))
        self.assertEqual(model_prepared.possible_feelings, ("relief",))
        self.assertEqual(model_prepared.status, "candidate_hold")
        with self.assertRaisesRegex(TypeError, "candidate encoding"):
            self.adapter.compile_encoding_v2(
                self.envelope(model_prepared.prepared, baseline=True),
                model_prepared.prepared, encoding_baseline_ref=self.baseline.token,
            )
        with self.assertRaisesRegex(ValueError, "quoted detail"):
            self.pipeline.prepare_first_ingress_encoding(
                "source-1", {"text": result["text"].replace("promise\"", "invented\"")},
                receipt, context, encoding_baseline_ref=self.baseline.token,
                audience="owner", purpose="context",
            )
        event_value = self.store.graph_snapshot((self.self_event,)).get(self.self_event).value
        self.store.graph_commit(GraphCandidate(
            self.event("event-update"), (GraphVersion(self.self_event, 1),),
            (GraphWrite(self.self_event, event_value),),
        ))
        with self.assertRaisesRegex(RuntimeError, "changed during encoding"):
            self.pipeline.prepare_first_ingress_encoding(
                "source-1", result, receipt, context,
                encoding_baseline_ref=self.baseline.token,
                audience="owner", purpose="context",
            )

    def test_first_ingress_result_rejects_unqualified_receipt_and_changed_source_quote(self):
        self.seed()
        receipt = CallReceipt("unknown", "encoding-1", "attempt-1", "call-1",
                              "digest-1", "provider-1", "model-1", None,
                              {}, {}, "unconfirmed", "unknown", False)
        context = EncodingContext(self.event_ref.token, self.perspective.token,
                                  (), (), (), ((self.source.token, 1),))
        with self.assertRaisesRegex(ValueError, "completed model receipt claim"):
            self.pipeline.prepare_first_ingress_encoding(
                "source-1", {"text": "{}"}, receipt, context,
                encoding_baseline_ref=self.baseline.token,
                audience="owner", purpose="context",
            )

    def test_held_first_ingress_compilation_requires_original_result_and_keeps_hold(self):
        import json
        from sylanne3.authority_service.v2_model_egress_contract import (
            ModelEgressObservationV1, ModelTerminalReceiptV2,
        )
        from sylanne3.authority_service.v2_model_result_read_contract import ModelResultReadV1
        from sylanne3.runtime_contracts import DomainProposal

        self.seed_self()
        baseline_value = {
            "baseline_id": "baseline-1", "source_refs": [self.source.token],
            "perspective_ref": self.self_perspective.token,
            "then_feeling_versions": [{"ref": self.feeling.token, "revision": 1}],
            "interpretation_versions": [{"ref": self.interpretation.token, "revision": 1}],
            "as_known_at": 2.0, "projection_policy_ref": "policy-1",
            "projection_policy_version": "v1", "basis_version": "scheme-1",
            "parameter_version": "params-1", "salience_interval": None,
            "tone_interval": None,
            "unknown_reasons": ["salience_interval:unknown", "tone_interval:unknown"],
        }
        self.store.graph_commit(GraphCandidate(
            self.event("baseline"), (GraphVersion(self.baseline, 0),),
            (GraphWrite(self.baseline, baseline_value),),
        ))
        context = EncodingContext(
            self.self_event.token, self.self_perspective.token, (self.feeling.token,),
            (self.interpretation.token,), (),
            tuple((key.token, 1) for key in
                  (self.source, self.self_event, self.self_perspective, self.self_mapping,
                   self.feeling,
                   self.interpretation, self.baseline)),
        )
        result = {"text": json.dumps({
            "event_summary": "A promise was reported",
            "quoted_details": [{"quote": "promise", "salience": 0.8}],
            "possible_meanings": ["trust"], "possible_feelings": ["relief"],
        })}
        receipt = CallReceipt("completed", "operation-1", "attempt-1", "call-1",
                              "a" * 64, "provider-1", "model-1", "provider-call-1",
                              {}, {}, "confirmed", "eligible", False, "start-1", "finish-1")
        claim = self.pipeline.prepare_first_ingress_encoding(
            "source-1", result, receipt, context,
            encoding_baseline_ref=self.baseline.token,
            audience="owner", purpose="context",
        )
        observation = ModelEgressObservationV1(
            "authority-1", "namespace-1", "worker-1", "operation-1", "call-1",
            "a" * 64, "completed", json.dumps(result, sort_keys=True, separators=(",", ":")),
            (), (), "provider-call-1",
        )
        terminal = ModelTerminalReceiptV2(
            "b" * 64, "call-1", "a" * 64, "c" * 64,
            observation.digest, "sha256:" + "d" * 64, "installation-1", "e" * 64,
        )
        read = ModelResultReadV1("call-1", observation, terminal)
        held = replace(claim, authority_observation_digest=observation.digest,
                       authority_operation_id=observation.operation_id)
        envelope = self.envelope(held.prepared, baseline=True)
        with self.assertRaisesRegex(TypeError, "candidate encoding"):
            self.adapter.compile_encoding_v2(
                envelope, held.prepared, encoding_baseline_ref=self.baseline.token)
        compiled = self.pipeline.compile_first_ingress_c02_v2(
            envelope, held, read, audience="owner", purpose="context",
        )
        self.assertEqual(compiled.status, "candidate_hold")
        self.assertNotIsInstance(compiled, DomainProposal)
        self.assertEqual(compiled.proposal.typed_writes[1].value["then_feeling_refs"],
                         [self.feeling.token])
        self.assertEqual(compiled.possible_feelings, ("relief",))
        self.assertNotIn("possible_feelings", compiled.proposal.typed_writes[1].value)
        D06DomainProvider().validate(compiled.proposal)
        with self.assertRaisesRegex(ValueError, "original Authority result"):
            self.pipeline.compile_first_ingress_c02_v2(
                envelope, replace(held, authority_observation_digest="f" * 64),
                read, audience="owner", purpose="context",
            )
        with self.assertRaisesRegex(ValueError, "committed read proof"):
            self.pipeline.compile_first_ingress_c02_v2(
                self.envelope(held.prepared, baseline=True, missing=(self.baseline,)),
                held, read, audience="owner", purpose="context",
            )
        self.pipeline.repository.set_access(
            self.event("withdraw"), "source-1", audiences=("owner",),
            purposes=("context",), status="withdrawn", recorded_at=3.0,
        )
        with self.assertRaisesRegex(PermissionError, "unavailable"):
            self.pipeline.compile_first_ingress_c02_v2(
                envelope, held, read, audience="owner", purpose="context",
            )

    def test_worker_original_result_prepares_and_compiles_only_held_c02(self):
        import json
        from sylanne3.authority_service.v2_model_egress_contract import (
            ModelEgressObservationV1, ModelTerminalReceiptV2,
        )
        from sylanne3.authority_service.v2_worker_model_result_contract import (
            WorkerModelResultReadRequestV1, WorkerModelResultReadV1,
        )
        from sylanne3.model_broker.first_ingress_encoding import build_first_ingress_encoding_payload
        from sylanne3.runtime.encoding_call_binding import EncodingCallBinding
        from sylanne3.runtime_contracts import canonical_serialize, DomainProposal

        original = SourceRecord(
            "source-1", "A reported promise", "alice", "reported", "reported",
            None, 2.0, "family-1", ("owner",), ("context", "consolidation"),
        )
        self.pipeline.repository.ingest(self.event("source"), original)
        refs = (self.event_ref, self.perspective, self.feeling, self.interpretation)
        self.store.graph_commit(GraphCandidate(
            self.event("context"), tuple(GraphVersion(key, 0) for key in refs),
            tuple(GraphWrite(key, {"committed": True}) for key in refs),
        ))
        self.seed_self_graph()
        self.store.graph_commit(GraphCandidate(
            self.event("baseline"), (GraphVersion(self.baseline, 0),),
            (GraphWrite(self.baseline, {
                "baseline_id": "baseline-1", "source_refs": [self.source.token],
                "perspective_ref": self.self_perspective.token,
                "then_feeling_versions": [{"ref": self.feeling.token, "revision": 1}],
                "interpretation_versions": [{"ref": self.interpretation.token, "revision": 1}],
                "as_known_at": 2.0, "projection_policy_ref": "policy-1",
                "projection_policy_version": "v1", "basis_version": "scheme-1",
                "parameter_version": "params-1", "salience_interval": None,
                "tone_interval": None,
                "unknown_reasons": ["salience_interval:unknown", "tone_interval:unknown"],
            }),),
        ))
        context = EncodingContext(
            self.self_event.token, self.self_perspective.token, (self.feeling.token,),
            (self.interpretation.token,), (),
            tuple((key.token, 1) for key in
                  (self.source, self.self_event, self.self_perspective, self.self_mapping,
                   self.feeling,
                   self.interpretation, self.baseline)),
        )
        payload, template = build_first_ingress_encoding_payload(original)
        frozen = {
            "schema": "sylanne.first-ingress-encoding-call.v2",
            "namespace": ["bot", "persona"], "job_id": "job-1",
            "source_id": "source-1", "source_revision": 1, "access_revision": 1,
            "budget_lease_id": "budget-1", "budget_reservation_operation_id": "ingress-1",
            "call_id": "call-1", "envelope": {
                "identity": {"operation_id": "acquire-1", "phase": "encode"},
                "authority": {"worker_fence": 1, "purpose": "consolidation",
                              "owner_scope": ["activity"], "actor": "worker-1",
                              "audience": ["owner"]},
                "character_interval_ref": "interval-1", "monotonic_deadline": 10.0,
            },
            "provider_id": "provider-1", "model_id": "model-1",
            "required_capabilities": [], "privacy_tier": "private",
            "prompt_template_digest": template, "payload": payload,
            "timeout_seconds": 10.0, "max_output_tokens": 100,
            "acquire_operation_id": "acquire-1", "original_operation_id": "ingress-1",
            "work_kind": "d06.encode_source", "worker_fence": 1,
            "worker_lease_expires_utc": "2100-01-01T00:00:00Z", "clock_epoch": "clock-1",
        }
        frozen["model_request_digest"] = canonical_digest({
            "envelope": frozen["envelope"], "call_id": "call-1",
            "provider_id": "provider-1", "model_id": "model-1",
            "purpose": "consolidation", "required_capabilities": [],
            "privacy_tier": "private", "template": template, "payload": payload,
            "timeout_seconds": 10.0, "max_output_tokens": 100,
        })
        binding = EncodingCallBinding(
            self.namespace, "job-1", "source-1", 1, 1, "budget-1", "ingress-1",
            canonical_digest(frozen), frozen["model_request_digest"], "call-1",
            canonical_serialize(frozen),
        )
        request = WorkerModelResultReadRequestV1(
            "authority-1", "namespace-1", self.namespace, "installation-1",
            "job-1", "acquire-1", "ingress-1", "call-1",
            binding.binding_digest, binding.model_request_digest,
            "operation-1", "read-1",
        )
        result = {"text": json.dumps({
            "event_summary": "A promise was reported",
            "quoted_details": [{"quote": "promise", "salience": 0.8}],
            "possible_meanings": ["trust"], "possible_feelings": ["relief"],
        })}
        observation = ModelEgressObservationV1(
            "authority-1", "namespace-1", "worker-1", "acquire-1", "call-1",
            binding.model_request_digest, "completed",
            canonical_serialize(result), (), (), None,
        )
        terminal = ModelTerminalReceiptV2(
            "b" * 64, "call-1", binding.model_request_digest, "c" * 64,
            observation.digest, "sha256:" + "d" * 64, "installation-1", "e" * 64,
        )
        read = WorkerModelResultReadV1(request, observation, terminal)
        held = self.pipeline.prepare_worker_first_ingress_encoding(
            read, binding, original, context,
            encoding_baseline_ref=self.baseline.token,
            audience="owner", purpose="consolidation",
        )
        self.assertEqual(held.status, "candidate_hold")
        self.assertEqual(held.consumer_operation_id, "operation-1")
        envelope = self.envelope(held.prepared, baseline=True)
        envelope = replace(envelope, authority=replace(
            envelope.authority, purpose="consolidation"))
        compiled = self.pipeline.compile_first_ingress_c02_v2(
            envelope, held, read, audience="owner", purpose="consolidation",
        )
        self.assertNotIsInstance(compiled, DomainProposal)
        self.assertEqual(compiled.status, "candidate_hold")
        self.assertNotIn("possible_feelings", compiled.proposal.typed_writes[1].value)
        with self.assertRaisesRegex(ValueError, "consumer operation"):
            self.pipeline.compile_first_ingress_c02_v2(
                replace(envelope, identity=replace(
                    envelope.identity, operation_id="other-operation")),
                held, read, audience="owner", purpose="consolidation",
            )
        with self.assertRaisesRegex(ValueError, "worker original result"):
            self.pipeline.prepare_worker_first_ingress_encoding(
                replace(read, request=replace(request, binding_digest="f" * 64)),
                binding, original, context,
                encoding_baseline_ref=self.baseline.token,
                audience="owner", purpose="consolidation",
            )
        self.pipeline.repository.set_access(
            self.event("withdraw"), "source-1", audiences=("owner",),
            purposes=("context", "consolidation"), status="withdrawn",
            recorded_at=3.0,
        )
        with self.assertRaisesRegex(PermissionError, "unavailable"):
            self.pipeline.compile_first_ingress_c02_v2(
                envelope, held, read, audience="owner", purpose="consolidation",
            )


if __name__ == "__main__":
    unittest.main()
