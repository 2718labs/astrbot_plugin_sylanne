import dataclasses
from hashlib import sha256
import json
import unittest

from sylanne3.model_broker.context_reply import (
    ContextReplyInputV1,
    ContextReplyInstallationV1,
    ContextReplyPartV1,
    freeze_context_reply_request_v1,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.runtime_contracts import (
    CONTEXT_REPLY_WORKFLOW_V1, ContextReplyOriginalSealV2,
    NamespaceId, QueryEpoch, VersionedRef,
    context_reply_graph_guard_digest_v2,
)


def ref(name, version=1):
    return VersionedRef(name, version)


AUDIENCE = ref("audience:private")
BLOCK_REF = '["persona","bot","persona",null,"d13.compressed_turn_block.v2","one"]'


def part(kind, name, text, **changes):
    values = dict(kind=kind, ref=ref(name), audience_ref=AUDIENCE,
                  expires_at_utc=150.0, text=text)
    values.update(changes)
    return ContextReplyPartV1(**values)


def example_input(**changes):
    values = dict(
        namespace=NamespaceId("bot", "persona"), scene_ref=ref("scene:1"),
        audience_ref=AUDIENCE, conversation_ref="conversation:1",
        access_epoch=2, delete_epoch=3, activation_generation=4,
        frozen_at_utc=100.0, expires_at_utc=140.0,
        question=part("question", "turn:current", "What happened now?"),
        evidence=(part("d06_evidence", "source:1", "The door opened.",
                       access_ref=ref("access:1", 2)),),
        history=(part("d13_history", "d13:block:1", "Earlier we discussed the door.",
                      dependencies=(ref("source:older"),)),),
        stable_history=(part("d13_history", BLOCK_REF, "The earlier door discussion.",
                             dependencies=(ref("source:older"),)),),
    )
    values.update(changes)
    return ContextReplyInputV1(**values)


INSTALLATION = ContextReplyInstallationV1(
    "install:1", "a" * 64, "provider:1", "model:1", 256)


class ContextReplyContractTests(unittest.TestCase):
    def test_stable_and_dynamic_messages_bind_exact_provider_wire(self):
        frozen = freeze_context_reply_request_v1(example_input(), INSTALLATION)
        wire = json.loads(frozen.canonical_wire)
        self.assertEqual([item["role"] for item in wire["messages"]],
                         ["system", "user", "user"])
        stable = json.loads(wire["messages"][1]["content"])
        dynamic = json.loads(wire["messages"][2]["content"])
        self.assertEqual(stable["stable_history"][0]["ref"]["ref"], BLOCK_REF)
        self.assertNotIn("sections", stable)
        self.assertEqual([section["kind"] for section in dynamic["sections"]],
                         ["question", "d06_evidence", "d07_focus", "required_check",
                          "d09_state", "d13_history"])
        self.assertEqual(dynamic["sections"][0]["parts"][0]["text"], "What happened now?")
        self.assertEqual(dynamic["sections"][1]["parts"][0]["access_ref"],
                         {"ref": "access:1", "version": 2})
        self.assertEqual(dynamic["sections"][5]["parts"][0]["kind"], "d13_history")
        self.assertTrue(frozen.canonical_wire.startswith(frozen.stable_prefix_wire))
        self.assertNotIn("What happened now?", frozen.stable_prefix_wire)
        self.assertEqual(frozen.digest, sha256(frozen.canonical_wire.encode("utf-8")).hexdigest())
        self.assertFalse(hasattr(frozen, "actual_input_tokens"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            frozen.messages[0].content = "changed"

    def test_dynamic_tail_changes_request_but_not_stable_prefix(self):
        original = example_input()
        changed = dataclasses.replace(original, question=dataclasses.replace(
            original.question, text="What happened next?"))
        first = freeze_context_reply_request_v1(original, INSTALLATION)
        second = freeze_context_reply_request_v1(changed, INSTALLATION)
        self.assertNotEqual(first.digest, second.digest)
        self.assertEqual(first.stable_prefix_digest, second.stable_prefix_digest)
        self.assertEqual(first.stable_prefix_wire, second.stable_prefix_wire)
        changed_block = dataclasses.replace(original, stable_history=(
            dataclasses.replace(original.stable_history[0], text="The door was discussed again."),
        ))
        self.assertNotEqual(first.stable_prefix_wire,
                            freeze_context_reply_request_v1(changed_block, INSTALLATION).stable_prefix_wire)
        different_install = dataclasses.replace(INSTALLATION, installation_id="install:2")
        self.assertNotEqual(first.stable_prefix_digest,
                            freeze_context_reply_request_v1(original, different_install).stable_prefix_digest)
        different_scene = dataclasses.replace(original, scene_ref=ref("scene:2"))
        self.assertNotEqual(first.stable_prefix_digest,
                            freeze_context_reply_request_v1(different_scene, INSTALLATION).stable_prefix_digest)
        other_audience = ref("audience:other")
        different_audience = dataclasses.replace(
            original, audience_ref=other_audience,
            question=dataclasses.replace(original.question, audience_ref=other_audience),
            evidence=tuple(dataclasses.replace(item, audience_ref=other_audience)
                           for item in original.evidence),
            history=tuple(dataclasses.replace(item, audience_ref=other_audience)
                          for item in original.history),
            stable_history=tuple(dataclasses.replace(item, audience_ref=other_audience)
                                 for item in original.stable_history),
        )
        self.assertNotEqual(first.stable_prefix_digest,
                            freeze_context_reply_request_v1(different_audience, INSTALLATION).stable_prefix_digest)

    def test_evidence_and_history_boundaries(self):
        with self.assertRaisesRegex(ValueError, "D06 evidence"):
            part("d06_evidence", "source:1", "fact")
        with self.assertRaisesRegex(ValueError, "D13 history"):
            part("d13_history", "d13:block", "history")
        with self.assertRaisesRegex(ValueError, "D13 cannot be fact evidence"):
            example_input(evidence=(part("d06_evidence", "d13:block", "not a fact",
                                         access_ref=ref("access:1")),))
        d13_graph_ref = '["persona","bot","persona",null,"d13.compressed_turn_block.v2","two"]'
        with self.assertRaisesRegex(ValueError, "D13 cannot be fact evidence"):
            example_input(evidence=(part("d06_evidence", d13_graph_ref, "not a fact",
                                         access_ref=ref("access:1")),))
        with self.assertRaisesRegex(ValueError, "audience or TTL"):
            example_input(question=part("question", "turn:1", "question",
                                        audience_ref=ref("audience:other")))
        with self.assertRaisesRegex(ValueError, "audience or TTL"):
            example_input(question=part("question", "turn:1", "question",
                                        expires_at_utc=120.0))
        with self.assertRaisesRegex(ValueError, "qualified D06 evidence"):
            example_input(evidence=())
        with self.assertRaisesRegex(ValueError, "stable history requires"):
            example_input(stable_history=(part("d13_history", "d13:raw-tail", "raw turn",
                                               dependencies=(ref("source:older"),)),))

    def test_v2_original_seal_cannot_relabel_a_v1_paid_call(self):
        fields = dict(namespace=NamespaceId("bot", "persona"),
                      c02_operation_id="c02:1", source_ref="source:1",
                      installation_id="install:1", provider_config_digest="a" * 64,
                      job_id="context-job:1", original_operation_id="context-op:1",
                      acquire_operation_id="context-acquire:1", call_id="context-call:1",
                      template_version=CONTEXT_REPLY_WORKFLOW_V1,
                      frozen_input_digest="b" * 64, model_request_digest="c" * 64,
                      graph_guard_digest="d" * 64)
        seal = ContextReplyOriginalSealV2(**fields)
        self.assertEqual(seal.template_version, CONTEXT_REPLY_WORKFLOW_V1)
        self.assertFalse(hasattr(seal, "terminal_receipt_digest"))
        with self.assertRaisesRegex(ValueError, "template identity"):
            ContextReplyOriginalSealV2(**(fields | {"template_version": "source_reply.v1"}))

    def test_graph_guard_binds_missing_correction_head_and_epochs(self):
        namespace = NamespaceId("bot", "persona")
        owner = Owner("persona", "bot", "persona")
        source = GraphVersion(AtomKey(owner, "memory.source.v1", "s"), 2)
        correction_head = GraphVersion(AtomKey(owner, "memory.source_correction_head.v1", "s"), 0)
        query = QueryEpoch(namespace, "context_reply", 5)
        def digest(reads, **changes):
            values = dict(graph_epoch=5, access_epoch=2, delete_epoch=3,
                          activation_generation=4)
            values.update(changes)
            return context_reply_graph_guard_digest_v2(reads, query, **values)
        current = digest((source, correction_head))
        self.assertEqual(current, digest((correction_head, source)))
        self.assertNotEqual(current, digest((source,)))
        self.assertNotEqual(current, digest((source, correction_head), delete_epoch=4))
        with self.assertRaisesRegex(ValueError, "repeats a key"):
            digest((source, source))


if __name__ == "__main__":
    unittest.main()
