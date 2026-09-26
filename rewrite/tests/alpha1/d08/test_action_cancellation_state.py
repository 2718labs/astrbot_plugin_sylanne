from dataclasses import asdict, replace
import json
import unittest

from sylanne3.domains.d08 import ActionCancellationState, GoalExecutionProvider
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, GraphWrite, NamespaceEpoch, Owner
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize

from .test_goal_execution_domain import _intent, _proposal, _schema


def _fixture(*, action=None, previous=None, state_revision=0, bot="bot"):
    action = action or _intent()
    owner = Owner("activity", bot, "persona", action.identity.activity_id)
    action_key = AtomKey(owner, "d08.action_intent.v1", action.action_id)
    state_key = AtomKey(owner, "d08.action_cancellation.v1", action.action_id)
    action_atom = GraphAtom(action_key, action.revision,
                            json.loads(canonical_serialize(asdict(action))))
    atoms = (action_atom,) if previous is None else (
        action_atom, GraphAtom(state_key, state_revision,
                               json.loads(canonical_serialize(asdict(previous)))),
    )
    snapshot = GraphSnapshot(atoms, (NamespaceEpoch(bot, "persona", 1),))
    base = _proposal()
    identity = replace(base.envelope.identity, activity_id=action.identity.activity_id,
                       attempt_id=action.identity.attempt_id,
                       operation_id="operation:cancel-1")
    guard = replace(base.envelope.version_guard, read_versions=(
        GraphVersion(action_key, action.revision), GraphVersion(state_key, state_revision),
    ))
    proposal = replace(base, envelope=replace(base.envelope, identity=identity,
                                               version_guard=guard))
    return proposal, snapshot, state_key


class ActionCancellationStateTests(unittest.TestCase):
    def test_initial_and_cancel_transition_are_bound_to_exact_action_attempt(self):
        provider = GoalExecutionProvider()
        intent = _intent()
        base = _proposal()
        proposal = replace(base, envelope=replace(base.envelope, identity=intent.identity))
        initial = provider.prepare_action_candidate(proposal, intent, _schema())
        state_write = next(write for write in initial.typed_writes
                           if write.key.type_name == "d08.action_cancellation.v1")
        self.assertEqual(state_write.value["cancel_epoch"], 0)
        self.assertEqual(state_write.value["actor"], proposal.envelope.authority.actor)
        self.assertEqual({v.revision for v in initial.envelope.version_guard.read_versions
                          if v.key in {write.key for write in initial.typed_writes}}, {0})
        absent = tuple(GraphAtom(write.key, 0, {}, False)
                       for write in initial.typed_writes)
        provider.validate(initial, GraphSnapshot(
            absent, (NamespaceEpoch("bot", "persona", 1),)))
        state = ActionCancellationState(**{**state_write.value,
                                           "source_refs": tuple(state_write.value["source_refs"])})
        proposal, snapshot, _ = _fixture(previous=state, state_revision=1)
        cancelled = provider.prepare_action_cancellation(proposal, _intent(), snapshot,
                                                          state="cancelled")
        self.assertEqual(cancelled.typed_writes[0].value["cancel_epoch"], 1)
        self.assertEqual(cancelled.typed_writes[0].value["state"], "cancelled")

    def test_stale_epoch_and_terminal_replay_are_rejected(self):
        provider = GoalExecutionProvider()
        proposal, snapshot, _ = _fixture()
        with self.assertRaisesRegex(ValueError, "initial cancellation"):
            provider.prepare_action_cancellation(proposal, _intent(), snapshot, state="cancelled")
        initial = ActionCancellationState.for_action(
            _intent(), state="active", actor="host:user",
            source_refs=("source:request-1",), operation_id="operation:initial",
        )
        proposal, snapshot, _ = _fixture(previous=initial, state_revision=2)
        stale = replace(proposal, envelope=replace(
            proposal.envelope, version_guard=replace(
                proposal.envelope.version_guard,
                read_versions=proposal.envelope.version_guard.read_versions[:1]
                + (GraphVersion(proposal.envelope.version_guard.read_versions[1].key, 1),),
            ),
        ))
        with self.assertRaisesRegex(ValueError, "guarded action"):
            provider.prepare_action_cancellation(stale, _intent(), snapshot, state="cancelled")
        cancelled = replace(initial, state="cancelled", cancel_epoch=1)
        proposal, snapshot, _ = _fixture(previous=cancelled, state_revision=3)
        with self.assertRaisesRegex(ValueError, "already terminal"):
            provider.prepare_action_cancellation(proposal, _intent(), snapshot, state="cancelled")

    def test_cross_namespace_and_later_attempt_are_rejected(self):
        provider = GoalExecutionProvider()
        proposal, snapshot, _ = _fixture()
        with self.assertRaisesRegex(ValueError, "initial active"):
            provider.prepare_action_cancellation(proposal, _intent(), snapshot, state="active")
        initial_state = ActionCancellationState.for_action(
            _intent(), state="active", actor="host:user",
            source_refs=("source:request-1",), operation_id="operation:initial")
        proposal, snapshot, _ = _fixture(previous=initial_state, state_revision=1)
        valid = provider.prepare_action_cancellation(proposal, _intent(), snapshot,
                                                      state="cancelled")
        foreign = GraphWrite(AtomKey(Owner("activity", "other-bot", "persona",
                                               _intent().identity.activity_id),
                                     "d08.action_cancellation.v1", _intent().action_id),
                             valid.typed_writes[0].value)
        with self.assertRaises(ValueError):
            replace(proposal, typed_writes=(foreign,))
        old = _intent()
        new = _intent(attempt_id="attempt:2")
        previous = ActionCancellationState.for_action(
            old, state="active", actor="host:user",
            source_refs=("source:request-1",), operation_id="operation:initial",
        )
        proposal, snapshot, _ = _fixture(action=new, previous=previous, state_revision=1)
        with self.assertRaisesRegex(ValueError, "stale or already terminal"):
            provider.prepare_action_cancellation(proposal, new, snapshot, state="cancelled")

    def test_duplicate_identity_cannot_reinitialize_state(self):
        provider = GoalExecutionProvider()
        initial = ActionCancellationState.for_action(
            _intent(), state="active", actor="host:user",
            source_refs=("source:request-1",), operation_id="operation:cancel-1",
        )
        proposal, snapshot, _ = _fixture(previous=initial, state_revision=1)
        with self.assertRaisesRegex(ValueError, "initial active"):
            provider.prepare_action_cancellation(proposal, _intent(), snapshot, state="active")
        self.assertEqual(initial.action_digest, canonical_digest(_intent()))


if __name__ == "__main__":
    unittest.main()
