"""A repeated cue is not reflection progress or a new causal budget."""

from dataclasses import asdict, replace

import pytest

from sylanne3.domains.d07 import D07DomainProvider, ReflectionCheckpoint
from sylanne3.domains.d07.reflection_transition import (
    compile_reflection_transition, reflection_checkpoint_key,
)
from sylanne3.graph_types import GraphAtom, GraphSnapshot, NamespaceEpoch
from sylanne3.runtime_contracts import NamespaceId


NS = NamespaceId("bot", "persona")


def _snapshot(checkpoint):
    key = reflection_checkpoint_key(NS, checkpoint.reflection_id)
    value = asdict(checkpoint)
    value.update(schema="d07.reflection_checkpoint.v1",
                 unresolved_slots=list(checkpoint.unresolved_slots),
                 discriminating_refs=list(checkpoint.discriminating_refs))
    return GraphSnapshot((GraphAtom(key, 3, value),),
                         (NamespaceEpoch(*NS.as_tuple, 9),))


def _compile(snapshot, *, evidence=("cue:old",), depth=1, resolved=()):
    return compile_reflection_transition(
        snapshot, NS, reflection_id="reflection", resolved_slots=resolved,
        discriminating_refs=evidence, causal_depth=depth,
    )


def test_repeated_cue_advances_no_progress_counter_and_requires_w01_cas():
    state = ReflectionCheckpoint("reflection", 1, 0, ("slot",), ("cue:old",), "continue")
    candidate = _compile(_snapshot(state))
    assert candidate is not None
    assert candidate.next_checkpoint.no_progress_count == 1
    assert candidate.next_checkpoint.discriminating_refs == ("cue:old",)
    assert candidate.prior_version.revision == 3
    assert candidate.graph_epoch == 9
    assert candidate.proposed_write.key == candidate.prior_version.key
    assert candidate.proposed_write.value["no_progress_count"] == 1
    assert "requires_w01" in candidate.status
    assert _compile(_snapshot(replace(state, no_progress_count=1))).next_checkpoint.status == "waiting_for_new_trigger"


def test_waiting_requires_novel_trigger_and_shared_depth_cannot_reset():
    state = ReflectionCheckpoint("reflection", 1, 2, ("slot",), ("cue:old",),
                                 "waiting_for_new_trigger")
    snapshot = _snapshot(state)
    assert _compile(snapshot) is None
    assert _compile(snapshot, depth=0, evidence=("cue:new",)) is None
    assert _compile(snapshot, depth=2, evidence=("cue:new",)) is None
    resumed = _compile(snapshot, evidence=("cue:new",))
    assert resumed is not None
    assert resumed.next_checkpoint.status == "continue"
    assert resumed.next_checkpoint.no_progress_count == 0
    assert resumed.next_checkpoint.discriminating_refs == ("cue:old", "cue:new")
    assert _compile(snapshot, evidence=("cue:new",), resolved=("invented",)) is None


def test_plain_domain_proposal_cannot_forge_reflection_progress():
    from rewrite.tests.alpha1.d07.test_cognition_domain import recollection_envelope

    checkpoint = ReflectionCheckpoint("reflection", 1, 0, ("slot",), (), "continue")
    candidate = _compile(_snapshot(checkpoint), evidence=())
    assert candidate is not None
    provider = D07DomainProvider()
    envelope, _ = recollection_envelope()
    proposal = replace(provider.proposal_for(envelope),
                       typed_writes=(candidate.proposed_write,))
    with pytest.raises(ValueError, match="W01 fenced transition adoption"):
        provider.validate(proposal)
