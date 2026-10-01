"""D06 checks one graph read set before W01 can adopt a recollection bundle."""

from dataclasses import asdict, replace

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.domains.d06.current_association_candidates import (
    CurrentAssociationBudgetV1, prepare_current_association_candidates_v1,
)
from sylanne3.domains.d06.current_c04_association_preflight import (
    CurrentC04AssemblyOriginalsV1, preflight_current_c04_association_v1,
)
from sylanne3.domains.d07 import AttentionTicket, FocusState, attention_ticket_key
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphWrite, Owner
from sylanne3.memory_association import PersistentAssociationReader
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import SourceRecord, access_key, association_key, source_key

from test_c04_atomic_real_issuers import C04Harness
from test_current_c04_bundle_v1 import _current_candidate


def test_two_moods_share_one_source_and_revocation_blocks_preflight(tmp_path):
    harness = C04Harness(tmp_path)
    namespace = harness.namespace
    scope = Scope(*namespace.as_tuple, "session")
    repository = MemoryRepository(harness.store, *namespace.as_tuple)
    cue = source_key(*namespace.as_tuple, "source-1")
    target = source_key(*namespace.as_tuple, "source-2")
    try:
        repository.ingest(
            Event(scope, "second-ingress", 1.5, "ingress", {}),
            SourceRecord("source-2", "another evening", "alice", "observed",
                         "confirmed", 1.5, 2.5, "family-2", ("owner",),
                         ("context",)),
        )
        edge = association_key(*namespace.as_tuple, "source-1", "related")
        attention = AttentionTicket(
            "attention-current", "question:past", None, cue.token,
            "interaction", 0.8, 0.7, 0.4, 0.3, 0.2, 0.0, 0.1, 0.1, 0.0,
            1, 100.0, True, True, (), (cue.token,),
        )
        attention_key = attention_ticket_key(namespace, attention.ticket_id)
        focus_key = AtomKey(Owner("persona", *namespace.as_tuple),
                            "d07.focus.v1", namespace.persona_id)
        focus = FocusState(namespace.persona_id, 4, attention_key.token, (), "chosen")
        before = harness.store.graph_snapshot((edge, attention_key, focus_key))
        harness.store.graph_commit(GraphCandidate(
            Event(scope, "link-and-focus", 3.0, "association", {}), before.versions,
            (GraphWrite(edge, {
                "association_id": "related", "source_ref": cue.token,
                "target_ref": target.token, "kind": "subjective_meaning",
                "weight": 0.8, "context_tags": ["evening"],
                "basis_source_refs": [cue.token],
                "content_reality": "subjective",
            }), GraphWrite(attention_key, {
                **asdict(attention), "schema": "d07.attention_ticket.v1",
                "cancel_refs": [], "source_refs": [cue.token],
            }), GraphWrite(focus_key, {
                **asdict(focus), "schema": "d07.focus.v1",
                "auxiliary_ticket_refs": [],
            })), before.epochs,
        ))
        projections = []
        latest = None
        for suffix, mood, revision in (("warm", 0.8, 1), ("guarded", -0.8, 2)):
            (candidate, envelope, ticket, candidates, scheme, coupling,
             mood_key, support, original) = _current_candidate(
                harness, suffix=suffix, mood_value=mood, mood_revision=revision,
            )
            initial_keys = (
                attention_key, focus_key, cue,
                access_key(*namespace.as_tuple, "source-1"),
                source_correction_head_key(namespace, "source-1"),
            )
            focus_snapshot = harness.store.graph_snapshot(initial_keys)
            associations = prepare_current_association_candidates_v1(
                candidate, ticket=ticket, focus_snapshot=focus_snapshot,
                namespace=namespace, reader=PersistentAssociationReader(repository),
                now=5.0, audience="owner", purpose="context",
                budget=CurrentAssociationBudgetV1(max_edges=1),
                context_tags=("evening",),
            )
            keys = {version.key for version in (
                *envelope.version_guard.read_versions, *associations.read_versions,
            )}
            keys.add(source_correction_head_key(namespace, "source-2"))
            current = harness.store.graph_snapshot(tuple(keys))
            reads = tuple({version.key: version for version in (
                *envelope.version_guard.read_versions, *current.versions,
            )}.values())
            envelope = replace(envelope, version_guard=replace(
                envelope.version_guard, read_versions=reads,
            ))
            originals = CurrentC04AssemblyOriginalsV1(
                mood_key, scheme, coupling, harness.providers["d04"],
                f"feeling-{suffix}",
                tuple(replace(support[domain], envelope=envelope)
                      for domain in ("d07", "d02", "d11")),
                original.choice_refs[0], original.d02_settlement_refs[0],
                original.d11_cost_settlement_refs[0],
                original.persistent_job_refs[0], original.outbox_refs[0],
            )
            result = preflight_current_c04_association_v1(
                candidate, ticket=ticket, candidates=candidates,
                associations=associations, current_snapshot=current,
                namespace=namespace, envelope=envelope, originals=originals,
                now=5.0, audience="owner", purpose="context",
            )
            assert result.status == "candidate_hold_w01_atomic_commit_and_same_transaction_traversal"
            assert {item.domain for item in result.bundle_candidate.proposals} == {
                "d02", "d04", "d06", "d07", "d11",
            }
            assert tuple(item.source_ref for item in result.association_candidates.candidates) == (
                target.token,
            )
            projections.append(next(item for item in result.bundle_candidate.proposals
                                    if item.domain == "d06").typed_writes[1].value)
            latest = (candidate, ticket, candidates, associations, current,
                      envelope, originals)
        assert projections[0]["source_ref"] == projections[1]["source_ref"] == cue.token
        assert projections[0]["subjective_tone"] != projections[1]["subjective_tone"]
        assert harness.store.graph_snapshot((cue,)).get(cue).revision == 1
        candidate, ticket, candidates, associations, current, envelope, originals = latest
        target_head = source_correction_head_key(namespace, "source-2")
        with pytest.raises(ValueError, match="closure"):
            preflight_current_c04_association_v1(
                candidate, ticket=ticket, candidates=candidates,
                associations=associations,
                current_snapshot=replace(current, atoms=tuple(
                    atom for atom in current.atoms if atom.key != target_head)),
                namespace=namespace, envelope=envelope, originals=originals,
                now=5.0, audience="owner", purpose="context",
            )
        repository.set_access(
            Event(scope, "withdraw-target", 7.0, "withdraw", {}), "source-2",
            audiences=("owner",), purposes=("context",),
            status="withdrawn", recorded_at=7.0,
        )
        current = harness.store.graph_snapshot(tuple(version.key
            for version in envelope.version_guard.read_versions))
        with pytest.raises(ValueError, match="epoch|closure"):
            preflight_current_c04_association_v1(
                candidate, ticket=ticket, candidates=candidates,
                associations=associations, current_snapshot=current,
                namespace=namespace, envelope=envelope, originals=originals,
                now=8.0, audience="owner", purpose="context",
            )
    finally:
        harness.close()
