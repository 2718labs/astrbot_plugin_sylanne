"""D04 content candidate checks bind a committed C04 feeling to source and mood."""

from dataclasses import fields, replace

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d04 import (
    MoodField, RecollectionSnapshotUnavailable,
    inspect_recollection_experience_snapshot,
)
from sylanne3.domains.d04.source_head import D04SourceHeadRead
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphWrite, Owner
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import access_key, source_key

from test_c04_atomic_real_issuers import C04Harness


def test_recollection_candidate_checks_content_but_cannot_authorize_literal(tmp_path):
    harness = C04Harness(tmp_path)
    try:
        source = source_key("bot", "persona", "source-1")
        access = access_key("bot", "persona", "source-1")
        mood_key = AtomKey(Owner("persona", "bot", "persona"),
                           "d04.mood_field.v1", "current")
        mood = MoodField("mood-c04", "scheme-1", (("care", 0.6),),
                         (source.token,), "parameter-1", "coupling-1", 2.0)
        prior = harness.store.graph_snapshot((mood_key,))
        harness.store.graph_commit(GraphCandidate(
            Event(Scope("bot", "persona", "session"), "mood-before-c04", 2.0,
                  "mood", {}), prior.versions,
            (GraphWrite(mood_key, {
                **mood.__dict__, "coordinates": [["care", 0.6]],
                "source_refs": [source.token],
            }),), prior.epochs,
        ))
        bundle = harness.bundle()
        receipt = harness.coordinator.commit_domain_bundle(bundle, harness.lease)
        experience_key = next(
            write.key for proposal in bundle.proposals if proposal.domain == "d04"
            for write in proposal.typed_writes
        )
        recollection_key = AtomKey.from_token(bundle.experience_refs[0])
        keys = (source, access, mood_key, recollection_key, experience_key)

        def inspect(snapshot):
            return inspect_recollection_experience_snapshot(
                snapshot, namespace=harness.namespace, audience=("owner",),
                purpose="context", experience_ref=experience_key.token,
                mood_key=mood_key, receipt=receipt,
                scheme=harness.providers["d04"]._active_scheme,
            )

        snapshot = harness.store.graph_snapshot(keys)
        result = inspect(snapshot)
        assert result.status == "snapshot_content_candidate"
        assert result.source_ref == source.token
        assert result.source_kind == result.provenance_eligibility == "observed"
        assert result.assertion_status == "confirmed"
        assert result.mood == mood
        assert result.experience.evidence_weight_delta == 0.0
        assert result.encoding_baseline_certified is False
        assert set(result.read_versions) == set(snapshot.versions)
        assert "source_text" not in {item.name for item in fields(result)}
        assert "shared evening" not in repr(result)

        # A caller can construct this DTO; it is not accepted as a trusted read.
        forged = D04SourceHeadRead(
            snapshot, harness.namespace, ("owner",), "context",
            None, True, True, True,
        )
        with pytest.raises(TypeError, match="read DTO is not authority"):
            inspect(forged)

        changed_mood = replace(snapshot, atoms=tuple(
            replace(atom, value={**atom.value, "source_refs": ["another-source"]})
            if atom.key == mood_key else atom for atom in snapshot.atoms
        ))
        with pytest.raises(RecollectionSnapshotUnavailable, match="mood identity"):
            inspect(changed_mood)

        repository = MemoryRepository(harness.store, "bot", "persona")
        repository.set_access(
            Event(Scope("bot", "persona", "session"), "revoke-after-c04", 3.0,
                  "withdraw", {}), "source-1", audiences=("owner",),
            purposes=("context",), status="withdrawn", recorded_at=3.0,
        )
        with pytest.raises(RecollectionSnapshotUnavailable, match="access_denied"):
            inspect(harness.store.graph_snapshot(keys))
        # A stale snapshot is still just a candidate; it never returns literal.
        assert "shared evening" not in repr(inspect(snapshot))
    finally:
        harness.close()
