"""D06 source corrections remain graph candidates until W01 adopts a full bundle."""

from dataclasses import replace
from pathlib import Path
import tempfile

import pytest

from sylanne3.domains.d06 import (
    CorrectionRequest, D06DomainAdapter, D06DomainProvider, SourceAdmission,
    SourceCorrectionReadSetV1,
)
from sylanne3.contracts import Event, Scope
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import (
    InterpretationRecord, SourceRecord, access_key, interpretation_key, source_key,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    RUNTIME_SCHEMA, VersionGuard, canonical_digest,
)


NAMESPACE = NamespaceId("bot", "persona")
ADAPTER = D06DomainAdapter(NAMESPACE)
SOURCE = source_key("bot", "persona", "source-1")
ACCESS = access_key("bot", "persona", "source-1")
TARGET = interpretation_key("bot", "persona", "meaning-1")
D07 = AtomKey(Owner("persona", "bot", "persona"), "d07.belief_revision.v1", "belief-1")


def setup():
    request = CorrectionRequest(
        "correction-1", (TARGET.token,), (SOURCE.token,),
        "我那时在忙，并非拒绝", 3, 2,
    )
    source = SourceRecord(
        "source-1", "未及时回复", "owner", "reported", "reported",
        1.0, 2.0, "chat-1", ("owner", "observer"), ("context", "audit"),
    )
    access = {"source_id": "source-1", "audiences": ["owner"],
              "purposes": ["context"], "status": "active", "recorded_at": 2.0}
    interpretation = InterpretationRecord(
        "meaning-1", ("source-1",), "owner", "她拒绝了我", "reported", 1.0, 2.0,
    )
    reads = SourceCorrectionReadSetV1((source,), (access,), (interpretation,), (D07.token,))
    new_source = ADAPTER.correction_source_key(request)
    new_access = access_key("bot", "persona", new_source.owner.subject)
    input_refs = (new_source.token, SOURCE.token, TARGET.token, D07.token)
    qualification = ADAPTER.admit_source(SourceAdmission(
        "source-1", source.text, source.speaker_id, "reported", "reported",
        "reported_claim", "not_applicable", source.occurred_at, source.recorded_at,
        source.provenance_root, source.audiences, source.purposes,
    )).qualification
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity("activity-1", None, "attempt-1", "source-correction",
                          request.request_id,
                          canonical_digest({"input_refs": list(input_refs)})),
        AuthorityContext("owner-actor", "d06", "capability", NAMESPACE,
                         ("event", "persona"), "context", ("owner",), "policy", 1),
        VersionGuard((
            GraphVersion(new_source, 0), GraphVersion(new_access, 0),
            GraphVersion(SOURCE, 1), GraphVersion(ACCESS, 1),
            GraphVersion(TARGET, 1), GraphVersion(D07, 1),
        ), (), 3, 2, "catalogue", "scheme", "operator", "policy", (), (), ()),
        qualification, input_refs, "budget", 100.0, 10.0, "interval", ("correction",),
    )
    return request, reads, envelope


def test_correction_compiles_reported_source_and_retraction_without_claiming_commit():
    request, reads, envelope = setup()
    candidate = ADAPTER.compile_source_correction(envelope, request, reads, recorded_at=5.0)
    proposal = candidate.proposal
    new_source, new_access, invalidation = proposal.typed_writes
    assert candidate.status == "proposal_requires_w01_atomic_bundle"
    assert candidate.correction_source_ref == new_source.key.token
    assert candidate.invalidated_target_refs == (TARGET.token,)
    assert candidate.d07_invalidation_refs == (D07.token,)
    assert candidate.required_reevaluation_domains == ("d07", "d04", "d05")
    assert proposal.required_bundle_parts == ("persistent_job", "outbox")
    assert new_source.value["source_kind"] == "reported"
    assert new_source.value["assertion_status"] == "reported"
    assert new_source.value["occurred_at"] is None
    assert new_source.value["parent_source_ids"] == ["source-1"]
    assert new_source.value["audiences"] == ["owner"]
    assert new_source.value["purposes"] == ["context"]
    assert new_access.value["status"] == "active"
    assert invalidation.key == TARGET
    assert invalidation.value["status"] == "retracted"
    assert invalidation.value["valid_to"] == 5.0
    assert invalidation.value["claim"] == reads.interpretations[0].claim
    assert GraphVersion(TARGET, 1) not in proposal.dependencies.current_invalidation
    assert GraphVersion(TARGET, 1) in proposal.dependencies.historical_provenance
    assert GraphVersion(D07, 1) not in proposal.dependencies.current_invalidation
    assert GraphVersion(D07, 1) in proposal.dependencies.historical_provenance
    actual_current = {dependency for write in proposal.typed_writes
                      for dependency in write.dependencies}
    classified_current = {version.key for version in proposal.dependencies.current_invalidation}
    assert actual_current == classified_current == {new_source.key}
    assert new_access.dependencies == (new_source.key,)
    assert invalidation.dependencies == (new_source.key,)


def test_correction_writes_commit_without_self_dependency_cycle():
    request, reads, envelope = setup()
    registry = TypeRegistry()
    for spec in D06DomainProvider.type_specs():
        registry.register(spec)
    with tempfile.TemporaryDirectory() as directory:
        store = GraphStore(Path(directory) / "correction.db", registry)
        try:
            repository = MemoryRepository(store, "bot", "persona")
            scope = Scope("bot", "persona", "session")
            repository.ingest(Event(scope, "source-ingress", 1.0, "ingress", {}),
                              reads.sources[0])
            initial = store.graph_snapshot((TARGET, SOURCE))
            store.graph_commit(GraphCandidate(
                Event(scope, "interpretation-ingress", 2.0, "ingress", {}),
                initial.versions,
                (GraphWrite(TARGET, reads.interpretations[0].to_dict(), (SOURCE,)),),
                initial.epochs,
            ))
            candidate = ADAPTER.compile_source_correction(
                envelope, request, reads, recorded_at=5.0,
            )
            write_keys = tuple(write.key for write in candidate.proposal.typed_writes)
            snapshot = store.graph_snapshot(write_keys)
            receipt = store.graph_commit(GraphCandidate(
                Event(scope, "correction-ingress", 5.0, "correction", {}),
                snapshot.versions, candidate.proposal.typed_writes, snapshot.epochs,
            ))
            assert GraphVersion(TARGET, 2) in receipt.revisions
            corrected = store.graph_snapshot((TARGET,))
            assert corrected.atoms[0].value["status"] == "retracted"
        finally:
            store.close()


def test_correction_rejects_revocation_missing_proof_and_stale_epochs():
    request, reads, envelope = setup()
    revoked = replace(reads, accesses=({**reads.accesses[0], "status": "withdrawn"},))
    with pytest.raises(ValueError, match="current source access"):
        ADAPTER.compile_source_correction(envelope, request, revoked, recorded_at=5.0)
    guard = envelope.version_guard
    missing = replace(guard, read_versions=tuple(
        version for version in guard.read_versions if version.key != TARGET))
    with pytest.raises(ValueError, match="complete CAS"):
        ADAPTER.compile_source_correction(replace(envelope, version_guard=missing),
                                          request, reads, recorded_at=5.0)
    stale = replace(guard, delete_epoch=3)
    with pytest.raises(ValueError, match="epochs"):
        ADAPTER.compile_source_correction(replace(envelope, version_guard=stale),
                                          request, reads, recorded_at=5.0)


def test_correction_rejects_wrong_target_cross_namespace_and_unrelated_claim():
    request, reads, envelope = setup()
    unrelated = replace(reads, interpretations=(replace(
        reads.interpretations[0], source_ids=("other-source",)),))
    with pytest.raises(ValueError, match="dependent interpretation"):
        ADAPTER.compile_source_correction(envelope, request, unrelated, recorded_at=5.0)
    other = AtomKey(Owner("persona", "other-bot", "persona"),
                    "d07.belief_revision.v1", "belief-1")
    cross_scope = replace(reads, d07_belief_refs=(other.token,))
    with pytest.raises(ValueError, match="shared graph contract"):
        ADAPTER.compile_source_correction(envelope, request, cross_scope, recorded_at=5.0)
    old = replace(reads, interpretations=(replace(
        reads.interpretations[0], status="retracted", valid_to=3.0),))
    with pytest.raises(ValueError, match="current dependent interpretation"):
        ADAPTER.compile_source_correction(envelope, request, old, recorded_at=5.0)
