"""D06 source withdrawal is a bound candidate, never a direct mutation."""

from dataclasses import replace

import pytest

from sylanne3.domains.d06 import D06DomainAdapter, D06DomainProvider
from sylanne3.domains.d06.source_access_revocation import (
    SourceAccessRevocationRequest, compile_source_access_revocation,
    revocation_operation_id,
)
from sylanne3.graph_types import GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    RUNTIME_SCHEMA, SourceQualification, VersionGuard, canonical_digest,
)


NAMESPACE = NamespaceId("bot", "persona")
ADAPTER = D06DomainAdapter(NAMESPACE)
SOURCE = source_key(*NAMESPACE.as_tuple, "source-1")
ACCESS = access_key(*NAMESPACE.as_tuple, "source-1")
REQUEST = SourceAccessRevocationRequest(
    "source-1", "paired-owner", "17b9c3c4-63df-4f5f-959b-9c2c0c1b682d", 3.0,
)


def fixture():
    source = SourceRecord("source-1", "private literal", "alice", "reported",
                          "reported", 1.0, 2.0, "family-1", ("owner",),
                          ("context",))
    access = {"source_id": "source-1", "audiences": ["owner"],
              "purposes": ["context"], "status": "active", "recorded_at": 2.0}
    snapshot = GraphSnapshot((GraphAtom(SOURCE, 1, source.to_dict()),
                              GraphAtom(ACCESS, 1, access)),
                             (NamespaceEpoch(*NAMESPACE.as_tuple, 2),))
    operation_id = revocation_operation_id(NAMESPACE, REQUEST)
    inputs = (SOURCE.token, ACCESS.token, "owner:paired-owner",
              f"revocation-request:{REQUEST.request_id}")
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity(REQUEST.request_id, operation_id, "attempt-1",
                          "source-access-revoke", operation_id,
                          canonical_digest({"input_refs": list(inputs)})),
        AuthorityContext("paired-owner", "d06", "owner-grant", NAMESPACE,
                         ("event", "persona"), "audit", ("owner",), "policy", 1),
        VersionGuard((GraphVersion(SOURCE, 1), GraphVersion(ACCESS, 1)), (),
                     4, 0, "catalogue", "scheme", "operator", "policy", (), (), ()),
        SourceQualification((SOURCE.token,), "reported", 1.0, 2.0,
                            "external_report", "qualified", None, "not_applicable"),
        inputs, "budget", 10.0, 10.0, "interval", ("owner-request",),
    )
    return snapshot, envelope


def test_revocation_is_one_exact_access_write_and_preserves_source():
    snapshot, envelope = fixture()
    candidate = compile_source_access_revocation(ADAPTER, envelope, REQUEST, snapshot)
    proposal = candidate.proposal
    assert candidate.status == "candidate_hold_authority_write_fence"
    assert candidate.operation_id == envelope.identity.operation_id
    assert candidate.requires_atomic_access_barrier
    assert proposal.required_bundle_parts == ()
    assert proposal.dependencies.current_invalidation == (GraphVersion(ACCESS, 1),)
    assert proposal.dependencies.historical_provenance == (GraphVersion(SOURCE, 1),)
    assert len(proposal.typed_writes) == 1
    write = proposal.typed_writes[0]
    assert write.key == ACCESS and write.dependencies == (SOURCE,)
    assert write.value == {**snapshot.get(ACCESS).value, "status": "withdrawn",
                           "recorded_at": 3.0}
    D06DomainProvider().validate(proposal, snapshot)


def test_wrong_actor_replay_or_stale_access_cannot_compile_or_bypass_provider():
    snapshot, envelope = fixture()
    wrong_actor = replace(envelope, authority=replace(envelope.authority,
                                                       actor="different-owner"))
    with pytest.raises(ValueError, match="Owner scope"):
        compile_source_access_revocation(ADAPTER, wrong_actor, REQUEST, snapshot)
    wrong_phase = replace(envelope, identity=replace(envelope.identity,
                                                     phase="source-correction"))
    with pytest.raises(ValueError, match="operation identity"):
        compile_source_access_revocation(ADAPTER, wrong_phase, REQUEST, snapshot)
    stale = replace(snapshot, atoms=(snapshot.get(SOURCE),
                                     replace(snapshot.get(ACCESS), revision=2)))
    with pytest.raises(ValueError, match="CAS"):
        compile_source_access_revocation(ADAPTER, envelope, REQUEST, stale)
    withdrawn = replace(snapshot, atoms=(snapshot.get(SOURCE),
                                         replace(snapshot.get(ACCESS),
                                                 value={**snapshot.get(ACCESS).value,
                                                        "status": "withdrawn"})))
    with pytest.raises(ValueError, match="withdrawn"):
        compile_source_access_revocation(ADAPTER, envelope, REQUEST, withdrawn)

    valid = compile_source_access_revocation(ADAPTER, envelope, REQUEST, snapshot).proposal
    bypass = replace(valid, envelope=wrong_phase)
    with pytest.raises(ValueError, match="bypasses"):
        D06DomainProvider().validate(bypass, snapshot)
    fabricated_job = replace(valid, required_bundle_parts=("persistent_job",))
    with pytest.raises(ValueError, match="bypasses"):
        D06DomainProvider().validate(fabricated_job, snapshot)
    widened = replace(valid, typed_writes=(replace(
        valid.typed_writes[0], value={**valid.typed_writes[0].value,
                                      "audiences": ["owner", "public"]}),))
    with pytest.raises(ValueError, match="current access head"):
        D06DomainProvider().validate(widened, snapshot)
    active_bypass = replace(valid, typed_writes=(replace(
        valid.typed_writes[0], value={**valid.typed_writes[0].value,
                                      "status": "active"}),))
    with pytest.raises(ValueError, match="dedicated mutation path"):
        D06DomainProvider().validate(active_bypass, snapshot)
    with pytest.raises(ValueError, match="UUID4"):
        SourceAccessRevocationRequest("source-1", "paired-owner", "replay", 3.0)
