"""D04 source heads follow D06 source and ancestor access semantics."""

from dataclasses import replace

from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.domains.d04.source_head import D04SourceHeadRead, derive_d04_source_heads
from sylanne3.graph_types import GraphAtom, GraphSnapshot, NamespaceEpoch
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.native_runtime.d04_block_instances import D04BlockIdentity, D04BlockInstance
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import FenceScope, NamespaceId


NAMESPACE = NamespaceId("bot", "persona")
EPOCH = NamespaceEpoch("bot", "persona", 7)


def _source(source_id: str, *, parents=()):
    record = SourceRecord(
        source_id, "evidence", "speaker", "reported", "reported", 1.0, 2.0,
        "family", ("entity:alice",), ("context", "expression"), parents,
    )
    return (
        GraphAtom(source_key("bot", "persona", source_id), 1, record.to_dict()),
        GraphAtom(access_key("bot", "persona", source_id), 1, {
            "source_id": source_id, "audiences": ["entity:alice"],
            "purposes": ["context", "expression"], "status": "active",
            "recorded_at": 2.0,
        }),
    )


def _fence():
    anchor = RestoreAnchor(
        authority_id="authority", namespace="authority-namespace",
        activation_generation=3, deletion_journal_id="deletion",
        deletion_seq=0, deletion_digest="genesis",
        execution_journal_id="execution", execution_seq=0,
        execution_digest="genesis", revocation_epoch=0, proof="opaque-proof",
    )
    permit = FencePermitV2(
        authority_id=anchor.authority_id, namespace=anchor.namespace,
        subject="subject", holder="holder", generation=3, operation="read",
        operation_id="read-1", token="t" * 32, fence_epoch=7, revision=2,
        pinned_anchor=anchor,
    )
    return FenceScope(
        NAMESPACE, anchor.namespace, 3, "read", "read-1", permit, anchor,
        EPOCH, 11,
    )


def _instance(source_id: str):
    identity = D04BlockIdentity(
        "role", "object", "meaning", source_key("bot", "persona", source_id).token,
    )
    return D04BlockInstance(identity, "", "", "clock", None, ())


def _case():
    atoms = _source("child", parents=("parent",)) + _source("parent") + _source("other")
    read = D04SourceHeadRead(
        GraphSnapshot(atoms, (EPOCH,)), NAMESPACE, ("entity:alice",),
        "context", _fence(), True, True, True,
    )
    return (_instance("child"), _instance("other")), read


def test_heads_bind_entire_ancestry_and_keep_sources_independent():
    instances, read = _case()
    result = derive_d04_source_heads(instances, read)
    assert result.held == {}
    assert len(result.heads) == 2
    child_head = result.heads[instances[0].identity]
    assert child_head.usable
    assert child_head.graph_source_version.startswith("sha256:")
    assert child_head.access_version.startswith("sha256:")
    changed = list(read.snapshot.atoms)
    changed[3] = replace(changed[3], revision=2)
    revised = derive_d04_source_heads(
        instances, replace(read, snapshot=replace(read.snapshot, atoms=tuple(changed))),
    )
    assert revised.heads[instances[0].identity].access_version != child_head.access_version
    assert revised.heads[instances[1].identity] == result.heads[instances[1].identity]


def test_parent_access_revoke_holds_only_descendant():
    instances, read = _case()
    changed = list(read.snapshot.atoms)
    changed[3] = replace(changed[3], value={**changed[3].value, "status": "withdrawn"})
    result = derive_d04_source_heads(
        instances, replace(read, snapshot=replace(read.snapshot, atoms=tuple(changed))),
    )
    assert result.held == {instances[0].identity: "source_or_ancestor_access_denied"}
    assert result.heads[instances[1].identity].usable


def test_missing_ancestor_and_cross_namespace_source_hold():
    instances, read = _case()
    missing = replace(read, snapshot=replace(read.snapshot, atoms=read.snapshot.atoms[:2]))
    assert derive_d04_source_heads(instances[:1], missing).held[instances[0].identity] == (
        "source_or_ancestor_unknown"
    )
    foreign = replace(instances[0], identity=replace(
        instances[0].identity, source_ref=source_key("other-bot", "persona", "child").token,
    ))
    assert derive_d04_source_heads((foreign,), read).held[foreign.identity] == (
        "source_namespace_mismatch"
    )


def test_snapshot_without_current_fence_or_barrier_never_qualifies():
    instances, read = _case()
    cases = (
        replace(read, fence=None),
        replace(read, current_fence_confirmed=False),
        replace(read, current_barrier_confirmed=False),
        replace(read, complete=False),
        replace(read, snapshot=replace(read.snapshot, epochs=(NamespaceEpoch("bot", "persona", 8),))),
    )
    for case in cases:
        result = derive_d04_source_heads(instances, case)
        assert not result.heads
        assert set(result.held) == {instance.identity for instance in instances}
