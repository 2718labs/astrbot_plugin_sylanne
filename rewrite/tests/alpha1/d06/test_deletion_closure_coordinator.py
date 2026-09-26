"""Production D06 deletion closure reads through the W01 coordinator port."""

from dataclasses import replace

import pytest

from sylanne3.contracts import Event, Scope, canonical_json
from sylanne3.domains.d06 import D06DomainProvider, ErasureRequest
from sylanne3.domains.d06.deletion_read import (
    read_deletion_closure_candidate_from_coordinator,
)
from sylanne3.graph_coordinator import AuthorityDenied, GraphCoordinator
from sylanne3.graph_store import GraphStore, ProductionGraphStore
from sylanne3.graph_types import (
    AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry,
)
from sylanne3.runtime.c02_bundle_codec import c02_bundle_to_wire
from sylanne3.memory_types import SourceRecord, source_key
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    NamespaceId, QueryEpoch, SnapshotRequirementsV2, canonical_digest,
)

from rewrite.tests.alpha1.runtime.test_graph_coordinator_v2_read import (
    ControlledFencePort, Provider, install,
)
from rewrite.tests.alpha1.contracts.test_c02_bundle_codec import _bundle


NAMESPACE = NamespaceId("bot", "persona")


@pytest.fixture
def deletion_runtime(tmp_path):
    registry = TypeRegistry()
    for spec in D06DomainProvider.type_specs():
        registry.register(spec)
    store = ProductionGraphStore(tmp_path / "memory.db", registry)
    anchor = RestoreAnchor(
        "authority", "opaque-namespace", 1, "deletion", 0, "genesis",
        "execution", 0, "genesis", 0, "authority-proof",
    )
    target = SnapshotRequirementsV2(
        NAMESPACE, anchor.authority_id, anchor.namespace, anchor.activation_generation,
        anchor.deletion_journal_id, anchor.deletion_seq, anchor.deletion_digest,
        anchor.execution_journal_id, anchor.execution_seq, anchor.execution_digest,
        anchor.revocation_epoch, "graph-incarnation",
    )
    port = ControlledFencePort(store, anchor)
    bootstrap = object()
    coordinator = GraphCoordinator(
        store, bootstrap, holder="holder", content_fence_v2=port,
    )
    coordinator.register_provider(bootstrap, "d06", Provider(), "d06-schema", "a" * 64)
    install(store, target)
    with store._lock:
        store._db.execute(
            "INSERT INTO graph_authority_epochs(bot,persona,access_epoch,delete_epoch) "
            "VALUES('bot','persona',1,0)"
        )
    authority, lease = coordinator.grant_deletion_read(
        bootstrap, actor="d06-service", namespace=NAMESPACE,
        activation_generation=1,
    )

    def commit(event_id, writes):
        keys = tuple(dict.fromkeys(
            key for write in writes for key in (write.key, *write.dependencies)
        ))
        snapshot = GraphStore.graph_snapshot(
            store, keys, _capability=store._coordinator_capability,
        )
        return GraphStore.graph_commit(
            store,
            GraphCandidate(
                Event(Scope("bot", "persona", "session"), event_id,
                      float(len(event_id)), "test", {}),
                snapshot.versions, tuple(writes), snapshot.epochs,
            ),
            _capability=store._coordinator_capability,
        )

    def allow_current_graph_epoch():
        def validate(scope):
            assert not store._lock._is_owned()
            assert scope.permit is port.active and scope.pinned_anchor == port.anchor
            assert scope.namespace == NAMESPACE
            current = GraphStore.graph_epoch(
                store, "bot", "persona", _capability=store._coordinator_capability,
            )
            assert scope.graph_epoch.revision == current.revision
            port.validations += 1
            if port.on_validate is not None:
                port.on_validate(port.validations)
            return port.active
        port.validate_fence = validate

    yield store, coordinator, bootstrap, port, authority, lease, commit, allow_current_graph_epoch
    store.close()


def _source(source_id, parents=()):
    return SourceRecord(
        source_id, source_id, "speaker", "reported", "reported", None, 1.0,
        "family", ("owner",), ("context",), parents,
    )


def _pending_c02(store, source, operation_id, *, evidence_source=None,
                 episode_source=None, wire=None):
    bundle = _bundle()
    event = AtomKey(Owner("event", "bot", "persona", "event"),
                    "d03.world_event", "current")
    baseline = AtomKey(Owner("event", "bot", "persona", "baseline"),
                       "d04.encoding_baseline.v1", "current")
    inputs = (source.token, event.token, baseline.token)
    episode = AtomKey(Owner("event", "bot", "persona", operation_id),
                      "memory.episode.v1", "current")
    trace = AtomKey(Owner("event", "bot", "persona", operation_id),
                    "memory.subjective_trace.v2", "current")
    envelope = replace(
        bundle.envelope,
        identity=replace(bundle.envelope.identity, operation_id=operation_id,
                         canonical_input_digest=canonical_digest(
                             {"input_refs": list(inputs)})),
        authority=replace(bundle.envelope.authority, namespace=NAMESPACE),
        version_guard=replace(
            bundle.envelope.version_guard,
            read_versions=(GraphVersion(source, 1),),
            query_epochs=(QueryEpoch(NAMESPACE, "all", 1),),
        ),
        source_qualification=replace(
            bundle.envelope.source_qualification, source_refs=(source.token,)),
        input_refs=inputs,
    )
    bundle = replace(
        bundle, envelope=envelope,
        proposals=tuple(replace(
            proposal, envelope=envelope,
            dependencies=replace(
                proposal.dependencies,
                current_invalidation=(GraphVersion(source, 1),)
                if proposal.domain == "d06" else (),
            ),
            typed_writes=(
                GraphWrite(episode, {"episode_id": operation_id,
                                     "source_refs": [episode_source or source.token],
                                     "event_ref": event.token}),
                GraphWrite(trace, {"trace_id": operation_id,
                                   "episode_ref": episode.token}),
            ) if proposal.domain == "d06" else tuple(replace(
                write,
                key=AtomKey(Owner(write.key.owner.kind, "bot", "persona",
                                  write.key.owner.subject),
                            write.key.type_name, write.key.name),
            ) for write in proposal.typed_writes),
        ) for proposal in bundle.proposals),
    )
    digest = bundle.digest
    attempt = "attempt-" + operation_id
    with store._lock:
        store._db.execute(
            "INSERT INTO graph_bundle_intents_v2"
            "(bot,persona,operation_id,digest,fence_attempt_id,"
            "requirements_json,anchor_json,graph_revision,graph_epoch) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            NAMESPACE.as_tuple + (operation_id, digest, attempt, "{}", "{}", 0, 0),
        )
        store._db.execute(
            "INSERT INTO graph_first_ingress_c02_candidates_v1"
            "(bot,persona,operation_id,schema,bundle_digest,fence_attempt_id,"
            "bundle_json,evidence_json) VALUES(?,?,?,?,?,?,?,?)",
            NAMESPACE.as_tuple + (
                operation_id, "sylanne.first-ingress-c02-candidate.v1",
                digest, attempt, wire if wire is not None else c02_bundle_to_wire(bundle),
                canonical_json({"source_ref": evidence_source if evidence_source is not None
                                else source.owner.subject}),
            ),
        )


def test_coordinator_candidate_includes_current_and_historical_d06_dependencies(deletion_runtime):
    store, coordinator, _, port, authority, lease, commit, allow_epoch = deletion_runtime
    root = source_key("bot", "persona", "root")
    child = source_key("bot", "persona", "child")
    other = source_key("bot", "persona", "other")
    interpretation = AtomKey(Owner("event", "bot", "persona", "interp"),
                             "memory.interpretation", "current")
    episode = AtomKey(Owner("event", "bot", "persona", "episode"),
                      "memory.episode.v1", "current")
    commit("root", (GraphWrite(root, _source("root").to_dict()),))
    commit("child", (GraphWrite(child, _source("child", ("root",)).to_dict()),))
    commit("other", (GraphWrite(other, _source("other").to_dict()),))
    commit("interpretation-1", (GraphWrite(
        interpretation, {
            "interpretation_id": "interp", "source_ids": ["root"],
            "subject_id": "self", "claim": "old", "status": "confirmed",
            "valid_from": 1.0, "recorded_at": 1.0, "valid_to": None,
    }, (root,)),))
    commit("interpretation-2", (GraphWrite(
        interpretation, {
            "interpretation_id": "interp", "source_ids": ["other"],
            "subject_id": "self", "claim": "revised", "status": "confirmed",
            "valid_from": 1.0, "recorded_at": 2.0, "valid_to": None,
        }, (root,)),))
    commit("episode", (GraphWrite(
        episode, {"episode_id": "episode", "source_refs": [child.token],
                  "event_ref": AtomKey(Owner("event", "bot", "persona", "event"),
                                       "d03.world_event", "current").token}),))
    allow_epoch()

    result = read_deletion_closure_candidate_from_coordinator(
        coordinator, authority, lease,
        ErasureRequest("erase", (root.token,), "all_derived", 1, 0),
        page_limit=2, max_pages=16,
    )
    assert result.status == "hold" and result.scan_complete
    assert result.source_descendant_refs == (child.token,)
    assert interpretation.token in result.current_dependency_refs
    assert interpretation.token in result.interpretation_refs
    assert GraphVersion(interpretation, 1) in result.historical_read_versions
    assert result.storage_path_status == "graph_atoms_and_pending_c02_candidates"
    assert "memory_retriever_direct_graph_atom_path" in result.covered_facets
    assert "source_derived_cache_inventory_unavailable" in result.missing_facets
    assert "retrieval_index_inventory_unavailable" in result.missing_facets
    assert "process_local_cache_inventory_unavailable" in result.missing_facets
    assert "independent_deletion_intent" in result.missing_facets
    assert "request_authorization" in result.missing_facets
    assert not hasattr(result, "deletion_permit")
    assert not any(spec.storage_role in {"cache", "projection"}
                   for spec in D06DomainProvider.type_specs())

    limited = read_deletion_closure_candidate_from_coordinator(
        coordinator, authority, lease,
        ErasureRequest("erase-limited", (root.token,), "all_derived", 1, 0),
        page_limit=1, max_pages=1,
    )
    assert limited.status == "partial_hold"
    assert not limited.scan_complete


def test_coordinator_candidate_rejects_generic_and_released_leases(deletion_runtime):
    _, coordinator, bootstrap, _, authority, lease, _, _ = deletion_runtime
    key = source_key("bot", "persona", "missing")
    request = ErasureRequest("erase", (key.token,), "all_derived", 1, 0)
    with pytest.raises(AuthorityDenied, match="deletion read lease"):
        read_deletion_closure_candidate_from_coordinator(
            coordinator, replace(authority, purpose="remember"), lease, request,
        )
    coordinator.release_deletion_read_lease(bootstrap, lease)
    with pytest.raises(AuthorityDenied, match="deletion read lease"):
        read_deletion_closure_candidate_from_coordinator(
            coordinator, authority, lease, request,
        )


def test_coordinator_candidate_holds_when_graph_changes_between_pages(deletion_runtime):
    store, coordinator, _, port, authority, lease, commit, allow_epoch = deletion_runtime
    root = source_key("bot", "persona", "root")
    commit("root", (GraphWrite(root, _source("root").to_dict()),))
    for index in range(3):
        key = source_key("bot", "persona", f"child-{index}")
        commit(f"child-{index}", (GraphWrite(key, _source(f"child-{index}", ("root",)).to_dict()),))
    allow_epoch()
    original_validate = port.validate_fence
    validations = 0
    changed = False

    def drift_after_first_fenced_read(scope):
        nonlocal validations, changed
        result = original_validate(scope)
        validations += 1
        # Three validations complete the first deletion snapshot. The next
        # fenced query validates before returning its first current-value page.
        if validations == 4 and not changed:
            changed = True
            added = source_key("bot", "persona", "late-child")
            commit("late-child", (GraphWrite(added, _source("late-child", ("root",)).to_dict()),))
        return result

    port.validate_fence = drift_after_first_fenced_read
    result = read_deletion_closure_candidate_from_coordinator(
        coordinator, authority, lease,
        ErasureRequest("erase", (root.token,), "all_derived", 1, 0),
        page_limit=1, max_pages=16,
    )
    assert changed, result
    assert result.status == "partial_hold"
    assert "current_snapshot_drift" in result.missing_facets


def test_pending_c02_inventory_matches_root_and_descendant_only(deletion_runtime):
    store, coordinator, _, _, authority, lease, commit, allow_epoch = deletion_runtime
    root = source_key("bot", "persona", "root")
    child = source_key("bot", "persona", "child")
    other = source_key("bot", "persona", "other")
    for key, parents in ((root, ()), (child, ("root",)), (other, ())):
        commit(key.owner.subject, (GraphWrite(key, _source(key.owner.subject, parents).to_dict()),))
    _pending_c02(store, root, "c02-root")
    _pending_c02(store, child, "c02-child")
    _pending_c02(store, other, "c02-other")
    allow_epoch()

    result = read_deletion_closure_candidate_from_coordinator(
        coordinator, authority, lease,
        ErasureRequest("erase", (root.token,), "all_derived", 1, 0),
    )
    assert result.status == "hold" and result.scan_complete
    assert result.pending_c02_sources == (("c02-child", child.token),
                                          ("c02-root", root.token))
    assert "pending_first_ingress_c02_inventory" in result.covered_facets
    assert "source_derived_cache_inventory_unavailable" in result.missing_facets


@pytest.mark.parametrize("damage", ["bad_wire", "wrong_source", "wrong_episode_source"])
def test_pending_c02_unreadable_source_holds_entire_inventory(deletion_runtime, damage):
    store, coordinator, _, _, authority, lease, commit, allow_epoch = deletion_runtime
    root = source_key("bot", "persona", "root")
    commit("root", (GraphWrite(root, _source("root").to_dict()),))
    _pending_c02(store, root, "c02-root",
                 wire="{}" if damage == "bad_wire" else None,
                 evidence_source="other" if damage == "wrong_source" else None,
                 episode_source=source_key("bot", "persona", "other").token
                 if damage == "wrong_episode_source" else None)
    allow_epoch()
    result = read_deletion_closure_candidate_from_coordinator(
        coordinator, authority, lease,
        ErasureRequest("erase", (root.token,), "all_derived", 1, 0),
    )
    assert result.status == "partial_hold"
    assert "deletion_snapshot_unavailable" in result.missing_facets
    assert result.pending_c02_sources == ()


def test_pending_c02_inventory_bound_holds(deletion_runtime):
    store, coordinator, _, _, authority, lease, commit, allow_epoch = deletion_runtime
    root = source_key("bot", "persona", "root")
    commit("root", (GraphWrite(root, _source("root").to_dict()),))
    _pending_c02(store, root, "c02-a")
    _pending_c02(store, root, "c02-b")
    allow_epoch()
    result = read_deletion_closure_candidate_from_coordinator(
        coordinator, authority, lease,
        ErasureRequest("erase", (root.token,), "all_derived", 1, 0),
        page_limit=1, max_pages=1,
    )
    assert result.status == "partial_hold"
    assert "deletion_snapshot_unavailable" in result.missing_facets


def test_pending_c02_change_during_fenced_read_holds(deletion_runtime):
    store, coordinator, _, port, authority, lease, commit, allow_epoch = deletion_runtime
    root = source_key("bot", "persona", "root")
    commit("root", (GraphWrite(root, _source("root").to_dict()),))
    allow_epoch()

    def insert_after_read(validation):
        if validation == 2:
            _pending_c02(store, root, "c02-late")

    port.on_validate = insert_after_read
    result = read_deletion_closure_candidate_from_coordinator(
        coordinator, authority, lease,
        ErasureRequest("erase", (root.token,), "all_derived", 1, 0),
    )
    assert result.status == "partial_hold"
    assert "deletion_snapshot_unavailable" in result.missing_facets
