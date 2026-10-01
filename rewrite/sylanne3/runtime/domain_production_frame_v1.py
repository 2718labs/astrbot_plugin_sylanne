"""Bounded materialization of an installed operation's actual W01 read plan."""
from dataclasses import replace
import json

from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, owner_grant_key
from ..memory_types import SourceRecord, source_key, access_key
from ..runtime_contracts import CommandEnvelope, FenceScope, NamespaceId, QueryEpoch, canonical_digest
from .domain_production_contracts_v1 import (
    CurrentOperationFrameV1, ProductionOperationLimitsV1, ProductionOwnerGuardV1,
    ProductionQueryCoverageV1, ProductionReadPlanV1,
)


def freeze_domain_production_frame_v1(graph, db, *, envelope, current_owner, scope,
        plan, now_utc, observed_originals=(), installed_policy_refs=(), limits=ProductionOperationLimitsV1()):
    """Read only; a frame carries no ability to commit or to perform execution."""
    from ..graph_coordinator import GraphCoordinator, OwnerLeaseBindingV1
    if (type(graph) is not GraphCoordinator or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or type(envelope) is not CommandEnvelope or type(current_owner) is not OwnerLeaseBindingV1
            or type(scope) is not FenceScope or type(plan) is not ProductionReadPlanV1
            or type(limits) is not ProductionOperationLimitsV1):
        raise ValueError("production frame needs the installed current W01 transaction")
    ns = envelope.authority.namespace
    metadata, epoch = graph._v2_graph_stamp(ns)
    if (scope.namespace != ns or current_owner.namespace != ns or scope.graph_epoch != epoch
            or scope.graph_revision != metadata.graph_revision or scope.generation != envelope.authority.activation_generation
            or not graph._anchor_matches(metadata.requirements, scope.pinned_anchor)
            or envelope.authority.activation_generation != metadata.requirements.activation_generation
            or current_owner.authorization_head == "genesis"
            or envelope.authority.actor != current_owner.actor
            or envelope.authority.purpose not in current_owner.purposes
            or not set(envelope.authority.audience).issubset(current_owner.audiences)):
        raise ValueError("production frame current namespace/Owner/fence or purpose/audience differs")
    atoms = {}
    def load(key):
        if type(key) is not AtomKey or NamespaceId.from_key(key) != ns:
            raise ValueError("production read plan crossed the actual namespace")
        if key in atoms:
            return atoms[key]
        if len(atoms) >= limits.max_graph_heads:
            raise ValueError("production read plan exceeds complete current head limit")
        graph._GraphCoordinator__store._registry.spec(key.type_name)
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (key.token, *ns.as_tuple)).fetchone()
        atom = GraphAtom(key, row[0], json.loads(row[1]), bool(row[2])) if row else GraphAtom(key, 0, {}, False)
        atoms[key] = atom
        return atom
    owner_key = owner_grant_key(*ns.as_tuple)
    owner = load(owner_key)
    if (not owner.valid or owner.revision != current_owner.grant_revision
            or canonical_digest(owner.value) != current_owner.grant_digest.removeprefix("sha256:")):
        raise ValueError("production actual Owner grant no longer matches its independently read head")
    pages = []
    query_epoch = QueryEpoch(ns, "namespace", epoch.revision)
    for type_id in plan.fixed_type_ids:
        graph._GraphCoordinator__store._registry.spec(type_id)
        rows = db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? "
            "ORDER BY token LIMIT ?", (*ns.as_tuple, type_id, limits.max_query_rows + 1)).fetchall()
        selected, complete = rows[:limits.max_query_rows], len(rows) <= limits.max_query_rows
        versions = tuple(GraphVersion(AtomKey.from_token(ref), revision) for ref, revision in selected)
        for version in versions:
            load(version.key)
        continuation = None if complete else "production-query:" + canonical_digest(
            (ns, type_id, epoch.revision, selected[-1][0]))[:48]
        pages.append(ProductionQueryCoverageV1(query_epoch, type_id, versions, complete, continuation))
    for key in plan.exact_keys:
        load(key)
    active, seen = set(), set()
    def source_closure(ref):
        key = AtomKey.from_token(ref)
        if key != source_key(*ns.as_tuple, key.owner.subject or ""):
            raise ValueError("production source locator is not canonical D06 identity")
        if ref in active:
            raise ValueError("production source family contains a cycle")
        if ref in seen:
            return
        active.add(ref)
        source = load(key)
        load(access_key(*ns.as_tuple, key.owner.subject))
        load(source_correction_head_key(ns, key.owner.subject))
        if source.valid and source.revision > 0:
            value = SourceRecord.from_dict(source.value)
            if value.source_id != key.owner.subject:
                raise ValueError("production source record and key identity differ")
            for parent in value.parent_source_ids:
                source_closure(source_key(*ns.as_tuple, parent).token)
        active.remove(ref)
        seen.add(ref)
    for ref in plan.source_roots:
        source_closure(ref)
    for original in observed_originals:
        for version in original.read_versions:
            if load(version.key).revision != version.revision:
                raise ValueError("production independently read original changed in the held transaction")
    rights = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
    if rights != (current_owner.access_epoch, current_owner.delete_epoch):
        raise ValueError("production current source rights differ from its Owner view")
    snapshot = GraphSnapshot(tuple(sorted(atoms.values(), key=lambda atom: atom.key.token)), (epoch,))
    inputs = tuple(sorted(set(plan.source_roots + plan.required_original_refs)))
    actual_envelope = replace(envelope,
        identity=replace(envelope.identity, canonical_input_digest=canonical_digest({"input_refs": list(inputs)})),
        input_refs=inputs, source_qualification=replace(envelope.source_qualification, source_refs=plan.source_roots),
        version_guard=replace(envelope.version_guard,
        read_versions=snapshot.versions, query_epochs=(query_epoch,), access_epoch=rights[0], delete_epoch=rights[1],
        catalogue_version=graph._GraphCoordinator__store._registry.catalogue_hash))
    owner_guard = ProductionOwnerGuardV1(owner_key.token, owner.revision, canonical_digest(owner.value),
        current_owner.authorization_head.removeprefix("sha256:"))
    return CurrentOperationFrameV1(actual_envelope, snapshot, now_utc, owner_guard,
        scope.generation, tuple(pages), tuple(installed_policy_refs), tuple(observed_originals), limits)
