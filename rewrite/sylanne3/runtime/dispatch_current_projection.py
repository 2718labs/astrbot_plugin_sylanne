"""Read the D03/D05 graph projection from the same D11 commit transaction."""

from __future__ import annotations

from dataclasses import dataclass
import json

from ..domains.d03.context import (
    ContextProvider, RoleBinding, RoleBindingRequest, RoleBindingResolution,
)
from ..domains.d05.relationship import BoundaryRule, BoundaryRuleReadSet, RelationshipProvider
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion
from ..runtime_contracts import NamespaceId, QueryEpoch, VersionedRef, canonical_digest
from .dispatch_source_correction_barrier import read_source_correction_barrier


@dataclass(frozen=True)
class CurrentDispatchProjectionV1:
    """Complete current D03/D05 rows; domain decisions remain with their owners."""

    namespace: NamespaceId
    graph_epoch: int
    role_bindings: tuple[GraphAtom, ...]
    boundary_rules: tuple[GraphAtom, ...]
    digest: str
    coverage: str = "full"
    missing_sources: tuple[str, ...] = ()


def read_current_dispatch_projection(
    db, namespace: NamespaceId, snapshot: GraphSnapshot, query: QueryEpoch,
) -> CurrentDispatchProjectionV1:
    """Reject a partial/stale read set while SQLite still holds the graph write lock."""
    if not db.in_transaction:
        raise ValueError("current dispatch projection requires the graph transaction")
    if (len(snapshot.epochs) != 1
            or query != QueryEpoch(namespace, "all", snapshot.epochs[0].revision)
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona)
            != namespace.as_tuple):
        raise ValueError("dispatch projection needs the full namespace query epoch")
    row = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if (row[0] if row else 0) != query.revision:
        raise ValueError("dispatch projection graph epoch changed")
    by_token = {atom.key.token: atom for atom in snapshot.atoms}
    if len(by_token) != len(snapshot.atoms):
        raise ValueError("dispatch projection read set repeats a graph key")
    typed: dict[str, list[GraphAtom]] = {
        "d03.role_binding": [], "d05.boundary_rule": [],
    }
    rows = db.execute(
        "SELECT token,revision,value,type_name FROM graph_atoms "
        "WHERE bot=? AND persona=? AND type_name IN "
        "('d03.role_binding','d05.boundary_rule') AND valid=1 ORDER BY token",
        namespace.as_tuple,
    ).fetchall()
    for token, revision, encoded, type_name in rows:
        atom = by_token.get(token)
        if (atom is None or not atom.valid or atom.revision != revision
                or atom.key != AtomKey.from_token(token)
                or atom.value != json.loads(encoded)):
            raise ValueError("dispatch projection omits or changed a current domain row")
        typed[type_name].append(atom)
    observed = {atom.key.token for group in typed.values() for atom in group}
    if any(atom.key.type_name in typed and atom.valid
           and atom.key.token not in observed for atom in snapshot.atoms):
        raise ValueError("dispatch projection snapshot has an unbacked domain row")
    roles = tuple(typed["d03.role_binding"])
    boundaries = tuple(typed["d05.boundary_rule"])
    missing = []
    for atom in boundaries:
        refs = atom.value.get("source_refs")
        if type(refs) is not list or not refs:
            missing.append(f"boundary_source_refs_unavailable:{atom.key.token}")
            continue
        barrier = read_source_correction_barrier(
            db, namespace, query, tuple(refs), dependent_ref=atom.key.token,
        )
        missing.extend(barrier.missing_sources)
    return CurrentDispatchProjectionV1(
        namespace, query.revision, roles, boundaries,
        canonical_digest({
            "namespace": namespace, "graph_epoch": query.revision,
            "role_bindings": roles, "boundary_rules": boundaries,
        }),
        "partial" if missing else "full", tuple(dict.fromkeys(missing)),
    )


def derive_current_domain_reads(
    db, projection: CurrentDispatchProjectionV1, request: RoleBindingRequest,
    context: ContextProvider,
) -> tuple[RoleBindingResolution, BoundaryRuleReadSet]:
    """Decode complete current D03/D05 rows; this is not dispatch admission."""
    if not db.in_transaction:
        raise ValueError("current domain reads require the graph transaction")
    namespace = projection.namespace
    if request.subject_persona_ref != f"persona:{namespace.persona_id}":
        raise ValueError("binding request differs from projected persona")
    if projection.digest != canonical_digest({
        "namespace": namespace, "graph_epoch": projection.graph_epoch,
        "role_bindings": projection.role_bindings,
        "boundary_rules": projection.boundary_rules,
    }):
        raise ValueError("current domain projection digest changed")
    row = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if (row[0] if row else 0) != projection.graph_epoch:
        raise ValueError("current domain projection epoch changed")
    projected = projection.role_bindings + projection.boundary_rules
    by_token = {atom.key.token: atom for atom in projected}
    if len(by_token) != len(projected):
        raise ValueError("current domain projection repeats a graph key")
    rows = db.execute(
        "SELECT token,revision,value,type_name FROM graph_atoms "
        "WHERE bot=? AND persona=? AND type_name IN "
        "('d03.role_binding','d05.boundary_rule') AND valid=1 ORDER BY token",
        namespace.as_tuple,
    ).fetchall()
    if len(rows) != len(projected):
        raise ValueError("current domain projection omits a current row")
    for token, revision, encoded, type_name in rows:
        atom = by_token.get(token)
        if (atom is None or not atom.valid or atom.key.type_name != type_name
                or (atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple
                or atom.revision != revision or atom.value != json.loads(encoded)):
            raise ValueError("current domain projection row changed")

    role_spec = next(spec for spec in context.type_specs()
                     if spec.name == "d03.role_binding")
    boundary_spec = next(spec for spec in RelationshipProvider().type_specs()
                         if spec.name == "d05.boundary_rule")
    bindings = []
    for atom in projection.role_bindings:
        if (atom.key.type_name != role_spec.name
                or atom.key.owner.kind not in role_spec.owner_kinds):
            raise ValueError("role binding graph type or owner changed")
        role_spec.validator(atom.value)
        binding = RoleBinding(**{
            **atom.value,
            "norm_refs": tuple(atom.value["norm_refs"]),
            "source_refs": tuple(atom.value["source_refs"]),
        })
        if (atom.key.name != binding.role_binding_id
                or atom.revision != binding.binding_version
                or binding.subject_persona_ref != f"persona:{namespace.persona_id}"
                or (atom.key.owner.kind == "scene"
                    and atom.key.owner.subject != binding.scene_ref)):
            raise ValueError("role binding graph identity or version changed")
        bindings.append(binding)
    if len({item.role_binding_id for item in bindings}) != len(bindings):
        raise ValueError("role binding identity repeats")
    resolved = context.resolve_role_binding(request, tuple(bindings))
    role_read = RoleBindingResolution(
        resolved.status, resolved.matched_bindings, resolved.applicable_norm_refs,
        resolved.missing_items,
        tuple(GraphVersion(atom.key, atom.revision) for atom in projection.role_bindings),
        QueryEpoch(namespace, "d03.role_binding", projection.graph_epoch),
        resolved.valid_until, request,
    )

    rules = []
    for atom in projection.boundary_rules:
        if (atom.key.type_name != boundary_spec.name
                or atom.key.owner.kind not in boundary_spec.owner_kinds):
            raise ValueError("boundary rule graph type or owner changed")
        boundary_spec.validator(atom.value)
        rule = BoundaryRule(**{
            **atom.value,
            **{name: tuple(atom.value[name]) for name in (
                "source_refs", "communicated_refs", "acknowledged_refs", "exception_refs",
            )},
        })
        if (atom.key.name != rule.rule_id or atom.revision != rule.scope_version
                or rule.subject_persona_ref != f"persona:{namespace.persona_id}"
                or atom.key.owner.subject != rule.target_entity_ref):
            raise ValueError("boundary rule graph identity or version changed")
        rules.append(rule)
    if len({item.rule_id for item in rules}) != len(rules):
        raise ValueError("boundary rule identity repeats")
    boundary_read = BoundaryRuleReadSet(
        namespace, QueryEpoch(namespace, "d05.boundary", projection.graph_epoch),
        tuple(rules),
        (VersionedRef("d05.boundary", projection.graph_epoch),)
        + tuple(VersionedRef(rule.rule_id, rule.scope_version) for rule in rules),
        projection.coverage, projection.missing_sources,
    )
    return role_read, boundary_read


__all__ = [
    "CurrentDispatchProjectionV1", "read_current_dispatch_projection",
    "derive_current_domain_reads",
]
