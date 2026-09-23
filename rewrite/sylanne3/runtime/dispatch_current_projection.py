"""Read the D03/D05 graph projection from the same D11 commit transaction."""

from __future__ import annotations

from dataclasses import dataclass
import json

from ..graph_types import AtomKey, GraphAtom, GraphSnapshot
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest


@dataclass(frozen=True)
class CurrentDispatchProjectionV1:
    """Complete current D03/D05 rows; domain decisions remain with their owners."""

    namespace: NamespaceId
    graph_epoch: int
    role_bindings: tuple[GraphAtom, ...]
    boundary_rules: tuple[GraphAtom, ...]
    digest: str


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
    return CurrentDispatchProjectionV1(
        namespace, query.revision, roles, boundaries,
        canonical_digest({
            "namespace": namespace, "graph_epoch": query.revision,
            "role_bindings": roles, "boundary_rules": boundaries,
        }),
    )


__all__ = ["CurrentDispatchProjectionV1", "read_current_dispatch_projection"]
