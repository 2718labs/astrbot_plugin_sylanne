"""Transaction-local D03/D05 cross-scene read for the W01 Owner fence.

The returned frame is evidence for a later admission decision.  In particular,
there is no current group-membership authority in the alpha1 graph, so a
positive domain projection cannot authorize group expression yet.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import sqlite3

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...runtime.dispatch_source_correction_barrier import read_source_correction_barrier
from ...runtime_contracts import NamespaceId, QueryEpoch
from .cross_scene_social import CrossSceneSocialCandidateV1, project_cross_scene_social_v1


_TYPES = (
    "memory.source", "memory.access", "d06.source_correction_head.v1",
    "d03.world_event", "d03.entity_anchor", "d03.account_binding",
    "d03.role_binding", "d05.contribution",
)


@dataclass(frozen=True, slots=True)
class CurrentCrossSceneSocialFrameV1:
    status: str
    reasons: tuple[str, ...]
    candidate: CrossSceneSocialCandidateV1 | None
    query: QueryEpoch | None
    current_versions: tuple[GraphVersion, ...]
    negative_predicates: tuple[str, ...]


def read_current_cross_scene_social_v1(
    db, snapshot: GraphSnapshot, query: QueryEpoch, source_ref: str, *,
    namespace: NamespaceId, target_scene_ref: str, audience_scope: str,
    relationship_contribution_key: str, now_utc: float,
) -> CurrentCrossSceneSocialFrameV1:
    """Read every relevant current row within W01's already held transaction.

    W01 must supply its Owner-fenced, full namespace snapshot and must repeat
    this read before model egress and final send.  This function never accepts
    a standalone snapshot as proof of Authority or current group membership.
    """
    def hold(reason: str, candidate=None, versions=(), predicates=()):
        return CurrentCrossSceneSocialFrameV1(
            "hold", (reason,), candidate, query if versions else None,
            tuple(versions), tuple(predicates),
        )

    if (not getattr(db, "in_transaction", False)
            or type(snapshot) is not GraphSnapshot
            or type(query) is not QueryEpoch
            or type(namespace) is not NamespaceId
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        return hold("owner_fenced_current_transaction_required")
    if (len(snapshot.epochs) != 1
            or query != QueryEpoch(namespace, "all", snapshot.epochs[0].revision)
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple):
        return hold("full_namespace_query_required")
    try:
        epoch_row = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()
        if (epoch_row[0] if epoch_row else 0) != query.revision:
            return hold("graph_epoch_changed")
        # Compare complete sets, not merely the positive atoms selected by the
        # domain projection.  New arrivals, competing bindings and revocations
        # must invalidate the old frame, including after a process restart.
        rows = db.execute(
            "SELECT token,revision,value,valid,type_name FROM graph_atoms "
            "WHERE bot=? AND persona=? AND type_name IN ("
            + ",".join("?" for _ in _TYPES) + ") ORDER BY token",
            (*namespace.as_tuple, *_TYPES),
        ).fetchall()
        relevant = tuple(atom for atom in snapshot.atoms
                         if atom.key.type_name in _TYPES)
        by_token = {atom.key.token: atom for atom in relevant}
        if len(by_token) != len(relevant) or len(rows) != len(relevant):
            return hold("current_social_row_set_changed")
        versions = []
        for token, revision, encoded, valid, type_name in rows:
            atom = by_token.get(token)
            if (atom is None or atom.key != AtomKey.from_token(token)
                    or atom.key.type_name != type_name
                    or (atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple
                    or atom.revision != revision or atom.valid != bool(valid)
                    or atom.value != json.loads(encoded)):
                return hold("current_social_row_set_changed")
            versions.append(GraphVersion(atom.key, revision))
        predicates = tuple(f"{name}:complete_current_set" for name in _TYPES)
        candidate = project_cross_scene_social_v1(
            snapshot, query, source_ref, namespace=namespace,
            target_scene_ref=target_scene_ref, audience_scope=audience_scope,
            relationship_contribution_key=relationship_contribution_key,
            now_utc=now_utc,
        )
        if candidate.status != "expression_candidate":
            return hold(candidate.reasons[0], candidate, versions, predicates)
        refs = {source_ref}
        for version in candidate.read_versions:
            if version.key.type_name in {"d03.role_binding", "d05.contribution"}:
                atom = by_token.get(version.key.token)
                source_refs = atom.value.get("source_refs") if atom else None
                if type(source_refs) is not list or not source_refs:
                    return hold("social_ancestry_unavailable", candidate,
                                versions, predicates)
                refs.update(source_refs)
        for ref in sorted(refs):
            barrier = read_source_correction_barrier(
                db, namespace, query, (ref,), dependent_ref=source_ref)
            if not barrier.clear:
                return hold("source_correction_pending", candidate, versions,
                            predicates + ("source_correction_heads:all_referenced",))
        predicates += ("source_correction_heads:all_referenced",)
        # No graph type or trusted host read presently proves the current
        # members of a group destination.  A role binding names a scene; it
        # cannot establish who can receive that scene's next message.
        return hold("current_group_membership_unavailable", candidate,
                    versions, predicates + ("target_group_membership:required",))
    except (sqlite3.Error, TypeError, ValueError, KeyError, json.JSONDecodeError):
        return hold("current_social_sql_read_unavailable")


__all__ = ["CurrentCrossSceneSocialFrameV1", "read_current_cross_scene_social_v1"]
