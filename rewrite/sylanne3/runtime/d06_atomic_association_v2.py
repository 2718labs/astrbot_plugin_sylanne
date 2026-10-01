"""D06 association traversal in W01's already fenced SQLite write transaction.

The caller holds GraphStore's lock and Authority fence and owns COMMIT/ROLLBACK.
This reader neither starts a transaction nor issues an experience. Its snapshot
and versions are inputs to W01's final guard and C04 association preflight.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3

from ..domains.d06 import SelectionTicket, source_correction_head_key
from ..domains.d06.current_association_candidates import (
    CurrentAssociationBudgetV1, CurrentAssociationCandidateV1,
    CurrentAssociationCandidatesV1,
)
from ..domains.d06.current_focus_binding import bind_current_c04_focus_v1
from ..domains.d06.current_recollection_bridge import CurrentC04SourceCandidateV1
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion
from ..memory_association import ActivationPolicy, AssociationActivator, AssociationEdge
from ..memory_types import SourceRecord, access_key, source_key, validate_access, validate_association
from ..runtime_contracts import NamespaceId


@dataclass(frozen=True, slots=True)
class AtomicAssociationReadV2:
    associations: CurrentAssociationCandidatesV1
    current_snapshot: GraphSnapshot
    status: str = "candidate_hold_w01_guard_and_c04_preflight"


def read_atomic_association_v2(
    db: sqlite3.Connection, candidate: CurrentC04SourceCandidateV1, *,
    ticket: SelectionTicket, focus_snapshot: GraphSnapshot,
    namespace: NamespaceId, now: float, audience: str, purpose: str,
    budget: CurrentAssociationBudgetV1,
    context_tags: tuple[str, ...] = (),
) -> AtomicAssociationReadV2:
    """Traverse and reauthorize a bounded neighborhood from one DB snapshot.

    W01 must use the returned snapshot and all association read versions in its
    envelope before calling ``preflight_current_c04_association_v1`` in this
    same transaction. A later transaction cannot adopt this candidate.
    """
    if not isinstance(db, sqlite3.Connection) or not db.in_transaction:
        raise ValueError("association read requires W01's active SQLite transaction")
    if (type(namespace) is not NamespaceId
            or type(candidate) is not CurrentC04SourceCandidateV1
            or type(focus_snapshot) is not GraphSnapshot
            or type(budget) is not CurrentAssociationBudgetV1
            or type(audience) is not str or not audience or audience == "*"
            or type(purpose) is not str or not purpose or purpose == "*"
            or type(context_tags) is not tuple or len(context_tags) > 8
            or any(type(tag) is not str or not tag for tag in context_tags)):
        raise ValueError("association scope or bounds are invalid")
    epoch = candidate.graph_epoch
    if (epoch.bot, epoch.persona) != namespace.as_tuple:
        raise ValueError("association cue crosses namespace")
    row = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                     namespace.as_tuple).fetchone()
    barriers = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if ((row[0] if row else 0) != epoch.revision
            or barriers != (candidate.access_epoch, candidate.deletion_epoch)):
        raise ValueError("association graph or access/delete barrier changed")

    atoms: dict[AtomKey, GraphAtom] = {}

    def read_key(key: AtomKey) -> GraphAtom:
        if (key.owner.bot, key.owner.persona) != namespace.as_tuple:
            raise ValueError("association read crosses namespace")
        if key not in atoms:
            if len(atoms) >= 4096:
                raise ValueError("association closure exceeds snapshot bound")
            current = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
                "AND bot=? AND persona=?", (key.token, *namespace.as_tuple),
            ).fetchone()
            atoms[key] = (GraphAtom(key, current[0], json.loads(current[1]), bool(current[2]))
                          if current else GraphAtom(key, 0, {}, False))
        return atoms[key]

    if focus_snapshot.epochs != (epoch,) or len(focus_snapshot.atoms) > 4096:
        raise ValueError("focus snapshot epoch or bound differs")
    if len({atom.key for atom in focus_snapshot.atoms}) != len(focus_snapshot.atoms):
        raise ValueError("focus snapshot repeats a key")
    for atom in focus_snapshot.atoms:
        if read_key(atom.key) != atom:
            raise ValueError("focus snapshot differs from current DB transaction")
    focused = bind_current_c04_focus_v1(
        candidate, ticket=ticket, focus_snapshot=focus_snapshot,
        namespace=namespace, now=now, audience=audience, purpose=purpose,
    )
    for version in focused.read_versions:
        if read_key(version.key).revision != version.revision:
            raise ValueError("C04 source revision differs from current DB transaction")

    authorized: dict[str, bool] = {}
    versions: dict[AtomKey, GraphVersion] = {v.key: v for v in focused.read_versions}

    def available(source_id: str) -> bool:
        if source_id in authorized:
            return authorized[source_id]
        pending = [source_id]
        seen: set[str] = set()
        local: dict[AtomKey, GraphVersion] = {}
        permitted = True
        while pending:
            item = pending.pop()
            if item in seen:
                continue
            seen.add(item)
            if len(seen) > 256:
                raise ValueError("association source ancestry exceeds bound")
            keys = (source_key(*namespace.as_tuple, item),
                    access_key(*namespace.as_tuple, item),
                    source_correction_head_key(namespace, item))
            source, access, head = (read_key(key) for key in keys)
            local.update((key, GraphVersion(key, atom.revision))
                         for key, atom in zip(keys, (source, access, head)))
            if (source.revision < 1 or not source.valid
                    or access.revision < 1 or not access.valid
                    or head.revision != 0 or head.valid):
                permitted = False
                continue
            record = SourceRecord.from_dict(source.value)
            validate_access(access.value)
            if record.source_id != item or access.value["source_id"] != item:
                raise ValueError("association source identity differs")
            if (access.value["status"] != "active"
                    or audience not in record.audiences
                    or audience not in access.value["audiences"]
                    or purpose not in record.purposes
                    or purpose not in access.value["purposes"]):
                permitted = False
            pending.extend(record.parent_source_ids)
        authorized[source_id] = permitted
        if permitted:
            for key, version in local.items():
                old = versions.get(key)
                if old is not None and old != version:
                    raise ValueError("association source versions conflict")
                versions[key] = version
        return permitted

    cue_key = AtomKey.from_token(focused.reconstruction.source_ref)
    if cue_key != source_key(*namespace.as_tuple, cue_key.owner.subject):
        raise ValueError("association cue is not a current D06 source")
    if not available(cue_key.owner.subject):
        raise PermissionError("association cue is unavailable")
    visited = {cue_key.owner.subject}
    frontier = (cue_key.owner.subject,)
    edges: list[AssociationEdge] = []
    edge_refs: list[str] = []
    partial = False
    for _ in range(budget.max_hops):
        next_frontier: list[str] = []
        for current in frontier:
            if len(edges) >= budget.max_edges:
                partial = True
                break
            rows = db.execute(
                "SELECT token,revision,value,valid FROM graph_atoms "
                "WHERE bot=? AND persona=? AND type_name='memory.association.v1' "
                "AND owner_kind='event' AND subject=? AND valid=1 "
                "ORDER BY token LIMIT ?",
                (*namespace.as_tuple, current,
                 min(32, budget.max_edges - len(edges)) + 1),
            ).fetchall()
            limit = min(32, budget.max_edges - len(edges))
            partial |= len(rows) > limit
            for token, revision, value_json, valid in rows[:limit]:
                key = AtomKey.from_token(token)
                atom = GraphAtom(key, revision, json.loads(value_json), bool(valid))
                if key not in atoms and len(atoms) >= 4096:
                    raise ValueError("association closure exceeds snapshot bound")
                if key in atoms and atoms[key] != atom:
                    raise ValueError("association edge differs from current DB transaction")
                atoms[key] = atom
                validate_association(atom.value)
                value = atom.value
                source = AtomKey.from_token(value["source_ref"])
                target = AtomKey.from_token(value["target_ref"])
                if (source != source_key(*namespace.as_tuple, current)
                        or key.owner.subject != current
                        or (target.owner.bot, target.owner.persona) != namespace.as_tuple):
                    raise ValueError("association edge owner or endpoint differs")
                fit = (1.0 if not value["context_tags"] else float(bool(
                    set(value["context_tags"]) & set(context_tags))))
                if not fit:
                    continue
                target_id = target.owner.subject
                if target_id not in visited and len(visited) >= budget.max_nodes:
                    partial = True
                    continue
                basis = tuple(AtomKey.from_token(ref)
                              for ref in value["basis_source_refs"])
                if not available(target_id) or any(
                    not available(item.owner.subject) for item in basis
                ):
                    continue
                edges.append(AssociationEdge(source.token, target.token,
                                             value["weight"], fit, key.token))
                edge_refs.append(key.token)
                versions[key] = GraphVersion(key, revision)
                if target_id not in visited:
                    visited.add(target_id)
                    next_frontier.append(target_id)
        frontier = tuple(next_frontier)
        if not frontier:
            break

    activation = AssociationActivator(ActivationPolicy(
        0.5, 0.25, budget.max_iterations, budget.max_nodes, 1e-6,
    )).propagate({cue_key.token: 1.0}, tuple(edges))
    allowed = {source_key(*namespace.as_tuple, item).token for item in visited
               if authorized.get(item, False)}
    salience = sum(focused.reconstruction.subjective_weight) / 2.0
    ranked = sorted(
        (CurrentAssociationCandidateV1(ref, value, value * salience)
         for ref, value in activation.activations
         if ref != cue_key.token and ref in allowed and value > 0),
        key=lambda item: (-item.mood_weighted_activation, item.source_ref),
    )
    selected = tuple(ranked[:budget.max_candidates])
    reason = ("hop_budget_exhausted" if budget.max_hops == 0 else
              "traversal_budget_or_page_limit" if partial else
              "candidate_limit" if len(ranked) > len(selected) else
              "no_eligible_association" if not selected else
              activation.stop_reason)
    associations = CurrentAssociationCandidatesV1(
        cue_key.token, selected, tuple(edge_refs),
        tuple(versions[key] for key in sorted(versions, key=lambda item: item.token)),
        epoch, len(activation.visited_refs), len(edge_refs),
        activation.iterations, reason,
    )
    return AtomicAssociationReadV2(
        associations,
        GraphSnapshot(tuple(atoms[key] for key in sorted(atoms,
                                                        key=lambda item: item.token)),
                      (epoch,), focus_snapshot.ingress_receipts,
                      focus_snapshot.scene_proofs),
    )


__all__ = ["AtomicAssociationReadV2", "read_atomic_association_v2"]
