"""Bounded original graph read set for an unexecuted C04 association work.

This is a W01 SQLite collector, not a D04 salience or D07 selection issuer.
The caller must hold the same current Owner/fence and write transaction used
to freeze the prepared operation.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3

from ..domains.d06 import source_correction_head_key
from ..domains.d06.c04_work_input_v2 import (
    AssociationQueryCoverageV2, FrozenGraphReadV2,
)
from ..domains.d06.current_association_candidates import CurrentAssociationBudgetV1
from ..graph_types import AtomKey, GraphAtom, NamespaceEpoch
from ..memory_types import SourceRecord, access_key, source_key
from ..runtime_contracts import NamespaceId


@dataclass(frozen=True, slots=True)
class C04AssociationGraphOriginalsV2:
    reads: tuple[FrozenGraphReadV2, ...]
    edge_queries: tuple[AssociationQueryCoverageV2, ...]
    graph_epoch: NamespaceEpoch
    truncated: bool


def collect_c04_association_graph_originals_v2(
    db: sqlite3.Connection, namespace: NamespaceId, *, cue_source_ref: str,
    focus_ref: str, attention_ticket_ref: str, mood_ref: str,
    budget: CurrentAssociationBudgetV1, context_tags: tuple[str, ...],
) -> C04AssociationGraphOriginalsV2:
    return _collect_c04_association_graph_originals_from_roots_v2(
        db, namespace, cue_source_ref=cue_source_ref, focus_ref=focus_ref,
        attention_ticket_ref=attention_ticket_ref, mood_ref=mood_ref, budget=budget,
        context_tags=context_tags, activation_roots=(cue_source_ref,))


def _collect_c04_association_graph_originals_from_roots_v2(
    db: sqlite3.Connection, namespace: NamespaceId, *, cue_source_ref: str,
    focus_ref: str, attention_ticket_ref: str, mood_ref: str,
    budget: CurrentAssociationBudgetV1, context_tags: tuple[str, ...], activation_roots: tuple[str, ...],
) -> C04AssociationGraphOriginalsV2:
    """Freeze raw graph atoms, negative heads, ancestry and edge query pages."""
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(namespace) is not NamespaceId
            or type(budget) is not CurrentAssociationBudgetV1):
        raise RuntimeError("current C04 graph transaction and bounded budget required")
    epoch_row = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if epoch_row is None:
        raise ValueError("C04 graph observation epoch is absent")
    observed: dict[AtomKey, FrozenGraphReadV2] = {}

    def read(key: AtomKey) -> FrozenGraphReadV2:
        if (key.owner.bot, key.owner.persona) != namespace.as_tuple:
            raise ValueError("C04 graph original crosses namespace")
        if key not in observed:
            if len(observed) >= 1024:
                raise ValueError("C04 graph original read bound exceeded")
            row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
                "AND bot=? AND persona=?", (key.token, *namespace.as_tuple),
            ).fetchone()
            observed[key] = (FrozenGraphReadV2.absent(key) if row is None else
                             FrozenGraphReadV2.from_atom(GraphAtom(
                                 key, row[0], json.loads(row[1]), bool(row[2]))))
        return observed[key]

    cue, focus, ticket, mood = (AtomKey.from_token(ref) for ref in (
        cue_source_ref, focus_ref, attention_ticket_ref, mood_ref))
    if (tuple(key.type_name for key in (cue, focus, ticket)) != (
            "memory.source", "d07.focus.v1", "d07.attention_ticket.v1")
            or mood.type_name not in {"d04.mood_field.v1", "d04.authored_mood_state.v1"}):
        raise ValueError("C04 graph anchor type differs")
    for key in (cue, focus, ticket, mood):
        row = read(key)
        if row.revision == 0 or not row.valid:
            raise ValueError("C04 graph anchor original is unavailable")
    ticket_value = observed[ticket].value
    from .c04_d04_state_codec_v3 import decode_c04_mood_v3
    mood_value = decode_c04_mood_v3(mood.token, observed[mood].value)
    source_refs = set((*activation_roots, *ticket_value["source_refs"],
                       *mood_value.source_refs))
    if any(type(ref) is not str for ref in source_refs):
        raise ValueError("C04 source ref differs")
    queries: list[AssociationQueryCoverageV2] = []
    frontier = set(activation_roots)
    edge_count = 0
    truncated = False
    for hop in range(budget.max_hops):
        following: set[str] = set()
        for ref in sorted(frontier):
            if len(queries) >= budget.max_nodes or edge_count >= budget.max_edges:
                truncated = True
                break
            source = AtomKey.from_token(ref)
            if source != source_key(*namespace.as_tuple, source.owner.subject):
                raise ValueError("C04 association query owner differs")
            remaining = budget.max_edges - edge_count
            rows = db.execute(
                "SELECT token,revision,value,valid FROM graph_atoms "
                "WHERE bot=? AND persona=? AND owner_kind='event' "
                "AND subject=? AND type_name='memory.association.v1' "
                "ORDER BY token LIMIT ?",
                (*namespace.as_tuple, source.owner.subject, remaining + 1),
            ).fetchall()
            chosen = rows[:remaining]
            edge_refs = []
            for token, revision, value, valid in chosen:
                edge_key = AtomKey.from_token(token)
                edge = FrozenGraphReadV2.from_atom(
                    GraphAtom(edge_key, revision, json.loads(value), bool(valid)))
                observed[edge_key] = edge
                edge_refs.append(token)
                edge_value = edge.value
                source_refs.update((edge_value["source_ref"],
                                    edge_value["target_ref"],
                                    *edge_value["basis_source_refs"]))
                if (not edge_value["context_tags"]
                        or set(edge_value["context_tags"]) & set(context_tags)):
                    following.add(edge_value["target_ref"])
            edge_count += len(chosen)
            next_after = edge_refs[-1] if len(rows) > remaining else None
            queries.append(AssociationQueryCoverageV2(
                ref, hop, tuple(edge_refs), next_after))
            if next_after is not None:
                truncated = True
                break
        if truncated:
            break
        frontier = following
        if not frontier:
            break
    pending = list(source_refs)
    seen: set[str] = set()
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        if len(seen) >= budget.max_nodes:
            raise ValueError("C04 source ancestor read bound exceeded")
        seen.add(ref)
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject):
            raise ValueError("C04 source original ref differs")
        source_row = read(key)
        read(access_key(*namespace.as_tuple, key.owner.subject))
        read(source_correction_head_key(namespace, key.owner.subject))
        if source_row.revision == 0 or not source_row.valid:
            raise ValueError("C04 source original is unavailable")
        record = SourceRecord.from_dict(source_row.value)
        pending.extend(source_key(*namespace.as_tuple, parent).token
                       for parent in record.parent_source_ids)
    return C04AssociationGraphOriginalsV2(
        tuple(observed[key] for key in sorted(observed, key=lambda item: item.token)),
        tuple(queries), NamespaceEpoch(*namespace.as_tuple, epoch_row[0]),
        truncated,
    )


__all__ = ["C04AssociationGraphOriginalsV2",
           "collect_c04_association_graph_originals_v2"]
