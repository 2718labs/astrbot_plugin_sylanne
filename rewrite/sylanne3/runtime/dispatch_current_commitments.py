"""Transaction-verified D08 graph facts for a future commitment conflict check."""

from __future__ import annotations

from dataclasses import dataclass
import json

from ..domains.d08.execution import ActionIntent, ActionOutcome, Commitment, GoalExecutionProvider
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion
from ..runtime_contracts import NamespaceId, QueryEpoch


_TYPES = (
    "d08.commitment.v1", "d08.action_intent.v1", "d08.action_outcome.v1",
)


@dataclass(frozen=True)
class CurrentD08ConflictFactsV1:
    """Verified graph inventory; external execution/cancellation coverage stays HOLD."""

    namespace: NamespaceId
    query_epoch: QueryEpoch
    commitments: tuple[Commitment, ...]
    action_intents: tuple[ActionIntent, ...]
    action_outcomes: tuple[ActionOutcome, ...]
    graph_versions: tuple[GraphVersion, ...]
    status: str = "hold"
    missing_sources: tuple[str, ...] = (
        "atomic_execution_effect_read", "current_action_cancellation_read",
    )


def read_current_d08_conflict_facts(
    db, namespace: NamespaceId, snapshot: GraphSnapshot, query: QueryEpoch,
) -> CurrentD08ConflictFactsV1:
    """Verify every current D08 conflict graph row in the graph write transaction.

    Graph rows alone cannot establish the D08 conflict check's execution and
    cancellation epochs, so this function never produces a passing snapshot.
    """
    if not db.in_transaction:
        raise ValueError("D08 conflict read requires the graph transaction")
    if (len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or query != QueryEpoch(namespace, "all", snapshot.epochs[0].revision)):
        raise ValueError("D08 conflict read requires the full namespace query epoch")
    row = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if (row[0] if row else 0) != query.revision:
        raise ValueError("D08 conflict graph epoch changed")

    atoms = tuple(atom for atom in snapshot.atoms
                  if atom.valid and atom.key.type_name in _TYPES)
    by_token = {atom.key.token: atom for atom in atoms}
    if len(by_token) != len(atoms):
        raise ValueError("D08 conflict snapshot repeats a graph key")
    rows = db.execute(
        "SELECT token,revision,value,type_name FROM graph_atoms "
        "WHERE bot=? AND persona=? AND type_name IN "
        "('d08.commitment.v1','d08.action_intent.v1','d08.action_outcome.v1') "
        "AND valid=1 ORDER BY token",
        namespace.as_tuple,
    ).fetchall()
    if len(rows) != len(atoms):
        raise ValueError("D08 conflict snapshot omits or invents a current row")

    specs = {spec.name: spec for spec in GoalExecutionProvider().register_types()}
    commitments = []
    intents = []
    outcomes = []
    for token, revision, encoded, type_name in rows:
        atom = by_token.get(token)
        if (atom is None or atom.key != AtomKey.from_token(token)
                or atom.key.type_name != type_name or atom.revision != revision
                or atom.value != json.loads(encoded)):
            raise ValueError("D08 conflict graph row changed")
        owner = atom.key.owner
        spec = specs[type_name]
        if ((owner.bot, owner.persona) != namespace.as_tuple
                or owner.kind not in spec.owner_kinds):
            raise ValueError("D08 conflict graph owner changed")
        decoded = spec.validator(atom.value)
        if type_name == "d08.commitment.v1":
            if (atom.key.name != decoded.commitment_id
                    or atom.revision != decoded.revision
                    or decoded.subject_ref != f"persona:{namespace.persona_id}"):
                raise ValueError("D08 commitment identity or revision changed")
            commitments.append(decoded)
        elif type_name == "d08.action_intent.v1":
            if (atom.key.name != decoded.action_id or atom.revision != decoded.revision
                    or owner.subject != decoded.identity.activity_id):
                raise ValueError("D08 action identity or revision changed")
            intents.append(decoded)
        else:
            if atom.key.name != decoded.outcome_id:
                raise ValueError("D08 outcome identity changed")
            outcomes.append(decoded)
    for values, field in ((commitments, "commitment_id"),
                          (intents, "action_id"), (outcomes, "outcome_id")):
        if len({getattr(value, field) for value in values}) != len(values):
            raise ValueError(f"D08 {field} repeats across graph owners")
    return CurrentD08ConflictFactsV1(
        namespace, QueryEpoch(namespace, "d08.conflict_graph", query.revision),
        tuple(commitments), tuple(intents), tuple(outcomes),
        tuple(GraphVersion(by_token[token].key, revision)
              for token, revision, _, _ in rows),
    )


__all__ = ["CurrentD08ConflictFactsV1", "read_current_d08_conflict_facts"]
