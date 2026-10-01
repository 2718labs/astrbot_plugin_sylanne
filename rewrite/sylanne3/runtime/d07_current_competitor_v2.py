"""Read the current primary attention ticket and its private source closure.

The caller holds a graph transaction and an Authority read or write fence.
This reader supplies evidence for a new attention choice; it never selects or
commits a focus on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math

from ..domains.d06 import source_correction_head_key
from ..domains.d07 import AttentionTicket, D07DomainProvider, attention_ticket_key
from ..graph_types import AtomKey, GraphAtom, GraphVersion
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..runtime_contracts import NamespaceId, canonical_digest
from ..host.post_c02_attention_driver import post_c02_attention_operation_id


@dataclass(frozen=True)
class D07CurrentCompetingTicketV2:
    ticket: AttentionTicket
    ticket_version: GraphVersion
    c02_operation_id: str
    audience: str
    atoms: tuple[GraphAtom, ...]

    @property
    def read_versions(self) -> tuple[GraphVersion, ...]:
        return tuple(GraphVersion(atom.key, atom.revision) for atom in self.atoms)


def read_current_d07_source_closure_in_transaction(
    db, namespace: NamespaceId, roots: tuple[str, ...], *, audience: str,
) -> tuple[GraphAtom, ...]:
    """Read expression-qualified roots, ancestors and absent correction heads."""
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or not roots or type(roots) is not tuple or len(roots) > 256
            or type(audience) is not str or not audience):
        raise ValueError("current D07 source closure requires a graph transaction")
    atoms: dict[AtomKey, GraphAtom] = {}
    active: set[str] = set()
    settled: set[str] = set()

    def load(atom_key: AtomKey) -> GraphAtom:
        if atom_key not in atoms:
            current = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (atom_key.token,),
            ).fetchone()
            atoms[atom_key] = (
                GraphAtom(atom_key, current[0], json.loads(current[1]), bool(current[2]))
                if current is not None else GraphAtom(atom_key, 0, {}, False)
            )
        return atoms[atom_key]

    def visit(ref: str) -> None:
        if ref in active or len(settled) >= 256:
            raise ValueError("D07 source closure is cyclic or unbounded")
        if ref in settled:
            return
        active.add(ref)
        source_id = AtomKey.from_token(ref).owner.subject
        source_atom_key = source_key(*namespace.as_tuple, source_id or "")
        if source_atom_key.token != ref:
            raise ValueError("D07 source key differs")
        source = load(source_atom_key)
        access = load(access_key(*namespace.as_tuple, source_id))
        correction = load(source_correction_head_key(namespace, source_id))
        if (not source.valid or source.revision < 1
                or not access.valid or access.revision < 1
                or correction.revision != 0 or correction.valid):
            raise ValueError("D07 source is unavailable")
        record = SourceRecord.from_dict(source.value)
        validate_access(access.value)
        if (record.source_id != source_id
                or record.assertion_status not in {"confirmed", "reported"}
                or audience not in record.audiences
                or "expression" not in record.purposes
                or access.value["source_id"] != source_id
                or access.value["status"] != "active"
                or audience not in access.value["audiences"]
                or "expression" not in access.value["purposes"]):
            raise ValueError("D07 source is not qualified")
        for parent in record.parent_source_ids:
            visit(source_key(*namespace.as_tuple, parent).token)
        active.remove(ref)
        settled.add(ref)

    for root in roots:
        visit(root)
    return tuple(atoms[key] for key in sorted(atoms, key=lambda item: item.token))


def read_current_primary_competitor_in_transaction(
    db, namespace: NamespaceId, primary_ticket_ref: str | None, *,
    now_utc: float,
) -> D07CurrentCompetingTicketV2 | None:
    """Return the original primary even if it has expired.

    An inaccessible or corrected source is not silently removed from the
    competition. The caller must HOLD until a separate authorized focus
    transition resolves it.
    """
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(now_utc) not in (float, int) or not math.isfinite(now_utc)):
        raise ValueError("current D07 competitor requires a graph transaction")
    if primary_ticket_ref is None:
        return None
    key = AtomKey.from_token(primary_ticket_ref)
    if key != attention_ticket_key(namespace, key.name):
        raise ValueError("primary attention ticket namespace differs")
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (key.token,),
    ).fetchone()
    if row is None or row[2] != 1 or row[0] < 1:
        raise ValueError("current primary attention ticket is absent")
    value = json.loads(row[1])
    spec = next(spec for spec in D07DomainProvider.type_specs()
                if spec.name == "d07.attention_ticket.v1")
    spec.validator(value)
    ticket = AttentionTicket(**{
        **{name: item for name, item in value.items() if name != "schema"},
        "cancel_refs": tuple(value["cancel_refs"]),
        "source_refs": tuple(value["source_refs"]),
    })
    if (ticket.ticket_id != key.name or len(ticket.source_refs) != 1
            or ticket.causal_root != ticket.source_refs[0]):
        raise ValueError("primary attention ticket original source differs")
    root_key = AtomKey.from_token(ticket.causal_root)
    if root_key != source_key(*namespace.as_tuple, root_key.owner.subject or ""):
        raise ValueError("primary attention source namespace differs")
    ingress = db.execute(
        "SELECT conversation_ref,visibility "
        "FROM graph_first_ingress_identity_v1 WHERE bot=? AND persona=? "
        "AND source_ref=?",
        namespace.as_tuple + (root_key.owner.subject,),
    ).fetchall()
    if len(ingress) != 1 or ingress[0][1] != "private":
        raise ValueError("primary attention original audience is unavailable")
    audience = ingress[0][0]
    issuance = db.execute(
        "SELECT operation_id,c02_operation_id FROM "
        "graph_d07_attention_issuance_v1 WHERE bot=? AND persona=? "
        "AND source_ref=?",
        namespace.as_tuple + (ticket.causal_root,),
    ).fetchall()
    originals = [
        (operation_id, c02_operation_id)
        for operation_id, c02_operation_id in issuance
        if (operation_id == post_c02_attention_operation_id(
                c02_operation_id, ticket.causal_root)
            and ticket.ticket_id == "attention:" + canonical_digest({
                "operation_id": operation_id,
            })[:48])
    ]
    if len(originals) != 1:
        raise ValueError("primary attention original issuance differs")
    _, c02_operation_id = originals[0]

    closure = read_current_d07_source_closure_in_transaction(
        db, namespace, ticket.source_refs, audience=audience)
    return D07CurrentCompetingTicketV2(
        ticket, GraphVersion(key, row[0]), c02_operation_id, audience,
        (GraphAtom(key, row[0], value, True),) + closure,
    )


__all__ = [
    "D07CurrentCompetingTicketV2", "read_current_primary_competitor_in_transaction",
    "read_current_d07_source_closure_in_transaction",
]
