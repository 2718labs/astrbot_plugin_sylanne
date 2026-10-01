"""Current Owner structural evidence, independent of message expression scope."""
import json

from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion
from ..memory_types import SourceRecord, access_key, source_key, validate_access


def read_current_structural_source_closure_v1(
    db, snapshot: GraphSnapshot, namespace,
    source_refs: tuple[str, ...],
) -> tuple[tuple[GraphVersion, ...], tuple[str, ...]]:
    """Read D03/D05 support sources without adding them to D09 speech scope.

    Owner scene/role configuration sources use the ``owner`` audience with
    ``context`` or ``audit`` purpose.  Verify that scope in the current source
    and access rows, including every ancestor.  This proves only that a
    structural dependency is live; it does not qualify text for expression.
    The D03/D05 providers decide the role/boundary check.
    """
    pending = list(source_refs)
    seen: set[str] = set()
    versions: dict[AtomKey, GraphVersion] = {}
    absent_heads: set[str] = set()
    while pending:
        ref = pending.pop()
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject):
            raise ValueError("structural source ref is not canonical")
        if key.owner.subject in seen:
            continue
        seen.add(key.owner.subject)
        if len(seen) > 256:
            raise ValueError("structural source ancestry exceeds bound")
        source_atom = _current_atom(db, snapshot, key)
        access = access_key(*namespace.as_tuple, key.owner.subject)
        access_atom = _current_atom(db, snapshot, access)
        record = SourceRecord.from_dict(source_atom.value)
        validate_access(access_atom.value)
        allowed = (set(record.purposes) & set(access_atom.value["purposes"])
                   & {"context", "audit"})
        if (record.source_id != key.owner.subject
                or access_atom.value["source_id"] != key.owner.subject
                or access_atom.value["status"] != "active"
                or "owner" not in record.audiences
                or "owner" not in access_atom.value["audiences"]
                or not allowed):
            raise ValueError("structural source or access lacks current purpose and audience")
        head = source_correction_head_key(namespace, key.owner.subject)
        if db.execute(
            "SELECT 1 FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (head.token, *namespace.as_tuple),
        ).fetchone() is not None:
            raise ValueError("structural source correction head is present")
        absent_heads.add(head.token)
        versions[key] = GraphVersion(key, source_atom.revision)
        versions[access] = GraphVersion(access, access_atom.revision)
        pending.extend(source_key(*namespace.as_tuple, parent).token
                       for parent in record.parent_source_ids)
    return (tuple(sorted(versions.values(), key=lambda item: item.key.token)),
            tuple(sorted(absent_heads)))


def _current_atom(db, snapshot: GraphSnapshot, key: AtomKey):
    matches = [atom for atom in snapshot.atoms if atom.key == key]
    if len(matches) != 1 or not matches[0].valid or matches[0].revision < 1:
        raise ValueError("staged graph atom missing")
    atom = matches[0]
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (key.token, key.owner.bot, key.owner.persona),
    ).fetchone()
    if row is None or row[0] != atom.revision or row[2] != 1 or json.loads(row[1]) != atom.value:
        raise ValueError("staged graph atom differs from SQLite")
    return atom


