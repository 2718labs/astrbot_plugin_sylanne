"""Typed Source getters for the live Life numeric joint bridge.

The Life numeric joint chain runs inside W01 with a private same-transaction
bridge issued only by ``_issue_life_joint_source_bridge_v1``. That bridge
carries the actually materialized domain production frame, so every joint
dependency must be read through the frame-qualified typed reader
(``CurrentDomainReadV1``): the frame's frozen snapshot is the authorization for
the exact head, and ``CurrentDomainReadV1.head`` re-checks the current DB head
against that snapshot after using the bound Method/post-commit reader.

Shared numeric modules therefore never let a Life bridge reach raw
``graph_atoms`` SQL. The conversation D04 Source reader keeps its own typed path
in ``d04_source_work_v3``; the two identities stay independent and a
conversation getter is never accepted for a Life bridge.

The complete-inventory rows getter is available because the Life joint/drive
read plan now declares the numeric families (checkpoints/states, coupling,
drives, contribution ledger); every returned row therefore comes from a frame
coverage page that the Method census materialized before Source ALL, never from
a live SQL enumeration against unplanned types.
"""
from __future__ import annotations


def require_live_life_joint_bridge_v1(db, bridge):
    """Validate the live private Life bridge and return its drive plus frame."""
    from .d06_life_numeric_joint_v1 import _require_life_joint_source_bridge_v1
    return _require_life_joint_source_bridge_v1(db, bridge)


def life_joint_bridge_reader_v1(db, bridge):
    """Return the frame-qualified typed reader for one live Life bridge."""
    from .d01_production_operations_v1 import CurrentDomainReadV1
    _current_drive, frame = require_live_life_joint_bridge_v1(db, bridge)
    return CurrentDomainReadV1(frame)


def read_life_joint_bridge_atom_v1(db, bridge, key):
    """Read one exact joint dependency through the Life frame's typed snapshot."""
    from ..graph_types import AtomKey
    if type(key) is not AtomKey:
        raise TypeError("Life joint typed read requires an exact atom key")
    return life_joint_bridge_reader_v1(db, bridge).head(db, key)


def read_life_joint_bridge_rows_v1(db, bridge, types, limit=None):
    """Read the complete typed inventory rows for the declared Life numeric families.

    Rows use the joint inventory shape ``(token, revision, canonical_json, valid)``;
    the frame coverage page is the authorization, so the canonical JSON column is
    the frame's logical value (the C09 logical Body representation) rather than a
    fresh raw storage read. ``limit`` mirrors the existing complete-page bound.
    """
    from ..contracts import canonical_json
    if type(types) is not tuple or not types or any(type(name) is not str or not name for name in types):
        raise TypeError("Life joint inventory read requires exact type names")
    if limit is not None and (type(limit) is not int or limit < 1):
        raise TypeError("Life joint inventory limit must be a positive integer")
    reader = life_joint_bridge_reader_v1(db, bridge)
    rows = []
    for type_name in types:
        for atom in reader.complete_inventory(db, type_name):
            rows.append((atom.key.token, atom.revision, canonical_json(atom.value), int(atom.valid)))
    rows.sort(key=lambda row: row[0])
    if limit is not None:
        return tuple(rows[:limit])
    return tuple(rows)
