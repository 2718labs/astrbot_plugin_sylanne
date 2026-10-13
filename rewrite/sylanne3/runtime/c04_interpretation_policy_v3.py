"""The manifest-pinned C04 default D07 branch, frozen with each preparation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..contracts import canonical_json
from ..domains.d07.current_issuer_v1 import InstalledCurrentInterpretationPolicyV3
from ..runtime_contracts import canonical_digest


_PRESENCE_POLICY = ("d07.c04.recollection_presence.v3", "1", "recollection_presence")


def installed_c04_presence_policy_v3():
    return InstalledCurrentInterpretationPolicyV3(*_PRESENCE_POLICY)


def _payload(*, binding_digest, installation_id, manifest_digest, algorithm_build_digest):
    policy = installed_c04_presence_policy_v3()
    return {"schema": "c04.installed-interpretation-code-policy.v3",
            "binding_digest": binding_digest, "installation_id": installation_id,
            "manifest_digest": manifest_digest,
            "algorithm_build_digest": algorithm_build_digest,
            "policy_id": policy.policy_id, "policy_version": policy.policy_version,
            "mode": policy.mode, "constant_digest": canonical_digest(_PRESENCE_POLICY),
            "module": "runtime/c04_interpretation_policy_v3.py",
            "module_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def install_c04_interpretation_policy_original_v3(db):
    if db.in_transaction:
        raise ValueError("install C04 code-policy store before transaction")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS graph_c04_code_policy_originals_v3 (
          bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
          payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL,
          PRIMARY KEY(bot,persona,operation_id));
        CREATE TRIGGER IF NOT EXISTS graph_c04_code_policy_no_update_v3
          BEFORE UPDATE ON graph_c04_code_policy_originals_v3
          BEGIN SELECT RAISE(ABORT, 'C04 code policy is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS graph_c04_code_policy_no_delete_v3
          BEFORE DELETE ON graph_c04_code_policy_originals_v3
          BEGIN SELECT RAISE(ABORT, 'C04 code policy is immutable'); END;
    """)


def record_installed_c04_interpretation_policy_v3(
    db, namespace, prepared, *, installation_id, manifest_digest,
):
    if not db.in_transaction:
        raise ValueError("W01 preparation code-policy transaction required")
    binding = prepared.binding
    payload = _payload(binding_digest=binding.binding_digest,
        installation_id=installation_id, manifest_digest=manifest_digest,
        algorithm_build_digest=binding.algorithm_build_digest)
    values = (canonical_json(payload), canonical_digest(payload))
    key = (*namespace.as_tuple, binding.operation_id)
    old = db.execute("SELECT payload_json,payload_digest FROM graph_c04_code_policy_originals_v3 "
                     "WHERE bot=? AND persona=? AND operation_id=?", key).fetchone()
    if old is not None and old != values:
        raise ValueError("C04 original installed code policy changed")
    if old is None:
        db.execute("INSERT INTO graph_c04_code_policy_originals_v3 VALUES(?,?,?,?,?)", (*key, *values))
    return payload


def read_installed_c04_interpretation_policy_v3(
    db, namespace, prepared, *, installation_id, manifest_digest,
):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    if not db.in_transaction:
        raise ValueError("W01 current code-policy transaction required")
    binding = prepared.binding
    row = _producer_original_point_v3(db,table='graph_c04_code_policy_originals_v3',columns=('payload_json', 'payload_digest'),key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple, binding.operation_id),legacy_reader=lambda: db.execute("SELECT payload_json,payload_digest FROM graph_c04_code_policy_originals_v3 "
                     "WHERE bot=? AND persona=? AND operation_id=?",
                     (*namespace.as_tuple, binding.operation_id)).fetchone())
    expected = _payload(binding_digest=binding.binding_digest, installation_id=installation_id,
                        manifest_digest=manifest_digest, algorithm_build_digest=binding.algorithm_build_digest)
    if row != (canonical_json(expected), canonical_digest(expected)):
        raise ValueError("C04 frozen code-policy installation original differs")
    return installed_c04_presence_policy_v3(), json.loads(row[0])


__all__ = ["installed_c04_presence_policy_v3", "install_c04_interpretation_policy_original_v3",
           "record_installed_c04_interpretation_policy_v3", "read_installed_c04_interpretation_policy_v3"]
