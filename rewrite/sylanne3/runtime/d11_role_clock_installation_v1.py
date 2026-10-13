"""Owner-approved D11 role clocks with durable signed originals and CAS.

The Owner supplies the exact rate and validity window. The origin must equal
every current component cursor; renewal must also preserve the previous clock.
No product default silently chooses simulation speed or fabricates elapsed time.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from decimal import Decimal
import json

from ..contracts import StaleRead
from ..runtime_contracts import canonical_digest, canonical_serialize
from .clock import CharacterClockMapping, _mapping_dict, get_clock_mapping, issue_clock_mapping, install_schema

TABLE = "runtime_d11_owner_role_clock_originals_v1"
SIGN_KIND = "d11.owner-role-clock-installation.v1"


def install_d11_role_clock_schema_v1(db):
    install_schema(db)
    db.execute(f"""CREATE TABLE IF NOT EXISTS {TABLE} (
        bot TEXT NOT NULL, persona TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0),
        operation_id TEXT NOT NULL, original_json TEXT NOT NULL,
        original_digest TEXT NOT NULL, signature TEXT NOT NULL,
        PRIMARY KEY(bot,persona,revision), UNIQUE(bot,persona,operation_id))""")
    for action in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS {TABLE}_no_{action.lower()}
            BEFORE {action} ON {TABLE}
            BEGIN SELECT RAISE(ABORT,'D11 Owner role clock original is immutable'); END""")


def role_clock_mapping_id_v1(namespace):
    return "d11-role-clock:" + canonical_digest(namespace)[:48]


def _mapping_original(db, namespace, saved):
    body, _digest = saved
    if body["schema"] != "d11.owner-role-clock-original.v1":
        raise ValueError("D11 role clock original schema differs")
    value = body["mapping"]
    mapping = get_clock_mapping(db, role_clock_mapping_id_v1(namespace))
    if (_mapping_dict(mapping) != value or mapping.version != body["revision"]
            or mapping.policy_ref != "d11.owner-explicit-role-clock.v1"):
        raise ValueError("D11 registered role clock changed or lacks current original")
    from .domain_background_read_v3 import _active_v3,background_point_v3,background_json_loads_v3
    if _active_v3(db)is not None:
        actual=background_point_v3(db,table='runtime_clock_operations',columns=('digest','mapping_id','version','mapping_json'),
            key_columns=('operation_id',),key=(body['clock_operation_id'],),legacy_reader=lambda:None)
        rows=() if actual is None else (actual,)
    else:
        rows = db.execute("SELECT digest,mapping_id,version,mapping_json FROM runtime_clock_operations WHERE operation_id=?",
            (body["clock_operation_id"],)).fetchall()
    if (len(rows) != 1 or rows[0][:3] != (body["clock_operation_digest"], mapping.mapping_id, mapping.version)
            or background_json_loads_v3(rows[0][3]) != value):
        raise ValueError("D11 registered role clock operation original differs")
    return mapping


def read_current_role_clock_installation_v1(reader, db, namespace):
    from .d04_semantic_installation_original_v3 import _current_inputs, _read_signed
    inputs = _current_inputs(reader, db, namespace)
    original = _read_signed(db, reader.graph._GraphCoordinator__d11_issuer, TABLE, SIGN_KIND, namespace)
    if original is None:
        raise ValueError("D11 role clock requires explicit Owner rate and origin initialization")
    body = original[0]
    expected = {"owner_guard": asdict(inputs["guard"]), "role_rows": inputs["role_rows"],
        "member_bindings": inputs["member_bindings"],
        "manifest_sha256": reader.qualified_original_manifest_sha256(db, namespace, body),
        "installation_ref": reader.qualified_original_installation_ref(db, namespace, body)}
    if any(canonical_serialize(body.get(key)) != canonical_serialize(value) for key, value in expected.items()):
        raise ValueError("D11 Owner role clock scope, role, membership or revocation changed")
    return _mapping_original(db, namespace, original)


def register_current_role_clock_v1(reader, authority, lease, *, operation_id,
        expected_version, character_origin, rate, wall_origin_utc, valid_from_utc, valid_until_utc):
    from .d04_semantic_installation_original_v3 import (
        _owner_write, _read_signed, _insert_signed, _installation_ref,
    )
    if type(expected_version) is not int or expected_version < 0:
        raise ValueError("D11 role clock expected_version must be a nonnegative integer")
    for label, number in (("rate", rate), ("character_origin", character_origin)):
        if type(number) is not str or str(Decimal(number)) != number:
            raise ValueError("D11 Owner clock " + label + " must be an explicit exact decimal string")
    namespace = authority.namespace
    mapping = CharacterClockMapping(role_clock_mapping_id_v1(namespace), expected_version + 1,
        wall_origin_utc, Decimal(character_origin), Decimal(rate), valid_from_utc, valid_until_utc,
        "d11.owner-explicit-role-clock.v1", "d11")
    request = {"action": "register_role_clock", "expected_version": expected_version,
               "mapping": _mapping_dict(mapping)}
    def commit(db, inputs, owner):
        issuer = reader.graph._GraphCoordinator__d11_issuer
        prior = _read_signed(db, issuer, TABLE, SIGN_KIND, namespace, operation_id=operation_id)
        if prior is not None:
            if prior[0]["owner"]["request_digest"] != owner["request_digest"]:
                raise ValueError("D11 role clock Owner operation ID reused with different input")
            return _receipt(prior)
        current = _read_signed(db, issuer, TABLE, SIGN_KIND, namespace)
        if (0 if current is None else current[0]["revision"]) != expected_version:
            raise StaleRead("D11 role clock expected version changed")
        if mapping.character_origin != Decimal.from_float(float(inputs["cursor"])):
            raise ValueError("D11 role clock origin differs from actual synchronized component cursor")
        now = datetime.fromtimestamp(owner["accepted_at_utc"], timezone.utc).isoformat().replace("+00:00", "Z")
        mapping.character_at(now)  # Installed trusted wall clock must lie in validity.
        if datetime.fromisoformat(wall_origin_utc.replace("Z", "+00:00")) > datetime.fromisoformat(now.replace("Z", "+00:00")):
            raise ValueError("D11 Owner role clock origin cannot be in the future")
        if current is not None:
            prior_mapping = _mapping_original(db, namespace, current)
            if prior_mapping.character_at(wall_origin_utc) != mapping.character_origin:
                raise ValueError("D11 role clock replacement would introduce a discontinuity")
        elif db.execute("SELECT 1 FROM runtime_character_clocks WHERE mapping_id=?", (mapping.mapping_id,)).fetchone():
            raise ValueError("D11 role clock already exists without an Owner original")
        clock_operation = "owner-role-clock:" + operation_id
        clock_digest = canonical_digest((namespace, operation_id, request, inputs["member_bindings"], inputs["role_rows"]))
        issue_clock_mapping(db, mapping, clock_operation, clock_digest)
        body = {"schema": "d11.owner-role-clock-original.v1", "namespace": asdict(namespace),
            "operation_id": operation_id, "revision": mapping.version, "mapping": _mapping_dict(mapping),
            "clock_operation_id": clock_operation, "clock_operation_digest": clock_digest,
            "installation_ref": _installation_ref(reader, namespace), "manifest_sha256": reader.manifest_sha256,
            "owner": owner, "owner_guard": asdict(inputs["guard"]), "role_rows": inputs["role_rows"],
            "member_bindings": inputs["member_bindings"], "graph_revision": inputs["scope"].graph_revision,
            "graph_epoch": inputs["scope"].graph_epoch.revision}
        saved = _insert_signed(db, issuer, TABLE, SIGN_KIND, namespace, body)
        read_current_role_clock_installation_v1(reader, db, namespace)
        return _receipt(saved)
    return _owner_write(reader, authority, lease, operation_id=operation_id, request=request, commit=commit)


def _receipt(saved):
    body, digest = saved
    return {"status": "owner_role_clock_registered", "operation_id": body["operation_id"],
        "mapping_id": body["mapping"]["mapping_id"], "mapping_version": body["revision"],
        "original_digest": digest, "mapping": body["mapping"]}
