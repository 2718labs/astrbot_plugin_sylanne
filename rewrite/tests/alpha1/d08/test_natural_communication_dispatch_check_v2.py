"""Current D08 check accepts the exact natural communication action kind."""

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.domains.d08 import ActionSchemaRecord
from sylanne3.domains.d08.communication_route_binding import (
    validate_communication_route_binding_v2,
)
from sylanne3.domains.d08.dispatch_check import read_dispatch_check_scope_v2
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, Owner
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize

from .test_dispatch_check_scope_v2 import _case, _route


def _communication_case():
    case = _case()
    db, snapshot, query, scope, effect, authority, old_intent, old_schema = case
    intent = replace(old_intent, action_kind="communication")
    schema = replace(old_schema, action_kind="communication")
    binding = ActionSchemaRecord.bind(intent, schema)
    owner = Owner("activity", *query.namespace.as_tuple,
                  intent.identity.activity_id)
    old_binding = ActionSchemaRecord.bind(old_intent, old_schema)
    schema_key = AtomKey(owner, "d08.action_schema.v1", binding.schema_ref)
    atoms = []
    for atom in snapshot.atoms:
        if atom.key.type_name == "d08.action_intent.v1":
            value = json.loads(canonical_serialize(asdict(intent)))
            atom = replace(atom, value=value)
            db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                       (canonical_serialize(value), atom.key.token))
        elif atom.key.type_name == "d08.action_schema.v1":
            db.execute("DELETE FROM graph_atoms WHERE token=?", (atom.key.token,))
            continue
        elif atom.key.type_name == "d08.action_cancellation.v1":
            value = dict(atom.value, action_digest=canonical_digest(intent))
            atom = replace(atom, value=value)
            db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                       (canonical_serialize(value), atom.key.token))
        atoms.append(atom)
    assert old_binding.schema_ref != binding.schema_ref
    schema_value = json.loads(canonical_serialize(asdict(binding)))
    atoms.append(GraphAtom(schema_key, 1, schema_value))
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?)", (
        schema_key.token, *query.namespace.as_tuple,
        schema_key.type_name, schema_key.name, 1,
        canonical_serialize(schema_value), 1,
    ))
    return (db, GraphSnapshot(tuple(atoms), snapshot.epochs), query, scope,
            effect, authority, intent, schema)


def _read(case, *, expected_action_kind="message", schema=None):
    db, snapshot, query, scope, effect, authority, intent, stored_schema = case
    route = _route(case)
    return read_dispatch_check_scope_v2(
        db, snapshot, query, scope, effect, authority, intent,
        stored_schema if schema is None else schema,
        route_binding=route, audience=(route.conversation_ref,),
        purpose="expression", now_utc=5.0,
        expected_action_kind=expected_action_kind,
    )


def test_message_default_and_natural_communication_keep_same_current_closure():
    message = _case()
    natural = _communication_case()
    try:
        old = _read(message)
        new = _read(natural, expected_action_kind="communication")
        assert old.receipt.result == new.receipt.result == "pass"
        assert old.receipt.coverage == new.receipt.coverage == "full"
        assert new.graph_query == natural[2]
        assert len(new.positive_reads) == 5
        assert tuple(item.predicate_ref for item in old.negative_queries) == tuple(
            item.predicate_ref for item in new.negative_queries)
        assert all(not item.matching_refs for item in new.negative_queries)
        assert new.receipt.action_ref == natural[6].action_id
    finally:
        message[0].close()
        natural[0].close()


def test_natural_kind_requires_exact_intent_schema_and_route_match():
    case = _communication_case()
    try:
        with pytest.raises(ValueError, match="private reply scope"):
            _read(case)
        with pytest.raises(ValueError, match="private reply scope"):
            _read(case, expected_action_kind="communication",
                  schema=replace(case[7], action_kind="message"))
        route = _route(case)
        with pytest.raises(ValueError, match="private reply entity"):
            validate_communication_route_binding_v2(
                route, case[6], (route.conversation_ref,),
                db=case[0], snapshot=case[1], scope=case[3], now=5.0,
            )
        with pytest.raises(ValueError, match="private reply scope"):
            _read(case, expected_action_kind="send")
    finally:
        case[0].close()
