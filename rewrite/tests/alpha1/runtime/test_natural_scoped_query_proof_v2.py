"""The original natural call survives unrelated graph writes, not route changes."""

from dataclasses import asdict, replace
import json
import sqlite3

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.domains.d03.context import AccountBinding, RoleBinding
from sylanne3.domains.d05.relationship import BoundaryRule
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.natural_scoped_query_proof_v2 import (
    NaturalPrivateScopeV2, NaturalScopedQueryHold,
    assert_natural_scoped_query_current_v2,
    natural_scoped_query_proof_from_wire_v2,
    read_natural_scoped_query_proof_v2,
)
from sylanne3.runtime_contracts import NamespaceId


NAMESPACE = NamespaceId("bot", "persona")
AUDIENCE = "conversation:private"
SCENE = "scene:private"
TARGET = "entity:account"


def _put(db, key, value, revision=1):
    db.execute(
        "INSERT INTO graph_atoms(token,bot,persona,type_name,name,revision,value,valid) "
        "VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(token) DO UPDATE SET "
        "revision=excluded.revision,value=excluded.value,valid=1",
        (key.token, *NAMESPACE.as_tuple, key.type_name, key.name,
         revision, canonical_json(json.loads(json.dumps(value)))),
    )


def _fixture():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE graph_atoms (token TEXT PRIMARY KEY,bot TEXT,persona TEXT,"
               "type_name TEXT,name TEXT,revision INTEGER,value TEXT,valid INTEGER)")
    account = AccountBinding(
        "account:sender", "platform", "sender", TARGET, "verification:one",
        0.0, None)
    account_key = AtomKey(
        Owner("persona", *NAMESPACE.as_tuple), "d03.account_binding",
        account.account_id)
    _put(db, account_key, asdict(account))
    role = RoleBinding(
        "binding:private", "persona:persona", "friend", TARGET, None,
        SCENE, "private", "private", (), 0.0, None, 1,
        ("source:role",), 1, "active")
    role_key = AtomKey(Owner("scene", *NAMESPACE.as_tuple, SCENE),
                       "d03.role_binding", role.role_binding_id)
    _put(db, role_key, asdict(role))
    source = SourceRecord(
        "source:question", "Did you pay?", "sender", "reported",
        "reported", None, 1.0, "source:question", (AUDIENCE,),
        ("expression",))
    source_key_value = source_key(*NAMESPACE.as_tuple, source.source_id)
    _put(db, source_key_value, source.to_dict())
    access = {
        "source_id": source.source_id, "audiences": [AUDIENCE],
        "purposes": ["expression"], "status": "active", "recorded_at": 1.0,
    }
    access_key_value = access_key(*NAMESPACE.as_tuple, source.source_id)
    _put(db, access_key_value, access)
    scope = NaturalPrivateScopeV2(
        NAMESPACE, "platform", "sender", TARGET, SCENE, AUDIENCE,
        account_key.token, role_key.token, (source_key_value.token,))
    db.commit()
    db.execute("BEGIN")
    return db, scope, access_key_value


def _rule(effect: str = "deny"):
    return BoundaryRule(
        "boundary:private", "persona:persona", TARGET, "message", AUDIENCE,
        SCENE, effect, "counterparty_explicit", ("source:boundary",),
        (), (), 0.0, None, 1, "actor", (), "active")


def test_unrelated_write_preserves_original_scope_and_wire(monkeypatch):
    db, scope, _ = _fixture()
    try:
        original_applies_to = RoleBinding.applies_to
        observed_requests = []

        def record_request(self, request):
            observed_requests.append(request)
            return original_applies_to(self, request)

        monkeypatch.setattr(RoleBinding, "applies_to", record_request)
        original = read_natural_scoped_query_proof_v2(db, scope, now_utc=2.0)
        assert len(observed_requests) == 1
        assert (observed_requests[0].requested_action_kind,
                observed_requests[0].purpose) == ("expression", "reply")
        wire = json.loads(json.dumps(asdict(original)))
        assert natural_scoped_query_proof_from_wire_v2(wire) == original
        digest = original.semantic_digest
        db.commit()
        # The namespace graph advances, including an unrelated valid D03 role.
        other = RoleBinding(
            "binding:other", "persona:persona", "colleague",
            "entity:other", None, "scene:other", "private", "private", (),
            0.0, None, 1, ("source:other",), 1, "active")
        _put(db, AtomKey(Owner("scene", *NAMESPACE.as_tuple, "scene:other"),
                         "d03.role_binding", other.role_binding_id), asdict(other))
        unrelated_boundary = replace(
            _rule("allow"), rule_id="boundary:other",
            target_entity_ref="entity:other")
        _put(db, AtomKey(Owner("relation", *NAMESPACE.as_tuple, "entity:other"),
                         "d05.boundary_rule", unrelated_boundary.rule_id),
             asdict(unrelated_boundary))
        _put(db, AtomKey(Owner("persona", *NAMESPACE.as_tuple),
                         "d07.unrelated", "current"), {"value": 1})
        db.commit()
        db.execute("BEGIN")
        assert assert_natural_scoped_query_current_v2(
            db, original, now_utc=3.0).semantic_digest == digest
    finally:
        db.close()


def test_existing_message_boundary_is_part_of_original_proof():
    db, scope, _ = _fixture()
    try:
        db.commit()
        rule = _rule("allow")
        _put(db, AtomKey(Owner("relation", *NAMESPACE.as_tuple, TARGET),
                         "d05.boundary_rule", rule.rule_id), asdict(rule))
        db.commit()
        db.execute("BEGIN")
        original = read_natural_scoped_query_proof_v2(db, scope, now_utc=2.0)
        assert len(original.boundary_matches) == 1
        assert original.boundary_matches[0].token.endswith(
            '"d05.boundary_rule","boundary:private"]')
        assert assert_natural_scoped_query_current_v2(
            db, original, now_utc=3.0) == original
    finally:
        db.close()


@pytest.mark.parametrize("change", ["role", "boundary", "revoke", "correction"])
def test_conflicting_role_boundary_and_d06_changes_hold(change):
    db, scope, access_key_value = _fixture()
    try:
        original = read_natural_scoped_query_proof_v2(db, scope, now_utc=2.0)
        db.commit()
        if change == "role":
            competing = RoleBinding(
                "binding:competing", "persona:persona", "other", TARGET,
                None, SCENE, "private", "private", (), 0.0, None, 1,
                ("source:other",), 1, "active")
            _put(db, AtomKey(Owner("scene", *NAMESPACE.as_tuple, SCENE),
                             "d03.role_binding", competing.role_binding_id),
                 asdict(competing))
        elif change == "boundary":
            rule = _rule()
            _put(db, AtomKey(Owner("relation", *NAMESPACE.as_tuple, TARGET),
                             "d05.boundary_rule", rule.rule_id), asdict(rule))
        elif change == "revoke":
            _put(db, access_key_value, {
                "source_id": "source:question", "audiences": [AUDIENCE],
                "purposes": ["expression"], "status": "revoked",
                "recorded_at": 1.0}, revision=2)
        else:
            from sylanne3.domains.d06 import source_correction_head_key
            key = source_correction_head_key(NAMESPACE, "source:question")
            _put(db, key, {"present": True})
        db.commit()
        db.execute("BEGIN")
        with pytest.raises(NaturalScopedQueryHold):
            assert_natural_scoped_query_current_v2(db, original, now_utc=3.0)
    finally:
        db.close()


def test_same_version_semantic_change_is_detected():
    db, scope, _ = _fixture()
    try:
        original = read_natural_scoped_query_proof_v2(db, scope, now_utc=2.0)
        db.commit()
        changed = RoleBinding(
            "binding:private", "persona:persona", "stranger", TARGET,
            None, SCENE, "private", "private", (), 0.0, None, 1,
            ("source:role",), 1, "active")
        _put(db, AtomKey(Owner("scene", *NAMESPACE.as_tuple, SCENE),
                         "d03.role_binding", changed.role_binding_id),
             asdict(changed))
        db.commit()
        db.execute("BEGIN")
        with pytest.raises(NaturalScopedQueryHold):
            assert_natural_scoped_query_current_v2(db, original, now_utc=3.0)
    finally:
        db.close()
