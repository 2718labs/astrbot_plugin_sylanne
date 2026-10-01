"""D08 reads staged/final rows; a missing current negative query holds."""

from dataclasses import asdict, replace
import json
import sqlite3

import pytest

from rewrite.tests.alpha1.d08.test_goal_execution_domain import _intent, _schema
from sylanne3.authority_service.v2_contract import (
    AuthorityCurrentEffectSnapshotV2, AuthorityUnresolvedEffectV1, FencePermitV2,
    canonical_digest as authority_digest,
)
from sylanne3.authority_service.v2_execution_bridge import CurrentEffectReadV2
from sylanne3.domains.d08 import ActionSchema, ActionSchemaRecord, Commitment, Goal
from sylanne3.domains.d08.dispatch_check import (
    D08_CRITERIA_REF_V1, read_dispatch_check_scope_v2,
)
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner,
)
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_journal import RecoveryConstraintFootprint
from sylanne3.runtime_contracts import (
    FenceScope, NamespaceId, QueryEpoch, VersionedRef, canonical_digest,
    canonical_serialize,
)


def _case(*, execution_seq=0):
    namespace = NamespaceId("bot", "persona")
    source = source_key(*namespace.as_tuple, "request-1")
    platform = json.dumps(["platform-id", "onebot", "bot"], separators=(",", ":"))
    conversation = json.dumps(["umo:private:user", "用户一"], separators=(",", ":"))
    sender = "sender:alice"
    account_suffix = canonical_digest({
        "namespace": namespace.as_tuple, "platform_ref": platform,
        "sender_ref": sender,
    })
    target = "entity:account-v1:" + account_suffix
    account_id = "account:v1:" + account_suffix
    event_id = "world:message-arrival-v1:one"
    event_key = AtomKey(Owner("event", *namespace.as_tuple, event_id),
                        "d03.world_event", "current")
    anchor_key = AtomKey(Owner("persona", *namespace.as_tuple),
                         "d03.entity_anchor", target)
    binding_key = AtomKey(Owner("persona", *namespace.as_tuple),
                          "d03.account_binding", account_id)
    intent = replace(_intent(), commitment_refs=(), source_refs=(source.token,),
                     purpose="expression", target_ref=target)
    specs = list(intent.required_checks)
    for index, spec in enumerate(specs):
        specs[index] = replace(spec, purpose="expression")
        if spec.check_kind == "commitment_conflict":
            specs[index] = replace(
                specs[index], subject_ref="persona:persona",
                criteria_version=D08_CRITERIA_REF_V1,
                required_input_versions=(
                    VersionedRef(D08_CRITERIA_REF_V1, 1),
                    VersionedRef(intent.goal_ref, 1),
                    VersionedRef("commitments-query:persona:persona", 2),
                    VersionedRef(f"execution-epoch:{intent.action_id}", execution_seq),
                    VersionedRef(f"cancellation-epoch:{intent.action_id}", 1),
                ),
            )
    intent = replace(intent, required_checks=tuple(specs))
    schema = ActionSchema(intent.schema_id, "message", False,
                          intent.required_checks)
    binding = ActionSchemaRecord.bind(intent, schema)
    goal = Goal(intent.goal_ref, 1, "active", intent.success_predicate,
                (source.token,), (), None, (), ())
    cancellation = {
        "action_id": intent.action_id, "action_revision": 1,
        "action_digest": canonical_digest(intent),
        "activity_id": intent.identity.activity_id,
        "attempt_id": intent.identity.attempt_id,
        "effect_id": intent.identity.effect_id,
        "cancel_epoch": 0, "state": "active", "actor": "host:user",
        "source_refs": [source.token],
        "operation_id": intent.identity.operation_id,
    }
    owner = Owner("activity", *namespace.as_tuple,
                  intent.identity.activity_id)
    atoms = (
        GraphAtom(source, 1, {"speaker_id": sender,
                              "audiences": [conversation]}),
        GraphAtom(access_key(*namespace.as_tuple, "request-1"), 1,
                  {"status": "active", "audiences": [conversation],
                   "purposes": ["expression"]}),
        GraphAtom(anchor_key, 1, {"entity_id": target, "kind": "account",
                                  "status": "active"}),
        GraphAtom(binding_key, 1, {
            "account_id": account_id, "platform_namespace": platform,
            "platform_identifier": sender, "entity_id": target,
            "verification_ref": event_key.token, "valid_from": 1.0,
            "valid_until": None,
        }),
        GraphAtom(event_key, 1, {
            "kind": "message_received", "reality": "host_observed",
            "scene_ref": "scene:private-1",
            "participant_roles": [[target, "sender_account"]],
            "source_refs": [source.token],
        }),
        GraphAtom(AtomKey(owner, "d08.goal.v1", goal.goal_id), 1,
                  json.loads(canonical_serialize(asdict(goal)))),
        GraphAtom(AtomKey(owner, "d08.action_intent.v1", intent.action_id), 1,
                  json.loads(canonical_serialize(asdict(intent)))),
        GraphAtom(AtomKey(owner, "d08.action_schema.v1", binding.schema_ref), 1,
                  json.loads(canonical_serialize(asdict(binding)))),
        GraphAtom(AtomKey(owner, "d08.action_cancellation.v1", intent.action_id),
                  1, cancellation),
    )
    snapshot = GraphSnapshot(atoms, (NamespaceEpoch(*namespace.as_tuple, 2),))
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE graph_epochs(bot TEXT, persona TEXT, revision INT)")
    db.execute("INSERT INTO graph_epochs VALUES(?,?,?)", (*namespace.as_tuple, 2))
    db.execute("CREATE TABLE graph_atoms(token TEXT,bot TEXT,persona TEXT,"
               "type_name TEXT,name TEXT,revision INT,value TEXT,valid INT)")
    for atom in atoms:
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?)", (
            atom.key.token, *namespace.as_tuple, atom.key.type_name,
            atom.key.name, atom.revision, json.dumps(atom.value), 1))
    db.commit()
    db.execute("BEGIN IMMEDIATE")
    authority_namespace = namespace_ref(namespace)
    execution_digest = ("genesis" if execution_seq == 0
                        else "sha256:" + "c" * 64)
    anchor = RestoreAnchor(
        "authority", authority_namespace, 1, "deletion", 0, "genesis",
        "execution", execution_seq, execution_digest, 0, "proof")
    permit = FencePermitV2(
        "authority", authority_namespace, "holder", "holder", 1,
        "write", "fence-attempt:1", "t" * 32, 0, 1, anchor)
    scope = FenceScope(namespace, authority_namespace, 1, "write",
                       "fence-attempt:1", permit, anchor,
                       NamespaceEpoch(*namespace.as_tuple, 1), 0)
    authority = AuthorityCurrentEffectSnapshotV2(
        "authority", authority_namespace, anchor,
        authority_digest(permit), execution_seq, execution_digest, "complete", ())
    effect = CurrentEffectReadV2(
        "authority", authority_namespace, intent.identity.effect_id, 1,
        "absent", execution_seq, execution_digest)
    return db, snapshot, QueryEpoch(namespace, "all", 2), scope, effect, authority, intent, schema


def _route(case):
    _, snapshot, query, _, _, _, intent, _ = case
    namespace = query.namespace
    source = source_key(*namespace.as_tuple, "request-1")
    platform = json.dumps(["platform-id", "onebot", "bot"], separators=(",", ":"))
    conversation = json.dumps(["umo:private:user", "用户一"], separators=(",", ":"))
    suffix = intent.target_ref.removeprefix("entity:account-v1:")
    account_id = "account:v1:" + suffix
    anchor = AtomKey(Owner("persona", *namespace.as_tuple),
                     "d03.entity_anchor", intent.target_ref)
    binding = AtomKey(Owner("persona", *namespace.as_tuple),
                      "d03.account_binding", account_id)
    event = AtomKey(Owner("event", *namespace.as_tuple,
                          "world:message-arrival-v1:one"),
                    "d03.world_event", "current")
    return CurrentReplyEntityRouteBindingV2(
        namespace, "c02:original", source.token, platform, "sender:alice",
        conversation, "scene:private-1", intent.target_ref, account_id,
        GraphVersion(anchor, 1), GraphVersion(binding, 1), GraphVersion(event, 1),
        GraphVersion(event, 1), GraphVersion(source, 1),
        GraphVersion(access_key(*namespace.as_tuple, "request-1"), 1),
        (GraphVersion(binding, 1),), query, None, "a" * 64,
    )


def _read(case, **overrides):
    db, snapshot, query, scope, effect, authority, intent, schema = case
    route = overrides.get("route_binding", _route(case))
    return read_dispatch_check_scope_v2(
        db, overrides.get("snapshot", snapshot), overrides.get("query", query),
        scope, effect, overrides.get("authority", authority), intent, schema,
        route_binding=route,
        audience=overrides.get("audience", (route.conversation_ref,)),
        purpose="expression", now_utc=5.0)


def test_current_d08_scope_has_full_empty_conflict_queries():
    case = _case()
    try:
        result = _read(case)
        assert (result.receipt.result, result.receipt.coverage) == ("pass", "full")
        assert len(result.positive_reads) == 5
        assert {item.predicate_ref for item in result.negative_queries} == {
            "d08.same_target_unfinished_commitments.v1",
            "d08.same_target_unfinished_actions.v1",
        }
        assert all(item.query == case[2] and not item.matching_refs
                   for item in result.negative_queries)
        with pytest.raises(ValueError, match="private reply entity"):
            read_dispatch_check_scope_v2(
                case[0], case[1], case[2], case[3], case[4], case[5],
                case[6], case[7], route_binding=_route(case),
                audience=("conversation:other",),
                purpose="expression", now_utc=5.0)
        with pytest.raises(ValueError, match="private reply scope"):
            read_dispatch_check_scope_v2(
                case[0], case[1], case[2], case[3], case[4], case[5],
                case[6], case[7], route_binding=_route(case),
                audience=(_route(case).conversation_ref,),
                purpose="proposal", now_utc=5.0)
    finally:
        case[0].close()


def test_unrelated_pending_commitment_keeps_full_negative_query_closure():
    case = _case()
    db, snapshot, _, _, _, _, intent, _ = case
    try:
        unrelated = Commitment(
            "commitment:other-person", 1, "persona:persona",
            "conversation:other", "deliver separate work", "unilateral",
            "communicated", "pending", None, ("receipt:earlier",), (),
            None, (intent.source_refs[0],))
        key = AtomKey(Owner("activity", "bot", "persona", "activity:other"),
                      "d08.commitment.v1", unrelated.commitment_id)
        atom = GraphAtom(
            key, 1, json.loads(canonical_serialize(asdict(unrelated))))
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?)", (
            key.token, "bot", "persona", key.type_name, key.name, 1,
            json.dumps(atom.value), 1))
        complete = replace(snapshot, atoms=snapshot.atoms + (atom,))
        result = _read(case, snapshot=complete)
        assert result.receipt.result == "pass"
        commitments_query = result.negative_queries[0]
        assert commitments_query.predicate_ref == (
            "d08.same_target_unfinished_commitments.v1")
        assert VersionedRef(key.token, 1) in commitments_query.scanned_versions
        assert commitments_query.matching_refs == ()
    finally:
        db.close()


def test_stale_graph_epoch_and_unfinished_commitment_hold():
    case = _case()
    db, snapshot, query, _, _, _, intent, _ = case
    try:
        db.execute("UPDATE graph_epochs SET revision=3")
        with pytest.raises(ValueError, match="graph epoch"):
            _read(case)
        db.execute("UPDATE graph_epochs SET revision=2")
        commitment = Commitment(
            "commitment:other", 1, "persona:persona", intent.target_ref,
            "other duty", "unilateral", "communicated", "pending", None,
            ("receipt:earlier",), (), None, (intent.source_refs[0],))
        key = AtomKey(Owner("activity", "bot", "persona", "activity:other"),
                      "d08.commitment.v1", commitment.commitment_id)
        atom = GraphAtom(
            key, 1, json.loads(canonical_serialize(asdict(commitment))))
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?)", (
            key.token, "bot", "persona", key.type_name, key.name, 1,
            json.dumps(atom.value), 1))
        with pytest.raises(ValueError, match="omits or invents"):
            _read(case)
        snapshot = replace(snapshot, atoms=snapshot.atoms + (atom,))
        with pytest.raises(ValueError, match="conflict remains"):
            _read(case, snapshot=snapshot)
    finally:
        db.close()


def test_incomplete_authority_effect_set_holds():
    case = _case()
    try:
        with pytest.raises(ValueError, match="Authority effect inventory"):
            _read(case, authority=replace(
                case[5], permit_digest="sha256:" + "a" * 64))
    finally:
        case[0].close()
    occupied = _case(execution_seq=1)
    try:
        other = AuthorityUnresolvedEffectV1(
            "effect:other", "operation:other", "mutation:other", "prepared",
            1, "sha256:" + "b" * 64,
            RecoveryConstraintFootprint(
                occupied[3].authority_namespace, "activity:other", "effect:other"))
        with pytest.raises(ValueError, match="Authority effect inventory"):
            _read(occupied, authority=replace(
                occupied[5], unresolved_effects=(other,)))
    finally:
        occupied[0].close()
