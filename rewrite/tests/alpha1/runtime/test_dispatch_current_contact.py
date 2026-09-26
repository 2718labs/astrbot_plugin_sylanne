"""Current D10 graph rows are local evidence, never dispatch authorization."""

from dataclasses import replace
import json
import sqlite3

import pytest

from sylanne3.domains.d08 import ActionIntent, GoalPredicate, RequiredCheckSpec
from sylanne3.domains.d10 import (
    ContactPolicy, LifeDomain, ProactiveOpportunity, contact_policy_graph_write,
    proactive_opportunity_graph_write,
)
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner, owner_grant_key,
)
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.dispatch_current_contact import read_current_contact
from sylanne3.runtime_contracts import (
    NamespaceId, OperationIdentity, QueryEpoch, VersionedRef, canonical_digest,
)


NS = NamespaceId("bot", "persona")


def _grant():
    return GraphAtom(owner_grant_key(*NS.as_tuple), 1, {
        "schema": "sylanne3.graph.owner_grant.v1", "authority_id": "authority",
        "installation_id": "installation", "grant_id": "grant",
        "principal": {"identity_provider": "local", "account_ref": "account",
                      "account_incarnation": "incarnation"},
        "ticket_id": "ticket", "creation_operation_id": "create",
        "creation_digest": "sha256:" + "a" * 64, "issue_operation_id": "issue",
        "grant_revision": 1, "state": "pending_authority", "scope": "bot/persona",
        "issuer_ref": "authority:installation", "capabilities": ["workbench.read"],
        "purposes": ["workbench_view"], "audiences": ["owner"],
        "activation_generation": 1, "graph_incarnation": "graph-one",
    })


def _fixture():
    source = source_key("bot", "persona", "source-one")
    policy = ContactPolicy("policy:one", NS, 1, "user:one", "private", "ordinary",
                           True, False, 1, 0.0, 24.0)
    opportunity = ProactiveOpportunity("opportunity:one", NS, source.token,
                                        "user:one", "private", "ordinary", 0.0, 10.0)
    policy_write = contact_policy_graph_write(
        policy, owner_grant_revision=1, approval_ref="approval:one",
        approval_authority_id="authority", installation_id="installation")
    opportunity_write = proactive_opportunity_graph_write(
        opportunity, source_revision=1, access_revision=1)
    criteria = AtomKey(Owner("persona", "bot", "persona"), "d10.criteria.v1", "contact")
    atoms = (
        _grant(), GraphAtom(source, 1, SourceRecord(
            "source-one", "An invitation", "user:one", "reported", "reported",
            None, 1.0, "source-one", ("persona",), ("expression",),
        ).to_dict()),
        GraphAtom(access_key("bot", "persona", "source-one"), 1, {
            "source_id": "source-one", "audiences": ["persona"],
            "purposes": ["expression"], "status": "active", "recorded_at": 1.0,
        }),
        GraphAtom(policy_write.key, 1, policy_write.value),
        GraphAtom(opportunity_write.key, 1, opportunity_write.value),
        GraphAtom(criteria, 1, {"rule": "contact"}),
    )
    epoch = QueryEpoch(NS, "all", 5)
    versions = (VersionedRef(criteria.token, 1), VersionedRef("policy:one", 1),
                VersionedRef("opportunity:one", 1),
                VersionedRef("d10.contact_policy:user:one:private:ordinary", 5))
    spec = RequiredCheckSpec("contact_policy", "d10.contact_policy", "persona:persona",
                             "action:one", "proactive_contact", criteria.token, versions)
    intent = ActionIntent(
        action_id="action:one", revision=1, goal_ref="goal:one", commitment_refs=(),
        target_ref="user:one", action_kind="message", purpose="proactive_contact",
        risk_class="limited", parameters_digest="a" * 64,
        identity=OperationIdentity("activity:one", "effect:one", "attempt:one", "prepare",
                                   "operation:one", canonical_digest({"input_refs": []})),
        schema_id="schema:one", required_checks=(spec,),
        success_predicate=GoalPredicate("communicated", "d11.observer", (), 0.0, None),
        effect_scope=("effect:one",), compensation_ref=None, source_refs=(source.token,),
    )
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE graph_epochs(bot TEXT,persona TEXT,revision INTEGER)")
    db.execute("CREATE TABLE graph_atoms(token TEXT,bot TEXT,persona TEXT,revision INTEGER,"
               "value TEXT,type_name TEXT,valid INTEGER)")
    db.execute("INSERT INTO graph_epochs VALUES ('bot','persona',5)")
    for atom in atoms:
        db.execute("INSERT INTO graph_atoms VALUES (?,?,?,?,?,?,1)", (
            atom.key.token, *NS.as_tuple, atom.revision, json.dumps(atom.value),
            atom.key.type_name))
    db.commit()
    db.execute("BEGIN IMMEDIATE")
    return db, GraphSnapshot(atoms, (NamespaceEpoch("bot", "persona", 5),)), epoch, intent


def test_contact_types_and_writes_bind_owner_and_source():
    db, snapshot, epoch, intent = _fixture()
    try:
        specs = {item.name: item for item in LifeDomain.type_specs()}
        for atom in snapshot.atoms:
            if atom.key.type_name in {"d10.contact_policy.v1", "d10.proactive_opportunity.v1"}:
                specs[atom.key.type_name].validator(atom.value)
        result = read_current_contact(db, NS, snapshot, epoch, intent,
                                      "policy:one", "opportunity:one", now=1.0)
        assert (result.local_check.result, result.receipt.result, result.status) == (
            "pass", "unknown", "hold")
    finally:
        db.close()


def test_omitted_policy_row_and_stale_epoch_are_rejected():
    db, snapshot, epoch, intent = _fixture()
    try:
        omitted = replace(snapshot, atoms=tuple(atom for atom in snapshot.atoms
                                                if atom.key.type_name != "d10.contact_policy.v1"))
        with pytest.raises(ValueError, match="omits"):
            read_current_contact(db, NS, omitted, epoch, intent,
                                 "policy:one", "opportunity:one", now=1.0)
        db.execute("UPDATE graph_epochs SET revision=6")
        with pytest.raises(ValueError, match="epoch changed"):
            read_current_contact(db, NS, snapshot, epoch, intent,
                                 "policy:one", "opportunity:one", now=1.0)
    finally:
        db.close()


def test_unbound_opportunity_source_is_rejected():
    db, snapshot, epoch, intent = _fixture()
    try:
        opportunity_atom = next(atom for atom in snapshot.atoms
                                if atom.key.type_name == "d10.proactive_opportunity.v1")
        bad = dict(opportunity_atom.value, source_ref="source:invented")
        with pytest.raises(ValueError, match="atom token"):
            LifeDomain.type_specs()[-1].validator(bad)
    finally:
        db.close()


def test_current_unanswered_claim_recomputes_no_response_and_quota():
    db, snapshot, epoch, intent = _fixture()
    try:
        key = AtomKey(Owner("persona", "bot", "persona"), "d10.contact_claim.v1",
                      "contact:old")
        value = {
            "contact_id": "contact:old", "communication_action_id": "action:old",
            "subject_ref": "user:one", "channel": "private", "category": "ordinary",
            "segment_effects": ["effect:old"], "observations": [["effect:old", "unknown"]],
            "status": "pending_confirmation", "policy_id": "policy:one",
            "policy_version": 1,
        }
        db.execute("INSERT INTO graph_atoms VALUES (?,?,?,?,?,?,1)", (
            key.token, *NS.as_tuple, 1, json.dumps(value), key.type_name))
        snapshot = replace(snapshot, atoms=snapshot.atoms + (GraphAtom(key, 1, value),))
        spec = intent.required_checks[0]
        intent = replace(intent, required_checks=(replace(
            spec, required_input_versions=spec.required_input_versions +
            (VersionedRef("contact:old", 1),)),))
        result = read_current_contact(db, NS, snapshot, epoch, intent,
                                      "policy:one", "opportunity:one", now=1.0)
        assert result.local_check.result == "fail"
        assert set(result.local_check.reasons) == {"no_response_gate", "quota"}
        assert result.receipt.result == "unknown"
        omitted = replace(snapshot, atoms=snapshot.atoms[:-1])
        with pytest.raises(ValueError, match="omits"):
            read_current_contact(db, NS, omitted, epoch, intent,
                                 "policy:one", "opportunity:one", now=1.0)
    finally:
        db.close()
