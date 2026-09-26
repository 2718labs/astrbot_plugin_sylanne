"""D03/D05 checks need current graph rows and their actual providers."""

from dataclasses import replace

from sylanne3.contracts import canonical_json
from sylanne3.domains.d03.context import RoleBindingRequest
from sylanne3.domains.d05.relationship import RelationshipProvider
from sylanne3.domains.d08 import ActionSchema, ActionSchemaRecord, RequiredCheckSpec
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, Owner
from sylanne3.runtime.dispatch_current_projection import (
    derive_current_domain_reads, read_current_dispatch_projection,
)
from sylanne3.runtime.dispatch_current_social_checks import verify_current_social_checks
from sylanne3.runtime_contracts import QueryEpoch, VersionedRef

from test_dispatch_admission_preflight import _candidates
from test_dispatch_current_projection import _typed_case
from test_dispatch_source_correction_barrier import _insert_head


def _case():
    db, namespace, snapshot, query, context, _ = _typed_case()
    criteria_keys = (snapshot.atoms[0].key, snapshot.atoms[1].key)
    _, original, _, _, _ = _candidates()
    specs = list(original.required_checks)
    specs[0] = RequiredCheckSpec(
        "role_binding", "d03.role_binding", "persona:persona", "action:one",
        "expression", criteria_keys[0].token,
        (VersionedRef(criteria_keys[0].token, 2),
         VersionedRef("d03.role_binding", 5),
         VersionedRef("binding:one", 2)),
    )
    specs[1] = RequiredCheckSpec(
        "boundary", "d05.boundary", "persona:persona", "action:one",
        "expression", criteria_keys[1].token,
        (VersionedRef(criteria_keys[1].token, 1),
         VersionedRef("d05.boundary", 5),
         VersionedRef("boundary:one", 1)),
    )
    intent = replace(original, required_checks=tuple(specs))
    schema = ActionSchemaRecord.bind(intent, ActionSchema(
        intent.schema_id, intent.action_kind, False, intent.required_checks,
    ))
    db.execute("BEGIN IMMEDIATE")
    projection = read_current_dispatch_projection(db, namespace, snapshot, query)
    request = RoleBindingRequest(
        "persona:persona", "entity:user", None, "scene:one", "message",
        "expression", 2.0, True,
    )
    role_read, boundary_read = derive_current_domain_reads(
        db, projection, request, context,
    )
    role_receipt = context.provide_required_check(
        intent, role_read, valid_until=10.0,
    )
    boundary_read = replace(
        boundary_read, input_versions=boundary_read.input_versions +
        (VersionedRef(criteria_keys[1].token, 1),),
    )
    boundary_receipt = RelationshipProvider(
        boundary_read_verifier=lambda observed: observed == boundary_read,
    ).boundary_required_check(
        intent, ActionSchema(schema.schema_id, schema.action_kind,
                             schema.proactive, schema.required_checks),
        boundary_read, audience_scope="conversation", scene_ref="scene:one",
        at_time=2.0, valid_until=10.0,
    )
    assert (role_receipt.result, boundary_receipt.result) == ("pass", "pass")
    return db, snapshot, projection, intent, schema, context, role_receipt, boundary_receipt


def _verify(case, **overrides):
    db, snapshot, projection, intent, schema, context, role, boundary = case
    return verify_current_social_checks(
        db, overrides.get("snapshot", snapshot),
        overrides.get("projection", projection), intent, schema,
        overrides.get("role", role), overrides.get("boundary", boundary),
        context=context, scene_ref="scene:one", audience_scope="conversation",
        now_utc=overrides.get("now_utc", 2.0),
        current_catalogue_confirmed=overrides.get("catalogue", True),
    )


def test_current_role_and_boundary_provider_receipts_verify():
    case = _case()
    try:
        result = _verify(case)
        assert (result.status, result.verified) == ("verified", True)
        assert _verify(case, catalogue=False).verified is False
    finally:
        case[0].close()


def test_correction_head_turns_prior_boundary_pass_into_hold():
    case = _case()
    db, snapshot, prior, *_ = case
    try:
        _insert_head(db, prior.namespace)
        current = read_current_dispatch_projection(
            db, prior.namespace, snapshot,
            QueryEpoch(prior.namespace, "all", prior.graph_epoch),
        )
        assert current.coverage == "partial"
        result = _verify(case, projection=current)
        assert (result.status, result.verified) == ("hold", False)
    finally:
        db.close()


def test_empty_binding_and_changed_boundary_hold():
    case = _case()
    db, snapshot, *_ = case
    try:
        role_atom, boundary_atom = snapshot.atoms[:2]
        db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (role_atom.key.token,))
        without_role = GraphSnapshot(snapshot.atoms[1:], snapshot.epochs)
        assert _verify(case, snapshot=without_role).verified is False
        db.execute("UPDATE graph_atoms SET valid=1 WHERE token=?", (role_atom.key.token,))
        changed_value = {**boundary_atom.value, "effect": "deny"}
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?", (
            canonical_json(changed_value), boundary_atom.key.token,
        ))
        changed_atoms = (role_atom, replace(boundary_atom, value=changed_value))
        changed = GraphSnapshot(changed_atoms, snapshot.epochs)
        assert _verify(case, snapshot=changed).verified is False
    finally:
        db.close()


def test_conflicting_binding_identity_holds():
    case = _case()
    db, snapshot, projection, *_ = case
    try:
        original = snapshot.atoms[0]
        duplicate = GraphAtom(
            AtomKey(Owner("persona", "bot", "persona"),
                    "d03.role_binding", original.key.name),
            original.revision, original.value,
        )
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
            duplicate.key.token, "bot", "persona", duplicate.key.type_name,
            duplicate.revision, canonical_json(duplicate.value), 1,
        ))
        changed = GraphSnapshot(snapshot.atoms + (duplicate,), snapshot.epochs)
        current = read_current_dispatch_projection(
            db, projection.namespace, changed,
            QueryEpoch(projection.namespace, "all", projection.graph_epoch),
        )
        assert _verify(case, snapshot=changed, projection=current).verified is False
    finally:
        db.close()


def test_expired_receipt_and_missing_current_criteria_hold():
    case = _case()
    db, snapshot, *_ = case
    try:
        assert _verify(case, now_utc=11.0).verified is False
        criteria = snapshot.atoms[0]
        db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (criteria.key.token,))
        assert _verify(case).verified is False
    finally:
        db.close()
