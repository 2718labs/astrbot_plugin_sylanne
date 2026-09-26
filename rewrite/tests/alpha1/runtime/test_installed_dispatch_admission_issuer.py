"""The installed issuer reads current graph rows and never invents PASS."""

from dataclasses import asdict, replace
import json
import sqlite3

import pytest

from sylanne3.graph_types import AtomKey, Owner
from sylanne3.graph_types import GraphReceipt, NamespaceEpoch
from sylanne3.graph_types import TypeRegistry
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_execution_bridge import CurrentEffectReadV2
from sylanne3.domains.d03 import ContextProvider, RoleBinding
from sylanne3.domains.d05 import BoundaryRule
from sylanne3.domains.d08 import (
    ActionCancellationState, ActionSchema, ActionSchemaRecord, Goal,
    GoalExecutionProvider,
)
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, D09ExpressionProvider, ExpressionClaim,
    SegmentCandidate,
)
from sylanne3.host.identity import astrbot_namespace
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.dispatch_candidate import DispatchCandidateEvidenceV1
from sylanne3.runtime.installed_dispatch_admission_issuer import (
    DispatchAdmissionHold, InstalledDispatchAdmissionIssuer,
    inspect_current_d06_source_grant,
    inspect_current_d03_d05,
    inspect_current_d11_dispatch_budget,
    inspect_current_d08_commitments,
    inspect_current_private_route,
    TrustedDispatchAdmissionContextV1,
)
from sylanne3.runtime_contracts import (
    FenceScope, NamespaceId, VersionedRef, canonical_digest,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime.dispatch_current_commitment_check import (
    CRITERIA_REF, CRITERIA_VERSION,
)
from sylanne3.runtime.issuers import D02ResourceIssuer, ResourceQuote
from sylanne3.runtime.budget import reserve_budget

from test_dispatch_admission_preflight import _candidates
from test_dispatch_budget_check import (
    _db as _budget_db, _intent as _budget_intent,
    CEILING, DIGEST, OPERATION,
)


def _social_case(*, effect="allow", rule_audience="entity:user"):
    from sylanne3.contracts import canonical_json
    db = sqlite3.connect(":memory:", isolation_level=None)
    db.executescript("""
        CREATE TABLE graph_epochs(bot TEXT,persona TEXT,revision INTEGER);
        CREATE TABLE graph_atoms(token TEXT,bot TEXT,persona TEXT,
            type_name TEXT,revision INTEGER,value TEXT,valid INTEGER);
    """)
    source = source_key("bot", "persona", "source-one")
    _, intent, batch, _, _ = _candidates(source_ref=source.token)
    role = RoleBinding(
        "binding:one", "persona:persona", "friend", "entity:user", None,
        "scene:one", "direct", "private", (), 0.0, None, 1,
        (source.token,), 2, "active",
    )
    boundary = BoundaryRule(
        "boundary:one", "persona:persona", "entity:user", "message",
        rule_audience, "scene:one", effect, "self_internal",
        (source.token,), (), (), 0.0, None, 1, "actor", (), "active",
    )
    versions = (
        (VersionedRef(source.token, 1), VersionedRef("d03.role_binding", 5),
         VersionedRef("binding:one", 2)),
        (VersionedRef(source.token, 1), VersionedRef("d05.boundary", 5),
         VersionedRef("boundary:one", 1)),
    )
    specs = list(intent.required_checks)
    for index in (0, 1):
        specs[index] = replace(specs[index], criteria_version=source.token,
                               required_input_versions=versions[index])
    intent = replace(intent, required_checks=tuple(specs))
    schema = ActionSchemaRecord.bind(
        intent, ActionSchema(intent.schema_id, intent.action_kind, False,
                             intent.required_checks),
    )
    owner = Owner("activity", "bot", "persona", intent.identity.activity_id)
    keys = (
        AtomKey(owner, "d08.action_intent.v1", intent.action_id),
        AtomKey(owner, "d08.action_schema.v1", schema.schema_ref),
        AtomKey(owner, "d09.verified_segment_batch.v1", batch["batch_id"]),
    )
    role_key = AtomKey(Owner("scene", "bot", "persona", "scene:one"),
                       "d03.role_binding", role.role_binding_id)
    boundary_key = AtomKey(Owner("relation", "bot", "persona", "entity:user"),
                           "d05.boundary_rule", boundary.rule_id)
    db.execute("INSERT INTO graph_epochs VALUES(?,?,?)", ("bot", "persona", 5))
    for key, revision, value in (
        (source, 1, {"source_id": "source-one"}),
        (keys[0], 1, asdict(intent)), (keys[1], 1, asdict(schema)),
        (keys[2], 1, batch), (role_key, 2, asdict(role)),
        (boundary_key, 1, asdict(boundary)),
    ):
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
            key.token, "bot", "persona", key.type_name, revision,
            canonical_json(json.loads(json.dumps(value))), 1,
        ))
    candidate = DispatchCandidateEvidenceV1(
        intent.identity.operation_id, keys[0].token, keys[1].token,
        "grant:one", keys[2].token, canonical_digest(intent),
        canonical_digest(schema), "1" * 64, batch["batch_digest"],
        intent.source_refs, (), (), 0, 0, 5, "source_qualified",
        tuple(batch["audiences"]), (), None,
    )
    context = ContextProvider()
    context.compile_scheme({
        "schema": "d03.context.scheme.v1", "roles": ("friend",), "norms": (),
    }, None)
    db.execute("BEGIN IMMEDIATE")
    return db, candidate, context, boundary_key


def _case():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE graph_epochs(bot TEXT,persona TEXT,revision INTEGER)")
    db.execute("CREATE TABLE graph_authority_epochs("
               "bot TEXT,persona TEXT,access_epoch INTEGER,delete_epoch INTEGER)")
    db.execute("CREATE TABLE graph_atoms("
               "token TEXT,bot TEXT,persona TEXT,revision INTEGER,"
               "value TEXT,valid INTEGER)")
    source = source_key("bot", "persona", "source-one")
    access = access_key("bot", "persona", "source-one")
    _schema, intent, *_ = _candidates(source_ref=source.token)
    pinned = (VersionedRef(source.token, 1), VersionedRef(access.token, 1))
    specs = tuple(replace(item, criteria_version=source.token,
                          required_input_versions=pinned)
                  if item.check_kind == "source_grant" else item
                  for item in intent.required_checks)
    intent = replace(intent, required_checks=specs)
    action_ref = AtomKey(
        Owner("activity", "bot", "persona", intent.identity.activity_id),
        "d08.action_intent.v1", intent.action_id,
    ).token
    values = ((source.token, {"source_id": "source-one"}),
              (access.token, {"source_id": "source-one", "status": "active"}))
    proof = tuple((ref, 1, canonical_digest(value)) for ref, value in values)
    candidate = DispatchCandidateEvidenceV1(
        intent.identity.operation_id, action_ref, "schema:one", "grant:one",
        "batch:one", canonical_digest(intent), "0" * 64, "1" * 64,
        "2" * 64, intent.source_refs, ((source.token, 1),),
        ((access.token, 1),), 3, 4, 7, "source_qualified",
        ("entity:user",), tuple((ref, version) for ref, version, _ in proof),
        canonical_digest(proof),
    )
    db.execute("INSERT INTO graph_epochs VALUES(?,?,?)", ("bot", "persona", 7))
    db.execute("INSERT INTO graph_authority_epochs VALUES(?,?,?,?)",
               ("bot", "persona", 3, 4))
    for ref, value in values:
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?)",
                   (ref, "bot", "persona", 1, json.dumps(value), 1))
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?)",
               (action_ref, "bot", "persona", 1, json.dumps(asdict(intent)), 1))
    db.commit()
    db.execute("BEGIN IMMEDIATE")
    return db, intent, specs[2], candidate


def test_d06_reads_current_rows_but_holds_without_independent_barrier():
    db, intent, spec, candidate = _case()
    try:
        inspection = inspect_current_d06_source_grant(
            db, intent, spec, candidate, audience=("entity:user",),
        )
        assert inspection.status == "hold"
        assert inspection.provider_result == "unknown"
        assert inspection.observed_versions == candidate.source_proof_versions
        assert inspection.missing == ("d06.independent_deletion_authority_barrier",)
        issuer = InstalledDispatchAdmissionIssuer()
        with pytest.raises(DispatchAdmissionHold) as error:
            issuer.issue_dispatch_admission(None, None, candidate, db,
                                            graph_incarnation="incarnation:one",
                                            now_utc=1.0)
        assert "d03.d05.installed_context_provider" in error.value.missing
        assert "d11.installed_signed_budget_grant_issuer" in error.value.missing
        assert issuer.verify_required_check(spec, None, None, db) is False
    finally:
        db.close()


def test_changed_row_or_epoch_cannot_reuse_qualified_candidate():
    db, intent, spec, candidate = _case()
    try:
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                   (json.dumps({"source_id": "replaced"}), intent.source_refs[0]))
        with pytest.raises(DispatchAdmissionHold) as error:
            inspect_current_d06_source_grant(
                db, intent, spec, candidate, audience=("entity:user",),
            )
        assert error.value.missing == ("d06.current_source_access_content",)
        db.execute("UPDATE graph_epochs SET revision=8")
        with pytest.raises(DispatchAdmissionHold) as error:
            inspect_current_d06_source_grant(
                db, intent, spec, candidate, audience=("entity:user",),
            )
        assert error.value.missing == ("d06.current_graph_epoch",)
    finally:
        db.close()


def test_no_graph_transaction_holds_before_reading():
    db, intent, spec, candidate = _case()
    try:
        db.rollback()
        with pytest.raises(DispatchAdmissionHold) as error:
            inspect_current_d06_source_grant(
                db, intent, spec, candidate, audience=("entity:user",),
            )
        assert error.value.missing == ("graph.current_write_transaction",)
    finally:
        db.close()


def test_d03_d05_scoped_receipts_come_from_complete_graph_rows():
    db, candidate, context, _ = _social_case()
    try:
        result = inspect_current_d03_d05(
            db, candidate, context=context, now_utc=2.0,
        )
        assert result.status == "checks_pass"
        assert result.missing == ()
        assert (result.role_receipt.result, result.boundary_receipt.result) == (
            "pass", "pass",
        )
        assert result.graph_epoch == 5
    finally:
        db.close()


@pytest.mark.parametrize("effect,scope,expected", [
    ("deny", "entity:user", "d05.current_boundary_not_pass"),
    ("allow", "conversation", "d05.audience_scope_mapping_unavailable"),
])
def test_d05_deny_and_unmapped_scope_hold(effect, scope, expected):
    db, candidate, context, _ = _social_case(
        effect=effect, rule_audience=scope,
    )
    try:
        result = inspect_current_d03_d05(
            db, candidate, context=context, now_utc=2.0,
        )
        assert result.status == "hold"
        assert expected in result.missing
    finally:
        db.close()


def test_current_boundary_row_change_recomputes_and_fails():
    db, candidate, context, key = _social_case()
    try:
        db.execute("UPDATE graph_atoms SET value=json_set(value,'$.effect','deny') "
                   "WHERE token=?", (key.token,))
        result = inspect_current_d03_d05(
            db, candidate, context=context, now_utc=2.0,
        )
        assert result.status == "hold"
        assert result.boundary_receipt.result == "fail"
    finally:
        db.close()


def test_new_boundary_rule_cannot_be_omitted_from_complete_read():
    db, candidate, context, key = _social_case()
    try:
        row = db.execute("SELECT value FROM graph_atoms WHERE token=?",
                         (key.token,)).fetchone()
        new_rule = {**json.loads(row[0]), "rule_id": "boundary:new",
                    "effect": "deny"}
        new_key = AtomKey(key.owner, key.type_name, "boundary:new")
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
            new_key.token, "bot", "persona", key.type_name, 1,
            json.dumps(new_rule), 1,
        ))
        result = inspect_current_d03_d05(
            db, candidate, context=context, now_utc=2.0,
        )
        assert result.status == "hold"
        assert "d05.current_boundary_not_pass" in result.missing
    finally:
        db.close()


def _signed_budget_case():
    db, d11 = _budget_db()
    d02 = D02ResourceIssuer(b"q" * 32)
    original = _budget_intent()
    quote = ResourceQuote(
        "quote:dispatch-one", 1, "bot", "persona",
        original.identity.activity_id, original.identity.operation_id,
        original.identity.effect_id, "parent", "message",
        "snapshot:dispatch-one", 20.0, "resource:dispatch-one",
        None, (), (), CEILING, None, 100.0,
    )
    d02.issue_quote(db, quote)
    reserve_budget(db, "parent", OPERATION, DIGEST, CEILING)
    spec = original.required_checks[0]
    quote_ref = "d02.resource_quote:" + quote.quote_id
    versions = (VersionedRef(quote_ref, quote.version),)
    versions += tuple(item for item in spec.required_input_versions
                      if item.ref != spec.criteria_version)
    intent = replace(original, required_checks=(replace(
        spec, criteria_version=quote_ref, required_input_versions=versions,
    ),))
    db.commit()
    db.execute("BEGIN IMMEDIATE")
    return db, d11, d02, intent


def test_signed_quote_is_the_budget_criteria_and_provider_passes_current_ledger():
    db, d11, d02, intent = _signed_budget_case()
    try:
        result = inspect_current_d11_dispatch_budget(
            db, intent, d11_issuer=d11, d02_issuer=d02, now_utc=10.0,
        )
        assert result.status == "check_pass"
        assert result.missing == ()
        assert (result.receipt.result, result.receipt.coverage) == ("pass", "full")
        assert result.receipt.input_versions == intent.required_checks[0].required_input_versions
    finally:
        db.close()


def test_unsigned_criteria_or_changed_signature_cannot_pass_budget():
    db, d11, d02, intent = _signed_budget_case()
    try:
        spec = intent.required_checks[0]
        changed = replace(intent, required_checks=(replace(
            spec, criteria_version="criteria:budget-1",
            required_input_versions=spec.required_input_versions +
            (VersionedRef("criteria:budget-1", 1),),
        ),))
        assert inspect_current_d11_dispatch_budget(
            db, changed, d11_issuer=d11, d02_issuer=d02,
            now_utc=10.0,
        ).missing == ("d11.criteria_not_signed_d02_quote_ref",)
        db.execute("UPDATE runtime_resource_quotes SET signature='tampered'")
        assert inspect_current_d11_dispatch_budget(
            db, intent, d11_issuer=d11, d02_issuer=d02,
            now_utc=10.0,
        ).missing == ("d11.current_signed_quote_grant_or_lease_unavailable",)
    finally:
        db.close()


def test_legacy_budget_spec_names_the_precise_missing_quote_version():
    db, d11, d02, _ = _signed_budget_case()
    try:
        result = inspect_current_d11_dispatch_budget(
            db, _budget_intent(), d11_issuer=d11, d02_issuer=d02,
            now_utc=10.0,
        )
        assert result.missing == (
            "d11.frozen_spec_missing_signed_d02_quote_version",
        )
        assert result.receipt is None
    finally:
        db.close()


def test_budget_quote_ceiling_and_reservation_state_are_current():
    db, d11, d02, intent = _signed_budget_case()
    try:
        db.execute("UPDATE runtime_budget_reservations SET ceiling_json=?",
                   (json.dumps({"model_microusd": 1}),))
        assert inspect_current_d11_dispatch_budget(
            db, intent, d11_issuer=d11, d02_issuer=d02,
            now_utc=10.0,
        ).missing == ("d11.signed_quote_reservation_scope_or_ceiling_differs",)
        db.execute("UPDATE runtime_budget_reservations SET state='settled'")
        assert inspect_current_d11_dispatch_budget(
            db, intent, d11_issuer=d11, d02_issuer=d02,
            now_utc=10.0,
        ).missing == ("d11.current_operation_reservation_unavailable",)
    finally:
        db.close()


def test_d08_complete_graph_inventory_identifies_unissued_authority_gates():
    db, candidate, _context, _key = _social_case()
    try:
        result = inspect_current_d08_commitments(db, candidate)
        assert result.status == "hold"
        assert result.graph_epoch == 5
        assert result.action_refs == ("action:one",)
        assert "d08.criteria_ref_has_no_authoritative_issuer" in result.missing
        assert "d08.current_pre_p2_authority_effect" in result.missing
        db.execute("UPDATE graph_epochs SET revision=6")
        assert inspect_current_d08_commitments(
            db, candidate,
        ).missing == ("d08.current_graph_epoch_differs",)
    finally:
        db.close()


def test_private_route_uses_committed_ingress_source_not_graph_token():
    account = json.dumps(["platform-1", "aiocqhttp", "bot-1"],
                         separators=(",", ":"))
    destination = json.dumps(["platform-1:FriendMessage:123", "123"],
                             separators=(",", ":"))
    namespace = NamespaceId(
        astrbot_namespace("platform-1", "bot-1", "route-check").bot_id,
        "persona",
    )
    source = source_key(*namespace.as_tuple, "source-one")
    _schema, intent, _batch, _request, _receipts, grant = _candidates(
        source_ref=source.token, include_grant=True,
    )
    grant = replace(grant, audiences=(destination,))
    scene = scene_ref_for_conversation(namespace, account, destination)
    use = ClaimUse("claim:one", 0, 5, ClaimKind.EXTERNAL_FACT)
    claim = ExpressionClaim("claim:one", "Hello", ClaimKind.EXTERNAL_FACT,
                            (source.token,), (destination,), ("expression",),
                            "disclosure:one")
    provider = D09ExpressionProvider()
    blueprint = provider.prepare_blueprint(grant, scene, 1, (claim,), now=1.0).blueprint
    batch = provider.build_verified_batch_v1(
        grant, blueprint,
        (SegmentCandidate("segment:one", intent.identity.effect_id,
                          "Hello", (use,), ("answer",), (), 0.0),),
        now=1.0,
    )
    batch_key = AtomKey(
        Owner("activity", *namespace.as_tuple, intent.identity.activity_id),
        "d09.verified_segment_batch.v1", batch["batch_id"],
    )
    candidate = DispatchCandidateEvidenceV1(
        intent.identity.operation_id, "action:unused", "schema:unused",
        "grant:unused", batch_key.token, "0" * 64, "1" * 64,
        "2" * 64, batch["batch_digest"], (source.token,), (), (),
        0, 0, 1, "source_qualified", (destination,), (), None,
    )
    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE graph_atoms(token TEXT,bot TEXT,persona TEXT,
            type_name TEXT,revision INTEGER,value TEXT,valid INTEGER);
        CREATE TABLE graph_first_ingress_identity_v1(
            bot TEXT,persona TEXT,source_ref TEXT,platform_ref TEXT,
            conversation_ref TEXT,visibility TEXT);
    """)
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
        batch_key.token, *namespace.as_tuple, batch_key.type_name, 1,
        json.dumps(batch), 1,
    ))
    db.execute("INSERT INTO graph_first_ingress_identity_v1 VALUES(?,?,?,?,?,?)", (
        *namespace.as_tuple, "source-one", account, destination, "private",
    ))
    db.commit()
    db.execute("BEGIN IMMEDIATE")
    try:
        verified = inspect_current_private_route(db, candidate, now_utc=2.0)
        assert (verified.status, verified.account_ref,
                verified.destination_ref, verified.scene_ref) == (
            "route_verified", account, destination, scene,
        )
        db.execute("UPDATE graph_first_ingress_identity_v1 "
                   "SET conversation_ref='wrong'")
        assert inspect_current_private_route(
            db, candidate, now_utc=2.0,
        ).status == "hold"
    finally:
        db.close()


def _d08_fixed_pre_p2_case():
    # The typed scope/effect here exercise mapping only. Production obtains
    # them from the installed V2 port before entering the graph transaction.
    db, candidate, _context, _key = _social_case()
    try:
        db.execute("ALTER TABLE graph_atoms ADD COLUMN name TEXT")
        for ref, in db.execute("SELECT token FROM graph_atoms").fetchall():
            db.execute("UPDATE graph_atoms SET name=? WHERE token=?",
                       (AtomKey.from_token(ref).name, ref))
        d08 = {item.name: item for item in GoalExecutionProvider().register_types()}
        row = db.execute("SELECT value FROM graph_atoms WHERE token=?",
                         (candidate.action_ref,)).fetchone()
        intent = d08["d08.action_intent.v1"].validator(json.loads(row[0]))
        checks = tuple(replace(item, criteria_version=CRITERIA_REF,
                               required_input_versions=(
                                   VersionedRef(CRITERIA_REF, CRITERIA_VERSION),
                                   VersionedRef(intent.goal_ref, 1),
                                   VersionedRef("commitments-query:persona:persona", 5),
                                   VersionedRef("execution-epoch:action:one", 0),
                                   VersionedRef("cancellation-epoch:action:one", 1),
                               )) if item.check_kind == "commitment_conflict" else item
                       for item in intent.required_checks)
        intent = replace(intent, required_checks=checks)
        schema = ActionSchemaRecord.bind(
            intent, ActionSchema(intent.schema_id, intent.action_kind, False, checks),
        )
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                   (json.dumps(asdict(intent)), candidate.action_ref))
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                   (json.dumps(asdict(schema)), candidate.schema_ref))
        goal = Goal(intent.goal_ref, 1, "active", intent.success_predicate,
                    (), (), None, (), ())
        cancellation = ActionCancellationState.for_action(
            intent, state="active", actor="host", source_refs=intent.source_refs,
            operation_id=intent.identity.operation_id,
        )
        for type_name, name, value in (
            ("d08.goal.v1", intent.goal_ref, goal),
            ("d08.action_cancellation.v1", intent.action_id, cancellation),
        ):
            key = AtomKey(Owner("activity", "bot", "persona",
                                intent.identity.activity_id), type_name, name)
            db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?)", (
                key.token, "bot", "persona", type_name, 1,
                json.dumps(asdict(value)), 1, name,
            ))
        candidate = replace(candidate, action_digest=canonical_digest(intent),
                            schema_digest=canonical_digest(schema), query_epoch=4)
        anchor = RestoreAnchor("authority", "ns", 1, "deletion", 0,
                               "genesis", "execution", 0, "genesis", 0,
                               "service-proof")
        permit = FencePermitV2("authority", "ns", "subject", "holder", 1,
                                "write", "attempt:one", "t" * 32, 1, 1, anchor)
        scope = FenceScope(NamespaceId("bot", "persona"), "ns", 1, "write",
                           "attempt:one", permit, anchor,
                           NamespaceEpoch("bot", "persona", 4), 1)
        effect = CurrentEffectReadV2("authority", "ns", "effect:one", 1,
                                     "absent", 0, "genesis")
        trusted = TrustedDispatchAdmissionContextV1(
            scope, None, None, None,
            GraphReceipt("committed", (), (), NamespaceEpoch("bot", "persona", 5)),
            None, effect,
        )
        return db, candidate, trusted, goal
    except BaseException:
        db.close()
        raise


def test_d08_fixed_pre_p2_policy_recomputes_current_goal_and_effect():
    db, candidate, trusted, goal = _d08_fixed_pre_p2_case()
    try:
        passed = inspect_current_d08_commitments(
            db, candidate, trusted_context=trusted, now_utc=2.0,
        )
        assert passed.status == "check_pass"
        assert passed.receipt.result == "pass"
        db.execute("UPDATE graph_atoms SET value=? WHERE type_name='d08.goal.v1'",
                   (json.dumps({**asdict(goal), "state": "abandoned"}),))
        blocked = inspect_current_d08_commitments(
            db, candidate, trusted_context=trusted, now_utc=2.0,
        )
        assert "d08.current_goal_not_active" in blocked.missing
    finally:
        db.close()


def test_production_store_transaction_d08_pre_p2_logic_only(tmp_path):
    # These graph rows are seeded directly; the Authority context is synthetic.
    # This verifies the installed reader against the production SQL schema and
    # transaction, not the V2 fence service or complete dispatch admission.
    fixture_db, candidate, trusted, _goal = _d08_fixed_pre_p2_case()
    store = ProductionGraphStore(tmp_path / "admission-logic.db", TypeRegistry())
    try:
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            store._db.execute(
                "INSERT INTO graph_epochs(bot,persona,revision) VALUES(?,?,?)",
                ("bot", "persona", 5),
            )
            for token, bot, persona, type_name, revision, value, valid, name in (
                fixture_db.execute(
                    "SELECT token,bot,persona,type_name,revision,value,valid,name "
                    "FROM graph_atoms"
                ).fetchall()
            ):
                key = AtomKey.from_token(token)
                store._db.execute(
                    "INSERT INTO graph_atoms("
                    "token,bot,persona,owner_kind,subject,type_name,name,"
                    "revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (token, bot, persona, key.owner.kind, key.owner.subject,
                     type_name, name, revision, value, valid),
                )
            passed = inspect_current_d08_commitments(
                store._db, candidate, trusted_context=trusted, now_utc=2.0,
            )
            assert passed.status == "check_pass"
            assert passed.receipt.result == "pass"
            revoked = replace(
                trusted,
                current_effect=CurrentEffectReadV2(
                    "authority", "ns", "effect:one", 1,
                    "executed", 1, "changed",
                ),
            )
            assert "d08.current_effect_not_absent_at_pinned_execution_head" in (
                inspect_current_d08_commitments(
                    store._db, candidate, trusted_context=revoked, now_utc=2.0,
                ).missing
            )
            original = AtomKey.from_token(candidate.action_ref)
            other = AtomKey(original.owner, original.type_name, "action:other")
            row = store._db.execute(
                "SELECT value FROM graph_atoms WHERE token=?",
                (candidate.action_ref,),
            ).fetchone()
            other_action = json.loads(row[0])
            other_action["action_id"] = "action:other"
            other_action["identity"]["operation_id"] = "operation:other"
            store._db.execute(
                "INSERT INTO graph_atoms("
                "token,bot,persona,owner_kind,subject,type_name,name,"
                "revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (other.token, "bot", "persona", other.owner.kind,
                 other.owner.subject, other.type_name, other.name, 1,
                 json.dumps(other_action), 1),
            )
            assert "d08.current_effect_shared_by_actions" in (
                inspect_current_d08_commitments(
                    store._db, candidate, trusted_context=trusted, now_utc=2.0,
                ).missing
            )
            store._db.execute("ROLLBACK")
    finally:
        fixture_db.close()
        store.close()


def test_d08_new_same_effect_action_is_visible_and_holds():
    db, candidate, _context, _key = _social_case()
    try:
        row = db.execute("SELECT value FROM graph_atoms WHERE token=?",
                         (candidate.action_ref,)).fetchone()
        action = json.loads(row[0])
        action["action_id"] = "action:other"
        action["identity"]["operation_id"] = "operation:other"
        original = AtomKey.from_token(candidate.action_ref)
        other = AtomKey(original.owner, original.type_name, "action:other")
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
            other.token, "bot", "persona", other.type_name, 1,
            json.dumps(action), 1,
        ))
        result = inspect_current_d08_commitments(db, candidate)
        assert result.status == "hold"
        assert result.action_refs == ("action:one", "action:other")
        assert "d08.current_effect_shared_by_actions" in result.missing
    finally:
        db.close()
