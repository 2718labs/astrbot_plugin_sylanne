"""Owner correction writes are admitted by the production V2 graph path."""

from dataclasses import replace
import hashlib
import json
from uuid import uuid4

import pytest

from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, canonical_digest as owner_contract_digest,
)
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.contracts import canonical_json
from sylanne3.domains.d07 import D07DomainProvider
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_coordinator import AuthorityDenied, UnavailableGuard
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.host.authority_profile import (
    AdminD06SourceCorrectionPolicy, AdminIngressClockPolicy,
)
from sylanne3.memory_types import (
    InterpretationRecord, SourceRecord, access_key, interpretation_key, source_key,
)
from sylanne3.workbench_api.source_correction import SourceCorrectionRequestV1
from sylanne3.workbench_api import (
    AuthenticatedSession, GraphWorkbenchIssuer, RequestContext, WorkbenchService,
)

from test_graph_v2_provisioning import _owner_issue_case


def _request(namespace, source_ref, target_ref, access_epoch, deletion_epoch, *,
             operation_id=None, statement="I meant something else"):
    operation_id = operation_id or str(uuid4())
    payload = {
        "schema": "d12.source_correction.v1", "correction_kind": "source_claim",
        "statement": statement, "source_refs": [source_ref],
        "target_refs": [target_ref], "access_epoch": access_epoch,
        "deletion_epoch": deletion_epoch,
    }
    command = {
        "action": "correct_or_edit", "scope": "/".join(namespace.as_tuple),
        "purpose": "workbench_user_action", "audience": "owner",
        "operation_id": operation_id, "input": payload,
    }
    digest = "sha256:" + hashlib.sha256(json.dumps(
        command, sort_keys=True, separators=(",", ":"),
        allow_nan=False).encode()).hexdigest()
    return SourceCorrectionRequestV1(
        namespace, operation_id, digest, statement, (source_ref,),
        (target_ref,), access_epoch, deletion_epoch)


def _case(tmp_path):
    d07 = D07DomainProvider()
    (store, authority_db, port, coordinator, policy, operation,
     pending, grant_value, bootstrap) = _owner_issue_case(
         tmp_path, first_ingress=True, role_types=True,
         return_bootstrap=True, extra_specs=d07.type_specs(),
         owner_capabilities=("workbench.read", "workbench.correct"),
         extra_work_kinds=("d06.source_correction",),
     )
    namespace = policy.namespace
    port.pending_owner = pending
    proof = coordinator.commit_first_owner_grant_v2(
        bootstrap, namespace=namespace, operation_id=operation.operation_id,
        grant_value=grant_value)
    guard = OwnerAuthorizationGuardV1(
        operation.authority_id, operation.installation_id, namespace,
        1, owner_contract_digest(proof), 0, 0)

    def guarded(*, namespace, authority_namespace, permit, **session_kwargs):
        port.outside_graph_lock()
        assert session_kwargs["owner_actor_id"] == "paired-owner"
        assert session_kwargs["owner_session_token"] == "A" * 43
        assert session_kwargs["owner_session_request"].principal == operation.principal
        return guard, permit

    port.get_current_owner_guard_for_fence = guarded
    coordinator._GraphCoordinator__owner_principal_resolver = (
        lambda actor, current: operation.principal
        if (actor, current) == ("paired-owner", namespace) else None)
    coordinator.register_provider(
        bootstrap, "d07", d07, "d07.proposal.v1",
        d07.descriptor.request_schema_hash)
    coordinator._GraphCoordinator__scene_clock_policy = AdminIngressClockPolicy(
        "fixture-paired-clock", 0.1, 1.0)
    source = source_key(*namespace.as_tuple, "source-1")
    access = access_key(*namespace.as_tuple, "source-1")
    parent = source_key(*namespace.as_tuple, "parent-1")
    parent_access = access_key(*namespace.as_tuple, "parent-1")
    target = interpretation_key(*namespace.as_tuple, "interpretation-1")
    belief = AtomKey(Owner("persona", *namespace.as_tuple),
                     "d07.belief_revision.v1", "belief-1")
    values = {
        source: SourceRecord(
            "source-1", "private old claim", "owner", "reported", "reported",
            1.0, 2.0, "family-1", ("owner",), ("context",),
            ("parent-1",)).to_dict(),
        parent: SourceRecord(
            "parent-1", "private ancestor", "owner", "reported", "reported",
            0.5, 1.0, "family-1", ("owner",), ("context",)).to_dict(),
        access: {"source_id": "source-1", "audiences": ["owner"],
                 "purposes": ["context"], "status": "active", "recorded_at": 2.0},
        parent_access: {"source_id": "parent-1", "audiences": ["owner"],
                        "purposes": ["context"], "status": "active",
                        "recorded_at": 1.0},
        target: InterpretationRecord(
            "interpretation-1", ("source-1",), "owner", "Old belief",
            "reported", 1.0, 2.0).to_dict(),
        belief: {
            "schema": "d07.belief_revision.v1", "belief_id": "belief-1",
            "question_key": "question-1", "hypothesis_ref": "hypothesis-1",
            "proposition": "Old belief", "stance": "support",
            "subjective_conviction": 0.6, "evidence_status": "insufficient",
            "eligibility": ["subjective_reaction"],
            "source_refs": [source.token, target.token],
            "source_families": ["family-1"], "current": True,
            "historical": True, "replaced_by": None,
            "invalidation_refs": [], "invalidation_kind": None,
        },
    }
    with store._lock:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        try:
            for key, value in values.items():
                db.execute(
                    "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,"
                    "type_name,name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,1)",
                    (key.token, *namespace.as_tuple, key.owner.kind,
                     key.owner.subject, key.type_name, key.name, 1,
                     canonical_json(value)),
                )
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    anchor = port.anchors[namespace]
    login = OwnerSessionLoginRequestV1(
        anchor.authority_id, anchor.namespace,
        port.installation_grant.installation_id, operation.principal,
        "credential:owner", 1, "owner", "http://localhost")
    policy_price = AdminD06SourceCorrectionPolicy(
        30.0, {"cpu_ms": 5}, "snapshot-1", "resource-1")
    epochs = store._db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    request = _request(namespace, source.token, target.token, *epochs)
    kwargs = dict(
        actor_id="paired-owner", principal=operation.principal,
        purpose="workbench_user_action", audience="owner",
        installation_policy=policy, admin_policy=policy_price,
        owner_session_token="A" * 43, owner_session_request=login,
    )
    return ((store, authority_db, coordinator, namespace), request, kwargs,
            source, parent_access, target, belief)


def test_source_correction_commits_atomic_bundle_and_replays_exact_receipt(tmp_path):
    case, request, kwargs, source, _, target, belief = _case(tmp_path)
    store, authority_db, coordinator, namespace = case
    try:
        receipt = coordinator.commit_source_correction_v1(request=request, **kwargs)
        assert receipt.operation_id == request.operation_id
        assert receipt.source_refs == request.source_refs
        assert receipt.invalidated_target_refs == request.target_refs
        assert coordinator.commit_source_correction_v1(request=request, **kwargs) == receipt
        db = store._db
        correction = db.execute(
            "SELECT value FROM graph_atoms WHERE token=?",
            (receipt.correction_source_ref,)).fetchone()
        assert json.loads(correction[0])["source_kind"] == "reported"
        head = source_correction_head_key(namespace, source.owner.subject)
        head_row = db.execute(
            "SELECT revision,value FROM graph_atoms WHERE token=?",
            (head.token,)).fetchone()
        assert head_row[0] == 1
        assert json.loads(head_row[1]) == {
            "source_ref": source.token, "source_revision": 1,
            "correction_source_ref": receipt.correction_source_ref,
            "target_refs": [target.token], "operation_id": request.operation_id,
            "state": "pending_reevaluation", "access_epoch": request.access_epoch,
            "deletion_epoch": request.deletion_epoch,
        }
        assert db.execute(
            "SELECT revision FROM graph_atoms WHERE token=?",
            (source.token,)).fetchone() == (1,)
        detail = json.loads(db.execute(
            "SELECT receipt_json FROM graph_bundle_operations WHERE operation_id=?",
            (request.operation_id,)).fetchone()[0])["source_correction"]
        assert detail["correction_head_refs"] == [head.token]
        assert json.loads(db.execute(
            "SELECT value FROM graph_atoms WHERE token=?",
            (target.token,)).fetchone()[0])["status"] == "retracted"
        assert json.loads(db.execute(
            "SELECT value FROM graph_atoms WHERE token=?",
            (belief.token,)).fetchone()[0])["current"] is False
        assert db.execute(
            "SELECT COUNT(*) FROM runtime_jobs WHERE operation_id=?",
            (request.operation_id,)).fetchone() == (1,)
        assert db.execute(
            "SELECT phase FROM graph_bundle_outbox WHERE outbox_ref=?",
            (receipt.reevaluation_outbox_ref,)).fetchone() == ("pending",)
        changed = _request(
            namespace, source.token, target.token, request.access_epoch,
            request.deletion_epoch, operation_id=request.operation_id,
            statement="Different claim")
        with pytest.raises(UnavailableGuard):
            coordinator.commit_source_correction_v1(request=changed, **kwargs)
    finally:
        store.close()
        authority_db.close()


def test_workbench_command_reaches_owner_fenced_correction_commit(tmp_path):
    case, request, kwargs, _, _, _, _ = _case(tmp_path)
    store, authority_db, coordinator, namespace = case
    scope = "/".join(namespace.as_tuple)

    class NoReadGrants:
        def resolve(self, **_):
            raise AssertionError("correction must not use a workbench read lease")

    class NoViews:
        def view_types(self, *_):
            return {}

    session = AuthenticatedSession(
        kwargs["actor_id"], "dashboard-session",
        {scope: frozenset({"workbench.correct"})},
        {scope: frozenset({"owner"})},
        {scope: frozenset({"workbench_user_action"})},
        owner_session_token=kwargs["owner_session_token"],
        owner_session_request=kwargs["owner_session_request"],
    )
    command = {
        "schema_version": "d12.contract.v1", "action": "correct_or_edit",
        "scope": scope, "purpose": "workbench_user_action", "audience": "owner",
        "operation_id": request.operation_id,
        "input": {
            "schema": request.schema, "correction_kind": "source_claim",
            "statement": request.statement,
            "source_refs": list(request.source_refs),
            "target_refs": list(request.target_refs),
            "access_epoch": request.access_epoch,
            "deletion_epoch": request.deletion_epoch,
        },
    }
    issuer = GraphWorkbenchIssuer(
        coordinator, NoReadGrants(), NoViews(),
        correction_installation_policy=kwargs["installation_policy"],
        correction_admin_policy=kwargs["admin_policy"],
    )
    try:
        response = WorkbenchService(issuer).handle(
            command, session=session, context=RequestContext(True, True, True))
        assert response.status == "ready"
        assert response.receipt["phase"] == "source_correction_committed"
        assert response.receipt["request_digest"] == request.request_digest
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_bundle_operations WHERE operation_id=?",
            (request.operation_id,)).fetchone() == (1,)
    finally:
        store.close()
        authority_db.close()


def test_source_correction_rejects_stale_epoch_and_revoked_ancestor(tmp_path):
    case, request, kwargs, _, parent_access, _, _ = _case(tmp_path)
    store, authority_db, coordinator, _ = case
    try:
        stale = _request(
            request.namespace, request.source_refs[0], request.target_refs[0],
            request.access_epoch + 1, request.deletion_epoch)
        with pytest.raises(UnavailableGuard):
            coordinator.commit_source_correction_v1(request=stale, **kwargs)
        row = store._db.execute(
            "SELECT value FROM graph_atoms WHERE token=?",
            (parent_access.token,)).fetchone()
        store._db.execute(
            "UPDATE graph_atoms SET value=?,revision=revision+1 WHERE token=?",
            (canonical_json({**json.loads(row[0]), "status": "withdrawn"}),
             parent_access.token),
        )
        with pytest.raises(UnavailableGuard):
            coordinator.commit_source_correction_v1(request=request, **kwargs)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_bundle_operations WHERE operation_id=?",
            (request.operation_id,)).fetchone() == (0,)
        assert store._db.execute(
            "SELECT COUNT(*) FROM runtime_resource_quotes").fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()


def test_source_correction_with_no_dependent_belief_still_queues_reevaluation(tmp_path):
    case, request, kwargs, _, _, _, belief = _case(tmp_path)
    store, authority_db, coordinator, _ = case
    try:
        store._db.execute("DELETE FROM graph_atoms WHERE token=?", (belief.token,))
        receipt = coordinator.commit_source_correction_v1(request=request, **kwargs)
        assert receipt.phase == "source_correction_committed"
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_bundle_outbox WHERE outbox_ref=?",
            (receipt.reevaluation_outbox_ref,)).fetchone() == (1,)
    finally:
        store.close()
        authority_db.close()


def test_quote_drift_rolls_back_quote_and_all_graph_writes(tmp_path, monkeypatch):
    case, request, kwargs, _, _, target, belief = _case(tmp_path)
    store, authority_db, coordinator, _ = case
    try:
        issuer = coordinator._GraphCoordinator__d11_issuer
        original = issuer.issue_d06_source_correction_quote

        def drift(*args, **kwargs):
            original(*args, **kwargs)
            return replace(kwargs["planned_quote"], version=2)

        monkeypatch.setattr(issuer, "issue_d06_source_correction_quote", drift)
        with pytest.raises(AuthorityDenied, match="quote plan changed"):
            coordinator.commit_source_correction_v1(request=request, **kwargs)
        db = store._db
        assert db.execute("SELECT COUNT(*) FROM runtime_resource_quotes").fetchone() == (0,)
        assert db.execute(
            "SELECT COUNT(*) FROM graph_bundle_operations WHERE operation_id=?",
            (request.operation_id,)).fetchone() == (0,)
        assert json.loads(db.execute(
            "SELECT value FROM graph_atoms WHERE token=?",
            (target.token,)).fetchone()[0])["status"] == "reported"
        assert json.loads(db.execute(
            "SELECT value FROM graph_atoms WHERE token=?",
            (belief.token,)).fetchone()[0])["current"] is True
    finally:
        store.close()
        authority_db.close()


def test_unfinished_attempt_holds_without_repricing_or_rewriting(tmp_path):
    case, request, kwargs, _, _, _, _ = _case(tmp_path)
    store, authority_db, coordinator, namespace = case
    try:
        store._db.execute(
            "INSERT INTO graph_bundle_intents_v2"
            "(bot,persona,operation_id,digest,fence_attempt_id,"
            "requirements_json,anchor_json,graph_revision,graph_epoch) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            namespace.as_tuple + (request.operation_id, "old-digest",
                                  "unfinished-attempt", "{}", "{}", 1, 1),
        )
        with pytest.raises(UnavailableGuard, match="outcome unknown"):
            coordinator.commit_source_correction_v1(request=request, **kwargs)
        assert store._db.execute(
            "SELECT COUNT(*) FROM runtime_resource_quotes").fetchone() == (0,)
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_bundle_operations WHERE operation_id=?",
            (request.operation_id,)).fetchone() == (0,)
    finally:
        store.close()
        authority_db.close()
