"""W01 persists only typed current D12 compilation under Owner and D11."""

import sqlite3
from uuid import uuid4

import pytest

from sylanne3.domains.d12.scheme_command import D12SchemeHold
from sylanne3.domains.d12.types import character_draft_key
from sylanne3.runtime.budget import (
    BudgetLease, create_budget_lease, install_schema as install_budget_schema,
)
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, D11BudgetGrantIssuer,
    install_schema as install_issuer_schema,
)
from sylanne3.runtime.d12_current_preview_plan_v1 import (
    read_current_d12_preview_plan_v1,
)
from sylanne3.runtime.d12_current_d07_policy_v1 import (
    read_current_d07_attention_policy_v1,
)
from sylanne3.runtime.d12_preview_behavior_original_v1 import (
    install_d12_preview_behavior_original_v1,
    read_d12_preview_behavior_original_v1,
    record_d12_preview_behavior_original_v1,
)
from sylanne3.runtime.d12_scheme_behavior_preview_v1 import (
    run_d12_scheme_behavior_preview_v1,
)
from sylanne3.runtime_contracts import canonical_digest
from tests.alpha1.d12.test_owner_graph_lease import NAMESPACE, owner_graph
from tests.alpha1.runtime.test_current_creator_draft_port_v1 import _creator_case
from tests.alpha1.runtime.test_d12_domain_scheme_compile_v1 import ATTENTION_POLICY


def _setup(owner_graph, fields, *, signed_kind="scheme_compile",
           activate=False):
    graph, coordinator, _, authority, lease = _creator_case(
        owner_graph,
        capabilities=["workbench.read", "workbench.compile",
                      "workbench.create", "workbench.experiment",
                      *(("workbench.activate",) if activate else ())],
        fields=fields,
    )
    issuer = D11BudgetGrantIssuer(b"d12-focused-budget-signing-key-012345")
    with graph._lock:
        db = graph._db
        db.execute("BEGIN IMMEDIATE")
        try:
            install_budget_schema(db)
            install_issuer_schema(db)
            budget = BudgetLease(
                "d12-budget", None, *NAMESPACE.as_tuple, "USD",
                {"cpu_ms": 1000, "thread_cpu_ms": 1000},
                {}, {}, {}, 1, "active",
            )
            create_budget_lease(db, budget, "d12-budget-create", "a" * 64)
            grant = BudgetLeaseGrant(
                "d12-grant", 1, *NAMESPACE.as_tuple, budget.lease_id,
                "USD", {"cpu_ms": 1000, "thread_cpu_ms": 1000},
                (("scheme_compile", "scheme_preview")
                 if signed_kind == "scheme_compile" else (signed_kind,)),
                1_000_000_000_000.0,
                "d12-budget-policy",
            )
            issuer.issue_budget_grant(db, grant)
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    coordinator._GraphCoordinator__d11_issuer = issuer
    return graph, coordinator, authority, lease


def test_current_d12_compile_persists_typed_candidate_and_original(owner_graph):
    fields = {"d02.body_profile": {
        "profile_id": "profile-1", "namespace": {
            "bot_id": NAMESPACE.bot_id, "persona_id": NAMESPACE.persona_id,
        }, "version": 1, "applicable_axes": ["energy"],
        "work_kinds": ["scheme_compile"],
    }}
    graph, coordinator, authority, lease = _setup(owner_graph, fields)
    operation = str(uuid4())
    original = coordinator.compile_current_scheme_for_operation_v1(
        authority, lease, operation_id=operation,
        draft_ref=character_draft_key(NAMESPACE).token,
        budget_ref="d12-budget",
    )
    assert original.operation_id == operation
    assert len(original.compiled.domain_receipts) == 1
    receipt = original.compiled.domain_receipts[0]
    assert receipt.domain == "d02" and receipt.candidate_ref.startswith(
        "d12-domain-candidate:")
    assert coordinator.read_compilation_original_v1(
        authority, lease, compiled_digest=original.compiled.compiled_digest,
    ) == original.compiled
    assert coordinator.compile_current_scheme_for_operation_v1(
        authority, lease, operation_id=operation,
        draft_ref=character_draft_key(NAMESPACE).token,
        budget_ref="d12-budget",
    ) == original
    with graph._lock:
        row = graph._db.execute(
            "SELECT candidate_digest,candidate_json FROM graph_d12_domain_candidates_v1 "
            "WHERE bot=? AND persona=? AND candidate_ref=?",
            (*NAMESPACE.as_tuple, receipt.candidate_ref),
        ).fetchone()
        assert row is not None and row[0] == receipt.candidate_ref.split(":", 1)[1]
        assert graph._db.execute(
            "SELECT COUNT(*) FROM graph_d12_compilation_operations_v1",
        ).fetchone() == (1,)
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            graph._db.execute(
                "DELETE FROM graph_d12_domain_candidates_v1 WHERE candidate_ref=?",
                (receipt.candidate_ref,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            graph._db.execute(
                "UPDATE graph_d12_compile_attempts_v1 SET request_digest='changed' "
                "WHERE operation_id=?", (operation,),
            )


def test_current_d12_compile_holds_unsupported_field_without_original(owner_graph):
    graph, coordinator, authority, lease = _setup(
        owner_graph, {"d01.voice": "clear"}, signed_kind="scheme_compile")
    with pytest.raises(D12SchemeHold):
        coordinator.compile_current_scheme_for_operation_v1(
            authority, lease, operation_id=str(uuid4()),
            draft_ref=character_draft_key(NAMESPACE).token,
            budget_ref="d12-budget",
        )
    with graph._lock:
        assert graph._db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND "
            "name='graph_d12_compilation_operations_v1'",
        ).fetchone() is None


def test_current_d12_compile_recovers_lost_finish_ack(owner_graph, monkeypatch):
    fields = {"d02.body_profile": {
        "profile_id": "profile-1", "namespace": {
            "bot_id": NAMESPACE.bot_id, "persona_id": NAMESPACE.persona_id,
        }, "version": 1, "applicable_axes": ["energy"],
        "work_kinds": ["scheme_compile"],
    }}
    graph, coordinator, authority, lease = _setup(owner_graph, fields)
    port = owner_graph[3]
    operation = str(uuid4())
    original_finish = port.finish_fence

    def lost_ack(scope, *, request_id, request_digest):
        original_finish(scope, request_id=request_id, request_digest=request_digest)
        if scope.operation == "write":
            raise RuntimeError("finish ACK lost after Authority committed")

    monkeypatch.setattr(port, "finish_fence", lost_ack)
    with pytest.raises(RuntimeError, match="ACK lost"):
        coordinator.compile_current_scheme_for_operation_v1(
            authority, lease, operation_id=operation,
            draft_ref=character_draft_key(NAMESPACE).token,
            budget_ref="d12-budget",
        )
    monkeypatch.setattr(port, "finish_fence", original_finish)
    recovered = coordinator.compile_current_scheme_for_operation_v1(
        authority, lease, operation_id=operation,
        draft_ref=character_draft_key(NAMESPACE).token,
        budget_ref="d12-budget",
    )
    assert recovered.operation_id == operation
    with graph._lock:
        assert graph._db.execute(
            "SELECT COUNT(*) FROM graph_d12_compilation_operations_v1",
        ).fetchone() == (1,)


def test_current_d12_compile_new_d07_candidate_is_durable(owner_graph):
    graph, coordinator, authority, lease = _setup(
        owner_graph, {"d07.attention_policy": ATTENTION_POLICY})
    original = coordinator.compile_current_scheme_for_operation_v1(
        authority, lease, operation_id=str(uuid4()),
        draft_ref=character_draft_key(NAMESPACE).token,
        budget_ref="d12-budget",
    )
    receipt = original.compiled.domain_receipts[0]
    assert receipt.domain == "d07"
    with graph._lock:
        assert graph._db.execute(
            "SELECT domain FROM graph_d12_domain_candidates_v1 "
            "WHERE bot=? AND persona=? AND candidate_ref=?",
            (*NAMESPACE.as_tuple, receipt.candidate_ref),
        ).fetchone() == ("d07",)


def test_current_d12_d07_preview_plan_rechecks_persisted_candidate(owner_graph):
    graph, coordinator, authority, lease = _setup(
        owner_graph, {"d07.attention_policy": ATTENTION_POLICY})
    original = coordinator.compile_current_scheme_for_operation_v1(
        authority, lease, operation_id=str(uuid4()),
        draft_ref=character_draft_key(NAMESPACE).token,
        budget_ref="d12-budget",
    )
    with graph._lock:
        db = graph._db
        db.execute("BEGIN")
        try:
            current_policy = read_current_d07_attention_policy_v1(db, NAMESPACE)
            assert current_policy.policy == current_policy.policy.default()
            assert current_policy.active_head_ref.revision == 1
            assert current_policy.compiled_digest is None
            compiled = original.compiled
            plan = read_current_d12_preview_plan_v1(
                db, NAMESPACE, operation_id=str(uuid4()),
                compiled_digest=compiled.compiled_digest,
                graph_revision=compiled.graph_revision,
                access_epoch=compiled.access_epoch,
                delete_epoch=compiled.delete_epoch,
            )
            assert plan.original == original
            assert plan.spec.candidate_digest == plan.candidate.candidate_digest
            assert plan.plan_digest
            report = run_d12_scheme_behavior_preview_v1(
                plan.spec, plan.baseline, plan.candidate)
            install_d12_preview_behavior_original_v1(db)
            record_d12_preview_behavior_original_v1(
                db, NAMESPACE, operation_id=plan.spec.operation_id,
                compiled_digest=compiled.compiled_digest,
                preview_seal="preview-seal", cost_ref="cost-ref",
                plan_digest=plan.plan_digest, report=report,
            )
            assert read_d12_preview_behavior_original_v1(
                db, NAMESPACE, operation_id=plan.spec.operation_id,
            ) == (compiled.compiled_digest, "preview-seal", "cost-ref",
                  plan.plan_digest, report)
            with pytest.raises(D12SchemeHold, match="not current"):
                read_current_d12_preview_plan_v1(
                    db, NAMESPACE, operation_id=str(uuid4()),
                    compiled_digest=compiled.compiled_digest,
                    graph_revision=compiled.graph_revision + 1,
                    access_epoch=compiled.access_epoch,
                    delete_epoch=compiled.delete_epoch,
                )
        finally:
            db.execute("ROLLBACK")


def test_current_d12_d07_preview_settles_cost_and_persists_behavior(owner_graph):
    graph, coordinator, authority, lease = _setup(
        owner_graph, {"d07.attention_policy": ATTENTION_POLICY})
    compiled = coordinator.compile_current_scheme_for_operation_v1(
        authority, lease, operation_id=str(uuid4()),
        draft_ref=character_draft_key(NAMESPACE).token,
        budget_ref="d12-budget",
    ).compiled
    operation_id = str(uuid4())
    preview = coordinator.preview_current_scheme_for_operation_v1(
        authority, lease, operation_id=operation_id,
        compiled_digest=compiled.compiled_digest,
        budget_ref="d12-budget",
    )
    assert preview.certificate.actual_cost_receipt_ref.startswith("d12-preview-cost:")
    assert preview.isolated_result.status == "isolated_preview_only"
    assert coordinator.read_preview_original_v1(
        authority, lease,
        preview_seal=preview.certificate.issuer_seal,
    ) == preview.certificate
    assert coordinator.preview_current_scheme_for_operation_v1(
        authority, lease, operation_id=operation_id,
        compiled_digest=compiled.compiled_digest,
        budget_ref="d12-budget",
    ) == preview
    with graph._lock:
        db = graph._db
        assert db.execute(
            "SELECT state FROM runtime_d12_preview_cost_v1 WHERE operation_id=?",
            (operation_id,),
        ).fetchone() == ("settled",)
        assert db.execute(
            "SELECT report_digest FROM graph_d12_preview_behavior_originals_v1 "
            "WHERE operation_id=?", (operation_id,),
        ).fetchone()[0]


def test_current_d12_preview_recovers_after_reserve_before_claim(owner_graph, monkeypatch):
    from sylanne3.runtime import d12_preview_budget_v1 as budget_module

    graph, coordinator, authority, lease = _setup(
        owner_graph, {"d07.attention_policy": ATTENTION_POLICY})
    compiled = coordinator.compile_current_scheme_for_operation_v1(
        authority, lease, operation_id=str(uuid4()),
        draft_ref=character_draft_key(NAMESPACE).token,
        budget_ref="d12-budget",
    ).compiled
    operation_id = str(uuid4())
    original_claim = budget_module.claim_d12_preview_run_v1

    def crash_before_claim(*_args, **_kwargs):
        raise RuntimeError("crash after committed reservation")

    monkeypatch.setattr(budget_module, "claim_d12_preview_run_v1", crash_before_claim)
    with pytest.raises(RuntimeError, match="committed reservation"):
        coordinator.preview_current_scheme_for_operation_v1(
            authority, lease, operation_id=operation_id,
            compiled_digest=compiled.compiled_digest, budget_ref="d12-budget",
        )
    monkeypatch.setattr(budget_module, "claim_d12_preview_run_v1", original_claim)
    with graph._lock:
        assert graph._db.execute(
            "SELECT state FROM runtime_d12_preview_cost_v1 WHERE operation_id=?",
            (operation_id,),
        ).fetchone() == ("prepared",)
    preview = coordinator.preview_current_scheme_for_operation_v1(
        authority, lease, operation_id=operation_id,
        compiled_digest=compiled.compiled_digest, budget_ref="d12-budget",
    )
    assert preview.certificate.actual_cost_receipt_ref.startswith("d12-preview-cost:")


def test_current_d12_preview_claimed_unknown_keeps_budget_and_never_reruns(
        owner_graph, monkeypatch):
    from sylanne3.runtime import d12_preview_budget_v1 as budget_module

    graph, coordinator, authority, lease = _setup(
        owner_graph, {"d07.attention_policy": ATTENTION_POLICY})
    compiled = coordinator.compile_current_scheme_for_operation_v1(
        authority, lease, operation_id=str(uuid4()),
        draft_ref=character_draft_key(NAMESPACE).token,
        budget_ref="d12-budget",
    ).compiled
    operation_id = str(uuid4())
    original_run = budget_module.run_d12_preview_once_v1

    def lost_report(*_args, **_kwargs):
        raise RuntimeError("sandbox report lost after claim")

    monkeypatch.setattr(budget_module, "run_d12_preview_once_v1", lost_report)
    with pytest.raises(RuntimeError, match="report lost"):
        coordinator.preview_current_scheme_for_operation_v1(
            authority, lease, operation_id=operation_id,
            compiled_digest=compiled.compiled_digest, budget_ref="d12-budget",
        )
    monkeypatch.setattr(budget_module, "run_d12_preview_once_v1", original_run)
    with pytest.raises(D12SchemeHold, match="unknown"):
        coordinator.preview_current_scheme_for_operation_v1(
            authority, lease, operation_id=operation_id,
            compiled_digest=compiled.compiled_digest, budget_ref="d12-budget",
        )
    with graph._lock:
        db = graph._db
        assert db.execute(
            "SELECT state FROM runtime_d12_preview_cost_v1 WHERE operation_id=?",
            (operation_id,),
        ).fetchone() == ("pending_confirmation",)
        assert db.execute(
            "SELECT COUNT(*) FROM graph_d12_preview_operations_v1 "
            "WHERE operation_id=?", (operation_id,),
        ).fetchone() == (0,)


def test_current_d12_preview_recovers_lost_finish_ack(owner_graph, monkeypatch):
    graph, coordinator, authority, lease = _setup(
        owner_graph, {"d07.attention_policy": ATTENTION_POLICY})
    compiled = coordinator.compile_current_scheme_for_operation_v1(
        authority, lease, operation_id=str(uuid4()),
        draft_ref=character_draft_key(NAMESPACE).token,
        budget_ref="d12-budget",
    ).compiled
    operation_id = str(uuid4())
    port = owner_graph[3]
    finish = port.finish_fence

    def lost_ack(scope, *, request_id, request_digest):
        finish(scope, request_id=request_id, request_digest=request_digest)
        if scope.operation == "write":
            raise RuntimeError("preview finish ACK lost")

    monkeypatch.setattr(port, "finish_fence", lost_ack)
    with pytest.raises(RuntimeError, match="ACK lost"):
        coordinator.preview_current_scheme_for_operation_v1(
            authority, lease, operation_id=operation_id,
            compiled_digest=compiled.compiled_digest, budget_ref="d12-budget",
        )
    monkeypatch.setattr(port, "finish_fence", finish)
    replay = coordinator.preview_current_scheme_for_operation_v1(
        authority, lease, operation_id=operation_id,
        compiled_digest=compiled.compiled_digest, budget_ref="d12-budget",
    )
    assert replay.certificate.compiled_digest == compiled.compiled_digest
    with graph._lock:
        assert graph._db.execute(
            "SELECT COUNT(*) FROM graph_d12_preview_operations_v1 "
            "WHERE operation_id=?", (operation_id,),
        ).fetchone() == (1,)


def test_current_d12_compile_requires_signed_exact_work_kind(owner_graph):
    graph, coordinator, authority, lease = _setup(
        owner_graph, {"d07.attention_policy": ATTENTION_POLICY},
        signed_kind="message",
    )
    with pytest.raises(D12SchemeHold):
        coordinator.compile_current_scheme_for_operation_v1(
            authority, lease, operation_id=str(uuid4()),
            draft_ref=character_draft_key(NAMESPACE).token,
            budget_ref="d12-budget",
        )
    with graph._lock:
        assert graph._db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='graph_d12_domain_candidates_v1'",
        ).fetchone() is None
