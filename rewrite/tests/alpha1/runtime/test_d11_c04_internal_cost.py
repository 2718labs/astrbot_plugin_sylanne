"""C04 CPU import charges only signed historical work, once."""

from dataclasses import replace
import hashlib
import json
import sqlite3

import pytest

from sylanne3.authority_service.contract import JournalHead
from sylanne3.authority_service.internal_work_contract import (
    InternalWorkBindingV1, InternalWorkTerminalProofV1,
    InternalWorkTerminalV2, _phase_id, claim_internal_work_v1,
)
from sylanne3.authority_service.internal_work_service import AuthorityInternalWorkService
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.domains.d02 import BodyDomain, BodyProfile, BodyState, WorkComponent
from sylanne3.domains.d02.body_quote_original import (
    D02BodyQuoteAuthority, FixedBodyPolicyV1, install_body_quote_schema,
)
from sylanne3.domains.d02.c04_fixed_component_cost import (
    read_c04_body_cost_original_v1, record_committed_c04_body_cost_v1,
    stage_c04_fixed_component_cost_v1,
)
from sylanne3.domains.d02.resource_outcome_verifier import outcome_verifier
from sylanne3.runtime.budget import (
    BudgetLease, create_budget_lease, get_budget_lease, install_schema as install_budget,
    reserve_budget,
)
from sylanne3.runtime.c04_internal_work_original_v1 import (
    C04InternalWorkPreparedV1, install_c04_internal_work_original_v1,
    record_c04_internal_work_prepared_v1,
)
from sylanne3.runtime.d11_c04_internal_cost import (
    C04CostHold, import_c04_cpu_terminal_v1, read_c04_cpu_cost_original_v1,
)
from sylanne3.runtime.issuers import (
    D02ResourceIssuer, ResourceQuote, install_schema as install_issuers,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest
from tests.alpha1.runtime.test_d02_body_quote_original import _envelope


BUILD = "e" * 64


@pytest.mark.parametrize("status,actual", [("failed", 9), ("completed", 23)])
def test_signed_terminal_import_and_replay(tmp_path, status, actual):
    namespace = NamespaceId("bot", "persona")
    db = sqlite3.connect(tmp_path / "business.sqlite")
    install_budget(db)
    install_issuers(db)
    install_body_quote_schema(db)
    issuer = D02ResourceIssuer(b"resource-key" * 3,
                               outcome_verifier=outcome_verifier)
    body_authority = D02BodyQuoteAuthority(b"body-key" * 4)
    create_budget_lease(
        db, BudgetLease("lease", None, "bot", "persona", "USD",
                        {"cpu_ms": 100}, {}, {}, {}, 1, "active"),
        "create", "1" * 64,
    )
    settlement_ref = AtomKey(
        Owner("activity", "bot", "persona", "activity"),
        "d02.settlement.v1", "settlement",
    ).token
    quote = ResourceQuote(
        "quote", 1, "bot", "persona", "activity", "operation",
        "effect", "lease", "d06.c04_internal_cpu.v1", "snapshot",
        4_102_444_800.0, "resource", None, (), (settlement_ref,),
        {"cpu_ms": 10}, None, 4_102_444_900.0,
    )
    issuer.issue_quote(db, quote)
    profile = BodyProfile("profile", namespace, 1, ("energy",),
                          (quote.work_kind,))
    state = BodyState("profile", 1, 0.8,
                      {quote.work_kind: 0.0}, 0.0, 0.0)
    policy = FixedBodyPolicyV1(
        "body-policy", 1, profile, state, quote.work_kind,
        WorkComponent("component", "cognition", 0.1),
        4_102_444_900.0,
    )
    body_authority.install_policy(db, policy)
    issued = body_authority.issue_fixed_quote_and_reservation(
        db, issuer, _envelope(quote), quote, policy.policy_id,
        policy.version, state, (), "reservation", "effect",
    )
    reservation_ref = issued.reservation_write.key.token
    binding = InternalWorkBindingV1(
        namespace_ref(namespace), "activity", "operation", "execution",
        "a" * 64, quote.quote_id, quote.version, canonical_digest(quote),
        issued.body_quote.quote_id, 1, canonical_digest(issued.body_quote),
        reservation_ref,
        "component", "lease", 1, "d06.association_activation.v2",
        "policy", BUILD,
    )
    budget_operation = "c04-internal-budget:" + binding.binding_digest
    reserve_budget(db, "lease", budget_operation, binding.binding_digest,
                   {"cpu_ms": 10})
    reserve_receipt = db.execute(
        "SELECT receipt_json FROM runtime_budget_operations "
        "WHERE operation_id=? AND phase='reserve'", (budget_operation,),
    ).fetchone()[0]
    reservation_digest = hashlib.sha256(reserve_receipt.encode()).hexdigest()
    prepared = C04InternalWorkPreparedV1(
        binding, BodyDomain.profile_write(profile).key.token, 1,
        BodyDomain.state_write(namespace, state).key.token, 1, 1,
        "owner-ref", 1, "c" * 64, budget_operation, reservation_digest,
        ((BodyDomain.state_write(namespace, state).key.token, 1),
         (reservation_ref, 1)), 2, 1, 0,
    )
    db.commit()
    db.execute("BEGIN IMMEDIATE")
    install_c04_internal_work_original_v1(db)
    record_c04_internal_work_prepared_v1(db, namespace, prepared)
    db.commit()

    journal = AuthorityV2ExecutionJournal(
        tmp_path / "journal.sqlite", namespace=binding.namespace,
        journal_id="journal", create=True,
    )
    service = AuthorityInternalWorkService(
        journal, core_head_verifier=lambda head: head == journal.verified_head(),
        component_signing_key=b"component-key" * 3,
        installed_build_digest=BUILD,
        trusted_manifest_sha256="f" * 64,
        installed_build_attestation={
            "schema": "sylanne.d06.algorithm-build.v1",
            "algorithm_id": "d06.association_activation.v2",
            "manifest_sha256": "f" * 64,
            "package_mode": "formal-alpha1",
            "status": "formal_package_bytes_only",
            "build_digest": "sha256:" + BUILD,
        },
    )
    claim = claim_internal_work_v1(binding)
    terminal_args = (
        binding.binding_digest, claim.mutation_id,
        _phase_id(binding.binding_digest, "terminal"), status, actual,
        binding.algorithm_ref, BUILD, binding.input_digest,
    )
    if status == "completed":
        from sylanne3.contracts import canonical_json

        terminal = InternalWorkTerminalV2(
            *terminal_args, "d" * 64,
            canonical_json({
                "input_digest": "sha256:" + binding.input_digest,
                "result_digest": "sha256:" + "d" * 64,
            }),
            "internal-work:component:" + binding.binding_digest,
            "0" * 64, "0" * 64, "0" * 64,
        )
        digest, signature = service.sign_component_completion(binding, terminal)
        terminal = replace(terminal, component_receipt_digest=digest,
                           component_receipt_signature=signature)
    else:
        terminal = InternalWorkTerminalV2(
            *terminal_args, None, None, None, None, None, "0" * 64,
        )
    terminal = replace(
        terminal, execution_signature=service.sign_execution_terminal(terminal),
    )
    with journal.freeze_writes():
        claim_append = journal.append_internal_work_claim_v1(
            binding, claim, JournalHead("journal", 0, "genesis"),
        )
        terminal_append = journal.append_internal_work_terminal_v1(
            binding, claim, terminal, journal.verified_head(),
        )
    proof = InternalWorkTerminalProofV1(
        binding, claim, terminal,
        claim_append.receipt_ref, claim_append.content_digest,
        terminal_append.receipt_ref, terminal_append.content_digest,
        journal.verified_head(),
    )
    try:
        original = import_c04_cpu_terminal_v1(
            db, namespace, "operation", proof, service, issuer,
        )
        assert original.actual_cpu_ms == actual
        assert original.status == status
        assert original.component_completed is (status == "completed")
        assert original.budget_receipt_status == ("overrun" if actual > 10
                                                  else "settled")
        assert get_budget_lease(db, "lease").used == {"cpu_ms": actual}
        assert import_c04_cpu_terminal_v1(
            db, namespace, "operation", proof, service, issuer,
        ) == original
        assert get_budget_lease(db, "lease").used == {"cpu_ms": actual}
        assert read_c04_cpu_cost_original_v1(
            db, namespace, "operation") == original
        if status == "completed":
            db.execute("BEGIN IMMEDIATE")
            body_cost = stage_c04_fixed_component_cost_v1(
                db, namespace, "operation", proof, issuer,
                body_authority, state, issued.reservation,
            )
            assert tuple(write.key.type_name for write in body_cost.writes) == (
                "d02.body_state.v1", "d02.reservation.v1",
                "d02.settlement.v1",
            )
            assert body_cost.actual_fixed_cost == 0.1
            assert body_cost.writes[0].value["energy"] == pytest.approx(0.7)
            assert body_cost.settlement_ref == settlement_ref
            db.execute("CREATE TABLE graph_atoms(token TEXT PRIMARY KEY, "
                       "revision INTEGER,value TEXT,valid INTEGER)")
            for revision, write in zip((2, 2, 1), body_cost.writes):
                db.execute("INSERT INTO graph_atoms VALUES(?,?,?,1)",
                           (write.key.token, revision, json.dumps(write.value)))
            body_original = record_committed_c04_body_cost_v1(
                db, namespace, "operation", proof, body_cost,
            )
            assert read_c04_body_cost_original_v1(
                db, namespace, "operation") == body_original
            db.rollback()  # GraphCoordinator owns the real three-write CAS.
        with pytest.raises(C04CostHold):
            import_c04_cpu_terminal_v1(
                db, namespace, "operation", replace(proof, terminal=replace(
                    terminal, actual_cpu_ms=actual + 1)), service, issuer,
            )
    finally:
        journal.close()
        db.close()
