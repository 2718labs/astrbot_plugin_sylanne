"""C04 policy and preparation gates under one real signed Owner graph."""

import asyncio
from pathlib import Path
import sys
import time

import pytest

from sylanne3.domains.d02 import BodyProfile, BodyState, WorkComponent
from sylanne3.domains.d02.body_quote_original import (
    D02BodyQuoteAuthority, FixedBodyPolicyV1,
)
from sylanne3.domains.d02.resource_outcome_verifier import C04_INTERNAL_CPU_WORK_KIND
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.authority_service.contract import JournalHead
from sylanne3.authority_service.internal_work_contract import (
    InternalWorkBindingV1, InternalWorkTerminalProofV1,
    InternalWorkTerminalV1, _phase_id, claim_internal_work_v1,
)
from sylanne3.runtime.c04_cpu_quote_policy import (
    C04InternalCpuQuotePolicyAuthorityV1, C04InternalCpuQuotePolicyV1,
)
from sylanne3.runtime_contracts import (
    CommandEnvelope, OperationIdentity, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, canonical_digest,
)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from tests.alpha1.runtime.test_post_c02_reply_assembly_v2 import (
    test_paired_reply_assembly_uses_real_c02_and_reply_admission as real_owner_case,
)


def _owner(case):
    graph = case["graph"]
    namespace = case["namespace"]
    activation = graph._v2_graph_stamp(namespace)[0].requirements.activation_generation
    return graph.grant_current_owner(
        case["bootstrap"], actor="owner-actor-reply", namespace=namespace,
        domains=("d02", "d11"), purpose="workbench_user_action",
        audience="owner", activation_generation=activation,
        owner_session_token=case["owner_session_token"],
        owner_session_request=case["owner_session_request"],
    )


def _policy(case):
    namespace = case["namespace"]
    profile = BodyProfile(
        "c04-fixed-profile", namespace, 1, ("energy",),
        (C04_INTERNAL_CPU_WORK_KIND,),
    )
    return FixedBodyPolicyV1(
        "c04-fixed-policy", 1, profile,
        BodyState(profile.profile_id, 1, 0.8, {"cognition": 0.0}, 0.0, 0.0),
        C04_INTERNAL_CPU_WORK_KIND,
        WorkComponent("c04-fixed-component", "cognition", 0.1),
        time.time() + 3600,
    )


def _envelope(case, authority, operation_id):
    namespace = case["namespace"]
    return CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity(
            "c04-test-activity", "c04-test-effect", "c04-test-attempt",
            "realize-recollection", operation_id,
            canonical_digest({"input_refs": []}),
        ),
        authority,
        VersionGuard(
            (), (), 0, 0, "catalogue", "scheme", "operator", "policy",
            (), (), (),
        ),
        SourceQualification(
            (), "reported", 1.0, 1.0, "external_report", "qualified",
            0.5, "not_applicable",
        ),
        (), case["policy"].root_grant.lease_id, time.time() + 300, 300.0,
        "character", (),
    )


def _counts(case):
    with case["store"]._lock:
        db = case["store"]._db
        return tuple((db.execute("SELECT count(*) FROM " + table).fetchone()[0]
                      if db.execute(
                          "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                          (table,),
                      ).fetchone() else 0)
                     for table in (
                         "d02_body_quotes_v1",
                         "graph_c04_internal_work_prepared_v1",
                         "runtime_budget_reservations",
                         "runtime_c04_cpu_quote_requests_v1",
                         "runtime_resource_quotes",
                     ))


def _cpu_policy(case):
    return C04InternalCpuQuotePolicyV1(
        "c04-cpu-policy", 1, case["namespace"], case["policy"].installation_id,
        "c04-cpu", 10, time.time() + 3600,
    )


@pytest.mark.asyncio
async def test_c04_legacy_prepare_holds_without_cost_or_prepared_rows(tmp_path):
    async def after_c02(case):
        graph = case["graph"]
        authority, lease, _ = await asyncio.to_thread(_owner, case)
        try:
            before = _counts(case)
            with pytest.raises(UnavailableGuard, match="non-executable"):
                await asyncio.to_thread(
                    graph.prepare_internal_work_v1, authority, lease,
                    envelope=_envelope(case, authority, "c04-v1-held"),
                    body_policy_id="c04-fixed-policy", body_policy_version=1,
                    cpu_policy_id="c04-cpu-policy", cpu_policy_version=1,
                    reservation_id="c04-v1-reservation",
                    execution_id="c04-v1-execution",
                    algorithm_ref="d06.association_activation.v2",
                )
            with pytest.raises(UnavailableGuard, match="C04 v2 adoption unavailable"):
                await asyncio.to_thread(
                    graph.commit_current_c04_adoption_v2,
                    authority, lease, operation_id="c04-v1-held",
                )
            assert _counts(case) == before
        finally:
            graph.release_current_owner_lease(case["bootstrap"], lease)

    await real_owner_case(
        tmp_path, "owned", after_c02=after_c02,
        enable_c04_body_work=True,
    )


@pytest.mark.asyncio
async def test_c04_body_cost_rejects_unimported_terminal_without_graph_write(tmp_path):
    async def after_c02(case):
        graph = case["graph"]
        namespace = case["namespace"]
        authority, lease, _ = await asyncio.to_thread(_owner, case)
        reservation_ref = AtomKey(
            Owner("activity", *namespace.as_tuple, "c04-test-activity"),
            "d02.reservation.v1", "unimported",
        ).token
        binding = InternalWorkBindingV1(
            namespace_ref(namespace), "c04-test-activity", "c04-no-cost",
            "c04-execution", "a" * 64, "quote", 1, "b" * 64,
            "body-quote", 1, "c" * 64, reservation_ref, "component",
            "lease", authority.activation_generation,
            "d06.association_activation.v2", "body-policy", "d" * 64,
        )
        claim = claim_internal_work_v1(binding)
        terminal = InternalWorkTerminalV1(
            binding.binding_digest, claim.mutation_id,
            _phase_id(binding.binding_digest, "terminal"), "completed", 1,
            "e" * 64, "component", "f" * 64,
        )
        proof = InternalWorkTerminalProofV1(
            binding, claim, terminal, "claim-ref", "1" * 64,
            "terminal-ref", "2" * 64,
            JournalHead("journal", 2, "sha256:" + "3" * 64),
        )
        try:
            with case["store"]._lock:
                before = case["store"]._db.execute(
                    "SELECT count(*) FROM graph_history"
                ).fetchone()[0]
            with pytest.raises(UnavailableGuard, match="independent C04 CPU cost"):
                await asyncio.to_thread(
                    graph.commit_current_c04_body_cost_v2,
                    authority, lease, proof=proof,
                )
            with case["store"]._lock:
                after = case["store"]._db.execute(
                    "SELECT count(*) FROM graph_history"
                ).fetchone()[0]
                body_rows = case["store"]._db.execute(
                    "SELECT count(*) FROM d02_c04_body_cost_originals_v1"
                ).fetchone()[0]
            assert after == before
            assert body_rows == 0
        finally:
            graph.release_current_owner_lease(case["bootstrap"], lease)

    await real_owner_case(
        tmp_path, "owned", after_c02=after_c02,
        enable_c04_body_work=True,
    )
