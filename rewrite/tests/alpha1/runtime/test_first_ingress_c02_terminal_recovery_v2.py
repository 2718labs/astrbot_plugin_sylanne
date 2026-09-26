"""A first-sealed C02 result commits with one pinned post-expiry read."""

import asyncio
from dataclasses import replace
import importlib
import json
import sys
import time
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from sylanne3.authority_service.v2_terminal_c02_recovery_contract import (
    OriginalC02ResultKeyV1, TerminalRecoveryReadFactV1,
    TerminalRecoveryReadRequestV1, from_wire,
)
from sylanne3.graph_coordinator import EventConflict, UnavailableGuard
from sylanne3.host.authority_profile import AdminD06FirstIngressC02Policy
from sylanne3.host.terminal_c02_recovery_query import (
    PinnedTerminalC02RecoveryQueryV1,
)
from sylanne3.domains.d06 import source_key
from sylanne3.runtime.c02_terminal_job import TerminalC02JobHold
from sylanne3.runtime.c02_terminal_job import pin_finished_terminal_read_from_host
from sylanne3.runtime.issuers import IssuerAuthorityDenied
from sylanne3.runtime.terminal_c02_recovery_candidate_v2 import (
    FrozenTerminalC02CandidateV2,
)

from test_first_ingress_c02_commit import c02_case


def _sealed_case(c02_case, monkeypatch):
    store, coordinator, bootstrap, namespace, installation, clock, intent, read, fact_port = c02_case
    port = coordinator._GraphCoordinator__content_fence_v2
    original_begin = port.begin_fence

    def stop_after_seal(**kwargs):
        if kwargs["operation"] == "write":
            raise RuntimeError("stop after first seal")
        return original_begin(**kwargs)

    monkeypatch.setattr(port, "begin_fence", stop_after_seal)
    admin = AdminD06FirstIngressC02Policy(
        120.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource")
    with pytest.raises(RuntimeError, match="stop after first seal"):
        coordinator.commit_first_ingress_c02_v2(
            bootstrap, intent, read, installation, admin, clock)
    monkeypatch.setattr(port, "begin_fence", original_begin)
    row = store._db.execute(
        "SELECT seal_json FROM graph_first_ingress_c02_candidates_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (read.request.consumer_operation_id,),
    ).fetchone()
    raw = json.loads(row[0])
    raw["original_key"] = from_wire(
        raw["original_key"], OriginalC02ResultKeyV1)
    seal = FrozenTerminalC02CandidateV2(**raw)
    expired_now = seal.original_worker_lease_expires_utc + 1.0
    assert expired_now < seal.business_deadline_utc

    def expired_clock(_policy):
        return SimpleNamespace(
            utc_upper_bound_seconds=expired_now,
            monotonic_after_seconds=time.monotonic())

    monkeypatch.setattr(port, "read_ingress_clock", expired_clock)
    request = coordinator.read_pending_first_ingress_c02_terminal_request_v2(
        bootstrap, namespace, read.request.consumer_operation_id)
    fact = TerminalRecoveryReadFactV1(
        request, "8" * 64, seal.original_key.stable_result_digest, "9" * 64)
    adapter = object.__new__(PinnedTerminalC02RecoveryQueryV1)
    adapter._request = request
    assert request.original_key == seal.original_key
    return (store, coordinator, bootstrap, namespace, installation, clock,
            admin, read, fact_port, seal, fact, adapter)


def test_expired_c02_uses_original_quote_and_job_in_one_graph_commit(
        c02_case, monkeypatch):
    (store, coordinator, bootstrap, namespace, installation, clock, admin,
     read, fact_port, seal, fact, adapter) = _sealed_case(c02_case, monkeypatch)
    quote_count = store._db.execute(
        "SELECT COUNT(*) FROM runtime_resource_quotes WHERE quote_id=?",
        (seal.quote_id,),
    ).fetchone()[0]

    async def pinned_query(_self):
        assert not store._lock._is_owned()
        return fact

    with patch.object(PinnedTerminalC02RecoveryQueryV1, "query_finished",
                      pinned_query):
        assert coordinator.claim_pending_first_ingress_c02_terminal_read_v2(
            bootstrap, namespace, read.request.consumer_operation_id,
            adapter.request) is True
        assert coordinator.claim_pending_first_ingress_c02_terminal_read_v2(
            bootstrap, namespace, read.request.consumer_operation_id,
            adapter.request) is False
        pinned = asyncio.run(pin_finished_terminal_read_from_host(adapter))
        receipt = coordinator.recover_pending_first_ingress_c02_v2_pinned(
            bootstrap, namespace, read.request.consumer_operation_id,
            installation, admin, clock, adapter, pinned)
    assert receipt.status == "committed"
    assert fact_port.calls == 0
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_resource_quotes WHERE quote_id=?",
        (seal.quote_id,),
    ).fetchone()[0] == quote_count
    assert store._db.execute(
        "SELECT phase,result_ref FROM runtime_jobs WHERE job_id=?",
        (read.request.job_id,),
    ).fetchone()[0] == "completed"
    assert store._db.execute(
        "SELECT 1 FROM graph_first_ingress_c02_candidates_v2 WHERE bot=? "
        "AND persona=? AND operation_id=?",
        namespace.as_tuple + (read.request.consumer_operation_id,),
    ).fetchone() is None
    archived = store._db.execute(
        "SELECT seal_json FROM graph_first_ingress_c02_committed_seals_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (read.request.consumer_operation_id,),
    ).fetchone()
    assert archived == (json.dumps(json.loads(archived[0]),
                                   sort_keys=True, separators=(",", ":")),)
    replay = coordinator.read_pending_first_ingress_c02_terminal_request_v2(
        bootstrap, namespace, read.request.consumer_operation_id)
    assert replay.status == "duplicate"
    assert replay.operation_digest == receipt.operation_digest
    assert fact_port.calls == 0
    assert (coordinator.read_committed_first_ingress_c02_terminal_request_v2(
        bootstrap, namespace, read.request.consumer_operation_id)
        == adapter.request)
    saved_receipt = store._db.execute(
        "SELECT receipt_json FROM graph_bundle_operations WHERE bot=? "
        "AND persona=? AND operation_id=?",
        namespace.as_tuple + (read.request.consumer_operation_id,),
    ).fetchone()[0]
    changed = json.loads(saved_receipt)
    changed["first_ingress_c02"]["terminal_read_attempt_id"] = "other-attempt"
    store._db.execute(
        "UPDATE graph_bundle_operations SET receipt_json=? WHERE bot=? "
        "AND persona=? AND operation_id=?",
        (json.dumps(changed),) + namespace.as_tuple
        + (read.request.consumer_operation_id,),
    )
    with pytest.raises(EventConflict):
        coordinator.read_pending_first_ingress_c02_terminal_request_v2(
            bootstrap, namespace, read.request.consumer_operation_id)
    store._db.execute(
        "UPDATE graph_bundle_operations SET receipt_json=? WHERE bot=? "
        "AND persona=? AND operation_id=?",
        (saved_receipt,) + namespace.as_tuple
        + (read.request.consumer_operation_id,),
    )
    original_intent = c02_case[6]
    coordinator._GraphCoordinator__original_c02_cost_intent_port = (
        lambda request: original_intent)
    coordinator.recover_committed_first_ingress_c02_unknown_cost_v2_pinned(
        bootstrap, namespace, read.request.consumer_operation_id, pinned)
    assert store._db.execute(
        "SELECT state FROM runtime_budget_reservations WHERE operation_id=?",
        (read.request.consumer_operation_id,),
    ).fetchone() == ("unknown",)
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_budget_operations WHERE operation_id=? "
        "AND phase='settle'",
        (read.request.consumer_operation_id,),
    ).fetchone() == (1,)
    coordinator.recover_committed_first_ingress_c02_unknown_cost_v2_pinned(
        bootstrap, namespace, read.request.consumer_operation_id, pinned)


def test_terminal_c02_rejects_mismatched_pinned_fact_before_write(
        c02_case, monkeypatch):
    (store, coordinator, bootstrap, namespace, installation, clock, admin,
     read, _, seal, fact, adapter) = _sealed_case(c02_case, monkeypatch)
    other_request = replace(fact.request, read_attempt_id="other-attempt")
    with patch.object(PinnedTerminalC02RecoveryQueryV1, "query_finished",
                      AsyncMock(return_value=replace(fact, request=other_request))):
        with pytest.raises(TerminalC02JobHold):
            asyncio.run(pin_finished_terminal_read_from_host(adapter))
    assert store._db.execute(
        "SELECT phase FROM runtime_jobs WHERE job_id=?",
        (read.request.job_id,),
    ).fetchone() == ("running",)
    assert store._db.execute(
        "SELECT 1 FROM graph_first_ingress_c02_candidates_v2 WHERE bot=? "
        "AND persona=? AND operation_id=?",
        namespace.as_tuple + (read.request.consumer_operation_id,),
    ).fetchone() is not None


def test_local_claim_without_remote_attempt_resends_only_original_id(
        c02_case, monkeypatch):
    (_, _, _, _, _, _, _, read, _, _, _, _) = _sealed_case(
        c02_case, monkeypatch)
    request = c02_case[1].read_pending_first_ingress_c02_terminal_request_v2(
        c02_case[2], c02_case[3], read.request.consumer_operation_id)
    model_stub = ModuleType("sylanne3.host.astrbot_model_call")
    model_stub.AstrBotModelProvider = type("AstrBotModelProvider", (), {})
    model_stub.LocalModelAdmission = type("LocalModelAdmission", (), {})
    star_stub = ModuleType("astrbot.api.star")
    star_stub.Context = type("Context", (), {})
    monkeypatch.setitem(sys.modules, "sylanne3.host.astrbot_model_call", model_stub)
    monkeypatch.setitem(sys.modules, "astrbot.api.star", star_stub)
    driver = importlib.import_module("sylanne3.host.first_ingress_c02_driver")

    class Runtime:
        async def read_pending_first_ingress_c02_terminal_request_v2(self, operation):
            assert operation == request.consumer_operation_id
            return request

        async def claim_pending_first_ingress_c02_terminal_read_v2(self, operation, actual):
            assert (operation, actual) == (request.consumer_operation_id, request)
            return False  # Previous process committed the exact local claim.

        async def recover_pending_first_ingress_c02_v2_pinned(self, *args):
            return None

    class Bundle:
        pass

    class Profile:
        profile_id = "profile"

    class Installation:
        def __init__(self):
            self.installation_policy = SimpleNamespace(
                namespace=request.original_key.namespace, manifest_digest="m" * 64)
            self.installation_grant = SimpleNamespace(
                installation_id=request.original_key.installation_id,
                channel_binding_sha256="binding")
            self.admin_bundle = Bundle()
            self.admin_bundle.tls_profile = Profile()
            self.admin_bundle.installation_policy = self.installation_policy
            self.package_root = "fixture"
            self.data_dir = "fixture"

    class Transport:
        calls = []

        def __init__(self, profiles):
            self.profiles = profiles

        async def handshake(self, *args, **kwargs):
            return SimpleNamespace(
                valid_pairing=lambda: True, channel_binding_sha256="binding")

        async def installation_grant_v2(self, *args):
            return installation.installation_grant

        async def terminal_c02_recovery_query_v1(self, *args, **kwargs):
            assert kwargs["read_request"] == request
            return None, None

        async def terminal_c02_recovery_read_v1(self, *args, **kwargs):
            self.calls.append(kwargs["read_request"])

        async def close(self):
            pass

    installation = Installation()
    monkeypatch.setattr(driver, "RuntimeContext", Runtime)
    monkeypatch.setattr(driver, "V2InstallationAssembly", Installation)
    monkeypatch.setattr(driver, "AdminInstallationBundle", Bundle)
    monkeypatch.setattr(driver, "AuthorityTlsProfile", Profile)
    monkeypatch.setattr(driver, "MtlsAuthorityTransport", Transport)
    monkeypatch.setattr(driver, "AuthorityProvisioningRequest", lambda **kw: kw)
    monkeypatch.setattr(driver, "PublisherPackageIdentity", lambda digest: digest)
    monkeypatch.setattr(driver, "PinnedTerminalC02RecoveryQueryV1", lambda **kw: object())

    async def pinned(_query):
        return object()

    monkeypatch.setattr(driver, "pin_finished_terminal_read_from_host", pinned)
    assert asyncio.run(driver.run_installed_pending_first_ingress_c02_v2(
        Runtime(), installation, request.consumer_operation_id)) is None
    assert Transport.calls == [request]


@pytest.mark.parametrize("lost_authority", ["source", "budget_grant"])
def test_terminal_c02_rechecks_current_source_and_budget_before_job_cas(
        c02_case, monkeypatch, lost_authority):
    (store, coordinator, bootstrap, namespace, installation, clock, admin,
     read, _, seal, fact, adapter) = _sealed_case(c02_case, monkeypatch)
    if lost_authority == "source":
        evidence = json.loads(store._db.execute(
            "SELECT evidence_json FROM graph_first_ingress_c02_candidates_v2 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (read.request.consumer_operation_id,),
        ).fetchone()[0])
        store._db.execute(
            "UPDATE graph_atoms SET valid=0 WHERE token=?",
            (source_key(*namespace.as_tuple, evidence["source_ref"]).token,),
        )
    else:
        store._db.execute(
            "UPDATE runtime_budget_grants SET status='revoked' "
            "WHERE lease_id=(SELECT budget_ref FROM runtime_jobs WHERE job_id=?)",
            (read.request.job_id,),
        )
    with patch.object(PinnedTerminalC02RecoveryQueryV1, "query_finished",
                      AsyncMock(return_value=fact)):
        assert coordinator.claim_pending_first_ingress_c02_terminal_read_v2(
            bootstrap, namespace, read.request.consumer_operation_id,
            adapter.request) is True
        pinned = asyncio.run(pin_finished_terminal_read_from_host(adapter))
        with pytest.raises((UnavailableGuard, IssuerAuthorityDenied)):
            coordinator.recover_pending_first_ingress_c02_v2_pinned(
                bootstrap, namespace, read.request.consumer_operation_id,
                installation, admin, clock, adapter, pinned)
    assert store._db.execute(
        "SELECT phase FROM runtime_jobs WHERE job_id=?",
        (read.request.job_id,),
    ).fetchone() == ("running",)
    assert store._db.execute(
        "SELECT 1 FROM graph_bundle_operations WHERE bot=? AND persona=? "
        "AND operation_id=?",
        namespace.as_tuple + (read.request.consumer_operation_id,),
    ).fetchone() is None
