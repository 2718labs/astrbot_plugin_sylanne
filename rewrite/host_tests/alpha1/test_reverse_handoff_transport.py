"""Reverse callback crosses real mTLS and the single GraphWorker lease."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
from pathlib import Path
import ssl
import tempfile
import threading
import unittest

import test_authority_mtls_loopback as tls_fixtures

from sylanne3.authority_service.reverse_handoff import (
    AdministratorReverseHandoffProfile, ReverseGraphClaimClient,
    require_exact_reverse_handoff_identity,
)
from sylanne3.authority_service.v2_execution_bridge import HandoffStartV2
from sylanne3.authority_service.v2_contract import (
    DispatchGraphClaimReceiptV1, DispatchHandoffContextV1,
    ExecutionBindingV1, ExecutionBindingV2, FencePermitV2,
    MutationReceiptV2, OwnerDispatchWitnessV1, PendingMutationV2, canonical_digest,
)
from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from sylanne3.graph_worker import GraphWorker
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.host.reverse_handoff import (
    AdministratorHostReverseProfile, HostReverseGraphClaimServer,
    begin_handoff_with_reverse_claim,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.runtime_journal import RecoveryConstraintFootprint


NS = NamespaceId("bot", "persona")
AUTH_NS = namespace_ref(NS)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _claim() -> tuple[ExecutionBindingV2, MutationReceiptV2, DispatchHandoffContextV1]:
    anchor = RestoreAnchor(
        "authority:test", AUTH_NS, 1, "deletion:test", 0, "genesis",
        "execution:test", 0, "genesis", 0, "proof:test")
    footprint = RecoveryConstraintFootprint(
        namespace=AUTH_NS, activity_id="activity-a", effect_id="effect-a",
        conflict_keys=("resource-a",))
    permit = FencePermitV2(
        "authority:test", AUTH_NS, "subject-a", "holder-a", 1,
        "dispatch", "operation-a", "A" * 43, 1, 1, anchor,
        "effect-a", _digest("a"),
        "sha256:" + hashlib.sha256(footprint._json().encode()).hexdigest())
    origin = ExecutionBindingV1(
        permit=permit, namespace=AUTH_NS, activity_id="activity-a",
        effect_id="effect-a", attempt_id="attempt-a",
        operation_id="operation-a", dispatch_generation=1,
        activation_generation=1, admission_ref="admission-a",
        verified_check_refs=("check-a",), payload_digest=_digest("c"),
        platform_capability_ref="capability-a", adapter_ref="adapter-a",
        account_ref="account-a", destination_ref="destination-a",
        worker_fence=1, content_fence="content-a", cancel_epoch=0,
        footprint=footprint)
    binding = ExecutionBindingV2(
        origin, "bot/persona", "graph-incarnation-a", _digest("d"),
        "graph-version-a", 3, 2, 0, _digest("e"), "d08.intent.v1",
        _digest("f"), "d08.action.v1", _digest("0"), "d08.checks.v1",
        _digest("1"), "2029-01-01T00:00:00Z", "clock-policy-a", _digest("2"))
    anchor1 = replace(anchor, execution_seq=1, execution_digest=_digest("3"))
    prepared = PendingMutationV2(
        permit, "prepare-a", _digest("4"), "prepared", anchor,
        "append-prepared", _digest("3"))
    prepared_receipt = MutationReceiptV2(prepared, anchor1, 2, "committed")
    permit1 = replace(permit, revision=2, pinned_anchor=anchor1)
    pending = PendingMutationV2(
        permit1, "claim-a", _digest("5"), "claimed", anchor1,
        "append-claimed", _digest("6"), prepared_receipt=prepared_receipt,
        binding=binding)
    anchor2 = replace(anchor1, execution_seq=2, execution_digest=_digest("6"))
    claimed = MutationReceiptV2(pending, anchor2, 3, "committed")
    context = DispatchHandoffContextV1(
        replace(permit1, revision=3, pinned_anchor=anchor2),
        canonical_digest(claimed), canonical_digest(binding), "handoff-a")
    return binding, claimed, context


def _witness(context: DispatchHandoffContextV1,
             binding: ExecutionBindingV2) -> OwnerDispatchWitnessV1:
    guard = OwnerAuthorizationGuardV1(
        context.permit.authority_id, "install-a", NamespaceId("bot", "persona"),
        1, _digest("9"), 0, 0)
    return OwnerDispatchWitnessV1(
        canonical_digest(context), context.permit.namespace,
        binding.graph_namespace, guard, "owner-issue-a", "grant-a", _digest("8"))


class _Store:
    def close(self) -> None:
        pass


class ReverseHandoffTlsTests(unittest.IsolatedAsyncioTestCase):
    async def test_pinned_identity_exact_handoff_and_single_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = tls_fixtures.AuthorityMtlsLoopbackTests._certificates(root)
            server_der = ssl.PEM_cert_to_DER_cert(files["server.pem"].read_text())
            client_der = ssl.PEM_cert_to_DER_cert(files["client.pem"].read_text())
            host_profile = AdministratorHostReverseProfile(
                "profile-a", "install-a", AUTH_NS,
                hashlib.sha256(client_der).hexdigest(), files["server.pem"],
                files["server.key"], files["ca.pem"], timeout_seconds=2)
            server = HostReverseGraphClaimServer(host_profile)
            listener = await server.start("127.0.0.1", 0)
            port = listener.sockets[0].getsockname()[1]
            client_profile = AdministratorReverseHandoffProfile(
                AUTH_NS, "profile-a", "install-a", "127.0.0.1", port,
                "localhost", hashlib.sha256(server_der).hexdigest(),
                files["ca.pem"], files["client.pem"], files["client.key"],
                timeout_seconds=2)
            client = ReverseGraphClaimClient(client_profile)
            wrong_peer_client = ReverseGraphClaimClient(replace(
                client_profile, client_certificate=files["second.pem"],
                client_private_key=files["second.key"]))
            wrong_install_client = ReverseGraphClaimClient(replace(
                client_profile, installation_id="install-other"))
            worker = await GraphWorker.start(lambda: _Store(), lambda _store: object(),
                                             capacity=1)
            binding, claimed, context = _claim()
            witness = _witness(context, binding)
            calls = []

            def graph_claim(_coordinator, callback_context, callback_binding,
                            _claimed, callback_witness):
                self.assertEqual(callback_witness, witness)
                calls.append(callback_context.handoff_id)
                return DispatchGraphClaimReceiptV1(
                    canonical_digest(callback_context), callback_binding.graph_namespace,
                    callback_binding.graph_incarnation, "graph-version-b", 4, 2, 0,
                    "claim-a", _digest("7"), "issuer-a")

            try:
                with ThreadPoolExecutor(max_workers=1) as authority_worker:
                    loop = asyncio.get_running_loop()

                    async def call_authority(callback, *args):
                        return await loop.run_in_executor(
                            authority_worker, callback, *args)

                    async with worker.exclusive_callback_window() as window:
                        async with server.register(context=context, binding=binding,
                                                   claimed=claimed, window=window,
                                                   claim_writer=graph_claim):
                            receipt = await asyncio.wait_for(
                                call_authority(client.claim, context, binding, claimed,
                                               witness), 3)
                            self.assertEqual(receipt.graph_claim_ref, "claim-a")
                            self.assertEqual(calls, ["handoff-a"])
                            # Exact replay observes the one graph transaction.
                            self.assertEqual(await call_authority(
                                client.claim, context, binding, claimed, witness), receipt)
                            self.assertEqual(calls, ["handoff-a"])
                            concurrent = await asyncio.gather(*(
                                asyncio.to_thread(client.claim, context, binding, claimed,
                                                  witness)
                                for _ in range(2)
                            ))
                            self.assertEqual(concurrent, [receipt, receipt])
                            self.assertEqual(calls, ["handoff-a"])
                            with self.assertRaises(RuntimeError):
                                await call_authority(
                                    client.claim, context, binding, claimed,
                                    replace(witness, grant_id="other-grant"))
                            self.assertEqual(calls, ["handoff-a"])
                            with self.assertRaises(RuntimeError):
                                await call_authority(client.claim,
                                    replace(context, handoff_id="wrong-handoff"),
                                    binding, claimed, witness)
                            with self.assertRaises(RuntimeError):
                                await call_authority(
                                    wrong_peer_client.claim, context, binding, claimed,
                                    witness)
                            with self.assertRaises(RuntimeError):
                                await call_authority(
                                    wrong_install_client.claim, context, binding, claimed,
                                    witness)
                            with self.assertRaises(RuntimeError):
                                await worker.call(lambda _coordinator: None)
                        # GraphWorker is drained before ordinary work resumes.
                self.assertIsNone(await worker.call(lambda _coordinator: None))
                wrong_namespace = replace(client_profile, namespace="ns-other")
                with self.assertRaises(RuntimeError):
                    await asyncio.to_thread(ReverseGraphClaimClient(
                        wrong_namespace).claim, context, binding, claimed, witness)

                async def begin(_claimed, _handoff_id):
                    receipt = await asyncio.to_thread(
                        client.claim, context, binding, claimed, witness)
                    return HandoffStartV2(
                        context.handoff_id, context.permit.operation_id,
                        context.permit.effect_id, context.permit.namespace,
                        context.claimed_receipt_digest, context.binding_digest,
                        receipt.graph_claim_ref, context.permit,
                        graph_claim_receipt=receipt)

                async with begin_handoff_with_reverse_claim(
                    worker=worker, server=server, claimed=claimed,
                    handoff_id=context.handoff_id, claim_writer=graph_claim,
                    begin=begin) as decision:
                    self.assertFalse(decision.replay)
                    with self.assertRaises(RuntimeError):
                        await worker.call(lambda _coordinator: None)
                    start = decision.take_fresh_start()
                    with self.assertRaises(RuntimeError):
                        decision.take_fresh_start()
                with self.assertRaises(RuntimeError):
                    decision.take_fresh_start()
                self.assertEqual(calls, ["handoff-a", "handoff-a"])

                async def replay(_claimed, _handoff_id):
                    return replace(start, replay=True)

                async with begin_handoff_with_reverse_claim(
                    worker=worker, server=server, claimed=claimed,
                    handoff_id=context.handoff_id, claim_writer=graph_claim,
                    begin=replay) as replay_decision:
                    self.assertTrue(replay_decision.replay)
                    with self.assertRaises(RuntimeError):
                        replay_decision.take_fresh_start()
                self.assertEqual(calls, ["handoff-a", "handoff-a"])

                async def fake_fresh(_claimed, _handoff_id):
                    return start

                with self.assertRaisesRegex(RuntimeError, "registered graph callback"):
                    async with begin_handoff_with_reverse_claim(
                        worker=worker, server=server, claimed=claimed,
                        handoff_id=context.handoff_id, claim_writer=graph_claim,
                        begin=fake_fresh):
                        self.fail("fresh start without callback must not enter")
                self.assertEqual(calls, ["handoff-a", "handoff-a"])
            finally:
                await worker.close()
                listener.close()
                await listener.wait_closed()

    async def test_callback_timeout_keeps_graph_lease_until_writer_exits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = tls_fixtures.AuthorityMtlsLoopbackTests._certificates(root)
            server_der = ssl.PEM_cert_to_DER_cert(files["server.pem"].read_text())
            client_der = ssl.PEM_cert_to_DER_cert(files["client.pem"].read_text())
            server = HostReverseGraphClaimServer(AdministratorHostReverseProfile(
                "profile-a", "install-a", AUTH_NS,
                hashlib.sha256(client_der).hexdigest(), files["server.pem"],
                files["server.key"], files["ca.pem"], timeout_seconds=3))
            listener = await server.start("127.0.0.1", 0)
            port = listener.sockets[0].getsockname()[1]
            client = ReverseGraphClaimClient(AdministratorReverseHandoffProfile(
                AUTH_NS, "profile-a", "install-a", "127.0.0.1", port,
                "localhost", hashlib.sha256(server_der).hexdigest(),
                files["ca.pem"], files["client.pem"], files["client.key"],
                timeout_seconds=0.6))
            worker = await GraphWorker.start(lambda: _Store(), lambda _store: object(),
                                             capacity=1)
            binding, claimed, context = _claim()
            witness = _witness(context, binding)
            entered = threading.Event()
            release = threading.Event()

            def slow_claim(_coordinator, callback_context, callback_binding,
                           _claimed, _witness_value):
                entered.set()
                if not release.wait(3):
                    raise RuntimeError("test graph writer was not released")
                return DispatchGraphClaimReceiptV1(
                    canonical_digest(callback_context), callback_binding.graph_namespace,
                    callback_binding.graph_incarnation, "graph-version-b", 4, 2, 0,
                    "claim-a", _digest("7"), "issuer-a")

            try:
                async with worker.exclusive_callback_window() as window:
                    async with server.register(context=context, binding=binding,
                                               claimed=claimed, window=window,
                                               claim_writer=slow_claim):
                        task = asyncio.create_task(asyncio.to_thread(
                            client.claim, context, binding, claimed, witness))
                        self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                        with self.assertRaises(RuntimeError):
                            await worker.call(lambda _coordinator: None)
                        with self.assertRaises(RuntimeError):
                            await task  # The client times out; graph work is still owned.
                        release.set()
                self.assertIsNone(await worker.call(lambda _coordinator: None))
            finally:
                release.set()
                await worker.close()
                listener.close()
                await listener.wait_closed()

    async def test_cancellation_drains_callback_before_releasing_lease(self) -> None:
        binding, claimed, _context = _claim()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = tls_fixtures.AuthorityMtlsLoopbackTests._certificates(root)
            client_der = ssl.PEM_cert_to_DER_cert(files["client.pem"].read_text())
            profile = AdministratorHostReverseProfile(
                "profile-a", "install-a", AUTH_NS,
                hashlib.sha256(client_der).hexdigest(), files["server.pem"],
                files["server.key"], files["ca.pem"])
            server = HostReverseGraphClaimServer(profile)
            worker = await GraphWorker.start(lambda: _Store(), lambda _store: object(),
                                             capacity=1)
            started = asyncio.Event()
            release = asyncio.Event()

            async def begin(_claimed, _handoff_id):
                started.set()
                await release.wait()
                raise RuntimeError("Authority result unknown")

            try:
                async def drive():
                    async with begin_handoff_with_reverse_claim(
                        worker=worker, server=server, claimed=claimed,
                        handoff_id="handoff-a", claim_writer=lambda *_: None,
                        begin=begin):
                        self.fail("cancelled handoff must not enter decision window")

                task = asyncio.create_task(drive())
                await asyncio.wait_for(started.wait(), 2)
                task.cancel()
                await asyncio.sleep(0)
                with self.assertRaises(RuntimeError):
                    await worker.call(lambda _coordinator: None)
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertIsNone(await worker.call(lambda _coordinator: None))
            finally:
                await worker.close()

    async def test_exact_p2_subject_holder_generation_token_and_epoch(self) -> None:
        binding, claimed, context = _claim()
        require_exact_reverse_handoff_identity(AUTH_NS, context, binding, claimed)
        for field, value in (
            ("subject", "other-subject"), ("holder", "other-holder"),
            ("generation", 2), ("token", "B" * 43), ("fence_epoch", 2),
        ):
            try:
                altered = replace(
                    context, permit=replace(context.permit, **{field: value}),
                )
            except ValueError:
                # The typed P2 contract can reject some cross-anchor changes
                # before the transport identity check is reached.
                continue
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                require_exact_reverse_handoff_identity(
                    AUTH_NS, altered, binding, claimed,
                )


if __name__ == "__main__":
    unittest.main()
