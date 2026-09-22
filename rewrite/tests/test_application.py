import asyncio
from dataclasses import dataclass
from pathlib import Path
import tempfile
import time
import unittest

from sylanne3.application import Application, Envelope
from sylanne3.contracts import EventConflict, Scope, StepResult
from sylanne3.delivery import RecordingTransport
from sylanne3.scheduler import BoundedScheduler
from sylanne3.store import Store


@dataclass(frozen=True)
class _Solution:
    solution: tuple[float, float]
    error_bound: float = 0.0


class _Job:
    def __init__(self, drive):
        self._drive = tuple(drive)

    def step(self, _budget, _cancelled):
        return StepResult(True, _Solution(self._drive))


class _Kernel:
    def job(self, **values):
        return _Job(values["drive"])


class ApplicationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "application.sqlite"
        self.scope = Scope("bot", "persona", "session")
        self.store = Store(self.path)
        self.scheduler = BoundedScheduler(workers=1, capacity=8)
        self.app = Application(self.store, self.scheduler, _Kernel(), proposal_timeout=0.05)

    async def asyncTearDown(self):
        await self.app.close()
        self.temp.cleanup()

    def envelope(self, message_id="message-1", text="you helped me", scope=None):
        return Envelope(scope or self.scope, message_id, text, 1.0, 2.0)

    @staticmethod
    async def support(_prompt):
        return '{"appraisal":"support","evidence":"helped"}'

    def ingress(self, store=None, scope=None):
        atom = (store or self.store).snapshot(scope or self.scope, ("ingress",)).get("ingress")
        return atom.value.get("items", {})

    async def test_success_claims_before_provider_commits_and_sends_once(self):
        observed = []

        async def proposer(prompt):
            observed.append((prompt, len(self.ingress())))
            return '{"appraisal":"support","evidence":"helped"}'

        sink = RecordingTransport()
        result = await self.app.handle(self.envelope(), proposer, sink)

        self.assertEqual(result.status, "committed")
        self.assertEqual(result.turn.status, "committed")
        self.assertEqual(len(sink.sent), 1)
        self.assertEqual(observed[0][1], 1)
        row = next(iter(self.ingress().values()))
        self.assertEqual(row["status"], "completed")
        self.assertEqual(row["envelope_digest"], self.envelope().digest)
        self.assertEqual(row["semantic_event_id"], "semantic:" + self.envelope().digest)
        self.assertEqual(row["state_scope"], {
            "bot": "bot", "persona": "persona", "session": "session",
        })

    async def test_timeout_validation_and_reentrant_handler_are_fail_closed(self):
        for invalid in (True, 0, -1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                Application(self.store, self.scheduler, _Kernel(), proposal_timeout=invalid)

        class ReentrantTransport:
            nested = None
            close_error = None

            async def send(inner, _action):
                try:
                    await self.app.close()
                except RuntimeError as exc:
                    inner.close_error = exc
                inner.nested = await self.app.handle(
                    self.envelope("nested", scope=Scope("other", "p", "s")),
                    self.support,
                    RecordingTransport(),
                )

        transport = ReentrantTransport()
        outer = await self.app.handle(self.envelope(), self.support, transport)
        self.assertEqual(outer.status, "committed")
        self.assertIsInstance(transport.close_error, RuntimeError)
        self.assertEqual(transport.nested.status, "busy")

    async def test_duplicate_restart_skips_provider_and_send(self):
        first_sink = RecordingTransport()
        self.assertEqual((await self.app.handle(self.envelope(), self.support, first_sink)).status, "committed")
        await self.app.close()

        self.store = Store(self.path)
        self.scheduler = BoundedScheduler(workers=1, capacity=8)
        self.app = Application(self.store, self.scheduler, _Kernel())
        calls = 0

        async def should_not_run(_prompt):
            nonlocal calls
            calls += 1
            return '{"appraisal":"support","evidence":"helped"}'

        sink = RecordingTransport()
        result = await self.app.handle(self.envelope(), should_not_run, sink)
        self.assertEqual(result.status, "duplicate")
        self.assertEqual(calls, 0)
        self.assertEqual(sink.sent, [])

    async def test_reused_message_id_with_different_envelope_conflicts(self):
        await self.app.handle(self.envelope(), self.support, RecordingTransport())
        with self.assertRaises(EventConflict):
            await self.app.handle(self.envelope(text="changed source"), self.support, RecordingTransport())

    async def test_stable_ingress_scope_detects_replay_after_destination_scope_changes(self):
        ingress_scope = Scope("host", "intake", "conversation")
        calls = 0

        async def proposer(prompt):
            nonlocal calls
            calls += 1
            return await self.support(prompt)

        await self.app.handle(self.envelope(), proposer, RecordingTransport(),
                              ingress_scope=ingress_scope)
        changed = self.envelope(scope=Scope("bot", "new-persona", "new-session"))
        with self.assertRaises(EventConflict):
            await self.app.handle(changed, proposer, RecordingTransport(),
                                  ingress_scope=ingress_scope)
        self.assertEqual(calls, 1)
        self.assertEqual(len(self.ingress(scope=ingress_scope)), 1)

    async def test_abstention_and_rejection_settle_without_reaction_or_send(self):
        cases = (
            ('{"appraisal":"abstain","evidence":""}', "abstained"),
            ('{"appraisal":"support","evidence":"not in source"}', "rejected"),
        )
        for index, (raw, expected) in enumerate(cases):
            async def proposer(_prompt, raw=raw):
                return raw

            scope = Scope("bot", "persona", f"session-{index}")
            sink = RecordingTransport()
            result = await self.app.handle(self.envelope(f"m-{index}", scope=scope), proposer, sink)
            self.assertEqual(result.status, expected)
            self.assertEqual(sink.sent, [])
            self.assertEqual(self.store.snapshot(scope, ("reaction",)).get("reaction").revision, 0)
            row = next(iter(self.ingress(scope=scope).values()))
            self.assertEqual(row["status"], expected)

    async def test_provider_timeout_is_rejected_and_not_retried(self):
        calls = 0

        async def blocked(_prompt):
            nonlocal calls
            calls += 1
            await asyncio.Event().wait()

        result = await self.app.handle(self.envelope(), blocked, RecordingTransport())
        self.assertEqual(result.status, "rejected")
        self.assertEqual(calls, 1)
        self.assertEqual((await self.app.handle(self.envelope(), self.support, RecordingTransport())).status,
                         "duplicate")
        self.assertEqual(calls, 1)

    async def test_provider_failure_is_sanitized_and_durable(self):
        async def failed(_prompt):
            raise RuntimeError("secret-provider-key=abc")

        result = await self.app.handle(self.envelope(), failed, RecordingTransport())
        self.assertEqual(result.status, "failed")
        encoded = repr(next(iter(self.ingress().values())))
        self.assertNotIn("secret-provider-key", encoded)
        self.assertNotIn("abc", encoded)

    async def test_cancellation_is_settled_and_never_automatically_retried(self):
        entered = asyncio.Event()

        async def blocked(_prompt):
            entered.set()
            await asyncio.Event().wait()

        task = asyncio.create_task(self.app.handle(self.envelope(), blocked, RecordingTransport()))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertEqual(next(iter(self.ingress().values()))["status"], "cancelled")
        self.assertEqual((await self.app.handle(self.envelope(), self.support, RecordingTransport())).status,
                         "duplicate")

    async def test_admission_is_immediate_for_capacity_and_same_scope(self):
        entered = asyncio.Event()
        release = asyncio.Event()

        async def blocked(_prompt):
            entered.set()
            await release.wait()
            return '{"appraisal":"abstain","evidence":""}'

        task = asyncio.create_task(self.app.handle(self.envelope(), blocked, RecordingTransport()))
        await entered.wait()
        started = time.monotonic()
        same_scope = await self.app.handle(self.envelope("other"), self.support, RecordingTransport())
        self.assertEqual(same_scope.status, "busy")
        self.assertLess(time.monotonic() - started, 0.04)
        release.set()
        await task

        other_store = Store(Path(self.temp.name) / "capacity.sqlite")
        other_scheduler = BoundedScheduler(workers=1, capacity=8)
        capacity_app = Application(other_store, other_scheduler, _Kernel(), capacity=1)
        entered = asyncio.Event()
        release = asyncio.Event()
        first = asyncio.create_task(capacity_app.handle(
            self.envelope("a", scope=Scope("b", "p", "a")), blocked, RecordingTransport()))
        await entered.wait()
        second = await capacity_app.handle(
            self.envelope("b", scope=Scope("b", "p", "b")), self.support, RecordingTransport())
        self.assertEqual(second.status, "busy")
        release.set()
        await first
        await capacity_app.close()

    async def test_two_application_instances_claim_once_and_merge_distinct_rows(self):
        other_store = Store(self.path)
        other_scheduler = BoundedScheduler(workers=1, capacity=8)
        other = Application(other_store, other_scheduler, _Kernel())
        try:
            calls = 0

            async def proposer(_prompt):
                nonlocal calls
                calls += 1
                await asyncio.sleep(0.01)
                return '{"appraisal":"abstain","evidence":""}'

            same = await asyncio.gather(
                self.app.handle(self.envelope(), proposer, RecordingTransport()),
                other.handle(self.envelope(), proposer, RecordingTransport()),
            )
            self.assertEqual(sorted(item.status for item in same), ["abstained", "duplicate"])
            self.assertEqual(calls, 1)

            shared_ingress = Scope("host", "intake", "same-destination")
            destination = Scope("b", "p", "a")
            entered = asyncio.Event()
            release = asyncio.Event()

            async def delayed(_prompt):
                nonlocal calls
                calls += 1
                entered.set()
                await release.wait()
                return '{"appraisal":"abstain","evidence":""}'

            first = asyncio.create_task(self.app.handle(
                self.envelope("m-a", scope=destination), delayed, RecordingTransport(),
                ingress_scope=shared_ingress,
            ))
            await entered.wait()
            second = await other.handle(
                self.envelope("m-b", scope=destination), proposer, RecordingTransport(),
                ingress_scope=shared_ingress,
            )
            self.assertEqual(second.status, "busy")
            self.assertEqual(calls, 2)
            release.set()
            self.assertEqual((await first).status, "abstained")
            retry = await other.handle(
                self.envelope("m-b", scope=destination), proposer, RecordingTransport(),
                ingress_scope=shared_ingress,
            )
            self.assertEqual(retry.status, "abstained")
            self.assertEqual(calls, 3)
            self.assertEqual(len(self.ingress(scope=shared_ingress)), 2)

            merge_ingress = Scope("host", "intake", "cross-destination")
            scopes = (Scope("b", "p", "x"), Scope("b", "p", "y"))
            merged = await asyncio.gather(*(
                app.handle(self.envelope(f"distinct-{i}", scope=scopes[i]), proposer,
                           RecordingTransport(), ingress_scope=merge_ingress)
                for i, app in enumerate((self.app, other))
            ))
            self.assertEqual([item.status for item in merged], ["abstained", "abstained"])
            self.assertEqual(len(self.ingress(scope=merge_ingress)), 2)
        finally:
            await other.close()

    async def test_close_rejects_new_work_and_joins_active_handler(self):
        entered = asyncio.Event()

        async def blocked(_prompt):
            entered.set()
            await asyncio.Event().wait()

        task = asyncio.create_task(self.app.handle(self.envelope(), blocked, RecordingTransport()))
        await entered.wait()
        await self.app.close()
        with self.assertRaises(asyncio.CancelledError):
            await task
        result = await self.app.handle(self.envelope("later"), self.support, RecordingTransport())
        self.assertEqual(result.status, "closed")


if __name__ == "__main__":
    unittest.main()
