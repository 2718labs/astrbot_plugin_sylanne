"""Bounded host ingress with durable, inspect-only replay receipts.

Claims left by a process crash are intentionally never replayed automatically.
A later delivery recovery policy must distinguish known failure from unknown
external acceptance before it can safely retry either proposal or delivery.
"""
from __future__ import annotations

import asyncio
import contextvars
from dataclasses import dataclass
import hashlib
import math
import time

from .contracts import Candidate, Event, EventConflict, Scope, Write
from .delivery import _finish
from .engine import Engine
from .semantics import Envelope, build_prompt, parse_proposal, to_event
from .store import StaleRead


_INGRESS = "ingress"
_MAX_INGRESS = 256
_CAS_RETRIES = 64
_TERMINAL = frozenset(("abstained", "rejected", "failed", "completed", "cancelled"))
_IN_HANDLER = contextvars.ContextVar("sylanne3_application_handler", default=False)


@dataclass(frozen=True)
class ApplicationResult:
    status: str
    turn: object | None = None


def _message_key(message_id: str) -> str:
    return hashlib.sha256(message_id.encode("utf-8")).hexdigest()


def _envelope_payload(envelope: Envelope) -> dict:
    return {
        "scope": {
            "bot": envelope.scope.bot,
            "persona": envelope.scope.persona,
            "session": envelope.scope.session,
        },
        "message_id": envelope.message_id,
        "text": envelope.text,
        "start_at": envelope.start_at,
        "occurred_at": envelope.occurred_at,
    }


class Application:
    """Own admission, durable ingress, semantic execution and shutdown order."""

    def __init__(self, store, scheduler, kernel, capacity=8, proposal_timeout=30):
        if type(capacity) is not int or capacity < 1:
            raise ValueError("capacity must be a positive integer")
        if (isinstance(proposal_timeout, bool)
                or not isinstance(proposal_timeout, (int, float))
                or not math.isfinite(proposal_timeout)
                or proposal_timeout <= 0):
            raise ValueError("proposal_timeout must be positive")
        self.store = store
        self.scheduler = scheduler
        self.kernel = kernel
        self.capacity = capacity
        self.proposal_timeout = float(proposal_timeout)
        self._closed = False
        self._active: set[asyncio.Task] = set()
        self._scopes: set[Scope] = set()
        self._close_task: asyncio.Task | None = None

    @staticmethod
    def _row_matches(row, envelope: Envelope) -> bool:
        if row.get("message_id") != envelope.message_id:
            raise EventConflict("message key collision")
        if row.get("envelope_digest") != envelope.digest:
            raise EventConflict("message ID reused with different envelope")
        return True

    def _claim_sync(self, ingress_scope: Scope, envelope: Envelope):
        key = _message_key(envelope.message_id)
        for _ in range(_CAS_RETRIES):
            snapshot = self.store.snapshot(ingress_scope, (_INGRESS,))
            ledger = snapshot.get(_INGRESS).value or {"items": {}}
            items = ledger.get("items")
            if type(items) is not dict:
                raise RuntimeError("invalid ingress ledger")
            prior = items.get(key)
            if prior is not None:
                self._row_matches(prior, envelope)
                return "duplicate", key
            state_scope = {
                "bot": envelope.scope.bot,
                "persona": envelope.scope.persona,
                "session": envelope.scope.session,
            }
            # A claimed row has no guessed lease or expiry. A crash therefore
            # leaves this destination blocked for explicit recovery/inspection.
            for row in items.values():
                if (type(row) is dict and row.get("status") == "claimed"
                        and row.get("state_scope") == state_scope):
                    return "busy", key
            if len(items) >= _MAX_INGRESS:
                return "full", key
            claimed_at = time.time()
            items[key] = {
                "message_id": envelope.message_id,
                "envelope_digest": envelope.digest,
                "state_scope": state_scope,
                "semantic_event_id": "semantic:" + envelope.digest,
                "status": "claimed",
                "claimed_at": claimed_at,
                "updated_at": claimed_at,
            }
            event = Event(
                ingress_scope,
                f"__ingress__:{key}:claim",
                envelope.occurred_at,
                "_ingress_claim",
                _envelope_payload(envelope),
            )
            try:
                receipt = self.store.commit(Candidate(
                    event,
                    snapshot.versions,
                    (Write(_INGRESS, ledger),),
                ))
            except StaleRead:
                continue
            if receipt.status == "duplicate":
                # An identical claim event won on another Store connection.
                return "duplicate", key
            return "claimed", key
        raise RuntimeError("ingress claim contention")

    def _settle_sync(self, ingress_scope: Scope, envelope: Envelope, key: str, status: str):
        if status not in _TERMINAL:
            raise ValueError("invalid ingress terminal status")
        for _ in range(_CAS_RETRIES):
            snapshot = self.store.snapshot(ingress_scope, (_INGRESS,))
            ledger = snapshot.get(_INGRESS).value
            items = ledger.get("items") if type(ledger) is dict else None
            row = items.get(key) if type(items) is dict else None
            if type(row) is not dict:
                raise RuntimeError("ingress claim is absent")
            self._row_matches(row, envelope)
            if row.get("status") == status:
                return
            if row.get("status") != "claimed":
                return
            row["status"] = status
            row["updated_at"] = time.time()
            event = Event(
                ingress_scope,
                f"__ingress__:{key}:{status}",
                envelope.occurred_at,
                "_ingress_settlement",
                {
                    "message_key": key,
                    "envelope_digest": envelope.digest,
                    "status": status,
                },
            )
            try:
                self.store.commit(Candidate(
                    event,
                    snapshot.versions,
                    (Write(_INGRESS, ledger),),
                ))
                return
            except StaleRead:
                continue
        raise RuntimeError("ingress settlement contention")

    async def _owned_sync(self, function, *args):
        result, cancellation = await _finish(asyncio.create_task(
            asyncio.to_thread(function, *args)))
        return result, cancellation

    async def _settle(self, ingress_scope, envelope, key, status):
        _, cancellation = await self._owned_sync(
            self._settle_sync, ingress_scope, envelope, key, status)
        if cancellation is not None:
            raise cancellation

    async def handle(self, envelope, proposer, transport, *, ingress_scope=None):
        if not isinstance(envelope, Envelope):
            raise TypeError("envelope must be Envelope")
        if ingress_scope is None:
            ingress_scope = envelope.scope
        if not isinstance(ingress_scope, Scope):
            raise TypeError("ingress_scope must be Scope")
        if not callable(proposer):
            raise TypeError("proposer must be callable")
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("handle requires an asyncio task")

        # No await occurs in this section, so admission is immediate and atomic
        # with respect to other coroutines on this event loop.
        if self._closed:
            return ApplicationResult("closed")
        if (task in self._active or len(self._active) >= self.capacity
                or envelope.scope in self._scopes):
            return ApplicationResult("busy")
        self._active.add(task)
        self._scopes.add(envelope.scope)
        context_token = _IN_HANDLER.set(True)

        key = None
        claimed = False
        try:
            (claim_status, key), cancellation = await self._owned_sync(
                self._claim_sync, ingress_scope, envelope)
            if cancellation is not None:
                if claim_status == "claimed":
                    await self._settle(ingress_scope, envelope, key, "cancelled")
                raise cancellation
            if claim_status == "duplicate":
                return ApplicationResult("duplicate")
            if claim_status == "busy":
                return ApplicationResult("busy")
            if claim_status == "full":
                return ApplicationResult("rejected")
            claimed = True

            try:
                raw = await asyncio.wait_for(
                    proposer(build_prompt(envelope)),
                    timeout=self.proposal_timeout,
                )
            except TimeoutError:
                await self._settle(ingress_scope, envelope, key, "rejected")
                return ApplicationResult("rejected")
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._settle(ingress_scope, envelope, key, "failed")
                return ApplicationResult("failed")

            try:
                proposal = parse_proposal(raw, envelope)
                event = to_event(envelope, proposal)
            except (TypeError, ValueError):
                await self._settle(ingress_scope, envelope, key, "rejected")
                return ApplicationResult("rejected")
            if event is None:
                await self._settle(ingress_scope, envelope, key, "abstained")
                return ApplicationResult("abstained")

            try:
                turn = await Engine(
                    self.store, self.scheduler, self.kernel, transport
                ).handle(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._settle(ingress_scope, envelope, key, "failed")
                return ApplicationResult("failed")
            status = "completed" if turn.status in ("committed", "duplicate") else "failed"
            await self._settle(ingress_scope, envelope, key, status)
            return ApplicationResult(turn.status, turn)
        except asyncio.CancelledError:
            if claimed and key is not None:
                # Own and join the receipt even if cancellation is repeated.
                await self._settle(ingress_scope, envelope, key, "cancelled")
            raise
        finally:
            _IN_HANDLER.reset(context_token)
            self._scopes.discard(envelope.scope)
            self._active.discard(task)

    async def _shutdown(self):
        current = asyncio.current_task()
        handlers = tuple(task for task in self._active if task is not current)
        for task in handlers:
            task.cancel()
        if handlers:
            await asyncio.gather(*handlers, return_exceptions=True)
        await self.scheduler.close()
        await asyncio.to_thread(self.store.close)

    async def close(self):
        if _IN_HANDLER.get() or asyncio.current_task() in self._active:
            raise RuntimeError("close cannot be called from an admitted handler")
        self._closed = True
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._shutdown())
        _, cancellation = await _finish(self._close_task)
        if cancellation is not None:
            raise cancellation
