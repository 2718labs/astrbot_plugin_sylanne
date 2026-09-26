"""Host-side reverse mTLS graph-claim port for an exact dispatcher lease.

Only an administrator-pinned Authority certificate may call this listener.
One registered handoff may submit one synchronous graph transaction through
GraphWorker's exclusive callback window. No Authority RPC runs in that call.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import ssl
from typing import Awaitable, Callable

from ..authority_service.v2_contract import (
    DispatchGraphClaimReceiptV1, DispatchHandoffContextV1,
    ExecutionBindingV2, MutationReceiptV2, canonical_digest, from_wire, to_wire,
)
from ..authority_service.v2_execution_bridge import HandoffStartV2
from ..graph_worker import GraphWorker


@dataclass(frozen=True, slots=True)
class AdministratorHostReverseProfile:
    profile_id: str
    installation_id: str
    namespace: str
    expected_authority_certificate_sha256: str
    certificate: Path
    private_key: Path
    authority_trust_root: Path
    timeout_seconds: float = 5.0
    max_message_bytes: int = 65_536

    def __post_init__(self) -> None:
        for value in (self.profile_id, self.installation_id, self.namespace):
            if type(value) is not str or not value or len(value) > 255:
                raise ValueError("reverse host administrator identity is invalid")
        digest = self.expected_authority_certificate_sha256
        if type(digest) is not str or len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest):
            raise ValueError("reverse host Authority pin is invalid")
        if (type(self.timeout_seconds) not in (int, float)
                or not 0 < self.timeout_seconds <= 30
                or type(self.max_message_bytes) is not int
                or not 512 <= self.max_message_bytes <= 1_048_576):
            raise ValueError("reverse host limits are invalid")
        for name in ("certificate", "private_key", "authority_trust_root"):
            path = Path(getattr(self, name))
            if not path.is_absolute() or not path.is_file() or path.is_symlink():
                raise ValueError("reverse host TLS material is unavailable or unsafe")
            object.__setattr__(self, name, path)

    def ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(
            ssl.Purpose.CLIENT_AUTH, cafile=str(self.authority_trust_root))
        context.load_cert_chain(str(self.certificate), str(self.private_key))
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context


@dataclass(slots=True)
class _Registration:
    context: DispatchHandoffContextV1
    binding: ExecutionBindingV2
    claimed: MutationReceiptV2
    window: object
    claim_writer: Callable
    task: asyncio.Task | None = None
    receipt: DispatchGraphClaimReceiptV1 | None = None


class HostReverseGraphClaimServer:
    """A content-free callback listener; caller owns its network exposure."""

    def __init__(self, profile: AdministratorHostReverseProfile) -> None:
        if type(profile) is not AdministratorHostReverseProfile:
            raise TypeError("administrator host reverse profile required")
        self.profile = profile
        self._registration: _Registration | None = None
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def register(self, *, context: DispatchHandoffContextV1,
                       binding: ExecutionBindingV2,
                       claimed: MutationReceiptV2,
                       window: object, claim_writer: Callable):
        """Register exactly one claim callback after acquiring GraphWorker lease.

        The caller must hold the window through the Authority response and any
        recovery for the same handoff. This port does not supply a claim writer.
        """
        if (type(context) is not DispatchHandoffContextV1
                or type(binding) is not ExecutionBindingV2
                or type(claimed) is not MutationReceiptV2
                or not callable(claim_writer)
                or context.permit.namespace != self.profile.namespace
                or claimed.pending.binding != binding
                or claimed.pending.prepared_receipt is None
                or claimed.pending.prepared_receipt.pending.permit != binding.permit
                or context.permit != replace(
                    claimed.pending.permit, revision=claimed.updated_revision,
                    pinned_anchor=claimed.after_anchor)
                or context.claimed_receipt_digest != canonical_digest(claimed)
                or context.binding_digest != canonical_digest(binding)
                or not callable(getattr(window, "call", None))):
            raise ValueError("reverse handoff registration identity differs")
        async with self._lock:
            if self._registration is not None:
                raise RuntimeError("reverse handoff registration is active")
            registration = _Registration(context, binding, claimed, window, claim_writer)
            self._registration = registration
        try:
            yield registration
        finally:
            try:
                if registration.task is not None:
                    try:
                        await asyncio.shield(registration.task)
                    except asyncio.CancelledError:
                        await asyncio.shield(registration.task)
                        raise
                    except Exception:
                        pass  # The original callback failure remains on its caller.
            finally:
                async with self._lock:
                    if self._registration is registration:
                        self._registration = None

    async def _claim(self, message: object) -> DispatchGraphClaimReceiptV1:
        profile = self.profile
        if (type(message) is not dict or set(message) != {
                "profile_id", "installation_id", "namespace", "context",
                "binding", "claimed_receipt"}
                or (message["profile_id"], message["installation_id"],
                    message["namespace"]) !=
                   (profile.profile_id, profile.installation_id, profile.namespace)):
            raise RuntimeError("reverse graph claim installation identity differs")
        context = from_wire(message["context"])
        binding = from_wire(message["binding"])
        claimed = from_wire(message["claimed_receipt"])
        if (type(context) is not DispatchHandoffContextV1
                or type(binding) is not ExecutionBindingV2
                or type(claimed) is not MutationReceiptV2
                or to_wire(context) != message["context"]
                or to_wire(binding) != message["binding"]
                or to_wire(claimed) != message["claimed_receipt"]):
            raise RuntimeError("reverse graph claim wire identity differs")
        async with self._lock:
            registration = self._registration
            if (registration is None or registration.context != context
                    or registration.binding != binding
                    or registration.claimed != claimed):
                raise RuntimeError("reverse graph claim handoff is not registered")
            if registration.receipt is not None:
                return registration.receipt
            if registration.task is None:
                registration.task = asyncio.create_task(registration.window.call(
                    registration.claim_writer, context, binding, claimed))
            task = registration.task
        receipt = await asyncio.shield(task)
        if (type(receipt) is not DispatchGraphClaimReceiptV1
                or receipt.context_digest != canonical_digest(context)
                or receipt.graph_namespace != binding.graph_namespace
                or receipt.graph_incarnation != binding.graph_incarnation):
            raise RuntimeError("reverse graph claim writer returned invalid receipt")
        registration.receipt = receipt
        return receipt

    async def serve_connection(self, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter) -> None:
        profile = self.profile
        try:
            tls = writer.get_extra_info("ssl_object")
            certificate = tls.getpeercert(binary_form=True) if tls else None
            if (certificate is None or hashlib.sha256(certificate).hexdigest()
                    != profile.expected_authority_certificate_sha256):
                return
            line = await asyncio.wait_for(reader.readuntil(b"\n"),
                                          profile.timeout_seconds)
            if len(line) > profile.max_message_bytes:
                return
            receipt = await self._claim(json.loads(line))
            data = json.dumps({"receipt": to_wire(receipt)}, sort_keys=True,
                              separators=(",", ":"), allow_nan=False).encode() + b"\n"
            if len(data) > profile.max_message_bytes:
                return
            writer.write(data)
            await asyncio.wait_for(writer.drain(), profile.timeout_seconds)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                TimeoutError, TypeError, ValueError, RuntimeError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, RuntimeError):
                pass

    async def start(self, host: str, port: int) -> asyncio.AbstractServer:
        return await asyncio.start_server(
            self.serve_connection, host, port, ssl=self.profile.ssl_context(),
            ssl_handshake_timeout=self.profile.timeout_seconds,
            limit=self.profile.max_message_bytes)


async def begin_handoff_with_reverse_claim(
    *, worker: GraphWorker, server: HostReverseGraphClaimServer,
    claimed: MutationReceiptV2, handoff_id: str,
    claim_writer: Callable,
    begin: Callable[[MutationReceiptV2, str], Awaitable[object]],
    recover: Callable[[MutationReceiptV2, str], Awaitable[object]] | None = None,
) -> HandoffStartV2:
    """Drain GraphWorker, register callback, then call Authority off worker.

    A failed or lost RPC stays HOLD. A caller-supplied recovery may query the
    same handoff while the lease is held; this helper never authorizes a send.
    """
    if (type(worker) is not GraphWorker or type(server) is not HostReverseGraphClaimServer
            or type(claimed) is not MutationReceiptV2
            or type(claimed.pending.binding) is not ExecutionBindingV2
            or claimed.pending.phase != "claimed"
            or claimed.durable_state != "committed"
            or type(handoff_id) is not str or not handoff_id
            or not callable(begin) or not callable(claim_writer)
            or (recover is not None and not callable(recover))):
        raise ValueError("reverse handoff requires a committed V2 claim and writer")
    binding = claimed.pending.binding
    context = DispatchHandoffContextV1(
        permit=replace(claimed.pending.permit,
                       revision=claimed.updated_revision,
                       pinned_anchor=claimed.after_anchor),
        claimed_receipt_digest=canonical_digest(claimed),
        binding_digest=canonical_digest(binding), handoff_id=handoff_id)

    def require_exact_start(start: object) -> HandoffStartV2:
        if (type(start) is not HandoffStartV2
                or start.handoff_id != handoff_id
                or start.namespace != context.permit.namespace
                or start.operation_id != context.permit.operation_id
                or start.effect_id != context.permit.effect_id
                or start.claim_digest != context.claimed_receipt_digest
                or start.binding_digest != context.binding_digest
                or start.permit != context.permit):
            raise RuntimeError("Authority handoff response identity differs")
        return start

    async with worker.exclusive_callback_window() as window:
        async with server.register(context=context, binding=binding, claimed=claimed,
                                   window=window, claim_writer=claim_writer):
            task = asyncio.create_task(begin(claimed, handoff_id))
            try:
                return require_exact_start(await asyncio.shield(task))
            except asyncio.CancelledError:
                # The remote worker may still be in the graph callback. Keep
                # the lease until this local RPC and any started graph call end.
                try:
                    await asyncio.shield(task)
                except Exception:
                    if recover is not None:
                        await asyncio.shield(recover(claimed, handoff_id))
                raise
            except Exception:
                if recover is None:
                    raise
                return require_exact_start(await recover(claimed, handoff_id))


__all__ = ("AdministratorHostReverseProfile", "HostReverseGraphClaimServer",
           "begin_handoff_with_reverse_claim")
