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
    ExecutionBindingV2, MutationReceiptV2, OwnerDispatchWitnessV1,
    AuthorityDispatchSnapshotV1,
    canonical_digest, from_wire, to_wire,
)
from ..authority_service.v2_execution_bridge import HandoffStartV2
from ..authority_service.reverse_handoff import (
    require_exact_authority_snapshot, require_exact_owner_witness,
    require_exact_reverse_handoff_identity,
)
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
    witness: OwnerDispatchWitnessV1 | None = None
    snapshot: AuthorityDispatchSnapshotV1 | None = None
    contact_policy_capsule: object | None = None
    task: asyncio.Task | None = None
    receipt: DispatchGraphClaimReceiptV1 | None = None


class HandoffDecisionWindow:
    """One fresh-start decision capability while GraphWorker remains drained.

    A replay or a duplicate take cannot supply a new sender with a fresh start.
    The future dispatcher must make its single send/no-send decision before the
    surrounding async context exits. This class does not send anything.
    """

    def __init__(self, start: HandoffStartV2, registration: _Registration) -> None:
        self._start = start
        self._registration = registration
        self._open = True
        self._taken = False

    @property
    def replay(self) -> bool:
        return self._start.replay

    def take_fresh_start(self) -> HandoffStartV2:
        if not self._open or self._taken or self._start.replay:
            raise RuntimeError("no fresh handoff decision remains")
        if (self._registration.task is None
                or self._registration.receipt != self._start.graph_claim_receipt):
            raise RuntimeError("fresh handoff lacks its registered graph callback")
        self._taken = True
        return self._start

    def _close(self) -> None:
        self._open = False


class HostReverseGraphClaimServer:
    """A content-free callback listener; caller owns its network exposure."""

    def __init__(self, profile: AdministratorHostReverseProfile) -> None:
        if type(profile) is not AdministratorHostReverseProfile:
            raise TypeError("administrator host reverse profile required")
        self.profile = profile
        self._registration: _Registration | None = None
        self._lock = asyncio.Lock()
        self._first_owner = None

    def install_first_owner_v1(self, service):
        from .first_owner_reverse_v1 import InstalledFirstOwnerGraphCommitV1
        from ..graph_coordinator import namespace_ref
        if (type(service) is not InstalledFirstOwnerGraphCommitV1 or self._first_owner is not None
                or namespace_ref(service.namespace) != self.profile.namespace
                or service.installation.installation_policy.installation_id != self.profile.installation_id):
            raise TypeError('one actual installed first Owner Host service required')
        self._first_owner = service

    @asynccontextmanager
    async def register(self, *, context: DispatchHandoffContextV1,
                       binding: ExecutionBindingV2,
                       claimed: MutationReceiptV2,
                       window: object, claim_writer: Callable):
        """Register exactly one claim callback after acquiring GraphWorker lease.

        The caller must hold the window through the Authority response and any
        recovery for the same handoff. This port does not supply a claim writer.
        """
        require_exact_reverse_handoff_identity(
            self.profile.namespace, context, binding, claimed,
        )
        if (not callable(claim_writer)
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
                from ..runtime.contact_dispatch_host_v3 import _PreparedContactP2WriterV1
                if type(registration.claim_writer) is _PreparedContactP2WriterV1:
                    registration.claim_writer.close()

    async def _claim(self, message: object) -> DispatchGraphClaimReceiptV1:
        profile = self.profile
        ordinary_fields = {"profile_id", "installation_id", "namespace", "context",
            "binding", "claimed_receipt", "owner_witness", "authority_snapshot"}
        if (type(message) is not dict or set(message) not in (
                ordinary_fields, ordinary_fields | {"contact_policy_capsule"})
                or (message["profile_id"], message["installation_id"],
                    message["namespace"]) !=
                   (profile.profile_id, profile.installation_id, profile.namespace)):
            raise RuntimeError("reverse graph claim installation identity differs")
        context = from_wire(message["context"])
        binding = from_wire(message["binding"])
        claimed = from_wire(message["claimed_receipt"])
        witness = from_wire(message["owner_witness"])
        snapshot = from_wire(message["authority_snapshot"])
        if (type(context) is not DispatchHandoffContextV1
                or type(binding) is not ExecutionBindingV2
                or type(claimed) is not MutationReceiptV2
                or type(witness) is not OwnerDispatchWitnessV1
                or type(snapshot) is not AuthorityDispatchSnapshotV1
                or to_wire(context) != message["context"]
                or to_wire(binding) != message["binding"]
                or to_wire(claimed) != message["claimed_receipt"]
                or to_wire(witness) != message["owner_witness"]
                or to_wire(snapshot) != message["authority_snapshot"]):
            raise RuntimeError("reverse graph claim wire identity differs")
        require_exact_reverse_handoff_identity(
            profile.namespace, context, binding, claimed,
        )
        require_exact_owner_witness(profile, context, binding, witness)
        require_exact_authority_snapshot(context, witness, snapshot)
        contact_capsule = None
        if "contact_policy_capsule" in message:
            from ..authority_service.contact_p2_contract_v1 import (
                contact_p2_policy_capsule_from_wire_v1, require_exact_contact_p2_policy_capsule_v1,
            )
            contact_capsule = contact_p2_policy_capsule_from_wire_v1(message["contact_policy_capsule"])
            require_exact_contact_p2_policy_capsule_v1(context,binding,claimed,witness,snapshot,contact_capsule)
        elif binding.origin.proactive_contact is True:
            raise RuntimeError("Contact reverse has no current Core policy capsule")
        recheck_contact = False
        async with self._lock:
            registration = self._registration
            if (registration is None or registration.context != context
                    or registration.binding != binding
                    or registration.claimed != claimed):
                raise RuntimeError("reverse graph claim handoff is not registered")
            if registration.witness is not None and registration.witness != witness:
                raise RuntimeError("reverse graph claim Owner witness changed")
            if registration.snapshot is not None and registration.snapshot != snapshot:
                raise RuntimeError("reverse graph claim Authority snapshot changed")
            if registration.task is not None:
                prior = registration.contact_policy_capsule
                if contact_capsule is not None and prior is not None:
                    from dataclasses import replace
                    if (contact_capsule.observed_at_utc < prior.observed_at_utc
                            or replace(contact_capsule,observed_at_utc=prior.observed_at_utc) != prior):
                        raise RuntimeError("Contact reverse current policy capsule changed")
                elif prior != contact_capsule:
                    raise RuntimeError("Contact reverse current policy variant changed")
            if registration.receipt is not None and contact_capsule is None:
                return registration.receipt
            recheck_contact = contact_capsule is not None and registration.task is not None
            if registration.task is None:
                registration.witness = witness
                registration.snapshot = snapshot
                registration.contact_policy_capsule = contact_capsule
                args = (context, binding, claimed, witness, snapshot)
                if contact_capsule is not None:
                    from ..runtime.contact_dispatch_host_v3 import require_prepared_contact_p2_writer_v1
                    require_prepared_contact_p2_writer_v1(registration.claim_writer)
                    args = (*args, contact_capsule)
                registration.task = asyncio.create_task(registration.window.call(
                    registration.claim_writer, *args))
            task = registration.task
        receipt = await asyncio.shield(task)
        if recheck_contact:
            from ..runtime.contact_dispatch_host_v3 import require_prepared_contact_p2_writer_v1
            actual_writer = require_prepared_contact_p2_writer_v1(registration.claim_writer)
            receipt = await registration.window.call(actual_writer.recheck,context,binding,claimed,
                witness,snapshot,contact_capsule,receipt)
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
            message = json.loads(line)
            from ..authority_service.first_owner_reverse_v1 import SCHEMA as FIRST_OWNER_SCHEMA
            if type(message) is dict and message.get('schema') == FIRST_OWNER_SCHEMA:
                if self._first_owner is None:
                    raise RuntimeError('first Owner Host service unavailable')
                from ..authority_service.v2_owner_contract import to_wire as owner_to_wire
                proof = await self._first_owner.commit(message)
                result = {'proof': owner_to_wire(proof)}
            else:
                receipt = await self._claim(message)
                result = {'receipt': to_wire(receipt)}
            data = json.dumps(result, sort_keys=True,
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


@asynccontextmanager
async def begin_handoff_with_reverse_claim(
    *, worker: GraphWorker, server: HostReverseGraphClaimServer,
    claimed: MutationReceiptV2, handoff_id: str,
    claim_writer: Callable,
    begin: Callable[[MutationReceiptV2, str], Awaitable[object]],
    recover: Callable[[MutationReceiptV2, str], Awaitable[object]] | None = None,
) -> HandoffDecisionWindow:
    """Keep GraphWorker drained through the caller's one send/no-send decision.

    A failed or lost RPC stays HOLD. A caller-supplied recovery may query the
    same handoff while the lease is held. Never make an Authority RPC from the
    graph callback or while holding the graph store lock. This helper never
    sends or turns a GraphCoordinator HOLD into a claim.
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
    require_exact_reverse_handoff_identity(
        server.profile.namespace, context, binding, claimed,
    )

    def require_exact_start(start: object) -> HandoffStartV2:
        if (type(start) is not HandoffStartV2
                or start.handoff_id != handoff_id
                or start.namespace != context.permit.namespace
                or start.operation_id != context.permit.operation_id
                or start.effect_id != context.permit.effect_id
                or start.claim_digest != context.claimed_receipt_digest
                or start.binding_digest != context.binding_digest
                or start.permit != context.permit
                or (not start.replay and (
                    start.graph_claim_receipt is None
                    or start.graph_claim_ref
                    != start.graph_claim_receipt.graph_claim_ref))):
            raise RuntimeError("Authority handoff response identity differs")
        return start

    async with worker.exclusive_callback_window() as window:
        async with server.register(context=context, binding=binding, claimed=claimed,
                                   window=window, claim_writer=claim_writer) as registration:
            task = asyncio.create_task(begin(claimed, handoff_id))
            try:
                start = require_exact_start(await asyncio.shield(task))
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
                start = require_exact_start(await recover(claimed, handoff_id))
            if (not start.replay
                    and (registration.task is None
                         or registration.receipt != start.graph_claim_receipt)):
                raise RuntimeError("fresh handoff did not use registered graph callback")
            decision = HandoffDecisionWindow(start, registration)
            try:
                yield decision
            finally:
                decision._close()


__all__ = ("AdministratorHostReverseProfile", "HostReverseGraphClaimServer",
           "HandoffDecisionWindow", "begin_handoff_with_reverse_claim")
