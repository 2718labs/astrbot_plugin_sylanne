"""Bounded trust in an installed host's OneBot ``call_action`` report.

This verifier does not prove recipient delivery or reading. Authority has
already authenticated the mTLS peer, original claim, durable handoff start,
graph claim, and exact route before invoking it. The installation deliberately
trusts that peer's AstrBot sender to report the adapter's return value.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .v2_contract import ExecutionBindingV2, MutationReceiptV2, PlatformObservationV2


_PEER_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE = "astrbot:onebot:call_action"


@dataclass(frozen=True, slots=True)
class HostOneBotObservationInstallationV2:
    """Administrator-pinned observation identity for one Authority namespace."""

    peer_certificate_sha256: str
    profile_id: str
    adapter_ref: str
    account_ref: str
    clock_source_ref: str

    def __post_init__(self) -> None:
        if type(self.profile_id) is not str or not self.profile_id:
            raise ValueError("installed observation profile is invalid")
        # Validate the remaining independent values before service startup.
        InstalledHostOneBotObservationVerifierV2(
            namespace="installed:validation",
            peer_certificate_sha256=self.peer_certificate_sha256,
            adapter_ref=self.adapter_ref, account_ref=self.account_ref,
            clock_source_ref=self.clock_source_ref)


class InstalledHostOneBotObservationVerifierV2:
    """Accept only a pinned installation's host-observed ACK or uncertainty.

    The ``subject`` is the service-derived mTLS subject, not a field supplied
    by the observation. A compromised or incorrectly installed host remains
    able to misreport its own adapter result; no universal OneBot 11 readback
    proves the recipient received or read a message.
    """

    def __init__(self, *, namespace: str, peer_certificate_sha256: str,
                 adapter_ref: str, account_ref: str,
                 clock_source_ref: str) -> None:
        if (type(namespace) is not str or not namespace
                or type(peer_certificate_sha256) is not str
                or not _PEER_SHA256.fullmatch(peer_certificate_sha256)
                or type(adapter_ref) is not str or not adapter_ref
                or type(clock_source_ref) is not str or not clock_source_ref):
            raise ValueError("installed observation identity is invalid")
        try:
            account = json.loads(account_ref)
        except (TypeError, ValueError) as exc:
            raise ValueError("installed OneBot account is invalid") from exc
        if (type(account) is not list or len(account) != 3
                or any(type(item) is not str or not item for item in account)
                or account[1] != "aiocqhttp"
                or not account[2].isascii() or not account[2].isdigit()
                or account[2].startswith("0")
                or json.dumps(account, ensure_ascii=True,
                              separators=(",", ":")) != account_ref):
            raise ValueError("installed OneBot account is invalid")
        self.namespace = namespace
        self.subject = "mtls:sha256:" + peer_certificate_sha256
        self.adapter_ref = adapter_ref
        self.account_ref = account_ref
        self.clock_source_ref = clock_source_ref

    def __call__(self, namespace: str, claimed_receipt: MutationReceiptV2,
                 observation: PlatformObservationV2) -> PlatformObservationV2 | None:
        if (type(claimed_receipt) is not MutationReceiptV2
                or type(observation) is not PlatformObservationV2
                or type(claimed_receipt.pending.binding) is not ExecutionBindingV2
                or namespace != self.namespace
                or claimed_receipt.pending.permit.namespace != self.namespace
                or claimed_receipt.pending.permit.subject != self.subject
                or claimed_receipt.pending.phase != "claimed"
                or claimed_receipt.durable_state != "committed"
                or observation.binding != claimed_receipt.pending.binding):
            return None
        origin = observation.binding.origin
        if (origin.adapter_ref != self.adapter_ref
                or origin.account_ref != self.account_ref
                or observation.adapter_ref != self.adapter_ref
                or observation.account_ref != self.account_ref
                or observation.destination_ref != origin.destination_ref
                or observation.evidence_source_ref != _SOURCE
                or observation.time_source_ref != self.clock_source_ref
                or observation.binding.clock_policy_ref != self.clock_source_ref
                or observation.platform_request_id is not None
                or observation.observation_id != "observation:" + hashlib.sha256(
                    observation.handoff_id.encode()).hexdigest()):
            return None
        if observation.outcome == "accepted":
            # DTO validation already requires an exact positive decimal ID.
            return observation
        if (observation.outcome == "unknown"
                and observation.platform_message_id is None):
            return observation
        return None


__all__ = [
    "HostOneBotObservationInstallationV2",
    "InstalledHostOneBotObservationVerifierV2",
]
