"""Passive v2 C02 seal for a business deadline beyond the worker lease.

This contract binds a *previously signed* C02 quote and a separate business
deadline at first seal. It neither signs the quote nor authorizes body release,
job completion, budget mutation, or a graph commit. Production must verify the
quote through the installed D02 issuer and the fact through Authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
import re

from ..authority_service.v2_terminal_c02_recovery_contract import (
    OriginalC02ResultKeyV1, TerminalRecoveryReadFactV1,
)
from ..runtime_contracts import (
    DomainBundle, NamespaceId, canonical_digest, canonical_serialize,
)
from .c02_bundle_codec import c02_bundle_from_wire, c02_bundle_to_wire
from .first_ingress_c02_identity import first_ingress_c02_consumer_operation_id_v1
from .issuers import (
    D06_FIRST_INGRESS_C02_WORK_KIND, ResourceQuote,
    d06_first_ingress_c02_quote_id,
)


SCHEMA = "sylanne.first-ingress-c02-candidate.v2"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _finite(value: float, name: str) -> float:
    if type(value) not in {float, int} or not math.isfinite(value):
        raise ValueError(f"invalid {name}")
    return float(value)


@dataclass(frozen=True, slots=True)
class FrozenTerminalC02CandidateV2:
    """Content-free seal; status does not grant a commit or a new budget."""

    original_key: OriginalC02ResultKeyV1
    bundle_digest: str
    quote_id: str
    quote_version: int
    quote_digest: str
    sealed_at_utc: float
    original_worker_lease_expires_utc: float
    business_deadline_utc: float
    admin_deadline_after_seconds: float
    root_grant_valid_until_utc: float
    schema: str = SCHEMA
    status: str = "frozen_v2_unqualified"

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA or self.status != "frozen_v2_unqualified"
                or type(self.original_key) is not OriginalC02ResultKeyV1
                or type(self.quote_version) is not int or self.quote_version != 1
                or type(self.bundle_digest) is not str
                or _DIGEST.fullmatch(self.bundle_digest) is None
                or type(self.quote_digest) is not str
                or _DIGEST.fullmatch(self.quote_digest) is None):
            raise ValueError("v2 C02 frozen identity differs")
        key = self.original_key
        if self.quote_id != d06_first_ingress_c02_quote_id(
                key.namespace, self.consumer_operation_id):
            raise ValueError("v2 C02 quote identity differs")
        sealed = _finite(self.sealed_at_utc, "seal time")
        lease = _finite(self.original_worker_lease_expires_utc, "worker lease")
        deadline = _finite(self.business_deadline_utc, "business deadline")
        window = _finite(self.admin_deadline_after_seconds, "admin window")
        grant = _finite(self.root_grant_valid_until_utc, "root grant expiry")
        if (window <= 0 or not sealed < lease or not sealed < deadline
                or deadline > min(sealed + window, grant)):
            raise ValueError("v2 C02 deadline exceeds original admin or grant bounds")

    @property
    def consumer_operation_id(self) -> str:
        key = self.original_key
        return first_ingress_c02_consumer_operation_id_v1(
            namespace=key.namespace, authority_id=key.authority_id,
            authority_namespace=key.authority_namespace,
            installation_id=key.installation_id, job_id=key.job_id,
            acquire_operation_id=key.acquire_operation_id,
            original_operation_id=key.original_operation_id,
            call_id=key.call_id, binding_digest=key.binding_digest,
            model_request_digest=key.model_request_digest)


@dataclass(frozen=True, slots=True)
class FrozenTerminalC02InspectionV2:
    bundle: DomainBundle
    seal: FrozenTerminalC02CandidateV2
    status: str = "frozen_v2_unqualified"


def inspect_frozen_terminal_c02_candidate_v2(
    *, namespace: NamespaceId, operation_id: str,
    seal: FrozenTerminalC02CandidateV2, bundle_json: str,
    quote_json: str,
) -> FrozenTerminalC02InspectionV2:
    """Check exact frozen bytes and identities; the D02 signature remains external."""
    if (type(namespace) is not NamespaceId
            or type(seal) is not FrozenTerminalC02CandidateV2
            or seal.original_key.namespace != namespace
            or seal.consumer_operation_id != operation_id):
        raise ValueError("v2 C02 namespace or operation differs")
    try:
        bundle = c02_bundle_from_wire(bundle_json)
        raw_quote = json.loads(quote_json)
        quote = ResourceQuote(**raw_quote)
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError("v2 C02 frozen bundle or quote wire differs") from exc
    envelope = bundle.envelope
    key = seal.original_key
    refs = envelope.version_guard.resource_lease_versions
    if (c02_bundle_to_wire(bundle) != bundle_json
            or canonical_serialize(asdict(quote)) != quote_json
            or bundle.digest != seal.bundle_digest
            or canonical_digest(asdict(quote)) != seal.quote_digest
            or (quote.quote_id, quote.version) != (seal.quote_id, seal.quote_version)
            or (quote.bot_id, quote.persona_id) != namespace.as_tuple
            or (quote.operation_id, quote.activity_id,
                quote.parent_budget_lease_ref, quote.work_kind,
                quote.deadline_utc, quote.valid_until_utc,
                quote.required_worker_fence) !=
               (operation_id, envelope.identity.activity_id,
                envelope.parent_budget_lease_ref,
                D06_FIRST_INGRESS_C02_WORK_KIND,
                seal.business_deadline_utc, seal.business_deadline_utc,
                envelope.authority.worker_fence)
            or len(refs) != 1
            or (refs[0].ref, refs[0].version) != (seal.quote_id, seal.quote_version)
            or envelope.identity.phase != "first_ingress_c02"
            or envelope.identity.operation_id != operation_id
            or envelope.authority.namespace != namespace
            or envelope.deadline_utc != seal.business_deadline_utc
            or envelope.authority.actor == ""
            or envelope.authority.worker_fence is None
            or key.installation_id == ""):
        raise ValueError("v2 C02 frozen quote or bundle differs")
    return FrozenTerminalC02InspectionV2(bundle, seal)


def recovery_fact_matches_frozen_v2(
    *, seal: FrozenTerminalC02CandidateV2,
    fact: TerminalRecoveryReadFactV1, trusted_now_utc: float,
) -> bool:
    """Identity/deadline preflight only; current graph/Authority still required."""
    if (type(seal) is not FrozenTerminalC02CandidateV2
            or type(fact) is not TerminalRecoveryReadFactV1):
        return False
    try:
        now = _finite(trusted_now_utc, "current time")
    except ValueError:
        return False
    return (seal.original_worker_lease_expires_utc <= now
            < seal.business_deadline_utc
            and fact.request.original_key == seal.original_key
            and fact.request.consumer_operation_id == seal.consumer_operation_id
            and fact.result_digest == seal.original_key.stable_result_digest)


__all__ = ("SCHEMA", "FrozenTerminalC02CandidateV2",
           "FrozenTerminalC02InspectionV2",
           "inspect_frozen_terminal_c02_candidate_v2",
           "recovery_fact_matches_frozen_v2")
