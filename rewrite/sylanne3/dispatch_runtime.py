"""Fail-closed final admission and the sole external handoff sequence.

The runtime owns ordering, not business truth.  A trusted business authority
must atomically validate RequiredChecks and issue a claim.  A separately
configured platform capability performs the one external handoff.  This file
has no recording transport or success fallback.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
import time
from typing import Protocol

from .runtime_contracts import RUNTIME_SCHEMA
from .runtime_journal import RecoveryConstraintFootprint


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@#=+-]{0,255}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OPERATION_STATES = frozenset({"absent", "claimed", "observed", "unknown", "settled"})
_OBSERVATION_STATES = frozenset({
    "handed_off", "accepted", "delivered", "read", "external_confirmed", "failed", "unknown",
})


class DispatchUnavailable(RuntimeError):
    """A required trusted authority or platform capability is unavailable."""


class DispatchBlocked(RuntimeError):
    """Final admission failed before platform handoff."""


class HandoffUncertain(RuntimeError):
    """The adapter cannot prove whether the provider accepted the effect."""

    def __init__(self, observation_ref: str):
        _identifier(observation_ref, "observation_ref")
        super().__init__("external handoff result is unknown")
        self.observation_ref = observation_ref


def _identifier(value: object, label: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} must be a stable content-free identifier")
    return value


def _refs(values: object, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise TypeError(f"{label} must be a tuple")
    if not allow_empty and not values:
        raise ValueError(f"{label} must not be empty")
    for item in values:
        _identifier(item, label)
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must not repeat references")
    return values


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{label} must be a canonical lowercase SHA-256 digest")
    return value


def _generation(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a nonnegative exact integer")
    return value


def _positive(value: object, label: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{label} must be a positive exact integer")
    return value


def _finite(value: object, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{label} must be finite")
    return float(value)


@dataclass(frozen=True)
class AdmissionAuthorityDescriptor:
    authority_ref: str
    contract_version: str

    def __post_init__(self) -> None:
        _identifier(self.authority_ref, "authority_ref")
        if self.contract_version != RUNTIME_SCHEMA:
            raise ValueError("admission authority contract version is incompatible")


@dataclass(frozen=True)
class PlatformCapabilityDescriptor:
    capability_ref: str
    provider_id: str
    supports_handoff: bool
    supports_query: bool
    verifies_payload_digest: bool

    def __post_init__(self) -> None:
        _identifier(self.capability_ref, "capability_ref")
        _identifier(self.provider_id, "provider_id")
        if any(type(value) is not bool for value in (
            self.supports_handoff, self.supports_query, self.verifies_payload_digest,
        )):
            raise TypeError("platform capability flags must be bool")


@dataclass(frozen=True)
class RecoveryGateDescriptor:
    gate_ref: str
    contract_version: str

    def __post_init__(self) -> None:
        _identifier(self.gate_ref, "gate_ref")
        if self.contract_version != RUNTIME_SCHEMA:
            raise ValueError("recovery gate contract version is incompatible")


@dataclass(frozen=True)
class DispatchRequest:
    namespace: str
    operation_id: str
    activity_id: str
    effect_id: str
    attempt_id: str
    command_digest: str
    payload_ref: str
    payload_digest: str
    platform_capability_ref: str
    required_check_refs: tuple[str, ...]
    dispatch_generation: int
    activation_generation: int
    worker_fence: int
    content_fence: str
    cancel_epoch: int
    footprint: RecoveryConstraintFootprint
    proactive_contact: bool
    segment_authorization_ref: str | None = None
    segment_manifest_digest: str | None = None
    segment_index: int | None = None
    segment_count: int | None = None
    contact_policy_check_ref: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "namespace", "operation_id", "activity_id", "effect_id", "attempt_id",
            "payload_ref", "platform_capability_ref", "content_fence",
        ):
            _identifier(getattr(self, name), name)
        _digest(self.command_digest, "command_digest")
        _digest(self.payload_digest, "payload_digest")
        object.__setattr__(self, "required_check_refs", _refs(
            self.required_check_refs, "required_check_refs"
        ))
        for name in ("dispatch_generation", "activation_generation", "worker_fence", "cancel_epoch"):
            _generation(getattr(self, name), name)
        if type(self.proactive_contact) is not bool:
            raise TypeError("proactive_contact must be bool")
        if not isinstance(self.footprint, RecoveryConstraintFootprint):
            raise TypeError("footprint must be RecoveryConstraintFootprint")
        if (
            self.footprint.namespace != self.namespace
            or self.footprint.activity_id != self.activity_id
            or self.footprint.effect_id != self.effect_id
        ):
            raise ValueError("recovery footprint identity does not match dispatch request")
        contact = self.footprint.contact_id is not None
        segment_values = (
            self.segment_authorization_ref, self.segment_manifest_digest,
            self.segment_index, self.segment_count,
        )
        if contact:
            if any(value is None for value in segment_values):
                raise ValueError("contact segments require finite authorization")
            _identifier(self.segment_authorization_ref, "segment_authorization_ref")
            _digest(self.segment_manifest_digest, "segment_manifest_digest")
            count = _positive(self.segment_count, "segment_count")
            if count > 3:
                raise ValueError("alpha1 expression batches may contain at most three segments")
            if type(self.segment_index) is not int or not 0 <= self.segment_index < count:
                raise ValueError("segment_index must identify an item in the finite manifest")
            if self.proactive_contact:
                _identifier(self.contact_policy_check_ref, "contact_policy_check_ref")
                if self.contact_policy_check_ref not in self.required_check_refs:
                    raise ValueError("proactive ContactPolicyCheck must be among required checks")
                if not self.footprint.quota_occupancies:
                    raise ValueError("proactive contact must carry its quota occupancy footprint")
            elif self.contact_policy_check_ref is not None:
                raise ValueError("responsive contact cannot invent a proactive policy check")
            elif self.footprint.quota_occupancies or self.footprint.object_gate_keys:
                raise ValueError("responsive contact cannot occupy proactive quota or no-response gates")
        elif any(value is not None for value in segment_values) or self.contact_policy_check_ref is not None:
            raise ValueError("non-contact dispatch cannot carry segment authorization")
        elif self.proactive_contact:
            raise ValueError("proactive_contact requires a contact identity")


@dataclass(frozen=True)
class BusinessOperation:
    status: str
    operation_id: str
    effect_id: str | None
    command_digest: str | None
    admission_ref: str | None
    observation_ref: str | None
    settlement_ref: str | None

    def __post_init__(self) -> None:
        if self.status not in _OPERATION_STATES:
            raise ValueError("unsupported business operation status")
        _identifier(self.operation_id, "operation_id")
        for name in ("effect_id", "admission_ref", "observation_ref", "settlement_ref"):
            _identifier(getattr(self, name), name, optional=True)
        if self.command_digest is not None:
            _digest(self.command_digest, "command_digest")
        if self.status == "absent" and any(
            value is not None for value in (
                self.effect_id, self.command_digest, self.admission_ref,
                self.observation_ref, self.settlement_ref,
            )
        ):
            raise ValueError("absent operation cannot carry execution identity")
        if self.status != "absent" and None in (
            self.effect_id, self.command_digest, self.admission_ref,
        ):
            raise ValueError("existing operation requires stable execution identity")
        if self.status in {"observed", "unknown", "settled"} and self.observation_ref is None:
            raise ValueError("observed operation states require an observation receipt")
        if self.status == "settled" and self.settlement_ref is None:
            raise ValueError("settled operation requires a settlement receipt")

    @classmethod
    def absent(cls, operation_id: str) -> "BusinessOperation":
        return cls("absent", operation_id, None, None, None, None, None)


@dataclass(frozen=True)
class RecoveryDecision:
    status: str
    effect_id: str
    command_digest: str
    activation_generation: int
    content_fence: str
    proof_ref: str
    operation: BusinessOperation | None

    def __post_init__(self) -> None:
        if self.status not in {"clear", "unresolved", "unavailable"}:
            raise ValueError("unsupported recovery decision status")
        _identifier(self.effect_id, "effect_id")
        _digest(self.command_digest, "command_digest")
        _generation(self.activation_generation, "activation_generation")
        _identifier(self.content_fence, "content_fence")
        _identifier(self.proof_ref, "proof_ref")
        if self.status == "unresolved":
            if not isinstance(self.operation, BusinessOperation) or self.operation.status == "absent":
                raise ValueError("unresolved recovery decision requires the original operation")
            if (
                self.operation.effect_id != self.effect_id
                or self.operation.command_digest != self.command_digest
            ):
                raise ValueError("recovered operation identity does not match the unresolved effect")
        elif self.operation is not None:
            raise ValueError("only an unresolved decision may carry a recovered operation")


@dataclass(frozen=True)
class BusinessDispatchClaim:
    admission_ref: str
    dispatch_id: str
    operation_id: str
    effect_id: str
    command_digest: str
    payload_digest: str
    platform_capability_ref: str
    verified_check_refs: tuple[str, ...]
    dispatch_generation: int
    activation_generation: int
    worker_fence: int
    content_fence: str
    cancel_epoch: int
    contact_id: str | None
    segment_id: str | None
    proactive_contact: bool
    contact_occupancy_ref: str | None
    segment_authorization_ref: str | None
    segment_manifest_digest: str | None
    segment_index: int | None
    segment_count: int | None

    def __post_init__(self) -> None:
        for name in (
            "admission_ref", "dispatch_id", "operation_id", "effect_id",
            "platform_capability_ref", "content_fence",
        ):
            _identifier(getattr(self, name), name)
        _digest(self.command_digest, "command_digest")
        _digest(self.payload_digest, "payload_digest")
        object.__setattr__(self, "verified_check_refs", _refs(
            self.verified_check_refs, "verified_check_refs"
        ))
        for name in ("dispatch_generation", "activation_generation", "worker_fence", "cancel_epoch"):
            _generation(getattr(self, name), name)
        if type(self.proactive_contact) is not bool:
            raise TypeError("proactive_contact must be bool")
        for name in (
            "contact_id", "segment_id", "contact_occupancy_ref",
            "segment_authorization_ref",
        ):
            _identifier(getattr(self, name), name, optional=True)
        if self.segment_manifest_digest is not None:
            _digest(self.segment_manifest_digest, "segment_manifest_digest")
        contact = self.contact_id is not None
        if contact != all(value is not None for value in (
            self.segment_id,
            self.segment_authorization_ref, self.segment_manifest_digest,
            self.segment_index, self.segment_count,
        )):
            raise ValueError("contact claim must include finite segment authorization")
        if contact:
            count = _positive(self.segment_count, "segment_count")
            if count > 3 or type(self.segment_index) is not int or not 0 <= self.segment_index < count:
                raise ValueError("contact claim is outside the finite three-segment manifest")
            if self.proactive_contact != (self.contact_occupancy_ref is not None):
                raise ValueError("only proactive contact claims carry contact occupancy")
        elif self.segment_index is not None or self.segment_count is not None:
            raise ValueError("non-contact claim cannot carry segment position")
        elif self.proactive_contact or self.contact_occupancy_ref is not None:
            raise ValueError("non-contact claim cannot carry proactive occupancy")


@dataclass(frozen=True)
class CurrentDispatchPermit:
    permit_ref: str
    admission_ref: str
    dispatch_id: str
    operation_id: str
    effect_id: str
    command_digest: str
    payload_digest: str
    platform_capability_ref: str
    verified_check_refs: tuple[str, ...]
    dispatch_generation: int
    activation_generation: int
    worker_fence: int
    content_fence: str
    cancel_epoch: int
    contact_id: str | None
    segment_id: str | None
    proactive_contact: bool
    contact_occupancy_ref: str | None
    segment_authorization_ref: str | None
    segment_manifest_digest: str | None
    segment_index: int | None
    segment_count: int | None
    expires_at_monotonic: float

    def __post_init__(self) -> None:
        _identifier(self.permit_ref, "permit_ref")
        # Reuse the claim validator for all invariant-bearing fields.
        BusinessDispatchClaim(
            admission_ref=self.admission_ref,
            dispatch_id=self.dispatch_id,
            operation_id=self.operation_id,
            effect_id=self.effect_id,
            command_digest=self.command_digest,
            payload_digest=self.payload_digest,
            platform_capability_ref=self.platform_capability_ref,
            verified_check_refs=self.verified_check_refs,
            dispatch_generation=self.dispatch_generation,
            activation_generation=self.activation_generation,
            worker_fence=self.worker_fence,
            content_fence=self.content_fence,
            cancel_epoch=self.cancel_epoch,
            contact_id=self.contact_id,
            segment_id=self.segment_id,
            proactive_contact=self.proactive_contact,
            contact_occupancy_ref=self.contact_occupancy_ref,
            segment_authorization_ref=self.segment_authorization_ref,
            segment_manifest_digest=self.segment_manifest_digest,
            segment_index=self.segment_index,
            segment_count=self.segment_count,
        )
        object.__setattr__(self, "expires_at_monotonic", _finite(
            self.expires_at_monotonic, "expires_at_monotonic"
        ))


@dataclass(frozen=True)
class HandoffStartReceipt:
    """Linearization receipt consumed immediately before adapter handoff.

    The trusted admission authority issues this while serializing current
    deletion, migration, cancellation, worker, and content fences.  Once
    issued, later revocation treats the effect as in-flight.
    """

    start_ref: str
    permit_ref: str
    operation_id: str
    effect_id: str
    platform_capability_ref: str
    dispatch_generation: int
    activation_generation: int
    worker_fence: int
    content_fence: str
    cancel_epoch: int
    proactive_contact: bool
    segment_authorization_ref: str | None
    segment_manifest_digest: str | None
    segment_index: int | None
    segment_count: int | None

    def __post_init__(self) -> None:
        for name in (
            "start_ref", "permit_ref", "operation_id", "effect_id",
            "platform_capability_ref", "content_fence",
        ):
            _identifier(getattr(self, name), name)
        for name in ("dispatch_generation", "activation_generation", "worker_fence", "cancel_epoch"):
            _generation(getattr(self, name), name)
        if type(self.proactive_contact) is not bool:
            raise TypeError("proactive_contact must be bool")
        for name in ("segment_authorization_ref",):
            _identifier(getattr(self, name), name, optional=True)
        if self.segment_manifest_digest is not None:
            _digest(self.segment_manifest_digest, "segment_manifest_digest")
        segment = self.segment_authorization_ref is not None
        if segment != all(value is not None for value in (
            self.segment_manifest_digest, self.segment_index, self.segment_count,
        )):
            raise ValueError("handoff start must bind the complete finite segment grant")
        if segment:
            count = _positive(self.segment_count, "segment_count")
            if count > 3 or type(self.segment_index) is not int or not 0 <= self.segment_index < count:
                raise ValueError("handoff start is outside the finite three-segment manifest")


@dataclass(frozen=True)
class PlatformObservation:
    status: str
    observation_ref: str
    provider_request_ref: str | None

    def __post_init__(self) -> None:
        if self.status not in _OBSERVATION_STATES:
            raise ValueError("unsupported platform observation status")
        _identifier(self.observation_ref, "observation_ref")
        _identifier(self.provider_request_ref, "provider_request_ref", optional=True)


@dataclass(frozen=True)
class DispatchSettlement:
    status: str
    settlement_ref: str

    def __post_init__(self) -> None:
        if self.status not in {"settled", "unknown", "pending_confirmation", "failed"}:
            raise ValueError("unsupported dispatch settlement status")
        _identifier(self.settlement_ref, "settlement_ref")


@dataclass(frozen=True)
class DispatchResult:
    status: str
    operation_id: str
    effect_id: str
    admission_ref: str
    observation_ref: str | None
    settlement_ref: str | None
    journal_sequence: int | None
    handoff_attempted: bool


class AdmissionAuthority(Protocol):
    descriptor: AdmissionAuthorityDescriptor

    def lookup_operation(self, namespace: str, operation_id: str) -> BusinessOperation: ...

    def claim(self, request: DispatchRequest) -> BusinessDispatchClaim: ...

    def revalidate(
        self, claim: BusinessDispatchClaim, request: DispatchRequest
    ) -> CurrentDispatchPermit: ...

    def begin_handoff(
        self, permit: CurrentDispatchPermit, request: DispatchRequest
    ) -> HandoffStartReceipt: ...

    def settle(
        self, claim: BusinessDispatchClaim, observation: PlatformObservation
    ) -> DispatchSettlement: ...

    def settle_existing(
        self, operation: BusinessOperation, observation: PlatformObservation
    ) -> DispatchSettlement: ...


class PlatformCapability(Protocol):
    descriptor: PlatformCapabilityDescriptor

    def handoff(
        self, request: DispatchRequest, start: HandoffStartReceipt
    ) -> PlatformObservation: ...

    def query_original(
        self, request: DispatchRequest, operation: BusinessOperation
    ) -> PlatformObservation: ...


class ExecutionRecoveryGate(Protocol):
    descriptor: RecoveryGateDescriptor

    def check_current(self, request: DispatchRequest) -> RecoveryDecision: ...


class DispatchRuntime:
    """Coordinates one claim, journal prepare, handoff, observation, settlement.

    The authority and platform objects are trust-root dependencies supplied by
    the host.  This class never constructs substitutes and never releases a
    contact occupancy.  Recovery must query the original operation/effect.
    """

    def __init__(
        self, journal: object, admission_authority: AdmissionAuthority | None,
        platform_capability: PlatformCapability | None,
        recovery_gate: ExecutionRecoveryGate | None, *, monotonic_clock=None,
    ) -> None:
        if journal is None or not all(callable(getattr(journal, name, None))
                                      for name in ("prepare", "observe")):
            raise DispatchUnavailable("a durable execution journal is required")
        if admission_authority is None or not isinstance(
            getattr(admission_authority, "descriptor", None), AdmissionAuthorityDescriptor
        ):
            raise DispatchUnavailable("a trusted business admission authority is required")
        if not all(callable(getattr(admission_authority, name, None))
                   for name in (
                       "lookup_operation", "claim", "revalidate", "begin_handoff",
                       "settle", "settle_existing",
                   )):
            raise DispatchUnavailable("business admission authority is incomplete")
        descriptor = getattr(platform_capability, "descriptor", None)
        if (
            platform_capability is None
            or not isinstance(descriptor, PlatformCapabilityDescriptor)
            or not descriptor.supports_handoff
            or not descriptor.verifies_payload_digest
            or not callable(getattr(platform_capability, "handoff", None))
        ):
            raise DispatchUnavailable("an explicit platform handoff capability is required")
        if (
            recovery_gate is None
            or not isinstance(getattr(recovery_gate, "descriptor", None), RecoveryGateDescriptor)
            or not callable(getattr(recovery_gate, "check_current", None))
        ):
            raise DispatchUnavailable("an independently current execution recovery gate is required")
        self._journal = journal
        self._authority = admission_authority
        self._platform = platform_capability
        self._recovery = recovery_gate
        self._clock = monotonic_clock or time.monotonic

    def dispatch(self, request: DispatchRequest) -> DispatchResult:
        if not isinstance(request, DispatchRequest):
            raise TypeError("request must be DispatchRequest")
        if request.platform_capability_ref != self._platform.descriptor.capability_ref:
            raise DispatchBlocked("request is not bound to the configured platform capability")
        recovery = self._recovery.check_current(request)
        self._assert_recovery(recovery, request)
        if recovery.status == "unavailable":
            raise DispatchUnavailable("current execution recovery proof is unavailable")
        operation = self._authority.lookup_operation(request.namespace, request.operation_id)
        if not isinstance(operation, BusinessOperation):
            raise DispatchUnavailable("operation lookup returned an untrusted shape")
        if recovery.status == "unresolved":
            recovered = recovery.operation
            assert recovered is not None
            if operation.status != "absent":
                self._assert_operation_identity(operation, request)
                if operation != recovered:
                    raise DispatchBlocked("business operation conflicts with recovery authority")
            return self._query_original(request, recovered)
        if operation.status != "absent":
            self._assert_operation_identity(operation, request)
            if operation.status == "settled":
                return DispatchResult(
                    "settled", request.operation_id, request.effect_id,
                    operation.admission_ref or "", operation.observation_ref,
                    operation.settlement_ref, None, False,
                )
            return self._query_original(request, operation)

        claim = self._authority.claim(request)
        self._assert_claim(claim, request)
        prepared = self._journal.prepare(
            effect_id=request.effect_id,
            command_digest=request.command_digest,
            dispatch_generation=request.dispatch_generation,
            activation_generation=request.activation_generation,
            admission_ref=claim.admission_ref,
            footprint=request.footprint,
        )
        permit = self._authority.revalidate(claim, request)
        self._assert_permit(permit, claim, request)
        start = self._authority.begin_handoff(permit, request)
        self._assert_handoff_start(start, permit, request)
        claimed = self._journal.observe(
            request.effect_id, request.command_digest, "claimed", start.start_ref,
        )
        try:
            # The configured adapter is contractually required to resolve the
            # opaque payload_ref and verify its bytes against payload_digest
            # before issuing the provider call.  No such capability means the
            # constructor fails closed.
            observation = self._platform.handoff(request, start)
            if not isinstance(observation, PlatformObservation):
                raise DispatchUnavailable("platform returned an untrusted observation shape")
        except HandoffUncertain as exc:
            observation = PlatformObservation("unknown", exc.observation_ref, None)
        except Exception:
            # The adapter call began; without a typed definite-negative receipt,
            # the only safe classification is unknown.  This is a local error
            # reference, never a fabricated provider acknowledgement.
            observation = PlatformObservation(
                "unknown", f"runtime:handoff-unknown:{request.operation_id}", None
            )
        observed = self._journal.observe(
            request.effect_id, request.command_digest,
            self._journal_phase(observation.status), observation.observation_ref,
        )
        return self._settle(
            request, claim, observation, observed.execution_seq, handoff_attempted=True,
        )

    def _query_original(
        self, request: DispatchRequest, operation: BusinessOperation
    ) -> DispatchResult:
        descriptor = self._platform.descriptor
        if not descriptor.supports_query or not callable(getattr(self._platform, "query_original", None)):
            return DispatchResult(
                "pending_confirmation", request.operation_id, request.effect_id,
                operation.admission_ref or "", operation.observation_ref,
                operation.settlement_ref, None, False,
            )
        try:
            observation = self._platform.query_original(request, operation)
            if not isinstance(observation, PlatformObservation):
                raise DispatchUnavailable("platform query returned an untrusted observation shape")
        except HandoffUncertain as exc:
            observation = PlatformObservation("unknown", exc.observation_ref, None)
        except Exception:
            observation = PlatformObservation(
                "unknown", f"runtime:query-unknown:{request.operation_id}", None
            )
        observed = self._journal.observe(
            request.effect_id, request.command_digest,
            self._journal_phase(observation.status), observation.observation_ref,
        )
        return self._settle_existing(
            request, operation, observation, observed.execution_seq,
        )

    def _settle(
        self, request: DispatchRequest, claim: BusinessDispatchClaim,
        observation: PlatformObservation, sequence: int, *, handoff_attempted: bool,
    ) -> DispatchResult:
        try:
            settlement = self._authority.settle(claim, observation)
            if not isinstance(settlement, DispatchSettlement):
                raise DispatchUnavailable("settlement returned an untrusted shape")
        except Exception:
            return DispatchResult(
                "pending_confirmation", request.operation_id, request.effect_id,
                claim.admission_ref, observation.observation_ref, None, sequence,
                handoff_attempted,
            )
        status = observation.status if settlement.status == "settled" else "pending_confirmation"
        if observation.status == "unknown":
            status = "pending_confirmation"
        return DispatchResult(
            status, request.operation_id, request.effect_id, claim.admission_ref,
            observation.observation_ref, settlement.settlement_ref, sequence,
            handoff_attempted,
        )

    def _settle_existing(
        self, request: DispatchRequest, operation: BusinessOperation,
        observation: PlatformObservation, sequence: int,
    ) -> DispatchResult:
        try:
            settlement = self._authority.settle_existing(operation, observation)
            if not isinstance(settlement, DispatchSettlement):
                raise DispatchUnavailable("existing settlement returned an untrusted shape")
        except Exception:
            return DispatchResult(
                "pending_confirmation", request.operation_id, request.effect_id,
                operation.admission_ref or "", observation.observation_ref, None,
                sequence, False,
            )
        status = observation.status if settlement.status == "settled" else "pending_confirmation"
        if observation.status == "unknown":
            status = "pending_confirmation"
        return DispatchResult(
            status, request.operation_id, request.effect_id,
            operation.admission_ref or "", observation.observation_ref,
            settlement.settlement_ref, sequence, False,
        )

    @staticmethod
    def _assert_recovery(recovery: RecoveryDecision, request: DispatchRequest) -> None:
        if not isinstance(recovery, RecoveryDecision):
            raise DispatchUnavailable("recovery gate returned an untrusted shape")
        if (
            recovery.effect_id != request.effect_id
            or recovery.command_digest != request.command_digest
            or recovery.activation_generation != request.activation_generation
            or recovery.content_fence != request.content_fence
        ):
            raise DispatchBlocked("recovery proof does not cover the current dispatch identity")
        if recovery.operation is not None and recovery.operation.operation_id != request.operation_id:
            raise DispatchBlocked("recovery proof points to a different operation")

    @staticmethod
    def _assert_operation_identity(operation: BusinessOperation, request: DispatchRequest) -> None:
        if (
            operation.operation_id != request.operation_id
            or operation.effect_id != request.effect_id
            or operation.command_digest != request.command_digest
        ):
            raise DispatchBlocked("operation identity conflicts with the frozen request")

    @staticmethod
    def _assert_claim(claim: BusinessDispatchClaim, request: DispatchRequest) -> None:
        if not isinstance(claim, BusinessDispatchClaim):
            raise DispatchBlocked("business authority did not issue a typed claim")
        expected = (
            request.operation_id, request.effect_id, request.command_digest, request.payload_digest,
            request.platform_capability_ref,
            request.required_check_refs, request.dispatch_generation, request.activation_generation,
            request.worker_fence, request.content_fence, request.cancel_epoch,
            request.footprint.contact_id, request.footprint.segment_id,
            request.proactive_contact,
            request.segment_authorization_ref, request.segment_manifest_digest,
            request.segment_index, request.segment_count,
        )
        actual = (
            claim.operation_id, claim.effect_id, claim.command_digest, claim.payload_digest,
            claim.platform_capability_ref,
            claim.verified_check_refs, claim.dispatch_generation, claim.activation_generation,
            claim.worker_fence, claim.content_fence, claim.cancel_epoch,
            claim.contact_id, claim.segment_id,
            claim.proactive_contact,
            claim.segment_authorization_ref, claim.segment_manifest_digest,
            claim.segment_index, claim.segment_count,
        )
        if actual != expected:
            raise DispatchBlocked("business claim does not cover the frozen request")
        if request.proactive_contact and claim.contact_occupancy_ref is None:
            raise DispatchBlocked("contact claim did not atomically occupy the contact window")

    def _assert_permit(
        self, permit: CurrentDispatchPermit, claim: BusinessDispatchClaim,
        request: DispatchRequest,
    ) -> None:
        if not isinstance(permit, CurrentDispatchPermit):
            raise DispatchBlocked("business authority did not issue a current permit")
        claim_fields = (
            "admission_ref", "dispatch_id", "operation_id", "effect_id", "command_digest",
            "payload_digest", "platform_capability_ref", "verified_check_refs",
            "dispatch_generation", "activation_generation",
            "worker_fence", "content_fence", "cancel_epoch", "contact_id", "segment_id",
            "proactive_contact", "contact_occupancy_ref", "segment_authorization_ref", "segment_manifest_digest",
            "segment_index", "segment_count",
        )
        if any(getattr(permit, name) != getattr(claim, name) for name in claim_fields):
            raise DispatchBlocked("current permit no longer matches the business claim")
        if permit.expires_at_monotonic < _finite(self._clock(), "monotonic clock"):
            raise DispatchBlocked("current dispatch permit expired before handoff")
        # Check request again so claim/permit cannot collude around changed input.
        self._assert_claim(claim, request)

    @staticmethod
    def _assert_handoff_start(
        start: HandoffStartReceipt, permit: CurrentDispatchPermit,
        request: DispatchRequest,
    ) -> None:
        if not isinstance(start, HandoffStartReceipt):
            raise DispatchBlocked("admission authority did not linearize handoff start")
        expected = (
            permit.permit_ref, request.operation_id, request.effect_id,
            request.platform_capability_ref, request.dispatch_generation,
            request.activation_generation, request.worker_fence,
            request.content_fence, request.cancel_epoch, request.proactive_contact,
            request.segment_authorization_ref, request.segment_manifest_digest,
            request.segment_index, request.segment_count,
        )
        actual = (
            start.permit_ref, start.operation_id, start.effect_id,
            start.platform_capability_ref, start.dispatch_generation,
            start.activation_generation, start.worker_fence,
            start.content_fence, start.cancel_epoch, start.proactive_contact,
            start.segment_authorization_ref, start.segment_manifest_digest,
            start.segment_index, start.segment_count,
        )
        if actual != expected:
            raise DispatchBlocked("handoff start does not cover current fences and segment grant")

    @staticmethod
    def _journal_phase(status: str) -> str:
        return {
            "handed_off": "handed_off",
            "accepted": "acknowledged",
            "delivered": "delivered",
            "read": "delivered",
            "external_confirmed": "delivered",
            "failed": "failed",
            "unknown": "unknown",
        }[status]


__all__ = (
    "AdmissionAuthority", "AdmissionAuthorityDescriptor", "BusinessDispatchClaim",
    "BusinessOperation", "CurrentDispatchPermit", "DispatchBlocked", "DispatchRequest",
    "DispatchResult", "DispatchRuntime", "DispatchSettlement", "DispatchUnavailable",
    "ExecutionRecoveryGate", "HandoffStartReceipt", "HandoffUncertain",
    "PlatformCapability", "PlatformCapabilityDescriptor", "PlatformObservation",
    "RecoveryDecision", "RecoveryGateDescriptor",
)
