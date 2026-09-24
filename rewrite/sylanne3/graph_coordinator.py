"""Restricted adoption path for typed, same-namespace domain bundles.

The caller holds a process-local authority object issued by the host bootstrap.
The strings in CommandEnvelope are audit assertions, never authentication.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, fields, replace
from contextlib import contextmanager, nullcontext
import hashlib
import json
import math
import secrets
import time
from typing import TYPE_CHECKING, Mapping
from types import SimpleNamespace

from .contracts import Event, EventConflict, Scope, StaleRead, canonical_json
from .graph_store import GraphStore, ProductionGraphStore
from .graph_types import (
    AtomKey, GraphCandidate, GraphSnapshot, GraphAtom, GraphVersion, GraphWrite,
    NamespaceEpoch, Owner, owner_grant_key, owner_grant_policy_digest_v1,
    validate_owner_grant_v1,
)
from .memory_types import access_key, source_key
from .runtime_contracts import (
    AuthorityContext, CommitReceipt, ContentFencePortV2, DomainBundle, FenceScope,
    NamespaceId, ProductAdvanceEvidenceV1, canonical_digest, canonical_serialize,
)
from .runtime.restore_anchor import (
    ExecutionJournalPort, SnapshotRequirements, validate_restore,
)
from .runtime.budget import (
    BudgetError, BudgetLease, BudgetReceipt, create_budget_lease, get_budget_lease,
    reserve_budget, settle_budget,
)
from .runtime.jobs import (
    PersistentJob, acquire_job, cancel_job, create_job, get_job,
)
from .runtime.d11_types import reconcile_runtime_write
from .runtime.dispatch_admission import (
    DispatchAdmissionV1, DispatchAdmissionReceiptV1,
    check_receipts_against_specs, insert_admission, load_admission, load_request,
)
from .runtime.dispatch_admission_preflight import preflight_dispatch_admission
from .runtime.dispatch_candidate import (
    DispatchCandidateRecoveryV1,
    dispatch_segment_payload_ref,
    qualify_dispatch_candidate_sources,
    validate_dispatch_candidate_writes,
)
from .authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerPrincipalV1,
)

if TYPE_CHECKING:
    from .authority_service.v2_owner_session import OwnerSessionLoginRequestV1
    from .workbench_api.d01_onboarding import VerifiedBudgetLease


@dataclass(frozen=True)
class BudgetAdmission:
    """D11-signed bounded spend for one immutable bundle operation."""

    lease_id: str
    expected_version: int
    ceiling: dict[str, int]
    pre_reserved: bool = False
    settle_now: bool = False
    actual: dict[str, int] | None = None
    execution_revoked: bool = False
    reservation_operation_id: str | None = None


@dataclass(frozen=True)
class JobBinding:
    """D11-signed link from graph job/outbox atoms to one durable job."""

    graph_job_ref: str
    job: PersistentJob
    outbox_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuntimeAdmission:
    budget: BudgetAdmission
    jobs: tuple[JobBinding, ...] = ()


@dataclass(frozen=True)
class ScheduleAdmission:
    budget: BudgetAdmission
    job: PersistentJob


def budget_operation_digest(envelope, lease_id: str,
                            ceiling: dict[str, int]) -> str:
    """Budget identity avoids a cycle through the graph cost receipt digest."""
    return canonical_digest({
        "schema": "sylanne.runtime.budget.v1",
        "namespace": list(envelope.authority.namespace.as_tuple),
        "activity_id": envelope.identity.activity_id,
        "operation_id": envelope.identity.operation_id,
        "input_digest": envelope.identity.canonical_input_digest,
        "lease_id": lease_id,
        "ceiling": ceiling,
    })


def namespace_ref(namespace: NamespaceId) -> str:
    """Bounded content-free identity shared by independent authorities."""
    if not isinstance(namespace, NamespaceId):
        raise TypeError("namespace must be NamespaceId")
    return "ns:sha256:" + hashlib.sha256(
        canonical_json(list(namespace.as_tuple)).encode("utf-8")
    ).hexdigest()


def _operation_capability_ref(namespace: NamespaceId, actor: str,
                              issuer_domain: str, domains: frozenset[str],
                              generation: int, operation_id: str) -> str:
    return "operation:" + canonical_digest({
        "namespace": list(namespace.as_tuple), "actor": actor,
        "issuer_domain": issuer_domain, "domains": sorted(domains),
        "generation": generation, "operation_id": operation_id,
    })


class AuthorityDenied(PermissionError):
    pass


class UnavailableGuard(RuntimeError):
    """A current authority, lease, or policy version is not installed."""


class FirstIngressOutcomeUnknown(UnavailableGuard):
    """The original ingress operation needs exact Authority reconciliation."""

    def __init__(self, operation_id: str, message: str):
        super().__init__(message)
        self.operation_id = operation_id


@dataclass(frozen=True)
class NamespaceProvisionReceiptV2:
    """Durable business genesis and the exact Authority finish to reconcile."""

    namespace: NamespaceId
    operation_id: str
    input_digest: str
    installation_id: str
    manifest_digest: str
    authority_id: str
    authority_namespace: str
    generation: int
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    catalogue_hash: str
    scheme_version: str
    operator_version: str
    policy_version: str
    root_lease_id: str
    root_grant_id: str
    root_grant_version: int
    root_grant_signature: str
    fence_attempt_id: str
    finish_request_id: str
    finish_request_digest: str
    permit_wire: dict[str, object]


@dataclass(frozen=True, slots=True)
class RoleInitializationReceiptV1:
    """One durable D01 first head; this receipt is not an Owner capability."""

    namespace: NamespaceId
    operation_id: str
    request_digest: str
    input_digest: str
    plan_id: str
    head_id: str
    owner_grant_id: str
    owner_grant_revision: int
    owner_authorization_head: str
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    fence_attempt_id: str
    finish_request_id: str
    finish_request_digest: str


@dataclass(frozen=True, slots=True)
class SceneBindingReceiptV1:
    """Durable first D03 scene binding, never a standing social-role permit."""

    namespace: NamespaceId
    operation_id: str
    request_digest: str
    input_digest: str
    scene_ref: str
    binding_id: str
    role_head_id: str
    owner_grant_id: str
    owner_authorization_head: str
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    fence_attempt_id: str
    finish_request_id: str
    finish_request_digest: str


@dataclass(frozen=True)
class CreationBudgetProofV1:
    """A fenced read of a D11 lease and its current signed grant, not spend authority."""

    budget: VerifiedBudgetLease
    grant_id: str
    grant_version: int
    grant_digest: str
    graph_revision: int
    graph_epoch: int
    owner_authorization_head: str


@dataclass(frozen=True)
class _NamespaceProvisionIntentV2:
    namespace: NamespaceId
    operation_id: str
    digest: str
    identity_json: str
    genesis_request_id: str
    fence_attempt_id: str
    graph_incarnation: str
    anchor_json: str | None


@dataclass(frozen=True)
class IngressIssuancePolicy:
    """Installation-owned, bounded inputs to first D06 encoding admission."""

    parent_budget_lease_ref: str
    ceiling: Mapping[str, int]
    grant_ceiling: Mapping[str, int]
    deadline_utc: float
    grant_valid_until_utc: float
    monotonic_deadline: float
    snapshot_ref: str
    resource_ref: str
    character_interval_ref: str

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not value for value in (
                self.parent_budget_lease_ref, self.snapshot_ref,
                self.resource_ref, self.character_interval_ref)):
            raise ValueError("ingress policy requires explicit resource identities")
        if (type(self.deadline_utc) not in (int, float)
                or type(self.grant_valid_until_utc) not in (int, float)
                or type(self.monotonic_deadline) not in (int, float)
                or not all(math.isfinite(float(value)) for value in (
                    self.deadline_utc, self.grant_valid_until_utc,
                    self.monotonic_deadline))
                or not float(self.grant_valid_until_utc) >= float(self.deadline_utc)):
            raise ValueError("ingress policy requires finite ordered deadlines")
        if any(not isinstance(amounts, Mapping) or not amounts
               or len(amounts) > 32
               or any(not isinstance(name, str) or not name
                      or type(amount) is not int or amount <= 0
                      or amount > 9_000_000_000_000_000
                      for name, amount in amounts.items())
               for amounts in (self.ceiling, self.grant_ceiling)):
            raise ValueError("ingress policy requires a bounded positive ceiling")
        if any(amount > self.grant_ceiling.get(name, 0)
               for name, amount in self.ceiling.items()):
            raise ValueError("ingress quote exceeds installation grant ceiling")
        object.__setattr__(self, "ceiling", dict(self.ceiling))
        object.__setattr__(self, "grant_ceiling", dict(self.grant_ceiling))


@dataclass(frozen=True)
class IngressClockSample:
    """One reading from an installation-owned, externally attested clock port."""

    wall_now_utc: float
    monotonic_now: float
    clock_epoch: str
    clock_trusted: bool

    def __post_init__(self) -> None:
        if (type(self.wall_now_utc) not in (int, float)
                or type(self.monotonic_now) not in (int, float)
                or not math.isfinite(self.wall_now_utc)
                or not math.isfinite(self.monotonic_now)
                or not isinstance(self.clock_epoch, str)
                or not 1 <= len(self.clock_epoch) <= 128
                or type(self.clock_trusted) is not bool):
            raise ValueError("invalid trusted ingress clock sample")


@dataclass(frozen=True)
class _IngressClockBinding:
    clock_epoch: str
    deadline_utc: float
    monotonic_deadline: float
    last_wall_utc: float
    last_monotonic: float


@dataclass(frozen=True)
class IngressLineage:
    source_ref: str
    source_kind: str
    provenance_family: str
    content_reality: str
    evidence_eligibility: str
    internal_activity_actuality: str

    def __post_init__(self) -> None:
        if (len(self.source_ref) != 64
                or any(char not in "0123456789abcdef" for char in self.source_ref)
                or self.source_kind != "reported"
                or self.content_reality != "external_report"
                or self.evidence_eligibility != "reported_claim"
                or self.internal_activity_actuality != "not_applicable"
                or not isinstance(self.provenance_family, str)
                or not 1 <= len(self.provenance_family) <= 512):
            raise ValueError("ingress lineage must remain a reported host source")


@dataclass(frozen=True)
class IngressHostFacts:
    namespace: NamespaceId
    platform_ref: str
    conversation_ref: str
    sender_ref: str
    message_id: str
    text: str
    occurred_at: float | None
    learned_at: float
    visibility: str
    lineage: IngressLineage

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, NamespaceId) or not isinstance(
                self.lineage, IngressLineage):
            raise TypeError("typed ingress host facts are required")
        if (any(not isinstance(value, str) or not 1 <= len(value) <= 512
                for value in (self.platform_ref, self.conversation_ref,
                              self.sender_ref, self.message_id))
                or not isinstance(self.text, str)
                or not 1 <= len(self.text) <= 32_768
                or self.visibility not in {"private", "group", "other"}
                or type(self.learned_at) not in (int, float)
                or not math.isfinite(self.learned_at) or self.learned_at <= 0
                or (self.occurred_at is not None and (
                    type(self.occurred_at) not in (int, float)
                    or not math.isfinite(self.occurred_at)
                    or self.occurred_at <= 0
                    or self.occurred_at > self.learned_at))):
            raise ValueError("invalid trusted ingress host facts")


@dataclass(frozen=True)
class IngressIssuanceRequest:
    host: IngressHostFacts
    admission: object
    candidate: object
    activity_id: str
    operation_id: str
    job_id: str
    job_ref: str
    outbox_id: str
    outbox_ref: str
    payload_ref: str
    idempotency_key: str

    def __post_init__(self) -> None:
        if not isinstance(self.host, IngressHostFacts):
            raise TypeError("typed ingress host facts are required")


@dataclass(frozen=True)
class IngressAuthorizationResult:
    envelope: object
    lease: object
    job: PersistentJob


def ingress_host_fingerprint(host: IngressHostFacts) -> str:
    """Match the canonical host fingerprint without importing the host package."""
    if not isinstance(host, IngressHostFacts):
        raise TypeError("IngressHostFacts required")
    lineage = {
        "$type": "sylanne3.host.ingress.SourceLineage",
        **asdict(host.lineage),
    }
    return canonical_digest({
        "namespace": host.namespace, "platform_ref": host.platform_ref,
        "conversation_ref": host.conversation_ref,
        "sender_ref": host.sender_ref, "message_id": host.message_id,
        "text": host.text, "occurred_at": host.occurred_at,
        "visibility": host.visibility, "lineage": lineage,
    })


@dataclass(frozen=True, eq=False)
class _AuthorityLease:
    marker: object


@dataclass(frozen=True, slots=True)
class OwnerLeaseBindingV1:
    """One process lease pinned to the committed graph and Authority heads."""

    principal: object
    actor: str
    namespace: NamespaceId
    purpose: str
    audience: str
    grant_id: str
    scope: str
    issuer_ref: str
    capabilities: frozenset[str]
    purposes: frozenset[str]
    audiences: frozenset[str]
    grant_digest: str
    grant_revision: int
    access_epoch: int
    delete_epoch: int
    graph_incarnation: str
    authorization_head: str
    authorization_revision: int
    revocation_epoch: int


@dataclass(frozen=True, slots=True)
class CurrentOwnerViewV1:
    """Read-only Owner heads observed under one V2 content fence."""

    authority_guard: OwnerAuthorizationGuardV1
    graph_binding: OwnerLeaseBindingV1


class GraphCoordinator:
    """One in-process authority over a GraphStore's business SQLite connection.

    ``bootstrap`` is an object held only by trusted host setup. Domain code gets
    no GraphStore or bootstrap reference. Registration and guard mutation are
    setup/administrative operations, not user-supplied command fields.
    """

    def __init__(self, store: GraphStore, bootstrap: object, *,
                 deletion_journal=None, migration_authority=None,
                 restore_authority=None,
                 execution_journal_port: ExecutionJournalPort | None = None,
                 snapshot_requirements=None, holder=None, content_fence=None,
                 content_fence_v2: ContentFencePortV2 | None = None,
                 closure_verifier=None, d02_issuer=None, d11_issuer=None,
                 ingress_policy=None, ingress_clock=None,
                 owner_principal_resolver=None,
                 dispatch_admission_issuer=None, dispatch_clock_policy=None,
                 scene_identity_port=None, scene_clock_policy=None):
        if not isinstance(store, GraphStore):
            raise TypeError("store must be GraphStore")
        if bootstrap is None or isinstance(bootstrap, (str, bytes, int, float)):
            raise TypeError("bootstrap must be an opaque host object")
        if isinstance(store, ProductionGraphStore):
            v2 = content_fence_v2 is not None
            if (not holder or (v2 and not isinstance(content_fence_v2, ContentFencePortV2))
                    or (not v2 and (deletion_journal is None
                        or migration_authority is None or restore_authority is None
                        or not callable(getattr(execution_journal_port, "verify_current_chain", None))
                        or not callable(snapshot_requirements) or not callable(content_fence)
                        or not callable(getattr(d02_issuer, "authorize_resources", None))
                        or not callable(getattr(d11_issuer, "admit_runtime", None))))):
                raise UnavailableGuard("production recovery and activation authority required")
        self.__store = store
        self.__bootstrap = bootstrap
        self.__deletion_journal = deletion_journal
        self.__migration_authority = migration_authority
        self.__restore_authority = restore_authority
        self.__execution_journal_port = execution_journal_port
        self.__snapshot_requirements = snapshot_requirements
        self.__holder = holder
        self.__content_fence = content_fence
        self.__content_fence_v2 = content_fence_v2
        self.__scene_identity_port = scene_identity_port
        self.__scene_clock_policy = scene_clock_policy
        self.__closure_verifier = closure_verifier
        self.__d02_issuer = d02_issuer
        self.__d11_issuer = d11_issuer
        # Installed by trusted host composition only.  A missing issuer leaves
        # D08/D09 candidates in HOLD; caller receipt strings are never enough.
        self.__dispatch_admission_issuer = dispatch_admission_issuer
        self.__dispatch_clock_policy = dispatch_clock_policy
        # No product numeric issuer is installed in alpha1. A DTO is never a permit.
        self.__product_advance_issuer = None
        if ingress_policy is not None and not callable(ingress_policy):
            raise TypeError("ingress_policy must be callable")
        self.__ingress_policy = ingress_policy
        if ingress_clock is not None and not callable(ingress_clock):
            raise TypeError("ingress_clock must be callable")
        self.__ingress_clock = ingress_clock
        if (owner_principal_resolver is not None
                and not callable(owner_principal_resolver)):
            raise TypeError("owner_principal_resolver must be callable")
        self.__owner_principal_resolver = owner_principal_resolver
        self.__ingress_clock_bindings: dict[
            tuple[NamespaceId, str, int], _IngressClockBinding] = {}
        self.__graph_capability = object()
        if isinstance(store, ProductionGraphStore):
            if getattr(store, "_coordinator_capability", None) is not None:
                raise AuthorityDenied("production graph store is already bound")
            store._coordinator_capability = self.__graph_capability
        self.__leases: dict[_AuthorityLease, tuple[str, str, str, NamespaceId, frozenset[str],
                                                  frozenset[str], int]] = {}
        self.__owner_leases: dict[_AuthorityLease, OwnerLeaseBindingV1] = {}
        self.__owner_session_proofs: dict[_AuthorityLease, tuple[str, object]] = {}
        self.__providers: dict[str, tuple[object, str, str]] = {}

    def _content_fence(self, namespace: NamespaceId, generation: int,
                       operation: str):
        if not isinstance(self.__store, ProductionGraphStore):
            return nullcontext()
        if self.__content_fence_v2 is not None:
            raise UnavailableGuard("v2 graph write path is not admitted")
        if self.__content_fence is None:
            raise UnavailableGuard("content authority fence unavailable")
        return self.__content_fence(namespace_ref(namespace), self.__holder,
                                    generation, operation)

    @staticmethod
    def _anchor_matches(requirements, anchor) -> bool:
        return (requirements.authority_id == anchor.authority_id
                and requirements.authority_namespace == anchor.namespace
                and requirements.activation_generation == anchor.activation_generation
                and requirements.deletion_journal_id == anchor.deletion_journal_id
                and requirements.deletion_seq == anchor.deletion_seq
                and requirements.deletion_digest == anchor.deletion_digest
                and requirements.execution_journal_id == anchor.execution_journal_id
                and requirements.execution_seq == anchor.execution_seq
                and requirements.execution_digest == anchor.execution_digest
                and requirements.revocation_epoch == anchor.revocation_epoch)

    def _v2_graph_stamp(self, namespace: NamespaceId):
        """Read both business stamps while the GraphStore lock is held."""
        store = self.__store
        metadata = store.graph_recovery_metadata(
            namespace, _capability=self.__graph_capability)
        if metadata is None:
            raise UnavailableGuard("v2 graph recovery metadata is absent")
        epoch = GraphStore.graph_epoch(
            store, *namespace.as_tuple, _capability=self.__graph_capability)
        return metadata, epoch

    def _read_v2(self, authority: AuthorityContext, reader, *,
                 owner_principal=None,
                 owner_binding: OwnerLeaseBindingV1 | None = None,
                 owner_view: bool = False,
                 owner_session_proof: tuple[str, object] | None = None):
        """Keep every Authority RPC outside the business graph lock."""
        if owner_view and owner_principal is None:
            raise ValueError("Owner view requires an expected principal")
        store = self.__store
        namespace = authority.namespace
        port = self.__content_fence_v2
        try:
            with store._lock:
                metadata, epoch = self._v2_graph_stamp(namespace)
            target = metadata.requirements
            if target.namespace != namespace or target.activation_generation != authority.activation_generation:
                raise UnavailableGuard("v2 graph recovery identity or generation differs")
            anchor = port.current_anchor(
                namespace=namespace, authority_namespace=target.authority_namespace)
            if not self._anchor_matches(target, anchor):
                raise UnavailableGuard("v2 graph recovery anchor differs")
            operation_id = "graph-read-" + secrets.token_hex(16)
            permit = port.begin_fence(
                namespace=namespace, authority_namespace=target.authority_namespace,
                holder=self.__holder, generation=authority.activation_generation,
                operation="read", operation_id=operation_id, expected_anchor=anchor)
            scope = FenceScope(namespace, target.authority_namespace,
                               authority.activation_generation, "read", operation_id,
                               permit, anchor, epoch, metadata.graph_revision)
            try:
                if port.validate_fence(scope) != permit:
                    raise UnavailableGuard("v2 read permit changed")
                if owner_principal is not None or owner_binding is not None:
                    observed_guard, observed_owner = self._owner_binding_in_fence(
                        authority, scope, owner_principal, owner_binding,
                        owner_session_proof)
                with store._lock:
                    if self._v2_graph_stamp(namespace) != (metadata, epoch):
                        raise UnavailableGuard("v2 graph recovery stamp changed")
                    result = reader()
                if port.validate_fence(scope) != permit:
                    raise UnavailableGuard("v2 read permit changed")
                if owner_principal is not None or owner_binding is not None:
                    current_guard, _ = self._owner_binding_in_fence(
                        authority, scope, owner_principal, observed_owner,
                        owner_session_proof)
                    if current_guard != observed_guard:
                        raise UnavailableGuard("Owner Authority guard changed during read")
                with store._lock:
                    if self._v2_graph_stamp(namespace) != (metadata, epoch):
                        raise UnavailableGuard("v2 graph recovery stamp changed")
                if port.validate_fence(scope) != permit:
                    raise UnavailableGuard("v2 read permit changed")
                if owner_view:
                    return CurrentOwnerViewV1(observed_guard, observed_owner)
                return result
            finally:
                port.finish_fence(
                    scope, request_id="finish:" + operation_id,
                    request_digest="sha256:" + canonical_digest({
                        "operation_id": operation_id, "permit_token": permit.token,
                        "action": "finish_read",
                    }))
        except UnavailableGuard:
            raise
        except Exception as exc:
            raise UnavailableGuard("v2 content authority is unavailable") from exc

    @staticmethod
    def _provision_row(db, namespace: NamespaceId):
        return db.execute(
            "SELECT operation_id,digest,receipt_json "
            "FROM graph_namespace_provisioning_v2 WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()

    @staticmethod
    def _provision_intent_row(db, namespace: NamespaceId):
        row = db.execute(
            "SELECT operation_id,digest,identity_json,genesis_request_id,"
            "fence_attempt_id,graph_incarnation,anchor_json "
            "FROM graph_namespace_provision_intents_v2 WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()
        if row is None:
            return None
        intent = _NamespaceProvisionIntentV2(namespace, *row)
        try:
            expected = GraphCoordinator._fixed_provision_ids(
                intent.identity_json, intent.operation_id, intent.digest)
            if (intent.genesis_request_id, intent.fence_attempt_id,
                    intent.graph_incarnation) != expected:
                raise ValueError("provisioning attempt IDs differ")
            if (intent.anchor_json is not None
                    and canonical_json(json.loads(intent.anchor_json))
                    != intent.anchor_json):
                raise ValueError("provisioning anchor is noncanonical")
        except (TypeError, ValueError, KeyError) as exc:
            raise UnavailableGuard("durable v2 provisioning intent is invalid") from exc
        return intent

    @staticmethod
    def _fixed_provision_ids(identity_json, operation_id, digest):
        identity = json.loads(identity_json)
        if type(identity) is not dict or canonical_json(identity) != identity_json:
            raise ValueError("noncanonical provisioning identity")
        base = {
            "identity": identity, "operation_id": operation_id,
            "input_digest": digest,
        }
        def fixed_id(domain):
            return canonical_digest({"domain": domain, **base})
        return (
            "namespace-genesis-" + fixed_id("genesis")[:48],
            "provision-write-" + fixed_id("write")[:48],
            "graph:" + fixed_id("incarnation"),
        )

    @staticmethod
    def _check_provision_intent(intent, operation_id, digest, identity_json):
        if (intent.operation_id != operation_id or intent.digest != digest
                or intent.identity_json != identity_json):
            raise AuthorityDenied("namespace provisioning identity differs")

    def _ensure_provision_intent(self, policy, grant, operation_id, digest):
        store = self.__store
        namespace = policy.namespace
        identity_json = canonical_json({
            "policy": policy.digest_payload(), "authority_id": grant.authority_id,
            "subject": grant.subject, "holder": grant.administrator_holder,
            "installation_id": grant.installation_id,
            "authority_namespace": policy.authority_namespace,
        })
        with store._lock:
            store._ensure_open()
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                intent = self._provision_intent_row(db, namespace)
                if intent is None:
                    if policy.root_grant.valid_until_utc <= time.time():
                        raise UnavailableGuard("root grant expired before namespace genesis")
                    if (self._provision_row(db, namespace) is not None
                            or store._recovery_row(namespace) is not None
                            or store._has_namespace_history(namespace)
                            or GraphStore.graph_epoch(
                                store, *namespace.as_tuple,
                                _capability=self.__graph_capability).revision != 0):
                        raise UnavailableGuard("namespace has unsealed business history")
                    genesis_id, attempt_id, incarnation = self._fixed_provision_ids(
                        identity_json, operation_id, digest)
                    intent = _NamespaceProvisionIntentV2(
                        namespace, operation_id, digest, identity_json,
                        genesis_id, attempt_id, incarnation, None)
                    db.execute(
                        "INSERT INTO graph_namespace_provision_intents_v2"
                        "(bot,persona,operation_id,digest,identity_json,"
                        "genesis_request_id,fence_attempt_id,graph_incarnation,anchor_json)"
                        " VALUES(?,?,?,?,?,?,?,?,NULL)",
                        namespace.as_tuple + (
                            intent.operation_id, intent.digest, intent.identity_json,
                            intent.genesis_request_id, intent.fence_attempt_id,
                            intent.graph_incarnation))
                self._check_provision_intent(intent, operation_id, digest, identity_json)
                if self._provision_row(db, namespace) is None:
                    if (store._recovery_row(namespace) is not None
                            or store._has_namespace_history(
                                namespace, provision_intent=(operation_id, digest))
                            or GraphStore.graph_epoch(
                                store, *namespace.as_tuple,
                                _capability=self.__graph_capability).revision != 0):
                        raise UnavailableGuard("namespace has unsealed business history")
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return intent, identity_json

    def _persist_provision_anchor(self, intent, anchor, identity_json):
        store = self.__store
        encoded = canonical_json(asdict(anchor))
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                current = self._provision_intent_row(db, intent.namespace)
                self._check_provision_intent(
                    current, intent.operation_id, intent.digest, identity_json)
                if current.anchor_json is None:
                    db.execute(
                        "UPDATE graph_namespace_provision_intents_v2 SET anchor_json=? "
                        "WHERE bot=? AND persona=? AND anchor_json IS NULL",
                        (encoded,) + intent.namespace.as_tuple)
                elif current.anchor_json != encoded:
                    raise UnavailableGuard("v2 provisioning genesis anchor differs")
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return self._provision_intent_row(store._db, intent.namespace)

    @staticmethod
    def _decode_provision_receipt(row) -> NamespaceProvisionReceiptV2:
        try:
            data = json.loads(row[2])
            if (type(data) is not dict
                    or set(data) != {item.name for item in fields(NamespaceProvisionReceiptV2)}
                    or type(data["namespace"]) is not dict):
                raise ValueError("invalid provisioning receipt fields")
            data["namespace"] = NamespaceId(**data["namespace"])
            receipt = NamespaceProvisionReceiptV2(**data)
            if (row[:2] != (receipt.operation_id, receipt.input_digest)
                    or canonical_json(asdict(receipt)) != row[2]):
                raise ValueError("noncanonical provisioning receipt")
            return receipt
        except (TypeError, ValueError, KeyError) as exc:
            raise UnavailableGuard("durable v2 provisioning receipt is invalid") from exc

    def _verify_provision_receipt(self, policy, operation_id: str, digest: str):
        """Called with the graph lock; inspect linked business facts, not Authority."""
        store = self.__store
        namespace = policy.namespace
        row = self._provision_row(store._db, namespace)
        if row is None:
            raise UnavailableGuard("durable v2 provisioning receipt is absent")
        if row[0] != operation_id or row[1] != digest:
            raise AuthorityDenied("namespace provisioning identity differs")
        receipt = self._decode_provision_receipt(row)
        intent = self._provision_intent_row(store._db, namespace)
        if (intent is not None and (
                intent.operation_id != operation_id or intent.digest != digest
                or intent.fence_attempt_id != receipt.fence_attempt_id
                or intent.graph_incarnation != receipt.graph_incarnation
                or intent.anchor_json is None)):
            raise UnavailableGuard("durable v2 provisioning intent differs from receipt")
        metadata, epoch = self._v2_graph_stamp(namespace)
        target = metadata.requirements
        if (receipt.namespace != namespace
                or receipt.installation_id != policy.installation_id
                or receipt.manifest_digest != policy.manifest_digest
                or receipt.authority_id != target.authority_id
                or receipt.authority_namespace != target.authority_namespace
                or receipt.generation != target.activation_generation
                or receipt.graph_incarnation != target.graph_incarnation
                or receipt.graph_revision != 0 or metadata.graph_revision < 0
                or receipt.graph_epoch != 0 or epoch.revision < 0
                or receipt.catalogue_hash != policy.catalogue_hash
                or receipt.scheme_version != policy.scheme_version
                or receipt.operator_version != policy.operator_version
                or receipt.policy_version != policy.policy_version
                or receipt.root_lease_id != policy.root_lease.lease_id
                or receipt.root_grant_id != policy.root_grant.grant_id
                or receipt.root_grant_version != policy.root_grant.version):
            raise UnavailableGuard("durable v2 provisioning receipt differs from recovery state")
        from .authority_service.v2_contract import FencePermitV2, from_wire
        try:
            permit = from_wire(receipt.permit_wire)
        except (TypeError, ValueError) as exc:
            raise UnavailableGuard("durable v2 provisioning permit is invalid") from exc
        if (type(permit) is not FencePermitV2 or permit.operation_id != receipt.fence_attempt_id
                or (intent is not None and intent.anchor_json != canonical_json(
                    asdict(permit.pinned_anchor)))
                or permit.subject != self.__content_fence_v2.installation_grant.subject
                or permit.authority_id != target.authority_id
                or permit.namespace != target.authority_namespace
                or permit.generation != target.activation_generation
                or permit.operation != "write" or permit.holder != self.__holder
                or permit.pinned_anchor.deletion_journal_id != target.deletion_journal_id
                or permit.pinned_anchor.execution_journal_id != target.execution_journal_id
                or permit.pinned_anchor.deletion_seq != 0
                or permit.pinned_anchor.deletion_digest != "genesis"
                or permit.pinned_anchor.execution_seq != 0
                or permit.pinned_anchor.execution_digest != "genesis"
                or permit.pinned_anchor.revocation_epoch != 0
                or receipt.finish_request_id != "finish:" + receipt.fence_attempt_id
                or receipt.finish_request_digest != "sha256:" + canonical_digest({
                    "operation_id": receipt.fence_attempt_id,
                    "permit_token": permit.token,
                    "action": "finish_namespace_provision",
                    "business_operation_id": operation_id,
                    "input_digest": digest,
                })):
            raise UnavailableGuard("durable v2 provisioning fence identity differs")
        for kind, version in (("scheme", policy.scheme_version),
                              ("operator", policy.operator_version),
                              ("policy", policy.policy_version),
                              ("activation", str(target.activation_generation))):
            if self._version(store._db, namespace, kind, "current") != str(version):
                raise UnavailableGuard("durable v2 provisioning guard changed")
        lease = get_budget_lease(store._db, policy.root_lease.lease_id)
        if (lease.parent_id is not None or lease.lease_id != policy.root_lease.lease_id
                or (lease.bot_id, lease.persona_id) != namespace.as_tuple
                or lease.currency != policy.root_lease.currency
                or lease.limits != policy.root_lease.limits):
            raise UnavailableGuard("durable v2 root budget differs")
        from .runtime.issuers import IssuerAuthorityDenied
        try:
            original_grant, original_signature = (
                self.__d11_issuer.signed_budget_grant_at_version(
                    store._db, lease.lease_id, receipt.root_grant_version))
        except IssuerAuthorityDenied as exc:
            raise UnavailableGuard("durable v2 D11 budget grant is invalid") from exc
        if original_grant != policy.root_grant:
            raise UnavailableGuard("durable v2 D11 budget grant differs")
        if original_signature != receipt.root_grant_signature:
            raise UnavailableGuard("durable v2 D11 signature differs")
        return receipt, metadata, epoch

    def _reconcile_provision_v2(self, policy, operation_id: str, digest: str):
        """Resolve an old write fence, then read under a fresh current fence."""
        from .authority_service.v2_contract import FencePermitV2, from_wire

        store = self.__store
        namespace = policy.namespace
        port = self.__content_fence_v2
        with store._lock:
            receipt, metadata, epoch = self._verify_provision_receipt(
                policy, operation_id, digest)
        target = metadata.requirements
        anchor = port.current_anchor(
            namespace=namespace, authority_namespace=target.authority_namespace)
        if not self._anchor_matches(target, anchor):
            raise UnavailableGuard("v2 provisioning recovery anchor differs")
        if not callable(getattr(port, "get_fence_operation", None)):
            raise UnavailableGuard("v2 Authority fence status is unavailable")
        original = from_wire(receipt.permit_wire)
        observed_permit, state = port.get_fence_operation(
            namespace=namespace, authority_namespace=target.authority_namespace,
            operation_id=receipt.fence_attempt_id)
        if (type(original) is not FencePermitV2
                or type(observed_permit) is not FencePermitV2
                or observed_permit != original
                or state not in {"active", "finished"}):
            raise UnavailableGuard("v2 provisioning Authority fence status differs")
        if state == "active":
            if (metadata.graph_revision != receipt.graph_revision
                    or epoch.revision != receipt.graph_epoch
                    or original.pinned_anchor != anchor):
                raise UnavailableGuard("active v2 provisioning fence lost its business stamp")
            write_scope = FenceScope(
                namespace, target.authority_namespace,
                target.activation_generation, "write", receipt.fence_attempt_id,
                original, anchor, epoch, metadata.graph_revision)
            if port.validate_fence(write_scope) != original:
                raise UnavailableGuard("active v2 provisioning permit changed")
            port.finish_fence(
                write_scope, request_id=receipt.finish_request_id,
                request_digest=receipt.finish_request_digest)
        attempt_id = "provision-read-" + secrets.token_hex(16)
        permit = port.begin_fence(
            namespace=namespace, authority_namespace=target.authority_namespace,
            holder=self.__holder, generation=target.activation_generation,
            operation="read", operation_id=attempt_id, expected_anchor=anchor)
        scope = FenceScope(namespace, target.authority_namespace,
                           target.activation_generation, "read", attempt_id,
                           permit, anchor, epoch, metadata.graph_revision)
        try:
            if port.validate_fence(scope) != permit:
                raise UnavailableGuard("v2 provisioning read permit changed")
            with store._lock:
                confirmed = self._verify_provision_receipt(policy, operation_id, digest)
                if confirmed != (receipt, metadata, epoch):
                    raise UnavailableGuard("v2 provisioning state changed during read")
            if port.validate_fence(scope) != permit:
                raise UnavailableGuard("v2 provisioning read permit changed")
            with store._lock:
                if self._verify_provision_receipt(policy, operation_id, digest) != confirmed:
                    raise UnavailableGuard("v2 provisioning state changed during read")
            return receipt
        finally:
            port.finish_fence(
                scope, request_id="finish:" + attempt_id,
                request_digest="sha256:" + canonical_digest({
                    "operation_id": attempt_id, "permit_token": permit.token,
                    "action": "finish_provision_read",
                }))

    def _stage_first_owner_grant_locked(self, operation, pending, grant_value,
                                        scope: FenceScope, expected_metadata,
                                        expected_epoch):
        """Commit one first Owner grant under an already verified v2 write fence.

        This is deliberately private. A caller must obtain the original pending
        operation online from the paired Authority while holding the same live
        write fence. A caller-supplied pending DTO or bootstrap is not admission.
        No public route is installed until that Authority port exists.
        """
        from .authority_service.v2_owner_contract import (
            OwnerAuthorizationOperationV1, OwnerAuthorizationReceiptV1,
            OwnerGraphCommitProofV1,
        )
        from .graph_store import GraphRecoveryMetadataV2

        store = self.__store
        if not isinstance(store, ProductionGraphStore) or self.__content_fence_v2 is None:
            raise UnavailableGuard("owner grant requires a production v2 graph")
        if not store._lock._is_owned() or not store._db.in_transaction:
            raise RuntimeError("owner grant requires the graph lock and transaction")
        if (type(operation) is not OwnerAuthorizationOperationV1
                or operation.action != "issue" or operation.ticket is None
                or type(pending) is not OwnerAuthorizationReceiptV1
                or pending.phase != "pending" or pending.operation != operation
                or pending.guard != operation.expected_guard):
            raise AuthorityDenied("original pending Owner issue is required")
        if (type(scope) is not FenceScope or scope.operation != "write"
                or scope.namespace != operation.namespace
                or scope.authority_namespace != scope.pinned_anchor.namespace
                or scope.generation != 1
                or type(expected_metadata) is not GraphRecoveryMetadataV2
                or type(expected_epoch) is not NamespaceEpoch):
            raise AuthorityDenied("Owner issue requires the exact v2 write scope")
        namespace = operation.namespace
        if (scope.graph_revision != expected_metadata.graph_revision
                or scope.graph_epoch != expected_epoch
                or expected_epoch.bot != namespace.bot_id
                or expected_epoch.persona != namespace.persona_id
                or self._v2_graph_stamp(namespace) != (expected_metadata, expected_epoch)):
            raise StaleRead("Owner issue graph stamp changed")
        target = expected_metadata.requirements
        if (target.namespace != namespace or target.graph_incarnation == ""
                or target.activation_generation != scope.generation
                or target.authority_id != operation.authority_id
                or target.authority_namespace != scope.authority_namespace
                or not self._anchor_matches(target, scope.pinned_anchor)):
            raise AuthorityDenied("Owner issue differs from graph recovery identity")
        if (type(grant_value) is not dict
                or "sha256:" + canonical_digest(grant_value) != operation.grant_digest):
            raise AuthorityDenied("Owner grant payload differs from reserved digest")
        validate_owner_grant_v1(grant_value)
        ticket = operation.ticket
        principal = operation.principal
        if ticket.policy_digest != owner_grant_policy_digest_v1(
                grant_value, bot=namespace.bot_id, persona=namespace.persona_id):
            raise AuthorityDenied("Owner grant permissions differ from paired policy")
        expected_fields = {
            "authority_id": operation.authority_id,
            "installation_id": operation.installation_id,
            "grant_id": operation.grant_id,
            "principal": {
                "identity_provider": principal.identity_provider,
                "account_ref": principal.account_ref,
                "account_incarnation": principal.account_incarnation,
            },
            "ticket_id": ticket.ticket_id,
            "creation_operation_id": ticket.creation_operation_id,
            "creation_digest": ticket.creation_digest,
            "issue_operation_id": operation.operation_id,
            "grant_revision": 1,
            "activation_generation": scope.generation,
            "graph_incarnation": target.graph_incarnation,
        }
        if any(grant_value[name] != value for name, value in expected_fields.items()):
            raise AuthorityDenied("Owner grant identity differs from pending issue")
        provision_row = self._provision_row(store._db, namespace)
        if provision_row is None:
            raise UnavailableGuard("Owner issue requires completed namespace genesis")
        provision = self._decode_provision_receipt(provision_row)
        if (provision.operation_id != ticket.creation_operation_id
                or "sha256:" + provision.input_digest != ticket.creation_digest
                or provision.installation_id != operation.installation_id
                or provision.authority_id != operation.authority_id
                or provision.authority_namespace != target.authority_namespace
                or provision.namespace != namespace
                or provision.graph_incarnation != target.graph_incarnation
                or provision.generation != scope.generation):
            raise AuthorityDenied("Owner claim differs from completed creation")
        row = store._db.execute(
            "SELECT operation_id,request_digest,grant_id,grant_digest,"
            "graph_incarnation,graph_access_epoch,graph_epoch,"
            "graph_receipt_digest,proof_json FROM graph_owner_issue_operations_v1 "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchone()
        key = owner_grant_key(*namespace.as_tuple)
        if row is not None:
            if row[:5] != (operation.operation_id, operation.request_digest,
                           operation.grant_id, operation.grant_digest,
                           target.graph_incarnation):
                raise AuthorityDenied("first Owner grant already belongs to another issue")
            proof = OwnerGraphCommitProofV1(
                namespace, row[0], row[1], row[2], row[3], row[4],
                1, row[5], row[6], row[7])
            atom = store._db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (key.token,),
            ).fetchone()
            if (row[8] != canonical_json(asdict(proof)) or atom is None
                    or atom != (1, canonical_json(grant_value), 1)):
                raise UnavailableGuard("durable Owner issue receipt differs from graph")
            return proof
        # The first Owner claim belongs to the namespace creation, not to a
        # later state in which host ingress or another content operation has
        # already established business history without that Owner.
        if (expected_metadata.graph_revision != provision.graph_revision
                or expected_epoch.revision != provision.graph_epoch
                or provision.graph_revision != 0 or provision.graph_epoch != 0):
            raise UnavailableGuard("first Owner claim requires creation genesis")
        # The active Owner write fence excludes another live namespace fence.
        # A terminal first-message rejection has no graph/business effect;
        # unresolved attempts still block Owner genesis.
        if store._db.execute(
                "SELECT 1 FROM graph_first_ingress_intents_v2 AS i "
                "LEFT JOIN graph_first_ingress_rejections_v2 AS r "
                "ON r.bot=i.bot AND r.persona=i.persona "
                "AND r.operation_id=i.operation_id "
                "WHERE i.bot=? AND i.persona=? AND "
                "(r.status IS NULL OR r.status!='rejected_no_commit' "
                "OR r.graph_revision!=i.graph_revision "
                "OR r.graph_epoch!=i.graph_epoch "
                "OR r.finish_request_id!='abort:'||i.fence_attempt_id) LIMIT 1",
                namespace.as_tuple).fetchone() is not None:
            raise UnavailableGuard("first Owner claim follows unresolved ingress")
        for table in (
                "graph_bundle_intents_v2",
                "graph_bundle_operations", "graph_product_advances",
                "graph_events", "graph_atoms"):
            if store._db.execute(
                    f"SELECT 1 FROM {table} WHERE bot=? AND persona=? LIMIT 1",
                    namespace.as_tuple).fetchone() is not None:
                raise UnavailableGuard("first Owner claim follows business activity")
        if (store._db.execute(
                "SELECT 1 FROM graph_atoms WHERE token=?", (key.token,)
                ).fetchone() is not None):
            raise UnavailableGuard("first Owner grant atom already exists")
        access_row = store._db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchone() or (0, 0)
        if access_row != (0, 0):
            raise UnavailableGuard("first Owner grant requires zero access epochs")
        event = Event(
            Scope(*namespace.as_tuple, "owner-authorization-v1"),
            operation.operation_id, 0, "first_owner_grant", {
                "request_digest": operation.request_digest,
                "grant_digest": operation.grant_digest,
            },
        )
        candidate = GraphCandidate(
            event, (GraphVersion(key, 0),),
            (GraphWrite(key, grant_value),), (expected_epoch,),
        )
        graph_receipt = GraphStore._graph_commit_in_transaction(
            store, candidate, _capability=self.__graph_capability,
            _owner_issue=True)
        if (graph_receipt.status != "committed"
                or graph_receipt.revisions != (GraphVersion(key, 1),)):
            raise UnavailableGuard("first Owner graph commit did not create revision one")
        store._db.execute(
            "INSERT INTO graph_authority_epochs(bot,persona,access_epoch,delete_epoch) "
            "VALUES(?,?,1,0)", namespace.as_tuple,
        )
        store.cas_graph_recovery_metadata(
            expected_metadata, target, _capability=self.__graph_capability)
        digest = "sha256:" + canonical_digest({
            "schema": "sylanne3.graph.owner_issue_receipt.v1",
            "namespace": list(namespace.as_tuple),
            "operation_id": operation.operation_id,
            "request_digest": operation.request_digest,
            "grant_id": operation.grant_id,
            "grant_digest": operation.grant_digest,
            "graph_incarnation": target.graph_incarnation,
            "grant_revision": 1,
            "graph_access_epoch": 1,
            "graph_epoch": graph_receipt.epoch.revision,
            "graph_revision": expected_metadata.graph_revision + 1,
            "atom_token": key.token,
        })
        proof = OwnerGraphCommitProofV1(
            namespace, operation.operation_id, operation.request_digest,
            operation.grant_id, operation.grant_digest,
            target.graph_incarnation, 1, 1, graph_receipt.epoch.revision, digest,
        )
        store._db.execute(
            "INSERT INTO graph_owner_issue_operations_v1"
            "(bot,persona,operation_id,request_digest,grant_id,grant_digest,"
            "graph_incarnation,graph_access_epoch,graph_epoch,"
            "graph_receipt_digest,proof_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            namespace.as_tuple + (
                operation.operation_id, operation.request_digest,
                operation.grant_id, operation.grant_digest,
                target.graph_incarnation, 1, graph_receipt.epoch.revision,
                digest, canonical_json(asdict(proof))),
        )
        return proof

    def commit_first_owner_grant_v2(self, bootstrap: object, *,
                                    namespace: NamespaceId, operation_id: str,
                                    grant_value: dict):
        """Commit only the paired pending first Owner issue under a v2 write fence.

        Authority is queried as the installed graph peer, never through a DTO
        supplied by the caller. The resulting proof is inert until Authority
        independently verifies it and finalizes the issue.
        """
        from .authority_service.contract import identifier
        from .authority_service.v2_contract import FencePermitV2, from_wire, to_wire
        from .authority_service.v2_owner_contract import OwnerGraphCommitProofV1

        if bootstrap is not self.__bootstrap:
            raise AuthorityDenied("owner graph issue requires host bootstrap")
        if (not isinstance(self.__store, ProductionGraphStore)
                or self.__content_fence_v2 is None):
            raise UnavailableGuard("owner graph issue requires production v2")
        if type(namespace) is not NamespaceId:
            raise TypeError("namespace must be NamespaceId")
        identifier(operation_id, "operation_id")
        validate_owner_grant_v1(grant_value)
        grant_digest = "sha256:" + canonical_digest(grant_value)
        store = self.__store
        port = self.__content_fence_v2
        with store._lock:
            metadata, epoch = self._v2_graph_stamp(namespace)
            intent = store._db.execute(
                "SELECT operation_id,grant_digest,fence_attempt_id,"
                "requirements_json,anchor_json,graph_revision,graph_epoch "
                "FROM graph_owner_issue_intents_v1 WHERE bot=? AND persona=? "
                "AND operation_id=? AND grant_digest=?",
                namespace.as_tuple + (operation_id, grant_digest),
            ).fetchone()
            rejected = store._db.execute(
                "SELECT status,permit_json,graph_revision,graph_epoch,"
                "finish_request_id,finish_request_digest "
                "FROM graph_owner_issue_rejections_v1 WHERE bot=? AND persona=? "
                "AND operation_id=? AND grant_digest=?",
                namespace.as_tuple + (operation_id, grant_digest),
            ).fetchone()
            saved = store._db.execute(
                "SELECT operation_id,permit_json,pre_graph_revision,"
                "pre_graph_epoch,post_graph_revision,post_graph_epoch,"
                "finish_request_id,finish_request_digest "
                "FROM graph_owner_issue_fences_v1 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            proof_row = store._db.execute(
                "SELECT operation_id,request_digest,grant_id,grant_digest,"
                "graph_incarnation,graph_access_epoch,graph_epoch,"
                "graph_receipt_digest,proof_json "
                "FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
        target = metadata.requirements
        if (target.namespace != namespace or target.activation_generation != 1
                or target.authority_id != port.installation_grant.authority_id
                or target.authority_namespace == ""):
            raise UnavailableGuard("owner graph recovery identity differs")
        anchor = port.current_anchor(
            namespace=namespace, authority_namespace=target.authority_namespace)
        if not self._anchor_matches(target, anchor):
            raise UnavailableGuard("owner graph recovery anchor differs")
        attempt_id = "owner-write-" + canonical_digest({
            "namespace": list(namespace.as_tuple), "operation_id": operation_id,
            "grant_digest": grant_digest,
        })[:48]
        identity = (operation_id, grant_digest, attempt_id,
                    canonical_json(asdict(target)), canonical_json(asdict(anchor)))
        if intent is not None and intent[:5] != identity:
            raise AuthorityDenied("first Owner issue intent differs")
        if intent is not None and (metadata.graph_revision, epoch.revision) != intent[5:7]:
            if saved is None:
                raise UnavailableGuard("uncommitted Owner issue graph stamp changed")
        if rejected is not None:
            if saved is not None or proof_row is not None or intent is None:
                raise UnavailableGuard("rejected Owner issue has business receipt")
            permit = from_wire(json.loads(rejected[1]))
            abort_id = "abort:" + attempt_id
            abort_digest = "sha256:" + canonical_digest({
                "operation_id": attempt_id, "permit_token": permit.token,
                "action": "rejected_no_owner_commit",
                "business_operation_id": operation_id,
                "grant_digest": grant_digest,
            })
            if (rejected[0] != "rejected_no_commit"
                    or rejected[2:4] != intent[5:7]
                    or rejected[4:6] != (abort_id, abort_digest)
                    or permit.operation_id != attempt_id
                    or permit.operation != "write" or permit.holder != self.__holder
                    or permit.subject != port.installation_grant.subject
                    or permit.authority_id != target.authority_id
                    or permit.namespace != target.authority_namespace
                    or permit.generation != 1
                    or permit.pinned_anchor != anchor):
                raise UnavailableGuard("durable Owner rejection identity differs")
            observed, state = port.get_fence_operation(
                namespace=namespace, authority_namespace=target.authority_namespace,
                operation_id=attempt_id)
            if observed != permit or state not in {"active", "finished"}:
                raise UnavailableGuard("rejected Owner issue fence differs")
            if state == "active":
                scope = FenceScope(namespace, target.authority_namespace, 1,
                    "write", attempt_id, permit, anchor,
                    NamespaceEpoch(*namespace.as_tuple, intent[6]), intent[5])
                if port.validate_fence(scope) != permit:
                    raise UnavailableGuard("rejected Owner write permit changed")
                port.finish_fence(scope, request_id=abort_id,
                                  request_digest=abort_digest)
            raise AuthorityDenied("Owner issue is terminal rejected_no_commit")
        if (saved is None) != (proof_row is None):
            raise UnavailableGuard("Owner graph proof and fence receipt disagree")
        if saved is not None:
            try:
                permit = from_wire(json.loads(saved[1]))
                proof = OwnerGraphCommitProofV1(
                    namespace, proof_row[0], proof_row[1], proof_row[2],
                    proof_row[3], proof_row[4], 1, proof_row[5],
                    proof_row[6], proof_row[7])
            except (TypeError, ValueError, KeyError) as exc:
                raise UnavailableGuard("durable Owner issue proof is invalid") from exc
            finish_id = "finish:" + attempt_id
            finish_digest = "sha256:" + canonical_digest({
                "operation_id": attempt_id, "permit_token": permit.token,
                "action": "finish_owner_issue", "business_operation_id": operation_id,
                "graph_receipt_digest": proof.graph_receipt_digest,
            })
            if (intent is None or saved[0] != operation_id
                    or saved[2:4] != intent[5:7]
                    or saved[4] != saved[2] + 1 or saved[5] != proof.graph_epoch
                    or saved[6:8] != (finish_id, finish_digest)
                    or proof_row[0] != operation_id or proof_row[3] != grant_digest
                    or proof_row[8] != canonical_json(asdict(proof))
                    or permit.operation_id != attempt_id or permit.operation != "write"
                    or permit.holder != self.__holder
                    or permit.subject != port.installation_grant.subject
                    or permit.authority_id != target.authority_id
                    or permit.namespace != target.authority_namespace
                    or permit.generation != 1 or permit.pinned_anchor != anchor):
                raise UnavailableGuard("durable Owner issue fence identity differs")
            with store._lock:
                atom = store._db.execute(
                    "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                    (owner_grant_key(*namespace.as_tuple).token,),
                ).fetchone()
                access = store._db.execute(
                    "SELECT access_epoch FROM graph_authority_epochs "
                    "WHERE bot=? AND persona=?", namespace.as_tuple,
                ).fetchone()
                if (atom != (1, canonical_json(grant_value), 1)
                        or access != (proof.graph_access_epoch,)):
                    raise UnavailableGuard("durable Owner grant differs from graph")
            observed, state = port.get_fence_operation(
                namespace=namespace, authority_namespace=target.authority_namespace,
                operation_id=attempt_id)
            if observed != permit or state not in {"active", "finished"}:
                raise UnavailableGuard("Owner issue Authority fence differs")
            if state == "active":
                if (metadata.graph_revision, epoch.revision) != saved[4:6]:
                    raise UnavailableGuard("active Owner issue lost its graph stamp")
                scope = FenceScope(
                    namespace, target.authority_namespace, 1, "write", attempt_id,
                    permit, anchor, NamespaceEpoch(*namespace.as_tuple, saved[3]),
                    saved[2])
                if port.validate_fence(scope) != permit:
                    raise UnavailableGuard("Owner issue write permit changed")
                port.finish_fence(scope, request_id=finish_id,
                                  request_digest=finish_digest)
            elif (metadata.graph_revision < saved[4]
                  or epoch.revision < saved[5]):
                raise UnavailableGuard("finished Owner issue lost its graph stamp")
            return proof
        if proof_row is not None:
            raise UnavailableGuard("Owner graph proof lacks durable fence receipt")
        if intent is None:
            with store._lock:
                db = store._db
                db.execute("BEGIN IMMEDIATE")
                try:
                    if self._v2_graph_stamp(namespace) != (metadata, epoch):
                        raise StaleRead("Owner issue graph stamp changed before intent")
                    db.execute(
                        "INSERT OR IGNORE INTO graph_owner_issue_intents_v1"
                        "(bot,persona,operation_id,grant_digest,fence_attempt_id,"
                        "requirements_json,anchor_json,graph_revision,graph_epoch) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        namespace.as_tuple + identity + (
                            metadata.graph_revision, epoch.revision),
                    )
                    intent = db.execute(
                        "SELECT operation_id,grant_digest,fence_attempt_id,"
                        "requirements_json,anchor_json,graph_revision,graph_epoch "
                        "FROM graph_owner_issue_intents_v1 WHERE bot=? AND persona=? "
                        "AND operation_id=? AND grant_digest=?",
                        namespace.as_tuple + (operation_id, grant_digest),
                    ).fetchone()
                    if intent != identity + (metadata.graph_revision, epoch.revision):
                        raise AuthorityDenied("Owner issue intent was not installed")
                    db.execute("COMMIT")
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
        from .runtime.restore_anchor import RestoreAnchor
        try:
            pinned_anchor = RestoreAnchor(**json.loads(intent[4]))
        except (TypeError, ValueError, KeyError) as exc:
            raise UnavailableGuard("Owner issue intent anchor is invalid") from exc
        if pinned_anchor != anchor:
            raise UnavailableGuard("Owner issue intent anchor changed")
        permit = port.begin_fence(
            namespace=namespace, authority_namespace=target.authority_namespace,
            holder=self.__holder, generation=1, operation="write",
            operation_id=attempt_id, expected_anchor=pinned_anchor,
            retain_on_unknown=True)
        if (type(permit) is not FencePermitV2 or permit.operation_id != attempt_id
                or permit.operation != "write" or permit.holder != self.__holder
                or permit.subject != port.installation_grant.subject
                or permit.authority_id != target.authority_id
                or permit.namespace != target.authority_namespace
                or permit.generation != 1 or permit.pinned_anchor != anchor):
            raise UnavailableGuard("Owner issue write permit differs")
        scope = FenceScope(namespace, target.authority_namespace, 1, "write",
                           attempt_id, permit, anchor, epoch, metadata.graph_revision)
        def reject_no_commit():
            abort_id = "abort:" + attempt_id
            abort_digest = "sha256:" + canonical_digest({
                "operation_id": attempt_id, "permit_token": permit.token,
                "action": "rejected_no_owner_commit",
                "business_operation_id": operation_id,
                "grant_digest": grant_digest,
            })
            rejection = (
                "rejected_no_commit", canonical_json(to_wire(permit)),
                metadata.graph_revision, epoch.revision,
                abort_id, abort_digest,
            )
            with store._lock:
                db = store._db
                db.execute("BEGIN IMMEDIATE")
                try:
                    if self._v2_graph_stamp(namespace) != (metadata, epoch):
                        raise UnavailableGuard("Owner issue rollback stamp changed")
                    if db.execute(
                        "SELECT 1 FROM graph_owner_issue_operations_v1 "
                        "WHERE bot=? AND persona=?", namespace.as_tuple,
                    ).fetchone() is not None:
                        raise UnavailableGuard("Owner issue has a business commit")
                    db.execute(
                        "INSERT OR IGNORE INTO graph_owner_issue_rejections_v1"
                        "(bot,persona,operation_id,grant_digest,status,permit_json,"
                        "graph_revision,graph_epoch,finish_request_id,"
                        "finish_request_digest) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        namespace.as_tuple + (operation_id, grant_digest) + rejection,
                    )
                    actual = db.execute(
                        "SELECT status,permit_json,graph_revision,graph_epoch,"
                        "finish_request_id,finish_request_digest "
                        "FROM graph_owner_issue_rejections_v1 WHERE bot=? AND persona=? "
                        "AND operation_id=? AND grant_digest=?",
                        namespace.as_tuple + (operation_id, grant_digest),
                    ).fetchone()
                    if actual != rejection:
                        raise UnavailableGuard("Owner issue rejection differs")
                    db.execute("COMMIT")
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
            if port.validate_fence(scope) != permit:
                raise UnavailableGuard("rejected Owner write permit changed")
            port.finish_fence(scope, request_id=abort_id,
                              request_digest=abort_digest)

        pending_reader = getattr(port, "get_pending_owner_issue_for_graph_write", None)
        if not callable(pending_reader):
            raise UnavailableGuard("paired pending Owner issue port is unavailable")
        pending = pending_reader(
            namespace=namespace, authority_namespace=target.authority_namespace,
            operation_id=operation_id, permit=permit)
        if pending is None or pending.operation.grant_digest != grant_digest:
            reject_no_commit()
            raise AuthorityDenied("paired pending Owner issue differs")
        if port.validate_fence(scope) != permit:
            raise UnavailableGuard("Owner issue write permit changed")
        rolled_back_error = None
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                if self._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise StaleRead("Owner issue graph stamp changed")
                if db.execute(
                    "SELECT operation_id,grant_digest,fence_attempt_id,"
                    "requirements_json,anchor_json,graph_revision,graph_epoch "
                    "FROM graph_owner_issue_intents_v1 WHERE bot=? AND persona=? "
                    "AND operation_id=? AND grant_digest=?",
                    namespace.as_tuple + (operation_id, grant_digest),
                ).fetchone() != intent:
                    raise AuthorityDenied("first Owner issue intent changed")
                proof = self._stage_first_owner_grant_locked(
                    pending.operation, pending, grant_value, scope, metadata, epoch)
                finish_id = "finish:" + attempt_id
                finish_digest = "sha256:" + canonical_digest({
                    "operation_id": attempt_id, "permit_token": permit.token,
                    "action": "finish_owner_issue", "business_operation_id": operation_id,
                    "graph_receipt_digest": proof.graph_receipt_digest,
                })
                db.execute(
                    "INSERT INTO graph_owner_issue_fences_v1"
                    "(bot,persona,operation_id,permit_json,pre_graph_revision,"
                    "pre_graph_epoch,post_graph_revision,post_graph_epoch,"
                    "finish_request_id,finish_request_digest) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    namespace.as_tuple + (
                        operation_id, canonical_json(to_wire(permit)),
                        metadata.graph_revision, epoch.revision,
                        metadata.graph_revision + 1, proof.graph_epoch,
                        finish_id, finish_digest),
                )
                db.execute("COMMIT")
            except BaseException as exc:
                if not db.in_transaction:
                    raise
                db.execute("ROLLBACK")
                if not isinstance(exc, Exception):
                    raise
                rolled_back_error = exc
        if rolled_back_error is not None:
            reject_no_commit()
            raise rolled_back_error
        if port.validate_fence(scope) != permit:
            raise UnavailableGuard("committed Owner issue permit changed")
        with store._lock:
            current, current_epoch = self._v2_graph_stamp(namespace)
            if (current.graph_revision != metadata.graph_revision + 1
                    or current_epoch.revision != proof.graph_epoch):
                raise UnavailableGuard("committed Owner issue graph stamp changed")
        port.finish_fence(scope, request_id=finish_id,
                          request_digest=finish_digest)
        return proof

    def _reject_owner_graph_write_v2(self, *, kind, namespace, operation_id,
                                     input_digest, attempt_id, metadata, epoch,
                                     anchor, permit, intent):
        """Persist a proven no-commit outcome before finishing its original fence."""
        from .authority_service.v2_contract import to_wire

        if kind not in {"role_init", "scene_binding"}:
            raise ValueError("unknown Owner graph write")
        table = ("graph_role_init_rejections_v1" if kind == "role_init"
                 else "graph_scene_binding_rejections_v1")
        receipt_table = ("graph_role_init_receipts_v1" if kind == "role_init"
                         else "graph_scene_binding_receipts_v1")
        intent_table = ("graph_role_init_intents_v1" if kind == "role_init"
                        else "graph_scene_binding_intents_v1")
        finish_id = "abort:" + attempt_id
        finish_digest = "sha256:" + canonical_digest({
            "operation_id": attempt_id, "permit_token": permit.token,
            "action": "rejected_no_commit", "business_operation_id": operation_id,
            "input_digest": input_digest, "kind": kind,
        })
        expected = (operation_id, "rejected_no_commit",
                    canonical_json(to_wire(permit)), metadata.graph_revision,
                    epoch.revision, finish_id, finish_digest)
        store = self.__store
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                if self._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise UnavailableGuard("Owner graph no-commit stamp changed")
                if db.execute(
                        f"SELECT 1 FROM {receipt_table} WHERE bot=? AND persona=? "
                        "AND operation_id=?", namespace.as_tuple + (operation_id,),
                ).fetchone() is not None:
                    raise UnavailableGuard("Owner graph business receipt exists")
                current_intent = db.execute(
                    f"SELECT * FROM {intent_table} WHERE bot=? AND persona=? "
                    "AND operation_id=?", namespace.as_tuple + (operation_id,),
                ).fetchone()
                if current_intent != namespace.as_tuple + intent:
                    raise UnavailableGuard("Owner graph durable intent changed")
                db.execute(
                    f"INSERT OR IGNORE INTO {table}"
                    "(bot,persona,operation_id,status,permit_json,graph_revision,"
                    "graph_epoch,finish_request_id,finish_request_digest) "
                    "VALUES(?,?,?,?,?,?,?,?,?)", namespace.as_tuple + expected,
                )
                recorded = db.execute(
                    f"SELECT operation_id,status,permit_json,graph_revision,"
                    "graph_epoch,finish_request_id,finish_request_digest "
                    f"FROM {table} WHERE bot=? AND persona=? AND operation_id=?",
                    namespace.as_tuple + (operation_id,),
                ).fetchone()
                if recorded != expected:
                    raise UnavailableGuard("Owner graph rejection identity differs")
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        self._finish_rejected_owner_graph_write_v2(
            kind=kind, namespace=namespace, operation_id=operation_id,
            input_digest=input_digest, attempt_id=attempt_id, metadata=metadata,
            epoch=epoch, anchor=anchor, rejection=expected)

    def _finish_rejected_owner_graph_write_v2(self, *, kind, namespace,
                                               operation_id, input_digest,
                                               attempt_id, metadata, epoch,
                                               anchor, rejection):
        from .authority_service.v2_contract import FencePermitV2, from_wire

        port = self.__content_fence_v2
        target = metadata.requirements
        try:
            permit = from_wire(json.loads(rejection[2]))
        except (TypeError, ValueError) as exc:
            raise UnavailableGuard("Owner graph rejected permit is invalid") from exc
        expected_digest = "sha256:" + canonical_digest({
            "operation_id": attempt_id, "permit_token": permit.token,
            "action": "rejected_no_commit", "business_operation_id": operation_id,
            "input_digest": input_digest, "kind": kind,
        })
        if (type(permit) is not FencePermitV2
                or rejection != (operation_id, "rejected_no_commit",
                                 rejection[2], metadata.graph_revision,
                                 epoch.revision, "abort:" + attempt_id,
                                 expected_digest)
                or permit.operation_id != attempt_id or permit.operation != "write"
                or permit.holder != self.__holder
                or permit.subject != port.installation_grant.subject
                or permit.authority_id != target.authority_id
                or permit.namespace != target.authority_namespace
                or permit.generation != 1 or permit.pinned_anchor != anchor):
            raise UnavailableGuard("Owner graph rejected fence identity differs")
        observed, state = port.get_fence_operation(
            namespace=namespace, authority_namespace=target.authority_namespace,
            operation_id=attempt_id)
        if observed != permit or state not in {"active", "finished"}:
            raise UnavailableGuard("Owner graph rejected Authority fence differs")
        if state == "active":
            scope = FenceScope(namespace, target.authority_namespace, 1, "write",
                               attempt_id, permit, anchor, epoch,
                               metadata.graph_revision)
            if port.validate_fence(scope) != permit:
                raise UnavailableGuard("Owner graph rejected permit changed")
            port.finish_fence(scope, request_id=rejection[5],
                              request_digest=rejection[6])

    def reject_unresolvable_role_initialization_v2(
            self, *, namespace: NamespaceId, operation_id: str,
            request_digest: str, principal: OwnerPrincipalV1,
            actor_id: str, owner_session_token: str,
            owner_session_request: OwnerSessionLoginRequestV1) -> bool:
        """Finish an original pending fence only when no first-role write is proven."""
        from .authority_service.v2_contract import FencePermitV2
        from .authority_service.v2_owner_contract import (
            OwnerGraphCommitProofV1, canonical_digest as owner_contract_digest,
        )

        if (type(namespace) is not NamespaceId or type(principal) is not OwnerPrincipalV1
                or type(operation_id) is not str or not operation_id
                or type(request_digest) is not str or not request_digest):
            raise TypeError("pending role recovery requires typed Owner identity")
        store = self.__store
        port = self.__content_fence_v2
        if not isinstance(store, ProductionGraphStore) or port is None:
            raise UnavailableGuard("pending role graph is unavailable")
        with store._lock:
            metadata, epoch = self._v2_graph_stamp(namespace)
            db = store._db
            intent = db.execute(
                "SELECT operation_id,input_digest,fence_attempt_id,"
                "requirements_json,anchor_json,graph_revision,graph_epoch "
                "FROM graph_role_init_intents_v1 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            if intent is None:
                return False
            request_proof = db.execute(
                "SELECT operation_id,request_digest,input_digest "
                "FROM graph_role_init_request_proofs_v1 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            saved = db.execute(
                "SELECT 1 FROM graph_role_init_receipts_v1 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            rejection = db.execute(
                "SELECT 1 FROM graph_role_init_rejections_v1 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            grant_key = owner_grant_key(*namespace.as_tuple)
            grant_row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (grant_key.token,),
            ).fetchone()
            owner_proof_row = db.execute(
                "SELECT operation_id,request_digest,grant_id,grant_digest,"
                "graph_incarnation,graph_access_epoch,graph_epoch,"
                "graph_receipt_digest,proof_json "
                "FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            business_atom = db.execute(
                "SELECT 1 FROM graph_atoms WHERE bot=? AND persona=? AND type_name IN "
                "('d01.persona_plan.v1','d01.persona_activation.v1',"
                "'runtime.role_resources.v1') LIMIT 1", namespace.as_tuple,
            ).fetchone()
        if request_proof is None:
            raise UnavailableGuard("pending role has no original request proof")
        if (intent[0] != operation_id
                or request_proof != (operation_id, request_digest, intent[1])):
            raise AuthorityDenied("pending role request identity differs")
        if saved is not None or rejection is not None or business_atom is not None:
            raise UnavailableGuard("pending role business outcome is not proven absent")
        if (metadata.graph_revision, epoch.revision) != intent[5:7]:
            raise UnavailableGuard("pending role graph stamp changed")
        target = metadata.requirements
        anchor = port.current_anchor(
            namespace=namespace, authority_namespace=target.authority_namespace)
        if (target.namespace != namespace or not self._anchor_matches(target, anchor)
                or intent[3] != canonical_json(asdict(target))
                or intent[4] != canonical_json(asdict(anchor))
                or grant_row is None or grant_row[0] != 1 or grant_row[2] != 1
                or owner_proof_row is None):
            raise UnavailableGuard("pending role recovery identity differs")
        grant = GraphAtom(grant_key, 1, json.loads(grant_row[1]), True)
        validate_owner_grant_v1(grant.value)
        proof = OwnerGraphCommitProofV1(
            namespace, owner_proof_row[0], owner_proof_row[1],
            owner_proof_row[2], owner_proof_row[3], owner_proof_row[4],
            1, owner_proof_row[5], owner_proof_row[6], owner_proof_row[7])
        if (owner_proof_row[8] != canonical_json(asdict(proof))
                or grant_row[1] != canonical_json(grant.value)
                or grant.value["principal"] != asdict(principal)
                or grant.value["grant_id"] != proof.grant_id
                or "sha256:" + canonical_digest(grant.value) != proof.grant_digest
                or grant.value["issue_operation_id"] != proof.operation_id
                or grant.value["graph_incarnation"] != proof.graph_incarnation
                or target.graph_incarnation != proof.graph_incarnation):
            raise AuthorityDenied("pending role Owner principal differs")
        self._check_owner_session_v2(
            namespace=namespace, principal=principal, actor_id=actor_id,
            token=owner_session_token, request=owner_session_request,
            target=target)
        attempt_id = intent[2]
        permit, state = port.get_fence_operation(
            namespace=namespace, authority_namespace=target.authority_namespace,
            operation_id=attempt_id)
        if (type(permit) is not FencePermitV2 or state != "active"
                or permit.operation_id != attempt_id or permit.operation != "write"
                or permit.holder != self.__holder
                or permit.subject != port.installation_grant.subject
                or permit.authority_id != target.authority_id
                or permit.namespace != target.authority_namespace
                or permit.generation != 1 or permit.pinned_anchor != anchor):
            raise UnavailableGuard("pending role original fence differs")
        guard_reader = getattr(port, "get_current_owner_guard_for_fence", None)
        if not callable(guard_reader):
            raise UnavailableGuard("pending role signed Owner guard is unavailable")
        guarded = guard_reader(
            namespace=namespace, authority_namespace=target.authority_namespace,
            permit=permit, owner_actor_id=actor_id,
            owner_session_token=owner_session_token,
            owner_session_request=owner_session_request)
        if (type(guarded) is not tuple or len(guarded) != 2
                or type(guarded[0]) is not OwnerAuthorizationGuardV1
                or guarded[1] != permit
                or guarded[0].authority_id != target.authority_id
                or guarded[0].installation_id != grant.value["installation_id"]
                or guarded[0].namespace != namespace
                or guarded[0].authorization_revision != 1
                or guarded[0].authorization_head != owner_contract_digest(proof)
                or guarded[0].pending_revoke_operation_id is not None
                or guarded[0].minimum_revocation_revision != 0
                or guarded[0].minimum_revocation_epoch != 0):
            raise UnavailableGuard("pending role signed Owner guard differs")
        self._reject_owner_graph_write_v2(
            kind="role_init", namespace=namespace, operation_id=operation_id,
            input_digest=intent[1], attempt_id=attempt_id, metadata=metadata,
            epoch=epoch, anchor=anchor, permit=permit, intent=intent)
        return True

    def replay_committed_role_initialization_v2(
            self, *, namespace: NamespaceId, operation_id: str,
            request_digest: str, principal: OwnerPrincipalV1,
            actor_id: str, owner_session_token: str,
            owner_session_request: OwnerSessionLoginRequestV1):
        """Recover an already committed first role from its original graph atoms."""
        from .domains.d01 import (
            PersonaPlan, _persona_block, _value_rule,
        )
        from .graph_types import Owner
        from .runtime.role_resources import (
            read_role_resources, role_resources_key,
        )
        from .workbench_api.d01_onboarding import (
            VerifiedBudgetLease, VerifiedCreationResources, VerifiedModelCapability,
        )

        if (type(namespace) is not NamespaceId or type(principal) is not OwnerPrincipalV1
                or type(operation_id) is not str or not operation_id
                or type(request_digest) is not str):
            raise TypeError("committed role replay requires typed Owner identity")
        store = self.__store
        if not isinstance(store, ProductionGraphStore):
            raise UnavailableGuard("committed role graph is unavailable")
        with store._lock:
            row = store._db.execute(
                "SELECT receipt_json FROM graph_role_init_receipts_v1 "
                "WHERE bot=? AND persona=?", namespace.as_tuple,
            ).fetchone()
            if row is None:
                return None
            try:
                payload = json.loads(row[0])
                receipt = RoleInitializationReceiptV1(
                    **{**payload, "namespace": NamespaceId(**payload["namespace"])})
            except (TypeError, ValueError, KeyError) as exc:
                raise UnavailableGuard("committed role receipt is invalid") from exc
            if (receipt.operation_id != operation_id
                    or receipt.request_digest != request_digest):
                raise AuthorityDenied("committed role request identity differs")
            plan_key = AtomKey(
                Owner("persona", *namespace.as_tuple),
                "d01.persona_plan.v1", receipt.plan_id)
            resource_key = role_resources_key(namespace, receipt.plan_id)
            plan_row = store._db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (plan_key.token,),
            ).fetchone()
            resource_row = store._db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (resource_key.token,),
            ).fetchone()
        if plan_row is None or resource_row is None:
            raise UnavailableGuard("committed role atoms are incomplete")
        try:
            plan_value = json.loads(plan_row[1])
            store._registry.validate(plan_key, plan_value)
            plan = PersonaPlan(
                plan_value["plan_id"], NamespaceId(**plan_value["namespace"]),
                plan_value["version"],
                tuple(_persona_block(item) for item in plan_value["blocks"]),
                tuple(_value_rule(item) for item in plan_value["values"]),
                plan_value["authored"],
            )
            selected = read_role_resources(
                GraphAtom(resource_key, resource_row[0], json.loads(resource_row[1]),
                          bool(resource_row[2])),
                namespace=namespace, plan_id=receipt.plan_id,
                head_id=receipt.head_id,
            )
            resources = VerifiedCreationResources(
                namespace, selected.blueprint_ref, selected.model_capability_ref,
                selected.budget_ref, plan.version, selected.blueprint_digest,
                plan.blocks[1:], plan.values,
                VerifiedModelCapability(
                    namespace, selected.model_capability_ref,
                    selected.model_resource_ref, selected.model_revision,
                    selected.model_digest),
                VerifiedBudgetLease(
                    namespace, selected.budget_ref, selected.budget_lease_ref,
                    selected.budget_version, selected.budget_digest),
            )
        except (TypeError, ValueError, KeyError) as exc:
            raise UnavailableGuard("committed role graph atoms are invalid") from exc
        return self.commit_role_initialization_v2(
            namespace=namespace, operation_id=operation_id, plan=plan,
            principal=principal, request_digest=request_digest,
            resources=resources, actor_id=actor_id,
            owner_session_token=owner_session_token,
            owner_session_request=owner_session_request)

    def read_current_creation_budget_v2(
            self, *, namespace: NamespaceId, budget_ref: str,
            actor_id: str, principal: OwnerPrincipalV1,
            owner_session_token: str,
            owner_session_request: OwnerSessionLoginRequestV1,
            expected: VerifiedBudgetLease | None = None) -> CreationBudgetProofV1:
        """Read an existing D11 lease/grant under current Owner and Authority fences.

        The ref is the durable lease ID. This read does not reserve budget or
        make a later D01 commit safe without its own lease-version check.
        """
        from .authority_service.contract import identifier
        from .runtime.issuers import IssuerAuthorityDenied
        from .workbench_api.d01_onboarding import VerifiedBudgetLease

        if (not isinstance(self.__store, ProductionGraphStore)
                or self.__content_fence_v2 is None
                or type(namespace) is not NamespaceId
                or type(principal) is not OwnerPrincipalV1):
            raise UnavailableGuard("creation budget requires production v2 Owner")
        identifier(budget_ref, "budget_ref")
        identifier(actor_id, "actor_id")
        from .authority_service.v2_owner_session import OwnerSessionLoginRequestV1
        if (type(owner_session_token) is not str or not owner_session_token
                or type(owner_session_request) is not OwnerSessionLoginRequestV1):
            raise UnavailableGuard("signed creation Owner session is unavailable")
        if expected is not None and type(expected) is not VerifiedBudgetLease:
            raise TypeError("expected creation budget must be a verified lease")
        grant_reader = getattr(self.__d11_issuer, "current_budget_grant", None)
        if not callable(grant_reader):
            raise UnavailableGuard("current signed D11 budget grant is unavailable")
        store = self.__store
        port = self.__content_fence_v2
        with store._lock:
            metadata, epoch = self._v2_graph_stamp(namespace)
        target = metadata.requirements
        if target.namespace != namespace or target.activation_generation != 1:
            raise UnavailableGuard("creation budget graph identity differs")
        if (owner_session_request.principal != principal
                or owner_session_request.authority_id != target.authority_id
                or owner_session_request.authority_namespace
                != target.authority_namespace
                or owner_session_request.installation_id
                != port.installation_grant.installation_id
                or owner_session_request.audience != "owner"):
            raise UnavailableGuard("creation Owner session identity differs")
        anchor = port.current_anchor(
            namespace=namespace, authority_namespace=target.authority_namespace)
        if not self._anchor_matches(target, anchor):
            raise UnavailableGuard("creation budget Authority anchor differs")
        attempt_id = "creation-budget-read-" + secrets.token_hex(16)
        permit = port.begin_fence(
            namespace=namespace, authority_namespace=target.authority_namespace,
            holder=self.__holder, generation=1, operation="read",
            operation_id=attempt_id, expected_anchor=anchor)
        scope = FenceScope(namespace, target.authority_namespace, 1, "read",
                           attempt_id, permit, anchor, epoch, metadata.graph_revision)
        authority = AuthorityContext(
            actor_id, "d12", "creation-budget-read", namespace, ("persona",),
            "workbench_user_action", ("owner",), "owner-grant-v1", 1)
        try:
            guard, owner = self._owner_binding_in_fence(
                authority, scope, principal, None,
                (owner_session_token, owner_session_request))
            if "workbench.create" not in owner.capabilities:
                raise AuthorityDenied("Owner grant lacks creation permission")
            if port.validate_fence(scope) != permit:
                raise UnavailableGuard("creation budget read permit changed")
            with store._lock:
                if self._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise StaleRead("creation budget graph stamp changed")
                db = store._db
                try:
                    lease = get_budget_lease(db, budget_ref)
                    grant = grant_reader(db, budget_ref)
                except (BudgetError, IssuerAuthorityDenied) as exc:
                    raise UnavailableGuard("current D11 budget lease/grant is absent") from exc
                if (lease.lease_id != budget_ref
                        or (lease.bot_id, lease.persona_id) != namespace.as_tuple
                        or lease.state != "active"
                        or grant.lease_id != lease.lease_id
                        or (grant.bot_id, grant.persona_id) != namespace.as_tuple
                        or grant.currency != lease.currency):
                    raise UnavailableGuard("D11 budget lease/grant differs or is inactive")
                budget = VerifiedBudgetLease(
                    namespace, budget_ref, lease.lease_id, lease.version,
                    "sha256:" + canonical_digest(asdict(lease)))
                if expected is not None and budget != expected:
                    raise UnavailableGuard("creation budget selection changed")
                result = CreationBudgetProofV1(
                    budget, grant.grant_id, grant.version,
                    "sha256:" + canonical_digest(asdict(grant)),
                    metadata.graph_revision, epoch.revision,
                    guard.authorization_head)
            if port.validate_fence(scope) != permit:
                raise UnavailableGuard("creation budget read permit changed")
            with store._lock:
                if self._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise StaleRead("creation budget graph stamp changed after read")
            return result
        finally:
            port.finish_fence(
                scope, request_id="finish:" + attempt_id,
                request_digest="sha256:" + canonical_digest({
                    "operation_id": attempt_id, "permit_token": permit.token,
                    "action": "finish_creation_budget_read",
                }))

    def commit_role_initialization_v2(self, *, namespace: NamespaceId,
                                      operation_id: str, plan, principal,
                                      request_digest: str, resources,
                                      actor_id: str, owner_session_token: str,
                                      owner_session_request: OwnerSessionLoginRequestV1):
        """Install one authored D01 plan and active head after committed Owner issue.

        This internal GraphWorker operation is not an Owner login endpoint. Its
        caller must separately authenticate the claimant; the graph worker
        checks the paired Authority's current guard under its exact write fence.
        """
        from .authority_service.contract import identifier
        from .authority_service.v2_contract import FencePermitV2, from_wire, to_wire
        from .authority_service.v2_owner_contract import (
            OwnerAuthorizationGuardV1, OwnerGraphCommitProofV1, OwnerPrincipalV1,
            canonical_digest as owner_contract_digest,
        )
        from .domains.d01 import PersonaDomain, PersonaPlan, _activation_key
        from .runtime.budget import BudgetError
        from .runtime.role_resources import (
            ROLE_RESOURCES_TYPE, RoleRuntimeResourcesV1, role_resources_write,
        )
        from .runtime.restore_anchor import RestoreAnchor
        from .workbench_api.d01_onboarding import (
            VerifiedBudgetLease, VerifiedCreationResources, VerifiedModelCapability,
        )

        if (not isinstance(self.__store, ProductionGraphStore)
                or self.__content_fence_v2 is None):
            raise UnavailableGuard("role initialization requires production v2")
        if type(namespace) is not NamespaceId or type(plan) is not PersonaPlan:
            raise TypeError("role initialization requires a typed namespace and plan")
        if type(principal) is not OwnerPrincipalV1:
            raise TypeError("role initialization requires the paired Owner principal")
        identifier(operation_id, "operation_id")
        if (type(request_digest) is not str or len(request_digest) != 71
                or not request_digest.startswith("sha256:")
                or any(char not in "0123456789abcdef" for char in request_digest[7:])):
            raise ValueError("full role creation request digest is required")
        if plan.namespace != namespace or plan.authored is not True:
            raise AuthorityDenied("role plan is not an authored plan for this namespace")
        if (type(resources) is not VerifiedCreationResources
                or resources.namespace != namespace
                or type(resources.model) is not VerifiedModelCapability
                or resources.model.namespace != namespace
                or resources.model.capability_ref != resources.model_capability_ref
                or type(resources.budget) is not VerifiedBudgetLease
                or resources.budget.namespace != namespace
                or resources.budget.budget_ref != resources.budget_ref
                or resources.blueprint_version != plan.version
                or plan.blocks[1:] != resources.blocks
                or plan.values != resources.values):
            raise AuthorityDenied("verified creation resources differ from authored plan")
        port = self.__content_fence_v2
        guard_reader = getattr(port, "get_current_owner_guard_for_fence", None)
        if not callable(guard_reader):
            raise UnavailableGuard("current Owner guard fence port is unavailable")
        store = self.__store
        domain = PersonaDomain()
        plan_write = domain.plan_write(plan)
        resource_value = RoleRuntimeResourcesV1(
            namespace.bot_id, namespace.persona_id, operation_id,
            plan.plan_id, plan.head_id, resources.blueprint_ref,
            resources.blueprint_digest, resources.model.capability_ref,
            resources.model.resource_ref, resources.model.revision,
            resources.model.digest, resources.budget.budget_ref,
            resources.budget.lease_ref, resources.budget.version,
            resources.budget.digest,
        )
        resource_write = role_resources_write(resource_value)

        def check_creation_budget(db):
            try:
                lease = get_budget_lease(db, resources.budget.lease_ref)
            except BudgetError as exc:
                raise AuthorityDenied("verified creation budget lease is unavailable") from exc
            if (lease.lease_id != resources.budget.lease_ref
                    or (lease.bot_id, lease.persona_id) != namespace.as_tuple
                    or lease.state != "active"
                    or lease.version != resources.budget.version
                    or "sha256:" + canonical_digest(asdict(lease)) != resources.budget.digest):
                raise AuthorityDenied("verified creation budget lease changed")

        try:
            spec = store._registry.spec(ROLE_RESOURCES_TYPE)
            if spec.writer_domain != "d11":
                raise UnavailableGuard("D11 role resource graph type is unavailable")
            store._registry.validate(resource_write.key, resource_write.value)
        except (KeyError, ValueError, TypeError) as exc:
            raise UnavailableGuard("D11 role resource graph type is unavailable") from exc
        activation_key = _activation_key(namespace)
        grant_key = owner_grant_key(*namespace.as_tuple)
        with store._lock:
            metadata, epoch = self._v2_graph_stamp(namespace)
            db = store._db
            grant_row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (grant_key.token,),
            ).fetchone()
            proof_row = db.execute(
                "SELECT operation_id,request_digest,grant_id,grant_digest,"
                "graph_incarnation,graph_access_epoch,graph_epoch,"
                "graph_receipt_digest,proof_json "
                "FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            access_row = db.execute(
                "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
                "WHERE bot=? AND persona=?", namespace.as_tuple,
            ).fetchone()
            intent = db.execute(
                "SELECT operation_id,input_digest,fence_attempt_id,"
                "requirements_json,anchor_json,graph_revision,graph_epoch "
                "FROM graph_role_init_intents_v1 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            saved = db.execute(
                "SELECT operation_id,input_digest,permit_json,receipt_json,"
                "pre_graph_revision,pre_graph_epoch,post_graph_revision,"
                "post_graph_epoch,finish_request_id,finish_request_digest "
                "FROM graph_role_init_receipts_v1 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            rejection = db.execute(
                "SELECT operation_id,status,permit_json,graph_revision,"
                "graph_epoch,finish_request_id,finish_request_digest "
                "FROM graph_role_init_rejections_v1 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
        if (grant_row is None or grant_row[0] != 1 or grant_row[2] != 1
                or proof_row is None or access_row != (1, 0)):
            raise UnavailableGuard("first Owner grant or access epoch is unavailable")
        grant = GraphAtom(grant_key, grant_row[0], json.loads(grant_row[1]), True)
        validate_owner_grant_v1(grant.value)
        proof = OwnerGraphCommitProofV1(
            namespace, proof_row[0], proof_row[1], proof_row[2], proof_row[3],
            proof_row[4], 1, proof_row[5], proof_row[6], proof_row[7])
        if (proof_row[8] != canonical_json(asdict(proof))
                or grant_row[1] != canonical_json(grant.value)
                or grant.value["grant_id"] != proof.grant_id
                or "sha256:" + canonical_digest(grant.value) != proof.grant_digest
                or grant.value["graph_incarnation"] != proof.graph_incarnation
                or grant.value["principal"] != asdict(principal)
                or grant.value["issue_operation_id"] != proof.operation_id
                or proof.graph_access_epoch != 1
                or metadata.requirements.graph_incarnation != proof.graph_incarnation):
            raise AuthorityDenied("role principal or grant differs from Owner issue")
        if ("workbench.create" not in grant.value["capabilities"]
                or "workbench_user_action" not in grant.value["purposes"]
                or "owner" not in grant.value["audiences"]):
            raise AuthorityDenied("Owner grant lacks role creation permission")
        target = metadata.requirements
        if (target.namespace != namespace or target.activation_generation != 1
                or target.authority_id != grant.value["authority_id"]
                or port.installation_grant.authority_id != target.authority_id
                or port.installation_grant.installation_id != grant.value["installation_id"]):
            raise UnavailableGuard("role recovery or installation identity differs")
        self._check_owner_session_v2(
            namespace=namespace, principal=principal, actor_id=actor_id,
            token=owner_session_token, request=owner_session_request,
            target=target)
        input_digest = "sha256:" + canonical_digest({
            "schema": "sylanne3.graph.role_initialization.v1",
            "namespace": list(namespace.as_tuple), "operation_id": operation_id,
            "request_digest": request_digest,
            "plan": asdict(plan), "principal": asdict(principal),
            "resources": asdict(resource_value),
            "owner_proof": asdict(proof),
        })
        attempt_id = "role-write-" + canonical_digest({
            "namespace": list(namespace.as_tuple), "operation_id": operation_id,
            "input_digest": input_digest,
        })[:48]
        anchor = port.current_anchor(
            namespace=namespace, authority_namespace=target.authority_namespace)
        if not self._anchor_matches(target, anchor):
            raise UnavailableGuard("role recovery anchor differs")
        identity = (operation_id, input_digest, attempt_id,
                    canonical_json(asdict(target)), canonical_json(asdict(anchor)))
        if intent is not None and intent[:5] != identity:
            if saved is None and rejection is None:
                self.reject_unresolvable_role_initialization_v2(
                    namespace=namespace, operation_id=operation_id,
                    request_digest=request_digest, principal=principal,
                    actor_id=actor_id, owner_session_token=owner_session_token,
                    owner_session_request=owner_session_request)
            raise AuthorityDenied("role initialization identity differs")
        if (saved is None) != (intent is None) and saved is not None:
            raise UnavailableGuard("role receipt lacks original intent")
        if rejection is not None:
            if intent is None or saved is not None:
                raise UnavailableGuard("rejected role has a business receipt")
            self._finish_rejected_owner_graph_write_v2(
                kind="role_init", namespace=namespace, operation_id=operation_id,
                input_digest=input_digest, attempt_id=attempt_id, metadata=metadata,
                epoch=epoch, anchor=anchor, rejection=rejection)
            raise UnavailableGuard("role initialization terminal rejected_no_commit")
        if saved is not None:
            try:
                payload = json.loads(saved[3])
                if type(payload) is not dict or type(payload.get("namespace")) is not dict:
                    raise ValueError("role receipt is not canonical")
                payload["namespace"] = NamespaceId(**payload["namespace"])
                receipt = RoleInitializationReceiptV1(**payload)
                permit = from_wire(json.loads(saved[2]))
            except (TypeError, ValueError, KeyError) as exc:
                raise UnavailableGuard("durable role receipt is invalid") from exc
            finish_digest = "sha256:" + canonical_digest({
                "operation_id": attempt_id, "permit_token": permit.token,
                "action": "finish_role_initialization",
                "business_operation_id": operation_id,
                "input_digest": input_digest,
            })
            if (type(permit) is not FencePermitV2
                    or saved[0:2] != (operation_id, input_digest)
                    or saved[4:6] != intent[5:7]
                    or saved[6:8] != (receipt.graph_revision, receipt.graph_epoch)
                    or saved[6] != saved[4] + 1
                    or saved[8:10] != ("finish:" + attempt_id, finish_digest)
                    or saved[3] != canonical_json(asdict(receipt))
                    or receipt.namespace != namespace
                    or receipt.operation_id != operation_id
                    or receipt.request_digest != request_digest
                    or receipt.input_digest != input_digest
                    or receipt.plan_id != plan.plan_id
                    or receipt.head_id != plan.head_id
                    or receipt.owner_grant_id != proof.grant_id
                    or receipt.owner_grant_revision != 1
                    or receipt.owner_authorization_head != owner_contract_digest(proof)
                    or receipt.graph_incarnation != proof.graph_incarnation
                    or receipt.fence_attempt_id != attempt_id
                    or receipt.finish_request_id != saved[8]
                    or receipt.finish_request_digest != saved[9]
                    or permit.operation_id != attempt_id or permit.operation != "write"
                    or permit.holder != self.__holder
                    or permit.subject != port.installation_grant.subject
                    or permit.authority_id != target.authority_id
                    or permit.namespace != target.authority_namespace
                    or permit.generation != 1 or permit.pinned_anchor != anchor):
                raise UnavailableGuard("durable role initialization receipt differs")
            with store._lock:
                plan_row = store._db.execute(
                    "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                    (plan_write.key.token,),
                ).fetchone()
                activation_row = store._db.execute(
                    "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                    (activation_key.token,),
                ).fetchone()
                resource_row = store._db.execute(
                    "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                    (resource_write.key.token,),
                ).fetchone()
                committed_guard = OwnerAuthorizationGuardV1(
                    target.authority_id, grant.value["installation_id"], namespace,
                    1, receipt.owner_authorization_head, 0, 0)
                expected_activation = domain.activation_write(
                    plan, grant, committed_guard)
                if (plan_row != (1, canonical_json(plan_write.value), 1)
                        or resource_row != (1, canonical_json(resource_write.value), 1)
                        or activation_row != (
                            1, canonical_json(expected_activation.value), 1)):
                    raise UnavailableGuard("durable role graph atoms differ")
            observed, state = port.get_fence_operation(
                namespace=namespace, authority_namespace=target.authority_namespace,
                operation_id=attempt_id)
            if observed != permit or state not in {"active", "finished"}:
                raise UnavailableGuard("role Authority fence differs")
            if state == "active":
                if (metadata.graph_revision, epoch.revision) != saved[6:8]:
                    raise UnavailableGuard("active role fence lost business stamp")
                scope = FenceScope(
                    namespace, target.authority_namespace, 1, "write", attempt_id,
                    permit, anchor, NamespaceEpoch(*namespace.as_tuple, intent[6]),
                    intent[5])
                if port.validate_fence(scope) != permit:
                    raise UnavailableGuard("role write permit changed")
                port.finish_fence(scope, request_id=saved[8],
                                  request_digest=saved[9])
            elif (metadata.graph_revision < saved[6]
                  or epoch.revision < saved[7]):
                raise UnavailableGuard("finished role lost business stamp")
            self._read_current_owner_session_v2(
                namespace=namespace, principal=principal, actor_id=actor_id,
                token=owner_session_token, request=owner_session_request,
                capability="workbench.create")
            return receipt
        if (intent is not None and
                (metadata.graph_revision, epoch.revision) != intent[5:7]):
            raise UnavailableGuard("uncommitted role graph stamp changed")
        try:
            with store._lock:
                check_creation_budget(store._db)
        except AuthorityDenied:
            if intent is None:
                raise
            if (metadata.graph_revision, epoch.revision) != intent[5:7]:
                raise UnavailableGuard("uncommitted role graph stamp changed")
            with store._lock:
                db = store._db
                if (db.execute(
                        "SELECT 1 FROM graph_role_init_receipts_v1 "
                        "WHERE bot=? AND persona=? AND operation_id=?",
                        namespace.as_tuple + (operation_id,),
                ).fetchone() is not None or db.execute(
                        "SELECT 1 FROM graph_atoms WHERE token IN (?,?,?) LIMIT 1",
                        (plan_write.key.token, activation_key.token,
                         resource_write.key.token),
                ).fetchone() is not None):
                    raise UnavailableGuard("role write outcome is not proven absent")
            observed, state = port.get_fence_operation(
                namespace=namespace, authority_namespace=target.authority_namespace,
                operation_id=attempt_id)
            if (type(observed) is not FencePermitV2 or state != "active"
                    or observed.operation_id != attempt_id
                    or observed.operation != "write"
                    or observed.holder != self.__holder
                    or observed.subject != port.installation_grant.subject
                    or observed.authority_id != target.authority_id
                    or observed.namespace != target.authority_namespace
                    or observed.generation != 1 or observed.pinned_anchor != anchor):
                raise UnavailableGuard("original role fence cannot prove no commit")
            self._reject_owner_graph_write_v2(
                kind="role_init", namespace=namespace, operation_id=operation_id,
                input_digest=input_digest, attempt_id=attempt_id, metadata=metadata,
                epoch=epoch, anchor=anchor, permit=observed, intent=intent)
            raise
        if (metadata.graph_revision != 1 or epoch.revision != proof.graph_epoch
                or proof.graph_epoch != 1):
            raise UnavailableGuard("role initialization requires first Owner graph head")
        with store._lock:
            if (store._db.execute(
                    "SELECT 1 FROM graph_atoms WHERE token IN (?,?,?) LIMIT 1",
                    (plan_write.key.token, activation_key.token,
                     resource_write.key.token)).fetchone() is not None):
                raise UnavailableGuard("initial role atoms already exist")
        if intent is None:
            with store._lock:
                db = store._db
                db.execute("BEGIN IMMEDIATE")
                try:
                    if self._v2_graph_stamp(namespace) != (metadata, epoch):
                        raise StaleRead("role graph stamp changed before intent")
                    db.execute(
                        "INSERT INTO graph_role_init_intents_v1"
                        "(bot,persona,operation_id,input_digest,fence_attempt_id,"
                        "requirements_json,anchor_json,graph_revision,graph_epoch) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        namespace.as_tuple + identity + (
                            metadata.graph_revision, epoch.revision),
                    )
                    db.execute(
                        "INSERT INTO graph_role_init_request_proofs_v1"
                        "(bot,persona,operation_id,request_digest,input_digest) "
                        "VALUES(?,?,?,?,?)",
                        namespace.as_tuple + (operation_id, request_digest, input_digest),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
            intent = identity + (metadata.graph_revision, epoch.revision)
        pinned_anchor = RestoreAnchor(**json.loads(intent[4]))
        if pinned_anchor != anchor:
            raise UnavailableGuard("role original fence anchor changed")
        permit = port.begin_fence(
            namespace=namespace, authority_namespace=target.authority_namespace,
            holder=self.__holder, generation=1, operation="write",
            operation_id=attempt_id, expected_anchor=pinned_anchor,
            retain_on_unknown=True)
        if (type(permit) is not FencePermitV2 or permit.operation_id != attempt_id
                or permit.operation != "write" or permit.holder != self.__holder
                or permit.subject != port.installation_grant.subject
                or permit.authority_id != target.authority_id
                or permit.namespace != target.authority_namespace
                or permit.generation != 1 or permit.pinned_anchor != anchor):
            raise UnavailableGuard("role write permit differs")
        scope = FenceScope(namespace, target.authority_namespace, 1, "write",
                           attempt_id, permit, anchor, epoch, metadata.graph_revision)
        try:
            guarded = guard_reader(
                namespace=namespace, authority_namespace=target.authority_namespace,
                permit=permit, owner_actor_id=actor_id,
                owner_session_token=owner_session_token,
                owner_session_request=owner_session_request)
            if (type(guarded) is not tuple or len(guarded) != 2
                    or type(guarded[0]) is not OwnerAuthorizationGuardV1
                    or guarded[1] != permit):
                raise UnavailableGuard("current Owner guard response is unavailable")
            guard = guarded[0]
            if (guard.authority_id != target.authority_id
                    or guard.installation_id != grant.value["installation_id"]
                    or guard.namespace != namespace
                    or guard.authorization_revision != 1
                    or guard.authorization_head != owner_contract_digest(proof)
                    or guard.pending_revoke_operation_id is not None
                    or guard.minimum_revocation_revision != 0
                    or guard.minimum_revocation_epoch != 0):
                raise AuthorityDenied("current Owner authorization differs from graph")
        except Exception:
            self._reject_owner_graph_write_v2(
                kind="role_init", namespace=namespace, operation_id=operation_id,
                input_digest=input_digest, attempt_id=attempt_id, metadata=metadata,
                epoch=epoch, anchor=anchor, permit=permit, intent=intent)
            raise
        if port.validate_fence(scope) != permit:
            raise UnavailableGuard("role write permit changed")
        class _CreationBudgetChangedNoCommit(Exception):
            pass

        budget_denial = None
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                if self._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise StaleRead("role graph stamp changed")
                if db.execute(
                    "SELECT operation_id,input_digest,fence_attempt_id,"
                    "requirements_json,anchor_json,graph_revision,graph_epoch "
                    "FROM graph_role_init_intents_v1 WHERE bot=? AND persona=?",
                    namespace.as_tuple,
                ).fetchone() != intent:
                    raise UnavailableGuard("role durable intent changed")
                current_grant = db.execute(
                    "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                    (grant_key.token,),
                ).fetchone()
                current_access = db.execute(
                    "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
                    "WHERE bot=? AND persona=?", namespace.as_tuple,
                ).fetchone()
                if current_grant != grant_row or current_access != (1, 0):
                    raise StaleRead("Owner grant changed before role initialization")
                try:
                    check_creation_budget(db)
                except AuthorityDenied as exc:
                    budget_denial = exc
                    raise _CreationBudgetChangedNoCommit from exc
                activation_write = domain.activation_write(plan, grant, guard)
                candidate = GraphCandidate(
                    Event(Scope(*namespace.as_tuple, "d01-role-initialization"),
                          operation_id, 0, "role_initialized", {
                              "input_digest": input_digest,
                              "owner_grant_id": proof.grant_id,
                              "authorization_head": guard.authorization_head,
                          }),
                    (GraphVersion(grant_key, 1), GraphVersion(plan_write.key, 0),
                     GraphVersion(activation_key, 0),
                     GraphVersion(resource_write.key, 0)),
                    (plan_write, activation_write, resource_write), (epoch,),
                )
                graph_receipt = GraphStore._graph_commit_in_transaction(
                    store, candidate, _capability=self.__graph_capability)
                if (graph_receipt.status != "committed"
                        or graph_receipt.epoch.revision != epoch.revision + 1
                        or graph_receipt.revisions != (
                            GraphVersion(plan_write.key, 1),
                            GraphVersion(activation_key, 1),
                            GraphVersion(resource_write.key, 1))):
                    raise UnavailableGuard("role graph transaction did not commit all atoms")
                store.cas_graph_recovery_metadata(
                    metadata, target, _capability=self.__graph_capability)
                finish_id = "finish:" + attempt_id
                finish_digest = "sha256:" + canonical_digest({
                    "operation_id": attempt_id, "permit_token": permit.token,
                    "action": "finish_role_initialization",
                    "business_operation_id": operation_id,
                    "input_digest": input_digest,
                })
                receipt = RoleInitializationReceiptV1(
                    namespace, operation_id, request_digest, input_digest, plan.plan_id,
                    plan.head_id, proof.grant_id, 1, guard.authorization_head,
                    proof.graph_incarnation, metadata.graph_revision + 1,
                    graph_receipt.epoch.revision, attempt_id,
                    finish_id, finish_digest,
                )
                db.execute(
                    "INSERT INTO graph_role_init_receipts_v1"
                    "(bot,persona,operation_id,input_digest,permit_json,receipt_json,"
                    "pre_graph_revision,pre_graph_epoch,post_graph_revision,"
                    "post_graph_epoch,finish_request_id,finish_request_digest) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    namespace.as_tuple + (
                        operation_id, input_digest, canonical_json(to_wire(permit)),
                        canonical_json(asdict(receipt)), metadata.graph_revision,
                        epoch.revision, receipt.graph_revision,
                        receipt.graph_epoch, finish_id, finish_digest),
                )
                db.execute("COMMIT")
            except _CreationBudgetChangedNoCommit:
                if db.in_transaction:
                    db.execute("ROLLBACK")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        if budget_denial is not None:
            self._reject_owner_graph_write_v2(
                kind="role_init", namespace=namespace, operation_id=operation_id,
                input_digest=input_digest, attempt_id=attempt_id, metadata=metadata,
                epoch=epoch, anchor=anchor, permit=permit, intent=intent)
            raise budget_denial
        if port.validate_fence(scope) != permit:
            raise UnavailableGuard("committed role write permit changed")
        with store._lock:
            current, current_epoch = self._v2_graph_stamp(namespace)
            if (current.graph_revision != receipt.graph_revision
                    or current_epoch.revision != receipt.graph_epoch):
                raise UnavailableGuard("committed role graph stamp changed")
        port.finish_fence(scope, request_id=finish_id,
                          request_digest=finish_digest)
        return receipt

    def _scene_binding_state_locked(self, namespace, guard, prior=None):
        """Read the complete current D01 head and D03 binding query at one epoch."""
        from .domains.d01 import PersonaDomain, _activation_key
        from .domains.d03 import RoleBinding
        from .graph_types import GraphSnapshot
        from .runtime_contracts import QueryEpoch

        store = self.__store
        db = store._db
        epoch = GraphStore.graph_epoch(
            store, *namespace.as_tuple, _capability=self.__graph_capability)
        activation_key = _activation_key(namespace)
        grant_key = owner_grant_key(*namespace.as_tuple)
        activation_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (activation_key.token,),
        ).fetchone()
        if activation_row is None or activation_row[2] != 1:
            raise UnavailableGuard("active D01 role head is absent")
        activation = json.loads(activation_row[1])
        if type(activation) is not dict or type(activation.get("plan_id")) is not str:
            raise UnavailableGuard("active D01 role head is invalid")
        from .graph_types import AtomKey, Owner
        plan_key = AtomKey(Owner("persona", *namespace.as_tuple),
                           "d01.persona_plan.v1", activation["plan_id"])
        atoms = []
        for key in (activation_key, plan_key, grant_key):
            row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (key.token,),
            ).fetchone()
            if row is None:
                raise UnavailableGuard("active role graph atoms are incomplete")
            atoms.append(GraphAtom(key, row[0], json.loads(row[1]), bool(row[2])))
        try:
            role = PersonaDomain.resolve_active_role(
                GraphSnapshot(tuple(atoms), (epoch,)), namespace=namespace,
                current_guard=guard)
        except (TypeError, ValueError) as exc:
            raise UnavailableGuard("active role differs from Owner guard") from exc
        saved_role = db.execute(
            "SELECT receipt_json FROM graph_role_init_receipts_v1 "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchone()
        if saved_role is None:
            raise UnavailableGuard("D01 role has no durable initialization receipt")
        data = json.loads(saved_role[0])
        if (type(data) is not dict or data.get("head_id") != role.head_id
                or data.get("owner_grant_id") != atoms[2].value["grant_id"]
                or data.get("owner_authorization_head") != guard.authorization_head):
            raise UnavailableGuard("D01 initialization receipt differs from active role")
        rows = db.execute(
            "SELECT token,revision,value FROM graph_atoms "
            "WHERE bot=? AND persona=? AND type_name='d03.role_binding' "
            "AND valid=1 ORDER BY token", namespace.as_tuple,
        ).fetchall()
        versions = []
        bindings = []
        for token, revision, encoded in rows:
            key = AtomKey.from_token(token)
            value = json.loads(encoded)
            try:
                binding = RoleBinding(**{
                    **value, "norm_refs": tuple(value["norm_refs"]),
                    "source_refs": tuple(value["source_refs"]),
                })
            except (TypeError, ValueError, KeyError) as exc:
                raise UnavailableGuard("current D03 binding is invalid") from exc
            if (key.name != binding.role_binding_id
                    or revision != binding.binding_version
                    or (key.owner.kind == "scene"
                        and key.owner.subject != binding.scene_ref)):
                raise UnavailableGuard("current D03 binding identity differs")
            versions.append(GraphVersion(key, revision))
            bindings.append(binding)
        query = QueryEpoch(namespace, "d03.role_binding", epoch.revision)
        if (prior is not None and (prior.query_epoch != query
                or len(prior.read_versions) != len(versions)
                or set(prior.read_versions) != set(versions))):
            raise StaleRead("D03 negative query versions or epoch changed")
        if prior is None:
            return role, tuple(bindings), epoch, tuple(versions)
        return role, tuple(bindings), epoch

    def _check_owner_session_v2(self, *, namespace, principal, actor_id,
                                token, request, target):
        from .authority_service.v2_owner_session import OwnerSessionLoginRequestV1

        port = self.__content_fence_v2
        if (type(actor_id) is not str or not actor_id
                or type(token) is not str or not token
                or type(request) is not OwnerSessionLoginRequestV1
                or request.principal != principal
                or request.authority_id != target.authority_id
                or request.authority_namespace != target.authority_namespace
                or request.installation_id
                != port.installation_grant.installation_id
                or request.audience != "owner"
                or self._current_owner_principal(actor_id, namespace) != principal):
            raise UnavailableGuard("current signed Owner session differs")

    def _read_current_owner_session_v2(self, *, namespace, principal, actor_id,
                                       token, request, capability):
        """Recheck a current signed Owner session under a new read fence."""
        port = self.__content_fence_v2
        store = self.__store
        with store._lock:
            metadata, epoch = self._v2_graph_stamp(namespace)
        target = metadata.requirements
        self._check_owner_session_v2(
            namespace=namespace, principal=principal, actor_id=actor_id,
            token=token, request=request, target=target)
        anchor = port.current_anchor(
            namespace=namespace, authority_namespace=target.authority_namespace)
        if not self._anchor_matches(target, anchor):
            raise UnavailableGuard("scene replay Authority anchor differs")
        attempt_id = "owner-session-read-" + secrets.token_hex(16)
        permit = port.begin_fence(
            namespace=namespace, authority_namespace=target.authority_namespace,
            holder=self.__holder, generation=1, operation="read",
            operation_id=attempt_id, expected_anchor=anchor)
        scope = FenceScope(namespace, target.authority_namespace, 1, "read",
                           attempt_id, permit, anchor, epoch, metadata.graph_revision)
        authority = AuthorityContext(
            actor_id, "d12", "owner-session-read", namespace,
            ("persona",), "workbench_user_action", ("owner",),
            "owner-grant-v1", 1)
        try:
            _, owner = self._owner_binding_in_fence(
                authority, scope, principal, None, (token, request))
            if capability not in owner.capabilities:
                raise AuthorityDenied("Owner grant lacks requested permission")
            if port.validate_fence(scope) != permit:
                raise UnavailableGuard("scene replay read permit changed")
        finally:
            port.finish_fence(
                scope, request_id="finish:" + attempt_id,
                request_digest="sha256:" + canonical_digest({
                    "operation_id": attempt_id, "permit_token": permit.token,
                    "action": "finish_owner_session_read",
                }))

    def replay_committed_scene_binding_v2(
            self, *, namespace: NamespaceId, operation_id: str,
            request_digest: str, principal: OwnerPrincipalV1,
            actor_id: str, owner_session_token: str,
            owner_session_request: OwnerSessionLoginRequestV1):
        """Read a completed Owner scene operation from its original frozen input."""
        from .domains.d03 import RoleBindingRequest, RoleBindingResolution
        from .host.current_scene import CurrentHostScene
        from .runtime_contracts import QueryEpoch

        if type(namespace) is not NamespaceId or type(principal) is not OwnerPrincipalV1:
            raise TypeError("typed scene replay identity is required")
        with self.__store._lock:
            db = self.__store._db
            saved = db.execute(
                "SELECT 1 FROM graph_scene_binding_receipts_v1 WHERE bot=? "
                "AND persona=? AND operation_id=?",
                namespace.as_tuple + (operation_id,),
            ).fetchone()
            if saved is None:
                return None
            proof = db.execute(
                "SELECT request_digest,principal_json,frozen_json "
                "FROM graph_scene_binding_request_proofs_v1 WHERE bot=? "
                "AND persona=? AND operation_id=?",
                namespace.as_tuple + (operation_id,),
            ).fetchone()
        if proof is None:
            raise UnavailableGuard("committed scene lacks original request proof; HOLD")
        if (proof[0] != request_digest
                or proof[1] != canonical_json(asdict(principal))):
            raise AuthorityDenied("scene operation request or principal differs")
        try:
            frozen = json.loads(proof[2])
            scene_data = frozen["scene"]
            scene = CurrentHostScene(
                NamespaceId(**scene_data["namespace"]),
                scene_data["platform_ref"], scene_data["conversation_ref"],
                scene_data["visibility"], scene_data["scene_ref"],
            )
            prior_data = frozen["prior"]
            query = prior_data["query_epoch"]
            versions = tuple(GraphVersion(
                AtomKey(Owner(**item["key"]["owner"]),
                        item["key"]["type_name"], item["key"]["name"]),
                item["revision"],
            ) for item in prior_data["read_versions"])
            prior = RoleBindingResolution(
                prior_data["status"], tuple(prior_data["matched_bindings"]),
                tuple(prior_data["applicable_norm_refs"]),
                tuple(prior_data["missing_items"]), versions,
                QueryEpoch(NamespaceId(**query["namespace"]),
                           query["scope_ref"], query["revision"]),
                prior_data["valid_until"],
                RoleBindingRequest(**prior_data["request"]),
            )
            if (proof[2] != canonical_json(frozen)
                    or frozen["prior_digest"] != canonical_digest(asdict(prior))):
                raise ValueError("frozen prior digest differs")
        except (TypeError, ValueError, KeyError) as exc:
            raise UnavailableGuard("committed scene frozen input is invalid") from exc
        return self.commit_scene_binding_v2(
            namespace=namespace, operation_id=operation_id, scene=scene,
            prior=prior, principal=principal, actor_id=actor_id,
            owner_session_token=owner_session_token,
            owner_session_request=owner_session_request,
            request_digest=request_digest,
        )

    def commit_scene_binding_v2(self, *, namespace: NamespaceId,
                                operation_id: str, scene, prior, principal,
                                actor_id: str, request_digest: str,
                                owner_session_token: str,
                                owner_session_request: OwnerSessionLoginRequestV1):
        """Commit one Owner-configured scene and two D06 provenance sources."""
        from .authority_service.contract import identifier
        from .authority_service.v2_contract import FencePermitV2, from_wire, to_wire
        from .authority_service.v2_owner_contract import (
            OwnerAuthorizationGuardV1, OwnerGraphCommitProofV1, OwnerPrincipalV1,
            canonical_digest as owner_contract_digest,
        )
        from .domains.d03 import ContextProvider, RoleBinding, RoleBindingResolution
        from .host.current_scene import CurrentHostScene
        from .host.authority_profile import AdminIngressClockPolicy
        from .runtime.restore_anchor import RestoreAnchor
        from .runtime_contracts import QueryEpoch
        from .workbench_api.scene_binding_evidence import build_scene_binding_evidence

        if (not isinstance(self.__store, ProductionGraphStore)
                or self.__content_fence_v2 is None):
            raise UnavailableGuard("scene binding requires production v2")
        if (type(namespace) is not NamespaceId or type(scene) is not CurrentHostScene
                or type(prior) is not RoleBindingResolution
                or type(principal) is not OwnerPrincipalV1):
            raise TypeError("scene binding requires typed scene, D03 and Owner inputs")
        identifier(operation_id, "operation_id")
        identifier(actor_id, "actor_id")
        if (type(request_digest) is not str or len(request_digest) != 71
                or not request_digest.startswith("sha256:")
                or any(char not in "0123456789abcdef" for char in request_digest[7:])):
            raise ValueError("full scene binding request digest is required")
        registration = self.__providers.get("d03")
        if registration is None or type(registration[0]) is not ContextProvider:
            raise UnavailableGuard("trusted D03 scene provider is unavailable")
        provider = registration[0]
        if (scene.namespace != namespace or prior.request is None
                or not prior.request.scope_complete
                or prior.status != "no_applicable_binding"
                or prior.matched_bindings or prior.missing_items
                or prior.query_epoch is None
                or prior.request.requested_action_kind != "bind_scene"
                or prior.request.purpose != "workbench_user_action"
                or scene.scene_ref != prior.request.scene_ref):
            raise AuthorityDenied("scene request is not a complete first binding")
        port = self.__content_fence_v2
        guard_reader = getattr(port, "get_current_owner_guard_for_fence", None)
        if not callable(guard_reader):
            raise UnavailableGuard("current Owner guard fence port is unavailable")
        store = self.__store
        with store._lock:
            metadata, epoch = self._v2_graph_stamp(namespace)
            db = store._db
            grant_key = owner_grant_key(*namespace.as_tuple)
            grant_row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (grant_key.token,),
            ).fetchone()
            proof_row = db.execute(
                "SELECT operation_id,request_digest,grant_id,grant_digest,"
                "graph_incarnation,graph_access_epoch,graph_epoch,"
                "graph_receipt_digest,proof_json "
                "FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            access_row = db.execute(
                "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
                "WHERE bot=? AND persona=?", namespace.as_tuple,
            ).fetchone()
            intent = db.execute(
                "SELECT operation_id,input_digest,binding_id,fence_attempt_id,"
                "requirements_json,anchor_json,graph_revision,graph_epoch "
                "FROM graph_scene_binding_intents_v1 WHERE bot=? AND persona=? "
                "AND operation_id=?", namespace.as_tuple + (operation_id,),
            ).fetchone()
            request_proof = db.execute(
                "SELECT request_digest,principal_json,frozen_json,input_digest "
                "FROM graph_scene_binding_request_proofs_v1 WHERE bot=? AND persona=? "
                "AND operation_id=?", namespace.as_tuple + (operation_id,),
            ).fetchone()
            saved = db.execute(
                "SELECT input_digest,permit_json,receipt_json,pre_graph_revision,"
                "pre_graph_epoch,post_graph_revision,post_graph_epoch,"
                "finish_request_id,finish_request_digest "
                "FROM graph_scene_binding_receipts_v1 WHERE bot=? AND persona=? "
                "AND operation_id=?", namespace.as_tuple + (operation_id,),
            ).fetchone()
            rejection = db.execute(
                "SELECT operation_id,status,permit_json,graph_revision,"
                "graph_epoch,finish_request_id,finish_request_digest "
                "FROM graph_scene_binding_rejections_v1 WHERE bot=? AND persona=? "
                "AND operation_id=?", namespace.as_tuple + (operation_id,),
            ).fetchone()
        if (grant_row is None or grant_row[0] != 1 or grant_row[2] != 1
                or proof_row is None or access_row != (1, 0)):
            raise UnavailableGuard("current first Owner grant is unavailable")
        grant = json.loads(grant_row[1])
        validate_owner_grant_v1(grant)
        proof = OwnerGraphCommitProofV1(
            namespace, proof_row[0], proof_row[1], proof_row[2], proof_row[3],
            proof_row[4], 1, proof_row[5], proof_row[6], proof_row[7])
        target = metadata.requirements
        self._check_owner_session_v2(
            namespace=namespace, principal=principal, actor_id=actor_id,
            token=owner_session_token, request=owner_session_request,
            target=target)
        if (proof_row[8] != canonical_json(asdict(proof))
                or grant_row[1] != canonical_json(grant)
                or "sha256:" + canonical_digest(grant) != proof.grant_digest
                or grant["principal"] != asdict(principal)
                or grant["grant_id"] != proof.grant_id
                or grant["graph_incarnation"] != proof.graph_incarnation
                or proof.graph_access_epoch != 1
                or target.namespace != namespace
                or target.graph_incarnation != proof.graph_incarnation
                or target.activation_generation != 1
                or target.authority_id != grant["authority_id"]
                or port.installation_grant.installation_id != grant["installation_id"]):
            raise AuthorityDenied("scene principal or Owner grant differs")
        if ("workbench.bind_scene" not in grant["capabilities"]
                or "workbench_user_action" not in grant["purposes"]
                or "owner" not in grant["audiences"]):
            raise AuthorityDenied("Owner grant lacks scene binding permission")
        if intent is not None and request_proof is None:
            raise UnavailableGuard("legacy scene intent lacks original request proof; HOLD")
        if request_proof is not None:
            if (request_proof[0] != request_digest
                    or request_proof[1] != canonical_json(asdict(principal))):
                raise AuthorityDenied("scene operation request or principal differs")
            try:
                frozen = json.loads(request_proof[2])
                original_scene = CurrentHostScene(**{
                    **frozen["scene"], "namespace": NamespaceId(**frozen["scene"]["namespace"]),
                })
                observed_at = frozen["observed_at"]
                original_actor = frozen["actor_id"]
            except (TypeError, ValueError, KeyError) as exc:
                raise UnavailableGuard("scene frozen request proof is invalid") from exc
            if (request_proof[2] != canonical_json(frozen)
                    or original_actor != actor_id
                    or original_scene.namespace != namespace
                    or original_scene.scene_ref != scene.scene_ref):
                raise AuthorityDenied("scene frozen request identity differs")
            pending_input_changed = (saved is None and (
                original_scene != scene
                or frozen["prior_digest"] != canonical_digest(asdict(prior))))
        else:
            verifier = getattr(self.__scene_identity_port, "verify", None)
            if not callable(verifier) or verifier(namespace, scene.scene_ref,
                                                 scene.visibility) != scene:
                raise UnavailableGuard("current scene identity is unavailable; HOLD")
            if type(self.__scene_clock_policy) is not AdminIngressClockPolicy:
                raise UnavailableGuard("paired scene clock policy is unavailable; HOLD")
            try:
                reading = port.read_ingress_clock(self.__scene_clock_policy)
                observed_at = reading.utc_upper_bound_seconds
            except Exception as exc:
                raise UnavailableGuard("paired scene clock is unavailable; HOLD") from exc
            original_scene = scene
            original_actor = actor_id
            frozen = {
                "scene": asdict(scene), "observed_at": observed_at,
                "actor_id": actor_id, "prior_digest": canonical_digest(asdict(prior)),
                "prior": json.loads(canonical_serialize(asdict(prior))),
                "at_time": prior.request.at_time,
            }
            pending_input_changed = False
        evidence = build_scene_binding_evidence(
            namespace=namespace, scene=original_scene, owner_actor=original_actor,
            operation_id=operation_id, request_digest=request_digest,
            authorization_head=owner_contract_digest(proof),
            observed_at=observed_at,
        )
        source_writes = tuple(
            GraphWrite(key, value) for source in (
                evidence.owner_config, evidence.host_identity)
            for key, value in ((source.source_key, source.source_value),
                               (source.access_key, source.access_value))
        )
        binding = RoleBinding(
            "binding:" + canonical_digest({"operation_id": operation_id,
                                            "scene_ref": original_scene.scene_ref})[:48],
            f"persona:{namespace.persona_id}", "scene_participant", None, None,
            original_scene.scene_ref, "scene", original_scene.visibility, (),
            frozen["at_time"], None, 0,
            (evidence.owner_config.source_key.token,
             evidence.host_identity.source_key.token), 1, "active",
        )
        write_key = AtomKey(Owner("scene", *namespace.as_tuple, binding.scene_ref),
                            "d03.role_binding", binding.role_binding_id)
        value = asdict(binding)
        value["norm_refs"] = list(binding.norm_refs)
        value["source_refs"] = list(binding.source_refs)
        input_digest = "sha256:" + canonical_digest({
            "schema": "sylanne3.graph.scene_binding.v1",
            "namespace": list(namespace.as_tuple), "operation_id": operation_id,
            "request_digest": request_digest, "frozen": frozen,
            "principal": asdict(principal), "owner_proof": asdict(proof),
        })
        if request_proof is not None and request_proof[3] != input_digest:
            raise UnavailableGuard("scene frozen input digest differs")
        attempt_id = "scene-write-" + canonical_digest({
            "namespace": list(namespace.as_tuple), "operation_id": operation_id,
            "input_digest": input_digest,
        })[:48]
        anchor = port.current_anchor(
            namespace=namespace, authority_namespace=target.authority_namespace)
        if not self._anchor_matches(target, anchor):
            raise UnavailableGuard("scene recovery anchor differs")
        identity = (operation_id, input_digest, binding.role_binding_id,
                    attempt_id, canonical_json(asdict(target)),
                    canonical_json(asdict(anchor)))
        if intent is not None and intent[:6] != identity:
            raise AuthorityDenied("scene binding operation replay differs")
        if rejection is not None:
            if intent is None or saved is not None:
                raise UnavailableGuard("rejected scene has a business receipt")
            self._finish_rejected_owner_graph_write_v2(
                kind="scene_binding", namespace=namespace,
                operation_id=operation_id, input_digest=input_digest,
                attempt_id=attempt_id, metadata=metadata, epoch=epoch,
                anchor=anchor, rejection=rejection)
            raise UnavailableGuard("scene binding terminal rejected_no_commit")
        if saved is not None:
            if intent is None:
                raise UnavailableGuard("scene receipt lacks durable intent")
            try:
                payload = json.loads(saved[2])
                if type(payload) is not dict or type(payload.get("namespace")) is not dict:
                    raise ValueError("scene receipt is not canonical")
                payload["namespace"] = NamespaceId(**payload["namespace"])
                receipt = SceneBindingReceiptV1(**payload)
                permit = from_wire(json.loads(saved[1]))
            except (TypeError, ValueError, KeyError) as exc:
                raise UnavailableGuard("durable scene receipt is invalid") from exc
            finish_id = "finish:" + attempt_id
            finish_digest = "sha256:" + canonical_digest({
                "operation_id": attempt_id, "permit_token": permit.token,
                "action": "finish_scene_binding",
                "business_operation_id": operation_id,
                "input_digest": input_digest,
            })
            if (type(permit) is not FencePermitV2
                    or saved[0] != input_digest
                    or saved[2] != canonical_json(asdict(receipt))
                    or saved[3:5] != intent[6:8]
                    or saved[5:7] != (receipt.graph_revision, receipt.graph_epoch)
                    or saved[5] != saved[3] + 1
                    or saved[7:9] != (finish_id, finish_digest)
                    or receipt.namespace != namespace
                    or receipt.operation_id != operation_id
                    or receipt.request_digest != request_digest
                    or receipt.input_digest != input_digest
                    or receipt.scene_ref != binding.scene_ref
                    or receipt.binding_id != binding.role_binding_id
                    or receipt.owner_grant_id != proof.grant_id
                    or receipt.owner_authorization_head != owner_contract_digest(proof)
                    or receipt.graph_incarnation != proof.graph_incarnation
                    or receipt.fence_attempt_id != attempt_id
                    or receipt.finish_request_id != finish_id
                    or receipt.finish_request_digest != finish_digest
                    or permit.operation_id != attempt_id or permit.operation != "write"
                    or permit.holder != self.__holder
                    or permit.subject != port.installation_grant.subject
                    or permit.authority_id != target.authority_id
                    or permit.namespace != target.authority_namespace
                    or permit.generation != 1 or permit.pinned_anchor != anchor):
                raise UnavailableGuard("durable scene receipt differs")
            with store._lock:
                for key, expected_value in (
                        *((item.key, item.value) for item in source_writes),
                        (write_key, value)):
                    atom = store._db.execute(
                        "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                        (key.token,),
                    ).fetchone()
                    if atom != (1, canonical_json(expected_value), 1):
                        raise UnavailableGuard("durable scene source or binding atom differs")
            observed, state = port.get_fence_operation(
                namespace=namespace, authority_namespace=target.authority_namespace,
                operation_id=attempt_id)
            if observed != permit or state not in {"active", "finished"}:
                raise UnavailableGuard("scene Authority fence differs")
            if state == "active":
                if (metadata.graph_revision, epoch.revision) != saved[5:7]:
                    raise UnavailableGuard("active scene fence lost business stamp")
                scope = FenceScope(
                    namespace, target.authority_namespace, 1, "write", attempt_id,
                    permit, anchor, NamespaceEpoch(*namespace.as_tuple, intent[7]),
                    intent[6])
                if port.validate_fence(scope) != permit:
                    raise UnavailableGuard("scene write permit changed")
                port.finish_fence(scope, request_id=finish_id,
                                  request_digest=finish_digest)
            elif (metadata.graph_revision < saved[5]
                  or epoch.revision < saved[6]):
                raise UnavailableGuard("finished scene lost business stamp")
            self._read_current_owner_session_v2(
                namespace=namespace, principal=principal, actor_id=actor_id,
                token=owner_session_token, request=owner_session_request,
                capability="workbench.bind_scene")
            return receipt
        # This command only creates the first binding for a scene. D03's
        # no_applicable_binding can also describe a revoked or out-of-window
        # valid atom; accepting a second one would make the scene unreadable.
        with store._lock:
            if store._db.execute(
                    "SELECT 1 FROM graph_atoms WHERE bot=? AND persona=? "
                    "AND owner_kind='scene' AND subject=? "
                    "AND type_name='d03.role_binding' AND valid=1 LIMIT 1",
                    namespace.as_tuple + (binding.scene_ref,),
            ).fetchone() is not None:
                raise AuthorityDenied("scene already has a valid D03 binding")
        if prior.query_epoch != QueryEpoch(namespace, "d03.role_binding", epoch.revision):
            raise StaleRead("D03 negative query versions or epoch changed")
        if intent is not None and (metadata.graph_revision, epoch.revision) != intent[6:8]:
            raise UnavailableGuard("uncommitted scene graph stamp changed")
        if intent is not None:
            with store._lock:
                if any(store._db.execute(
                    "SELECT 1 FROM graph_atoms WHERE token=?", (key.token,),
                ).fetchone() is not None for key in (
                    *(item.key for item in source_writes), write_key,
                )):
                    raise UnavailableGuard("pending scene has a business atom; HOLD")
        if intent is None:
            with store._lock:
                db = store._db
                db.execute("BEGIN IMMEDIATE")
                try:
                    if self._v2_graph_stamp(namespace) != (metadata, epoch):
                        raise StaleRead("scene graph stamp changed before intent")
                    db.execute(
                        "INSERT INTO graph_scene_binding_intents_v1"
                        "(bot,persona,operation_id,input_digest,binding_id,"
                        "fence_attempt_id,requirements_json,anchor_json,"
                        "graph_revision,graph_epoch) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        namespace.as_tuple + identity + (
                            metadata.graph_revision, epoch.revision),
                    )
                    db.execute(
                        "INSERT INTO graph_scene_binding_request_proofs_v1"
                        "(bot,persona,operation_id,request_digest,principal_json,"
                        "frozen_json,input_digest) VALUES(?,?,?,?,?,?,?)",
                        namespace.as_tuple + (
                            operation_id, request_digest,
                            canonical_json(asdict(principal)),
                            canonical_json(frozen), input_digest),
                    )
                    db.execute("COMMIT")
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise
            intent = identity + (metadata.graph_revision, epoch.revision)
        pinned_anchor = RestoreAnchor(**json.loads(intent[5]))
        if pinned_anchor != anchor:
            raise UnavailableGuard("scene original fence anchor changed")
        permit = port.begin_fence(
            namespace=namespace, authority_namespace=target.authority_namespace,
            holder=self.__holder, generation=1, operation="write",
            operation_id=attempt_id, expected_anchor=pinned_anchor,
            retain_on_unknown=True)
        if (type(permit) is not FencePermitV2 or permit.operation_id != attempt_id
                or permit.operation != "write" or permit.holder != self.__holder
                or permit.subject != port.installation_grant.subject
                or permit.authority_id != target.authority_id
                or permit.namespace != target.authority_namespace
                or permit.generation != 1 or permit.pinned_anchor != anchor):
            raise UnavailableGuard("scene write permit differs")
        scope = FenceScope(namespace, target.authority_namespace, 1, "write",
                           attempt_id, permit, anchor, epoch, metadata.graph_revision)
        try:
            if pending_input_changed:
                raise UnavailableGuard("pending scene proof differs from original")
            verifier = getattr(self.__scene_identity_port, "verify", None)
            if (not callable(verifier)
                    or verifier(namespace, original_scene.scene_ref,
                                original_scene.visibility) != original_scene):
                raise UnavailableGuard("current scene identity changed")
            guarded = guard_reader(
                namespace=namespace, authority_namespace=target.authority_namespace,
                permit=permit, owner_actor_id=actor_id,
                owner_session_token=owner_session_token,
                owner_session_request=owner_session_request)
            if (type(guarded) is not tuple or len(guarded) != 2
                    or type(guarded[0]) is not OwnerAuthorizationGuardV1
                    or guarded[1] != permit):
                raise UnavailableGuard("current scene Owner guard is unavailable")
            guard = guarded[0]
            if (guard.authority_id != target.authority_id
                    or guard.installation_id != grant["installation_id"]
                    or guard.namespace != namespace
                    or guard.authorization_revision != 1
                    or guard.authorization_head != owner_contract_digest(proof)
                    or guard.pending_revoke_operation_id is not None
                    or guard.minimum_revocation_revision != 0
                    or guard.minimum_revocation_epoch != 0):
                raise AuthorityDenied("scene Owner authorization changed")
        except Exception:
            self._reject_owner_graph_write_v2(
                kind="scene_binding", namespace=namespace,
                operation_id=operation_id, input_digest=input_digest,
                attempt_id=attempt_id, metadata=metadata, epoch=epoch,
                anchor=anchor, permit=permit, intent=intent)
            raise
        if port.validate_fence(scope) != permit:
            raise UnavailableGuard("scene write permit changed")
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                if self._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise StaleRead("scene graph stamp changed")
                if db.execute(
                    "SELECT operation_id,input_digest,binding_id,fence_attempt_id,"
                    "requirements_json,anchor_json,graph_revision,graph_epoch "
                    "FROM graph_scene_binding_intents_v1 WHERE bot=? AND persona=? "
                    "AND operation_id=?", namespace.as_tuple + (operation_id,),
                ).fetchone() != intent:
                    raise UnavailableGuard("scene durable intent changed")
                role, bindings, current_epoch = self._scene_binding_state_locked(
                    namespace, guard, prior)
                if current_epoch != epoch:
                    raise StaleRead("scene negative query epoch changed")
                if db.execute(
                        "SELECT 1 FROM graph_atoms WHERE bot=? AND persona=? "
                        "AND owner_kind='scene' AND subject=? "
                        "AND type_name='d03.role_binding' AND valid=1 LIMIT 1",
                        namespace.as_tuple + (binding.scene_ref,),
                ).fetchone() is not None:
                    raise AuthorityDenied("scene already has a valid D03 binding")
                observed_negative = provider.resolve_role_binding(
                    prior.request, bindings)
                if observed_negative.status != "no_applicable_binding":
                    raise AuthorityDenied("scene has an applicable binding")
                write = provider.build_owner_scene_binding_write(
                    binding, role, guard, prior,
                    owner_config_source_key=evidence.owner_config.source_key,
                    host_identity_source_key=evidence.host_identity.source_key,
                )
                if (write.key != write_key or write.value != value
                        or write.key.type_name != "d03.role_binding"):
                    raise AuthorityDenied("D03 Owner binding write differs")
                expected_versions = (
                    set(role.read_versions) | set(prior.read_versions)
                    | {GraphVersion(write.key, 0)}
                    | {GraphVersion(item.key, 0) for item in source_writes}
                )
                if prior.query_epoch != QueryEpoch(
                        namespace, "d03.role_binding", epoch.revision):
                    raise StaleRead("D03 negative query changed")
                candidate = GraphCandidate(
                    Event(Scope(*namespace.as_tuple, "d03-scene-binding"),
                          operation_id, 0, "scene_binding", {
                              "request_digest": request_digest,
                              "input_digest": input_digest,
                              "role_head_id": role.head_id,
                          }),
                    tuple(sorted(expected_versions, key=lambda item: item.key.token)),
                    source_writes + (write,),
                    (epoch,),
                )
                graph_receipt = GraphStore._graph_commit_in_transaction(
                    store, candidate, _capability=self.__graph_capability)
                if (graph_receipt.status != "committed"
                        or set(graph_receipt.revisions) != {
                            GraphVersion(item.key, 1) for item in source_writes + (write,)
                        }
                        or graph_receipt.epoch.revision != epoch.revision + 1):
                    raise UnavailableGuard("D03 scene binding graph commit differed")
                store.cas_graph_recovery_metadata(
                    metadata, target, _capability=self.__graph_capability)
                finish_id = "finish:" + attempt_id
                finish_digest = "sha256:" + canonical_digest({
                    "operation_id": attempt_id, "permit_token": permit.token,
                    "action": "finish_scene_binding",
                    "business_operation_id": operation_id,
                    "input_digest": input_digest,
                })
                receipt = SceneBindingReceiptV1(
                    namespace, operation_id, request_digest, input_digest,
                    binding.scene_ref, binding.role_binding_id, role.head_id,
                    proof.grant_id, guard.authorization_head,
                    proof.graph_incarnation, metadata.graph_revision + 1,
                    graph_receipt.epoch.revision, attempt_id,
                    finish_id, finish_digest,
                )
                db.execute(
                    "INSERT INTO graph_scene_binding_receipts_v1"
                    "(bot,persona,operation_id,input_digest,permit_json,receipt_json,"
                    "pre_graph_revision,pre_graph_epoch,post_graph_revision,"
                    "post_graph_epoch,finish_request_id,finish_request_digest) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    namespace.as_tuple + (
                        operation_id, input_digest, canonical_json(to_wire(permit)),
                        canonical_json(asdict(receipt)), metadata.graph_revision,
                        epoch.revision, receipt.graph_revision,
                        receipt.graph_epoch, finish_id, finish_digest),
                )
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        if port.validate_fence(scope) != permit:
            raise UnavailableGuard("committed scene write permit changed")
        with store._lock:
            current, current_epoch = self._v2_graph_stamp(namespace)
            if (current.graph_revision != receipt.graph_revision
                    or current_epoch.revision != receipt.graph_epoch):
                raise UnavailableGuard("committed scene graph stamp changed")
        port.finish_fence(scope, request_id=finish_id,
                          request_digest=finish_digest)
        return receipt

    def read_active_role_v2(self, *, namespace: NamespaceId):
        """Read the current D01 head under one paired Authority read fence."""
        return self._read_active_scene_v2(namespace, None)[0]

    def read_first_scene_binding_proof_v2(
        self, *, namespace: NamespaceId, scene_ref: str, purpose: str,
        principal, actor_id: str, owner_session_token: str | None = None,
        owner_session_request: OwnerSessionLoginRequestV1 | None = None,
    ):
        """Prove a complete first-binding absence with current Owner and D01 heads."""
        from .authority_service.contract import identifier
        from .authority_service.v2_owner_contract import (
            OwnerAuthorizationGuardV1, OwnerPrincipalV1,
        )
        from .authority_service.v2_owner_session import OwnerSessionLoginRequestV1
        from .domains.d03 import (
            ContextProvider, RoleBindingRequest, RoleBindingResolution,
        )
        from .runtime_contracts import QueryEpoch
        from .workbench_api.d03_onboarding import (
            CurrentFirstBindingProof, CurrentGraphGuardMetadata,
        )

        if (not isinstance(self.__store, ProductionGraphStore)
                or self.__content_fence_v2 is None or type(namespace) is not NamespaceId
                or type(principal) is not OwnerPrincipalV1):
            raise UnavailableGuard("first scene proof requires production v2 Owner")
        identifier(scene_ref, "scene_ref")
        identifier(purpose, "purpose")
        identifier(actor_id, "actor_id")
        if not scene_ref.startswith("scene:"):
            raise ValueError("scene_ref must be a scene identity")
        if self._current_owner_principal(actor_id, namespace) != principal:
            raise UnavailableGuard("current Owner pairing differs")
        signed_session = (owner_session_token is not None
                          or owner_session_request is not None)
        if signed_session and (type(owner_session_token) is not str
                               or not owner_session_token
                               or type(owner_session_request)
                               is not OwnerSessionLoginRequestV1):
            raise UnavailableGuard("Owner session token and request must be paired")
        port = self.__content_fence_v2
        guard_reader = getattr(port, "get_current_owner_guard_for_fence", None)
        if not callable(guard_reader):
            raise UnavailableGuard("current Owner guard fence port is unavailable")
        store = self.__store
        with store._lock:
            metadata, epoch = self._v2_graph_stamp(namespace)
        target = metadata.requirements
        if target.namespace != namespace or target.activation_generation != 1:
            raise UnavailableGuard("first scene recovery identity differs")
        anchor = port.current_anchor(
            namespace=namespace, authority_namespace=target.authority_namespace)
        if not self._anchor_matches(target, anchor):
            raise UnavailableGuard("first scene recovery anchor differs")
        session_kwargs = {}
        if signed_session:
            if (owner_session_request.authority_id != anchor.authority_id
                    or owner_session_request.authority_namespace
                    != target.authority_namespace
                    or owner_session_request.installation_id
                    != port.installation_grant.installation_id
                    or owner_session_request.principal != principal
                    or owner_session_request.audience != "owner"):
                raise UnavailableGuard("first scene Owner session identity differs")
            session_kwargs = {
                "owner_actor_id": actor_id,
                "owner_session_token": owner_session_token,
                "owner_session_request": owner_session_request,
            }
        attempt_id = "scene-negative-read-" + secrets.token_hex(16)
        permit = port.begin_fence(
            namespace=namespace, authority_namespace=target.authority_namespace,
            holder=self.__holder, generation=1, operation="read",
            operation_id=attempt_id, expected_anchor=anchor)
        scope = FenceScope(namespace, target.authority_namespace, 1, "read",
                           attempt_id, permit, anchor, epoch, metadata.graph_revision)
        authority = AuthorityContext(
            actor_id, "d12", "first-scene-read", namespace,
            ("persona", "scene"), purpose, ("owner",), "owner-grant-v1", 1)

        def current_guard():
            guarded = guard_reader(
                namespace=namespace,
                authority_namespace=target.authority_namespace,
                permit=permit, **session_kwargs)
            if (type(guarded) is not tuple or len(guarded) != 2
                    or type(guarded[0]) is not OwnerAuthorizationGuardV1
                    or guarded[1] != permit):
                raise UnavailableGuard("current Owner guard is unavailable")
            return guarded[0]

        def check_owner(guard):
            with store._lock:
                if self._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise StaleRead("first scene graph stamp changed")
                binding = self._owner_graph_binding_locked(authority, principal)
            if (guard.authority_id != anchor.authority_id
                    or guard.installation_id
                    != port.installation_grant.installation_id
                    or guard.namespace != namespace
                    or guard.authorization_revision != binding.authorization_revision
                    or guard.authorization_head != binding.authorization_head
                    or guard.minimum_revocation_revision != 0
                    or guard.minimum_revocation_epoch != binding.revocation_epoch
                    or guard.pending_revoke_operation_id is not None):
                raise UnavailableGuard("first scene Owner head changed")
            return binding

        def current_graph_guard_locked():
            db = store._db
            epochs = db.execute(
                "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
                "WHERE bot=? AND persona=?", namespace.as_tuple,
            ).fetchone()
            if epochs is None:
                raise UnavailableGuard("first scene graph authority epochs are unavailable")
            return CurrentGraphGuardMetadata(
                namespace, epoch.revision, epochs[0], epochs[1],
                store._registry.catalogue_hash,
                self._version(db, namespace, "scheme", "current"),
                self._version(db, namespace, "operator", "current"),
                self._version(db, namespace, "policy", "current"),
            )

        try:
            guard = current_guard()
            if port.validate_fence(scope) != permit:
                raise UnavailableGuard("first scene read permit changed")
            owner = check_owner(guard)
            with store._lock:
                if self._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise StaleRead("first scene graph stamp changed")
                role, bindings, current_epoch, versions = (
                    self._scene_binding_state_locked(namespace, guard))
                if current_epoch != epoch:
                    raise StaleRead("first scene query epoch changed")
                # First binding means no valid binding atom for this scene,
                # including one that is currently out of its effective window.
                if any(item.scene_ref == scene_ref for item in bindings):
                    raise AuthorityDenied("scene already has a valid D03 binding")
                request = RoleBindingRequest(
                    f"persona:{namespace.persona_id}", None, None, scene_ref,
                    "bind_scene", purpose, time.time(), True)
                result = ContextProvider().resolve_role_binding(
                    request, bindings)
                if result.status != "no_applicable_binding":
                    raise UnavailableGuard("first scene D03 query is incomplete")
                prior = RoleBindingResolution(
                    result.status, result.matched_bindings,
                    result.applicable_norm_refs, result.missing_items,
                    versions, QueryEpoch(namespace, "d03.role_binding", epoch.revision),
                    result.valid_until, request)
                graph_guard = current_graph_guard_locked()
            if port.validate_fence(scope) != permit:
                raise UnavailableGuard("first scene read permit changed")
            if (self._current_owner_principal(actor_id, namespace) != principal
                    or current_guard() != guard or check_owner(guard) != owner):
                raise UnavailableGuard("first scene Owner head changed")
            with store._lock:
                if self._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise StaleRead("first scene graph stamp changed after read")
                if current_graph_guard_locked() != graph_guard:
                    raise StaleRead("first scene graph guard changed after read")
            return CurrentFirstBindingProof(role, prior, guard, graph_guard)
        finally:
            port.finish_fence(
                scope, request_id="finish:" + attempt_id,
                request_digest="sha256:" + canonical_digest({
                    "operation_id": attempt_id, "permit_token": permit.token,
                    "action": "finish_first_scene_read",
                }))

    def read_active_scene_v2(self, *, namespace: NamespaceId, scene_ref: str):
        """Read current D01 head and one scene binding at the same graph epoch."""
        from .authority_service.contract import identifier
        identifier(scene_ref, "scene_ref")
        if not scene_ref.startswith("scene:"):
            raise ValueError("scene_ref must be a scene identity")
        return self._read_active_scene_v2(namespace, scene_ref)

    def _read_active_scene_v2(self, namespace: NamespaceId,
                              scene_ref: str | None):
        from .authority_service.v2_owner_contract import (
            OwnerAuthorizationGuardV1, OwnerGraphCommitProofV1,
            canonical_digest as owner_contract_digest,
        )
        from .domains.d01 import PersonaDomain, _activation_key
        from .domains.d03 import RoleBinding
        from .graph_types import AtomKey, GraphSnapshot, Owner

        if (not isinstance(self.__store, ProductionGraphStore)
                or self.__content_fence_v2 is None or type(namespace) is not NamespaceId):
            raise UnavailableGuard("active role requires a production v2 namespace")
        port = self.__content_fence_v2
        guard_reader = getattr(port, "get_current_owner_guard_for_fence", None)
        if not callable(guard_reader):
            raise UnavailableGuard("current Owner guard fence port is unavailable")
        store = self.__store
        with store._lock:
            metadata, epoch = self._v2_graph_stamp(namespace)
        target = metadata.requirements
        if target.namespace != namespace or target.activation_generation != 1:
            raise UnavailableGuard("active role recovery identity differs")
        anchor = port.current_anchor(
            namespace=namespace, authority_namespace=target.authority_namespace)
        if not self._anchor_matches(target, anchor):
            raise UnavailableGuard("active role recovery anchor differs")
        attempt_id = "role-read-" + secrets.token_hex(16)
        permit = port.begin_fence(
            namespace=namespace, authority_namespace=target.authority_namespace,
            holder=self.__holder, generation=1, operation="read",
            operation_id=attempt_id, expected_anchor=anchor)
        scope = FenceScope(namespace, target.authority_namespace, 1, "read",
                           attempt_id, permit, anchor, epoch, metadata.graph_revision)
        try:
            guarded = guard_reader(
                namespace=namespace,
                authority_namespace=target.authority_namespace,
                permit=permit)
            if (type(guarded) is not tuple or len(guarded) != 2
                    or type(guarded[0]) is not OwnerAuthorizationGuardV1
                    or guarded[1] != permit):
                raise UnavailableGuard("current Owner guard is unavailable")
            guard = guarded[0]
            if port.validate_fence(scope) != permit:
                raise UnavailableGuard("active role read permit changed")
            with store._lock:
                if self._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise StaleRead("active role graph stamp changed")
                db = store._db
                proof_row = db.execute(
                    "SELECT operation_id,request_digest,grant_id,grant_digest,"
                    "graph_incarnation,graph_access_epoch,graph_epoch,"
                    "graph_receipt_digest,proof_json "
                    "FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?",
                    namespace.as_tuple,
                ).fetchone()
                if proof_row is None:
                    raise UnavailableGuard("first Owner graph proof is absent")
                proof = OwnerGraphCommitProofV1(
                    namespace, proof_row[0], proof_row[1], proof_row[2],
                    proof_row[3], proof_row[4], 1, proof_row[5],
                    proof_row[6], proof_row[7])
                if (proof_row[8] != canonical_json(asdict(proof))
                        or guard.authorization_head != owner_contract_digest(proof)
                        or guard.authorization_revision != 1
                        or guard.pending_revoke_operation_id is not None
                        or guard.minimum_revocation_revision != 0
                        or guard.minimum_revocation_epoch != 0):
                    raise UnavailableGuard("current Owner authorization differs")
                activation_key = _activation_key(namespace)
                activation_row = db.execute(
                    "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                    (activation_key.token,),
                ).fetchone()
                if activation_row is None or activation_row[2] != 1:
                    raise UnavailableGuard("active role head is absent")
                activation = json.loads(activation_row[1])
                plan_key = AtomKey(
                    Owner("persona", *namespace.as_tuple),
                    "d01.persona_plan.v1", activation["plan_id"])
                keys = (activation_key, plan_key,
                        owner_grant_key(*namespace.as_tuple))
                atoms = []
                for key in keys:
                    row = db.execute(
                        "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                        (key.token,),
                    ).fetchone()
                    if row is None:
                        raise UnavailableGuard("active role graph atoms are incomplete")
                    atoms.append(GraphAtom(
                        key, row[0], json.loads(row[1]), bool(row[2])))
                try:
                    role = PersonaDomain.resolve_active_role(
                        GraphSnapshot(tuple(atoms), (epoch,)), namespace=namespace,
                        current_guard=guard)
                except (TypeError, ValueError) as exc:
                    raise UnavailableGuard("active role qualification failed") from exc
                role_row = db.execute(
                    "SELECT receipt_json FROM graph_role_init_receipts_v1 "
                    "WHERE bot=? AND persona=?", namespace.as_tuple,
                ).fetchone()
                if role_row is None:
                    raise UnavailableGuard("active role lacks initialization receipt")
                role_receipt = json.loads(role_row[0])
                if (role_receipt.get("head_id") != role.head_id
                        or role_receipt.get("owner_grant_id")
                        != atoms[2].value["grant_id"]
                        or role_receipt.get("owner_authorization_head")
                        != guard.authorization_head):
                    raise UnavailableGuard("active role receipt differs")
                binding = None
                if scene_ref is not None:
                    rows = db.execute(
                        "SELECT token,revision,value FROM graph_atoms WHERE bot=? "
                        "AND persona=? AND owner_kind='scene' AND subject=? "
                        "AND type_name='d03.role_binding' AND valid=1",
                        namespace.as_tuple + (scene_ref,),
                    ).fetchall()
                    if len(rows) != 1:
                        raise UnavailableGuard("current scene binding is unavailable")
                    key = AtomKey.from_token(rows[0][0])
                    value = json.loads(rows[0][2])
                    binding = RoleBinding(**{
                        **value, "norm_refs": tuple(value["norm_refs"]),
                        "source_refs": tuple(value["source_refs"]),
                    })
                    if (rows[0][1] != binding.binding_version
                            or key.name != binding.role_binding_id
                            or binding.scene_ref != scene_ref
                            or binding.subject_persona_ref
                            != f"persona:{namespace.persona_id}"
                            or binding.status != "active"):
                        raise UnavailableGuard("current scene binding differs")
                    scene_row = db.execute(
                        "SELECT r.receipt_json FROM graph_history AS h "
                        "JOIN graph_scene_binding_receipts_v1 AS r "
                        "ON r.bot=h.event_bot AND r.persona=h.event_persona "
                        "AND r.operation_id=h.event_id "
                        "WHERE h.token=? AND h.revision=? "
                        "AND h.event_session='d03-scene-binding'",
                        (key.token, rows[0][1]),
                    ).fetchone()
                    if scene_row is None:
                        raise UnavailableGuard("scene binding lacks fenced receipt")
                    scene_receipt = json.loads(scene_row[0])
                    if (scene_receipt.get("scene_ref") != scene_ref
                            or scene_receipt.get("binding_id") != binding.role_binding_id
                            or scene_receipt.get("role_head_id") != role.head_id):
                        raise UnavailableGuard("scene binding receipt differs")
            if port.validate_fence(scope) != permit:
                raise UnavailableGuard("active role read permit changed")
            with store._lock:
                if self._v2_graph_stamp(namespace) != (metadata, epoch):
                    raise StaleRead("active role graph stamp changed after read")
            return role, binding
        finally:
            port.finish_fence(
                scope, request_id="finish:" + attempt_id,
                request_digest="sha256:" + canonical_digest({
                    "operation_id": attempt_id, "permit_token": permit.token,
                    "action": "finish_active_role_read",
                }))

    def provision_namespace_v2(self, bootstrap: object, policy, *,
                               operation_id: str) -> NamespaceProvisionReceiptV2:
        """Install one administrator-owned namespace under a v2 write fence.

        The DTO is a value contract, not administrator authentication. The host
        must load it through its protected installation profile before passing
        this coordinator's opaque bootstrap capability.
        """
        from .installation_policy import AdminInstallationPolicy
        from .runtime.issuers import (
            BudgetLeaseGrant, D11BudgetGrantIssuer, D11BudgetJobIssuer,
            install_schema as install_issuer_schema,
        )
        from .runtime_contracts import (
            InstallationGrantV2, NamespaceBootstrapV2, NamespaceRuntimeState,
            SnapshotRequirementsV2,
        )
        from .authority_service.v2_contract import to_wire

        self._admin(bootstrap)
        store = self.__store
        port = self.__content_fence_v2
        if (not isinstance(store, ProductionGraphStore) or port is None
                or not callable(getattr(port, "provision_namespace", None))
                or type(self.__d11_issuer) not in (D11BudgetGrantIssuer, D11BudgetJobIssuer)):
            raise UnavailableGuard("production v2 provisioning authorities are unavailable")
        if type(policy) is not AdminInstallationPolicy:
            raise TypeError("verified administrator installation policy is required")
        if (type(operation_id) is not str or not operation_id
                or len(operation_id) > 128):
            raise ValueError("invalid namespace provisioning operation ID")
        grant = getattr(port, "installation_grant", None)
        namespace = policy.namespace
        if (type(grant) is not InstallationGrantV2
                or grant.authority_id != policy.expected_authority_id
                or grant.administrator_holder != policy.administrator_holder
                or grant.installation_id != policy.installation_id
                or grant.manifest_digest != policy.manifest_digest
                or self.__holder != policy.administrator_holder
                or policy.catalogue_hash != store._registry.catalogue_hash
                or policy.root_lease.parent_id is not None
                or (policy.root_lease.bot_id, policy.root_lease.persona_id) != namespace.as_tuple
                or (policy.root_grant.bot_id, policy.root_grant.persona_id) != namespace.as_tuple
                or policy.root_grant.lease_id != policy.root_lease.lease_id):
            raise AuthorityDenied("administrator installation policy differs from paired authority")
        digest = canonical_digest(policy.digest_payload())
        # The installation DTO freezes its budget maps. D11's durable JSON
        # primitives take their own normalized, mutable value copies.
        source_lease = policy.root_lease
        root_lease = BudgetLease(
            source_lease.lease_id, source_lease.parent_id,
            source_lease.bot_id, source_lease.persona_id,
            source_lease.currency, dict(source_lease.limits),
            dict(source_lease.used), dict(source_lease.reserved),
            dict(source_lease.unconfirmed), source_lease.version,
            source_lease.state,
        )
        source_grant = policy.root_grant
        root_grant = BudgetLeaseGrant(
            source_grant.grant_id, source_grant.version,
            source_grant.bot_id, source_grant.persona_id,
            source_grant.lease_id, source_grant.currency,
            dict(source_grant.max_ceiling),
            tuple(source_grant.allowed_work_kinds),
            source_grant.valid_until_utc, source_grant.policy_ref,
        )
        with store._lock:
            row = self._provision_row(store._db, namespace)
        if row is not None:
            if row[:2] != (operation_id, digest):
                raise AuthorityDenied("namespace provisioning identity differs")
            return self._reconcile_provision_v2(policy, operation_id, digest)
        intent, identity_json = self._ensure_provision_intent(
            policy, grant, operation_id, digest)

        if intent.anchor_json is None:
            observed = port.provision_namespace(
                namespace=namespace, request_id=intent.genesis_request_id)
            if (type(observed) is not NamespaceBootstrapV2
                    or observed.namespace != namespace
                    or observed.authority_id != policy.expected_authority_id
                    or observed.authority_namespace != policy.authority_namespace
                    or observed.holder != self.__holder
                    or observed.state is not NamespaceRuntimeState.ACTIVE
                    or observed.phase != "active" or observed.generation != 1
                    or observed.anchor is None or observed.blocking_reasons):
                raise UnavailableGuard("Authority v2 namespace genesis is not active")
            anchor = observed.anchor
            current_anchor = port.current_anchor(
                namespace=namespace, authority_namespace=policy.authority_namespace)
            if current_anchor != anchor:
                raise UnavailableGuard("Authority v2 current anchor differs from genesis")
            intent = self._persist_provision_anchor(intent, anchor, identity_json)
        else:
            from .runtime.restore_anchor import RestoreAnchor
            try:
                data = json.loads(intent.anchor_json)
                if (type(data) is not dict
                        or set(data) != {field.name for field in fields(RestoreAnchor)}):
                    raise ValueError("invalid anchor fields")
                anchor = RestoreAnchor(**data)
            except (TypeError, ValueError) as exc:
                raise UnavailableGuard("durable v2 provisioning anchor is invalid") from exc
        current_anchor = port.current_anchor(
            namespace=namespace, authority_namespace=policy.authority_namespace)
        if (anchor != current_anchor or anchor.authority_id != policy.expected_authority_id
                or anchor.namespace != policy.authority_namespace
                or anchor.activation_generation != 1 or anchor.deletion_seq != 0
                or anchor.execution_seq != 0 or anchor.revocation_epoch != 0):
            raise UnavailableGuard("Authority v2 current anchor differs from genesis")
        with store._lock:
            epoch = GraphStore.graph_epoch(
                store, *namespace.as_tuple, _capability=self.__graph_capability)
            if epoch.revision != 0:
                raise UnavailableGuard("namespace graph has a prior epoch")
        attempt_id = intent.fence_attempt_id
        try:
            permit = port.begin_fence(
                namespace=namespace, authority_namespace=policy.authority_namespace,
                holder=self.__holder, generation=1, operation="write",
                operation_id=attempt_id, expected_anchor=anchor,
                retain_on_unknown=True)
        except Exception as exc:
            raise UnavailableGuard(
                "v2 provisioning write fence unavailable; HOLD pending exact attempt") from exc
        scope = FenceScope(namespace, policy.authority_namespace, 1, "write",
                           attempt_id, permit, anchor, epoch, 0)
        finish_id = "finish:" + attempt_id
        finish_digest = "sha256:" + canonical_digest({
            "operation_id": attempt_id, "permit_token": permit.token,
            "action": "finish_namespace_provision",
            "business_operation_id": operation_id, "input_digest": digest,
        })
        if port.validate_fence(scope) != permit:
            raise UnavailableGuard("v2 provisioning write permit changed")
        requirements = SnapshotRequirementsV2(
            namespace, anchor.authority_id, anchor.namespace,
            anchor.activation_generation, anchor.deletion_journal_id,
            anchor.deletion_seq, anchor.deletion_digest,
            anchor.execution_journal_id, anchor.execution_seq,
            anchor.execution_digest, anchor.revocation_epoch,
            intent.graph_incarnation,
        )
        with store._lock:
            store._ensure_open()
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                current_intent = self._provision_intent_row(db, namespace)
                self._check_provision_intent(
                    current_intent, operation_id, digest, identity_json)
                if current_intent != intent or self._provision_row(db, namespace) is not None:
                    raise UnavailableGuard("namespace provisioned concurrently; retry reconciliation")
                if GraphStore.graph_epoch(
                        store, *namespace.as_tuple,
                        _capability=self.__graph_capability) != epoch:
                    raise UnavailableGuard("namespace graph epoch changed")
                store._install_graph_recovery_genesis_locked(
                    requirements, _capability=self.__graph_capability,
                    provision_intent=(operation_id, digest))
                for kind, version in (("scheme", policy.scheme_version),
                                      ("operator", policy.operator_version),
                                      ("policy", policy.policy_version),
                                      ("activation", "1")):
                    db.execute(
                        "INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) "
                        "VALUES(?,?,?,?,?)",
                        namespace.as_tuple + (kind, "current", str(version)),
                    )
                create_budget_lease(
                    db, root_lease,
                    "root-budget-" + canonical_digest({
                        "namespace": list(namespace.as_tuple),
                        "operation_id": operation_id,
                    })[:48], digest)
                install_issuer_schema(db)
                grant_signature = self.__d11_issuer.issue_budget_grant(
                    db, root_grant)
                receipt = NamespaceProvisionReceiptV2(
                    namespace, operation_id, digest, policy.installation_id,
                    policy.manifest_digest, anchor.authority_id,
                    anchor.namespace, 1, requirements.graph_incarnation,
                    0, epoch.revision, policy.catalogue_hash,
                    str(policy.scheme_version), str(policy.operator_version),
                    str(policy.policy_version), policy.root_lease.lease_id,
                    policy.root_grant.grant_id, policy.root_grant.version,
                    grant_signature, attempt_id, finish_id, finish_digest,
                    to_wire(permit),
                )
                db.execute(
                    "INSERT INTO graph_namespace_provisioning_v2"
                    "(bot,persona,operation_id,digest,receipt_json) VALUES(?,?,?,?,?)",
                    namespace.as_tuple + (operation_id, digest,
                                          canonical_json(asdict(receipt))),
                )
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        if port.validate_fence(scope) != permit:
            raise UnavailableGuard("v2 provisioning write permit changed after commit")
        with store._lock:
            if self._verify_provision_receipt(policy, operation_id, digest)[0] != receipt:
                raise UnavailableGuard("v2 provisioning state changed after commit")
        port.finish_fence(scope, request_id=finish_id,
                          request_digest=finish_digest)
        return receipt

    def _admit_content(self, namespace: NamespaceId, generation: int,
                       operation: str, refs: tuple[str, ...] = ()) -> None:
        """Called while the authority fence and business lock are held."""
        if not isinstance(self.__store, ProductionGraphStore):
            return
        if self.__deletion_journal is None:
            raise UnavailableGuard("independent deletion journal unavailable")
        identity = namespace_ref(namespace)
        try:
            self.__migration_authority.check(
                namespace=identity, holder=self.__holder,
                generation=generation, operation=operation)
            snapshot = self.__snapshot_requirements(namespace)
            if not isinstance(snapshot, SnapshotRequirements) or snapshot.namespace != identity:
                raise UnavailableGuard("business restore requirements unavailable")
            if snapshot.activation_generation != generation:
                raise UnavailableGuard("business snapshot activation generation is stale")
            anchor = validate_restore(
                snapshot=snapshot, authority=self.__restore_authority,
                deletion_journal=self.__deletion_journal,
                execution_journal_port=self.__execution_journal_port,
                active_generation=generation,
            )
            if (anchor.deletion_seq != snapshot.deletion_seq
                    or anchor.execution_seq != snapshot.execution_seq
                    or anchor.revocation_epoch != snapshot.revocation_epoch):
                raise UnavailableGuard("independent constraints require recovery merge")
            self.__deletion_journal.assert_access(
                identity, content_refs=refs or None,
                closure_verifier=self.__closure_verifier)
        except UnavailableGuard:
            raise
        except Exception as exc:
            raise UnavailableGuard("current content authority is unavailable") from exc

    def register_provider(self, bootstrap: object, domain: str, provider: object,
                          proposal_schema: str, proposal_schema_hash: str) -> None:
        self._admin(bootstrap)
        if not domain or domain in self.__providers:
            raise ValueError("domain must be nonempty and registered once")
        if not callable(getattr(provider, "validate", None)):
            raise TypeError("provider requires validate")
        if (type(proposal_schema_hash) is not str or len(proposal_schema_hash) != 64
                or any(ch not in "0123456789abcdef" for ch in proposal_schema_hash)):
            raise ValueError("proposal schema hash must be SHA-256")
        self.__providers[domain] = (provider, proposal_schema, proposal_schema_hash)

    def grant(self, bootstrap: object, *, actor: str, issuer_domain: str,
              namespace: NamespaceId, domains: tuple[str, ...],
              activation_generation: int,
              operation_id: str | None = None) -> tuple[object, str]:
        self._admin(bootstrap)
        if (issuer_domain == "d12"
                and isinstance(self.__store, ProductionGraphStore)):
            raise UnavailableGuard("D12 requires a current Owner graph lease")
        return self._grant_registered(
            actor=actor, issuer_domain=issuer_domain, namespace=namespace,
            domains=domains, activation_generation=activation_generation,
            operation_id=operation_id)

    def _grant_registered(self, *, actor: str, issuer_domain: str,
                          namespace: NamespaceId, domains: tuple[str, ...],
                          activation_generation: int,
                          operation_id: str | None = None) -> tuple[object, str]:
        if not actor or not issuer_domain or not isinstance(namespace, NamespaceId):
            raise ValueError("invalid authority grant")
        domain_set = frozenset(domains)
        if not domain_set or any(domain not in self.__providers for domain in domain_set):
            raise AuthorityDenied("unregistered domain in authority grant")
        if type(activation_generation) is not int or activation_generation < 0:
            raise ValueError("invalid activation generation")
        if operation_id is not None and (not isinstance(operation_id, str)
                                      or not operation_id or len(operation_id) > 128):
            raise ValueError("invalid scoped operation identity")
        lease = _AuthorityLease(object())
        ref = (secrets.token_hex(24) if operation_id is None else
               _operation_capability_ref(namespace, actor, issuer_domain,
                                         domain_set, activation_generation,
                                         operation_id))
        owners = frozenset(kind for spec in self.__store._registry.specs
                           if spec.writer_domain in domain_set
                           for kind in spec.owner_kinds)
        self.__leases[lease] = (ref, actor, issuer_domain, namespace, domain_set,
                                owners, activation_generation)
        return lease, ref

    def grant_current_owner(self, bootstrap: object, *, actor: str,
                            namespace: NamespaceId, domains: tuple[str, ...],
                            purpose: str, audience: str,
                            activation_generation: int,
                            owner_session_token: str | None = None,
                            owner_session_request: object | None = None,
                            ) -> tuple[AuthorityContext, object, OwnerLeaseBindingV1]:
        """Mint a D12 read lease only from a trusted paired principal and live heads."""
        self._admin(bootstrap)
        if (not isinstance(self.__store, ProductionGraphStore)
                or self.__content_fence_v2 is None
                or self.__owner_principal_resolver is None):
            raise UnavailableGuard("current Owner principal resolver is unavailable")
        if not purpose or not audience:
            raise ValueError("Owner read requires purpose and audience")
        proof = self._owner_session_proof(
            actor, owner_session_token, owner_session_request)
        principal = self._current_owner_principal(actor, namespace)
        lease, ref = self._grant_registered(
            actor=actor, issuer_domain="d12", namespace=namespace,
            domains=domains, activation_generation=activation_generation)
        owner_scope = tuple(sorted(self.__leases[lease][5]))
        authority = AuthorityContext(
            actor, "d12", ref, namespace, owner_scope, purpose,
            (audience,), "owner-grant-v1", activation_generation)
        try:
            binding = self._read_v2(
                authority,
                lambda: self._owner_graph_binding_locked(authority, principal),
                owner_principal=principal, owner_session_proof=proof)
        except BaseException:
            del self.__leases[lease]
            raise
        self.__owner_leases[lease] = binding
        if proof is not None:
            self.__owner_session_proofs[lease] = proof
        return authority, lease, binding

    def release_current_owner_lease(self, bootstrap: object, lease: object) -> None:
        """End one D12 read lease after its worker command completes."""
        self._admin(bootstrap)
        if lease not in self.__owner_leases:
            raise AuthorityDenied("current Owner lease required")
        del self.__owner_leases[lease]
        self.__owner_session_proofs.pop(lease, None)
        del self.__leases[lease]

    def read_current_owner_view(self, bootstrap: object, *, actor: str,
                                namespace: NamespaceId, purpose: str,
                                audience: str,
                                expected_principal: OwnerPrincipalV1,
                                owner_session_token: str | None = None,
                                owner_session_request: object | None = None,
                                ) -> CurrentOwnerViewV1:
        """Project current Owner heads without minting a process lease."""
        self._admin(bootstrap)
        if (not isinstance(self.__store, ProductionGraphStore)
                or self.__content_fence_v2 is None
                or self.__owner_principal_resolver is None):
            raise UnavailableGuard("current Owner read authority is unavailable")
        if type(expected_principal) is not OwnerPrincipalV1:
            raise UnavailableGuard("expected Owner principal is unavailable")
        if not isinstance(namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        proof = self._owner_session_proof(
            actor, owner_session_token, owner_session_request)
        with self.__store._lock:
            metadata, _ = self._v2_graph_stamp(namespace)
        authority = AuthorityContext(
            actor, "d12", "owner-view:" + secrets.token_hex(16), namespace,
            ("persona",), purpose, (audience,), "owner-view-v1",
            metadata.requirements.activation_generation)
        return self._read_v2(
            authority, lambda: None, owner_principal=expected_principal,
            owner_view=True, owner_session_proof=proof)

    @staticmethod
    def _owner_session_proof(actor: str, token: str | None,
                             request: object | None) -> tuple[str, object] | None:
        from .authority_service.v2_owner_session import OwnerSessionLoginRequestV1

        if token is None and request is None:
            return None
        if (type(token) is not str or not token
                or type(request) is not OwnerSessionLoginRequestV1
                or type(actor) is not str or not actor):
            raise UnavailableGuard("Owner signed session proof is unavailable")
        return token, request

    def _current_owner_principal(self, actor: str, namespace: NamespaceId):
        from .authority_service.v2_owner_contract import OwnerPrincipalV1

        if self.__owner_principal_resolver is None:
            raise UnavailableGuard("current Owner pairing is unavailable")
        try:
            principal = self.__owner_principal_resolver(actor, namespace)
        except Exception as exc:
            raise UnavailableGuard("current Owner pairing is unavailable") from exc
        if type(principal) is not OwnerPrincipalV1:
            raise UnavailableGuard("current Owner pairing is unavailable")
        return principal

    def _owner_graph_binding_locked(self, authority: AuthorityContext,
                                    principal) -> OwnerLeaseBindingV1:
        """Resolve the graph ACL and its independently finalized issue proof."""
        from .authority_service.v2_owner_contract import (
            OwnerGraphCommitProofV1, OwnerPrincipalV1,
            canonical_digest as owner_contract_digest,
        )

        if type(principal) is not OwnerPrincipalV1:
            raise UnavailableGuard("trusted Owner principal is unavailable")
        store = self.__store
        namespace = authority.namespace
        metadata, graph_epoch = self._v2_graph_stamp(namespace)
        target = metadata.requirements
        db = store._db
        atom = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (owner_grant_key(*namespace.as_tuple).token,),
        ).fetchone()
        proof_row = db.execute(
            "SELECT operation_id,request_digest,grant_id,grant_digest,"
            "graph_incarnation,graph_access_epoch,graph_epoch,"
            "graph_receipt_digest,proof_json "
            "FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchone()
        if (atom is None or atom[0] != 1 or atom[2] != 1
                or proof_row is None or epochs is None):
            raise UnavailableGuard("current Owner graph grant is unavailable")
        try:
            grant = json.loads(atom[1])
            validate_owner_grant_v1(grant)
            proof = OwnerGraphCommitProofV1(
                namespace, proof_row[0], proof_row[1], proof_row[2],
                proof_row[3], proof_row[4], 1, proof_row[5],
                proof_row[6], proof_row[7])
        except (TypeError, ValueError, KeyError) as exc:
            raise UnavailableGuard("durable Owner graph grant is invalid") from exc
        if (atom[1] != canonical_json(grant)
                or proof_row[8] != canonical_json(asdict(proof))
                or "sha256:" + canonical_digest(grant) != proof.grant_digest
                or grant["grant_id"] != proof.grant_id
                or grant["issue_operation_id"] != proof.operation_id
                or grant["principal"] != asdict(principal)
                or grant["graph_incarnation"] != proof.graph_incarnation
                or grant["graph_incarnation"] != target.graph_incarnation
                or grant["authority_id"] != target.authority_id
                or grant["installation_id"]
                != self.__content_fence_v2.installation_grant.installation_id
                or grant["activation_generation"] != authority.activation_generation
                or grant["scope"] != "bot/persona"
                or target.namespace != namespace
                or target.activation_generation != authority.activation_generation
                or proof.graph_access_epoch > epochs[0]
                or proof.graph_epoch > graph_epoch.revision
                or "workbench.read" not in grant["capabilities"]
                or authority.purpose not in grant["purposes"]
                or not set(authority.audience).issubset(grant["audiences"])):
            raise AuthorityDenied("Owner graph grant does not authorize this read")
        return OwnerLeaseBindingV1(
            principal, authority.actor, namespace, authority.purpose,
            authority.audience[0], grant["grant_id"], grant["scope"],
            grant["issuer_ref"], frozenset(grant["capabilities"]),
            frozenset(grant["purposes"]), frozenset(grant["audiences"]),
            proof.grant_digest, 1, epochs[0], epochs[1], proof.graph_incarnation,
            owner_contract_digest(proof), 1, 0)

    def _owner_binding_in_fence(self, authority: AuthorityContext,
                                scope: FenceScope, principal,
                                expected: OwnerLeaseBindingV1 | None,
                                owner_session_proof: tuple[str, object] | None = None,
                                ) -> tuple[OwnerAuthorizationGuardV1, OwnerLeaseBindingV1]:
        port = self.__content_fence_v2
        if (principal is None and expected is None):
            raise UnavailableGuard("Owner lease has no paired principal")
        paired = self._current_owner_principal(
            authority.actor, authority.namespace)
        if paired != (expected.principal if expected is not None else principal):
            raise UnavailableGuard("Owner pairing changed")
        reader = getattr(port, "get_current_owner_guard_for_fence", None)
        if not callable(reader):
            raise UnavailableGuard("current Owner guard fence port is unavailable")
        proof_args = {}
        if owner_session_proof is not None:
            token, request = owner_session_proof
            if request.principal != paired:
                raise UnavailableGuard("Owner signed session principal differs")
            proof_args = {
                "owner_actor_id": authority.actor,
                "owner_session_token": token,
                "owner_session_request": request,
            }
        guarded = reader(
            namespace=authority.namespace, authority_namespace=scope.authority_namespace,
            permit=scope.permit, **proof_args)
        if (type(guarded) is not tuple or len(guarded) != 2
                or type(guarded[0]) is not OwnerAuthorizationGuardV1
                or guarded[1] != scope.permit):
            raise UnavailableGuard("current Owner Authority head is unavailable")
        guard = guarded[0]
        if expected is not None:
            principal = expected.principal
        with self.__store._lock:
            metadata, epoch = self._v2_graph_stamp(authority.namespace)
            if (metadata.graph_revision != scope.graph_revision
                    or epoch != scope.graph_epoch):
                raise StaleRead("Owner graph stamp changed under read fence")
            current = self._owner_graph_binding_locked(authority, principal)
        if (guard.authority_id != scope.pinned_anchor.authority_id
                or guard.installation_id
                != self.__content_fence_v2.installation_grant.installation_id
                or guard.namespace != authority.namespace
                or guard.authorization_revision != current.authorization_revision
                or guard.authorization_head != current.authorization_head
                or guard.minimum_revocation_revision != 0
                or guard.minimum_revocation_epoch != current.revocation_epoch
                or guard.pending_revoke_operation_id is not None
                or (expected is not None and current != expected)):
            raise UnavailableGuard("Owner lease differs from current grant or revoke head")
        return guard, current

    def _admin(self, bootstrap: object) -> None:
        if bootstrap is not self.__bootstrap:
            raise AuthorityDenied("host bootstrap authority required")

    @contextmanager
    def _admin_write_gate(self, namespace: NamespaceId):
        """Allow installer bookkeeping only on this authority's active holder."""
        if not isinstance(self.__store, ProductionGraphStore):
            yield
            return
        if self.__content_fence_v2 is not None:
            raise UnavailableGuard("v2 graph write path is not admitted")
        try:
            proof = self.__migration_authority.current(namespace_ref(namespace))
        except Exception as exc:
            raise UnavailableGuard("installer write activation is unavailable") from exc
        with self._content_fence(namespace, proof.generation, "write"):
            try:
                self.__migration_authority.check(
                    namespace=namespace_ref(namespace), holder=self.__holder,
                    generation=proof.generation, operation="write")
            except Exception as exc:
                raise UnavailableGuard("installer write activation is unavailable") from exc
            yield

    def set_guard_version(self, bootstrap: object, namespace: NamespaceId,
                          kind: str, ref: str, version: str | int) -> None:
        self._admin(bootstrap)
        if not isinstance(namespace, NamespaceId) or not kind or not ref or not str(version):
            raise ValueError("invalid guard version")
        store = self.__store
        with self._admin_write_gate(namespace), store._lock:
            store._ensure_open()
            store._db.execute("BEGIN IMMEDIATE")
            try:
                store._db.execute(
                    "INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) "
                    "VALUES(?,?,?,?,?) ON CONFLICT(bot,persona,kind,ref) DO UPDATE "
                    "SET version=excluded.version",
                    namespace.as_tuple + (kind, ref, str(version)),
                )
                store._db.execute("COMMIT")
            except BaseException:
                store._db.execute("ROLLBACK")
                raise

    def advance_authority_epoch(self, bootstrap: object, namespace: NamespaceId,
                                kind: str) -> int:
        self._admin(bootstrap)
        if kind not in {"access", "delete"}:
            raise ValueError("kind must be access or delete")
        store = self.__store
        with self._admin_write_gate(namespace), store._lock:
            store._ensure_open()
            store._db.execute("BEGIN IMMEDIATE")
            try:
                store._db.execute(
                    "INSERT OR IGNORE INTO graph_authority_epochs(bot,persona) VALUES(?,?)",
                    namespace.as_tuple,
                )
                column = kind + "_epoch"
                store._db.execute(
                    f"UPDATE graph_authority_epochs SET {column}={column}+1 "
                    "WHERE bot=? AND persona=?", namespace.as_tuple,
                )
                revision = store._db.execute(
                    f"SELECT {column} FROM graph_authority_epochs WHERE bot=? AND persona=?",
                    namespace.as_tuple,
                ).fetchone()[0]
                store._db.execute("COMMIT")
                return revision
            except BaseException:
                store._db.execute("ROLLBACK")
                raise

    def _authorize(self, lease: object, authority: AuthorityContext,
                   domains: frozenset[str], *, owner_read: bool = False) -> None:
        try:
            ref, actor, issuer_domain, namespace, allowed, owner_scope, generation = self.__leases[lease]
        except (KeyError, TypeError):
            raise AuthorityDenied("unknown process authority") from None
        if (authority.capability_ref != ref or authority.actor != actor
                or authority.issuer_domain != issuer_domain
                or authority.namespace != namespace
                or authority.activation_generation != generation
                or not set(authority.owner_scope).issubset(owner_scope)
                or not domains.issubset(allowed)):
            raise AuthorityDenied("authority assertion does not match process grant")
        if (issuer_domain == "d12"
                and isinstance(self.__store, ProductionGraphStore)):
            binding = self.__owner_leases.get(lease)
            if (not owner_read or binding is None
                    or binding.actor != authority.actor
                    or binding.namespace != authority.namespace
                    or binding.purpose != authority.purpose
                    or authority.audience != (binding.audience,)
                    or authority.provider_policy_ref != "owner-grant-v1"):
                raise UnavailableGuard("current Owner graph read lease is unavailable")

    @staticmethod
    def _version(db, namespace: NamespaceId, kind: str, ref: str) -> str:
        row = db.execute(
            "SELECT version FROM graph_guard_versions WHERE bot=? AND persona=? "
            "AND kind=? AND ref=?", namespace.as_tuple + (kind, ref),
        ).fetchone()
        if row is None:
            raise UnavailableGuard(f"{kind} authority is unavailable")
        return row[0]

    def _admit_ingress_deadline(self, namespace: NamespaceId,
                                operation_id: str, generation: int,
                                deadline_utc: float) -> None:
        """Rebind durable UTC to this process; never trust envelope monotonic."""
        if self.__ingress_clock is None:
            raise UnavailableGuard("installation-owned ingress clock is unavailable")
        try:
            sample = self.__ingress_clock()
        except Exception as exc:
            raise UnavailableGuard("trusted ingress clock read failed") from exc
        if type(sample) is not IngressClockSample or not sample.clock_trusted:
            raise UnavailableGuard("trusted ingress clock is unavailable")
        if sample.wall_now_utc >= deadline_utc:
            raise UnavailableGuard("ingress UTC deadline has expired")
        key = (namespace, operation_id, generation)
        prior = self.__ingress_clock_bindings.get(key)
        if prior is None:
            monotonic_deadline = sample.monotonic_now + (
                deadline_utc - sample.wall_now_utc)
            if not math.isfinite(monotonic_deadline):
                raise UnavailableGuard("ingress monotonic deadline cannot be rebuilt")
            self.__ingress_clock_bindings[key] = _IngressClockBinding(
                sample.clock_epoch, deadline_utc, monotonic_deadline,
                sample.wall_now_utc, sample.monotonic_now)
            return
        if (prior.clock_epoch != sample.clock_epoch
                or prior.deadline_utc != deadline_utc
                or sample.monotonic_now < prior.last_monotonic
                or sample.wall_now_utc < prior.last_wall_utc):
            raise UnavailableGuard("ingress process clock binding changed")
        if sample.monotonic_now >= prior.monotonic_deadline:
            raise UnavailableGuard("ingress monotonic deadline has expired")
        self.__ingress_clock_bindings[key] = _IngressClockBinding(
            prior.clock_epoch, prior.deadline_utc,
            prior.monotonic_deadline, sample.wall_now_utc,
            sample.monotonic_now)

    def _exact_ingress_without_query(self, db, bundle: DomainBundle, *,
                                     deadline_check=None) -> bool:
        """Only the issued four-key first ingress may omit a range predicate."""
        if not isinstance(bundle, DomainBundle):
            return False
        envelope = bundle.envelope
        identity = envelope.identity
        authority = envelope.authority
        guard = envelope.version_guard
        namespace = authority.namespace
        if (identity.phase != "ingress" or authority.issuer_domain != "d06"
                or guard.query_epochs or len(guard.resource_lease_versions) != 1
                or len(guard.read_versions) != 4
                or any(read.revision != 0 for read in guard.read_versions)
                or len(envelope.source_qualification.source_refs) != 1
                or envelope.input_refs != envelope.source_qualification.source_refs
                or tuple(proposal.domain for proposal in bundle.proposals) != ("d06", "d11")
                or len(bundle.persistent_job_refs) != 1
                or len(bundle.outbox_refs) != 1):
            return False
        if authority.capability_ref != _operation_capability_ref(
                namespace, authority.actor, "d06", frozenset({"d06", "d11"}),
                authority.activation_generation, identity.operation_id):
            return False
        try:
            source = AtomKey.from_token(envelope.source_qualification.source_refs[0])
            if (source != source_key(*namespace.as_tuple, source.owner.subject or "")
                    or NamespaceId.from_key(source) != namespace):
                return False
            access = access_key(*namespace.as_tuple, source.owner.subject or "")
            job = AtomKey.from_token(bundle.persistent_job_refs[0])
            outbox = AtomKey.from_token(bundle.outbox_refs[0])
        except (TypeError, ValueError):
            return False
        if (job.type_name != "runtime.job" or outbox.type_name != "runtime.outbox"
                or job.owner.kind != "activity" or outbox.owner.kind != "activity"
                or job.owner.subject != identity.activity_id
                or outbox.owner.subject != identity.activity_id
                or any(NamespaceId.from_key(key) != namespace for key in (job, outbox))
                or {read.key for read in guard.read_versions}
                != {source, access, job, outbox}
                or {write.key for write in bundle.proposals[0].typed_writes}
                != {source, access}
                or {write.key for write in bundle.proposals[1].typed_writes}
                != {job, outbox}):
            return False
        row = db.execute(
            "SELECT activation_generation,quote_id,policy_json "
            "FROM runtime_ingress_issuance "
            "WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (identity.operation_id,),
        ).fetchone()
        sealed = db.execute(
            "SELECT bundle_digest FROM ingress_first_observations "
            "WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (identity.operation_id,),
        ).fetchone()
        if (row is None or row[0] != authority.activation_generation
                or row[1] != guard.resource_lease_versions[0].ref
                or sealed is None or sealed[0] != bundle.digest):
            return False
        try:
            policy = IngressIssuancePolicy(**json.loads(row[2]))
        except (TypeError, ValueError, KeyError) as exc:
            raise UnavailableGuard("durable ingress policy is invalid") from exc
        if policy.deadline_utc != envelope.deadline_utc:
            return False
        if deadline_check is None:
            self._admit_ingress_deadline(
                namespace, identity.operation_id,
                authority.activation_generation, policy.deadline_utc)
        else:
            deadline_check(policy.deadline_utc)
        return True

    def _check_guard(self, db, bundle: DomainBundle, *,
                     ingress_deadline_check=None) -> GraphSnapshot:
        store = self.__store
        envelope = bundle.envelope
        namespace = envelope.authority.namespace
        guard = envelope.version_guard
        if guard.catalogue_version != store._registry.catalogue_hash:
            raise StaleRead("type catalogue changed")
        for kind, version in (("scheme", guard.scheme_version),
                              ("operator", guard.operator_version),
                              ("policy", guard.policy_version)):
            if self._version(db, namespace, kind, "current") != version:
                raise StaleRead(f"{kind} version changed")
        if self._version(db, namespace, "activation", "current") != str(
                envelope.authority.activation_generation):
            raise StaleRead("activation generation changed")
        # A namespace string flag cannot prove a particular worker still owns
        # its job. Runtime job identity/fence is checked inside the same commit.
        budget = get_budget_lease(db, envelope.parent_budget_lease_ref)
        if (budget.state != "active" or
                (budget.bot_id, budget.persona_id) != namespace.as_tuple):
            raise UnavailableGuard("parent budget lease is unavailable for this namespace")
        epoch_row = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchone()
        access_epoch, delete_epoch = epoch_row if epoch_row else (0, 0)
        if (guard.access_epoch, guard.delete_epoch) != (access_epoch, delete_epoch):
            raise StaleRead("access or deletion epoch changed")
        graph_epoch = GraphStore.graph_epoch(
            store, *namespace.as_tuple, _capability=self.__graph_capability)
        if not guard.query_epochs and not self._exact_ingress_without_query(
                db, bundle, deadline_check=ingress_deadline_check):
            raise UnavailableGuard("namespace query epoch is required")
        for query in guard.query_epochs:
            if query.namespace != namespace or query.revision != graph_epoch.revision:
                raise StaleRead("positive or negative query changed")
        for kind, refs in (("source_grant", guard.source_grant_refs),
                           ("focus_lease", guard.focus_lease_versions),
                           ("resource_lease", guard.resource_lease_versions)):
            for item in refs:
                if self._version(db, namespace, kind, item.ref) != str(item.version):
                    raise StaleRead(f"{kind} changed")
        atoms = []
        for read in guard.read_versions:
            if NamespaceId.from_key(read.key) != namespace:
                raise AuthorityDenied("cross-namespace read")
            store._validate_key(read.key)
            row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (read.key.token,),
            ).fetchone()
            revision = row[0] if row else 0
            if revision != read.revision:
                raise StaleRead("read version changed")
            atoms.append(GraphAtom(read.key, revision, json.loads(row[1]), bool(row[2]))
                         if row else GraphAtom(read.key, 0, {}, False))
        return GraphSnapshot(tuple(atoms), (graph_epoch,))

    @staticmethod
    def _parse_ref(ref: str, namespace: NamespaceId) -> AtomKey:
        key = AtomKey.from_token(ref)
        if NamespaceId.from_key(key) != namespace:
            raise AuthorityDenied("bundle reference crosses namespace")
        return key

    def _first_ingress_boundary_locked(self, namespace: NamespaceId,
                                       guard: OwnerAuthorizationGuardV1,
                                       scene_ref: str, visibility: str,
                                       at_time: float) -> None:
        """Require the current Owner, active role, and fenced scene graph heads."""
        from .authority_service.v2_owner_contract import (
            OwnerGraphCommitProofV1, canonical_digest as owner_contract_digest,
        )
        from .domains.d03 import RoleBinding, RoleBindingRequest

        db = self.__store._db
        proof_row = db.execute(
            "SELECT operation_id,request_digest,grant_id,grant_digest,"
            "graph_incarnation,graph_access_epoch,graph_epoch,"
            "graph_receipt_digest,proof_json "
            "FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchone()
        if proof_row is None or epochs != (1, 0):
            raise UnavailableGuard("first ingress current Owner proof is absent")
        proof = OwnerGraphCommitProofV1(
            namespace, proof_row[0], proof_row[1], proof_row[2],
            proof_row[3], proof_row[4], 1, proof_row[5], proof_row[6],
            proof_row[7],
        )
        grant_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (owner_grant_key(*namespace.as_tuple).token,),
        ).fetchone()
        if grant_row is None or grant_row[0] != 1 or grant_row[2] != 1:
            raise UnavailableGuard("first ingress current Owner grant is absent")
        grant = json.loads(grant_row[1])
        validate_owner_grant_v1(grant)
        metadata, _ = self._v2_graph_stamp(namespace)
        if (proof_row[8] != canonical_json(asdict(proof))
                or grant_row[1] != canonical_json(grant)
                or "sha256:" + canonical_digest(grant) != proof.grant_digest
                or grant["grant_id"] != proof.grant_id
                or grant["issue_operation_id"] != proof.operation_id
                or grant["graph_incarnation"] != proof.graph_incarnation
                or proof.graph_incarnation != metadata.requirements.graph_incarnation
                or proof.graph_access_epoch != epochs[0]
                or guard.namespace != namespace
                or guard.authority_id != grant["authority_id"]
                or guard.installation_id
                != self.__content_fence_v2.installation_grant.installation_id
                or guard.installation_id != grant["installation_id"]
                or guard.authorization_revision != 1
                or guard.authorization_head != owner_contract_digest(proof)
                or guard.minimum_revocation_revision != 0
                or guard.minimum_revocation_epoch != 0
                or guard.pending_revoke_operation_id is not None):
            raise UnavailableGuard("first ingress current Owner head differs")
        role, _, _, _ = self._scene_binding_state_locked(namespace, guard)
        rows = db.execute(
            "SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? "
            "AND owner_kind='scene' AND subject=? "
            "AND type_name='d03.role_binding' AND valid=1",
            namespace.as_tuple + (scene_ref,),
        ).fetchall()
        if len(rows) != 1:
            raise UnavailableGuard("first ingress current scene binding is absent")
        token, revision, encoded = rows[0]
        key = AtomKey.from_token(token)
        value = json.loads(encoded)
        try:
            binding = RoleBinding(**{
                **value, "norm_refs": tuple(value["norm_refs"]),
                "source_refs": tuple(value["source_refs"]),
            })
            request = RoleBindingRequest(
                f"persona:{namespace.persona_id}", None, None, scene_ref,
                "message", "context", at_time, True)
        except (TypeError, ValueError, KeyError) as exc:
            raise UnavailableGuard("first ingress current scene binding is invalid") from exc
        if (key.name != binding.role_binding_id
                or key.owner.subject != scene_ref
                or revision != binding.binding_version
                or binding.scene_ref != scene_ref
                or binding.scope_selector != "scene"
                or binding.visibility_scope != visibility
                or not binding.applies_to(request)):
            raise AuthorityDenied("first ingress scene does not admit this conversation")
        receipt_row = db.execute(
            "SELECT r.receipt_json FROM graph_history AS h "
            "JOIN graph_scene_binding_receipts_v1 AS r "
            "ON r.bot=h.event_bot AND r.persona=h.event_persona "
            "AND r.operation_id=h.event_id "
            "WHERE h.token=? AND h.revision=? "
            "AND h.event_session='d03-scene-binding'",
            (token, revision),
        ).fetchone()
        if receipt_row is None:
            raise UnavailableGuard("first ingress scene lacks fenced binding receipt")
        scene_receipt = json.loads(receipt_row[0])
        if (scene_receipt.get("scene_ref") != scene_ref
                or scene_receipt.get("binding_id") != binding.role_binding_id
                or scene_receipt.get("role_head_id") != role.head_id
                or scene_receipt.get("owner_grant_id") != proof.grant_id
                or scene_receipt.get("owner_authorization_head")
                != guard.authorization_head):
            raise UnavailableGuard("first ingress scene receipt differs from current heads")

    def commit_first_ingress_v2(self, bootstrap: object, host: IngressHostFacts,
                                installation_policy, clock_policy,
                                encoding_policy) -> CommitReceipt:
        """Commit the first reported source and encoding job in one fenced write."""
        from .authority_service.v2_contract import FencePermitV2, from_wire, to_wire
        from .domains.d06 import D06DomainAdapter, SourceAdmission
        from .host.authority_profile import (
            AdminIngressClockPolicy, AdminIngressEncodingPolicy,
        )
        from .installation_policy import AdminInstallationPolicy
        from .runtime.d11_types import runtime_job_key, runtime_outbox_key
        from .runtime.first_ingress_bundle import build_first_ingress_bundle
        from .runtime.first_ingress_v2 import (
            finish_digest, ingress_ids, policy_identity,
            scene_ref_for_conversation, trusted_upper,
        )
        from .runtime.issuers import (
            D02ResourceIssuer, D11BudgetJobIssuer, ResourceQuote,
            install_schema as install_issuer_schema,
        )
        from .runtime_contracts import (
            RUNTIME_SCHEMA, CommandEnvelope, OperationIdentity,
            VersionGuard, VersionedRef,
        )

        self._admin(bootstrap)
        if (installation_policy is None or clock_policy is None
                or encoding_policy is None):
            raise UnavailableGuard("v2 first ingress administrator policy missing; HOLD")
        if (type(host) is not IngressHostFacts
                or type(installation_policy) is not AdminInstallationPolicy
                or type(clock_policy) is not AdminIngressClockPolicy
                or type(encoding_policy) is not AdminIngressEncodingPolicy):
            raise TypeError("typed v2 first ingress facts and policies required")
        store = self.__store
        port = self.__content_fence_v2
        if (not isinstance(store, ProductionGraphStore) or port is None
                or type(self.__d02_issuer) is not D02ResourceIssuer
                or type(self.__d11_issuer) is not D11BudgetJobIssuer
                or self.__d11_issuer.resource_issuer is not self.__d02_issuer):
            raise UnavailableGuard("v2 first ingress authorities are unavailable")
        namespace = host.namespace
        policy = installation_policy
        if namespace != policy.namespace or host.lineage.source_ref == "":
            raise AuthorityDenied("first ingress namespace or source differs")
        scene_ref = scene_ref_for_conversation(
            namespace, host.platform_ref, host.conversation_ref)
        source_identity, activity_id, operation_id, job_id, outbox_id, idem = (
            ingress_ids(host.lineage.source_ref))
        fingerprint = ingress_host_fingerprint(host)
        identity_json = policy_identity(
            policy, clock_policy, encoding_policy, fingerprint,
            host.lineage.source_ref, host.conversation_ref)
        attempt_id = "first-ingress-" + canonical_digest({
            "namespace": list(namespace.as_tuple), "operation_id": operation_id,
            "identity": identity_json,
        })[:48]
        grant = policy.root_grant
        if ("d06.encode_source" not in grant.allowed_work_kinds
                or any(amount > grant.max_ceiling.get(name, 0)
                       for name, amount in encoding_policy.quote_ceiling.items())):
            raise UnavailableGuard("root grant does not admit source encoding ceiling")

        # All Authority calls precede the business lock. The profile's signed
        # root grant is read from the provisioned DB; no new grant is minted.
        with store._lock:
            provision = self._provision_row(store._db, namespace)
            if provision is None:
                raise UnavailableGuard("v2 namespace is not provisioned")
            genesis = self._decode_provision_receipt(provision)
            metadata, epoch = self._v2_graph_stamp(namespace)
            stored_grant, signature = self.__d11_issuer.signed_budget_grant_at_version(
                store._db, grant.lease_id, grant.version)
            if (stored_grant != grant or signature != genesis.root_grant_signature
                    or genesis.root_grant_id != grant.grant_id
                    or genesis.root_lease_id != grant.lease_id
                    or genesis.installation_id != policy.installation_id
                    or genesis.manifest_digest != policy.manifest_digest):
                raise UnavailableGuard("provisioned signed root grant differs")
            row = store._db.execute(
                "SELECT identity_json,learned_at,deadline_utc,fence_attempt_id,"
                "requirements_json,anchor_json,graph_revision,graph_epoch,"
                "monotonic_deadline "
                "FROM graph_first_ingress_intents_v2 WHERE bot=? AND persona=? "
                "AND operation_id=?", namespace.as_tuple + (operation_id,),
            ).fetchone()
        target = metadata.requirements
        if (target.namespace != namespace
                or target.authority_id != policy.expected_authority_id
                or target.authority_namespace != policy.authority_namespace
                or target.activation_generation != genesis.generation):
            raise UnavailableGuard("v2 first ingress recovery identity differs")
        anchor = port.current_anchor(
            namespace=namespace, authority_namespace=target.authority_namespace)
        if not self._anchor_matches(target, anchor):
            raise UnavailableGuard("v2 first ingress Authority anchor differs")
        reading = None
        upper = None
        requirements_json = canonical_json(asdict(target))
        anchor_json = canonical_json(asdict(anchor))

        def read_clock():
            try:
                sample = port.read_ingress_clock(clock_policy)
                return sample, trusted_upper(sample)
            except Exception as exc:
                raise UnavailableGuard("paired ingress clock unavailable; HOLD") from exc

        if row is None:
            reading, upper = read_clock()
            learned_at = upper
            deadline = min(
                math.nextafter(math.fsum((learned_at,
                    encoding_policy.deadline_after_seconds)), -math.inf),
                grant.valid_until_utc)
            if (deadline <= learned_at or
                    host.occurred_at is not None and host.occurred_at > learned_at):
                raise UnavailableGuard("paired ingress clock cannot admit source")
            monotonic_deadline = reading.monotonic_after_seconds + (
                deadline - reading.utc_upper_bound_seconds)
            if not math.isfinite(monotonic_deadline):
                raise UnavailableGuard("paired ingress monotonic deadline is invalid")
            with store._lock:
                db = store._db
                db.execute("BEGIN IMMEDIATE")
                try:
                    if self._v2_graph_stamp(namespace) != (metadata, epoch):
                        raise StaleRead("first ingress pre-stamp changed")
                    db.execute(
                        "INSERT OR IGNORE INTO graph_first_ingress_intents_v2"
                        "(bot,persona,operation_id,identity_json,learned_at,"
                        "deadline_utc,fence_attempt_id,requirements_json,"
                        "anchor_json,graph_revision,graph_epoch,"
                        "monotonic_deadline) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        namespace.as_tuple + (operation_id, identity_json,
                        learned_at, deadline, attempt_id, requirements_json,
                        anchor_json, metadata.graph_revision, epoch.revision,
                        monotonic_deadline),
                    )
                    row = db.execute(
                        "SELECT identity_json,learned_at,deadline_utc,"
                        "fence_attempt_id,requirements_json,anchor_json,"
                        "graph_revision,graph_epoch,monotonic_deadline "
                        "FROM graph_first_ingress_intents_v2 "
                        "WHERE bot=? AND persona=? AND operation_id=?",
                        namespace.as_tuple + (operation_id,),
                    ).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        if (row[0] != identity_json or row[3] != attempt_id
                or row[4] != requirements_json or row[5] != anchor_json):
            raise UnavailableGuard("durable first ingress intent identity differs")
        learned_at, deadline = row[1:3]
        if (not math.isfinite(learned_at) or not math.isfinite(deadline)
                or not math.isfinite(row[8])
                or deadline <= learned_at or deadline > grant.valid_until_utc):
            raise UnavailableGuard("durable first ingress time is invalid")

        def deadline_check(expected):
            if expected != deadline or trusted_upper(reading) >= deadline:
                raise UnavailableGuard("first ingress paired deadline expired")

        with store._lock:
            db = store._db
            saved = db.execute(
                "SELECT digest,permit_json,pre_graph_revision,pre_graph_epoch,"
                "post_graph_revision,post_graph_epoch,finish_request_id,"
                "finish_request_digest FROM graph_bundle_fences_v2 "
                "WHERE bot=? AND persona=? AND operation_id=?",
                namespace.as_tuple + (operation_id,),
            ).fetchone()
            rejected = db.execute(
                "SELECT status,permit_json,graph_revision,graph_epoch,"
                "finish_request_id,finish_request_digest "
                "FROM graph_first_ingress_rejections_v2 "
                "WHERE bot=? AND persona=? AND operation_id=?",
                namespace.as_tuple + (operation_id,),
            ).fetchone()
            receipt = self._get_operation_fenced(
                AuthorityContext(policy.administrator_holder, "d06", "audit",
                    namespace, ("event", "activity"), "context",
                    (host.conversation_ref,), grant.policy_ref,
                    target.activation_generation), operation_id, v2=True)
        if receipt is not None or rejected is not None:
            if (receipt is None) == (rejected is None):
                raise UnavailableGuard("first ingress terminal ledgers disagree")
            encoded = saved[1] if receipt is not None and saved else (
                rejected[1] if rejected else None)
            if encoded is None:
                raise UnavailableGuard("first ingress terminal permit absent")
            permit = from_wire(json.loads(encoded))
            if (type(permit) is not FencePermitV2
                    or permit.operation_id != attempt_id
                    or permit.pinned_anchor != anchor
                    or permit.holder != self.__holder
                    or permit.subject != port.installation_grant.subject):
                raise UnavailableGuard("first ingress terminal permit differs")
            try:
                observed, state = port.get_fence_operation(
                    namespace=namespace,
                    authority_namespace=target.authority_namespace,
                    operation_id=attempt_id)
            except Exception as exc:
                raise FirstIngressOutcomeUnknown(
                    operation_id, "first ingress terminal Authority status unknown; HOLD"
                ) from exc
            if observed != permit or state not in {"active", "finished"}:
                raise UnavailableGuard("first ingress Authority status differs")
            if receipt is not None:
                with store._lock:
                    obs = store._db.execute(
                        "SELECT content_fingerprint,learned_at,bundle_digest "
                        "FROM ingress_first_observations WHERE bot=? AND persona=? "
                        "AND operation_id=?",
                        namespace.as_tuple + (operation_id,),
                    ).fetchone()
                if (saved[0] != receipt.operation_digest
                        or obs != (fingerprint, learned_at, receipt.operation_digest)
                        or saved[2:4] != row[6:8]
                        or saved[4] != saved[2] + 1
                        or saved[5] != receipt.invalidated_epochs[0].revision
                        or saved[5] <= saved[3]
                        or saved[6] != "finish:" + attempt_id
                        or saved[7] != finish_digest(
                            attempt_id, permit.token, operation_id,
                            receipt.operation_digest)):
                    raise UnavailableGuard("first ingress business receipt differs")
                if state == "active":
                    if (metadata.graph_revision != saved[4]
                            or epoch.revision != saved[5]):
                        raise UnavailableGuard("first ingress committed stamp differs")
                    scope = FenceScope(namespace, target.authority_namespace,
                        target.activation_generation, "write", attempt_id,
                        permit, anchor, NamespaceEpoch(*namespace.as_tuple,
                            row[7]), row[6])
                    try:
                        if port.validate_fence(scope) != permit:
                            raise UnavailableGuard("first ingress permit changed")
                        port.finish_fence(scope, request_id=saved[6],
                                          request_digest=saved[7])
                    except Exception as exc:
                        raise FirstIngressOutcomeUnknown(
                            operation_id,
                            "first ingress committed finish unconfirmed; HOLD"
                        ) from exc
                elif (metadata.graph_revision < saved[4]
                      or epoch.revision < saved[5]):
                    raise UnavailableGuard(
                        "finished first ingress lost its business recovery stamp")
                return receipt
            if (rejected[0] != "rejected_no_commit"
                    or rejected[2:4] != row[6:8]
                    or rejected[4] != "abort:" + attempt_id
                    or rejected[5] != finish_digest(
                        attempt_id, permit.token, operation_id, None,
                        rejected=True)):
                raise UnavailableGuard("first ingress rejection differs")
            scope = FenceScope(namespace, target.authority_namespace,
                target.activation_generation, "write", attempt_id,
                permit, anchor, NamespaceEpoch(*namespace.as_tuple, row[7]),
                row[6])
            if state == "active":
                if port.validate_fence(scope) != permit:
                    raise UnavailableGuard("first ingress rejected permit changed")
                try:
                    port.finish_fence(scope, request_id=rejected[4],
                                      request_digest=rejected[5])
                except Exception as exc:
                    raise FirstIngressOutcomeUnknown(
                        operation_id,
                        "first ingress rejected finish unconfirmed; HOLD"
                    ) from exc
            raise UnavailableGuard("first ingress terminal rejected_no_commit")
        if reading is None:
            reading, upper = read_clock()
        if upper >= deadline or upper >= grant.valid_until_utc:
            raise UnavailableGuard("first ingress paired deadline expired")
        if (metadata.graph_revision, epoch.revision) != row[6:8]:
            raise UnavailableGuard("uncommitted first ingress pre-stamp changed")
        try:
            # Authority treats the original active operation ID as an exact
            # retry, including after a lost begin response or process crash.
            permit = port.begin_fence(
                namespace=namespace,
                authority_namespace=target.authority_namespace,
                holder=self.__holder, generation=target.activation_generation,
                operation="write", operation_id=attempt_id,
                expected_anchor=anchor, retain_on_unknown=True)
        except Exception as exc:
            raise FirstIngressOutcomeUnknown(
                operation_id,
                "first ingress begin outcome unknown; HOLD original attempt") from exc
        scope = FenceScope(namespace, target.authority_namespace,
            target.activation_generation, "write", attempt_id, permit,
            anchor, epoch, metadata.graph_revision)
        if port.validate_fence(scope) != permit:
            raise UnavailableGuard("first ingress write permit changed")
        guard_reader = getattr(port, "get_current_owner_guard_for_fence", None)
        try:
            if not callable(guard_reader):
                raise UnavailableGuard("first ingress current Owner guard is unavailable")
            guarded = guard_reader(
                namespace=namespace, authority_namespace=target.authority_namespace,
                permit=permit)
            if (type(guarded) is not tuple or len(guarded) != 2
                    or type(guarded[0]) is not OwnerAuthorizationGuardV1
                    or guarded[1] != permit):
                raise UnavailableGuard("first ingress current Owner guard is unavailable")
            owner_guard = guarded[0]
        except Exception:
            self._reject_first_ingress_v2(
                namespace, operation_id, row, permit, scope)
            raise

        actor = policy.administrator_holder
        lease, capability_ref = self.grant(
            bootstrap, actor=actor, issuer_domain="d06", namespace=namespace,
            domains=("d06", "d11"),
            activation_generation=target.activation_generation,
            operation_id=operation_id)
        authority = AuthorityContext(
            actor, "d06", capability_ref, namespace, ("event", "activity"),
            "context", (host.conversation_ref,), grant.policy_ref,
            target.activation_generation)
        source = source_key(*namespace.as_tuple, host.lineage.source_ref)
        access = access_key(*namespace.as_tuple, host.lineage.source_ref)
        job_key = runtime_job_key(*namespace.as_tuple, activity_id, job_id)
        outbox_key = runtime_outbox_key(*namespace.as_tuple, activity_id, outbox_id)
        quote_id = "ingress-q-" + hashlib.sha256(
            canonical_json([*namespace.as_tuple, operation_id]).encode()
        ).hexdigest()[:40]
        ingress_policy = IngressIssuancePolicy(
            grant.lease_id, dict(encoding_policy.quote_ceiling),
            dict(grant.max_ceiling), deadline, grant.valid_until_utc,
            row[8],
            encoding_policy.snapshot_ref, encoding_policy.resource_ref,
            encoding_policy.character_interval_ref)
        result = None
        transaction_rolled_back = False
        try:
            with store._lock:
                db = store._db
                db.execute("BEGIN IMMEDIATE")
                try:
                    if self._v2_graph_stamp(namespace) != (metadata, epoch):
                        raise StaleRead("first ingress recovery stamp changed")
                    if db.execute(
                        "SELECT identity_json,learned_at,deadline_utc,"
                        "fence_attempt_id,requirements_json,anchor_json,"
                        "graph_revision,graph_epoch,monotonic_deadline "
                        "FROM graph_first_ingress_intents_v2 WHERE bot=? "
                        "AND persona=? AND operation_id=?",
                        namespace.as_tuple + (operation_id,),
                    ).fetchone() != row:
                        raise UnavailableGuard("first ingress durable intent changed")
                    deadline_check(deadline)
                    for key in (source, access, job_key, outbox_key):
                        if db.execute("SELECT 1 FROM graph_atoms WHERE token=?",
                                      (key.token,)).fetchone():
                            raise StaleRead("first ingress revision-0 key changed")
                    if db.execute(
                        "SELECT 1 FROM graph_bundle_operations WHERE bot=? "
                        "AND persona=? AND operation_id=?",
                        namespace.as_tuple + (operation_id,),
                    ).fetchone():
                        raise EventConflict("first ingress operation already committed")
                    current_grant = self.__d11_issuer.current_budget_grant(
                        db, grant.lease_id)
                    if current_grant != grant:
                        raise AuthorityDenied("root grant changed before ingress")
                    self._first_ingress_boundary_locked(
                        namespace, owner_guard, scene_ref, host.visibility,
                        trusted_upper(reading))
                    budget = get_budget_lease(db, grant.lease_id)
                    if budget.state != "active" or any(
                            amount > budget.limits.get(name, 0)
                            - budget.used.get(name, 0)
                            - budget.reserved.get(name, 0)
                            - budget.unconfirmed.get(name, 0)
                            for name, amount in encoding_policy.quote_ceiling.items()):
                        raise UnavailableGuard("root budget has insufficient capacity")
                    epochs = db.execute(
                        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
                        "WHERE bot=? AND persona=?", namespace.as_tuple,
                    ).fetchone() or (0, 0)
                    guard_data = {
                        "access_epoch": epochs[0], "delete_epoch": epochs[1],
                        "scheme": self._version(db, namespace, "scheme", "current"),
                        "operator": self._version(db, namespace, "operator", "current"),
                        "policy": self._version(db, namespace, "policy", "current"),
                    }
                    admission = SourceAdmission(
                        host.lineage.source_ref, host.text, host.sender_ref,
                        host.lineage.source_kind, "reported",
                        host.lineage.evidence_eligibility,
                        host.lineage.internal_activity_actuality,
                        host.occurred_at, learned_at,
                        host.lineage.provenance_family,
                        (host.conversation_ref,), ("context", "consolidation"))
                    candidate = D06DomainAdapter(namespace).admit_source(admission)
                    command = CommandEnvelope(
                        RUNTIME_SCHEMA,
                        OperationIdentity(activity_id, None, "first", "ingress",
                            operation_id, canonical_digest({
                                "input_refs": list(candidate.qualification.source_refs)})),
                        authority,
                        VersionGuard(
                            tuple(GraphVersion(key, 0) for key in
                                  (source, access, job_key, outbox_key)),
                            (), epochs[0], epochs[1],
                            store._registry.catalogue_hash,
                            guard_data["scheme"], guard_data["operator"],
                            guard_data["policy"], (), (),
                            (VersionedRef(quote_id, 1),)),
                        candidate.qualification,
                        candidate.qualification.source_refs,
                        grant.lease_id, deadline,
                        ingress_policy.monotonic_deadline,
                        encoding_policy.character_interval_ref,
                        (host.message_id,))
                    install_issuer_schema(db)
                    db.execute("""CREATE TABLE IF NOT EXISTS ingress_first_observations(
                        bot TEXT NOT NULL, persona TEXT NOT NULL,
                        operation_id TEXT NOT NULL,
                        content_fingerprint TEXT NOT NULL,
                        learned_at REAL NOT NULL CHECK(learned_at > 0),
                        bundle_digest TEXT,
                        PRIMARY KEY(bot,persona,operation_id))""")
                    db.execute("""CREATE TABLE IF NOT EXISTS runtime_ingress_issuance(
                        bot TEXT NOT NULL, persona TEXT NOT NULL,
                        operation_id TEXT NOT NULL,
                        activation_generation INTEGER NOT NULL,
                        request_digest TEXT NOT NULL, policy_json TEXT NOT NULL,
                        quote_id TEXT NOT NULL, grant_id TEXT NOT NULL,
                        guard_json TEXT NOT NULL,
                        PRIMARY KEY(bot,persona,operation_id))""")
                    db.execute(
                        "INSERT INTO ingress_first_observations"
                        "(bot,persona,operation_id,content_fingerprint,"
                        "learned_at,bundle_digest) VALUES(?,?,?,?,?,NULL)",
                        namespace.as_tuple + (operation_id, fingerprint,
                                              learned_at))
                    quote = ResourceQuote(
                        quote_id, 1, *namespace.as_tuple, activity_id,
                        operation_id, None, grant.lease_id,
                        "d06.encode_source", encoding_policy.snapshot_ref,
                        deadline, encoding_policy.resource_ref, job_key.token,
                        (outbox_key.token,), (), dict(encoding_policy.quote_ceiling),
                        None, deadline)
                    self.__d02_issuer.issue_quote(db, quote)
                    db.execute(
                        "INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) "
                        "VALUES(?,?,?,?,?)",
                        namespace.as_tuple + ("resource_lease", quote_id, "1"))
                    db.execute(
                        "INSERT INTO runtime_ingress_issuance"
                        "(bot,persona,operation_id,activation_generation,"
                        "request_digest,policy_json,quote_id,grant_id,guard_json) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        namespace.as_tuple + (
                            operation_id, target.activation_generation,
                            canonical_digest(identity_json),
                            canonical_json(asdict(ingress_policy)), quote_id,
                            grant.grant_id, canonical_json(guard_data)))
                    now_utc = trusted_upper(reading)
                    job = self.__d11_issuer.job_for(
                        command, db, now_utc=now_utc)
                    bundle = build_first_ingress_bundle(
                        command, job, admission,
                        source_identity=source_identity,
                        payload_ref=host.lineage.source_ref,
                        idempotency_key=idem)
                    db.execute(
                        "UPDATE ingress_first_observations SET bundle_digest=? "
                        "WHERE bot=? AND persona=? AND operation_id=?",
                        (bundle.digest,) + namespace.as_tuple + (operation_id,))
                    finish_id = "finish:" + attempt_id
                    finished_digest = finish_digest(
                        attempt_id, permit.token, operation_id, bundle.digest)
                    result = self._commit_domain_bundle_fenced(
                        bundle, lease, in_transaction=True, now_utc=now_utc,
                        ingress_deadline_check=deadline_check,
                        v2_write=(metadata, epoch, finish_id,
                                  finished_digest,
                                  canonical_json(to_wire(permit))))
                    db.execute("COMMIT")
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                        transaction_rolled_back = True
                    raise
        except Exception as exc:
            if transaction_rolled_back:
                try:
                    self._reject_first_ingress_v2(
                        namespace, operation_id, row, permit, scope)
                except Exception as reconcile_exc:
                    raise FirstIngressOutcomeUnknown(
                        operation_id,
                        "first ingress rejection finish unconfirmed; HOLD original attempt"
                    ) from reconcile_exc
                raise
            raise FirstIngressOutcomeUnknown(
                operation_id,
                "first ingress commit outcome unknown; HOLD original attempt") from exc
        try:
            if port.validate_fence(scope) != permit:
                raise UnavailableGuard("first ingress permit changed after commit")
        except Exception as exc:
            raise FirstIngressOutcomeUnknown(
                operation_id, "first ingress committed permit unconfirmed; HOLD"
            ) from exc
        with store._lock:
            current, current_epoch = self._v2_graph_stamp(namespace)
            if (current.graph_revision != metadata.graph_revision + 1
                    or current_epoch.revision != result.invalidated_epochs[0].revision):
                raise FirstIngressOutcomeUnknown(
                    operation_id, "first ingress committed stamp unconfirmed; HOLD")
        try:
            port.finish_fence(scope, request_id=finish_id,
                              request_digest=finished_digest)
        except Exception as exc:
            raise FirstIngressOutcomeUnknown(
                operation_id,
                "first ingress finish outcome unknown; HOLD original attempt") from exc
        return result

    def _reject_first_ingress_v2(self, namespace, operation_id, row,
                                 permit, scope) -> None:
        """Only a proven rollback may become a durable abort identity."""
        from .authority_service.v2_contract import to_wire
        from .runtime.first_ingress_v2 import finish_digest

        store = self.__store
        attempt_id = row[3]
        abort_id = "abort:" + attempt_id
        digest = finish_digest(
            attempt_id, permit.token, operation_id, None, rejected=True)
        expected = ("rejected_no_commit", canonical_json(to_wire(permit)),
                    row[6], row[7], abort_id, digest)
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                current, current_epoch = self._v2_graph_stamp(namespace)
                if (current_epoch != scope.graph_epoch
                        or current.graph_revision != scope.graph_revision
                        or db.execute(
                            "SELECT 1 FROM graph_bundle_operations WHERE bot=? "
                            "AND persona=? AND operation_id=?",
                            namespace.as_tuple + (operation_id,),
                        ).fetchone()):
                    raise UnavailableGuard("first ingress rollback cannot be proven")
                if current.graph_revision != row[6]:
                    raise UnavailableGuard("first ingress rollback stamp changed")
                db.execute(
                    "INSERT OR IGNORE INTO graph_first_ingress_rejections_v2"
                    "(bot,persona,operation_id,status,permit_json,graph_revision,"
                    "graph_epoch,finish_request_id,finish_request_digest) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    namespace.as_tuple + (operation_id,) + expected)
                if db.execute(
                    "SELECT status,permit_json,graph_revision,graph_epoch,"
                    "finish_request_id,finish_request_digest "
                    "FROM graph_first_ingress_rejections_v2 "
                    "WHERE bot=? AND persona=? AND operation_id=?",
                    namespace.as_tuple + (operation_id,),
                ).fetchone() != expected:
                    raise UnavailableGuard("first ingress rejection identity differs")
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        port = self.__content_fence_v2
        try:
            if port.validate_fence(scope) != permit:
                raise UnavailableGuard("first ingress rejected permit changed")
        except Exception as exc:
            raise FirstIngressOutcomeUnknown(
                operation_id, "first ingress rejected permit unconfirmed; HOLD"
            ) from exc
        try:
            port.finish_fence(scope, request_id=abort_id,
                              request_digest=digest)
        except Exception as exc:
            raise FirstIngressOutcomeUnknown(
                operation_id, "first ingress rejected finish outcome unknown; HOLD"
            ) from exc

    def issue_ingress_authorization(self, bootstrap: object, request, session):
        """Issue first D06+D11 ingress from installation policy and signed facts.

        The policy callback is installed with the coordinator and receives only
        namespace and policy identity. It cannot inspect chat content or the DB.
        A missing callback, observation, or real issuer fails closed.
        """
        from .domains.d06 import D06DomainAdapter, SourceAdmission
        from .runtime.d11_types import runtime_job_key, runtime_outbox_key
        from .runtime.issuers import (
            BudgetLeaseGrant, D02ResourceIssuer, D11BudgetJobIssuer,
            ResourceQuote, install_schema as install_issuer_schema,
        )
        from .runtime_contracts import (
            RUNTIME_SCHEMA, CommandEnvelope, OperationIdentity,
            VersionGuard, VersionedRef,
        )

        self._admin(bootstrap)
        if not isinstance(request, IngressIssuanceRequest):
            raise TypeError("typed ingress issuance request required")
        if not isinstance(getattr(session, "authority", None), AuthorityContext) or \
                getattr(session, "lease", None) is None:
            raise TypeError("ingress authority session required")
        authority = session.authority
        self._authorize(session.lease, authority, frozenset({"d06", "d11"}))
        if authority.capability_ref != _operation_capability_ref(
                authority.namespace, authority.actor, authority.issuer_domain,
                frozenset({"d06", "d11"}), authority.activation_generation,
                request.operation_id):
            raise AuthorityDenied("ingress lease is not scoped to this operation")
        if (authority.issuer_domain != "d06" or authority.purpose != "context"
                or authority.namespace != request.host.namespace
                or authority.audience != (request.host.conversation_ref,)
                or not {"event", "activity"}.issubset(authority.owner_scope)):
            raise AuthorityDenied("ingress session differs from trusted host scope")
        if (type(self.__d02_issuer) is not D02ResourceIssuer
                or type(self.__d11_issuer) is not D11BudgetJobIssuer
                or self.__d11_issuer.resource_issuer is not self.__d02_issuer
                or self.__ingress_policy is None):
            raise UnavailableGuard("real D02/D11 issuers and ingress policy are required")
        host = request.host
        namespace = host.namespace
        admission = request.admission
        expected_admission = SourceAdmission(
            host.lineage.source_ref, host.text, host.sender_ref,
            host.lineage.source_kind, "reported",
            host.lineage.evidence_eligibility,
            host.lineage.internal_activity_actuality,
            host.occurred_at, host.learned_at,
            host.lineage.provenance_family,
            (host.conversation_ref,), ("context", "consolidation"),
        )
        if (host.lineage.content_reality != "external_report"
                or admission != expected_admission
                or admission.parent_source_ids
                or request.candidate != D06DomainAdapter(namespace).admit_source(admission)):
            raise AuthorityDenied("ingress source differs from canonical host report")
        digest = hashlib.sha256(
            ("sylanne3.host-ingress.v1:" + host.lineage.source_ref).encode("ascii")
        ).hexdigest()
        if (request.activity_id != "ingress-" + digest[:24]
                or request.operation_id != "host-ingress-" + digest[:32]
                or request.job_id != "encode-" + digest[:24]
                or request.outbox_id != "encode-outbox-" + digest[:24]
                or request.payload_ref != host.lineage.source_ref
                or request.idempotency_key != "host-ingress:" + digest
                or request.job_ref != runtime_job_key(
                    *namespace.as_tuple, request.activity_id, request.job_id).token
                or request.outbox_ref != runtime_outbox_key(
                    *namespace.as_tuple, request.activity_id, request.outbox_id).token):
            raise AuthorityDenied("ingress runtime refs differ from canonical identity")
        request_digest = canonical_digest(request)
        source = source_key(*namespace.as_tuple, admission.source_id)
        access = access_key(*namespace.as_tuple, admission.source_id)
        keys = (source, access, self._parse_ref(request.job_ref, namespace),
                self._parse_ref(request.outbox_ref, namespace))
        store = self.__store
        with self._content_fence(namespace, authority.activation_generation, "write"):
            with store._lock:
                store._ensure_open()
                store._db.execute("BEGIN IMMEDIATE")
                try:
                    db = store._db
                    self._admit_content(namespace, authority.activation_generation,
                                        "write", tuple(key.token for key in keys))
                    if self._version(db, namespace, "activation", "current") != str(
                            authority.activation_generation):
                        raise StaleRead("activation generation changed")
                    observation = db.execute(
                        "SELECT content_fingerprint,learned_at FROM ingress_first_observations "
                        "WHERE bot=? AND persona=? AND operation_id=?",
                        namespace.as_tuple + (request.operation_id,),
                    ).fetchone()
                    if observation is None:
                        raise UnavailableGuard("canonical first observation is absent")
                    if (observation[0] != ingress_host_fingerprint(host)
                            or observation[1] != host.learned_at):
                        raise EventConflict("ingress content or canonical learned time changed")
                    install_issuer_schema(db)
                    db.execute("""CREATE TABLE IF NOT EXISTS runtime_ingress_issuance(
                        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
                        activation_generation INTEGER NOT NULL,
                        request_digest TEXT NOT NULL, policy_json TEXT NOT NULL,
                        quote_id TEXT NOT NULL, grant_id TEXT NOT NULL,
                        guard_json TEXT NOT NULL,
                        PRIMARY KEY(bot,persona,operation_id))""")
                    prior = db.execute(
                        "SELECT activation_generation,request_digest,policy_json,"
                        "quote_id,grant_id,guard_json "
                        "FROM runtime_ingress_issuance WHERE bot=? AND persona=? "
                        "AND operation_id=?",
                        namespace.as_tuple + (request.operation_id,),
                    ).fetchone()
                    if prior is not None and prior[0] != authority.activation_generation:
                        raise StaleRead("ingress issuance activation generation changed")
                    if prior is not None and prior[1] != request_digest:
                        raise EventConflict("ingress operation request changed")
                    if prior is None:
                        policy = self.__ingress_policy(namespace, authority.provider_policy_ref)
                        if not isinstance(policy, IngressIssuancePolicy):
                            raise UnavailableGuard("typed installed ingress policy unavailable")
                        quote_id = "ingress-q-" + hashlib.sha256(
                            canonical_json([*namespace.as_tuple, request.operation_id]).encode()
                        ).hexdigest()[:40]
                        grant_id = "ingress-g-" + hashlib.sha256(
                            canonical_json([*namespace.as_tuple,
                                            policy.parent_budget_lease_ref,
                                            authority.provider_policy_ref]).encode()
                        ).hexdigest()[:40]
                        epochs = db.execute(
                            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
                            "WHERE bot=? AND persona=?", namespace.as_tuple,
                        ).fetchone() or (0, 0)
                        guard_data = {
                            "access_epoch": epochs[0], "delete_epoch": epochs[1],
                            "scheme": self._version(db, namespace, "scheme", "current"),
                            "operator": self._version(db, namespace, "operator", "current"),
                            "policy": self._version(db, namespace, "policy", "current"),
                        }
                        for key in keys:
                            if db.execute("SELECT 1 FROM graph_atoms WHERE token=?",
                                          (key.token,)).fetchone() is not None:
                                raise StaleRead("first ingress atom already exists")
                        lease = get_budget_lease(db, policy.parent_budget_lease_ref)
                        if (lease.state != "active" or
                                (lease.bot_id, lease.persona_id) != namespace.as_tuple):
                            raise UnavailableGuard("existing active parent budget required")
                        if any(amount > lease.limits.get(name, 0)
                               for name, amount in policy.grant_ceiling.items()):
                            raise UnavailableGuard("installation grant exceeds parent budget limit")
                        if any(amount > lease.limits.get(name, 0)
                               - lease.used.get(name, 0)
                               - lease.reserved.get(name, 0)
                               - lease.unconfirmed.get(name, 0)
                               for name, amount in policy.ceiling.items()):
                            raise UnavailableGuard("parent budget has insufficient available capacity")
                        grant = BudgetLeaseGrant(
                            grant_id, 1, *namespace.as_tuple, lease.lease_id,
                            lease.currency, policy.grant_ceiling, ("d06.encode_source",),
                            policy.grant_valid_until_utc, authority.provider_policy_ref,
                        )
                        if db.execute("SELECT 1 FROM runtime_budget_grants WHERE lease_id=?",
                                      (lease.lease_id,)).fetchone() is None:
                            self.__d11_issuer.issue_budget_grant(db, grant)
                        elif self.__d11_issuer.current_budget_grant(db, lease.lease_id) != grant:
                            raise AuthorityDenied("existing signed D11 grant differs from ingress policy")
                        quote = ResourceQuote(
                            quote_id, 1, *namespace.as_tuple, request.activity_id,
                            request.operation_id, None, lease.lease_id,
                            "d06.encode_source", policy.snapshot_ref,
                            policy.deadline_utc, policy.resource_ref, request.job_ref,
                            (request.outbox_ref,), (), policy.ceiling, None,
                            policy.deadline_utc,
                        )
                        self.__d02_issuer.issue_quote(db, quote)
                        db.execute(
                            "INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) "
                            "VALUES(?,?,?,?,?)",
                            namespace.as_tuple + ("resource_lease", quote_id, "1"),
                        )
                        db.execute(
                            "INSERT INTO runtime_ingress_issuance VALUES(?,?,?,?,?,?,?,?,?)",
                            namespace.as_tuple + (
                                request.operation_id, authority.activation_generation,
                                request_digest,
                                json.dumps(asdict(policy), sort_keys=True),
                                quote_id, grant_id,
                                json.dumps(guard_data, sort_keys=True)),
                        )
                    else:
                        policy = IngressIssuancePolicy(**json.loads(prior[2]))
                        quote_id, grant_id = prior[3], prior[4]
                        guard_data = json.loads(prior[5])
                    self._admit_ingress_deadline(
                        namespace, request.operation_id,
                        authority.activation_generation, policy.deadline_utc)
                    if (self._version(db, namespace, "scheme", "current") != guard_data["scheme"]
                            or self._version(db, namespace, "operator", "current") != guard_data["operator"]
                            or self._version(db, namespace, "policy", "current") != guard_data["policy"]
                            or self._version(db, namespace, "resource_lease", quote_id) != "1"):
                        raise StaleRead("ingress guard version changed")
                    current_epochs = db.execute(
                        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
                        "WHERE bot=? AND persona=?", namespace.as_tuple,
                    ).fetchone() or (0, 0)
                    if tuple(current_epochs) != (
                            guard_data["access_epoch"], guard_data["delete_epoch"]):
                        raise StaleRead("ingress access or deletion epoch changed")
                    committed = db.execute(
                        "SELECT 1 FROM graph_bundle_operations WHERE bot=? AND persona=? "
                        "AND operation_id=?", namespace.as_tuple + (request.operation_id,),
                    ).fetchone() is not None
                    if not committed:
                        for key in keys:
                            if db.execute("SELECT 1 FROM graph_atoms WHERE token=?",
                                          (key.token,)).fetchone() is not None:
                                raise StaleRead("first ingress atom changed")
                    identity = OperationIdentity(
                        request.activity_id, None, "first", "ingress",
                        request.operation_id, canonical_digest({
                            "input_refs": list(request.candidate.qualification.source_refs),
                        }),
                    )
                    envelope = CommandEnvelope(
                        RUNTIME_SCHEMA, identity, authority,
                        VersionGuard(
                            tuple(GraphVersion(key, 0) for key in keys),
                            (),
                            guard_data["access_epoch"], guard_data["delete_epoch"],
                            store._registry.catalogue_hash,
                            guard_data["scheme"], guard_data["operator"],
                            guard_data["policy"], (), (),
                            (VersionedRef(quote_id, 1),),
                        ),
                        request.candidate.qualification,
                        request.candidate.qualification.source_refs,
                        policy.parent_budget_lease_ref, policy.deadline_utc,
                        policy.monotonic_deadline, policy.character_interval_ref,
                        (host.message_id,),
                    )
                    quote = self.__d02_issuer.qualified_quote(envelope, db)
                    if (quote.quote_id != quote_id or quote.graph_job_ref != request.job_ref
                            or quote.outbox_refs != (request.outbox_ref,)
                            or dict(quote.ceiling) != dict(policy.ceiling)
                            or quote.snapshot_ref != policy.snapshot_ref
                            or quote.resource_ref != policy.resource_ref):
                        raise AuthorityDenied("signed D02 quote differs from durable ingress policy")
                    grant = self.__d11_issuer.current_budget_grant(
                        db, policy.parent_budget_lease_ref)
                    if (grant.grant_id != grant_id
                            or dict(grant.max_ceiling) != dict(policy.grant_ceiling)
                            or grant.valid_until_utc != policy.grant_valid_until_utc
                            or grant.policy_ref != authority.provider_policy_ref):
                        raise AuthorityDenied("signed D11 grant differs from durable ingress policy")
                    current_lease = get_budget_lease(db, policy.parent_budget_lease_ref)
                    if not committed and any(
                            amount > current_lease.limits.get(name, 0)
                            - current_lease.used.get(name, 0)
                            - current_lease.reserved.get(name, 0)
                            - current_lease.unconfirmed.get(name, 0)
                            for name, amount in policy.ceiling.items()):
                        raise UnavailableGuard("parent budget has insufficient available capacity")
                    job = self.__d11_issuer.job_for(envelope, db)
                    if (job.job_id != request.job_id or
                            job.work_kind != "d06.encode_source"):
                        raise AuthorityDenied("D11 job differs from ingress encoding work")
                    db.execute("COMMIT")
                    return IngressAuthorizationResult(envelope, session.lease, job)
                except BaseException:
                    if store._db.in_transaction:
                        store._db.execute("ROLLBACK")
                    raise

    def reserve_and_schedule(self, envelope, lease: object) -> tuple[BudgetReceipt, PersistentJob]:
        """Reserve before an external effect and persist its runnable job atomically.

        The D02/D11 issuers are trusted host dependencies. A command envelope
        alone is never permission to spend or schedule work.
        """
        authority = envelope.authority
        self._authorize(lease, authority, frozenset())
        if (not callable(getattr(self.__d02_issuer, "authorize_schedule", None))
                or not callable(getattr(self.__d11_issuer, "admit_schedule", None))):
            raise UnavailableGuard("D02 and D11 schedule issuers are required")
        namespace = authority.namespace
        store = self.__store
        with self._content_fence(namespace, authority.activation_generation, "write"):
            with store._lock:
                store._ensure_open()
                self._admit_content(namespace, authority.activation_generation, "write",
                                    tuple(item.key.token for item in
                                          envelope.version_guard.read_versions))
                store._db.execute("BEGIN IMMEDIATE")
                try:
                    self._check_guard(store._db, SimpleNamespace(envelope=envelope))
                    if self.__d02_issuer.authorize_schedule(envelope, store._db) is not True:
                        raise AuthorityDenied("D02 did not authorize scheduling resources")
                    admission = self.__d11_issuer.admit_schedule(envelope, store._db)
                    if not isinstance(admission, ScheduleAdmission):
                        raise AuthorityDenied("D11 did not issue a typed schedule admission")
                    budget, job = admission.budget, admission.job
                    if not isinstance(budget, BudgetAdmission) or not isinstance(job, PersistentJob):
                        raise AuthorityDenied("D11 schedule admission is incomplete")
                    if (budget.lease_id != envelope.parent_budget_lease_ref
                            or budget.pre_reserved or budget.settle_now
                            or budget.reservation_operation_id is not None):
                        raise AuthorityDenied("schedule must reserve the command budget once")
                    current = get_budget_lease(store._db, budget.lease_id)
                    if (current.state != "active" or current.version != budget.expected_version
                            or (current.bot_id, current.persona_id) != namespace.as_tuple):
                        raise StaleRead("D11 schedule budget lease is stale")
                    identity = envelope.identity
                    if ((job.bot_id, job.persona_id) != namespace.as_tuple
                            or job.operation_id != identity.operation_id
                            or job.activity_id != identity.activity_id
                            or job.effect_id != identity.effect_id
                            or job.budget_ref != budget.lease_id
                            or job.phase not in {"queued", "waiting"}):
                        raise AuthorityDenied("D11 schedule job identity differs from command")
                    digest = budget_operation_digest(envelope, budget.lease_id,
                                                     budget.ceiling)
                    receipt = reserve_budget(store._db, budget.lease_id,
                                             identity.operation_id, digest, budget.ceiling)
                    job_operation = "job:" + hashlib.sha256(
                        (identity.operation_id + job.job_id).encode("utf-8")
                    ).hexdigest()[:32]
                    persisted = create_job(store._db, job, job_operation, digest)
                    store._db.execute("COMMIT")
                    return receipt, persisted
                except BaseException:
                    store._db.execute("ROLLBACK")
                    raise

    def acquire_persistent_job(self, authority: AuthorityContext, lease: object,
                               job_id: str, *, now_utc: str,
                               lease_seconds: int) -> PersistentJob:
        self._authorize(lease, authority, frozenset())
        return self._mutate_job(authority, job_id, lambda db: acquire_job(
            db, job_id, authority.actor, now_utc=now_utc,
            lease_seconds=lease_seconds))

    def cancel_persistent_job(self, authority: AuthorityContext, lease: object,
                              job_id: str, operation_id: str,
                              digest: str) -> PersistentJob:
        self._authorize(lease, authority, frozenset())
        return self._mutate_job(authority, job_id, lambda db: cancel_job(
            db, job_id, operation_id, digest))

    def _mutate_job(self, authority: AuthorityContext, job_id: str, mutation):
        namespace = authority.namespace
        store = self.__store
        with self._content_fence(namespace, authority.activation_generation, "write"):
            with store._lock:
                store._ensure_open()
                self._admit_content(namespace, authority.activation_generation, "write")
                store._db.execute("BEGIN IMMEDIATE")
                try:
                    if self._version(store._db, namespace, "activation", "current") != str(
                            authority.activation_generation):
                        raise StaleRead("activation generation changed")
                    job = get_job(store._db, job_id)
                    if (job.bot_id, job.persona_id) != namespace.as_tuple:
                        raise AuthorityDenied("job crosses namespace")
                    result = mutation(store._db)
                    store._db.execute("COMMIT")
                    return result
                except BaseException:
                    store._db.execute("ROLLBACK")
                    raise

    def _admit_runtime_bundle(self, db, bundle: DomainBundle, *,
                              now_utc: float | None = None) -> RuntimeAdmission:
        """Apply D02/D11 decisions in the graph's existing SQLite transaction."""
        if self.__d02_issuer is None or self.__d11_issuer is None:
            raise UnavailableGuard("D02 and D11 runtime issuers are required")
        time_kwargs = {} if now_utc is None else {"now_utc": now_utc}
        if self.__d02_issuer.authorize_resources(
                bundle, db, **time_kwargs) is not True:
            raise AuthorityDenied("D02 resource admission did not approve the bundle")
        admission = self.__d11_issuer.admit_runtime(bundle, db, **time_kwargs)
        if not isinstance(admission, RuntimeAdmission):
            raise AuthorityDenied("D11 did not issue a typed runtime admission")
        envelope = bundle.envelope
        identity = envelope.identity
        budget = admission.budget
        if not isinstance(budget, BudgetAdmission):
            raise AuthorityDenied("D11 budget admission is missing")
        if budget.lease_id != envelope.parent_budget_lease_ref:
            raise AuthorityDenied("D11 budget lease differs from the command parent")
        lease = get_budget_lease(db, budget.lease_id)
        if (lease.state != "active" or
                (lease.bot_id, lease.persona_id) != envelope.authority.namespace.as_tuple
                or type(budget.expected_version) is not int
                or budget.expected_version != lease.version):
            raise StaleRead("D11 budget admission has stale lease version")
        budget_operation_id = budget.reservation_operation_id or identity.operation_id
        budget_digest = budget_operation_digest(envelope, budget.lease_id,
                                                budget.ceiling)
        if budget.pre_reserved:
            row = db.execute(
                "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
                "WHERE lease_id=? AND operation_id=?",
                (budget.lease_id, budget_operation_id),
            ).fetchone()
            if (row is None or row[0] != budget_digest
                    or json.loads(row[1]) != budget.ceiling
                    or row[2] not in {"reserved", "unknown"}):
                raise UnavailableGuard("matching durable budget reservation is absent")
        else:
            if budget.reservation_operation_id is not None:
                raise AuthorityDenied("inline reserve must use the bundle operation ID")
            reserve_budget(db, budget.lease_id, budget_operation_id,
                           budget_digest, budget.ceiling)
        if budget.settle_now:
            if len(bundle.d11_cost_settlement_refs) != 1:
                raise AuthorityDenied("settlement requires one D11 graph cost receipt")
            cost_receipt = settle_budget(db, budget.lease_id, budget_operation_id,
                                         budget_digest, budget.actual,
                                         execution_revoked=budget.execution_revoked)
            self._verify_cost_atom(db, bundle, lease, budget, budget_operation_id,
                                   cost_receipt)
        elif bundle.d11_cost_settlement_refs:
            raise AuthorityDenied("D11 graph cost receipt lacks budget settlement")
        jobs = admission.jobs
        if (not isinstance(jobs, tuple) or
                any(not isinstance(binding, JobBinding) for binding in jobs)):
            raise AuthorityDenied("D11 job bindings must be typed")
        if (len({item.graph_job_ref for item in jobs}) != len(jobs)
                or {item.graph_job_ref for item in jobs}
                != set(bundle.persistent_job_refs)):
            raise AuthorityDenied("durable jobs do not match graph job refs")
        outbox_refs = tuple(ref for item in jobs for ref in item.outbox_refs)
        if len(set(outbox_refs)) != len(outbox_refs) or set(outbox_refs) != set(bundle.outbox_refs):
            raise AuthorityDenied("outbox refs lack a unique durable job binding")
        for binding in jobs:
            job = binding.job
            if (job.operation_id != identity.operation_id
                    or job.activity_id != identity.activity_id
                    or job.effect_id != identity.effect_id
                    or (job.bot_id, job.persona_id) != envelope.authority.namespace.as_tuple
                    or job.budget_ref != budget.lease_id):
                raise AuthorityDenied("D11 durable job identity differs from bundle")
            if budget.pre_reserved:
                existing = get_job(db, job.job_id)
                if (existing.operation_id != job.operation_id
                        or existing.activity_id != job.activity_id
                        or existing.budget_ref != job.budget_ref
                        or (existing.bot_id, existing.persona_id)
                        != (job.bot_id, job.persona_id)
                        or existing.phase in {"draining", "cancelled", "failed"}):
                    raise UnavailableGuard("pre-reserved job is stale or cancelled")
            else:
                if job.phase not in {"queued", "waiting"}:
                    raise AuthorityDenied("new durable job must start queued or waiting")
                job_operation = "job:" + hashlib.sha256(
                    (bundle.digest + job.job_id).encode("utf-8")).hexdigest()[:32]
                create_job(db, job, job_operation, bundle.digest)
                existing = job
            if envelope.authority.worker_fence is not None and (
                    existing.phase != "running"
                    or existing.lease_holder != envelope.authority.actor
                    or existing.fence != envelope.authority.worker_fence
                    or existing.cancel_epoch != 0):
                raise UnavailableGuard("worker result lost its job fence")
        if envelope.authority.worker_fence is not None and not jobs:
            raise UnavailableGuard("worker result has no durable job to fence")
        return admission

    @staticmethod
    def _verify_cost_atom(db, bundle, lease, budget, operation_id, receipt):
        """The graph cost atom must agree with the committed budget receipt."""
        ref = bundle.d11_cost_settlement_refs[0]
        writes = (write for proposal in bundle.proposals
                  for write in proposal.typed_writes)
        value = next((write.value for write in writes if write.key.token == ref), None)
        if not isinstance(value, dict):
            raise AuthorityDenied("D11 cost graph atom is missing")
        row = db.execute(
            "SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? "
            "AND persona_id=? AND operation_id=? AND phase='settle'",
            (lease.bot_id, lease.persona_id, operation_id),
        ).fetchone()
        if row is None:
            raise UnavailableGuard("D11 budget settlement receipt is missing")
        receipt_digest = hashlib.sha256(row[0].encode("utf-8")).hexdigest()
        identity = bundle.envelope.identity
        expected = {
            "bot_id": lease.bot_id, "persona_id": lease.persona_id,
            "activity_id": identity.activity_id,
            "bundle_operation_id": identity.operation_id,
            "effect_id": identity.effect_id,
            "lease_id": lease.lease_id, "currency": lease.currency,
            "cost_operation_id": operation_id,
            "status": receipt.status, "ceiling": budget.ceiling,
            "actual": budget.actual,
            "unconfirmed": budget.ceiling if budget.actual is None else {},
            "budget_phase": "settle", "budget_operation_id": operation_id,
            "budget_receipt_digest": receipt_digest,
        }
        if any(value.get(key) != item for key, item in expected.items()):
            raise AuthorityDenied("D11 cost graph atom differs from budget settlement")

    def read_snapshot(self, authority: AuthorityContext, lease: object,
                      keys) -> GraphSnapshot:
        if not isinstance(authority, AuthorityContext):
            raise TypeError("authority required")
        keys = tuple(keys)
        if not keys:
            raise ValueError("read_snapshot requires explicit keys")
        if any(NamespaceId.from_key(key) != authority.namespace
               or key.owner.kind not in authority.owner_scope for key in keys):
            raise AuthorityDenied("read key is outside authorized namespace or owner scope")
        domains = frozenset(self.__store._registry.spec(key.type_name).writer_domain
                            for key in keys)
        self._authorize(lease, authority, domains, owner_read=True)
        if isinstance(self.__store, ProductionGraphStore) and self.__content_fence_v2 is not None:
            return self._read_v2(authority, lambda: GraphStore.graph_snapshot(
                self.__store, keys, _capability=self.__graph_capability),
                owner_binding=self.__owner_leases.get(lease),
                owner_session_proof=self.__owner_session_proofs.get(lease))
        with self._content_fence(authority.namespace, authority.activation_generation, "read"):
            store = self.__store
            with store._lock:
                self._admit_content(authority.namespace, authority.activation_generation,
                                    "read", tuple(key.token for key in keys))
                return GraphStore.graph_snapshot(
                    store, keys, _capability=self.__graph_capability)

    def query(self, authority: AuthorityContext, lease: object, *,
              type_names: tuple[str, ...], owner_kind: str, **filters):
        if not isinstance(authority, AuthorityContext):
            raise TypeError("authority required")
        if not type_names or owner_kind not in authority.owner_scope:
            raise AuthorityDenied("query must select authorized types and owner kind")
        if filters.get("include_invalid"):
            raise AuthorityDenied("ordinary content query cannot include invalid atoms")
        domains = frozenset(self.__store._registry.spec(name).writer_domain
                            for name in type_names)
        self._authorize(lease, authority, domains, owner_read=True)
        if isinstance(self.__store, ProductionGraphStore) and self.__content_fence_v2 is not None:
            return self._read_v2(authority, lambda: GraphStore.graph_query(
                self.__store, *authority.namespace.as_tuple, type_names=type_names,
                owner_kind=owner_kind, _capability=self.__graph_capability, **filters),
                owner_binding=self.__owner_leases.get(lease),
                owner_session_proof=self.__owner_session_proofs.get(lease))
        with self._content_fence(authority.namespace, authority.activation_generation, "read"):
            store = self.__store
            with store._lock:
                # A range query has no finite content reference set. After any
                # deletion it remains closed until a D06 range-closure proof exists.
                self._admit_content(authority.namespace, authority.activation_generation,
                                    "read")
                return GraphStore.graph_query(
                    store, *authority.namespace.as_tuple, type_names=type_names,
                    owner_kind=owner_kind, _capability=self.__graph_capability, **filters)

    def get_operation(self, authority: AuthorityContext, lease: object,
                      operation_id: str) -> CommitReceipt | None:
        """Resolve an uncertain commit from the durable business operation ledger."""
        if not isinstance(authority, AuthorityContext) or not operation_id:
            raise ValueError("valid authority and operation ID are required")
        self._authorize(lease, authority, frozenset())
        if isinstance(self.__store, ProductionGraphStore) and self.__content_fence_v2 is not None:
            return self._read_v2(authority, lambda: self._get_operation_fenced(
                authority, operation_id, v2=True))
        with self._content_fence(authority.namespace, authority.activation_generation, "read"):
            return self._get_operation_fenced(authority, operation_id)

    def get_dispatch_candidate_evidence(self, authority: AuthorityContext,
                                        lease: object, operation_id: str):
        """Rebuild a source-HOLD candidate from committed historical graph atoms."""
        if not isinstance(authority, AuthorityContext) or not operation_id:
            raise ValueError("authority and operation ID are required")
        self._authorize(lease, authority, frozenset({"d08", "d09"}))
        reader = lambda: self._get_dispatch_candidate_evidence_locked(
            authority.namespace, operation_id)
        if (isinstance(self.__store, ProductionGraphStore)
                and self.__content_fence_v2 is not None):
            return self._read_v2(authority, reader)
        with self._content_fence(authority.namespace, authority.activation_generation, "read"):
            with self.__store._lock:
                self._admit_content(authority.namespace,
                                    authority.activation_generation, "read")
                return reader()

    def _get_dispatch_candidate_evidence_locked(self, namespace, operation_id):
        from .domains.d08 import GoalExecutionProvider
        from .graph_types import AtomKey, GraphWrite

        store = self.__store
        db = store._db
        row = db.execute(
            "SELECT activity_id,effect_id,receipt_json FROM graph_bundle_operations "
            "WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (operation_id,),
        ).fetchone()
        if row is None:
            return None
        data = json.loads(row[2]).get("dispatch_candidate")
        if data is None:
            return None
        if (type(data) is not dict or data.get("schema") != "sylanne.d11.dispatch_candidate.v1"
                or data.get("status") not in {"source_hold", "source_qualified"}
                or type(data.get("refs")) is not list or len(data["refs"]) != 4):
            raise UnavailableGuard("durable dispatch candidate receipt is invalid")
        event = db.execute(
            "SELECT revisions,epoch_revision,reads FROM graph_events WHERE bot=? "
            "AND persona=? AND session=? AND event_id=?",
            namespace.as_tuple + (row[0], operation_id),
        ).fetchone()
        if event is None or event[1] != data.get("graph_epoch"):
            raise UnavailableGuard("dispatch candidate graph event is missing")
        revisions = {item.key.token: item.revision
                     for item in GraphStore._version_rows(event[0])}
        typed_writes = []
        for position, item in enumerate(data["refs"]):
            if (type(item) is not list or len(item) != 2
                    or type(item[0]) is not str or type(item[1]) is not int
                    or item[1] < 1 or revisions.get(item[0]) != item[1]):
                raise UnavailableGuard("dispatch candidate write version differs")
            key = AtomKey.from_token(item[0])
            expected_type = (
                "d08.action_intent.v1", "d08.action_schema.v1",
                "d08.communication_intent_grant.v1", "d09.verified_segment_batch.v1",
            )[position]
            if key.type_name != expected_type:
                raise UnavailableGuard("dispatch candidate graph type differs")
            history = db.execute(
                "SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
                "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
                (item[0], item[1]) + namespace.as_tuple + (row[0], operation_id),
            ).fetchone()
            if history is None or history[1] != 1:
                raise UnavailableGuard("dispatch candidate history is unavailable")
            typed_writes.append(("d09" if position == 3 else "d08",
                                 GraphWrite(key, json.loads(history[0]))))
        action = next(spec for spec in GoalExecutionProvider().register_types()
                      if spec.name == "d08.action_intent.v1").validator(
                          typed_writes[0][1].value)
        if (action.identity.operation_id != operation_id
                or action.identity.activity_id != row[0]
                or action.identity.effect_id != row[1]):
            raise UnavailableGuard("dispatch candidate operation identity differs")
        candidate = validate_dispatch_candidate_writes(
            tuple(typed_writes), namespace=namespace, identity=action.identity,
            read_versions=GraphStore._version_rows(event[2]),
            source_refs=tuple(data.get("source_refs", ())),
            access_epoch=data.get("access_epoch"),
            delete_epoch=data.get("delete_epoch"),
            query_epoch=data.get("query_epoch"),
        )
        if candidate is not None and data["status"] == "source_qualified":
            read_versions = GraphStore._version_rows(event[2])
            if (data.get("graph_epoch") != candidate.query_epoch + 1
                    or type(data.get("source_audience")) is not list
                    or type(data.get("source_proof_versions")) is not list):
                raise UnavailableGuard("dispatch source proof graph epoch differs")
            atoms = []
            for read in read_versions:
                if read.revision == 0:
                    atoms.append(GraphAtom(read.key, 0, {}, False))
                    continue
                history = db.execute(
                    "SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
                    (read.key.token, read.revision),
                ).fetchone()
                if history is None:
                    raise UnavailableGuard("dispatch source proof history is unavailable")
                atoms.append(GraphAtom(read.key, read.revision, json.loads(history[0]),
                                       bool(history[1])))
            candidate = qualify_dispatch_candidate_sources(
                candidate, action, GraphSnapshot(tuple(atoms), (
                    NamespaceEpoch(*namespace.as_tuple, candidate.query_epoch),)),
                audience=tuple(data["source_audience"]),
                batch_audiences=tuple(typed_writes[3][1].value["audiences"]),
                current_barrier_confirmed=True,
                valid_until=typed_writes[3][1].value["valid_until"],
            )
            if (candidate.status != "source_qualified"
                    or [list(item) for item in candidate.source_proof_versions]
                    != data["source_proof_versions"]
                    or candidate.source_proof_digest != data.get("source_proof_digest")):
                raise UnavailableGuard("dispatch source proof differs from graph history")
        if candidate is None or candidate.digest != data.get("digest"):
            raise UnavailableGuard("dispatch candidate digest differs")
        if isinstance(store, ProductionGraphStore):
            metadata = self._v2_graph_stamp(namespace)[0]
            if (data.get("graph_incarnation") != metadata.requirements.graph_incarnation
                    or type(data.get("graph_revision")) is not int
                    or data["graph_revision"] > metadata.graph_revision):
                raise UnavailableGuard("dispatch candidate recovery stamp differs")
        return DispatchCandidateRecoveryV1(
            candidate, tuple((ref, revision) for ref, revision in data["refs"]),
            data["graph_epoch"], data["graph_incarnation"], data["graph_revision"],
        )

    def _get_operation_fenced(self, authority: AuthorityContext,
                              operation_id: str, *, v2: bool = False) -> CommitReceipt | None:
        namespace = authority.namespace
        store = self.__store
        with store._lock:
            store._ensure_open()
            if not v2:
                self._admit_content(namespace, authority.activation_generation, "read")
                if self._version(store._db, namespace, "activation", "current") != str(
                        authority.activation_generation):
                    raise StaleRead("activation generation changed")
            row = store._db.execute(
                "SELECT digest,activity_id,effect_id,commit_seq,receipt_json "
                "FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                namespace.as_tuple + (operation_id,),
            ).fetchone()
            if row is None:
                return None
            graph = store._db.execute(
                "SELECT reads,revisions,epoch_revision FROM graph_events WHERE bot=? "
                "AND persona=? AND session=? AND event_id=?",
                namespace.as_tuple + (row[1], operation_id),
            ).fetchone()
            if graph is None:
                raise EventConflict("bundle operation has no graph event")
            data = json.loads(row[4])
            return CommitReceipt(
                "committed", operation_id, row[0], row[1], row[2], row[3],
                GraphStore._version_rows(graph[0]), GraphStore._version_rows(graph[1]),
                (NamespaceEpoch(*namespace.as_tuple, graph[2]),),
                tuple(data["ledger_refs"]), tuple(data["outbox_refs"]),
            )

    def _check_product_advance(self, db, bundle: DomainBundle,
                               snapshot: GraphSnapshot, writes: tuple) -> dict | None:
        """Bind an advance to current D04 state before any business write."""
        if not isinstance(self.__store, ProductionGraphStore):
            if bundle.product_advance is not None:
                raise UnavailableGuard("product advance evidence requires production graph authority")
            return None
        state_items = tuple(write for write in writes if write.key.type_name in {
            "d04.feeling_state.v1", "d04.mood_field.v1"})
        state_writes = {write.key.type_name: write for write in state_items}
        if len(state_writes) != len(state_items):
            raise AuthorityDenied("multiple D04 state writes of the same type")
        advance = False
        for write in state_writes.values():
            current = snapshot.get(write.key)
            if current is None:
                raise StaleRead("D04 write key is absent from the complete read set")
            if current.revision == 0:
                # Initial state creation has no preceding numerical interval.
                continue
            if not current.valid:
                raise StaleRead("D04 state is invalid")
            old, new = current.value, write.value
            if new["revision"] != old["revision"] + 1:
                raise StaleRead("D04 state revision is not the next revision")
            if new["cursor"] < old["cursor"]:
                raise StaleRead("D04 state cursor moved backwards")
            if new["cursor"] == old["cursor"]:
                semantic_fields = ({"meaning_refs", "interpretation_refs",
                                    "active_driver_refs", "historical_source_refs", "revision"}
                                   if write.key.type_name == "d04.feeling_state.v1"
                                   else {"source_refs", "revision"})
                if any(new.get(name) != old.get(name)
                       for name in set(old) | set(new) if name not in semantic_fields):
                    raise AuthorityDenied("same-cursor D04 correction changed numerical state")
            else:
                advance = True
        evidence = bundle.product_advance
        if not advance:
            if evidence is not None:
                raise AuthorityDenied("product advance evidence has no existing interval to advance")
            if bundle.envelope.identity.phase == "d11.product_advance_candidate.v1":
                raise AuthorityDenied("product advance phase has no numerical interval")
            return None
        if evidence is None:
            raise UnavailableGuard("D04 time advance requires product numeric evidence")
        if (type(evidence) is not ProductAdvanceEvidenceV1
                or bundle.envelope.identity.phase != "d11.product_advance_candidate.v1"
                or set(state_writes) != {"d04.feeling_state.v1", "d04.mood_field.v1"}):
            raise AuthorityDenied("product advance requires one feeling and one mood write")
        feeling = state_writes["d04.feeling_state.v1"]
        mood = state_writes["d04.mood_field.v1"]
        if (feeling.key.token != evidence.feeling_ref
                or mood.key.token != evidence.mood_ref):
            raise AuthorityDenied("product advance refs differ from D04 writes")
        old_feeling, old_mood = snapshot.get(feeling.key), snapshot.get(mood.key)
        if (old_feeling is None or old_mood is None
                or not old_feeling.valid or not old_mood.valid
                or old_feeling.revision == 0 or old_mood.revision == 0
                or old_feeling.value["cursor"] != evidence.from_cursor
                or old_mood.value["cursor"] != evidence.from_cursor
                or feeling.value["cursor"] != evidence.to_cursor
                or mood.value["cursor"] != evidence.to_cursor
                or feeling.value["process_id"] != old_feeling.value["process_id"]
                or mood.value["mood_id"] != old_mood.value["mood_id"]):
            raise StaleRead("product advance does not follow the current joint state")
        candidate_digest = canonical_digest({
            "schema": "sylanne.d04.product.advance.candidate.v1",
            "feeling": {"ref": feeling.key.token, "value": feeling.value},
            "mood": {"ref": mood.key.token, "value": mood.value},
        })
        if evidence.candidate_digest != candidate_digest:
            raise AuthorityDenied("product evidence does not bind the exact D04 writes")
        namespace = bundle.envelope.authority.namespace
        parent = db.execute(
            "SELECT process_id,feeling_ref,mood_ref,to_cursor,next_error_bound "
            "FROM graph_product_advances WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (evidence.parent_operation_id,),
        ).fetchone()
        if (parent is None or parent[0] != old_feeling.value["process_id"]
                or (parent[1], parent[2]) != (evidence.feeling_ref, evidence.mood_ref)
                or parent[3] != evidence.from_cursor
                or parent[4] != evidence.previous_error_bound):
            raise StaleRead("product advance has no matching committed error predecessor")
        parent_event = db.execute(
            "SELECT e.revisions FROM graph_events e JOIN graph_bundle_operations b "
            "ON b.bot=e.bot AND b.persona=e.persona AND b.activity_id=e.session "
            "AND b.operation_id=e.event_id WHERE b.bot=? AND b.persona=? "
            "AND b.operation_id=?", namespace.as_tuple + (evidence.parent_operation_id,),
        ).fetchone()
        if parent_event is None:
            raise StaleRead("product advance parent graph receipt is missing")
        parent_versions = dict(json.loads(parent_event[0]))
        if (parent_versions.get(evidence.feeling_ref) != old_feeling.revision
                or parent_versions.get(evidence.mood_ref) != old_mood.revision):
            raise StaleRead("product advance parent is not the current joint state")
        conflict = db.execute(
            "SELECT 1 FROM graph_product_advances WHERE bot=? AND persona=? "
            "AND process_id=? AND (replay_key=? OR "
            "(from_cursor<? AND to_cursor>?)) LIMIT 1",
            namespace.as_tuple + (old_feeling.value["process_id"], evidence.replay_key,
                                  evidence.to_cursor, evidence.from_cursor),
        ).fetchone()
        if conflict is not None:
            raise EventConflict("product advance replay or interval already committed")
        issuer = self.__product_advance_issuer
        if issuer is None:
            raise UnavailableGuard("trusted product numeric issuer is unavailable")
        # Future issuer verification must be a local, pure check; FFI runs outside
        # this transaction and binds the complete joint input/output digests.
        if issuer.verify(evidence, bundle) is not True:
            raise AuthorityDenied("product numeric issuer did not verify evidence")
        return {**asdict(evidence), "process_id": old_feeling.value["process_id"]}

    def get_dispatch_admission(self, authority: AuthorityContext, lease: object,
                               admission_ref: str) -> DispatchAdmissionReceiptV1 | None:
        """Read a committed D11 admission identity through the normal content fence."""
        self._authorize(lease, authority, frozenset({"d11"}))
        reader = lambda: load_admission(
            self.__store._db, authority.namespace, admission_ref)
        if (isinstance(self.__store, ProductionGraphStore)
                and self.__content_fence_v2 is not None):
            return self._read_v2(authority, reader)
        with self._content_fence(authority.namespace,
                                 authority.activation_generation, "read"):
            with self.__store._lock:
                self._admit_content(authority.namespace,
                                    authority.activation_generation, "read")
                return reader()

    def get_committed_dispatch_request(self, authority: AuthorityContext,
                                       lease: object, admission_ref: str):
        """Recover a historical D11 command, never a current platform send permit."""
        self._authorize(lease, authority, frozenset({"d08", "d09", "d11"}))
        reader = lambda: self._get_committed_dispatch_request_locked(
            authority.namespace, admission_ref)
        if (isinstance(self.__store, ProductionGraphStore)
                and self.__content_fence_v2 is not None):
            return self._read_v2(authority, reader)
        with self._content_fence(authority.namespace,
                                 authority.activation_generation, "read"):
            with self.__store._lock:
                self._admit_content(authority.namespace,
                                    authority.activation_generation, "read")
                return reader()

    def _get_committed_dispatch_request_locked(self, namespace, admission_ref):
        db = self.__store._db
        loaded = load_request(db, namespace, admission_ref)
        if loaded is None:
            return None
        receipt, request = loaded
        admission = receipt.admission
        candidate = self._get_dispatch_candidate_evidence_locked(
            namespace, request.operation_id)
        row = db.execute(
            "SELECT receipt_json FROM graph_bundle_operations "
            "WHERE bot=? AND persona=? AND operation_id=? AND effect_id=?",
            namespace.as_tuple + (request.operation_id, request.effect_id),
        ).fetchone()
        graph_admission = json.loads(row[0]).get("dispatch_admission") if row else None
        if (candidate is None or candidate.evidence.status != "source_qualified"
                or graph_admission != {
                    "schema": admission.schema, "ref": admission_ref,
                    "digest": receipt.receipt_digest,
                }
                or admission.candidate_digest != candidate.evidence.digest
                or admission.batch_digest != candidate.evidence.batch_digest
                or receipt.graph_epoch != candidate.graph_epoch
                or receipt.graph_revision != (
                    candidate.graph_revision if candidate.graph_revision is not None
                    else candidate.graph_epoch)
                or admission.graph_incarnation != (
                    candidate.graph_incarnation or "nonproduction-graphstore")
                or request.payload_ref != dispatch_segment_payload_ref(
                    candidate.evidence.batch_ref, request.segment_index)):
            raise UnavailableGuard("stored dispatch request differs from graph receipt")
        batch_ref, batch_revision = candidate.write_versions[3]
        batch_row = db.execute(
            "SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
            "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
            (batch_ref, batch_revision) + namespace.as_tuple + (
                request.activity_id, request.operation_id),
        ).fetchone()
        if batch_row is None or batch_row[1] != 1:
            raise UnavailableGuard("stored dispatch request batch is unavailable")
        batch = json.loads(batch_row[0])
        index = request.segment_index
        if (type(index) is not int or not 0 <= index < len(batch["segments"])
                or batch["batch_digest"] != admission.batch_digest
                or batch["segments"][index]["effect_id"] != request.effect_id
                or batch["segments"][index]["payload_digest"] != request.payload_digest
                or batch["segments"][index]["segment_authorization_ref"]
                != request.segment_authorization_ref
                or batch["grant_manifest_digest"] != request.segment_manifest_digest
                or len(batch["segments"]) != request.segment_count):
            raise UnavailableGuard("stored dispatch request segment differs")
        return request

    def get_dispatch_text_segment(self, authority: AuthorityContext,
                                  lease: object, request):
        """Read one D09 body through its committed D11 admission and graph fence.

        The route is limited to the AstrBot ingress identity profile. This
        read is content provenance, not a current host send permit.
        """
        from .dispatch_runtime import DispatchRequest

        if type(request) is not DispatchRequest or request.namespace != "/".join(
                authority.namespace.as_tuple):
            raise ValueError("dispatch request namespace differs")
        self._authorize(lease, authority, frozenset({"d08", "d09", "d11"}))
        reader = lambda: self._get_dispatch_text_segment_locked(
            authority.namespace, request)
        if (isinstance(self.__store, ProductionGraphStore)
                and self.__content_fence_v2 is not None):
            return self._read_v2(authority, reader)
        with self._content_fence(authority.namespace,
                                 authority.activation_generation, "read"):
            with self.__store._lock:
                self._admit_content(authority.namespace,
                                    authority.activation_generation, "read")
                return reader()

    def _get_dispatch_text_segment_locked(self, namespace, request):
        from .domains.d09 import ClaimKind, ClaimUse, D09ExpressionProvider
        from .runtime.dispatch_candidate import GraphDispatchTextSegmentV1

        db = self.__store._db
        row = db.execute(
            "SELECT admission_ref FROM graph_dispatch_admissions "
            "WHERE bot=? AND persona=? AND operation_id=? AND effect_id=?",
            namespace.as_tuple + (request.operation_id, request.effect_id),
        ).fetchone() if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='graph_dispatch_admissions'"
        ).fetchone() else None
        if row is None:
            return None
        receipt = load_admission(db, namespace, row[0])
        candidate = self._get_dispatch_candidate_evidence_locked(
            namespace, request.operation_id)
        if receipt is None or candidate is None:
            raise UnavailableGuard("dispatch admission or candidate is absent")
        admission = receipt.admission
        evidence = candidate.evidence
        if (evidence.status != "source_qualified"
                or admission.request_digest != canonical_digest(request)
                or admission.candidate_digest != evidence.digest
                or admission.batch_digest != evidence.batch_digest
                or admission.segment_index != request.segment_index
                or admission.payload_digest != request.payload_digest
                or admission.dispatch_generation != request.dispatch_generation
                or admission.graph_incarnation != (
                    candidate.graph_incarnation or "nonproduction-graphstore")
                or receipt.graph_epoch != candidate.graph_epoch
                or request.payload_ref != dispatch_segment_payload_ref(
                    evidence.batch_ref, request.segment_index)):
            raise UnavailableGuard("dispatch text admission differs from graph candidate")
        batch_ref, batch_revision = candidate.write_versions[3]
        batch_row = db.execute(
            "SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
            "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
            (batch_ref, batch_revision) + namespace.as_tuple + (
                request.activity_id, request.operation_id),
        ).fetchone()
        if batch_row is None or batch_row[1] != 1:
            raise UnavailableGuard("committed D09 batch is unavailable")
        batch = json.loads(batch_row[0])
        next(spec for spec in D09ExpressionProvider.register_types()
             if spec.name == "d09.verified_segment_batch.v1").validator(batch)
        index = request.segment_index
        if (type(index) is not int or not 0 <= index < len(batch["segments"])
                or batch_ref != evidence.batch_ref
                or batch["batch_digest"] != evidence.batch_digest
                or batch["scene_ref"] != admission.scene_ref
                or tuple(batch["audiences"]) != admission.audience
                or len(admission.audience) != 1):
            raise UnavailableGuard("D09 batch scope differs from dispatch admission")
        segment = batch["segments"][index]
        if (segment["effect_id"] != request.effect_id
                or segment["payload_digest"] != request.payload_digest
                or segment["segment_authorization_ref"] != request.segment_authorization_ref
                or batch["grant_manifest_digest"] != request.segment_manifest_digest
                or len(batch["segments"]) != request.segment_count):
            raise UnavailableGuard("D09 text segment differs from dispatch command")
        # Ingress freezes platform_ref=[platform_id,platform_name,self_id] and
        # conversation_ref=[UMO,conversation_id]. Rebuild its bot and scene.
        try:
            account = json.loads(admission.account_ref)
            route = json.loads(admission.audience[0])
        except (TypeError, ValueError) as exc:
            raise UnavailableGuard("AstrBot route encoding is unavailable") from exc
        from .host.identity import astrbot_namespace

        if (type(account) is not list or len(account) != 3
                or type(route) is not list or len(route) != 2
                or any(type(item) is not str or not item for item in (*account, *route))
                or admission.destination_ref != admission.audience[0]
                or json.dumps(account, ensure_ascii=True, separators=(",", ":"))
                != admission.account_ref
                or json.dumps(route, ensure_ascii=True, separators=(",", ":")) != admission.audience[0]):
            raise UnavailableGuard("dispatch route is not bound to AstrBot ingress")
        if astrbot_namespace(account[0], account[2], "route-check").bot_id != namespace.bot_id:
            raise UnavailableGuard("dispatch account differs from AstrBot graph namespace")
        from .runtime.first_ingress_v2 import scene_ref_for_conversation

        if scene_ref_for_conversation(
                namespace, admission.account_ref, admission.destination_ref,
        ) != admission.scene_ref:
            raise UnavailableGuard("dispatch scene differs from AstrBot ingress")
        uses = tuple(ClaimUse(item["claim_ref"], item["start"], item["end"],
                              ClaimKind(item["asserted_as"]))
                     for item in segment["claim_uses"])
        return GraphDispatchTextSegmentV1(
            segment["body"], tuple(segment["media_refs"]), uses,
            account[0], account[1], account[2], route[0], route[1],
            admission.scene_ref,
        )

    @staticmethod
    def _dispatch_clock_upper(reading) -> float:
        from .host.v2_fence_port import VerifiedIngressClockV2
        from .runtime.first_ingress_v2 import trusted_upper

        if type(reading) is not VerifiedIngressClockV2:
            raise UnavailableGuard("paired dispatch admission clock is unqualified")
        try:
            return trusted_upper(reading)
        except ValueError as exc:
            raise UnavailableGuard("paired dispatch admission clock is unqualified") from exc

    def _issue_dispatch_admission(self, db, bundle, snapshot, candidate,
                                  action, schema, grant, batch, *,
                                  graph_receipt, v2_write, now_utc, projection,
                                  clock_reading=None):
        """Fail closed unless a host issuer supplies and proves every current fact.

        This is called from the graph receipt hook, after D11's reservation,
        while the ordinary graph write transaction and fence remain active.
        """
        issuer = self.__dispatch_admission_issuer
        if issuer is None:
            return None
        if (candidate.status != "source_qualified"
                or (isinstance(self.__store, ProductionGraphStore)
                    and v2_write is None)):
            raise UnavailableGuard("dispatch admission requires current D06 proof and write fence")
        if projection is None:
            raise UnavailableGuard("dispatch admission lacks complete D03/D05 graph projection")
        for method in ("issue_dispatch_admission", "verify_required_check",
                       "verify_command_provenance", "verify_journal_constraints",
                       "verify_domain_context"):
            if not callable(getattr(issuer, method, None)):
                raise UnavailableGuard("trusted dispatch admission issuer is incomplete")
        envelope = bundle.envelope
        identity = envelope.identity
        graph_incarnation = (
            v2_write[0].requirements.graph_incarnation
            if v2_write is not None else "nonproduction-graphstore"
        )
        if now_utc is None:
            raise UnavailableGuard("trusted dispatch admission clock is unavailable")
        if type(now_utc) not in (int, float) or not math.isfinite(now_utc):
            raise UnavailableGuard("trusted dispatch admission clock is invalid")
        now = float(now_utc)
        issued = issuer.issue_dispatch_admission(
            bundle, snapshot, candidate, db, graph_incarnation=graph_incarnation,
            now_utc=now,
        )
        if (type(issued) is not tuple or len(issued) != 2
                or type(issued[1]) is not DispatchAdmissionV1):
            raise UnavailableGuard("trusted issuer did not produce typed dispatch admission")
        request, admission = issued
        from .domains.d03 import RoleBinding

        current_bindings = []
        for atom in projection.role_bindings:
            value = atom.value
            binding = RoleBinding(**{
                **value, "norm_refs": tuple(value["norm_refs"]),
                "source_refs": tuple(value["source_refs"]),
            })
            if (atom.key.name == binding.role_binding_id
                    and atom.revision == binding.binding_version
                    and binding.status == "active"
                    and binding.scene_ref == batch["scene_ref"]
                    and binding.effective_from <= now
                    and (binding.effective_until is None or now <= binding.effective_until)):
                current_bindings.append(binding)
        if not any(binding.role_binding_id == admission.binding_ref
                   for binding in current_bindings):
            raise UnavailableGuard("dispatch admission lacks a current D03 scene binding")
        from .domains.d05 import BoundaryRule, RelationshipProvider

        current_rules = tuple(BoundaryRule(**{
            **atom.value,
            "source_refs": tuple(atom.value["source_refs"]),
            "communicated_refs": tuple(atom.value["communicated_refs"]),
            "acknowledged_refs": tuple(atom.value["acknowledged_refs"]),
            "exception_refs": tuple(atom.value["exception_refs"]),
        }) for atom in projection.boundary_rules)
        if any(atom.key.name != rule.rule_id
               for atom, rule in zip(projection.boundary_rules, current_rules)):
            raise UnavailableGuard("current D05 boundary identity differs")
        # The transaction-checked projection proves read coverage. This only
        # vetoes explicit deny/conflict; the issuer still owns full D05 approval.
        for audience in envelope.authority.audience:
            boundary = RelationshipProvider().provide_required_check(
                subject_persona_ref=f"persona:{envelope.authority.namespace.persona_id}",
                target_entity_ref=action.target_ref,
                action_kind=action.action_kind,
                audience_scope=audience,
                scene_ref=batch["scene_ref"], at_time=now,
                rules=current_rules, coverage_complete=True,
            )
            if boundary.result in {"deny", "conflict"}:
                raise UnavailableGuard("current D05 boundary vetoed dispatch admission")
        if isinstance(self.__store, ProductionGraphStore):
            policy = self.__dispatch_clock_policy
            if (clock_reading is None or policy is None
                    or admission.clock_policy_ref != policy.source_id
                    or admission.clock_policy_digest != canonical_digest(asdict(policy))):
                raise UnavailableGuard("dispatch admission clock evidence differs")
        from .dispatch_runtime import DispatchRequest

        if type(request) is not DispatchRequest:
            raise UnavailableGuard("trusted issuer did not produce typed dispatch command")
        if request.payload_ref != dispatch_segment_payload_ref(
                candidate.batch_ref, request.segment_index):
            raise UnavailableGuard("dispatch payload reference differs from D09 graph segment")
        preflight = preflight_dispatch_admission(
            schema, action, batch, request, admission.check_receipts,
            now_utc=now, trusted_check_verifier=lambda spec, receipt: (
                issuer.verify_required_check(spec, receipt, snapshot, db) is True),
        )
        if set(preflight.missing) != {
            "d09.source_qualification", "dispatch.command_provenance",
            "graph.current_admission",
        }:
            raise UnavailableGuard("dispatch admission candidate or checks are incomplete")
        check_receipts_against_specs(admission, schema.required_checks, now)
        admission.require_current(now)
        if (issuer.verify_domain_context(admission, snapshot, db) is not True
                or issuer.verify_command_provenance(request, admission, db) is not True
                or issuer.verify_journal_constraints(request, admission) is not True):
            raise UnavailableGuard("dispatch domain, command, or journal is unverified")
        reads = tuple((item.key.token, item.revision) for item in snapshot.versions)
        parts = (action.identity.activity_id, action.identity.effect_id,
                 action.identity.attempt_id, action.identity.operation_id)
        segment = batch["segments"][request.segment_index]
        if (
            admission.namespace != "/".join(envelope.authority.namespace.as_tuple)
            or admission.graph_incarnation != graph_incarnation
            or (admission.activity_id, admission.effect_id,
                admission.attempt_id, admission.operation_id) != parts
            or admission.dispatch_generation != request.dispatch_generation
            or request.activation_generation != envelope.authority.activation_generation
            or admission.dispatch_generation != envelope.authority.activation_generation
            or admission.candidate_digest != candidate.digest
            or admission.request_digest != canonical_digest(request)
            or admission.action_intent_digest != candidate.action_digest
            or admission.action_schema_digest != candidate.schema_digest
            or admission.required_checks_digest != canonical_digest(schema.required_checks)
            or admission.grant_digest != candidate.grant_digest
            or admission.batch_digest != candidate.batch_digest
            or admission.segment_index != request.segment_index
            or admission.payload_digest != segment["payload_digest"]
            or admission.scene_ref != batch["scene_ref"]
            or admission.object_ref != action.target_ref
            or admission.action_ref != action.action_id
            or admission.purpose != action.purpose
            or admission.audience != envelope.authority.audience
            or admission.graph_reads != reads
            or admission.query_epoch != snapshot.epochs[0].revision
            or (admission.access_epoch, admission.delete_epoch) != (
                envelope.version_guard.access_epoch,
                envelope.version_guard.delete_epoch)
            or admission.budget_parent_lease_ref != envelope.parent_budget_lease_ref
            or admission.budget_lease_ref != envelope.parent_budget_lease_ref
            or admission.budget_reservation_operation_id != identity.operation_id
            or admission.budget_reservation_digest != budget_operation_digest(
                envelope, admission.budget_lease_ref, dict(admission.budget_ceiling))
            or not any(
                item.parent_budget_ref == admission.budget_lease_ref
                and item.upper_bound is not None
                for item in request.footprint.budgets
            )
        ):
            raise UnavailableGuard("dispatch admission differs from current graph candidate")
        if (admission.action_intent_schema_version != "d08.action_intent.v1"
                or admission.action_schema_version != "d08.action_schema.v1"
                or admission.required_checks_schema_version != "d08.required_check_spec.v1"):
            raise UnavailableGuard("dispatch contract schema version differs")
        lease = get_budget_lease(db, admission.budget_lease_ref)
        reservation = db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (admission.budget_lease_ref, admission.budget_reservation_operation_id),
        ).fetchone()
        if (lease.state != "active" or lease.version != admission.budget_version
                or lease.currency != admission.budget_currency
                or (lease.bot_id, lease.persona_id) != envelope.authority.namespace.as_tuple
                or reservation is None
                or reservation[0] != admission.budget_reservation_digest
                or json.loads(reservation[1]) != dict(admission.budget_ceiling)
                or reservation[2] != "reserved"):
            raise UnavailableGuard("dispatch budget reservation changed before admission")
        if request.proactive_contact and admission.contact_reservation_ref is None:
            raise UnavailableGuard("proactive contact has no durable occupation")
        graph_revision = (v2_write[0].graph_revision + 1 if v2_write is not None
                          else graph_receipt.epoch.revision)
        receipt = DispatchAdmissionReceiptV1(
            admission, graph_revision, graph_receipt.epoch.revision,
            canonical_digest({
                "admission_digest": admission.digest,
                "graph_revision": graph_revision,
                "graph_epoch": graph_receipt.epoch.revision,
            }),
        )
        insert_admission(db, receipt, request)
        return receipt

    def commit_domain_bundle(self, bundle: DomainBundle, lease: object) -> CommitReceipt:
        if not isinstance(bundle, DomainBundle):
            raise TypeError("bundle must be DomainBundle")
        authority = bundle.envelope.authority
        self._authorize(lease, authority,
                        frozenset(proposal.domain for proposal in bundle.proposals))
        if (isinstance(self.__store, ProductionGraphStore)
                and self.__content_fence_v2 is not None):
            return self._commit_domain_bundle_v2(bundle, lease)
        with self._content_fence(authority.namespace, authority.activation_generation, "write"):
            store = self.__store
            with store._lock:
                self._admit_content(
                    authority.namespace, authority.activation_generation, "write",
                    tuple(item.key.token for item in bundle.envelope.version_guard.read_versions)
                    + tuple(write.key.token for proposal in bundle.proposals
                            for write in proposal.typed_writes),
                )
            return self._commit_domain_bundle_fenced(bundle, lease)

    def _commit_domain_bundle_v2(self, bundle: DomainBundle,
                                 lease: object) -> CommitReceipt:
        """Commit under a durable write attempt; reconcile before any duplicate read."""
        from .authority_service.v2_contract import FencePermitV2, from_wire, to_wire

        store = self.__store
        port = self.__content_fence_v2
        authority = bundle.envelope.authority
        namespace = authority.namespace
        operation_id = bundle.envelope.identity.operation_id
        digest = bundle.digest
        attempt_id = "graph-write-" + canonical_digest({
            "namespace": list(namespace.as_tuple), "operation_id": operation_id,
            "bundle_digest": digest,
        })[:48]
        with store._lock:
            metadata, epoch = self._v2_graph_stamp(namespace)
            prior = store._db.execute(
                "SELECT digest FROM graph_bundle_operations WHERE bot=? AND persona=? "
                "AND operation_id=?", namespace.as_tuple + (operation_id,),
            ).fetchone()
            saved = store._db.execute(
                "SELECT digest,permit_json,pre_graph_revision,pre_graph_epoch,"
                "post_graph_revision,post_graph_epoch,finish_request_id,finish_request_digest "
                "FROM graph_bundle_fences_v2 WHERE bot=? AND persona=? AND operation_id=?",
                namespace.as_tuple + (operation_id,),
            ).fetchone()
            intent = store._db.execute(
                "SELECT digest,fence_attempt_id,requirements_json,anchor_json,"
                "graph_revision,graph_epoch FROM graph_bundle_intents_v2 "
                "WHERE bot=? AND persona=? AND operation_id=?",
                namespace.as_tuple + (operation_id,),
            ).fetchone()
            rejection = store._db.execute(
                "SELECT digest,status,permit_json,graph_revision,graph_epoch,"
                "finish_request_id,finish_request_digest FROM graph_bundle_rejections_v2 "
                "WHERE bot=? AND persona=? AND operation_id=?",
                namespace.as_tuple + (operation_id,),
            ).fetchone()
        target = metadata.requirements
        if target.namespace != namespace or target.activation_generation != authority.activation_generation:
            raise UnavailableGuard("v2 graph recovery identity or generation differs")
        anchor = port.current_anchor(
            namespace=namespace, authority_namespace=target.authority_namespace)
        if not self._anchor_matches(target, anchor):
            raise UnavailableGuard("v2 graph recovery anchor differs")
        requirements_json = canonical_json(asdict(target))
        anchor_json = canonical_json(asdict(anchor))
        if intent is None and prior is None:
            with store._lock:
                db = store._db
                db.execute("BEGIN IMMEDIATE")
                try:
                    if self._v2_graph_stamp(namespace) != (metadata, epoch):
                        raise StaleRead("v2 graph recovery stamp changed before intent")
                    db.execute(
                        "INSERT OR IGNORE INTO graph_bundle_intents_v2"
                        "(bot,persona,operation_id,digest,fence_attempt_id,"
                        "requirements_json,anchor_json,graph_revision,graph_epoch) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        namespace.as_tuple + (
                            operation_id, digest, attempt_id, requirements_json,
                            anchor_json, metadata.graph_revision, epoch.revision),
                    )
                    intent = db.execute(
                        "SELECT digest,fence_attempt_id,requirements_json,anchor_json,"
                        "graph_revision,graph_epoch FROM graph_bundle_intents_v2 "
                        "WHERE bot=? AND persona=? AND operation_id=?",
                        namespace.as_tuple + (operation_id,),
                    ).fetchone()
                    db.execute("COMMIT")
                except BaseException:
                    db.execute("ROLLBACK")
                    raise
        if intent is None:
            raise UnavailableGuard("durable v2 bundle intent is absent")
        if intent[0] != digest:
            raise EventConflict("operation ID reused with different bundle")
        if (intent[1] != attempt_id or intent[2] != requirements_json
                or intent[3] != anchor_json):
            raise UnavailableGuard("durable v2 bundle intent identity differs")
        if prior is None and (intent[4], intent[5]) != (
                metadata.graph_revision, epoch.revision):
            raise UnavailableGuard("uncommitted v2 bundle intent lost its graph stamp")
        if rejection is not None:
            if prior is not None or saved is not None:
                raise UnavailableGuard("rejected v2 bundle has a business receipt")
            self._finish_rejected_bundle_v2(
                namespace, metadata, epoch, anchor, attempt_id, digest,
                operation_id, rejection)
            raise UnavailableGuard("v2 bundle is terminal rejected_no_commit")
        if prior is not None:
            if prior[0] != digest:
                raise EventConflict("operation ID reused with different bundle")
            if saved is None or saved[0] != digest:
                raise UnavailableGuard("durable v2 bundle fence receipt is absent")
            try:
                original = from_wire(json.loads(saved[1]))
            except (TypeError, ValueError) as exc:
                raise UnavailableGuard("durable v2 bundle permit is invalid") from exc
            if (type(original) is not FencePermitV2
                    or original.operation_id != attempt_id
                    or original.operation != "write" or original.holder != self.__holder
                    or original.subject != port.installation_grant.subject
                    or original.authority_id != target.authority_id
                    or original.namespace != target.authority_namespace
                    or original.generation != target.activation_generation
                    or original.pinned_anchor != anchor
                    or (saved[2], saved[3]) != (intent[4], intent[5])
                    or saved[4] != saved[2] + 1
                    or saved[5] < saved[3]
                    or saved[6] != "finish:" + attempt_id
                    or saved[7] != "sha256:" + canonical_digest({
                        "operation_id": attempt_id, "permit_token": original.token,
                        "action": "finish_domain_bundle",
                        "business_operation_id": operation_id, "bundle_digest": digest,
                    })):
                raise UnavailableGuard("durable v2 bundle fence identity differs")
            observed, state = port.get_fence_operation(
                namespace=namespace, authority_namespace=target.authority_namespace,
                operation_id=attempt_id)
            if observed != original or state not in {"active", "finished"}:
                raise UnavailableGuard("v2 bundle Authority fence status differs")
            if state == "active":
                if (metadata.graph_revision != saved[4]
                        or epoch.revision != saved[5]):
                    raise UnavailableGuard("active v2 bundle fence lost its business stamp")
                scope = FenceScope(
                    namespace, target.authority_namespace, target.activation_generation,
                    "write", attempt_id, original, anchor,
                    NamespaceEpoch(*namespace.as_tuple, saved[3]), saved[2])
                if port.validate_fence(scope) != original:
                    raise UnavailableGuard("v2 bundle write permit changed")
                port.finish_fence(scope, request_id=saved[6], request_digest=saved[7])
            elif (metadata.graph_revision < saved[4]
                  or epoch.revision < saved[5]):
                raise UnavailableGuard("finished v2 bundle fence lost its business stamp")
            return self._read_v2(authority, lambda: self._commit_domain_bundle_fenced(
                bundle, lease, v2_read=True))
        if saved is not None:
            raise UnavailableGuard("v2 bundle fence exists without business receipt")
        dispatch_clock_reading = None
        if (self.__dispatch_admission_issuer is not None
                and any(write.key.type_name == "d09.verified_segment_batch.v1"
                        for proposal in bundle.proposals for write in proposal.typed_writes)):
            from .host.authority_profile import AdminIngressClockPolicy

            if type(self.__dispatch_clock_policy) is not AdminIngressClockPolicy:
                raise UnavailableGuard("dispatch admission clock policy is unavailable")
            try:
                dispatch_clock_reading = port.read_ingress_clock(
                    self.__dispatch_clock_policy)
            except Exception as exc:
                raise UnavailableGuard("paired dispatch admission clock is unavailable") from exc
        permit = port.begin_fence(
            namespace=namespace, authority_namespace=target.authority_namespace,
            holder=self.__holder, generation=target.activation_generation,
            operation="write", operation_id=attempt_id, expected_anchor=anchor,
            retain_on_unknown=True)
        scope = FenceScope(namespace, target.authority_namespace,
                           target.activation_generation, "write", attempt_id,
                           permit, anchor, epoch, metadata.graph_revision)
        finish_id = "finish:" + attempt_id
        finish_digest = "sha256:" + canonical_digest({
            "operation_id": attempt_id, "permit_token": permit.token,
            "action": "finish_domain_bundle", "business_operation_id": operation_id,
            "bundle_digest": digest,
        })
        if port.validate_fence(scope) != permit:
            raise UnavailableGuard("v2 bundle write permit changed")
        transaction_state = {"phase": "before_transaction"}
        try:
            receipt = self._commit_domain_bundle_fenced(
                bundle, lease, v2_write=(metadata, epoch, finish_id,
                                         finish_digest, canonical_json(to_wire(permit))),
                v2_transaction_state=transaction_state,
                dispatch_clock_reading=dispatch_clock_reading)
        except Exception:
            if transaction_state["phase"] in {"before_transaction", "rolled_back"}:
                rejection = self._record_rejected_bundle_v2(
                    namespace, operation_id, digest, attempt_id, metadata, epoch,
                    intent, permit)
                self._finish_rejected_bundle_v2(
                    namespace, metadata, epoch, anchor, attempt_id, digest,
                    operation_id, rejection)
            raise
        if port.validate_fence(scope) != permit:
            raise UnavailableGuard("v2 bundle write permit changed after commit")
        with store._lock:
            current, current_epoch = self._v2_graph_stamp(namespace)
            if (current.requirements != metadata.requirements
                    or current.graph_revision != metadata.graph_revision + 1
                    or current_epoch.revision != receipt.invalidated_epochs[0].revision):
                raise UnavailableGuard("v2 bundle graph stamp changed after commit")
        port.finish_fence(scope, request_id=finish_id, request_digest=finish_digest)
        return receipt

    def _record_rejected_bundle_v2(self, namespace, operation_id, digest,
                                   attempt_id, metadata, epoch, intent, permit):
        """Record a proven rollback before any Authority abort finish."""
        from .authority_service.v2_contract import to_wire

        store = self.__store
        finish_id = "abort:" + attempt_id
        finish_digest = "sha256:" + canonical_digest({
            "operation_id": attempt_id, "permit_token": permit.token,
            "action": "rejected_no_commit", "business_operation_id": operation_id,
            "bundle_digest": digest,
        })
        expected = (
            digest, "rejected_no_commit", canonical_json(to_wire(permit)),
            metadata.graph_revision, epoch.revision, finish_id, finish_digest,
        )
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                current_intent = db.execute(
                    "SELECT digest,fence_attempt_id,requirements_json,anchor_json,"
                    "graph_revision,graph_epoch FROM graph_bundle_intents_v2 "
                    "WHERE bot=? AND persona=? AND operation_id=?",
                    namespace.as_tuple + (operation_id,),
                ).fetchone()
                if (current_intent != intent
                        or self._v2_graph_stamp(namespace) != (metadata, epoch)
                        or db.execute(
                            "SELECT 1 FROM graph_bundle_operations WHERE bot=? "
                            "AND persona=? AND operation_id=?",
                            namespace.as_tuple + (operation_id,),
                        ).fetchone() is not None
                        or db.execute(
                            "SELECT 1 FROM graph_bundle_fences_v2 WHERE bot=? "
                            "AND persona=? AND operation_id=?",
                            namespace.as_tuple + (operation_id,),
                        ).fetchone() is not None):
                    raise UnavailableGuard("v2 bundle rollback cannot be proven")
                db.execute(
                    "INSERT OR IGNORE INTO graph_bundle_rejections_v2"
                    "(bot,persona,operation_id,digest,status,permit_json,"
                    "graph_revision,graph_epoch,finish_request_id,finish_request_digest) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    namespace.as_tuple + (operation_id,) + expected,
                )
                recorded = db.execute(
                    "SELECT digest,status,permit_json,graph_revision,graph_epoch,"
                    "finish_request_id,finish_request_digest "
                    "FROM graph_bundle_rejections_v2 WHERE bot=? AND persona=? "
                    "AND operation_id=?", namespace.as_tuple + (operation_id,),
                ).fetchone()
                if recorded != expected:
                    raise UnavailableGuard("v2 bundle rejection identity differs")
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return expected

    def _finish_rejected_bundle_v2(self, namespace, metadata, epoch, anchor,
                                   attempt_id, digest, operation_id, rejection):
        from .authority_service.v2_contract import FencePermitV2, from_wire

        port = self.__content_fence_v2
        target = metadata.requirements
        try:
            permit = from_wire(json.loads(rejection[2]))
        except (TypeError, ValueError) as exc:
            raise UnavailableGuard("durable v2 rejected permit is invalid") from exc
        if (rejection[0] != digest or rejection[1] != "rejected_no_commit"
                or type(permit) is not FencePermitV2
                or permit.operation_id != attempt_id or permit.operation != "write"
                or permit.subject != port.installation_grant.subject
                or permit.holder != self.__holder
                or permit.authority_id != target.authority_id
                or permit.namespace != target.authority_namespace
                or permit.generation != target.activation_generation
                or permit.pinned_anchor != anchor
                or (rejection[3], rejection[4]) != (
                    metadata.graph_revision, epoch.revision)
                or rejection[5] != "abort:" + attempt_id
                or rejection[6] != "sha256:" + canonical_digest({
                    "operation_id": attempt_id, "permit_token": permit.token,
                    "action": "rejected_no_commit",
                    "business_operation_id": operation_id, "bundle_digest": digest,
                })):
            raise UnavailableGuard("durable v2 rejected fence identity differs")
        observed, state = port.get_fence_operation(
            namespace=namespace, authority_namespace=target.authority_namespace,
            operation_id=attempt_id)
        if observed != permit or state not in {"active", "finished"}:
            raise UnavailableGuard("rejected v2 Authority fence status differs")
        scope = FenceScope(namespace, target.authority_namespace,
                           target.activation_generation, "write", attempt_id,
                           permit, anchor, epoch, metadata.graph_revision)
        if state == "active" and port.validate_fence(scope) != permit:
            raise UnavailableGuard("rejected v2 write permit changed")
        port.finish_fence(scope, request_id=rejection[5], request_digest=rejection[6])

    def _commit_domain_bundle_fenced(self, bundle: DomainBundle,
                                     lease: object, *, v2_read: bool = False,
                                     v2_write=None, v2_transaction_state=None,
                                     in_transaction: bool = False,
                                     now_utc: float | None = None,
                                     dispatch_clock_reading=None,
                                     ingress_deadline_check=None) -> CommitReceipt:
        """Join a caller-owned graph transaction when ``in_transaction`` is set.

        The caller holds the store lock and owns COMMIT or ROLLBACK.
        """
        envelope = bundle.envelope
        namespace = envelope.authority.namespace
        domains = frozenset(proposal.domain for proposal in bundle.proposals)
        if not domains:
            raise ValueError("domain bundle requires proposals")
        self._authorize(lease, envelope.authority, domains)
        store = self.__store
        writes = tuple(write for proposal in bundle.proposals for write in proposal.typed_writes)
        dispatch_candidate = validate_dispatch_candidate_writes(
            tuple((proposal.domain, write) for proposal in bundle.proposals
                  for write in proposal.typed_writes),
            namespace=namespace, identity=envelope.identity,
            read_versions=envelope.version_guard.read_versions,
            source_refs=envelope.source_qualification.source_refs,
            access_epoch=envelope.version_guard.access_epoch,
            delete_epoch=envelope.version_guard.delete_epoch,
            query_epoch=envelope.version_guard.query_epochs[0].revision
            if len(envelope.version_guard.query_epochs) == 1 else -1,
        )
        if len({write.key for write in writes}) != len(writes):
            raise ValueError("duplicate writes across proposals")
        read_map = {item.key: item.revision for item in envelope.version_guard.read_versions}
        if not set(write.key for write in writes).issubset(read_map):
            raise ValueError("all writes require read versions, including absent keys")
        for proposal in bundle.proposals:
            registration = self.__providers.get(proposal.domain)
            if registration is None:
                raise AuthorityDenied("unregistered proposal domain")
            _, schema, schema_hash = registration
            if (proposal.proposal_schema, proposal.proposal_schema_hash) != (schema, schema_hash):
                raise AuthorityDenied("proposal schema differs from registered provider")
            for write in proposal.typed_writes:
                spec = store._registry.spec(write.key.type_name)
                if (spec.writer_domain != proposal.domain or spec.schema_hash is None
                        or write.key.owner.kind not in envelope.authority.owner_scope):
                    raise AuthorityDenied("writer lacks registered type or owner capability")
                if not set(write.dependencies).issubset(read_map):
                    raise ValueError("dependency is outside complete read set")
            for ref in (proposal.dependencies.current_invalidation
                        + proposal.dependencies.historical_provenance
                        + proposal.dependencies.associations
                        + proposal.dependencies.numeric_coupling):
                if read_map.get(ref.key) != ref.revision:
                    raise StaleRead("dependency reference is not guarded")
            current = {ref.key for ref in proposal.dependencies.current_invalidation}
            actual_current = set()
            for write in proposal.typed_writes:
                actual_current.update(write.dependencies)
                if not set(write.dependencies).issubset(current):
                    raise ValueError("graph invalidation edges must match classified dependencies")
            if actual_current != current:
                raise ValueError("classified current dependencies are not materialized")
        write_tokens = {write.key.token for write in writes}
        for write in writes:
            if (write.key.type_name == "runtime.job"
                    and write.key.token not in bundle.persistent_job_refs):
                raise ValueError("runtime.job write must be a bound persistent job ref")
            if (write.key.type_name == "runtime.outbox"
                    and write.key.token not in bundle.outbox_refs):
                raise ValueError("runtime.outbox write must be a bound outbox ref")
            if write.key.type_name == "runtime.outbox":
                if write.value.get("dispatch_generation") != envelope.authority.activation_generation:
                    raise StaleRead("outbox dispatch generation differs from active holder")
                if write.value.get("idempotency_key") not in bundle.idempotency_keys:
                    raise AuthorityDenied("outbox idempotency key is not in the bundle ledger")
        part_refs = (
            ("experience", bundle.experience_refs), ("choice", bundle.choice_refs),
            ("d02_settlement", bundle.d02_settlement_refs),
            ("cost_settlement", bundle.d11_cost_settlement_refs),
            ("idempotency", bundle.idempotency_keys),
            ("persistent_job", bundle.persistent_job_refs),
            ("outbox", bundle.outbox_refs),
        )
        for kind, refs in part_refs:
            for ref in refs:
                if kind in {"idempotency"}:
                    continue
                key = self._parse_ref(ref, namespace)
                if key.token not in write_tokens:
                    raise ValueError(f"{kind} reference must be written in the same bundle")
                required_type = {
                    "cost_settlement": "runtime.cost_settlement",
                    "persistent_job": "runtime.job",
                    "outbox": "runtime.outbox",
                }.get(kind)
                if required_type is not None and key.type_name != required_type:
                    raise AuthorityDenied(f"{kind} requires {required_type}")
                required_writer = {
                    "d02_settlement": "d02", "cost_settlement": "d11",
                    "persistent_job": "d11", "outbox": "d11",
                }.get(kind)
                if required_writer is not None and (
                        store._registry.spec(key.type_name).writer_domain != required_writer):
                    raise AuthorityDenied(f"{kind} requires the {required_writer} graph writer")
        new_sources = []
        for source in envelope.source_qualification.source_refs:
            key = self._parse_ref(source, namespace)
            if key not in read_map:
                raise StaleRead("source outside complete read set")
            if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
                raise AuthorityDenied("source reference is not a canonical D06 source")
            access = access_key(*namespace.as_tuple, key.owner.subject or "")
            access_revision = read_map.get(access)
            if access_revision is None:
                raise StaleRead("source access record is outside complete read set")
            if read_map[key] == 0:
                if access_revision != 0:
                    raise StaleRead("new source cannot reuse an existing access record")
                source_writes = tuple((proposal.domain, write) for proposal in bundle.proposals
                                      for write in proposal.typed_writes if write.key == key)
                access_writes = tuple((proposal.domain, write) for proposal in bundle.proposals
                                      for write in proposal.typed_writes if write.key == access)
                if (len(source_writes) != 1 or len(access_writes) != 1
                        or source_writes[0][0] != "d06" or access_writes[0][0] != "d06"):
                    raise AuthorityDenied("new source requires D06 source and access writes")
                record = access_writes[0][1].value
                if (record.get("source_id") != key.owner.subject
                        or record.get("status") != "active"
                        or not set(envelope.authority.audience).issubset(record.get("audiences", ()))
                        or envelope.authority.purpose not in record.get("purposes", ())
                        or key not in access_writes[0][1].dependencies):
                    raise AuthorityDenied("new source access does not cover this use")
                if not (bundle.persistent_job_refs and bundle.outbox_refs
                        and bundle.idempotency_keys):
                    raise ValueError("new source requires encoding job, outbox and idempotency")
                new_sources.append(key)
            elif access_revision == 0:
                raise StaleRead("existing source has no access record")
        digest = bundle.digest
        identity = envelope.identity
        event = Event(Scope(*namespace.as_tuple, identity.activity_id),
                      identity.operation_id, envelope.source_qualification.learned_at,
                      "domain_bundle", {"bundle_digest": digest})
        result: list[CommitReceipt] = []
        runtime_admissions: list[RuntimeAdmission] = []
        product_advances: list[dict] = []
        qualified_dispatch_candidates = []
        guard_snapshots: list[GraphSnapshot] = []
        dispatch_projections = []

        def guard(db):
            if v2_write is not None:
                expected, expected_epoch = v2_write[:2]
                if self._v2_graph_stamp(namespace) != (expected, expected_epoch):
                    raise StaleRead("v2 graph recovery stamp changed")
                if db.execute(
                        "SELECT 1 FROM graph_bundle_rejections_v2 WHERE bot=? "
                        "AND persona=? AND operation_id=?",
                        namespace.as_tuple + (identity.operation_id,),
                ).fetchone() is not None:
                    raise UnavailableGuard("v2 bundle is terminal rejected_no_commit")
            elif not v2_read:
                self._admit_content(
                    namespace, envelope.authority.activation_generation, "write",
                    tuple(item.key.token for item in envelope.version_guard.read_versions)
                    + tuple(write.key.token for write in writes),
                )
            prior = db.execute(
                "SELECT digest FROM graph_bundle_operations WHERE bot=? AND persona=? "
                "AND operation_id=?", namespace.as_tuple + (identity.operation_id,),
            ).fetchone()
            if prior is not None:
                if prior[0] != digest:
                    raise EventConflict("operation ID reused with different bundle")
                return
            snapshot = self._check_guard(
                db, bundle, ingress_deadline_check=ingress_deadline_check)
            if dispatch_candidate is not None and self.__dispatch_admission_issuer is not None:
                from .runtime.dispatch_current_projection import (
                    read_current_dispatch_projection,
                )

                if len(envelope.version_guard.query_epochs) != 1:
                    raise UnavailableGuard("dispatch admission needs one full graph query")
                try:
                    dispatch_projections.append(read_current_dispatch_projection(
                        db, namespace, snapshot, envelope.version_guard.query_epochs[0],
                    ))
                except ValueError as exc:
                    raise UnavailableGuard(
                        "dispatch D03/D05 graph projection is incomplete") from exc
            guard_snapshots.append(snapshot)
            product_advance = self._check_product_advance(db, bundle, snapshot, writes)
            if product_advance is not None:
                product_advances.append(product_advance)
            for source in envelope.source_qualification.source_refs:
                key = self._parse_ref(source, namespace)
                if key in new_sources:
                    continue
                atom = snapshot.get(key)
                access = snapshot.get(access_key(*namespace.as_tuple,
                                                 key.owner.subject or ""))
                if atom is None or not atom.valid or access is None or not access.valid:
                    raise StaleRead("source or access is absent or invalid")
                if (access.value.get("status") != "active"
                        or access.value.get("source_id") != key.owner.subject
                        or not set(envelope.authority.audience).issubset(
                            access.value.get("audiences", ()))
                        or envelope.authority.purpose not in access.value.get("purposes", ())):
                    raise AuthorityDenied("source access no longer covers this use")
            if (dispatch_candidate is not None
                    and len(envelope.version_guard.query_epochs) == 1
                    and envelope.version_guard.query_epochs[0].scope_ref == "all"):
                from .domains.d08 import GoalExecutionProvider

                action_write = next(write for write in writes
                                    if write.key.type_name == "d08.action_intent.v1")
                action = next(spec for spec in GoalExecutionProvider().register_types()
                              if spec.name == "d08.action_intent.v1").validator(
                                  action_write.value)
                qualified_dispatch_candidates.append(qualify_dispatch_candidate_sources(
                    dispatch_candidate, action, snapshot,
                    audience=envelope.authority.audience,
                    batch_audiences=tuple(next(write.value["audiences"] for write in writes
                                               if write.key.type_name ==
                                               "d09.verified_segment_batch.v1")),
                    current_barrier_confirmed=True,
                    valid_until=next(write.value["valid_until"] for write in writes
                                     if write.key.type_name == "d09.verified_segment_batch.v1"),
                ))
            for proposal in bundle.proposals:
                provider = self.__providers[proposal.domain][0]
                # Providers may return approval or the exact unchanged proposal.
                # A transformed candidate would need its own validation pass.
                validated = provider.validate(proposal, snapshot)
                if validated is not True and validated != proposal:
                    raise AuthorityDenied("domain validation did not approve proposal")
            runtime_admissions.append(self._admit_runtime_bundle(
                db, bundle, now_utc=(
                    self._dispatch_clock_upper(dispatch_clock_reading)
                    if dispatch_clock_reading is not None else now_utc)))
            for proposal in bundle.proposals:
                for write in proposal.typed_writes:
                    if write.key.type_name.startswith("runtime."):
                        if proposal.domain != "d11":
                            raise AuthorityDenied("runtime graph write requires D11")
                        reconcile_runtime_write(db, write)

        def receipt_hook(db, graph_receipt):
            prior = db.execute(
                "SELECT digest,receipt_json FROM graph_bundle_operations WHERE bot=? "
                "AND persona=? AND operation_id=?",
                namespace.as_tuple + (identity.operation_id,),
            ).fetchone()
            if prior:
                if prior[0] != digest:
                    raise EventConflict("operation ID reused with different bundle")
                if graph_receipt.status != "duplicate":
                    raise EventConflict("operation ledger and graph event disagree")
                data = json.loads(prior[1])
                # Stored receipt is reconstructed from current canonical graph
                # event data; no caller-supplied status can mark a duplicate.
                result.append(CommitReceipt(
                    "duplicate", identity.operation_id, digest,
                    identity.activity_id, identity.effect_id, data["commit_seq"],
                    envelope.version_guard.read_versions,
                    graph_receipt.revisions, (graph_receipt.epoch,),
                    tuple(data["ledger_refs"]), tuple(data["outbox_refs"]),
                ))
                return
            if graph_receipt.status != "committed":
                raise EventConflict("graph event exists without bundle operation ledger")
            if identity.phase == "ingress" and not envelope.version_guard.query_epochs:
                # This runs after graph writes but before SQLite COMMIT.  The
                # sealed four-key exception must still hold, and the current
                # process clock may have advanced during provider validation.
                if v2_write is not None:
                    expected, expected_epoch = v2_write[:2]
                    current_metadata, current_epoch = self._v2_graph_stamp(namespace)
                    if (current_metadata != expected
                            or current_epoch != graph_receipt.epoch
                            or current_epoch.revision != expected_epoch.revision + 1):
                        raise StaleRead("v2 graph recovery stamp changed")
                elif not v2_read:
                    self._admit_content(
                        namespace, envelope.authority.activation_generation, "write",
                        tuple(item.key.token for item in envelope.version_guard.read_versions)
                        + tuple(write.key.token for write in writes),
                    )
                if self._version(db, namespace, "activation", "current") != str(
                        envelope.authority.activation_generation):
                    raise StaleRead("ingress activation generation changed before commit")
                epoch_row = db.execute(
                    "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
                    "WHERE bot=? AND persona=?", namespace.as_tuple,
                ).fetchone() or (0, 0)
                if tuple(epoch_row) != (
                        envelope.version_guard.access_epoch,
                        envelope.version_guard.delete_epoch):
                    raise StaleRead("ingress access or deletion epoch changed before commit")
                if not self._exact_ingress_without_query(
                        db, bundle, deadline_check=ingress_deadline_check):
                    raise UnavailableGuard("sealed ingress authority changed before commit")
            seq_row = db.execute(
                "SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            seq = (seq_row[0] if seq_row else 0) + 1
            db.execute(
                "INSERT INTO graph_bundle_sequence(bot,persona,last_seq) VALUES(?,?,?) "
                "ON CONFLICT(bot,persona) DO UPDATE SET last_seq=excluded.last_seq",
                namespace.as_tuple + (seq,),
            )
            ledger_refs = tuple(ref for kind, refs in part_refs if kind not in {"outbox"}
                                for ref in refs)
            data = {"commit_seq": seq, "ledger_refs": list(ledger_refs),
                    "outbox_refs": list(bundle.outbox_refs)}
            if dispatch_candidate is not None:
                candidate_evidence = (qualified_dispatch_candidates[0]
                                      if qualified_dispatch_candidates else dispatch_candidate)
                versions = {item.key.token: item.revision
                            for item in graph_receipt.revisions}
                refs = (dispatch_candidate.action_ref,
                        dispatch_candidate.schema_ref,
                        dispatch_candidate.grant_ref,
                        dispatch_candidate.batch_ref)
                if any(versions.get(ref, 0) < 1 for ref in refs):
                    raise UnavailableGuard("dispatch candidate lacks same-commit graph versions")
                data["dispatch_candidate"] = {
                    "schema": "sylanne.d11.dispatch_candidate.v1",
                    "status": candidate_evidence.status,
                    "digest": candidate_evidence.digest,
                    "refs": [[ref, versions[ref]] for ref in refs],
                    "graph_epoch": graph_receipt.epoch.revision,
                    "source_refs": list(dispatch_candidate.source_refs),
                    "access_epoch": dispatch_candidate.access_epoch,
                    "delete_epoch": dispatch_candidate.delete_epoch,
                    "query_epoch": dispatch_candidate.query_epoch,
                    "source_audience": list(candidate_evidence.source_audience),
                    "source_proof_versions": [list(item) for item in
                                              candidate_evidence.source_proof_versions],
                    "source_proof_digest": candidate_evidence.source_proof_digest,
                    "graph_incarnation": (
                        v2_write[0].requirements.graph_incarnation
                        if v2_write is not None else None),
                    "graph_revision": (
                        v2_write[0].graph_revision + 1
                        if v2_write is not None else None),
                }
                if self.__dispatch_admission_issuer is not None:
                    from .domains.d08 import GoalExecutionProvider

                    d08_types = {spec.name: spec for spec in
                                 GoalExecutionProvider().register_types()}
                    linked = {write.key.type_name: write.value for write in writes
                              if write.key.type_name in {
                                  "d08.action_intent.v1", "d08.action_schema.v1",
                                  "d08.communication_intent_grant.v1",
                                  "d09.verified_segment_batch.v1",
                              }}
                    admission_receipt = self._issue_dispatch_admission(
                        db, bundle, guard_snapshots[0], candidate_evidence,
                        d08_types["d08.action_intent.v1"].validator(
                            linked["d08.action_intent.v1"]),
                        d08_types["d08.action_schema.v1"].validator(
                            linked["d08.action_schema.v1"]),
                        d08_types["d08.communication_intent_grant.v1"].validator(
                            linked["d08.communication_intent_grant.v1"]),
                        linked["d09.verified_segment_batch.v1"],
                        graph_receipt=graph_receipt, v2_write=v2_write,
                        projection=dispatch_projections[0] if dispatch_projections else None,
                        now_utc=(
                            self._dispatch_clock_upper(dispatch_clock_reading)
                            if dispatch_clock_reading is not None else now_utc),
                        clock_reading=dispatch_clock_reading,
                    )
                    data["dispatch_admission"] = {
                        "schema": admission_receipt.admission.schema,
                        "ref": admission_receipt.admission.admission_ref,
                        "digest": admission_receipt.receipt_digest,
                    }
            if product_advances:
                data["product_advance_candidate"] = product_advances[0]
            db.execute(
                "INSERT INTO graph_bundle_operations(bot,persona,operation_id,digest,"
                "activity_id,effect_id,commit_seq,receipt_json) VALUES(?,?,?,?,?,?,?,?)",
                namespace.as_tuple + (identity.operation_id, digest, identity.activity_id,
                                      identity.effect_id, seq, canonical_json(data)),
            )
            if product_advances:
                advance = product_advances[0]
                db.execute(
                    "INSERT INTO graph_product_advances"
                    "(bot,persona,operation_id,process_id,feeling_ref,mood_ref,"
                    "parent_operation_id,replay_key,from_cursor,to_cursor,candidate_digest,"
                    "numeric_input_digest,numeric_output_digest,native_manifest_sha256,"
                    "native_sha256,previous_error_bound,next_error_bound) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    namespace.as_tuple + (
                        identity.operation_id, advance["process_id"], advance["feeling_ref"],
                        advance["mood_ref"], advance["parent_operation_id"], advance["replay_key"],
                        advance["from_cursor"], advance["to_cursor"], advance["candidate_digest"],
                        advance["numeric_input_digest"], advance["numeric_output_digest"],
                        advance["native_manifest_sha256"], advance["native_sha256"],
                        advance["previous_error_bound"], advance["next_error_bound"]),
                )
            for kind, refs in part_refs:
                for ref in refs:
                    db.execute(
                        "INSERT INTO graph_bundle_refs(bot,persona,operation_id,ref_kind,ref) "
                        "VALUES(?,?,?,?,?)",
                        namespace.as_tuple + (identity.operation_id, kind, ref),
                    )
            for ref in bundle.outbox_refs:
                db.execute(
                    "INSERT INTO graph_bundle_outbox(bot,persona,outbox_ref,operation_id,phase) "
                    "VALUES(?,?,?,?, 'pending')",
                    namespace.as_tuple + (ref, identity.operation_id),
                )
            if len(runtime_admissions) != 1:
                raise UnavailableGuard("D11 runtime admission was not recorded")
            for binding in runtime_admissions[0].jobs:
                for outbox_ref in binding.outbox_refs:
                    db.execute(
                        "INSERT INTO graph_outbox_jobs(bot,persona,outbox_ref,job_id,operation_id) "
                        "VALUES(?,?,?,?,?)",
                        namespace.as_tuple + (outbox_ref, binding.job.job_id,
                                              identity.operation_id),
                    )
            for proposal in bundle.proposals:
                for kind, edges in (("historical_provenance", proposal.dependencies.historical_provenance),
                                    ("association", proposal.dependencies.associations),
                                    ("numeric_coupling", proposal.dependencies.numeric_coupling)):
                    for write in proposal.typed_writes:
                        for ref in edges:
                            db.execute(
                                "INSERT INTO graph_dependency_edges(dependent_token,dependency_token,"
                                "dependency_revision,edge_kind,operation_id) VALUES(?,?,?,?,?)",
                                (write.key.token, ref.key.token, ref.revision, kind,
                                 identity.operation_id),
                            )
            if v2_write is not None:
                expected, expected_epoch, finish_id, finish_digest, permit_json = v2_write
                store.cas_graph_recovery_metadata(
                    expected, expected.requirements,
                    _capability=self.__graph_capability)
                db.execute(
                    "INSERT INTO graph_bundle_fences_v2"
                    "(bot,persona,operation_id,digest,permit_json,pre_graph_revision,"
                    "pre_graph_epoch,post_graph_revision,post_graph_epoch,"
                    "finish_request_id,finish_request_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    namespace.as_tuple + (
                        identity.operation_id, digest, permit_json,
                        expected.graph_revision, expected_epoch.revision,
                        expected.graph_revision + 1, graph_receipt.epoch.revision,
                        finish_id, finish_digest),
                )
            result.append(CommitReceipt(
                "committed", identity.operation_id, digest, identity.activity_id,
                identity.effect_id, seq, envelope.version_guard.read_versions,
                graph_receipt.revisions, (graph_receipt.epoch,), ledger_refs,
                bundle.outbox_refs,
            ))

        candidate = GraphCandidate(event, envelope.version_guard.read_versions,
                                   writes, ())
        if in_transaction:
            GraphStore._graph_commit_in_transaction(
                store, candidate, _guard=guard, _receipt_hook=receipt_hook,
                _capability=self.__graph_capability,
            )
        else:
            GraphStore.graph_commit(
                store, candidate, _guard=guard, _receipt_hook=receipt_hook,
                _capability=self.__graph_capability,
                _transaction_state=v2_transaction_state,
            )
        return result[0]


__all__ = [
    "GraphCoordinator", "AuthorityDenied", "UnavailableGuard",
    "FirstIngressOutcomeUnknown", "namespace_ref",
    "BudgetAdmission", "JobBinding", "RuntimeAdmission", "ScheduleAdmission",
    "OwnerLeaseBindingV1", "budget_operation_digest",
]
