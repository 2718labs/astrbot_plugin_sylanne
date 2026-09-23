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
from typing import Mapping
from types import SimpleNamespace

from .contracts import Event, EventConflict, Scope, StaleRead, canonical_json
from .graph_store import GraphStore, ProductionGraphStore
from .graph_types import AtomKey, GraphCandidate, GraphSnapshot, GraphAtom, GraphVersion, NamespaceEpoch
from .memory_types import access_key, source_key
from .runtime_contracts import (
    AuthorityContext, CommitReceipt, ContentFencePortV2, DomainBundle, FenceScope,
    NamespaceId, canonical_digest,
)
from .runtime.restore_anchor import (
    ExecutionJournalPort, SnapshotRequirements, validate_restore,
)
from .runtime.budget import (
    BudgetLease, BudgetReceipt, create_budget_lease, get_budget_lease,
    reserve_budget, settle_budget,
)
from .runtime.jobs import (
    PersistentJob, acquire_job, cancel_job, create_job, get_job,
)
from .runtime.d11_types import reconcile_runtime_write


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
                 ingress_policy=None, ingress_clock=None):
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
        self.__closure_verifier = closure_verifier
        self.__d02_issuer = d02_issuer
        self.__d11_issuer = d11_issuer
        if ingress_policy is not None and not callable(ingress_policy):
            raise TypeError("ingress_policy must be callable")
        self.__ingress_policy = ingress_policy
        if ingress_clock is not None and not callable(ingress_clock):
            raise TypeError("ingress_clock must be callable")
        self.__ingress_clock = ingress_clock
        self.__ingress_clock_bindings: dict[
            tuple[NamespaceId, str, int], _IngressClockBinding] = {}
        self.__graph_capability = object()
        if isinstance(store, ProductionGraphStore):
            if getattr(store, "_coordinator_capability", None) is not None:
                raise AuthorityDenied("production graph store is already bound")
            store._coordinator_capability = self.__graph_capability
        self.__leases: dict[_AuthorityLease, tuple[str, str, str, NamespaceId, frozenset[str],
                                                  frozenset[str], int]] = {}
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

    def _read_v2(self, authority: AuthorityContext, reader):
        """Keep every Authority RPC outside the business graph lock."""
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
                with store._lock:
                    if self._v2_graph_stamp(namespace) != (metadata, epoch):
                        raise UnavailableGuard("v2 graph recovery stamp changed")
                    result = reader()
                if port.validate_fence(scope) != permit:
                    raise UnavailableGuard("v2 read permit changed")
                with store._lock:
                    if self._v2_graph_stamp(namespace) != (metadata, epoch):
                        raise UnavailableGuard("v2 graph recovery stamp changed")
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
                   domains: frozenset[str]) -> None:
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
            finish_digest, ingress_ids, policy_identity, trusted_upper,
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
        self._authorize(lease, authority, domains)
        if isinstance(self.__store, ProductionGraphStore) and self.__content_fence_v2 is not None:
            return self._read_v2(authority, lambda: GraphStore.graph_snapshot(
                self.__store, keys, _capability=self.__graph_capability))
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
        self._authorize(lease, authority, domains)
        if isinstance(self.__store, ProductionGraphStore) and self.__content_fence_v2 is not None:
            return self._read_v2(authority, lambda: GraphStore.graph_query(
                self.__store, *authority.namespace.as_tuple, type_names=type_names,
                owner_kind=owner_kind, _capability=self.__graph_capability, **filters))
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
                v2_transaction_state=transaction_state)
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
            for proposal in bundle.proposals:
                provider = self.__providers[proposal.domain][0]
                # Providers may return approval or the exact unchanged proposal.
                # A transformed candidate would need its own validation pass.
                validated = provider.validate(proposal, snapshot)
                if validated is not True and validated != proposal:
                    raise AuthorityDenied("domain validation did not approve proposal")
            runtime_admissions.append(self._admit_runtime_bundle(
                db, bundle, now_utc=now_utc))
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
            db.execute(
                "INSERT INTO graph_bundle_operations(bot,persona,operation_id,digest,"
                "activity_id,effect_id,commit_seq,receipt_json) VALUES(?,?,?,?,?,?,?,?)",
                namespace.as_tuple + (identity.operation_id, digest, identity.activity_id,
                                      identity.effect_id, seq, canonical_json(data)),
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
    "budget_operation_digest",
]
