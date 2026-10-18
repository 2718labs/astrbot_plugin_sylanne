"""Private installed Host handles for actual paired foreground observations."""
from contextlib import contextmanager
from dataclasses import dataclass

from ..runtime_contracts import CommitReceipt, FenceScope, canonical_digest
from ..authority_service.current_foreground_activity_v1 import (ForegroundActivityRequestV1, ForegroundActivityEvidenceV1,
    foreground_fence_operation_id_v1, DraftRootRegistrationRequestV1, DraftRootRegistrationEvidenceV1)
from ..authority_service.v2_contract import FencePermitV2
from .d01_production_operations_v1 import CurrentDomainReadV1
from .d11_life_preparation_v1 import _record, _read
from .d11_artifact_draft_contract_v1 import DraftActivityScopeV1
from .d11_life_contract_v1 import LifeInputRefV1
from .issuers import D11BudgetJobIssuer
from ..domains.d01.production_operations_v1 import plain_v1

_KEY = object()
_ACTIVE = {}
_STOP_KEY = object()
_STOP_ACTIVE = {}


@dataclass(frozen=True, slots=True, init=False, weakref_slot=True)
class _IssuedOwnerStopProjectionV1:
    graph: object
    scope: FenceScope
    observation: object

    def __init__(self, key, graph, scope, observation):
        if key is not _STOP_KEY:
            raise TypeError("Stop projection comes only from its actual paired observer")
        object.__setattr__(self, "graph", graph)
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "observation", observation)


@contextmanager
def owner_stop_projection_for_fence_v1(graph, *, scope, original_ref):
    from ..graph_coordinator import GraphCoordinator
    from ..host.v2_fence_port import V2FencePort
    from ..authority_service.owner_stop_reply_v1 import OwnerStopReplyProjectionObservedV1
    import weakref
    if type(graph) is not GraphCoordinator or type(scope) is not FenceScope or scope.operation != "write":
        raise TypeError("Stop projection requires its installed Graph and actual write scope")
    store = graph._GraphCoordinator__store
    port = graph._GraphCoordinator__content_fence_v2
    if type(port) is not V2FencePort or store._db.in_transaction:
        raise ValueError("Stop projection observation must run outside the actual Graph transaction")
    observed = port.observe_owner_stop_reply_projection_for_fence_v1(scope=scope, original_ref=original_ref)
    if (type(observed) is not OwnerStopReplyProjectionObservedV1 or observed.permit != scope.permit
            or observed.request.namespace != scope.namespace
            or observed.graph_revision != scope.graph_revision or observed.graph_epoch != scope.graph_epoch.revision
            or scope.operation_id != "owner-stop-projection:" + observed.initial_original.operation_id):
        raise ValueError("Stop projection observation changed its exact held scope/stamp")
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(scope.namespace)
    if (metadata.requirements != observed.requirements or epoch != scope.graph_epoch
            or metadata.graph_revision != observed.graph_revision
            or not graph._anchor_matches(observed.requirements, scope.pinned_anchor)):
        raise ValueError("Stop projection observed Graph/Core anchor is no longer current")
    if len(_STOP_ACTIVE) >= 8:
        raise ValueError("Stop projection private handle slots are occupied")
    issued = _IssuedOwnerStopProjectionV1(_STOP_KEY, graph, scope, observed)
    _STOP_ACTIVE[id(issued)] = weakref.ref(issued)
    try:
        yield issued
    finally:
        _STOP_ACTIVE.pop(id(issued), None)


def require_owner_stop_projection_issuance_v1(issued, graph, scope):
    if (type(issued) is not _IssuedOwnerStopProjectionV1 or issued.graph is not graph or issued.scope != scope
            or _STOP_ACTIVE.get(id(issued), lambda: None)() is not issued):
        raise TypeError("actual active private Stop projection observation is required")
    return issued.observation


def reobserve_owner_stop_projection_v1(issued):
    observed = require_owner_stop_projection_issuance_v1(issued, issued.graph, issued.scope)
    if issued.graph._GraphCoordinator__store._db.in_transaction:
        raise ValueError("Stop projection Authority reobservation cannot run in a Graph transaction")
    current = issued.graph._GraphCoordinator__content_fence_v2.observe_owner_stop_reply_projection_for_fence_v1(
        scope=issued.scope, original_ref=observed.initial_original.original_ref)
    if current != observed:
        raise ValueError("Stop projection current Owner/C09/Graph/permit observation changed")
    return current


@dataclass(frozen=True, slots=True, init=False)
class _IssuedForegroundActivityV1:
    graph: object
    port: object
    scope: FenceScope
    request: ForegroundActivityRequestV1
    evidence: ForegroundActivityEvidenceV1
    digest: str

    def __init__(self, key, graph, port, scope, request, evidence):
        if key is not _KEY:
            raise TypeError("foreground handle comes only from the paired installed port")
        for name, value in (("graph", graph), ("port", port), ("scope", scope), ("request", request),
                ("evidence", evidence), ("digest", canonical_digest(evidence))):
            object.__setattr__(self, name, value)


@contextmanager
def foreground_activity_for_fence_v1(graph, *, scope, request):
    """Authority RPC finishes before the Root enters its Graph write transaction."""
    from ..graph_coordinator import GraphCoordinator
    from ..host.v2_fence_port import V2FencePort
    from ..authority_service.current_foreground_activity_v1 import (ForegroundActivityRequestV2,
        ForegroundActivityPreparationParentRequestV2, ForegroundActivityEvidenceV2, foreground_fence_operation_id_v2)
    internal_v2 = type(request) in {ForegroundActivityRequestV2, ForegroundActivityPreparationParentRequestV2}
    if type(graph) is not GraphCoordinator or type(scope) is not FenceScope or type(request) not in {
            ForegroundActivityRequestV1, ForegroundActivityRequestV2, ForegroundActivityPreparationParentRequestV2}:
        raise TypeError("foreground issuance needs its installed Graph and exact registered request")
    port = graph._GraphCoordinator__content_fence_v2
    if type(port) is not V2FencePort:
        raise TypeError("foreground issuance requires the actual paired fence port")
    if graph._GraphCoordinator__store._db.in_transaction:
        raise ValueError("foreground Authority calls cannot run in a Graph transaction")
    fence_id = foreground_fence_operation_id_v2 if internal_v2 else foreground_fence_operation_id_v1
    if scope.operation_id != fence_id(request):
        raise ValueError("foreground live fence is not bound to this exact registered request")
    evidence, observed_permit = port.admit_foreground_activity_for_fence_v1(scope=scope, request=request)
    expected_evidence = ForegroundActivityEvidenceV2 if internal_v2 else ForegroundActivityEvidenceV1
    if (type(evidence) is not expected_evidence or type(observed_permit) is not FencePermitV2
            or observed_permit != scope.permit or evidence.current_self.permit != scope.permit
            or evidence.request != request or evidence.query_epoch.revision != scope.graph_epoch.revision):
        raise ValueError("foreground paired result differs from its actual held fence")
    if len(_ACTIVE) >= 8:
        raise ValueError("foreground issued-handle slots are occupied")
    issued = _IssuedForegroundActivityV1(_KEY, graph, port, scope, request, evidence)
    _ACTIVE[id(issued)] = issued
    try:
        yield issued
    finally:
        del _ACTIVE[id(issued)]


def require_foreground_activity_issuance_v1(value, graph, scope):
    if (type(value) is not _IssuedForegroundActivityV1 or _ACTIVE.get(id(value)) is not value
            or value.graph is not graph or value.port is not graph._GraphCoordinator__content_fence_v2
            or value.scope != scope or value.digest != canonical_digest(value.evidence)):
        raise ValueError("foreground actual issued handle is absent, changed or belongs to another runtime")
    return value.evidence


def reobserve_foreground_activity_v1(value, graph, scope):
    from .foreground_mesh_issuance_v1 import is_personal_mesh_issuance_v1,reobserve_personal_mesh_activity_v1
    if is_personal_mesh_issuance_v1(value):
        return reobserve_personal_mesh_activity_v1(value,graph,scope)
    require_foreground_activity_issuance_v1(value, graph, scope)
    if graph._GraphCoordinator__store._db.in_transaction:
        raise ValueError("foreground currentness RPC must precede the Graph transaction")
    observed, permit = value.port.read_current_foreground_activity_for_fence_v1(scope=scope, original_request=value.request)
    if permit != scope.permit or observed != value.evidence:
        raise ValueError("foreground source/self/cycle/Owner/budget current witness changed")
    return observed


def record_foreground_life_scope_after_commit_v1(db, *, graph, issued, frame, receipt, issuer):
    """Actual same-transaction original only; signing audit data grants no permission."""
    if type(receipt) is not CommitReceipt or type(issuer) is not D11BudgetJobIssuer:
        raise TypeError("foreground original needs the actual installed issuer and Graph receipt")
    evidence = require_foreground_activity_issuance_v1(issued, graph, issued.scope)
    read = CurrentDomainReadV1(frame)
    if (receipt.status != "committed" or receipt.operation_id != frame.envelope.identity.operation_id
            or receipt.activity_id != evidence.request.activity_id
            or frame.envelope.authority.actor != evidence.current_self.self_entity_ref
            or frame.owner_guard != evidence.owner_guard):
        raise ValueError("foreground receipt/actor/upstream Owner differs from its issued operation")
    actual = db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*frame.envelope.authority.namespace.as_tuple, receipt.operation_id)).fetchone()
    if actual != (receipt.operation_digest, receipt.activity_id, receipt.effect_id, receipt.commit_seq):
        raise ValueError("foreground original was not committed by the actual W01 transaction")
    if evidence.request.operation_kind == "derive_ingress_artifact_task_scope_v1":
        from .ingress_artifact_task_scope_v1 import record_task_scope_after_commit_v1
        return record_task_scope_after_commit_v1(db,graph=graph,issued=issued,frame=frame,receipt=receipt,issuer=issuer)
    root = evidence.root_capability
    if root is None:
        return ()
    source = read.head(db, evidence.request.plan_source_ref, required=True)
    from .current_method_learning_read_v3 import method_post_commit_atom_digest_v3
    source_digest = method_post_commit_atom_digest_v3(db, source)
    scope = DraftActivityScopeV1(receipt.activity_id, evidence.current_self.self_entity_ref,
        evidence.request.ingress_operation_id, evidence.request.c02_operation_id,
        LifeInputRefV1(source.key.token, source.revision, source_digest),
        evidence.request.parent_budget_lease_ref, root.registration_ref, canonical_digest(plain_v1(root)),
        evidence.valid_until_utc, frame.owner_guard.grant_ref, frame.owner_guard.grant_revision, frame.owner_guard.grant_digest)
    ref = "foreground-scope:" + canonical_digest((frame.envelope.authority.namespace, scope))[:48]
    originals = [_record(db, issuer=issuer, namespace=frame.envelope.authority.namespace, kind="activity_scope",
        ref=ref, operation_id=receipt.operation_id, value=scope)]
    old = _read(db, issuer=issuer, namespace=frame.envelope.authority.namespace,
        kind="draft_root_capability", ref=root.registration_ref)
    if old is None:
        raise ValueError("ordinary activity cannot create a missing root permission original")
    elif canonical_digest(old[0]) != canonical_digest(plain_v1(root)):
        raise ValueError("foreground root registration changed its original capability")
    return tuple(originals)


@dataclass(frozen=True, slots=True, init=False)
class _IssuedDraftRootRegistrationV1:
    graph: object
    port: object
    scope: FenceScope
    evidence: DraftRootRegistrationEvidenceV1
    digest: str

    def __init__(self, key, graph, port, scope, evidence):
        if key is not _KEY:
            raise TypeError("root registration handle requires the successful paired Owner setup call")
        for name, value in (("graph", graph), ("port", port), ("scope", scope), ("evidence", evidence),
                ("digest", canonical_digest(evidence))):
            object.__setattr__(self, name, value)


@contextmanager
def draft_root_registration_for_fence_v1(graph, *, scope, request,
        owner_actor_ref, owner_session_token, owner_session_request):
    """Called only by the explicit authenticated installation/setup command."""
    from ..graph_coordinator import GraphCoordinator
    from ..host.v2_fence_port import V2FencePort
    if type(graph) is not GraphCoordinator or type(scope) is not FenceScope or type(request) is not DraftRootRegistrationRequestV1:
        raise TypeError("explicit root setup requires its installed Graph and typed request")
    port = graph._GraphCoordinator__content_fence_v2
    if type(port) is not V2FencePort or graph._GraphCoordinator__store._db.in_transaction:
        raise ValueError("root setup paired call must occur outside the Graph transaction")
    evidence, permit = port.admit_draft_root_registration_for_fence_v1(scope=scope, request=request,
        owner_actor_ref=owner_actor_ref, owner_session_token=owner_session_token,
        owner_session_request=owner_session_request)
    if (type(evidence) is not DraftRootRegistrationEvidenceV1 or evidence.permit != scope.permit
            or permit != scope.permit or evidence.request != request or evidence.owner_actor_ref != owner_actor_ref):
        raise ValueError("root setup paired result differs from its real Owner request/fence")
    if len(_ACTIVE) >= 8:
        raise ValueError("foreground issued-handle slots are occupied")
    issued = _IssuedDraftRootRegistrationV1(_KEY, graph, port, scope, evidence)
    _ACTIVE[id(issued)] = issued
    try:
        yield issued
    finally:
        del _ACTIVE[id(issued)]


@dataclass(frozen=True, slots=True)
class InstalledDraftRootRegistrationReadersV1:
    graph: object
    issuer: D11BudgetJobIssuer
    issued: _IssuedDraftRootRegistrationV1

    def __post_init__(self):
        if (type(self.issued) is not _IssuedDraftRootRegistrationV1 or _ACTIVE.get(id(self.issued)) is not self.issued
                or self.issued.graph is not self.graph or type(self.issuer) is not D11BudgetJobIssuer
                or self.issuer is not self.graph._GraphCoordinator__d11_issuer):
            raise ValueError("root registration reader requires the actual paired Owner-issued setup handle")


def read_plan_draft_root_registration_v1(db, *, namespace, request):
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..graph_types import owner_grant_key
    if type(request) is not DraftRootRegistrationRequestV1 or request.namespace != namespace:
        raise TypeError("root setup read plan requires its exact installed Owner request")
    return production_read_plan_v1((), (owner_grant_key(*namespace.as_tuple),), (request.source_ref,), ())


def stage_register_current_draft_root_in_transaction_v1(db, *, frame, request, installed_readers):
    from ..domains.d01.production_operations_v1 import stage_result_v1
    if type(installed_readers) is not InstalledDraftRootRegistrationReadersV1 or type(request) is not DraftRootRegistrationRequestV1:
        raise TypeError("root setup compiler requires its private paired Owner issuance")
    installed_readers.__post_init__()
    issued = installed_readers.issued
    evidence = issued.evidence
    read = CurrentDomainReadV1(frame)
    read.check(db)
    if (request != evidence.request or frame.envelope.identity.operation_id != request.operation_id
            or frame.envelope.authority.actor != evidence.owner_actor_ref or frame.owner_guard != evidence.owner_guard
            or frame.envelope.authority.purpose != request.purpose or frame.envelope.authority.audience != request.audiences
            or evidence.query_epoch.revision != frame.snapshot.epochs[0].revision
            or any(read.head(db, version.key).revision != version.revision for version in evidence.read_versions)):
        raise ValueError("root setup changed its genuine Owner/source/readset qualification")
    read.source_family(db, (request.source_ref,))
    clock = tuple(original for original in frame.observed_originals if original.kind == "d11.trusted_tick")
    if len(clock) != 1:
        raise ValueError("root setup requires its actual paired trusted clock original")
    provider = installed_readers.graph._GraphCoordinator__providers["d10"]
    return stage_result_v1(frame, "d10", "register_artifact_draft_root", request,
        provenance={"draft_root_request": request, "draft_root_capability": evidence.capability,
            "cause_frozen_at_utc": float(frame.now_utc), "clock_sample_digest": clock[0].original_digest},
        receiver_events=(("d11", "artifact_draft_root_registered"),),
        proposal_schema=provider[1], proposal_hash=provider[2])


def record_draft_root_registration_after_commit_v1(db, *, graph, issued, frame, receipt, issuer):
    if (type(issued) is not _IssuedDraftRootRegistrationV1 or _ACTIVE.get(id(issued)) is not issued
            or issued.graph is not graph or issued.port is not graph._GraphCoordinator__content_fence_v2
            or issued.digest != canonical_digest(issued.evidence) or type(receipt) is not CommitReceipt
            or type(issuer) is not D11BudgetJobIssuer):
        raise ValueError("actual paired root setup issuance/commit is absent")
    evidence = issued.evidence
    if (receipt.status != "committed" or receipt.operation_id != evidence.request.operation_id
            or receipt.operation_id != frame.envelope.identity.operation_id
            or frame.envelope.authority.actor != evidence.owner_actor_ref or frame.owner_guard != evidence.owner_guard):
        raise ValueError("root setup cannot borrow a role actor or another Owner receipt")
    if (frame.envelope.authority.purpose != evidence.request.purpose
            or frame.envelope.authority.audience != evidence.request.audiences
            or evidence.request.source_ref not in frame.envelope.source_qualification.source_refs
            or evidence.query_epoch.revision != frame.snapshot.epochs[0].revision
            or any(frame.snapshot.get(version.key) is None
                or frame.snapshot.get(version.key).revision != version.revision for version in evidence.read_versions)):
        raise ValueError("root setup current source closure/watermark is not guarded by the actual final CAS")
    row = db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*frame.envelope.authority.namespace.as_tuple, receipt.operation_id)).fetchone()
    if row != (receipt.operation_digest, receipt.activity_id, receipt.effect_id, receipt.commit_seq):
        raise ValueError("root setup original must follow the actual same-transaction Graph CAS")
    return _record(db, issuer=issuer, namespace=frame.envelope.authority.namespace, kind="draft_root_capability",
        ref=evidence.capability.registration_ref, operation_id=receipt.operation_id, value=evidence.capability)


def record_live_post_c02_foreground_cause_after_cas_v1(db, *, graph, bundle, receipt, clock_reading, live_now):
    """Private receipt hook: archive this live transition's actual paired clock once."""
    from ..graph_coordinator import GraphCoordinator
    from ..host.authority_profile import AdminForegroundPolicyV1
    from ..host.model_workflows_v4 import AdminModelWorkflowsV4
    from ..host.model_workflows_v5 import AdminModelWorkflowsV5
    from ..host.model_workflows_v6 import AdminModelWorkflowsV6
    from ..host.model_workflows_v7 import AdminModelWorkflowsV7
    from ..host.model_workflows_v8 import AdminModelWorkflowsV8
    from ..host.model_workflows_v9 import AdminModelWorkflowsV9
    from .foreground_cycle_v1 import ForegroundPostC02CauseV1, foreground_post_c02_cause_ref_v1
    from .ingress_observation import read_committed_ingress_identity
    from ..memory_types import SourceRecord
    from .c09_life_originals_v1 import require_foreground_post_c02_cause_history_v1
    from dataclasses import asdict
    from ..runtime_contracts import canonical_serialize
    import json
    if (type(graph) is not GraphCoordinator or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or receipt.status != "committed" or bundle.envelope.identity.phase != "first_ingress_c02"
            or receipt.operation_id != bundle.envelope.identity.operation_id):
        raise ValueError("foreground cause requires this actual private new C02 CAS receipt")
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None:
        return None
    installed = assembly.admin_bundle
    if (type(installed.model_workflows) not in (AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9)
            or type(installed.foreground) is not AdminForegroundPolicyV1
            or installed.foreground.deadline_policy.natural is None):
        return None
    ns = bundle.envelope.authority.namespace
    if installed.installation_policy.namespace != ns:
        raise ValueError("foreground cause installation namespace differs from its actual C02")
    sources = tuple(version for version in receipt.read_versions if version.key.type_name == "memory.source")
    if len(sources) != 1:
        raise ValueError("foreground cause requires its exact single C02 task Source")
    version = sources[0]
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (version.key.token, *ns.as_tuple)).fetchone()
    if row is None or row[2] != 1 or row[0] != version.revision:
        raise ValueError("foreground cause actual C02 readmember Source changed")
    record = SourceRecord.from_dict(json.loads(row[1]))
    ingress = read_committed_ingress_identity(db, ns, record.source_id)
    if ingress is None:
        raise ValueError("foreground cause lacks its actual admitted ingress")
    policy = installed.foreground
    cause = ForegroundPostC02CauseV1(ns, installed.installation_policy.installation_id,
        installed.installation_policy.manifest_digest, json.loads(ingress.identity_json)["operation_id"],
        receipt.operation_id, version.key.token, version.revision, canonical_digest(json.loads(row[1])),
        canonical_digest(receipt), receipt.commit_seq, canonical_digest(asdict(policy)),
        canonical_digest(asdict(policy.deadline_policy)), canonical_digest(clock_reading.sample), float(live_now))
    original = _record(db, issuer=graph._GraphCoordinator__d11_issuer, namespace=ns,
        kind="foreground_post_c02_cause", ref=foreground_post_c02_cause_ref_v1(ns, receipt.operation_id),
        operation_id=receipt.operation_id, value=cause)
    event_kind = "foreground_post_c02_cause_available"
    dedupe = canonical_digest((ns, receipt.operation_id, "d11", event_kind))
    values = (*ns.as_tuple, dedupe, receipt.operation_id, "d11", event_kind,
        original.original_ref, original.original_digest, "pending", None, None)
    if db.execute("SELECT 1 FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?",
            (*ns.as_tuple, dedupe)).fetchone() is not None:
        raise ValueError("a new C02 cause cannot replace an existing causal outbox")
    db.execute("INSERT INTO graph_domain_production_outbox_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)", values)
    require_foreground_post_c02_cause_history_v1(db, cause)
    return original


@dataclass(frozen=True, slots=True, init=False)
class _IssuedForegroundReceiptReadV1:
    graph: object
    scope: FenceScope
    current_self: object
    current_owner: object
    operation_id: str
    source_ref: str
    purpose: str
    audiences: tuple[str, ...]

    def __init__(self, key, graph, scope, current_self, current_owner, operation_id, source_ref, purpose, audiences):
        if key is not _KEY:
            raise TypeError("foreground historical receipt read needs its real paired current self/Source fence")
        for name, value in (("graph", graph), ("scope", scope), ("current_self", current_self),
                ("current_owner", current_owner), ("operation_id", operation_id), ("source_ref", source_ref),
                ("purpose", purpose), ("audiences", audiences)):
            object.__setattr__(self, name, value)


@contextmanager
def foreground_receipt_read_for_fence_v1(graph, *, scope, operation_id, source_ref, purpose, audiences):
    from ..graph_coordinator import GraphCoordinator
    from ..host.self_identity_current_port import InstalledCurrentSelfIdentityPort
    from ..host.v2_fence_port import V2FencePort
    from ..authority_service.v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
    from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    if (type(graph) is not GraphCoordinator or type(scope) is not FenceScope or scope.operation != "read"
            or graph._GraphCoordinator__store._db.in_transaction or type(audiences) is not tuple or not audiences):
        raise ValueError("foreground receipt read requires its actual outside-transaction read fence")
    self_port, port = graph._GraphCoordinator__self_identity_port, graph._GraphCoordinator__content_fence_v2
    if type(self_port) is not InstalledCurrentSelfIdentityPort or type(port) is not V2FencePort:
        raise TypeError("foreground receipt read requires the actual paired installed self and content ports")
    def observe():
        current = self_port.current_self_identity(namespace=scope.namespace, authority_namespace=scope.authority_namespace,
            request_operation_id=scope.operation_id, permit=scope.permit)
        owner, permit = port.get_current_background_owner_authority_for_fence_v1(namespace=scope.namespace,
            authority_namespace=scope.authority_namespace, permit=scope.permit)
        if (type(current) is not AuthorityCurrentSelfIdentityV1 or type(owner) is not D12CurrentOwnerAuthorityV1
                or current.permit != scope.permit or permit != scope.permit
                or current.owner_authorization_head != owner.guard.authorization_head
                or current.graph_revision != scope.graph_revision or current.graph_epoch != scope.graph_epoch.revision):
            raise ValueError("foreground actual historical read self/Owner/source-location stamp differs")
        return current, owner
    current, owner = observe()
    if len(_ACTIVE) >= 8:
        raise ValueError("foreground issued-handle slots are occupied")
    issued = _IssuedForegroundReceiptReadV1(_KEY, graph, scope, current, owner, operation_id, source_ref, purpose, audiences)
    _ACTIVE[id(issued)] = issued
    try:
        yield issued
        if observe() != (current, owner):
            raise ValueError("foreground current self/Owner/Source read observation changed before disclosure")
    finally:
        del _ACTIVE[id(issued)]


def read_foreground_receipt_in_transaction_v1(db, *, graph, issued, streaming_source_qualification=None, streaming_graph_stamp=None):
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..domains.d03.self_identity_qualification import self_identity_mapping_from_current
    from ..domains.d03.self_perspective import self_mapping_key
    from ..graph_types import owner_grant_key
    import json
    if (type(issued) is not _IssuedForegroundReceiptReadV1 or _ACTIVE.get(id(issued)) is not issued
            or issued.graph is not graph or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or graph._v2_graph_stamp(issued.scope.namespace)[1] != issued.scope.graph_epoch):
        raise ValueError("foreground narrow receipt read lost its actual privately issued current read fence")
    ns = issued.scope.namespace
    row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (self_mapping_key(ns).token,)).fetchone()
    if row is None or row[1] != 1 or json.loads(row[0]) != plain_v1(self_identity_mapping_from_current(issued.current_self)):
        raise ValueError("foreground receipt current registered self mapping differs")
    grant = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (owner_grant_key(*ns.as_tuple).token,)).fetchone()
    if grant is None or grant[1] != 1:
        raise ValueError("foreground receipt lost its actual current upstream Owner grant")
    value = json.loads(grant[0])
    if issued.purpose not in value["purposes"] or not set(issued.audiences) <= set(value["audiences"]):
        raise ValueError("foreground receipt current purpose/audience exceeds its real Owner constraint")
    original = read_adopted_domain_operation_v1(db, ns, issued.operation_id)
    if original is None or issued.source_ref not in {version.key.token for version in original["read_versions"]}:
        raise ValueError("foreground narrow read requires its actual historical Source-bound adopted original")
    roots = tuple(version.key.token for version in original["read_versions"] if version.key.type_name == "memory.source")
    _source_family_current_sql_v1(db, namespace=ns, roots=roots, purpose=issued.purpose, audiences=issued.audiences,
        streaming_qualified=streaming_source_qualification,streaming_scope=issued.scope,streaming_graph_stamp=streaming_graph_stamp)
    if original["payload"]["authority"]["actor"] != issued.current_self.self_entity_ref:
        raise ValueError("foreground historical receipt belongs to another original actor")
    saved = db.execute("SELECT receipt_json FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?",
        (*ns.as_tuple, issued.operation_id)).fetchone()
    if saved is None or saved[0] is None:
        raise ValueError("foreground original mechanical write has no saved durable receipt")
    result = json.loads(saved[0])
    if (result.get("schema") != "sylanne.domain-production-receipt.v1"
            or result.get("original_digest") != original["original_digest"]
            or result.get("receipt_digest") != canonical_digest(original["receipt"])):
        raise ValueError("foreground saved receipt differs from its exact immutable W01 adopted original")
    return result
