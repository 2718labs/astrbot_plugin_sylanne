"""Private Self C04 preparation scope. No public capability or Owner DTO."""
from contextlib import contextmanager
from dataclasses import dataclass

from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest, canonical_serialize
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .d06_ingress_c03_selection_v1 import read_adopted_ingress_c03_selection_v1
from .d07_ingress_recall_result_v1 import read_adopted_ingress_recall_routing_v1
from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
from .foreground_call_plan_v1 import resolve_current_foreground_reply_budget_v1
from .foreground_cycle_v1 import require_current_foreground_responsibility_v1
from .jobs import get_job
from .d11_types import job_graph_write
from .c04_v3_contracts import AssociationBudgetV3

PREPARE_OPERATION = "prepare_ingress_c04_v1"
_KEY = object()
_ACTIVE = {}


@dataclass(frozen=True, slots=True)
class PrepareIngressC04RequestV1:
    c02_operation_id: str
    job_ref: str
    source_ref: str
    c03_selection_ref: str
    c03_selection_digest: str
    recall_policy_digest: str

    def __post_init__(self):
        if (type(self.c02_operation_id) is not str or not self.c02_operation_id
                or AtomKey.from_token(self.job_ref).type_name != "runtime.job"
                or AtomKey.from_token(self.source_ref).type_name != "memory.source"):
            raise ValueError("Self C04 needs actual C02/cycle/cue locators")
        for value in (self.c03_selection_digest, self.recall_policy_digest):
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("Self C04 needs exact original commitments")


def ingress_c04_ids_v4(namespace, c02_operation_id, selection_original_digest):
    marker = canonical_digest((namespace, c02_operation_id, selection_original_digest, PREPARE_OPERATION))[:48]
    return {"prepare": "ingress-c04-prepare:" + marker, "adopt": "ingress-c04-adopt:" + marker,
        "effect": "ingress-c04-effect:" + marker, "execution": "ingress-c04-execution:" + marker,
        "reservation": "ingress-c04-body:" + marker}


@dataclass(frozen=True, slots=True, init=False)
class _IssuedSelfC04ScopeV4:
    graph: object
    issued: object
    scope: object
    frame: object
    request: PrepareIngressC04RequestV1
    bundle: object
    selection: object
    selection_original_digest: str
    selection_ref: str
    budget: AssociationBudgetV3
    identity_digest: str
    scope_payload_json: str
    current_self_json: str

    def __init__(self, key, **values):
        if key is not _KEY:
            raise TypeError("Self C04 scope is issued only by the fixed installed transaction")
        for name, value in values.items():
            object.__setattr__(self, name, value)


def _self_c04_scope_preimage_v4(*,request,selection_original_digest,current_self,owner_guard,authority,identity,
        deadline,budget,policy,responsibility_digest,c03_metadata_bridge):
    return {"schema":"c04.self-preparation-scope.v4","request":request,
        "selection_original_digest":selection_original_digest,"self":current_self,"owner_guard":owner_guard,
        "authority":authority,"identity":identity,"deadline":deadline,"budget":budget,"policy":policy,
        "responsibility_digest":responsibility_digest,"c03_metadata_bridge":c03_metadata_bridge}


def _qualified_values(db, *, graph, issued, scope, frame, request, bundle):
    from .domain_production_registry_v1 import installed_operation_v1
    from ..authority_service.current_foreground_activity_v1 import foreground_typed_command_digest_v1
    if (type(request) is not PrepareIngressC04RequestV1 or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or bundle is not graph._GraphCoordinator__d07_execution_service_v1.bundle):
        raise ValueError("Self C04 requires its actual installed W01 transaction")
    evidence = require_foreground_activity_issuance_v1(issued, graph, scope)
    env, ns = frame.envelope, frame.envelope.authority.namespace
    if (evidence.request.operation_kind != PREPARE_OPERATION
            or evidence.request.request_digest != foreground_typed_command_digest_v1(
                installed_operation_v1(PREPARE_OPERATION), request)
            or evidence.request.c02_operation_id != request.c02_operation_id
            or evidence.request.cue_source_ref != request.source_ref
            or evidence.request.cycle_job_ref != request.job_ref
            or env.authority.actor != evidence.current_self.self_entity_ref
            or frame.owner_guard != evidence.owner_guard
            or env.authority.purpose != evidence.request.purpose
            or env.authority.audience != evidence.request.audiences
            or request.recall_policy_digest != bundle.d06_recall.policy_digest):
        raise ValueError("Self C04 changed its actual independent Foreground issuance")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    actual = read_adopted_ingress_c03_selection_v1(db, namespace=ns, c02_operation_id=request.c02_operation_id)
    if actual is None:
        raise MissingProductionOriginalV1("actual_adopted_c03_direct_selection")
    selected, original, bridge = actual
    ref = "d06-current:" + original["original_digest"][:48]
    if (selected.selected_source_ref is None or ref != request.c03_selection_ref
            or canonical_digest(selected) != request.c03_selection_digest
            or (selected.cycle_job_ref, selected.cue_source_ref) != (request.job_ref, request.source_ref)
            or (selected.installation_id, selected.manifest_digest) !=
                (bundle.installation_policy.installation_id, bundle.installation_policy.manifest_digest)
            or selected.audience != env.authority.audience or selected.purpose != env.authority.purpose
            or (selected.access_epoch, selected.delete_epoch) != (evidence.access_epoch, evidence.delete_epoch)):
        raise ValueError("Self C04 selection differs from the actual C03 metadata CAS")
    ids = ingress_c04_ids_v4(ns, request.c02_operation_id, original["original_digest"])
    if (env.identity.operation_id != ids["prepare"] or env.identity.effect_id != ids["effect"]
            or env.identity.activity_id != selected.child_activity_id):
        raise ValueError("Self C04 child identity is not its fixed adopted C03 child")
    routing = read_adopted_ingress_recall_routing_v1(db, namespace=ns,
        c02_operation_id=request.c02_operation_id, issuer=graph._GraphCoordinator__d11_issuer)
    if routing is None or canonical_digest(routing) != selected.routing_adoption_digest:
        raise ValueError("Self C04 profile lost its exact adopted C3 routing")
    profile = next(profile for profile in bundle.d06_recall.profiles if profile.name == routing["mode"])
    policy = bundle.d06_recall
    budget = AssociationBudgetV3(profile.max_hops, policy.max_edges, profile.max_nodes,
        policy.max_iterations, min(profile.max_candidates, policy.max_recollection_candidates))
    family = read.source_family(db, (request.source_ref, selected.selected_source_ref))
    qualified_sources = {v.key.token for v in evidence.read_versions if v.key.type_name == "memory.source" and v.revision > 0}
    if not set(family) <= qualified_sources:
        raise ValueError("Self C04 historical roots were not independently qualified in this issuance")
    selected_head = read.head(db, selected.selected_source_ref, required=True)
    if (selected_head.revision != selected.selected_source_revision
            or canonical_digest(selected_head.value) != selected.selected_source_digest):
        raise ValueError("Self C04 selected Source changed since actual C03 selection")
    cycle = get_job(db, AtomKey.from_token(request.job_ref).name)
    if (read.head(db, request.job_ref, required=True).value != job_graph_write(cycle).value
            or cycle.cancel_epoch != selected.cancel_generation or cycle.cancel_epoch
            or cycle.phase != "running" or cycle.lease_holder != env.authority.actor):
        raise ValueError("Self C04 parent cycle is not the actual running Self responsibility")
    issuer = graph._GraphCoordinator__d11_issuer
    responsibility = require_current_foreground_responsibility_v1(db, namespace=ns, job=cycle,
        installed_bundle=bundle, issuer=issuer, owner_guard=frame.owner_guard,
        purpose=env.authority.purpose, audiences=env.authority.audience, now_utc=frame.now_utc)
    if (responsibility is None or responsibility.digest != selected.responsibility_digest
            or env.deadline_utc > responsibility.deadline_utc or frame.now_utc >= env.deadline_utc):
        raise ValueError("Self C04 changed its original responsibility/deadline")
    resolve_current_foreground_reply_budget_v1(db, namespace=ns, c02_operation_id=request.c02_operation_id,
        source_ref=request.source_ref, issuer=issuer, installed_bundle=bundle, now_utc=frame.now_utc)
    from ..authority_service.v2_self_identity_contract import to_wire
    material=_self_c04_scope_preimage_v4(request=request,selection_original_digest=original["original_digest"],
        current_self=evidence.current_self,owner_guard=frame.owner_guard,authority=env.authority,identity=env.identity,
        deadline=env.deadline_utc,budget=budget,policy=policy.policy_digest,
        responsibility_digest=responsibility.digest,c03_metadata_bridge=bridge)
    digest=canonical_digest(material)
    captured=(canonical_serialize(material),canonical_serialize(to_wire(evidence.current_self)))
    return selected,original["original_digest"],ref,budget,digest,captured


@contextmanager
def issue_self_c04_scope_v4(graph, *, issued, scope, frame, request, bundle):
    db = graph._GraphCoordinator__store._db
    selection, original_digest, ref, budget, digest, captured = _qualified_values(db, graph=graph, issued=issued,
        scope=scope, frame=frame, request=request, bundle=bundle)
    value = _IssuedSelfC04ScopeV4(_KEY, graph=graph, issued=issued, scope=scope, frame=frame,
        request=request, bundle=bundle, selection=selection, selection_original_digest=original_digest,
        selection_ref=ref, budget=budget, identity_digest=digest,
        scope_payload_json=captured[0],current_self_json=captured[1])
    _ACTIVE[id(value)] = value
    try:
        yield value
    finally:
        del _ACTIVE[id(value)]


def require_self_c04_scope_v4(value, db):
    if type(value) is not _IssuedSelfC04ScopeV4 or _ACTIVE.get(id(value)) is not value:
        raise ValueError("actual private Self C04 scope is absent")
    current = _qualified_values(db, graph=value.graph, issued=value.issued, scope=value.scope,
        frame=value.frame, request=value.request, bundle=value.bundle)
    if current != (value.selection, value.selection_original_digest, value.selection_ref, value.budget, value.identity_digest,
            (value.scope_payload_json,value.current_self_json)):
        raise ValueError("Self C04 exact current scope changed")
    return value


def export_self_c04_scope_original_v5(value,db,*,expected_digest):
    """Consume the actual private issuance before its preparation mutates Graph."""
    import json
    from ..authority_service.v2_self_identity_contract import from_wire,to_wire,AuthorityCurrentSelfIdentityV1
    actual=require_self_c04_scope_v4(value,db)
    material=json.loads(actual.scope_payload_json);wire=json.loads(actual.current_self_json)
    current=from_wire(wire)
    if (type(current) is not AuthorityCurrentSelfIdentityV1 or to_wire(current)!=wire
            or canonical_digest(material)!=actual.identity_digest or actual.identity_digest!=expected_digest
            or canonical_serialize(current)!=canonical_serialize(material['self'])):
        raise ValueError("Self C04 private preimage differs from its actual issued work")
    return canonical_serialize({'schema':'c04.self-preparation-original.v1','scope_payload':material,'current_self_wire':wire})


def collect_self_c04_graph_v4(db, *, scope, focus_ref, attention_ticket_ref, mood_ref, context_tags=()):
    from .c04_association_graph_collector_v2 import _collect_c04_association_graph_originals_from_roots_v2
    from ..domains.d06.current_association_candidates import CurrentAssociationBudgetV1
    actual = require_self_c04_scope_v4(scope, db)
    s, budget = actual.selection, actual.budget
    result = _collect_c04_association_graph_originals_from_roots_v2(db, s.namespace,
        cue_source_ref=s.cue_source_ref, focus_ref=focus_ref, attention_ticket_ref=attention_ticket_ref,
        mood_ref=mood_ref, budget=CurrentAssociationBudgetV1(budget.max_hops, budget.max_edges,
            budget.max_nodes, budget.max_iterations, budget.max_candidates), context_tags=context_tags,
        activation_roots=(s.cue_source_ref, s.selected_source_ref))
    # Positive direct selection is requalified; the historical negative/query
    # epoch remains in the C03 original, never refreshed by this collector.
    source = next(row for row in result.reads if row.key.token == s.selected_source_ref)
    if source.revision != s.selected_source_revision or canonical_digest(source.value) != s.selected_source_digest:
        raise ValueError("Self C04 collection changed the actual C03 selected Source")
    return result


def prepare_self_c04_body_resources_v4(db, *, scope, work):
    """Materialize signed CPU/Body resources once; caller owns final CAS/freeze."""
    from .c04_direct_seed_v4 import AssociationWorkInputV4
    from .c04_frozen_association_original_v3 import _verify_current_association_input_heads_common_v3
    from .c04_prepare_service_v3 import _prepare_c04_body_resources_v3
    from ..graph_types import GraphVersion
    actual = require_self_c04_scope_v4(scope, db)
    env = actual.frame.envelope
    selection = actual.selection
    ids = ingress_c04_ids_v4(selection.namespace, selection.c02_operation_id, actual.selection_original_digest)
    if (type(work) is not AssociationWorkInputV4 or work.direct_selection != selection
            or work.c03_selection_ref != actual.selection_ref
            or work.c03_selection_original_digest != actual.selection_original_digest
            or work.self_scope_digest != actual.identity_digest
            or work.namespace != selection.namespace or work.activity_id != selection.child_activity_id
            or work.operation_id != env.identity.operation_id or work.budget != actual.budget
            or (work.purpose, (work.audience,)) != (env.authority.purpose, env.authority.audience)
            or work.graph_epoch != actual.frame.snapshot.epochs[0].revision
            or (work.access_epoch, work.delete_epoch) !=
                (actual.frame.envelope.version_guard.access_epoch, actual.frame.envelope.version_guard.delete_epoch)
            or work.owner_epoch != actual.scope.pinned_anchor.revocation_epoch):
        raise ValueError("Self C04 work differs from its actual private selected inputs")
    # This helper verifies real Source/Mood/checkpoint/baseline currentness;
    # neither its input DTO nor its returned resources is an execution permit.
    _verify_current_association_input_heads_common_v3(db, work)
    heads = {row.ref: row for row in work.reads}
    ticket = heads[work.attention_ticket_ref].value
    if ticket["valid_until"] < env.deadline_utc:
        raise ValueError("Self C04 deadline exceeds its actual attention lifetime")
    authority = actual.graph._GraphCoordinator__c04_cpu_quote_authority
    quote = authority.request_self_quote_v4(db, scope=actual)
    reads = {AtomKey.from_token(row.ref): row.revision for row in work.reads}
    for target in work.targets:
        reads[AtomKey.from_token(target.condition.current_checkpoint.ref)] = target.condition.current_checkpoint.revision
    reads[AtomKey.from_token(actual.frame.owner_guard.grant_ref)] = actual.frame.owner_guard.grant_revision
    policy = actual.bundle.d06_recall
    return _prepare_c04_body_resources_v3(db, envelope=env, resource=quote,
        body_policy_id=policy.body_policy_id, body_policy_version=policy.body_policy_version,
        reservation_id=ids["reservation"], d02_issuer=actual.graph._GraphCoordinator__d02_issuer,
        body_authority=actual.graph._GraphCoordinator__body_quote_authority,
        now_utc=actual.frame.now_utc,
        original_reads=tuple(GraphVersion(key, revision) for key, revision in sorted(reads.items(), key=lambda pair: pair[0].token)))
