"""Actual Owner authorizes one SourceNote task; Source and work permissions remain independent."""
from dataclasses import dataclass
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d08.personal_plan_v1 import PersonalPlanV1
from ..graph_types import AtomKey, GraphVersion, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .domain_production_contracts_v1 import ProductionOwnerGuardV1
from .domain_production_erasure_v1 import decode_typed_production_value_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d11_life_preparation_v1 import _read, _record
from .budget import get_budget_lease, require_budget_family_admissible

OPERATION = "authorize_source_note_task_v1"
KIND = "source_note_task_authorization"
SCHEMA = "d11.source-note-task-authorization.v1"
NOTE_WORK_KIND = "d10.life.source_note.v1"
HEAD_KINDS = {"source": "memory.source", "body_source": "memory.source", "goal": "d08.goal.v1",
    "plan": "d08.personal_plan.v1", "project": "d10.life_project.v1", "recipe": "d10.activity_recipe.v1",
    "target": "d03.entity_anchor", "role": "d03.role_binding", "account": "d03.account_binding"}


@dataclass(frozen=True, slots=True)
class AuthorizeSourceNoteTaskRequestV1:
    c02_operation_id: str
    source_ref: str
    body_source_ref: str
    goal_ref: str
    plan_ref: str
    project_ref: str
    recipe_ref: str
    target_entity_ref: str
    role_binding_ref: str
    account_binding_ref: str

    @property
    def head_refs(self):
        return {"source": self.source_ref, "body_source": self.body_source_ref, "goal": self.goal_ref,
            "plan": self.plan_ref, "project": self.project_ref, "recipe": self.recipe_ref,
            "target": self.target_entity_ref, "role": self.role_binding_ref, "account": self.account_binding_ref}

    def __post_init__(self):
        if type(self.c02_operation_id) is not str or not self.c02_operation_id:
            raise ValueError("SourceNote authorization requires its actual C02 original locator")
        for name, ref in self.head_refs.items():
            if AtomKey.from_token(ref).type_name != HEAD_KINDS[name]:
                raise ValueError("SourceNote authorization requires actual typed current selectors")


@dataclass(frozen=True, slots=True)
class SourceNoteTaskAuthorizationV1:
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    request: AuthorizeSourceNoteTaskRequestV1
    authorization_operation_id: str
    owner_guard: ProductionOwnerGuardV1
    owner_actor_ref: str
    cause_original_ref: str
    cause_original_digest: str
    heads: tuple[tuple[str, GraphVersion, str], ...]
    parent_budget_lease_ref: str
    parent_grant_id: str
    parent_grant_version: int
    parent_grant_digest: str
    c02_receipt_digest: str
    c02_commit_seq: int
    original_deadline_utc: float
    source_refs: tuple[str, ...]
    schema: str = SCHEMA

    def __post_init__(self):
        if (self.schema != SCHEMA or type(self.namespace) is not NamespaceId
                or type(self.request) is not AuthorizeSourceNoteTaskRequestV1
                or type(self.owner_guard) is not ProductionOwnerGuardV1
                or {row[0] for row in self.heads} != set(HEAD_KINDS) or len(self.heads) != len(HEAD_KINDS)
                or self.parent_grant_version < 1 or self.c02_commit_seq < 1):
            raise ValueError("SourceNote authorization requires its exact actual Owner/task/root original")
        for name, version, digest in self.heads:
            if (type(version) is not GraphVersion or version.revision < 1
                    or version.key.token != self.request.head_refs[name]
                    or NamespaceId.from_key(version.key) != self.namespace or len(digest) != 64):
                raise ValueError("SourceNote authorization current head commitment differs")
        if not self.source_refs or any(AtomKey.from_token(ref).type_name != "memory.source" for ref in self.source_refs):
            raise ValueError("SourceNote authorization needs actual bounded Source roots")

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))

    @property
    def original_ref(self):
        return "source-note-task-authorization:" + canonical_digest((self.namespace, self.authorization_operation_id))[:48]


_READERS_KEY = object()


class InstalledSourceNoteTaskAuthorizationReadersV1:
    def __init__(self, key, *, issuer, installed_bundle, owner_guard, owner_binding, generation):
        if key is not _READERS_KEY:
            raise TypeError("SourceNote authorization requires its actual Owner fence factory")
        self.issuer, self.installed_bundle = issuer, installed_bundle
        self.owner_guard, self.owner_binding, self.generation = owner_guard, owner_binding, generation

    def require_owner_frame(self, frame):
        owner, authority = self.owner_binding, frame.envelope.authority
        if (authority.actor != owner.actor or "workbench.create" not in owner.capabilities
                or frame.owner_guard.grant_ref != owner_grant_key(*authority.namespace.as_tuple).token
                or (frame.owner_guard.grant_revision, frame.owner_guard.grant_digest) != (owner.grant_revision, owner.grant_digest)
                or frame.owner_guard.owner_head_digest != self.owner_guard.authorization_head.removeprefix("sha256:")
                or frame.activation_generation != self.generation or authority.activation_generation != self.generation
                or authority.purpose not in owner.purposes or not set(authority.audience) <= owner.audiences):
            raise ValueError("SourceNote authorization changed this actual Owner lease/frame scope")


def install_source_note_task_authorization_readers_v1(graph, *, scope, owner_guard, owner_binding):
    from ..graph_coordinator import GraphCoordinator, OwnerLeaseBindingV1
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    if (type(graph) is not GraphCoordinator or type(owner_guard) is not OwnerAuthorizationGuardV1
            or type(owner_binding) is not OwnerLeaseBindingV1
            or not any(binding is owner_binding for binding in graph._GraphCoordinator__owner_leases.values())
            or owner_guard.namespace != scope.namespace or owner_binding.namespace != scope.namespace
            or owner_guard.authorization_head != owner_binding.authorization_head
            or owner_guard.authorization_revision != owner_binding.authorization_revision
            or owner_guard.pending_revoke_operation_id is not None):
        raise ValueError("SourceNote authorization requires this invocation's actual current Owner binding")
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None:
        raise MissingProductionOriginalV1("actual_SourceNote_installed_initial_bundle")
    return InstalledSourceNoteTaskAuthorizationReadersV1(_READERS_KEY,
        issuer=graph._GraphCoordinator__d11_issuer, installed_bundle=assembly.admin_bundle,
        owner_guard=owner_guard, owner_binding=owner_binding, generation=scope.generation)


def _actual_authorization(db, *, frame, request, readers):
    if type(readers) is not InstalledSourceNoteTaskAuthorizationReadersV1:
        raise TypeError("actual installed Owner SourceNote authorization readers required")
    readers.require_owner_frame(frame)
    read = CurrentDomainReadV1(frame); read.check(db)
    bundle = readers.installed_bundle
    ns = frame.envelope.authority.namespace
    if bundle is None or bundle.installation_policy.namespace != ns:
        raise MissingProductionOriginalV1("actual_installed_source_note_owner_authorization_bundle")
    heads = {name: read.head(db, ref, required=True) for name, ref in request.head_refs.items()}
    grant_head = read.head(db, owner_grant_key(*ns.as_tuple), required=True)
    if (grant_head.key.token, grant_head.revision, canonical_digest(grant_head.value)) != (
            frame.owner_guard.grant_ref, frame.owner_guard.grant_revision, frame.owner_guard.grant_digest):
        raise ValueError("SourceNote task requires this exact actual Owner grant")
    plan = decode_typed_production_value_v1(heads["plan"].value, PersonalPlanV1)
    target, role, account = heads["target"].value, heads["role"].value, heads["account"].value
    if (plan.goal_ref != request.goal_ref or plan.goal_revision != heads["goal"].value["revision"]
            or plan.state != "active" or heads["goal"].value["state"] != "active"
            or target["status"] != "active" or role["status"] != "active"
            or role["target_entity_ref"] != target["entity_id"]
            or role["subject_persona_ref"] != "persona:" + ns.persona_id
            or frame.now_utc < role["effective_from"]
            or role["effective_until"] is not None and frame.now_utc >= role["effective_until"]
            or frame.now_utc < account["valid_from"]
            or account["valid_until"] is not None and frame.now_utc >= account["valid_until"]):
        raise MissingProductionOriginalV1("actual_current_explicit_source_note_Goal_Plan_target_role_account")
    # The existing project/recipe parser remains the authority for the activity kind.
    project = heads["project"].value; recipe = heads["recipe"].value
    from .d11_life_contract_v1 import RECIPE_ID
    if (project["reality"] != "real_execution" or project["next_step"] != "source_note"
            or recipe != {"recipe_id": RECIPE_ID, "version": 1, "reality": "real_execution",
                "allowed_steps": ["source_note"], "preemptible": True}):
        raise ValueError("SourceNote task cannot borrow an artifact project or recipe")
    from .foreground_cycle_v1 import _adopted_c02_v1
    c02 = _adopted_c02_v1(db, ns, request.c02_operation_id)
    from .foreground_cycle_v1 import require_actual_c02_cue_source_v1
    require_actual_c02_cue_source_v1(db, namespace=ns, c02_operation_id=request.c02_operation_id,
        source_version=GraphVersion(heads["source"].key,heads["source"].revision))
    from .ingress_observation import read_committed_ingress_identity
    from ..memory_types import SourceRecord
    identity = read_committed_ingress_identity(db, ns, SourceRecord.from_dict(heads["source"].value).source_id)
    if identity is None:
        raise MissingProductionOriginalV1("actual_source_note_C02_ingress_identity")
    ingress = json.loads(identity.identity_json)
    if (account["platform_namespace"], account["platform_identifier"]) != (ingress["platform_ref"], ingress["sender_ref"]):
        raise ValueError("SourceNote account commitment differs from its actual cue sender")
    roots = tuple(dict.fromkeys((request.source_ref, request.body_source_ref, *plan.source_refs, *role["source_refs"])))
    read.source_family(db, roots)
    for name in ("goal", "plan", "project", "recipe", "target", "role", "account"):
        atom = heads[name]
        history = db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?", (atom.key.token, atom.revision)).fetchone()
        if history is None:
            raise MissingProductionOriginalV1("actual_source_note_authorized_head_origin")
        read.committed_operation(db, history[0])
        original = read_adopted_domain_operation_v1(db, ns, history[0])
        if name in {"goal", "plan"} and (original is None
                or original["domain"] != "d08"
                or original["operation_kind"] not in {"create_personal_plan", "revise_personal_plan"}
                or original["payload"]["authority"]["actor"] != frame.envelope.authority.actor):
            raise MissingProductionOriginalV1("actual_Owner_SourceNote_personal_Goal_Plan_producer")
    parent = get_budget_lease(db, frame.envelope.parent_budget_lease_ref)
    require_budget_family_admissible(db, parent.lease_id)
    root = readers.issuer.current_budget_grant(db, parent.lease_id)
    if (parent.lease_id != bundle.installation_policy.root_lease.lease_id or root != bundle.installation_policy.root_grant
            or NOTE_WORK_KIND not in root.allowed_work_kinds):
        raise MissingProductionOriginalV1("original_root_already_allows_source_note")
    from .foreground_cycle_v1 import (foreground_post_c02_cause_ref_v1, foreground_deadline_utc_v1)
    from .c09_life_originals_v1 import read_foreground_post_c02_cause_original_v1
    from dataclasses import asdict
    cause_ref = foreground_post_c02_cause_ref_v1(ns, request.c02_operation_id)
    cause = read_foreground_post_c02_cause_original_v1(db, namespace=ns, issuer=readers.issuer, original_ref=cause_ref)
    policy = bundle.foreground
    if policy is None or policy.deadline_policy.natural is None:
        raise MissingProductionOriginalV1("installed_SourceNote_original_causal_deadline_policy")
    if (cause.installation_id != bundle.installation_policy.installation_id
            or cause.manifest_digest != bundle.installation_policy.manifest_digest
            or cause.c02_operation_id != request.c02_operation_id or cause.source_ref != request.source_ref
            or cause.source_revision != heads["source"].revision
            or cause.source_digest != canonical_digest(heads["source"].value)
            or cause.c02_receipt_digest != canonical_digest(c02)
            or cause.foreground_policy_digest != canonical_digest(asdict(policy))
            or cause.deadline_policy_digest != canonical_digest(asdict(policy.deadline_policy))):
        raise ValueError("SourceNote authorization changed its original frozen C02 cause")
    read.original(cause_ref)
    sealed = db.execute("SELECT seal_json FROM graph_first_ingress_c02_committed_seals_v2 WHERE bot=? AND persona=? AND operation_id=?",
        (*ns.as_tuple, request.c02_operation_id)).fetchone()
    if sealed is None:
        raise MissingProductionOriginalV1("actual_SourceNote_original_C02_absolute_business_deadline")
    seal = json.loads(sealed[0])
    deadline = min(frame.envelope.deadline_utc, root.valid_until_utc, seal["root_grant_valid_until_utc"],
        seal["business_deadline_utc"], cause.cause_frozen_at_utc + policy.deadline_policy.natural.window_seconds)
    goal_deadline = heads["goal"].value["satisfaction_predicate"]["valid_until"]
    if goal_deadline is not None: deadline = min(deadline, goal_deadline)
    if deadline <= frame.now_utc:
        raise MissingProductionOriginalV1("actual_source_note_original_absolute_deadline")
    return SourceNoteTaskAuthorizationV1(ns, bundle.installation_policy.installation_id,
        bundle.installation_policy.manifest_digest, request, frame.envelope.identity.operation_id, frame.owner_guard, frame.envelope.authority.actor,
        cause_ref, canonical_digest(plain_v1(cause)),
        tuple((name, GraphVersion(atom.key, atom.revision), canonical_digest(atom.value)) for name, atom in sorted(heads.items())),
        parent.lease_id, root.grant_id, root.version, canonical_digest(root), canonical_digest(c02), c02.commit_seq,
        foreground_deadline_utc_v1(deadline), roots)


def stage_authorize_source_note_task_v1(db, *, frame, request, installed_readers):
    if type(request) is not AuthorizeSourceNoteTaskRequestV1:
        raise TypeError("exact Owner SourceNote authorization request required")
    value = _actual_authorization(db, frame=frame, request=request, readers=installed_readers)
    from .d11_types import D11RuntimeProvider, D11_PROPOSAL_SCHEMA
    return stage_result_v1(frame, "d11", OPERATION, request, provenance={"source_note_task_authorization": value},
        proposal_schema=D11_PROPOSAL_SCHEMA, proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)


def record_source_note_task_authorization_after_cas_v1(db, *, frame, stage, receipt, installed_readers):
    value = decode_typed_production_value_v1(json.loads(stage.original_payload_json)["provenance"]["source_note_task_authorization"], SourceNoteTaskAuthorizationV1)
    if receipt.status != "committed" or receipt.operation_id != value.authorization_operation_id:
        raise ValueError("SourceNote authorization needs its actual Owner W01 receipt")
    return _record(db, issuer=installed_readers.issuer, namespace=value.namespace, kind=KIND,
        ref=value.original_ref, operation_id=value.authorization_operation_id, value=value)


def read_source_note_task_authorization_v1(db, *, namespace, original_ref, issuer):
    saved = _read(db, issuer=issuer, namespace=namespace, kind=KIND, ref=original_ref)
    if saved is None: return None
    value = decode_typed_production_value_v1(saved[0], SourceNoteTaskAuthorizationV1)
    actual = read_adopted_domain_operation_v1(db, namespace, saved[1])
    if (value.namespace != namespace or value.original_ref != original_ref or value.digest != canonical_digest(saved[0])
            or actual is None or actual["operation_kind"] != OPERATION or actual["receipt"].status != "committed"
            or actual["payload"]["provenance"]["source_note_task_authorization"] != saved[0]):
        raise ValueError("SourceNote task authorization lost its actual signed Owner operation")
    return value, actual


def read_plan_source_note_task_authorization_v1(db, *, namespace, request):
    keys = [owner_grant_key(*namespace.as_tuple), *(AtomKey.from_token(ref) for ref in request.head_refs.values())]
    roots = [request.source_ref, request.body_source_ref]
    for ref in (request.plan_ref, request.role_binding_ref):
        row = db.execute("SELECT value FROM graph_atoms WHERE token=? AND valid=1", (ref,)).fetchone()
        if row: roots.extend(json.loads(row[0])["source_refs"])
    from .foreground_cycle_v1 import foreground_post_c02_cause_ref_v1
    originals = (request.c02_operation_id, foreground_post_c02_cause_ref_v1(namespace, request.c02_operation_id),
        *(ref for name, ref in request.head_refs.items() if name not in {"source", "body_source"}))
    return production_read_plan_v1((), keys, tuple(dict.fromkeys(roots)), originals)
