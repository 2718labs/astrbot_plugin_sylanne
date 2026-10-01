"""An explicit Owner operation adopts a project's internal entity and role."""
from dataclasses import dataclass

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d03.context import ContextProvider, EntityAnchor, RoleBinding, RoleBindingRequest
from ..graph_types import AtomKey, GraphWrite, Owner, owner_grant_key
from ..runtime_contracts import canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .d08_life_admission_v1 import _adopted, _context_provider


@dataclass(frozen=True, slots=True)
class PrepareLifeProjectContextRequestV1:
    project_ref: str
    source_ref: str
    social_role: str
    norm_refs: tuple[str, ...]

    def __post_init__(self):
        if (AtomKey.from_token(self.project_ref).type_name != "d10.life_project.v1"
                or AtomKey.from_token(self.source_ref).type_name != "memory.source"
                or type(self.social_role) is not str or not self.social_role
                or type(self.norm_refs) is not tuple or len(self.norm_refs) > 32
                or len(set(self.norm_refs)) != len(self.norm_refs)
                or any(type(v) is not str or not v for v in self.norm_refs)):
            raise ValueError("project context requires an explicit current Owner role and catalogue norm selection")


class InstalledD03LifeProjectContextReaderV1:
    def __init__(self, *, issuer):
        from .issuers import D11BudgetJobIssuer
        if type(issuer) is not D11BudgetJobIssuer:
            raise TypeError("project context needs the actual installed original issuer")
        self.issuer = issuer


def life_project_context_keys_v1(namespace, project_ref):
    tag = canonical_digest((namespace, project_ref))[:48]
    owner = Owner("persona", *namespace.as_tuple)
    return (AtomKey(owner, "d03.entity_anchor", "entity:life-project:" + tag),
        AtomKey(owner, "d03.role_binding", "binding:life-project:" + tag))


def read_plan_life_project_context_v1(db, *, namespace, request):
    return production_read_plan_v1(("d12.active_scheme_head.v1",),
        (owner_grant_key(*namespace.as_tuple), AtomKey.from_token(request.project_ref),
            *life_project_context_keys_v1(namespace, request.project_ref)), (request.source_ref,), (request.project_ref,))


def stage_prepare_life_project_context_in_transaction_v1(db, *, frame, request, installed_readers):
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    project = read.head(db, request.project_ref, required=True)
    _adopted(db, read, project)
    if project.value["reality"] != "real_execution" or project.value["next_step"] != "source_note":
        raise MissingProductionOriginalV1("actual_source_note_project_context")
    for audience in frame.envelope.authority.audience:
        for purpose in ("context", "consolidation"):
            read.source_family(db, (request.source_ref,), purpose=purpose, audience=audience)
    entity_key, role_key = life_project_context_keys_v1(ns, request.project_ref)
    if any(read.head(db, key).revision for key in (entity_key, role_key)):
        raise ValueError("project context cannot overwrite a previously adopted entity or role")
    provider = _context_provider(db, read)
    entity = EntityAnchor(entity_key.name, "activity", "persona:" + ns.persona_id,
        (request.project_ref, request.source_ref), "active")
    role = RoleBinding(role_key.name, "persona:" + ns.persona_id, request.social_role, entity.entity_id,
        None, None, "exact_project_target", "persona:" + ns.persona_id, request.norm_refs,
        frame.now_utc, None, 0, (request.source_ref,), 1, "active")
    resolution = provider.resolve_role_binding(RoleBindingRequest(role.subject_persona_ref, entity.entity_id,
        None, None, "source_note", "consolidation", frame.now_utc, True), (role,))
    if resolution.status != "complete":
        raise MissingProductionOriginalV1("actual_project_context_role_norm_catalogue")
    # Role's relation to the entity is historical provenance of this same
    # event; the new entity is not a pre-existing invalidation dependency.
    writes = (GraphWrite(entity_key, plain_v1(entity), (project.key, AtomKey.from_token(request.source_ref))),
        GraphWrite(role_key, plain_v1(role)))
    stage = stage_result_v1(frame, "d03", "prepare_life_project_context", request, writes=writes,
        provenance={"life_project_ref": request.project_ref, "life_context_source_ref": request.source_ref},
        proposal_schema="d03.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
    provider.validate(stage.proposals[0], frame.snapshot)
    return stage
