"""Adopt project context from an explicit Owner choice or installed Self standing scope."""
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


@dataclass(frozen=True, slots=True)
class PrepareArtifactDraftProjectContextRequestV1:
    project_ref: str
    recipe_ref: str
    source_ref: str
    social_role: str
    norm_refs: tuple[str, ...]

    def __post_init__(self):
        PrepareLifeProjectContextRequestV1(self.project_ref, self.source_ref, self.social_role, self.norm_refs)
        if AtomKey.from_token(self.recipe_ref).type_name != "d10.activity_recipe.v1":
            raise ValueError("artifact context requires its actual adopted recipe selector")


@dataclass(frozen=True, slots=True)
class AdoptOwnerArtifactProjectContextRequestV1(PrepareArtifactDraftProjectContextRequestV1):
    """The five explicit Owner choice fields; no Self actor or permission input."""


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


def read_plan_artifact_draft_project_context_v1(db, *, namespace, request):
    from ..domains.d03.self_perspective import self_mapping_key
    from .d10_project_checkpoint_v1 import artifact_project_context_read_inputs_v1
    if type(request) not in {PrepareArtifactDraftProjectContextRequestV1, AdoptOwnerArtifactProjectContextRequestV1}:
        raise TypeError("exact artifact project context request required")
    keys, roots, originals = artifact_project_context_read_inputs_v1(db, namespace=namespace, project_ref=request.project_ref)
    return production_read_plan_v1(("d12.active_scheme_head.v1",),
        (owner_grant_key(*namespace.as_tuple), *keys, AtomKey.from_token(request.recipe_ref), self_mapping_key(namespace),
            *life_project_context_keys_v1(namespace, request.project_ref)), roots, originals)


def stage_prepare_artifact_draft_project_context_in_transaction_v1(db, *, frame, request, installed_readers):
    from ..domains.d03.self_perspective import SelfIdentityMapping, self_mapping_key
    from .d10_project_checkpoint_v1 import (read_current_artifact_project_definition_v1,
        artifact_project_context_read_inputs_v1)
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
    from .d01_production_operations_v1 import waiting_stage_v1
    if (type(request) is not PrepareArtifactDraftProjectContextRequestV1
            or type(installed_readers) is not InstalledArtifactDraftModelReadersV1):
        raise TypeError("artifact context needs its exact request and installed task readers")
    try:
        read = CurrentDomainReadV1(frame)
        read.check(db)
        ns = frame.envelope.authority.namespace
        from ..host.authority_profile import AdminArtifactDraftPolicyV2
        policy=installed_readers.installed_bundle.artifact_draft
        if type(policy) is AdminArtifactDraftPolicyV2 and (request.social_role,request.norm_refs)!=(
                policy.standing_scope.social_role,policy.standing_scope.norm_refs):
            raise ValueError("Self project role differs from the actual initial standing envelope")
        if frame.envelope.authority.purpose != "consolidation":
            raise ValueError("artifact context must retain its actual admitted consolidation purpose")
        project, _ = read_current_artifact_project_definition_v1(db, frame=frame,
            project_ref=request.project_ref, recipe_ref=request.recipe_ref, source_ref=request.source_ref)
        _, roots, _ = artifact_project_context_read_inputs_v1(db, namespace=ns, project_ref=request.project_ref)
        mapping_atom = read.head(db, self_mapping_key(ns), required=True)
        mapping = SelfIdentityMapping(**mapping_atom.value)
        if (mapping.status != "active" or mapping.self_entity_ref != frame.envelope.authority.actor
                or mapping.persona_ref != "persona:" + ns.persona_id):
            raise MissingProductionOriginalV1("actual_current_artifact_project_self_mapping")
        read.original(mapping.certification_ref, kind="d03.current_self_identity")
        entity_key, role_key = life_project_context_keys_v1(ns, request.project_ref)
        if any(read.head(db, key).revision for key in (entity_key, role_key)):
            raise ValueError("artifact context cannot replace an adopted entity or role")
        provider = _context_provider(db, read)
        entity = EntityAnchor(entity_key.name, "activity", mapping.persona_ref,
            (request.project_ref, *roots, mapping_atom.key.token), "active")
        role = RoleBinding(role_key.name, mapping.persona_ref, request.social_role, entity.entity_id,
            None, None, "exact_project_target", mapping.persona_ref, request.norm_refs,
            frame.now_utc, None, 0, roots, 1, "active")
        resolution = provider.resolve_role_binding(RoleBindingRequest(mapping.persona_ref, entity.entity_id,
            None, None, "artifact_draft_v1", "consolidation", frame.now_utc, True), (role,))
        if resolution.status != "complete":
            raise MissingProductionOriginalV1("actual_artifact_project_context_role_norm_catalogue")
        writes = (GraphWrite(entity_key, plain_v1(entity),
            (project.key, mapping_atom.key, *(AtomKey.from_token(ref) for ref in roots))), GraphWrite(role_key, plain_v1(role)))
        stage = stage_result_v1(frame, "d03", "prepare_artifact_draft_project_context", request, writes=writes,
            provenance={"artifact_project_ref": request.project_ref, "artifact_recipe_ref": request.recipe_ref,
                "artifact_context_source_refs": roots, "self_mapping_ref": mapping_atom.key.token},
            receiver_events=(("d08", "artifact_project_context_available"),),
            proposal_schema="d03.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
        provider.validate(stage.proposals[0], frame.snapshot)
        return verify_d03_artifact_project_context_stage_v1(stage)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d03", "prepare_artifact_draft_project_context", request, missing)


def verify_d03_artifact_project_context_stage_v1(stage):
    if stage.domain != "d03" or stage.operation_kind != "prepare_artifact_draft_project_context":
        raise ValueError("unregistered artifact project context stage")
    provider = ContextProvider()
    for proposal in stage.proposals:
        provider.validate(proposal)
        if tuple(write.key.type_name for write in proposal.typed_writes) != ("d03.entity_anchor", "d03.role_binding"):
            raise ValueError("artifact context requires exactly its registered entity and role writes")
    return stage


def stage_adopt_owner_artifact_project_context_in_transaction_v1(db, *, frame, request, installed_readers):
    from ..domains.d03.self_perspective import SelfIdentityMapping, self_mapping_key
    from .d10_project_checkpoint_v1 import read_current_artifact_project_definition_v1, artifact_project_context_read_inputs_v1
    from .d11_artifact_draft_model_v1 import InstalledArtifactDraftModelReadersV1
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    if (type(request) is not AdoptOwnerArtifactProjectContextRequestV1
            or type(installed_readers) is not InstalledArtifactDraftModelReadersV1
            or type(installed_readers.owner_assignment_guard) is not OwnerAuthorizationGuardV1):
        raise TypeError("project role adoption requires its exact Owner request and installed Owner readers")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns, owner = frame.envelope.authority.namespace, installed_readers.owner_assignment_guard
    if (frame.envelope.authority.purpose != "consolidation" or owner.namespace != ns
            or owner.authorization_head.removeprefix("sha256:") != frame.owner_guard.owner_head_digest):
        raise ValueError("project role adoption lost its actual current Owner frame")
    project, _ = read_current_artifact_project_definition_v1(db, frame=frame,
        project_ref=request.project_ref, recipe_ref=request.recipe_ref, source_ref=request.source_ref)
    _, roots, _ = artifact_project_context_read_inputs_v1(db, namespace=ns, project_ref=request.project_ref)
    mapping_atom = read.head(db, self_mapping_key(ns), required=True)
    mapping = SelfIdentityMapping(**mapping_atom.value)
    if mapping.status != "active" or mapping.persona_ref != "persona:" + ns.persona_id:
        raise MissingProductionOriginalV1("actual_current_artifact_project_self_mapping")
    certification = read.original(mapping.certification_ref, kind="d03.current_self_identity")
    entity_key, role_key = life_project_context_keys_v1(ns, request.project_ref)
    if any(read.head(db, key).revision for key in (entity_key, role_key)):
        raise ValueError("Owner project role adoption cannot replace an existing binding")
    provider = _context_provider(db, read)
    entity = EntityAnchor(entity_key.name, "activity", mapping.persona_ref,
        (request.project_ref, *roots, mapping_atom.key.token), "active")
    role = RoleBinding(role_key.name, mapping.persona_ref, request.social_role, entity.entity_id,
        None, None, "exact_project_target", mapping.persona_ref, request.norm_refs, frame.now_utc, None, 0, roots, 1, "active")
    resolution = provider.resolve_role_binding(RoleBindingRequest(mapping.persona_ref, entity.entity_id,
        None, None, "artifact_draft_v1", "consolidation", frame.now_utc, True), (role,))
    if resolution.status != "complete":
        raise MissingProductionOriginalV1("actual_artifact_project_context_role_norm_catalogue")
    writes = (GraphWrite(entity_key, plain_v1(entity),
        (project.key, mapping_atom.key, *(AtomKey.from_token(ref) for ref in roots))), GraphWrite(role_key, plain_v1(role)))
    stage = stage_result_v1(frame, "d03", "adopt_owner_artifact_project_context_v1", request, writes=writes,
        provenance={"artifact_project_ref": request.project_ref, "artifact_recipe_ref": request.recipe_ref,
            "artifact_context_source_refs": roots, "self_mapping_ref": mapping_atom.key.token,
            "self_certification_ref": certification.original_ref, "self_certification_digest": certification.original_digest,
            "owner_actor_ref": frame.envelope.authority.actor},
        receiver_events=(("d08", "artifact_project_context_available"),),
        proposal_schema="d03.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
    for proposal in stage.proposals:
        provider.validate(proposal, frame.snapshot)
    return stage


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
