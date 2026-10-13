"""D06 actual Owner material intake: authored text with no platform or experience claim."""
from dataclasses import dataclass

from ..domains.d01.production_operations_v1 import stage_result_v1
from ..domains.d06 import D06DomainProvider
from ..graph_types import GraphWrite, owner_grant_key
from ..memory_types import SourceRecord, source_key, access_key, validate_access
from ..runtime_contracts import canonical_digest
from .source_note_task_authorization_v1 import install_source_note_task_authorization_readers_v1
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .budget import get_budget_lease, require_budget_family_admissible

OPERATION = 'admit_owner_material_source_v1'
MAX_TEXT_CHARACTERS = 65536


@dataclass(frozen=True, slots=True)
class AdmitOwnerMaterialSourceRequestV1:
    text: str

    def __post_init__(self):
        if type(self.text) is not str or not self.text.strip() or len(self.text) > MAX_TEXT_CHARACTERS:
            raise ValueError('Owner material requires nonempty text within the actual SourceRecord character bound')


def owner_material_source_id_v1(namespace, operation_id):
    return canonical_digest(('d06.owner-material-source.v1',namespace,operation_id))


def install_owner_material_source_readers_v1(graph, *, scope, owner_guard, owner_binding):
    return install_source_note_task_authorization_readers_v1(graph,scope=scope,owner_guard=owner_guard,owner_binding=owner_binding)


def validated_owner_material_source_v1(db, *, frame, request, installed_readers):
    from .source_note_task_authorization_v1 import InstalledSourceNoteTaskAuthorizationReadersV1
    if type(request) is not AdmitOwnerMaterialSourceRequestV1 or type(installed_readers) is not InstalledSourceNoteTaskAuthorizationReadersV1:
        raise TypeError('Owner material uses its actual current Owner binding factory')
    installed_readers.require_owner_frame(frame)
    owner = installed_readers.owner_binding
    if 'owner' not in owner.audiences or not {'context','consolidation'} <= set(owner.purposes):
        raise MissingProductionOriginalV1('actual_Owner_material_rights_for_owner_context_consolidation')
    read = CurrentDomainReadV1(frame); read.check(db)
    ns = frame.envelope.authority.namespace
    owner_head = read.head(db,owner_grant_key(*ns.as_tuple),required=True)
    if (owner_head.key.token,owner_head.revision,canonical_digest(owner_head.value)) != (
            frame.owner_guard.grant_ref,frame.owner_guard.grant_revision,frame.owner_guard.grant_digest):
        raise ValueError('Owner material must bind the actual current Owner grant')
    parent = get_budget_lease(db,frame.envelope.parent_budget_lease_ref)
    require_budget_family_admissible(db,parent.lease_id)
    grant = installed_readers.issuer.current_budget_grant(db,parent.lease_id)
    if (parent.lease_id != installed_readers.installed_bundle.installation_policy.root_lease.lease_id
            or grant != installed_readers.installed_bundle.installation_policy.root_grant
            or grant.valid_until_utc <= frame.now_utc):
        raise MissingProductionOriginalV1('actual_Owner_material_current_original_root')
    source_id = owner_material_source_id_v1(ns,frame.envelope.identity.operation_id)
    source_ref, access_ref = source_key(*ns.as_tuple,source_id),access_key(*ns.as_tuple,source_id)
    if read.head(db,source_ref).revision or read.head(db,access_ref).revision:
        raise ValueError('Owner material source identity already exists or was erased; never replace or revive it')
    source = SourceRecord(source_id,request.text,owner.actor,'authored','unknown',None,frame.now_utc,
        'owner-material:' + source_id,('owner',),('context','consolidation'),(), 'unknown')
    access = {'source_id':source_id,'audiences':['owner'],'purposes':['context','consolidation'],
        'status':'active','recorded_at':frame.now_utc}
    validate_access(access)
    return source,access,source_ref,access_ref


def stage_admit_owner_material_source_v1(db, *, frame, request, installed_readers):
    source,access,source_ref,access_ref=validated_owner_material_source_v1(db,
        frame=frame,request=request,installed_readers=installed_readers)
    provider = D06DomainProvider()
    return stage_result_v1(frame,'d06',OPERATION,request,
        writes=(GraphWrite(source_ref,source.to_dict()),GraphWrite(access_ref,access,(source_ref,))),
        provenance={'source_ref':source_ref.token,'source':source,'source_access':access},
        proposal_schema='d06.proposal.v1',proposal_hash=provider.descriptor.request_schema_hash)


def read_plan_owner_material_source_v1(db, *, namespace, operation_id, request):
    source_id = owner_material_source_id_v1(namespace,operation_id)
    return production_read_plan_v1((),(owner_grant_key(*namespace.as_tuple),source_key(*namespace.as_tuple,source_id),
        access_key(*namespace.as_tuple,source_id)),(),())
