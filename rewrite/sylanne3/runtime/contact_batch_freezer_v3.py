"""Issue Contact v2 facts only inside the installed provisional SQL stage.

The codecs in D09 are public shapes. This issuer accepts no caller evidence:
its content, read rows, Owner, qualification and generation come from the
identity-registered material and its exact active E+1 projection.
"""
from dataclasses import fields

from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d08.execution import CommunicationIntentGrant
from ..domains.d09.contact_batch_v3 import contact_batch_keys_v3, validate_contact_verified_batch_v3
from ..domains.d09.contact_batch_v3 import (
    BATCH, CURRENT_TYPES, ContactVerifiedBatchV3, ContactBatchProvenanceV3,
    contact_batch_writes_from_proof_v3,
)
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_serialize
from .contact_final_projection_v3 import require_contact_projection_read_v3
from .contact_final_stage_v3 import require_installed_contact_material_v3
from .d10_offline_tick_execution_v1 import OfflineTickGraphReadV1


def _contact_batch_owner_head_v3(material):
    """Join the actual Authority head to its production frame and policy.

    The caller must already hold the exact installed material/read witness.
    The two typed guards have different contracts and wire field names.
    """
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    authority_guard, production_guard = material.owner_guard, material.frame.owner_guard
    if (type(authority_guard) is not OwnerAuthorizationGuardV1
            or type(production_guard) is not ProductionOwnerGuardV1
            or authority_guard.namespace != material.scope.namespace
            or authority_guard.authorization_head.removeprefix('sha256:') != production_guard.owner_head_digest
            or material.current_policy.original.owner_head_digest.removeprefix('sha256:') != production_guard.owner_head_digest):
        raise ValueError('Contact v3 actual Authority/frame/policy Owner head differs')
    return production_guard.owner_head_digest


def freeze_installed_contact_verified_batch_v3(material, db, *, read, action, qualification, parent_grant_ref, grant):
    material = require_installed_contact_material_v3(material)
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    if (type(material.request) is not PrepareCurrentContactDispatchRequestV3
            or material.operation.request_type is not PrepareCurrentContactDispatchRequestV3):
        raise ValueError('Contact v2 freezer requires the exact installed versioned command')
    require_contact_projection_read_v3(read, db, phases=('provisional_e_plus_1',))
    if read._witness.material is not material or read._witness.bundle is not material.final_bundle:
        raise ValueError('Contact v2 freezer is not its actual installed provisional stage')
    from .contact_final_stage_v3 import _qualification
    actual, route = _qualification(material, db, read, action)
    if canonical_serialize(actual) != canonical_serialize(qualification):
        raise ValueError('Contact v2 supplied qualification differs from the actual six providers')
    from ..domains.d08.execution import RequiredCheckRegistry
    from .contact_final_action_v1 import contact_whole_grant_request_v1
    registry = RequiredCheckRegistry()
    registry.register(action.schema)
    decision = registry.qualify(action.intent, actual.checks, now=material.frame.now_utc)
    expected_grant = registry.freeze_contact_communication_grant_v1(action.intent, decision,
        contact_whole_grant_request_v1(material.content), route_binding=route, db=db,
        read=read, scope=material.scope, now=material.frame.now_utc)
    if canonical_serialize(grant) != canonical_serialize(expected_grant):
        raise ValueError('Contact v2 grant differs from its actual installed whole-content qualification')
    from ..runtime_contracts import canonical_digest
    key = contact_batch_keys_v3(material.content.namespace,material.content.activity_id,material.content.contact_id)[0]
    if type(grant) is not CommunicationIntentGrant or grant.contact_id != material.content.contact_id:
        raise ValueError('Contact3 actual parent grant changed its whole contact scope')
    batch = ContactVerifiedBatchV3(BATCH,key.name,1,material.content.segments[0].operation_id,
        material.content,material.content.digest,parent_grant_ref,1,canonical_digest(grant),grant.segment_manifest_digest)
    validate_contact_verified_batch_v3(plain_v1(batch))
    # The original E snapshot is still pinned and independently SQL checked by
    # the private reader. Projected rows never replace these frozen E inputs.
    rows = tuple(OfflineTickGraphReadV1(atom.key.token, atom.revision,
        canonical_serialize(atom.value), atom.valid) for atom in material.frame.snapshot.atoms)
    rows = tuple(sorted(rows, key=lambda row: row.ref))
    selected = tuple(row for row in rows if AtomKey.from_token(row.ref).type_name in CURRENT_TYPES)
    metadata, _ = material.runtime.graph._v2_graph_stamp(material.scope.namespace)
    owner_head = _contact_batch_owner_head_v3(material)
    if (metadata.requirements.activation_generation != material.scope.generation
            or metadata.requirements.namespace != material.scope.namespace):
        raise ValueError('Contact v2 current Owner/recovery scope differs')
    proof = ContactBatchProvenanceV3(batch, material.scope.generation,
        metadata.requirements.graph_incarnation, owner_head,
        rows, selected, material.frame.query_coverage, actual)
    return contact_batch_writes_from_proof_v3(proof)
