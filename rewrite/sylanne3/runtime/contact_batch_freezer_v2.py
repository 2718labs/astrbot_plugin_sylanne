"""Issue Contact v2 facts only inside the installed provisional SQL stage.

The codecs in D09 are public shapes. This issuer accepts no caller evidence:
its content, read rows, Owner, qualification and generation come from the
identity-registered material and its exact active E+1 projection.
"""
from dataclasses import fields

from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d09.contact_batch_v1 import freeze_contact_verified_batch_v1, validate_contact_verified_batch_v1
from ..domains.d09.contact_batch_v2 import (
    BATCH, CURRENT_TYPES, ContactVerifiedBatchV2, ContactBatchProvenanceV2,
    contact_batch_writes_from_proof_v2,
)
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_serialize
from .contact_final_projection_v1 import require_contact_projection_read_v1
from .contact_final_stage_v1 import require_installed_contact_material_v1
from .d10_offline_tick_execution_v1 import OfflineTickGraphReadV1


def freeze_installed_contact_verified_batch_v2(material, db, *, read, action, qualification, parent_grant_ref, grant):
    material = require_installed_contact_material_v1(material)
    from .contact_final_stage_v2 import PrepareCurrentContactDispatchRequestV2
    if (type(material.request) is not PrepareCurrentContactDispatchRequestV2
            or material.operation.request_type is not PrepareCurrentContactDispatchRequestV2):
        raise ValueError('Contact v2 freezer requires the exact installed versioned command')
    require_contact_projection_read_v1(read, db, phases=('provisional_e_plus_1',))
    if read._witness.material is not material or read._witness.bundle is not material.final_bundle:
        raise ValueError('Contact v2 freezer is not its actual installed provisional stage')
    from .contact_final_stage_v1 import _qualification
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
    legacy_write = freeze_contact_verified_batch_v1(material.content, parent_grant_ref, grant)
    legacy = validate_contact_verified_batch_v1(legacy_write.value)
    batch = ContactVerifiedBatchV2(**{field.name: BATCH if field.name == 'schema' else getattr(legacy, field.name)
        for field in fields(ContactVerifiedBatchV2)})
    # The original E snapshot is still pinned and independently SQL checked by
    # the private reader. Projected rows never replace these frozen E inputs.
    rows = tuple(OfflineTickGraphReadV1(atom.key.token, atom.revision,
        canonical_serialize(atom.value), atom.valid) for atom in material.frame.snapshot.atoms)
    rows = tuple(sorted(rows, key=lambda row: row.ref))
    selected = tuple(row for row in rows if AtomKey.from_token(row.ref).type_name in CURRENT_TYPES)
    metadata, _ = material.runtime.graph._v2_graph_stamp(material.scope.namespace)
    if (metadata.requirements.activation_generation != material.scope.generation
            or metadata.requirements.namespace != material.scope.namespace
            or material.owner_guard.owner_head_digest != material.current_policy.original.owner_head_digest.removeprefix('sha256:')):
        raise ValueError('Contact v2 current Owner/recovery scope differs')
    proof = ContactBatchProvenanceV2(batch, material.scope.generation,
        metadata.requirements.graph_incarnation, material.owner_guard.owner_head_digest,
        rows, selected, material.frame.query_coverage, actual)
    return contact_batch_writes_from_proof_v2(proof)
