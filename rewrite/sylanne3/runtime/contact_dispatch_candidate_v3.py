"""Same-transaction contact content identity; admission remains W01's work."""
from dataclasses import dataclass

from ..domains.d08 import ActionSchema, ActionSchemaRecord, GoalExecutionProvider
from ..domains.d08.execution import BASE_REQUIRED_PROVIDERS, PROACTIVE_REQUIRED_PROVIDER
from ..domains.d09.contact_batch_v3 import BATCH, validate_contact_verified_batch_v3
from ..graph_types import AtomKey, GraphVersion, GraphWrite
from ..memory_types import access_key, source_key
from ..runtime_contracts import NamespaceId, OperationIdentity, canonical_digest


@dataclass(frozen=True, slots=True)
class ContactDispatchCandidateEvidenceV3:
    operation_id: str
    effect_id: str
    contact_id: str
    action_ref: str
    schema_ref: str
    grant_ref: str
    batch_ref: str
    action_digest: str
    schema_digest: str
    grant_digest: str
    batch_digest: str
    reviewed_content_digest: str
    segment_id: str
    segment_index: int
    payload_digest: str
    source_refs: tuple[str, ...]
    content_dependency_versions: tuple[GraphVersion, ...]
    access_epoch: int
    delete_epoch: int
    query_epoch: int
    status: str = "contact_paid_pair_current_admission_pending"

    @property
    def digest(self):
        return canonical_digest(self)


def contact_dispatch_segment_payload_ref_v3(batch_ref, index):
    if (type(batch_ref) is not str or AtomKey.from_token(batch_ref).type_name != BATCH
            or type(index) is not int or not 0 <= index < 3):
        raise ValueError("contact payload needs its actual finite batch and position")
    return "d09-contact:" + canonical_digest((BATCH, batch_ref, index))


def validate_contact_dispatch_candidate_writes_v3(
        writes: tuple[tuple[str, GraphWrite], ...], *, namespace: NamespaceId,
        identity: OperationIdentity, read_versions: tuple[GraphVersion, ...],
        source_refs: tuple[str, ...], access_epoch: int, delete_epoch: int, query_epoch: int):
    """Join the first action to its whole batch and immutable parent grant.

    Later actions use the already adopted parent and a fresh segment
    qualification; they cannot recreate a batch through this entry point.
    """
    names = {"d08.action_intent.v1": "d08", "d08.action_schema.v1": "d08",
        "d08.communication_intent_grant.v1": "d08", BATCH: "d09"}
    selected = {}
    for domain, write in writes:
        name = write.key.type_name
        if name not in names:
            continue
        if (name in selected or domain != names[name]
                or (write.key.owner.bot, write.key.owner.persona) != namespace.as_tuple
                or write.key.owner.kind != "activity" or write.key.owner.subject != identity.activity_id):
            raise ValueError("contact candidate has a duplicate or foreign graph writer")
        selected[name] = write
    if set(selected) != set(names):
        raise ValueError("contact batch needs its same-transaction action, schema and parent grant")
    if any(type(value) is not int or value < 0 for value in (access_epoch, delete_epoch, query_epoch)):
        raise ValueError("contact candidate needs actual graph epochs")
    specs = {spec.name: spec for spec in GoalExecutionProvider().register_types()}
    aw, sw, gw, bw = (selected[name] for name in names)
    action, schema, grant = (specs[write.key.type_name].validator(write.value) for write in (aw, sw, gw))
    batch = validate_contact_verified_batch_v3(bw.value)
    from ..domains.d09.contact_batch_v3 import PROVENANCE, ELIGIBILITY, decode_contact_batch_companion_v3, contact_batch_writes_from_proof_v3
    companions = {write.key.type_name: write for domain,write in writes if write.key.type_name in (PROVENANCE,ELIGIBILITY)}
    if len(companions) != 2 or sum(write.key.type_name in (PROVENANCE,ELIGIBILITY) for _,write in writes) != 2:
        raise ValueError('Contact v2 candidate lacks its unique provenance/eligibility')
    if any(domain != 'd09' for domain,write in writes if write.key.type_name in (PROVENANCE,ELIGIBILITY)):
        raise ValueError('Contact v2 companion has another domain writer')
    proof = decode_contact_batch_companion_v3(PROVENANCE, companions[PROVENANCE].value)
    actual = {bw.key.type_name:bw, **companions}
    from ..runtime_contracts import canonical_serialize
    for expected in contact_batch_writes_from_proof_v3(proof):
        w = actual[expected.key.type_name]
        if w.key != expected.key or canonical_serialize(w.value) != canonical_serialize(expected.value) or set(w.dependencies) != set(expected.dependencies):
            raise ValueError('Contact v2 candidate fact/proof/projection differs')
    if proof.batch != batch or proof.batch.producing_operation_id != identity.operation_id:
        raise ValueError('Contact v2 candidate producing identity differs')
    content, first = batch.content, batch.content.segments[0]
    from .contact_final_action_v1 import contact_action_parameters_digest_v1, contact_final_action_ids_v1, contact_whole_grant_request_v1
    ids = contact_final_action_ids_v1(content.contact_id, 0)
    required = set(BASE_REQUIRED_PROVIDERS) | {PROACTIVE_REQUIRED_PROVIDER}
    if (type(schema) is not ActionSchemaRecord or not schema.proactive
            or ActionSchemaRecord.bind(action, ActionSchema(schema.schema_id, schema.action_kind,
                schema.proactive, schema.required_checks)) != schema
            or {(item.check_kind, item.provider_id) for item in action.required_checks} != required
            or len(action.required_checks) != len(required)
            or action.action_kind != "message" or action.purpose != "expression"
            or (action.action_id, action.goal_ref, action.schema_id) != (ids["action"], ids["goal"], ids["schema"])
            or not {ref for item in content.segments for claim in item.claims for ref in claim.source_refs}.issubset(action.source_refs)
            or tuple(action.source_refs) != tuple(source_refs)
            or action.parameters_digest != contact_action_parameters_digest_v1(content, 0)
            or action.effect_scope != (first.segment.effect_id,)
            or action.identity != identity or (content.namespace, content.activity_id) != (namespace, identity.activity_id)
            or (first.operation_id, first.segment.effect_id) != (identity.operation_id, identity.effect_id)
            or (aw.key.name, sw.key.name, gw.key.name, bw.key.name) !=
               (action.action_id, schema.schema_ref, grant.grant_id, batch.batch_id)
            or (grant.action_id, grant.intent_ref, grant.intent_revision, grant.target_ref) !=
               (action.action_id, action.action_id, action.revision, action.target_ref)
            or (batch.parent_grant_ref, batch.parent_grant_digest) != (gw.key.token, canonical_digest(grant))
            or batch.segment_manifest_digest != grant.segment_manifest_digest
            or grant.contact_id != content.contact_id or grant.audiences != (content.audience_id,)
            or grant.communication_action_id != contact_whole_grant_request_v1(content).communication_action_id
            or grant.required_slots != content.required_slots or grant.promise_grants
            or grant.route_binding_digest != content.route_semantic_digest
            or grant.cancellation_epoch != content.cancellation_epoch
            or grant.valid_until > content.valid_until or grant.contact_policy_check_ref is None
            or len(grant.segment_grants) != len(content.segments)):
        raise ValueError("contact action or parent grant differs from the whole reviewed scope")
    refs = tuple("check:" + canonical_digest({"kind": item.check_kind, "provider": item.provider_id,
        "subject": item.subject_ref, "action": item.action_ref, "purpose": item.purpose,
        "criteria_version": item.criteria_version, "input_versions": item.required_input_versions})
        for item in action.required_checks)
    if grant.required_check_refs != refs:
        raise ValueError("contact parent grant does not bind the action's six checks")
    for item, permitted in zip(content.segments, grant.segment_grants, strict=True):
        if ((permitted.segment_id, permitted.effect_id, permitted.position, permitted.payload_digest,
                permitted.prerequisite_segment_ref) != (item.segment.segment_id, item.segment.effect_id,
                item.position, item.payload_digest, item.prerequisite_segment_ref)
                or permitted.allowed_media or len(item.segment.body) > permitted.max_chars
                or not {claim.kind.value for claim in item.claims}.issubset(grant.allowed_claim_kinds)):
            raise ValueError("contact parent authorization differs from a reviewed segment")
    reads = {row.key.token: row.revision for row in read_versions}
    written = {write.key for _, write in writes}
    if (len(reads) != len(read_versions) or tuple(source_refs) != action.source_refs
            or not source_refs or any(reads.get(row.key.token) != row.revision for row in content.read_versions)
            or any(reads.get(key.token) != 0 for key in written)
            or any(row.key in written for row in content.read_versions)):
        raise ValueError("contact candidate lost its actual qualified read closure")
    for ref in source_refs:
        key = AtomKey.from_token(ref)
        if (key != source_key(*namespace.as_tuple, key.owner.subject or "")
                or reads.get(ref, 0) < 1
                or reads.get(access_key(*namespace.as_tuple, key.owner.subject or "").token, 0) < 1):
            raise ValueError("contact sources need their canonical current access originals")
    return ContactDispatchCandidateEvidenceV3(identity.operation_id, identity.effect_id, content.contact_id,
        aw.key.token, sw.key.token, gw.key.token, bw.key.token, canonical_digest(action), canonical_digest(schema),
        canonical_digest(grant), batch.digest, content.digest, first.segment.segment_id, 0,
        first.payload_digest, tuple(source_refs), tuple(row for row in read_versions if row.key not in written),
        access_epoch, delete_epoch, query_epoch)
