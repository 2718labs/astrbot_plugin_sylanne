"""Actual Owner scope adoption and deterministic D09 promise expression."""
from __future__ import annotations
from dataclasses import dataclass, replace
from contextvars import ContextVar
from contextlib import contextmanager
import json

from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d08.commitment_communication_v1 import (
    SCOPE_TYPE, USE_TYPE, SCOPE_TYPES, USE_TYPES, CommitmentTermsCommunicationIntentV2, CommitmentTermsPromiseUseV2,
    commitment_communication_effect_id_v1, scope_route_source_v1, scope_use_dependencies_v1, scope_terms_match_v1, communication_scope_version_key_v1,
    communication_scope_request_v1, decode_communication_scope_v1, decode_communication_use_v1, RegisterCurrentCommitmentCommunicationInputRequestV1,
    CommitmentCommunicationIntentV1, CommitmentPromiseUseV1, communication_scope_id_v1,
    communication_scope_key_v1, commitment_terms_digest_v1, promise_use_key_v1,
    decode_commitment_communication_v1,
)
from ..domains.d08.execution import _decode
from ..domains.d09 import ClaimKind, ExpressionClaim, ClaimUse, SegmentCandidate, segment_payload_digest
from ..graph_types import AtomKey, GraphVersion, GraphWrite
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1


def derive_commitment_communication_input_v1(db, *, frame, request):
    from ..domains.d03.prebatch_social import _private_route
    from .persona_growth_birth_v1 import current_persona_birth_control_v1
    if type(request) is not RegisterCurrentCommitmentCommunicationInputRequestV1:
        raise TypeError("exact Owner commitment communication request required")
    read = CurrentDomainReadV1(frame); read.check(db)
    namespace = frame.envelope.authority.namespace
    control = current_persona_birth_control_v1(db, namespace=namespace)
    if not {control.activation_version, control.persona_head_version}.issubset(frame.envelope.version_guard.read_versions):
        raise ValueError("communication approval lost actual current persona control metadata")
    atom = read.head(db, request.commitment.ref, required=True)
    commitment = _decode("d08.commitment.v1", atom.value)
    from .d08_commitment_fulfillment_v1 import reject_legacy_terms_ack_v1
    reject_legacy_terms_ack_v1(db,frame=frame,commitment_key=atom.key)
    if (atom.revision != request.commitment.version or commitment.revision != atom.revision
            or commitment.subject_ref != "persona:" + namespace.persona_id
            or commitment.establishment_kind not in {"unilateral", "bilateral"}
            or commitment.establishment_state not in {"private_intention", "offered", "communicated"}
            or commitment.fulfillment_state != "pending"
            or tuple(commitment.source_refs) != (request.source_ref,)
            or not frame.now_utc < request.valid_until_utc <= frame.envelope.deadline_utc):
        raise ValueError("approved communication requires its exact live unfulfilled commitment and same Source root/deadline")
    platform,audience,scene=read_current_commitment_communication_route_v1(db,frame=frame,read=read,
        commitment=commitment,source_ref=request.source_ref,roots=(request.source_ref,))
    # Fresh final D03/D05 checks, external SourceALL, budget and route remain
    # mandatory; a private approval alone never authorizes a send.
    return CommitmentCommunicationIntentV1(namespace,
        communication_scope_id_v1(namespace, request),
        GraphVersion(atom.key, atom.revision), canonical_digest(commitment), commitment_terms_digest_v1(commitment),
        commitment.subject_ref, commitment.counterparty_ref, (request.source_ref,), platform, audience, scene,
        request.approved_literal, request.valid_until_utc, frame.now_utc, frame.envelope.identity.operation_id,
        frame.envelope.authority.actor, frame.owner_guard, control.graph_incarnation,
        control.activation_value["activation_generation"], control.head_id)


def read_current_commitment_communication_route_v1(db,*,frame,read,commitment,source_ref,roots):
    from ..domains.d03.prebatch_social import _private_route
    namespace=frame.envelope.authority.namespace
    source_family={}
    for root in roots:source_family.update(read.source_family(db,(root,)))
    from .current_commitment_input_source_v3 import read_current_commitment_actor_entity_v3,read_current_commitment_applicable_inventory_v3
    account, entity = read_current_commitment_actor_entity_v3(db,frame,source_ref,expected_entity=commitment.counterparty_ref)
    platform, audience, sender, message, scene = _private_route(db, namespace, source_ref)
    if frame.envelope.authority.audience != (audience,):
        raise ValueError('Owner Source audience differs from its actual current inbound conversation')
    # The first named route is explicitly limited to the actual Source root
    # and its independently qualified ancestors. Additional D03/D05 provenance
    # cannot silently expand the approved expression's information boundary.
    from ..authority_service.habit_authority_source_read_v3 import _source_refs_v3
    from ..domains.d03.context import RoleBinding,RoleBindingRequest
    from ..domains.d05.relationship import BoundaryRule
    related_sources=set(_source_refs_v3(entity.value))
    role_request=RoleBindingRequest(commitment.subject_ref,commitment.counterparty_ref,None,scene,'message','expression',frame.now_utc,True)
    for item in read_current_commitment_applicable_inventory_v3(db,frame,'d03.role_binding'):
        if item.valid:
            value=dict(item.value)
            for field in ('source_refs','norm_refs'):value[field]=tuple(value[field])
            role=RoleBinding(**value)
            if role.applies_to(role_request):related_sources.update(role.source_refs)
    for item in read_current_commitment_applicable_inventory_v3(db,frame,'d05.boundary_rule'):
        if item.valid:
            value=dict(item.value)
            for field in ('source_refs','communicated_refs','acknowledged_refs','exception_refs'):value[field]=tuple(value[field])
            boundary=BoundaryRule(**value)
            if boundary.applies_to(subject_persona_ref=commitment.subject_ref,target_entity_ref=commitment.counterparty_ref,
                    action_kind='message',audience_scope=audience,scene_ref=scene,at_time=frame.now_utc):
                related_sources.update(boundary.source_refs)
    from .current_method_learning_read_v3 import _method_active
    typed_terms=_method_active(db).operation_kind=='input:register_commitment_terms_communication'
    if typed_terms:
        from .current_commitment_input_source_v3 import current_commitment_policy_binding_v3
        policy_refs,policy_audiences,_=current_commitment_policy_binding_v3(db,frame)
        if not related_sources<=set(policy_refs):raise ValueError('actual applicable policy provenance changed after its sealed selector')
        return platform,audience,scene
    if not related_sources<=set(source_family):
        raise ValueError('named commitment communication v1 rejects D03/D05 provenance outside its actual Source ancestor closure')
    for ref in sorted(related_sources):read.source_family(db,(ref,))
    return platform,audience,scene



@dataclass(frozen=True, slots=True)
class CommitmentLiteralExpressionV1:
    scope: CommitmentCommunicationIntentV1
    scope_version: GraphVersion
    promise_use: CommitmentPromiseUseV1
    claims: tuple[ExpressionClaim, ...]
    segments: tuple[SegmentCandidate, ...]
    payload_digest: str
    provenance_digest: str

    @property
    def result_read_request_digest(self):
        request = communication_scope_request_v1(self.scope)
        return canonical_digest(plain_v1(request))

    @property
    def observation_digest(self):
        return self.scope.digest


def prepare_commitment_literal_expression_v1(scope, scope_version, *, identity, action_id):
    if (type(scope) not in (CommitmentCommunicationIntentV1,CommitmentTermsCommunicationIntentV2) or type(scope_version) is not GraphVersion
            or scope_version.key != communication_scope_version_key_v1(scope)
            or scope_version.revision != 1):
        raise TypeError("actual exact Owner scope head required for deterministic expression")
    if type(scope)is CommitmentTermsCommunicationIntentV2 and identity.effect_id!=commitment_communication_effect_id_v1(scope.scope_id):
        raise ValueError("V2 performance payload effect differs from its actual deterministic action effect")
    body = scope.approved_literal
    claim_id = "commitment-literal:" + canonical_digest((scope.digest, identity, action_id))[:48]
    claim = ExpressionClaim(claim_id, body, ClaimKind.INTERNAL_ACTIVITY, scope.source_refs,
        (scope.conversation_ref,), ("expression",), scope_route_source_v1(scope))
    uses = (ClaimUse(claim_id, 0, len(body), ClaimKind.INTERNAL_ACTIVITY),)
    digest = segment_payload_digest(body, (), uses)
    segment = SegmentCandidate("segment:" + canonical_digest((scope.digest, identity))[:48],
        identity.effect_id, body, uses, ("commitment",), (), 0.0)
    use_type = CommitmentTermsPromiseUseV2 if type(scope) is CommitmentTermsCommunicationIntentV2 else CommitmentPromiseUseV1
    extra = ({"fulfillment_terms":scope.fulfillment_terms,"role":scope.role,"terms_acceptance":scope.terms_acceptance}
        if type(scope) is CommitmentTermsCommunicationIntentV2 else {})
    use = use_type(scope.namespace, scope_version, scope.digest, scope.commitment,
        scope.terms_digest, identity.operation_id, action_id, identity.effect_id, segment.segment_id,
        digest, canonical_digest(body), canonical_digest({"body": body, "speech_act": "promise", "scope": scope_version}),
        0, len(body), scope.target_ref, scope.conversation_ref, scope.source_refs,**extra)
    return CommitmentLiteralExpressionV1(scope, scope_version, use, (claim,), (segment,), digest,
        canonical_digest(use))


def require_exact_commitment_promise_use_v1(use, *, scope, commitment, scope_version, intent, segment):
    if (type(use) not in (CommitmentPromiseUseV1,CommitmentTermsPromiseUseV2) or type(scope) not in (CommitmentCommunicationIntentV1,CommitmentTermsCommunicationIntentV2)
            or scope_version != use.scope or scope.digest != use.scope_digest
            or scope.commitment != use.commitment
            or canonical_digest(commitment) != scope.commitment_digest
            or not scope_terms_match_v1(scope,commitment)
            or scope.terms_digest != use.terms_digest
            or intent.commitment_refs != (commitment.commitment_id,)
            or (intent.identity.operation_id, intent.action_id, intent.identity.effect_id,
                intent.target_ref, intent.source_refs) !=
               (use.operation_id, use.action_id, use.effect_id, use.target_ref, use.source_refs)
            or (scope.target_ref, scope.conversation_ref, scope.source_refs) !=
               (use.target_ref, use.audience_ref, use.source_refs)
            or (segment.segment_id, segment.effect_id) != (use.segment_id, use.effect_id)
            or segment.body != scope.approved_literal
            or (use.start, use.end) != (0, len(segment.body))
            or canonical_digest(segment.body) != use.literal_digest
            or segment_payload_digest(segment.body, segment.media_refs, segment.claim_uses) != use.payload_digest):
        raise ValueError("actual adopted promise scope, terms, output span, segment or effect changed")


def commitment_communication_parameters_v1(expression):
    if type(expression) is not CommitmentLiteralExpressionV1:
        raise TypeError("exact deterministic promise expression required")
    return canonical_digest({"schema": "d08.commitment-literal-parameters.v1",
        "scope": expression.scope_version, "scope_digest": expression.scope.digest,
        "promise_use": expression.promise_use, "payload_digest": expression.payload_digest})


_NAMED_FULL = ContextVar("actual_named_commitment_communication_full_v1", default=None)


@contextmanager
def bind_named_commitment_full_v1(proof, graph, db):
    from .current_graph_full_read_v3 import COMMITMENT_COMMUNICATION_FULL_READ_V1
    proof._actual()
    if proof.contract is not COMMITMENT_COMMUNICATION_FULL_READ_V1 or proof.commitment_scope_original is None:
        raise ValueError("named communication requires its dedicated actual complete Source Work")
    proof.commitment_scope_original.require_current_v1(proof, graph, db)
    token = _NAMED_FULL.set((proof, graph, db))
    try:
        yield proof
    finally:
        _NAMED_FULL.reset(token)


def current_named_commitment_scope_v1(db, namespace):
    current = _NAMED_FULL.get()
    if current is None:
        return None
    proof, graph, actual_db = current
    if actual_db is not db or namespace != proof.namespace:
        raise ValueError("named communication crossed its actual Source Work")
    scope = proof.commitment_scope_original.require_current_v1(proof, graph, db)
    from .current_graph_full_read_v3 import require_bound_graph_full_read_proof_for_db_v3, CURRENT_DISPATCH_FAMILY_V3, SOURCE_METADATA_FAMILY_V3
    active = require_bound_graph_full_read_proof_for_db_v3(db, namespace,
        required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3, SOURCE_METADATA_FAMILY_V3}))
    if active.work is not proof.work or active.operation is not proof.operation:
        raise ValueError("named communication changed its original ordinary Work retention")
    proof.source_material.require_current(db=db, prepared_full_read=active, namespace=namespace,
        source_ref=scope_route_source_v1(scope), audiences=(scope.conversation_ref,), purpose="expression")
    return scope


def require_live_commitment_literal_v1(expression, identity):
    current = _NAMED_FULL.get()
    if current is None:
        raise ValueError("Owner literal expression has no actual named Source-qualified Work")
    proof, graph, db = current
    scope = current_named_commitment_scope_v1(db, proof.namespace)
    if expression != prepare_commitment_literal_expression_v1(scope,
            GraphVersion(proof.commitment_scope_original.key, 1), identity=identity,
            action_id=expression.promise_use.action_id):
        raise ValueError("literal expression differs from the actual adopted Owner scope")
    return scope


def add_named_commitment_check_versions_v1(check_inputs, *, db, namespace):
    scope = current_named_commitment_scope_v1(db, namespace)
    if scope is None:
        return check_inputs
    version = VersionedRef(scope.commitment.key.name, scope.commitment.revision)
    from .post_c02_reply_action_v2 import post_c02_reply_action_ids_v2
    from ..host.post_c02_reply_driver import post_c02_reply_operation_id
    proof = _NAMED_FULL.get()[0]
    from ..runtime_contracts import OperationIdentity
    c02 = proof.source_material.inputs.c02_receipt.operation_id
    operation = post_c02_reply_operation_id(c02, scope_route_source_v1(scope))
    identity = OperationIdentity(proof.source_material.inputs.c02_receipt.activity_id,
        commitment_communication_effect_id_v1(scope.scope_id),
        "attempt:commitment-literal:" + canonical_digest((scope.scope_id, operation))[:40],
        "commitment_literal_v1", operation, canonical_digest({"scope": proof.commitment_scope_original.key.token,
            "source": scope_route_source_v1(scope), "c02": c02}))
    refs = named_commitment_check_refs_v1(scope, identity=identity,
        action_id=post_c02_reply_action_ids_v2(c02, scope_route_source_v1(scope))[1])
    return replace(check_inputs, sets=tuple(replace(row, versions=(*row.versions, version, *refs))
        if row.check_kind == "commitment_conflict" else row for row in check_inputs.sets))


def current_named_commitment_for_action_v1(db, namespace, intent, *, now_utc):
    if _NAMED_FULL.get() is None:
        from .d08_commitment_dispatch_read_v1 import current_named_dispatch_scope_for_action_v1
        return current_named_dispatch_scope_for_action_v1(db, namespace, intent, now_utc=now_utc)
    scope = current_named_commitment_scope_v1(db, namespace)
    if scope is None:
        return None
    proof, graph, _ = _NAMED_FULL.get()
    expected = prepare_commitment_literal_expression_v1(scope,
        GraphVersion(proof.commitment_scope_original.key, 1), identity=intent.identity, action_id=intent.action_id)
    if (intent.commitment_refs != (scope.commitment.key.name,)
            or intent.parameters_digest != commitment_communication_parameters_v1(expected)
            or intent.target_ref != scope.target_ref or intent.source_refs != scope.source_refs
            or not now_utc < scope.valid_until_utc):
        raise ValueError("private commitment exception requires this exact actual approved communication output")
    from .current_graph_full_read_v3 import require_bound_graph_full_read_v3, CURRENT_DISPATCH_FAMILY_V3
    projection, query = require_bound_graph_full_read_v3(graph, db, namespace,
        required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3}))
    atom = projection.get(scope.commitment.key)
    if atom is None or not atom.valid or atom.revision != scope.commitment.revision:
        raise ValueError("approved communication commitment is no longer its exact current head")
    commitment = _decode("d08.commitment.v1", atom.value)
    if canonical_digest(commitment) != scope.commitment_digest:
        raise ValueError("approved communication commitment terms changed")
    from ..graph_types import owner_grant_key
    owner = projection.get(owner_grant_key(*namespace.as_tuple))
    if (owner is None or not owner.valid or owner.revision != scope.owner_guard.grant_revision
            or canonical_digest(owner.value) != scope.owner_guard.grant_digest
            or owner.value["graph_incarnation"] != scope.graph_incarnation
            or owner.value["activation_generation"] != scope.activation_generation):
        raise ValueError("approved literal cannot survive Owner or persona incarnation replacement")
    return scope


def named_promise_use_metadata_key_v1(db, namespace, candidate):
    from ..domains.d08.commitment_communication_v1 import USE_TYPE, decode_commitment_communication_v1
    uses = tuple(write for write in candidate.writes if write.key.type_name in USE_TYPES)
    if not uses:
        return None
    scope = current_named_commitment_scope_v1(db, namespace)
    actions = tuple(write for write in candidate.writes if write.key.type_name == "d08.action_intent.v1")
    if scope is None or len(uses) != 1 or len(actions) != 1:
        raise ValueError("promise metadata delta requires this actual named scope and one complete action")
    action = _decode("d08.action_intent.v1", actions[0].value)
    current_named_commitment_for_action_v1(db, namespace, action, now_utc=scope.approved_at_utc)
    proof = _NAMED_FULL.get()[0]
    expected = prepare_commitment_literal_expression_v1(scope,
        GraphVersion(proof.commitment_scope_original.key, 1), identity=action.identity, action_id=action.action_id)
    use = decode_communication_use_v1(uses[0].value)
    key = promise_use_key_v1(namespace, action.identity.activity_id, expected.promise_use)
    if (use != expected.promise_use or uses[0].key != key
            or uses[0].dependencies != scope_use_dependencies_v1(expected.scope_version,scope)):
        raise ValueError("promise metadata delta changed its exact actual use/output/Source dependencies")
    return key


@dataclass(frozen=True, slots=True)
class CommitmentDispatchEvidenceV1:
    namespace: NamespaceId
    operation_id: str
    effect_id: str
    action_ref: str
    schema_ref: str
    grant_ref: str
    batch_ref: str
    scope_ref: str
    use_ref: str
    segment_id: str
    payload_digest: str
    source_refs: tuple[str, ...]
    current_read_versions: tuple[GraphVersion, ...]
    candidate_digest: str
    scope: CommitmentCommunicationIntentV1
    promise_use: CommitmentPromiseUseV1

    @property
    def digest(self):
        return self.candidate_digest


@dataclass(frozen=True, slots=True)
class CommitmentDispatchRecoveryV1:
    evidence: CommitmentDispatchEvidenceV1
    write_versions: tuple[tuple[str, int], ...]
    graph_epoch: int
    graph_incarnation: str
    graph_revision: int


def recover_commitment_dispatch_candidate_in_transaction_v1(db, namespace, operation_id, *, prepared_history=None):
    from ..graph_store import GraphStore
    from ..runtime_storage_v3 import read_graph_row_v3
    from ..domains.d08.execution import GoalExecutionProvider
    from ..domains.d09 import D09ExpressionProvider, ClaimUse, ClaimKind
    from .domain_background_read_v3 import background_json_loads_v3
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("named communication recovery needs its actual pinned current transaction")
    row = (db.execute("SELECT activity_id,effect_id,receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation_id)).fetchone()
        if prepared_history is None else prepared_history.row_v1())
    if row is None:
        return None
    saved = (background_json_loads_v3(row[2]) if prepared_history is None else prepared_history.receipt_v1()).get("dispatch_candidate")
    if saved is None:
        return None
    if (type(saved) is not dict or saved.get("schema") != "sylanne.d11.dispatch_candidate.v1"
            or saved.get("status") != "source_qualified" or len(saved.get("refs", ())) != 4):
        raise ValueError("actual generic communication candidate is incomplete")
    event = (db.execute("SELECT revisions,epoch_revision,reads FROM graph_events WHERE bot=? AND persona=? "
        "AND session=? AND event_id=?", (*namespace.as_tuple, row[0], operation_id)).fetchone()
        if prepared_history is None else prepared_history.event_v1())
    if event is None or event[1] != saved["graph_epoch"]:
        raise ValueError("named communication lost its actual committed graph event")
    revisions = (GraphStore._version_rows(event[0]) if prepared_history is None else tuple(GraphVersion(AtomKey.from_token(ref), rev) for ref, rev in event[0]))
    event_reads = (GraphStore._version_rows(event[2]) if prepared_history is None else tuple(GraphVersion(AtomKey.from_token(ref), rev) for ref, rev in event[2]))
    def history(ref, revision):
        if prepared_history is not None:
            from .d08_commitment_dispatch_read_v1 import NamedCommitmentDispatchReadV1
            from .d08_commitment_outbound_receipt_v1 import NamedCommitmentOutboundReceiptMetadataV1
            if type(prepared_history) not in (NamedCommitmentDispatchReadV1, NamedCommitmentOutboundReceiptMetadataV1) or prepared_history.owner.db is not db:
                raise ValueError("exact actual named SourceALL history stream required")
            return prepared_history.history_v1(ref, revision)
        key = AtomKey.from_token(ref)
        if NamespaceId.from_key(key) != namespace:
            raise ValueError("named communication history crossed namespace")
        value = read_graph_row_v3(db, ("value", "valid"), where="token=? AND revision=?",
            parameters=(ref, revision), history=True)
        if value is None or value[1] != 1:
            raise ValueError("actual named communication historical body was removed")
        return background_json_loads_v3(value[0])
    values = [history(ref, revision) for ref, revision in saved["refs"]]
    action = _decode("d08.action_intent.v1", values[0])
    if action.identity.phase != "commitment_literal_v1":
        return None
    kinds = ("d08.action_intent.v1", "d08.action_schema.v1", "d08.communication_intent_grant.v1", "d09.verified_segment_batch.v1")
    for (ref, revision), kind in zip(saved["refs"], kinds):
        key = AtomKey.from_token(ref)
        if key.type_name != kind or GraphVersion(key, revision) not in revisions:
            raise ValueError("named candidate member differs from its original event writes")
    schema = _decode(kinds[1], values[1]); grant = _decode(kinds[2], values[2]); batch = values[3]
    next(spec for spec in D09ExpressionProvider().register_types() if spec.name == kinds[3]).validator(batch)
    from .dispatch_candidate import DispatchCandidateEvidenceV1,validate_dispatch_candidate_writes
    candidate=validate_dispatch_candidate_writes(tuple(("d09" if i==3 else "d08",GraphWrite(AtomKey.from_token(ref),values[i]))
        for i,(ref,revision)in enumerate(saved["refs"])),namespace=namespace,identity=action.identity,
        read_versions=event_reads,source_refs=tuple(saved["source_refs"]),access_epoch=saved.get("access_epoch"),
        delete_epoch=saved.get("delete_epoch"),query_epoch=saved.get("query_epoch"))
    audience=saved.get("source_audience");proof_rows=saved.get("source_proof_versions");proof_digest=saved.get("source_proof_digest")
    if (type(candidate)is not DispatchCandidateEvidenceV1 or saved["graph_epoch"]!=candidate.query_epoch+1
            or type(audience)is not list or tuple(audience)!=grant.audiences or not audience
            or type(proof_rows)is not list or not proof_rows
            or any(type(item)is not list or len(item)!=2 or type(item[0])is not str or type(item[1])is not int or item[1]<1 for item in proof_rows)
            or len({item[0]for item in proof_rows})!=len(proof_rows)
            or type(proof_digest)is not str or len(proof_digest)!=64 or any(c not in "0123456789abcdef"for c in proof_digest)):
        raise ValueError("named qualified candidate lost its actual immutable Source proof metadata")
    for ref,revision in proof_rows:
        key=AtomKey.from_token(ref)
        if (key.type_name not in {"memory.source","memory.access"}or NamespaceId.from_key(key)!=namespace
                or GraphVersion(key,revision)not in event_reads):
            raise ValueError("named Source qualification differs from its original event readset")
    if not set((*candidate.source_read_versions,*candidate.access_read_versions))<=set(tuple(item)for item in proof_rows):
        raise ValueError("named qualification omitted an actual candidate Source/Access version")
    candidate=replace(candidate,status=saved["status"],source_audience=tuple(audience),
        source_proof_versions=tuple(tuple(item)for item in proof_rows),source_proof_digest=proof_digest)
    if candidate.digest!=saved.get("digest"):
        raise ValueError("named candidate digest differs from its actual four historical members and Source proof")
    uses = tuple(version for version in revisions if version.key.type_name in USE_TYPES)
    if len(uses) != 1 or uses[0].revision != 1:
        raise ValueError("named communication lacks its one actual same-commit PromiseUse")
    use = decode_communication_use_v1(history(uses[0].key.token, 1))
    scope = decode_communication_scope_v1(history(use.scope.key.token, use.scope.revision))
    original_commitment = _decode("d08.commitment.v1", history(use.commitment.key.token, use.commitment.revision))
    if type(scope) is CommitmentTermsCommunicationIntentV2:
        required=(scope.fulfillment_terms,*scope.policy_read_versions,*(()if scope.terms_acceptance is None else(scope.terms_acceptance,)))
        if not set(required)<=set(event_reads):
            raise ValueError("terms communication final lacks its exact original terms/causal acceptance CAS")
    expression = prepare_commitment_literal_expression_v1(scope, use.scope, identity=action.identity, action_id=action.action_id)
    if (use != expression.promise_use or uses[0].key != promise_use_key_v1(namespace, action.identity.activity_id, use)
            or action.identity.operation_id != operation_id or (action.identity.activity_id, action.identity.effect_id) != row[:2]
            or action.parameters_digest != commitment_communication_parameters_v1(expression)
            or schema.intent_digest != canonical_digest(action) or schema.required_checks != action.required_checks
            or grant.promise_grants != (use.scope.key.token,) or grant.action_id != action.action_id
            or grant.target_ref != scope.target_ref or grant.audiences != (scope.conversation_ref,)
            or batch["grant_digest"] != canonical_digest(grant) or batch["batch_digest"] != candidate.batch_digest
            or batch["scene_ref"] != scope.scene_ref or batch["target_ref"] != scope.target_ref
            or batch["audiences"] != [scope.conversation_ref] or batch["claims"] != plain_v1(expression.claims)
            or tuple(saved["source_refs"]) != scope.source_refs or len(batch["segments"]) != 1
            or use.scope not in event_reads or use.commitment not in event_reads):
        raise ValueError("named exact Scope/PromiseUse/action/grant/readset differs from actual adoption")
    segment = expression.segments[0]; actual = batch["segments"][0]
    if ((actual["segment_id"], actual["effect_id"], actual["body"], actual["payload_digest"]) != (
            use.segment_id, use.effect_id, scope.approved_literal, use.payload_digest)
            or actual["claim_uses"] != plain_v1(segment.claim_uses)
            or actual["media_refs"] or actual["source_refs"] != list(scope.source_refs)
            or actual["audiences"] != [scope.conversation_ref]):
        raise ValueError("named actual delivered segment differs from its approved literal")
    require_exact_commitment_promise_use_v1(use, scope=scope, commitment=original_commitment,
        scope_version=use.scope, intent=action, segment=segment)
    evidence = CommitmentDispatchEvidenceV1(namespace, operation_id, action.identity.effect_id,
        *(ref for ref, revision in saved["refs"]), use.scope.key.token, uses[0].key.token,
        use.segment_id, use.payload_digest, scope.source_refs,
        tuple(version for version in event_reads if version.key not in {item.key for item in revisions}),
        candidate.digest, scope, use)
    return CommitmentDispatchRecoveryV1(evidence,
        (*tuple((ref, revision) for ref, revision in saved["refs"]), (uses[0].key.token, 1)),
        saved["graph_epoch"], saved["graph_incarnation"], saved["graph_revision"])


def recover_observed_commitment_dispatch_v1(db, namespace, operation_id):
    from .current_commitment_lifecycle_source_v3 import current_commitment_lifecycle_recovery_v3
    actual=current_commitment_lifecycle_recovery_v3(db,namespace,operation_id)
    if actual is not None:return actual
    from .natural_dispatch_current_read_v2 import recover_natural_dispatch_candidate_in_transaction_v2
    natural = recover_natural_dispatch_candidate_in_transaction_v2(db, namespace, operation_id)
    return natural if natural is not None else recover_commitment_dispatch_candidate_in_transaction_v1(db, namespace, operation_id)


def named_commitment_check_refs_v1(scope, *, identity, action_id):
    scope_version = GraphVersion(communication_scope_version_key_v1(scope), 1)
    expression = prepare_commitment_literal_expression_v1(scope, scope_version, identity=identity, action_id=action_id)
    use_key = promise_use_key_v1(scope.namespace, identity.activity_id, expression.promise_use)
    refs=(VersionedRef(scope_version.key.token,1),VersionedRef(use_key.token,1))
    if type(scope) is CommitmentTermsCommunicationIntentV2:
        refs+=(VersionedRef(scope.fulfillment_terms.key.token,scope.fulfillment_terms.revision),)
        refs+=tuple(VersionedRef(v.key.token,v.revision)for v in scope.policy_read_versions)
        if scope.terms_acceptance is not None:refs+=(VersionedRef(scope.terms_acceptance.key.token,scope.terms_acceptance.revision),)
    return refs


def append_named_promise_use_provisional_v1(proposal, action_candidate):
    current = _NAMED_FULL.get()
    if current is None:
        return proposal
    from ..domains.d08.commitment_communication_v1 import USE_TYPE
    proof, graph, db = current
    scope = current_named_commitment_scope_v1(db, proposal.envelope.authority.namespace)
    intent = action_candidate.intent
    expression = prepare_commitment_literal_expression_v1(scope,
        GraphVersion(proof.commitment_scope_original.key, 1), identity=intent.identity, action_id=intent.action_id)
    if intent.parameters_digest != commitment_communication_parameters_v1(expression):
        raise ValueError("provisional PromiseUse differs from its exact named action output")
    if any(write.key.type_name in USE_TYPES for write in proposal.typed_writes):
        raise ValueError("provisional PromiseUse can be appended only once")
    key = promise_use_key_v1(scope.namespace, intent.identity.activity_id, expression.promise_use)
    if db.execute("SELECT 1 FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
            (*scope.namespace.as_tuple, key.token)).fetchone() is not None:
        raise ValueError("new PromiseUse requires its genuine absent original head")
    reads = proposal.envelope.version_guard.read_versions
    if key not in {version.key for version in reads}:
        reads = (*reads, GraphVersion(key, 0))
    envelope = replace(proposal.envelope, version_guard=replace(proposal.envelope.version_guard, read_versions=reads))
    return replace(proposal, envelope=envelope, typed_writes=(*proposal.typed_writes,
        GraphWrite(key, plain_v1(expression.promise_use),
            scope_use_dependencies_v1(expression.scope_version,scope))))


def current_named_commitment_check_refs_v1(db, namespace, intent, *, now_utc):
    scope = current_named_commitment_for_action_v1(db, namespace, intent, now_utc=now_utc)
    if scope is None: return ()
    refs = named_commitment_check_refs_v1(scope, identity=intent.identity, action_id=intent.action_id)
    for ref in refs:
        row = db.execute("SELECT revision,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
            (*namespace.as_tuple, ref.ref)).fetchone()
        if row != (ref.version, 1):
            raise ValueError("actual first-communication check requires both exact Scope and same-commit PromiseUse heads")
    return refs
