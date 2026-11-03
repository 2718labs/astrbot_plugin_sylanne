"""Exact C09 codecs and producer joins for the independent labor recipe.

Graph checks authenticate original producer membership and Source dependencies.
Retained duration facts additionally require the final Core/execution proof.
"""
from dataclasses import fields
from decimal import Decimal
import json
from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .c09_paged_sql_v2 import C09PagedCaptureHold
from .d11_character_labor_accounting_v1 import KIND as BASIS_KIND, character_labor_accounting_basis_from_wire_v1
from .d11_character_work_segment_v1 import BODY_KIND, ADMISSION_KIND, SEGMENT_KIND, PREPARED_METADATA_KIND, labor_body_preparation_from_wire_v1, character_labor_admission_from_wire_v1, character_labor_prepared_metadata_from_wire_v1, character_work_segment_from_wire_v1
from .d11_life_contract_v1 import RegisteredCharacterLaborLifePlanV1, life_from_wire_v1
PLAN_KIND = 'character_labor_plan_v1'
PREPARED_KIND = 'character_labor_prepared_v1'
ADOPTION_METADATA_KIND = 'character_labor_adoption_metadata_v1'
CHECKPOINT_KIND = 'body_policy_checkpoint_v1'
REBUILD_BINDING_KIND = 'character_labor_rebuild_selection_binding_v1'
LABOR_KINDS = frozenset((PLAN_KIND, PREPARED_KIND, BODY_KIND, ADMISSION_KIND, PREPARED_METADATA_KIND, SEGMENT_KIND, BASIS_KIND, ADOPTION_METADATA_KIND, CHECKPOINT_KIND, REBUILD_BINDING_KIND))

def decode_character_labor_original_v1(kind, raw):
    if kind == PLAN_KIND:
        value = life_from_wire_v1(raw, RegisteredCharacterLaborLifePlanV1)
    elif kind == PREPARED_KIND:
        from .d11_life_preparation_v1 import D11CharacterLaborLifePreparedV1, life_prepared_from_wire_v1
        value = life_prepared_from_wire_v1(raw)
        if type(value) is not D11CharacterLaborLifePreparedV1:
            raise C09PagedCaptureHold('labor C cannot alias an old recipe Prepared')
    elif kind == BODY_KIND:
        value = labor_body_preparation_from_wire_v1(raw)
    elif kind == ADMISSION_KIND:
        if type(raw) is not dict or set(raw) != {'schema', 'admission', 'body_preparation_digest', 'receipt_digest'} or raw['schema'] != 'd11.character-labor-admission-original.v1':
            raise C09PagedCaptureHold('exact independent labor Admission original required')
        value = character_labor_admission_from_wire_v1(raw['admission'])
        if raw['body_preparation_digest'] != value.body_preparation_digest:
            raise C09PagedCaptureHold('labor Admission changed its authenticated B')
        for name in ('receipt_digest', 'body_preparation_digest'):
            from .d11_offline_originals_v1 import _digest
            _digest(raw[name])
        return value
    elif kind == PREPARED_METADATA_KIND:
        value = character_labor_prepared_metadata_from_wire_v1(raw)
    elif kind == SEGMENT_KIND:
        value = character_work_segment_from_wire_v1(raw)
    elif kind == BASIS_KIND:
        value = character_labor_accounting_basis_from_wire_v1(raw)
    elif kind == ADOPTION_METADATA_KIND:
        from .character_labor_adoption_metadata_v1 import character_labor_adoption_metadata_from_wire_v1
        value = character_labor_adoption_metadata_from_wire_v1(raw)
        for original,expected in (
                (value.prepared_original,PREPARED_KIND),(value.prepared_metadata_original,PREPARED_METADATA_KIND),
                (value.basis_original,BASIS_KIND),(value.segment_original,SEGMENT_KIND),
                (value.adopted_original,'adopted_life')):
            if original.kind != 'd11.life_'+expected:
                raise C09PagedCaptureHold('labor adoption metadata changed an exact signed predecessor kind')
    elif kind == REBUILD_BINDING_KIND:
        from .d02_character_labor_rebuild_v1 import (
            character_labor_rebuild_selection_binding_from_wire_v1,
            character_labor_rebuild_selection_binding_wire_v1)
        value = character_labor_rebuild_selection_binding_from_wire_v1(raw)
        if character_labor_rebuild_selection_binding_wire_v1(value) != raw:
            raise C09PagedCaptureHold('labor selection binding changed its official permit transport')
        return value
    elif kind == CHECKPOINT_KIND:
        from .d02_character_labor_rebuild_v1 import body_policy_checkpoint_from_wire_v1
        value = body_policy_checkpoint_from_wire_v1(raw)
    else:
        raise C09PagedCaptureHold('unregistered character-labor original kind')
    if plain_v1(value) != raw:
        raise C09PagedCaptureHold('character-labor original is not its exact closed canonical wire')
    return value

def validate_character_labor_original_identity_v1(kind, *, namespace, original_ref, producing_operation_id, raw):
    value = decode_character_labor_original_v1(kind, raw)
    if kind == PLAN_KIND:
        ns = NamespaceId.from_key(AtomKey.from_token(value.input_source.ref))
        if any((NamespaceId.from_key(AtomKey.from_token(getattr(value, name).ref)) != ns for name in ('project', 'recipe', 'action_intent', 'input_access'))):
            raise C09PagedCaptureHold('labor Plan crosses original Graph namespace')
    else:
        ns = value.binding.namespace if kind == PREPARED_KIND else value.namespace
    if ns != namespace:
        raise C09PagedCaptureHold('labor original crossed its actual namespace')
    if kind == PREPARED_KIND:
        ref, op = (value.binding.prepared_original_ref, value.prepare_operation_id)
        if value.requirements_json is None or value.labor_admission_ref is None:
            raise C09PagedCaptureHold('labor Prepared lacks its genuine final C stamp')
    elif kind == BODY_KIND:
        ref, op = ('character-labor-body:' + value.body_prepare_operation_id, value.body_prepare_operation_id)
    elif kind == ADMISSION_KIND:
        ref, op = (value.admission_ref, value.admission_operation_id)
    elif kind == PREPARED_METADATA_KIND:
        ref, op = ('character-labor-prepared-metadata:' + value.binding.execution_id, value.binding.prepare_operation_id)
    elif kind == BASIS_KIND:
        ref, op = ('character-labor-accounting:' + value.execution_id, value.prepare_operation_id)
    elif kind == SEGMENT_KIND:
        ref, op = (value.segment_id, producing_operation_id)
    elif kind == ADOPTION_METADATA_KIND:
        ref, op = (value.prepared_original.original_ref, value.operation_id)
    elif kind == CHECKPOINT_KIND:
        ref, op = (value.original_ref, value.producing_operation_id)
    elif kind == REBUILD_BINDING_KIND:
        ref, op = (value.original_ref, value.command.mutation_operation_id)
    else:
        ref, op = (original_ref, producing_operation_id)
    if (original_ref, producing_operation_id) != (ref, op):
        raise C09PagedCaptureHold('labor original lost its exact physical producer/locator')
    return value

def read_character_labor_inventory_row_v1(columns, row, *, authority_namespace, issuer):
    from .d11_character_labor_accounting_v1 import COLUMNS, SIGN_KIND as BASIS_SIGN
    from .d11_life_preparation_v1 import SIGN_KIND as LIFE_SIGN
    from ..runtime_contracts import namespace_ref
    if tuple(columns) != COLUMNS or len(row) != len(COLUMNS):
        raise C09PagedCaptureHold('exact character-labor Life row shape required')
    ns = NamespaceId(row[0], row[1])
    if authority_namespace is not None and namespace_ref(ns) != authority_namespace:
        raise C09PagedCaptureHold('labor original differs from the actual capture namespace')
    from .domain_production_erasure_v1 import _json
    raw = _json(row[5])
    value = validate_character_labor_original_identity_v1(row[2], namespace=ns, original_ref=row[3], producing_operation_id=row[4], raw=raw)
    if canonical_digest(raw) != row[6]:
        raise C09PagedCaptureHold('labor original actual complete payload digest changed')
    from .d02_character_labor_rebuild_v1 import BODY_POLICY_CHECKPOINT_SIGN_KIND_V1, REBUILD_SELECTION_BINDING_SIGN_KIND_V1
    sign = BASIS_SIGN if row[2] == BASIS_KIND else BODY_POLICY_CHECKPOINT_SIGN_KIND_V1 if row[2] == CHECKPOINT_KIND else REBUILD_SELECTION_BINDING_SIGN_KIND_V1 if row[2] == REBUILD_BINDING_KIND else LIFE_SIGN
    issuer._signer.verify(sign, canonical_serialize((ns, row[2], row[3], row[6])), row[7])
    return (row[2], row[3], raw, row[6])

def _parent(read_original, ns, kind, ref, digest=None):
    saved = read_original((ns, kind, ref))
    if saved is None or (digest is not None and saved[3] != digest):
        raise C09PagedCaptureHold('labor original lacks its actual signed predecessor: ' + kind)
    return saved

def _body_for_plan(read_original, ns, plan):
    original = plan.labor_body_preparation_original
    saved = _parent(read_original, ns, BODY_KIND, original.original_ref, original.original_digest)
    body = saved[1]
    if (body.namespace, body.action_operation_id, body.activity_id, body.effect_id, body.recipe_ref, body.recipe_revision, body.recipe_digest, body.action_intent_ref) != (ns, plan.operation_id, plan.activity_id, plan.effect_id, plan.recipe.ref, plan.recipe.revision, plan.recipe.digest, plan.action_intent.ref) or plan.input_source.ref not in body.source_refs:
        raise C09PagedCaptureHold('labor Plan differs from the actual adopted A/B/recipe/input Source')
    return body

def _metadata_parents(read_original, ns, value):
    b = value.binding
    plan = _parent(read_original, ns, PLAN_KIND, b.plan_original_ref, b.plan_digest)[1]
    if plan != value.plan:
        raise C09PagedCaptureHold('labor C changed its original independently registered Plan')
    body = _body_for_plan(read_original, ns, plan)
    saved = _parent(read_original, ns, ADMISSION_KIND, value.labor_admission_ref, value.labor_admission_digest)
    admission = saved[1]
    if (saved[0], admission.binding_digest, admission.execution_id, admission.prepared_original_ref, admission.body_preparation_digest, admission.policy_digest, admission.quote_digest, admission.reservation_ref, admission.reservation_revision, admission.reservation_digest) != (b.prepare_operation_id, b.digest, b.execution_id, b.prepared_original_ref, canonical_digest(plain_v1(body)), canonical_digest(plain_v1(body.policy)), canonical_digest(body.quote), body.reservation_ref, body.reservation_revision, body.reservation_digest):
        raise C09PagedCaptureHold('labor C independent Admission differs from its actual B and binding')
    return (body, saved)

def _basis_accounting(read_original, ns, basis):
    from .d11_character_labor_accounting_v1 import _require_accounting
    saved = _parent(read_original, ns, 'accounting_prepared', basis.accounting_ref, basis.accounting_digest)
    _require_accounting(basis, saved[1])
    if saved[0] != basis.prepare_operation_id:
        raise C09PagedCaptureHold('labor basis changed its original C CPU accounting producer')
    return saved[1]

def require_character_labor_segment_basis_v1(segment, basis, accounting):
    from .clock import _mapping_from_dict
    from .d11_character_labor_accounting_v1 import _require_accounting
    _require_accounting(basis, accounting)
    q, p = (basis.quote, basis.policy)
    mapping = _mapping_from_dict(json.loads(basis.clock_mapping_json))
    if (segment.namespace, segment.execution_id, segment.effect_id, segment.binding_digest, segment.prepared_digest, segment.admission_ref, segment.admission_original_digest, segment.body_preparation_ref, segment.body_preparation_digest, segment.recipe_ref, segment.recipe_revision, segment.recipe_digest, segment.policy_digest, segment.clock_mapping_ref, segment.clock_mapping_version, segment.clock_original_digest, segment.algorithm_build_digest, segment.component_ids) != (basis.namespace, basis.execution_id, basis.effect_id, basis.binding_digest, basis.prepared_digest, basis.admission_ref, basis.admission_digest, basis.body_preparation_ref, basis.body_preparation_digest, basis.recipe_ref, basis.recipe_revision, basis.recipe_digest, basis.policy_digest, q.clock_mapping_ref, q.clock_mapping_version, q.clock_original_digest, accounting.binding.algorithm_build_digest, tuple((c.component_id for c in (*p.fixed_components, *p.duration_components)))) or Decimal(segment.from_character) != mapping.character_at(segment.started_at_utc) or (segment.to_character is not None and Decimal(segment.to_character) != mapping.character_at(segment.ended_at_utc)):
        raise C09PagedCaptureHold('labor Segment differs from its independent original numeric/clock accounting basis')

def verify_character_labor_original_join_v1(*, ns, kind, ref, op, value, raw, digest, read_original):
    """Only exact captured, signature-checked predecessor originals are accepted."""
    if kind == PLAN_KIND:
        _body_for_plan(read_original, ns, value)
    elif kind == PREPARED_KIND:
        body, admission = _metadata_parents(read_original, ns, value)
        generic = _parent(read_original, ns, 'action_admission', value.admission_ref, value.admission_digest)
        if generic[0] != value.prepare_operation_id or generic[1].binding_digest != value.binding.digest or generic[1].plan_digest != value.binding.plan_digest:
            raise C09PagedCaptureHold('labor Prepared lost its actual five-provider action admission')
        _parent(read_original, ns, BASIS_KIND, 'character-labor-accounting:' + value.binding.execution_id)
        metadata = _parent(read_original, ns, PREPARED_METADATA_KIND, 'character-labor-prepared-metadata:' + value.binding.execution_id)[1]
        if metadata.prepared_digest != digest or metadata.binding != value.binding or metadata.receipt_digest != admission[2]['receipt_digest']:
            raise C09PagedCaptureHold('labor final Prepared differs from its authenticated C metadata')
    elif kind == BODY_KIND:
        if value.quote.policy_digest != canonical_digest(plain_v1(value.policy)):
            raise C09PagedCaptureHold('labor B numeric policy commitment changed')
    elif kind == ADMISSION_KIND:
        saved = _parent(read_original, ns, BODY_KIND, value.body_preparation_ref, value.body_preparation_digest)
        body = saved[1]
        if value.policy_digest != canonical_digest(plain_v1(body.policy)) or value.quote_digest != canonical_digest(body.quote) or raw['body_preparation_digest'] != saved[3]:
            raise C09PagedCaptureHold('labor Admission lost its actual signed B numeric contract')
    elif kind == PREPARED_METADATA_KIND:
        body, admission = _metadata_parents(read_original, ns, value)
        prepared = _parent(read_original, ns, PREPARED_KIND, value.prepared_ref, value.prepared_digest)
        if prepared[0] != op or prepared[1].binding != value.binding or value.receipt_digest != admission[2]['receipt_digest']:
            raise C09PagedCaptureHold('labor C metadata lacks its actual final Prepared/admission receipt')
    elif kind == BASIS_KIND:
        _basis_accounting(read_original, ns, value)
        metadata = read_original((ns, PREPARED_METADATA_KIND, 'character-labor-prepared-metadata:' + value.execution_id))
        if metadata is not None:
            m = metadata[1]
            body, admission = _metadata_parents(read_original, ns, m)
            if (m.binding.digest, m.prepared_ref, m.prepared_digest, m.receipt_digest, m.labor_admission_ref, m.labor_admission_digest, body.policy, body.quote, body.receipt_digest) != (value.binding_digest, value.prepared_ref, value.prepared_digest, value.receipt_digest, value.admission_ref, value.admission_digest, value.policy, value.quote, value.body_receipt_digest):
                raise C09PagedCaptureHold('labor basis differs from its actual first-C09 B/C originals')
    elif kind == SEGMENT_KIND:
        basis = _parent(read_original, ns, BASIS_KIND, 'character-labor-accounting:' + value.execution_id)[1]
        accounting = _basis_accounting(read_original, ns, basis)
        require_character_labor_segment_basis_v1(value, basis, accounting)
        from .d11_life_contract_v1 import life_adoption_operation_id_v1
        if op != life_adoption_operation_id_v1(accounting.binding):
            raise C09PagedCaptureHold('labor Segment row is not its actual unique adoption producer')
    elif kind == ADOPTION_METADATA_KIND:
        basis = _parent(read_original, ns, BASIS_KIND, value.basis_original.original_ref, value.basis_original.original_digest)[1]
        accounting = _basis_accounting(read_original, ns, basis)
        segment = _parent(read_original, ns, SEGMENT_KIND, value.segment_original.original_ref, value.segment_original.original_digest)[1]
        require_character_labor_segment_basis_v1(segment, basis, accounting)
        b = accounting.binding
        from .d11_life_contract_v1 import life_adoption_operation_id_v1
        if ((value.authority_id,value.authority_namespace,value.installation_id,value.manifest_digest,
                value.execution_id,value.effect_id,value.binding_digest,value.operation_id,
                value.prepared_original.original_ref,value.prepared_original.original_digest,
                value.authority_segment_digest,value.component_ids) !=
                (b.authority_id,b.authority_namespace,b.installation_id,b.manifest_digest,
                b.execution_id,b.effect_id,b.digest,life_adoption_operation_id_v1(b),
                basis.prepared_ref,basis.prepared_digest,canonical_digest(plain_v1(segment)),segment.component_ids)
                or value.checkpoint.value_digest != value.checkpoint_original_digest):
            raise C09PagedCaptureHold('labor adoption metadata changed its actual independent basis/Segment/W01 identity')
    elif kind in {CHECKPOINT_KIND, REBUILD_BINDING_KIND}:
        # Both have dedicated actual Graph/attempt producers, checked by the
        # registered frozen-source consumers rather than a fabricated Life parent.
        return
    else:
        raise C09PagedCaptureHold('unregistered character-labor historical join')
