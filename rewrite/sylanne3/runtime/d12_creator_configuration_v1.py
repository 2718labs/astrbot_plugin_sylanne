"""Typed creator draft editing; persistence and authorization belong to W01."""
from __future__ import annotations

from copy import deepcopy

from ..domains.d12.scheme_command import D12DomainCompileRejectionV1, D12SchemeHold
from ..domains.d12.types import (
    ActiveSchemeHeadV1, CharacterDraft, active_scheme_head_key, character_draft_key,
)
from ..runtime_contracts import canonical_digest
from .d12_domain_scheme_compile_v1 import compile_d12_domain_scheme_candidate_v1


SUPPORTED_FIELDS = (
    ("d01.persona_plan", "Persona"),
    ("d02.body_profile", "Body"),
    ("d03.context_scheme", "Context"),
    ("d04.affect_scheme", "Affect"),
    ("d04.authored_root", "Authored root (dedicated Owner operation)"),
    ("d05.relationship_scheme", "Relationship"),
    ("d06.encoding_projection_policy", "Memory encoding"),
    ("d07.attention_policy", "Attention"),
    ("d08.action_schemas", "Actions"),
    ("d09.expression_policy", "Expression"),
    ("d10.activity_recipe", "Activity"),
)
AUTHORED_ROOT = "d04.authored_root"
EDITABLE_FIELDS = frozenset(path for path, _ in SUPPORTED_FIELDS if path != AUTHORED_ROOT)


def supported_configuration_fields_v1():
    return [{"path": path, "label": label, "editable": path != AUTHORED_ROOT}
            for path, label in SUPPORTED_FIELDS]


def decode_current_configuration_draft_v1(namespace, snapshot, *, allow_missing=False):
    """Decode actual atoms, including a genuine absent draft when requested."""
    draft_key, head_key = character_draft_key(namespace), active_scheme_head_key(namespace)
    atoms = {atom.key: atom for atom in snapshot.atoms}
    draft_atom, head_atom = atoms[draft_key], atoms[head_key]
    if (len(snapshot.epochs) != 1
            or head_atom.revision > 0 and not head_atom.valid
            or draft_atom.revision > 0 and not draft_atom.valid):
        raise ValueError("current creator draft or head unavailable")
    if draft_atom.revision == 0:
        if not allow_missing or head_atom.revision != 0:
            raise ValueError("current creator draft is absent or partly initialized")
        return CharacterDraft(namespace.persona_id, 0, {}, {})
    payload = dict(draft_atom.value)
    if payload.pop("schema") != draft_key.type_name:
        raise ValueError("draft schema differs")
    draft = CharacterDraft(**payload)
    if draft.scope != namespace.persona_id or draft.revision != draft_atom.revision:
        raise ValueError("draft revision differs")
    if head_atom.revision:
        payload = dict(head_atom.value)
        if payload.pop("schema") != head_key.type_name:
            raise ValueError("active head schema differs")
        head = ActiveSchemeHeadV1(**payload)
        if head.scope != namespace.persona_id or head.generation != head_atom.revision:
            raise ValueError("active head revision differs")
    return draft


def edited_configuration_draft_v1(namespace, current, fields):
    """Replace editable fields while preserving any dedicated authored root."""
    if type(fields) is not dict or not set(fields) <= EDITABLE_FIELDS:
        raise D12SchemeHold("only supported editable draft fields may be saved",
                            code="invalid_configuration_fields")
    values = deepcopy(fields)
    sources = {name: "owner" for name in values}
    if AUTHORED_ROOT in current.fields:
        values[AUTHORED_ROOT] = deepcopy(current.fields[AUTHORED_ROOT])
        sources[AUTHORED_ROOT] = current.field_sources[AUTHORED_ROOT]
    if not values:
        raise D12SchemeHold("a configuration draft needs a typed field",
                            code="invalid_configuration_fields")
    draft = CharacterDraft(namespace.persona_id, current.revision + 1, values, sources)
    draft_digest = canonical_digest(draft)
    for domain in sorted({name.split(".", 1)[0] for name in values}):
        material = tuple((name, values[name], sources[name]) for name in sorted(values)
                         if name.split(".", 1)[0] == domain)
        candidate = compile_d12_domain_scheme_candidate_v1(
            namespace=namespace, draft_digest=draft_digest, domain=domain,
            fields=material, field_input_digest=canonical_digest((draft_digest, domain, material)))
        if type(candidate) is D12DomainCompileRejectionV1:
            raise D12SchemeHold("typed configuration compilation rejected",
                                code="invalid_configuration_fields", diagnostics=candidate.diagnostics)
    return draft
