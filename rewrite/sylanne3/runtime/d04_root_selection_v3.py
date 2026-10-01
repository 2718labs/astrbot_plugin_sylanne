"""Freeze a current explicit Owner root selection before spending native CPU."""
from __future__ import annotations
from dataclasses import asdict, dataclass
import json
from ..domains.d04.authored_lineage_v3 import (AuthoredRootInputV3, AuthoredRootBlockInputV3,
    RootAuthoredFacetV3, compile_authored_root_candidate_v3, encode_authored_root_candidate_v3,
    CHECKPOINT_TYPE, FEELING_TYPE, MOOD_TYPE)
from ..domains.d12.types import CharacterDraft, ActiveSchemeHeadV1, character_draft_key, active_scheme_head_key
from ..graph_types import AtomKey, Owner, owner_grant_key
from ..runtime_contracts import canonical_digest, canonical_serialize
from .d12_compiled_candidate_store_v1 import read_current_compiled_authored_root_selection_v1
from .scheme_original_store_v1 import read_compilation_original_for_operation_v1


@dataclass(frozen=True, slots=True)
class D04RootExecutionSelectionV3:
    candidate: object
    new_head: ActiveSchemeHeadV1
    read_rows: tuple
    compiled_digest: str
    field_input_digest: str
    root_input_digest: str


def read_current_root_execution_selection_v3(graph, db, authority, *, operation_id, compiled_digest, preset):
    """No native load/call, no proposed current values and no premature adoption."""
    if not db.in_transaction or db is not graph._GraphCoordinator__store._db:
        raise ValueError("root execution selection requires the actual Owner transaction")
    namespace, store = authority.namespace, graph._GraphCoordinator__store
    draft_key, head_key = character_draft_key(namespace), active_scheme_head_key(namespace)
    activation = AtomKey(Owner("persona", *namespace.as_tuple), "d01.persona_activation.v1", "current")
    rows = []
    for key in (draft_key, head_key, activation, owner_grant_key(*namespace.as_tuple)):
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
        if row is None or row[0] < 1 or row[2] != 1 or canonical_serialize(json.loads(row[1])) != row[1]:
            raise ValueError("root execution current draft/head/Owner/role is absent or malformed")
        store._registry.validate(key, json.loads(row[1]))
        rows.append((key.token, row[0], row[1], row[2]))
    raw = json.loads(rows[0][2])
    if raw.pop("schema", None) != draft_key.type_name:
        raise ValueError("root execution current draft schema differs")
    draft = CharacterDraft(**raw)
    raw_head = json.loads(rows[1][2])
    if raw_head.pop("schema", None) != head_key.type_name:
        raise ValueError("root execution current scheme head schema differs")
    previous = ActiveSchemeHeadV1(**raw_head)
    compilation = read_compilation_original_for_operation_v1(db, namespace, compiled_digest=compiled_digest)
    if compilation is None:
        raise ValueError("root execution requires its actual compiled original")
    compiled = compilation.compiled
    receipts = tuple(item for item in compiled.domain_receipts if item.domain == "d04")
    if (draft.scope != namespace.persona_id or draft.revision != rows[0][1]
            or previous.scope != namespace.persona_id or previous.generation != rows[1][1]
            or compiled.compiled_digest != compiled_digest or compiled.draft_ref != draft_key.token
            or compiled.draft_revision != draft.revision or compiled.draft_digest != canonical_digest(draft)
            or compiled.active_head_ref != head_key.token or compiled.active_head_revision != previous.generation
            or len(receipts) != 1 or receipts[0].field_names != ("d04.authored_root",)):
        raise ValueError("root execution compiled selection no longer matches current heads")
    field = draft.fields.get("d04.authored_root")
    if (type(field) is not dict or set(field) != {"candidate_id", "cursor", "preset_digest", "asset_digest", "blocks"}
            or type(field["blocks"]) is not list or not draft.field_sources.get("d04.authored_root")):
        raise ValueError("root execution requires exact explicit block choices")
    source = draft.field_sources["d04.authored_root"]
    field_digest = canonical_digest((canonical_digest(draft), "d04", (("d04.authored_root", field, source),)))
    selected = read_current_compiled_authored_root_selection_v1(db, namespace, canonical_digest(draft), field_digest)
    if (selected.field_value_json != canonical_serialize(field) or selected.field_source != source
            or receipts[0].field_input_digest != field_digest
            or receipts[0].candidate_ref != "d12-domain-candidate:" + selected.candidate_digest):
        raise ValueError("root execution exact compiled domain candidate differs")
    blocks = []
    for item in field["blocks"]:
        if type(item) is not dict or set(item) != {"facet", "axes", "latent_state", "ordered_box", "initial_error_ref"}:
            raise ValueError("root execution block shape differs")
        blocks.append(AuthoredRootBlockInputV3(RootAuthoredFacetV3(**item["facet"]), tuple(item["axes"]),
            tuple(item["latent_state"]), tuple(tuple(pair) for pair in item["ordered_box"]), item["initial_error_ref"]))
    selected_input = AuthoredRootInputV3(field["candidate_id"], namespace.as_tuple, authority.actor,
        f"{draft_key.token}@{draft.revision}:{canonical_digest(draft)}", field["cursor"], field["preset_digest"],
        field["asset_digest"], tuple(blocks))
    candidate = compile_authored_root_candidate_v3(preset, selected_input)
    for block in candidate.blocks:
        for type_name in (CHECKPOINT_TYPE, FEELING_TYPE if block.kind == "feeling" else MOOD_TYPE):
            key = AtomKey(Owner("persona", *namespace.as_tuple), type_name, block.block_id)
            if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (key.token,)).fetchone():
                raise ValueError("root execution cannot replace an existing or retired member")
            rows.append((key.token, 0, "{}", 0))
    head = ActiveSchemeHeadV1(namespace.persona_id, previous.generation + 1, compiled_digest,
        draft_key.token, draft.revision, canonical_digest(draft), previous.compiled_digest,
        operation_id, "administrative_edit")
    return D04RootExecutionSelectionV3(candidate, head, tuple(sorted(rows)), compiled_digest,
        field_digest, canonical_digest(selected_input))
