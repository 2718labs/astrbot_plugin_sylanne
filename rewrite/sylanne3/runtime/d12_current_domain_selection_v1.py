"""Follow actual adopted scheme history to the most recent domain selection.

A later adoption for another domain preserves the earlier selected policy.
Editable drafts never replace an adopted original, and broken lineage holds.
"""
from __future__ import annotations
import json
from ..domains.d12.types import ActiveSchemeHeadV1, active_scheme_head_key
from ..graph_types import GraphVersion
from ..runtime_contracts import NamespaceId, canonical_serialize
from .scheme_original_store_v1 import read_compilation_original_for_operation_v1


def read_current_domain_selection_v1(db, namespace, *, domain, field_name):
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("current domain selection requires a pinned Graph transaction")
    key = active_scheme_head_key(namespace)
    current = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
    if current is None:
        return GraphVersion(key, 0), None, None
    version = GraphVersion(key, current[0])
    row, expected_digest = current, None
    for _ in range(4096):
        revision, encoded, valid = row
        if valid != 1:
            raise ValueError("adopted scheme history is invalid")
        raw = json.loads(encoded)
        if (type(raw) is not dict or canonical_serialize(raw) != encoded
                or raw.get("schema") != key.type_name):
            raise ValueError("adopted scheme history is malformed")
        head = ActiveSchemeHeadV1(**{k: v for k, v in raw.items() if k != "schema"})
        if (head.scope != namespace.persona_id or head.generation != revision
                or expected_digest is not None and head.compiled_digest != expected_digest):
            raise ValueError("adopted scheme ancestry differs")
        historical = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
            (key.token, revision)).fetchone()
        if historical != (encoded, 1):
            raise ValueError("adopted scheme has no matching immutable history")
        if head.adoption_kind == "initial":
            if revision != 1 or head.previous_compiled_digest is not None:
                raise ValueError("initial adopted scheme history differs")
            return version, None, None
        original = read_compilation_original_for_operation_v1(db, namespace, compiled_digest=head.compiled_digest)
        if original is None:
            raise ValueError("adopted domain compilation original is missing")
        compiled = original.compiled
        if (compiled.draft_ref != head.draft_ref or compiled.draft_revision != head.draft_revision
                or compiled.draft_digest != head.draft_digest or compiled.active_head_revision + 1 != revision
                or len({item.domain for item in compiled.domain_receipts}) != len(compiled.domain_receipts)):
            raise ValueError("adopted domain compilation/head differs")
        selected = tuple(item for item in compiled.domain_receipts if item.domain == domain)
        if selected:
            if len(selected) != 1 or selected[0].field_names != (field_name,):
                raise ValueError("adopted domain field selection differs")
            return version, compiled, selected[0]
        prior = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
            (key.token, revision - 1)).fetchone()
        if prior is None:
            raise ValueError("inherited domain selection has missing adopted ancestry")
        row = revision - 1, prior[0], prior[1]
        expected_digest = head.previous_compiled_digest
    raise ValueError("adopted domain ancestry exceeds complete read bound")
