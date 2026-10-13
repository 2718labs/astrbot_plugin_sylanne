"""Current D06 source closure for a future fenced context-reply result read.

This is one part of Authority qualification. It does not verify the original
paid V2 job, D07 focus, D13 slice, model terminal, or permission to release a
body. Those must all be read under the same Authority result-read fence.
"""

from __future__ import annotations

from .current_authority_graph_read_v3 import (require_authority_context_source_material_v3,
    read_authority_current_point_v3,authority_current_json_v3,authority_current_json_matches_v3)

from dataclasses import dataclass
import json
import math
import sqlite3

from ..contracts import canonical_json
from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..model_broker.context_reply import (
    FrozenContextReplyRequestV1, freeze_context_reply_request_v1,
)
from ..runtime_contracts import NamespaceId


@dataclass(frozen=True, slots=True)
class CurrentContextReplySourceClosureV1:
    namespace: NamespaceId
    frozen_input_digest: str
    read_versions: tuple[GraphVersion, ...]
    status: str = "candidate_requires_original_paid_v2_and_current_authority_fence"


def read_current_context_reply_sources_v1(
    db: sqlite3.Connection, frozen: FrozenContextReplyRequestV1, *,
    now_utc: float,
) -> CurrentContextReplySourceClosureV1 | None:
    """Rebuild all evidence ancestry from current rows, never caller refs alone."""
    material=require_authority_context_source_material_v3(db,frozen)
    if (not isinstance(db, sqlite3.Connection) or not db.in_transaction
            or type(frozen) is not FrozenContextReplyRequestV1
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)
            or material is None and freeze_context_reply_request_v1(
                frozen.input, frozen.installation) != frozen
            or not frozen.input.frozen_at_utc <= now_utc < frozen.input.expires_at_utc):
        return None
    input = frozen.input
    namespace = input.namespace
    try:
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
        recovery=read_authority_current_point_v3(db,table='graph_recovery_metadata_v2',columns=('requirements_json',),
            key_columns=('bot','persona'),key=namespace.as_tuple,legacy_reader=lambda:db.execute(
                'SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',namespace.as_tuple).fetchone())
        if (epochs != (input.access_epoch, input.delete_epoch)
                or recovery is None):
            return None
        requirements = authority_current_json_v3(recovery[0])
        if (not authority_current_json_matches_v3(recovery[0],requirements,legacy_serializer=canonical_json)
                or requirements.get("namespace") != {
                    "bot_id": namespace.bot_id, "persona_id": namespace.persona_id}
                or requirements.get("activation_generation")
                   != input.activation_generation):
            return None

        records: dict[str, SourceRecord] = {}
        versions: dict[str, GraphVersion] = {}
        pending = [part.ref.ref for part in input.evidence]
        evidence = {part.ref.ref: part for part in input.evidence}
        while pending:
            ref = pending.pop()
            if ref in records:
                continue
            if len(records) >= 256:
                return None
            key = AtomKey.from_token(ref)
            source_id = key.owner.subject or ""
            if key != source_key(*namespace.as_tuple, source_id):
                return None
            access = access_key(*namespace.as_tuple, source_id)
            head = source_correction_head_key(namespace, source_id)
            if material is None:
                source_row = db.execute(
                    "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                    (key.token,)).fetchone()
                access_row = db.execute(
                    "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                    (access.token,)).fetchone()
                head_row = db.execute(
                    "SELECT revision,valid FROM graph_atoms WHERE token=?",
                    (head.token,)).fetchone()
                dependency = db.execute(
                    "SELECT dependency_revision FROM graph_dependencies WHERE "
                    "dependent_token=? AND dependency_token=?",
                    (access.token, key.token)).fetchone()
                if (source_row is None or access_row is None
                        or source_row[2] != 1 or access_row[2] != 1
                        or source_row[0] < 1 or access_row[0] < 1
                        or head_row is not None and head_row != (0, 0)
                        or dependency != (source_row[0],)):
                    return None
                source_value = json.loads(source_row[1])
                access_value = json.loads(access_row[1])
                if (canonical_json(source_value) != source_row[1]
                        or canonical_json(access_value) != access_row[1]):
                    return None
                record = SourceRecord.from_dict(source_value)
            else:
                witness=material.witnesses[ref].require_current_v3()
                record=material.source_records.get(ref,material.metadata_records[ref])
                access_atom=material.work.projection.get(access);correction=material.work.projection.get(head)
                dependency=read_authority_current_point_v3(db,table='graph_dependencies',columns=('dependency_revision',),
                    key_columns=('dependent_token','dependency_token'),key=(access.token,key.token),legacy_reader=lambda:None)
                if (not witness.valid or witness.revision<1 or not access_atom.valid or access_atom.revision<1
                        or correction.valid or correction.revision!=0 or dependency!=(witness.revision,)):
                    return None
                source_revision,access_revision=witness.revision,access_atom.revision;access_value=access_atom.value
            if material is None:source_revision,access_revision=source_row[0],access_row[0]
            validate_access(access_value)
            if (record.source_id != source_id
                    or record.assertion_status not in {"confirmed", "reported"}
                    or input.audience_ref.ref not in record.audiences
                    or "expression" not in record.purposes
                    or access_value["source_id"] != source_id
                    or access_value["status"] != "active"
                    or input.audience_ref.ref not in access_value["audiences"]
                    or "expression" not in access_value["purposes"]):
                return None
            part = evidence.get(ref)
            if (part is not None and (
                    part.ref.version != source_revision
                    or part.access_ref is None
                    or part.access_ref.ref != access.token
                    or part.access_ref.version != access_revision
                    or part.text != record.text)):
                return None
            records[ref] = record
            for atom_key, revision in (
                (key, source_revision), (access, access_revision), (head, 0),
            ):
                versions[atom_key.token] = GraphVersion(atom_key, revision)
            pending.extend(source_key(*namespace.as_tuple, parent).token
                           for parent in record.parent_source_ids)

        active: set[str] = set()
        settled: set[str] = set()

        def cycle(ref: str) -> bool:
            if ref in active:
                return True
            if ref in settled:
                return False
            active.add(ref)
            if any(cycle(source_key(*namespace.as_tuple, parent).token)
                   for parent in records[ref].parent_source_ids):
                return True
            active.remove(ref)
            settled.add(ref)
            return False

        if any(cycle(part.ref.ref) for part in input.evidence):
            return None
        return CurrentContextReplySourceClosureV1(
            namespace, frozen.digest,
            tuple(versions[key] for key in sorted(versions)))
    except (KeyError, TypeError, ValueError, sqlite3.Error, RecursionError):
        return None


__all__ = [
    "CurrentContextReplySourceClosureV1",
    "read_current_context_reply_sources_v1",
]
