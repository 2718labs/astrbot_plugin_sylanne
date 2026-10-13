"""Decode replay inputs from one complete, current D04 component read."""

from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3
from typing import TYPE_CHECKING

from ..domains.d04.affect import AffectScheme
from ..domains.d04.numeric_drive import decode_sourced_numeric_drive, SourcedNumericDrive
from ..domains.d04.root import decode_numeric_checkpoint, NumericCheckpoint
from ..graph_types import TypeRegistry
from ..memory_types import SourceRecord
from ..native_runtime.d04_joint_product_math import D04FamilyAssignment
from ..runtime_contracts import NamespaceId, QueryEpoch
from .joint_numeric_component import (
    JointNumericComponentCandidate, JointNumericHold, read_joint_numeric_component,
)

if TYPE_CHECKING:
    from ..domains.d04.authored_lineage_v3 import AuthoredNumericCheckpointV2


@dataclass(frozen=True, slots=True)
class D04CurrentJointReplayInputV2:
    component: JointNumericComponentCandidate
    checkpoints: tuple[NumericCheckpoint | AuthoredNumericCheckpointV2, ...]
    drives: tuple[SourcedNumericDrive, ...]
    families: tuple[D04FamilyAssignment, ...]
    status: str = "current_owner_fenced_input_pending_installed_replay"


def read_current_joint_replay_input_in_transaction_v2(
    db: sqlite3.Connection, *, namespace: NamespaceId, registry: TypeRegistry,
    scheme: AffectScheme, root_ref: str, role_start: float, role_end: float,
    expected_query_epoch: QueryEpoch, expected_graph_incarnation: str,
    expected_graph_revision: int, expected_access_epoch: int,
    expected_delete_epoch: int, audience: tuple[str, ...], purpose: str,
    authored_topology_verifier=None, _life_source_bridge=None,
) -> D04CurrentJointReplayInputV2:
    """Read the complete component and its exact typed ABI2 inputs in one tx.

    The result is not a numeric certificate. The caller must hold the current
    Owner/Authority fence and re-read this input before any graph write.
    """
    from ..domains.d04.authored_lineage_v3 import decode_authored_numeric_checkpoint_v2
    component = read_joint_numeric_component(
        db, namespace=namespace, registry=registry, scheme=scheme,
        root_ref=root_ref, role_start=role_start, role_end=role_end,
        expected_query_epoch=expected_query_epoch,
        expected_graph_incarnation=expected_graph_incarnation,
        expected_graph_revision=expected_graph_revision,
        expected_access_epoch=expected_access_epoch,
        expected_delete_epoch=expected_delete_epoch,
        audience=audience, purpose=purpose, authored_topology_verifier=authored_topology_verifier,
        _life_source_bridge=_life_source_bridge,
    )
    versions = {version.key.token: version.revision for version in component.read_versions}

    def value_at(ref: str) -> dict:
        revision = versions.get(ref)
        if revision is None or revision < 1:
            raise JointNumericHold("joint replay input is absent from complete read set")
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?", (ref,),
        ).fetchone()
        if row is None or row[0] != revision or row[2] != 1:
            raise JointNumericHold("joint replay input changed during current read")
        return json.loads(row[1])

    checkpoints = tuple(
        decode_authored_numeric_checkpoint_v2(value_at(ref))
        if component.root_original_digest is not None
        else decode_numeric_checkpoint(value_at(ref))
        for ref in component.checkpoint_refs
    )
    drives = tuple(decode_sourced_numeric_drive(value_at(version.key.token))
                   for block in component.block_drives
                   for version in block.drive_versions)
    families = tuple(D04FamilyAssignment(
        ref, SourceRecord.from_dict(value_at(ref)).provenance_root,
    ) for ref in sorted({drive.source_ref for drive in drives}))
    return D04CurrentJointReplayInputV2(component, checkpoints, drives, families)
