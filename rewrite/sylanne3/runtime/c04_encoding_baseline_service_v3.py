"""Issue and freeze a source's encoding-time C04 baseline in W01's graph tx."""

from __future__ import annotations

from dataclasses import asdict
import json
import sqlite3

from ..domains.d04.c04_projection_issuer_v3 import (
    conditional_encoding_baseline_contract_v3,
    issue_encoding_baseline_proof_v3,
)
from ..domains.d04.encoding_baseline_v2 import ExactGraphRefV2
from ..domains.d04.interval_projection_v2 import D04IntervalProjectionPolicyV2
from ..domains.d04.numeric_drive import decode_sourced_numeric_drive
from ..native_runtime.d04_tanh_readout_asset import D04LoadedTanhReadoutAsset
from ..runtime_contracts import NamespaceId, canonical_digest
from .c04_encoding_baseline_store_v3 import (
    C04EncodingBaselineStoreRecordV3, _joint_numeric,
    record_c04_encoding_baseline_v3,
)
from .c04_encoding_context_original_v3 import (
    W01EncodingGraphReadV3, issue_d11_encoding_context_original_v3,
)
from .d04_joint_output_original_store_v1 import read_d04_joint_output_original_v1


def issue_and_record_c04_encoding_baseline_v3(
    db: sqlite3.Connection, *, namespace: NamespaceId,
    encoding_operation_id: str, joint_operation_id: str,
    source_ref: str, perspective_ref: str,
    baseline_id: str, owner_fence_digest: str,
    as_known_at: float,
    owner_epoch: int, access_epoch: int, delete_epoch: int,
    asset: D04LoadedTanhReadoutAsset,
    policy: D04IntervalProjectionPolicyV2,
) -> C04EncodingBaselineStoreRecordV3:
    """W01 calls in a separate fenced encoding read after joint adoption.

    Perspective, interpretations, MeaningFacets, Feeling versions and time
    come from that operation's exact read/history. Its receipt must include
    the already committed joint Feeling and checkpoint versions. No caller
    interval is accepted.
    """
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise ValueError("W01 encoding Owner transaction is required")
    rights = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if rights != (access_epoch, delete_epoch):
        raise ValueError("encoding rights epoch differs")
    context = issue_d11_encoding_context_original_v3(
        trusted_w01_read=W01EncodingGraphReadV3(
            db, namespace, encoding_operation_id, joint_operation_id,
            source_ref, perspective_ref, owner_fence_digest, as_known_at),
        facet_issuer_evidence=None,
    )
    output = read_d04_joint_output_original_v1(db, namespace, joint_operation_id)
    if output is None or output.original_digest != context.joint_output_original_digest:
        raise ValueError("encoding output original differs")
    numeric_ref = next((member.checkpoint_ref for member in output.members
                        if member.predecessor_state_ref == context.feelings[0].ref), None)
    if numeric_ref is None:
        raise ValueError("encoding Feeling numeric member is absent")
    numeric_revision = next(member.predecessor_checkpoint_revision + 1
                            for member in output.members
                            if member.checkpoint_ref == numeric_ref)
    numeric = _joint_numeric(
        db, namespace, joint_operation_id, numeric_ref, numeric_revision,
        context.joint_receipt_digest, context.joint_numeric_original_digest,
    )
    drives = []
    for ref, revision, *_ in numeric.receipt.source_versions:
        row = db.execute(
            "SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
            (ref, revision),
        ).fetchone()
        if row is None or row[1] != 1:
            raise ValueError("encoding joint drive historical original is absent")
        drives.append(decode_sourced_numeric_drive(json.loads(row[0])))
    proof = issue_encoding_baseline_proof_v3(
        joint_operation_id=joint_operation_id,
        baseline_id=baseline_id,
        source_version=ExactGraphRefV2(context.source.ref,
                                       context.source.revision),
        perspective_version=ExactGraphRefV2(context.perspective.ref,
                                            context.perspective.revision),
        interpretation_versions=tuple(ExactGraphRefV2(item.ref, item.revision)
                                      for item in context.interpretations),
        as_known_at=context.as_known_at,
        output_original=output, numeric_original=numeric,
        drives=tuple(drives), asset=asset, policy=policy,
    )
    original = conditional_encoding_baseline_contract_v3(
        proof, encoding_operation_id=encoding_operation_id,
        owner_epoch=owner_epoch, access_epoch=access_epoch,
        delete_epoch=delete_epoch,
    )
    return record_c04_encoding_baseline_v3(
        db, original=original, proof=proof, numeric_original=numeric,
        historical_closure_digest=canonical_digest(asdict(context)),
    )


__all__ = ["issue_and_record_c04_encoding_baseline_v3"]
