"""Pure C04 proof/codec regression over actual retained paid joint originals.

No baseline is committed and no current Owner authority is reconstructed. The
separate installed product case covers the live encoding read and atomic issue.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time

import pytest

from sylanne3.domains.d04.c04_projection_issuer_v3 import (
    issue_encoding_baseline_proof_v3, verify_encoding_baseline_proof_v3,
)
from sylanne3.domains.d04.encoding_baseline_v2 import ExactGraphRefV2, ProjectionNumericErrorV2
from sylanne3.domains.d04.encoding_salience_v2 import (
    D04EncodingSalienceHold, project_encoding_salience_from_joint_output_v2,
)
from sylanne3.domains.d04.interval_projection_v2 import (
    D04AuthoredProjectionMemberBindingV3, D04ProjectionMemberBindingV2,
    D04IntervalProjectionHold,
)
from sylanne3.domains.d04.numeric_drive import decode_sourced_numeric_drive
from sylanne3.domains.d04.projection_issuer_v2 import load_installed_d04_projection_assets_v2
from sylanne3.graph_types import AtomKey
from sylanne3.runtime.c04_encoding_baseline_store_v3 import _decode_proof, _joint_numeric, _receipt
from sylanne3.runtime.d04_joint_advance_v2 import (
    JointNumericOriginalV1, JointNumericOriginalVerificationV1, _decode_numeric_candidate,
)
from sylanne3.runtime.d04_joint_output_original_store_v1 import read_d04_joint_output_original_v1
from sylanne3.runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


@pytest.fixture(scope="module")
def actual_authored_baseline_premises():
    location = os.environ.get("SYLANNE_C04_RETAINED_GRAPH")
    package = os.environ.get("SYLANNE_C04_RETAINED_PACKAGE")
    if not location or not package:
        pytest.skip("requires actual retained paid authored joint adoption and its installed package")
    path, root = Path(location).resolve(strict=True), Path(package).resolve(strict=True)
    assert not any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal"))
    before = hashlib.sha256(path.read_bytes()).digest()
    manifest = hashlib.sha256((root / "release-manifest.json").read_bytes()).hexdigest()
    policy, asset = load_installed_d04_projection_assets_v2(root, manifest)
    db = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True, isolation_level=None)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        rows = db.execute("SELECT bot,persona,operation_id FROM graph_d04_joint_advances_v2").fetchall()
        assert len(rows) == 1
        bot, persona, operation = rows[0]
        namespace = NamespaceId(bot, persona)
        output = read_d04_joint_output_original_v1(db, namespace, operation)
        assert output.schema == "d04.joint-state-output.v2"
        assert output.native_manifest_sha256 == manifest
        member = next(item for item in output.members if item.kind == "feeling")
        row = db.execute("SELECT numeric_receipt_json,verification_json FROM graph_d04_joint_numeric_originals_v1 "
                         "WHERE bot=? AND persona=? AND operation_id=?", rows[0]).fetchone()
        verification = json.loads(row[1])
        verification["numeric_error"] = ProjectionNumericErrorV2(**verification["numeric_error"])
        numeric = JointNumericOriginalV1(member.checkpoint_ref, member.predecessor_checkpoint_revision + 1,
            operation, canonical_digest(asdict(_receipt(db, namespace, operation))),
            _decode_numeric_candidate(row[0]), JointNumericOriginalVerificationV1(**verification))
        numeric = _joint_numeric(db, namespace, operation, numeric.original_ref, numeric.original_revision,
            numeric.adoption_receipt_digest, canonical_digest(asdict(numeric)))
        drives = []
        for ref, revision, *_ in numeric.receipt.source_versions:
            payload, valid = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
                (ref, revision)).fetchone()
            assert valid == 1
            drives.append(decode_sourced_numeric_drive(json.loads(payload)))
        sources = {(drive.source_ref, drive.source_revision) for drive in drives}
        assert len(sources) == 1
        source_ref, source_revision = sources.pop()
        perspective_rows = db.execute("SELECT token,revision FROM graph_atoms WHERE type_name='d03.self_perspective.v1' AND valid=1").fetchall()
        interpretation_rows = db.execute("SELECT token,revision FROM graph_atoms WHERE type_name='d07.current_interpretation.v1' AND valid=1 ORDER BY token").fetchall()
        assert len(perspective_rows) == 1 and interpretation_rows
        # This is a present read-only observation for a conditional arithmetic
        # proof. It is not a backdated or adopted encoding-context original.
        proof = issue_encoding_baseline_proof_v3(joint_operation_id=operation,
            baseline_id="retained-proof:" + canonical_digest((operation, source_ref)),
            source_version=ExactGraphRefV2(source_ref, source_revision),
            perspective_version=ExactGraphRefV2(*perspective_rows[0]),
            interpretation_versions=tuple(ExactGraphRefV2(*item) for item in interpretation_rows),
            as_known_at=time.time(), output_original=output, numeric_original=numeric,
            drives=tuple(drives), asset=asset, policy=policy)
        assert db.total_changes == 0
        return proof, output, numeric, tuple(drives), asset, policy
    finally:
        db.close()
        assert hashlib.sha256(path.read_bytes()).digest() == before


def test_actual_authored_projection_and_cold_proof_roundtrip(actual_authored_baseline_premises):
    proof, output, numeric, drives, asset, policy = actual_authored_baseline_premises
    assert len(proof.feeling_bindings) == 2
    assert all(type(item) is D04AuthoredProjectionMemberBindingV3 for item in proof.feeling_bindings)
    assert _decode_proof(canonical_serialize(asdict(proof))) == proof
    assert verify_encoding_baseline_proof_v3(proof, joint_operation_id=output.operation_id,
        output_original=output, numeric_original=numeric, drives=drives, asset=asset, policy=policy)
    assert proof.numeric_error.inherited_state_error_2norm == numeric.verification.numeric_error.inherited_state_error_2norm
    assert proof.numeric_error.solve_state_error_2norm == numeric.verification.numeric_error.solve_state_error_2norm


def test_actual_authored_projection_rejects_legacy_and_mixed_bindings(actual_authored_baseline_premises):
    proof, output, _, _, asset, policy = actual_authored_baseline_premises
    binding = proof.feeling_bindings[0]
    with pytest.raises(D04IntervalProjectionHold):
        D04ProjectionMemberBindingV2(**asdict(binding))
    with pytest.raises(D04IntervalProjectionHold):
        replace(binding, checkpoint_revision=True)
    cp, feeling = AtomKey.from_token(binding.checkpoint_ref), AtomKey.from_token(binding.feeling_ref)
    legacy = D04ProjectionMemberBindingV2(
        AtomKey(cp.owner, "d04.numeric_checkpoint.v1", cp.name).token, binding.checkpoint_revision,
        AtomKey(feeling.owner, "d04.feeling_state.v1", feeling.name).token, binding.feeling_revision)
    with pytest.raises(D04EncodingSalienceHold):
        project_encoding_salience_from_joint_output_v2(output_original=output, asset=asset, policy=policy,
            member_bindings=(legacy, *proof.feeling_bindings[1:]))
    for alteration in ("mixed", "half_legacy", "extra", "projection_only"):
        raw = deepcopy(asdict(proof))
        if alteration == "extra":
            raw["feeling_bindings"][0]["lineage_waiver"] = True
        elif alteration == "projection_only":
            raw["projection"]["member_bindings"][0]["feeling_revision"] += 1
        else:
            raw["feeling_bindings"][0]["checkpoint_ref"] = legacy.checkpoint_ref
            if alteration == "mixed":
                raw["feeling_bindings"][0]["feeling_ref"] = legacy.feeling_ref
        with pytest.raises(ValueError):
            _decode_proof(canonical_serialize(raw))
