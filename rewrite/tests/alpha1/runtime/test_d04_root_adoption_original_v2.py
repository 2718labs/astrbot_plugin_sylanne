"""Exact, immutable D04 root-v2 original under one caller-owned graph transaction."""

from dataclasses import asdict, replace
import json
import sqlite3

import pytest

from sylanne3.domains.d04.root import (
    AuthoredRootPreset, RootAssetBindings, RootBlockTemplate,
    RootBlockIdentity, AuthoredRootBlockInput, AuthoredRootInput,
    compile_authored_root_candidate,
)
from sylanne3.domains.d04.root_projection_v2 import (
    RootProjectionCandidateV2, RootProjectionMemberCandidateV2,
)
from sylanne3.domains.d12.authored_root import D12AuthoredRootIntentV2
from sylanne3.graph_types import AtomKey, GraphVersion, NamespaceEpoch, Owner
from sylanne3.native_runtime.authored_root_initial_box import (
    AuthoredRootInitialBoxMathCandidate, AuthoredRootInitialBoxBlockMathCandidate,
)
from sylanne3.native_runtime.loader import NativeLoadBinding
from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.d04_root_adoption_contract_v2 import (
    RootAdoptionEvidenceV2, RootAdoptionWriteV2,
)
from sylanne3.runtime.d04_root_adoption_original_v2 import (
    D04RootAdoptionOriginalHold, RootGraphReadOriginalV2,
    RootGraphWriteOriginalV2, install_d04_root_adoption_original_v2,
    read_d04_root_adoption_original_v2, record_d04_root_adoption_original_v2,
    _projection_digest,
)
from sylanne3.runtime_contracts import (
    CommitReceipt, NamespaceId, VersionedRef, canonical_digest, canonical_serialize,
)


H = "a" * 64


def _fixture():
    ns = NamespaceId("bot", "persona")
    owner = Owner("persona", "bot", "persona")
    axes = tuple(f"axis:{n:02d}" for n in range(24))
    assets = RootAssetBindings("s", "o", "p", "c", "r", *(H,) * 5)
    preset = AuthoredRootPreset("preset", "1", assets, axes, (
        RootBlockTemplate("f1", "feeling", "author_supplied_box"),
        RootBlockTemplate("f2", "feeling", "author_supplied_box"),
        RootBlockTemplate("m", "mood", "author_supplied_box"),
    ))
    blocks = tuple(AuthoredRootBlockInput(
        RootBlockIdentity(name, name, kind,
                          f"object:{name}" if kind == "feeling" else None,
                          f"meaning:{name}" if kind == "feeling" else None,
                          f"source:{name}"), axes, (2.0,) * 24,
        ((1.9, 2.1),) * 24, f"box:{name}",
    ) for name, kind in (("f1", "feeling"), ("f2", "feeling"), ("m", "mood")))
    draft_ref = AtomKey(owner, "d12.character_draft.v1", "current").token
    d01_ref = AtomKey(owner, "d01.role_head.v1", "current").token
    root_input = AuthoredRootInput("candidate", ns.as_tuple, "owner",
                                   f"{draft_ref}@2:{H}", 0.0,
                                   preset.digest, assets.digest, blocks)
    candidate = compile_authored_root_candidate(preset, root_input)
    intent = D12AuthoredRootIntentV2(
        "root-op", ns, "owner", "session", draft_ref, 2, H,
        AtomKey(owner, "d12.active_scheme_head.v1", "current").token,
        1, 5, 2, 3, "owner_authored", preset.digest, assets.digest,
        canonical_digest(root_input), candidate.digest, root_input,
    )
    binding = NativeLoadBinding(H, H, "windows", "x86_64", None, 2)
    math_blocks = tuple(AuthoredRootInitialBoxBlockMathCandidate(H, H, 0.2)
                        for _ in blocks)
    binding_digest = canonical_digest(asdict(binding))
    transcript = canonical_digest({
        "schema": "d04.authored-root-initial-box-math.v1",
        "candidate_sha256": candidate.digest,
        "binding_sha256": binding_digest,
        "blocks": [asdict(block) for block in math_blocks],
        "status": "conditional_math_candidate",
    })
    math = AuthoredRootInitialBoxMathCandidate(
        candidate.digest, binding, binding_digest, math_blocks, transcript,
    )
    projection = RootProjectionCandidateV2(
        candidate.digest, transcript, H, H, 2, H, H,
        ("f1", "f2", "m"),
        tuple(RootProjectionMemberCandidateV2(
            name, kind, H, H, (2.0,) * 24, ((1.9, 2.1),) * 24, 0.2, (), H,
        ) for name, kind in (("f1", "feeling"), ("f2", "feeling"), ("m", "mood"))),
        H,
    )
    projection = replace(projection, projection_digest=_projection_digest(asdict(projection)))
    budget = BudgetLease("lease", None, "bot", "persona", "USD",
                         {"compute": 10}, {}, {}, {}, 1, "active")
    reads = tuple(RootGraphReadOriginalV2(ref, revision, True, "{}") for ref, revision
                  in sorted(((d01_ref, 1), (draft_ref, 2))))
    writes = []
    pairs = []
    for name, kind in (("f1", "feeling"), ("f2", "feeling"), ("m", "mood")):
        checkpoint_ref = AtomKey(owner, "d04.numeric_checkpoint.v1", name).token
        state_ref = AtomKey(owner, "d04.feeling_state.v1" if kind == "feeling"
                            else "d04.mood_field.v1", name).token
        checkpoint_json = canonical_serialize({"block": name, "kind": kind})
        state_json = canonical_serialize({"state": name})
        writes.extend((RootGraphWriteOriginalV2(checkpoint_ref, 1, checkpoint_json),
                       RootGraphWriteOriginalV2(state_ref, 1, state_json)))
        pairs.append(RootAdoptionWriteV2(
            checkpoint_ref, canonical_digest(json.loads(checkpoint_json)),
            state_ref, canonical_digest(json.loads(state_json)),
        ))
    writes = tuple(sorted(writes, key=lambda item: item.ref))
    pairs = tuple(sorted(pairs, key=lambda item: item.checkpoint_ref))
    receipt = CommitReceipt(
        "committed", "root-op", H, "activity", None, 1,
        tuple(GraphVersion(AtomKey.from_token(item.ref), item.revision) for item in reads),
        tuple(GraphVersion(AtomKey.from_token(item.ref), 1) for item in writes),
        (NamespaceEpoch("bot", "persona", 6),), (), (),
    )
    evidence = RootAdoptionEvidenceV2(
        namespace=ns, operation_id="root-op", owner_actor="owner",
        owner_session_ref="session", owner_session_binding_digest=H,
        parent_budget_lease_ref="lease",
        parent_budget_original_digest=canonical_digest(asdict(budget)),
        d01_head=VersionedRef(d01_ref, 1), draft_head=VersionedRef(draft_ref, 2),
        draft_digest=H, root_input_digest=canonical_digest(root_input),
        candidate_digest=candidate.digest, preset_digest=preset.digest,
        asset_digest=assets.digest, native_manifest_sha256=H, native_sha256=H,
        initial_transcript_digest=transcript,
        output_projection_digest=projection.projection_digest,
        graph_read_set_digest=canonical_digest(reads), writes=pairs,
        output_write_set_digest=canonical_digest(pairs), bundle_digest=H,
    )
    return ns, intent, evidence, candidate, math, projection, budget, reads, writes, receipt


def _db(fixture):
    ns, intent, _, _, _, _, _, _, writes, receipt = fixture
    db = sqlite3.connect(":memory:", isolation_level=None)
    db.execute("CREATE TABLE graph_bundle_operations (bot TEXT, persona TEXT, "
               "operation_id TEXT, digest TEXT, activity_id TEXT, effect_id TEXT, "
               "commit_seq INTEGER, receipt_json TEXT)")
    db.execute("CREATE TABLE graph_events (bot TEXT, persona TEXT, session TEXT, "
               "event_id TEXT, reads TEXT, revisions TEXT, epoch_revision INTEGER)")
    db.execute("CREATE TABLE graph_history (token TEXT, revision INTEGER, "
               "event_bot TEXT, event_persona TEXT, event_session TEXT, "
               "event_id TEXT, value TEXT, valid INTEGER)")
    install_d04_root_adoption_original_v2(db)
    db.execute("BEGIN IMMEDIATE")
    db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, intent.operation_id, receipt.operation_digest,
                receipt.activity_id, receipt.effect_id, receipt.commit_seq,
                canonical_serialize({"ledger_refs": [], "outbox_refs": []})))
    versions = lambda rows: json.dumps([[item.key.token, item.revision] for item in rows])
    db.execute("INSERT INTO graph_events VALUES(?,?,?,?,?,?,?)",
               (*ns.as_tuple, receipt.activity_id, receipt.operation_id,
                versions(receipt.read_versions), versions(receipt.write_versions), 6))
    for item in writes:
        db.execute("INSERT INTO graph_history VALUES(?,?,?,?,?,?,?,?)",
                   (item.ref, 1, *ns.as_tuple, receipt.activity_id,
                    receipt.operation_id, item.value_json, 1))
    return db


def _record(db, data):
    ns, intent, evidence, candidate, math, projection, budget, reads, writes, receipt = data
    return record_d04_root_adoption_original_v2(
        db, intent=intent, evidence=evidence, candidate=candidate,
        initial_box=math, projection=projection, parent_budget=budget,
        reads=reads, writes=writes, receipt=receipt,
        owner_session_binding_digest=H,
    )


def test_root_original_exact_retry_and_cold_read():
    data = _fixture()
    db = _db(data)
    original = _record(db, data)
    assert _record(db, data) == original
    db.execute("COMMIT")
    db.execute("BEGIN")
    assert read_d04_root_adoption_original_v2(
        db, namespace=data[0], operation_id="root-op") == original
    db.execute("ROLLBACK")


def test_root_original_rejects_changed_retry_and_history_tamper():
    data = _fixture()
    db = _db(data)
    _record(db, data)
    with pytest.raises(D04RootAdoptionOriginalHold):
        _record(db, (*data[:2], replace(data[2], owner_session_binding_digest="b" * 64),
                     *data[3:]))
    db.execute("UPDATE graph_history SET value='{}' WHERE token=?",
               (data[8][0].ref,))
    with pytest.raises(D04RootAdoptionOriginalHold):
        read_d04_root_adoption_original_v2(db, namespace=data[0], operation_id="root-op")


def test_root_original_requires_caller_transaction_and_rolls_back():
    data = _fixture()
    db = _db(data)
    _record(db, data)
    db.execute("ROLLBACK")
    with pytest.raises(D04RootAdoptionOriginalHold):
        read_d04_root_adoption_original_v2(db, namespace=data[0], operation_id="root-op")
    db.execute("BEGIN")
    with pytest.raises(D04RootAdoptionOriginalHold, match="absent"):
        read_d04_root_adoption_original_v2(db, namespace=data[0], operation_id="root-op")


def test_rehashed_projection_tamper_still_fails_content_proof():
    data = _fixture()
    db = _db(data)
    _record(db, data)
    db.execute("DROP TRIGGER graph_d04_root_adoption_no_update_v2")
    row = db.execute("SELECT original_json FROM graph_d04_root_adoption_originals_v2").fetchone()
    body = json.loads(row[0])
    projection = json.loads(body["projection_json"])
    projection["members"][0]["latent_state"][0] = 3.0
    body["projection_json"] = canonical_serialize(projection)
    db.execute("UPDATE graph_d04_root_adoption_originals_v2 "
               "SET original_json=?,original_digest=?",
               (canonical_serialize(body), canonical_digest({
                   **body, "namespace": data[0],
               })))
    with pytest.raises(D04RootAdoptionOriginalHold):
        read_d04_root_adoption_original_v2(db, namespace=data[0], operation_id="root-op")
