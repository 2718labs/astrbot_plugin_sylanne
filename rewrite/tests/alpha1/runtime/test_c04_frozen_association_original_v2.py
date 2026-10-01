"""Software boundary for C04 durable input; no D04 issuer is implied."""

from dataclasses import replace
from dataclasses import asdict
import json
import sqlite3

import pytest

from sylanne3.authority_service.internal_work_contract import InternalWorkBindingV1
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.c04_frozen_association_original_v2 import (
    install_c04_frozen_association_original_v2,
    read_c04_frozen_association_original_v2,
    record_c04_frozen_association_original_v2,
    verify_current_association_input_heads_v2,
)
from sylanne3.runtime.c04_association_graph_collector_v2 import (
    collect_c04_association_graph_originals_v2,
)
from sylanne3.runtime.c04_internal_work_original_v1 import (
    C04InternalWorkPreparedV1, install_c04_internal_work_original_v1,
    read_c04_internal_work_prepared_v1, record_c04_internal_work_prepared_v1,
)
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
from tests.alpha1.d06.test_c04_work_input_v2 import _input


def _database(work):
    db = sqlite3.connect(":memory:")
    db.execute("""CREATE TABLE graph_atoms (
        token TEXT PRIMARY KEY,bot TEXT,persona TEXT,owner_kind TEXT,
        subject TEXT,type_name TEXT,name TEXT,revision INTEGER,
        value TEXT,valid INTEGER)""")
    db.execute("CREATE TABLE graph_epochs (bot TEXT,persona TEXT,revision INTEGER)")
    db.execute("INSERT INTO graph_epochs VALUES(?,?,?)",
               (*work.namespace.as_tuple, work.graph_epoch.revision))
    for read in work.reads:
        if read.revision:
            owner = read.key.owner
            db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (read.key.token, owner.bot, owner.persona, owner.kind,
                        owner.subject, read.key.type_name, read.key.name,
                        read.revision, read.value_json, int(read.valid)))
    install_c04_internal_work_original_v1(db)
    install_c04_frozen_association_original_v2(db)
    return db


def _binding(work):
    reservation = AtomKey(
        Owner("activity", *work.namespace.as_tuple, work.activity_id),
        "d02.reservation.v1", "reservation",
    )
    return InternalWorkBindingV1(
        namespace_ref(work.namespace), work.activity_id, work.operation_id,
        "execution", work.input_digest.removeprefix("sha256:"),
        "resource-quote", 1, "1" * 64, "body-quote", 1, "2" * 64,
        reservation.token, "component", "budget-lease", 1,
        work.algorithm_id, "body-policy", "3" * 64,
    )


def _prepared(binding):
    return C04InternalWorkPreparedV1(
        binding, "profile", 1, "state", 1, 1, "owner", 1, "4" * 64,
        "budget-operation", "5" * 64, (), 1, 1, 0,
    )


def test_frozen_original_reopens_and_absent_head_or_edge_page_changed() -> None:
    work = _input()
    binding = _binding(work)
    db = _database(work)
    try:
        db.commit()
        db.execute("BEGIN IMMEDIATE")
        with pytest.raises(ValueError, match="prepared original"):
            record_c04_frozen_association_original_v2(
                db, work.namespace, binding, work)
        record_c04_internal_work_prepared_v1(db, work.namespace, _prepared(binding))
        assert record_c04_frozen_association_original_v2(
            db, work.namespace, binding, work) == work
        assert record_c04_frozen_association_original_v2(
            db, work.namespace, binding, work) == work
        db.commit()
        db.execute("BEGIN")
        assert read_c04_frozen_association_original_v2(
            db, work.namespace, binding).to_json() == work.to_json()
        db.commit()
        correction = next(read for read in work.reads if read.revision == 0)
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (correction.key.token, *work.namespace.as_tuple,
                    correction.key.owner.kind, correction.key.owner.subject,
                    correction.key.type_name, correction.key.name, 1, "{}", 1))
        with pytest.raises(ValueError, match="absent graph head appeared"):
            read_c04_frozen_association_original_v2(db, work.namespace, binding)
        db.rollback()
        edge = next(read for read in work.reads
                    if read.key.type_name == "memory.association.v1")
        db.execute("DELETE FROM graph_atoms WHERE token=?", (edge.key.token,))
        with pytest.raises(ValueError, match="graph original changed"):
            verify_current_association_input_heads_v2(db, work)
        db.rollback()
    finally:
        db.close()


def test_frozen_original_requires_same_semantic_input_and_build_pin() -> None:
    work = _input()
    binding = _binding(work)
    db = _database(work)
    try:
        db.commit()
        db.execute("BEGIN IMMEDIATE")
        record_c04_internal_work_prepared_v1(db, work.namespace, _prepared(binding))
        with pytest.raises(ValueError, match="differs from prepared"):
            record_c04_frozen_association_original_v2(
                db, work.namespace, binding,
                replace(work, salience_original=replace(
                    work.salience_original, conditioned_interval=(0.5, 0.8))))
        with pytest.raises(ValueError, match="differs from prepared"):
            record_c04_frozen_association_original_v2(
                db, work.namespace, replace(binding, algorithm_build_digest=None),
                work)
        assert db.execute("SELECT count(*) FROM graph_c04_association_inputs_v2"
                          ).fetchone() == (0,)
    finally:
        db.close()


def test_bounded_collector_reads_raw_heads_and_empty_edge_page() -> None:
    work = _input()
    db = _database(work)
    try:
        mood = next(read for read in work.reads
                    if read.key.type_name == "d04.mood_field.v1")
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                   (json.dumps({**mood.value, "source_refs": [work.cue_source_ref]},
                               sort_keys=True, separators=(",", ":")),
                    mood.key.token))
        originals = collect_c04_association_graph_originals_v2(
            db, work.namespace, cue_source_ref=work.cue_source_ref,
            focus_ref=work.focus_ref,
            attention_ticket_ref=work.attention_ticket_ref,
            mood_ref=work.mood_ref, budget=work.budget,
            context_tags=work.context_tags,
        )
        assert originals.graph_epoch == work.graph_epoch
        assert originals.edge_queries == work.edge_queries
        assert {read.key for read in originals.reads} == {
            read.key for read in work.reads}
        assert any(read.revision == 0 for read in originals.reads)
        assert originals.truncated is False
    finally:
        db.close()


def test_historical_prepared_digest_without_build_field_stays_readable() -> None:
    work = _input()
    legacy = replace(_binding(work), algorithm_build_digest=None)
    shape = asdict(_prepared(legacy))
    shape["binding"].pop("algorithm_build_digest")
    db = _database(work)
    try:
        db.commit()
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            "INSERT INTO graph_c04_internal_work_prepared_v1 VALUES(?,?,?,?,?,?)",
            (*work.namespace.as_tuple, work.operation_id,
             legacy.binding_digest, canonical_digest(shape),
             canonical_serialize(shape)),
        )
        assert read_c04_internal_work_prepared_v1(
            db, work.namespace, work.operation_id).binding == legacy
        with pytest.raises(ValueError, match="differs from prepared"):
            record_c04_frozen_association_original_v2(
                db, work.namespace, legacy, work)
    finally:
        db.close()
