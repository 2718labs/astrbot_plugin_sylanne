"""C04 prepared bytes survive a reopen and cannot be replaced in place."""

from dataclasses import replace
import sqlite3

import pytest

from sylanne3.authority_service.internal_work_contract import InternalWorkBindingV1
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.runtime.c04_internal_work_original_v1 import (
    C04InternalWorkPreparedV1, install_c04_internal_work_original_v1,
    read_c04_internal_work_prepared_v1, record_c04_internal_work_prepared_v1,
)
from sylanne3.runtime_contracts import NamespaceId


def test_c04_prepared_original_reopen_and_conflicting_replay(tmp_path):
    namespace = NamespaceId("bot", "persona")
    binding = InternalWorkBindingV1(
        namespace_ref(namespace), "activity", "operation", "execution",
        "a" * 64, "resource-quote", 1, "b" * 64,
        "body-quote", 1, "c" * 64, "reservation", "component",
        "budget-lease", 1, "algorithm", "policy",
    )
    original = C04InternalWorkPreparedV1(
        binding, "profile-ref", 1, "state-ref", 1, 1,
        "owner-ref", 1, "d" * 64, "budget-operation", "e" * 64,
        (("state-ref", 1), ("reservation", 1)), 8, 2, 0,
    )
    path = tmp_path / "graph.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        install_c04_internal_work_original_v1(db)
        assert record_c04_internal_work_prepared_v1(db, namespace, original) == original
        db.commit()
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        assert read_c04_internal_work_prepared_v1(db, namespace, "operation") == original
        assert record_c04_internal_work_prepared_v1(db, namespace, original) == original
        with pytest.raises(ValueError, match="immutable original"):
            record_c04_internal_work_prepared_v1(
                db, namespace, replace(
                    original, binding=replace(binding, input_digest="f" * 64)))
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("DELETE FROM graph_c04_internal_work_prepared_v1")
        db.rollback()
