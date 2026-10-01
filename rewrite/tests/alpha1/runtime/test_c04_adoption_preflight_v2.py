"""C04 adoption reads independent costs without creating an experience."""

import sqlite3

import pytest

from sylanne3.runtime.c04_adoption_preflight_v2 import (
    C04AdoptionHold, inspect_current_c04_adoption_v2,
)
from sylanne3.runtime.c04_internal_work_original_v1 import (
    install_c04_internal_work_original_v1,
)
from sylanne3.runtime_contracts import NamespaceId


def test_no_executable_prepared_original_cannot_adopt_or_charge(tmp_path):
    db = sqlite3.connect(tmp_path / "graph.db")
    db.execute("BEGIN IMMEDIATE")
    install_c04_internal_work_original_v1(db)
    before = db.total_changes
    with pytest.raises(C04AdoptionHold, match="prepared original absent"):
        inspect_current_c04_adoption_v2(
            db, NamespaceId("bot", "persona"), "operation",
            installed_algorithm_build_digest="a" * 64,
        )
    assert db.total_changes == before
    db.rollback()
    db.close()
