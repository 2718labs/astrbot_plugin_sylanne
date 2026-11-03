"""Actual retained-cache SQL limits, without model or paid-job fixtures."""
import sqlite3
import pytest
from sylanne3.runtime.d11_derived_cache_payload_v1 import (
    TABLE, MAX_RETAINED_PAYLOAD_BYTES_V1, install_derived_payload_schema_v1,
    derived_payload_capacity_available_v1,
)
from sylanne3.runtime_contracts import NamespaceId


@pytest.fixture
def cache():
    db = sqlite3.connect(":memory:")
    install_derived_payload_schema_v1(db)
    yield db
    db.close()


def retain(db, count, size):
    db.executemany("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?)",
        (("bot", "persona", "block:" + str(i), "a" * 64, b"x" * size)
         for i in range(count)))


@pytest.mark.parametrize("count,allowed", [(255, True), (256, False), (257, False)])
def test_actual_retained_block_count_limits_new_members(cache, count, allowed):
    retain(cache, count, 1)
    assert derived_payload_capacity_available_v1(cache, NamespaceId("bot", "persona"), 1) is allowed
    assert derived_payload_capacity_available_v1(cache, NamespaceId("bot", "other"), 1) is True


@pytest.mark.parametrize("additional,allowed", [(524288, True), (524289, False)])
def test_actual_retained_byte_limit_keeps_exact_boundary(cache, additional, allowed):
    retain(cache, 15, 524288)
    assert derived_payload_capacity_available_v1(cache, NamespaceId("bot", "persona"), additional) is allowed
    assert MAX_RETAINED_PAYLOAD_BYTES_V1 == 8388608


def test_storage_is_available_only_after_actual_body_reclaim(cache):
    retain(cache, 16, 524288)
    namespace = NamespaceId("bot", "persona")
    assert derived_payload_capacity_available_v1(cache, namespace, 1) is False
    # This isolated cache table has no financial ledger. Bookkeeping alone has
    # not removed bytes; the named physical payload must actually be deleted.
    cache.execute("DELETE FROM " + TABLE + " WHERE bot=? AND persona=? AND block_ref=?",
        ("bot", "persona", "block:0"))
    assert derived_payload_capacity_available_v1(cache, namespace, 524288) is True
    cache.commit()
    with pytest.raises(ValueError, match="caller-owned W01 transaction"):
        derived_payload_capacity_available_v1(cache, namespace, 1)
