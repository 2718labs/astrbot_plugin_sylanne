"""C09 V4 stays unavailable when one current original family is missing."""

import pytest

from sylanne3.runtime.c09_sanitized_recovery_extractor_v4 import (
    C09RecoveryAnchorOriginalV4, C09RecoveryFactsHold,
    extract_sanitized_recovery_facts_v4,
)


class _IncompleteInstalledReader:
    def read_current_anchor_v4(self, *, namespace, operation_id):
        return C09RecoveryAnchorOriginalV4(
            "authority", "installation", namespace, operation_id,
            "sha256:" + "a" * 64, "b" * 64,
        )

    def read_current_execution_originals_v4(self, *, namespace, operation_id):
        return ()

    def read_current_d02_originals_v4(self, *, namespace, operation_id):
        return None

    def read_current_d11_originals_v4(self, *, namespace, operation_id):
        return None

    def read_current_unknown_originals_v4(self, *, namespace, operation_id):
        return ()

    def read_current_graph_originals_v4(self, *, namespace, operation_id):
        return None


def test_missing_original_families_hold_without_synthesizing_empty_facts():
    with pytest.raises(C09RecoveryFactsHold) as exc:
        extract_sanitized_recovery_facts_v4(
            port=_IncompleteInstalledReader(), namespace="bot/persona",
            operation_id="erase:one",
        )
    assert exc.value.missing == ("d02", "d11", "graph")


def test_unimplemented_port_holds_all_original_families():
    with pytest.raises(C09RecoveryFactsHold) as exc:
        extract_sanitized_recovery_facts_v4(
            port=object(), namespace="bot/persona", operation_id="erase:one",
        )
    assert exc.value.missing == (
        "anchor", "execution", "d02", "d11", "unknown", "graph",
    )
