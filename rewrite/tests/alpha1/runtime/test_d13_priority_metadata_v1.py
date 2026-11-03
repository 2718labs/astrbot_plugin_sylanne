"""Pure D13 metadata decisions only; no READ, Source or scheduling grant is issued."""
from types import SimpleNamespace
import pytest
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.runtime.d13_priority_metadata_v1 import D13PriorityMetadataReadV1


@pytest.mark.parametrize("case", ("absent", "pending", "expired_pending", "queued", "ambiguous", "wrong_route"))
def test_complete_metadata_priority_never_treats_unresolved_as_absence(case):
    ns = NamespaceId("bot", "persona")
    scene = AtomKey(Owner("scene", *ns.as_tuple, "scene:one"), "d03.role_binding", "role:one").token
    parent = SimpleNamespace(graph=None, db=None, authority=SimpleNamespace(namespace=ns, audience=("conversation",)),
        operation=None, mode="priority", scene_ref="scene:one", scene_token=scene,
        now_utc=100.0, ledger_blocks={})
    reader = D13PriorityMetadataReadV1(parent)
    if case in {"pending", "expired_pending", "ambiguous"}:
        row = ("pending:one", "scene:one", 1, "a" * 64)
        reader.schedules["pending:one"] = (row, "conversation", "operation:pending", 100.0 if case == "expired_pending" else 110.0)
    if case in {"queued", "ambiguous", "wrong_route"}:
        reader.intents["job:one"] = ("scene:one", scene,
            "other" if case == "wrong_route" else "conversation", "operation:one", "b" * 64, 110.0, "c" * 64)
        job = [None] * 14; job[0] = "job:one"; job[5] = "queued"; job[12] = 0
        reader.jobs["job:one"] = tuple(job)
        reader.ledgers["job:one"] = ("job:one", scene, "d" * 64, "queued", 110.0)
    reader.phase = "select"
    reader.selection_iterator = iter(reader.intents.items())
    def finish():
        # At most one immutable item is inspected on each actual READ advance.
        for _ in range(8):
            if reader.phase == "select": reader._select(None)
            elif reader.phase == "select_pending": reader._select_pending()
            if reader.complete: return reader.result
        pytest.fail("finite metadata choice did not finish")
    if case in {"ambiguous", "wrong_route"}:
        with pytest.raises(AuthorityUnavailable, match="multiple outstanding|scene/conversation"):
            finish()
        assert not reader.complete
    else:
        result = finish()
        expected = {"absent": "no_outstanding_paid", "pending": "pending_paid_schedule",
                    "expired_pending": "hold", "queued": "existing_paid"}[case]
        assert result.status == expected
        if case == "expired_pending": assert result.reason == "paid_original_expired"
        if case != "absent": assert result.job_ref is not None
        assert not hasattr(result, "source_qualification")


def test_bounded_qualified_scan_preserves_individual_refusal_before_aggregate():
    """Pure text codec callbacks only; no private READ/applicability proof is issued."""
    from sylanne3.domains.d13.precompression import _structural_fragments
    from sylanne3.runtime.d13_deterministic_applicability_v3 import (
        _ClauseScanV3, _DeterministicApplicabilityReadV3,
    )
    text = "not " + "a" * 76 + "." + "not " + "b" * 76 + "." + "unknown " + "c" * 170 + "."
    with pytest.raises(ValueError, match="qualified source clause cannot be folded safely"):
        _structural_fragments(text)
    # Only the pure clause accumulator is used, without constructor/registry/issuer.
    accumulator = object.__new__(_DeterministicApplicabilityReadV3)
    accumulator.required = []
    accumulator.first = None
    accumulator.first_seen = False
    accumulator.aggregate_overflow = False
    scan = _ClauseScanV3(text, len(text.encode("utf8")), accumulator._first_pass)
    with pytest.raises(ValueError, match="qualified source clause cannot be folded safely"):
        while not scan.advance(None):
            pass
    assert accumulator.aggregate_overflow
