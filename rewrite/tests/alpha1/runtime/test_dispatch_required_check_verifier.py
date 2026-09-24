"""Only a recomputed and digest-pinned D06 source check can verify."""

from dataclasses import replace

from sylanne3.domains.d06 import D06DomainProvider, SourceGrantRead
from sylanne3.graph_types import GraphSnapshot
from sylanne3.runtime.dispatch_required_check_verifier import (
    verify_current_d06_source_grant,
)

from test_dispatch_source_qualification import _case, _qualify


def _current():
    candidate, intent, snapshot = _case()
    candidate = _qualify(candidate, intent, snapshot)
    spec = intent.required_checks[0]
    receipt = D06DomainProvider.provide_required_check(
        intent, SourceGrantRead(snapshot, ("entity:user",), "expression", True, True),
        valid_until=10.0,
    )
    assert candidate.status == "source_qualified"
    assert (receipt.result, receipt.coverage) == ("pass", "full")
    return candidate, intent, snapshot, spec, receipt


def _verify(candidate, intent, snapshot, spec, receipt, **changes):
    return verify_current_d06_source_grant(
        snapshot, intent, spec, receipt, candidate,
        audience=changes.get("audience", ("entity:user",)),
        now_utc=changes.get("now_utc", 2.0),
        current_barrier_confirmed=changes.get("barrier", True),
    )


def test_current_provider_check_and_pinned_content_digest_verify():
    inputs = _current()
    result = _verify(*inputs)
    assert (result.status, result.verified) == ("verified", True)
    assert result.recomputed_digest is not None


def test_no_authority_barrier_or_changed_source_content_holds():
    candidate, intent, snapshot, spec, receipt = _current()
    assert _verify(candidate, intent, snapshot, spec, receipt,
                   barrier=False).status == "hold"
    atoms = list(snapshot.atoms)
    atoms[0] = replace(atoms[0], value={**atoms[0].value, "text": "changed"})
    changed = GraphSnapshot(tuple(atoms), snapshot.epochs)
    result = _verify(candidate, intent, changed, spec, receipt)
    assert result.status == "hold"
    assert result.reason == "source_proof_digest_differs"
    assert result.verified is False


def test_forged_receipt_and_other_required_check_never_pass():
    candidate, intent, snapshot, spec, receipt = _current()
    for forged in (
        replace(receipt, issuer="d08.commitment_conflict"),
        replace(receipt, input_versions=receipt.input_versions[:-1]),
        replace(receipt, valid_until=1.0),
        replace(receipt, result="unknown", coverage="partial"),
    ):
        assert _verify(candidate, intent, snapshot, spec, forged).verified is False
    assert _verify(candidate, intent, snapshot,
                   replace(spec, check_kind="dispatch_budget"), receipt).verified is False
    assert _verify(candidate, intent, snapshot, spec, receipt,
                   audience=("entity:other",)).verified is False
