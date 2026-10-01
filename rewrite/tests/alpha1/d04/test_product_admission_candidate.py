"""A complete D04 premise remains HOLD until W01 authenticates originals."""

from dataclasses import asdict, replace

import pytest

from sylanne3.domains.d04.product_admission import (
    D04SchemeOriginalClaimV1, compile_d04_product_admission_candidate,
)
from sylanne3.domains.d04.product_readout import D04ReadoutHold
from sylanne3.domains.d12.scheme_command import (
    D12CompiledSchemeV1, D12DomainCompileReceiptV1, compiled_scheme_digest_v1,
)
from sylanne3.domains.d12.types import (
    ActiveSchemeHeadV1, active_scheme_head_key, character_draft_key,
)
from sylanne3.graph_types import GraphAtom, GraphVersion
from sylanne3.native_runtime.d04_mixed_readout_preflight import preflight_d04_mixed_readout
from sylanne3.runtime_contracts import canonical_digest

from rewrite.tests.alpha1.numerics.test_d04_mixed_readout_preflight import _fixture


def _premise():
    graph, numeric, frame, asset, math, readout = _fixture()
    head_key = active_scheme_head_key(graph.namespace)
    draft_key = character_draft_key(graph.namespace)
    compiled = D12CompiledSchemeV1(
        graph.namespace, draft_key.token, 1, "d" * 64,
        head_key.token, 0, graph.graph_revision - 1,
        graph.access_epoch, graph.delete_epoch,
        (D12DomainCompileReceiptV1(
            "d04", ("affect_scheme",), "e" * 64, "candidate:d04", "f" * 64,
        ),), "", "fixture-only",
    )
    compiled = replace(compiled, compiled_digest=compiled_scheme_digest_v1(compiled))
    head = ActiveSchemeHeadV1(
        graph.namespace.persona_id, 1, compiled.compiled_digest,
        draft_key.token, 1, compiled.draft_digest,
        None, "operation:adopt", "initial",
    )
    value = {"schema": head_key.type_name, **asdict(head)}
    head_atom = GraphAtom(head_key, 1, value)
    source_read = replace(frame.source_read, snapshot=replace(
        frame.source_read.snapshot,
        atoms=frame.source_read.snapshot.atoms + (head_atom,),
    ))
    closure_digest = canonical_digest(tuple(sorted(
        (atom.key.token, atom.revision, canonical_digest(atom.value), atom.valid)
        for atom in source_read.snapshot.atoms
    )))
    frame = replace(frame, source_read=source_read, adoption=replace(
        frame.adoption, graph_closure_digest=closure_digest,
    ))
    head_version = GraphVersion(head_key, 1)
    graph = replace(graph, read_versions=graph.read_versions + (head_version,))
    mixed = preflight_d04_mixed_readout(
        graph=graph, numeric_snapshot=numeric, frame=frame,
        asset=asset, math_readout=math, candidate=readout,
    )
    original = D04SchemeOriginalClaimV1(
        head_version, canonical_digest(value), compiled,
        frame.checkpoint.assets.scheme_sha256, canonical_digest(frame.active_scheme),
        graph.graph_incarnation, graph.graph_revision,
    )
    return dict(graph=graph, numeric_snapshot=numeric, frame=frame,
                asset=asset, math_readout=math, readout=readout,
                mixed=mixed, scheme_original=original)


def test_complete_structural_premise_is_still_hold_without_w01_original():
    candidate = compile_d04_product_admission_candidate(**_premise())
    assert candidate.status == "hold_for_w01_current_fence_scheme_original_and_product_adoption"
    assert candidate.graph_revision == 11
    assert candidate.scheme_head_version in candidate.read_versions
    assert candidate.numeric_inventory_digest
    assert candidate.source_closure_digest
    assert candidate.readout_proof_digest
    assert candidate.numeric_error_bound >= 0
    with pytest.raises(ValueError, match="cannot grant adoption"):
        replace(candidate, status="adopted")


def test_stale_scheme_head_and_forged_original_claim_are_rejected():
    premise = _premise()
    original = premise["scheme_original"]
    with pytest.raises(D04ReadoutHold, match="Scheme head"):
        compile_d04_product_admission_candidate(**{
            **premise, "scheme_original": replace(original, head_value_digest="0" * 64),
        })
    with pytest.raises(D04ReadoutHold, match="Scheme original"):
        compile_d04_product_admission_candidate(**{
            **premise, "scheme_original": replace(
                original, installed_scheme_asset_sha256="0" * 64),
        })
    with pytest.raises(D04ReadoutHold, match="Scheme original"):
        compile_d04_product_admission_candidate(**{
            **premise, "scheme_original": replace(
                original, compiled_original=replace(
                    original.compiled_original, draft_digest="0" * 64)),
        })


def test_unsigned_mixed_receipt_cannot_self_promote_or_hide_changed_readout():
    premise = _premise()
    with pytest.raises(D04ReadoutHold, match="unsigned mixed premise"):
        compile_d04_product_admission_candidate(**{
            **premise, "mixed": replace(premise["mixed"], status="adopted"),
        })
    with pytest.raises(D04ReadoutHold, match="independent replay"):
        compile_d04_product_admission_candidate(**{
            **premise, "mixed": replace(
                premise["mixed"], readout_proof_digest="0" * 64),
        })


def test_source_read_must_share_numeric_inventory_fence():
    premise = _premise()
    frame = premise["frame"]
    stale_fence = replace(frame.source_read.fence, graph_revision=12)
    source_read = replace(frame.source_read, fence=stale_fence)
    with pytest.raises(D04ReadoutHold, match="current graph fence"):
        compile_d04_product_admission_candidate(**{
            **premise, "frame": replace(frame, source_read=source_read),
        })
