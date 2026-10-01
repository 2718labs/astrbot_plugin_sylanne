"""Cross-check a mixed D04 readout against graph version and complete SCC rows."""

from __future__ import annotations

from dataclasses import replace
import math

import pytest

from sylanne3.domains.d04.numeric_coupling import build_numeric_coupling_write
from sylanne3.domains.d04.product_issuer import (
    D04CurrentProductReadFrameV1, D04VerifiedNumericAdoptionV1,
)
from sylanne3.domains.d04.root import encode_numeric_checkpoint
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, Owner
from sylanne3.native_runtime.d04_mixed_readout_preflight import (
    D04MixedReadoutHold, preflight_d04_mixed_readout,
)
from sylanne3.runtime.authoritative_coupling_snapshot import D04UnsignedCouplingSnapshotCandidateV1
from sylanne3.runtime_contracts import QueryEpoch, canonical_digest

from rewrite.tests.alpha1.d04.test_product_readout_candidate import _case, _project


def _fixture():
    checkpoint, ref, source, scheme, asset, readout_math, read = _case()
    candidate = _project((checkpoint, ref, source, scheme, asset, readout_math, read))
    namespace = read.namespace
    checkpoint_atom = read.snapshot.get(AtomKey.from_token(ref))
    state_atom = read.snapshot.get(AtomKey.from_token(checkpoint.graph_state.ref))
    numeric = GraphSnapshot((checkpoint_atom,), read.snapshot.epochs)
    graph = D04UnsignedCouplingSnapshotCandidateV1(
        namespace=namespace, graph_incarnation="incarnation:test", graph_revision=11,
        query_epoch=QueryEpoch(namespace, "all", 7), catalogue_hash="c" * 64,
        access_epoch=2, delete_epoch=3,
        scheme_version=scheme.scheme_version, operator_version=scheme.operator_version,
        parameter_version=scheme.parameter_version,
        coupling_version=scheme.coupling_version,
        axis_ids=checkpoint.axes, axis_units=("normalized",) * 24,
        fixed_template_asset_digest=checkpoint.asset_digest,
        checkpoint_ref=ref, checkpoint_revision=3,
        checkpoint_value_digest=canonical_digest(encode_numeric_checkpoint(checkpoint)),
        graph_state_version=GraphVersion(state_atom.key, state_atom.revision),
        graph_state_value_digest=canonical_digest(state_atom.value),
        source_refs=(source,), numeric_coupling_rows_digest=canonical_digest(()),
        numeric_coupling_versions=(), read_versions=read.snapshot.versions,
        read_values_digest="values:test", snapshot_digest="snapshot:test",
    )
    closure = canonical_digest(tuple(sorted(
        (atom.key.token, atom.revision, canonical_digest(atom.value), atom.valid)
        for atom in read.snapshot.atoms
    )))
    adoption = D04VerifiedNumericAdoptionV1(
        ref, 3, checkpoint.commit_operation_id, "receipt:test",
        checkpoint.certificate_source, checkpoint.certificate_digest,
        checkpoint.asset_digest, checkpoint.numeric_error_bound,
        "a" * 64, "b" * 64, closure,
    )
    frame = D04CurrentProductReadFrameV1(
        checkpoint, ref, 3, source, read, scheme, adoption,
        graph.graph_incarnation, graph.graph_revision,
        graph.access_epoch, graph.delete_epoch,
    )
    return graph, numeric, frame, asset, readout_math, candidate


def _run(items):
    graph, numeric, frame, asset, readout_math, candidate = items
    return preflight_d04_mixed_readout(
        graph=graph, numeric_snapshot=numeric, frame=frame,
        asset=asset, math_readout=readout_math, candidate=candidate,
    )


def test_opposing_tendencies_survive_independent_tanh_oracle_but_stay_unsigned():
    case = _fixture()
    result = _run(case)
    assert result.status == "unsigned_hold_for_w01_fenced_scc_and_adoption"
    by_axis = {row.axis_id: row for row in case[-1].tendencies}
    care = by_axis["affiliative_approach:fast"]
    boundary = by_axis["boundary_protection:fast"]
    assert care.tendency == "care" and boundary.tendency == "protect_boundary"
    assert care.target_ref == boundary.target_ref == "person:one"
    assert care.meaning_ref == boundary.meaning_ref == "meaning:ambivalence"
    assert care.lower <= math.tanh(0.8) <= care.upper
    assert boundary.lower <= math.tanh(0.6) <= boundary.upper
    assert care.lower > 0 and boundary.lower > 0
    assert len(result.read_versions) >= len(case[0].read_versions)


@pytest.mark.parametrize("change, message", (
    ("graph_revision", "source graph version"),
    ("checkpoint_value", "source graph version"),
    ("feeling_value", "source graph version"),
    ("source_revision", "source graph versions"),
    ("scheme_version", "Scheme version"),
    ("missing_numeric_row", "omits or changes an SCC row"),
    ("missing_tendency", "tendency projection"),
    ("wrong_certificate", "numeric adoption"),
))
def test_cross_boundary_mismatch_rejects_unsigned_candidate(change, message):
    graph, numeric, frame, asset, readout_math, candidate = _fixture()
    if change == "graph_revision":
        graph = replace(graph, graph_revision=12)
    elif change == "checkpoint_value":
        graph = replace(graph, checkpoint_value_digest="0" * 64)
    elif change == "feeling_value":
        graph = replace(graph, graph_state_value_digest="0" * 64)
    elif change == "source_revision":
        source_version = next(version for version in graph.read_versions
                              if version.key.type_name == "memory.source")
        graph = replace(graph, read_versions=tuple(
            replace(version, revision=2) if version == source_version else version
            for version in graph.read_versions))
    elif change == "scheme_version":
        graph = replace(graph, parameter_version="stale:parameter")
    elif change == "missing_numeric_row":
        second = AtomKey(Owner("persona", "bot:one", "alice"),
                         "d04.numeric_checkpoint.v1", "block:two")
        graph = replace(graph, read_versions=graph.read_versions + (GraphVersion(second, 1),))
    elif change == "missing_tendency":
        candidate = replace(candidate, tendencies=candidate.tendencies[1:])
    else:
        frame = replace(frame, adoption=replace(
            frame.adoption, certificate_digest="0" * 64))
    with pytest.raises(D04MixedReadoutHold, match=message):
        _run((graph, numeric, frame, asset, readout_math, candidate))


def test_valid_cross_block_edge_forces_joint_scc_not_fixed_chain():
    graph, numeric, frame, asset, readout_math, candidate = _fixture()
    second = AtomKey(Owner("persona", "bot:one", "alice"),
                     "d04.numeric_checkpoint.v1", "block:two")
    edge = build_numeric_coupling_write(
        scheme=frame.active_scheme, edge_version=1,
        left_ref=graph.checkpoint_ref, left_axis=graph.axis_ids[0],
        right_ref=second.token, right_axis=graph.axis_ids[0],
        coefficient=0.125, source_ref=frame.source_ref,
        effective_from=0.0, effective_until=20.0,
    )
    edge_atom = GraphAtom(edge.key, 1, edge.value)
    numeric = replace(numeric, atoms=numeric.atoms + (
        GraphAtom(second, 1, {}), edge_atom,
    ))
    graph = replace(
        graph,
        read_versions=graph.read_versions + (GraphVersion(second, 1),
                                             GraphVersion(edge.key, 1)),
        numeric_coupling_versions=(GraphVersion(edge.key, 1),),
        numeric_coupling_rows_digest=canonical_digest(((
            edge.key.token, 1, canonical_digest(edge.value), True,
        ),)),
    )
    with pytest.raises(D04MixedReadoutHold, match="coupled SCC member"):
        _run((graph, numeric, frame, asset, readout_math, candidate))


def test_forged_zero_error_readout_cannot_erase_checkpoint_box():
    graph, numeric, frame, asset, readout_math, candidate = _fixture()
    boxes = list(frame.checkpoint.certified_box)
    boxes[0] = (0.0, 0.2)
    checkpoint = replace(frame.checkpoint, certified_box=tuple(boxes),
                         numeric_error_bound=0.2)
    encoded = encode_numeric_checkpoint(checkpoint)
    graph = replace(graph, checkpoint_value_digest=canonical_digest(encoded))
    numeric = replace(numeric, atoms=(replace(numeric.atoms[0], value=encoded),))
    atoms = tuple(replace(atom, value=encoded)
                  if atom.key.token == graph.checkpoint_ref else atom
                  for atom in frame.source_read.snapshot.atoms)
    read = replace(frame.source_read,
                   snapshot=replace(frame.source_read.snapshot, atoms=atoms))
    closure = canonical_digest(tuple(sorted(
        (atom.key.token, atom.revision, canonical_digest(atom.value), atom.valid)
        for atom in atoms
    )))
    frame = replace(frame, checkpoint=checkpoint, source_read=read,
                    adoption=replace(frame.adoption, numeric_error_bound=0.2,
                                     graph_closure_digest=closure))
    with pytest.raises(D04MixedReadoutHold, match="checkpoint/error replay"):
        _run((graph, numeric, frame, asset, readout_math, candidate))
