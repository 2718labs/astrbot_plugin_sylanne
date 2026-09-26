"""The D04 product preflight binds conditional math without issuing authority."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from sylanne3.domains.d04.numeric_drive import sourced_numeric_drive_write
from sylanne3.native_runtime.d04_candidate import (
    D04FixedBlockBoxTrajectoryCandidate, D04ProductionReadoutUnavailable,
    require_d04_production_readout,
)
from sylanne3.native_runtime.d04_engineering_scheme import build_d04_engineering_candidate
from sylanne3.native_runtime.d04_product_admission import (
    D04ProductPreflightHold, d04_numeric_graph_binding_digest,
    preflight_d04_product_numeric_readout,
)
from sylanne3.native_runtime.d04_snapshot_compiler import (
    D04NumericTopologyRow, compile_d04_fixed_chain_snapshot_candidate,
)
from sylanne3.native_runtime.fixed_block_transcript import FixedBlockStep

from rewrite.tests.alpha1.runtime.test_authoritative_coupling_snapshot import (
    _fixture, _insert, _read,
)
from rewrite.tests.alpha1.runtime.test_current_numeric_sources import _drive
from rewrite.tests.alpha1.numerics.test_current_numeric_sources_multisource import _read_v2


ROOT = Path(__file__).resolve().parents[4]


def _inputs(tmp_path):
    store, namespace, scheme, assets, source, root = _fixture(tmp_path)
    drive = sourced_numeric_drive_write(_drive(root, source))
    _insert(store._db, namespace, drive.key, drive.value)
    graph = _read(store, namespace, scheme, assets, root)
    sources = _read_v2(store, graph, scheme, (drive.key.token,))
    graph_binding = d04_numeric_graph_binding_digest(graph, sources)
    snapshot = compile_d04_fixed_chain_snapshot_candidate(
        affect_template=(ROOT / "resources/catalogue/d04-affect-scheme.json").read_bytes(),
        operator_template=(ROOT / "resources/catalogue/d04-fixed-block-operator.json").read_bytes(),
        graph_version=graph_binding,
        topology_rows=tuple(D04NumericTopologyRow(axis, ()) for axis in graph.axis_ids),
        external_numeric_nodes=(), initial_state=sources.initial_state,
        drive=sources.drive, readout=(1.0,) + (0.0,) * 23,
    )
    model = build_d04_engineering_candidate()
    first = FixedBlockStep(
        model.k, model.r, model.j, model.a, model.alpha,
        sources.initial_state, sources.drive, sources.initial_state,
        1.0 / 256.0, 0.1, 64, 1e-5,
    )
    math = SimpleNamespace(
        trajectory=SimpleNamespace(steps=(SimpleNamespace(input=first),), final_error=0.2),
        production_binding="binding", transcript_sha256="math-digest",
    )
    candidate = D04FixedBlockBoxTrajectoryCandidate(
        "affect-digest", "operator-digest", graph.scheme_version,
        graph.operator_version, graph.parameter_version, graph.coupling_version,
        math,
    )
    return store, graph, sources, snapshot, candidate


def _mock_native(monkeypatch):
    from sylanne3.native_runtime import d04_product_admission as admission

    monkeypatch.setattr(admission, "_assets", lambda root, handle: (
        {name: getattr(handle.graph, name) for name in (
            "scheme_version", "operator_version", "parameter_version", "coupling_version")},
        "affect-digest",
        {name: getattr(handle.graph, name) for name in (
            "scheme_version", "operator_version", "parameter_version", "coupling_version")},
        "operator-digest",
    ))
    calls = []

    def replay(handle, boxed, coefficients):
        calls.append((boxed, coefficients))
        return SimpleNamespace(readout=SimpleNamespace(lower=1.8, upper=2.2),
                               transcript_sha256="readout-digest")

    monkeypatch.setattr(admission, "run_fixed_block_box_linear_readout_math", replay)
    return calls


def test_current_graph_values_and_exact_fixed_operator_reach_only_hold(tmp_path, monkeypatch):
    store, graph, sources, snapshot, candidate = _inputs(tmp_path)
    try:
        calls = _mock_native(monkeypatch)
        result = preflight_d04_product_numeric_readout(
            SimpleNamespace(production_binding="binding", graph=graph),
            ROOT, graph, sources, snapshot, candidate,
        )
        assert result.status == "candidate_hold"
        assert result.graph_binding_digest == snapshot.graph_version
        assert result.snapshot_sha256 == snapshot.snapshot_sha256
        assert result.inherited_error == 0.2
        assert calls == [(candidate.math, snapshot.readout)]
        assert "fenced_current_graph_issuer" in result.missing_authorities
        with pytest.raises(D04ProductionReadoutUnavailable):
            require_d04_production_readout(candidate)
    finally:
        store.close()


@pytest.mark.parametrize("change,match", (
    ("graph", "different graph version"),
    ("drive", "state or drive"),
    ("snapshot_digest", "fields or digest"),
    ("operator", "fixed block differs"),
    ("source_digest", "graph and numeric sources"),
))
def test_stale_or_forged_premise_rejected_before_native_replay(
    tmp_path, monkeypatch, change, match,
):
    store, graph, sources, snapshot, candidate = _inputs(tmp_path)
    try:
        calls = _mock_native(monkeypatch)
        if change == "graph":
            snapshot = replace(snapshot, graph_version="graph:stale")
        elif change == "drive":
            sources = replace(sources, drive=(0.2,) + sources.drive[1:])
        elif change == "snapshot_digest":
            snapshot = replace(snapshot, snapshot_sha256="f" * 64)
        elif change == "operator":
            first = candidate.math.trajectory.steps[0].input
            wrong = replace(first, alpha=(0.0,) + first.alpha[1:])
            candidate.math.trajectory.steps = (SimpleNamespace(input=wrong),)
        elif change == "source_digest":
            sources = replace(sources, coupling_snapshot_digest="stale")
        with pytest.raises(D04ProductPreflightHold, match=match):
            preflight_d04_product_numeric_readout(
                SimpleNamespace(production_binding="binding", graph=graph),
                ROOT, graph, sources, snapshot, candidate,
            )
        assert calls == []
    finally:
        store.close()
