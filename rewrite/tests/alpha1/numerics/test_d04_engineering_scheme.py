"""Structural checks for the unadmitted D04 engineering candidate."""

from __future__ import annotations

import math

import pytest

from sylanne3.native_runtime.d04_engineering_scheme import (
    DIMENSION,
    LAYERS,
    MECHANISMS,
    build_d04_engineering_candidate,
)
from sylanne3.native_runtime.fixed_block_transcript import FixedBlockCSR, FixedBlockStep


def _dense(matrix: FixedBlockCSR) -> tuple[tuple[float, ...], ...]:
    rows = [[0.0] * matrix.cols for _ in range(matrix.rows)]
    for row in range(matrix.rows):
        for position in range(matrix.offsets[row], matrix.offsets[row + 1]):
            rows[row][matrix.indices[position]] = matrix.values[position]
    return tuple(tuple(row) for row in rows)


def test_candidate_has_complete_24d_native_shape_and_disjoint_chains() -> None:
    candidate = build_d04_engineering_candidate()
    assert candidate.schema == "d04.engineering-candidate.v1"
    assert candidate.axis_ids == tuple(
        f"{mechanism}:{layer}" for mechanism in MECHANISMS for layer in LAYERS
    )
    assert len(candidate.axis_ids) == DIMENSION == 24
    assert all((matrix.rows, matrix.cols) == (24, 24) for matrix in (
        candidate.k, candidate.r, candidate.j, candidate.a,
    ))
    assert candidate.alpha == (0.25,) * 24

    k, r, j, a = map(_dense, (candidate.k, candidate.r, candidate.j, candidate.a))
    for channel in range(8):
        first = channel * 3
        assert tuple(k[first + layer][first + layer] for layer in range(3)) == (
            1.125, 1.25, 1.125,
        )
        assert k[first][first + 1] == k[first + 1][first] == -0.125
        assert k[first + 1][first + 2] == k[first + 2][first + 1] == -0.125
        assert k[first][first + 2] == 0.0
        assert tuple(r[first + layer][first + layer] for layer in range(3)) == (
            1.0, 0.125, 0.015625,
        )
    assert all(k[row][col] == 0.0 for row in range(24) for col in range(24)
               if row // 3 != col // 3)
    assert all(j[row][col] == 0.0 for row in range(24) for col in range(24))
    assert all(a[row][col] == float(row == col) for row in range(24) for col in range(24))


def test_candidate_operator_fits_generic_native_input_without_narrowing_it() -> None:
    candidate = build_d04_engineering_candidate()
    # This constructs an ABI2 input; it does not run or certify a native step.
    zero = (0.0,) * 24
    step = FixedBlockStep(candidate.k, candidate.r, candidate.j, candidate.a,
                          candidate.alpha, zero, zero, zero, 0.125, 0.0, 16, 1e-8)
    assert len(step.previous) == 24
    # ABI2 accepts finite mathematical inputs outside this D04 candidate's domain.
    unrestricted = (-2.0, 5.0) + (0.0,) * 22
    native_step = FixedBlockStep(candidate.k, candidate.r, candidate.j, candidate.a,
                                 candidate.alpha, unrestricted, zero, unrestricted,
                                 0.125, 0.0, 16, 1e-8)
    assert native_step.previous[:2] == (-2.0, 5.0)


def test_candidate_quadratic_form_has_declared_sparse_factor_structure() -> None:
    candidate = build_d04_engineering_candidate()
    k = _dense(candidate.k)
    probes = (
        tuple(float(index % 3 - 1) for index in range(24)),
        tuple(float(index == 0) for index in range(24)),
        tuple(float(index == 1) for index in range(24)),
        tuple(float(index == 23) for index in range(24)),
    )
    for vector in probes:
        quadratic = math.fsum(vector[row] * k[row][col] * vector[col]
                              for row in range(24) for col in range(24))
        factor_energy = math.fsum(value * value for value in vector) + 0.125 * math.fsum(
            (vector[channel * 3 + left] - vector[channel * 3 + right]) ** 2
            for channel in range(8) for left, right in ((0, 1), (1, 2))
        )
        assert quadratic == factor_energy
        assert quadratic > 0.0


def test_tanh_readout_does_not_clip_or_replace_latent_coordinates() -> None:
    candidate = build_d04_engineering_candidate()
    latent = (0.0, 2.0, 4.0) * 8
    readout = candidate.project_latent(latent)
    assert readout[:3] == (0.0, math.tanh(2.0), math.tanh(4.0))
    assert latent[:3] == (0.0, 2.0, 4.0)
    assert all(0.0 <= value < 1.0 for value in readout)
    with pytest.raises(ValueError, match="\\[0, 4\\]\\^24"):
        candidate.project_latent((0.0,) * 23)
    with pytest.raises(ValueError, match="\\[0, 4\\]\\^24"):
        candidate.project_latent((float("inf"),) + (0.0,) * 23)
    for invalid in (-0.01, 4.01):
        with pytest.raises(ValueError, match="\\[0, 4\\]\\^24"):
            candidate.project_latent((invalid,) + (0.0,) * 23)
