"""An isolated D04 engineering candidate, never a packaged or adopted scheme.

Each of eight provisional mechanisms has fast, residual, and slow latent
coordinates.  The fixed block is one object/meaning/source instance; this
module does not assign source identity, dose, time, or authority to adopt it.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from .fixed_block_transcript import FixedBlockCSR


SCHEMA = "d04.engineering-candidate.v1"
MECHANISMS = (
    "gain_engagement",
    "loss_response",
    "affiliative_approach",
    "boundary_protection",
    "agency_mobilization",
    "low_control_response",
    "self_congruence",
    "self_discrepancy",
)
LAYERS = ("fast", "residual", "slow")
DIMENSION = len(MECHANISMS) * len(LAYERS)
COUPLING_BETA = 1.0 / 8.0
NONLINEAR_ALPHA = 1.0 / 4.0
RECOVERY_RATES = (1.0, 1.0 / 8.0, 1.0 / 64.0)


def _csr(rows: tuple[dict[int, float], ...], columns: int) -> FixedBlockCSR:
    offsets = [0]
    indices: list[int] = []
    values: list[float] = []
    for row in rows:
        for column in sorted(row):
            indices.append(column)
            values.append(row[column])
        offsets.append(len(indices))
    return FixedBlockCSR(len(rows), columns, tuple(offsets), tuple(indices), tuple(values))


@dataclass(frozen=True, slots=True)
class D04EngineeringCandidate:
    """Complete conditional ABI2 operator, without numerical certification."""

    axis_ids: tuple[str, ...]
    k: FixedBlockCSR
    r: FixedBlockCSR
    j: FixedBlockCSR
    a: FixedBlockCSR
    alpha: tuple[float, ...]
    schema: str = SCHEMA

    def project_latent(self, latent: tuple[float, ...]) -> tuple[float, ...]:
        """Project the candidate latent domain [0, 4]^24 without clipping."""
        if len(latent) != DIMENSION or any(
            not math.isfinite(value) or not 0.0 <= value <= 4.0 for value in latent
        ):
            raise ValueError("D04 candidate latent vector must lie in [0, 4]^24")
        return tuple(math.tanh(value) for value in latent)


def build_d04_engineering_candidate() -> D04EngineeringCandidate:
    """Construct K=I+Bᵀ(1/8 I)B for eight disjoint three-node chains."""
    axes = tuple(f"{mechanism}:{layer}" for mechanism in MECHANISMS for layer in LAYERS)
    k_rows = [{index: 1.0} for index in range(DIMENSION)]
    for channel in range(len(MECHANISMS)):
        start = channel * len(LAYERS)
        for left, right in ((start, start + 1), (start + 1, start + 2)):
            k_rows[left][left] += COUPLING_BETA
            k_rows[right][right] += COUPLING_BETA
            k_rows[left][right] = -COUPLING_BETA
            k_rows[right][left] = -COUPLING_BETA
    r_rows = [{index: RECOVERY_RATES[index % len(LAYERS)]} for index in range(DIMENSION)]
    j_rows = [{} for _ in range(DIMENSION)]
    a_rows = [{index: 1.0} for index in range(DIMENSION)]
    return D04EngineeringCandidate(
        axes,
        _csr(tuple(k_rows), DIMENSION),
        _csr(tuple(r_rows), DIMENSION),
        _csr(tuple(j_rows), DIMENSION),
        _csr(tuple(a_rows), DIMENSION),
        (NONLINEAR_ALPHA,) * DIMENSION,
    )
