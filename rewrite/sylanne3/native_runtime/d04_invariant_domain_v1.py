"""Exact CSR proof of a closed invariant cube for the frozen D04 ODE.

This is an installed mathematical checker, not a native flag or an Authority
receipt. Its premises and result are committed by the actual series prefix.
"""
from dataclasses import asdict, dataclass
from fractions import Fraction
from hashlib import sha256
from pathlib import Path
import math

from .fixed_block_transcript import _digest
from .tanh_interval import _outward_binary64

VERIFIER_FILES = ("d04_invariant_domain_v1.py", "d04_series_math_v1.py",
                  "tanh_interval.py", "tanh_asset_readout.py")


@dataclass(frozen=True, slots=True)
class D04InvariantBranchMarginsV1:
    family_id: str | None
    lower: tuple[str, ...]
    upper: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class D04SeriesInvariantDomainCertificateV1:
    root_digest: str
    plan_digest: str
    frozen_input_digest: str
    verifier_files: tuple[tuple[str, str], ...]
    branches: tuple[D04InvariantBranchMarginsV1, ...]
    proof_kind: str = "installed_exact_csr_invariant_v1"
    schema: str = "d04.series-invariant-domain.v1"

    @property
    def digest(self):
        return _digest(asdict(self))


def _rows(matrix):
    rows = []
    for i in range(matrix.rows):
        row = {}
        columns = matrix.indices[matrix.offsets[i]:matrix.offsets[i + 1]]
        if any(left >= right for left, right in zip(columns, columns[1:])):
            raise ValueError("invariant proof CSR must use native strictly increasing columns")
        for position in range(matrix.offsets[i], matrix.offsets[i + 1]):
            j = matrix.indices[position]
            row[j] = row.get(j, Fraction()) + Fraction.from_float(matrix.values[position])
        rows.append({j: value for j, value in row.items() if value})
    return tuple(rows)


def prove_d04_series_invariant_domain_v1(frozen, *, root_digest):
    """Prove inward faces exactly for every actual full/LOO constant drive.

    For F=d-R(Kz+Aᵀ alpha tanh(Az)), J=0, positive diagonal R and
    single-coordinate A rows make the nonlinear gradient zero on z_i=0
    and nonnegative on z_i=4. The two recorded rational face margins then
    prove F_i>=0 on the lower face and F_i<=0 on the upper face. The smooth
    finite vector field has unique solutions, so the cube is invariant.
    """
    from .d04_joint_product_math import D04JointCompiledInputsV1
    if type(frozen) is not D04JointCompiledInputsV1:
        raise TypeError("invariant proof requires the actual closed frozen joint model")
    step = frozen.full_step
    n = len(step.previous)
    if (any(len(drive) != n for _, drive in frozen.family_drives)
            or len({family for family, _ in frozen.family_drives}) != len(frozen.family_drives)
            or any(type(family) is not str or not family for family, _ in frozen.family_drives)
            or frozen.plan.family_count != len(frozen.family_drives)):
        raise ValueError("invariant proof loses the complete actual family inventory")
    if (len(frozen.initial_lower) != n or len(frozen.initial_upper) != n
            or any(not 0 <= low <= center <= high <= 4 for low, center, high in
                   zip(frozen.initial_lower, step.previous, frozen.initial_upper))):
        return None
    r, j, a, k = (_rows(matrix) for matrix in (step.r, step.j, step.a, step.k))
    if (any(row for row in j) or any(set(row) != {i} or row[i] <= 0 for i, row in enumerate(r))
            or any(len(row) > 1 for row in a) or any(value < 0 for value in step.alpha)):
        return None
    branches = []
    for family, drive in ((None, step.drive), *frozen.family_drives):
        lower, upper = [], []
        for i, (row, value) in enumerate(zip(k, drive)):
            positive = sum((entry for column, entry in row.items() if column != i and entry > 0), Fraction())
            negative = sum((entry for column, entry in row.items() if column != i and entry < 0), Fraction())
            d = Fraction.from_float(value)
            lo = d - 4 * r[i][i] * positive
            hi = 4 * r[i][i] * (row.get(i, Fraction()) + negative) - d
            if lo < 0 or hi < 0:
                return None
            lower.append(str(lo))
            upper.append(str(hi))
        branches.append(D04InvariantBranchMarginsV1(family, tuple(lower), tuple(upper)))
    directory = Path(__file__).resolve().parent
    verifier_files = tuple((name, sha256((directory / name).read_bytes()).hexdigest()) for name in VERIFIER_FILES)
    return D04SeriesInvariantDomainCertificateV1(root_digest, frozen.plan.digest,
        _digest(asdict(frozen)), verifier_files, tuple(branches))


def require_installed_d04_invariant_verifier_v1(certificate, manifest_digest):
    """Bind each actual checker file to the same installed release manifest."""
    import json
    package = Path(__file__).resolve().parents[3]
    data = (package / "release-manifest.json").read_bytes()
    if sha256(data).hexdigest() != manifest_digest:
        raise ValueError("invariant verifier installed manifest differs from numeric binding")
    manifest = json.loads(data)
    for name, digest in certificate.verifier_files:
        relative = "rewrite/sylanne3/native_runtime/" + name
        rows = tuple(row for row in manifest["files"] if row["path"] == relative)
        source = (package / relative).read_bytes()
        if (len(rows) != 1 or rows[0]["sha256"] != digest or rows[0]["bytes"] != len(source)
                or sha256(source).hexdigest() != digest):
            raise ValueError("invariant verifier file lost its actual installed origin")


def invariant_d04_state_boxes_v1(values, error, certificate):
    """Enclose ball∩proved cube; retain E and cover the complete resulting box."""
    if (type(certificate) is not D04SeriesInvariantDomainCertificateV1
            or certificate.proof_kind != "installed_exact_csr_invariant_v1"
            or type(error) is not float or not math.isfinite(error) or error < 0):
        raise ValueError("closed invariant proof and original native error required")
    radius, squared, boxes = Fraction.from_float(error), Fraction(), []
    for value in values:
        if type(value) is not float or not math.isfinite(value) or not 0 <= value <= 4:
            raise ValueError("native center leaves proved cube; no projection is permitted")
        center = Fraction.from_float(value)
        low, high = max(Fraction(), center - radius), min(Fraction(4), center + radius)
        lower, upper = _outward_binary64(low, lower=True), _outward_binary64(high, lower=False)
        boxes.append((lower, upper))
        deviation = max(center - Fraction.from_float(lower), Fraction.from_float(upper) - center)
        squared += deviation * deviation
    scalar = max(error, math.sqrt(float(squared)))
    while Fraction.from_float(scalar) ** 2 < squared:
        scalar = math.nextafter(scalar, math.inf)
    return tuple(boxes), scalar
