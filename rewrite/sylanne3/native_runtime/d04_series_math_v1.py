"""Bounded native chunks of one frozen full/whole-family removal series.

Absolute h ordinals belong to the root plan. Each branch carries its own
output and accumulated certified error; no chunk initializes a removal
branch from full, and no continuation calls the initial-box ABI again.
Authentication and atomic business adoption belong to the installed runtime.
"""
from dataclasses import asdict, dataclass, replace
from fractions import Fraction

from .d04_fixed_trajectory_v2 import (run_d04_fixed_trajectory_v2,
    verify_d04_fixed_trajectory_v2, trajectory_digest_v2)
from .d04_joint_product_math import (D04JointCompiledInputsV1, D04JointMemberReadout,
    D04JointProductMathHold)
from .fixed_block_transcript import FixedBlockTrajectoryMathTranscript, _digest, _same_float_bits
from .initial_box_trajectory import _native_initial_radius
from .tanh_asset_readout import run_d04_conditional_tanh_readout_math
from .tanh_interval import _outward_binary64
from .d04_invariant_domain_v1 import (D04SeriesInvariantDomainCertificateV1,
    prove_d04_series_invariant_domain_v1, invariant_d04_state_boxes_v1)


@dataclass(frozen=True, slots=True)
class D04SeriesBranchEndpointV1:
    family_id: str | None
    output: tuple[float, ...]
    trajectory_error: float
    prefix_digest: str


@dataclass(frozen=True, slots=True)
class D04SeriesChunkMathV1:
    root_digest: str
    plan_digest: str
    start_step_index: int
    end_step_index: int
    predecessor_digest: str | None
    initial_error: float
    full: FixedBlockTrajectoryMathTranscript
    family_loo: tuple[tuple[str, FixedBlockTrajectoryMathTranscript], ...]
    endpoints: tuple[D04SeriesBranchEndpointV1, ...]
    schema: str = "d04.series-chunk-math.v1"
    invariant_domain: D04SeriesInvariantDomainCertificateV1 | None = None

    @property
    def digest(self):
        payload = {"schema": self.schema, "root": self.root_digest, "plan": self.plan_digest,
            "start": self.start_step_index, "end": self.end_step_index,
            "predecessor": self.predecessor_digest, "initial_error": self.initial_error,
            "full": self.full.transcript_sha256,
            "family_loo": tuple((family, branch.transcript_sha256) for family, branch in self.family_loo),
            "endpoints": tuple(asdict(endpoint) for endpoint in self.endpoints)}
        if self.schema == "d04.series-chunk-math.v2":
            payload["invariant_domain"] = None if self.invariant_domain is None else self.invariant_domain.digest
        return _digest(payload)


def _branch_prefix(root_digest, plan_digest, start, end, family, previous_prefix, transcript):
    return _digest(("d04.series-branch-prefix.v1", root_digest, plan_digest,
        start, end, family, previous_prefix, transcript.transcript_sha256))


def run_d04_series_chunk_math_v1(handle, frozen, *, root_digest, predecessor=None):
    if type(frozen) is not D04JointCompiledInputsV1:
        raise D04JointProductMathHold("series requires the complete frozen joint model")
    if predecessor is not None:
        verify_d04_series_chunk_math_v1(frozen, predecessor, root_digest=root_digest)
        start = predecessor.end_step_index
        initial_error = predecessor.initial_error
        previous_digest = predecessor.digest
        endpoints = predecessor.endpoints
    else:
        start, previous_digest = 0, None
        initial_error = max(frozen.inherited_error, _native_initial_radius(handle,
            frozen.full_step.previous, frozen.initial_lower, frozen.initial_upper))
        endpoints = tuple(D04SeriesBranchEndpointV1(family, frozen.full_step.previous,
            initial_error, "") for family in (None, *(family for family, _ in frozen.family_drives)))
    steps = frozen.plan.chunk(start)
    branches = []
    next_endpoints = []
    models = ((None, frozen.full_step.drive), *frozen.family_drives)
    for (family, drive), endpoint in zip(models, endpoints):
        if family != endpoint.family_id:
            raise D04JointProductMathHold("series branch inventory changed")
        first = replace(frozen.full_step, drive=drive, previous=endpoint.output,
            iterate=endpoint.output, previous_error=endpoint.trajectory_error, h=steps[0])
        trajectory = run_d04_fixed_trajectory_v2(handle, first, steps)
        branches.append((family, trajectory))
        next_endpoints.append(D04SeriesBranchEndpointV1(family, trajectory.output,
            trajectory.final_error, _branch_prefix(root_digest, frozen.plan.digest,
                start, start + len(steps), family, endpoint.prefix_digest, trajectory)))
    proof = prove_d04_series_invariant_domain_v1(frozen, root_digest=root_digest)
    result = D04SeriesChunkMathV1(root_digest, frozen.plan.digest, start, start + len(steps),
        previous_digest, initial_error, branches[0][1], tuple(branches[1:]), tuple(next_endpoints),
        schema="d04.series-chunk-math.v2", invariant_domain=proof)
    return verify_d04_series_chunk_math_v1(frozen, result, root_digest=root_digest, predecessor=predecessor)


def verify_d04_series_chunk_math_v1(frozen, value, *, root_digest, predecessor=None):
    """Pure bounded verification, also used after authenticated terminal restore.

With no predecessor supplied, verify only this chunk's local structure.
The installed prefix walker supplies every real predecessor before adoption.
"""
    if (type(value) is not D04SeriesChunkMathV1 or value.schema not in {"d04.series-chunk-math.v1", "d04.series-chunk-math.v2"}
            or value.root_digest != root_digest or value.plan_digest != frozen.plan.digest
            or tuple(family for family, _ in value.family_loo) != tuple(family for family, _ in frozen.family_drives)
            or len(value.endpoints) != 1 + len(frozen.family_drives)):
        raise D04JointProductMathHold("series chunk root/plan/whole-family inventory differs")
    if value.schema == "d04.series-chunk-math.v1":
        if value.invariant_domain is not None:
            raise D04JointProductMathHold("historical series v1 cannot acquire a new invariant certificate")
    elif value.invariant_domain != prove_d04_series_invariant_domain_v1(frozen, root_digest=root_digest):
        raise D04JointProductMathHold("series invariant certificate differs from the complete frozen model")
    steps = frozen.plan.chunk(value.start_step_index)
    if value.end_step_index != value.start_step_index + len(steps):
        raise D04JointProductMathHold("series chunk loses absolute h ordinals")
    if value.start_step_index == 0:
        if value.predecessor_digest is not None or predecessor is not None:
            raise D04JointProductMathHold("initial chunk cannot have a predecessor")
        if value.initial_error < frozen.inherited_error:
            raise D04JointProductMathHold("initial series error drops inherited uncertainty")
        previous_endpoints = tuple(D04SeriesBranchEndpointV1(family, frozen.full_step.previous,
            value.initial_error, "") for family in (None, *(family for family, _ in frozen.family_drives)))
    elif predecessor is not None:
        if (value.start_step_index != predecessor.end_step_index
                or value.predecessor_digest != predecessor.digest
                or value.initial_error != predecessor.initial_error):
            raise D04JointProductMathHold("series chunk is not the exact authenticated successor")
        previous_endpoints = predecessor.endpoints
    else:
        if value.predecessor_digest is None:
            raise D04JointProductMathHold("noninitial chunk has no predecessor commitment")
        previous_endpoints = None
    for position, ((family, drive), (_, branch), endpoint) in enumerate(zip(
            ((None, frozen.full_step.drive), *frozen.family_drives),
            ((None, value.full), *value.family_loo), value.endpoints)):
        prior = None if previous_endpoints is None else previous_endpoints[position]
        first = branch.steps[0].input
        expected = replace(frozen.full_step, h=steps[0], drive=drive,
            previous=first.previous if prior is None else prior.output,
            iterate=first.previous if prior is None else prior.output,
            previous_error=first.previous_error if prior is None else prior.trajectory_error)
        verify_d04_fixed_trajectory_v2(branch, first=expected, step_plan=steps)
        if (endpoint.family_id != family or not _same_float_bits(endpoint.output, branch.output)
                or not _same_float_bits((endpoint.trajectory_error,), (branch.final_error,))
                or branch.production_binding != value.full.production_binding):
            raise D04JointProductMathHold("series branch endpoint/error/native binding changed")
        if prior is not None and endpoint.prefix_digest != _branch_prefix(root_digest,
                frozen.plan.digest, value.start_step_index, value.end_step_index,
                family, prior.prefix_digest, branch):
            raise D04JointProductMathHold("series branch prefix does not commit the real predecessor")
    return value


def read_d04_series_final_members_v1(frozen, chunks, *, root_digest):
    """Verify a complete contiguous prefix and read all final full/LOO endpoints.

No trajectory is concatenated into the old 4096-step codec.
"""
    if type(chunks) is not tuple or not chunks:
        raise D04JointProductMathHold("final series needs its actual complete chunk prefix")
    previous = None
    for chunk in chunks:
        verify_d04_series_chunk_math_v1(frozen, chunk, root_digest=root_digest, predecessor=previous)
        previous = chunk
    if chunks[0].start_step_index != 0 or previous.end_step_index != frozen.plan.total_step_count:
        raise D04JointProductMathHold("final series prefix does not cover the original entire role interval")
    members = []
    for index, ref in enumerate(frozen.member_refs):
        section = slice(index * 24, (index + 1) * 24)
        full_endpoint = previous.endpoints[0]
        from .tanh_asset_readout import run_d04_invariant_tanh_readout_math
        def readout(endpoint):
            if previous.invariant_domain is None:
                return run_d04_conditional_tanh_readout_math(frozen.readout,
                    endpoint.output[section], endpoint.trajectory_error)
            return run_d04_invariant_tanh_readout_math(frozen.readout,
                endpoint.output[section], endpoint.trajectory_error, previous.invariant_domain)
        full = readout(full_endpoint)
        without = tuple((endpoint.family_id, readout(endpoint)) for endpoint in previous.endpoints[1:])
        effects = tuple((family, tuple((_outward_binary64(Fraction.from_float(lhs.lower)
            - Fraction.from_float(rhs.upper), lower=True), _outward_binary64(Fraction.from_float(lhs.upper)
            - Fraction.from_float(rhs.lower), lower=False)) for lhs, rhs in zip(full.outputs, branch.outputs)))
            for family, branch in without)
        members.append(D04JointMemberReadout(ref, full, without, effects))
    return tuple(members)


def read_d04_series_certified_box_v1(chunk, values, error, policy):
    """The authenticated v2 proof selects intersection; v1 retains ball semantics."""
    from ..domains.d04.joint_state_output_v1 import _latent_box
    if chunk.invariant_domain is None:
        return _latent_box(values, error, policy)
    if (chunk.schema != "d04.series-chunk-math.v2" or policy.latent_lower != 0 or policy.latent_upper != 4):
        raise D04JointProductMathHold("invariant certificate differs from the installed latent domain")
    return invariant_d04_state_boxes_v1(values, error, chunk.invariant_domain)
