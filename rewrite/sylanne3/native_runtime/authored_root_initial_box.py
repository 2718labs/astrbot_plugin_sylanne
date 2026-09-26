"""Conditional native initial-box math for an authored D04 root candidate.

The author-declared boxes are premises. This module verifies their numerical
radii with a package-bound ABI2 handle, without authenticating authored source,
D04 assets, or graph adoption.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from ..domains.d04.root import (
    AuthoredRootCandidate,
    encode_root_checkpoint_candidate,
)
from ..runtime_contracts import canonical_digest
from .abi2 import ABI2ResultError
from .initial_box_trajectory import _box_digest, _native_initial_radius
from .loader import ABI2NativeLibrary, NativeLoadBinding


@dataclass(frozen=True, slots=True)
class AuthoredRootInitialBoxBlockMathCandidate:
    checkpoint_sha256: str
    initial_box_sha256: str
    verified_initial_error: float


@dataclass(frozen=True, slots=True)
class AuthoredRootInitialBoxMathCandidate:
    candidate_sha256: str
    production_binding: NativeLoadBinding
    binding_sha256: str
    blocks: tuple[AuthoredRootInitialBoxBlockMathCandidate, ...]
    transcript_sha256: str
    status: str = "conditional_math_candidate"


def run_authored_root_initial_box_math(
    handle: ABI2NativeLibrary,
    candidate: AuthoredRootCandidate,
) -> AuthoredRootInitialBoxMathCandidate:
    """Verify each declared box radius; preserve exact candidate and package identity."""
    if type(candidate) is not AuthoredRootCandidate:
        raise TypeError("expected AuthoredRootCandidate")
    if not isinstance(handle, ABI2NativeLibrary) or handle.production_binding is None:
        raise ABI2ResultError("authored root initial box requires a package-bound ABI2 handle")
    if not handle.capabilities.supports_initial_box_math_v1 or handle._initial_box is None:
        raise ABI2ResultError("native initial-box math capability is absent")
    binding = handle.production_binding
    blocks = []
    for checkpoint in candidate.checkpoints:
        lower = tuple(interval[0] for interval in checkpoint.ordered_box)
        upper = tuple(interval[1] for interval in checkpoint.ordered_box)
        radius = _native_initial_radius(handle, checkpoint.latent_state, lower, upper)
        blocks.append(AuthoredRootInitialBoxBlockMathCandidate(
            checkpoint_sha256=canonical_digest(encode_root_checkpoint_candidate(checkpoint)),
            initial_box_sha256=_box_digest(checkpoint.latent_state, lower, upper,
                                           radius, binding),
            verified_initial_error=radius,
        ))
    block_candidates = tuple(blocks)
    candidate_sha256 = candidate.digest
    binding_sha256 = canonical_digest(asdict(binding))
    transcript_sha256 = canonical_digest({
        "schema": "d04.authored-root-initial-box-math.v1",
        "candidate_sha256": candidate_sha256,
        "binding_sha256": binding_sha256,
        "blocks": [asdict(block) for block in block_candidates],
        "status": "conditional_math_candidate",
    })
    return AuthoredRootInitialBoxMathCandidate(
        candidate_sha256, binding, binding_sha256, block_candidates,
        transcript_sha256,
    )


def verify_authored_root_initial_box_math(
    handle: ABI2NativeLibrary,
    candidate: AuthoredRootCandidate,
    transcript: AuthoredRootInitialBoxMathCandidate,
) -> None:
    """Replay native verification against this candidate and this exact package."""
    if type(transcript) is not AuthoredRootInitialBoxMathCandidate:
        raise TypeError("expected AuthoredRootInitialBoxMathCandidate")
    if transcript.candidate_sha256 != candidate.digest:
        raise ABI2ResultError("authored root candidate digest mismatch")
    if not isinstance(handle, ABI2NativeLibrary) or transcript.production_binding != handle.production_binding:
        raise ABI2ResultError("authored root production binding mismatch")
    if transcript != run_authored_root_initial_box_math(handle, candidate):
        raise ABI2ResultError("authored root candidate initial-box transcript mismatch")
