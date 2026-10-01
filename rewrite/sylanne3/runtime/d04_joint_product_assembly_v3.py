"""Assemble installed D04 outputs into the existing W01 joint adoption contract.

The input is a current fenced preparation. Numerical work and output issuance
run outside the graph transaction; only W01 may adopt the resulting bundle.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..domains.d04.joint_state_output_v1 import (
    JointStateFrozenPredecessorsV1, JointStateOutputOriginalV1,
    issue_joint_state_outputs_v1,
)
from ..domains.d04.trusted_joint_replay import (
    D04InstalledJointNumericReplayV1,
    replay_package_bound_joint_numeric_original_v1,
)
from ..graph_types import GraphSnapshot
from ..runtime_contracts import CommandEnvelope
from .d04_current_joint_replay_input_v2 import D04CurrentJointReplayInputV2


@dataclass(frozen=True, slots=True)
class D04JointProductPreparationV3:
    envelope: CommandEnvelope
    current: D04CurrentJointReplayInputV2
    predecessors: JointStateFrozenPredecessorsV1
    snapshot: GraphSnapshot


@dataclass(frozen=True, slots=True)
class D04InstalledJointProductV3:
    preparation: D04JointProductPreparationV3
    replay: D04InstalledJointNumericReplayV1
    output: JointStateOutputOriginalV1


def run_installed_d04_joint_product_v3(
    preparation: D04JointProductPreparationV3, *, installation,
    output_policy, max_iterations: int, tolerance: float,
) -> D04InstalledJointProductV3:
    """Run the package-bound ABI2 and fixed output issuer without SQL locks."""
    current = preparation.current
    replay = replay_package_bound_joint_numeric_original_v1(
        installation, current.component, checkpoints=current.checkpoints,
        drives=current.drives, families=current.families,
        readout_id=output_policy.policy.readout_id,
        max_iterations=max_iterations, tolerance=tolerance,
    )
    output = issue_joint_state_outputs_v1(
        replay, preparation.predecessors, output_policy)
    return D04InstalledJointProductV3(preparation, replay, output)



__all__ = ["D04JointProductPreparationV3", "D04InstalledJointProductV3",
           "run_installed_d04_joint_product_v3"]
