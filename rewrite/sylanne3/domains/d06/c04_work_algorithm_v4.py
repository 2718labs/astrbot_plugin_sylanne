"""Versioned two-root activation; no invented association edge or model call."""
from ...runtime.c04_direct_seed_v4 import AssociationWorkInputV4, AssociationWorkResultV4
from ...runtime.c04_v3_contracts import AssociationScoreV3
from .c04_work_algorithm_v3 import _compute_association_activation_from_roots_v3

ALGORITHM_ID = "d06.association_activation.direct_seed.v4"


def activate_association_work_v4(work):
    if type(work) is not AssociationWorkInputV4 or work.algorithm_id != ALGORITHM_ID:
        raise TypeError("exact installed direct-seed C04 input required")
    work.validate_closure()
    conditions = {target.source_ref: target.condition for target in work.targets}
    salience = {ref: sum(condition.conditioned_salience_interval) / 2
        for ref, condition in conditions.items()}
    # Fixed policy: both explicitly qualified roots have unit input activation.
    # Existing activation kernel clamps each node to [0, 1]. A direct seed is
    # an activation input, never a graph edge or an external-event assertion.
    computed = _compute_association_activation_from_roots_v3(work,
        conditioned_salience=salience,
        initial_activation={ref: 1.0 for ref in work.activation_roots})
    result = AssociationWorkResultV4(work.namespace, work.operation_id, work.input_digest,
        work.algorithm_id, work.algorithm_build_digest,
        tuple(AssociationScoreV3(item.source_ref, item.activation, item.conditioned_salience,
            item.mood_weighted_activation, conditions[item.source_ref].digest)
            for item in computed.candidates),
        computed.visited_nodes, computed.visited_edges, computed.iterations,
        work.truncated, computed.stop_reason)
    result.validate_input(work)
    return result
