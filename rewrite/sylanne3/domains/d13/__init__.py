"""D13 short-context selection primitives."""

from .raw_slice import assemble_raw_slice, render_raw_slice
from .precompression import (
    PrecompressionPlan, plan_precompression, compile_deterministic_candidate,
    adopt_candidate, decide_activation, accept_model_candidate,
    accept_model_or_deterministic, select_detail_slots,
)
from .provider import (
    D13ShortContextProvider, ShortContextProjectionQueryV1,
    block_graph_value, validate_block_graph_value, render_active_slice,
    retirement_reason, prepare_retirement,
)

__all__ = [
    "assemble_raw_slice", "render_raw_slice", "PrecompressionPlan",
    "plan_precompression", "compile_deterministic_candidate",
    "adopt_candidate", "decide_activation",
    "accept_model_candidate", "accept_model_or_deterministic", "select_detail_slots",
    "D13ShortContextProvider", "ShortContextProjectionQueryV1",
    "block_graph_value", "validate_block_graph_value",
    "render_active_slice", "retirement_reason", "prepare_retirement",
]
