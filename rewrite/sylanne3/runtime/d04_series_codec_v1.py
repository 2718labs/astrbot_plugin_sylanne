"""Closed series DTO codec, preserving the old numeric-v3 codec limits."""
from dataclasses import fields
from typing import get_args, get_origin, get_type_hints, Union
import types

from .d04_numeric_artifact_v3 import _json, _unpack, _typed
from .d04_semantic_mapping_v3 import evidence_payload_v3
from ..native_runtime.d04_fixed_trajectory_v2 import D04ExactSeriesStepPlanV1
from ..native_runtime.d04_joint_product_math import D04JointCompiledInputsV1
from ..native_runtime.d04_series_math_v1 import D04SeriesBranchEndpointV1, D04SeriesChunkMathV1
from ..native_runtime.d04_tanh_readout_asset import D04LoadedTanhReadoutAsset, D04TanhReadoutRow
from ..native_runtime.fixed_block_transcript import FixedBlockTrajectoryMathTranscript
from ..native_runtime.d04_fixed_trajectory_v2 import (
    _compact_d04_fixed_trajectory_payload_v2, decode_compact_d04_fixed_trajectory_v2,
    _decode_compact_d04_fixed_trajectory_payload_v2,
)
from ..native_runtime.d04_invariant_domain_v1 import D04SeriesInvariantDomainCertificateV1, D04InvariantBranchMarginsV1

_SERIES_TYPES = frozenset((D04ExactSeriesStepPlanV1, D04JointCompiledInputsV1,
    D04SeriesBranchEndpointV1, D04SeriesChunkMathV1, D04LoadedTanhReadoutAsset, D04TanhReadoutRow,
    D04SeriesInvariantDomainCertificateV1, D04InvariantBranchMarginsV1))


def _series_typed(kind, raw, trajectory_decoder=decode_compact_d04_fixed_trajectory_v2):
    origin, args = get_origin(kind), get_args(kind)
    if origin in (types.UnionType, Union):
        matches = []
        for option in args:
            try:
                matches.append(_series_typed(option, raw, trajectory_decoder))
            except (TypeError, ValueError, KeyError):
                pass
        if len(matches) != 1:
            raise ValueError("series DTO variant differs")
        return matches[0]
    if origin is tuple:
        if type(raw) is not list:
            raise ValueError("series tuple requires array")
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_series_typed(args[0], value, trajectory_decoder) for value in raw)
        if len(args) != len(raw):
            raise ValueError("series tuple length differs")
        return tuple(_series_typed(child, value, trajectory_decoder) for child, value in zip(args, raw))
    if kind is FixedBlockTrajectoryMathTranscript:
        return trajectory_decoder(raw, _typed)
    if kind in _SERIES_TYPES:
        if kind is D04SeriesChunkMathV1 and type(raw) is dict and raw.get("schema") == "d04.series-chunk-math.v1":
            if set(raw) != {f.name for f in fields(kind)} - {"invariant_domain"}:
                raise ValueError("historical series v1 fields differ")
            raw = {**raw, "invariant_domain": None}
        if type(raw) is not dict or set(raw) != {f.name for f in fields(kind)}:
            raise ValueError("series DTO fields differ: " + kind.__name__)
        hints = get_type_hints(kind)
        return kind(**{name: _series_typed(hints[name], raw[name], trajectory_decoder) for name in raw})
    return _typed(kind, raw)


def decode_series_dto_v1(kind, raw):
    if kind not in _SERIES_TYPES:
        raise ValueError("closed series root DTO required")
    value = _series_typed(kind, _unpack(_json(raw)))
    if encode_series_dto_v1(value) != _json(raw):
        raise ValueError("series exact binary64 codec roundtrip differs")
    return value


def _decode_series_chunk_for_final_verifier_v1(raw):
    """Private original collectors consume this unqualified structure.

    Authority collectors fully verify each chunk before issuing commitments;
    final/history collectors pass their entire prefix to the final math
    verifier before returning any adopted original. Public decoding retains
    its complete trajectory verification contract.
    """
    wire = _json(raw)
    value = _series_typed(D04SeriesChunkMathV1, _unpack(wire),
        _decode_compact_d04_fixed_trajectory_payload_v2)
    if encode_series_dto_v1(value) != wire:
        raise ValueError("series exact binary64 structural roundtrip differs")
    return value


def encode_series_dto_v1(value):
    if type(value) not in _SERIES_TYPES:
        raise ValueError("closed series root DTO required")
    def encode(item):
        if type(item) is FixedBlockTrajectoryMathTranscript:
            return _compact_d04_fixed_trajectory_payload_v2(item)
        if type(item) in _SERIES_TYPES:
            return {f.name: encode(getattr(item, f.name)) for f in fields(item)
                    if not (type(item) is D04SeriesChunkMathV1 and item.schema == "d04.series-chunk-math.v1"
                            and f.name == "invariant_domain")}
        if type(item) in {tuple, list}:
            return [encode(child) for child in item]
        return evidence_payload_v3(item)
    return encode(value)
