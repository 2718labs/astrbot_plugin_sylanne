"""Closed, finite commitments to one Authority-authenticated complete prefix."""
from dataclasses import dataclass

from ..authority_service.d04_series_contract_v1 import (
    D04SeriesChunkBindingV1, D04SeriesTerminalV1, from_wire, to_wire, _digest)


@dataclass(frozen=True, slots=True)
class D04SeriesPrefixPacketV1:
    terminal: D04SeriesTerminalV1
    sha256: str
    length: int

    def __post_init__(self):
        _digest(self.sha256)
        if (type(self.terminal) is not D04SeriesTerminalV1 or type(self.length) is not int
                or self.length <= 0 or self.terminal.measurement.status != "chunk_completed"
                or self.terminal.measurement.actual_cpu_ms > self.terminal.binding.numeric.cpu_ceiling_ms):
            raise ValueError("series prefix packet requires its actual completed bounded terminal")


@dataclass(frozen=True, slots=True)
class D04SeriesPrefixManifestV1:
    root_ref: str
    root_digest: str
    plan_digest: str
    total_step_count: int
    chunk_step_limit: int
    chunk_count: int
    packets: tuple[D04SeriesPrefixPacketV1, ...]
    schema: str = "d04.series-prefix-manifest.v1"

    def __post_init__(self):
        _digest(self.root_digest)
        _digest(self.plan_digest)
        if (self.schema != "d04.series-prefix-manifest.v1" or not self.root_ref
                or type(self.total_step_count) is not int or self.total_step_count <= 0
                or type(self.chunk_step_limit) is not int or not 1 <= self.chunk_step_limit <= 512
                or type(self.chunk_count) is not int
                or self.chunk_count != (self.total_step_count + self.chunk_step_limit - 1) // self.chunk_step_limit
                or type(self.packets) is not tuple or len(self.packets) != self.chunk_count):
            raise ValueError("series prefix manifest finite complete inventory differs")
        previous = None
        start = 0
        for packet in self.packets:
            if type(packet) is not D04SeriesPrefixPacketV1:
                raise ValueError("series prefix manifest packet type differs")
            binding = packet.terminal.binding
            if ((binding.root_ref, binding.root_digest, binding.plan_digest, binding.start_step_index) !=
                    (self.root_ref, self.root_digest, self.plan_digest, start)
                    or binding.end_step_index != min(start + self.chunk_step_limit, self.total_step_count)
                    or (previous is not None and (binding.predecessor_ref, binding.predecessor_digest) !=
                        (previous.binding.numeric.operation_id, previous.measurement.chunk_math_digest))):
                raise ValueError("series prefix manifest loses its exact contiguous terminal chain")
            if previous is not None:
                a, b = previous.binding.numeric, binding.numeric
                if (a.namespace, a.authority_id, a.authority_namespace, a.installation_id,
                        a.job_id, a.activity_id, a.deadline_utc, a.native_manifest_sha256, a.native_sha256) != (
                        b.namespace, b.authority_id, b.authority_namespace, b.installation_id,
                        b.job_id, b.activity_id, b.deadline_utc, b.native_manifest_sha256, b.native_sha256):
                    raise ValueError("series prefix manifest changes its installed execution origin")
            start, previous = binding.end_step_index, packet.terminal
        if start != self.total_step_count:
            raise ValueError("series prefix manifest is incomplete")


def prefix_manifest_to_wire_v1(value):
    if type(value) is not D04SeriesPrefixManifestV1:
        raise TypeError("typed actual series prefix manifest required")
    return {"schema": value.schema, "root_ref": value.root_ref, "root_digest": value.root_digest,
        "plan_digest": value.plan_digest, "total_step_count": value.total_step_count,
        "chunk_step_limit": value.chunk_step_limit, "chunk_count": value.chunk_count,
        "packets": [{"terminal": to_wire(packet.terminal),
            "sha256": packet.sha256, "length": packet.length} for packet in value.packets]}


def prefix_manifest_from_wire_v1(raw, *, final_binding):
    fields = {"schema", "root_ref", "root_digest", "plan_digest", "total_step_count", "chunk_step_limit", "chunk_count", "packets"}
    if (type(final_binding) is not D04SeriesChunkBindingV1 or type(raw) is not dict or set(raw) != fields
            or type(raw["packets"]) is not list or type(raw["chunk_count"]) is not int
            or type(raw["total_step_count"]) is not int or raw["total_step_count"] != final_binding.end_step_index
            or type(raw["chunk_step_limit"]) is not int or not 1 <= raw["chunk_step_limit"] <= 512
            or raw["chunk_count"] != (raw["total_step_count"] + raw["chunk_step_limit"] - 1) // raw["chunk_step_limit"]
            or len(raw["packets"]) != raw["chunk_count"]):
        raise ValueError("series prefix manifest closed fields/bounds differ")
    packets = []
    for packet in raw["packets"]:
        if type(packet) is not dict or set(packet) != {"terminal", "sha256", "length"}:
            raise ValueError("series prefix packet closed fields differ")
        packets.append(D04SeriesPrefixPacketV1(from_wire(packet["terminal"], D04SeriesTerminalV1),
            packet["sha256"], packet["length"]))
    value = D04SeriesPrefixManifestV1(raw["root_ref"], raw["root_digest"], raw["plan_digest"],
        raw["total_step_count"], raw["chunk_step_limit"], raw["chunk_count"], tuple(packets), raw["schema"])
    if value.packets[-1].terminal.binding != final_binding:
        raise ValueError("series prefix manifest final installed binding differs")
    return value
