"""Versioned, candidate-only D04 authored initial root contract.

These values preserve latent initial conditions. They are neither FeelingState
readouts nor a numerical/product certificate. D11 must separately authenticate
the author, assets, initial box and graph transaction before adoption.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
import re

from ...graph_types import TypeSpec
from ...runtime_contracts import canonical_digest, canonical_serialize, schema_hash


_HASH = re.compile(r"[0-9a-f]{64}\Z")


def _text(value: object, name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


def _hash(value: object, name: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _number(value: object, name: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    return float(value)


def _fields(payload: object, expected: set[str], name: str) -> dict:
    if type(payload) is not dict or set(payload) != expected:
        raise ValueError(f"{name} fields differ from v1 schema")
    return payload


def _list(value: object, name: str) -> list:
    if type(value) is not list:
        raise ValueError(f"{name} must be a JSON array")
    return value


@dataclass(frozen=True)
class RootAssetBindings:
    scheme_version: str
    operator_version: str
    parameter_version: str
    coupling_version: str
    readout_version: str
    scheme_sha256: str
    operator_sha256: str
    parameter_sha256: str
    coupling_sha256: str
    readout_sha256: str

    def __post_init__(self) -> None:
        for name in ("scheme_version", "operator_version", "parameter_version",
                     "coupling_version", "readout_version"):
            _text(getattr(self, name), name)
        for name in ("scheme_sha256", "operator_sha256", "parameter_sha256",
                     "coupling_sha256", "readout_sha256"):
            _hash(getattr(self, name), name)

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))


@dataclass(frozen=True)
class RootBlockIdentity:
    block_id: str
    kind: str
    object_ref: str | None
    meaning_ref: str | None
    authored_source_id: str

    def __post_init__(self) -> None:
        _text(self.block_id, "block_id")
        _text(self.authored_source_id, "authored_source_id")
        if self.kind == "feeling":
            _text(self.object_ref, "object_ref")
            _text(self.meaning_ref, "meaning_ref")
        elif self.kind == "mood":
            if self.object_ref is not None or self.meaning_ref is not None:
                raise ValueError("mood block has no object or meaning")
        else:
            raise ValueError("root block kind must be feeling or mood")


@dataclass(frozen=True)
class AuthoredRootPreset:
    namespace: tuple[str, str]
    author_id: str
    draft_id: str
    preset_id: str
    assets: RootAssetBindings
    axes: tuple[str, ...]
    blocks: tuple[RootBlockIdentity, ...]
    cursor: float
    historical_source_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.namespace) is not tuple or len(self.namespace) != 2:
            raise ValueError("namespace must bind one bot and persona")
        for item in self.namespace:
            _text(item, "namespace")
        for name in ("author_id", "draft_id", "preset_id"):
            _text(getattr(self, name), name)
        if type(self.assets) is not RootAssetBindings:
            raise ValueError("assets must be exact RootAssetBindings")
        if (type(self.axes) is not tuple or len(self.axes) != 24
                or any(type(axis) is not str or not axis.strip() for axis in self.axes)
                or len(set(self.axes)) != 24):
            raise ValueError("axes must be 24 unique ordered axis IDs")
        if (type(self.blocks) is not tuple or not self.blocks
                or any(type(block) is not RootBlockIdentity for block in self.blocks)):
            raise ValueError("blocks must contain root block identities")
        if len({block.block_id for block in self.blocks}) != len(self.blocks):
            raise ValueError("block IDs must be unique")
        if sum(block.kind == "mood" for block in self.blocks) != 1:
            raise ValueError("root needs exactly one role mood block")
        signatures = [(block.kind, block.object_ref, block.meaning_ref, block.authored_source_id)
                      for block in self.blocks]
        if len(set(signatures)) != len(signatures):
            raise ValueError("object, meaning and source blocks must be distinct")
        object.__setattr__(self, "cursor", _number(self.cursor, "cursor"))
        if self.historical_source_refs != ():
            raise ValueError("historical_source_refs must be empty for an authored root")

    @property
    def digest(self) -> str:
        return canonical_digest(encode_root_preset(self))


@dataclass(frozen=True)
class RootNumericCheckpointCandidate:
    preset_digest: str
    asset_digest: str
    block_id: str
    namespace: tuple[str, str]
    author_id: str
    draft_id: str
    block: RootBlockIdentity
    assets: RootAssetBindings
    axes: tuple[str, ...]
    latent_state: tuple[float, ...]
    ordered_box: tuple[tuple[float, float], ...]
    initial_error_source: str
    initial_error_ref: str
    cursor: float

    def __post_init__(self) -> None:
        _hash(self.preset_digest, "preset_digest")
        _hash(self.asset_digest, "asset_digest")
        _text(self.block_id, "block_id")
        if type(self.namespace) is not tuple or len(self.namespace) != 2:
            raise ValueError("namespace must bind one bot and persona")
        for item in self.namespace:
            _text(item, "namespace")
        _text(self.author_id, "author_id")
        _text(self.draft_id, "draft_id")
        if type(self.block) is not RootBlockIdentity or self.block.block_id != self.block_id:
            raise ValueError("block identity differs from checkpoint block_id")
        if type(self.assets) is not RootAssetBindings or self.assets.digest != self.asset_digest:
            raise ValueError("asset_digest differs from checkpoint assets")
        if (type(self.axes) is not tuple or len(self.axes) != 24
                or any(type(axis) is not str or not axis.strip() for axis in self.axes)
                or len(set(self.axes)) != 24):
            raise ValueError("axes must be 24 unique ordered axis IDs")
        if type(self.latent_state) is not tuple or len(self.latent_state) != 24:
            raise ValueError("latent_state must have 24 coordinates")
        if type(self.ordered_box) is not tuple or len(self.ordered_box) != 24:
            raise ValueError("ordered_box must have 24 intervals")
        values: list[float] = []
        boxes: list[tuple[float, float]] = []
        for index, (value, interval) in enumerate(zip(self.latent_state, self.ordered_box)):
            numeric = _number(value, f"latent_state[{index}]")
            if not 0.0 <= numeric <= 4.0:
                raise ValueError("latent_state must stay in [0, 4]")
            if type(interval) is not tuple or len(interval) != 2:
                raise ValueError("ordered_box entries must be pairs")
            low = _number(interval[0], "ordered_box low")
            high = _number(interval[1], "ordered_box high")
            if not 0.0 <= low <= numeric <= high <= 4.0:
                raise ValueError("ordered_box must contain latent_state within [0, 4]")
            values.append(numeric)
            boxes.append((low, high))
        object.__setattr__(self, "latent_state", tuple(values))
        object.__setattr__(self, "ordered_box", tuple(boxes))
        if self.initial_error_source != "author_declared_box":
            raise ValueError("initial_error_source is a declaration pending trusted verification")
        _text(self.initial_error_ref, "initial_error_ref")
        object.__setattr__(self, "cursor", _number(self.cursor, "cursor"))


@dataclass(frozen=True)
class AuthoredRootCandidate:
    preset: AuthoredRootPreset
    preset_digest: str
    checkpoints: tuple[RootNumericCheckpointCandidate, ...]
    status: str = "candidate"

    def __post_init__(self) -> None:
        if type(self.preset) is not AuthoredRootPreset:
            raise ValueError("preset must be an authored root preset")
        _hash(self.preset_digest, "preset_digest")
        if self.preset_digest != self.preset.digest:
            raise ValueError("preset_digest differs from the exact preset")
        if type(self.checkpoints) is not tuple or any(
                type(item) is not RootNumericCheckpointCandidate for item in self.checkpoints):
            raise ValueError("checkpoints must be root numeric candidates")
        if tuple(item.block_id for item in self.checkpoints) != tuple(
                block.block_id for block in self.preset.blocks):
            raise ValueError("checkpoints must cover each block exactly once in preset order")
        for item, block in zip(self.checkpoints, self.preset.blocks):
            if item.preset_digest != self.preset_digest:
                raise ValueError("checkpoint preset_digest differs from candidate")
            if item.namespace != self.preset.namespace:
                raise ValueError("checkpoint namespace differs from the preset")
            if item.author_id != self.preset.author_id or item.draft_id != self.preset.draft_id:
                raise ValueError("checkpoint author or draft differs from the preset")
            if item.block != block:
                raise ValueError("checkpoint block identity differs from the preset")
            if item.assets != self.preset.assets:
                raise ValueError("checkpoint assets differ from the preset")
            if item.asset_digest != self.preset.assets.digest:
                raise ValueError("checkpoint asset_digest differs from candidate")
            if item.axes != self.preset.axes:
                raise ValueError("checkpoint axes differ from the preset")
            if item.cursor != self.preset.cursor:
                raise ValueError("checkpoint cursor differs from the role cursor")
        if self.status != "candidate":
            raise ValueError("authored root is candidate-only")


def encode_root_preset(value: AuthoredRootPreset) -> dict:
    if type(value) is not AuthoredRootPreset:
        raise TypeError("expected AuthoredRootPreset")
    return json.loads(canonical_serialize({"schema": "d04.authored_root_preset.v1", **asdict(value)}))


def encode_root_checkpoint_candidate(value: RootNumericCheckpointCandidate) -> dict:
    if type(value) is not RootNumericCheckpointCandidate:
        raise TypeError("expected RootNumericCheckpointCandidate")
    return json.loads(canonical_serialize({"schema": "d04.root_numeric_checkpoint_candidate.v1", **asdict(value)}))


def encode_root_candidate(value: AuthoredRootCandidate) -> dict:
    if type(value) is not AuthoredRootCandidate:
        raise TypeError("expected AuthoredRootCandidate")
    return json.loads(canonical_serialize({
        "schema": "d04.authored_root_candidate.v1", "preset": encode_root_preset(value.preset),
        "preset_digest": value.preset_digest,
        "checkpoints": [encode_root_checkpoint_candidate(item) for item in value.checkpoints],
        "status": value.status,
    }))


def decode_root_preset(payload: object) -> AuthoredRootPreset:
    value = _fields(payload, {"schema", "namespace", "author_id", "draft_id", "preset_id",
                              "assets", "axes", "blocks", "cursor", "historical_source_refs"}, "preset")
    if value["schema"] != "d04.authored_root_preset.v1":
        raise ValueError("unsupported authored root preset schema")
    assets = _fields(value["assets"], set(RootAssetBindings.__dataclass_fields__), "assets")
    blocks = tuple(RootBlockIdentity(**_fields(item, set(RootBlockIdentity.__dataclass_fields__), "block"))
                   for item in _list(value["blocks"], "blocks"))
    return AuthoredRootPreset(
        namespace=tuple(_list(value["namespace"], "namespace")), author_id=value["author_id"],
        draft_id=value["draft_id"], preset_id=value["preset_id"],
        assets=RootAssetBindings(**assets), axes=tuple(_list(value["axes"], "axes")),
        blocks=blocks, cursor=value["cursor"],
        historical_source_refs=tuple(_list(value["historical_source_refs"], "historical_source_refs")),
    )


def decode_root_checkpoint_candidate(payload: object) -> RootNumericCheckpointCandidate:
    value = _fields(payload, {"schema", *RootNumericCheckpointCandidate.__dataclass_fields__}, "checkpoint")
    if value["schema"] != "d04.root_numeric_checkpoint_candidate.v1":
        raise ValueError("unsupported numeric checkpoint candidate schema")
    return RootNumericCheckpointCandidate(
        preset_digest=value["preset_digest"], asset_digest=value["asset_digest"],
        block_id=value["block_id"], namespace=tuple(_list(value["namespace"], "namespace")),
        author_id=value["author_id"], draft_id=value["draft_id"],
        block=RootBlockIdentity(**_fields(value["block"], set(RootBlockIdentity.__dataclass_fields__), "block")),
        assets=RootAssetBindings(**_fields(value["assets"], set(RootAssetBindings.__dataclass_fields__), "assets")),
        axes=tuple(_list(value["axes"], "axes")),
        latent_state=tuple(_list(value["latent_state"], "latent_state")),
        ordered_box=tuple(tuple(_list(item, "ordered_box interval")) for item in
                          _list(value["ordered_box"], "ordered_box")),
        initial_error_source=value["initial_error_source"],
        initial_error_ref=value["initial_error_ref"], cursor=value["cursor"],
    )


def decode_root_candidate(payload: object) -> AuthoredRootCandidate:
    value = _fields(payload, {"schema", "preset", "preset_digest", "checkpoints", "status"}, "candidate")
    if value["schema"] != "d04.authored_root_candidate.v1":
        raise ValueError("unsupported authored root candidate schema")
    return AuthoredRootCandidate(
        preset=decode_root_preset(value["preset"]), preset_digest=value["preset_digest"],
        checkpoints=tuple(decode_root_checkpoint_candidate(item) for item in
                          _list(value["checkpoints"], "checkpoints")),
        status=value["status"],
    )


def root_type_specs() -> tuple[TypeSpec, ...]:
    """Register graph-visible candidate records, never an adopted checkpoint."""
    definitions = (
        ("d04.authored_root_preset.v1", decode_root_preset),
        ("d04.authored_root_candidate.v1", decode_root_candidate),
        ("d04.root_numeric_checkpoint_candidate.v1", decode_root_checkpoint_candidate),
    )
    return tuple(TypeSpec(
        name=name, owner_kinds=("persona",), storage_role="projection", validator=decoder,
        immutable=True, writer_domain="d04", schema_hash=schema_hash({
            "type": name, "version": 1, "writer_domain": "d04", "candidate_only": True,
        }),
    ) for name, decoder in definitions)
