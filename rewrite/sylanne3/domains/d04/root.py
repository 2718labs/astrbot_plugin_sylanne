"""Versioned D04 authored root candidates and committed numeric checkpoint.

The shipped preset is reusable across roles; each candidate owns its selection
and latent initial conditions. Candidates are neither FeelingState readouts nor
numerical/product certificates. D11 must separately authenticate the author,
installed assets, initial box and graph transaction before adoption.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
import re

from ...graph_types import TypeSpec
from ...runtime_contracts import canonical_digest, canonical_serialize, schema_hash
from ...graph_types import AtomKey
from .encoding_baseline import CommittedRef


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
class RootBlockTemplate:
    template_id: str
    kind: str
    initial_rule: str

    def __post_init__(self) -> None:
        _text(self.template_id, "template_id")
        if self.kind not in {"feeling", "mood"}:
            raise ValueError("root block template kind must be feeling or mood")
        if self.initial_rule != "author_supplied_box":
            raise ValueError("unsupported authored root initial rule")


@dataclass(frozen=True)
class RootBlockIdentity:
    block_id: str
    template_id: str
    kind: str
    object_ref: str | None
    meaning_ref: str | None
    authored_source_id: str

    def __post_init__(self) -> None:
        _text(self.block_id, "block_id")
        _text(self.template_id, "template_id")
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
    preset_id: str
    preset_version: str
    assets: RootAssetBindings
    axes: tuple[str, ...]
    block_templates: tuple[RootBlockTemplate, ...]

    def __post_init__(self) -> None:
        for name in ("preset_id", "preset_version"):
            _text(getattr(self, name), name)
        if type(self.assets) is not RootAssetBindings:
            raise ValueError("assets must be exact RootAssetBindings")
        if (type(self.axes) is not tuple or len(self.axes) != 24
                or any(type(axis) is not str or not axis.strip() for axis in self.axes)
                or len(set(self.axes)) != 24):
            raise ValueError("axes must be 24 unique ordered axis IDs")
        if (type(self.block_templates) is not tuple or not self.block_templates
                or any(type(item) is not RootBlockTemplate for item in self.block_templates)):
            raise ValueError("block_templates must contain root block templates")
        if len({item.template_id for item in self.block_templates}) != len(self.block_templates):
            raise ValueError("block template IDs must be unique")
        if sum(item.kind == "mood" for item in self.block_templates) != 1:
            raise ValueError("preset needs exactly one role mood template")

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
class NumericCheckpoint:
    """Graph value after D11 adoption; constructing it grants no write authority.

    A root has no predecessor. Later advances/revisions bind the exact receipt
    of the preceding committed operation. The issuer and coordinator must verify
    all certificate, receipt, and graph claims before committing this value.
    """

    checkpoint_id: str
    namespace: tuple[str, str]
    block: RootBlockIdentity
    assets: RootAssetBindings
    asset_digest: str
    axes: tuple[str, ...]
    latent_state: tuple[float, ...]
    certified_box: tuple[tuple[float, float], ...]
    numeric_error_bound: float
    certificate_source: str
    certificate_digest: str
    cursor: float
    graph_state: CommittedRef
    readout_proof_digest: str
    commit_operation_id: str
    predecessor_kind: str
    predecessor_receipt_digest: str | None

    def __post_init__(self) -> None:
        _text(self.checkpoint_id, "checkpoint_id")
        if type(self.namespace) is not tuple or len(self.namespace) != 2:
            raise ValueError("namespace must bind one bot and persona")
        for item in self.namespace:
            _text(item, "namespace")
        if type(self.block) is not RootBlockIdentity:
            raise ValueError("block must be an exact RootBlockIdentity")
        if type(self.assets) is not RootAssetBindings:
            raise ValueError("assets must be exact RootAssetBindings")
        _hash(self.asset_digest, "asset_digest")
        if self.asset_digest != self.assets.digest:
            raise ValueError("asset_digest differs from checkpoint assets")
        if (type(self.axes) is not tuple or len(self.axes) != 24
                or any(type(axis) is not str or not axis.strip() for axis in self.axes)
                or len(set(self.axes)) != 24):
            raise ValueError("axes must be 24 unique ordered axis IDs")
        if type(self.latent_state) is not tuple or len(self.latent_state) != 24:
            raise ValueError("latent_state must have 24 coordinates")
        if type(self.certified_box) is not tuple or len(self.certified_box) != 24:
            raise ValueError("certified_box must have 24 intervals")
        state: list[float] = []
        boxes: list[tuple[float, float]] = []
        for index, (value, interval) in enumerate(zip(self.latent_state, self.certified_box)):
            numeric = _number(value, f"latent_state[{index}]")
            if not 0.0 <= numeric <= 4.0:
                raise ValueError("latent_state must stay in [0, 4]")
            if type(interval) is not tuple or len(interval) != 2:
                raise ValueError("certified_box entries must be pairs")
            low = _number(interval[0], "certified_box low")
            high = _number(interval[1], "certified_box high")
            if not 0.0 <= low <= numeric <= high <= 4.0:
                raise ValueError("certified_box must contain latent_state within [0, 4]")
            state.append(numeric)
            boxes.append((low, high))
        error = _number(self.numeric_error_bound, "numeric_error_bound")
        if error < 0 or any(max(value - low, high - value) > error
                            for value, (low, high) in zip(state, boxes)):
            raise ValueError("numeric_error_bound must cover certified_box")
        object.__setattr__(self, "latent_state", tuple(state))
        object.__setattr__(self, "certified_box", tuple(boxes))
        object.__setattr__(self, "numeric_error_bound", error)
        if self.certificate_source not in {"trusted_initial_box", "trusted_abi2"}:
            raise ValueError("certificate_source must identify a trusted verifier")
        _hash(self.certificate_digest, "certificate_digest")
        object.__setattr__(self, "cursor", _number(self.cursor, "cursor"))
        if type(self.graph_state) is not CommittedRef:
            raise ValueError("graph_state must be an exact CommittedRef")
        key = AtomKey.from_token(self.graph_state.ref)
        expected_type = ("d04.feeling_state.v1" if self.block.kind == "feeling"
                         else "d04.mood_field.v1")
        if (key.type_name != expected_type or key.owner.kind != "persona"
                or (key.owner.bot, key.owner.persona) != self.namespace
                or key.name != self.block.block_id):
            raise ValueError("graph_state differs from checkpoint block or namespace")
        _hash(self.readout_proof_digest, "readout_proof_digest")
        _text(self.commit_operation_id, "commit_operation_id")
        if self.predecessor_kind == "none":
            if self.predecessor_receipt_digest is not None or self.certificate_source != "trusted_initial_box":
                raise ValueError("root checkpoint must have no predecessor and an initial box")
        elif self.predecessor_kind in {"root", "advance", "revision"}:
            _hash(self.predecessor_receipt_digest, "predecessor_receipt_digest")
            if self.certificate_source != "trusted_abi2":
                raise ValueError("successor checkpoint requires trusted_abi2")
        else:
            raise ValueError("unsupported predecessor_kind")


@dataclass(frozen=True)
class AuthoredRootCandidate:
    preset: AuthoredRootPreset
    preset_digest: str
    candidate_id: str
    namespace: tuple[str, str]
    author_id: str
    draft_id: str
    cursor: float
    blocks: tuple[RootBlockIdentity, ...]
    historical_source_refs: tuple[str, ...]
    checkpoints: tuple[RootNumericCheckpointCandidate, ...]
    status: str = "candidate"

    def __post_init__(self) -> None:
        if type(self.preset) is not AuthoredRootPreset:
            raise ValueError("preset must be an authored root preset")
        _hash(self.preset_digest, "preset_digest")
        if self.preset_digest != self.preset.digest:
            raise ValueError("preset_digest differs from the exact preset")
        _text(self.candidate_id, "candidate_id")
        if type(self.namespace) is not tuple or len(self.namespace) != 2:
            raise ValueError("namespace must bind one bot and persona")
        for item in self.namespace:
            _text(item, "namespace")
        _text(self.author_id, "author_id")
        _text(self.draft_id, "draft_id")
        object.__setattr__(self, "cursor", _number(self.cursor, "cursor"))
        if self.historical_source_refs != ():
            raise ValueError("historical_source_refs must be empty for an authored root")
        if (type(self.blocks) is not tuple or not self.blocks
                or any(type(block) is not RootBlockIdentity for block in self.blocks)):
            raise ValueError("blocks must contain root block identities")
        if len({block.block_id for block in self.blocks}) != len(self.blocks):
            raise ValueError("block IDs must be unique")
        if sum(block.kind == "mood" for block in self.blocks) != 1:
            raise ValueError("candidate needs exactly one role mood block")
        signatures = [(block.kind, block.object_ref, block.meaning_ref, block.authored_source_id)
                      for block in self.blocks]
        if len(set(signatures)) != len(signatures):
            raise ValueError("object, meaning and source blocks must be distinct")
        templates = {item.template_id: item for item in self.preset.block_templates}
        for block in self.blocks:
            template = templates.get(block.template_id)
            if template is None or template.kind != block.kind:
                raise ValueError("block template does not match the shipped preset")
        if type(self.checkpoints) is not tuple or any(
                type(item) is not RootNumericCheckpointCandidate for item in self.checkpoints):
            raise ValueError("checkpoints must be root numeric candidates")
        if tuple(item.block_id for item in self.checkpoints) != tuple(
                block.block_id for block in self.blocks):
            raise ValueError("checkpoints must cover each block exactly once in candidate order")
        for item, block in zip(self.checkpoints, self.blocks):
            if item.preset_digest != self.preset_digest:
                raise ValueError("checkpoint preset_digest differs from candidate")
            if item.namespace != self.namespace:
                raise ValueError("checkpoint namespace differs from the candidate")
            if item.author_id != self.author_id or item.draft_id != self.draft_id:
                raise ValueError("checkpoint author or draft differs from the candidate")
            if item.block != block:
                raise ValueError("checkpoint block identity differs from the candidate")
            if item.assets != self.preset.assets:
                raise ValueError("checkpoint assets differ from the preset")
            if item.asset_digest != self.preset.assets.digest:
                raise ValueError("checkpoint asset_digest differs from candidate")
            if item.axes != self.preset.axes:
                raise ValueError("checkpoint axes differ from the preset")
            if item.cursor != self.cursor:
                raise ValueError("checkpoint cursor differs from the role cursor")
        if self.status != "candidate":
            raise ValueError("authored root is candidate-only")

    @property
    def digest(self) -> str:
        return canonical_digest(encode_root_candidate(self))


@dataclass(frozen=True)
class AuthoredRootBlockInput:
    """One explicit authored 24D initial condition and its declared box."""

    identity: RootBlockIdentity
    axes: tuple[str, ...]
    latent_state: tuple[float, ...]
    ordered_box: tuple[tuple[float, float], ...]
    initial_error_ref: str


@dataclass(frozen=True)
class AuthoredRootInput:
    """Role selection of exact preset bytes and per-block authored values."""

    candidate_id: str
    namespace: tuple[str, str]
    author_id: str
    draft_id: str
    cursor: float
    preset_digest: str
    asset_digest: str
    blocks: tuple[AuthoredRootBlockInput, ...]


def compile_authored_root_candidate(
    preset: AuthoredRootPreset,
    selection: AuthoredRootInput,
) -> AuthoredRootCandidate:
    """Compile a pure candidate; authentication and numeric admission remain external.

    The selected digests bind the supplied preset and asset references. Each
    block supplies a latent state and box; no readout or historical event is
    inferred. The initial box remains an author declaration until D11 verifies
    it with the trusted native initial-box contract.
    """
    if type(preset) is not AuthoredRootPreset or type(selection) is not AuthoredRootInput:
        raise TypeError("expected an authored root preset and role input")
    if selection.preset_digest != preset.digest:
        raise ValueError("preset_digest differs from selected preset")
    if selection.asset_digest != preset.assets.digest:
        raise ValueError("asset_digest differs from selected preset assets")
    if (type(selection.blocks) is not tuple or not selection.blocks
            or any(type(block) is not AuthoredRootBlockInput for block in selection.blocks)):
        raise ValueError("blocks must be explicit authored root block inputs")
    checkpoints = tuple(
        RootNumericCheckpointCandidate(
            preset_digest=selection.preset_digest,
            asset_digest=selection.asset_digest,
            block_id=item.identity.block_id,
            namespace=selection.namespace,
            author_id=selection.author_id,
            draft_id=selection.draft_id,
            block=item.identity,
            assets=preset.assets,
            axes=item.axes,
            latent_state=item.latent_state,
            ordered_box=item.ordered_box,
            initial_error_source="author_declared_box",
            initial_error_ref=item.initial_error_ref,
            cursor=selection.cursor,
        ) for item in selection.blocks
    )
    return AuthoredRootCandidate(
        preset=preset,
        preset_digest=selection.preset_digest,
        candidate_id=selection.candidate_id,
        namespace=selection.namespace,
        author_id=selection.author_id,
        draft_id=selection.draft_id,
        cursor=selection.cursor,
        blocks=tuple(item.identity for item in selection.blocks),
        historical_source_refs=(),
        checkpoints=checkpoints,
    )


def encode_root_preset(value: AuthoredRootPreset) -> dict:
    if type(value) is not AuthoredRootPreset:
        raise TypeError("expected AuthoredRootPreset")
    return json.loads(canonical_serialize({"schema": "d04.authored_root_preset.v1", **asdict(value)}))


def encode_root_checkpoint_candidate(value: RootNumericCheckpointCandidate) -> dict:
    if type(value) is not RootNumericCheckpointCandidate:
        raise TypeError("expected RootNumericCheckpointCandidate")
    return json.loads(canonical_serialize({"schema": "d04.root_numeric_checkpoint_candidate.v1", **asdict(value)}))


def encode_numeric_checkpoint(value: NumericCheckpoint) -> dict:
    if type(value) is not NumericCheckpoint:
        raise TypeError("expected NumericCheckpoint")
    return json.loads(canonical_serialize({"schema": "d04.numeric_checkpoint.v1", **asdict(value)}))


def encode_root_candidate(value: AuthoredRootCandidate) -> dict:
    if type(value) is not AuthoredRootCandidate:
        raise TypeError("expected AuthoredRootCandidate")
    return json.loads(canonical_serialize({
        "schema": "d04.authored_root_candidate.v1", "preset": encode_root_preset(value.preset),
        "preset_digest": value.preset_digest,
        "candidate_id": value.candidate_id, "namespace": value.namespace,
        "author_id": value.author_id, "draft_id": value.draft_id,
        "cursor": value.cursor, "blocks": [asdict(item) for item in value.blocks],
        "historical_source_refs": value.historical_source_refs,
        "checkpoints": [encode_root_checkpoint_candidate(item) for item in value.checkpoints],
        "status": value.status,
    }))


def decode_root_preset(payload: object) -> AuthoredRootPreset:
    value = _fields(payload, {"schema", "preset_id", "preset_version", "assets",
                              "axes", "block_templates"}, "preset")
    if value["schema"] != "d04.authored_root_preset.v1":
        raise ValueError("unsupported authored root preset schema")
    assets = _fields(value["assets"], set(RootAssetBindings.__dataclass_fields__), "assets")
    templates = tuple(RootBlockTemplate(**_fields(item, set(RootBlockTemplate.__dataclass_fields__), "template"))
                      for item in _list(value["block_templates"], "block_templates"))
    return AuthoredRootPreset(
        preset_id=value["preset_id"], preset_version=value["preset_version"],
        assets=RootAssetBindings(**assets), axes=tuple(_list(value["axes"], "axes")),
        block_templates=templates,
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


def decode_numeric_checkpoint(payload: object) -> NumericCheckpoint:
    value = _fields(payload, {"schema", *NumericCheckpoint.__dataclass_fields__}, "numeric checkpoint")
    if value["schema"] != "d04.numeric_checkpoint.v1":
        raise ValueError("unsupported numeric checkpoint schema")
    return NumericCheckpoint(
        checkpoint_id=value["checkpoint_id"],
        namespace=tuple(_list(value["namespace"], "namespace")),
        block=RootBlockIdentity(**_fields(value["block"], set(RootBlockIdentity.__dataclass_fields__), "block")),
        assets=RootAssetBindings(**_fields(value["assets"], set(RootAssetBindings.__dataclass_fields__), "assets")),
        asset_digest=value["asset_digest"], axes=tuple(_list(value["axes"], "axes")),
        latent_state=tuple(_list(value["latent_state"], "latent_state")),
        certified_box=tuple(tuple(_list(item, "certified_box interval")) for item in
                            _list(value["certified_box"], "certified_box")),
        numeric_error_bound=value["numeric_error_bound"],
        certificate_source=value["certificate_source"],
        certificate_digest=value["certificate_digest"], cursor=value["cursor"],
        graph_state=CommittedRef(**_fields(value["graph_state"], set(CommittedRef.__dataclass_fields__),
                                           "graph_state")),
        readout_proof_digest=value["readout_proof_digest"],
        commit_operation_id=value["commit_operation_id"],
        predecessor_kind=value["predecessor_kind"],
        predecessor_receipt_digest=value["predecessor_receipt_digest"],
    )


def decode_root_candidate(payload: object) -> AuthoredRootCandidate:
    value = _fields(payload, {"schema", "preset", "preset_digest", "candidate_id",
                              "namespace", "author_id", "draft_id", "cursor", "blocks",
                              "historical_source_refs", "checkpoints", "status"}, "candidate")
    if value["schema"] != "d04.authored_root_candidate.v1":
        raise ValueError("unsupported authored root candidate schema")
    return AuthoredRootCandidate(
        preset=decode_root_preset(value["preset"]), preset_digest=value["preset_digest"],
        candidate_id=value["candidate_id"], namespace=tuple(_list(value["namespace"], "namespace")),
        author_id=value["author_id"], draft_id=value["draft_id"], cursor=value["cursor"],
        blocks=tuple(RootBlockIdentity(**_fields(item, set(RootBlockIdentity.__dataclass_fields__), "block"))
                     for item in _list(value["blocks"], "blocks")),
        historical_source_refs=tuple(_list(value["historical_source_refs"], "historical_source_refs")),
        checkpoints=tuple(decode_root_checkpoint_candidate(item) for item in
                          _list(value["checkpoints"], "checkpoints")),
        status=value["status"],
    )


def root_type_specs() -> tuple[TypeSpec, ...]:
    """Register distinct candidate and committed checkpoint graph surfaces."""
    definitions = (
        ("d04.authored_root_preset.v1", decode_root_preset, AuthoredRootPreset),
        ("d04.authored_root_candidate.v1", decode_root_candidate, AuthoredRootCandidate),
        ("d04.root_numeric_checkpoint_candidate.v1", decode_root_checkpoint_candidate,
         RootNumericCheckpointCandidate),
    )
    candidates = tuple(TypeSpec(
        name=name, owner_kinds=("persona",), storage_role="projection", validator=decoder,
        immutable=True, writer_domain="d04", schema_hash=schema_hash({
            "type": name, "version": 1, "writer_domain": "d04", "candidate_only": True,
            "fields": tuple(dto.__dataclass_fields__),
            "asset_fields": tuple(RootAssetBindings.__dataclass_fields__),
            "template_fields": tuple(RootBlockTemplate.__dataclass_fields__),
            "block_fields": tuple(RootBlockIdentity.__dataclass_fields__),
        }),
    ) for name, decoder, dto in definitions)
    return candidates + (TypeSpec(
        name="d04.numeric_checkpoint.v1", owner_kinds=("persona",), storage_role="state",
        validator=decode_numeric_checkpoint, immutable=False, writer_domain="d04",
        schema_hash=schema_hash({
            "type": "d04.numeric_checkpoint.v1", "version": 1, "writer_domain": "d04",
            "fields": tuple(NumericCheckpoint.__dataclass_fields__),
            "asset_fields": tuple(RootAssetBindings.__dataclass_fields__),
            "block_fields": tuple(RootBlockIdentity.__dataclass_fields__),
            "graph_version_fields": tuple(CommittedRef.__dataclass_fields__),
        }),
    ),)
