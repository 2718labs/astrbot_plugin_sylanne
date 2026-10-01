"""Blank authored D04 root lineage and conditional exact initial writes.

These values contain no event, D06 source, D07 interpretation, or adoption
authority. W01 must authenticate the Owner and installed assets and replay the
ABI2 initial-box proof before committing the returned writes atomically.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
import re

from ...graph_types import AtomKey, Owner, TypeSpec
from ...native_runtime.initial_box_trajectory import _box_digest, _native_initial_radius
from ...native_runtime.loader import ABI2NativeLibrary, NativeLoadBinding
from ...native_runtime.d04_tanh_readout_asset import D04LoadedTanhReadoutAsset
from ...native_runtime.tanh_asset_readout import run_d04_conditional_tanh_readout_math
from ...runtime_contracts import canonical_digest, canonical_serialize, schema_hash
from .encoding_baseline import CommittedRef
from .joint_state_output_v1 import JointStateAxisOutputV1, JointStateOutputPolicyV1, _axis_output
from .numeric_coupling import REGISTERED_AXIS_IDS
from .root import AuthoredRootPreset, RootAssetBindings
from .root_projection_v2 import _covers_box, _identity_asset


_SHA = re.compile(r"[0-9a-f]{64}\Z")
FEELING_TYPE = "d04.authored_feeling_state.v1"
MOOD_TYPE = "d04.authored_mood_state.v1"
CHECKPOINT_TYPE = "d04.numeric_checkpoint.v2"


def _text(value: object, label: str) -> None:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{label} must be nonempty")


def _sha(value: object, label: str) -> None:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise ValueError(f"{label} must be a SHA-256 digest")


def _finite(value: object, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{label} must be finite")
    return float(value)


def _exact(value: object, names: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != names:
        raise ValueError(f"{label} fields differ")
    return value


def _array(value: object, label: str) -> list:
    if type(value) is not list:
        raise ValueError(f"{label} must be an array")
    return value


def _namespace(value: object) -> None:
    if type(value) is not tuple or len(value) != 2:
        raise ValueError("namespace must be an exact pair")
    for item in value:
        _text(item, "namespace item")


def _axes(values: object) -> None:
    if type(values) is not tuple or values != REGISTERED_AXIS_IDS:
        raise ValueError("authored root requires exact ordered 24 axes")


def _box(values: object, boxes: object) -> None:
    if type(values) is not tuple or len(values) != 24 or type(boxes) is not tuple or len(boxes) != 24:
        raise ValueError("latent values and box need 24 axes")
    for center, interval in zip(values, boxes):
        if type(interval) is not tuple or len(interval) != 2:
            raise ValueError("box entry must be an exact pair")
        c, low, high = (_finite(center, "center"), _finite(interval[0], "lower"),
                        _finite(interval[1], "upper"))
        if not 0 <= low <= c <= high <= 4:
            raise ValueError("authored latent box leaves [0, 4]")


@dataclass(frozen=True, slots=True)
class RootAuthoredFacetV3:
    block_id: str
    template_id: str
    kind: str
    facet_id: str
    object_ref: None = None
    meaning_ref: None = None

    def __post_init__(self) -> None:
        for name in ("block_id", "template_id", "facet_id"):
            _text(getattr(self, name), name)
        if self.kind not in {"feeling", "mood"} or self.object_ref is not None or self.meaning_ref is not None:
            raise ValueError("blank authored facet cannot claim a graph object or meaning")


@dataclass(frozen=True, slots=True)
class AuthoredRootBlockInputV3:
    facet: RootAuthoredFacetV3
    axes: tuple[str, ...]
    latent_state: tuple[float, ...]
    ordered_box: tuple[tuple[float, float], ...]
    initial_error_ref: str

    def __post_init__(self) -> None:
        if type(self.facet) is not RootAuthoredFacetV3:
            raise TypeError("facet must be RootAuthoredFacetV3")
        _axes(self.axes)
        _box(self.latent_state, self.ordered_box)
        _text(self.initial_error_ref, "initial_error_ref")


@dataclass(frozen=True, slots=True)
class AuthoredRootInputV3:
    candidate_id: str
    namespace: tuple[str, str]
    author_id: str
    draft_id: str
    cursor: float
    preset_digest: str
    asset_digest: str
    blocks: tuple[AuthoredRootBlockInputV3, ...]

    def __post_init__(self) -> None:
        for name in ("candidate_id", "author_id", "draft_id"):
            _text(getattr(self, name), name)
        _namespace(self.namespace)
        _finite(self.cursor, "cursor")
        _sha(self.preset_digest, "preset_digest")
        _sha(self.asset_digest, "asset_digest")
        if type(self.blocks) is not tuple or len(self.blocks) < 3 or any(
                type(item) is not AuthoredRootBlockInputV3 for item in self.blocks):
            raise ValueError("root requires at least two authored Feeling blocks and Mood")


def encode_authored_root_input_v3(value: AuthoredRootInputV3) -> dict:
    return _encode(value, "d04.authored_root_input.v3", AuthoredRootInputV3)


def decode_authored_root_input_v3(value: object) -> AuthoredRootInputV3:
    raw = _exact(value, {"schema", *AuthoredRootInputV3.__dataclass_fields__}, "root input")
    if raw["schema"] != "d04.authored_root_input.v3":
        raise ValueError("authored root input schema differs")
    blocks = []
    for item in _array(raw["blocks"], "blocks"):
        fields = _exact(item, set(AuthoredRootBlockInputV3.__dataclass_fields__), "block input")
        blocks.append(AuthoredRootBlockInputV3(
            RootAuthoredFacetV3(**_exact(fields["facet"], set(RootAuthoredFacetV3.__dataclass_fields__), "facet")),
            tuple(_array(fields["axes"], "axes")),
            tuple(_array(fields["latent_state"], "latent_state")),
            tuple(tuple(_array(box, "box")) for box in _array(fields["ordered_box"], "ordered_box")),
            fields["initial_error_ref"],
        ))
    result = AuthoredRootInputV3(
        raw["candidate_id"], tuple(_array(raw["namespace"], "namespace")),
        raw["author_id"], raw["draft_id"], raw["cursor"],
        raw["preset_digest"], raw["asset_digest"], tuple(blocks),
    )
    if encode_authored_root_input_v3(result) != raw:
        raise ValueError("authored root input canonical round trip differs")
    return result


@dataclass(frozen=True, slots=True)
class RootCheckpointCandidateV3:
    block: RootAuthoredFacetV3
    namespace: tuple[str, str]
    author_id: str
    draft_id: str
    preset_digest: str
    asset_digest: str
    axes: tuple[str, ...]
    latent_state: tuple[float, ...]
    ordered_box: tuple[tuple[float, float], ...]
    initial_error_ref: str
    cursor: float

    def __post_init__(self) -> None:
        if type(self.block) is not RootAuthoredFacetV3:
            raise TypeError("checkpoint block must be authored facet")
        _namespace(self.namespace)
        for name in ("author_id", "draft_id", "initial_error_ref"):
            _text(getattr(self, name), name)
        for name in ("preset_digest", "asset_digest"):
            _sha(getattr(self, name), name)
        _axes(self.axes)
        _box(self.latent_state, self.ordered_box)
        _finite(self.cursor, "cursor")


@dataclass(frozen=True, slots=True)
class AuthoredRootCandidateV3:
    preset: AuthoredRootPreset
    candidate_id: str
    namespace: tuple[str, str]
    author_id: str
    draft_id: str
    cursor: float
    blocks: tuple[RootAuthoredFacetV3, ...]
    checkpoints: tuple[RootCheckpointCandidateV3, ...]
    historical_source_refs: tuple[()] = ()
    status: str = "candidate_hold_for_w01_v3_adoption"

    def __post_init__(self) -> None:
        if type(self.preset) is not AuthoredRootPreset:
            raise TypeError("preset must be exact AuthoredRootPreset")
        _text(self.candidate_id, "candidate_id")
        _namespace(self.namespace)
        for name in ("author_id", "draft_id"):
            _text(getattr(self, name), name)
        _finite(self.cursor, "cursor")
        if self.historical_source_refs != () or self.status != "candidate_hold_for_w01_v3_adoption":
            raise ValueError("authored root cannot claim historical source or adoption")
        if (self.blocks != tuple(item.block for item in self.checkpoints)
                or len(self.blocks) < 3
                or len({item.block_id for item in self.blocks}) != len(self.blocks)
                or len({item.facet_id for item in self.blocks}) != len(self.blocks)
                or sum(item.kind == "mood" for item in self.blocks) != 1
                or sum(item.kind == "feeling" for item in self.blocks) < 2):
            raise ValueError("authored root block closure differs")
        templates = {item.template_id: item.kind for item in self.preset.block_templates}
        if any(templates.get(block.template_id) != block.kind for block in self.blocks):
            raise ValueError("authored facet differs from preset template")
        for item in self.checkpoints:
            if (item.namespace != self.namespace or item.author_id != self.author_id
                    or item.draft_id != self.draft_id or item.preset_digest != self.preset.digest
                    or item.asset_digest != self.preset.assets.digest
                    or item.axes != self.preset.axes or item.cursor != self.cursor):
                raise ValueError("candidate checkpoint differs from root selection")

    @property
    def digest(self) -> str:
        return canonical_digest(encode_authored_root_candidate_v3(self))


def compile_authored_root_candidate_v3(
    preset: AuthoredRootPreset, selection: AuthoredRootInputV3,
) -> AuthoredRootCandidateV3:
    if type(preset) is not AuthoredRootPreset or type(selection) is not AuthoredRootInputV3:
        raise TypeError("expected preset and authored V3 input")
    if selection.preset_digest != preset.digest or selection.asset_digest != preset.assets.digest:
        raise ValueError("authored selection differs from installed preset")
    checkpoints = tuple(RootCheckpointCandidateV3(
        item.facet, selection.namespace, selection.author_id, selection.draft_id,
        selection.preset_digest, selection.asset_digest, item.axes,
        item.latent_state, item.ordered_box, item.initial_error_ref,
        selection.cursor,
    ) for item in selection.blocks)
    return AuthoredRootCandidateV3(
        preset, selection.candidate_id, selection.namespace, selection.author_id,
        selection.draft_id, selection.cursor,
        tuple(item.facet for item in selection.blocks), checkpoints,
    )


def encode_authored_root_candidate_v3(value: AuthoredRootCandidateV3) -> dict:
    if type(value) is not AuthoredRootCandidateV3:
        raise TypeError("expected AuthoredRootCandidateV3")
    from .root import encode_root_preset

    return json.loads(canonical_serialize({
        "schema": "d04.authored_root_candidate.v3",
        **{name: item for name, item in asdict(value).items() if name != "preset"},
        "preset": encode_root_preset(value.preset),
    }))


def decode_authored_root_candidate_v3(value: object) -> AuthoredRootCandidateV3:
    raw = _exact(value, {"schema", *AuthoredRootCandidateV3.__dataclass_fields__}, "candidate")
    if raw["schema"] != "d04.authored_root_candidate.v3":
        raise ValueError("authored root candidate schema differs")
    from .root import decode_root_preset

    preset = decode_root_preset(raw["preset"])
    blocks = tuple(RootAuthoredFacetV3(**_exact(item, set(RootAuthoredFacetV3.__dataclass_fields__), "facet"))
                   for item in _array(raw["blocks"], "blocks"))
    checkpoints = []
    for item in _array(raw["checkpoints"], "checkpoints"):
        fields = _exact(item, set(RootCheckpointCandidateV3.__dataclass_fields__), "checkpoint")
        checkpoints.append(RootCheckpointCandidateV3(
            block=RootAuthoredFacetV3(**_exact(fields["block"], set(RootAuthoredFacetV3.__dataclass_fields__), "facet")),
            namespace=tuple(_array(fields["namespace"], "namespace")),
            author_id=fields["author_id"], draft_id=fields["draft_id"],
            preset_digest=fields["preset_digest"], asset_digest=fields["asset_digest"],
            axes=tuple(_array(fields["axes"], "axes")),
            latent_state=tuple(_array(fields["latent_state"], "latent_state")),
            ordered_box=tuple(tuple(_array(box, "box")) for box in _array(fields["ordered_box"], "ordered_box")),
            initial_error_ref=fields["initial_error_ref"], cursor=fields["cursor"],
        ))
    candidate = AuthoredRootCandidateV3(
        preset, raw["candidate_id"], tuple(_array(raw["namespace"], "namespace")),
        raw["author_id"], raw["draft_id"], raw["cursor"], blocks,
        tuple(checkpoints), tuple(_array(raw["historical_source_refs"], "historical_source_refs")),
        raw["status"],
    )
    if encode_authored_root_candidate_v3(candidate) != raw:
        raise ValueError("candidate canonical round trip differs")
    return candidate


@dataclass(frozen=True, slots=True)
class AuthoredFeelingStateV1:
    block_id: str
    facet_id: str
    root_operation_id: str
    root_candidate_digest: str
    owner_draft_id: str
    preset_digest: str
    asset_digest: str
    basis_version: str
    operator_version: str
    parameter_version: str
    coupling_version: str
    coordinates: tuple[tuple[str, float], ...]
    readout_proof_digest: str
    cursor: float
    revision: int = 1
    interpretation_refs: tuple[str, ...] = ()
    historical_source_refs: tuple[str, ...] = ()
    active_driver_refs: tuple[str, ...] = ()
    status: str = "authored_initial_parameter_not_observation"

    def __post_init__(self) -> None:
        _state(self, feeling=True)


@dataclass(frozen=True, slots=True)
class AuthoredMoodStateV1:
    block_id: str
    facet_id: str
    root_operation_id: str
    root_candidate_digest: str
    owner_draft_id: str
    preset_digest: str
    asset_digest: str
    basis_version: str
    parameter_version: str
    coupling_version: str
    coordinates: tuple[tuple[str, float], ...]
    readout_proof_digest: str
    cursor: float
    revision: int = 1
    source_refs: tuple[str, ...] = ()
    active_driver_refs: tuple[str, ...] = ()
    status: str = "authored_initial_parameter_not_observation"

    def __post_init__(self) -> None:
        _state(self, feeling=False)


def _state(value: AuthoredFeelingStateV1 | AuthoredMoodStateV1, *, feeling: bool) -> None:
    for name in ("block_id", "facet_id", "root_operation_id", "owner_draft_id", "basis_version",
                 "parameter_version", "coupling_version"):
        _text(getattr(value, name), name)
    if feeling:
        _text(value.operator_version, "operator_version")
    for name in ("root_candidate_digest", "preset_digest", "asset_digest", "readout_proof_digest"):
        _sha(getattr(value, name), name)
    if (type(value.coordinates) is not tuple or len(value.coordinates) != 24
            or tuple(axis for axis, _ in value.coordinates) != REGISTERED_AXIS_IDS):
        raise ValueError("authored state coordinates need exact ordered axes")
    for _, number in value.coordinates:
        if not -1 <= _finite(number, "coordinate") <= 1:
            raise ValueError("readout coordinate leaves [-1, 1]")
    _finite(value.cursor, "cursor")
    if type(value.revision) is not int or value.revision < 1:
        raise ValueError("state revision must be positive")
    refs = (value.interpretation_refs, value.historical_source_refs) if feeling else (value.source_refs,)
    for group in (*refs, value.active_driver_refs):
        if type(group) is not tuple or len(group) != len(set(group)):
            raise ValueError("authored state references must be unique tuples")
        for ref in group:
            _text(ref, "authored state reference")
    if value.status == "authored_initial_parameter_not_observation":
        if value.revision != 1 or any(refs) or value.active_driver_refs:
            raise ValueError("root authored state cannot claim later provenance")
    elif value.status == "authored_joint_continuation":
        if value.revision < 2 or not value.active_driver_refs:
            raise ValueError("authored joint continuation needs real driver references")
    else:
        raise ValueError("unknown authored state status")


@dataclass(frozen=True, slots=True)
class AuthoredNumericCheckpointV2:
    checkpoint_id: str
    namespace: tuple[str, str]
    block: RootAuthoredFacetV3
    assets: RootAssetBindings
    asset_digest: str
    axes: tuple[str, ...]
    latent_state: tuple[float, ...]
    certified_box: tuple[tuple[float, float], ...]
    numeric_error_bound: float
    certificate_digest: str
    cursor: float
    graph_state: CommittedRef
    readout_proof_digest: str
    root_candidate_digest: str
    commit_operation_id: str
    predecessor_receipt_digest: str | None = None
    status: str = "trusted_initial_box_pending_w01_v3_adoption"

    def __post_init__(self) -> None:
        _text(self.checkpoint_id, "checkpoint_id")
        _namespace(self.namespace)
        if type(self.block) is not RootAuthoredFacetV3 or type(self.assets) is not RootAssetBindings:
            raise TypeError("checkpoint block and assets must be exact")
        _sha(self.asset_digest, "asset_digest")
        if self.asset_digest != self.assets.digest:
            raise ValueError("checkpoint asset digest differs")
        _axes(self.axes)
        _box(self.latent_state, self.certified_box)
        error = _finite(self.numeric_error_bound, "numeric_error_bound")
        if error < 0 or not _covers_box(self.latent_state, self.certified_box, error):
            raise ValueError("checkpoint error does not cover initial box")
        for name in ("certificate_digest", "readout_proof_digest", "root_candidate_digest"):
            _sha(getattr(self, name), name)
        _finite(self.cursor, "cursor")
        if type(self.graph_state) is not CommittedRef:
            raise TypeError("graph_state must be CommittedRef")
        key = AtomKey.from_token(self.graph_state.ref)
        expected = FEELING_TYPE if self.block.kind == "feeling" else MOOD_TYPE
        if (key.type_name != expected or key.owner.kind != "persona"
                or (key.owner.bot, key.owner.persona) != self.namespace
                or key.name != self.block.block_id):
            raise ValueError("checkpoint graph state differs")
        _text(self.commit_operation_id, "commit_operation_id")
        if self.status == "trusted_initial_box_pending_w01_v3_adoption":
            if self.graph_state.revision != 1 or self.predecessor_receipt_digest is not None:
                raise ValueError("root checkpoint has no predecessor or adoption authority")
        elif self.status == "trusted_joint_advance":
            if self.graph_state.revision < 2:
                raise ValueError("joint checkpoint must advance the authored state")
            _sha(self.predecessor_receipt_digest, "predecessor_receipt_digest")
        else:
            raise ValueError("unknown authored checkpoint status")


def _encode(value: object, schema: str, expected: type) -> dict:
    if type(value) is not expected:
        raise TypeError(f"expected {expected.__name__}")
    return json.loads(canonical_serialize({"schema": schema, **asdict(value)}))


def encode_authored_feeling_state_v1(value: AuthoredFeelingStateV1) -> dict:
    return _encode(value, FEELING_TYPE, AuthoredFeelingStateV1)


def encode_authored_mood_state_v1(value: AuthoredMoodStateV1) -> dict:
    return _encode(value, MOOD_TYPE, AuthoredMoodStateV1)


def encode_authored_numeric_checkpoint_v2(value: AuthoredNumericCheckpointV2) -> dict:
    return _encode(value, CHECKPOINT_TYPE, AuthoredNumericCheckpointV2)


def _decode_state(value: object, schema: str, cls: type) -> object:
    raw = _exact(value, {"schema", *cls.__dataclass_fields__}, "state")
    if raw["schema"] != schema:
        raise ValueError("authored state schema differs")
    fields = dict(raw)
    fields.pop("schema")
    fields["coordinates"] = tuple(tuple(_array(item, "coordinate"))
                                  for item in _array(fields["coordinates"], "coordinates"))
    for name in ("interpretation_refs", "historical_source_refs", "source_refs", "active_driver_refs"):
        if name in fields:
            fields[name] = tuple(_array(fields[name], name))
    result = cls(**fields)
    if _encode(result, schema, cls) != raw:
        raise ValueError("authored state canonical round trip differs")
    return result


def decode_authored_feeling_state_v1(value: object) -> AuthoredFeelingStateV1:
    return _decode_state(value, FEELING_TYPE, AuthoredFeelingStateV1)


def decode_authored_mood_state_v1(value: object) -> AuthoredMoodStateV1:
    return _decode_state(value, MOOD_TYPE, AuthoredMoodStateV1)


def decode_authored_numeric_checkpoint_v2(value: object) -> AuthoredNumericCheckpointV2:
    raw = _exact(value, {"schema", *AuthoredNumericCheckpointV2.__dataclass_fields__}, "checkpoint")
    if raw["schema"] != CHECKPOINT_TYPE:
        raise ValueError("authored checkpoint schema differs")
    fields = dict(raw)
    fields.pop("schema")
    fields["namespace"] = tuple(_array(fields["namespace"], "namespace"))
    fields["block"] = RootAuthoredFacetV3(**_exact(fields["block"], set(RootAuthoredFacetV3.__dataclass_fields__), "facet"))
    fields["assets"] = RootAssetBindings(**_exact(fields["assets"], set(RootAssetBindings.__dataclass_fields__), "assets"))
    fields["axes"] = tuple(_array(fields["axes"], "axes"))
    fields["latent_state"] = tuple(_array(fields["latent_state"], "latent_state"))
    fields["certified_box"] = tuple(tuple(_array(item, "box")) for item in _array(fields["certified_box"], "box"))
    fields["graph_state"] = CommittedRef(**_exact(fields["graph_state"], set(CommittedRef.__dataclass_fields__), "graph_state"))
    result = AuthoredNumericCheckpointV2(**fields)
    if encode_authored_numeric_checkpoint_v2(result) != raw:
        raise ValueError("authored checkpoint canonical round trip differs")
    return result


def validate_authored_joint_predecessor_v3(
    checkpoint: AuthoredNumericCheckpointV2,
    state: AuthoredFeelingStateV1 | AuthoredMoodStateV1,
    checkpoint_revision: int,
) -> None:
    """Check the paired current values; graph originals authenticate their lineage."""
    feeling = checkpoint.block.kind == "feeling"
    if (type(checkpoint) is not AuthoredNumericCheckpointV2
            or type(state) is not (AuthoredFeelingStateV1 if feeling else AuthoredMoodStateV1)
            or type(checkpoint_revision) is not int
            or checkpoint_revision != checkpoint.graph_state.revision
            or state.revision != checkpoint_revision
            or state.block_id != checkpoint.block.block_id
            or state.facet_id != checkpoint.block.facet_id
            or state.root_candidate_digest != checkpoint.root_candidate_digest
            or state.asset_digest != checkpoint.asset_digest
            or state.basis_version != checkpoint.assets.scheme_version
            or state.parameter_version != checkpoint.assets.parameter_version
            or state.coupling_version != checkpoint.assets.coupling_version
            or (feeling and state.operator_version != checkpoint.assets.operator_version)
            or state.cursor != checkpoint.cursor
            or state.readout_proof_digest != checkpoint.readout_proof_digest):
        raise ValueError("authored checkpoint and state identities differ")
    if checkpoint_revision == 1:
        if (checkpoint.status != "trusted_initial_box_pending_w01_v3_adoption"
                or state.status != "authored_initial_parameter_not_observation"
                or state.root_operation_id != checkpoint.commit_operation_id):
            raise ValueError("authored initial predecessor differs")
    elif (checkpoint.status != "trusted_joint_advance"
          or state.status != "authored_joint_continuation"
          or not state.active_driver_refs):
        raise ValueError("authored continuation predecessor differs")


def authored_lineage_type_specs_v3() -> tuple[TypeSpec, ...]:
    definitions = (
        ("d04.authored_root_candidate.v3", decode_authored_root_candidate_v3, AuthoredRootCandidateV3, "projection", True),
        (FEELING_TYPE, decode_authored_feeling_state_v1, AuthoredFeelingStateV1, "state", False),
        (MOOD_TYPE, decode_authored_mood_state_v1, AuthoredMoodStateV1, "state", False),
        (CHECKPOINT_TYPE, decode_authored_numeric_checkpoint_v2, AuthoredNumericCheckpointV2, "state", False),
    )
    return tuple(TypeSpec(name, ("persona",), role, decoder, immutable=immutable,
                          schema_version=3 if name.endswith(".v3") else 2 if name == CHECKPOINT_TYPE else 1,
                          writer_domain="d04", schema_hash=schema_hash({
                              "type": name, "writer_domain": "d04",
                              "fields": tuple(cls.__dataclass_fields__),
                              "authored_lineage": 3,
                          })) for name, decoder, cls, role, immutable in definitions)


@dataclass(frozen=True, slots=True)
class AuthoredInitialBoxBlockProofV3:
    checkpoint_digest: str
    initial_box_digest: str
    verified_initial_error: float


@dataclass(frozen=True, slots=True)
class AuthoredInitialBoxProofV3:
    candidate_digest: str
    production_binding: NativeLoadBinding
    binding_digest: str
    blocks: tuple[AuthoredInitialBoxBlockProofV3, ...]
    proof_digest: str
    status: str = "conditional_native_math_pending_w01_replay"


def run_authored_initial_box_math_v3(
    handle: ABI2NativeLibrary, candidate: AuthoredRootCandidateV3,
) -> AuthoredInitialBoxProofV3:
    """Run actual package-bound ABI2 initial-box math; grant no graph authority."""
    if type(candidate) is not AuthoredRootCandidateV3 or not isinstance(handle, ABI2NativeLibrary):
        raise TypeError("expected V3 candidate and ABI2 handle")
    binding = handle.production_binding
    if (type(binding) is not NativeLoadBinding or binding.abi_version != 2
            or not handle.capabilities.supports_initial_box_math_v1 or handle._initial_box is None):
        raise ValueError("package-bound ABI2 initial-box capability is absent")
    blocks = []
    for checkpoint in candidate.checkpoints:
        lower = tuple(pair[0] for pair in checkpoint.ordered_box)
        upper = tuple(pair[1] for pair in checkpoint.ordered_box)
        radius = _native_initial_radius(handle, checkpoint.latent_state, lower, upper)
        blocks.append(AuthoredInitialBoxBlockProofV3(
            canonical_digest(asdict(checkpoint)),
            _box_digest(checkpoint.latent_state, lower, upper, radius, binding), radius,
        ))
    fields = dict(candidate_digest=candidate.digest, production_binding=binding,
                  binding_digest=canonical_digest(asdict(binding)), blocks=tuple(blocks),
                  status="conditional_native_math_pending_w01_replay")
    return AuthoredInitialBoxProofV3(**fields, proof_digest=canonical_digest(fields))


def verify_authored_initial_box_math_v3(
    handle: ABI2NativeLibrary, candidate: AuthoredRootCandidateV3,
    proof: AuthoredInitialBoxProofV3,
) -> None:
    """Require W01's currently pinned ABI2 handle to reproduce every radius."""
    if type(proof) is not AuthoredInitialBoxProofV3 or proof != run_authored_initial_box_math_v3(handle, candidate):
        raise ValueError("V3 initial box proof differs from installed ABI2 replay")


@dataclass(frozen=True, slots=True)
class AuthoredRootWriteMemberV3:
    checkpoint_ref: str
    checkpoint: AuthoredNumericCheckpointV2
    state_ref: str
    state: AuthoredFeelingStateV1 | AuthoredMoodStateV1
    axes: tuple[JointStateAxisOutputV1, ...]


@dataclass(frozen=True, slots=True)
class AuthoredRootWritesCandidateV3:
    candidate_digest: str
    operation_id: str
    initial_box_proof_digest: str
    native_manifest_sha256: str
    native_sha256: str
    policy_digest: str
    readout_sha256: str
    readout_output_digest: str
    members: tuple[AuthoredRootWriteMemberV3, ...]
    write_set_digest: str
    issuance_digest: str
    status: str = "candidate_pending_w01_v3_atomic_adoption"


def authored_root_write_rows_v3(
    members: tuple[AuthoredRootWriteMemberV3, ...],
) -> tuple[tuple[str, int, dict], ...]:
    rows = []
    for item in members:
        rows.append((item.checkpoint_ref, 1, encode_authored_numeric_checkpoint_v2(item.checkpoint)))
        encode = encode_authored_feeling_state_v1 if type(item.state) is AuthoredFeelingStateV1 else encode_authored_mood_state_v1
        rows.append((item.state_ref, 1, encode(item.state)))
    return tuple(sorted(rows, key=lambda row: row[0]))


def issue_authored_root_writes_v3(
    candidate: AuthoredRootCandidateV3, initial_box_proof: AuthoredInitialBoxProofV3,
    readout: D04LoadedTanhReadoutAsset, policy: JointStateOutputPolicyV1,
    operation_id: str,
) -> AuthoredRootWritesCandidateV3:
    """Pure deterministic write derivation; W01 must replay all trusted premises."""
    if (type(candidate) is not AuthoredRootCandidateV3
            or type(initial_box_proof) is not AuthoredInitialBoxProofV3
            or type(readout) is not D04LoadedTanhReadoutAsset
            or type(policy) is not JointStateOutputPolicyV1):
        raise TypeError("V3 root issuer needs typed inputs")
    _text(operation_id, "operation_id")
    binding = initial_box_proof.production_binding
    fields = dict(candidate_digest=initial_box_proof.candidate_digest,
                  production_binding=binding,
                  binding_digest=initial_box_proof.binding_digest,
                  blocks=initial_box_proof.blocks,
                  status=initial_box_proof.status)
    if (candidate.digest != initial_box_proof.candidate_digest
            or binding.abi_version != 2
            or candidate.preset.axes != REGISTERED_AXIS_IDS
            or candidate.preset.assets.readout_sha256 != readout.asset_sha256
            or candidate.preset.assets.readout_version != readout.readout_version
            or initial_box_proof.status != "conditional_native_math_pending_w01_replay"
            or initial_box_proof.binding_digest != canonical_digest(asdict(binding))
            or initial_box_proof.proof_digest != canonical_digest(fields)
            or len(initial_box_proof.blocks) != len(candidate.checkpoints)):
        raise ValueError("V3 initial box proof or readout identity differs")
    _identity_asset(readout, policy)
    owner = Owner("persona", *candidate.namespace)
    members = []
    for checkpoint, block_proof in zip(candidate.checkpoints, initial_box_proof.blocks):
        lower = tuple(pair[0] for pair in checkpoint.ordered_box)
        upper = tuple(pair[1] for pair in checkpoint.ordered_box)
        if (block_proof.checkpoint_digest != canonical_digest(asdict(checkpoint))
                or block_proof.initial_box_digest != _box_digest(
                    checkpoint.latent_state, lower, upper,
                    block_proof.verified_initial_error, binding)
                or not _covers_box(checkpoint.latent_state, checkpoint.ordered_box,
                                   block_proof.verified_initial_error)):
            raise ValueError("V3 initial box block proof differs")
        numeric = run_d04_conditional_tanh_readout_math(
            readout, checkpoint.latent_state, block_proof.verified_initial_error)
        if numeric.asset_sha256 != policy.readout_sha256 or len(numeric.outputs) != 24:
            raise ValueError("V3 root readout differs")
        axes = tuple(_axis_output(axis, row.output_id, output.lower, output.upper,
                                  policy.max_readout_interval_width)
                     for axis, row, output in zip(REGISTERED_AXIS_IDS, readout.rows, numeric.outputs))
        if any(axis.axis_id != row.axis_id or axis.axis_id != output.axis_id
               or row.output_id != output.output_id
               for axis, row, output in zip(axes, readout.rows, numeric.outputs)):
            raise ValueError("V3 readout axis identity differs")
        proof_digest = canonical_digest(axes)
        coordinates = tuple((item.axis_id, item.representative) for item in axes)
        common = dict(block_id=checkpoint.block.block_id, facet_id=checkpoint.block.facet_id,
                      root_operation_id=operation_id, root_candidate_digest=candidate.digest,
                      owner_draft_id=candidate.draft_id, preset_digest=candidate.preset.digest,
                      asset_digest=candidate.preset.assets.digest,
                      basis_version=candidate.preset.assets.scheme_version,
                      parameter_version=candidate.preset.assets.parameter_version,
                      coupling_version=candidate.preset.assets.coupling_version,
                      coordinates=coordinates, readout_proof_digest=proof_digest,
                      cursor=candidate.cursor)
        if checkpoint.block.kind == "feeling":
            state = AuthoredFeelingStateV1(**common,
                        operator_version=candidate.preset.assets.operator_version)
            state_type = FEELING_TYPE
        else:
            state = AuthoredMoodStateV1(**common)
            state_type = MOOD_TYPE
        state_ref = AtomKey(owner, state_type, checkpoint.block.block_id).token
        cp = AuthoredNumericCheckpointV2(
            checkpoint.block.block_id, candidate.namespace, checkpoint.block,
            candidate.preset.assets, candidate.preset.assets.digest, checkpoint.axes,
            checkpoint.latent_state, checkpoint.ordered_box,
            block_proof.verified_initial_error, block_proof.initial_box_digest,
            checkpoint.cursor, CommittedRef(state_ref, 1), proof_digest,
            candidate.digest, operation_id,
        )
        members.append(AuthoredRootWriteMemberV3(
            AtomKey(owner, CHECKPOINT_TYPE, checkpoint.block.block_id).token,
            cp, state_ref, state, axes,
        ))
    ordered = tuple(sorted(members, key=lambda item: item.checkpoint_ref))
    rows = authored_root_write_rows_v3(ordered)
    readout_output_digest = canonical_digest(tuple(
        (item.checkpoint_ref, item.checkpoint.readout_proof_digest)
        for item in ordered))
    data = dict(candidate_digest=candidate.digest, operation_id=operation_id,
                initial_box_proof_digest=initial_box_proof.proof_digest,
                native_manifest_sha256=binding.manifest_sha256,
                native_sha256=binding.native_sha256, policy_digest=policy.digest,
                readout_sha256=readout.asset_sha256,
                readout_output_digest=readout_output_digest, members=ordered,
                write_set_digest=canonical_digest(rows),
                status="candidate_pending_w01_v3_atomic_adoption")
    return AuthoredRootWritesCandidateV3(**data,
        issuance_digest=canonical_digest(data))
