"""Immutable D04 evidence for affect at memory encoding time.

This contract records version claims and explicitly unknown projections. A
future issuer must verify graph commits and numerical evidence before known
intervals can be admitted. This module does not derive them from coordinates.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ...graph_types import AtomKey, GraphSnapshot


def _text(value: object, name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


def _canonical_ref(value: object, name: str, type_name: str) -> str:
    token = _text(value, name)
    try:
        key = AtomKey.from_token(token)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a canonical {type_name} ref") from exc
    if key.type_name != type_name:
        raise ValueError(f"{name} must be a canonical {type_name} ref")
    return token


def _typed_key(value: object, name: str, allowed: dict[str, frozenset[str]]) -> AtomKey:
    token = _text(value, name)
    try:
        key = AtomKey.from_token(token)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a canonical graph ref") from exc
    if key.owner.kind not in allowed.get(key.type_name, frozenset()):
        raise ValueError(f"{name} must reference an allowed graph type and owner")
    return key


_PERSPECTIVE_TYPES = {
    "d03.entity_anchor": frozenset({"persona"}),
    "d03.role_binding": frozenset({"persona", "scene"}),
    "d03.self_perspective.v1": frozenset({"persona"}),
}
_INTERPRETATION_TYPES = {
    "d07.current_interpretation.v1": frozenset({"activity"}),
    "d07.belief_revision.v1": frozenset({"persona"}),
}


@dataclass(frozen=True)
class CommittedRef:
    ref: str
    revision: int

    def __post_init__(self) -> None:
        token = _text(self.ref, "ref")
        try:
            AtomKey.from_token(token)
        except (TypeError, ValueError) as exc:
            raise ValueError("ref must be a canonical graph ref") from exc
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("revision must be a positive exact integer")


def _versions(values: object, name: str, *, type_name: str | None = None) -> tuple[CommittedRef, ...]:
    if type(values) is not tuple or any(type(item) is not CommittedRef for item in values):
        raise ValueError(f"{name} must be a tuple of CommittedRef values")
    if len({item.ref for item in values}) != len(values):
        raise ValueError(f"{name} must have unique refs")
    if type_name is not None:
        for item in values:
            _canonical_ref(item.ref, name, type_name)
    return values


def _bounded_interval(value: object, name: str, lower: float) -> tuple[float, float] | None:
    if value is None:
        return None
    if type(value) is not tuple or len(value) != 2:
        raise ValueError(f"{name} must be a two-value tuple or None")
    low, high = value
    if any(type(item) not in (int, float) or not math.isfinite(item) for item in value):
        raise ValueError(f"{name} must contain finite numbers")
    if not lower <= low <= high <= 1.0:
        raise ValueError(f"{name} must be ordered and within [{lower}, 1]")
    return float(low), float(high)


@dataclass(frozen=True)
class EncodingBaseline:
    baseline_id: str
    source_refs: tuple[str, ...]
    perspective_ref: str
    then_feeling_versions: tuple[CommittedRef, ...]
    interpretation_versions: tuple[CommittedRef, ...]
    as_known_at: float | None
    projection_policy_ref: str
    projection_policy_version: str
    basis_version: str
    parameter_version: str
    salience_interval: tuple[float, float] | None
    tone_interval: tuple[float, float] | None
    unknown_reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("baseline_id", "perspective_ref", "projection_policy_ref",
                     "projection_policy_version", "basis_version", "parameter_version"):
            _text(getattr(self, name), name)
        if type(self.source_refs) is not tuple or not self.source_refs:
            raise ValueError("source_refs must be a nonempty tuple")
        for ref in self.source_refs:
            _canonical_ref(ref, "source_refs", "memory.source")
        if len(set(self.source_refs)) != len(self.source_refs):
            raise ValueError("source_refs must have unique refs")
        source_keys = tuple(
            AtomKey.from_token(_canonical_ref(ref, "source_refs", "memory.source"))
            for ref in self.source_refs
        )
        if any(key.owner.kind != "event" or key.name != "record" for key in source_keys):
            raise ValueError("source_refs must use canonical memory.source keys")
        namespace = {(key.owner.bot, key.owner.persona) for key in source_keys}
        if len(namespace) != 1:
            raise ValueError("source_refs must share a namespace")
        perspective_key = _typed_key(self.perspective_ref, "perspective_ref", _PERSPECTIVE_TYPES)
        _versions(self.then_feeling_versions, "then_feeling_versions", type_name="d04.feeling_state.v1")
        _versions(self.interpretation_versions, "interpretation_versions")
        interpretation_keys = tuple(
            _typed_key(item.ref, "interpretation_versions", _INTERPRETATION_TYPES)
            for item in self.interpretation_versions
        )
        version_keys = tuple(AtomKey.from_token(item.ref) for item in (
            *self.then_feeling_versions,
        ))
        if any(key.owner.kind != "persona" for key in version_keys):
            raise ValueError("then_feeling_versions must use persona feeling keys")
        if any((key.owner.bot, key.owner.persona) not in namespace for key in (
            perspective_key, *version_keys, *interpretation_keys,
        )):
            raise ValueError("perspective and version refs must share the source namespace")
        if self.as_known_at is not None:
            if type(self.as_known_at) not in (int, float) or not math.isfinite(self.as_known_at):
                raise ValueError("as_known_at must be finite or None")
            object.__setattr__(self, "as_known_at", float(self.as_known_at))
        object.__setattr__(self, "salience_interval", _bounded_interval(
            self.salience_interval, "salience_interval", 0.0,
        ))
        object.__setattr__(self, "tone_interval", _bounded_interval(
            self.tone_interval, "tone_interval", -1.0,
        ))
        if type(self.unknown_reasons) is not tuple:
            raise ValueError("unknown_reasons must be a tuple of unique reasons")
        for reason in self.unknown_reasons:
            _text(reason, "unknown reason")
        if len(set(self.unknown_reasons)) != len(self.unknown_reasons):
            raise ValueError("unknown_reasons must be a tuple of unique reasons")
        for name in ("salience_interval", "tone_interval"):
            if (getattr(self, name) is None) != any(
                reason.startswith(f"{name}:") and reason[len(name) + 1:].strip()
                for reason in self.unknown_reasons
            ):
                raise ValueError(f"{name} must have an unknown reason exactly when absent")
        if self.salience_interval is not None or self.tone_interval is not None:
            raise ValueError("known intervals require a verified projection issuer")

    def verify_committed_refs(self, snapshot: GraphSnapshot) -> None:
        """Require valid graph atoms at the referenced committed revisions."""
        if not isinstance(snapshot, GraphSnapshot):
            raise TypeError("baseline reference verification requires a graph snapshot")
        for token in (*self.source_refs, self.perspective_ref,
                      *self.perspective_dependency_refs(snapshot)):
            atom = snapshot.get(AtomKey.from_token(token))
            if atom is None or not atom.valid or atom.revision < 1:
                raise ValueError("baseline source or perspective lacks a committed graph atom")
        for item in (*self.then_feeling_versions, *self.interpretation_versions):
            atom = snapshot.get(AtomKey.from_token(item.ref))
            if atom is None or not atom.valid or atom.revision != item.revision:
                raise ValueError("baseline version ref lacks its committed graph revision")

    def perspective_dependency_refs(self, snapshot: GraphSnapshot) -> tuple[str, ...]:
        """Bind a D03 self perspective to its current mapping and arrival fact."""
        key = AtomKey.from_token(self.perspective_ref)
        if key.type_name != "d03.self_perspective.v1":
            return ()
        if not isinstance(snapshot, GraphSnapshot):
            raise TypeError("self perspective needs a committed graph snapshot")
        from ..d03.self_perspective import (
            SelfIdentityMapping, SelfPerspective, self_mapping_key,
            self_perspective_id, self_perspective_key,
        )
        from ..d03.context import WorldEvent
        from ...runtime_contracts import NamespaceId

        namespace = NamespaceId(key.owner.bot, key.owner.persona)
        perspective_atom = snapshot.get(key)
        if (perspective_atom is None or not perspective_atom.valid
                or perspective_atom.revision < 1):
            raise ValueError("D03 self perspective is not committed")
        try:
            perspective = SelfPerspective(**perspective_atom.value)
            mapping_key = AtomKey.from_token(perspective.identity_mapping_ref)
            event_key = AtomKey.from_token(perspective.arrival_event_ref)
        except (TypeError, ValueError, KeyError) as exc:
            raise ValueError("D03 self perspective value is invalid") from exc
        mapping_atom = snapshot.get(mapping_key)
        event_atom = snapshot.get(event_key)
        if (mapping_atom is None or event_atom is None
                or not mapping_atom.valid or not event_atom.valid
                or mapping_atom.revision < 1 or event_atom.revision < 1):
            raise ValueError("D03 self perspective mapping or arrival is unavailable")
        try:
            mapping = SelfIdentityMapping(**mapping_atom.value)
            event = WorldEvent(**{
                **event_atom.value,
                "participant_roles": tuple(tuple(item) for item in event_atom.value["participant_roles"]),
                "source_refs": tuple(event_atom.value["source_refs"]),
            })
        except (TypeError, ValueError, KeyError) as exc:
            raise ValueError("D03 self perspective mapping or arrival is invalid") from exc
        if (key != self_perspective_key(namespace, perspective.perspective_id)
                or mapping_key != self_mapping_key(namespace)
                or event_key.owner.kind != "event"
                or (event_key.owner.bot, event_key.owner.persona) != namespace.as_tuple
                or event_key.owner.subject != event.event_id
                or event_key.name != "current"
                or perspective.perspective_id != self_perspective_id(
                    namespace, perspective.scene_ref, event_key.token)
                or perspective.persona_ref != mapping.persona_ref
                or perspective.persona_ref != f"persona:{namespace.persona_id}"
                or perspective.self_entity_ref != mapping.self_entity_ref
                or perspective.role_head_id != mapping.role_head_id
                or mapping.status != "active"
                or perspective.scene_ref != event.scene_ref
                or event.kind != "message_received"
                or event.reality != "host_observed"
                or event.source_refs != self.source_refs
                or event.learned_at != self.as_known_at
                or len(event.participant_roles) != 1
                or event.participant_roles[0][1] != "sender_account"
                or event.participant_roles[0][0] == perspective.self_entity_ref):
            raise ValueError("D03 self perspective is unrelated to baseline source or self")
        return mapping_key.token, event_key.token


def decode_encoding_baseline(payload: object) -> EncodingBaseline:
    """Decode a graph JSON object without accepting missing or extra fields."""
    if type(payload) is not dict or set(payload) != set(EncodingBaseline.__dataclass_fields__):
        raise ValueError("encoding baseline fields differ from v1 schema")
    decoded = dict(payload)
    for name in ("source_refs", "unknown_reasons"):
        if type(decoded[name]) is list:
            decoded[name] = tuple(decoded[name])
    for name in ("salience_interval", "tone_interval"):
        if type(decoded[name]) is list:
            decoded[name] = tuple(decoded[name])
    for name in ("then_feeling_versions", "interpretation_versions"):
        if type(decoded[name]) is not list:
            raise ValueError(f"{name} must be a list")
        refs = []
        for item in decoded[name]:
            if type(item) is not dict or set(item) != {"ref", "revision"}:
                raise ValueError(f"{name} entries must have ref and revision")
            refs.append(CommittedRef(**item))
        decoded[name] = tuple(refs)
    return EncodingBaseline(**decoded)
