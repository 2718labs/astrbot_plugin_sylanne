"""Pure D05 validators and projections; no secondary relationship store."""

from dataclasses import dataclass, fields, replace
import hashlib
import json
import math
import re
from collections.abc import Callable

from ...graph_types import AtomKey, TypeSpec, GraphSnapshot, GraphVersion, GraphWrite, Owner
from ...runtime_contracts import (
    CheckReceipt,
    DomainProposal,
    NamespaceId,
    ProviderDescriptor,
    QueryEpoch,
    VersionedRef,
    schema_hash,
    canonical_serialize,
    canonical_digest,
)
from ..d08.execution import ActionIntent, ActionSchema


RELATIONSHIP_PROJECTION_STATUS_SCHEMA_V1 = "d05.relationship-projection-status.v2"
RELATIONSHIP_WORKBENCH_TYPES_V2 = ("d05.relationship_projection", "d05.dimension_estimate.v2", "d05.relationship_profile.v2")
RELATIONSHIP_PUBLIC_STATUSES_V1 = frozenset({
    "unknown", "available", "unavailable", "stale", "blocked_rebuild",
    "rebuilt", "sanitized", "reset",
})
RELATIONSHIP_STATUS_PUBLIC_V1 = {
    **{status: status for status in RELATIONSHIP_PUBLIC_STATUSES_V1},
    "source_qualified": "available",
    "held_source_correction": "blocked_rebuild",
    "pending_bounded_reevaluation": "available",
}
CONTRIBUTION_KINDS_V2 = {
    "external_observation": "external_interaction",
    "recollection": "internal_recollection",
    "simulation": "simulated_trial",
}
_LEGACY_CONTRIBUTION_FIELDS_V1 = frozenset({
    "owner_persona_ref", "canonical_event_or_family_ref", "subject_entity_ref",
    "target_dimension", "semantics", "contribution_revision", "source_refs",
})
_LEGACY_PROJECTION_FIELDS_V1 = frozenset({"subject_entity_ref", "dimension", "status"})
_PROJECTION_FIELDS_V2 = _LEGACY_PROJECTION_FIELDS_V1 | {
    "schema_version", "source_qualification", "estimate", "influence_status",
}


def _id(value: str, label: str, prefix: str | None = None) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a nonempty string")
    if prefix and not value.startswith(prefix):
        raise ValueError(f"{label} must start with {prefix!r}")


def _time(value: float | int, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{label} must be finite")
    return float(value)


def _refs(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if not isinstance(values, tuple) or not values or len(values) != len(set(values)):
        raise ValueError(f"{label} must be a nonempty tuple without duplicates")
    for value in values:
        _id(value, label)
    return values


def _tuple_payload(payload: dict, *fields: str) -> dict:
    if not isinstance(payload, dict):
        raise TypeError("graph payload must be an object")
    decoded = dict(payload)
    tuple_fields = (*fields, "legacy_alias_keys") if "source_refs" in fields else fields
    for field in tuple_fields:
        if field in decoded and isinstance(decoded[field], list):
            decoded[field] = tuple(decoded[field])
    return decoded


def _strict_payload(payload: object, value_type: type, *tuple_fields: str) -> None:
    if type(payload) is not dict:
        raise TypeError("graph payload must be an object")
    expected = {field.name for field in fields(value_type)}
    actual = set(payload)
    if actual != expected:
        raise ValueError(
            f"{value_type.__name__} payload fields must match exactly; "
            f"missing={sorted(expected - actual)!r}, extra={sorted(actual - expected)!r}"
        )
    value_type(**_tuple_payload(payload, *tuple_fields))


def decode_relationship_projection_payload_v1(payload: object) -> dict:
    """Exact historical v1 or current v2 decoding, without granting currentness."""
    if type(payload) is not dict:
        raise TypeError("graph payload must be an object")
    shape = set(payload)
    if shape not in (_LEGACY_PROJECTION_FIELDS_V1, _PROJECTION_FIELDS_V2):
        raise ValueError("relationship projection has an exact shape")
    _id(payload["subject_entity_ref"], "subject_entity_ref", "entity:")
    _id(payload["dimension"], "dimension")
    _id(payload["status"], "status")
    if shape == _PROJECTION_FIELDS_V2:
        if payload["schema_version"] != 2 or type(payload["schema_version"]) is not int:
            raise ValueError("relationship projection schema version differs")
        if payload["source_qualification"] not in {"qualified", "unavailable", "unknown"}:
            raise ValueError("relationship source qualification is unregistered")
        if payload["estimate"] != "unknown":
            raise ValueError("relationship estimate requires an actual registered bounded evaluator")
        if payload["influence_status"] not in {"not_evaluated", "unapplied_pending", "legacy_unresolved"}:
            raise ValueError("relationship influence state is unregistered")
        if payload["status"] == "held_source_correction" and payload["source_qualification"] != "unavailable":
            raise ValueError("held relationship projection cannot carry current source qualification")
    return dict(payload)


def _validate_relationship_projection(payload: object) -> None:
    decoded = decode_relationship_projection_payload_v1(payload)
    if set(decoded) != _PROJECTION_FIELDS_V2:
        raise ValueError("new relationship projection requires exact v2 schema")
    if decoded["status"] not in RELATIONSHIP_STATUS_PUBLIC_V1 or decoded["status"] == "pending_bounded_reevaluation":
        raise ValueError("relationship projection has no public status token")


def translate_relationship_projection_v2(payload: object, *, source_qualification: str = "unknown") -> dict:
    """Prepare current metadata; callers must authenticate any positive qualification."""
    old = decode_relationship_projection_payload_v1(payload)
    status = old["status"]
    if status not in RELATIONSHIP_STATUS_PUBLIC_V1:
        status, source_qualification = "unavailable", "unavailable"
    influence = old.get("influence_status", "not_evaluated")
    if status == "pending_bounded_reevaluation":
        status, influence = "source_qualified", "unapplied_pending"
    if status == "held_source_correction":
        source_qualification = "unavailable"
    result = {"subject_entity_ref": old["subject_entity_ref"], "dimension": old["dimension"],
        "status": status, "schema_version": 2, "source_qualification": source_qualification,
        "estimate": "unknown", "influence_status": influence}
    _validate_relationship_projection(result)
    return result


def decode_relationship_contribution_payload_v1(payload: object) -> "RelationshipContribution":
    """Recognize only the exact delivered seven-field v1 or explicit v2 shape."""
    if type(payload) is not dict:
        raise TypeError("contribution payload must be an object")
    shape = set(payload)
    if shape == _LEGACY_CONTRIBUTION_FIELDS_V1:
        return RelationshipContribution(**_tuple_payload(payload, "source_refs"))
    if shape != {field.name for field in fields(RelationshipContribution)} or payload.get("schema_version") != 2:
        raise ValueError("contribution payload has no registered exact schema")
    return RelationshipContribution(**_tuple_payload(payload, "source_refs", "legacy_alias_keys"))


def _validate_relationship_contribution_v2(payload: object) -> None:
    value = decode_relationship_contribution_payload_v1(payload)
    if value.schema_version != 2:
        raise ValueError("new relationship contribution requires exact v2 schema")


def translate_relationship_contribution_v2(payload: object, *, canonical_activity_identity: str | None = None,
        recollection_activity_ref: str | None = None, legacy_alias_keys: tuple[str, ...] = ()) -> "RelationshipContribution":
    """Convert authenticated migration material without creating an activity/score."""
    old = decode_relationship_contribution_payload_v1(payload)
    if old.schema_version == 2:
        return old
    identity_status = "resolved"
    canonical = old.canonical_event_or_family_ref
    if old.semantics == "recollection":
        if canonical_activity_identity is None or recollection_activity_ref is None:
            identity_status = "legacy_unresolved"
        else:
            canonical = canonical_activity_identity
    elif canonical_activity_identity is not None or recollection_activity_ref is not None:
        raise ValueError("external/simulation migration cannot invent a recollection")
    return replace(old, canonical_event_or_family_ref=canonical, schema_version=2,
        kind=CONTRIBUTION_KINDS_V2[old.semantics], recollection_activity_ref=recollection_activity_ref,
        identity_status=identity_status, legacy_alias_keys=legacy_alias_keys)


def relationship_projection_public_v2(payload: object) -> dict:
    value = decode_relationship_projection_payload_v1(payload)
    legacy = set(value) == _LEGACY_PROJECTION_FIELDS_V1
    registered = value["status"] in RELATIONSHIP_STATUS_PUBLIC_V1
    qualified = not legacy and value["source_qualification"] == "qualified"
    availability = RELATIONSHIP_STATUS_PUBLIC_V1.get(value["status"], "unavailable")
    if availability == "available" and not qualified:
        availability = "unavailable"
    result = {"dimension": value["dimension"], "status": availability, "availability": availability,
        "source_qualification": value.get("source_qualification", "unknown"), "estimate": "unknown",
        "influence_status": value.get("influence_status",
            "unapplied_pending" if value["status"] == "pending_bounded_reevaluation" else "not_evaluated")}
    if not registered:
        result["diagnostic_error"] = "unregistered_legacy_relationship_state"
    return result


@dataclass(frozen=True)
class RelationshipContribution:
    owner_persona_ref: str
    canonical_event_or_family_ref: str
    subject_entity_ref: str
    target_dimension: str
    semantics: str
    contribution_revision: int
    source_refs: tuple[str, ...]
    schema_version: int = 1
    kind: str | None = None
    recollection_activity_ref: str | None = None
    identity_status: str = "legacy_unresolved"
    legacy_alias_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _id(self.owner_persona_ref, "owner_persona_ref", "persona:")
        _id(self.canonical_event_or_family_ref, "canonical_event_or_family_ref")
        _id(self.subject_entity_ref, "subject_entity_ref", "entity:")
        _id(self.target_dimension, "target_dimension")
        if self.semantics not in CONTRIBUTION_KINDS_V2:
            raise ValueError("unsupported contribution semantics")
        if type(self.contribution_revision) is not int or self.contribution_revision < 1:
            raise ValueError("contribution_revision must be positive")
        _refs(self.source_refs, "source_refs")
        if type(self.schema_version) is not int or self.schema_version not in {1, 2}:
            raise ValueError("contribution schema version is unregistered")
        if self.schema_version == 1:
            if (self.kind is not None or self.recollection_activity_ref is not None
                    or self.identity_status != "legacy_unresolved" or self.legacy_alias_keys):
                raise ValueError("legacy contribution cannot carry unproven v2 identity")
            return
        if self.kind != CONTRIBUTION_KINDS_V2[self.semantics] or self.identity_status not in {"resolved", "legacy_unresolved"}:
            raise ValueError("contribution kind/identity status differs from its registered semantics")
        if self.semantics == "recollection":
            if self.identity_status == "resolved":
                key = AtomKey.from_token(self.recollection_activity_ref)
                if key.type_name != "d06.recollection.v1" or key.owner.kind != "activity":
                    raise ValueError("resolved recollection requires its actual activity graph ref")
            elif self.recollection_activity_ref is not None:
                raise ValueError("unresolved legacy recollection must not fabricate an activity")
        elif self.recollection_activity_ref is not None or self.identity_status != "resolved":
            raise ValueError("external/simulation contribution cannot claim a recollection")
        if type(self.legacy_alias_keys) is not tuple or len(set(self.legacy_alias_keys)) != len(self.legacy_alias_keys):
            raise ValueError("legacy aliases must be an exact tuple without duplicates")
        for ref in self.legacy_alias_keys:
            key = AtomKey.from_token(ref)
            if key.type_name != "d05.contribution" or key.owner.kind != "relation":
                raise ValueError("legacy alias has another domain/type")

    @property
    def key(self) -> str:
        # Registered kind and semantics are bijective. Retain delivered
        # external-family keys, while internal canonical identity is the
        # namespace/activity/effect commitment supplied by the real reader.
        body = (self.owner_persona_ref, self.canonical_event_or_family_ref,
                self.subject_entity_ref, self.target_dimension, self.semantics)
        digest = hashlib.sha256(json.dumps(body, separators=(",", ":")).encode("utf-8")).hexdigest()
        return f"contribution:{digest}"

    def with_revision(self, revision: int) -> "RelationshipContribution":
        return replace(self, contribution_revision=revision)


RelationshipContributionV2 = RelationshipContribution


@dataclass(frozen=True, slots=True)
class AuthenticatedRecollectionMigrationMaterialV2:
    namespace: NamespaceId
    legacy_source_token: str
    recollection_activity_ref: str
    canonical_activity_identity: str
    activity_id: str
    effect_id: str | None
    operation_id: str
    commit_seq: int
    write_version: GraphVersion
    original_digest: str
    content_source_refs: tuple[str, ...]
    content_families: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]

    def __post_init__(self):
        key = AtomKey.from_token(self.recollection_activity_ref)
        legacy = AtomKey.from_token(self.legacy_source_token)
        if (type(self.namespace) is not NamespaceId or NamespaceId.from_key(key) != self.namespace
                or NamespaceId.from_key(legacy) != self.namespace or legacy.type_name != "d05.contribution"
                or key.type_name != "d06.recollection.v1" or key.owner.subject != self.activity_id
                or self.write_version.key != key or self.write_version.revision < 1
                or type(self.commit_seq) is not int or self.commit_seq < 1
                or self.write_version not in self.read_versions):
            raise ValueError("actual recollection migration material identity differs")
        _id(self.operation_id, "operation_id")
        _id(self.canonical_activity_identity, "canonical_activity_identity", "recollection-activity:")
        if self.effect_id is not None:
            _id(self.effect_id, "effect_id")
        if re.fullmatch(r"[0-9a-f]{64}", self.original_digest) is None:
            raise ValueError("actual recollection migration material digest differs")
        _refs(self.content_source_refs, "content_source_refs")
        _refs(self.content_families, "content_families")
        if len(self.content_source_refs) > 32 or len(self.read_versions) > 1024:
            raise ValueError("actual recollection migration material exceeds its registered bound")


@dataclass(frozen=True, slots=True)
class MigrationBatchV2:
    writes: tuple[GraphWrite, ...]
    read_versions: tuple[GraphVersion, ...]
    source_tokens: tuple[str, ...]
    aliases: tuple[tuple[str, str, bool], ...]
    coverage_gaps: tuple[tuple[str, str], ...]
    current_validity: tuple[tuple[str, bool], ...]
    retired_source_tokens: tuple[str, ...]


def _migration_source_qualification_v2(snapshot, namespace, source_refs):
    """Fixed catalogue-maintenance audit eligibility; Owner action is a separate gate."""
    from ...memory_types import SourceRecord, access_key, source_key, validate_access
    from ..d06 import source_correction_head_key
    checked, dependencies, pending = set(), [], list(source_refs)
    qualified = bool(source_refs)
    while pending:
        ref = pending.pop()
        if ref in checked:
            continue
        checked.add(ref)
        if len(checked) > 32:
            raise ValueError("D05 migration family closure exceeds its registered bound")
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject):
            raise ValueError("D05 migration source crossed namespace")
        access = access_key(*namespace.as_tuple, key.owner.subject)
        correction = source_correction_head_key(namespace, key.owner.subject)
        source_atom, access_atom, correction_atom = (snapshot.get(item) for item in (key, access, correction))
        dependencies.extend((key, access, correction))
        if (source_atom is None or access_atom is None or correction_atom is None
                or source_atom.revision < 1 or access_atom.revision < 1
                or not source_atom.valid or not access_atom.valid):
            qualified = False
            continue
        source = SourceRecord.from_dict(source_atom.value)
        validate_access(access_atom.value)
        if (source.source_id != key.owner.subject or access_atom.value["source_id"] != source.source_id
                or access_atom.value["status"] != "active"
                or "owner" not in source.audiences or "owner" not in access_atom.value["audiences"]
                or "audit" not in source.purposes or "audit" not in access_atom.value["purposes"]
                or correction_atom.revision != 0):
            qualified = False
        pending.extend(source_key(*namespace.as_tuple, parent).token for parent in source.parent_source_ids)
    return qualified, tuple(dict.fromkeys(dependencies))


def translate_d05_current_heads_v2(snapshot: GraphSnapshot, namespace: NamespaceId,
        batch_tokens: tuple[str, ...], *, authenticated_recollections=(), legacy_consumed_keys=(),
        source_catalogue_hash: str) -> MigrationBatchV2:
    """Bounded schema proposals; maintenance owns CAS, validity and publication.

    No activity, numeric delta, consumption or authorization is issued here.
    Historical signed payload bytes are inputs, never rewritten by this codec.
    """
    if source_catalogue_hash not in {
            "6a05fc901a3c45696faaab63746a6bf795db79282c6be7fdc8bffb6c228a71d1",
            "fb3c44ee4ce9bf85325bb445b891144929aea14d6d7d722f6004d4df817f4f8f"}:
        raise ValueError("D05 migration source catalogue is not registered")
    if (type(snapshot) is not GraphSnapshot or type(namespace) is not NamespaceId
            or type(batch_tokens) is not tuple or not 1 <= len(batch_tokens) <= 32
            or len(set(batch_tokens)) != len(batch_tokens) or len(snapshot.atoms) > 1024
            or len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple):
        raise ValueError("D05 migration requires one bounded fenced namespace snapshot")
    if any(NamespaceId.from_key(atom.key) != namespace for atom in snapshot.atoms):
        raise ValueError("D05 migration snapshot contains another namespace")
    if any(type(item) is not AuthenticatedRecollectionMigrationMaterialV2 or item.namespace != namespace
           for item in authenticated_recollections):
        raise TypeError("D05 migration needs actual typed recollection materials")
    writes, aliases, gaps, validity, retired = [], [], [], [], []
    consumed = set(legacy_consumed_keys)
    contributions = tuple(atom for atom in snapshot.atoms if atom.revision > 0 and atom.key.type_name == "d05.contribution")

    def emit(key, value, dependencies, valid):
        target = snapshot.get(key)
        if target is None:
            raise ValueError("D05 migration target lacks an exact positive/negative CAS head")
        writes.append(GraphWrite(key, json.loads(canonical_serialize(value)), dependencies))
        validity.append((key.token, valid))

    for token in batch_tokens:
        key = AtomKey.from_token(token)
        atom = snapshot.get(key)
        if atom is None or atom.revision < 1 or key.owner.kind != "relation":
            raise ValueError("D05 migration batch source head is absent")
        if key.type_name == "d05.contribution":
            old = decode_relationship_contribution_payload_v1(atom.value)
            if key.owner.subject != old.subject_entity_ref or key.name != old.key:
                raise ValueError("D05 migration contribution owner/key differs")
            qualified, dependencies = _migration_source_qualification_v2(snapshot, namespace, old.source_refs)
            valid = atom.valid and qualified
            if old.schema_version == 2:
                emit(key, dict(atom.value), dependencies, valid)
                continue
            materials = {item.canonical_activity_identity: item for item in authenticated_recollections
                         if item.legacy_source_token == token}
            old_alias = (token,)
            if old.semantics != "recollection" or not materials:
                new = translate_relationship_contribution_v2(atom.value, legacy_alias_keys=old_alias)
                emit(key, {field.name: getattr(new, field.name) for field in fields(new)}, dependencies, valid)
                aliases.append((key.token, token, token in consumed))
                if new.identity_status == "legacy_unresolved":
                    gaps.append((token, "legacy_unresolved_missing_committed_recollection_original"))
            elif len(materials) == 1:
                material = next(iter(materials.values()))
                new = translate_relationship_contribution_v2(atom.value,
                    canonical_activity_identity=old.canonical_event_or_family_ref,
                    recollection_activity_ref=material.recollection_activity_ref, legacy_alias_keys=old_alias)
                emit(key, {field.name: getattr(new, field.name) for field in fields(new)}, dependencies, valid)
                aliases.append((key.token, token, token in consumed))
            else:
                # Retain the old alias/history but prevent a third active head.
                legacy = translate_relationship_contribution_v2(atom.value, legacy_alias_keys=old_alias)
                emit(key, {field.name: getattr(legacy, field.name) for field in fields(legacy)}, dependencies, False)
                retired.append(token)
                for identity, material in sorted(materials.items()):
                    new = translate_relationship_contribution_v2(atom.value, canonical_activity_identity=identity,
                        recollection_activity_ref=material.recollection_activity_ref, legacy_alias_keys=old_alias)
                    new_key = AtomKey(key.owner, key.type_name, new.key)
                    emit(new_key, {field.name: getattr(new, field.name) for field in fields(new)}, dependencies, valid)
                    aliases.append((new_key.token, token, token in consumed))
        elif key.type_name == "d05.relationship_projection":
            old = decode_relationship_projection_payload_v1(atom.value)
            if key.owner.subject != old["subject_entity_ref"]:
                raise ValueError("D05 migration projection owner differs")
            matching = tuple(item for item in contributions if item.key.owner == key.owner
                and item.value["target_dimension"] == old["dimension"])
            roots = tuple(dict.fromkeys(ref for item in matching for ref in item.value["source_refs"]))
            qualified, dependencies = _migration_source_qualification_v2(snapshot, namespace, roots)
            new = translate_relationship_projection_v2(old,
                source_qualification="qualified" if qualified and atom.valid else "unavailable")
            if old["status"] not in RELATIONSHIP_STATUS_PUBLIC_V1:
                gaps.append((token, "unregistered_legacy_relationship_state"))
            current_items = tuple((item, decode_relationship_contribution_payload_v1(item.value)) for item in matching if item.valid)
            if any(decoded.semantics in {"recollection", "simulation"} for _, decoded in current_items):
                new["influence_status"] = "unapplied_pending"
            if any(decoded.semantics == "recollection" and (
                    (decoded.schema_version == 2 and decoded.identity_status == "legacy_unresolved")
                    or (decoded.schema_version == 1 and not any(material.legacy_source_token == item.key.token
                        for material in authenticated_recollections))) for item, decoded in current_items):
                new["influence_status"] = "legacy_unresolved"
                gaps.append((token, "legacy_unresolved_relationship_history"))
            emit(key, new, dependencies, atom.valid and qualified)
        else:
            raise ValueError("catalogue migration writes only D05 contribution/projection")
    if len(writes) > 64 or len({write.key for write in writes}) != len(writes):
        raise ValueError("D05 migration write batch exceeds registered bound or repeats a target")
    return MigrationBatchV2(tuple(writes), snapshot.versions, batch_tokens, tuple(aliases), tuple(gaps),
        tuple(validity), tuple(retired))


@dataclass(frozen=True)
class BoundaryRule:
    rule_id: str
    subject_persona_ref: str
    target_entity_ref: str
    action_kind: str
    audience_scope: str
    scene_ref: str | None
    effect: str
    basis: str
    source_refs: tuple[str, ...]
    communicated_refs: tuple[str, ...]
    acknowledged_refs: tuple[str, ...]
    valid_from: float
    valid_until: float | None
    scope_version: int
    revision_actor: str
    exception_refs: tuple[str, ...]
    status: str

    def __post_init__(self) -> None:
        _id(self.rule_id, "rule_id", "boundary:")
        _id(self.subject_persona_ref, "subject_persona_ref", "persona:")
        _id(self.target_entity_ref, "target_entity_ref", "entity:")
        _id(self.action_kind, "action_kind")
        _id(self.audience_scope, "audience_scope")
        if self.scene_ref is not None:
            _id(self.scene_ref, "scene_ref", "scene:")
        if self.effect not in {"deny", "allow"}:
            raise ValueError("unsupported boundary effect")
        if self.basis not in {"runtime_policy", "counterparty_explicit", "self_internal", "mutual_agreement", "inferred_preference"}:
            raise ValueError("unsupported boundary basis")
        _refs(self.source_refs, "source_refs")
        if not isinstance(self.communicated_refs, tuple) or not isinstance(self.acknowledged_refs, tuple):
            raise ValueError("boundary receipt refs must be tuples")
        _time(self.valid_from, "valid_from")
        if self.valid_until is not None and _time(self.valid_until, "valid_until") < self.valid_from:
            raise ValueError("valid_until precedes valid_from")
        if type(self.scope_version) is not int or self.scope_version < 1:
            raise ValueError("scope_version must be positive")
        _id(self.revision_actor, "revision_actor")
        if not isinstance(self.exception_refs, tuple):
            raise ValueError("exception_refs must be a tuple")
        if self.status not in {"active", "superseded", "revoked"}:
            raise ValueError("unsupported boundary status")

    def applies_to(self, *, subject_persona_ref: str, target_entity_ref: str,
                   action_kind: str, audience_scope: str, scene_ref: str | None,
                   at_time: float) -> bool:
        return (
            self.status == "active"
            and self.subject_persona_ref == subject_persona_ref
            and self.target_entity_ref == target_entity_ref
            and self.action_kind == action_kind
            and self.audience_scope == audience_scope
            and (self.scene_ref is None or self.scene_ref == scene_ref)
            and self.valid_from <= at_time
            and (self.valid_until is None or at_time <= self.valid_until)
        )


@dataclass(frozen=True)
class BoundaryCheck:
    result: str
    matched_rule_ids: tuple[str, ...]
    missing_items: tuple[str, ...]


@dataclass(frozen=True)
class BoundaryRuleReadSet:
    """One D05 boundary query result, tied to a complete graph read.

    The read verifier is supplied by the trusted graph integration. A caller
    assertion such as ``coverage_complete=True`` is not sufficient evidence.
    ``input_versions`` includes the query-scope epoch and every current rule
    revision returned by that query.
    """

    namespace: NamespaceId
    query_epoch: QueryEpoch | None
    rules: tuple[BoundaryRule, ...]
    input_versions: tuple[VersionedRef, ...]
    coverage: str
    missing_items: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        if self.query_epoch is not None and not isinstance(self.query_epoch, QueryEpoch):
            raise TypeError("query_epoch must be QueryEpoch or None")
        if not isinstance(self.rules, tuple) or any(type(item) is not BoundaryRule for item in self.rules):
            raise TypeError("rules must be a tuple of BoundaryRule values")
        if not isinstance(self.input_versions, tuple) or any(
            type(item) is not VersionedRef for item in self.input_versions
        ):
            raise TypeError("input_versions must be a tuple of VersionedRef values")
        if len({item.ref for item in self.input_versions}) != len(self.input_versions):
            raise ValueError("input_versions cannot repeat a ref")
        if self.coverage not in {"full", "partial", "none"}:
            raise ValueError("coverage must be full, partial, or none")
        if not isinstance(self.missing_items, tuple):
            raise TypeError("missing_items must be a tuple")
        if any(not isinstance(item, str) or not item for item in self.missing_items):
            raise ValueError("missing_items must contain nonempty strings")
        if self.query_epoch is not None and self.query_epoch.namespace != self.namespace:
            raise ValueError("query epoch namespace differs from read namespace")


@dataclass(frozen=True)
class InvalidationResult:
    current_status: str
    historical_refs: tuple[str, ...]


class RelationshipProvider:
    """D05 projection and validation only; W01 owns adoption and epochs."""

    def __init__(self, *, boundary_read_verifier: Callable[[BoundaryRuleReadSet], bool] | None = None) -> None:
        self._dimensions: frozenset[str] = frozenset()
        self._semantics: frozenset[str] = frozenset()
        self._boundary_read_verifier = boundary_read_verifier

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider_id="d05.relationship", contract_version="sylanne.runtime.v1",
            request_schema_hash=schema_hash({"domain": "d05", "request": 1}),
            response_schema_hash=schema_hash({"domain": "d05", "response": 1}),
            owner_capabilities=("persona", "relation"), supported_modalities=("text",),
            supported_purposes=("respond", "check", "project"), supported_platforms=("astrbot",),
            timeout_mode="bounded", cancellation_mode="cooperative", idempotency_mode="operation_id",
            cost_reporting_mode="actual_or_unconfirmed", health_capabilities=("probe",),
            recovery_capabilities=("query_operation",),
        )

    @property
    def workbench_view_contract(self) -> dict[str, dict[str, object]]:
        return {"relations": {
            "types": RELATIONSHIP_WORKBENCH_TYPES_V2,
            "fields": ("relations", "coverage"),
            "projection_context": "d12.projection_context.v2",
        }}

    @staticmethod
    def project_workbench(view_type: str, atoms: tuple[dict, ...], *, context: object) -> dict:
        """Show committed subjective statuses without source or boundary metadata."""
        from ...graph_coordinator import verify_complete_projection_snapshot_v1
        from ...workbench_api.domain_registry import ProjectionContextV2

        types = RELATIONSHIP_WORKBENCH_TYPES_V2
        if view_type != "relations" or type(context) is not ProjectionContextV2:
            raise ValueError("unsupported D05 workbench projection context")
        if not verify_complete_projection_snapshot_v1(
            context.snapshot_proof, authority=context.authority, view_type=view_type,
            type_names=types, owner_kind="relation", audience=context.audience,
            purpose=context.purpose,
        ):
            raise ValueError("complete fenced snapshot proof is unavailable")
        if type(atoms) is not tuple:
            raise TypeError("atoms must be a tuple")

        relations: dict[str, dict] = {}
        seen_dimensions: set[tuple[str, str]] = set()
        for atom in atoms:
            if type(atom) is not dict or set(atom) != {"key", "type", "name", "revision", "value"}:
                raise ValueError("D05 workbench atom has an invalid shape")
            key = AtomKey.from_token(atom["key"])
            atom_type = atom["type"]
            if (key.type_name != atom_type or key.name != atom["name"]
                    or atom_type not in types or key.owner.kind != "relation"
                    or (key.owner.bot, key.owner.persona) != context.authority.namespace.as_tuple
                    or type(atom["revision"]) is not int or atom["revision"] < 1):
                raise ValueError("D05 workbench atom crosses its graph scope")
            value = atom["value"]
            if atom_type != "d05.relationship_projection":
                from .relationship_revision_v2 import PROFILE_TYPE, ESTIMATE_TYPE, RelationshipProfileV2, DimensionEstimateV2
                from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
                cls = RelationshipProfileV2 if atom_type == PROFILE_TYPE else DimensionEstimateV2
                current = decode_typed_production_value_v1(value, cls)
                if current.scope.namespace != context.authority.namespace or current.scope.owner != key.owner:
                    raise ValueError("relationship current estimate/profile crossed its directed namespace")
                if atom_type == PROFILE_TYPE:
                    if key != current.scope.key(PROFILE_TYPE, "profile"):
                        raise ValueError("relationship profile changed its exact aggregate identity")
                    continue
                if key != current.scope.key(ESTIMATE_TYPE):
                    raise ValueError("relationship estimate changed its exact dimension identity")
                subject, dimension = current.scope.subject_entity_ref, current.scope.dimension
                identity = (subject, current.scope.relationship_domain, current.scope.context_ref, dimension)
                if identity in seen_dimensions:
                    raise ValueError("duplicate relationship scoped dimension")
                seen_dimensions.add(identity)
                now = context.trusted_now_utc
                in_time = now is not None and current.valid_from <= now and (current.valid_until is None or now < current.valid_until)
                available = current.status == "current" and in_time
                availability = "blocked_rebuild" if current.status != "current" else "unknown" if now is None else "available" if in_time else "stale"
                time_status = "time_unavailable" if now is None else "current" if in_time else "stale"
                relation = relations.setdefault(subject, {"subject_entity_ref": subject, "dimensions": []})
                relation["dimensions"].append({"dimension": dimension, "domain": current.scope.relationship_domain,
                    "context_id": canonical_digest((current.scope.relationship_domain, current.scope.context_ref))[:32],
                    "status": availability, "availability": availability, "time_status": time_status,
                    "source_qualification": "qualified", "estimate": current.estimate if available else "unknown",
                    "subjective_confidence": current.subjective_confidence if available else None,
                    "evidence_coverage": current.evidence_coverage,
                    "independent_external_families": len(current.independent_families),
                    "influence_status": "bounded_applied" if available else "unapplied_pending"})
                continue
            value = decode_relationship_projection_payload_v1(value)
            subject = value["subject_entity_ref"]
            dimension = value["dimension"]
            if (re.fullmatch(r"entity:[A-Za-z0-9_.:-]{1,96}", subject) is None
                    or re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", dimension) is None):
                raise ValueError("relationship projection scope has no public token")
            if (subject, dimension) in seen_dimensions:
                raise ValueError("duplicate relationship dimension")
            seen_dimensions.add((subject, dimension))
            if key.owner.subject != subject:
                raise ValueError("relation subject differs from graph Owner")
            relation = relations.setdefault(subject, {
                "subject_entity_ref": subject, "dimensions": [],
            })
            public = relationship_projection_public_v2(value)
            if context.audience != "owner":
                public.pop("diagnostic_error", None)
            relation["dimensions"].append(public)
        for relation in relations.values():
            relation["dimensions"].sort(key=lambda item: item["dimension"])
        return {"relations": [relations[subject] for subject in sorted(relations)],
                "coverage": "complete"}

    def type_specs(self) -> tuple[TypeSpec, ...]:
        layouts = (
            (
                "d05.contribution", ("relation",), "state",
                _validate_relationship_contribution_v2,
                tuple(field.name for field in fields(RelationshipContribution)),
            ),
            (
                "d05.boundary_rule", ("relation",), "state",
                lambda value: _strict_payload(
                    value, BoundaryRule, "source_refs", "communicated_refs",
                    "acknowledged_refs", "exception_refs",
                ),
                tuple(field.name for field in fields(BoundaryRule)),
            ),
            (
                "d05.relationship_projection", ("relation",), "projection",
                _validate_relationship_projection,
                tuple(sorted(_PROJECTION_FIELDS_V2)),
            ),
        )
        base_specs = tuple(TypeSpec(
            name,
            owners,
            storage,
            validator,
            writer_domain="d05",
            schema_version=2 if name in {"d05.contribution", "d05.relationship_projection"} else 1,
            schema_hash=schema_hash({
                "type": name,
                "schema_version": 2 if name in {"d05.contribution", "d05.relationship_projection"} else 1,
                "owner_kinds": sorted(owners),
                "storage_role": storage,
                "fields": field_names,
                **({"status_schema": RELATIONSHIP_PROJECTION_STATUS_SCHEMA_V1,
                    "status_public_mapping": RELATIONSHIP_STATUS_PUBLIC_V1}
                   if name == "d05.relationship_projection" else {}),
                **({"kind_semantics": CONTRIBUTION_KINDS_V2,
                    "identity_statuses": ("resolved", "legacy_unresolved")}
                   if name == "d05.contribution" else {}),
            }),
        ) for name, owners, storage, validator, field_names in layouts)
        from .relationship_revision_v2 import relationship_revision_type_specs_v2
        return base_specs + relationship_revision_type_specs_v2()

    def register_types(self) -> tuple[str, ...]:
        return tuple(spec.name for spec in self.type_specs())

    def validate(self, proposal: DomainProposal, snapshot: object) -> DomainProposal:
        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if proposal.domain != "d05":
            raise ValueError("D05 provider cannot validate another domain's candidate")
        if proposal.proposal_schema != "d05.proposal.v1":
            raise ValueError("unsupported D05 proposal schema")
        allowed_types = frozenset(self.register_types())
        if any(write.key.type_name not in allowed_types for write in proposal.typed_writes):
            raise ValueError("D05 candidates may only contain D05 graph writes")
        decoders = {
            "d05.contribution": _validate_relationship_contribution_v2,
            "d05.boundary_rule": lambda value: BoundaryRule(**_tuple_payload(
                value, "source_refs", "communicated_refs", "acknowledged_refs", "exception_refs"
            )),
        }
        for write in proposal.typed_writes:
            if write.key.type_name == "d05.relationship_projection":
                _id(write.value["subject_entity_ref"], "subject_entity_ref", "entity:")
                self.validate_dimension(write.value["dimension"])
                _validate_relationship_projection(write.value)
            elif write.key.type_name in decoders:
                decoders[write.key.type_name](write.value)
            else:
                from .relationship_revision_v2 import _VALUE_TYPES, PROFILE_TYPE, ESTIMATE_TYPE, CONTRIBUTION_TYPE, CHECKPOINT_TYPE, EXPECTATION_TYPE, RECIPROCITY_TYPE, REPAIR_TYPE
                from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
                value = decode_typed_production_value_v1(write.value, _VALUE_TYPES[write.key.type_name])
                if write.key.type_name == CONTRIBUTION_TYPE:
                    expected = value.key
                elif write.key.type_name == CHECKPOINT_TYPE:
                    expected = AtomKey.from_token(value.checkpoint_ref)
                else:
                    suffix = "profile" if write.key.type_name == PROFILE_TYPE else value.expectation_ref if write.key.type_name == EXPECTATION_TYPE else value.pattern_ref if write.key.type_name == RECIPROCITY_TYPE else (value.dispute_ref, value.action_kind) if write.key.type_name == REPAIR_TYPE else ""
                    expected = value.scope.key(write.key.type_name, suffix)
                if write.key != expected or write.key.owner != value.scope.owner:
                    raise ValueError("relationship revision Graph key changed its exact directed scope")
        return proposal

    def compile_scheme(self, draft: dict, snapshot: object) -> dict:
        if not isinstance(draft, dict) or set(draft) != {"schema", "dimensions", "contribution_semantics"}:
            raise ValueError("D05 scheme has an exact shape")
        if draft["schema"] != "d05.relationship.scheme.v1":
            raise ValueError("unsupported D05 scheme")
        dimensions = _refs(draft["dimensions"], "dimensions")
        semantics = _refs(draft["contribution_semantics"], "contribution_semantics")
        if not set(semantics) <= {"external_observation", "recollection", "simulation"}:
            raise ValueError("unsupported scheme contribution semantics")
        self._dimensions = frozenset(dimensions)
        self._semantics = frozenset(semantics)
        return {"schema": draft["schema"], "dimensions": dimensions, "contribution_semantics": semantics}

    def validate_dimension(self, dimension: str) -> None:
        _id(dimension, "dimension")
        if dimension not in self._dimensions:
            raise ValueError("dimension is not registered by the active scheme")

    def provide_required_check(
        self, *, subject_persona_ref: str, target_entity_ref: str, action_kind: str,
        audience_scope: str, scene_ref: str | None, at_time: float,
        rules: tuple[BoundaryRule, ...], coverage_complete: bool,
    ) -> BoundaryCheck:
        _id(subject_persona_ref, "subject_persona_ref", "persona:")
        _id(target_entity_ref, "target_entity_ref", "entity:")
        _id(action_kind, "action_kind")
        _id(audience_scope, "audience_scope")
        if scene_ref is not None:
            _id(scene_ref, "scene_ref", "scene:")
        _time(at_time, "at_time")
        if type(coverage_complete) is not bool:
            raise ValueError("coverage_complete must be bool")
        if not isinstance(rules, tuple) or any(not isinstance(rule, BoundaryRule) for rule in rules):
            raise TypeError("rules must be BoundaryRule values")
        if not coverage_complete:
            return BoundaryCheck("unknown", (), ("boundary_coverage",))
        matches = tuple(rule for rule in rules if rule.applies_to(
            subject_persona_ref=subject_persona_ref, target_entity_ref=target_entity_ref,
            action_kind=action_kind, audience_scope=audience_scope, scene_ref=scene_ref,
            at_time=at_time,
        ))
        denied = tuple(sorted(rule.rule_id for rule in matches if rule.effect == "deny"))
        if denied:
            return BoundaryCheck("deny", denied, ())
        allowed = tuple(sorted(rule.rule_id for rule in matches if rule.effect == "allow"))
        if len(allowed) > 1:
            return BoundaryCheck("conflict", allowed, ("multiple_allow_rules",))
        return BoundaryCheck("pass" if allowed else "pass", allowed, ())

    def boundary_required_check_from_graph(
        self, intent: ActionIntent, schema: ActionSchema, coordinator: object, *,
        authority: object, lease: object, namespace: NamespaceId,
        audience_scope: str, scene_ref: str | None, at_time: float,
        valid_until: float,
    ) -> CheckReceipt:
        """Evaluate D05 boundaries from a complete current relation-owner query.

        The coordinator owns read authorization and deletion fences.  This
        method retains every returned rule version and the range-query epoch;
        D11 still has to recheck both at final admission.
        """
        if type(intent) is not ActionIntent or type(schema) is not ActionSchema:
            raise TypeError("D08 action intent and schema are required")
        if not isinstance(namespace, NamespaceId):
            raise TypeError("namespace is required")
        if not callable(getattr(coordinator, "query", None)):
            raise TypeError("authorized graph coordinator query is required")
        _id(intent.target_ref, "target_ref", "entity:")
        if namespace.persona_id != next(
            (item.subject_ref.removeprefix("persona:")
             for item in intent.required_checks
             if item.check_kind == "boundary" and item.provider_id == "d05.boundary"),
            None,
        ):
            raise ValueError("boundary subject differs from namespace")

        epoch = None
        after = None
        rules = []
        while True:
            page = coordinator.query(
                authority, lease, type_names=("d05.boundary_rule",),
                owner_kind="relation", subject=intent.target_ref,
                after=after, expected_epoch=epoch, limit=512,
            )
            if len(page.snapshot.epochs) != 1:
                raise ValueError("boundary query requires one namespace epoch")
            current_epoch = page.snapshot.epochs[0]
            if (current_epoch.bot, current_epoch.persona) != namespace.as_tuple:
                raise ValueError("boundary query crossed namespace")
            if epoch is None:
                epoch = current_epoch
            elif epoch != current_epoch:
                raise ValueError("boundary query changed epoch")
            for atom in page.snapshot.atoms:
                if (not atom.valid or atom.key.type_name != "d05.boundary_rule"
                        or atom.key.owner.kind != "relation"
                        or (atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple
                        or atom.key.owner.subject != intent.target_ref):
                    raise ValueError("boundary rule escaped its relation scope")
                _strict_payload(
                    atom.value, BoundaryRule, "source_refs", "communicated_refs",
                    "acknowledged_refs", "exception_refs",
                )
                rule = BoundaryRule(**_tuple_payload(
                    atom.value, "source_refs", "communicated_refs",
                    "acknowledged_refs", "exception_refs",
                ))
                if (atom.key.name != rule.rule_id
                        or atom.revision != rule.scope_version
                        or rule.target_entity_ref != intent.target_ref
                        or rule.subject_persona_ref != f"persona:{namespace.persona_id}"):
                    raise ValueError("boundary rule differs from its graph scope or revision")
                rules.append(rule)
            if page.next_after is None:
                break
            if (not page.snapshot.atoms or page.next_after != page.snapshot.atoms[-1].key
                    or page.next_after == after):
                raise ValueError("boundary query pagination is invalid")
            after = page.next_after

        specs = tuple(item for item in intent.required_checks
                      if item.check_kind == "boundary" and item.provider_id == "d05.boundary")
        if len(specs) != 1:
            raise ValueError("action needs one D05 boundary check")
        spec = specs[0]
        criteria = tuple(item for item in spec.required_input_versions
                         if item.ref == spec.criteria_version)
        if len(criteria) != 1:
            raise ValueError("boundary criteria version is missing")
        assert epoch is not None
        observed = tuple(sorted((
            *criteria, VersionedRef("d05.boundary", epoch.revision),
            *(VersionedRef(rule.rule_id, rule.scope_version) for rule in rules),
        ), key=lambda item: item.ref))
        read_set = BoundaryRuleReadSet(
            namespace, QueryEpoch(namespace, "d05.boundary", epoch.revision),
            tuple(rules), observed, "full",
        )
        # The verifier is scoped to this one freshly obtained read.  No caller
        # supplied coverage assertion can turn a different read into a pass.
        checker = RelationshipProvider(boundary_read_verifier=lambda value: value is read_set)
        return checker.boundary_required_check(
            intent, schema, read_set, audience_scope=audience_scope,
            scene_ref=scene_ref, at_time=at_time, valid_until=valid_until,
        )

    def boundary_required_check(
        self,
        intent: ActionIntent,
        schema: ActionSchema,
        read_set: BoundaryRuleReadSet,
        *,
        audience_scope: str,
        scene_ref: str | None,
        at_time: float,
        valid_until: float,
    ) -> CheckReceipt:
        """Return D05's candidate boundary check for D08.

        Passing only means the boundary query is complete/current and no
        applicable D05 rule denies this action. D11 must still revalidate the
        graph and all action qualifications before any real dispatch.
        """
        if type(intent) is not ActionIntent or type(schema) is not ActionSchema:
            raise TypeError("intent and action schema must be D08 values")
        if type(read_set) is not BoundaryRuleReadSet:
            raise TypeError("read_set must be BoundaryRuleReadSet")
        _id(audience_scope, "audience_scope")
        if scene_ref is not None:
            _id(scene_ref, "scene_ref", "scene:")
        timestamp = _time(at_time, "at_time")
        expiry = _time(valid_until, "valid_until")

        check_kind = "boundary"
        provider_id = "d05.boundary"
        schema_specs = tuple(item for item in schema.required_checks
                             if item.check_kind == check_kind and item.provider_id == provider_id)
        intent_specs = tuple(item for item in intent.required_checks
                             if item.check_kind == check_kind and item.provider_id == provider_id)
        if len(schema_specs) != 1 or len(intent_specs) != 1:
            raise ValueError("schema and intent must contain exactly one D05 boundary check")
        spec = schema_specs[0]
        if (schema.schema_id != intent.schema_id or schema.action_kind != intent.action_kind
                or spec != intent_specs[0] or spec.action_ref != intent.action_id
                or spec.purpose != intent.purpose or intent.action_kind != schema.action_kind):
            raise ValueError("D05 boundary check does not match the frozen D08 action")
        _id(spec.subject_ref, "subject_ref", "persona:")
        _id(intent.target_ref, "target_ref", "entity:")

        epoch = read_set.query_epoch
        epoch_version = (VersionedRef("d05.boundary", epoch.revision)
                         if epoch is not None and epoch.scope_ref == "d05.boundary" else None)
        rule_versions = tuple(sorted(
            (VersionedRef(rule.rule_id, rule.scope_version) for rule in read_set.rules),
            key=lambda item: item.ref,
        ))
        graph_versions = tuple(sorted(
            ((VersionedRef(spec.criteria_version,
                           next(item.version for item in spec.required_input_versions
                                if item.ref == spec.criteria_version)),)
             + ((epoch_version,) if epoch_version is not None else ()) + rule_versions),
            key=lambda item: item.ref,
        ))
        observed = read_set.input_versions
        exact_versions = (
            len({item.ref for item in graph_versions}) == len(graph_versions)
            and set(observed) == set(graph_versions)
            and set(observed) == set(spec.required_input_versions)
        )
        scope_matches = (
            read_set.namespace.persona_id == spec.subject_ref.removeprefix("persona:")
            and epoch is not None and epoch.scope_ref == "d05.boundary"
            and all(rule.subject_persona_ref == spec.subject_ref
                    and rule.target_entity_ref == intent.target_ref
                    for rule in read_set.rules)
        )
        trusted_current = False
        if self._boundary_read_verifier is not None:
            try:
                trusted_current = self._boundary_read_verifier(read_set) is True
            except Exception:
                trusted_current = False
        complete = (
            trusted_current and scope_matches and read_set.coverage == "full"
            and not read_set.missing_items and exact_versions
            and expiry >= timestamp
        )
        if not complete:
            coverage = "full" if read_set.coverage == "full" and scope_matches else read_set.coverage
            return CheckReceipt(spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
                                observed, coverage, "unknown", timestamp, provider_id)

        matches = tuple(rule for rule in read_set.rules if rule.applies_to(
            subject_persona_ref=spec.subject_ref,
            target_entity_ref=intent.target_ref,
            action_kind=intent.action_kind,
            audience_scope=audience_scope,
            scene_ref=scene_ref,
            at_time=timestamp,
        ))
        revoked_or_superseded = tuple(
            rule for rule in read_set.rules
            if rule.status in {"revoked", "superseded"}
            and rule.subject_persona_ref == spec.subject_ref
            and rule.target_entity_ref == intent.target_ref
            and rule.action_kind == intent.action_kind
            and rule.audience_scope == audience_scope
            and (rule.scene_ref is None or rule.scene_ref == scene_ref)
            and rule.valid_from <= timestamp
            and (rule.valid_until is None or timestamp <= rule.valid_until)
        )
        if revoked_or_superseded:
            return CheckReceipt(spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
                                spec.required_input_versions, "full", "unknown", timestamp, provider_id)
        # A full current query can prove there is no surviving rule, but it
        # cannot prove why an older no-contact rule disappeared.  Source
        # deletion is not an instruction to initiate contact.  A proactive
        # action needs a current, independently sourced contact setting or
        # permission rule in this exact scope; inbound replies keep their
        # separate frozen non-proactive qualification.
        if schema.proactive and not matches:
            return CheckReceipt(spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
                                spec.required_input_versions, "full", "unknown", timestamp, provider_id)
        denied = tuple(item for item in matches if item.effect == "deny")
        allowed = tuple(item for item in matches if item.effect == "allow")
        if denied and allowed or len(allowed) > 1:
            result = "unknown"
        elif denied:
            result = "fail"
        else:
            result = "pass"
        rule_expiries = tuple(item.valid_until for item in matches if item.valid_until is not None)
        check_expiry = min((expiry, *rule_expiries)) if rule_expiries else expiry
        return CheckReceipt(spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
                            spec.required_input_versions, "full", result, check_expiry, provider_id)

    def invalidate(self, refs: tuple[str, ...]) -> InvalidationResult:
        raise ValueError("D05 invalidation requires a current correction snapshot and W01 adoption")

    def project(self, query: dict, snapshot: tuple[BoundaryRule, ...]) -> BoundaryCheck:
        if not isinstance(query, dict):
            raise TypeError("query must be a mapping")
        return self.provide_required_check(rules=snapshot, **query)

    def cleanup(self, plan: object) -> dict:
        return {"domain": "d05", "status": "delegated_to_runtime", "plan": plan}
