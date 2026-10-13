"""Stable, bounded private-route negative query for a sealed natural call.

The caller owns the Authority fence and SQLite transaction.  A proof must be
stored with the original preparation by that caller; this module never grants
model egress or recreates the original ModelCallRequest.  Its graph epoch is a
read stamp only and is deliberately absent from the comparison identity.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
import math

from ..contracts import canonical_json
from ..domains.d03.context import AccountBinding, RoleBinding, RoleBindingRequest
from ..domains.d05.relationship import BoundaryRule
from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..runtime_contracts import NamespaceId, canonical_digest


SCHEMA = "sylanne.d09.natural-scoped-query-proof.v2"


class NaturalScopedQueryHold(RuntimeError):
    """A private route, matching set, or D06 closure cannot be certified."""


@dataclass(frozen=True, slots=True)
class NaturalPrivateScopeV2:
    namespace: NamespaceId
    platform_ref: str
    sender_ref: str
    target_entity_ref: str
    scene_ref: str
    audience_id: str
    account_binding_ref: str
    role_binding_ref: str
    source_roots: tuple[str, ...]

    def __post_init__(self) -> None:
        if (type(self.namespace) is not NamespaceId
                or any(type(getattr(self, field)) is not str
                       or not getattr(self, field) for field in (
                           "platform_ref", "sender_ref", "target_entity_ref",
                           "scene_ref", "audience_id", "account_binding_ref",
                           "role_binding_ref"))
                or not self.target_entity_ref.startswith("entity:")
                or not self.scene_ref.startswith("scene:")
                or type(self.source_roots) is not tuple
                or not self.source_roots
                or len(set(self.source_roots)) != len(self.source_roots)):
            raise ValueError("complete private route scope required")
        for ref, expected in ((self.account_binding_ref, "d03.account_binding"),
                              (self.role_binding_ref, "d03.role_binding")):
            key = AtomKey.from_token(ref)
            if ((key.owner.bot, key.owner.persona) != self.namespace.as_tuple
                    or key.type_name != expected):
                raise ValueError("route selection crosses namespace or type")
        for ref in self.source_roots:
            key = AtomKey.from_token(ref)
            if key != source_key(*self.namespace.as_tuple, key.owner.subject or ""):
                raise ValueError("source root is not a canonical D06 source")


@dataclass(frozen=True, slots=True, order=True)
class ScopedAtomEvidenceV2:
    token: str
    revision: int
    semantic_digest: str | None

    def __post_init__(self) -> None:
        AtomKey.from_token(self.token)
        if (type(self.revision) is not int or self.revision < 0
                or (self.revision == 0) != (self.semantic_digest is None)):
            raise ValueError("invalid scoped atom version")
        if self.semantic_digest is not None and (
                type(self.semantic_digest) is not str
                or len(self.semantic_digest) != 64
                or any(ch not in "0123456789abcdef"
                       for ch in self.semantic_digest)):
            raise ValueError("invalid scoped atom digest")


@dataclass(frozen=True, slots=True)
class NaturalScopedQueryProofV2:
    scope: NaturalPrivateScopeV2
    account_matches: tuple[ScopedAtomEvidenceV2, ...]
    role_matches: tuple[ScopedAtomEvidenceV2, ...]
    boundary_matches: tuple[ScopedAtomEvidenceV2, ...]
    d06_closure: tuple[ScopedAtomEvidenceV2, ...]
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA or type(self.scope) is not NaturalPrivateScopeV2
                or any(type(group) is not tuple or
                       any(type(item) is not ScopedAtomEvidenceV2 for item in group)
                       or tuple(sorted(group)) != group
                       or len({item.token for item in group}) != len(group)
                       for group in (self.account_matches, self.role_matches,
                                     self.boundary_matches, self.d06_closure))
                or len(self.account_matches) != 1
                or self.account_matches[0].token != self.scope.account_binding_ref
                or len(self.role_matches) != 1
                or self.role_matches[0].token != self.scope.role_binding_ref):
            raise ValueError("complete scoped query proof required")

    @property
    def semantic_digest(self) -> str:
        return canonical_digest(self)


def natural_private_scope_from_binding_v2(
    binding, frozen,
) -> NaturalPrivateScopeV2:
    """Derive the exact private predicate from W01's typed original inputs."""
    from ..model_broker.natural_reply import FrozenNaturalReplyRequestV2
    from ..model_broker.natural_reply_history_v3 import FrozenNaturalReplyRequestV3
    from ..model_broker.natural_reply_history_v4 import FrozenNaturalReplyRequestV4
    from ..model_broker.natural_reply_history_v6 import FrozenNaturalReplyRequestV6
    from ..model_broker.natural_reply_history_v7 import FrozenNaturalReplyRequestV7
    from .reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2

    if (type(binding) is not CurrentReplyEntityRouteBindingV2
            or type(frozen) not in (FrozenNaturalReplyRequestV2, FrozenNaturalReplyRequestV3, FrozenNaturalReplyRequestV4,FrozenNaturalReplyRequestV6,FrozenNaturalReplyRequestV7)):
        raise NaturalScopedQueryHold("typed original route and input required")
    plan = frozen.input.plan
    if (plan.namespace != binding.namespace
            or plan.scene_id != binding.scene_ref
            or plan.audience_id != binding.conversation_ref
            or plan.audience_ref.ref != binding.binding_version.key.token
            or plan.audience_ref.version != binding.binding_version.revision):
        raise NaturalScopedQueryHold("natural plan and private route differ")
    role_key = AtomKey.from_token(plan.scene_ref.ref)
    if ((role_key.owner.bot, role_key.owner.persona) != binding.namespace.as_tuple
            or role_key.type_name != "d03.role_binding"
            or plan.scene_ref.version < 1):
        raise NaturalScopedQueryHold("natural plan role proof is invalid")
    source_refs = tuple(sorted({ref.ref for unit in plan.units
                                if unit.d06_claim_kind is not None
                                for ref in unit.source_refs}))
    if not source_refs:
        raise NaturalScopedQueryHold("D06 source roots missing")
    return NaturalPrivateScopeV2(
        binding.namespace, binding.platform_ref, binding.sender_ref,
        binding.target_entity_ref, binding.scene_ref, binding.conversation_ref,
        binding.binding_version.key.token, plan.scene_ref.ref, source_refs)


def assert_original_scoped_d06_projection_v2(
    proof: NaturalScopedQueryProofV2, frozen,
) -> None:
    """Tie the stored source closure back to the frozen qualified units."""
    from ..model_broker.natural_reply import FrozenNaturalReplyRequestV2
    from ..model_broker.natural_reply_history_v3 import FrozenNaturalReplyRequestV3
    from ..model_broker.natural_reply_history_v4 import FrozenNaturalReplyRequestV4
    from ..model_broker.natural_reply_history_v6 import FrozenNaturalReplyRequestV6
    from ..model_broker.natural_reply_history_v7 import FrozenNaturalReplyRequestV7

    if (type(proof) is not NaturalScopedQueryProofV2
            or type(frozen) not in (FrozenNaturalReplyRequestV2, FrozenNaturalReplyRequestV3, FrozenNaturalReplyRequestV4,FrozenNaturalReplyRequestV6,FrozenNaturalReplyRequestV7)
            or frozen.input.plan.namespace != proof.scope.namespace
            or frozen.input.plan.audience_id != proof.scope.audience_id
            or frozen.input.plan.scene_id != proof.scope.scene_ref
            or frozen.input.plan.scene_ref.ref != proof.scope.role_binding_ref
            or frozen.input.plan.audience_ref.ref
               != proof.scope.account_binding_ref
            or frozen.input.plan.scene_ref.version
               != proof.role_matches[0].revision
            or frozen.input.plan.audience_ref.version
               != proof.account_matches[0].revision):
        raise NaturalScopedQueryHold("stored scope differs from frozen input")
    expected: dict[str, int] = {}
    unit_sources: set[str] = set()
    for unit in frozen.input.plan.units:
        if unit.d06_claim_kind is None:
            continue
        if unit.audience_ref != proof.scope.audience_id:
            raise NaturalScopedQueryHold("D06 unit audience differs")
        unit_sources.update(ref.ref for ref in unit.source_refs)
        for ref in (*unit.source_refs, *unit.access_refs,
                    *unit.correction_refs):
            previous = expected.setdefault(ref.ref, ref.version)
            if previous != ref.version:
                raise NaturalScopedQueryHold("D06 unit repeats a changed ref")
    observed = {item.token: item.revision for item in proof.d06_closure}
    if (not expected or expected != observed
            or proof.scope.source_roots != tuple(sorted(unit_sources))):
        raise NaturalScopedQueryHold("D06 qualified source closure is incomplete")


def natural_scoped_query_proof_from_wire_v2(value: dict) -> NaturalScopedQueryProofV2:
    """Decode a persisted original proof with exact fields; caller authenticates it."""
    if type(value) is not dict or set(value) != {
            field.name for field in fields(NaturalScopedQueryProofV2)}:
        raise ValueError("scoped proof fields differ")
    raw_scope = value["scope"]
    if type(raw_scope) is not dict or set(raw_scope) != {
            field.name for field in fields(NaturalPrivateScopeV2)}:
        raise ValueError("private scope fields differ")
    scope = NaturalPrivateScopeV2(
        **{**raw_scope, "namespace": NamespaceId(**raw_scope["namespace"]),
           "source_roots": tuple(raw_scope["source_roots"])})
    groups = {}
    for name in ("account_matches", "role_matches", "boundary_matches",
                 "d06_closure"):
        rows = value[name]
        if type(rows) is not list:
            raise ValueError("scoped proof group must be a list")
        groups[name] = tuple(ScopedAtomEvidenceV2(**row) for row in rows)
    proof = NaturalScopedQueryProofV2(scope, **groups, schema=value["schema"])
    if json.loads(json.dumps(asdict(proof))) != value:
        raise ValueError("scoped proof wire differs")
    return proof


def _decoded(raw: str) -> dict:
    value = json.loads(raw)
    if type(value) is not dict or canonical_json(value) != raw:
        raise NaturalScopedQueryHold("noncanonical graph atom")
    return value


def _evidence(token: str, revision: int, value: dict) -> ScopedAtomEvidenceV2:
    if type(revision) is not int or revision < 1:
        raise NaturalScopedQueryHold("invalid graph revision")
    return ScopedAtomEvidenceV2(token, revision, canonical_digest(value))


def _current(db, key: AtomKey) -> tuple[int, dict]:
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? "
        "AND persona=? AND type_name=?",
        (key.token, key.owner.bot, key.owner.persona, key.type_name),
    ).fetchone()
    if row is None or row[2] != 1:
        raise NaturalScopedQueryHold("D06 closure atom absent or invalid")
    return row[0], _decoded(row[1])


def _d06_closure(db, scope: NaturalPrivateScopeV2, *, prepared_inventory=None) -> tuple[ScopedAtomEvidenceV2, ...]:
    namespace = scope.namespace
    pending = [AtomKey.from_token(ref).owner.subject for ref in scope.source_roots]
    visited: set[str] = set()
    result: dict[str, ScopedAtomEvidenceV2] = {}
    while pending:
        source_id = pending.pop()
        if source_id in visited:
            continue
        visited.add(source_id)
        if len(visited) > 256:
            raise NaturalScopedQueryHold("D06 source ancestry exceeds bound")
        source = source_key(*namespace.as_tuple, source_id)
        access = access_key(*namespace.as_tuple, source_id)
        correction = source_correction_head_key(namespace, source_id)
        from ..authority_service.current_authority_graph_read_v3 import (
            require_authority_source_metadata_v3)
        authority_source = (require_authority_source_metadata_v3(
            db, namespace, source.token) if prepared_inventory is None else None)
        if authority_source is not None:
            from .dispatch_initial_source_read_v3 import _SourceMetadataRecordV3
            authority_source.require_current_v3()
            source_revision = authority_source.revision
            access_atom = authority_source.work.projection.get(access)
            if not access_atom.valid or access_atom.revision < 1:
                raise NaturalScopedQueryHold("D06 current access is absent")
            access_revision, access_value = access_atom.revision, access_atom.value
            record = _SourceMetadataRecordV3(authority_source.metadata)
        elif prepared_inventory is None:
            source_revision, source_value = _current(db, source)
            access_revision, access_value = _current(db, access)
            record = SourceRecord.from_dict(source_value)
        else:
            from .dispatch_initial_source_read_v3 import _SourceMetadataRecordV3
            witness=prepared_inventory.source_metadata(db,namespace,prepared_inventory.query,source,require_grant=False)
            source_revision=witness.revision
            access_atom=prepared_inventory.projection.get(access)
            if access_atom is None or not access_atom.valid or access_atom.revision<1:
                raise NaturalScopedQueryHold("D06 current access is absent")
            access_revision,access_value=access_atom.revision,access_atom.value
            prepared_inventory.operation.retain(4096)
            record=_SourceMetadataRecordV3(witness.metadata)
        validate_access(access_value)
        if (record.source_id != source_id
                or access_value["source_id"] != source_id
                or access_value["status"] != "active"
                or scope.audience_id not in record.audiences
                or scope.audience_id not in access_value["audiences"]
                or "expression" not in record.purposes
                or "expression" not in access_value["purposes"]):
            raise NaturalScopedQueryHold("D06 source or access is not qualified")
        correction_row = db.execute(
            "SELECT revision,valid FROM graph_atoms WHERE token=? AND bot=? "
            "AND persona=? AND type_name=?",
            (correction.token, *namespace.as_tuple, correction.type_name),
        ).fetchone()
        if correction_row is not None:
            raise NaturalScopedQueryHold("D06 source correction head is present")
        source_evidence = (
            ScopedAtomEvidenceV2(source.token, source_revision,
                authority_source.canonical_semantic_digest)
            if authority_source is not None else
            _evidence(source.token, source_revision, source_value)
            if prepared_inventory is None else
            ScopedAtomEvidenceV2(source.token, source_revision, witness.payload_sha256))
        for item in (source_evidence,
                     _evidence(access.token, access_revision, access_value),
                     ScopedAtomEvidenceV2(correction.token, 0, None)):
            result[item.token] = item
        pending.extend(record.parent_source_ids)
    return tuple(sorted(result.values()))


def read_natural_scoped_query_proof_v2(
    db, scope: NaturalPrivateScopeV2, *, now_utc: float, prepared_inventory=None,
) -> NaturalScopedQueryProofV2:
    """Scan every current D03/D05 row for this private route in one SQLite tx."""
    if (not db.in_transaction or type(scope) is not NaturalPrivateScopeV2
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        raise NaturalScopedQueryHold("current transactional private scope required")
    namespace = scope.namespace
    authority_rows = None
    if prepared_inventory is None:
        from ..authority_service.current_authority_graph_read_v3 import (
            require_authority_graph_type_rows_v3)
        authority_rows = require_authority_graph_type_rows_v3(
            db, namespace, ("d03.account_binding", "d03.role_binding",
                "d05.boundary_rule"), ("token", "revision", "value"))
    if authority_rows is not None:
        rows = tuple((token, revision, value, AtomKey.from_token(token).type_name)
            for token, revision, value in authority_rows)
    elif prepared_inventory is None:
        rows = db.execute(
            "SELECT token,revision,value,type_name FROM graph_atoms WHERE bot=? "
            "AND persona=? AND valid=1 AND type_name IN "
            "('d03.account_binding','d03.role_binding','d05.boundary_rule') "
            "ORDER BY token", namespace.as_tuple,
        ).fetchall()
    else:
        from .dispatch_current_inventory_v3 import PreparedCurrentDispatchInventoryV3
        if type(prepared_inventory)is not PreparedCurrentDispatchInventoryV3:
            raise NaturalScopedQueryHold("actual private full-EOF natural inventory required")
        projection=prepared_inventory.require_current(db,namespace,prepared_inventory.query)
        rows=tuple((atom.key.token,atom.revision,atom.value,atom.key.type_name)
            for atom in projection.atoms_for_types_v3(frozenset({'d03.account_binding','d03.role_binding','d05.boundary_rule'}))if atom.valid)
        rows=tuple(sorted(rows,key=lambda row:row[0]))
    accounts, roles, boundaries = [], [], []
    try:
        role_request = RoleBindingRequest(
            f"persona:{namespace.persona_id}", scope.target_entity_ref,
            None, scope.scene_ref, "expression", "reply", now_utc, True)
        for token, revision, raw, type_name in rows:
            key = AtomKey.from_token(token)
            if ((key.owner.bot, key.owner.persona) != namespace.as_tuple
                    or key.type_name != type_name):
                raise NaturalScopedQueryHold("scanned row identity differs")
            value = _decoded(raw) if prepared_inventory is None and authority_rows is None else raw
            if type_name == "d03.account_binding":
                item = AccountBinding(**value)
                if key.name != item.account_id:
                    raise NaturalScopedQueryHold("account graph identity differs")
                if (item.platform_namespace == scope.platform_ref
                        and item.platform_identifier == scope.sender_ref
                        and item.valid_from <= now_utc
                        and (item.valid_until is None
                             or now_utc < item.valid_until)):
                    if item.entity_id != scope.target_entity_ref:
                        raise NaturalScopedQueryHold("sender account changed entity")
                    accounts.append(_evidence(token, revision, value))
            elif type_name == "d03.role_binding":
                item = RoleBinding(**{
                    **value, "norm_refs": tuple(value["norm_refs"]),
                    "source_refs": tuple(value["source_refs"])})
                if key.name != item.role_binding_id or revision != item.binding_version:
                    raise NaturalScopedQueryHold("role graph identity differs")
                if item.applies_to(role_request):
                    roles.append(_evidence(token, revision, value))
            else:
                item = BoundaryRule(**{
                    **value, **{name: tuple(value[name]) for name in (
                        "source_refs", "communicated_refs", "acknowledged_refs",
                        "exception_refs")}})
                if key.name != item.rule_id or revision != item.scope_version:
                    raise NaturalScopedQueryHold("boundary graph identity differs")
                if item.applies_to(
                        subject_persona_ref=f"persona:{namespace.persona_id}",
                        target_entity_ref=scope.target_entity_ref,
                        action_kind="message", audience_scope=scope.audience_id,
                        scene_ref=scope.scene_ref, at_time=now_utc):
                    if item.effect == "deny":
                        raise NaturalScopedQueryHold("current private route is denied")
                    boundaries.append(_evidence(token, revision, value))
        if (len(accounts) != 1 or accounts[0].token != scope.account_binding_ref
                or len(roles) != 1 or roles[0].token != scope.role_binding_ref
                or len(boundaries) > 1):
            raise NaturalScopedQueryHold("private route matching set is ambiguous")
        return NaturalScopedQueryProofV2(
            scope, tuple(sorted(accounts)), tuple(sorted(roles)),
            tuple(sorted(boundaries)), _d06_closure(db, scope,prepared_inventory=prepared_inventory))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise NaturalScopedQueryHold("private route graph scan is invalid") from exc


def assert_natural_scoped_query_current_v2(
    db, original: NaturalScopedQueryProofV2, *, now_utc: float, prepared_inventory=None,
) -> NaturalScopedQueryProofV2:
    """Return the fresh read only when keys, versions and semantics match.

    The caller must authenticate ``original`` as part of the original sealed
    preparation and hold a live Authority fence across this SQLite read.
    """
    if type(original) is not NaturalScopedQueryProofV2:
        raise NaturalScopedQueryHold("original typed scope proof required")
    current = read_natural_scoped_query_proof_v2(
        db, original.scope, now_utc=now_utc,prepared_inventory=prepared_inventory)
    if current != original:
        raise NaturalScopedQueryHold("private route or D06 closure changed")
    return current


__all__ = [
    "SCHEMA", "NaturalScopedQueryHold", "NaturalPrivateScopeV2",
    "ScopedAtomEvidenceV2", "NaturalScopedQueryProofV2",
    "natural_private_scope_from_binding_v2",
    "assert_original_scoped_d06_projection_v2",
    "natural_scoped_query_proof_from_wire_v2",
    "read_natural_scoped_query_proof_v2",
    "assert_natural_scoped_query_current_v2",
]


def assert_current_natural_producer_scope_v1(db, original, frozen, *, now_utc, read_versions=None):
    """Compose unchanged Source proof with actual live producer verification.

    Producer heads remain in the adopted plan/read set; they are never stored
    as fake Source members of d06_closure. Frozen input fields stay unchanged.
    """
    assert_original_scoped_d06_projection_v2(original, frozen)
    assert_natural_scoped_query_current_v2(db, original, now_utc=now_utc)
    from .natural_producer_qualification_v1 import assert_live_frozen_producer_basis_v1
    required = assert_live_frozen_producer_basis_v1(frozen, now_utc=now_utc)
    if read_versions is not None and any(row not in read_versions for row in required):
        raise NaturalScopedQueryHold("actual producer read set is incomplete")
    return required
