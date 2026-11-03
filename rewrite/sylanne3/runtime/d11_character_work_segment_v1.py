"""Explicit D11 character-work admission and D02's first labor reservation.

B is an ordinary current Owner/W01 preparation. C binds that immutable B to
the mechanically constructed real Life binding; a C candidate is private and
is not claim authority until its real Graph receipt has committed.
"""
from __future__ import annotations
from dataclasses import dataclass, fields
from datetime import datetime, timezone
import json
import math
import weakref

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d02 import BodyDomain, BodyReservation, _reservation
from ..domains.d02.character_labor_v1 import (
    CharacterLaborPolicyV1, CharacterLaborQuoteV1,
    character_labor_policy_from_wire_v1, character_labor_quote_from_wire_v1,
    reserve_character_labor_v1, _positive_ratio,
    character_labor_rebuild_key_v1,
)
from ..graph_types import AtomKey, Owner
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import (
    CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1,
)
from .d11_life_contract_v1 import RECIPE_ID, WORK_KIND
from .issuers import ResourceQuote

PROTOCOL = "source_note_nonpreemptible_segment.v1"
BODY_KIND = "character_labor_body_preparation_v1"
ADMISSION_KIND = "character_labor_admission_v1"
SEGMENT_KIND = "character_work_segment_v1"


def _closed(raw, cls):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(cls)}:
        raise ValueError("exact character-work original fields required")
    return dict(raw)


@dataclass(frozen=True, slots=True)
class PrepareCharacterLaborBodyRequestV1:
    action_intent_ref: str
    policy_ref: str
    policy_revision: int
    clock_mapping_ref: str
    duration_upper: float
    cpu_ceiling_ms: int

    def __post_init__(self):
        if (AtomKey.from_token(self.action_intent_ref).type_name != "d08.action_intent.v1"
                or type(self.policy_ref) is not str or not self.policy_ref
                or type(self.clock_mapping_ref) is not str or not self.clock_mapping_ref
                or type(self.policy_revision) is not int or self.policy_revision < 1
                or type(self.duration_upper) not in (int, float)
                or not math.isfinite(self.duration_upper) or self.duration_upper <= 0
                or type(self.cpu_ceiling_ms) is not int or not 1 <= self.cpu_ceiling_ms <= 60000):
            raise ValueError("labor B needs its exact current policy/clock and unchanged finite CPU ceiling")


@dataclass(frozen=True, slots=True)
class LaborBodyPreparationOriginalV1:
    namespace: NamespaceId
    action_intent_ref: str
    action_intent_digest: str
    action_operation_id: str
    body_prepare_operation_id: str
    activity_id: str
    effect_id: str
    recipe_ref: str
    recipe_revision: int
    recipe_digest: str
    policy: CharacterLaborPolicyV1
    quote: CharacterLaborQuoteV1
    clock_mapping_json: str
    clock_original_json: str
    reservation_ref: str
    reservation_revision: int
    reservation_digest: str
    settlement_ref: str
    receipt_digest: str
    source_refs: tuple[str, ...]
    schema: str = "d02.labor-body-preparation-original.v1"

    def __post_init__(self):
        if (self.schema != "d02.labor-body-preparation-original.v1"
                or type(self.namespace) is not NamespaceId
                or type(self.policy) is not CharacterLaborPolicyV1
                or type(self.quote) is not CharacterLaborQuoteV1
                or self.body_prepare_operation_id != "d02-character-labor-body:" + self.action_operation_id
                or type(self.reservation_revision) is not int or self.reservation_revision < 1
                or type(self.source_refs) is not tuple or not self.source_refs):
            raise ValueError("labor B must retain its actual first reservation and committed A")
        q, p = self.quote, self.policy
        if ((q.namespace, q.activity_id, q.effect_id, q.policy_ref, q.policy_revision, q.policy_digest)
                != (self.namespace, self.activity_id, self.effect_id, p.policy_ref, p.revision, canonical_digest(plain_v1(p)))
                or (p.namespace, p.recipe_ref, p.recipe_revision, p.recipe_digest)
                != (self.namespace, self.recipe_ref, self.recipe_revision, self.recipe_digest)
                or canonical_digest(json.loads(self.clock_original_json)) != q.clock_original_digest):
            raise ValueError("labor B policy, quote, recipe or original role clock changed")
        from .clock import _mapping_from_dict
        mapping = _mapping_from_dict(json.loads(self.clock_mapping_json))
        if (mapping.mapping_id, mapping.version) != (q.clock_mapping_ref, q.clock_mapping_version):
            raise ValueError("labor B clock locator and signed original differ")
        if (AtomKey.from_token(self.reservation_ref).type_name != "d02.reservation.v1"
                or AtomKey.from_token(self.settlement_ref).type_name != "d02.settlement.v1"):
            raise ValueError("labor B must name its actual single D02 reservation and settlement")


def labor_body_preparation_from_wire_v1(raw):
    value = _closed(raw, LaborBodyPreparationOriginalV1)
    value["namespace"] = NamespaceId(**value["namespace"])
    value["policy"] = character_labor_policy_from_wire_v1(value["policy"])
    value["quote"] = character_labor_quote_from_wire_v1(value["quote"])
    value["source_refs"] = tuple(value["source_refs"])
    return LaborBodyPreparationOriginalV1(**value)


@dataclass(frozen=True, slots=True)
class CharacterLaborAdmissionV1:
    namespace: NamespaceId
    admission_ref: str
    admission_operation_id: str
    binding_digest: str
    prepared_original_ref: str
    execution_id: str
    action_operation_id: str
    body_preparation_ref: str
    body_preparation_digest: str
    policy_digest: str
    quote_digest: str
    reservation_ref: str
    reservation_revision: int
    reservation_digest: str
    body_state_version: int
    parent_budget_lease_ref: str
    clock_original_digest: str
    owner_guard_digest: str
    source_epoch: int
    deletion_epoch: int
    expires_at_utc: float
    recipe_version: int = 2
    executor_protocol: str = PROTOCOL
    schema: str = "d11.character-labor-admission.v1"

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId
                or self.schema != "d11.character-labor-admission.v1"
                or self.executor_protocol != PROTOCOL or self.recipe_version != 2
                or self.admission_ref != "character-labor-admission:" + self.execution_id
                or type(self.reservation_revision) is not int or self.reservation_revision < 1
                or type(self.body_state_version) is not int or self.body_state_version < 1
                or any(type(n) is not int or n < 0 for n in (self.source_epoch, self.deletion_epoch))
                or not math.isfinite(self.expires_at_utc) or self.expires_at_utc <= 0):
            raise ValueError("labor C needs an explicit reverse-bound v2 recipe and actual reservation")
        for name in ("binding_digest", "body_preparation_digest", "policy_digest", "quote_digest",
                "reservation_digest", "clock_original_digest", "owner_guard_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("labor admission loses an authentic original commitment")


def character_labor_admission_from_wire_v1(raw):
    value = _closed(raw, CharacterLaborAdmissionV1)
    value["namespace"] = NamespaceId(**value["namespace"])
    return CharacterLaborAdmissionV1(**value)


@dataclass(frozen=True, slots=True)
class CharacterLaborBodyStageV1:
    stage: object
    request: PrepareCharacterLaborBodyRequestV1
    root: object
    resource_quote: ResourceQuote
    policy: CharacterLaborPolicyV1
    quote: CharacterLaborQuoteV1
    reservation: BodyReservation
    clock_mapping_json: str
    clock_original_json: str


def _refs(namespace, activity, operation):
    tag = canonical_digest((namespace, operation))[:48]
    owner = Owner("activity", *namespace.as_tuple, activity)
    return (AtomKey(owner, "d02.reservation.v1", "character-labor:" + tag),
        AtomKey(owner, "d02.settlement.v1", "character-labor:" + tag))


def read_plan_character_labor_body_v1(db, *, namespace, activity_id, operation_id,
        request, now_utc, installed_readers=None):
    from .d01_production_operations_v1 import raw_head_value_v1
    from .d11_life_product_adapter_v1 import raw_life_original_v1, life_inventory_read_inputs_v1, LIFE_CURRENT_TYPES
    from .d11_life_scope_v1 import life_scope_from_action_v1
    if type(request) is not PrepareCharacterLaborBodyRequestV1:
        raise TypeError("exact explicit labor B request required")
    action = raw_head_value_v1(db, namespace, AtomKey.from_token(request.action_intent_ref))
    if action is None:
        raise MissingProductionOriginalV1("current_character_labor_action_A")
    root = raw_life_original_v1(db, namespace, "source_note_action",
        "life-root:" + action["identity"]["operation_id"])
    if root is None:
        raise MissingProductionOriginalV1("actual_character_labor_root_A")
    scope = life_scope_from_action_v1(db, namespace=namespace, action_ref=request.action_intent_ref,
        project_ref=root["project_ref"], input_source_ref=root["input_source_ref"],
        audiences=root["audiences"], now_utc=now_utc)
    keys, roots, originals = life_inventory_read_inputs_v1(db, namespace=namespace, scope=scope)
    keys.extend((AtomKey.from_token(root["project_ref"]), AtomKey.from_token(root["recipe_ref"]),
        AtomKey.from_token(request.action_intent_ref), *_refs(namespace, activity_id, operation_id)))
    roots.append(root["input_source_ref"])
    originals.extend((request.policy_ref, request.clock_mapping_ref, "life-root:" + root["action_operation_id"]))
    return production_read_plan_v1((*LIFE_CURRENT_TYPES, "d02.character_labor_rebuild_head.v1"),
        keys, roots, originals)


def _policy(readers, read, db, policy_ref, revision):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    columns = ("policy_ref", "revision", "kind", "payload_json", "payload_digest", "signature")
    row = _producer_original_point_v3(db, table="graph_d02_production_policies_v1", columns=columns,
        key_columns=("bot", "persona", "policy_ref", "revision"),
        key=(*read.frame.envelope.authority.namespace.as_tuple, policy_ref, revision),
        legacy_reader=lambda: db.execute("SELECT " + ",".join(columns) +
            " FROM graph_d02_production_policies_v1 WHERE bot=? AND persona=? AND policy_ref=? AND revision=?",
            (*read.frame.envelope.authority.namespace.as_tuple, policy_ref, revision)).fetchone())
    if row is None:
        raise MissingProductionOriginalV1("current_explicit_character_labor_policy")
    value, _ = readers._policy(read, row)
    if type(value) is not CharacterLaborPolicyV1:
        raise TypeError("ordinary Fixed Body policy cannot issue continuous labor")
    return value


def _recipe(read, db, policy):
    recipe = read.head(db, policy.recipe_ref, required=True)
    expected = {"recipe_id": RECIPE_ID, "version": 2, "reality": "real_execution",
        "allowed_steps": ["source_note"], "preemptible": False}
    if ((recipe.revision, canonical_digest(recipe.value)) != (policy.recipe_revision, policy.recipe_digest)
            or recipe.value != expected or policy.work_kind != WORK_KIND or policy.reality != "real_execution"):
        raise ValueError("labor requires the formally adopted nonpreemptible SourceNote v2 recipe")
    return recipe


def stage_prepare_character_labor_body_in_transaction_v1(db, *, frame, request, installed_readers):
    from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
    from .d08_source_note_action_v1 import require_source_note_action_original_v1
    from .joint_node_execution_v1 import require_joint_bound_action_gate_v1
    from .d10_offline_tick_execution_v1 import read_current_offline_clock_reference_v1
    from .d11_role_clock_installation_v1 import read_current_role_clock_installation_v1
    from .clock import _mapping_dict
    if type(request) is not PrepareCharacterLaborBodyRequestV1 or type(installed_readers) is not InstalledD02ProductionReadersV1:
        raise TypeError("exact installed D02 reader and labor B request required")
    read = CurrentDomainReadV1(frame); read.check(db)
    ns, identity = frame.envelope.authority.namespace, frame.envelope.identity
    require_joint_bound_action_gate_v1(db, namespace=ns, action_ref=request.action_intent_ref,
        issuer=installed_readers.issuer, frame=frame)
    root = require_source_note_action_original_v1(db, namespace=ns,
        action_intent_ref=request.action_intent_ref, issuer=installed_readers.issuer, frame=frame,
        installed_bundle=installed_readers.installed_bundle,
        body_quote_authority=installed_readers.body_quote_authority)
    if (identity.operation_id != "d02-character-labor-body:" + root.action_operation_id
            or (identity.activity_id, identity.effect_id) != (root.activity_id, root.effect_id)
            or not set(frame.envelope.authority.audience) <= set(root.audiences)):
        raise ValueError("labor B changed its committed A, effect, or allowed audiences")
    for audience in root.audiences:
        for purpose in ("context", "consolidation"):
            read.source_family(db, (root.input_source_ref,), purpose=purpose, audience=audience)
    policy = _policy(installed_readers, read, db, request.policy_ref, request.policy_revision)
    _recipe(read, db, policy)
    profile, state, reservations = installed_readers._current_body(db, read, policy.profile_id)
    census = installed_readers.require_labor_census_v1(db, read, state)
    if policy.work_kind not in profile.work_kinds or any(
            not set(dict(c.fatigue_rates)) <= set(state.fatigue) for c in policy.duration_components):
        raise ValueError("labor policy changed actual Body work kind or fatigue axes")
    head = read.head(db, character_labor_rebuild_key_v1(ns, state.profile_id))
    if (not head.revision or not head.valid or head.value["status"] != "current"
            or head.value["processed_cursor"] != state.cursor
            or head.value["body_state_version"] != state.version
            or head.value["body_state_digest"] != canonical_digest(state)
            or head.value["originals_root"] != character_labor_census_duration_root_v1(census)
            or (head.value["source_epoch"],head.value["deletion_epoch"])
                != (frame.envelope.version_guard.access_epoch,frame.envelope.version_guard.delete_epoch)):
        raise MissingProductionOriginalV1("confirmed_current_character_resource_cursor")
    mapping = read_current_role_clock_installation_v1(installed_readers.role_clock_reader, db, ns)
    actual_mapping, clock_original = read_current_offline_clock_reference_v1(db, namespace=ns,
        issuer=installed_readers.issuer)
    if actual_mapping != mapping or request.clock_mapping_ref != mapping.mapping_id:
        raise ValueError("labor B differs from the actual current Owner role clock")
    duration = request.duration_upper
    if duration > policy.duration_upper:
        raise ValueError("labor request exceeds the explicit policy duration ceiling")
    now_text = datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace("+00:00", "Z")
    mapping.character_at(now_text)
    expiry = min(frame.envelope.deadline_utc, policy.valid_until_utc,
        datetime.fromisoformat(mapping.valid_until_utc.replace("Z", "+00:00")).timestamp())
    if expiry <= frame.now_utc:
        raise ValueError("labor B cannot renew expired policy, clock, or command")
    reservation_key, settlement_key = _refs(ns, identity.activity_id, identity.operation_id)
    if read.head(db, reservation_key).revision or read.head(db, settlement_key).revision:
        raise ValueError("labor B reservation identity has already been adopted")
    technical = ResourceQuote("resource-quote:character-labor:" + canonical_digest((ns, identity.operation_id)), 1,
        *ns.as_tuple, identity.activity_id, identity.operation_id, identity.effect_id,
        frame.envelope.parent_budget_lease_ref, WORK_KIND, "graph:" + canonical_digest(frame.snapshot),
        frame.envelope.deadline_utc, "resource:character-labor:" + identity.operation_id, None, (),
        (settlement_key.token,), {"cpu_ms": request.cpu_ceiling_ms}, None, frame.envelope.deadline_utc)
    ceiling = math.fsum((*[c.energy_cost for c in policy.fixed_components],
        *[_positive_ratio((c.energy_drain_rate, duration), ()) for c in policy.duration_components]))
    quote = CharacterLaborQuoteV1("character-labor-quote:" + canonical_digest((ns, identity.operation_id)),
        ns, policy.policy_ref, policy.revision, canonical_digest(plain_v1(policy)),
        state.profile_id, state.version, identity.activity_id, identity.effect_id,
        frame.envelope.parent_budget_lease_ref, technical.quote_id, technical.version,
        canonical_digest(technical), mapping.mapping_id, mapping.version,
        canonical_digest(json.loads(clock_original)), duration, ceiling, expiry)
    reservation = reserve_character_labor_v1(state, reservations, quote,
        reservation_id=reservation_key.name, now_utc=frame.now_utc)
    write = BodyDomain.reservation_write(ns, identity.activity_id, reservation)
    domain = BodyDomain()
    primary = stage_result_v1(frame, "d02", "prepare_character_labor_body", request, writes=(write,),
        provenance={"character_labor_resource_quote": technical, "character_labor_quote": quote,
            "character_labor_policy": policy, "character_labor_action_ref": root.action_intent_ref},
        proposal_schema="d02.proposal.v1", proposal_hash=domain.descriptor.request_schema_hash)
    domain.validate(primary.proposals[0], frame.snapshot)
    return CharacterLaborBodyStageV1(primary, request, root, technical, policy, quote, reservation,
        canonical_serialize(_mapping_dict(mapping)), clock_original)


def issue_character_labor_quotes_before_cas_v1(db, *, frame, staged, installed_readers):
    if type(staged) is not CharacterLaborBodyStageV1:
        raise TypeError("actual independently constructed labor B stage required")
    rebuilt = stage_prepare_character_labor_body_in_transaction_v1(db, frame=frame,
        request=staged.request, installed_readers=installed_readers)
    if rebuilt != staged:
        raise ValueError("labor B changed before its actual first reservation CAS")
    installed_readers.issuer.resource_issuer.issue_quote(db, staged.resource_quote)


def record_character_labor_body_preparation_after_cas_v1(db, *, frame, staged, receipt, issuer):
    from .foreground_command_writer_outputs_v3 import record_foreground_writer_life_v3
    if type(staged) is not CharacterLaborBodyStageV1:
        raise TypeError("actual labor B stage required")
    write = staged.stage.proposals[0].typed_writes[0]
    if len(receipt.write_versions) != 1 or receipt.write_versions[0].key != write.key:
        raise ValueError("labor B must adopt exactly its actual unique reservation")
    root, q, p = staged.root, staged.quote, staged.policy
    original = LaborBodyPreparationOriginalV1(staged.stage.namespace,
        root.action_intent_ref, root.action_intent_digest, root.action_operation_id,
        frame.envelope.identity.operation_id, root.activity_id, root.effect_id,
        p.recipe_ref, p.recipe_revision, p.recipe_digest, p, q, staged.clock_mapping_json,
        staged.clock_original_json, write.key.token, receipt.write_versions[0].revision,
        canonical_digest(write.value), staged.resource_quote.d02_settlement_refs[0],
        canonical_digest(receipt), (root.input_source_ref,))
    return record_foreground_writer_life_v3(db, issuer=issuer, namespace=original.namespace,
        kind=BODY_KIND, ref="character-labor-body:" + original.body_prepare_operation_id,
        operation_id=original.body_prepare_operation_id, value=original,
        recorder=record_character_labor_body_preparation_after_cas_v1,
        frame=frame, actual_receipt=receipt)


def require_character_labor_body_preparation_v1(db, *, namespace, operation_id, issuer):
    from .d11_life_preparation_v1 import _read
    from .d04_root_original_store_v1 import _receipt
    saved = _read(db, issuer=issuer, namespace=namespace, kind=BODY_KIND,
        ref="character-labor-body:" + operation_id)
    if saved is None:
        raise MissingProductionOriginalV1("actual_signed_character_labor_B")
    original = labor_body_preparation_from_wire_v1(saved[0])
    receipt = _receipt(db, namespace, operation_id)
    if (saved[1] != operation_id or original.namespace != namespace
            or original.body_prepare_operation_id != operation_id
            or canonical_digest(receipt) != original.receipt_digest
            or len(receipt.write_versions) != 1
            or (receipt.write_versions[0].key.token, receipt.write_versions[0].revision)
                != (original.reservation_ref, original.reservation_revision)):
        raise ValueError("signed labor B lost its actual one-reservation Graph receipt")
    return original


class _CharacterLaborAdmissionCandidateV1:
    __slots__ = ("frame", "prepared", "body", "admission", "identity", "__weakref__")

    def __init__(self, frame, prepared, body, admission):
        self.frame, self.prepared, self.body, self.admission = frame, prepared, body, admission
        self.identity = object()


_CANDIDATES = weakref.WeakKeyDictionary()


def prepare_character_labor_admission_v1(db, *, frame, prepared, body_preparation, installed_readers):
    from .d11_life_preparation_v1 import D11CharacterLaborLifePreparedV1
    from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
    if type(installed_readers) is not InstalledD02ProductionReadersV1:
        raise TypeError("labor C requires the actual installed D02 Body reader")
    if type(prepared) is not D11CharacterLaborLifePreparedV1:
        raise TypeError('exact new character-labor Prepared required; old Fixed cannot upgrade')
    if type(body_preparation) is not LaborBodyPreparationOriginalV1:
        raise TypeError("actual signed labor B original required")
    read = CurrentDomainReadV1(frame); read.check(db)
    b, p = prepared.binding, prepared.plan
    body = require_character_labor_body_preparation_v1(db, namespace=b.namespace,
        operation_id=body_preparation.body_prepare_operation_id, issuer=installed_readers.issuer)
    if body != body_preparation:
        raise ValueError("labor C did not retain its actual signed B")
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    if p.labor_body_preparation_original != ProductionOriginalRefV1("d11.life_" + BODY_KIND,
            "character-labor-body:" + body.body_prepare_operation_id, canonical_digest(plain_v1(body))):
        raise ValueError("new labor plan does not reference the actual signed first reservation")
    if (b.owner_grant_ref, b.owner_grant_revision, b.owner_grant_digest) != (
            frame.owner_guard.grant_ref, frame.owner_guard.grant_revision, frame.owner_guard.grant_digest):
        raise ValueError("labor C changed its actual current Owner")
    for audience in p.audiences:
        for purpose in ("context", "consolidation"):
            read.source_family(db, body.source_refs, purpose=purpose, audience=audience)
    if (p.recipe_version != 2 or p.recipe_id != RECIPE_ID or p.body_effect_request_json is not None
            or frame.envelope.identity.operation_id != b.prepare_operation_id
            or body.action_operation_id != b.operation_id
            or (body.activity_id, body.effect_id, body.namespace) != (b.activity_id, b.effect_id, b.namespace)
            or body.policy.executor_protocol != PROTOCOL
            or (p.recipe.ref, p.recipe.revision, p.recipe.digest)
                != (body.recipe_ref, body.recipe_revision, body.recipe_digest)):
        raise ValueError("labor C cannot upgrade an old Fixed plan or a different real A/B/recipe")
    _recipe(read, db, body.policy)
    reservation = read.head(db, body.reservation_ref, required=True)
    _, state, _ = installed_readers._current_body(db, read, body.quote.profile_id)
    if ((reservation.revision, canonical_digest(reservation.value))
                != (body.reservation_revision, body.reservation_digest)
            or state.version != body.quote.state_version
            or frame.envelope.parent_budget_lease_ref != body.quote.parent_budget_lease_ref
            or b.parent_budget_lease_ref != body.quote.parent_budget_lease_ref
            or canonical_digest(json.loads(prepared.clock_original_json)) != body.quote.clock_original_digest):
        raise ValueError("labor C changed B's Body state, first reservation, parent lease or clock")
    actual_quote = installed_readers.issuer.resource_issuer.original_signed_quote(db,
        body.quote.technical_quote_ref, body.quote.technical_quote_version)
    if canonical_digest(actual_quote) != body.quote.technical_quote_digest or actual_quote.ceiling.get("cpu_ms", 0) < b.cpu_ceiling_ms:
        raise ValueError("labor C lost its actual B technical resource quote")
    guard = frame.envelope.version_guard
    expiry = min(body.quote.valid_until_utc, frame.envelope.deadline_utc,
        datetime.fromisoformat(b.deadline_utc.replace("Z", "+00:00")).timestamp())
    if frame.now_utc >= expiry:
        raise ValueError("labor C cannot renew its original preparation deadline")
    admission = CharacterLaborAdmissionV1(b.namespace, "character-labor-admission:" + b.execution_id,
        b.prepare_operation_id, b.digest, b.prepared_original_ref, b.execution_id, b.operation_id,
        "character-labor-body:" + body.body_prepare_operation_id, canonical_digest(plain_v1(body)),
        canonical_digest(plain_v1(body.policy)), canonical_digest(body.quote), body.reservation_ref,
        body.reservation_revision, body.reservation_digest, state.version, b.parent_budget_lease_ref,
        body.quote.clock_original_digest, canonical_digest(frame.owner_guard),
        guard.access_epoch, guard.delete_epoch, expiry)
    candidate = _CharacterLaborAdmissionCandidateV1(frame, prepared, body, admission)
    _CANDIDATES[candidate] = candidate.identity
    return candidate


def require_character_labor_admission_candidate_v1(candidate, *, db, frame, prepared):
    if (type(candidate) is not _CharacterLaborAdmissionCandidateV1
            or _CANDIDATES.get(candidate) is not candidate.identity
            or candidate.frame is not frame or candidate.prepared is not prepared or not db.in_transaction):
        raise ValueError("labor evaluation requires this actual W01 frame's private C candidate")
    CurrentDomainReadV1(frame).check(db)
    return candidate.admission, candidate.body


def _require_character_labor_candidate_after_cas_v1(candidate, *, db, frame, receipt):
    from .d04_root_original_store_v1 import _receipt
    from ..runtime_contracts import CommitReceipt
    from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
    from .c09_paged_sql_v2 import current_c09_sql_meter_v2
    if (type(candidate) is not _CharacterLaborAdmissionCandidateV1
            or _CANDIDATES.get(candidate) is not candidate.identity
            or candidate.frame is not frame or not db.in_transaction
            or type(receipt) is not CommitReceipt or receipt.status != "committed"
            or candidate.prepared.binding.prepare_operation_id != receipt.operation_id
            or frame.envelope.identity.operation_id != receipt.operation_id):
        raise ValueError("labor C recorder requires its actual private candidate and committed transaction")
    ns = frame.envelope.authority.namespace
    if _receipt(db, ns, receipt.operation_id) != receipt:
        raise ValueError("labor C recorder differs from the actual saved bundle/event receipt")
    expected = {v.key.token:v.revision for v in frame.envelope.version_guard.read_versions}
    actual = {v.key.token:v.revision for v in receipt.read_versions}
    if (len(expected) != len(frame.envelope.version_guard.read_versions)
            or len(actual) != len(receipt.read_versions) or actual != expected
            or any(actual.get(v.key.token) != v.revision for v in frame.snapshot.versions)):
        raise ValueError("labor C actual receipt lost its complete original read-set")
    epochs = receipt.invalidated_epochs
    if (len(epochs) != 1 or (epochs[0].bot_id, epochs[0].persona_id) != ns.as_tuple
            or epochs[0].revision != frame.snapshot.epochs[0].revision + 1):
        raise ValueError("labor C recorder must follow this frame's exact E+1 commit")
    meter = current_c09_sql_meter_v2()
    epoch = _runtime_bounded_fixed_row_v3(db,meter,"graph_epochs",("revision",),
        "bot=? AND persona=?",ns.as_tuple)
    rights = _runtime_bounded_fixed_row_v3(db,meter,"graph_authority_epochs",("access_epoch","delete_epoch"),
        "bot=? AND persona=?",ns.as_tuple)
    guard = frame.envelope.version_guard
    if epoch != (epochs[0].revision,) or rights != (guard.access_epoch,guard.delete_epoch):
        raise ValueError("labor C current commit/Source authority epoch changed before signing")
    if not receipt.write_versions:
        raise ValueError("labor C has no actual committed prepared job write")
    for version in receipt.write_versions:
        if NamespaceId.from_key(version.key) != ns:
            raise ValueError("labor C wrote another namespace")
        current = _runtime_bounded_fixed_row_v3(db,meter,"graph_atoms",("revision","valid"),
            "token=? AND bot=? AND persona=?",(version.key.token,*ns.as_tuple))
        history = _runtime_bounded_fixed_row_v3(db,meter,"graph_history",
            ("event_bot","event_persona","event_session","event_id","valid"),
            "token=? AND revision=?",(version.key.token,version.revision))
        if (current is None or current[0] != version.revision or history is None
                or history[:4] != (*ns.as_tuple,frame.envelope.identity.activity_id,receipt.operation_id)
                or history[4] != current[1]):
            raise ValueError("labor C write/head/history is not its actual same-operation output")
    return candidate.admission, candidate.body


def record_character_labor_admission_after_cas_v1(db, *, frame, candidate, receipt, issuer):
    from .foreground_command_writer_outputs_v3 import record_foreground_writer_life_v3
    admission, body = _require_character_labor_candidate_after_cas_v1(candidate,
        db=db, frame=frame, receipt=receipt)
    if receipt.operation_id != admission.admission_operation_id:
        raise ValueError("labor C receipt belongs to another actual preparation")
    value = {"schema": "d11.character-labor-admission-original.v1",
        "admission": plain_v1(admission), "body_preparation_digest": canonical_digest(plain_v1(body)),
        "receipt_digest": canonical_digest(receipt)}
    result = record_foreground_writer_life_v3(db, issuer=issuer, namespace=admission.namespace,
        kind=ADMISSION_KIND, ref=admission.admission_ref, operation_id=admission.admission_operation_id,
        value=value, recorder=record_character_labor_admission_after_cas_v1, frame=frame, actual_receipt=receipt)
    _CANDIDATES.pop(candidate)
    return result


def require_committed_character_labor_admission_v1(db, *, prepared, issuer):
    from .d11_life_preparation_v1 import _read, D11CharacterLaborLifePreparedV1
    from .d04_root_original_store_v1 import _receipt
    if type(prepared) is not D11CharacterLaborLifePreparedV1:
        raise TypeError("new exact character-labor Prepared required")
    if prepared.labor_admission_ref is None or prepared.labor_admission_digest is None:
        raise MissingProductionOriginalV1("persisted_character_labor_C_admission")
    b = prepared.binding
    saved = _read(db, issuer=issuer, namespace=b.namespace, kind=ADMISSION_KIND,
        ref=prepared.labor_admission_ref)
    if saved is None:
        raise MissingProductionOriginalV1("signed_character_labor_admission_original")
    raw = saved[0]
    if (type(raw) is not dict or set(raw) != {"schema", "admission",
                "body_preparation_digest", "receipt_digest"}
            or raw["schema"] != "d11.character-labor-admission-original.v1"
            or canonical_digest(raw) != prepared.labor_admission_digest):
        raise ValueError("character-labor C original changed its closed signed commitment")
    admission = character_labor_admission_from_wire_v1(raw["admission"])
    receipt = _receipt(db, b.namespace, b.prepare_operation_id)
    if (saved[1] != b.prepare_operation_id or admission.admission_operation_id != b.prepare_operation_id
            or admission.admission_ref != prepared.labor_admission_ref
            or admission.binding_digest != b.digest or admission.execution_id != b.execution_id
            or admission.prepared_original_ref != b.prepared_original_ref
            or canonical_digest(receipt) != raw["receipt_digest"]):
        raise ValueError("labor admission lost its exact actual binding and C Graph receipt")
    original = prepared.plan.labor_body_preparation_original
    operation = original.original_ref.removeprefix("character-labor-body:")
    body = require_character_labor_body_preparation_v1(db, namespace=b.namespace,
        operation_id=operation, issuer=issuer)
    digest = canonical_digest(plain_v1(body))
    if (digest != raw["body_preparation_digest"] or digest != original.original_digest
            or digest != admission.body_preparation_digest
            or body.action_operation_id != b.operation_id
            or canonical_digest(plain_v1(body.policy)) != admission.policy_digest
            or canonical_digest(body.quote) != admission.quote_digest
            or admission.reservation_ref != body.reservation_ref):
        raise ValueError("labor admission and its signed plan disagree about the unique B reservation")
    return admission, body


@dataclass(frozen=True, slots=True)
class CharacterWorkSegmentOriginalV1:
    namespace: NamespaceId
    effect_id: str
    execution_id: str
    segment_id: str
    binding_digest: str
    prepared_digest: str
    admission_ref: str
    admission_original_digest: str
    body_preparation_ref: str
    body_preparation_digest: str
    recipe_ref: str
    recipe_revision: int
    recipe_digest: str
    policy_digest: str
    component_ids: tuple[str, ...]
    channel_id: str
    executor_protocol: str
    algorithm_build_digest: str
    clock_mapping_ref: str
    clock_mapping_version: int
    clock_original_digest: str
    claim_original_ref: str
    claim_sequence: int
    claim_digest: str
    terminal_original_ref: str | None
    terminal_sequence: int | None
    terminal_digest: str | None
    started_at_utc: str
    from_character: str
    ended_at_utc: str | None
    to_character: str | None
    status: str
    signature: str
    schema: str = "d11.character-work-segment-original.v1"

    def __post_init__(self):
        from decimal import Decimal
        from .d11_offline_originals_v1 import _utc
        from .d11_life_contract_v1 import _digest, _text
        for name in ("binding_digest", "prepared_digest", "admission_original_digest",
                "body_preparation_digest", "recipe_digest", "policy_digest",
                "algorithm_build_digest", "clock_original_digest", "signature"):
            _digest(getattr(self, name))
        for name in ("effect_id", "execution_id", "admission_ref", "body_preparation_ref",
                "recipe_ref", "clock_mapping_ref", "claim_original_ref", "from_character"):
            _text(getattr(self, name))
        if not self.claim_digest.startswith("sha256:"):
            raise ValueError("character-work claim must retain its real journal chain digest")
        _digest(self.claim_digest[7:])
        if self.terminal_digest is not None:
            if not self.terminal_digest.startswith("sha256:"):
                raise ValueError("character-work terminal must retain its real journal chain digest")
            _digest(self.terminal_digest[7:])
        if self.to_character is not None:
            _text(self.to_character)
        if (self.schema != "d11.character-work-segment-original.v1"
                or type(self.namespace) is not NamespaceId or self.executor_protocol != PROTOCOL
                or self.channel_id != "main_focus"
                or type(self.component_ids) is not tuple or not 1 <= len(self.component_ids) <= 16
                or len(set(self.component_ids)) != len(self.component_ids)
                or type(self.claim_sequence) is not int or self.claim_sequence < 1
                or type(self.recipe_revision) is not int or self.recipe_revision < 1
                or type(self.clock_mapping_version) is not int or self.clock_mapping_version < 1
                or self.status not in {"active", "completed", "failed", "unknown"}):
            raise ValueError("closed D11-owned character-work segment identity required")
        identity = canonical_digest((self.namespace, self.effect_id, self.execution_id,
            self.binding_digest, self.claim_sequence, self.claim_digest))
        if self.segment_id != "character-work:" + identity:
            raise ValueError("character-work identity must retain its actual unique claim")
        start = Decimal(self.from_character)
        if not start.is_finite() or start < 0:
            raise ValueError("character-work start must be the actual finite role clock original")
        _utc(self.started_at_utc)
        terminal = (self.terminal_original_ref, self.terminal_sequence,
            self.terminal_digest, self.ended_at_utc)
        if any(v is None for v in terminal):
            if any(v is not None for v in terminal) or self.status != "active" or self.to_character is not None:
                raise ValueError("unpaired terminal cannot close a character-work interval")
        else:
            if (type(self.terminal_sequence) is not int or self.terminal_sequence <= self.claim_sequence
                    or _utc(self.ended_at_utc) < _utc(self.started_at_utc) or self.status == "active"):
                raise ValueError("character-work end must be its actual subsequent terminal")
        if self.to_character is not None:
            end = Decimal(self.to_character)
            if not end.is_finite() or end < start:
                raise ValueError("character clock cannot run backwards within one labor segment")
        if self.status == "completed" and self.to_character is None:
            raise ValueError("completed labor requires a known actual character endpoint")


def character_work_segment_from_wire_v1(raw):
    value = _closed(raw, CharacterWorkSegmentOriginalV1)
    value["namespace"] = NamespaceId(**value["namespace"])
    value["component_ids"] = tuple(value["component_ids"])
    return CharacterWorkSegmentOriginalV1(**value)


class _CharacterLaborClaimQualificationV1:
    __slots__ = ("service", "work", "prepared", "admission", "body", "permit", "identity", "__weakref__")

    def __init__(self, service, work, prepared, admission, body):
        self.service, self.work, self.prepared = weakref.ref(service), work, prepared
        self.admission, self.body, self.permit = admission, body, work.permit
        self.identity = object()


_QUALIFICATIONS = weakref.WeakKeyDictionary()


def qualify_character_labor_claim_v1(service, work):
    from ..authority_service.d11_life_service_v1 import AuthorityD11LifeServiceV1
    from ..authority_service.current_authority_graph_read_v3 import require_current_authority_character_labor_call_work_v1
    from .d11_life_preparation_v1 import D11CharacterLaborLifePreparedV1
    if type(service) is not AuthorityD11LifeServiceV1:
        raise TypeError("character-work claim belongs to the installed actual D11 Life service")
    prepared, admission, body = require_current_authority_character_labor_call_work_v1(service, work)
    if (type(prepared) is not D11CharacterLaborLifePreparedV1
            or type(admission) is not CharacterLaborAdmissionV1
            or type(body) is not LaborBodyPreparationOriginalV1
            or (admission.namespace, admission.binding_digest) != (service.namespace, prepared.binding.digest)
            or admission.body_preparation_digest != canonical_digest(plain_v1(body))
            or work.permit.operation != "write" or work.permit.operation_id != service._gate_id(prepared.binding, "claim")):
        raise ValueError("labor Source Work lost its actual new Prepared/C/B and same real claim WRITE permit")
    qualification = _CharacterLaborClaimQualificationV1(service, work, prepared, admission, body)
    _QUALIFICATIONS[qualification] = qualification.identity
    return qualification


def require_character_labor_claim_current_v1(qualification, *, service, prepared, binding, permit):
    from .d11_life_preparation_v1 import D11CharacterLaborLifePreparedV1
    if type(prepared) is not D11CharacterLaborLifePreparedV1:
        if qualification is not None:
            raise ValueError("a legacy Fixed preparation cannot borrow a labor qualification")
        return None
    if (type(qualification) is not _CharacterLaborClaimQualificationV1
            or _QUALIFICATIONS.get(qualification) is not qualification.identity
            or qualification.service() is not service or qualification.prepared is not prepared
            or qualification.prepared.binding != binding or qualification.permit != permit
            or qualification.work.service is not service or not qualification.work.complete
            or qualification.work.failure is not None):
        raise ValueError("labor claim requires its actual completed Source Work and original permit")
    if service._now() >= qualification.admission.expires_at_utc:
        raise ValueError("labor qualification cannot renew expired original policy, quote or command")
    return qualification


def release_character_labor_claim_qualification_v1(qualification):
    if type(qualification) is not _CharacterLaborClaimQualificationV1:
        raise TypeError("actual labor claim qualification required")
    _QUALIFICATIONS.pop(qualification, None)


PREPARED_METADATA_KIND = "character_labor_prepared_metadata_v1"


@dataclass(frozen=True, slots=True)
class CharacterLaborPreparedMetadataV1:
    namespace: NamespaceId
    prepared_ref: str
    prepared_digest: str
    prepared_schema: str
    binding: object
    plan: object
    labor_admission_ref: str
    labor_admission_digest: str
    clock_mapping_json: str
    clock_original_json: str
    quote_json: str
    signed_grant_json: str
    signed_grant_signature: str
    parent_budget_json: str
    reserve_receipt_json: str
    owner_guard_json: str
    prepare_command_identity_json: str
    owner_prepare_request_digest: str
    owner_prepare_attempt_id: str
    prepared_at_utc: str
    read_versions: tuple
    source_roots: tuple[str, ...]
    receipt_digest: str
    graph_epoch: int
    requirements_json: str
    graph_revision: int
    job_projection_json: str
    job_projection_revision: int
    schema: str = "d11.character-labor-prepared-metadata.v1"

    def __post_init__(self):
        from .d11_life_contract_v1 import D11LifeExecutionBindingV1, RegisteredCharacterLaborLifePlanV1
        from ..runtime_contracts import VersionedRef
        if (self.schema != "d11.character-labor-prepared-metadata.v1"
                or self.prepared_schema != "d11.character-labor-life-prepared.v1"
                or type(self.namespace) is not NamespaceId
                or type(self.binding) is not D11LifeExecutionBindingV1
                or type(self.plan) is not RegisteredCharacterLaborLifePlanV1
                or self.binding.namespace != self.namespace or self.prepared_ref != self.binding.prepared_original_ref
                or self.labor_admission_ref != "character-labor-admission:" + self.binding.execution_id
                or type(self.read_versions) is not tuple or len(self.read_versions) > 1024
                or any(type(v) is not VersionedRef for v in self.read_versions)
                or len({v.ref for v in self.read_versions}) != len(self.read_versions)
                or type(self.source_roots) is not tuple or not 1 <= len(self.source_roots) <= 32
                or len(set(self.source_roots)) != len(self.source_roots)
                or type(self.graph_epoch) is not int or self.graph_epoch < 0
                or type(self.graph_revision) is not int or self.graph_revision < 0
                or type(self.job_projection_revision) is not int or self.job_projection_revision < 1
                or type(self.requirements_json) is not str or type(self.job_projection_json) is not str):
            raise ValueError("exact bodyless metadata of the actual new C Prepared required")
        b, p = self.binding, self.plan
        if ((p.activity_id, p.effect_id, p.operation_id, p.attempt_id, p.parent_budget_lease_ref)
                != (b.activity_id, b.effect_id, b.operation_id, b.attempt_id, b.parent_budget_lease_ref)
                or b.plan_digest != canonical_digest(plain_v1(p))
                or p.input_source.ref not in self.source_roots
                or not set(self.source_roots) <= {v.ref for v in self.read_versions
                    if AtomKey.from_token(v.ref).type_name == "memory.source"}):
            raise ValueError("bodyless labor metadata changed its actual plan, Source roots or read-set")
        for name in ("prepared_digest", "labor_admission_digest", "receipt_digest",
                "owner_prepare_request_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("labor metadata needs its actual immutable producer commitments")


def character_labor_prepared_metadata_from_wire_v1(raw):
    from .d11_life_contract_v1 import (
        D11LifeExecutionBindingV1, RegisteredCharacterLaborLifePlanV1, life_from_wire_v1)
    from ..runtime_contracts import VersionedRef
    value = _closed(raw, CharacterLaborPreparedMetadataV1)
    value["namespace"] = NamespaceId(**value["namespace"])
    value["binding"] = life_from_wire_v1(value["binding"], D11LifeExecutionBindingV1)
    value["plan"] = life_from_wire_v1(value["plan"], RegisteredCharacterLaborLifePlanV1)
    value["read_versions"] = tuple(VersionedRef(**v) for v in value["read_versions"])
    value["source_roots"] = tuple(value["source_roots"])
    result = CharacterLaborPreparedMetadataV1(**value)
    if plain_v1(result) != raw:
        raise ValueError("bodyless labor Prepared metadata is not canonical")
    return result


def record_character_labor_prepared_metadata_after_cas_v1(db, *, frame, prepared,
        prepared_original, receipt, issuer):
    from .d11_life_preparation_v1 import D11CharacterLaborLifePreparedV1, SIGN_KIND, TABLE
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    from .foreground_command_writer_outputs_v3 import record_foreground_writer_life_v3
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from ..runtime_contracts import VersionedRef
    if (type(prepared) is not D11CharacterLaborLifePreparedV1
            or type(prepared_original) is not ProductionOriginalRefV1
            or prepared_original.kind != "d11.life_character_labor_prepared_v1"
            or prepared_original.original_ref != prepared.binding.prepared_original_ref
            or prepared.labor_admission_ref is None or prepared.labor_admission_digest is None
            or frame.envelope.identity.operation_id != prepared.prepare_operation_id
            or receipt.operation_id != prepared.prepare_operation_id):
        raise ValueError("labor metadata must follow the real final new Prepared INSERT and C receipt")
    # The real producer has already computed and signed the full Prepared.
    # Read only its fixed authenticated header; never hash source_record_json here.
    row = _producer_original_point_v3(db, table=TABLE,
        columns=("producing_operation_id", "payload_digest", "signature"),
        key_columns=("bot", "persona", "kind", "original_ref"),
        key=(*prepared.binding.namespace.as_tuple, "character_labor_prepared_v1", prepared_original.original_ref),
        legacy_reader=lambda: db.execute("SELECT producing_operation_id,payload_digest,signature FROM " + TABLE +
            " WHERE bot=? AND persona=? AND kind=? AND original_ref=?",
            (*prepared.binding.namespace.as_tuple, "character_labor_prepared_v1", prepared_original.original_ref)).fetchone())
    if row is None or row[:2] != (prepared.prepare_operation_id, prepared_original.original_digest):
        raise ValueError("labor metadata has no actual same-C signed Prepared header")
    issuer._signer.verify(SIGN_KIND, canonical_serialize((prepared.binding.namespace,
        "character_labor_prepared_v1", prepared_original.original_ref, row[1])), row[2])
    if (len(receipt.invalidated_epochs) != 1
            or (receipt.invalidated_epochs[0].bot, receipt.invalidated_epochs[0].persona) != prepared.binding.namespace.as_tuple
            or prepared.graph_epoch != receipt.invalidated_epochs[0].revision):
        raise ValueError("labor metadata lost the final actual C namespace stamp")
    selected_versions = tuple(VersionedRef(r.ref, r.revision) for r in prepared.read_rows)
    full_versions = {v.key.token: v.revision for v in receipt.read_versions}
    if any(full_versions.get(v.ref) != v.version for v in selected_versions):
        raise ValueError("labor C Body selection is outside its complete actual W01 read-set")
    # Current validation sees C's genuinely committed outputs, not their
    # pre-CAS absence. The real receipt is the only authority for this mapping.
    for written in receipt.write_versions:
        full_versions[written.key.token] = written.revision
    versions = tuple(VersionedRef(ref, revision) for ref, revision in sorted(full_versions.items()))
    roots = tuple(sorted(v.ref for v in selected_versions if AtomKey.from_token(v.ref).type_name == "memory.source"))
    metadata = CharacterLaborPreparedMetadataV1(prepared.binding.namespace, prepared_original.original_ref,
        row[1], prepared.schema, prepared.binding, prepared.plan,
        prepared.labor_admission_ref, prepared.labor_admission_digest,
        prepared.clock_mapping_json, prepared.clock_original_json, prepared.quote_json,
        prepared.signed_grant_json, prepared.signed_grant_signature, prepared.parent_budget_json,
        prepared.reserve_receipt_json, prepared.owner_guard_json, prepared.prepare_command_identity_json,
        prepared.owner_prepare_request_digest, prepared.owner_prepare_attempt_id, prepared.prepared_at_utc,
        versions, roots, canonical_digest(receipt), receipt.invalidated_epochs[0].revision,
        prepared.requirements_json, prepared.graph_revision,
        prepared.job_projection_json, prepared.job_projection_revision)
    return record_foreground_writer_life_v3(db, issuer=issuer, namespace=metadata.namespace,
        kind=PREPARED_METADATA_KIND, ref="character-labor-prepared-metadata:" + metadata.binding.execution_id,
        operation_id=prepared.prepare_operation_id, value=metadata,
        recorder=record_character_labor_prepared_metadata_after_cas_v1, frame=frame, actual_receipt=receipt)



def issue_character_work_segment_original_v1(service, work):
    """Derive one labor fact from the original signed clock/start/terminal only."""
    from decimal import Decimal, localcontext
    from ..authority_service.character_labor_source_read_v1 import require_character_labor_source_metadata_v1
    from ..authority_service.d11_life_execution_owner_v1 import (
        _CURRENT, require_own_d11_life_invocation_v1, read_own_d11_life_originals_v1)
    from .d10_offline_tick_execution_v1 import _decode_json
    from .clock import CharacterClockMapping
    metadata, admission, body = require_character_labor_source_metadata_v1(service, work)
    binding = metadata.binding
    invocation = _CURRENT.get()
    require_own_d11_life_invocation_v1(invocation, service=service, binding=binding)
    if (work.request.phase != "adoption" or invocation.phase != "adoption_metadata"
            or invocation.permit != work.permit or not work.complete
            or body.policy.executor_protocol != PROTOCOL or not body.policy.accept_local_write_wait
            or metadata.plan.executor_protocol != PROTOCOL or metadata.plan.recipe_version != 2
            or binding.algorithm_build_digest != service.build["algorithm_build_digest"]):
        raise ValueError("character-work fact requires the actual installed nonpreemptible adoption reader")
    claim, terminal = read_own_d11_life_originals_v1(invocation, binding, work=work)
    if claim is None:
        raise MissingProductionOriginalV1("actual_character_labor_signed_start")
    mapping = _decode_json(metadata.clock_mapping_json, CharacterClockMapping)
    original = json.loads(metadata.clock_original_json)
    if ((claim.payload.clock_mapping_ref, claim.payload.clock_mapping_version)
                != (mapping.mapping_id, mapping.version)
            or (mapping.mapping_id, mapping.version)
                != (body.quote.clock_mapping_ref, body.quote.clock_mapping_version)
            or canonical_digest(original) != body.quote.clock_original_digest):
        raise ValueError("character-work interval differs from the original signed Owner clock")
    with localcontext() as context:
        context.prec = 28
        if Decimal(claim.payload.character_at) != mapping.character_at(claim.payload.claimed_at_utc):
            raise ValueError("character-work start differs from its authenticated clock endpoint")
        if terminal is not None and terminal.payload.character_at is not None:
            if Decimal(terminal.payload.character_at) != mapping.character_at(terminal.payload.completed_at_utc):
                raise ValueError("character-work terminal differs from its authenticated clock endpoint")
    identity = canonical_digest((binding.namespace, binding.effect_id, binding.execution_id,
        binding.digest, claim.claim_sequence, claim.claim_digest))
    material = dict(namespace=binding.namespace, effect_id=binding.effect_id,
        execution_id=binding.execution_id, segment_id="character-work:" + identity,
        binding_digest=binding.digest, prepared_digest=metadata.prepared_digest,
        admission_ref=metadata.labor_admission_ref,
        admission_original_digest=metadata.labor_admission_digest,
        body_preparation_ref=metadata.plan.labor_body_preparation_original.original_ref,
        body_preparation_digest=metadata.plan.labor_body_preparation_original.original_digest,
        recipe_ref=body.recipe_ref, recipe_revision=body.recipe_revision, recipe_digest=body.recipe_digest,
        policy_digest=canonical_digest(plain_v1(body.policy)),
        component_ids=tuple(c.component_id for c in (*body.policy.fixed_components, *body.policy.duration_components)),
        channel_id="main_focus", executor_protocol=PROTOCOL,
        algorithm_build_digest=binding.algorithm_build_digest,
        clock_mapping_ref=mapping.mapping_id, clock_mapping_version=mapping.version,
        clock_original_digest=canonical_digest(original),
        claim_original_ref=claim.original_ref, claim_sequence=claim.claim_sequence,
        claim_digest=claim.claim_digest,
        terminal_original_ref=None if terminal is None else terminal.original_ref,
        terminal_sequence=None if terminal is None else terminal.terminal_sequence,
        terminal_digest=None if terminal is None else terminal.terminal_digest,
        started_at_utc=claim.payload.claimed_at_utc, from_character=claim.payload.character_at,
        ended_at_utc=None if terminal is None else terminal.payload.completed_at_utc,
        to_character=None if terminal is None else terminal.payload.character_at,
        status="active" if terminal is None else terminal.payload.status,
        schema="d11.character-work-segment-original.v1")
    return CharacterWorkSegmentOriginalV1(**material, signature=service._sign(material))


def character_labor_census_duration_root_v1(census):
    """Stable duration identities; live-to-retained classification changes no debt."""
    from ..authority_service.character_labor_census_v1 import CharacterLaborCensusV1
    if type(census) is not CharacterLaborCensusV1:
        raise TypeError("exact complete Life census is required")
    entries = tuple((e.execution_id,e.binding_digest,e.prepared_digest,e.claim_sequence,
        e.claim_digest,e.terminal_sequence,e.terminal_digest,e.status) for e in census.entries
        if e.classification in {"character_labor_v1","retained_duration_v1"})
    return canonical_digest(("d02.character-labor-duration-census.v1",census.namespace,entries))


def record_character_labor_segment_after_cas_v1(db, *, frame, inputs, receipt, issuer):
    """Persist the authenticated duration fact only from its actual adoption CAS."""
    from .current_character_labor_adoption_v1 import (
        PreparedCharacterLaborAdoptionV1,require_character_labor_adoption_after_cas_v1)
    from .foreground_command_writer_outputs_v3 import record_foreground_writer_life_v3
    from .d11_life_preparation_v1 import D11CharacterLaborLifePreparedV1
    from .issuers import D11BudgetJobIssuer
    if type(inputs) is not PreparedCharacterLaborAdoptionV1 or type(issuer) is not D11BudgetJobIssuer:
        raise TypeError("actual sealed labor adoption inputs and installed D11 issuer required")
    prepared,body,admission,segment,census,gate,source_versions,resource_proof = (
        require_character_labor_adoption_after_cas_v1(inputs,db=db,frame=frame,receipt=receipt))
    if (type(prepared) is not D11CharacterLaborLifePreparedV1
            or type(body) is not LaborBodyPreparationOriginalV1
            or type(admission) is not CharacterLaborAdmissionV1
            or type(segment) is not CharacterWorkSegmentOriginalV1):
        raise TypeError("labor segment recorder requires the exact new protocol originals")
    from .d11_life_contract_v1 import life_adoption_operation_id_v1
    if issuer is not inputs._actual_v1().graph._GraphCoordinator__d11_issuer:
        raise ValueError("labor segment recorder changed its actual installed D11 issuer")
    b = prepared.binding
    if (segment.namespace != b.namespace or segment.binding_digest != b.digest
            or segment.execution_id != b.execution_id or segment.effect_id != b.effect_id
            or segment.admission_ref != prepared.labor_admission_ref
            or segment.admission_original_digest != prepared.labor_admission_digest
            or segment.body_preparation_digest != canonical_digest(plain_v1(body))
            or segment.policy_digest != canonical_digest(plain_v1(body.policy))
            or segment.component_ids != tuple(c.component_id for c in
                (*body.policy.fixed_components,*body.policy.duration_components))
            or admission.binding_digest != b.digest
            or receipt.operation_id != frame.envelope.identity.operation_id
            or receipt.operation_id != life_adoption_operation_id_v1(b)):
        raise ValueError("labor segment lost its actual adopted C/B/binding/receipt")
    # The Authority's independent start/terminal signature remains inside the
    # new Graph original unchanged; W01 authenticates this distinct adoption.
    return record_foreground_writer_life_v3(db,issuer=issuer,namespace=b.namespace,
        kind=SEGMENT_KIND,ref=segment.segment_id,operation_id=receipt.operation_id,value=segment,
        recorder=record_character_labor_segment_after_cas_v1,frame=frame,actual_receipt=receipt)
