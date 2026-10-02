"""Installed D02 current passive-time and settled-work readers."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math

from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d02 import BodyDomain, BodyPassiveRates, BodyProfile, BodyState, _reservation
from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
from ..domains.d02.production_operations_v1 import (
    AdvanceCurrentBodyRequestV1, ApplyCurrentBodyEffectRequestV1, CurrentBodyAdvanceInputsV1,
    CurrentBodyEffectInputsV1, PassiveBodySegmentV1, compile_advance_current_body_v1,
    compile_apply_current_body_effect_v1, verify_d02_production_stage_v1,
)
from ..graph_types import AtomKey, Owner
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from .d11_c04_internal_cost import read_c04_cpu_cost_original_v1
from .d11_role_clock_installation_v1 import read_current_role_clock_installation_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .d01_production_operations_v1 import (
    CurrentDomainReadV1, MissingProductionOriginalV1, table_exists_v1, waiting_stage_v1,
)
from .issuers import D02ResourceIssuer, D11BudgetJobIssuer


@dataclass(frozen=True, slots=True)
class PassiveBodyPolicyV1:
    policy_ref: str
    revision: int
    namespace: NamespaceId
    profile_id: str
    from_role_cursor: float
    to_role_cursor: float
    rates: BodyPassiveRates

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or type(self.rates) is not BodyPassiveRates
                or type(self.revision) is not int or self.revision < 1 or not self.policy_ref or not self.profile_id
                or any(type(v) not in (int, float) or not math.isfinite(v) for v in
                       (self.from_role_cursor, self.to_role_cursor))
                or not 0 <= self.from_role_cursor < self.to_role_cursor):
            raise ValueError("body passive policy requires explicit finite role interval and rates")


@dataclass(frozen=True, slots=True)
class SettledBodyEffectPolicyV1:
    policy_ref: str
    revision: int
    namespace: NamespaceId
    profile_id: str
    work_kind: str
    component_id: str
    fatigue_increase: float
    load_increase: float

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or type(self.revision) is not int or self.revision < 1
                or any(type(v) is not str or not v for v in
                       (self.policy_ref, self.profile_id, self.work_kind, self.component_id))
                or any(type(v) not in (int, float) or not math.isfinite(v) or v < 0
                       for v in (self.fatigue_increase, self.load_increase))):
            raise ValueError("body effect policy requires explicit installed component effects")


@dataclass(frozen=True, slots=True)
class CompletedActionBodyComponentV1:
    original_ref: str
    action_intent_ref: str
    action_outcome_ref: str
    observation_ref: str
    observation_digest: str
    body_quote_ref: str
    body_quote_version: int
    resource_quote_ref: str
    resource_quote_version: int
    reservation_ref: str
    settlement_ref: str
    component_id: str
    paid_cost_refs: tuple[str, ...]

    def __post_init__(self):
        if (type(self.body_quote_version) is not int or self.body_quote_version < 1
                or type(self.resource_quote_version) is not int or self.resource_quote_version < 1
                or type(self.paid_cost_refs) is not tuple or not self.paid_cost_refs):
            raise ValueError("completed action body component needs actual quoted/paid originals")


def install_d02_production_schema_v1(db):
    if db.in_transaction:
        raise ValueError("install D02 production schema before runtime transactions")
    db.execute("CREATE TABLE IF NOT EXISTS graph_d02_production_policies_v1 ("
        "bot TEXT NOT NULL,persona TEXT NOT NULL,policy_ref TEXT NOT NULL,revision INTEGER NOT NULL,"
        "kind TEXT NOT NULL,profile_id TEXT NOT NULL,from_role_cursor REAL,to_role_cursor REAL,"
        "payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,signature TEXT NOT NULL,"
        "PRIMARY KEY(bot,persona,policy_ref,revision))")
    db.execute("CREATE TABLE IF NOT EXISTS graph_d02_action_components_v1 ("
        "bot TEXT NOT NULL,persona TEXT NOT NULL,original_ref TEXT NOT NULL,producing_operation_id TEXT NOT NULL,"
        "payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,signature TEXT NOT NULL,source_refs_json TEXT NOT NULL,"
        "PRIMARY KEY(bot,persona,original_ref))")


class InstalledD02ProductionReadersV1:
    def __init__(self, *, issuer, body_quote_authority, role_clock_reader):
        from ..host.installed_d04_semantic_mapping_v3 import InstalledD04SemanticMappingReaderV3
        if (type(issuer) is not D11BudgetJobIssuer or type(body_quote_authority) is not D02BodyQuoteAuthority
                or type(role_clock_reader) is not InstalledD04SemanticMappingReaderV3):
            raise TypeError("D02 needs installed D11/body signer and actual fenced role-clock reader")
        self.issuer = issuer
        self.body_quote_authority = body_quote_authority
        self.role_clock_reader = role_clock_reader

    def install_policy(self, db, *, frame, policy):
        """W01's fixed administrator-policy installation, never a data command."""
        if type(policy) not in {PassiveBodyPolicyV1, SettledBodyEffectPolicyV1}:
            raise TypeError("exact D02 passive/effect policy required")
        read = CurrentDomainReadV1(frame)
        read.check(db)
        if policy.namespace != frame.envelope.authority.namespace:
            raise ValueError("D02 installed policy namespace differs")
        pinned = tuple(item for item in frame.installed_policy_refs if item.policy_ref == policy.policy_ref and item.revision == policy.revision)
        digest = canonical_digest(plain_v1(policy))
        if len(pinned) != 1 or pinned[0].revision != policy.revision or pinned[0].policy_digest != digest:
            raise ValueError("D02 policy was not selected by current installed policy authority")
        kind = "passive" if type(policy) is PassiveBodyPolicyV1 else "effect"
        encoded = canonical_serialize(plain_v1(policy))
        start, end = ((policy.from_role_cursor, policy.to_role_cursor) if kind == "passive" else (None, None))
        expected = (kind, policy.profile_id, start, end, encoded, digest,
                    self.issuer._signer.sign("d11.d02-production-policy.v1", encoded))
        row = db.execute("SELECT kind,profile_id,from_role_cursor,to_role_cursor,payload_json,payload_digest,signature "
            "FROM graph_d02_production_policies_v1 WHERE bot=? AND persona=? AND policy_ref=? AND revision=?",
            (*policy.namespace.as_tuple, policy.policy_ref, policy.revision)).fetchone()
        if row is not None and row != expected:
            raise ValueError("D02 policy identity replay differs")
        if row is None:
            maximum = db.execute("SELECT max(revision) FROM graph_d02_production_policies_v1 WHERE bot=? AND persona=? AND policy_ref=?",
                (*policy.namespace.as_tuple, policy.policy_ref)).fetchone()[0]
            if policy.revision != (maximum or 0) + 1:
                raise ValueError("D02 installed policy revision must advance its actual predecessor")
            db.execute("INSERT INTO graph_d02_production_policies_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (*policy.namespace.as_tuple, policy.policy_ref, policy.revision, *expected))

    def _policy(self, read, row):
        ref, revision, kind, encoded, digest, signature = row
        self.issuer._signer.verify("d11.d02-production-policy.v1", encoded, signature)
        raw = json.loads(encoded)
        if canonical_serialize(raw) != encoded or canonical_digest(raw) != digest:
            raise ValueError("D02 installed policy original changed")
        pin = tuple(item for item in read.frame.installed_policy_refs if item.policy_ref == ref and item.revision == revision)
        if len(pin) != 1 or pin[0].policy_digest != digest:
            raise MissingProductionOriginalV1("installed_d02_policy_version:" + ref)
        raw["namespace"] = NamespaceId(**raw["namespace"])
        if kind == "passive":
            raw["rates"] = BodyPassiveRates(**raw["rates"])
            policy = PassiveBodyPolicyV1(**raw)
        elif kind == "effect":
            policy = SettledBodyEffectPolicyV1(**raw)
        else:
            raise ValueError("unrecognized D02 installed policy kind")
        if policy.namespace != read.frame.envelope.authority.namespace or policy.policy_ref != ref or policy.revision != revision:
            raise ValueError("D02 installed policy namespace/version changed")
        return policy, ProductionOriginalRefV1("d02." + kind + "_policy", ref, digest)

    def _current_body(self, db, read, profile_id=None):
        states = read.complete_inventory(db, "d02.body_state.v1")
        valid = tuple(atom for atom in states if atom.valid and (profile_id is None or atom.key.name == profile_id))
        if len(valid) != 1:
            raise MissingProductionOriginalV1("unique_current_body_profile_state")
        atom = valid[0]
        state = BodyState(**atom.value)
        if atom.key.owner.kind != "persona" or state.version != atom.revision or state.profile_id != atom.key.name:
            raise ValueError("current body state identity/version changed")
        ns = read.frame.envelope.authority.namespace
        profile_atom = read.head(db, AtomKey(Owner("persona", *ns.as_tuple), "d02.body_profile.v1", state.profile_id), required=True)
        raw = dict(profile_atom.value)
        raw["namespace"] = NamespaceId(**raw["namespace"])
        raw["applicable_axes"], raw["work_kinds"] = tuple(raw["applicable_axes"]), tuple(raw["work_kinds"])
        profile = BodyProfile(**raw)
        if profile.namespace != ns or profile.version != profile_atom.revision:
            raise ValueError("current body profile identity/version changed")
        reservations = tuple(_reservation(atom.value) for atom in read.complete_inventory(db, "d02.reservation.v1") if atom.valid)
        if len({item.effect_id for item in reservations}) != len(reservations):
            raise ValueError("body reservation inventory repeats an effect")
        return profile, state, reservations

    def record_current_action_body_component_v1(self, db, *, frame, producing_operation_id, component):
        """Concrete producer from an actually observed admitted message action.

        Handoff/unknown alone cannot complete a generic physical recipe. The
        currently supported external component is the observed communication
        action named by its original signed body/resource quote.
        """
        if type(component) is not CompletedActionBodyComponentV1:
            raise TypeError("exact completed action body component required")
        read = CurrentDomainReadV1(frame)
        read.check(db)
        read.committed_operation(db, producing_operation_id)
        from ..domains.d08.execution import _decode, _decode_intent
        action_atom = read.head(db, component.action_intent_ref, required=True)
        outcome_atom = read.head(db, component.action_outcome_ref, required=True)
        action, outcome = _decode_intent(action_atom.value), _decode("d08.action_outcome.v1", outcome_atom.value)
        observed, observed_original = read.adopted_outbound_observation(db, component.observation_ref)
        platform = observed.pending.platform_observation
        origin = getattr(platform.binding, "origin", platform.binding)
        if (action.action_kind not in {"message", "communication"} or platform.outcome not in {"accepted", "delivered"}
                or origin.effect_id != action.identity.effect_id or outcome.effect_id != origin.effect_id
                or outcome.action_id != action.action_id or outcome.attempt_id != action.identity.attempt_id
                or outcome.unknown_effects or outcome.effect_id not in outcome.completed_effects
                or component.observation_ref not in outcome.observation_refs
                or observed_original.original_digest != component.observation_digest):
            raise ValueError("body component is not this actual completed communication effect")
        quote = self.issuer.resource_issuer.original_signed_quote(db, component.resource_quote_ref, component.resource_quote_version)
        body = self.body_quote_authority.original_body_quote(db, component.body_quote_ref,
            component.body_quote_version, quote, quote.operation_id)
        if ((quote.bot_id, quote.persona_id, quote.activity_id, quote.effect_id) !=
                (*frame.envelope.authority.namespace.as_tuple, action.identity.activity_id, action.identity.effect_id)
                or body.activity_id != action.identity.activity_id or body.work_kind != quote.work_kind
                or tuple(quote.d02_settlement_refs) != (component.settlement_ref,)):
            raise ValueError("communication body quote/settlement does not bind the original action")
        part = next((part for part in body.components if part.component_id == component.component_id), None)
        if part is None or part.duration_rate != 0:
            raise ValueError("communication body completion needs its original fixed component")
        reservation = _reservation(read.head(db, component.reservation_ref, required=True).value)
        if reservation.quote_id != body.quote_id or reservation.effect_id != action.identity.effect_id:
            raise ValueError("communication body reservation belongs to another effect")
        read.source_family(db, action.source_refs)
        for ref in component.paid_cost_refs:
            read.settled_cost_original(db, ref, activity_id=action.identity.activity_id,
                effect_id=action.identity.effect_id, operation_id=quote.operation_id)
        encoded, digest = canonical_serialize(plain_v1(component)), canonical_digest(plain_v1(component))
        expected = (producing_operation_id, encoded, digest,
            self.issuer._signer.sign("d11.d02-completed-action-component.v1", encoded), canonical_serialize(action.source_refs))
        row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature,source_refs_json FROM graph_d02_action_components_v1 "
            "WHERE bot=? AND persona=? AND original_ref=?", (*frame.envelope.authority.namespace.as_tuple, component.original_ref)).fetchone()
        if row is not None and row != expected:
            raise ValueError("completed action body original replay conflicts")
        if row is None:
            db.execute("INSERT INTO graph_d02_action_components_v1 VALUES(?,?,?,?,?,?,?,?)",
                (*frame.envelope.authority.namespace.as_tuple, component.original_ref, *expected))
        return ProductionOriginalRefV1("d02.completed_action_component", component.original_ref, digest)

    def _read_action_effect(self, db, read, request):
        row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM graph_d02_action_components_v1 "
            "WHERE bot=? AND persona=? AND original_ref=?", (*read.frame.envelope.authority.namespace.as_tuple,
                                                             request.settlement_operation_ref)).fetchone()
        if row is None:
            return None
        self.issuer._signer.verify("d11.d02-completed-action-component.v1", row[1], row[3])
        raw = json.loads(row[1])
        if canonical_digest(raw) != row[2] or canonical_serialize(raw) != row[1]:
            raise ValueError("completed body action original changed")
        raw["paid_cost_refs"] = tuple(raw["paid_cost_refs"])
        completion = CompletedActionBodyComponentV1(**raw)
        read.committed_operation(db, row[0])
        read.original(request.settlement_operation_ref, kind="d02.completed_action_component", digest=row[2])
        if request.component_terminal_ref != completion.observation_ref or request.body_quote_ref != completion.body_quote_ref:
            raise ValueError("body effect names another original completed action")
        observed, terminal = read.adopted_outbound_observation(db, completion.observation_ref)
        if terminal.original_digest != completion.observation_digest or observed.pending.platform_observation.outcome not in {"accepted", "delivered"}:
            raise ValueError("body effect actual action observation changed")
        quote = self.issuer.resource_issuer.original_signed_quote(db, completion.resource_quote_ref, completion.resource_quote_version)
        body = self.body_quote_authority.original_body_quote(db, completion.body_quote_ref, completion.body_quote_version, quote, quote.operation_id)
        profile, state, _ = self._current_body(db, read, body.profile_id)
        reservation = _reservation(read.head(db, completion.reservation_ref, required=True).value)
        if reservation.quote_id != body.quote_id or reservation.effect_id != quote.effect_id:
            raise ValueError("body action reservation original changed")
        rows = db.execute("SELECT policy_ref,revision,kind,payload_json,payload_digest,signature FROM graph_d02_production_policies_v1 "
            "WHERE bot=? AND persona=? AND policy_ref=? AND kind='effect' ORDER BY revision DESC LIMIT 1",
            (*read.frame.envelope.authority.namespace.as_tuple, request.effect_policy_ref)).fetchall()
        if not rows:
            raise MissingProductionOriginalV1("installed_body_effect_policy:" + request.effect_policy_ref)
        policy, policy_original = self._policy(read, rows[0])
        if (policy.profile_id, policy.work_kind, policy.component_id) != (profile.profile_id, body.work_kind, completion.component_id):
            raise ValueError("body action effect policy does not cover the completed component")
        component = next(part for part in body.components if part.component_id == completion.component_id)
        settlement = read.head(db, completion.settlement_ref)
        costs = tuple(read.settled_cost_original(db, ref, activity_id=quote.activity_id,
            effect_id=quote.effect_id, operation_id=quote.operation_id) for ref in completion.paid_cost_refs)
        return CurrentBodyEffectInputsV1(state, reservation, body, completion.component_id, completion.observation_ref,
            completion.settlement_ref, policy.work_kind, policy.fatigue_increase, policy.load_increase,
            component.fixed_cost, terminal, policy_original, costs, bool(settlement.revision))

    def read_advance(self, db, frame, request):
        read = CurrentDomainReadV1(frame)
        read.check(db)
        profile, state, reservations = self._current_body(db, read)
        trigger = read.original(request.trigger_original_ref)
        if trigger.kind not in {"d11.trusted_tick", "d10.life_interval", "d10.offline_interval", "d11.clock_sample"}:
            raise ValueError("passive body trigger is not actual trusted time or adopted life interval")
        mapping = read_current_role_clock_installation_v1(self.role_clock_reader, db, frame.envelope.authority.namespace)
        if request.clock_mapping_ref != mapping.mapping_id:
            raise ValueError("passive body clock differs from current signed role mapping")
        now = datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace("+00:00", "Z")
        if request.target_role_cursor > float(mapping.character_at(now)):
            raise ValueError("passive body target exceeds actual trusted role time")
        clock = read.original(mapping.mapping_id, kind="d11.role_clock")
        if not table_exists_v1(db, "graph_d02_production_policies_v1"):
            raise MissingProductionOriginalV1("installed_passive_rate_history")
        rows = db.execute("SELECT policy_ref,revision,kind,payload_json,payload_digest,signature "
            "FROM graph_d02_production_policies_v1 WHERE bot=? AND persona=? AND kind='passive' AND profile_id=? "
            "AND to_role_cursor>? AND from_role_cursor<? ORDER BY from_role_cursor,policy_ref,revision LIMIT ?",
            (*frame.envelope.authority.namespace.as_tuple, profile.profile_id, state.cursor,
             request.target_role_cursor, frame.limits.max_role_segments + 1)).fetchall()
        policies = [self._policy(read, row) for row in rows]
        segments, cursor = [], state.cursor
        for policy, original in policies[:frame.limits.max_role_segments]:
            start, end = max(cursor, policy.from_role_cursor), min(request.target_role_cursor, policy.to_role_cursor)
            if start != cursor:
                raise MissingProductionOriginalV1("contiguous_passive_rate_history")
            if segments and policy.from_role_cursor < segments[-1].to_cursor:
                raise ValueError("passive policy history contains an overlapping interval")
            segments.append(PassiveBodySegmentV1(start, end, policy.rates, original))
            cursor = end
        complete = cursor == request.target_role_cursor
        continuation = None if complete else "d02-body-continuation:" + canonical_digest((request, cursor, mapping.version))[:48]
        return CurrentBodyAdvanceInputsV1(profile, state, tuple(segments), clock, trigger, reservations, complete, continuation)

    def read_effect(self, db, frame, request):
        read = CurrentDomainReadV1(frame)
        read.check(db)
        from .d02_life_effect_v1 import read_life_body_effect_v1
        life = read_life_body_effect_v1(self, db, read, request)
        if life is not None:
            return life
        if table_exists_v1(db, "graph_d02_action_components_v1"):
            action = self._read_action_effect(db, read, request)
            if action is not None:
                return action
        ns = frame.envelope.authority.namespace
        operation = request.settlement_operation_ref
        if not table_exists_v1(db, "graph_c04_internal_work_prepared_v1"):
            raise MissingProductionOriginalV1("original_component_preparation")
        prepared = read_c04_internal_work_prepared_v1(db, ns, operation)
        cost = read_c04_cpu_cost_original_v1(db, ns, operation)
        if (prepared is None or cost is None or cost.status != "completed" or not cost.component_completed
                or cost.budget_receipt_status not in {"settled", "overrun"}):
            raise MissingProductionOriginalV1("actual_completed_component_and_cpu_settlement")
        binding = prepared.binding
        if (cost.binding_digest != binding.binding_digest or cost.prepared_digest != prepared.prepared_digest
                or request.body_quote_ref != binding.body_quote_ref
                or request.component_terminal_ref != "internal-work:component:" + binding.binding_digest):
            raise ValueError("body effect does not match original completed component")
        terminal = read.original(request.component_terminal_ref, digest=cost.proof_digest)
        resource_quote = self.issuer.resource_issuer.original_signed_quote(db, binding.resource_quote_ref, binding.resource_quote_version)
        body_quote = self.body_quote_authority.original_body_quote(db, binding.body_quote_ref,
            binding.body_quote_version, resource_quote, operation)
        if canonical_digest(resource_quote) != binding.resource_quote_digest or canonical_digest(body_quote) != binding.body_quote_digest:
            raise ValueError("body effect original signed quotes differ")
        profile, state, _ = self._current_body(db, read, body_quote.profile_id)
        reservation_atom = read.head(db, binding.body_reservation_ref, required=True)
        reservation = _reservation(reservation_atom.value)
        if reservation.effect_id != resource_quote.effect_id or reservation.quote_id != body_quote.quote_id:
            raise ValueError("body effect reservation original differs")
        if not table_exists_v1(db, "graph_d02_production_policies_v1"):
            raise MissingProductionOriginalV1("installed_body_effect_policy:" + request.effect_policy_ref)
        rows = db.execute("SELECT policy_ref,revision,kind,payload_json,payload_digest,signature "
            "FROM graph_d02_production_policies_v1 WHERE bot=? AND persona=? AND policy_ref=? AND kind='effect' "
            "ORDER BY revision DESC LIMIT 2", (*ns.as_tuple, request.effect_policy_ref)).fetchall()
        if not rows:
            raise MissingProductionOriginalV1("installed_body_effect_policy:" + request.effect_policy_ref)
        policy, policy_original = self._policy(read, rows[0])
        if (policy.profile_id != profile.profile_id or policy.work_kind != body_quote.work_kind
                or policy.component_id != binding.component_id):
            raise ValueError("body effect policy component scope differs")
        component = next((item for item in body_quote.components if item.component_id == binding.component_id), None)
        if component is None or component.duration_rate != 0:
            raise MissingProductionOriginalV1("original_fixed_body_component")
        if len(resource_quote.d02_settlement_refs) != 1:
            raise ValueError("body effect original must bind exactly one D02 settlement")
        settlement_ref = resource_quote.d02_settlement_refs[0]
        settlement = read.head(db, settlement_ref)
        if settlement.revision and not settlement.valid:
            raise ValueError("body settlement original was invalidated")
        cost_original = read.original(cost.terminal_receipt_ref, digest=cost.terminal_receipt_digest)
        return CurrentBodyEffectInputsV1(state, reservation, body_quote, binding.component_id,
            request.component_terminal_ref, settlement_ref, policy.work_kind, policy.fatigue_increase,
            policy.load_increase, component.fixed_cost, terminal, policy_original, (cost_original,), bool(settlement.revision))


def stage_advance_current_body_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD02ProductionReadersV1:
        raise TypeError("installed D02 readers required")
    try:
        stage = compile_advance_current_body_v1(frame, request, installed_readers.read_advance(db, frame, request))
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d02", "advance_body", request, missing)
    return verify_d02_production_stage_v1(stage)


def stage_apply_current_body_effect_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD02ProductionReadersV1:
        raise TypeError("installed D02 readers required")
    try:
        stage = compile_apply_current_body_effect_v1(frame, request, installed_readers.read_effect(db, frame, request))
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d02", "apply_body_effect", request, missing)
    return verify_d02_production_stage_v1(stage)


advance_current_body_v1 = stage_advance_current_body_in_transaction_v1
apply_current_body_effect_v1 = stage_apply_current_body_effect_in_transaction_v1
D02_PRODUCTION_STORAGE_INVENTORY_V1 = {"graph_d02_production_policies_v1": {
    "namespace_columns": ("bot", "persona"), "content_columns": ("payload_json",),
    "recovery": "signed_installed_policy_and_clock_history"},
    "graph_d02_action_components_v1": {"namespace_columns": ("bot", "persona"), "content_columns": ("payload_json",),
        "source_closure_column": "source_refs_json", "operation_column": "producing_operation_id",
        "recovery": "same_actual_observed_communication_component_only"}}


def read_plan_current_d02_operation_v1(db, *, namespace, activity_id, operation_kind, request):
    from .d01_production_operations_v1 import production_read_plan_v1, raw_registered_input_v1, raw_head_value_v1
    from ..graph_types import owner_grant_key
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("D02 fixed read plan requires current W01 transaction")
    keys, roots, originals = [owner_grant_key(*namespace.as_tuple)], [], []
    types = ("d02.body_state.v1", "d02.body_profile.v1", "d02.reservation.v1")
    if operation_kind == "advance_body" and type(request) is AdvanceCurrentBodyRequestV1:
        originals.extend((request.clock_mapping_ref, request.trigger_original_ref))
    elif operation_kind == "apply_body_effect" and type(request) is ApplyCurrentBodyEffectRequestV1:
        originals.extend((request.component_terminal_ref, request.body_quote_ref, request.effect_policy_ref, request.settlement_operation_ref))
        from .d11_life_preparation_v1 import TABLE as LIFE_TABLE
        if table_exists_v1(db,LIFE_TABLE):
            rows=db.execute("SELECT payload_json FROM "+LIFE_TABLE+" WHERE bot=? AND persona=? AND kind='adopted_life' AND json_extract(payload_json,'$.terminal.original_ref')=? LIMIT 2",(*namespace.as_tuple,request.component_terminal_ref)).fetchall()
            if len(rows)>1:raise ValueError('Life Body read plan has conflicting terminal originals')
            if rows:
                from .d11_life_contract_v1 import D11LifeTerminalV1, life_from_wire_v1
                from .d11_life_graph_types_v1 import life_role_segment_key_v1
                from .d11_life_fact_provenance_v1 import life_fact_auxiliary_key_v1, PROVENANCE_TYPE, ELIGIBILITY_TYPE
                terminal=life_from_wire_v1(json.loads(rows[0][0])['terminal'],D11LifeTerminalV1)
                b=terminal.binding
                facts=(AtomKey.from_token(b.artifact_ref),life_role_segment_key_v1(b,'start'),life_role_segment_key_v1(b,'end'))
                keys.extend(facts)
                keys.extend(life_fact_auxiliary_key_v1(fact,kind) for fact in facts for kind in (PROVENANCE_TYPE,ELIGIBILITY_TYPE))
                originals.extend((b.prepared_original_ref,b.artifact_ref))
                prepared=raw_registered_input_v1(db,LIFE_TABLE,namespace,b.prepared_original_ref)
                if prepared:
                    from .d11_life_outcome_provenance_v1 import life_outcome_read_keys_v1
                    keys.extend(life_outcome_read_keys_v1(b,prepared['plan']['action_intent']['ref']))
                    keys.extend(AtomKey.from_token(row['ref']) for row in prepared['read_rows'])
                    roots.extend(row['ref'] for row in prepared['read_rows'] if AtomKey.from_token(row['ref']).type_name=='memory.source')
        action_component = raw_registered_input_v1(db, "graph_d02_action_components_v1", namespace, request.settlement_operation_ref)
        if action_component:
            keys.extend(AtomKey.from_token(action_component[name]) for name in (
                "action_intent_ref", "action_outcome_ref", "reservation_ref", "settlement_ref"))
            originals.extend(action_component["paid_cost_refs"])
            action = raw_head_value_v1(db, namespace, AtomKey.from_token(action_component["action_intent_ref"]))
            if action:
                roots.extend(action["source_refs"])
        if table_exists_v1(db, "graph_c04_internal_work_prepared_v1"):
            prepared = read_c04_internal_work_prepared_v1(db, namespace, request.settlement_operation_ref)
            if prepared:
                keys.extend((AtomKey.from_token(prepared.body_state_ref), AtomKey.from_token(prepared.body_profile_ref),
                             AtomKey.from_token(prepared.binding.body_reservation_ref)))
                if table_exists_v1(db, "runtime_resource_quotes"):
                    row = db.execute("SELECT quote_json FROM runtime_resource_quotes WHERE quote_id=? AND version=?",
                                     (prepared.binding.resource_quote_ref, prepared.binding.resource_quote_version)).fetchone()
                    if row:
                        quote = json.loads(row[0])
                        keys.extend(AtomKey.from_token(ref) for ref in quote["d02_settlement_refs"])
                cost = read_c04_cpu_cost_original_v1(db, namespace, request.settlement_operation_ref)
                if cost:
                    originals.append(cost.terminal_receipt_ref)
    else:
        raise ValueError("unregistered exact D02 production request")
    return production_read_plan_v1(types, keys, roots, originals)
