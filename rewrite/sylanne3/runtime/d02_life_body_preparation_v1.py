"""Real Owner B produces the quoted Body reservation of committed Life root A."""
from dataclasses import dataclass, replace
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d02 import BodyDomain
from ..graph_types import AtomKey, Owner
from ..runtime_contracts import canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .d08_source_note_action_v1 import require_source_note_action_original_v1
from .d11_life_contract_v1 import LifeBodyComponentContractV1, WORK_KIND
from .issuers import ResourceQuote


@dataclass(frozen=True, slots=True)
class PrepareSourceNoteBodyRequestV1:
    action_intent_ref: str
    body_policy_id: str
    body_policy_version: int
    effect_policy_ref: str
    cpu_ceiling_ms: int

    def __post_init__(self):
        if (AtomKey.from_token(self.action_intent_ref).type_name != "d08.action_intent.v1"
                or not self.body_policy_id or not self.effect_policy_ref
                or type(self.body_policy_version) is not int or self.body_policy_version < 1
                or type(self.cpu_ceiling_ms) is not int or not 1 <= self.cpu_ceiling_ms <= 60000):
            raise ValueError("Life Body preparation requires fixed installed policies and a finite CPU ceiling")


@dataclass(frozen=True, slots=True)
class LifeBodyPreparationStageV1:
    stage: object
    request: PrepareSourceNoteBodyRequestV1
    root: object
    quote: ResourceQuote
    body: object
    reservation: object
    effect_policy: object


@dataclass(frozen=True, slots=True)
class LifeBodyPreparationOriginalV1:
    action_intent_ref: str
    action_intent_digest: str
    action_operation_id: str
    body_prepare_operation_id: str
    activity_id: str
    effect_id: str
    body_quote_ref: str
    body_quote_version: int
    body_quote_digest: str
    resource_quote_ref: str
    resource_quote_version: int
    resource_quote_digest: str
    reservation_ref: str
    reservation_revision: int
    reservation_digest: str
    settlement_ref: str
    component_id: str
    effect_policy_ref: str
    effect_policy_revision: int
    effect_policy_digest: str
    receipt_digest: str
    schema: str = "d02.life-body-preparation-original.v1"

    def __post_init__(self):
        if (self.schema != "d02.life-body-preparation-original.v1"
                or self.body_prepare_operation_id != "d02-life-body:" + self.action_operation_id
                or self.reservation_revision < 1):
            raise ValueError("Life Body original must retain its actual distinct producing command B")


def life_body_preparation_original_from_wire_v1(raw):
    return LifeBodyPreparationOriginalV1(**raw)


def _refs(namespace, activity, operation):
    tag = canonical_digest((namespace, operation))[:48]
    owner = Owner("activity", *namespace.as_tuple, activity)
    return (AtomKey(owner, "d02.reservation.v1", "life-body:" + tag),
        AtomKey(owner, "d02.settlement.v1", "life-body:" + tag))


def read_plan_source_note_body_v1(db, *, namespace, activity_id, operation_id, request, now_utc):
    from .d11_life_product_adapter_v1 import life_inventory_read_inputs_v1, raw_life_original_v1, LIFE_CURRENT_TYPES
    from .d11_life_scope_v1 import life_scope_from_action_v1
    row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (request.action_intent_ref, *namespace.as_tuple)).fetchone()
    if row is None or row[1] != 1:
        raise MissingProductionOriginalV1("current_source_note_body_root")
    action = json.loads(row[0])
    root = raw_life_original_v1(db, namespace, "source_note_action", "life-root:" + action["identity"]["operation_id"])
    if root is None:
        raise MissingProductionOriginalV1("actual_source_note_body_root_original")
    scope = life_scope_from_action_v1(db, namespace=namespace, action_ref=request.action_intent_ref,
        project_ref=root["project_ref"], input_source_ref=root["input_source_ref"], audiences=root["audiences"], now_utc=now_utc)
    keys, roots, originals = life_inventory_read_inputs_v1(db, namespace=namespace, scope=scope)
    keys += [AtomKey.from_token(root["project_ref"]), AtomKey.from_token(root["recipe_ref"])]
    roots += [root["input_source_ref"]]
    keys += [AtomKey.from_token(request.action_intent_ref), *_refs(namespace, activity_id, operation_id)]
    return production_read_plan_v1(LIFE_CURRENT_TYPES, keys,
        roots, (*originals, request.action_intent_ref, request.effect_policy_ref))


def stage_prepare_source_note_body_in_transaction_v1(db, *, frame, request, installed_readers):
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns, identity = frame.envelope.authority.namespace, frame.envelope.identity
    root = require_source_note_action_original_v1(db, namespace=ns, action_intent_ref=request.action_intent_ref,
        issuer=installed_readers.issuer)
    action = read.head(db, request.action_intent_ref, required=True)
    if (identity.operation_id != "d02-life-body:" + root.action_operation_id
            or (identity.activity_id, identity.effect_id) != (root.activity_id, root.effect_id)
            or canonical_digest(action.value) != root.action_intent_digest
            or not set(frame.envelope.authority.audience) <= set(root.audiences)):
        raise ValueError("Life Body command B differs from its actual committed root A")
    for audience in root.audiences:
        for purpose in ("context", "consolidation"):
            read.source_family(db, (root.input_source_ref,), purpose=purpose, audience=audience)
    policy = installed_readers.body_quote_authority.policy(db, ns, request.body_policy_id, request.body_policy_version)
    profile, state, reservations = installed_readers._current_body(db, read, policy.profile.profile_id)
    if policy.work_kind != WORK_KIND or profile != policy.profile:
        raise ValueError("Life Body policy does not price the actual installed source-note component")
    row = db.execute("SELECT policy_ref,revision,kind,payload_json,payload_digest,signature FROM graph_d02_production_policies_v1 "
        "WHERE bot=? AND persona=? AND policy_ref=? AND kind='effect' ORDER BY revision DESC LIMIT 1",
        (*ns.as_tuple, request.effect_policy_ref)).fetchone()
    if row is None:
        raise MissingProductionOriginalV1("actual_source_note_body_effect_policy")
    effect_policy, _ = installed_readers._policy(read, row)
    if (effect_policy.profile_id, effect_policy.work_kind, effect_policy.component_id) != (profile.profile_id, WORK_KIND, policy.component.component_id):
        raise ValueError("Life Body effect policy and original quoted component differ")
    reservation_key, settlement_key = _refs(ns, identity.activity_id, identity.operation_id)
    if read.head(db, reservation_key).revision or read.head(db, settlement_key).revision:
        raise ValueError("Life Body reservation identity is already adopted")
    quote = ResourceQuote("resource-quote:life-body:" + canonical_digest((ns, identity.operation_id)), 1,
        *ns.as_tuple, identity.activity_id, identity.operation_id, identity.effect_id, frame.envelope.parent_budget_lease_ref,
        WORK_KIND, "graph:" + canonical_digest(frame.snapshot), frame.envelope.deadline_utc,
        "resource:life-body:" + identity.operation_id, None, (), (settlement_key.token,),
        {"cpu_ms": request.cpu_ceiling_ms}, None, frame.envelope.deadline_utc)
    domain = BodyDomain()
    body = domain.quote_work(profile, state, identity.activity_id, WORK_KIND, 0.0, (policy.component,), valid_until=policy.valid_until)
    body = replace(body, quote_id="body-quote:" + canonical_digest({"namespace": list(ns.as_tuple),
        "operation_id": identity.operation_id, "policy_id": policy.policy_id, "policy_version": policy.version}))
    reservation = domain.reserve_work(state, reservations, body, reservation_key.name, identity.effect_id)
    write = domain.reservation_write(ns, identity.activity_id, reservation)
    primary = stage_result_v1(frame, "d02", "prepare_source_note_body", request, writes=(write,),
        provenance={"life_body_root_action_ref": root.action_intent_ref, "life_body_root_action_digest": root.action_intent_digest,
            "life_body_resource_quote": quote, "life_body_quote": body, "life_body_effect_policy": effect_policy},
        proposal_schema="d02.proposal.v1", proposal_hash=domain.descriptor.request_schema_hash)
    domain.validate(primary.proposals[0], frame.snapshot)
    return LifeBodyPreparationStageV1(primary, request, root, quote, body, reservation, effect_policy)


def issue_life_body_quotes_before_cas_v1(db, *, frame, staged, installed_readers):
    # Called once after the independent pure rebuild, inside the same W01 SQL
    # transaction as its actual reservation Graph CAS. Any failure rolls back.
    read = CurrentDomainReadV1(frame)
    _, state, reservations = installed_readers._current_body(db, read, staged.body.profile_id)
    installed_readers.issuer.resource_issuer.issue_quote(db, staged.quote)
    issued = installed_readers.body_quote_authority.issue_fixed_quote_and_reservation(db,
        installed_readers.issuer.resource_issuer, frame.envelope, staged.quote,
        staged.request.body_policy_id, staged.request.body_policy_version, state, reservations,
        staged.reservation.reservation_id, staged.root.effect_id)
    if issued.body_quote != staged.body or issued.reservation != staged.reservation:
        raise ValueError("actual signed Body quote differs from the independently built reservation")


def record_life_body_preparation_after_cas_v1(db, *, frame, staged, receipt, issuer):
    from .d11_life_preparation_v1 import _record
    write = staged.stage.proposals[0].typed_writes[0]
    if len(receipt.write_versions) != 1 or receipt.write_versions[0].key != write.key:
        raise ValueError("Life Body preparation must adopt exactly its actual reservation")
    root, body, quote, policy = staged.root, staged.body, staged.quote, staged.effect_policy
    original = LifeBodyPreparationOriginalV1(root.action_intent_ref, root.action_intent_digest, root.action_operation_id,
        frame.envelope.identity.operation_id, root.activity_id, root.effect_id, body.quote_id, 1, canonical_digest(body),
        quote.quote_id, quote.version, canonical_digest(quote), write.key.token, receipt.write_versions[0].revision,
        canonical_digest(write.value), quote.d02_settlement_refs[0], policy.component_id, policy.policy_ref,
        policy.revision, canonical_digest(plain_v1(policy)), canonical_digest(receipt))
    return _record(db, issuer=issuer, namespace=staged.stage.namespace, kind="life_body_preparation",
        ref="life-body:" + original.body_prepare_operation_id, operation_id=original.body_prepare_operation_id, value=original)


def require_life_body_preparation_v1(db, *, prepared, issuer, resource_issuer, body_quote_authority):
    from .d11_life_preparation_v1 import _read
    from .d04_root_original_store_v1 import _receipt
    b = prepared.binding
    contract = LifeBodyComponentContractV1(**json.loads(prepared.plan.body_effect_request_json))
    saved = _read(db, issuer=issuer, namespace=b.namespace, kind="life_body_preparation",
        ref="life-body:" + contract.body_prepare_operation_id)
    if saved is None:
        raise MissingProductionOriginalV1("actual_signed_life_body_preparation")
    raw, operation = saved
    original = life_body_preparation_original_from_wire_v1(raw)
    root = require_source_note_action_original_v1(db, namespace=b.namespace, action_intent_ref=prepared.plan.action_intent.ref, issuer=issuer)
    if (operation != original.body_prepare_operation_id or original.action_operation_id != b.operation_id
            or (original.action_intent_ref, original.action_intent_digest, original.activity_id, original.effect_id) !=
                (root.action_intent_ref, root.action_intent_digest, b.activity_id, b.effect_id)):
        raise ValueError("signed Life Body preparation does not bind the true root A")
    for name in ("body_quote_ref", "body_quote_version", "body_quote_digest", "resource_quote_ref", "resource_quote_version",
            "resource_quote_digest", "reservation_ref", "settlement_ref", "component_id", "effect_policy_ref", "body_prepare_operation_id"):
        if getattr(original, name) != getattr(contract, name):
            raise ValueError("caller Life Body contract differs from its actual signed preparation")
    receipt = _receipt(db, b.namespace, operation)
    if (canonical_digest(receipt) != original.receipt_digest or len(receipt.write_versions) != 1
            or (receipt.write_versions[0].key.token, receipt.write_versions[0].revision) != (original.reservation_ref, original.reservation_revision)):
        raise ValueError("Life Body preparation loses its actual Graph reservation receipt")
    history = db.execute("SELECT value,valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?",
        (original.reservation_ref, original.reservation_revision)).fetchone()
    if (history is None or history[1:] != (1, *b.namespace.as_tuple, b.activity_id, operation)
            or canonical_digest(json.loads(history[0])) != original.reservation_digest):
        raise ValueError("Life Body reservation loses its actual producing event")
    quote = resource_issuer.original_signed_quote(db, original.resource_quote_ref, original.resource_quote_version)
    body = body_quote_authority.original_body_quote(db, original.body_quote_ref, original.body_quote_version, quote, operation)
    if (canonical_digest(quote) != original.resource_quote_digest or canonical_digest(body) != original.body_quote_digest
            or (quote.operation_id, quote.activity_id, quote.effect_id) != (operation, b.activity_id, b.effect_id)
            or quote.ceiling.get("cpu_ms", 0) < b.cpu_ceiling_ms):
        raise ValueError("Life Body original quote identity or explicit CPU ceiling differs")
    return original
