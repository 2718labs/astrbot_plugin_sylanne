"""D08 originals for a party's exact agreed confirmation predicate.

External confirmation never creates local ActionOutcome, execution or CPU cost.
"""
from dataclasses import dataclass
import json

from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d08.execution import GoalPredicate, _decode_joint_plan
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import SourceRecord
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .domain_background_read_v3 import (background_point_v3, background_rows_v3, background_json_loads_v3,
    background_json_matches_v3, background_json_digest_v3, background_verify_signature_v3, background_history_v3)
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .natural_producer_qualification_v1 import _producer_original_point_v3

TABLE = "graph_d08_joint_node_originals_v1"
SIGN_KIND = "d11.d08-joint-node-original.v1"
COLUMNS = ("bot", "persona", "original_ref", "kind", "producing_operation_id", "payload_json", "payload_digest", "signature", "source_refs_json")
CONFIRMATION_PROVIDER = "d08.joint-external-confirmation.v1"
EXTERNAL_KINDS = frozenset(("external_node_contract_v1", "external_node_observation_v1"))


@dataclass(frozen=True, slots=True)
class JointExternalNodeContractV1:
    namespace: NamespaceId
    node_id: str
    party_ref: str
    success_predicate: GoalPredicate
    source_refs: tuple[str, ...]
    audience: tuple[str, ...]
    purpose: str
    original_deadline_utc: float
    schema: str = "d08.joint-external-node-contract.v1"

    def __post_init__(self):
        if (self.schema != "d08.joint-external-node-contract.v1" or type(self.namespace) is not NamespaceId
                or not self.node_id.startswith("task:") or not self.party_ref.startswith("entity:")
                or type(self.success_predicate) is not GoalPredicate
                or (self.success_predicate.kind, self.success_predicate.observation_provider) not in {
                    ("explicit_confirmation", CONFIRMATION_PROVIDER), ("recipient_acknowledged", CONFIRMATION_PROVIDER)}
                or type(self.source_refs) is not tuple or not 1 <= len(self.source_refs) <= 32
                or len(set(self.source_refs)) != len(self.source_refs)
                or type(self.audience) is not tuple or not self.audience
                or self.success_predicate.valid_until != self.original_deadline_utc):
            raise ValueError("external node contract requires the exact finite pre-agreed confirmation predicate")
        if dict(self.success_predicate.parameters) != {"party_ref": self.party_ref, "node_id": self.node_id}:
            raise ValueError("external confirmation predicate must name the actual responsible party and node")
        for ref in self.source_refs:
            key = AtomKey.from_token(ref)
            if key.type_name != "memory.source" or NamespaceId.from_key(key) != self.namespace:
                raise ValueError("external contract Source crossed namespace")

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))

    @property
    def original_ref(self):
        return "joint-external-contract:" + self.digest


@dataclass(frozen=True, slots=True)
class RegisterJointExternalNodeContractRequestV1:
    contract: JointExternalNodeContractV1


@dataclass(frozen=True, slots=True)
class ObserveJointExternalNodeRequestV1:
    plan_ref: str
    expected_plan_revision: int
    node_id: str
    inbound_source: GraphVersion
    interpretation: GraphVersion
    party_consent_ref: str
    party_consent_digest: str

    def __post_init__(self):
        if (AtomKey.from_token(self.plan_ref).type_name != "d08.joint_plan.v1"
                or self.expected_plan_revision < 1 or not self.node_id.startswith("task:")
                or self.inbound_source.key.type_name != "memory.source"
                or self.interpretation.key.type_name != "d07.current_interpretation.v1"
                or self.inbound_source.revision < 1 or self.interpretation.revision < 1):
            raise ValueError("external observation requires actual current plan, inbound Source and D07 heads")


@dataclass(frozen=True, slots=True)
class JointExternalNodeObservationV1:
    namespace: NamespaceId
    plan_ref: str
    plan_revision: int
    terms_digest: str
    node_id: str
    party_ref: str
    contract_ref: str
    contract_digest: str
    party_consent_ref: str
    party_consent_digest: str
    inbound_source: GraphVersion
    source_digest: str
    interpretation: GraphVersion
    interpretation_digest: str
    actor_heads: tuple[GraphVersion, ...]
    success_predicate: GoalPredicate
    question_scope: str
    proposition: str
    observed_at_utc: float
    source_refs: tuple[str, ...]
    producing_operation_id: str
    qualification: str = "externally_confirmed"
    schema: str = "d08.joint-external-node-observation.v1"

    def __post_init__(self):
        if (self.schema != "d08.joint-external-node-observation.v1" or self.qualification != "externally_confirmed"
                or self.success_predicate.observation_provider != CONFIRMATION_PROVIDER
                or self.success_predicate.kind not in {"explicit_confirmation", "recipient_acknowledged"}
                or self.inbound_source.key.type_name != "memory.source"
                or self.interpretation.key.type_name != "d07.current_interpretation.v1"
                or len(self.actor_heads) != 2 or self.plan_revision < 1
                or self.inbound_source.key.token not in self.source_refs):
            raise ValueError("external observation does not prove its exact agreed confirmation predicate")

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))

    @property
    def original_ref(self):
        return "joint-external-observation:" + canonical_digest((self.namespace, self.plan_ref,
            self.plan_revision, self.node_id, self.inbound_source, self.interpretation, self.terms_digest))


from .joint_compensation_v1 import JointCompensationAuthorizationV1


ORIGINAL_TYPES = {"compensation_authorization_v1": JointCompensationAuthorizationV1,
    "external_node_contract_v1": JointExternalNodeContractV1,
    "external_node_observation_v1": JointExternalNodeObservationV1}


def install_joint_external_schema_v1(db):
    db.execute("CREATE TABLE IF NOT EXISTS " + TABLE + " (bot TEXT NOT NULL,persona TEXT NOT NULL,original_ref TEXT NOT NULL,"
        "kind TEXT NOT NULL,producing_operation_id TEXT NOT NULL,payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,"
        "signature TEXT NOT NULL,source_refs_json TEXT NOT NULL,PRIMARY KEY(bot,persona,original_ref))")
    db.execute("CREATE INDEX IF NOT EXISTS graph_d08_joint_node_original_kind_v1 ON " + TABLE + "(bot,persona,kind,original_ref)")


def read_joint_d08_original_v1(db, *, namespace, original_ref, issuer):
    row = _producer_original_point_v3(db, table=TABLE,
        columns=("kind", "producing_operation_id", "payload_json", "payload_digest", "signature"),
        key_columns=("bot", "persona", "original_ref"), key=(*namespace.as_tuple, original_ref),
        legacy_reader=lambda: db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
            " WHERE bot=? AND persona=? AND original_ref=?", (*namespace.as_tuple, original_ref)).fetchone())
    if row is None:
        raise MissingProductionOriginalV1("actual_registered_joint_d08_original:" + original_ref)
    background_verify_signature_v3(issuer._signer, SIGN_KIND, row[2], row[4])
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    raw = background_json_loads_v3(row[2])
    value = decode_typed_production_value_v1(raw, ORIGINAL_TYPES[row[0]])
    original = read_adopted_domain_operation_v1(db, namespace, row[1])
    if (value.namespace != namespace or value.original_ref != original_ref or value.digest != row[3]
            or not background_json_matches_v3(row[2], raw) or background_json_digest_v3(row[2], raw) != row[3]
            or original is None or (original["domain"], original["operation_kind"]) != ("d08", {
                "external_node_contract_v1": "input:register_joint_external_contract_v1",
                "external_node_observation_v1": "input:observe_joint_external_node_v1",
                "compensation_authorization_v1": "input:register_joint_compensation_v1"}[row[0]])):
        raise ValueError("D08 Joint original changed its exact signed bytes and actual writer")
    return value


def external_node_question_scope_v1(plan, terms_digest, node, contract):
    return "d08.joint-external-node-confirmation:" + canonical_digest((
        plan.plan_id, plan.revision, terms_digest, node.node_id, contract.party_ref,
        contract.digest, plain_v1(node.success_predicate)))


def _external_node_v1(db, *, frame, plan_ref, revision, node_id, issuer):
    from .joint_node_execution_v1 import _plan_original_v1, QualifyJointPlanNodesRequestV1
    from .d08_production_operations_v1 import InstalledD08ProductionReadersV1
    request = QualifyJointPlanNodesRequestV1(plan_ref, revision, "")
    plan, inputs = _plan_original_v1(db, frame=frame, request=request, readers=InstalledD08ProductionReadersV1(issuer=issuer))
    node = next((node for node in plan.nodes if node.node_id == node_id), None)
    if node is None or node.owner_ref == "persona:" + frame.envelope.authority.namespace.persona_id:
        raise ValueError("external observation cannot impersonate a local persona node")
    contract = read_joint_d08_original_v1(db, namespace=frame.envelope.authority.namespace,
        original_ref=node.resource_ref, issuer=issuer)
    if (type(contract) is not JointExternalNodeContractV1 or (contract.node_id, contract.party_ref,
            contract.success_predicate) != (node.node_id, node.owner_ref, node.success_predicate)):
        raise ValueError("external contract is outside the exact adopted party terms")
    return plan, inputs, node, contract


def qualify_external_observation_v1(db, *, frame, request, issuer):
    read = CurrentDomainReadV1(frame); read.check(db)
    plan, inputs, node, contract = _external_node_v1(db, frame=frame, plan_ref=request.plan_ref,
        revision=request.expected_plan_revision, node_id=request.node_id, issuer=issuer)
    consent = next((original for original in inputs.consent_originals if original.original_ref == request.party_consent_ref), None)
    if consent is None or consent.original_digest != request.party_consent_digest:
        raise ValueError("external confirmation changed its exact original party consent")
    consent_row = _producer_original_point_v3(db, table="graph_d08_party_consents_v1", columns=("payload_json",),
        key_columns=("bot", "persona", "original_ref"), key=(*contract.namespace.as_tuple, request.party_consent_ref),
        legacy_reader=lambda: db.execute("SELECT payload_json FROM graph_d08_party_consents_v1 WHERE bot=? AND persona=? AND original_ref=?",
            (*contract.namespace.as_tuple, request.party_consent_ref)).fetchone())
    consent_value = background_json_loads_v3(consent_row[0])
    if consent_value["participant_ref"] != contract.party_ref or node.node_id not in consent_value["accepted_scope"]:
        raise ValueError("inbound confirmation has another party's responsibility")
    source = read.head(db, request.inbound_source.key, required=True)
    if source.revision != request.inbound_source.revision:
        raise MissingProductionOriginalV1("current_external_confirmation_source_version")
    account, entity = read.actor_entity(db, source.key.token, expected_entity=contract.party_ref)
    question_scope = external_node_question_scope_v1(plan, inputs.terms_digest, node, contract)
    interpretation, _, records = read.adopted_interpretation(db, request.interpretation.key.token, question_scope=question_scope)
    proposition = "confirmed" if node.success_predicate.kind == "explicit_confirmation" else "acknowledged"
    if (interpretation.revision != request.interpretation.revision or interpretation.value["proposition"] != proposition
            or source.key.token not in interpretation.value["source_refs"] or source.key.token not in records):
        raise MissingProductionOriginalV1("actual_exact_external_node_confirmation_interpretation")
    record = SourceRecord.from_dict(source.value)
    observed = record.recorded_at
    if not node.success_predicate.valid_from <= observed <= contract.original_deadline_utc or observed > frame.now_utc:
        raise MissingProductionOriginalV1("external_confirmation_within_original_predicate_interval")
    roots = tuple(dict.fromkeys((*contract.source_refs, source.key.token, *interpretation.value["source_refs"])))
    for audience in contract.audience:
        read.source_family(db, roots, purpose=contract.purpose, audience=audience)
    return JointExternalNodeObservationV1(contract.namespace, request.plan_ref, plan.revision, inputs.terms_digest,
        node.node_id, contract.party_ref, contract.original_ref, contract.digest, request.party_consent_ref,
        request.party_consent_digest, request.inbound_source, canonical_digest(source.value), request.interpretation,
        canonical_digest(interpretation.value), (GraphVersion(account.key, account.revision), GraphVersion(entity.key, entity.revision)),
        node.success_predicate, question_scope, proposition, observed, roots, frame.envelope.identity.operation_id)




def current_external_node_observation_v1(db, *, frame, plan_ref, plan, inputs, node, issuer):
    namespace = frame.envelope.authority.namespace
    rows = tuple((ref, encoded) for ref, encoded, _ in _external_original_rows_v1(db, namespace, "external_node_observation_v1"))
    if len(rows) > 128:
        raise MissingProductionOriginalV1("bounded_external_node_observation_inventory")
    matches = []
    for ref, encoded in rows:
        raw = background_json_loads_v3(encoded)
        if (raw["plan_ref"], raw["plan_revision"], raw["node_id"]) != (plan_ref, plan.revision, node.node_id):
            continue
        value = read_joint_d08_original_v1(db, namespace=namespace, original_ref=ref, issuer=issuer)
        request = ObserveJointExternalNodeRequestV1(plan_ref, plan.revision, node.node_id, value.inbound_source,
            value.interpretation, value.party_consent_ref, value.party_consent_digest)
        try:
            current = qualify_external_observation_v1(db, frame=frame, request=request, issuer=issuer)
        except MissingProductionOriginalV1:
            continue
        if plain_v1(current) != {**plain_v1(value), "producing_operation_id": frame.envelope.identity.operation_id}:
            raise ValueError("external observation no longer matches its actual current actor/Source/interpretation")
        matches.append(value)
    if len(matches) > 1:
        # Several real confirmations establish the same predicate; no new effect.
        matches.sort(key=lambda value: (value.observed_at_utc, value.original_ref))
    return None if not matches else matches[-1]


def external_joint_input_read_plan_v1(db, *, namespace, request):
    if type(request) is RegisterJointExternalNodeContractRequestV1:
        return production_read_plan_v1(("d03.entity_anchor",), (), request.contract.source_refs, ())
    from .joint_node_execution_v1 import joint_input_read_plan_v1, QualifyJointPlanNodesRequestV1
    plan = joint_input_read_plan_v1(db, namespace=namespace,
        request=QualifyJointPlanNodesRequestV1(request.plan_ref, request.expected_plan_revision, ""))
    return production_read_plan_v1((*plan.fixed_type_ids, "d03.account_binding", "d03.entity_anchor", "d07.current_interpretation.v1"),
        (*plan.exact_keys, request.inbound_source.key, request.interpretation.key),
        (*plan.source_roots, request.inbound_source.key.token), (*plan.required_original_refs, request.party_consent_ref))


def validate_joint_external_input_v1(db, *, frame, request, issuer):
    if type(request) is ObserveJointExternalNodeRequestV1:
        return qualify_external_observation_v1(db, frame=frame, request=request, issuer=issuer)
    if type(request) is not RegisterJointExternalNodeContractRequestV1 or type(request.contract) is not JointExternalNodeContractV1:
        raise TypeError("exact registered external contract or actual observed confirmation required")
    contract = request.contract; read = CurrentDomainReadV1(frame); read.check(db)
    if contract.namespace != frame.envelope.authority.namespace or frame.now_utc >= contract.original_deadline_utc:
        raise ValueError("external node contract changed namespace or original deadline")
    parties = tuple(atom for atom in read.complete_inventory(db, "d03.entity_anchor") if atom.valid
        and atom.value["entity_id"] == contract.party_ref and atom.value["status"] == "active")
    if len(parties) != 1:
        raise MissingProductionOriginalV1("actual_current_external_node_party")
    for audience in contract.audience:
        read.source_family(db, contract.source_refs, purpose=contract.purpose, audience=audience)
    return contract


def _external_original_rows_v1(db, namespace, kind, *, node_id=None):
    from .current_method_learning_read_v3 import read_bound_method_joint_original_keys_v3
    handled,keys=False,None
    if node_id is not None:
        if kind!="external_node_observation_v1":raise ValueError("actual external-node metadata selector differs")
        from .artifact_borrowed_source_v3 import read_bound_artifact_borrowed_joint_observation_keys_v3
        handled,keys=read_bound_artifact_borrowed_joint_observation_keys_v3(db,namespace=namespace,node_id=node_id)
        if not handled:
            from ..authority_service.original_artifact_recipe_metadata_v3 import read_bound_original_artifact_joint_observation_keys_v3
            handled,keys=read_bound_original_artifact_joint_observation_keys_v3(db,namespace=namespace,node_id=node_id)
    if not handled:
        handled, keys = read_bound_method_joint_original_keys_v3(db, table=TABLE, namespace=namespace, kind=kind)
    if not handled:
        keys = background_rows_v3(db, table=TABLE, columns=("original_ref",),
            group_columns=("bot", "persona", "kind"), group=(*namespace.as_tuple, kind),
            order_columns=("original_ref",), limit=129,
            legacy_reader=lambda: db.execute("SELECT original_ref FROM " + TABLE +
                " WHERE bot=? AND persona=? AND kind=? ORDER BY original_ref LIMIT 129", (*namespace.as_tuple, kind)).fetchall())
    from .artifact_host_dispatch_source_v3 import register_artifact_host_input_census_v3
    register_artifact_host_input_census_v3(db,table=TABLE,namespace=namespace,kind=kind,keys=keys)
    result = []
    for (ref,) in keys:
        row = _producer_original_point_v3(db, table=TABLE, columns=("kind", "producing_operation_id", "payload_json", "payload_digest", "signature"),
            key_columns=("bot", "persona", "original_ref"), key=(*namespace.as_tuple, ref),
            legacy_reader=lambda ref=ref: db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
                " WHERE bot=? AND persona=? AND original_ref=?", (*namespace.as_tuple, ref)).fetchone())
        result.append((ref, row[2], row[3]))
    return tuple(result)


def joint_external_plan_read_inputs_v1(db, *, namespace, node):
    row = _producer_original_point_v3(db, table=TABLE, columns=("payload_json",),
        key_columns=("bot", "persona", "original_ref"), key=(*namespace.as_tuple, node.resource_ref),
        legacy_reader=lambda: db.execute("SELECT payload_json FROM " + TABLE + " WHERE bot=? AND persona=? AND original_ref=?",
            (*namespace.as_tuple, node.resource_ref)).fetchone())
    keys, roots, originals = [], [], [node.resource_ref]
    if row is not None:
        raw = background_json_loads_v3(row[0]); roots.extend(raw["source_refs"])
    rows = _external_original_rows_v1(db, namespace, "external_node_observation_v1",node_id=node.node_id)
    if len(rows) > 128:
        raise MissingProductionOriginalV1("bounded_current_external_node_observations")
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    for ref, encoded, digest in rows:
        value = decode_typed_production_value_v1(background_json_loads_v3(encoded), JointExternalNodeObservationV1)
        if value.node_id == node.node_id:
            keys.extend((value.inbound_source.key, value.interpretation.key, *(head.key for head in value.actor_heads)))
            roots.extend(value.source_refs); originals.append(ref)
    return keys, roots, originals


def joint_external_result_versions_v1(db, *, namespace, node):
    keys, roots, originals = joint_external_plan_read_inputs_v1(db, namespace=namespace, node=node)
    from .domain_background_read_v3 import background_graph_head_v3
    result = []
    for key in tuple(dict.fromkeys((*keys, *(AtomKey.from_token(ref) for ref in roots)))):
        head = background_graph_head_v3(db, namespace, key)
        result.append((key.token, None if head is None else (head[0], head[2])))
    result.extend((ref,) for ref in originals)
    return tuple(result)


def current_external_observation_requests_v1(db, *, frame, plan_ref, issuer):
    from .joint_node_execution_v1 import _plan_original_v1, QualifyJointPlanNodesRequestV1
    from .d08_production_operations_v1 import InstalledD08ProductionReadersV1
    read = CurrentDomainReadV1(frame); atom = read.head(db, plan_ref, required=True)
    plan, inputs = _plan_original_v1(db, frame=frame,
        request=QualifyJointPlanNodesRequestV1(plan_ref, atom.revision, ""), readers=InstalledD08ProductionReadersV1(issuer=issuer))
    requests = []
    for node in plan.nodes:
        if node.owner_ref == "persona:" + frame.envelope.authority.namespace.persona_id:
            continue
        contract = read_joint_d08_original_v1(db, namespace=frame.envelope.authority.namespace, original_ref=node.resource_ref, issuer=issuer)
        if type(contract) is not JointExternalNodeContractV1:
            raise MissingProductionOriginalV1("registered_external_node_observer_for_actual_predicate")
        question = external_node_question_scope_v1(plan, inputs.terms_digest, node, contract)
        if current_external_node_observation_v1(db, frame=frame, plan_ref=plan_ref, plan=plan, inputs=inputs, node=node, issuer=issuer) is not None:
            continue
        consent_ref = next(original for original in inputs.consent_originals
            if (background_json_loads_v3(_producer_original_point_v3(db, table="graph_d08_party_consents_v1", columns=("payload_json",),
                key_columns=("bot", "persona", "original_ref"), key=(*contract.namespace.as_tuple, original.original_ref),
                legacy_reader=lambda original=original: db.execute("SELECT payload_json FROM graph_d08_party_consents_v1 WHERE bot=? AND persona=? AND original_ref=?",
                    (*contract.namespace.as_tuple, original.original_ref)).fetchone())[0])["participant_ref"] == node.owner_ref))
        interpretations = tuple(value for value in read.complete_inventory(db, "d07.current_interpretation.v1")
            if value.valid and value.value["question_key"] == question and value.value["current"] is True)
        for interpretation in interpretations:
            for source_ref in interpretation.value["source_refs"]:
                source = read.head(db, source_ref, required=True)
                request = ObserveJointExternalNodeRequestV1(plan_ref, plan.revision, node.node_id,
                    GraphVersion(source.key, source.revision), GraphVersion(interpretation.key, interpretation.revision),
                    consent_ref.original_ref, consent_ref.original_digest)
                try:
                    qualify_external_observation_v1(db, frame=frame, request=request, issuer=issuer)
                except MissingProductionOriginalV1:
                    continue
                requests.append(request); break
            if requests and requests[-1].node_id == node.node_id:
                break
    return tuple(requests)


@dataclass(frozen=True, slots=True)
class PrepareJointExternalSemanticQuestionRequestV1:
    plan_ref: str
    expected_plan_revision: int
    node_id: str
    inbound_source: GraphVersion
    attention_ticket: GraphVersion
    c02_operation_id: str
    attention_issuance_operation_id: str


def joint_semantic_question_ref_v1(request):
    return "joint-external-question:" + canonical_digest((request.plan_ref, request.expected_plan_revision,
        request.node_id, request.inbound_source, request.attention_ticket, request.c02_operation_id))


def prepare_joint_external_question_v1(db, *, frame, request, issuer):
    from ..domains.d07 import AttentionTicket
    from .d07_execution_v1 import D07SemanticQuestionV1
    from ..runtime_contracts import VersionedRef
    from ..host.post_c02_attention_driver import post_c02_attention_operation_id
    from .d12_current_d07_policy_v1 import read_current_d07_attention_policy_v1
    from .joint_node_execution_v1 import _joint_head_v1
    read = CurrentDomainReadV1(frame); read.check(db)
    plan, inputs, node, contract = _external_node_v1(db, frame=frame, plan_ref=request.plan_ref,
        revision=request.expected_plan_revision, node_id=request.node_id, issuer=issuer)
    source = read.head(db, request.inbound_source.key, required=True)
    if source.revision != request.inbound_source.revision:
        raise MissingProductionOriginalV1("actual_joint_question_inbound_source_revision")
    read.actor_entity(db, source.key.token, expected_entity=node.owner_ref)
    ticket_atom = read.head(db, request.attention_ticket.key, required=True)
    if ticket_atom.revision != request.attention_ticket.revision:
        raise MissingProductionOriginalV1("actual_joint_question_attention_ticket_revision")
    raw = {k: v for k, v in ticket_atom.value.items() if k != "schema"}
    ticket = AttentionTicket(**{**raw, "source_refs": tuple(raw["source_refs"]), "cancel_refs": tuple(raw["cancel_refs"])})
    if (source.key.token not in ticket.source_refs or ticket.causal_root != source.key.token
            or request.attention_issuance_operation_id != post_c02_attention_operation_id(request.c02_operation_id, source.key.token)
            or ticket.ticket_id != "attention:" + canonical_digest({"operation_id": request.attention_issuance_operation_id})[:48]):
        raise ValueError("Joint question must retain the actual C02-issued ticket and admitted Source")
    issuance = _producer_original_point_v3(db, table="graph_d07_attention_issuance_v1",
        columns=("source_ref", "c02_operation_id", "bundle_digest"), key_columns=("bot", "persona", "operation_id"),
        key=(*contract.namespace.as_tuple, request.attention_issuance_operation_id),
        legacy_reader=lambda: db.execute("SELECT source_ref,c02_operation_id,bundle_digest FROM graph_d07_attention_issuance_v1 "
            "WHERE bot=? AND persona=? AND operation_id=?", (*contract.namespace.as_tuple, request.attention_issuance_operation_id)).fetchone())
    history = background_history_v3(db, ticket_atom.key.token, 1, columns=("event_id",))
    adopted = _producer_original_point_v3(db, table="graph_bundle_operations", columns=("digest", "activity_id", "effect_id", "commit_seq"),
        key_columns=("bot", "persona", "operation_id"), key=(*contract.namespace.as_tuple, request.attention_issuance_operation_id),
        legacy_reader=lambda: db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
            (*contract.namespace.as_tuple, request.attention_issuance_operation_id)).fetchone())
    if (issuance is None or issuance[:2] != (source.key.token, request.c02_operation_id)
            or history is None or history[0] != request.attention_issuance_operation_id
            or adopted is None or adopted[0] != issuance[2] or adopted[3] < 1):
        raise MissingProductionOriginalV1("actual_adopted_c02_joint_attention_issuance")
    policy = read_current_d07_attention_policy_v1(db, contract.namespace)
    if policy.active_head_ref not in frame.snapshot.versions:
        raise MissingProductionOriginalV1("current_joint_semantic_attention_policy")
    if not ticket.eligible or not ticket.resources_available or ticket.cancel_refs or frame.now_utc >= min(ticket.valid_until, contract.original_deadline_utc):
        raise MissingProductionOriginalV1("actual_live_joint_semantic_ticket_and_original_deadline")
    # Registration is not a model permit. Ordinary serving-concern rechecks
    # current D12 Owner, fair choice, standing grant, quote and original budget.
    for audience in contract.audience:
        read.source_family(db, ticket.source_refs, purpose=frame.envelope.authority.purpose, audience=audience)
    question_scope = external_node_question_scope_v1(plan, inputs.terms_digest, node, contract)
    proposition = "confirmed" if node.success_predicate.kind == "explicit_confirmation" else "acknowledged"
    question = "Determine whether this actual responsible party explicitly " + proposition + " the exact agreed node predicate. "         "Use only the admitted statement and frozen Joint terms; uncertain, withdrawn or conflicting statements remain unknown. "         "This question concerns a confirmation condition and makes no claim of local execution, artifact verification or CPU cost."
    return D07SemanticQuestionV1(question_scope, question, VersionedRef(request.plan_ref, plan.revision), tuple(ticket.source_refs))


def current_joint_semantic_question_requests_v1(db, *, frame, plan_ref, issuer):
    from .joint_node_execution_v1 import _plan_original_v1, QualifyJointPlanNodesRequestV1
    from .d08_production_operations_v1 import InstalledD08ProductionReadersV1
    from .d07_execution_v1 import read_current_d07_semantic_question_v1
    read = CurrentDomainReadV1(frame); plan_atom = read.head(db, plan_ref, required=True)
    plan, inputs = _plan_original_v1(db, frame=frame, request=QualifyJointPlanNodesRequestV1(plan_ref, plan_atom.revision, ""),
        readers=InstalledD08ProductionReadersV1(issuer=issuer))
    result = []
    for node in plan.nodes:
        if node.owner_ref == "persona:" + frame.envelope.authority.namespace.persona_id:
            continue
        contract = read_joint_d08_original_v1(db, namespace=frame.envelope.authority.namespace, original_ref=node.resource_ref, issuer=issuer)
        if current_external_node_observation_v1(db, frame=frame, plan_ref=plan_ref, plan=plan, inputs=inputs, node=node, issuer=issuer) is not None:
            continue
        for ticket_atom in read.complete_inventory(db, "d07.attention_ticket.v1"):
            if not ticket_atom.valid:
                continue
            source_ref = ticket_atom.value["causal_root"]
            source = read.head(db, source_ref, required=True)
            history = background_history_v3(db, ticket_atom.key.token, 1, columns=("event_id",))
            if history is None:
                continue
            issuance_operation = history[0]
            issuance = _producer_original_point_v3(db, table="graph_d07_attention_issuance_v1",
                columns=("source_ref", "c02_operation_id", "bundle_digest"), key_columns=("bot", "persona", "operation_id"),
                key=(*contract.namespace.as_tuple, issuance_operation),
                legacy_reader=lambda: db.execute("SELECT source_ref,c02_operation_id,bundle_digest FROM graph_d07_attention_issuance_v1 "
                    "WHERE bot=? AND persona=? AND operation_id=?", (*contract.namespace.as_tuple, issuance_operation)).fetchone())
            if issuance is None or issuance[0] != source_ref:
                continue
            request = PrepareJointExternalSemanticQuestionRequestV1(plan_ref, plan.revision, node.node_id,
                GraphVersion(source.key, source.revision), GraphVersion(ticket_atom.key, ticket_atom.revision),
                issuance[1], issuance_operation)
            try:
                prepare_joint_external_question_v1(db, frame=frame, request=request, issuer=issuer)
            except MissingProductionOriginalV1:
                continue
            if read_current_d07_semantic_question_v1(db, issuer, contract.namespace, joint_semantic_question_ref_v1(request)) is None:
                result.append(request)
            break
    return tuple(result)


def joint_semantic_input_read_plan_v1(db, *, namespace, request):
    from .joint_node_execution_v1 import joint_input_read_plan_v1, QualifyJointPlanNodesRequestV1
    from ..domains.d07.concern_round import concern_round_key
    from ..domains.d12.types import active_scheme_head_key
    plan = joint_input_read_plan_v1(db, namespace=namespace,
        request=QualifyJointPlanNodesRequestV1(request.plan_ref, request.expected_plan_revision, ""))
    return production_read_plan_v1((*plan.fixed_type_ids, "d07.attention_ticket.v1", "d07.focus.v1", "d07.concern_round.v1"),
        (*plan.exact_keys, request.inbound_source.key, request.attention_ticket.key, active_scheme_head_key(namespace)),
        (*plan.source_roots, request.inbound_source.key.token), (*plan.required_original_refs, request.inbound_source.key.token))


@dataclass(frozen=True, slots=True)
class JointExternalSemanticBasisV1:
    namespace: NamespaceId
    question_ref: str
    question_digest: str
    request: PrepareJointExternalSemanticQuestionRequestV1
    source_refs: tuple[str, ...]
    parent_budget_lease_ref: str
    parent_grant_id: str
    parent_grant_version: int
    parent_grant_digest: str
    original_deadline_utc: float
    producing_operation_id: str
    schema: str = "d07.joint-external-semantic-basis.v1"

    @property
    def original_ref(self):
        return "joint-semantic-basis:" + canonical_digest((self.namespace, self.question_ref))




def read_current_joint_semantic_basis_v1(db, *, namespace, question_ref, issuer):
    from .d07_execution_v1 import read_d07_original_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    ref = "joint-semantic-basis:" + canonical_digest((namespace, question_ref))
    row = read_d07_original_v1(db, issuer, namespace, "joint_external_semantic_basis_v1", ref)
    if row is None:
        raise MissingProductionOriginalV1("actual_joint_semantic_signed_parent_basis")
    value = decode_typed_production_value_v1(row[0], JointExternalSemanticBasisV1)
    producer = read_adopted_domain_operation_v1(db, namespace, value.producing_operation_id)
    if (value.namespace != namespace or value.original_ref != ref or value.question_ref != question_ref
            or producer is None or (producer["domain"], producer["operation_kind"]) != ("d07", "input:prepare_joint_external_semantic_question_v1")
            or producer["payload"]["parent_budget"] != value.parent_budget_lease_ref
            or producer["payload"]["request"] != plain_v1(value.request)):
        raise ValueError("Joint semantic basis lost its actual Owner/C02/parent producer")
    source = _producer_original_point_v3(db, table="graph_d07_execution_originals_v1",
        columns=("payload_json", "payload_digest", "signature"), key_columns=("bot", "persona", "kind", "original_ref"),
        key=(*namespace.as_tuple, "joint_external_semantic_basis_v1", ref),
        legacy_reader=lambda: db.execute("SELECT payload_json,payload_digest,signature FROM graph_d07_execution_originals_v1 "
            "WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*namespace.as_tuple, "joint_external_semantic_basis_v1", ref)).fetchone())
    from .domain_background_read_v3 import register_joint_semantic_budget_locator_v3
    register_joint_semantic_budget_locator_v3(db, original=source[0], namespace=namespace, kind="joint_external_semantic_basis_v1",
        original_ref=ref, digest=source[1], signature=source[2], lease_id=value.parent_budget_lease_ref,
        version=value.parent_grant_version, signer=issuer._signer)
    return value


def require_current_joint_semantic_basis_v1(db, *, frame, question_ref, issuer):
    basis = read_current_joint_semantic_basis_v1(db, namespace=frame.envelope.authority.namespace, question_ref=question_ref, issuer=issuer)
    if frame.envelope.parent_budget_lease_ref != basis.parent_budget_lease_ref or frame.now_utc >= basis.original_deadline_utc:
        raise MissingProductionOriginalV1("actual_original_joint_semantic_parent_and_deadline")
    grant = issuer.current_budget_grant(db, basis.parent_budget_lease_ref)
    if (grant.grant_id, grant.version, canonical_digest(grant)) != (basis.parent_grant_id, basis.parent_grant_version, basis.parent_grant_digest):
        raise MissingProductionOriginalV1("current_original_joint_semantic_grant")
    question = prepare_joint_external_question_v1(db, frame=frame, request=basis.request, issuer=issuer)
    if canonical_digest(plain_v1(question)) != basis.question_digest:
        raise ValueError("Joint semantic question changed its admitted actor/Source/plan terms")
    return basis


def resolve_joint_external_cognition_v1(db, *, frame, original, issuer):
    from .domain_production_followups_v1 import DomainFollowupCommandV1, DomainFollowupResolutionV1
    from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1
    from ..domains.d07 import AttentionTicket
    from ..domains.d07.concern_round import ConcernRoundV1, read_concern_round, choose_concern_segment
    from .d12_current_d07_policy_v1 import read_current_d07_attention_policy_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    request = decode_typed_production_value_v1(original["payload"]["request"], PrepareJointExternalSemanticQuestionRequestV1)
    question_ref = joint_semantic_question_ref_v1(request)
    basis = require_current_joint_semantic_basis_v1(db, frame=frame, question_ref=question_ref, issuer=issuer)
    observed = current_external_observation_requests_v1(db, frame=frame, plan_ref=request.plan_ref, issuer=issuer)
    confirmed = tuple(value for value in observed if value.node_id == request.node_id)
    if confirmed:
        commands = tuple(DomainFollowupCommandV1("d08", "input:observe_joint_external_node_v1", value,
            "joint-confirmation:" + canonical_digest((basis.namespace, question_ref))[:48], frame.envelope.authority.audience[0],
            frame.envelope.authority.audience) for value in confirmed)
        return DomainFollowupResolutionV1("ready", commands, (request.plan_ref,), ())
    read = CurrentDomainReadV1(frame); ticket_atom = read.head(db, request.attention_ticket.key, required=True)
    category = ticket_atom.value["category"]
    tickets = []
    for atom in read.complete_inventory(db, "d07.attention_ticket.v1"):
        if atom.valid:
            raw = {k: v for k, v in atom.value.items() if k != "schema"}
            tickets.append(AttentionTicket(**{**raw, "source_refs": tuple(raw["source_refs"]), "cancel_refs": tuple(raw["cancel_refs"])}))
    policy = read_current_d07_attention_policy_v1(db, basis.namespace).policy
    found = read_concern_round(frame.snapshot, basis.namespace, category)
    state = found[0] if found is not None else ConcernRoundV1(basis.namespace.persona_id, category, 0, 0, (), (), (), ())
    focus = next(atom for atom in read.complete_inventory(db, "d07.focus.v1") if atom.valid)
    choice = choose_concern_segment(state, tuple(tickets), policy, now=frame.now_utc, focus_epoch=focus.value["focus_epoch"])
    if choice is None or choice.ticket_id != ticket_atom.value["ticket_id"]:
        return DomainFollowupResolutionV1("waiting_for_original", (), (request.plan_ref,),
            ("actual_fair_c02_joint_semantic_source_choice",), "joint-semantic-fairness:" + question_ref)
    return DomainFollowupResolutionV1("partial", (DomainFollowupCommandV1("d07", "serve_concern",
        ServeCurrentConcernRequestV1(category, question_ref), "joint-cognition:" + canonical_digest((basis.namespace, question_ref))[:48],
        frame.envelope.authority.audience[0], frame.envelope.authority.audience),), (request.plan_ref,),
        ("actual_adopted_joint_semantic_interpretation",), "joint-semantic-result:" + question_ref)


def validate_joint_d08_joins_v1(db):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1, DomainProductionErasureHold
    from .joint_node_execution_v1 import validate_joint_retained_producer_v1
    for bot, persona, ref, kind, operation, encoded, digest in db.execute(
            "SELECT bot,persona,original_ref,kind,producing_operation_id,payload_json,payload_digest FROM " + TABLE):
        namespace = NamespaceId(bot, persona)
        value = decode_typed_production_value_v1(json.loads(encoded), ORIGINAL_TYPES[kind])
        if value.namespace != namespace or value.original_ref != ref or value.digest != digest:
            raise DomainProductionErasureHold("Joint D08 original changed its exact namespace/ref/digest")
        if kind == "external_node_contract_v1":
            request = RegisterJointExternalNodeContractRequestV1(value)
            operation_kind = "input:register_joint_external_contract_v1"
        elif kind == "external_node_observation_v1":
            request = ObserveJointExternalNodeRequestV1(value.plan_ref, value.plan_revision, value.node_id,
                value.inbound_source, value.interpretation, value.party_consent_ref, value.party_consent_digest)
            operation_kind = "input:observe_joint_external_node_v1"
        else:
            from .joint_compensation_v1 import RegisterJointCompensationRequestV1
            request = RegisterJointCompensationRequestV1(value)
            operation_kind = "input:register_joint_compensation_v1"
        validate_joint_retained_producer_v1(db, namespace=namespace, operation_id=operation, domain="d08",
            operation_kind=operation_kind, request_digest=canonical_digest(plain_v1(request)))
