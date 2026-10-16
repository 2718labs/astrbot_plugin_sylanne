"""Joint Contact birth contract and metadata-only Source locator parser."""
from dataclasses import asdict
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..graph_types import AtomKey,Owner
from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1
from ..domains.d01.production_operations_v1 import plain_v1

def qualify_contact_prospective_binding_v1(db,*,frame,binding,issuer):
    from .joint_node_execution_v1 import JointContactProspectiveBindingV1
    from .contact_prospective_v1 import read_contact_prospective_original_v1,contact_prospective_original_ref_v1
    from .joint_contact_preparation_v1 import read_current_joint_contact_preparation_v1
    from ..domains.d08.execution import _decode_intent,ActionSchemaRecord,_check_spec,ActionSchema
    import json
    if type(binding) is not JointContactProspectiveBindingV1:
        raise TypeError("exact immutable Contact prospective Joint binding required")
    read=CurrentDomainReadV1(frame);read.check(db)
    if binding.namespace!=frame.envelope.authority.namespace:
        raise ValueError("Contact prospective binding crossed its current namespace")
    original=read_contact_prospective_original_v1(db,issuer,binding.namespace,binding.contact_id)
    if original is None:raise MissingProductionOriginalV1("actual_signed_contact_prospective_birth")
    raw=json.loads(original.payload_json);terms=raw["terms"];candidate=raw["candidate"]
    preparation=read_current_joint_contact_preparation_v1(db,namespace=binding.namespace,
        original_ref=raw["joint_preparation"]["ref"],issuer=issuer)
    declared=preparation.request
    if (original.digest!=binding.prospective_original_digest
            or contact_prospective_original_ref_v1(binding.namespace,binding.contact_id,raw["birth_operation_id"])!=binding.prospective_original_ref
            or binding.refresh_rule!=raw["refresh_rule"]
            or (declared.joint_plan_ref,declared.joint_plan_revision,declared.node_id,preparation.owner_ref)!=(
                binding.plan_ref,binding.plan_revision,binding.node_id,binding.owner_ref)
            or (declared.prepare_contact_operation_id,declared.qualified_contact_dedupe_key)!=(
                binding.executor.prepare_contact_operation_id,binding.executor.qualified_outbox_dedupe_key)
            or terms["dedupe_key"]!=declared.qualified_contact_dedupe_key
            or (terms["budget_lease_ref"],terms["grant_id"],terms["grant_version"],terms["grant_digest"],raw["deadline_utc"])!=(
                binding.parent_budget_lease_ref,binding.parent_grant_id,binding.parent_grant_version,
                binding.parent_grant_digest,binding.original_deadline_utc)
            or binding.audience!=preparation.audience or binding.purpose!="expression"):
        raise ValueError("Contact Joint prospective binding changed real birth/preparation/old-cause/budget/deadline")
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2
    plan,_,_,plan_digest=read_adopted_contact_plan_v2(db,namespace=binding.namespace,contact_id=binding.contact_id,issuer=issuer)
    if plan_digest!=preparation.contact_plan_original_digest or plan.activity_id!=AtomKey.from_token(binding.action_ref).owner.subject:
        raise ValueError("Contact prospective actual Plan/activity owner changed")
    action=_decode_intent(candidate["action"])
    schema_raw=candidate["schema"]
    schema=ActionSchema(schema_raw["schema_id"],schema_raw["action_kind"],schema_raw["proactive"],
        tuple(_check_spec(value) for value in schema_raw["required_checks"]))
    record=ActionSchemaRecord.bind(action,schema)
    action_key=AtomKey.from_token(binding.action_ref)
    expected_action=AtomKey(action_key.owner,"d08.action_intent.v1",action.action_id)
    expected_schema=AtomKey(action_key.owner,"d08.action_schema.v1",record.schema_ref)
    if (action_key!=expected_action or binding.action_schema_ref!=expected_schema.token
            or action_key.owner.kind!="activity"
            or binding.action_revision!=1 or binding.action_schema_revision!=1
            or binding.action_digest!=canonical_digest(candidate["action"])
            or binding.action_schema_digest!=canonical_digest(plain_v1(record))
            or (binding.action_kind,binding.target_ref,binding.goal_id,binding.success_predicate)!=(
                action.action_kind,action.target_ref,action.goal_ref,action.success_predicate)
            or binding.target_entity_ref!=action.target_ref
            or action.identity.operation_id!=raw["final_operation_id"]
            or action.identity.effect_id!=raw["effect_id"]
            or not set(action.source_refs)<=set(binding.source_refs)
            or set(binding.source_refs)!=set(preparation.source_refs)):
        raise ValueError("Contact Joint prospective binding changed its complete actual birth Action/Schema")
    grant=issuer.current_budget_grant(db,binding.parent_budget_lease_ref)
    if (grant.grant_id,grant.version,canonical_digest(grant))!=(
            binding.parent_grant_id,binding.parent_grant_version,binding.parent_grant_digest):
        raise MissingProductionOriginalV1("actual_current_contact_joint_parent_grant")
    groups=dict(preparation.source_purpose_groups)
    expression=tuple(ref for ref in binding.source_refs if "expression" in groups.get(ref,()))
    context=tuple(ref for ref in binding.source_refs if "context" in groups.get(ref,()))
    if set(expression)|set(context)!=set(binding.source_refs):
        raise ValueError("Contact prospective Source groups do not cover actual birth closure")
    for audience in binding.audience:
        if expression:read.source_family(db,expression,purpose="expression",audience=audience)
        if context:read.source_family(db,context,purpose="context",audience=audience)
    read.original(binding.prospective_original_ref,kind="d10.contact-prospective-original.v1",digest=original.digest)
    read.original(preparation.original_ref,kind="d10.joint-contact-preparation-original.v1",digest=preparation.digest)
    cancellation=AtomKey(action_key.owner,"d08.action_cancellation.v1",action.action_id)
    current=read.head(db,cancellation)
    if current.valid and current.revision and current.value["state"]=="cancelled":return action,"cancelled"
    return action,"cancelled" if frame.now_utc>=binding.original_deadline_utc else "current"


class JointContactSourceLocatorParserV1:
    """Pure fixed locator parser; the actual Contact Work owns permission and IO."""
    _PATHS={
        "plan":frozenset({("source_refs",)}),
        "adoption":frozenset({("request","joint_plan_proposal_ref"),
            ("request","party_consent_original_refs")}),
        "intent":frozenset({("source_refs",),("current_goal_refs",)}),
        "consent":frozenset({("inbound_source_ref",),("acceptance_interpretation_ref",),("outbound_receipt_refs",)}),
        "compensation":frozenset({("source_refs",),("trigger_binding_ref",),("repair_binding_ref",)}),
        "goal":frozenset({("source_refs",)}),
        "interpretation":frozenset({("source_refs",)}),
        "binding":frozenset({("source_refs",),("plan_ref",),("plan_revision",)}),
    }
    def __init__(self,kind,*,ensure_ascii):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        if kind not in self._PATHS:raise ValueError("unregistered fixed Joint Contact locator kind")
        self.kind=kind;self.parser=C09CanonicalJSONStreamV2(ensure_ascii=ensure_ascii)
        self.values={};self.scalar=bytearray();self.path=None;self.complete=False;self.eof=None
    def _event(self,event):
        import json
        path=tuple(event.path)
        selected=any(path==root or len(path)==len(root)+1 and path[:-1]==root
            for root in self._PATHS[self.kind])
        if self.kind=="plan" and len(path)==3 and path[0]=="nodes" and type(path[1]) is int and path[2] in {"resource_ref","compensation_ref"}:
            selected=True
        if not selected:return
        if event.kind=="scalar_start":self.path=path;self.scalar.clear()
        elif event.kind=="scalar_chunk":
            if len(self.scalar)+len(event.raw)>4096:raise ValueError("Joint locator scalar exceeds its registered identifier bound")
            self.scalar.extend(event.raw)
        elif event.kind=="scalar_end":
            self.values[path]=json.loads(bytes(self.scalar));self.scalar.clear();self.path=None
    def feed(self,fragment):
        if self.complete:raise ValueError("Joint locator already reached canonical EOF")
        self.parser.feed(fragment,self._event)
    def finish(self):
        self.eof=self.parser.finish();self.complete=True
        return dict(self.values),self.eof

JOINT_CONTACT_LOCATOR_RECIPES_V1={
    "plan":("graph_atoms","value",("token","bot","persona")),
    "adoption":("graph_domain_production_originals_v1","original_payload_json",("bot","persona","operation_id")),
    "intent":("graph_d08_joint_plan_intents_v1","payload_json",("bot","persona","original_ref")),
    "consent":("graph_d08_party_consents_v1","payload_json",("bot","persona","original_ref")),
    "binding":("graph_d10_production_inputs_v1","payload_json",("bot","persona","original_ref")),
    "compensation":("graph_d08_joint_node_originals_v1","payload_json",("bot","persona","original_ref")),
    "goal":("graph_atoms","value",("token","bot","persona")),
    "interpretation":("graph_atoms","value",("token","bot","persona")),
}


def contact_prospective_joint_read_inputs_v1(binding):
    from .joint_node_execution_v1 import JointContactProspectiveBindingV1
    if type(binding) is not JointContactProspectiveBindingV1:raise TypeError("exact signed Contact prospective binding required")
    keys=tuple(AtomKey.from_token(ref) for ref in (binding.action_ref,binding.action_schema_ref,
        binding.goal_ref,binding.target_entity_ref,binding.role_ref) if ref is not None)
    return keys,binding.source_refs,(binding.prospective_original_ref,binding.executor.prepare_contact_operation_id)
