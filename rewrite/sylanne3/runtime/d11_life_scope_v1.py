"""The semantic inputs of a source-note inside complete current inventories.

Inventory coverage remains a separate query guard. A row outside this actual
internal activity is not a grant to read its unrelated Source content.
"""
from dataclasses import dataclass
import json

from ..domains.d03.context import RoleBinding, RoleBindingRequest, _tuple_payload
from ..domains.d05.relationship import BoundaryRule, _tuple_payload as boundary_payload
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId
from .d01_production_operations_v1 import MissingProductionOriginalV1


@dataclass(frozen=True, slots=True)
class LifeSemanticScopeV1:
    namespace: NamespaceId
    project_ref: str
    input_source_ref: str
    entity_ref: str
    target_ref: str
    action_id: str
    goal_id: str
    commitment_refs: tuple[str, ...]
    audiences: tuple[str, ...]
    now_utc: float | None

    def role_request(self):
        if self.now_utc is None:
            raise ValueError("current Life role resolution requires trusted time")
        return RoleBindingRequest("persona:" + self.namespace.persona_id,
            self.target_ref, None, None, "source_note", "consolidation", self.now_utc, True)

    def role_applies(self, role):
        if self.now_utc is not None:
            return role.applies_to(self.role_request())
        return (role.status == "active" and role.subject_persona_ref == "persona:" + self.namespace.persona_id
            and role.target_entity_ref in {None, self.target_ref}
            and role.group_ref is None and role.scene_ref is None)

    def boundary_applies(self, rule):
        if self.now_utc is not None:
            return any(rule.applies_to(subject_persona_ref="persona:" + self.namespace.persona_id,
                target_entity_ref=self.target_ref, action_kind="source_note", audience_scope=audience,
                scene_ref=None, at_time=self.now_utc) for audience in self.audiences)
        return (rule.status == "active" and rule.subject_persona_ref == "persona:" + self.namespace.persona_id
            and rule.target_entity_ref == self.target_ref and rule.action_kind == "source_note"
            and rule.audience_scope in self.audiences and rule.scene_ref is None)

    def includes(self, kind, key, value):
        if kind == "d03.role_binding":
            return self.role_applies(RoleBinding(**_tuple_payload(value, "norm_refs", "source_refs")))
        if kind == "d05.boundary_rule":
            return self.boundary_applies(BoundaryRule(**boundary_payload(value,
                "source_refs", "communicated_refs", "acknowledged_refs", "exception_refs")))
        if kind == "d03.entity_anchor":
            return key.token == self.entity_ref
        if kind == "d08.goal.v1":
            return value["goal_id"] == self.goal_id
        if kind == "d08.commitment.v1":
            return (value["commitment_id"] in self.commitment_refs
                or value["fulfillment_state"] not in {"fulfilled", "withdrawn"})
        if kind == "d08.action_intent.v1":
            return value["action_id"] == self.action_id or value["target_ref"] == self.target_ref
        if kind in {"d08.action_schema.v1", "d08.action_cancellation.v1"}:
            return value["action_ref" if kind == "d08.action_schema.v1" else "action_id"] == self.action_id
        if kind == "d07.attention_ticket.v1":
            return value["concern_ref"] == self.project_ref and self.input_source_ref in value["source_refs"]
        # Focus is the singleton current focus; the qualified reader decides
        # whether its actual ticket is this activity's usable primary ticket.
        return kind in {"d07.focus.v1", "d01.persona_activation.v1", "d01.persona_plan.v1",
            "d02.body_state.v1", "d02.body_profile.v1", "d02.reservation.v1", "d02.settlement.v1",
            "d12.active_scheme_head.v1"}


@dataclass(frozen=True,slots=True)
class DraftLifeSemanticScopeV1(LifeSemanticScopeV1):
    def role_request(self):
        if self.now_utc is None:raise ValueError("current draft role resolution requires trusted time")
        return RoleBindingRequest("persona:"+self.namespace.persona_id,self.target_ref,None,None,
            "artifact_draft_v1","consolidation",self.now_utc,True)

    def boundary_applies(self,rule):
        if self.now_utc is not None:
            return any(rule.applies_to(subject_persona_ref="persona:"+self.namespace.persona_id,
                target_entity_ref=self.target_ref,action_kind="artifact_draft_v1",audience_scope=audience,
                scene_ref=None,at_time=self.now_utc) for audience in self.audiences)
        return (rule.status=="active" and rule.subject_persona_ref=="persona:"+self.namespace.persona_id
            and rule.target_entity_ref==self.target_ref and rule.action_kind=="artifact_draft_v1"
            and rule.audience_scope in self.audiences and rule.scene_ref is None)


def life_scope_from_action_v1(db, *, namespace, action_ref, project_ref, input_source_ref, audiences, now_utc):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    row=_producer_original_point_v3(db,table="graph_atoms",columns=("value","valid"),
        key_columns=("token","bot","persona"),key=(action_ref,*namespace.as_tuple),
        legacy_reader=lambda:db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (action_ref,*namespace.as_tuple)).fetchone())
    if row is None or row[1] != 1:
        raise MissingProductionOriginalV1("current_life_action_scope")
    from ..domains.d08.execution import _decode
    action = _decode("d08.action_intent.v1", json.loads(row[0]))
    # Entity owners can differ from the action owner. Locate the real bounded
    # inventory member, rather than inventing a namespace key as provenance.
    from .borrowed_habit_classification_v3 import read_bound_borrowed_habit_inventory_v3
    handled,atoms=read_bound_borrowed_habit_inventory_v3(db,namespace,"d03.entity_anchor")
    from ..runtime_contracts import canonical_serialize
    entities=tuple((atom.key.token,canonical_serialize(atom.value))for atom in atoms if atom.valid)if handled else db.execute(
        "SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d03.entity_anchor' AND valid=1 ORDER BY token LIMIT 129",
        namespace.as_tuple).fetchall()
    if len(entities) > 128:
        raise MissingProductionOriginalV1("complete_life_input_inventory:d03.entity_anchor")
    matches = [token for token, encoded in entities if json.loads(encoded)["entity_id"] == action.target_ref]
    if len(matches) != 1:
        raise MissingProductionOriginalV1("unique_current_life_target_entity")
    kind=DraftLifeSemanticScopeV1 if action.action_kind=="artifact_draft_v1" else LifeSemanticScopeV1
    return kind(namespace, project_ref, input_source_ref, matches[0], action.target_ref,
        action.action_id, action.goal_ref, action.commitment_refs, tuple(audiences), now_utc)


def life_semantic_source_refs_v1(value):
    """Select D06 sources; project and Owner-original locators stay originals."""
    result = []
    for ref in (*value.get("source_refs", ()), *value.get("creation_evidence_refs", ()), *value.get("reason_refs", ())):
        try:
            key = AtomKey.from_token(ref)
        except ValueError:
            continue
        if key.type_name == "memory.source":
            result.append(ref)
    return tuple(dict.fromkeys(result))
