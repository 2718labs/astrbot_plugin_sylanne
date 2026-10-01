"""Authenticate D01 activation through its actual dedicated or W01 event."""
from dataclasses import asdict
import json

from ..contracts import Event, Scope, canonical_json
from ..domains.d01 import PersonaActivation, PersonaDomain, _validate_persona_plan
from ..graph_types import AtomKey, Owner, owner_grant_key, validate_owner_grant_v1
from ..runtime_contracts import NamespaceId, canonical_digest
from ..authority_service.v2_owner_contract import OwnerGraphCommitProofV1, canonical_digest as owner_digest
from ..authority_service.v2_contract import FencePermitV2, from_wire, to_wire
from .role_resources import RoleRuntimeResourcesV1, role_resources_key
from .d01_production_operations_v1 import MissingProductionOriginalV1


def life_activation_read_keys_v1(db, namespace):
    key = AtomKey(Owner("persona", *namespace.as_tuple), "d01.persona_activation.v1", "current")
    row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
    if row is None or row[1] != 1:
        return (key,)
    raw = json.loads(row[0])
    activation = PersonaActivation(**{**raw, "namespace": NamespaceId(**raw["namespace"])})
    return (key, AtomKey(key.owner, "d01.persona_plan.v1", activation.plan_id),
        role_resources_key(namespace, activation.plan_id))


def _canonical(encoded):
    raw = json.loads(encoded)
    if canonical_json(raw) != encoded:
        raise ValueError("D01 initialization original is not canonical")
    return raw


def _require_generic_activation_original_v1(db, *, read, activation_atom, plan_atom, activation, history):
    """Verify the installed growth operation's real W01 originals and members."""
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d04_root_original_store_v1 import _receipt
    ns, frame = activation.namespace, read.frame
    operation = history[5]
    original = read_adopted_domain_operation_v1(db, ns, operation)
    if original is None:
        raise MissingProductionOriginalV1("actual_d01_activation_bundle_original")
    receipt, payload = original["receipt"], original["payload"]
    if (original["domain"], original["operation_kind"], payload.get("schema"), payload.get("coverage")) != (
            "d01", "adopt_growth", "d01.current-adopt_growth.v1", "complete"):
        raise ValueError("Life activation is not an installed completed D01 growth adoption")
    if (receipt != _receipt(db, ns, operation) or receipt.status != "committed"
            or receipt.activity_id != history[4] or receipt.operation_id != operation
            or (payload["identity"]["activity_id"], payload["identity"]["effect_id"]) != (receipt.activity_id, receipt.effect_id)
            or payload["owner_guard"] != asdict(frame.owner_guard)
            or payload["authority"]["activation_generation"] != frame.activation_generation
            or payload["missing_inputs"] or payload["continuation_ref"] is not None
            or len(receipt.invalidated_epochs) != 1 or receipt.invalidated_epochs[0].revision > frame.snapshot.epochs[0].revision):
        raise ValueError("Life D01 growth original lost its actual current Owner/bundle receipt")
    candidate = payload["provenance"]["candidate"]
    writes = payload["writes"]
    if (not 3 <= len(writes) <= 64 or candidate["typed_writes"] != writes
            or candidate["head_id"] != activation.head_id or candidate["revision"]["new_head"] != activation.head_id
            or activation_atom.revision < 2 or plan_atom.revision < 2 or activation.plan_version < 2):
        raise ValueError("Life D01 growth original lost its exact successor candidate")
    versions = {v.key.token: v.revision for v in receipt.write_versions}
    if len(versions) != len(writes) or set(versions) != {w["key"] for w in writes}:
        raise ValueError("Life D01 growth receipt differs from its whole actual member set")
    specs = {spec.name: spec for spec in PersonaDomain().type_specs()}
    member_rows = []
    for write in writes:
        key = AtomKey.from_token(write["key"])
        if key.type_name not in {"d01.persona_plan.v1", "d01.persona_revision.v1", "d01.persona_activation.v1", "d01.growth_contribution.v1"}:
            raise ValueError("Life D01 growth bundle contains another domain's member")
        specs[key.type_name].validator(write["value"])
        row = db.execute("SELECT value,valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?",
            (key.token, versions[key.token])).fetchone()
        expected = (canonical_json(write["value"]), 1, *ns.as_tuple, receipt.activity_id, operation)
        if row != expected:
            raise ValueError("Life D01 growth original lost an actual member history")
        member_rows.append((key.token, versions[key.token], expected[0], 1))
    for atom in (plan_atom, activation_atom):
        members = [w for w in writes if w["key"] == atom.key.token]
        if len(members) != 1 or members[0]["value"] != atom.value or versions[atom.key.token] != atom.revision:
            raise ValueError("Life current D01 head differs from its actual adopted growth member")
    revisions = [w for w in writes if AtomKey.from_token(w["key"]).type_name == "d01.persona_revision.v1"]
    if len(revisions) != 1 or revisions[0]["value"] != candidate["revision"]:
        raise ValueError("Life D01 growth continuity revision differs")
    prior = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
        (plan_atom.key.token, plan_atom.revision - 1)).fetchone()
    if prior is None or prior[1] != 1:
        raise MissingProductionOriginalV1("actual_d01_previous_plan_history")
    prior_plan = _canonical(prior[0])
    _validate_persona_plan(prior_plan)
    if (prior_plan["plan_id"] != activation.plan_id or prior_plan["version"] + 1 != activation.plan_version
            or candidate["revision"]["previous_head"] != prior_plan["plan_id"] + "@" + str(prior_plan["version"])
            or not {(plan_atom.key.token, plan_atom.revision - 1), (activation_atom.key.token, activation_atom.revision - 1)}
                <= {(v.key.token, v.revision) for v in receipt.read_versions}):
        raise ValueError("Life D01 growth receipt omits its actual predecessor heads")
    event = Event(Scope(*ns.as_tuple, receipt.activity_id), operation, payload["now_utc"],
        "domain_bundle", {"bundle_digest": receipt.operation_digest})
    row = db.execute("SELECT digest,reads,revisions,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*ns.as_tuple, receipt.activity_id, operation)).fetchone()
    expected_event = (event.digest, canonical_json([[v.key.token, v.revision] for v in receipt.read_versions]),
        canonical_json([[v.key.token, v.revision] for v in receipt.write_versions]), receipt.invalidated_epochs[0].revision)
    actual_members = db.execute("SELECT token,revision,value,valid FROM graph_history WHERE event_bot=? AND event_persona=? AND event_session=? AND event_id=? AND valid=1 ORDER BY token",
        (*ns.as_tuple, receipt.activity_id, operation)).fetchall()
    if row != expected_event or actual_members != sorted(member_rows):
        raise ValueError("Life D01 growth actual Graph event/whole member history differs")
    fence = db.execute("SELECT digest,permit_json,pre_graph_revision,pre_graph_epoch,post_graph_revision,post_graph_epoch,finish_request_id,finish_request_digest "
        "FROM graph_bundle_fences_v2 WHERE bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, operation)).fetchone()
    attempt = db.execute("SELECT request_digest,attempt_id,anchor_json,graph_revision,graph_epoch,permit_json "
        "FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, operation)).fetchone()
    if fence is None or attempt is None or attempt[5] is None:
        raise MissingProductionOriginalV1("actual_d01_growth_owner_fence_original")
    permit_wire = _canonical(fence[1])
    permit = from_wire(permit_wire)
    stamp = db.execute("SELECT graph_revision,requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
    if stamp is None:
        raise MissingProductionOriginalV1("actual_current_d01_graph_metadata")
    current_requirements = _canonical(stamp[1])
    if (type(permit) is not FencePermitV2 or to_wire(permit) != permit_wire or permit.operation != "write"
            or permit.operation_id != attempt[1] or permit.authority_id != current_requirements["authority_id"]
            or permit.namespace != current_requirements["authority_namespace"] or permit.generation != frame.activation_generation
            or current_requirements["namespace"] != asdict(ns) or current_requirements["activation_generation"] != frame.activation_generation
            or attempt[2] != canonical_json(asdict(permit.pinned_anchor)) or attempt[5] != fence[1]
            or fence[0] != receipt.operation_digest or fence[2:4] != attempt[3:5]
            or fence[4:6] != (fence[2] + 1, fence[3] + 1)
            or fence[5] != receipt.invalidated_epochs[0].revision or fence[4] > stamp[0]
            or fence[6] != "finish:" + attempt[1]
            or fence[7] != "sha256:" + canonical_digest({"schema": "w01.owner-domain-write.v3",
                "operation_id": operation, "request_digest": attempt[0], "permit_token": permit.token})):
        raise ValueError("Life D01 growth actual Owner fence/commit stamp differs")
    return activation


def require_current_life_activation_original_v1(db, *, read):
    """Dispatch by the current head's actual producer, never by missing pieces."""
    from ..graph_coordinator import RoleInitializationReceiptV1
    read.check(db)
    frame, ns = read.frame, read.frame.envelope.authority.namespace
    keys = life_activation_read_keys_v1(db, ns)
    if len(keys) != 3:
        raise MissingProductionOriginalV1("current_life_persona_activation")
    activation_atom, plan_atom = tuple(read.head(db, key, required=True) for key in keys[:2])
    activations = tuple(a for a in read.complete_inventory(db, "d01.persona_activation.v1") if a.valid)
    if activations != (activation_atom,):
        raise MissingProductionOriginalV1("unique_current_life_persona_activation")
    raw = activation_atom.value
    activation = PersonaActivation(**{**raw, "namespace": NamespaceId(**raw["namespace"])})
    grant_atom = read.head(db, owner_grant_key(*ns.as_tuple), required=True)
    grant = grant_atom.value
    validate_owner_grant_v1(grant)
    proof_row = db.execute("SELECT operation_id,request_digest,grant_id,grant_digest,graph_incarnation,graph_access_epoch,graph_epoch,graph_receipt_digest,proof_json "
        "FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=? AND operation_id=?",
        (*ns.as_tuple, grant["issue_operation_id"])).fetchone()
    if proof_row is None:
        raise MissingProductionOriginalV1("actual_life_current_owner_issue_original")
    proof = OwnerGraphCommitProofV1(ns, *proof_row[:5], grant["grant_revision"], *proof_row[5:8])
    if (proof_row[8] != canonical_json(asdict(proof)) or proof.grant_id != grant["grant_id"]
            or proof.grant_digest != "sha256:" + canonical_digest(grant)
            or proof.grant_revision != grant_atom.revision or proof.graph_incarnation != grant["graph_incarnation"]
            or proof.graph_access_epoch > frame.envelope.version_guard.access_epoch
            or proof.graph_epoch > frame.snapshot.epochs[0].revision
            or owner_digest(proof) != "sha256:" + frame.owner_guard.owner_head_digest):
        raise ValueError("Life D01 initialization current Owner original differs")
    _validate_persona_plan(plan_atom.value)
    if ((activation.namespace, activation.activation_generation, activation.owner_grant_id, activation.owner_grant_revision,
            activation.authorization_revision, activation.graph_incarnation, activation.state) !=
            (ns, frame.activation_generation, proof.grant_id, grant_atom.revision, frame.owner_guard.grant_revision, proof.graph_incarnation, "active")
            or grant["activation_generation"] != frame.activation_generation
            or (plan_atom.value["plan_id"], plan_atom.value["version"], plan_atom.value["namespace"]) !=
                (activation.plan_id, activation.plan_version, asdict(ns))):
        raise ValueError("Life current D01 activation/plan differs from its actual Owner")
    history = db.execute("SELECT value,valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?",
        (activation_atom.key.token, activation_atom.revision)).fetchone()
    if history is None or history[:4] != (canonical_json(activation_atom.value), 1, *ns.as_tuple):
        raise MissingProductionOriginalV1("actual_current_d01_activation_history")
    if history[4] != "d01-role-initialization":
        return _require_generic_activation_original_v1(db, read=read, activation_atom=activation_atom,
            plan_atom=plan_atom, activation=activation, history=history)
    resource_atom = read.head(db, keys[2], required=True)
    resources = RoleRuntimeResourcesV1(**resource_atom.value)
    intents = db.execute("SELECT operation_id,input_digest,fence_attempt_id,requirements_json,anchor_json,graph_revision,graph_epoch "
        "FROM graph_role_init_intents_v1 WHERE bot=? AND persona=?", ns.as_tuple).fetchall()
    requests = db.execute("SELECT operation_id,request_digest,input_digest FROM graph_role_init_request_proofs_v1 WHERE bot=? AND persona=?", ns.as_tuple).fetchall()
    receipts = db.execute("SELECT operation_id,input_digest,permit_json,receipt_json,pre_graph_revision,pre_graph_epoch,post_graph_revision,post_graph_epoch,finish_request_id,finish_request_digest "
        "FROM graph_role_init_receipts_v1 WHERE bot=? AND persona=?", ns.as_tuple).fetchall()
    if len(intents) != 1 or len(requests) != 1 or len(receipts) != 1:
        raise MissingProductionOriginalV1("unique_actual_d01_role_initialization_original")
    intent, request, row = intents[0], requests[0], receipts[0]
    receipt_raw = _canonical(row[3])
    receipt = RoleInitializationReceiptV1(**{**receipt_raw, "namespace": NamespaceId(**receipt_raw["namespace"])})
    permit_wire = _canonical(row[2])
    permit = from_wire(permit_wire)
    requirements, anchor = _canonical(intent[3]), _canonical(intent[4])
    input_digest = "sha256:" + canonical_digest({"schema": "sylanne3.graph.role_initialization.v1",
        "namespace": list(ns.as_tuple), "operation_id": receipt.operation_id, "request_digest": receipt.request_digest,
        "plan": plan_atom.value, "principal": grant["principal"], "resources": resource_atom.value, "owner_proof": asdict(proof)})
    attempt = "role-write-" + canonical_digest({"namespace": list(ns.as_tuple),
        "operation_id": receipt.operation_id, "input_digest": input_digest})[:48]
    if (type(permit) is not FencePermitV2 or to_wire(permit) != permit_wire or permit.operation != "write"
            or permit.operation_id != attempt or permit.authority_id != grant["authority_id"]
            or permit.namespace != requirements["authority_namespace"] or permit.generation != frame.activation_generation
            or anchor != asdict(permit.pinned_anchor) or requirements["namespace"] != asdict(ns)
            or requirements["authority_id"] != permit.authority_id or requirements["graph_incarnation"] != proof.graph_incarnation
            or requirements["activation_generation"] != frame.activation_generation
            or grant["activation_generation"] != frame.activation_generation
            or request != (intent[0], receipt.request_digest, intent[1]) or row[:2] != intent[:2]
            or row[4:8] != (intent[5], intent[6], receipt.graph_revision, receipt.graph_epoch)
            or row[8:] != (receipt.finish_request_id, receipt.finish_request_digest)
            or receipt.namespace != ns or receipt.operation_id != intent[0]
            or receipt.input_digest != intent[1] or receipt.input_digest != input_digest
            or receipt.fence_attempt_id != attempt or intent[2] != attempt
            or receipt.finish_request_id != "finish:" + attempt
            or receipt.finish_request_digest != "sha256:" + canonical_digest({"operation_id": attempt,
                "permit_token": permit.token, "action": "finish_role_initialization",
                "business_operation_id": receipt.operation_id, "input_digest": input_digest})
            or receipt.owner_authorization_head != owner_digest(proof)
            or (receipt.owner_grant_id, receipt.owner_grant_revision, receipt.graph_incarnation) != (proof.grant_id, grant_atom.revision, proof.graph_incarnation)
            or (receipt.plan_id, receipt.head_id) != (activation.plan_id, activation.head_id)
            or (resources.namespace, resources.operation_id, resources.plan_id, resources.head_id) != (ns, receipt.operation_id, activation.plan_id, activation.head_id)
            or (activation.namespace, activation.activation_generation, activation.owner_grant_id, activation.owner_grant_revision,
                activation.authorization_revision, activation.graph_incarnation, activation.state) !=
                (ns, frame.activation_generation, proof.grant_id, grant_atom.revision, frame.owner_guard.grant_revision, proof.graph_incarnation, "active")
            or (plan_atom.value["plan_id"], plan_atom.value["version"], plan_atom.value["namespace"]) != (activation.plan_id, activation.plan_version, asdict(ns))
            or activation.head_id != activation.plan_id + "@" + str(activation.plan_version)
            or tuple(a.revision for a in (plan_atom, activation_atom, resource_atom)) != (1, 1, 1)
            or (receipt.graph_revision, receipt.graph_epoch) != (intent[5] + 1, intent[6] + 1)):
        raise ValueError("Life dedicated D01 initialization identity/receipt changed")
    event = Event(Scope(*ns.as_tuple, "d01-role-initialization"), receipt.operation_id, 0, "role_initialized",
        {"input_digest": input_digest, "owner_grant_id": proof.grant_id, "authorization_head": owner_digest(proof)})
    event_row = db.execute("SELECT digest,reads,epoch_reads,revisions,invalidated,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*ns.as_tuple, event.scope.session, event.event_id)).fetchone()
    members = (plan_atom, activation_atom, resource_atom)
    expected = (event.digest, canonical_json([[grant_atom.key.token, grant_atom.revision],
        *[[a.key.token, 0] for a in members]]), canonical_json([[*ns.as_tuple, intent[6]]]),
        canonical_json([[a.key.token, 1] for a in members]), "[]", receipt.graph_epoch)
    histories = db.execute("SELECT token,revision,value,valid FROM graph_history WHERE event_bot=? AND event_persona=? AND event_session=? AND event_id=? ORDER BY token",
        (*ns.as_tuple, event.scope.session, event.event_id)).fetchall()
    if (event_row != expected or histories != sorted((a.key.token, a.revision, canonical_json(a.value), 1) for a in members)
            or receipt.graph_epoch > frame.snapshot.epochs[0].revision):
        raise ValueError("Life D01 initialization actual Graph event/history differs")
    stamp = db.execute("SELECT graph_revision,requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
    current_requirements = None if stamp is None else _canonical(stamp[1])
    if (stamp is None or stamp[0] < receipt.graph_revision or current_requirements["namespace"] != asdict(ns)
            or current_requirements["authority_id"] != grant["authority_id"]
            or current_requirements["authority_namespace"] != permit.namespace
            or current_requirements["activation_generation"] != frame.activation_generation):
        raise ValueError("Life D01 initialization exceeds current Graph revision")
    return activation
