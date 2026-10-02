"""Closed W01 domain read planning and genuine original resolution.

No SQL identifier, callable, schema or scan type comes from a public request.
This module performs no RPC. Independently reread C04 terminals, trusted clock
samples and restore anchors enter through W01's installed pre-read adapter.
An absent original is omitted, so the domain reader returns its precise HOLD;
the locator's own hash is never used as an original or authority receipt.
"""
from __future__ import annotations

from dataclasses import dataclass
import json

from ..graph_types import AtomKey, GraphVersion
from ..graph_types import Owner
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import (
    MissingProductionOriginalV1, production_read_plan_v1, raw_registered_input_v1,
    raw_head_value_v1, read_plan_current_d01_operation_v1, table_exists_v1,
)
from .d02_production_operations_v1 import read_plan_current_d02_operation_v1
from .d05_production_operations_v1 import read_plan_current_d05_operation_v1
from .d08_production_operations_v1 import read_plan_current_d08_operation_v1
from .d10_production_operations_v1 import read_plan_current_d10_operation_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1, ProductionPolicyRefV1, ProductionReadPlanV1
from .issuers import D11BudgetJobIssuer


_READ_PLANNERS = {"d01": read_plan_current_d01_operation_v1, "d02": read_plan_current_d02_operation_v1,
    "d05": read_plan_current_d05_operation_v1, "d08": read_plan_current_d08_operation_v1,
    "d10": read_plan_current_d10_operation_v1}
_INPUT_TABLES = (
    ("graph_d01_production_inputs_v1", "d11.d01-production-input.v1", "d01", "kind"),
    ("graph_d05_boundary_intents_v1", "d11.d05-boundary-intent.v1", "d05", "boundary_intent"),
    ("graph_d08_joint_plan_intents_v1", "d11.d08-joint-plan-intent.v1", "d08", "joint_plan_intent"),
    ("graph_d08_party_consents_v1", "d11.d08-party-consent.v1", "d08", "party_consent"),
    ("graph_d10_production_inputs_v1", "d11.d10-production-input.v1", "d10", "kind"),
    ("graph_d02_action_components_v1", "d11.d02-completed-action-component.v1", "d02", "completed_action_component"),
)
_POLICY_TABLES = (
    ("graph_d02_production_policies_v1", "d11.d02-production-policy.v1", "d02"),
    ("graph_d05_production_policies_v1", "d11.d05-production-policy.v1", "d05"),
)


def read_plan_current_domain_operation_v1(db, *, namespace, activity_id, domain, operation_kind, request, operation_id=None, now_utc=None, audiences=None, life_d04_before_capture_policy=None):
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("domain read plan needs the actual W01 current transaction")
    if operation_kind.startswith("input:"):
        from .domain_production_inputs_v1 import read_plan_current_domain_input_v1
        return read_plan_current_domain_input_v1(db, namespace=namespace, activity_id=activity_id,
            producer_kind=operation_kind[len("input:"):], request=request)
    if operation_kind == "prepare_contact_dispatch_v3":
        from .contact_final_stage_v3 import read_plan_contact_final_v3
        return read_plan_contact_final_v3(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if operation_kind == "prepare_contact_dispatch":
        from .contact_final_stage_v2 import read_plan_contact_final_v2
        return read_plan_contact_final_v2(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if operation_kind == "adopt_contact_expression_plan_v2":
        from .contact_plan_adoption_v2 import read_plan_contact_expression_v2
        return read_plan_contact_expression_v2(db,namespace=namespace,activity_id=activity_id,
            operation_kind=operation_kind,request=request)
    if operation_kind == "adopt_contact_expression_plan":
        from .contact_product_adapter_v1 import read_plan_contact_expression_v1
        return read_plan_contact_expression_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if operation_kind == "prepare_contact_model_v2":
        from .contact_product_adapter_v2 import read_plan_contact_model_v2
        return read_plan_contact_model_v2(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if operation_kind == "prepare_contact_model":
        from .contact_product_adapter_v1 import read_plan_contact_model_v1
        return read_plan_contact_model_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if operation_kind == "focus_life_project":
        from .d07_life_project_focus_v1 import read_plan_life_project_focus_v1
        return read_plan_life_project_focus_v1(db, namespace=namespace, operation_id=operation_id, request=request)
    if operation_kind == "prepare_life_project_context":
        from .d03_life_project_context_v1 import read_plan_life_project_context_v1
        return read_plan_life_project_context_v1(db, namespace=namespace, request=request)
    if operation_kind == "prepare_source_note_action":
        from .d08_source_note_action_v1 import read_plan_source_note_action_v1
        return read_plan_source_note_action_v1(db, namespace=namespace, activity_id=activity_id,
            operation_id=operation_id, request=request, now_utc=now_utc, audiences=audiences)
    if operation_kind == "prepare_source_note_body":
        from .d02_life_body_preparation_v1 import read_plan_source_note_body_v1
        return read_plan_source_note_body_v1(db, namespace=namespace, activity_id=activity_id,
            operation_id=operation_id, request=request, now_utc=now_utc)
    if domain == "d10" and operation_kind == "prepare_offline_tick":
        from .d10_offline_tick_execution_v1 import read_plan_current_offline_tick_v1
        return read_plan_current_offline_tick_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if domain == "d10" and operation_kind == "prepare_life":
        from .d11_life_product_adapter_v1 import read_plan_current_life_preparation_v1
        return read_plan_current_life_preparation_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request, now_utc=now_utc,
            before_capture_policy=life_d04_before_capture_policy)
    if domain == "d10" and operation_kind == "advance_life":
        from .d10_production_operations_v1 import AdvanceCurrentLifeRequestV1
        from .d11_life_product_adapter_v1 import read_plan_current_life_progress_v2
        if type(request) is AdvanceCurrentLifeRequestV1:
            # The installed V2 planner already retains complete current query
            # inventories and separates Source roots from project/Owner
            # creation originals. Do not reinterpret these typed originals as
            # expression/source authority through the generic inventory path.
            actual = read_plan_current_life_progress_v2(
                db, namespace=namespace, activity_id=activity_id, request=request,
            )
            if actual is not None:
                return actual
    if operation_kind == "adopt_internal_life_content_v1":
        from .internal_life_content_adoption_v1 import read_plan_content_adoption_v1
        return read_plan_content_adoption_v1(db,namespace=namespace,activity_id=activity_id,operation_kind=operation_kind,request=request)
    if operation_kind == "acquire_internal_life_content_v2":
        from .internal_life_content_worker_v2 import read_plan_internal_life_acquire_v2
        return read_plan_internal_life_acquire_v2(db,namespace=namespace,activity_id=activity_id,
            operation_kind=operation_kind,request=request)
    if operation_kind == "acquire_internal_life_content":
        from .internal_life_content_worker_v1 import read_plan_internal_life_acquire_v1
        return read_plan_internal_life_acquire_v1(db,namespace=namespace,activity_id=activity_id,
            operation_kind=operation_kind,request=request)
    if operation_kind == "prepare_internal_life_content":
        from .internal_life_content_preparation_v1 import read_plan_internal_life_content_v1
        return read_plan_internal_life_content_v1(db,namespace=namespace,activity_id=activity_id,
            operation_kind=operation_kind,request=request)
    if operation_kind == "prepare_internal_life_numeric_drive":
        from .d06_life_numeric_drive_v1 import read_plan_life_numeric_drive_v1
        return read_plan_life_numeric_drive_v1(db, namespace=namespace, activity_id=activity_id, operation_kind=operation_kind, request=request)
    if operation_kind == "prepare_internal_life_numeric_joint":
        from .d06_life_numeric_joint_v1 import read_plan_life_numeric_joint_v1
        return read_plan_life_numeric_joint_v1(db, namespace=namespace, activity_id=activity_id, operation_kind=operation_kind, request=request)
    if operation_kind == "prepare_internal_life_interval_baseline":
        from .d04_life_encoding_baseline_v1 import read_plan_life_encoding_baseline_v1
        return read_plan_life_encoding_baseline_v1(db, namespace=namespace, activity_id=activity_id, operation_kind=operation_kind, request=request)
    if operation_kind == "adopt_internal_life_numeric_trace":
        from .d06_life_numeric_trace_v1 import read_plan_life_numeric_trace_v1
        return read_plan_life_numeric_trace_v1(db, namespace=namespace, activity_id=activity_id, operation_kind=operation_kind, request=request)
    if operation_kind in {'prepare_internal_life_numeric', 'acquire_internal_life_numeric', 'adopt_internal_life_numeric'}:
        from .d06_life_numeric_task_v1 import read_plan_life_numeric_prepare_v1, read_plan_life_numeric_adopt_v1
        from .d06_life_numeric_worker_v1 import read_plan_life_numeric_acquire_v1
        planner = {'prepare_internal_life_numeric':read_plan_life_numeric_prepare_v1,
            'acquire_internal_life_numeric':read_plan_life_numeric_acquire_v1,
            'adopt_internal_life_numeric':read_plan_life_numeric_adopt_v1}[operation_kind]
        return planner(db, namespace=namespace, activity_id=activity_id, operation_kind=operation_kind, request=request)
    if domain == "d06" and operation_kind == "prepare_internal_life_numeric_context":
        from .d06_life_numeric_context_v1 import read_plan_life_numeric_context_v1
        return read_plan_life_numeric_context_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if domain == "d06" and operation_kind == "encode_internal_life":
        from .d06_internal_life_encoding_v1 import read_plan_internal_life_encoding_v1
        return read_plan_internal_life_encoding_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if domain == "d06" and operation_kind == "encode_structured_experience":
        from .d06_structured_experience_v1 import read_plan_current_d06_structured_experience_v1
        return read_plan_current_d06_structured_experience_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if domain == "d06" and operation_kind == "form_association":
        from .d06_association_formation_v1 import read_plan_current_d06_association_v1
        return read_plan_current_d06_association_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if domain == "d07":
        from .d07_production_operations_v1 import read_plan_current_d07_operation_v1
        return read_plan_current_d07_operation_v1(db, namespace=namespace, activity_id=activity_id,
            operation_kind=operation_kind, request=request)
    if domain not in _READ_PLANNERS:
        raise ValueError("domain has no registered current production operations")
    plan = _READ_PLANNERS[domain](db, namespace=namespace, activity_id=activity_id,
                                operation_kind=operation_kind, request=request)
    # A typed inventory supplies current negative-query coverage. Its relevant
    # content/source fields are actual graph locators, not new instructions.
    roots = list(plan.source_roots)
    for type_name in plan.fixed_type_ids:
        if domain == "d08" and operation_kind == "recheck_action" and type_name == "d03.role_binding":
            # Owner configuration participates as an authoritative current
            # role head, not as conversation evidence or a passing D03 check.
            continue
        if type_name not in {"d03.entity_anchor", "d03.role_binding", "d03.world_event", "d05.boundary_rule"}:
            continue
        rows = db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? AND valid=1 "
                          "ORDER BY token LIMIT 129", (*namespace.as_tuple, type_name)).fetchall()
        if len(rows) > 128:
            # Materialization records its partial page; it must not claim full
            # entity/boundary coverage or arbitrarily omit private tails.
            continue
        for (encoded,) in rows:
            value = json.loads(encoded)
            for ref in value.get("source_refs", value.get("creation_evidence_refs", ())):
                roots.append(ref)
    keys = plan.exact_keys
    if operation_id is not None and domain == "d01" and operation_kind == "adopt_growth":
        keys += (waiting_domain_job_key_v1(namespace, operation_id, domain, "growth", activity_id),)
    return production_read_plan_v1(plan.fixed_type_ids, keys, roots, plan.required_original_refs)


def waiting_domain_job_key_v1(namespace, operation_id, domain, kind, activity_id):
    job_id = domain + "-pending:" + canonical_digest((namespace, operation_id, domain, kind, "waiting-original"))[:48]
    return AtomKey(Owner("activity", *namespace.as_tuple, activity_id), "runtime.job", job_id)


def _issuer(installed_readers):
    issuer = getattr(installed_readers, "issuer", None)
    if type(issuer) is not D11BudgetJobIssuer:
        raise TypeError("domain originals need the actual installed D11 issuer")
    return issuer


def _committed(db, namespace, operation):
    row = db.execute("SELECT digest,receipt_json,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                     (*namespace.as_tuple, operation)).fetchone()
    if row is None or row[2] < 1 or json.loads(row[1]).get("commit_seq") != row[2]:
        raise ValueError("production original lost its actually committed producing operation")


def _signed_input(db, namespace, ref, issuer):
    found = []
    for table, sign_kind, domain, kind in _INPUT_TABLES:
        if not table_exists_v1(db, table):
            continue
        select_kind = "kind" if kind == "kind" else "?"
        args = () if kind == "kind" else (kind,)
        row = db.execute("SELECT " + select_kind + ",producing_operation_id,payload_json,payload_digest,signature "
            "FROM " + table + " WHERE bot=? AND persona=? AND original_ref=?", (*args, *namespace.as_tuple, ref)).fetchone()
        if row is None:
            continue
        issuer._signer.verify(sign_kind, row[2], row[4])
        raw = json.loads(row[2])
        if canonical_serialize(raw) != row[2] or canonical_digest(raw) != row[3]:
            raise ValueError("signed production input bytes changed")
        _committed(db, namespace, row[1])
        found.append(ProductionOriginalRefV1(domain + "." + row[0], ref, row[3]))
    if len(found) > 1:
        raise ValueError("production original locator collides across registered domains")
    return found[0] if found else None


def _signed_policy(db, namespace, ref, issuer):
    found = []
    for table, sign_kind, domain in _POLICY_TABLES:
        if not table_exists_v1(db, table):
            continue
        row = db.execute("SELECT revision,payload_json,payload_digest,signature FROM " + table +
            " WHERE bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC LIMIT 1", (*namespace.as_tuple, ref)).fetchone()
        if row is None:
            continue
        issuer._signer.verify(sign_kind, row[1], row[3])
        raw = json.loads(row[1])
        if (canonical_serialize(raw) != row[1] or canonical_digest(raw) != row[2]
                or raw.get("policy_ref") != ref or raw.get("revision") != row[0]
                or raw.get("namespace") != {"bot_id": namespace.bot_id, "persona_id": namespace.persona_id}):
            raise ValueError("signed production policy current identity changed")
        found.append((ProductionOriginalRefV1(domain + ".installed_policy", ref, row[2]),
                      ProductionPolicyRefV1(ref, row[0], row[2])))
    if len(found) > 1:
        raise ValueError("production policy locator collides across domains")
    return found[0] if found else None


def _graph_original(db, namespace, ref):
    try:
        key = AtomKey.from_token(ref)
    except (TypeError, ValueError):
        return None
    if NamespaceId.from_key(key) != namespace:
        raise ValueError("production graph original crossed namespace")
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                     (ref, *namespace.as_tuple)).fetchone()
    if row is None or row[0] < 1 or row[2] != 1:
        return None
    history = db.execute("SELECT value,valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?",
                         (ref, row[0])).fetchone()
    if history is None or history[:2] != (row[1], row[2]) or history[2:4] != namespace.as_tuple:
        raise ValueError("production original has no exact adopted graph history")
    event = db.execute("SELECT revisions FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
                       history[2:]).fetchone()
    if event is None:
        raise ValueError("production graph original has no actual graph event")
    from ..graph_store import GraphStore
    if GraphVersion(key, row[0]) not in GraphStore._version_rows(event[0]):
        raise ValueError("production original head was not adopted by its graph event")
    value = json.loads(row[1])
    kind = key.type_name
    if key.type_name == "runtime.cost_settlement":
        from .d11_types import cost_settlement_from_runtime
        cost = cost_settlement_from_runtime(db, **{name: value[name] for name in (
            "bot_id", "persona_id", "activity_id", "bundle_operation_id", "effect_id",
            "settlement_id", "lease_id", "cost_operation_id", "budget_operation_id", "budget_phase",
            "prior_unknown_ref", "execution_revoked")})
        from ..domains.d01.production_operations_v1 import plain_v1
        if plain_v1(cost) != value:
            raise ValueError("current cost head differs from the actual D11 budget settlement")
        kind = "d11.cost_settlement"
    return ProductionOriginalRefV1(kind, ref, canonical_digest(value), (GraphVersion(key, row[0]),))


def _role_clock_original(db, namespace, ref, issuer):
    from .d11_role_clock_installation_v1 import TABLE, SIGN_KIND, role_clock_mapping_id_v1
    if ref != role_clock_mapping_id_v1(namespace) or not table_exists_v1(db, TABLE):
        return None
    from .d04_semantic_installation_original_v3 import _read_signed
    saved = _read_signed(db, issuer, TABLE, SIGN_KIND, namespace)
    if saved is None:
        return None
    body, digest = saved
    if body["mapping"]["mapping_id"] != ref:
        raise ValueError("signed current role clock locator changed")
    from .clock import get_clock_mapping, _mapping_dict
    if _mapping_dict(get_clock_mapping(db, ref)) != body["mapping"]:
        raise ValueError("signed current clock mapping lost its actual D11 operation")
    versions = tuple(GraphVersion(AtomKey.from_token(row[0]), row[1]) for row in body["role_rows"])
    return ProductionOriginalRefV1("d11.role_clock", ref, digest, versions)


def _adopted_domain_original(db, namespace, ref):
    if not table_exists_v1(db, "graph_domain_production_originals_v1"):
        return None
    row = db.execute("SELECT operation_id FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? "
        "AND (operation_id=? OR domain || '-current:' || substr(original_digest,1,48)=?) LIMIT 2",
        (*namespace.as_tuple, ref, ref)).fetchall()
    if not row:
        return None
    if len(row) != 1:
        raise ValueError("domain adopted original identity is ambiguous")
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    saved = read_adopted_domain_operation_v1(db, namespace, row[0][0])
    # These inputs are immutable historical adoptions. Their pre-CAS read
    # versions are retained by the original reader, not asserted as current
    # heads after that adoption has legitimately changed body/role state.
    # Each consumer's fixed read plan separately qualifies current sources.
    return ProductionOriginalRefV1(saved["domain"] + ".current-" + saved["operation_kind"], ref,
                                  saved["original_digest"])


def _outbound_original(db, namespace, ref):
    if not table_exists_v1(db, "graph_d13_outbound_observations_v1"):
        return None
    rows = db.execute("SELECT observation_digest,observation_json,original_json,original_digest FROM graph_d13_outbound_observations_v1 "
        "WHERE bot=? AND persona=? AND (source_ref=? OR observation_digest=? OR final_operation_id=?) LIMIT 3",
        (*namespace.as_tuple, ref, ref, ref)).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise MissingProductionOriginalV1("unique_current_outbound_observation:" + ref)
    from ..authority_service.v2_contract import MutationReceiptV2, from_wire
    digest, observed_json, original_json, original_digest = rows[0]
    observed, original = from_wire(json.loads(observed_json)), json.loads(original_json)
    if (type(observed) is not MutationReceiptV2 or observed.durable_state != "committed"
            or observed.pending.phase != "observed" or canonical_digest(observed) != digest
            or canonical_digest(original) != original_digest or original["observation_digest"] != digest):
        raise ValueError("actual independent outbound observation original changed")
    return ProductionOriginalRefV1("d11.outbound_observation", ref, digest)


def read_current_domain_original_refs_v1(db, *, namespace, plan, installed_readers, authenticated_external_originals=()):
    if not db.in_transaction or type(namespace) is not NamespaceId or type(plan) is not ProductionReadPlanV1:
        raise ValueError("domain originals require the current W01 transaction and exact read plan")
    issuer = _issuer(installed_readers)
    if (type(authenticated_external_originals) is not tuple
            or any(type(original) is not ProductionOriginalRefV1 for original in authenticated_external_originals)):
        raise TypeError("outside-transaction originals must come from the installed Authority adapter")
    external = {original.original_ref: original for original in authenticated_external_originals}
    if len(external) != len(authenticated_external_originals):
        raise ValueError("independent production original references repeat")
    result = []
    for ref in plan.required_original_refs:
        original = _signed_input(db, namespace, ref, issuer)
        policy = _signed_policy(db, namespace, ref, issuer)
        if policy:
            if original:
                raise ValueError("production original and policy locator collide")
            original = policy[0]
        original = original or _role_clock_original(db, namespace, ref, issuer)
        original = original or _adopted_domain_original(db, namespace, ref)
        original = original or _outbound_original(db, namespace, ref)
        if original is None:
            from .d11_offline_originals_v1 import read_current_d11_offline_original_ref_v1
            original = read_current_d11_offline_original_ref_v1(db, namespace=namespace, original_ref=ref, issuer=issuer)
        if original is None:
            from .d11_life_product_adapter_v1 import read_current_life_original_ref_v1
            original = read_current_life_original_ref_v1(db, namespace=namespace, original_ref=ref, issuer=issuer)
        original = original or _graph_original(db, namespace, ref)
        if original is None:
            service = getattr(installed_readers, "execution_reader", None)
            if service is not None:
                from .d07_execution_v1 import read_current_original_ref_v1
                original = read_current_original_ref_v1(db, namespace=namespace, ref=ref, issuer=issuer)
        supplied = external.get(ref)
        if supplied is not None:
            if original is not None and (original.original_digest != supplied.original_digest
                    or original.read_versions != supplied.read_versions):
                raise ValueError("independent original differs from the durable current DB original")
            original = supplied
        if original is not None:
            result.append(original)
    # Actual external restore anchors/ticks may be implicit dependencies of a
    # fixed reader, even when their lookup is not a caller-controlled field.
    for original in authenticated_external_originals:
        if original.original_ref not in {item.original_ref for item in result}:
            if original.kind not in {"d11.restore_anchor", "d11.trusted_tick", "d11.clock_sample", "d03.current_self_identity"}:
                continue
            result.append(original)
    return tuple(result)


def read_current_domain_policy_refs_v1(db, *, namespace, plan, installed_readers):
    issuer = _issuer(installed_readers)
    refs = []
    for ref in plan.required_original_refs:
        found = _signed_policy(db, namespace, ref, issuer)
        if found:
            refs.append(found[1])
    # D02 passive advancement uses explicit historical boundaries for the
    # current profile; all those signed versions remain relevant to the read.
    if "d02.body_state.v1" in plan.fixed_type_ids and table_exists_v1(db, "graph_d02_production_policies_v1"):
        rows = db.execute("SELECT policy_ref,revision,payload_json,payload_digest,signature FROM graph_d02_production_policies_v1 "
                          "WHERE bot=? AND persona=? AND kind='passive' ORDER BY from_role_cursor,policy_ref,revision LIMIT 129",
                          namespace.as_tuple).fetchall()
        if len(rows) > 128:
            raise MissingProductionOriginalV1("bounded_passive_policy_history",
                continuation="passive-policy:" + canonical_digest(namespace)[:48])
        for ref, revision, encoded, digest, signature in rows:
            issuer._signer.verify("d11.d02-production-policy.v1", encoded, signature)
            if canonical_digest(json.loads(encoded)) != digest:
                raise ValueError("D02 historical passive policy bytes changed")
            refs.append(ProductionPolicyRefV1(ref, revision, digest))
    if len({(ref.policy_ref, ref.revision) for ref in refs}) != len(refs):
        refs = list({(ref.policy_ref, ref.revision): ref for ref in refs}.values())
    return tuple(sorted(refs, key=lambda item: (item.policy_ref, item.revision)))


@dataclass(frozen=True, slots=True)
class CurrentDomainCommandIdentityV1:
    activity_id: str
    effect_id: str | None
    purpose: str
    audience_ref: str


def read_current_domain_command_identity_v1(db, *, namespace, operation_kind, request,
        requested_activity_id, requested_audience_ref, installed_readers=None, operation_id=None):
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("command identity must be derived in the current W01 transaction")
    activity, effect, purpose = requested_activity_id, None, "context"
    if operation_kind in {"prepare_life_project_context", "focus_life_project"}:
        purpose = "consolidation"
    elif operation_kind == "prepare_source_note_action":
        from .d08_source_note_action_v1 import source_note_effect_id_v1
        effect, purpose = source_note_effect_id_v1(namespace, request.project_ref, operation_id), "consolidation"
    elif operation_kind == "prepare_source_note_body":
        from .d08_source_note_action_v1 import require_source_note_action_original_v1
        root = require_source_note_action_original_v1(db, namespace=namespace,
            action_intent_ref=request.action_intent_ref, issuer=_issuer(installed_readers))
        if operation_id != "d02-life-body:" + root.action_operation_id:
            raise ValueError("Body B must be the actual distinct command of root A")
        activity, effect, purpose = root.activity_id, root.effect_id, "consolidation"
    elif operation_kind in {'prepare_internal_life_content', 'acquire_internal_life_content', 'acquire_internal_life_content_v2','adopt_internal_life_content_v1'}:
        from .internal_life_content_preparation_v1 import PrepareInternalLifeContentRequestV1
        from .internal_life_content_worker_v1 import AcquireInternalLifeContentRequestV1
        from .d06_internal_life_episode_v2 import PROVENANCE,decode_internal_life_value_v2
        from ..model_broker.internal_life_content_v1 import internal_life_content_ids_for_occurrence_v1
        from .internal_life_content_worker_v2 import AcquireInternalLifeContentRequestV2
        from .internal_life_content_adoption_v1 import AdoptInternalLifeContentRequestV1
        expected = (AdoptInternalLifeContentRequestV1 if operation_kind=="adopt_internal_life_content_v1" else PrepareInternalLifeContentRequestV1 if operation_kind == 'prepare_internal_life_content' else
            AcquireInternalLifeContentRequestV2 if operation_kind == 'acquire_internal_life_content_v2' else AcquireInternalLifeContentRequestV1)
        if type(request) is not expected:
            raise TypeError('exact Life content preparation request required')
        episode=AtomKey.from_token(request.episode_ref)
        proof=decode_internal_life_value_v2(PROVENANCE,
            raw_head_value_v1(db,namespace,AtomKey(episode.owner,PROVENANCE,'record')))
        ids=internal_life_content_ids_for_occurrence_v1(proof)
        if (proof.event.namespace!=namespace or proof.episode.episode_ref!=request.episode_ref
                or proof.event.causal_operation_id!=request.causal_operation_id
                or proof.event.activity.activity_id!=requested_activity_id
                or operation_id!=('life-content-adopt:'+ids['job'].removeprefix('life-content-job:') if operation_kind=='adopt_internal_life_content_v1' else ids['prepare' if operation_kind == 'prepare_internal_life_content' else 'acquire'])):
            raise ValueError('Life content command must use its immutable occurrence once identity')
        activity,effect,purpose=proof.event.activity.activity_id,None,'consolidation'
    elif operation_kind in {'prepare_internal_life_numeric', 'acquire_internal_life_numeric', 'adopt_internal_life_numeric'}:
        from .d06_life_numeric_context_v1 import life_numeric_context_ids_v1, decode_life_numeric_context_original_v1, KIND
        from .d06_life_numeric_task_v1 import _identity
        from .d11_life_product_adapter_v1 import raw_life_original_v1
        from ..model_broker.internal_life_numeric_v1 import internal_life_numeric_ids_v1
        raw = raw_life_original_v1(db, namespace, KIND, life_numeric_context_ids_v1(namespace, request.episode_ref)['original'])
        if raw is None:
            raise MissingProductionOriginalV1('actual_life_numeric_context')
        original = decode_life_numeric_context_original_v1(raw)
        ids = internal_life_numeric_ids_v1(_identity(original))
        suffix = {'prepare_internal_life_numeric':'prepare', 'acquire_internal_life_numeric':'acquire', 'adopt_internal_life_numeric':'adopt'}[operation_kind]
        from .d06_internal_life_episode_v2 import PROVENANCE, decode_internal_life_value_v2
        episode = AtomKey.from_token(request.episode_ref)
        proof_raw = raw_head_value_v1(db, namespace, AtomKey(episode.owner, PROVENANCE, 'record'))
        if proof_raw is None:
            raise MissingProductionOriginalV1('actual_internal_life_episode_provenance')
        proof = decode_internal_life_value_v2(PROVENANCE, proof_raw)
        if (original.namespace != namespace or original.episode_ref != request.episode_ref
                or proof.event.namespace != namespace or proof.episode.episode_ref != request.episode_ref
                or proof.event.causal_operation_id != request.causal_operation_id
                or proof.event.activity.activity_id != requested_activity_id or operation_id != ids[suffix]):
            raise ValueError('numeric Life task identity differs from its actual occurrence')
        activity, effect, purpose = proof.event.activity.activity_id, None, 'consolidation'
    elif operation_kind in {'prepare_internal_life_interval_baseline', 'adopt_internal_life_numeric_trace', 'prepare_internal_life_numeric_joint', 'prepare_internal_life_numeric_drive'}:
        from .d06_internal_life_episode_v2 import PROVENANCE, decode_internal_life_value_v2
        from .d06_life_numeric_drive_v1 import life_numeric_drive_ids_v1
        from .d06_life_numeric_joint_v1 import life_numeric_joint_ids_v1
        from .d04_life_encoding_baseline_v1 import life_encoding_baseline_ids_v1
        from .d06_life_numeric_trace_v1 import life_numeric_trace_operation_v1
        if operation_kind == 'prepare_internal_life_numeric_drive':
            expected = life_numeric_drive_ids_v1(namespace, request.episode_ref, request.appraisal_ref)['operation']
        elif operation_kind == 'prepare_internal_life_numeric_joint':
            expected = life_numeric_joint_ids_v1(namespace, request.episode_ref, request.appraisal_ref)['prepare']
        elif operation_kind == 'prepare_internal_life_interval_baseline':
            expected = life_encoding_baseline_ids_v1(namespace, request.episode_ref, request.joint_operation_id)['operation']
        else:
            expected = life_numeric_trace_operation_v1(namespace, request.episode_ref, request.joint_operation_id)
        episode = AtomKey.from_token(request.episode_ref)
        raw = raw_head_value_v1(db, namespace, AtomKey(episode.owner, PROVENANCE, 'record'))
        if raw is None:
            raise MissingProductionOriginalV1('actual_internal_life_episode_provenance')
        proof = decode_internal_life_value_v2(PROVENANCE, raw)
        if (proof.event.namespace != namespace or proof.episode.episode_ref != request.episode_ref
                or proof.event.causal_operation_id != request.causal_operation_id
                or proof.event.activity.activity_id != requested_activity_id or operation_id != expected):
            raise ValueError('numeric Life mathematical command differs from actual occurrence and adopted input')
        activity, effect, purpose = proof.event.activity.activity_id, None, 'consolidation'
    elif operation_kind == "prepare_internal_life_numeric_context":
        from .d06_life_numeric_context_v1 import PrepareLifeNumericContextRequestV1, life_numeric_context_ids_v1
        from .d06_internal_life_episode_v2 import PROVENANCE, decode_internal_life_value_v2
        if type(request) is not PrepareLifeNumericContextRequestV1:
            raise TypeError('exact numeric Life context request required')
        episode = AtomKey.from_token(request.episode_ref)
        raw = raw_head_value_v1(db, namespace, AtomKey(episode.owner, PROVENANCE, 'record'))
        if raw is None:
            raise MissingProductionOriginalV1('actual_internal_life_episode_provenance')
        proof = decode_internal_life_value_v2(PROVENANCE, raw)
        if (proof.event.namespace != namespace or proof.episode.episode_ref != request.episode_ref
                or proof.event.causal_operation_id != request.causal_operation_id
                or proof.event.activity.activity_id != requested_activity_id
                or operation_id != life_numeric_context_ids_v1(namespace, request.episode_ref)['operation']):
            raise ValueError('numeric Life context exact occurrence once identity differs')
        activity, effect, purpose = proof.event.activity.activity_id, None, 'consolidation'
    elif operation_kind == "encode_internal_life":
        from .d06_internal_life_encoding_v1 import EncodeInternalLifeRequestV1
        from .d06_internal_life_episode_v2 import PROVENANCE, decode_internal_life_value_v2
        if type(request) is not EncodeInternalLifeRequestV1:
            raise TypeError('exact Life encoding locator required')
        episode = AtomKey.from_token(request.episode_ref)
        proof_value = raw_head_value_v1(db, namespace, AtomKey(episode.owner, PROVENANCE, 'record'))
        if proof_value is None:
            raise MissingProductionOriginalV1('actual_internal_life_episode_provenance')
        proof = decode_internal_life_value_v2(PROVENANCE, proof_value)
        if (proof.event.namespace != namespace or proof.episode.episode_ref != request.episode_ref
                or proof.event.causal_operation_id != request.causal_operation_id
                or proof.event.activity.activity_id != requested_activity_id):
            raise ValueError('Life encoding identity is not its actual occurrence')
        activity = proof.event.activity.activity_id
        effect = 'effect:life-encoding:' + canonical_digest((namespace, request.episode_ref, operation_id))[:48]
        purpose = 'consolidation'
    elif operation_kind in {"encode_structured_experience", "form_association", "adopt_growth", "adopt_relationship_contribution", "reevaluate_relationship",
            "input:prepare_growth_input", "input:derive_growth_trial"}:
        purpose = "consolidation"
    elif operation_kind == "prepare_contact_dispatch_v3":
        from .contact_final_stage_v3 import command_identity_contact_final_v3
        activity, effect, audience = command_identity_contact_final_v3(db, namespace=namespace,
            request=request, operation_id=operation_id, issuer=_issuer(installed_readers))
        if (requested_activity_id, requested_audience_ref) != (activity, audience):
            raise ValueError("Contact3 final command differs from its actual paid activity/audience")
        purpose = "expression"
    elif operation_kind == "prepare_contact_dispatch":
        from .contact_final_stage_v2 import command_identity_contact_final_v2
        activity, effect, audience = command_identity_contact_final_v2(db, namespace=namespace,
            request=request, operation_id=operation_id, issuer=_issuer(installed_readers))
        if (requested_activity_id, requested_audience_ref) != (activity, audience):
            raise ValueError('Contact final command differs from its original activity/private audience')
        purpose = 'expression'
    elif operation_kind == "prepare_contact_model_v2":
        from .contact_product_adapter_v2 import command_identity_contact_model_v2
        activity, effect, purpose = command_identity_contact_model_v2(db, namespace=namespace,
            request=request, operation_id=operation_id, issuer=_issuer(installed_readers))
        if requested_activity_id != activity:
            raise ValueError("Contact V2 preparation must use its actual adopted activity")
    elif operation_kind == "prepare_contact_model":
        from .contact_product_adapter_v1 import command_identity_contact_model_v1
        activity, effect, purpose = command_identity_contact_model_v1(db, namespace=namespace,
            request=request, operation_id=operation_id, issuer=_issuer(installed_readers))
        if requested_activity_id != activity:
            raise ValueError("contact model preparation must use its adopted stable activity")
    elif operation_kind in {"adopt_contact_expression_plan", "adopt_contact_expression_plan_v2"}:
        from ..domains.d08.contact_plan_v1 import contact_ids_v1
        opportunity = raw_head_value_v1(db, namespace, AtomKey.from_token(request.opportunity_ref))
        if opportunity is None:
            raise MissingProductionOriginalV1("actual_current_contact_opportunity")
        activity = contact_ids_v1(namespace, opportunity["source_ref"], opportunity["subject_ref"], "private_text")["activity"]
        if requested_activity_id != activity:
            raise ValueError("contact command activity differs from its stable actual cause")
        purpose = "expression"
    elif operation_kind in {"prepare_contact", "input:create_goal", "input:create_contact_opportunity"}:
        purpose = "expression"
    elif operation_kind in {"recheck_action", "settle_observed_action"}:
        action = raw_head_value_v1(db, namespace, AtomKey.from_token(request.action_intent_ref))
        if action:
            from ..domains.d08.execution import _decode_intent
            intent = _decode_intent(action)
            activity, effect, purpose = intent.identity.activity_id, intent.identity.effect_id, intent.purpose
    elif operation_kind == "apply_body_effect":
        from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
        prepared = read_c04_internal_work_prepared_v1(db, namespace, request.settlement_operation_ref) if table_exists_v1(db, "graph_c04_internal_work_prepared_v1") else None
        if prepared:
            activity = prepared.binding.activity_id
            if installed_readers is not None:
                quote = _issuer(installed_readers).resource_issuer.original_signed_quote(db,
                    prepared.binding.resource_quote_ref, prepared.binding.resource_quote_version)
                effect = quote.effect_id
        else:
            completion = raw_registered_input_v1(db, "graph_d02_action_components_v1", namespace, request.settlement_operation_ref)
            if completion:
                if installed_readers is not None:
                    _signed_input(db, namespace, request.settlement_operation_ref, _issuer(installed_readers))
                action = raw_head_value_v1(db, namespace, AtomKey.from_token(completion["action_intent_ref"]))
                if action:
                    from ..domains.d08.execution import _decode_intent
                    intent = _decode_intent(action)
                    activity, effect, purpose = intent.identity.activity_id, intent.identity.effect_id, intent.purpose
    elif operation_kind in {"input:register_life_plan_v2", "input:register_life_outcome_v2", "prepare_life"}:
        from .d11_life_contract_v1 import RegisteredLifePlanV2, life_from_wire_v1
        from .d11_life_product_adapter_v1 import raw_life_original_v1
        if operation_kind == "input:register_life_plan_v2":
            plan = request.plan
        else:
            ref = request.plan_original_ref if operation_kind == "prepare_life" else request.outcome.plan_original_ref
            raw = raw_life_original_v1(db, namespace, "plan", ref)
            if raw is None:
                raise MissingProductionOriginalV1("actual_registered_life_plan_v2")
            plan = life_from_wire_v1(raw, RegisteredLifePlanV2)
            if installed_readers is not None:
                from .d11_life_preparation_v1 import read_registered_life_plan_v2
                plan = read_registered_life_plan_v2(db, namespace=namespace,
                    issuer=_issuer(installed_readers), original_ref=ref)
        action = raw_head_value_v1(db, namespace, AtomKey.from_token(plan.action_intent.ref))
        if action is None:
            raise MissingProductionOriginalV1("actual_current_life_root_action")
        from ..domains.d08.execution import _decode_intent
        intent = _decode_intent(action)
        if operation_kind == "prepare_life" and operation_id != request.prepare_operation_id:
            raise ValueError("Life prepare command differs from the actual requested Owner operation")
        activity, effect, purpose = intent.identity.activity_id, intent.identity.effect_id, intent.purpose
        if requested_audience_ref not in plan.audiences:
            raise ValueError("Life command audience is outside the actual registered input scope")
    elif operation_kind == "input:register_life_plan":
        action = raw_head_value_v1(db, namespace, AtomKey.from_token(request.plan.action_intent_ref))
        if action:
            from ..domains.d08.execution import _decode_intent
            intent = _decode_intent(action)
            activity, effect, purpose = intent.identity.activity_id, intent.identity.effect_id, intent.purpose
    elif operation_kind in {"advance_life", "input:register_life_outcome"}:
        from .d11_life_product_adapter_v1 import raw_life_original_v1
        life_outcome = raw_life_original_v1(db, namespace, "outcome", request.activity_outcome_ref) if operation_kind == "advance_life" else None
        if life_outcome is not None:
            from .d11_life_preparation_v1 import read_registered_life_plan_v2
            from .d11_life_contract_v1 import RegisteredLifeOutcomeV2, life_from_wire_v1
            current = life_from_wire_v1(life_outcome, RegisteredLifeOutcomeV2)
            plan = read_registered_life_plan_v2(db, namespace=namespace,
                issuer=_issuer(installed_readers), original_ref=current.plan_original_ref)
            if plan is None:
                raise MissingProductionOriginalV1("actual_registered_life_plan_v2")
            if plan.activity_id != requested_activity_id or requested_audience_ref not in plan.audiences:
                raise ValueError("Life V2 command differs from the actual plan identity/audience")
            return CurrentDomainCommandIdentityV1(plan.activity_id, plan.effect_id, "consolidation", requested_audience_ref)
        if operation_kind == "input:register_life_outcome":
            outcome = {"plan_original_ref": request.outcome.plan_original_ref}
        else:
            outcome = raw_registered_input_v1(db, "graph_d10_production_inputs_v1", namespace, request.activity_outcome_ref)
        if outcome:
            if installed_readers is not None and operation_kind == "advance_life":
                _signed_input(db, namespace, request.activity_outcome_ref, _issuer(installed_readers))
            plan = raw_registered_input_v1(db, "graph_d10_production_inputs_v1", namespace, outcome["plan_original_ref"])
            if plan:
                if installed_readers is not None:
                    _signed_input(db, namespace, outcome["plan_original_ref"], _issuer(installed_readers))
                action = raw_head_value_v1(db, namespace, AtomKey.from_token(plan["action_intent_ref"]))
                if action:
                    from ..domains.d08.execution import _decode_intent
                    intent = _decode_intent(action)
                    activity, effect, purpose = intent.identity.activity_id, intent.identity.effect_id, intent.purpose
    elif operation_kind in {"serve_concern", "advance_reflection", "run_simulation"}:
        service = getattr(installed_readers, "execution_reader", None)
        if service is not None and hasattr(service, "read_current_command_identity_v1"):
            value = service.read_current_command_identity_v1(db, namespace=namespace,
                operation_kind=operation_kind, request=request, operation_id=operation_id,
                requested_activity_id=requested_activity_id)
            if value is not None:
                activity, effect, purpose = value.activity_id, value.effect_id, value.purpose
    if activity != requested_activity_id:
        raise ValueError("requested activity differs from the actual prepared/outcome original")
    return CurrentDomainCommandIdentityV1(activity, effect, purpose, requested_audience_ref)


@dataclass(frozen=True, slots=True)
class C04IndependentOriginalReadRequestV1:
    binding: object
    component_ref: str
    component_proof_digest: str | None
    terminal_receipt_ref: str | None
    terminal_receipt_digest: str | None


def read_independent_current_original_requests_v1(db, *, namespace, plan):
    """Return actual immutable C04 identities for W01's OUTSIDE-SQL RPC."""
    from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
    from .d11_c04_internal_cost import read_c04_cpu_cost_original_v1
    if not table_exists_v1(db, "graph_c04_internal_work_prepared_v1"):
        return ()
    requested = set(plan.required_original_refs)
    rows = db.execute("SELECT operation_id FROM graph_c04_internal_work_prepared_v1 WHERE bot=? AND persona=? ORDER BY operation_id LIMIT 129",
                      namespace.as_tuple).fetchall()
    if len(rows) > 128:
        raise MissingProductionOriginalV1("bounded_c04_original_lookup")
    result = []
    for (operation,) in rows:
        prepared = read_c04_internal_work_prepared_v1(db, namespace, operation)
        component = "internal-work:component:" + prepared.binding.binding_digest
        cost = read_c04_cpu_cost_original_v1(db, namespace, operation)
        if component not in requested and (cost is None or cost.terminal_receipt_ref not in requested):
            continue
        result.append(C04IndependentOriginalReadRequestV1(prepared.binding, component,
            cost.proof_digest if cost else None, cost.terminal_receipt_ref if cost else None,
            cost.terminal_receipt_digest if cost else None))
    return tuple(result)


def rebuild_current_domain_stage_v1(db, *, frame, request, domain, operation_kind, installed_readers):
    """Closed current issuer dispatcher used by W01's private commit witness."""
    if not db.in_transaction:
        raise ValueError("domain stage reissuance requires W01's current business transaction")
    if domain == "d01":
        from .d01_production_operations_v1 import stage_evaluate_current_values_in_transaction_v1, stage_adopt_current_growth_in_transaction_v1
        dispatch = {"evaluate_values": stage_evaluate_current_values_in_transaction_v1,
                    "adopt_growth": stage_adopt_current_growth_in_transaction_v1}
    elif domain == "d02":
        from .d02_production_operations_v1 import stage_advance_current_body_in_transaction_v1, stage_apply_current_body_effect_in_transaction_v1
        dispatch = {"advance_body": stage_advance_current_body_in_transaction_v1,
                    "apply_body_effect": stage_apply_current_body_effect_in_transaction_v1}
    elif domain == "d05":
        from .d05_production_operations_v1 import stage_adopt_current_relationship_contribution_in_transaction_v1, stage_revise_current_boundary_in_transaction_v1, stage_reevaluate_current_relationship_in_transaction_v1
        dispatch = {"adopt_relationship_contribution": stage_adopt_current_relationship_contribution_in_transaction_v1,
            "revise_boundary": stage_revise_current_boundary_in_transaction_v1,
            "reevaluate_relationship": stage_reevaluate_current_relationship_in_transaction_v1}
    elif domain == "d07":
        from .d07_production_operations_v1 import stage_serve_current_concern_in_transaction_v1, stage_advance_current_reflection_in_transaction_v1, stage_run_current_simulation_in_transaction_v1
        dispatch = {"serve_concern": stage_serve_current_concern_in_transaction_v1,
            "advance_reflection": stage_advance_current_reflection_in_transaction_v1,
            "run_simulation": stage_run_current_simulation_in_transaction_v1}
    elif domain == "d06" and operation_kind == "encode_structured_experience":
        from .d06_structured_experience_v1 import stage_encode_current_structured_experience_in_transaction_v1
        dispatch = {"encode_structured_experience": stage_encode_current_structured_experience_in_transaction_v1}
    elif domain == "d06" and operation_kind == "form_association":
        from .d06_association_formation_v1 import stage_form_current_association_in_transaction_v1
        dispatch = {"form_association": stage_form_current_association_in_transaction_v1}
    elif domain == "d08":
        from .d08_production_operations_v1 import stage_acknowledge_current_bilateral_in_transaction_v1, stage_adopt_current_joint_plan_in_transaction_v1, stage_recheck_current_action_in_transaction_v1
        dispatch = {"acknowledge_bilateral": stage_acknowledge_current_bilateral_in_transaction_v1,
            "adopt_joint_plan": stage_adopt_current_joint_plan_in_transaction_v1,
            "recheck_action": stage_recheck_current_action_in_transaction_v1}
    elif domain == "d10":
        from .d10_production_operations_v1 import stage_current_life_effect_experience_bundle_in_transaction_v1, stage_current_offline_body_experience_bundle_in_transaction_v1, stage_prepare_current_contact_in_transaction_v1
        dispatch = {"advance_life": stage_current_life_effect_experience_bundle_in_transaction_v1,
            "advance_offline": stage_current_offline_body_experience_bundle_in_transaction_v1,
            "prepare_contact": stage_prepare_current_contact_in_transaction_v1}
    else:
        raise ValueError("unregistered production domain stage")
    if operation_kind not in dispatch:
        raise ValueError("unregistered exact current domain operation")
    return dispatch[operation_kind](db, frame=frame, request=request, installed_readers=installed_readers)


def verify_current_domain_operation_stage_v1(db, *, frame, request, domain, operation_kind,
        installed_readers, stage):
    current = rebuild_current_domain_stage_v1(db, frame=frame, request=request, domain=domain,
        operation_kind=operation_kind, installed_readers=installed_readers)
    if current != stage:
        raise ValueError("domain stage differs from independently reissued current originals")
    return current
