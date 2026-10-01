"""Concrete pinned SQLite proof of a current D04 numeric prepared original.

The Authority service separately checks its signed Owner grant/fence and the
paired executor admission. This independent reader checks shared Graph and
immutable preparation bytes; caller-generated digests cannot replace rows.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json

from ..runtime_contracts import canonical_digest, canonical_serialize
from .d04_numeric_contract_v3 import D04NumericBindingV3


@dataclass(frozen=True, slots=True)
class D04NumericPreparedReadV3:
    binding: D04NumericBindingV3
    prepared_ref: str
    prepared_digest: str
    job_phase: str
    worker_fence: int
    worker_holder: str | None
    reservation_operation_id: str
    reservation_digest: str
    quote_digest: str
    authority_anchor_json: str
    frozen_input_json: str
    owner_selectors: tuple[dict, ...]
    authority_projection_digest: str
    schema: str = "d04.current_numeric_prepared_read.v3"


def read_numeric_policy_owner_selectors_v3(db,binding,budget_issuer,frozen,*,now_utc,require_current_budget=True):
    """Independently verify signed dose/grant/accepting-Owner originals."""
    from ..runtime.issuers import D11BudgetGrantIssuer
    from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
    from ..runtime.d04_semantic_installation_original_v3 import _read_signed,TABLE,SIGN_KIND
    from ..runtime.d11_role_clock_installation_v1 import TABLE as CLOCK_TABLE,SIGN_KIND as CLOCK_SIGN_KIND,_mapping_original
    from ..runtime.d04_semantic_policy import AdminD04SemanticDrivePolicyV1
    if not isinstance(budget_issuer,D11BudgetGrantIssuer) or not db.in_transaction:
        raise ValueError("actual signed D11 authority and existing Graph read transaction required")
    saved=_read_signed(db,budget_issuer,TABLE,SIGN_KIND,binding.namespace)
    clock=_read_signed(db,budget_issuer,CLOCK_TABLE,CLOCK_SIGN_KIND,binding.namespace)
    if saved is None or clock is None:raise ValueError("actual Owner semantic/clock acceptance absent")
    if saved[0].get("state")!="active":raise ValueError("actual semantic mapping is not active")
    original_clock=_mapping_original(db,binding.namespace,clock)
    clock_input=frozen["evidence_inputs"]["clock"]
    from ..runtime.clock import _mapping_dict
    if (original_clock.mapping_id!=clock_input["mapping_id"] or original_clock.version!=clock_input["mapping_version"]
            or canonical_serialize(_mapping_dict(original_clock))!=clock_input["registered_mapping_json"]):
        raise ValueError("numeric original Owner role-clock authority changed")
    if require_current_budget:
        original_clock.character_at(datetime.fromtimestamp(now_utc,timezone.utc).isoformat().replace("+00:00","Z"))
    refs=frozen.get("mapping_original_refs")
    if type(refs) is not list or not refs:raise ValueError("numeric actual mapping original closure absent")
    commitments=[]
    for ref in refs:
        row=read_d04_original_v3(db,binding.namespace,"semantic_mapping",ref)
        if row is None:raise ValueError("numeric actual semantic drive mapping original absent")
        raw=row[0];installed=raw["mapping_installation"]
        if (raw.get("namespace")!=asdict(binding.namespace) or raw.get("schema")!="d04.semantic_mapping_acceptance.v3"
                or installed["acceptance_digest"]!=saved[1] or installed["acceptance_revision"]!=saved[0]["revision"]
                or installed["acceptance_ref"]!="d04-semantic-acceptance:"+saved[0]["operation_id"]
                or canonical_serialize(installed["asset"])!=canonical_serialize(saved[0]["bound_asset"])
                or raw["mapping_installation_digest"]!=canonical_digest(installed)):
            raise ValueError("numeric mapping differs from its actual signed Owner acceptance")
        authority=raw["dose_policy_authority"];kind="d11.installed-d04-semantic-dose-policy.v3"
        if type(authority) is not dict or set(authority)!={"kind","payload_json","signature"} or authority["kind"]!=kind:
            raise ValueError("numeric semantic dose authority shape differs")
        budget_issuer._signer.verify(kind,authority["payload_json"],authority["signature"])
        dose=dict(raw["dose_policy"]);dose["namespace"]=binding.namespace
        dose["mechanism_max_abs_doses"]={key:tuple(value) for key,value in dose["mechanism_max_abs_doses"].items()}
        policy=AdminD04SemanticDrivePolicyV1(**dose)
        grant,signature=budget_issuer.signed_budget_grant_at_version(db,policy.lease_id,policy.grant_version)
        stored=db.execute("SELECT grant_json,signature FROM runtime_budget_grants WHERE lease_id=? AND version=?",(policy.lease_id,policy.grant_version)).fetchone()
        signed={"kind":"budget-grant.v1","payload_json":stored[0],"signature":signature}
        body={"schema":kind,"namespace":asdict(binding.namespace),"installation_id":policy.installation_id,
            "manifest_digest":binding.native_manifest_sha256,"mapping_original_ref":ref,
            "mapping_acceptance_digest":installed["acceptance_digest"],"appraisal_acceptance_digest":raw["appraisal_acceptance_digest"],
            "dose_policy":raw["dose_policy"],"signed_budget_grant":signed}
        if (stored[1]!=signature or raw["signed_budget_grant"]!=signed or canonical_serialize(body)!=authority["payload_json"]
                or (grant.bot_id,grant.persona_id)!=binding.namespace.as_tuple or grant.grant_id!=policy.grant_id
                or policy.work_kind not in grant.allowed_work_kinds
                or policy.installation_id!=saved[0]["owner_guard"]["installation_id"]):
            raise ValueError("numeric signed dose policy/budget scope differs")
        if require_current_budget and (budget_issuer.current_budget_grant(db,policy.lease_id)!=grant or grant.valid_until_utc<=now_utc):
            raise ValueError("numeric current semantic dose grant is inactive/expired")
        commitments.append((ref,row[1],canonical_digest(authority),canonical_digest(signed)))
    selectors=[]
    for body,commitment in (saved,clock):
        owner=body["owner"]
        if body.get("manifest_sha256")!=binding.native_manifest_sha256:
            raise ValueError("numeric accepting Owner belongs to a different installed package")
        selectors.append({"actor_id":owner["actor_id"],"principal":owner["principal"],
            "installation_id":body["owner_guard"]["installation_id"],"owner_guard":body["owner_guard"],
            "acceptance_digest":commitment})
    return tuple(selectors),canonical_digest((tuple(commitments),saved[1],clock[1]))


def read_current_d04_numeric_prepared_v3(db, binding, resource_issuer, now_utc, *, budget_issuer):
    """Composition-installed reader; never take a request-specific callback."""
    from ..runtime.d04_numeric_cost_v3 import read_d04_numeric_prepared_v3
    from ..runtime.d04_appraisal_driver_v3 import (
        D04GraphReadV3, require_current_read_rows_v3, read_d04_original_v3,
    )
    from ..runtime.jobs import get_job
    from ..runtime.d11_types import job_graph_write
    from ..runtime.budget import get_budget_lease, require_budget_family_admissible
    if not db.in_transaction or type(binding) is not D04NumericBindingV3:
        raise ValueError("D04 numeric proof requires a pinned shared Graph transaction")
    prepared = read_d04_numeric_prepared_v3(db, binding.namespace, binding.operation_id)
    if prepared is None or prepared.binding != binding:
        raise ValueError("D04 numeric immutable prepared binding differs")
    frozen = json.loads(prepared.input_payload_json)
    if canonical_digest(frozen) != binding.input_digest:
        raise ValueError("D04 frozen numeric input original changed")
    # All graph read rows are captured in one actual preparation, including
    # source/access/correction ancestor negatives and complete numeric scan.
    rows = frozen.get("read_rows")
    if type(rows) is not list or not rows:
        raise ValueError("D04 frozen numeric source/role/current read closure missing")
    typed_rows = tuple(D04GraphReadV3(**row) for row in rows)
    if len({r.ref for r in typed_rows}) != len(typed_rows):
        raise ValueError("D04 numeric duplicate dependency read")
    require_current_read_rows_v3(db, typed_rows, binding.namespace)
    job = get_job(db, binding.job_id)
    if (job.operation_id != binding.operation_id or job.activity_id != binding.activity_id
            or (job.bot_id, job.persona_id) != binding.namespace.as_tuple
            or job.work_kind != "d04.joint_numeric_cpu.v3" or job.phase != "running"
            or job.cancel_epoch or job.fence < 1 or job.lease_holder is None
            or job.effect_id is not None or job.lease_expires_utc is None
            or now_utc >= min(datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp(),
                              datetime.fromisoformat(job.lease_expires_utc.replace("Z", "+00:00")).timestamp(),
                              datetime.fromisoformat(binding.deadline_utc.replace("Z", "+00:00")).timestamp())):
        raise ValueError("D04 numeric current worker no longer executable")
    worker = frozen.get("worker_original")
    expected_worker = {"holder":job.lease_holder,"fence":job.fence,"cancel_epoch":job.cancel_epoch,
                       "lease_expires_utc":job.lease_expires_utc,"deadline_utc":job.deadline_utc}
    if worker != expected_worker:
        raise ValueError("D04 frozen worker birth/fence/cancel/deadline changed")
    graph_job = job_graph_write(job)
    atom = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (graph_job.key.token,)).fetchone()
    if atom is None or atom[1] != 1 or json.loads(atom[0]) != graph_job.value:
        raise ValueError("D04 numeric worker projection differs")
    original_job = json.loads(prepared.job_payload_json)
    if (original_job["job_id"] != job.job_id or original_job["work_kind"] != job.work_kind
            or original_job["continuation"] != dict(job.continuation)
            or original_job["operator_versions"] != dict(job.operator_versions)):
        raise ValueError("D04 numeric immutable job plan changed")
    quote = resource_issuer.original_signed_quote(db, binding.quote_id, binding.quote_version)
    if (canonical_digest(quote) != binding.quote_digest or quote.work_kind != job.work_kind
            or quote.operation_id != binding.operation_id
            or quote.activity_id != binding.activity_id
            or quote.parent_budget_lease_ref != binding.parent_budget_lease_ref
            or dict(quote.ceiling) != {"cpu_ms": binding.cpu_ceiling_ms}
            or quote.graph_job_ref != graph_job.key.token or now_utc >= quote.valid_until_utc):
        raise ValueError("D04 numeric signed current quote differs")
    numeric_grant=budget_issuer.current_budget_grant(db,binding.parent_budget_lease_ref)
    if ((numeric_grant.bot_id,numeric_grant.persona_id)!=binding.namespace.as_tuple
            or numeric_grant.lease_id!=binding.parent_budget_lease_ref or quote.work_kind not in numeric_grant.allowed_work_kinds
            or numeric_grant.max_ceiling.get("cpu_ms",0)<binding.cpu_ceiling_ms or numeric_grant.valid_until_utc<=now_utc):
        raise ValueError("numeric current signed CPU grant differs")
    lease = get_budget_lease(db, binding.parent_budget_lease_ref)
    require_budget_family_admissible(db, lease.lease_id)
    if (lease.bot_id, lease.persona_id) != binding.namespace.as_tuple or lease.state != "active":
        raise ValueError("D04 numeric current parent budget unavailable")
    reserve = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (lease.lease_id, binding.reservation_operation_id)).fetchone()
    receipt = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
        "AND operation_id=? AND phase='reserve'", (*binding.namespace.as_tuple, binding.reservation_operation_id)).fetchone()
    if (reserve is None or reserve[0] != binding.reservation_digest or reserve[2] != "reserved"
            or json.loads(reserve[1]) != {"cpu_ms": binding.cpu_ceiling_ms}
            or receipt != (prepared.reserve_receipt_json,)):
        raise ValueError("D04 numeric original reserve receipt differs")
    metadata = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
        binding.namespace.as_tuple).fetchone()
    if metadata is None:
        raise ValueError("D04 numeric current Authority anchor missing")
    anchor = json.loads(metadata[0])
    if (anchor.get("authority_id") != binding.authority_id
            or anchor.get("authority_namespace") != binding.authority_namespace
            or anchor.get("activation_generation") != binding.activation_generation):
        raise ValueError("D04 numeric current Authority installation/generation differs")
    installed = frozen.get("installed_identity")
    if type(installed) is not dict or any(installed.get(k) != getattr(binding, k) for k in (
            "installation_id", "owner_grant_ref", "owner_grant_revision", "owner_grant_digest",
            "algorithm_id", "algorithm_build_digest", "native_manifest_sha256", "native_sha256",
            "output_policy_digest")):
        raise ValueError("D04 numeric frozen installed identity/Owner/native differs")
    selectors,projection=read_numeric_policy_owner_selectors_v3(db,binding,budget_issuer,frozen,now_utc=now_utc)
    return D04NumericPreparedReadV3(binding, prepared.original_ref, prepared.digest,
        job.phase, job.fence, job.lease_holder, binding.reservation_operation_id,
        binding.reservation_digest, binding.quote_digest, canonical_serialize(anchor), prepared.input_payload_json,
        selectors,projection)
