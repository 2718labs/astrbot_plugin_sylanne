"""Independent current reads for the actual reserved Owner-authored root CPU."""
from dataclasses import dataclass,asdict
from datetime import datetime
import json

from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from .d04_root_execution_contract_v3 import D04RootExecutionBindingV3
from .v2_owner_session import OwnerSessionLoginRequestV1,from_wire as session_from_wire


@dataclass(frozen=True,slots=True)
class D04RootPreparedReadV3:
    prepared: object
    input_payload: dict
    owner_request: OwnerSessionLoginRequestV1
    owner_actor: str
    authority_anchor_json: str
    graph_revision: int
    projection_digest: str


def read_root_original_basis_v3(db,binding):
    from ..runtime.d04_root_execution_v3 import read_root_prepared_v3
    if not db.in_transaction or type(binding) is not D04RootExecutionBindingV3:
        raise ValueError("root original requires exact namespace and actual Graph read transaction")
    prepared=read_root_prepared_v3(db,binding.namespace,binding.operation_id)
    if prepared is None or prepared.binding!=binding:raise ValueError("actual root preparation absent/changed")
    raw=json.loads(prepared.input_payload_json)
    if (raw.get("schema")!="d04.authored-root-input.v3" or raw.get("namespace")!=asdict(binding.namespace)
            or raw.get("operation_id")!=binding.operation_id or canonical_digest(raw)!=binding.input_digest):
        raise ValueError("root prepared payload identity differs")
    request=session_from_wire({"kind":"owner_session_login_request_v1",**json.loads(raw["owner_session_request_json"])})
    if (type(request) is not OwnerSessionLoginRequestV1 or request.authority_id!=binding.authority_id
            or request.authority_namespace!=binding.authority_namespace or request.installation_id!=binding.installation_id
            or request.audience!="owner" or request.credential_id!=raw["owner_session_id"]):
        raise ValueError("root original accepting Owner public selector differs")
    actor=raw["owner"]["actor"]
    if type(actor) is not str or not actor:raise ValueError("root original accepting Owner actor absent")
    metadata=db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",binding.namespace.as_tuple).fetchone()
    if metadata is None:raise ValueError("root installed Graph location absent")
    return D04RootPreparedReadV3(prepared,raw,request,actor,metadata[0],metadata[1],
        canonical_digest((prepared.digest,metadata,raw["owner"],raw["owner_session_request_json"])))


def require_root_read_rows_v3(db,read):
    from ..graph_types import AtomKey
    rows=read.input_payload["read_rows"]
    if type(rows) is not list or not rows or len(rows)>1024 or len({row[0] for row in rows})!=len(rows):
        raise ValueError("root exact current read closure absent/duplicate")
    for item in rows:
        if type(item) is not list or len(item)!=4:raise ValueError("root current read row shape differs")
        ref,revision,value,valid=item;key=AtomKey.from_token(ref)
        if (key.owner.bot,key.owner.persona)!=read.prepared.binding.namespace.as_tuple or type(revision) is not int or revision<0 or valid not in (0,1):
            raise ValueError("root current read row namespace/version differs")
        actual=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",(ref,)).fetchone()
        if revision==0:
            if valid!=0 or value!="{}" or actual is not None:raise ValueError("root absent member already exists")
        elif actual!=(revision,value,valid):raise ValueError("root original draft/head/role/Owner changed")


def read_current_d04_root_prepared_v3(db,binding,*,resource_issuer,budget_issuer,now_utc):
    from ..domains.d04.authored_lineage_v3 import decode_authored_root_candidate_v3
    from ..runtime.budget import get_budget_lease,require_budget_family_admissible
    from ..runtime.d11_d04_root_freeze_v3 import ROOT_WORK_KIND_V3
    from ..graph_types import owner_grant_key
    read=read_root_original_basis_v3(db,binding);prepared,raw=read.prepared,read.input_payload
    require_root_read_rows_v3(db,read)
    if (json.loads(read.authority_anchor_json)!=raw["requirements"] or read.graph_revision!=raw["graph_revision"]
            or raw["requirements"]["authority_id"]!=binding.authority_id
            or raw["requirements"]["authority_namespace"]!=binding.authority_namespace
            or raw["requirements"]["activation_generation"]!=binding.activation_generation):
        raise ValueError("root prepared Graph snapshot changed")
    candidate=decode_authored_root_candidate_v3(raw["candidate"])
    if candidate.digest!=binding.candidate_digest or candidate.preset.preset_id!=binding.preset_id or candidate.preset.digest!=binding.preset_digest:
        raise ValueError("root actual candidate/preset differs")
    quote=resource_issuer.original_signed_quote(db,binding.quote_id,binding.quote_version)
    if (canonical_digest(quote)!=binding.quote_digest or canonical_serialize(quote)!=prepared.quote_payload_json
            or (quote.bot_id,quote.persona_id)!=binding.namespace.as_tuple or quote.work_kind!=ROOT_WORK_KIND_V3
            or quote.operation_id!=binding.operation_id or quote.parent_budget_lease_ref!=binding.parent_budget_lease_ref
            or quote.graph_job_ref is not None or quote.effect_id is not None
            or dict(quote.ceiling)!={"thread_cpu_ms":binding.cpu_ceiling_ms} or quote.valid_until_utc<=now_utc):
        raise ValueError("root actual signed CPU quote differs")
    grant=budget_issuer.current_budget_grant(db,binding.parent_budget_lease_ref)
    signed,signature=budget_issuer.signed_budget_grant_at_version(db,grant.lease_id,grant.version)
    grant_row=db.execute("SELECT grant_json,signature FROM runtime_budget_grants WHERE lease_id=? AND version=?",(grant.lease_id,grant.version)).fetchone()
    if (grant!=signed or grant_row!=(prepared.signed_grant_payload_json,prepared.signed_grant_signature)
            or signature!=prepared.signed_grant_signature or grant.allowed_work_kinds!=(ROOT_WORK_KIND_V3,)
            or dict(grant.max_ceiling)!={"thread_cpu_ms":binding.cpu_ceiling_ms}
            or (grant.bot_id,grant.persona_id)!=binding.namespace.as_tuple or grant.valid_until_utc<=now_utc):
        raise ValueError("root actual signed dedicated budget grant changed")
    lease=get_budget_lease(db,binding.parent_budget_lease_ref)
    require_budget_family_admissible(db,lease.lease_id)
    reserve=db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (lease.lease_id,binding.reservation_operation_id)).fetchone()
    original=db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*binding.namespace.as_tuple,binding.reservation_operation_id)).fetchone()
    if (lease.state!="active" or (lease.bot_id,lease.persona_id)!=binding.namespace.as_tuple or reserve is None
            or reserve[0]!=binding.reservation_digest or json.loads(reserve[1])!={"thread_cpu_ms":binding.cpu_ceiling_ms}
            or reserve[2:]!=("reserved",None) or original!=(prepared.reserve_receipt_json,)
            or now_utc>=datetime.fromisoformat(binding.deadline_utc.replace("Z","+00:00")).timestamp()):
        raise ValueError("root actual current reservation/deadline differs")
    owner=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",(owner_grant_key(*binding.namespace.as_tuple).token,)).fetchone()
    if (owner is None or owner[0]!=binding.owner_grant_revision or owner[2]!=1
            or canonical_digest(json.loads(owner[1]))!=binding.owner_grant_digest
            or "workbench.activate" not in json.loads(owner[1])["capabilities"]):
        raise ValueError("root actual current Owner activation capability differs")
    return read
