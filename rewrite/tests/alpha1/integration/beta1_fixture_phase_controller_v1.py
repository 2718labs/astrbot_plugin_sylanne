"""Two-stage Beta1 fixture locators; these originals convey no executable grant."""
from dataclasses import asdict
from contextlib import contextmanager
from contextvars import ContextVar
from hashlib import sha256
from pathlib import Path
import json
import os

CONTINUATION_SCHEMA = "sylanne.test.beta1.fixture-continuation.v1"
_SCENARIOS = frozenset({"numeric-positive", "numeric-registration", "numeric-mutation-prepare",
    "numeric-mutation-acquire", "numeric-authorization-installation", "numeric-authorization-lease",
    "numeric-authorization-reservation", "numeric-authorization-configuration",
    "numeric-authorization-worker", "numeric-authorization-time", "d13-positive",
    "d13-expired", "d13-admission", "d13-derived", "d13-derived-expiry"})
_CONTINUATION_FIELDS = frozenset({"schema", "scenario", "setup_file", "setup_sha256",
    "package_root", "manifest_digest", "namespace", "authority_namespace", "installation_id",
    "initial_cold_fixture", "c09_operation_id", "original_deadline_utc", "root_grant",
    "root_original", "owner_issue_operation_id", "owner_issue_receipt_digest", "principal",
    "owner_session", "owner_console_session", "owner_key_original", "original_clock", "originals", "scenario_selectors",
    "scenario_source_ref", "migration_source_ref", "migration_c02_operation_id", "migration_source_execution_id",
    "initial_process", "context_original", "scenario_c02_operation_id", "key_id", "continuation_digest", "signature"})


async def produce_current_beta1_migration_source_v1(case, *, scenario, original_deadline_utc):
    """One real C02 admission, independently identified from the scenario Source."""
    from sylanne3.runtime.first_ingress_v2 import trusted_upper
    if scenario not in _SCENARIOS:
        raise ValueError("closed Beta1 scenario required")
    bundle=case["installed_bundle"]
    now=trusted_upper(case["port"].read_ingress_clock(bundle.ingress_clock))
    if (original_deadline_utc>case["policy"].root_grant.valid_until_utc
            or now>=original_deadline_utc):
        raise ValueError("Beta1 original fixture grant/deadline cannot admit migration Source")
    # The existing issuer reserves and settles actual C02/model/CPU cost against
    # this same Root. No availability flag, alternate grant or allowance is made.
    first,c02,envelope,execution_id=await case["commit_second_c02"](
        "beta1-migration-source:"+scenario,
        "This separate fixture message is the explicitly selected maintenance Source.",
        return_envelope=True,return_execution_id=True)
    import asyncio
    current=await asyncio.to_thread(case["graph"].read_post_c02_attention_inputs_v1,
        case["bootstrap"],case["namespace"],c02.operation_id,None,bundle)
    if current[0].operation_id!=c02.operation_id or len(current[2].source_refs)!=1:
        raise ValueError("migration Source lost its actual C02 qualification")
    source=current[2].source_refs[0]
    if source==case["source_ref"]:
        raise ValueError("migration must not delete the scenario Source")
    return {"source_ref":source,"c02_operation_id":c02.operation_id,
        "first_ingress_operation_id":first.operation_id,"source_execution_id":execution_id}


def persist_current_beta1_fixture_continuation_v1(case, *, setup_file, setup_sha256,
        scenario, migration, c09_operation_id, originals, context_original, original_deadline_utc):
    """Save only the actual initial lineage and protected session locators.

    The original configuration and scopes are never rewritten. A later loader
    authenticates these selectors, then obtains fresh current product proofs.
    """
    from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1
    from sylanne3.authority_service.c09_storage_control_v1 import canonical
    from sylanne3.runtime.first_ingress_v2 import trusted_upper
    from sylanne3.runtime_contracts import canonical_digest
    from sylanne3.runtime.domain_production_contracts_v1 import ProductionOriginalRefV1
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from c09_life_provider_cache_acceptance_v1 import _write_new
    if scenario not in _SCENARIOS or type(originals) is not tuple or not originals:
        raise ValueError("closed nonempty Beta1 continuation originals required")
    if any(type(ref) is not ProductionOriginalRefV1 for ref in originals):
        raise TypeError("actual typed production original locators required")
    setup=Path(setup_file).resolve(strict=True)
    if sha256(setup.read_bytes()).hexdigest()!=setup_sha256:
        raise ValueError("initial protected setup differs from its original pin")
    daemon=case["c09_daemon"];control=daemon.c09_control
    if daemon.server is not case["server"] or daemon.core is not case["core"]:
        raise ValueError("actual fixture Authority composition required")
    control.lease.require_held()
    clock=case["port"].read_ingress_clock(case["installed_bundle"].ingress_clock)
    root=case["policy"].root_grant
    if (original_deadline_utc>root.valid_until_utc or trusted_upper(clock)>=original_deadline_utc
            or migration["source_ref"]==case["source_ref"]):
        raise ValueError("Beta1 continuation cannot renew Root or deleted Source")
    authored_root=(dict(operation_id=case["root_operation_id"],
        digest=case["root_original"].original_digest) if scenario.startswith("numeric-") else None)
    body=dict(schema=CONTINUATION_SCHEMA,scenario=scenario,setup_file=str(setup),setup_sha256=setup_sha256,
        package_root=str(case["package_root"]),manifest_digest=case["manifest_digest"],
        namespace=list(case["namespace"].as_tuple),authority_namespace=case["authority_namespace"],
        installation_id=case["policy"].installation_id,initial_cold_fixture=case["c09_cold_fixture"],
        c09_operation_id=c09_operation_id,original_deadline_utc=original_deadline_utc,
        root_grant=dict(grant_id=root.grant_id,version=root.version,lease_id=root.lease_id,
            digest=canonical_digest(plain_v1(root))),
        root_original=authored_root,
        owner_issue_operation_id=case["owner_issue_operation"].operation_id,
        owner_issue_receipt_digest=canonical_digest(case["owner_issue_committed"]),
        principal=asdict(case["principal"]),
        owner_key_original=persist_current_beta1_owner_key_v1(case),
        owner_session=dict(token=case["owner_session_token"],request=plain_v1(case["owner_session_request"])),
        owner_console_session=dict(token=case["owner_console_session_token"],
            request=plain_v1(case["owner_console_session_request"])),
        original_clock=dict(source_id=clock.sample.source_id,epoch=clock.sample.epoch),
        originals=[plain_v1(ref) for ref in originals],context_original=dict(context_original),
        scenario_selectors=current_beta1_scenario_selectors_v3(case,scenario),
        scenario_c02_operation_id=case["c02"].operation_id,scenario_source_ref=case["source_ref"],
        migration_source_ref=migration["source_ref"],migration_c02_operation_id=migration["c02_operation_id"],
        migration_source_execution_id=migration["source_execution_id"],
        initial_process=read_process_identity_v1(os.getpid()))
    signed=control.sign_original_v1(CONTINUATION_SCHEMA,body,"continuation_digest")
    if set(signed)!=_CONTINUATION_FIELDS:
        raise ValueError("Beta1 continuation exact fields differ")
    target=control.key_path.parent/("beta1-continuation-"+scenario+".json")
    _write_new(target,canonical(signed).encode("utf8"))
    return {"path":str(target),"sha256":sha256(target.read_bytes()).hexdigest(),
        "continuation_digest":signed["continuation_digest"],"original_deadline_utc":original_deadline_utc}


CONTEXT_SCHEMA = "sylanne.test.beta1.fixture-context.v1"
_CONTEXT_FIELDS = frozenset({"schema","scenario","setup_sha256","namespace",
    "installation_id","c02_operation_id","scenario_source_ref","envelope",
    "key_id","context_digest","signature"})


def persist_current_beta1_fixture_context_v1(case, *, setup_sha256, scenario):
    """Seal the initial observed text envelope, never the migration Source."""
    from sylanne3.host.ingress import HostIngressEnvelope
    from sylanne3.authority_service.c09_storage_control_v1 import canonical
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from c09_life_provider_cache_acceptance_v1 import _write_new
    envelope=case["ingress"];control=case["c09_daemon"].c09_control
    if (scenario not in _SCENARIOS or type(envelope) is not HostIngressEnvelope
            or envelope.namespace!=case["namespace"] or envelope.attachments):
        raise ValueError("actual text-only initial Beta1 ingress required")
    control.lease.require_held()
    body=dict(schema=CONTEXT_SCHEMA,scenario=scenario,setup_sha256=setup_sha256,
        namespace=list(case["namespace"].as_tuple),installation_id=case["policy"].installation_id,
        c02_operation_id=case["c02"].operation_id,scenario_source_ref=case["source_ref"],
        envelope=plain_v1(envelope))
    signed=control.sign_original_v1(CONTEXT_SCHEMA,body,"context_digest")
    if set(signed)!=_CONTEXT_FIELDS:raise ValueError("Beta1 context field coverage differs")
    target=control.key_path.parent/("beta1-context-"+scenario+".json")
    _write_new(target,canonical(signed).encode("utf8"))
    return dict(path=str(target),sha256=sha256(target.read_bytes()).hexdigest(),
        context_digest=signed["context_digest"])


def read_beta1_fixture_context_original_v1(control, *, continuation, setup_sha256, scenario):
    """Restore exactly the original observation after same-Control verification."""
    from sylanne3.host.ingress import HostIngressEnvelope,SourceLineage
    from sylanne3.runtime_contracts import NamespaceId
    control.lease.require_held()
    control.verify_original_v1(continuation,"continuation_digest")
    locator=continuation["context_original"]
    if type(locator) is not dict or set(locator)!={"path","sha256","context_digest"}:
        raise ValueError("exact protected context locator required")
    path=Path(locator["path"]).resolve(strict=True)
    if path.parent!=control.key_path.parent.resolve(strict=True):
        raise ValueError("context is outside its original protected Control directory")
    data=path.read_bytes()
    if sha256(data).hexdigest()!=locator["sha256"]:raise ValueError("context bytes changed")
    raw=json.loads(data);control.verify_original_v1(raw,"context_digest")
    if (set(raw)!=_CONTEXT_FIELDS or raw["schema"]!=CONTEXT_SCHEMA
            or raw["context_digest"]!=locator["context_digest"]
            or raw["scenario"]!=scenario or continuation["scenario"]!=scenario
            or raw["setup_sha256"]!=setup_sha256 or continuation["setup_sha256"]!=setup_sha256
            or raw["namespace"]!=continuation["namespace"]
            or raw["installation_id"]!=continuation["installation_id"]
            or raw["scenario_source_ref"]!=continuation["scenario_source_ref"]
            or raw["c02_operation_id"]!=continuation["scenario_c02_operation_id"]):
        raise ValueError("context is not the original same-cohort Beta1 observation")
    value=raw["envelope"]
    if (type(value) is not dict or set(value)!=set(HostIngressEnvelope.__dataclass_fields__)
            or type(value["lineage"]) is not dict
            or set(value["lineage"])!=set(SourceLineage.__dataclass_fields__)
            or value["attachments"]!=[]):
        raise ValueError("exact text-only Host ingress encoding required")
    ns=value["namespace"]
    if type(ns) is not dict or set(ns)!=set(NamespaceId.__dataclass_fields__):
        raise ValueError("exact initial ingress namespace required")
    envelope=HostIngressEnvelope(NamespaceId(**ns),value["platform_ref"],value["conversation_ref"],
        value["sender_ref"],value["message_id"],value["text"],value["occurred_at"],
        value["learned_at"],value["visibility"],SourceLineage(**value["lineage"]),())
    if list(envelope.namespace.as_tuple)!=continuation["namespace"]:
        raise ValueError("initial ingress namespace differs")
    return envelope


def read_beta1_fixture_session_original_v1(control, *, continuation, namespace, installation_id):
    """Decode old protected sessions; current Core must still authorize them."""
    from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
    from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1,_verifier
    control.lease.require_held();control.verify_original_v1(continuation,"continuation_digest")
    if (set(continuation)!=_CONTINUATION_FIELDS or continuation["schema"]!=CONTINUATION_SCHEMA
            or continuation["namespace"]!=list(namespace.as_tuple)
            or continuation["installation_id"]!=installation_id):
        raise ValueError("same original Beta1 Owner session cohort required")
    principal_raw=continuation["principal"]
    if type(principal_raw) is not dict or set(principal_raw)!=set(OwnerPrincipalV1.__dataclass_fields__):
        raise ValueError("exact original Owner principal required")
    principal=OwnerPrincipalV1(**principal_raw);sessions=[]
    for field,audience in (("owner_session","owner"),("owner_console_session","sylanne-owner-console")):
        saved=continuation[field]
        if type(saved) is not dict or set(saved)!={"token","request"}:
            raise ValueError("exact protected original Owner session required")
        raw=saved["request"]
        if type(raw) is not dict or set(raw)!=set(OwnerSessionLoginRequestV1.__dataclass_fields__):
            raise ValueError("exact original Owner session request required")
        actual=dict(raw);actual["principal"]=OwnerPrincipalV1(**raw["principal"])
        request=OwnerSessionLoginRequestV1(**actual);_verifier(saved["token"])
        if (request.principal!=principal or request.installation_id!=installation_id
                or request.authority_namespace!=continuation["authority_namespace"]
                or request.audience!=audience):
            raise ValueError("original Owner session identity changed")
        sessions.append((saved["token"],request))
    return principal,sessions[0][0],sessions[0][1],sessions[1][0],sessions[1][1]


_OWNER_KEY_FIELDS = frozenset({"path","sha256","public_key_sha256","credential_id",
    "credential_epoch","principal"})


def persist_current_beta1_owner_key_v1(case):
    """Save the initial paired signer once in this existing protected Control directory."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
    from c09_life_provider_cache_acceptance_v1 import _write_new
    daemon=case["c09_daemon"];control=daemon.c09_control;control.lease.require_held()
    key=case["owner_key"];request=case["owner_session_request"]
    directory=control.key_path.parent.resolve(strict=True);info=directory.stat()
    if (not isinstance(key,Ed25519PrivateKey) or request.principal!=case["principal"]
            or info.st_uid!=os.getuid() or info.st_mode&0o022):
        raise ValueError("initial paired Owner signer and owned protected Control directory required")
    target=directory/"beta1-owner-signing-key.pkcs8.pem"
    material=key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
    _write_new(target,material)
    public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    return dict(path=str(target),sha256=sha256(material).hexdigest(),
        public_key_sha256=sha256(public).hexdigest(),credential_id=request.credential_id,
        credential_epoch=request.credential_epoch,principal=asdict(request.principal))


def _read_original_beta1_owner_key_v1(control,continuation,principal,request):
    import stat
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key,Encoding,PublicFormat
    control.lease.require_held();control.verify_original_v1(continuation,"continuation_digest")
    locator=continuation["owner_key_original"]
    if (type(locator) is not dict or set(locator)!=_OWNER_KEY_FIELDS
            or locator["principal"]!=asdict(principal) or request.principal!=principal
            or locator["credential_id"]!=request.credential_id
            or locator["credential_epoch"]!=request.credential_epoch):
        raise ValueError("exact original paired Owner signing-key locator required")
    directory=control.key_path.parent.resolve(strict=True);target=Path(locator["path"])
    if target!=directory/"beta1-owner-signing-key.pkcs8.pem":
        raise ValueError("Owner signing key left the original protected Control directory")
    fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid()
                or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>8192):
            raise ValueError("original private Owner signing-key file differs")
        with os.fdopen(fd,"rb",closefd=False) as stream:material=stream.read(8193)
    finally:os.close(fd)
    if sha256(material).hexdigest()!=locator["sha256"]:
        raise ValueError("original Owner signing-key bytes changed")
    key=load_pem_private_key(material,password=None)
    if (not isinstance(key,Ed25519PrivateKey) or sha256(key.public_key().public_bytes(
            Encoding.Raw,PublicFormat.Raw)).hexdigest()!=locator["public_key_sha256"]):
        raise ValueError("original Owner credential public key changed")
    return key


async def login_current_beta1_owner_after_cold_v3(case, *, continuation):
    """New Core challenge, original signer and absolute session cap; no re-pairing."""
    import asyncio
    import math
    from datetime import datetime,timezone
    from sylanne3.runtime.first_ingress_v2 import trusted_upper
    from sylanne3.runtime_contracts import canonical_digest
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.authority_service.contract import AuthorityUnavailable
    control=case["c09_daemon"].c09_control;control.lease.require_held()
    principal,old_owner,owner_request,old_console,console_request=read_beta1_fixture_session_original_v1(
        control,continuation=continuation,namespace=case["namespace"],
        installation_id=case["policy"].installation_id)
    root=case["policy"].root_grant;bundle=case["installed_bundle"]
    if continuation["root_grant"]!=dict(grant_id=root.grant_id,version=root.version,
            lease_id=root.lease_id,digest=canonical_digest(plain_v1(root))):
        raise ValueError("cold Owner login changed the initial Root grant or budget")
    deadline=continuation["original_deadline_utc"]
    now=trusted_upper(case["port"].read_ingress_clock(bundle.ingress_clock))
    if not math.isfinite(deadline) or now>=math.floor(deadline) or deadline>root.valid_until_utc:
        raise ValueError("cold Owner login cannot renew the absolute initial fixture deadline")
    cap=datetime.fromtimestamp(math.floor(deadline),timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
    key=_read_original_beta1_owner_key_v1(control,continuation,principal,owner_request)
    tokens=[]
    for archived,request in ((old_owner,owner_request),(old_console,console_request)):
        if case["owner_sessions"] is not case["c09_daemon"].server._v2_owner_sessions:
            raise ValueError("cold login lost its actual current Core session store")
        try:
            await asyncio.to_thread(case["owner_sessions"].require_current,
                transport_credential=case["peer"],request=request,token=archived)
        except AuthorityUnavailable:
            pass
        else:
            raise ValueError("archived Owner session survived actual cold Core rotation")
        challenge=await asyncio.to_thread(case["port"].begin_owner_session,
            namespace=case["namespace"],authority_namespace=case["authority_namespace"],request=request)
        if challenge.request!=request:
            raise ValueError("cold login challenge changed the original paired Owner identity")
        token=await asyncio.to_thread(case["port"].accept_owner_session,namespace=case["namespace"],
            authority_namespace=case["authority_namespace"],challenge=challenge,
            signature=key.sign(challenge.signed_bytes()),session_expires_no_later_than_utc=cap)
        if not await asyncio.to_thread(case["port"].current_owner_session,namespace=case["namespace"],
                authority_namespace=case["authority_namespace"],request=request,token=token):
            raise ValueError("new capped cold Owner session is not current")
        tokens.append(token)
    case.update(principal=principal,owner_session_token=tokens[0],owner_session_request=owner_request,
        owner_console_session_token=tokens[1],owner_console_session_request=console_request,
        beta1_fresh_original_key_login=True)
    return principal


async def accept_current_beta1_migration_v3(case, *, setup_file,setup_sha256,scenario,originals,
        original_deadline_utc):
    """Real second maintenance Source, actual C09 acceptance, then signed selectors."""
    import asyncio
    from test_c09_installed_life_archive_v1 import _accept_actual_current_barrier_v3
    migration=await produce_current_beta1_migration_source_v1(case,scenario=scenario,
        original_deadline_utc=original_deadline_utc)
    context=persist_current_beta1_fixture_context_v1(case,setup_sha256=setup_sha256,scenario=scenario)
    selected=dict(case,source_ref=migration["source_ref"],
        content_source_execution_id=migration["source_execution_id"],
        life_audience=case["ingress"].conversation_ref)
    accepted=await asyncio.to_thread(_accept_actual_current_barrier_v3,selected)
    continuation=persist_current_beta1_fixture_continuation_v1(case,setup_file=setup_file,
        setup_sha256=setup_sha256,scenario=scenario,migration=migration,
        c09_operation_id=accepted["operation_id"],originals=originals,context_original=context,
        original_deadline_utc=original_deadline_utc)
    return dict(phase="business_current_v3",scenario=scenario,pid=os.getpid(),
        operation_id=accepted["operation_id"],cold_fixture=accepted["cold_fixture"],
        source_execution_id=accepted["source_execution_id"],
        source_execution_commitment=accepted["source_execution_commitment"],
        continuation=continuation,scenario_source_ref=case["source_ref"],
        migration_source_ref=migration["source_ref"],migration_c02_operation_id=migration["c02_operation_id"])


async def run_current_beta1_storage_phase_v3(*,phase,scenario,setup_file,setup_sha256,
        continuation_file,continuation_sha256):
    """Use the existing actual C09 actor/retirement/cold EOF implementation."""
    from beta1_resumed_case_support_v1 import read_current_beta1_resume_configuration_v3
    from c09_life_authority_phase_support_v1 import run_life_current_cold_phase_v3
    if phase not in {"prepare_switch_current_v3","release_current_v3","cold_current_v3"}:
        raise ValueError("closed actual Beta1 C09 storage phase required")
    _,continuation,_,_,_=read_current_beta1_resume_configuration_v3(setup_file=setup_file,
        setup_sha256=setup_sha256,continuation_file=continuation_file,
        continuation_sha256=continuation_sha256,scenario=scenario)
    original=continuation["initial_cold_fixture"]
    result=await run_life_current_cold_phase_v3(original["path"],phase,
        expected_fixture_digest=original["fixture_digest"],operation_id=continuation["c09_operation_id"],
        source_execution_id=continuation["migration_source_execution_id"])
    return dict(result,scenario=scenario,continuation_digest=continuation["continuation_digest"],
        original_deadline_utc=continuation["original_deadline_utc"])


_CURRENT_CASE=ContextVar("beta1_actual_resumed_fixture_case",default=None)
_ISSUED_CASES={}


def register_current_beta1_fixture_case_v3(case):
    from sylanne3.host.authority_profile import require_artifact_phase_fixture_qualification_v1
    from sylanne3.runtime_storage_v3 import runtime_storage_v3
    control=case["c09_daemon"].c09_control
    current=control.read_verified_current_storage_v3();current.require_current("business")
    if (current.stage!="RELEASED" or current.storage_generation<1
            or runtime_storage_v3(case["store"]._db)is None):
        raise ValueError("actual selected cold Beta1 case required")
    require_artifact_phase_fixture_qualification_v1(case["installed_bundle"],client_grant=case["client_grant"])
    _ISSUED_CASES[id(case)]=case


def unregister_current_beta1_fixture_case_v3(case):
    if _ISSUED_CASES.pop(id(case))is not case:raise ValueError("actual Beta1 case registration differs")


@contextmanager
def current_beta1_fixture_case_scope_v3(case):
    if _ISSUED_CASES.get(id(case))is not case:raise ValueError("actual cold Beta1 constructor required")
    token=_CURRENT_CASE.set(case)
    try:yield case
    finally:_CURRENT_CASE.reset(token)


def current_beta1_fixture_case_v3(installed_root):
    from sylanne3.host.installed_package import verify_installed_backend_runtime_v1
    case=_CURRENT_CASE.get()
    if case is not None:
        if (_ISSUED_CASES.get(id(case))is not case or case["package_root"]!=Path(installed_root)):
            raise ValueError("current Beta1 fixture left its actual constructor/package")
        return case
    root=Path(installed_root);pin=sha256((root/"release-manifest.json").read_bytes()).hexdigest()
    checked=verify_installed_backend_runtime_v1(root,pin)
    if (checked.package_version,checked.build_mode,checked.runtime_scope)==(
            "3.0.0-beta1","beta1-candidate","backend-beta1-server-test"):
        raise ValueError("Beta1 requires its full current protected phase suite; legacy fixture fallback HOLD")
    return None


def current_beta1_scenario_selectors_v3(case,scenario):
    if scenario.startswith("numeric-"):
        from sylanne3.runtime_contracts import canonical_digest
        from sylanne3.domains.d01.production_operations_v1 import plain_v1
        before=case["numeric_before"];prepared=case["numeric_life_prepared"];occurrence=case["numeric_occurrence"]
        return dict(episode_ref=case["episode_ref"],life_activity_id=case["life_activity_id"],
            life_causal_operation_id=case["life_causal_operation_id"],life_audience=case["life_audience"],
            before_digest=before.digest,before_original_ref=before.original_ref,
            before_checkpoint_refs=sorted(m.checkpoint.ref for m in before.members),
            negative_donor=case.get("beta1_negative_donor"),
            prepared_original_ref=prepared.binding.prepared_original_ref,prepared_operation_id=prepared.prepare_operation_id,
            occurrence_digest=canonical_digest(plain_v1(occurrence)),
            occurrence_completed_at=occurrence.event.activity.completed_at,
            execution_id=occurrence.event.activity.execution_id,experience_source_ref=occurrence.event.activity.source_ref)
    return dict(conversation_ref=case["ingress"].conversation_ref,confirmed_turn_count=6)


async def read_current_beta1_fixture_metadata_v3(case,*,versions,event_scopes,producing_operation_ids):
    """The actual worker owns the Owner lease until the fixed metadata Work is terminal."""
    from contextlib import ExitStack
    from sylanne3.graph_worker import OwnedGraphStorageResultV3
    from beta1_fixture_evidence_read_v3 import (Beta1FixtureEvidenceRequestV3,
        prepare_current_beta1_fixture_evidence_read_v3)
    worker=await case["get_http_worker"]()
    def prepare(graph):
        lifetime=ExitStack()
        try:
            authority,lease,_=graph.grant_current_owner(case["bootstrap"],actor="owner-actor-reply",
                namespace=case["namespace"],domains=("d11",),purpose="context",
                audience=case["ingress"].conversation_ref,activation_generation=1,
                owner_session_token=case["owner_session_token"],owner_session_request=case["owner_session_request"])
            lifetime.callback(graph.release_current_owner_lease,case["bootstrap"],lease)
            request=Beta1FixtureEvidenceRequestV3(versions,producing_operation_ids,event_scopes,
                case["beta1_original_deadline_utc"])
            work=prepare_current_beta1_fixture_evidence_read_v3(graph,authority,lease,case["installed_bundle"],request)
            def complete(reader):return tuple(reader.rows)
            def failed(error):raise error
            work.map_terminal_v3("issuer",complete,failed);work.adopt_request_lifetime_v3(lifetime)
            return work
        except BaseException:
            lifetime.close();raise
    owned=await worker.call(prepare)
    if type(owned)is not OwnedGraphStorageResultV3:raise TypeError("actual metadata Work retention required")
    rows,retention=owned.take_value_v3()
    try:return rows
    finally:retention.release()


async def call_current_beta1_numeric_v3(case,method,*,retain_result=False,**parameters):
    from contextlib import ExitStack
    from d04_numeric_life_acceptance_support_v1 import numeric_owner
    from sylanne3.graph_worker import GraphStorageWorkV3,OwnedGraphStorageResultV3
    worker=await case["get_http_worker"]()
    def invoke(graph):
        lifetime=ExitStack()
        try:
            authority,lease=lifetime.enter_context(numeric_owner(case))
            result=getattr(graph,method)(authority,lease,**parameters)
            if type(result)is GraphStorageWorkV3:
                result.adopt_request_lifetime_v3(lifetime);return result
            lifetime.close();return result
        except BaseException:
            lifetime.close();raise
    result=await worker.call(invoke)
    if type(result)is OwnedGraphStorageResultV3:
        value,retention=result.take_value_v3()
        if retain_result:return value,retention
        try:return value
        finally:retention.release()
    if retain_result:raise TypeError("actual current Numeric READ result ownership required")
    return result


def numeric_before_digest_v3(case):
    return case["beta1_numeric_selectors"]["before_digest"] if "beta1_numeric_selectors"in case else case["numeric_before"].digest


def numeric_prepare_operation_v3(case):
    return case["beta1_numeric_selectors"]["prepared_operation_id"] if "beta1_numeric_selectors"in case else case["numeric_life_prepared"].prepare_operation_id


def numeric_occurrence_completed_at_v3(case):
    return case["beta1_numeric_selectors"]["occurrence_completed_at"] if "beta1_numeric_selectors"in case else case["numeric_occurrence"].event.activity.completed_at


async def run_current_beta1_numeric_business_phase_v3(*,scenario,setup_file,setup_sha256,fixture_root,installed_root):
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    from test_installed_life_numeric_before_v1 import run_installed_life_before_case
    from sylanne3.runtime.domain_production_contracts_v1 import ProductionOriginalRefV1
    from sylanne3.runtime.d04_life_before_original_v1 import KIND
    setup=Path(setup_file).resolve(strict=True)
    if sha256(setup.read_bytes()).hexdigest()!=setup_sha256:
        raise ValueError("Root-prepared Numeric setup differs from its original pin")
    initial=M1PhaseFixtureInstallationV2.from_protected_setup_v2(setup)
    if (initial.package_root!=Path(installed_root) or initial.c04_component_key is None
            or initial.workflows.life_numeric is None):
        raise ValueError("actual current protected Numeric installation required")
    selected=initial.initial_bundle.life_d04_before_capture_policy
    if selected is None:raise ValueError("Root-prepared before selector required before actual Owner root")
    outcome=None
    async def completed(case):
        nonlocal outcome
        before=case["numeric_before"];prepared=case["numeric_life_prepared"]
        from sylanne3.runtime.d12_installed_services_v1 import install_d12_services_v1
        worker=await case["get_http_worker"]()
        await worker.call(lambda graph:install_d12_services_v1(graph,bootstrap=case["bootstrap"]))
        await prepare_current_beta1_negative_donor_v3(case,scenario=scenario)
        originals=(ProductionOriginalRefV1("d11.life_"+KIND,before.original_ref,before.digest),
            ProductionOriginalRefV1("d11.life_prepared",prepared.binding.prepared_original_ref,prepared.digest))
        outcome=await accept_current_beta1_migration_v3(case,setup_file=setup,
            setup_sha256=setup_sha256,scenario=scenario,originals=originals,
            original_deadline_utc=initial.initial_bundle.installation_policy.root_grant.valid_until_utc)
    joint=scenario=="numeric-positive" or scenario.startswith("numeric-authorization-")
    await run_installed_life_before_case(initial.data_dir,installed_root,after_before_async=completed,
        initial_phase_fixture_installation=initial,complete_c09_current_v3=True,
        c09_protected_root=Path(fixture_root)/"protected",c09_phase_setup_file=setup,
        enable_d04_semantic_drive=joint,enable_d04_joint_numeric=joint)
    if outcome is None:raise ValueError("actual Numeric producer did not reach its terminal before original")
    return outcome


async def run_current_beta1_consumer_phase_v3(*,scenario,node,setup_file,setup_sha256,
        continuation_file,continuation_sha256,fixture_root,installed_root,consumer):
    from beta1_resumed_case_support_v1 import resume_current_beta1_fixture_case_v3
    from sylanne3.runtime_storage_v3 import runtime_storage_v3
    async with resume_current_beta1_fixture_case_v3(setup_file=setup_file,setup_sha256=setup_sha256,
            continuation_file=continuation_file,continuation_sha256=continuation_sha256,scenario=scenario) as case:
        with current_beta1_fixture_case_scope_v3(case):
            await consumer(Path(fixture_root),Path(installed_root))
        current=case["c09_daemon"].c09_control.read_verified_current_storage_v3()
        current.require_current("business")
        continuation=case["beta1_continuation"]
        if runtime_storage_v3(case["store"]._db)is None:
            raise ValueError("permanent consumer left actual selected V3 Graph")
        return dict(phase="consumer_current_v3",pid=os.getpid(),scenario=scenario,node=node,
            setup_sha256=setup_sha256,operation_id=continuation["c09_operation_id"],
            continuation_digest=continuation["continuation_digest"],
            original_deadline_utc=continuation["original_deadline_utc"],
            storage_generation=current.storage_generation,manifest_digest=current.manifest_digest,
            source_kind="current_selected_v3",fresh_original_key_capped_login=case["beta1_fresh_original_key_login"],
            exit_code=0)


def run_current_beta1_node_main_v3(*,module_file,scenario_consumers,business):
    import asyncio,sys
    if len(sys.argv) not in {8,10} or sys.argv[1]!="--beta1-current-phase":
        raise ValueError("closed protected Beta1 permanent node phase invocation required")
    _,_,phase,scenario,setup,pin,root,node,*continuation=sys.argv
    consumer,parameter=scenario_consumers[scenario]
    selection=consumer.__name__+("["+parameter+"]" if parameter is not None else "")
    if (node!="tests/alpha1/integration/"+Path(module_file).name+"::"+selection
            or scenario not in _SCENARIOS):
        raise ValueError("fixed permanent Beta1 node/scenario selection differs")
    installed=Path(os.environ["SYLANNE_C09_INSTALLED_ROOT"]).resolve(strict=True)
    async def invoke():
        if phase=="business_current_v3":
            if continuation:raise ValueError("first business phase cannot resume a consumed setup")
            return await business(scenario=scenario,setup_file=setup,setup_sha256=pin,
                fixture_root=root,installed_root=installed)
        continuation_file,continuation_sha256=continuation
        if phase=="consumer_current_v3":
            async def fixed(tmp,package):
                if parameter is None:await consumer(tmp,package)
                else:await consumer(tmp,package,parameter)
            return await run_current_beta1_consumer_phase_v3(scenario=scenario,node=node,
                setup_file=setup,setup_sha256=pin,continuation_file=continuation_file,
                continuation_sha256=continuation_sha256,fixture_root=root,installed_root=installed,consumer=fixed)
        return await run_current_beta1_storage_phase_v3(phase=phase,scenario=scenario,setup_file=setup,
            setup_sha256=pin,continuation_file=continuation_file,continuation_sha256=continuation_sha256)
    try:outcome=asyncio.run(invoke())
    finally:
        import sitecustomize
        sitecustomize.audit(phase="beta1-"+phase)
    print(json.dumps(outcome,sort_keys=True))


async def run_current_beta1_d13_business_phase_v3(*,scenario,setup_file,setup_sha256,fixture_root,installed_root):
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    from test_installed_d13_paid_v1 import _run_installed_d13_paid_case
    from sylanne3.runtime.domain_production_contracts_v1 import ProductionOriginalRefV1
    from sylanne3.runtime_contracts import canonical_digest
    setup=Path(setup_file).resolve(strict=True)
    if sha256(setup.read_bytes()).hexdigest()!=setup_sha256:
        raise ValueError("Root-prepared D13 setup differs from its original pin")
    initial=M1PhaseFixtureInstallationV2.from_protected_setup_v2(setup)
    if (initial.package_root!=Path(installed_root) or initial.c04_component_key is None
            or initial.initial_bundle.d13_paid_precompression is None):
        raise ValueError("actual current protected D13 installation required")
    outcome=None
    async def confirmed(case,window,receipts):
        nonlocal outcome
        if len(window.turns)!=6 or len(receipts)!=6 or window.missing_ranges:
            raise ValueError("six original actual confirmed turns required before maintenance migration")
        originals=tuple(ProductionOriginalRefV1("d13.confirmed_inbound_turn",receipt.completion_ref,
            canonical_digest(receipt)) for receipt in receipts)
        case["beta1_initial_confirmed_turns"]=receipts
        outcome=await accept_current_beta1_migration_v3(case,setup_file=setup,
            setup_sha256=setup_sha256,scenario=scenario,originals=originals,
            original_deadline_utc=initial.initial_bundle.installation_policy.root_grant.valid_until_utc)
    await _run_installed_d13_paid_case(initial.data_dir,installed_root,
        expired=scenario=="d13-expired",admission_only=scenario=="d13-admission",
        derived_v6=scenario in {"d13-derived","d13-derived-expiry"},
        reclaim_after_expiry=scenario=="d13-derived-expiry",initial_phase_fixture_installation=initial,
        complete_c09_current_v3=True,c09_protected_root=Path(fixture_root)/"protected",
        c09_phase_setup_file=setup,after_window_async=confirmed)
    if outcome is None:raise ValueError("actual D13 producer did not confirm its original six-turn window")
    return outcome


async def _read_current_beta1_job_metadata_v3(case,job_id,request_type,*,audience):
    from contextlib import ExitStack
    from sylanne3.graph_worker import OwnedGraphStorageResultV3
    from beta1_fixture_evidence_read_v3 import (Beta1ExactNumericJobMetadataRequestV3,
        Beta1ExactD13JobMetadataRequestV3,prepare_current_beta1_fixture_evidence_read_v3)
    if _ISSUED_CASES.get(id(case))is not case:
        raise ValueError("actual registered cold Numeric fixture required")
    worker=await case["get_http_worker"]()
    donor=case["beta1_numeric_selectors"]["negative_donor"]if request_type is Beta1ExactNumericJobMetadataRequestV3 else None
    selector=(donor["reservation_operation_id"],donor["quote_id"],donor["quote_version"],donor["operation_digest"],donor["commit_seq"])if donor is not None and donor["kind"]=="internal_life_content"else None
    request=request_type(job_id,case["beta1_original_deadline_utc"],reservation_donor_selector=selector)
    return await _read_current_beta1_metadata_request_v3(case,request,audience=audience)


async def _read_current_beta1_metadata_request_v3(case,request,*,audience):
    from contextlib import ExitStack
    from sylanne3.graph_worker import OwnedGraphStorageResultV3
    from beta1_fixture_evidence_read_v3 import prepare_current_beta1_fixture_evidence_read_v3
    if _ISSUED_CASES.get(id(case))is not case:raise ValueError("actual registered cold Beta1 metadata case required")
    worker=await case["get_http_worker"]()
    def begin(graph):
        lifetime=ExitStack()
        try:
            authority,lease,_=graph.grant_current_owner(case["bootstrap"],actor="owner-actor-reply",
                namespace=case["namespace"],domains=("d11",),purpose="context",audience=audience,
                activation_generation=1,owner_session_token=case["owner_session_token"],
                owner_session_request=case["owner_session_request"])
            lifetime.callback(graph.release_current_owner_lease,case["bootstrap"],lease)
            work=prepare_current_beta1_fixture_evidence_read_v3(graph,authority,lease,case["installed_bundle"],
                request)
            def complete(reader):return reader.snapshot.result_v3(tuple(reader.rows))
            def failed(error):raise error
            work.map_terminal_v3("issuer",complete,failed);work.adopt_request_lifetime_v3(lifetime)
            return work
        except BaseException:
            lifetime.close();raise
    owned=await worker.call(begin)
    if type(owned)is not OwnedGraphStorageResultV3:raise TypeError("actual exact-job metadata Work retention required")
    value,retention=owned.take_value_v3()
    try:return value
    finally:retention.release()


async def call_current_beta1_d13_v3(case,method,*,retain_result=False,**parameters):
    from contextlib import ExitStack
    from sylanne3.graph_worker import GraphStorageWorkV3,OwnedGraphStorageResultV3
    from sylanne3.runtime_contracts import AuthorityContext
    worker=await case["get_http_worker"]()
    def invoke(graph):
        policy=case["policy"];grant=case["client_grant"]
        anchor=case["port"].current_anchor(namespace=policy.namespace,authority_namespace=policy.authority_namespace)
        lease,capability=graph.grant(case["bootstrap"],actor=grant.subject,issuer_domain="d11",
            namespace=policy.namespace,domains=("d11","d13"),activation_generation=anchor.activation_generation,
            operation_id="beta1-d13-current-read:"+method)
        lifetime=ExitStack();lifetime.callback(graph.release_authority_lease,case["bootstrap"],lease)
        try:
            authority=AuthorityContext(grant.subject,"d11",capability,policy.namespace,("persona",),"context",
                (case["ingress"].conversation_ref,),policy.root_grant.policy_ref,anchor.activation_generation)
            value=getattr(graph,method)(authority,lease,**parameters)
            if type(value)is GraphStorageWorkV3:value.adopt_request_lifetime_v3(lifetime);return value
            lifetime.close();return value
        except BaseException:
            lifetime.close();raise
    result=await worker.call(invoke)
    if type(result)is OwnedGraphStorageResultV3:
        value,retention=result.take_value_v3()
        if retain_result:return value,retention
        try:return value
        finally:retention.release()
    if retain_result:raise TypeError("actual current D13 body READ retention required")
    return result


async def cancel_current_beta1_numeric_job_v3(case,job_id,*,operation_id):
    from contextlib import ExitStack
    from sylanne3.graph_worker import GraphStorageWorkV3,OwnedGraphStorageResultV3
    from sylanne3.runtime_contracts import canonical_digest
    from d04_numeric_life_acceptance_support_v1 import numeric_owner
    worker=await case["get_http_worker"]()
    input_data={"object_ref":"job:"+job_id,"control":"cancel_job","config_diff":{},"test_intent":None}
    request_digest="sha256:"+canonical_digest(input_data)
    def invoke(graph):
        lifetime=ExitStack()
        try:
            authority,lease=lifetime.enter_context(numeric_owner(case))
            port=case["beta1_workbench_lifecycle"]
            if port.owner_access.coordinator is not graph:
                raise ValueError("actual same selected Graph D12 lifecycle port required")
            result=port.commit_current_control_v1(authority,lease,operation_id=operation_id,
                request_digest=request_digest,input_data=input_data)
            if type(result)is GraphStorageWorkV3:result.adopt_request_lifetime_v3(lifetime);return result
            lifetime.close();return result
        except BaseException:
            lifetime.close();raise
    result=await worker.call(invoke)
    if type(result)is OwnedGraphStorageResultV3:
        result,retention=result.take_value_v3()
        try:return result
        finally:retention.release()
    return result


async def read_current_beta1_numeric_metadata_v3(case,job_id):
    from beta1_fixture_evidence_read_v3 import Beta1ExactNumericJobMetadataRequestV3
    return await _read_current_beta1_job_metadata_v3(case,job_id,Beta1ExactNumericJobMetadataRequestV3,
        audience=case["life_audience"])


async def read_current_beta1_d13_metadata_v3(case,job_id):
    from beta1_fixture_evidence_read_v3 import Beta1ExactD13JobMetadataRequestV3
    return await _read_current_beta1_job_metadata_v3(case,job_id,Beta1ExactD13JobMetadataRequestV3,
        audience=case["ingress"].conversation_ref)


async def prepare_current_beta1_negative_donor_v3(case,*,scenario):
    """Normal first-phase producers charge this original Root before migration."""
    if scenario not in {"numeric-authorization-lease","numeric-authorization-reservation"}:return
    from sylanne3.runtime_contracts import canonical_digest
    worker=await case["get_http_worker"]()
    bundle=case["graph"]._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    if bundle is not case["installed_bundle"]:
        raise ValueError("normal donor producer left actual original installed components; HOLD_PREPARATION")
    transport=case["model_http_client"]._transport;original_handler=transport.handler;observed_provider_calls=[]
    def observe_provider(request):
        observed_provider_calls.append(request.url.host);return original_handler(request)
    transport.handler=observe_provider
    try:
        if scenario=="numeric-authorization-lease":
            from sylanne3.runtime.foreground_call_plan_v1 import foreground_reply_budget_ids_v1
            operation=case["c02"].operation_id
            receipt=await worker.call(lambda graph:graph.prepare_post_c02_foreground_cycle_v1(
                case["bootstrap"],bundle,c02_operation_id=operation,source_ref=case["source_ref"]))
            selector=dict(kind="foreground_reply_allocation",lease_id=foreground_reply_budget_ids_v1(
                case["namespace"],operation)[0],c02_operation_id=operation,source_ref=case["source_ref"])
        else:
            from sylanne3.runtime.internal_life_content_preparation_v1 import (
                PrepareInternalLifeContentRequestV1,internal_life_content_ids_for_occurrence_v1,OPERATION)
            from d04_numeric_life_acceptance_support_v1 import numeric_owner
            operation=internal_life_content_ids_for_occurrence_v1(case["numeric_occurrence"])["prepare"]
            request=PrepareInternalLifeContentRequestV1(case["episode_ref"],case["life_causal_operation_id"])
            def prepare(graph):
                with numeric_owner(case,purpose="consolidation",audience=case["life_audience"])as(authority,lease):
                    return graph.run_current_domain_operation_v1(authority,lease,operation_kind=OPERATION,
                        request=request,operation_id=operation,activity_id=case["life_activity_id"],
                        audience_ref=case["life_audience"],parent_budget_lease_ref=case["policy"].root_grant.lease_id)
            receipt=await worker.call(prepare)
            selector=dict(kind="internal_life_content",reservation_operation_id=operation,
                quote_id=internal_life_content_ids_for_occurrence_v1(case["numeric_occurrence"])["quote"],quote_version=1,
                parent_budget_lease_ref=case["policy"].root_grant.lease_id)
    finally:transport.handler=original_handler
    if observed_provider_calls:raise ValueError("normal donor preparation made an actual provider request; HOLD_PREPARATION")
    if(type(receipt)is not dict or receipt.get("schema")!="sylanne.domain-production-receipt.v1"
            or receipt["receipt"]["status"]!="committed"):
        refusal=case["graph"]._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1
        raise ValueError("normal independent donor producer refused; HOLD_PREPARATION: "+str(refusal))
    selector.update(operation_id=receipt["operation_id"],receipt_digest=canonical_digest(receipt),
        operation_digest=receipt["receipt"]["operation_digest"],commit_seq=receipt["receipt"]["commit_seq"],
        provider_calls_observed=len(observed_provider_calls),provider_observation_scope="normal_donor_preparation_only")
    case["beta1_negative_donor"]=selector


from contextlib import asynccontextmanager

@asynccontextmanager
async def current_beta1_native_original_read_v3(case,*,request,installed_trace_reader=None):
    """Keep actual Owner lease and Source result alive through their native consumer."""
    import asyncio
    from contextlib import ExitStack
    from d04_numeric_life_acceptance_support_v1 import numeric_owner
    from sylanne3.graph_worker import GraphStorageWorkV3,OwnedGraphStorageResultV3
    worker=await case["get_http_worker"]();lifetime=ExitStack();retention=None
    def begin(graph):
        authority,lease=lifetime.enter_context(numeric_owner(case,purpose="consolidation",audience=case["life_audience"]))
        if installed_trace_reader is None:
            work=graph.read_current_life_numeric_joint_prepared_v3(authority,lease,request=request)
        else:
            work=installed_trace_reader.read(authority=authority,lease=lease,request=request,
                activity_id=case["life_activity_id"])
        if type(work)is not GraphStorageWorkV3:raise TypeError("actual Native original Source Work required")
        return work
    pending=asyncio.create_task(worker.call(begin))
    try:
        owned=await asyncio.shield(pending)
        if type(owned)is not OwnedGraphStorageResultV3:raise TypeError("actual retained Native original result required")
        value,retention=owned.take_value_v3()
        yield value
    finally:
        try:
            if retention is None:
                owned=await asyncio.shield(pending)
                if type(owned)is OwnedGraphStorageResultV3:
                    _,retention=owned.take_value_v3()
        finally:
            if retention is not None:retention.release()
            await worker.call(lambda graph:lifetime.close())


@asynccontextmanager
async def current_beta1_numeric_identity_selector_v3(case):
    import asyncio
    from contextlib import ExitStack
    from d04_numeric_life_acceptance_support_v1 import numeric_owner
    from sylanne3.graph_worker import GraphStorageWorkV3,OwnedGraphStorageResultV3
    lifetime=ExitStack();retention=None;work=None;worker=await case["get_http_worker"]()
    def begin(graph):
        nonlocal work
        authority,lease=lifetime.enter_context(numeric_owner(case,purpose="consolidation",audience=case["life_audience"]))
        work=graph.read_current_life_numeric_identity_v3(authority,lease,episode_ref=case["episode_ref"],
            causal_operation_id=case["life_causal_operation_id"])
        if type(work)is not GraphStorageWorkV3:raise TypeError("actual identity Source Work required")
        return work
    pending=asyncio.create_task(worker.call(begin))
    try:
        owned=await asyncio.shield(pending)
        if type(owned)is not OwnedGraphStorageResultV3:raise TypeError("actual retained identity Source result required")
        value,retention=owned.take_value_v3()
        yield work,value
    finally:
        try:
            if retention is None:
                owned=await asyncio.shield(pending)
                if type(owned)is OwnedGraphStorageResultV3:_,retention=owned.take_value_v3()
        finally:
            if retention is not None:retention.release()
            await worker.call(lambda graph:lifetime.close())


async def read_current_beta1_numeric_absence_metadata_v3(case,*,identity_result_reference,identity_value):
    from beta1_fixture_evidence_read_v3 import Beta1NumericJobAbsenceMetadataRequestV3
    if case["beta1_continuation"]["scenario"]!="numeric-mutation-prepare":
        raise ValueError("fixed permanent Numeric prepare-mutation absence observer required")
    request=Beta1NumericJobAbsenceMetadataRequestV3(identity_result_reference,identity_value,case["beta1_original_deadline_utc"])
    return await _read_current_beta1_metadata_request_v3(case,request,audience=case["life_audience"])


async def read_current_beta1_numeric_accepted_metadata_v3(case,*,job_id,adopted):
    from beta1_fixture_evidence_read_v3 import Beta1NumericAcceptedMetadataRequestV3
    from sylanne3.runtime.domain_production_originals_v1 import _receipt
    if adopted["operation_kind"]!="adopt_internal_life_numeric"or adopted["operation_id"]!=adopted["receipt"]["operation_id"]:
        raise ValueError("actual fixed Numeric adopt receipt required")
    request=Beta1NumericAcceptedMetadataRequestV3(job_id,_receipt(adopted["receipt"]),
        numeric_before_digest_v3(case),case["beta1_original_deadline_utc"])
    return await _read_current_beta1_metadata_request_v3(case,request,audience=case["life_audience"])


@asynccontextmanager
async def current_beta1_numeric_model_draft_read_v3(case,*,job_id):
    """Acquire before MODEL preparation; retain this same real Owner through seal."""
    import asyncio
    from contextlib import ExitStack
    from d04_numeric_life_acceptance_support_v1 import numeric_owner
    from sylanne3.graph_worker import GraphStorageWorkV3,OwnedGraphStorageResultV3
    lifetime=ExitStack();retention=None;binding=None;worker=await case["get_http_worker"]()
    def begin(graph):
        nonlocal binding
        binding=lifetime.enter_context(numeric_owner(case,purpose="consolidation",audience=case["life_audience"]))
        authority,lease=binding
        work=graph.read_current_life_numeric_model_draft_v3(authority,lease,episode_ref=case["episode_ref"],
            causal_operation_id=case["life_causal_operation_id"],job_id=job_id)
        if type(work)is not GraphStorageWorkV3:raise TypeError("actual model draft Source Work required")
        return work
    pending=asyncio.create_task(worker.call(begin))
    try:
        owned=await asyncio.shield(pending)
        if type(owned)is not OwnedGraphStorageResultV3:raise TypeError("actual retained model draft result required")
        value,retention=owned.take_value_v3()
        yield value,binding[0],binding[1]
    finally:
        try:
            if retention is None:
                owned=await asyncio.shield(pending)
                if type(owned)is OwnedGraphStorageResultV3:_,retention=owned.take_value_v3()
        finally:
            if retention is not None:retention.release()
            await worker.call(lambda graph:lifetime.close())


async def seal_current_beta1_numeric_model_v3(case,authority,lease,*,job_id,intent,permit):
    from sylanne3.runtime.domain_production_contracts_v1 import ProductionOriginalRefV1
    worker=await case['get_http_worker']()
    value=await worker.call(lambda graph:graph.seal_current_life_numeric_call_v3(authority,lease,
        episode_ref=case['episode_ref'],causal_operation_id=case['life_causal_operation_id'],
        job_id=job_id,intent=intent,permit=permit))
    if type(value)is not ProductionOriginalRefV1:
        raise TypeError('actual Numeric MODEL seal Work metadata original required')
    return value
