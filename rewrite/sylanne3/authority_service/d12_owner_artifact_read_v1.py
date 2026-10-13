"""Actual installed Life/Owner readonly artifact collector, without production frames."""
from dataclasses import fields
import json
import sqlite3
from .contract import AuthorityUnavailable
from .current_foreground_activity_v1 import _source_family_current_sql_v1
from .d11_artifact_draft_executor_v1 import _resource, _pinned_root, _readback
from ..graph_types import AtomKey, NamespaceEpoch, owner_grant_key, validate_owner_grant_v1
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
from ..domains.d08.execution import _decode_intent, _decode
from ..runtime.d12_owner_artifact_read_v1 import (OwnerArtifactReadRequestV1, OwnerArtifactReadBindingV1,
    OwnerArtifactReadResultV1, OwnerArtifactReadObservationV1)
from ..runtime.d11_life_terminal_v1 import read_adopted_life_original_v1
from ..runtime.d11_life_preparation_v1 import _read, read_prepared_life_v1
from ..runtime.d11_life_adoption_v1 import require_draft_terminal_readback_v1
from ..runtime.d11_life_contract_v1 import D11LifeTerminalV1, D11DraftTerminalV1, life_from_wire_v1
from ..runtime.d11_life_fact_provenance_v1 import require_current_life_fact_eligibility_v1, life_current_fact_reads_v1
from ..runtime.d11_life_outcome_provenance_v1 import life_outcome_key_v1
from ..runtime.d10_life_progress_provenance_v1 import validate_life_progress_provenance_history_v1
from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
from ..runtime.d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1, MAX_DRAFT_BYTES


def _head(db, namespace, ref):
    key=AtomKey.from_token(ref)
    if NamespaceId.from_key(key)!=namespace: raise AuthorityUnavailable("artifact readonly selection crossed namespace")
    row=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",(ref,*namespace.as_tuple)).fetchone()
    if row is None or row[2]!=1: raise AuthorityUnavailable("artifact current adopted member unavailable")
    return key,row[0],json.loads(row[1])


def _current_owner(service, *, credential, subject, permit, actor, session_token, session_request):
    current, observed=service.owner_service.get_current_owner_authority_for_fence_v1(
        credential=credential,subject=subject,permit=permit,actor=actor,session_token=session_token,session_request=session_request)
    if observed!=permit or current.guard.namespace!=service.namespace: raise AuthorityUnavailable("artifact current Owner fence differs")
    return current


def _snapshot(service, request, location, current_owner, session_request):
    db=sqlite3.connect(service.graph_path.as_uri()+"?mode=ro",uri=True,isolation_level=None)
    try:
        db.execute("PRAGMA query_only=ON");db.execute("BEGIN")
        service.current_source_location.require_graph_snapshot_v1(db,location,graph_db_path=service.graph_path)
        ns=request.namespace
        _,_,grant=_head(db,ns,owner_grant_key(*ns.as_tuple).token);validate_owner_grant_v1(grant)
        if (grant['state']!='pending_authority' or grant['grant_revision']!=1 or grant['authority_id']!=current_owner.guard.authority_id or grant['installation_id']!=current_owner.guard.installation_id
                or grant['principal']!=plain_v1(session_request.principal) or 'workbench.read' not in grant['capabilities']
                or 'workbench_view' not in grant['purposes'] or 'owner' not in grant['audiences']):
            raise AuthorityUnavailable("artifact actual current Owner grant lacks viewing scope")
        project_key,project_revision,project_value=_head(db,ns,request.project_ref)
        key,revision,raw=_head(db,ns,request.progress_ref)
        if key.type_name!='d10.life_progress.v1' or set(raw)!={f.name for f in fields(LifeProgressHeadV1)}:
            raise AuthorityUnavailable("artifact selector lacks exact current Life progress")
        values=dict(raw);values['source_refs']=tuple(values['source_refs']);values['receipt_refs']=tuple(values['receipt_refs'])
        progress=LifeProgressHeadV1(**values)
        if progress.project_ref!=request.project_ref or progress.step!='artifact_draft_v1' or progress.artifact_ref is None or progress.reality!='real_execution':
            raise AuthorityUnavailable("artifact selection is not actual adopted file progress")
        adopted=read_adopted_life_original_v1(db,namespace=ns,result_ref=progress.artifact_ref,issuer=service.issuer)
        if adopted is None: raise AuthorityUnavailable("artifact signed adopted original unavailable")
        terminal=life_from_wire_v1(adopted['terminal'],D11LifeTerminalV1)
        if type(terminal) is not D11DraftTerminalV1: raise AuthorityUnavailable("artifact actual file terminal unavailable")
        binding=terminal.binding
        prepared=read_prepared_life_v1(db,binding=binding,issuer=service.issuer)
        if prepared is None: raise AuthorityUnavailable("artifact signed preparation unavailable")
        witness=require_draft_terminal_readback_v1(prepared=prepared,terminal=terminal)
        if ((prepared.plan.project.ref,prepared.plan.recipe.ref,binding.activity_id,binding.effect_id,binding.artifact_ref,terminal.original_ref)!=
                (progress.project_ref,progress.recipe_ref,progress.activity_id,progress.effect_id,progress.artifact_ref,progress.terminal_ref)):
            raise AuthorityUnavailable("artifact preparation/progress original identity differs")
        if (witness.version,witness.content_digest)!=(request.expected_artifact_version,request.expected_content_digest):
            raise AuthorityUnavailable("artifact selected version or content digest is stale")
        history=db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?",(key.token,revision)).fetchone()
        production=None if history is None else read_adopted_domain_operation_v1(db,ns,history[0])
        if production is None: raise AuthorityUnavailable("artifact actual adopted progress operation unavailable")
        writes=validate_life_progress_provenance_history_v1(db,prepared=prepared,terminal=terminal,progress=progress,production=production)
        require_current_life_fact_eligibility_v1(db,prepared=prepared,terminal=terminal,adopted=adopted)
        for write in writes:
            _,actual_revision,actual_value=_head(db,ns,write.key.token)
            if actual_revision!=1 or canonical_serialize(actual_value)!=canonical_serialize(write.value):
                raise AuthorityUnavailable("artifact current progress/provenance/eligibility changed")
        action_ref=prepared.plan.action_intent
        action_row=db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",(action_ref.ref,action_ref.revision)).fetchone()
        if action_row is None or action_row[1]!=1 or canonical_digest(json.loads(action_row[0]))!=action_ref.digest:
            raise AuthorityUnavailable("artifact historical Action identity unavailable")
        action=_decode_intent(json.loads(action_row[0]));outcome_key=life_outcome_key_v1(binding,action_ref.ref)
        _,_,outcome_value=_head(db,ns,outcome_key.token);outcome=_decode('d08.action_outcome.v1',outcome_value)
        if (outcome.action_id!=action.action_id or outcome.effect_id!=binding.effect_id or outcome.attempt_id!=binding.attempt_id
                or outcome.result_level!='completed_verified' or outcome.completed_effects!=(binding.effect_id,)
                or outcome.unknown_effects or outcome.observation_refs!=(terminal.original_ref,)):
            raise AuthorityUnavailable("artifact actual adopted Action postcondition unavailable")
        root_row=_read(db,issuer=service.issuer,namespace=ns,kind='draft_root_capability',ref=binding.root_registration_ref)
        if root_row is None or canonical_digest(root_row[0])!=binding.root_registration_digest:
            raise AuthorityUnavailable("artifact signed root registration unavailable")
        root=draft_from_wire_v1(root_row[0],DraftRootCapabilityV1)
        if (root.resource_id!=prepared.plan.target.root_resource_id or root.root_identity!=prepared.plan.target.root_identity
                or root.registration_ref!=prepared.plan.target.root_registration_ref or prepared.plan.target.filename not in root.filenames
                or root.owner_grant_ref!=owner_grant_key(*ns.as_tuple).token
                or (root.owner_grant_revision,root.owner_grant_digest)!=(_head(db,ns,root.owner_grant_ref)[1],canonical_digest(grant))
                or witness.content_length>min(MAX_DRAFT_BYTES,root.max_bytes,prepared.plan.target.max_bytes)):
            raise AuthorityUnavailable("artifact current registered root/Owner/byte scope differs")
        roots=tuple(dict.fromkeys((prepared.plan.input_source.ref,*prepared.plan.content.source_refs,*progress.source_refs,root.source_ref)))
        source_versions=_source_family_current_sql_v1(db,namespace=ns,roots=roots,purpose='context',audiences=('owner',))
        material=[]
        for version in source_versions:
            row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(version.key.token,)).fetchone()
            material.append((version.key.token,version.revision,None if row is None else canonical_digest(json.loads(row[1])),None if row is None else bool(row[2])))
        epochs=db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',ns.as_tuple).fetchone()
        if epochs is None: raise AuthorityUnavailable("artifact actual Source authority epochs unavailable")
        source_commitment=canonical_digest((roots,material,epochs,project_key.token,project_revision,canonical_digest(project_value),key.token,revision,canonical_digest(raw),canonical_digest(outcome_value)))
        return prepared,witness,source_commitment,canonical_digest(root_row[0])
    finally:
        if db.in_transaction: db.rollback()
        db.close()


def observe_owner_artifact_for_fence_v1(service, *, credential, subject, permit, request, actor,
        session_token, session_request, expected_binding=None):
    from .d11_life_service_v1 import AuthorityD11LifeServiceV1
    from .v2_contract import FencePermitV2
    from .v2_owner_session import OwnerSessionLoginRequestV1
    if (type(service) is not AuthorityD11LifeServiceV1 or type(request) is not OwnerArtifactReadRequestV1
            or type(permit) is not FencePermitV2 or permit.operation!='read' or permit.subject!=subject
            or type(session_request) is not OwnerSessionLoginRequestV1 or service.current_source_location is None
            or service.draft_inventory_manifest is None or request.namespace!=service.namespace or request.installation_id!=service.installation_id
            or expected_binding is not None and type(expected_binding) is not OwnerArtifactReadBindingV1):
        raise AuthorityUnavailable("actual paired Owner artifact readonly composition required")
    current=_current_owner(service,credential=credential,subject=subject,permit=permit,actor=actor,session_token=session_token,session_request=session_request)
    location=service.current_source_location.observe_business_for_fence_v1(credential=credential,subject=subject,permit=permit)
    prepared,witness,source_commitment,root_commitment=_snapshot(service,request,location,current,session_request)
    resource=_resource(service,service.draft_inventory_manifest,prepared.plan)
    observed=OwnerArtifactReadBindingV1(request.digest,canonical_digest(permit),current.guard,
        location.current_graph_metadata.requirements.graph_incarnation,location.current_graph_metadata.graph_revision,
        location.graph_epoch.revision,source_commitment,root_commitment,canonical_digest(witness.file_identity),service._utc_text(service._now()))
    if expected_binding is not None:
        if observed.current_commitment!=expected_binding.current_commitment: raise AuthorityUnavailable("artifact metadata changed within current read fence")
        with service.owner_service.fences._frozen() as (db, *_): service.current_source_location.require_current_in_tx_v1(db,location)
        return OwnerArtifactReadObservationV1(observed,None)
    captured=bytearray()
    with _pinned_root(resource.path,prepared.plan.target.root_identity) as (root,directory_fd):
        actual=_readback(root/prepared.plan.target.filename,expected_length=witness.content_length,expected_digest=witness.content_digest,
            expected_identity=witness.file_identity,directory_fd=directory_fd,body_capture=captured)
    if actual!=witness.file_identity: raise AuthorityUnavailable("artifact same-handle file identity changed")
    try: body=captured.decode('utf-8',errors='strict')
    except UnicodeError as exc: raise AuthorityUnavailable("artifact text encoding unsupported") from exc
    fresh=_current_owner(service,credential=credential,subject=subject,permit=permit,actor=actor,session_token=session_token,session_request=session_request)
    final_location=service.current_source_location.observe_business_for_fence_v1(credential=credential,subject=subject,permit=permit)
    final_prepared,final_witness,final_source,final_root=_snapshot(service,request,final_location,fresh,session_request)
    final=OwnerArtifactReadBindingV1(request.digest,canonical_digest(permit),fresh.guard,
        final_location.current_graph_metadata.requirements.graph_incarnation,final_location.current_graph_metadata.graph_revision,
        final_location.graph_epoch.revision,final_source,final_root,canonical_digest(final_witness.file_identity),service._utc_text(service._now()))
    if final.current_commitment!=observed.current_commitment or final_prepared.digest!=prepared.digest: raise AuthorityUnavailable("artifact current Owner/Source/Graph qualification changed after body read")
    with service.owner_service.fences._frozen() as (db, *_): service.current_source_location.require_current_in_tx_v1(db,final_location)
    result=OwnerArtifactReadResultV1(request.namespace,request.installation_id,request.project_ref,request.progress_ref,
        prepared.binding.artifact_ref,witness.version,witness.content_digest,witness.content_length,body,final)
    return OwnerArtifactReadObservationV1(final,result)
