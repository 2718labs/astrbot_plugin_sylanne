"""Same-installation Owner location through actual released C09 storage.

The rev1 grant and Owner issue proof remain immutable. This is a separate
storage continuation, never a migration target admission or a new permission.
"""
from dataclasses import asdict,dataclass
import json
import hashlib
from pathlib import Path
import sqlite3
from ..contracts import canonical_json
from ..graph_store import GraphStore
from ..graph_types import owner_grant_key,validate_owner_grant_v1
from ..runtime.c09_graph_originals_read_v4 import read_graph_rebase_certificate_v1
from ..runtime.lifecycle_operations_v1 import digest
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import NamespaceId,canonical_serialize,canonical_digest
from .contract import AuthorityUnavailable
from .c09_close_apply_v1 import InstalledC09CloseApplyV1,_prepared_deletion_receipt_original_v1
from .c09_storage_control_v1 import C09StorageControlV1
from .v2_owner_contract import OwnerAuthorizationGuardV1,OwnerPrincipalV1,canonical_digest as owner_digest
from .v2_owner_session import OwnerSessionLoginRequestV1,_principal
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from .v2_fence_service import AuthorityV2FenceService

SCHEMA='d12.owner-storage-admission.v1'


@dataclass(frozen=True,slots=True)
class D12OwnerStorageAdmissionV1:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    holder: str
    source_grant_ref: str
    source_grant_revision: int
    source_grant_digest: str
    source_owner_guard: OwnerAuthorizationGuardV1
    principal: OwnerPrincipalV1
    source_graph_incarnation: str
    current_graph_incarnation: str
    activation_generation: int
    revocation_epoch: int
    storage_generation: int
    pointer_version: int
    manifest_digest: str
    release_digest: str
    certificate_chain: tuple[tuple[str,str,str],...]
    original_ref: str
    original_digest: str
    schema: str = SCHEMA

    def __post_init__(self):
        if (self.schema!=SCHEMA or type(self.namespace) is not NamespaceId or type(self.source_owner_guard) is not OwnerAuthorizationGuardV1
                or type(self.principal) is not OwnerPrincipalV1 or self.source_owner_guard.namespace!=self.namespace
                or self.source_owner_guard.installation_id!=self.installation_id
                or self.source_graph_incarnation==self.current_graph_incarnation or self.source_grant_revision!=1
                or any(type(v) is not int or v<1 for v in (self.activation_generation,self.revocation_epoch,self.storage_generation,self.pointer_version))
                or type(self.certificate_chain) is not tuple or not self.certificate_chain):raise ValueError('actual same-installation C09 Owner continuation required')
        for name in ('authority_namespace','installation_id','holder','source_grant_ref','source_graph_incarnation','current_graph_incarnation','original_ref'):
            if type(getattr(self,name)) is not str or not getattr(self,name):raise ValueError('Owner storage location identity absent')
        for value in (self.source_grant_digest,self.original_digest):
            if type(value) is not str or not value.startswith('sha256:') or len(value)!=71 or any(c not in '0123456789abcdef' for c in value[7:]):raise ValueError('Owner storage continuation digest differs')
        for value in (self.manifest_digest,self.release_digest,*(v for row in self.certificate_chain for v in row)):
            if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):raise ValueError('C09 storage original digest differs')
        body=asdict(self);body.pop('original_digest')
        if digest(body)!=self.original_digest:raise ValueError('Owner storage original commitment differs')
        material=dict(body);material.pop('original_ref')
        if self.original_ref!='d12-owner-storage:'+digest(material)[7:]:raise ValueError('Owner storage original address differs')

    def to_wire(self):return asdict(self)


def owner_storage_admission_from_wire_v1(raw):
    if type(raw) is not dict or set(raw)!=set(D12OwnerStorageAdmissionV1.__dataclass_fields__):raise ValueError('Owner storage admission fields differ')
    value=dict(raw);value['namespace']=NamespaceId(**value['namespace']);guard=dict(value['source_owner_guard'])
    guard['namespace']=NamespaceId(**guard['namespace']);value['source_owner_guard']=OwnerAuthorizationGuardV1(**guard)
    value['principal']=OwnerPrincipalV1(**value['principal']);value['certificate_chain']=tuple(tuple(row) for row in value['certificate_chain'])
    result=D12OwnerStorageAdmissionV1(**value)
    if json.loads(canonical_serialize(result.to_wire()))!=raw:raise ValueError('Owner storage wire noncanonical')
    return result


class InstalledD12OwnerStorageAdmissionServiceV1:
    def __init__(self,*,fences,owner_tickets,graph_db_path,namespace_id,installation_id,holder,control,close_apply):
        if (type(fences) is not AuthorityV2FenceService or type(owner_tickets) is not AuthorityV2OwnerTicketStore
                or owner_tickets._core is not fences.core or type(namespace_id) is not NamespaceId
                or type(control) is not C09StorageControlV1 or type(close_apply) is not InstalledC09CloseApplyV1
                or close_apply.control is not control or control._applied_reader is not close_apply
                or control.installation_id!=installation_id or close_apply.graph_application.namespace!=namespace_id):raise TypeError('actual installed Owner/Core/C09 RELEASED readers required')
        self.fences=fences;self.core=fences.core;self.tickets=owner_tickets;self.sessions=owner_tickets._owner_sessions
        self.namespace=fences.namespace;self.namespace_id=namespace_id;self.installation_id=installation_id;self.holder=holder
        self.graph_path=Path(graph_db_path).resolve(strict=True);self.control=control;self.close_apply=close_apply

    def _head_in_tx(self,db):
        head=self.tickets.current_migration_head_in_tx(db,authority_namespace=self.namespace)
        if (head is None or head.state!='active' or head.guard.installation_id!=self.installation_id
                or head.guard.namespace!=self.namespace_id or head.guard.pending_revoke_operation_id is not None
                or head.guard.minimum_revocation_epoch or head.guard.minimum_revocation_revision):raise AuthorityUnavailable('source storage Owner head is not current/unchanged')
        return head

    def _background_identity_in_tx(self,db,head):
        pairing=self.sessions._current_pairing_source
        if pairing is None:raise AuthorityUnavailable('source current Owner pairing absent')
        principal=head.issue_operation.principal
        actor=pairing.current_principal_binding(authority_namespace=self.namespace,installation_id=self.installation_id,principal=principal)
        if actor is None:raise AuthorityUnavailable('source current Owner actor absent')
        key=db.execute('SELECT credential_id,credential_epoch FROM authority_owner_credentials_v1 WHERE authority_namespace=? AND installation_id=? AND principal_json=?',
            (self.namespace,self.installation_id,_principal(principal))).fetchone()
        if key is None:raise AuthorityUnavailable('source current Owner key absent')
        request=OwnerSessionLoginRequestV1(authority_id=head.guard.authority_id,authority_namespace=self.namespace,
            installation_id=self.installation_id,principal=principal,credential_id=key[0],credential_epoch=key[1],
            audience='sylanne-owner-console',dashboard_origin='https://installed.invalid')
        self.sessions._current_key(db,request)
        pairing.require_current_actor_in_tx(db,authority_namespace=self.namespace,installation_id=self.installation_id,
            actor_id=actor.actor_id,principal=principal)
        return actor,request

    def _storage_observation(self):
        # C09 qualification reads both Graph and Core. Complete it before taking
        # this service's Graph snapshot; the snapshot may only compare originals.
        context=self.control.read_verified_current_storage_v1()
        context.require_current('business')
        release=None;originals={}
        if context.stage=='RELEASED':
            release=self.close_apply.read_storage_applied_original_v1(context=context)
            with self.control._db() as control_db:
                self.control._current(control_db)
                rows=control_db.execute('SELECT operation_id,prepared_original_json,prepared_digest FROM c09_storage_operations_v1 WHERE prepared_original_json IS NOT NULL').fetchmany(1025)
            if len(rows)>1024:raise AuthorityUnavailable('Owner storage ancestry exceeds installed bound')
            for operation,raw,commitment in rows:
                prepared=json.loads(raw)
                self.control.verify_original_v1(prepared,'prepared_digest')
                if prepared['prepared_digest']!=commitment or prepared['operation_id']!=operation:raise AuthorityUnavailable('Owner storage PREPARED row commitment differs')
                if prepared['namespace']!=self.namespace or prepared['installation_id']!=self.installation_id:continue
                # Only the ancestry of the currently selected original is used
                # below. Unfinished independent operations confer no location.
                originals[operation]=(prepared,None,None,None,None)
            operation=context.prepared_original['operation_id'];seen=set()
            by_certificate={value[0]['graph_certificate_original']['certificate_digest']:key for key,value in originals.items()}
            while operation is not None:
                if operation in seen or operation not in originals:raise AuthorityUnavailable('Owner storage signed ancestry absent/ambiguous')
                seen.add(operation);prepared,_,_,_,_=originals[operation]
                released=self.control.read_operation_event_v1(operation,'RELEASED')['details']['release_original']
                self.control.verify_original_v1(released,'release_digest')
                # The storage rebase and the subsequent closed append are two
                # distinct durable transitions. Read the actual closed mutation
                # and its independent journal append before opening Graph SQL.
                closed=self.close_apply._closed_original(operation)
                if closed is None or canonical_digest(closed)!=released['closed_digest']:
                    raise AuthorityUnavailable('Owner storage RELEASED closed original differs')
                with sqlite3.connect(self.graph_path.as_uri()+'?mode=ro',uri=True) as observed_graph:
                    observed_graph.execute('BEGIN')
                    ack=self.close_apply.graph_application._read_ack_locked(observed_graph,operation)
                if (ack is None or ack['ack_digest']!=released['graph_ack_digest']
                        or ack['closed_digest']!=released['closed_digest']
                        or (ack['deletion_seq'],ack['deletion_digest'],ack['deletion_epoch'])
                            !=(released['applied_seq'],released['applied_digest'],released['applied_epoch'])):
                    raise AuthorityUnavailable('Owner storage actual applied Graph ACK differs')
                event_digest=hashlib.sha256(json.dumps((operation,ack['deletion_seq'],ack['deletion_digest'],
                    'sha256:'+ack['graph_receipt_digest']),sort_keys=True,separators=(',',':')).encode()).hexdigest()
                with self.core._tx() as actual_core:
                    events=actual_core.execute("SELECT seq FROM authority_events WHERE namespace=? AND kind='scoped_erasure_applied' AND generation=? AND detail_digest=?",
                        (self.namespace,closed.after_anchor.activation_generation,event_digest)).fetchall()
                    if len(events)!=1:raise AuthorityUnavailable('Owner storage actual scoped application event differs')
                    if operation==context.prepared_original['operation_id']:
                        applied=self.close_apply.scoped.state_locked(actual_core)
                        actual_anchor=self.core._anchor(actual_core,self.namespace,self.core._row(actual_core,self.namespace))
                        if (applied.aggregate_phase!='clear' or applied.active_operation_id is not None
                                or (applied.applied_seq,applied.applied_digest,applied.applied_epoch)
                                    !=(released['applied_seq'],released['applied_digest'],released['applied_epoch'])
                                or actual_anchor.revocation_epoch!=closed.after_anchor.revocation_epoch+1):
                            raise AuthorityUnavailable('Owner storage actual scoped application anchor differs')
                accepted=_prepared_deletion_receipt_original_v1(prepared['accepted_receipt_original'])
                with self.core._tx() as actual_core:
                    mutation_ids=actual_core.execute("SELECT mutation_id FROM authority_v2_mutations WHERE namespace=? AND operation_id=? AND mutation_kind='deletion'",
                        (self.namespace,accepted.pending.permit.operation_id)).fetchmany(5)
                if len(mutation_ids)!=3:raise AuthorityUnavailable('Owner storage exact deletion entrance originals absent')
                phases={}
                for (mutation_id,) in mutation_ids:
                    original=self.close_apply.scoped.read_ancestor_receipt(credential=self.close_apply.credential,
                        subject=self.close_apply.subject,mutation_id=mutation_id)
                    target=original.pending.target_phase
                    if (original.pending.deletion_operation_id!=operation or target in phases
                            or target not in {'pending','accepted','closed'}):
                        raise AuthorityUnavailable('Owner storage deletion entrance identity differs')
                    phases[target]=original
                if (phases.get('accepted')!=accepted or phases.get('closed')!=closed
                        or canonical_digest(accepted)!=prepared['accepted_receipt_digest']
                        or phases['pending'].pending.source_phase!='absent'
                        or accepted.pending.source_phase!='pending'
                        or phases['pending'].after_anchor!=accepted.pending.before_anchor
                        or accepted.after_anchor!=RestoreAnchor(**prepared['old_core_anchor_original'])):
                    raise AuthorityUnavailable('Owner storage exact pending/accepted/rebase sequence differs')
                originals[operation]=(prepared,released,closed,ack,phases['pending'])
                prior=prepared['graph_certificate_original']['prior_certificate_digest']
                operation=None if prior is None else by_certificate.get(prior)
                if prior is not None and operation is None:raise AuthorityUnavailable('Owner storage prior signed original absent')
        return context,release,originals

    def _read_graph(self,*,owner_head,anchor):
        context,release,originals=self._storage_observation()
        member=next(m for m in context.manifest['members'] if m['role']=='graph')
        if Path(member['resolved_path']).resolve()!=self.graph_path or context.manifest['authority_id']!=anchor.authority_id:raise AuthorityUnavailable('source Owner Graph is not selected current storage')
        db=sqlite3.connect(self.graph_path.as_uri()+'?mode=ro',uri=True,isolation_level=None)
        try:
            db.execute('BEGIN')
            metadata=GraphStore._decode_recovery(db.execute('SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',self.namespace_id.as_tuple).fetchone(),self.namespace_id)
            grant_row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(owner_grant_key(*self.namespace_id.as_tuple).token,)).fetchone()
            proof=db.execute('SELECT proof_json FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?',self.namespace_id.as_tuple).fetchone()
            if metadata is None or grant_row is None or grant_row[2]!=1 or proof!=(canonical_json(asdict(owner_head.issue_proof)),):raise AuthorityUnavailable('source storage immutable Owner proof absent/changed')
            grant=json.loads(grant_row[1]);validate_owner_grant_v1(grant);req=metadata.requirements
            if (grant_row[0]!=1 or digest(grant)!=owner_head.grant_digest or grant['principal']!=asdict(owner_head.issue_operation.principal)
                    or grant['graph_incarnation']!=owner_head.issue_proof.graph_incarnation
                    or grant['installation_id']!=self.installation_id or grant['scope']!='/'.join(self.namespace_id.as_tuple)
                    or grant['activation_generation']!=req.activation_generation
                    or req.authority_id!=anchor.authority_id or req.authority_namespace!=anchor.namespace
                    or any(getattr(req,n)!=getattr(anchor,n) for n in ('activation_generation','revocation_epoch','deletion_journal_id','deletion_seq','deletion_digest','execution_journal_id','execution_seq','execution_digest'))):raise AuthorityUnavailable('source storage current Graph/Owner/fence differs')
            admission=(None if req.graph_incarnation==grant['graph_incarnation'] else
                self._read_released_lineage(db,metadata,grant,owner_head,context,release,originals))
        finally:db.close()
        # Recheck the real pointer, current closed receipt and actual applied
        # Core after releasing Graph, before the caller's final permit CAS.
        context.require_current('business')
        if release is not None and self.close_apply.read_storage_applied_original_v1(context=context)!=release:
            raise AuthorityUnavailable('Owner storage release changed during Graph observation')
        return metadata,grant,admission

    def _read_released_lineage(self,graph,metadata,grant,head,context,release,originals):
        if context.stage!='RELEASED' or context.prepared_original is None:raise AuthorityUnavailable('Owner storage continuation requires actual C09 RELEASED')
        if release is None:raise AuthorityUnavailable('Owner storage actual applied observation absent')
        operation=context.prepared_original['operation_id']
        latest=self.close_apply.graph_application._certificate_locked(graph,context,operation)
        if latest.new_incarnation!=metadata.requirements.graph_incarnation or latest.certificate_digest!=context.manifest['certificate_digest']:raise AuthorityUnavailable('Owner storage selected certificate differs')
        certificates={}
        for (op,) in graph.execute('SELECT operation_id FROM graph_c09_rebase_certificates_v1 WHERE bot=? AND persona=?',self.namespace_id.as_tuple):
            cert=read_graph_rebase_certificate_v1(graph,self.namespace_id,op)
            if cert is None or cert.certificate_digest in certificates:raise AuthorityUnavailable('Owner storage certificate ancestry ambiguous')
            certificates[cert.certificate_digest]=cert
        chain=[];seen=set();current=latest;origin=grant['graph_incarnation']
        while True:
            if current.certificate_digest in seen:raise AuthorityUnavailable('Owner storage ancestry cycles')
            seen.add(current.certificate_digest);chain.append(current)
            if current.old_incarnation==origin:break
            prior=certificates.get(current.prior_certificate_digest)
            if prior is None or prior.new_incarnation!=current.old_incarnation:raise AuthorityUnavailable('Owner storage does not descend from immutable grant location')
            current=prior
        previous_incarnation=origin;previous_epoch=None;commitments=[];generation=grant['activation_generation']
        for cert in reversed(chain):
            observed=originals.get(cert.operation_id)
            if observed is None or observed[1] is None:raise AuthorityUnavailable('Owner storage signed RELEASED ancestry absent')
            prepared,released,closed,ack,pending=observed
            before=RestoreAnchor(**prepared['old_core_anchor_original']);after=RestoreAnchor(**prepared['new_core_anchor_original'])
            if (prepared['namespace']!=self.namespace or prepared['installation_id']!=self.installation_id
                    or prepared['operation_id']!=cert.operation_id
                    or released['storage_generation']!=prepared['maintenance_generation']
                    or ack['certificate_digest']!=cert.certificate_digest
                    or ack['manifest_digest']!=prepared['new_manifest_digest']
                    or canonical_serialize(prepared['graph_certificate_original'])!=canonical_serialize(asdict(cert))
                    or cert.old_incarnation!=previous_incarnation or before.namespace!=self.namespace or after.namespace!=self.namespace
                    or before.authority_id!=head.guard.authority_id or after.authority_id!=before.authority_id
                    or before.activation_generation!=generation or after.activation_generation!=generation
                    or previous_epoch is not None and pending.pending.before_anchor.revocation_epoch!=previous_epoch
                    or after.revocation_epoch!=before.revocation_epoch+1
                    or self.close_apply.graph_application._read_ack_locked(graph,cert.operation_id)!=ack
                    or closed.pending.before_anchor!=after
                    or closed.pending.deletion_operation_id!=cert.operation_id
                    or closed.pending.source_phase!='accepted' or closed.pending.target_phase!='closed'
                    or canonical_digest(closed)!=released['closed_digest']
                    or closed.after_anchor.deletion_seq!=released['applied_seq']
                    or closed.after_anchor.deletion_digest!=released['applied_digest']
                    or released['manifest_digest']!=prepared['new_manifest_digest'] or released['operation_id']!=cert.operation_id or released['state']!='applied'):
                raise AuthorityUnavailable('Owner storage actual signed C09 lineage differs')
            commitments.append((cert.certificate_digest,prepared['prepared_digest'],released['release_digest']))
            previous_incarnation,previous_epoch=cert.new_incarnation,closed.after_anchor.revocation_epoch+1
        if metadata.requirements.revocation_epoch!=previous_epoch or metadata.requirements.activation_generation!=generation:raise AuthorityUnavailable('Owner storage current metadata differs from RELEASED lineage')
        body=dict(schema=SCHEMA,namespace=self.namespace_id,authority_namespace=self.namespace,installation_id=self.installation_id,
            holder=self.holder,source_grant_ref=owner_grant_key(*self.namespace_id.as_tuple).token,source_grant_revision=1,
            source_grant_digest=head.grant_digest,source_owner_guard=head.guard,principal=head.issue_operation.principal,
            source_graph_incarnation=origin,current_graph_incarnation=previous_incarnation,activation_generation=generation,
            revocation_epoch=previous_epoch,storage_generation=context.storage_generation,pointer_version=context.pointer_version,
            manifest_digest=context.manifest_digest,release_digest=release['release_digest'],certificate_chain=tuple(commitments))
        # The persisted wire contract commits the plain typed-field shape,
        # matching __post_init__ and to_wire, not canonical DTO discriminators.
        material={**body,'namespace':asdict(body['namespace']),
            'source_owner_guard':asdict(body['source_owner_guard']),'principal':asdict(body['principal'])}
        body['original_ref']='d12-owner-storage:'+digest(material)[7:]
        material['original_ref']=body['original_ref']
        return D12OwnerStorageAdmissionV1(**body,original_digest=digest(material))

    def _observe(self,*,credential,subject,permit,actor=None,session_token=None,session_request=None):
        from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
        self.fences.validate_fence(credential=credential,subject=subject,permit=permit)
        if permit.holder!=self.holder or permit.namespace!=self.namespace:raise AuthorityUnavailable('source storage actual holder differs')
        guard=self.tickets.get_current_guard(credential=credential,authority_namespace=self.namespace,
            installation_id=self.installation_id,subject=subject,permit=permit,owner_actor_id=actor,
            owner_session_token=session_token,owner_session_request=session_request)
        with self.core._tx() as db:
            head=self._head_in_tx(db)
            if head.guard!=guard:raise AuthorityUnavailable('source Owner guard changed')
            if actor is None:self._background_identity_in_tx(db,head)
        metadata,grant,admission=self._read_graph(owner_head=head,anchor=permit.pinned_anchor)
        with self.fences._frozen() as (db,deletion,execution,_):
            anchor=self.fences._current_locked(db,deletion,execution)
            self.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
            if self._head_in_tx(db)!=head:raise AuthorityUnavailable('source Owner changed after C09 location read')
            if actor is None:self._background_identity_in_tx(db,head)
            else:
                self.sessions.require_current_in_tx(db,token=session_token,request=session_request)
                self.sessions._current_pairing_source.require_current_actor_in_tx(db,authority_namespace=self.namespace,
                    installation_id=self.installation_id,actor_id=actor,principal=session_request.principal)
        return D12CurrentOwnerAuthorityV1(guard,None,admission),permit

    def get_current_owner_authority_for_fence_v1(self,*,credential,subject,permit,actor,session_token,session_request):
        return self._observe(credential=credential,subject=subject,permit=permit,actor=actor,session_token=session_token,session_request=session_request)

    def get_current_background_owner_authority_for_fence_v1(self,*,credential,subject,permit):
        return self._observe(credential=credential,subject=subject,permit=permit)


def require_owner_storage_graph_binding_v1(admission,*,authority,principal,grant,proof,metadata,installation_id,holder,guard):
    if type(admission) is not D12OwnerStorageAdmissionV1:raise AuthorityUnavailable('typed actual Owner storage continuation required')
    req=metadata.requirements
    if (admission.namespace!=authority.namespace or admission.namespace!=principal_namespace(grant,authority.namespace)
            or admission.principal!=principal or admission.source_owner_guard!=guard
            or admission.installation_id!=installation_id or admission.holder!=holder
            or admission.source_grant_ref!=owner_grant_key(*authority.namespace.as_tuple).token
            or admission.source_grant_digest!=proof.grant_digest or admission.source_grant_digest!=digest(grant)
            or admission.source_grant_revision!=proof.grant_revision or admission.source_graph_incarnation!=proof.graph_incarnation
            or admission.source_graph_incarnation!=grant['graph_incarnation'] or grant['installation_id']!=installation_id
            or grant['principal']!=asdict(principal) or admission.source_owner_guard.authorization_head!=owner_digest(proof)
            or admission.current_graph_incarnation!=req.graph_incarnation or admission.activation_generation!=req.activation_generation
            or admission.activation_generation!=authority.activation_generation or admission.revocation_epoch!=req.revocation_epoch
            or admission.authority_namespace!=req.authority_namespace or admission.source_owner_guard.authority_id!=req.authority_id):
        raise AuthorityUnavailable('Owner storage continuation/current Graph immutable binding differs')
    return admission


def principal_namespace(grant,namespace):
    if grant['scope']!='/'.join(namespace.as_tuple):raise AuthorityUnavailable('Owner storage grant scope differs')
    return namespace
