"""Independent Owner-session Habit standing policy ledger on installed Core."""
from dataclasses import asdict
import hashlib,hmac
from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2
from .v2_owner_session import OwnerSessionLoginRequestV1,_principal
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from .d10_habit_contract_v1 import (HabitStandingPolicyOriginalV1,
    habit_standing_policy_original_from_wire_v1,habit_standing_policy_original_to_wire_v1)
from ..domains.d10.habit_policy_v1 import HabitPolicyDefinitionV1,habit_policy_definition_to_wire_v1
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize

from .d10_habit_ledger_v1 import (POLICY_TABLE as TABLE,POLICY_DDL as DDL,POLICY_COLUMNS,
    habit_ledger_triggers_v1,habit_ledger_decode_v1,habit_identity_commitment_v1,habit_scope_identity_commitment_v1,MAX_PAYLOAD_BYTES)
TRIGGERS=habit_ledger_triggers_v1(TABLE)

class InstalledD10HabitPolicyServiceV1:
    def __init__(self,*,fences,owner_tickets,owner_service,namespace,installation_id,signing_key,trusted_now_utc,create=False):
        if (type(owner_tickets)is not AuthorityV2OwnerTicketStore or owner_tickets._core is not fences.core
                or owner_service.core is not fences.core or owner_service.fences is not fences
                or owner_service.installation_id!=installation_id or type(namespace)is not NamespaceId
                or type(signing_key)is not bytes or len(signing_key)!=32):
            raise AuthorityUnavailable("Habit standing policy needs actual paired Core/Owner installation")
        self.fences,self.core,self.tickets=fences,fences.core,owner_tickets
        self.owner_service,self.namespace,self.installation_id=owner_service,namespace,installation_id
        self._key,self._clock=signing_key,trusted_now_utc
        self._current=None
        with self.core._tx()as db:
            for kind,name,ddl in (("table",TABLE,DDL),*(("trigger",name,ddl)for name,ddl in TRIGGERS)):
                row=db.execute("SELECT sql FROM sqlite_master WHERE type=? AND name=?",(kind,name)).fetchone()
                if row is None and create:db.execute(ddl)
                elif row!=(ddl,):raise AuthorityUnavailable("Habit standing original ledger schema differs")

    def install_current_v1(self,current):
        from .current_habit_occurrence_v1 import InstalledCurrentHabitOccurrenceV1
        if (type(current)is not InstalledCurrentHabitOccurrenceV1 or current.policy_service is not self
                or current.self_identity._owner_storage is not self.owner_service
                or self._current is not None and self._current is not current):
            raise AuthorityUnavailable("Habit policy/current bridge requires its actual fixed installation")
        self._current=current

    def _sign_v1(self,wire):
        return hmac.new(self._key,canonical_serialize(wire).encode("utf8"),hashlib.sha256).hexdigest()

    def _identity_v1(self,kind,value):return habit_identity_commitment_v1(self._key,kind,value)

    def _decode_v1(self,row):
        return habit_ledger_decode_v1(TABLE,POLICY_COLUMNS,row,key=self._key,
            authority_namespace=self.fences.namespace,authority_id=self.fences.core._id(self.core._db),
            installation_id=self.installation_id)

    def _head_v1(self,db,policy_id):
        identity=self._identity_v1("policy",policy_id)
        floors=db.execute("SELECT MAX(policy_revision),MAX(cancellation_generation) FROM "+TABLE+
            " WHERE authority_namespace=? AND installation_id=? AND policy_commitment=?",
            (self.fences.namespace,self.installation_id,identity)).fetchone()
        if floors[0]is None:return None
        rows=db.execute("SELECT * FROM "+TABLE+" WHERE authority_namespace=? AND installation_id=? AND policy_commitment=? AND policy_revision=? ORDER BY operation_commitment",
            (self.fences.namespace,self.installation_id,identity,floors[0])).fetchmany(2)
        if len(rows)!=1:raise AuthorityUnavailable("Habit actual highest policy revision has conflicting immutable originals")
        value=self._decode_v1(rows[0])
        from .d10_habit_ledger_v1 import HabitRetirementV1
        if type(value)is HabitRetirementV1:
            raise AuthorityUnavailable("Habit current policy head was retired; no fallback to an older grant")
        if value.definition.cancellation_generation!=floors[1]:
            raise AuthorityUnavailable("Habit current revision falls below actual historical cancellation floor")
        return value


    def _window_cue_inventory_v1(self,db,*,definition,permit,original,now):
        from .d10_habit_contract_v1 import HabitPolicyWindowCueInventoryV1,HabitWindowCueOriginalV1
        from .d10_habit_ledger_v1 import OCCURRENCE_TABLE,OCCURRENCE_COLUMNS,HabitRetirementV1
        from ..domains.d10.habit_occurrence_v1 import habit_window_v1
        from ..domains.d10.habit_policy_v1 import habit_policy_key_v1
        window,start,end=habit_window_v1(definition,max(now,definition.window_anchor_utc))
        stable=canonical_digest((self.namespace,definition.policy_id,window));ref='habit-window-cue:'+stable
        rows=db.execute('SELECT * FROM '+OCCURRENCE_TABLE+' WHERE authority_namespace=? AND installation_id=? AND original_commitment=?',
            (self.fences.namespace,self.installation_id,self._identity_v1('original',ref))).fetchmany(2)
        if len(rows)>1:raise AuthorityUnavailable('Habit exact stable clock original identity is not unique')
        refs=();digests=();kinds=()
        if rows:
            value=habit_ledger_decode_v1(OCCURRENCE_TABLE,OCCURRENCE_COLUMNS,rows[0],key=self._key,
                authority_namespace=self.fences.namespace,authority_id=self.core._id(db),installation_id=self.installation_id)
            if rows[0][2]!=self._identity_v1('policy',definition.policy_id):
                raise AuthorityUnavailable('Habit current-window clock original crossed actual policy identity')
            if type(value)is HabitWindowCueOriginalV1:
                if(value.selector.namespace,value.selector.policy_ref,value.selector.window_id,value.selector.window_start_utc,value.selector.window_end_utc)!=(
                        self.namespace,habit_policy_key_v1(self.namespace,definition.policy_id).token,window,start,end):
                    raise AuthorityUnavailable('Habit current new Definition window differs from actual prior immutable clock original')
                kind='window_cue'
            elif type(value)is HabitRetirementV1 and value.disposition=='cue_retired':kind='cue_retired'
            else:raise AuthorityUnavailable('Habit stable clock locator selected a different immutable row kind')
            refs=(ref,);digests=(value.digest,);kinds=(kind,)
        return HabitPolicyWindowCueInventoryV1(namespace=self.namespace,installation_id=self.installation_id,
            policy_ref=habit_policy_key_v1(self.namespace,definition.policy_id).token,definition_digest=canonical_digest(definition),
            operation_id=original.operation_id,permit_token=permit.token,standing_original_ref=original.original_ref,
            standing_original_digest=original.digest,window_id=window,window_start_utc=start,window_end_utc=end,
            core_cue_original_refs=refs,core_cue_record_digests=digests,core_cue_record_kinds=kinds)

    def _owner_v1(self,db,observed,permit):
        head=self.tickets.current_migration_head_in_tx(db,authority_namespace=self.fences.namespace)
        if (head is None or head.state!="active"or head.guard!=observed.guard or head.guard.authority_id!=permit.authority_id
                or head.guard.pending_revoke_operation_id is not None or head.guard.minimum_revocation_epoch
                or head.guard.minimum_revocation_revision>=head.guard.authorization_revision):
            raise AuthorityUnavailable("Habit current Owner original changed")
        return head

    def _epoch_v1(self,db,head):
        row=db.execute("SELECT revocation_epoch FROM authority_owner_session_principals_v1 "
            "WHERE authority_namespace=? AND installation_id=? AND principal_json=?",
            (self.fences.namespace,self.installation_id,_principal(head.issue_operation.principal))).fetchone()
        return 0 if row is None else row[0]

    def change(self,*,credential,subject,permit,actor,session_token,session_request,operation_id,action,definition):
        if (type(permit)is not FencePermitV2 or permit.operation!="write"or type(session_request)is not OwnerSessionLoginRequestV1
                or session_request.audience!="owner"or type(definition)is not HabitPolicyDefinitionV1
                or definition.namespace!=self.namespace or action not in{"issue","revise","revoke"}
                or type(operation_id)is not str or not operation_id.startswith("habit-policy:")or not operation_id.removeprefix("habit-policy:") or self._current is None):
            raise AuthorityUnavailable("Habit change requires actual Owner session WRITE and typed Definition")
        observed,returned=self.owner_service.get_current_owner_authority_for_fence_v1(
            credential=credential,subject=subject,permit=permit,actor=actor,session_token=session_token,session_request=session_request)
        if returned!=permit:raise AuthorityUnavailable("Habit change changed original Owner WRITE permit")
        root=self._current.qualify_standing_definition_v1(credential=credential,subject=subject,permit=permit,
            definition=definition,operation_id=operation_id)
        try:
            from .habit_authority_source_read_v3 import habit_standing_source_closure_versions_v1
            source_closure=habit_standing_source_closure_versions_v1(root)
            now=self._clock()
            with self.fences._frozen()as(db,deletion,execution,_):
                anchor=self.fences._current_locked(db,deletion,execution)
                self.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
                self.tickets._owner_sessions.require_current_in_tx(db,token=session_token,request=session_request)
                head=self._owner_v1(db,observed,permit);epoch=self._epoch_v1(db,head)
                self._current.require_standing_root_v1(root,definition=definition,permit=permit,owner=head)
                current=self._head_v1(db,definition.policy_id)
                old=db.execute("SELECT * FROM "+TABLE+" WHERE authority_namespace=? AND installation_id=? AND operation_commitment=?",
                    (self.fences.namespace,self.installation_id,self._identity_v1("operation",operation_id))).fetchone()
                if old is not None:
                    value=self._decode_v1(old)
                    if (value is not None and (value.definition,value.action,value.owner_actor_id,value.owner_head_digest,
                            value.owner_authorization_revision,value.owner_principal_epoch)!=(definition,action,actor,
                            head.guard.authorization_head,head.guard.authorization_revision,epoch)
                            or current!=value):
                        raise AuthorityUnavailable("Habit exact operation replay differs")
                    return value,self._window_cue_inventory_v1(db,definition=definition,permit=permit,original=value,now=now)
                if action=="issue":
                    if current is not None or definition.revision!=1:
                        raise AuthorityUnavailable("Habit issue requires its absent exact first policy revision")
                elif action=="revise":
                    if (current is None or current.action=="revoke"or definition.revision!=current.definition.revision+1
                            or (definition.parent_root_grant_ref,definition.parent_root_grant_id,definition.parent_root_grant_version,
                                definition.parent_root_grant_digest)!=(current.definition.parent_root_grant_ref,current.definition.parent_root_grant_id,
                                current.definition.parent_root_grant_version,current.definition.parent_root_grant_digest)
                            or definition.original_valid_until_utc>current.definition.original_valid_until_utc
                            or definition.cancellation_generation<current.definition.cancellation_generation):
                        raise AuthorityUnavailable("Habit revision changed original Root/deadline/cancellation lineage")
                elif(current is None or current.action=="revoke"or definition.state!="stopped"
                        or definition.revision!=current.definition.revision+1
                        or definition.cancellation_generation!=current.definition.cancellation_generation+1
                        or(definition.parent_root_grant_ref,definition.parent_root_grant_id,definition.parent_root_grant_version,
                            definition.parent_root_grant_digest)!=(current.definition.parent_root_grant_ref,current.definition.parent_root_grant_id,
                            current.definition.parent_root_grant_version,current.definition.parent_root_grant_digest)
                        or definition.original_valid_until_utc>current.definition.original_valid_until_utc):
                    raise AuthorityUnavailable("Habit revoke requires one exact next stopped revision within original Root/TTL")
                if now>=definition.original_valid_until_utc:raise AuthorityUnavailable("Habit original absolute deadline expired")
                material=dict(authority_namespace=self.fences.namespace,authority_id=self.core._id(db),
                    installation_id=self.installation_id,namespace=self.namespace,definition=definition,root_lease_id=root.root_lease_id,
                    root_grant=root.root_grant,source_closure_versions=source_closure,
                    target_commitment=habit_scope_identity_commitment_v1(self._key,"target",self.namespace,self.installation_id,definition.target_ref),
                    project_commitment=habit_scope_identity_commitment_v1(self._key,"project",self.namespace,self.installation_id,definition.project_ref),
                    owner_principal=head.issue_operation.principal,owner_actor_id=actor,
                    owner_head_digest=head.guard.authorization_head,owner_authorization_revision=head.guard.authorization_revision,
                    owner_principal_epoch=epoch,operation_id=operation_id,action=action,issued_at_utc=now,
                    schema="d10.habit-standing-policy-original.v1")
                wire={**material,"namespace":asdict(self.namespace),"definition":habit_policy_definition_to_wire_v1(definition),
                    "root_grant":asdict(root.root_grant),"source_closure_versions":[asdict(v)for v in source_closure],
                    "owner_principal":asdict(head.issue_operation.principal)}
                value=HabitStandingPolicyOriginalV1(**material,signature=self._sign_v1(wire))
                payload=canonical_serialize(habit_standing_policy_original_to_wire_v1(value))
                if len(payload.encode("utf8"))>MAX_PAYLOAD_BYTES:raise AuthorityUnavailable("Habit standing payload exceeds original fixed row resource admission")
                db.execute("INSERT INTO "+TABLE+" VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(value.authority_namespace,value.installation_id,
                    self._identity_v1("policy",definition.policy_id),definition.revision,definition.cancellation_generation,
                    self._identity_v1("operation",operation_id),"policy_"+action,payload,value.digest,value.signature,value.target_commitment,value.project_commitment))
                return value,self._window_cue_inventory_v1(db,definition=definition,permit=permit,original=value,now=now)
        finally:root.release_v3()

    def read_current(self,*,credential,subject,permit,policy_id):
        if type(permit)is not FencePermitV2 or permit.operation not in{"read","write"}:
            raise AuthorityUnavailable("Habit current original requires its actual borrowed read/write permit")
        observed,returned=self.owner_service.get_current_background_owner_authority_for_fence_v1(
            credential=credential,subject=subject,permit=permit)
        if returned!=permit:raise AuthorityUnavailable("Habit current original changed Owner permit")
        now=self._clock()
        with self.fences._frozen()as(db,deletion,execution,_):
            anchor=self.fences._current_locked(db,deletion,execution)
            self.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
            head=self._owner_v1(db,observed,permit);value=self._head_v1(db,policy_id)
            if (value is None or value.action=="revoke"or value.authority_id!=self.core._id(db)
                    or value.owner_principal!=head.issue_operation.principal or value.owner_head_digest!=head.guard.authorization_head
                    or value.owner_authorization_revision!=head.guard.authorization_revision
                    or value.owner_principal_epoch!=self._epoch_v1(db,head)or now>=value.definition.original_valid_until_utc):
                return None
            return value
