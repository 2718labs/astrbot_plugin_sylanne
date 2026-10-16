"""Fixed C4 recipe metadata on the actual original Foreground Authority Work.

The pure composer chooses locators; this private state authenticates each
complete canonical EOF. No projected object is a Graph Body or permission.
"""
from weakref import WeakKeyDictionary
from .contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime.artifact_recipe_metadata_v3 import(ArtifactMetadataLocatorV3,ArtifactMetadataLocatorNeededV3,
    ArtifactRecipeMetadataV3,compose_artifact_borrowed_metadata_plan_v3,artifact_recipe_metadata_retain_path_v3)
from ..runtime.artifact_joint_recipe_metadata_v3 import(augment_artifact_joint_business_metadata_plan_v3,
    artifact_joint_business_metadata_path_v3,artifact_joint_registered_metadata_profile_v3,
    artifact_joint_registration_request_frame_v3,artifact_joint_registration_request_digest_v3)
from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .original_foreground_source_read_v3 import(require_original_foreground_work_v3,_reserve,_locator_sources_v3)

_STATES=WeakKeyDictionary()
_COLUMNS=WeakKeyDictionary()
_MODEL_KINDS=frozenset({'prepare_artifact_draft_model','acquire_artifact_draft_model',
    'prepare_artifact_draft_model_v2','acquire_artifact_draft_model_v2'})

class _OriginalArtifactColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self,state,locator,*,table,column,keys,key,cell=None,domain=None,full_control=False,signature=None):
        self.state,self.locator,self.domain,self.full_control=state,locator,domain,full_control
        self.signer=state.work.service.issuer._signer;self.signature_kind,self.signature=(None,None)if signature is None else signature
        self.signature_state=None;self.signature_bytes=0;self.signature_verified=False
        self.registration_request_digest=None;self.registration_hasher=None;self.registration_suffix=b''
        if locator.family=='joint_registered':
            frame=artifact_joint_registration_request_frame_v3(locator.kind,locator.ref)
            if frame is not None:
                from hashlib import sha256
                self.registration_hasher=sha256(frame[0]);self.registration_suffix=frame[1]
        super().__init__(state.work,table=table,column=column,key_columns=keys,key=key,cell_id=cell)
        from .named_joint_binding_source_read_v3 import _MetadataStreamV3
        base=_MetadataStreamV3(self,self.cell is None or self.cell.header[0]=='canonical-json.ascii.v1')
        self.stream=base
        column_owner=self
        class Stream:
            def feed(self,fragment,emit):
                if column_owner.registration_hasher is not None:column_owner.registration_hasher.update(fragment)
                if column_owner.signature_state is not None:
                    column_owner.signature_state.update(fragment);column_owner.signature_bytes+=len(fragment)
                base.feed(fragment,emit)
            def finish(self):return base.finish()
        self.parser=Stream();_COLUMNS[self]=state
        if signature is not None:self.signature_state=self.signer.begin_original_stream_verification_v3(self.signature_kind,self)
    def _emit(self,event):
        keep=True if self.full_control else artifact_joint_business_metadata_path_v3(self.locator,event.path,actual_domain_kind=self.domain)
        if keep is None:keep=artifact_recipe_metadata_retain_path_v3(self.locator,event.path,actual_domain_kind=self.domain)
        keep=keep or self.locator.family=='relationship_policy'and event.path==('schema_version',)
        if keep:super()._emit(event)
    def finish_v3(self):
        self.state.require_v3()
        value=self.require_v3(self.owner)
        if self.signature_kind is not None and not self.signature_verified:
            self.signer.finish_original_stream_verification_v3(self.signature_kind,self.signature,self,self.signature_state)
            self.signature_verified=True
        if self.locator.family=='joint_registered':
            if self.registration_hasher is not None:
                framed=self.registration_hasher.copy();framed.update(self.registration_suffix)
                self.registration_request_digest=framed.hexdigest()
            else:self.registration_request_digest=artifact_joint_registration_request_digest_v3(self.locator.kind,value)
        return value,self.stream.semantic.hexdigest()


def require_original_artifact_signature_column_v3(column,*,signer,kind,signature=None,verifier=None,complete=False):
    if type(column)is not _OriginalArtifactColumnV3 or _COLUMNS.get(column)is not column.state:
        raise AuthorityUnavailable('Actual original Artifact metadata signature column required')
    state=column.state;state.require_v3()
    fixed=(column.locator.family=='relationship_policy'and kind in{'d11.d05-production-policy.v1','d11.d05-production-policy.v2'})
    if column.locator.family=='joint_registered':
        table,kinds,sign_kind,domain,operation=artifact_joint_registered_metadata_profile_v3(column.locator.kind)
        fixed=(column.table==table and column.column=='payload_json'and column.key_columns==('bot','persona','original_ref')
            and column.key==(*state.work.namespace.as_tuple,column.locator.ref)and kind==sign_kind)
    if(not fixed or signer is not state.work.service.issuer._signer or column.signer is not signer or column.signature_kind!=kind):
        raise AuthorityUnavailable('Original Artifact policy signature escaped its fixed exact profile')
    if complete and(not column.complete or column.signature!=signature or column.signature_state is not verifier
            or column.signature_bytes!=(column.cell.header[3]if column.cell is not None else column.total)):
        raise AuthorityUnavailable('Original Artifact policy signature did not reach actual raw-byte whole EOF')
    return column

class OriginalArtifactRecipeMetadataV3:
    def __init__(self,metadata):
        work=metadata.work;require_original_foreground_work_v3(work)
        if work.original_profile!='original-foreground-source.v1'or work.request.operation_kind not in _MODEL_KINDS:
            raise AuthorityUnavailable('Exact original C4 model command profile required')
        self.metadata,self.work=metadata,work
        self.values={};self.locator=None;self.phase='select';self.column=None;self.complete=False
        self.cursor='';self.rows=[];self.domain_ref_matches={};self.domain_headers={};self.life_headers={}
        self.plan=None;self.item=None;self.parts={};self.part_names=[];self.domain_scan_index=0
        self.joint_pending={};self.joint_observation_refs=[];self.joint_observation_cursor='';self.joint_observation_complete=False
        from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v1,artifact_draft_model_ids_v2
        selector=metadata.actual_selector;phase=work.request.operation_kind.endswith('_v2')
        ids=artifact_draft_model_ids_v2(selector)if phase else artifact_draft_model_ids_v1(selector)
        self.supplemental=[ArtifactMetadataLocatorV3('life','c4_phase_prepared'if phase else'c4_prepared',ids['job'])]
        if work.request.operation_kind.startswith('acquire_'):
            self.supplemental.append(ArtifactMetadataLocatorV3('life','c4_phase_frozen'if phase else'c4_frozen',ids['frozen']))
        if phase:
            from ..runtime.artifact_phase_postconditions_v1 import artifact_phase_postcondition_contract_ref_v1,CONTRACT_KIND
            metadata.signed.add((CONTRACT_KIND,artifact_phase_postcondition_contract_ref_v1(selector)))
        _STATES[work]=self
    def require_v3(self):
        require_original_foreground_work_v3(self.work)
        if _STATES.get(self.work)is not self or self.work.original_metadata is not self.metadata:
            raise AuthorityUnavailable('Original C4 recipe metadata lost actual Work/private profile')
    def _open(self,*,table,column,keys,key,cell=None,domain=None,full_control=False,signature=None):
        self.column=_OriginalArtifactColumnV3(self,self.locator,table=table,column=column,keys=keys,key=key,
            cell=cell,domain=domain,full_control=full_control,signature=signature)
    def _store(self,value):
        self.values[self.locator]=value;self.locator=None;self.phase='select';self.cursor='';self.rows=[];self.parts={}
        _reserve(self.work,(self.values,self.rows,self.domain_headers,self.life_headers))
    def _negative(self):self._store(None)
    def _head(self,ref,row,raw):
        key=AtomKey.from_token(ref);m=self.metadata
        m.heads[ref]=row;m.rows[ref]=raw;m.exact.add(ref)
        m.roots.update(_locator_sources_v3(raw))
        from .original_foreground_source_read_v3 import _CONTEXT_TYPES
        from ..domains.d05.relationship_revision_v2 import ESTIMATE_TYPE
        if key.type_name in _CONTEXT_TYPES or key.type_name==ESTIMATE_TYPE:m.context_roots.update(_locator_sources_v3(raw))
        return GraphVersion(key,row[0]),bool(row[1]),raw
    def _select(self):
        while self.supplemental:
            locator=self.supplemental.pop(0)
            if locator not in self.values:self.locator=locator;self.phase='header';return
        try:
            self.plan=compose_artifact_borrowed_metadata_plan_v3(namespace=self.work.namespace,
                operation_kind=self.work.request.operation_kind,activity_id=self.work.request.activity_id,
                metadata=ArtifactRecipeMetadataV3(self.values),request=self.metadata.actual_request,
                actual_selector=self.metadata.actual_selector)
            self.plan=augment_artifact_joint_business_metadata_plan_v3(namespace=self.work.namespace,
                phase=self.metadata.actual_selector,plan=self.plan,metadata=ArtifactRecipeMetadataV3(self.values))
            # This Authority observer does not mint a Host PersonalMeshIssuance.
            # The Mesh wrapper adds no locators for this original profile;
            # Host applies the existing helper to its actual issued object.
        except ArtifactMetadataLocatorNeededV3 as needed:
            self.locator=needed.locator;self.phase='header';return
        m=self.metadata;p=self.plan
        m.candidate_evidence_plan=p;m.roots.update(p.source_roots);m.required_originals.update(p.required_original_refs)
        for key in p.exact_keys:
            if NamespaceId.from_key(key)!=self.work.namespace:raise AuthorityUnavailable('Original recipe exact key crossed namespace')
            if key.type_name=='memory.source':m.roots.add(key.token)
            if key.token not in m.exact:m.exact.add(key.token);m.pending.append(key.token)
        m.family_types.update(p.fixed_type_ids)
        m.original_cursor='';m.producer_scan_index=0;m.producer_scan_complete=False
        self.complete=True
    def advance(self,meter):
        self.require_v3();w=self.work;m=self.metadata;ns=w.namespace.as_tuple
        if self.complete:return
        if self.column is not None:
            if not self.column.advance(meter):return
            raw,digest=self.column.finish_v3();registration_digest=self.column.registration_request_digest
            _COLUMNS.pop(self.column,None);self.column=None
            self._consume(raw,digest,registration_digest=registration_digest);return
        if self.phase=='select':self._select();return
        loc=self.locator
        if loc.family in{'graph','inventory'}:
            if loc.family=='graph':
                key=AtomKey.from_token(loc.ref)
                if NamespaceId.from_key(key)!=w.namespace or key.type_name!=loc.kind:raise AuthorityUnavailable('Original C4 exact metadata key differs')
                row=meter.read_fixed_row(w.db,'graph_atoms',('revision','valid','value_cell_id'),'token=?',(loc.ref,))
                if row is None:m.heads[loc.ref]=(0,0,None);m.exact.add(loc.ref);self._negative();return
                self.item=(loc.ref,row)
            else:
                row=meter.read_fixed_row(w.db,'graph_atoms',('token','revision','valid','value_cell_id'),
                    'bot=? AND persona=? AND type_name=? AND token>? ORDER BY token',(*ns,loc.kind,self.cursor))
                if row is None:
                    m.families[loc.kind]=[version for version,valid,value in self.rows];m.family_eof.add(loc.kind)
                    self._store(tuple(self.rows));return
                self.cursor=row[0];self.item=(row[0],row[1:])
            ref,head=self.item
            if len(self.rows)>=128:raise AuthorityUnavailable('Original recipe family exceeds the unchanged original evidence bound')
            actual=ArtifactMetadataLocatorV3('graph',AtomKey.from_token(ref).type_name,ref)
            # Inventory is an EOF of the same fixed per-type metadata profile.
            self.column=_OriginalArtifactColumnV3(self,actual,table='graph_atoms',column='value',keys=('token',),key=(ref,),cell=head[2])
            self.phase='graph_value';return
        if loc.family=='history':
            row=meter.read_fixed_row(w.db,'graph_history',('event_id','valid','value_cell_id','event_bot','event_persona'),
                'token=? AND revision=?',(loc.ref,loc.revision))
            if row is None:self._negative();return
            if row[3:]!=ns:raise AuthorityUnavailable('Original Artifact historical producer crossed namespace')
            if loc.kind=='event':self._store({'event_id':row[0]});return
            self.item=row
            self._open(table='graph_history',column='value',keys=('token','revision'),key=(loc.ref,loc.revision),cell=row[2]);return
        if loc.family=='installation':
            # InstalledCurrentForegroundActivityV1 actually passes no Host readers.
            if(loc.kind,loc.ref)!=('personal_candidate','current'):raise AuthorityUnavailable('No actual original installation metadata profile')
            self._store({'reader_present':False});return
        if loc.family=='job':
            row=meter.read_fixed_row(w.db,'runtime_jobs',('bot_id','persona_id','activity_id','operation_id'),'job_id=?',(loc.ref,))
            if row is None:self._negative();return
            if row[:2]!=ns:raise AuthorityUnavailable('Original Artifact job metadata crossed namespace')
            self.item=row;m.job_ids.add(loc.ref)
            self._open(table='runtime_jobs',column='continuation_json',keys=('job_id',),key=(loc.ref,));return
        if loc.family in{'life','life_header','artifact_milestone'}:
            from ..runtime.artifact_task_observer_v1 import ARTIFACT_TASK_MILESTONE_KIND_V2
            kind=ARTIFACT_TASK_MILESTONE_KIND_V2 if loc.family=='artifact_milestone'else loc.kind
            key=(*ns,kind,loc.ref)
            row=meter.read_fixed_row(w.db,'graph_d11_life_originals_v1',('producing_operation_id','payload_digest','signature'),
                'bot=? AND persona=? AND kind=? AND original_ref=?',key)
            if row is None:
                m.originals['life',kind,loc.ref]=None;self._negative();return
            cached=self.life_headers.get((kind,loc.ref))
            if loc.family=='life_header'and cached is not None:
                if cached!=(row[0],row[1],row[2]):raise AuthorityUnavailable('Original Life header changed after complete EOF')
                self._store({'operation_id':row[0],'payload_digest':row[1],'signature':row[2]});return
            # A header request first traverses the corresponding signed Body metadata EOF.
            self.item=(kind,row)
            profile=ArtifactMetadataLocatorV3('life',kind,loc.ref)if loc.family=='life_header'else loc
            self.column=_OriginalArtifactColumnV3(self,profile,table='graph_d11_life_originals_v1',column='payload_json',
                keys=('bot','persona','kind','original_ref'),key=key);return
        if loc.family=='domain':
            from ..runtime.domain_production_originals_v1 import TABLE,PHYSICAL_TABLE
            if loc.kind=='original_ref':
                if self.domain_scan_index<2:
                    table=(TABLE,PHYSICAL_TABLE)[self.domain_scan_index]
                    row=meter.read_fixed_row(w.db,table,('operation_id','domain','original_digest'),
                        'bot=? AND persona=? AND operation_id>? ORDER BY operation_id',(*ns,self.cursor))
                    if row is None:self.domain_scan_index+=1;self.cursor='';return
                    self.cursor=row[0]
                    if row[1]+'-current:'+row[2][:48]==loc.ref:
                        prior=self.domain_ref_matches.setdefault(loc.ref,row[0])
                        if prior!=row[0]:raise AuthorityUnavailable('Original Artifact domain ref has ambiguous producers')
                    return
                operation=self.domain_ref_matches.get(loc.ref)
                if operation is None:self.domain_scan_index=0;self._negative();return
            elif loc.kind=='operation':operation=loc.ref
            else:raise AuthorityUnavailable('Unregistered original Domain metadata locator')
            self.domain_scan_index=0
            header_columns=('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest')
            table=TABLE;row=meter.read_fixed_row(w.db,table,header_columns,'bot=? AND persona=? AND operation_id=?',(*ns,operation));cell=None
            if row is None:
                table=PHYSICAL_TABLE;physical=meter.read_fixed_row(w.db,table,(*header_columns,'original_payload_cell_id'),
                    'bot=? AND persona=? AND operation_id=?',(*ns,operation))
                if physical is not None:row=physical[:6];cell=physical[6]
            if row is None:self._negative();return
            bundle=meter.read_fixed_row(w.db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
                'bot=? AND persona=? AND operation_id=?',(*ns,operation))
            if bundle is None or bundle[0]!=row[4]or type(bundle[3])is not int or bundle[3]<1:
                raise AuthorityUnavailable('Original Artifact Domain metadata has no actual positive W01 COMMIT')
            self.item=(table,operation,row,bundle);self.parts={};self.part_names=['read_versions_json','receipt_json']
            self.phase='domain_payload'
            self._open(table=table,column='original_payload_json'if cell is None else'original_payload_cell_id',
                keys=('bot','persona','operation_id'),key=(*ns,operation),cell=cell,domain=row[:2]);return
        if loc.family=='joint_registered_index':
            if(loc.kind,loc.ref)!=('external_observations','all'):
                raise AuthorityUnavailable('Unregistered original Joint fixed metadata inventory')
            if not self.joint_observation_complete:
                table,kinds,sign_kind,domain,operation=artifact_joint_registered_metadata_profile_v3('external_observation')
                row=meter.read_fixed_row(w.db,table,('original_ref',),
                    'bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref',
                    (*ns,kinds[0],self.joint_observation_cursor))
                if row is not None:
                    if len(self.joint_observation_refs)>=128:raise AuthorityUnavailable('Original Joint external metadata exceeds formal 128-row bound')
                    self.joint_observation_cursor=row[0];self.joint_observation_refs.append(row[0]);_reserve(w,self.joint_observation_refs);return
                self.joint_observation_complete=True
            for ref in self.joint_observation_refs:
                child=ArtifactMetadataLocatorV3('joint_registered','external_observation',ref)
                if child not in self.values:self.locator=child;self.phase='header';return
            self._store(tuple((ref,self.values[ArtifactMetadataLocatorV3('joint_registered','external_observation',ref)]['payload'])
                for ref in self.joint_observation_refs));return
        if loc.family=='joint_registered':
            table,kinds,sign_kind,domain,operation=artifact_joint_registered_metadata_profile_v3(loc.kind)
            if loc in self.joint_pending:
                payload,header,registration_digest=self.joint_pending[loc]
                producer=ArtifactMetadataLocatorV3('domain','operation',header[1])
                if producer not in self.values:self.locator=producer;self.phase='header';return
                original=self.values[producer]
                if(original is None or(original['domain'],original['operation_kind'])!=(domain,operation)
                        or original['request_digest']!=registration_digest):
                    raise AuthorityUnavailable('Original Joint signed metadata has no exact formal same-W01 producer')
                self.joint_pending.pop(loc)
                self._store({'payload':payload,'payload_digest':header[2],'operation_id':header[1],
                    'request_digest':original['request_digest']});return
            columns=('kind','producing_operation_id','payload_digest','signature')if kinds else('producing_operation_id','payload_digest','signature')
            row=meter.read_fixed_row(w.db,table,columns,'bot=? AND persona=? AND original_ref=?',(*ns,loc.ref))
            if row is None:self._negative();return
            header=tuple(row)if kinds else(sign_kind,*row)
            if kinds and header[0]not in kinds:raise AuthorityUnavailable('Original Joint metadata row kind differs from fixed typed locator')
            self.item=(table,header)
            self._open(table=table,column='payload_json',keys=('bot','persona','original_ref'),key=(*ns,loc.ref),
                signature=(sign_kind,header[3]));return
        if loc.family=='relationship_policy':
            row=meter.read_fixed_row(w.db,'graph_d05_production_policies_v1',('revision','payload_digest','signature'),
                'bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC',(*ns,loc.ref))
            if row is None:self._negative();return
            self.item=row
            self._open(table='graph_d05_production_policies_v1',column='payload_json',keys=('bot','persona','policy_ref','revision'),
                key=(*ns,loc.ref,row[0]));return
        raise AuthorityUnavailable('Pure C4 original metadata requested a family outside the actual installed reader profile')
    def _consume(self,raw,digest,*,registration_digest=None):
        w=self.work;m=self.metadata;loc=self.locator
        if loc.family in{'graph','inventory'}:
            ref,row=self.item;value=self._head(ref,row,raw)
            if loc.family=='graph':self._store(value)
            else:self.rows.append(value);self.phase='header'
            return
        if loc.family=='history':
            row=self.item;m.history_heads[loc.ref,loc.revision]=(row[1],row[2]);m.roots.update(_locator_sources_v3(raw))
            self._store({'event_id':row[0],'value':raw});return
        if loc.family=='job':
            row=self.item;self._store({'activity_id':row[2],'operation_id':row[3],'continuation':raw});return
        if loc.family in{'life','life_header','artifact_milestone'}:
            from ..runtime.d11_life_preparation_v1 import SIGN_KIND
            kind,row=self.item
            if digest!=row[1]:raise AuthorityUnavailable('Original Artifact Life metadata canonical whole EOF differs')
            w.service.issuer._signer.verify(SIGN_KIND,canonical_serialize((w.namespace,kind,loc.ref,digest)),row[2])
            self.life_headers[kind,loc.ref]=row;m.producers.add(row[0]);m.originals['life',kind,loc.ref]=raw
            m.roots.update(_locator_sources_v3(raw))
            if loc.family=='life_header':self._store({'operation_id':row[0],'payload_digest':row[1],'signature':row[2]})
            else:self._store(raw)
            return
        if loc.family=='joint_registered':
            table,header=self.item
            if digest!=header[2]:raise AuthorityUnavailable('Original Joint signed metadata canonical/HMAC whole EOF differs')
            if 'namespace'in raw and raw['namespace']!={'bot_id':w.namespace.bot_id,'persona_id':w.namespace.persona_id}:
                raise AuthorityUnavailable('Original Joint signed metadata crossed actual namespace')
            self.joint_pending[loc]=(raw,header,registration_digest);self.phase='header';return
        if loc.family=='domain':
            table,operation,row,bundle=self.item
            if self.phase=='domain_payload':
                if(digest!=row[3]or raw['identity']!={'phase':row[1],'operation_id':operation}
                        or raw['namespace']!={'bot_id':w.namespace.bot_id,'persona_id':w.namespace.persona_id}):
                    raise AuthorityUnavailable('Original Artifact Domain payload identity/phase or canonical EOF differs')
                self.parts['payload']=raw
            else:self.parts[self.phase]=raw
            if self.part_names:
                name=self.part_names.pop(0);self.phase=name
                self._open(table=table,column=name,keys=('bot','persona','operation_id'),key=(*w.namespace.as_tuple,operation),full_control=True);return
            from ..runtime.domain_production_originals_v1 import _receipt
            reads=tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in self.parts['read_versions_json'])
            receipt=_receipt(self.parts['receipt_json'])
            if(receipt.status!='committed'or receipt.operation_id!=operation or receipt.read_versions!=reads or canonical_digest(receipt)!=row[5]
                    or(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq)!=bundle):
                raise AuthorityUnavailable('Original Artifact Domain metadata changed actual positive receipt/bundle')
            payload=self.parts['payload'];m.producers.add(operation);m.originals['producer',operation]=payload
            m.roots.update(_locator_sources_v3(payload))
            value={'domain':row[0],'operation_kind':row[1],'request_digest':row[2],'original_digest':row[3],'payload':payload,'read_versions':reads,'receipt':receipt}
            self.domain_headers[operation]=row
            self._store(value);return
        if loc.family=='relationship_policy':
            row=self.item
            if digest!=row[1]:raise AuthorityUnavailable('Original Artifact policy metadata canonical EOF differs')
            if self.phase!='policy_signature':
                kind='d11.d05-production-policy.v2'if raw.get('schema_version')==2 else'd11.d05-production-policy.v1'
                self.phase='policy_signature'
                self._open(table='graph_d05_production_policies_v1',column='payload_json',keys=('bot','persona','policy_ref','revision'),
                    key=(*w.namespace.as_tuple,loc.ref,row[0]),signature=(kind,row[2]));return
            m.context_roots.update(raw.get('policy_source_refs',()));m.roots.update(raw.get('policy_source_refs',()));self._store(raw);return
        raise AuthorityUnavailable('No actual original C4 metadata EOF consumer for fixed locator')


def read_bound_original_artifact_joint_observation_keys_v3(db,*,namespace,node_id):
    """Select refs from this Work's signed metadata EOF before original Body reads."""
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from .original_foreground_source_read_v3 import original_foreground_work_v3,require_original_foreground_body_v3
    work=_authority_attachment_owner_v3(db)
    if work is None or original_foreground_work_v3(work)is None:return False,None
    require_original_foreground_body_v3(work)
    state=_STATES.get(work)
    if state is None:raise AuthorityUnavailable('Original Joint observation selector has no actual recipe metadata state')
    state.require_v3()
    locator=ArtifactMetadataLocatorV3('joint_registered_index','external_observations','all')
    if namespace!=work.namespace or not state.complete or not state.joint_observation_complete or locator not in state.values:
        raise AuthorityUnavailable('Original Joint observation selector requires its completed signed whole inventory EOF')
    refs=tuple((ref,)for ref,value in state.values[locator]if value['node_id']==node_id)
    if any(ref not in state.plan.required_original_refs for(ref,)in refs):
        raise AuthorityUnavailable('Original Joint observation selector escaped its exact qualified business recipe')
    return True,refs


def release_original_artifact_recipe_metadata_v3(work):
    state=_STATES.pop(work,None)
    if state is None:return
    for column,owner in tuple(_COLUMNS.items()):
        if owner is state:_COLUMNS.pop(column,None)
    state.values.clear();state.rows.clear();state.domain_headers.clear();state.life_headers.clear();state.column=None
    state.joint_pending.clear();state.joint_observation_refs.clear()
