"""C09 Contact Plan3 birth joins on the actual frozen Graph-role Source.

Only the installed build may issue a reader. Historical bytes and query cuts
prove the producing CAS; they do not grant current Source use.
"""
from hashlib import sha256
from weakref import WeakKeyDictionary
import json

from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..graph_types import AtomKey
from .contact_plan_adoption_v3 import TABLE,COLUMNS,SIGN_KIND,contact_plan_logical_descriptor_v3,validate_contact_plan_original_payload_v3
from .domain_production_originals_v1 import PHYSICAL_TABLE,_receipt
from ..runtime_contracts import _canonical_value
from .c09_paged_sql_v2 import C09PagedCaptureHold,require_c09_reserved_meter_v3,c09_sql_meter_quantum_v2,read_legacy_sql_cell_fragment_v2
from .c09_graph_row_codec_v2 import _C09RegisteredGraphValueV3
from .owner_material_source_storage_v3 import CanonicalValueStreamV3

_ISSUER = object()
_BIRTHS = WeakKeyDictionary()


class _BirthCellV3:
    def __init__(self,reader,cell_id,descriptor,meter,*,retain_value=True):
        self.reader,self.cell_id,self.descriptor = reader,cell_id,descriptor
        self.header = reader.scope.read_cell_header_v3(cell_id,meter=meter)
        if (self.header[1],self.header[4],self.header[6])!=descriptor:
            raise C09PagedCaptureHold('Contact birth cell physical descriptor differs')
        from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
        self.retain_value = retain_value
        self.offset,self.complete,self.parser = 0,False,(_C09RegisteredGraphValueV3(
            source_arena=reader.scope.arena,ensure_ascii=descriptor[0]=='canonical-json.ascii.v1') if retain_value else
            C09MemorySourceJSONStreamV3(source_arena=reader.scope.arena,ensure_ascii=descriptor[0]=='canonical-json.ascii.v1'))
    def advance(self,meter):
        self.reader.require_current(meter)
        if self.offset<self.header[4]:
            fragment,total = self.reader.scope.read_cell_fragment_v3(self.cell_id,start=self.offset,
                length=min(1024,self.header[4]-self.offset),meter=meter)
            if total!=self.header[4] or not fragment:
                raise C09PagedCaptureHold('Contact birth physical fragment length differs')
            self.parser.feed(fragment,lambda event:None)
            self.offset += len(fragment)
            return False
        parsed = self.parser.finish()
        if (parsed.byte_count,parsed.sha256)!=(self.header[4],self.header[6]):
            raise C09PagedCaptureHold('Contact birth complete canonical/physical EOF differs')
        self.reader.scope.require_cell_eof_v3(self.cell_id,self.header[5],meter=meter)
        self.value,self.complete = self.parser.value if self.retain_value else None,True
        return True


class ContactPlanBirthReadV3:
    def __init__(self,issuer,build,row,origin,meter,*,actual_capture):
        from .c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
        if issuer is not _ISSUER or type(build) is not InstalledGraphRebaseBuildV2:
            raise C09PagedCaptureHold('actual installed Graph build Contact birth issuer required')
        build.require_current()
        from ..authority_service.c09_source_physical_read_v3 import SourcePhysicalReadScopeV3
        from .c09_contact_plan_physical_v3 import C09MappedContactPlanCaptureV3
        from .c09_graph_rebase_candidate_v2 import _actual_source_locator_v2
        from .c09_paged_sql_v2 import require_c09_capture_member_v2,require_c09_logical_source_row_member_v3
        if type(actual_capture) is not C09MappedContactPlanCaptureV3 or actual_capture.build is not build:
            raise C09PagedCaptureHold('Contact birth requires its actual independently recomputed physical Source producer')
        self.build,self.row,self.origin = build,tuple(row),origin
        self.scope = actual_capture.scope
        if (type(self.scope) is not SourcePhysicalReadScopeV3 or self.scope.session is not build.session
                or self.scope.pair is not build.pair or self.scope.role!='graph'
                or self.scope.source is not build.pair.source or self.scope.source_original is not build.pair.source_original
                or actual_capture.shape.table!=TABLE or actual_capture.shape.columns!=COLUMNS
                or actual_capture.shape.primary_key_columns!=('bot','persona','contact_id')
                or actual_capture.key!=tuple(row[:3]) or actual_capture.physical!=tuple(row)):
            raise C09PagedCaptureHold('Contact birth actual registered Graph-role session/pair/shape/row differs')
        self.scope.require_current(meter=meter)
        commitment=actual_capture.require_complete(build,actual_capture.shape,actual_capture.key,actual_capture.metadata)
        locator=_actual_source_locator_v2(build,actual_capture.shape,meter)
        if (locator.storage_role!='graph' or origin['stream_id']!=locator.identity.stream_id
                or origin['row_commitment']!=commitment):
            raise C09PagedCaptureHold('Contact birth actual full mapped row differs from sealed Source directory/member')
        require_c09_capture_member_v2(build.pair.candidate,locator.identity,origin['ordinal'],tuple(row[:3]),commitment,meter=meter)
        descriptor=require_c09_logical_source_row_member_v3(build.pair.candidate,locator.identity,role='graph',
            table_name=TABLE,key=tuple(row[:3]),record_ordinal=origin['ordinal'],meter=meter)
        if canonical_serialize(descriptor)!=canonical_serialize(actual_capture.row.result.descriptor):
            raise C09PagedCaptureHold('Contact birth actual whole cell/row descriptor differs from captured Source original')
        self.namespace = NamespaceId(row[0],row[1])
        if self.namespace.as_tuple!=tuple(json.loads(build.scope.graph_namespace)):
            raise C09PagedCaptureHold('Contact birth selected Source namespace differs')
        self.issuer = build.session.get_c09_domain_original_issuer_v2()
        self.issuer._signer.verify(SIGN_KIND,canonical_serialize(contact_plan_logical_descriptor_v3(row)),row[13])
        self.phase,self.pending,self.complete = 'payload',_BirthCellV3(self,row[4],(row[5],row[6],row[7]),meter),False
        self.writes,self.reads,self.read_index,self.query_index,self.after,self.query_rows = (),(),0,0,'',[]
        self.descriptor = None
        self.born_sources,self.born_atoms,self.source_purposes={},{},None
        self.scope.arena.add(self)
    def _source_heap_bytes(self):
        from .source_correction_read_v3 import _heap
        return 65536+_heap((self.born_sources,self.born_atoms,self.source_purposes,
            getattr(self,'payload',None),getattr(self,'domain',None),self.query_rows))
    def require_current(self,meter):
        self.build.require_current()
        self.scope.require_current(meter=meter)
        if self.scope.source_original is not self.build.pair.source_original:
            raise C09PagedCaptureHold('Contact birth actual captured Source identity changed')
    def _point(self,meter,table,columns,where,key):
        return meter.read_fixed_row(self.scope.source,table,columns,where,key)
    def advance(self,meter):
        self.require_current(meter)
        if self.pending is not None:
            if not self.pending.advance(meter):
                return
            pending,self.pending = self.pending,None
            if self.phase=='payload':
                self.payload = pending.value
                self.plan,self.expression,self.proof = validate_contact_plan_original_payload_v3(self.payload)
                if (self.plan.namespace,self.plan.contact_id,self.proof.producing_operation_id)!=(self.namespace,self.row[2],self.row[3]):
                    raise C09PagedCaptureHold('Contact birth logical payload identity differs')
                self.pending = _BirthCellV3(self,self.row[9],('canonical-json.ascii.v1',self.row[10],self.row[11]),meter)
                self.phase = 'selection'
            elif self.phase=='selection':
                selection = pending.value
                if (selection['schema']!='d10.contact-plan-source-selection.v3' or selection['plan']!=self.payload['plan']
                        or selection['business_deadline']!=self.payload['business_deadline']
                        or selection['contact_id']!=self.row[2] or selection['producing_operation_id']!=self.row[3]
                        or selection['proof']!={'schema':self.proof.schema,
                            'historical_reads':[{'ref':r.ref,'revision':r.revision,'valid':r.valid}for r in self.proof.historical_reads],
                            'current_reads':[{'ref':r.ref,'revision':r.revision,'valid':r.valid}for r in self.proof.current_reads]}):
                    raise C09PagedCaptureHold('Contact birth independent Source-selection metadata EOF differs from full original')
                purposes=selection['source_purposes']
                if (type(purposes)is not list or len(purposes)!=len(selection['source_refs'])
                        or [r['ref']for r in purposes]!=selection['source_refs']
                        or any(set(r)!={'ref','purposes'} or not r['purposes'] or r['purposes']!=sorted(set(r['purposes']))
                            or not set(r['purposes'])<={'expression','context'}for r in purposes)):
                    raise C09PagedCaptureHold('Contact birth signed per-ref Source purpose metadata coverage differs')
                self.source_purposes=tuple((row['ref'],tuple(row['purposes']))for row in purposes)
                self.birth_digest = CanonicalValueStreamV3(self.payload['birth_bundle'])
                self.phase = 'bundle_digest'
            elif self.phase=='domain':
                self.domain = pending.value
                self.phase = 'receipt'
            elif self.phase=='member':
                name,key,digest,value = self.writes[self.read_index]
                if pending.header[6]!=digest or pending.value!=value:
                    raise C09PagedCaptureHold('Contact birth actual three-member canonical payload differs')
                self.read_index += 1
            elif self.phase=='read':
                read = self.reads[self.read_index]
                if pending.header[6]!=read.payload_sha256:
                    raise C09PagedCaptureHold('Contact born read cell differs from its immutable physical commitment')
                if read.semantic_sha256 is not None and canonical_digest(pending.value)!=read.semantic_sha256:
                    raise C09PagedCaptureHold('Contact born nonSource semantic commitment differs')
                if AtomKey.from_token(read.ref).type_name=='memory.source':
                    self.born_sources[read.ref]=dict(pending.parser._source_metadata)
                elif read.valid:
                    self.born_atoms[read.ref]=pending.value
                self.read_index += 1
            else:
                raise C09PagedCaptureHold('Contact birth pending cell has another fixed phase')
            return
        if self.phase=='bundle_digest':
            self.birth_digest.read_fragment(meter)
            if not self.birth_digest.complete:
                return
            self.physical = self._point(meter,PHYSICAL_TABLE,
                ('domain','operation_kind','original_digest','original_payload_cell_id','prepared_digest',
                    'bundle_digest','receipt_digest'), 'bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,self.row[3]))
            if (self.physical is None or self.physical[:2]!=('d08','adopt_contact_expression_plan_v2')
                    or self.physical[5]!=self.birth_digest.hash.hexdigest() or self.physical[6]!=self.row[12]):
                raise C09PagedCaptureHold('Contact birth actual physical production receipt/bundle differs')
            header = self.scope.read_cell_header_v3(self.physical[3],meter=meter)
            self.pending = _BirthCellV3(self,self.physical[3],(header[1],header[4],self.physical[2]),meter)
            self.phase = 'domain'
            return
        if self.phase=='receipt':
            raw = self._point(meter,PHYSICAL_TABLE,('receipt_json',),'bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,self.row[3]))
            if raw is None:
                raise C09PagedCaptureHold('Contact birth actual receipt absent')
            self.receipt = _receipt(json.loads(raw[0]))
            self.receipt_digest = CanonicalValueStreamV3(_canonical_value(self.receipt,set()))
            self.phase = 'receipt_digest'
            return
        if self.phase=='receipt_digest':
            self.receipt_digest.read_fragment(meter)
            if not self.receipt_digest.complete:
                return
            from ..domains.d08.contact_plan_v3 import contact_plan_keys_v3
            from ..domains.d01.production_operations_v1 import plain_v1
            keys = contact_plan_keys_v3(self.plan)
            versions = tuple((version.key.token,version.revision)for version in self.receipt.write_versions)
            if (self.receipt_digest.hash.hexdigest()!=self.row[12] or self.payload['receipt_digest']!=self.row[12]
                    or self.receipt.operation_id!=self.row[3] or self.receipt.operation_digest!=self.physical[5]
                    or self.receipt.status!='committed' or set(versions)!={(key.token,1)for key in keys}
                    or {(r.ref,r.revision)for r in self.proof.historical_reads}!=
                        {(v.key.token,v.revision)for v in self.receipt.read_versions}
                    or self.domain['provenance']['proof']!=plain_v1(self.proof)):
                raise C09PagedCaptureHold('Contact birth actual complete receipt/readset/three-member joins differ')
            self.bundle = self._point(meter,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
                'bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,self.row[3]))
            if self.bundle!=(self.receipt.operation_digest,self.receipt.activity_id,self.receipt.effect_id,self.receipt.commit_seq):
                raise C09PagedCaptureHold('Contact birth actual shared W01 ledger differs')
            self.event = self._point(meter,'graph_events',('digest','reads','epoch_reads','revisions','epoch_revision'),
                'bot=? AND persona=? AND session=? AND event_id=?',(*self.namespace.as_tuple,self.receipt.activity_id,self.row[3]))
            if (self.event is None or json.loads(self.event[1])!=[[v.key.token,v.revision]for v in self.receipt.read_versions]
                    or json.loads(self.event[3])!=[[v.key.token,v.revision]for v in self.receipt.write_versions]):
                raise C09PagedCaptureHold('Contact birth actual Graph event/read/write originals differ')
            from ..contracts import Event,Scope
            expected_event = Event(Scope(*self.namespace.as_tuple,self.receipt.activity_id),self.row[3],
                self.domain['now_utc'],'domain_bundle',{'bundle_digest':self.receipt.operation_digest})
            if (self.event[0]!=expected_event.digest or self.event[2]!='[]'
                    or len(self.receipt.invalidated_epochs)!=1 or self.receipt.invalidated_epochs[0].revision!=self.event[4]):
                raise C09PagedCaptureHold('Contact birth producing event/epoch differs from its immutable W01 command')
            self.reads = self.proof.historical_reads
            self.birth_epoch = self.event[4]-1
            if any(query.epoch.revision!=self.birth_epoch for query in self.proof.query_coverage):
                raise C09PagedCaptureHold('Contact birth historical query cut differs from its actual producer')
            self.member_keys,self.member_values,self.member_headers,self.member_dependencies = keys,[plain_v1(self.plan),plain_v1(self.proof),None],[],[]
            self.read_index,self.phase = 0,'member_prepare'
            return
        if self.phase=='member_prepare':
            if self.read_index==3:
                self.read_index,self.phase = 0,'read_prepare'
                return
            key = self.member_keys[self.read_index]
            row = self._point(meter,'graph_history',('value_cell_id','valid','dependencies','event_bot','event_persona','event_session','event_id'),
                'token=? AND revision=?',(key.token,1))
            if row is None or row[1]!=1 or row[3:]!=(*self.namespace.as_tuple,self.receipt.activity_id,self.row[3]):
                raise C09PagedCaptureHold('Contact born member history/event identity differs')
            expected = self.member_values[self.read_index]
            if self.read_index==2:
                from ..domains.d08.contact_plan_v3 import ContactExpressionPlanEligibilityV3
                from ..runtime_contracts import VersionedRef
                from ..domains.d01.production_operations_v1 import plain_v1
                expected = plain_v1(ContactExpressionPlanEligibilityV3(self.namespace,VersionedRef(self.member_keys[0].token,1),
                    VersionedRef(self.member_keys[1].token,1),self.member_headers[1][6],self.row[3],
                    self.proof.activation_generation,self.proof.graph_incarnation,self.proof.current_reads))
            dependencies = json.loads(row[2])
            revisions = {r.ref:r.revision for r in self.proof.current_reads}
            revisions.update({key.token:1 for key in self.member_keys})
            wanted = set()if self.read_index<2 else {(ref,rev)for ref,rev in revisions.items()if ref!=key.token}
            if {tuple(edge)for edge in dependencies}!=wanted or len(dependencies)!=len(wanted):
                raise C09PagedCaptureHold('Contact born eligibility dependency edges differ')
            header = self.scope.read_cell_header_v3(row[0],meter=meter)
            self.member_headers.append(header)
            self.writes = tuple((*self.writes,(None,key,header[6],expected)))
            self.pending = _BirthCellV3(self,row[0],(header[1],header[4],header[6]),meter)
            self.phase = 'member'
            return
        if self.phase=='member':
            self.phase='member_prepare'
            return
        if self.phase=='read_prepare':
            if self.read_index==len(self.reads):
                from .contact_source_purposes_v3 import derive_contact_source_purpose_groups_metadata_v3
                from ..memory_types import access_key
                derived=derive_contact_source_purpose_groups_metadata_v3(self.namespace,self.payload['plan'],self.born_sources,self.born_atoms)
                if derived!=self.source_purposes:
                    raise C09PagedCaptureHold('Contact born purpose metadata differs from actual opportunity/route/boundary/ancestor read cut')
                for ref,purposes in derived:
                    source=self.born_sources[ref];key=AtomKey.from_token(ref)
                    access=self.born_atoms.get(access_key(*self.namespace.as_tuple,key.owner.subject).token)
                    if (access is None or access['status']!='active' or access['source_id']!=source['source_id']
                            or not set(purposes)<=set(source['purposes']) or not set(purposes)<=set(access['purposes'])
                            or self.plan.audience_id not in source['audiences'] or self.plan.audience_id not in access['audiences']):
                        raise C09PagedCaptureHold('Contact born Source rights do not support its exact independently derived purpose set')
                terms=self.payload['business_deadline']
                policy=self.born_atoms.get(self.payload['policy_ref'])
                opportunity=self.born_atoms.get(self.payload['opportunity_ref'])
                if (policy is None or opportunity is None
                        or policy['window_end']!=terms['policy_window_end_utc']
                        or policy['approval_ref']!=terms['policy_original_ref']
                        or opportunity['expires_at']!=terms['opportunity_expires_at_utc']
                        or canonical_digest(opportunity)!=terms['opportunity_digest']
                        or terms['raw_check_valid_until_utc']!=min(policy['window_end'],opportunity['expires_at'])):
                    raise C09PagedCaptureHold('Contact born business deadline differs from actual policy/opportunity read cut')
                from .issuers import _decode_grant
                original=self._point(meter,'runtime_budget_grants',('grant_json','signature'),
                    'lease_id=? AND version=?',(terms['parent_budget_lease_ref'],terms['root_grant_version']))
                if original is None:raise C09PagedCaptureHold('Contact born original Root grant absent')
                self.issuer._signer.verify('budget-grant.v1',original[0],original[1])
                grant=_decode_grant(original[0])
                if ((grant.bot_id,grant.persona_id)!=self.namespace.as_tuple
                        or (grant.lease_id,grant.version)!=(terms['parent_budget_lease_ref'],terms['root_grant_version'])
                        or grant.valid_until_utc!=terms['root_grant_valid_until_utc'] or canonical_digest(grant)!=terms['root_grant_digest']):
                    raise C09PagedCaptureHold('Contact business deadline original signed Root grant differs')
                self.phase='queries'
                return
            read = self.reads[self.read_index]
            latest = self.scope.source.execute('SELECT MAX(h.revision) FROM graph_history h JOIN graph_events e ON '
                '(h.event_bot,h.event_persona,h.event_session,h.event_id)=(e.bot,e.persona,e.session,e.event_id) '
                'WHERE e.bot=? AND e.persona=? AND e.epoch_revision<=? AND h.token=?',(*self.namespace.as_tuple,self.birth_epoch,read.ref)).fetchone()[0]
            meter.charge_read(8)
            if latest!= (read.revision if read.revision else None):
                raise C09PagedCaptureHold('Contact born read selected a different original query-cut revision')
            if not read.revision:
                self.read_index+=1
                return
            row = self._point(meter,'graph_history',('value_cell_id','valid'),'token=? AND revision=?',(read.ref,read.revision))
            if row is None or bool(row[1])!=read.valid:
                raise C09PagedCaptureHold('Contact born read valid/member metadata differs')
            self.pending = _BirthCellV3(self,row[0],(read.codec,read.byte_count,read.payload_sha256),meter,
                retain_value=read.semantic_sha256 is not None)
            self.phase='read'
            return
        if self.phase=='read':
            self.phase='read_prepare'
            return
        if self.phase=='queries':
            if self.query_index==len(self.proof.query_coverage):
                self.descriptor = {'schema':'d10.contact-plan-born-proof.v3','scope_digest':self.build.scope.scope_digest,
                    'source_role_digest':self.scope.source_original.role_source_digest,'plan_key':self.row[:3],
                    'logical_payload_digest':self.row[8],'source_selection_digest':self.row[11],
                    'producing_operation_id':self.row[3],'receipt_digest':self.row[12],
                    'bundle_digest':self.physical[5],'birth_epoch':self.birth_epoch,'origin':self.origin}
                self.complete=True
                _BIRTHS[self]=(self.build,self.scope,self.row,self.origin,canonical_digest(self.descriptor))
                return
            query = self.proof.query_coverage[self.query_index]
            sql=('WITH latest AS (SELECT h.token,MAX(h.revision) AS revision FROM graph_history h JOIN graph_events e ON '
                '(h.event_bot,h.event_persona,h.event_session,h.event_id)=(e.bot,e.persona,e.session,e.event_id) '
                "WHERE e.bot=? AND e.persona=? AND e.epoch_revision<=? AND h.token>? AND json_extract(h.token,'$[4]')=? GROUP BY h.token) "
                'SELECT token,revision FROM latest ORDER BY token LIMIT 1')
            found=self.scope.source.execute(sql,(*self.namespace.as_tuple,self.birth_epoch,self.after,query.type_id)).fetchone()
            meter.charge_read(8 if found is None else len(found[0].encode())+32)
            if found is not None:
                self.query_rows.append(found);self.after=found[0]
                return
            if tuple(self.query_rows)!=tuple((v.key.token,v.revision)for v in query.row_versions):
                raise C09PagedCaptureHold('Contact born complete historical positive/negative query keyset differs')
            self.query_index+=1;self.query_rows=[];self.after=''
            return
        raise C09PagedCaptureHold('Contact birth reader has no other closed phase')
    def require_complete(self,build,meter):
        self.require_current(meter)
        if (build is not self.build or not self.complete
                or _BIRTHS.get(self)!=(self.build,self.scope,self.row,self.origin,canonical_digest(self.descriptor))):
            raise C09PagedCaptureHold('Contact Plan birth requires its actual same-build whole historical EOF proof')
        return self.descriptor


def advance_contact_plan_birth_v3(build):
    from .c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2,_actual_source_locator_v2
    from .c09_paged_sql_v2 import read_c09_table_shape_v2,require_c09_capture_member_v2
    if type(build) is not InstalledGraphRebaseBuildV2:
        raise C09PagedCaptureHold('actual Graph-role build required for Contact birth advancement')
    build.require_current()
    if build.contact_plan_birth_complete_v3:
        return False
    saved_after,saved_complete = build.contact_plan_birth_after_v3,build.contact_plan_birth_complete_v3
    saved_proofs = dict(build.contact_plan_birth_proofs_v3)
    try:
        return _advance_contact_plan_birth_quantum_v3(build)
    except BaseException:
        build.contact_plan_birth_reader_v3 = None
        build.contact_plan_birth_capture_v3 = None
        build.contact_plan_birth_after_v3,build.contact_plan_birth_complete_v3 = saved_after,saved_complete
        build.contact_plan_birth_proofs_v3 = saved_proofs
        raise


def _advance_contact_plan_birth_quantum_v3(build):
    from .c09_graph_rebase_candidate_v2 import _actual_source_locator_v2
    from .c09_paged_sql_v2 import read_c09_table_shape_v2,require_c09_capture_member_v2
    prospective_capture=None
    with build.session.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            scope = build.session.begin_source_physical_read_v3(build.pair,meter=meter)
            with scope.read_database_v3(meter=meter):
                exists=meter.read_fixed_row(build.pair.source,'sqlite_master',('name',),'type=? AND name=?',('table',TABLE))
                if exists is None:
                    build.contact_plan_birth_complete_v3=True
                    return False
                reader=build.contact_plan_birth_reader_v3
                if reader is None:
                    row=meter.read_fixed_row(build.pair.source,TABLE,COLUMNS,'(bot,persona,contact_id)>(?,?,?) ORDER BY bot,persona,contact_id',
                        build.contact_plan_birth_after_v3)
                    if row is None:
                        build.contact_plan_birth_complete_v3=True
                        return False
                    shape=read_c09_table_shape_v2(build.pair.source,TABLE,meter=meter)
                    locator=_actual_source_locator_v2(build,shape,meter)
                    key=row[:3]
                    original=meter.read_fixed_row(build.pair.candidate,'c09_capture_members_v2',('record_ordinal','commitment'),
                        'stream_id=? AND primary_key_json=?',(locator.identity.stream_id,canonical_serialize(key)))
                    if original is None:
                        raise C09PagedCaptureHold('Contact birth row has no actual captured index member')
                    require_c09_capture_member_v2(build.pair.candidate,locator.identity,original[0],key,original[1],meter=meter)
                    origin={'stream_id':locator.identity.stream_id,'ordinal':original[0],'row_commitment':original[1]}
                    from .c09_contact_plan_physical_v3 import C09MappedContactPlanCaptureV3
                    capture=build.contact_plan_birth_capture_v3
                    if capture is None:
                        from .c09_paged_sql_v2 import read_c09_next_row_metadata_v2
                        found=read_c09_next_row_metadata_v2(build.pair.source,shape,build.contact_plan_birth_after_v3)
                        if found is None or tuple(found[0])!=tuple(key):
                            raise C09PagedCaptureHold('Contact birth actual Source metadata discovery changed')
                        capture=C09MappedContactPlanCaptureV3(build,shape,key,found[1])
                    if not (capture.row.complete and capture.value.complete and capture.quantum_completed):
                        prospective_capture=capture.next_quantum(budget)
                    else:
                        reader=ContactPlanBirthReadV3(_ISSUER,build,row,origin,meter,actual_capture=capture)
                        build.contact_plan_birth_reader_v3=reader
                        build.contact_plan_birth_capture_v3=None
                else:
                    reader.advance(meter)
                if reader is not None and reader.complete:
                    reader.require_complete(build,meter)
                    build.contact_plan_birth_proofs_v3[reader.row[:3]]=reader
                    build.contact_plan_birth_after_v3=reader.row[:3]
                    build.contact_plan_birth_reader_v3=None
    if prospective_capture is not None:
        prospective_capture.quantum_completed=True
        build.contact_plan_birth_capture_v3=prospective_capture
    build.require_current()
    return True
