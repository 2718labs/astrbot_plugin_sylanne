"""Exact Contact Plan3 WRITE preparation and three sealed Graph members.

The actual background child retains one operation. Each advance owns one SQL
quantum; only its final CAS publishes cell headers and the signed Plan record.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import fields, replace
from hashlib import sha256
from weakref import WeakKeyDictionary, WeakSet, ref
import json

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import GraphWrite, NamespaceEpoch
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime_storage_v3 import runtime_storage_v3, _operation, runtime_storage_quantum_v3
from .owner_material_source_storage_v3 import CanonicalValueStreamV3
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2

_ISSUER = object()
_PREPARED = WeakSet()
_BINDINGS = WeakKeyDictionary()
_WRITES = WeakSet()
_VALUES = {}
_BOUND = ContextVar('contact_plan_physical_write_v3', default=None)

STREAM_TABLE = 'graph_contact_plan_streams_v3'
STREAM_DDL = ('CREATE TABLE '+STREAM_TABLE+'(bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,'
    'request_digest TEXT NOT NULL,attempt_id TEXT NOT NULL,permit_digest TEXT NOT NULL,graph_revision INTEGER NOT NULL,'
    'graph_epoch INTEGER NOT NULL,selection_digest TEXT NOT NULL,descriptor_json TEXT NOT NULL,phase TEXT NOT NULL '
    "CHECK(phase IN ('preparing','sealed','committed','aborted')),PRIMARY KEY(bot,persona,operation_id)) STRICT")


def install_contact_plan_stream_schema_v3(db):
    db.execute(STREAM_DDL.replace('CREATE TABLE ','CREATE TABLE IF NOT EXISTS ',1))
    if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(STREAM_TABLE,)).fetchone() != (STREAM_DDL,):
        raise AuthorityUnavailable('Contact Plan3 physical stream exact schema differs')


class ContactPlanCellStreamV3:
    def __init__(self,prepared,name,value,locator,owner_ref):
        require_contact_plan_physical_v3(prepared)
        self.prepared,self.name,self.value,self.locator,self.owner_ref = prepared,name,value,locator,owner_ref
        self.stream = CanonicalValueStreamV3(value)
        self.phase,self.ordinal,self.offset,self.complete = 'hash',0,0,False
        self.raw_sha,self.byte_count,self.cell_id,self.header = None,None,None,None
        self.root,self.verify_hash,self.verify_root = None,sha256(),None
        self.write_cursor = (0,0,None,sha256().hexdigest())
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
    def advance(self,meter):
        prepared = require_contact_plan_physical_v3(self.prepared)
        prepared.require_current(meter=meter)
        if self.phase == 'hash':
            self.stream.read_fragment(meter)
            if not self.stream.complete:
                return
            self.raw_sha,self.byte_count = self.stream.hash.hexdigest(),self.stream.offset
            from .dispatch_current_inventory_v3 import _freeze_value_v3
            self.frozen_value = _freeze_value_v3(self.value)
            self.phase = 'hash_complete'
            return
        if self.phase == 'hash_complete':
            if prepared.event_digest is None:
                return
            self.origin = {'schema':'sylanne3.runtime-cell-origin.v3','selection_digest':prepared.operation.selection_digest,
                'role':'graph','authority_id':prepared.handle.selected.basis.control.authority_id,
                'installation_id':prepared.handle.selected.basis.control.installation_id,'namespace':prepared.namespace.as_tuple,
                'operation_id':prepared.operation_id,'event_digest':prepared.event_digest,'locator':self.locator,
                'read_proof':{'schema':'sylanne.contact-plan-stream-origin.v3','stream_ref':prepared.stream_ref,
                    'request_digest':prepared.request_digest,'permit_digest':prepared.permit_digest,
                    'readset_digest':prepared.readset_digest,'namespace_epoch':prepared.epoch.revision,
                    'source_selection_digest':prepared.source_selection_digest}}
            self.origin_digest = canonical_digest(self.origin)
            self.cell_id = canonical_digest({'schema':'sylanne3.runtime-cell-identity.v3','instance':prepared.handle.instance,
                'origin_digest':self.origin_digest,'locator':self.locator,'payload_sha256':self.raw_sha})
            self.root = canonical_digest(('sylanne3.segmented-cell-genesis.v1',self.cell_id))
            self.verify_root = self.root
            self.write_cursor = (0,0,self.root,sha256().hexdigest())
            self.stream = CanonicalValueStreamV3(self.value)
            self.phase = 'write'
            return
        if self.phase == 'write':
            fragment = self.stream.read_fragment(meter)
            if fragment is not None:
                segment_sha = sha256(fragment).hexdigest()
                prior = prepared.db.execute('SELECT byte_offset,payload,payload_sha256 FROM segmented_cell_segments_v1 '
                    'WHERE cell_id=? AND ordinal=?',(self.cell_id,self.ordinal)).fetchone()
                meter.charge_read(32 if prior is None else len(prior[1])+128)
                if prior is None:
                    meter.charge_write(len(fragment)+256)
                    prepared.db.execute('INSERT INTO segmented_cell_segments_v1 VALUES(?,?,?,?,?)',
                        (self.cell_id,self.ordinal,self.offset,fragment,segment_sha))
                elif prior != (self.offset,fragment,segment_sha):
                    raise AuthorityUnavailable('Contact Plan3 existing staged segment differs')
                self.root = canonical_digest(('sylanne3.segmented-cell-link.v1',self.root,self.cell_id,
                    self.ordinal,self.offset,len(fragment),segment_sha))
                self.ordinal += 1
                self.offset += len(fragment)
                self.write_cursor = (self.ordinal,self.offset,self.root,self.stream.hash.hexdigest())
            if self.stream.complete:
                if (self.stream.hash.hexdigest(),self.offset) != (self.raw_sha,self.byte_count):
                    raise AuthorityUnavailable('Contact Plan3 actual second canonical EOF differs')
                self.count = self.ordinal
                self.ordinal,self.offset,self.phase = 0,0,'verify'
            return
        if self.phase == 'verify':
            if self.ordinal < self.count:
                row = prepared.db.execute('SELECT byte_offset,payload,payload_sha256 FROM segmented_cell_segments_v1 '
                    'WHERE cell_id=? AND ordinal=?',(self.cell_id,self.ordinal)).fetchone()
                if row is None:
                    raise AuthorityUnavailable('Contact Plan3 staged physical segment absent')
                meter.charge_read(len(row[1])+256)
                if row[0] != self.offset or sha256(row[1]).hexdigest() != row[2]:
                    raise AuthorityUnavailable('Contact Plan3 staged physical segment offset/hash differs')
                self.parser.feed(row[1],lambda event:None)
                self.verify_hash.update(row[1])
                self.verify_root = canonical_digest(('sylanne3.segmented-cell-link.v1',self.verify_root,self.cell_id,
                    self.ordinal,self.offset,len(row[1]),row[2]))
                self.ordinal += 1
                self.offset += len(row[1])
                return
            extra = prepared.db.execute('SELECT ordinal FROM segmented_cell_segments_v1 WHERE cell_id=? AND ordinal>=? LIMIT 1',
                (self.cell_id,self.count)).fetchone()
            meter.charge_read(16)
            parsed = self.parser.finish()
            if (extra is not None or (parsed.byte_count,parsed.sha256)!=(self.byte_count,self.raw_sha)
                    or self.verify_hash.hexdigest()!=self.raw_sha or self.verify_root!=self.root):
                raise AuthorityUnavailable('Contact Plan3 independent physical/canonical EOF differs')
            self.header = (self.cell_id,'canonical-json.ascii.v1',self.owner_ref,prepared.operation_id,
                self.byte_count,self.count,self.raw_sha,self.root,self.origin_digest)
            self.phase,self.complete,self.parser,self.stream = 'sealed',True,None,None
    def publish_in_transaction(self,prepared,meter):
        if prepared is not self.prepared or not self.complete or prepared.phase != 'publishing':
            raise AuthorityUnavailable('Contact Plan3 cell cannot publish before its actual final CAS')
        origin = self.origin
        row = (self.origin_digest,prepared.operation.selection_digest,'graph',origin['authority_id'],origin['installation_id'],
            canonical_serialize(prepared.namespace.as_tuple),prepared.operation_id,prepared.event_digest,
            canonical_serialize(self.locator),canonical_serialize(origin['read_proof']))
        prior = prepared.db.execute('SELECT * FROM runtime_cell_origins_v3 WHERE origin_digest=?',(self.origin_digest,)).fetchone()
        if prior is None:
            meter.charge_write(sum(len(str(value).encode()) for value in row)+256)
            prepared.db.execute('INSERT INTO runtime_cell_origins_v3 VALUES(?,?,?,?,?,?,?,?,?,?)',row)
        elif prior != row:
            raise AuthorityUnavailable('Contact Plan3 immutable actual origin differs')
        prior = prepared.db.execute('SELECT * FROM segmented_cells_v1 WHERE cell_id=?',(self.cell_id,)).fetchone()
        if prior is None:
            meter.charge_write(sum(len(str(value).encode()) for value in self.header)+256)
            prepared.db.execute('INSERT INTO segmented_cells_v1 VALUES(?,?,?,?,?,?,?,?,?)',self.header)
        elif prior != self.header:
            raise AuthorityUnavailable('Contact Plan3 immutable actual header differs')
        return self.cell_id


class SealedContactPlanGraphWriteV3:
    def __init__(self,issuer,prepared,key,value,dependencies,name):
        if issuer is not _ISSUER:
            raise AuthorityUnavailable('Contact Plan3 write requires its actual private producer')
        require_contact_plan_physical_v3(prepared)
        self.prepared,self.key,self.value,self.dependencies,self.name = prepared,key,value,tuple(dependencies),name
        write = GraphWrite.__new__(GraphWrite)
        object.__setattr__(write,'key',key)
        object.__setattr__(write,'value',value)
        object.__setattr__(write,'dependencies',self.dependencies)
        object.__setattr__(write,'_sealed_contact_plan_v3',self)
        self._write_ref,self._pending = ref(write),write
        _WRITES.add(self)
        _VALUES[id(value)] = ref(self,lambda _,identity=id(value):_VALUES.pop(identity,None))
    @property
    def write(self):
        return self._write_ref()
    def take_write_v3(self):
        value,self._pending = self._pending,None
        if value is None:
            raise AuthorityUnavailable('Contact Plan3 write ownership already transferred')
        return value


def issued_contact_plan_graph_write_v3(write):
    holder = getattr(write,'_sealed_contact_plan_v3',None)
    return type(write) is GraphWrite and type(holder) is SealedContactPlanGraphWriteV3 and holder in _WRITES and holder.write is write


def require_contact_plan_graph_write_v3(write):
    if not issued_contact_plan_graph_write_v3(write):
        raise AuthorityUnavailable('Contact Plan3 requires its actual three-member writer')
    holder = write._sealed_contact_plan_v3
    prepared = require_contact_plan_physical_v3(holder.prepared)
    if (write.key,write.value,write.dependencies)!=(holder.key,holder.value,holder.dependencies) or holder.name not in prepared.cells:
        raise AuthorityUnavailable('Contact Plan3 member changed after its actual producer')
    from .dispatch_current_inventory_v3 import _freeze_value_v3
    cell = prepared.cells[holder.name]
    if cell.raw_sha is not None and _freeze_value_v3(write.value) != cell.frozen_value:
        raise AuthorityUnavailable('Contact Plan3 metadata value changed after actual canonical EOF')
    return holder


def clone_contact_plan_graph_write_v3(write):
    holder = require_contact_plan_graph_write_v3(write)
    return SealedContactPlanGraphWriteV3(_ISSUER,holder.prepared,holder.key,holder.value,holder.dependencies,holder.name).take_write_v3()


def contact_plan_sealed_value_v3(key,value):
    weak = _VALUES.get(id(value))
    holder = None if weak is None else weak()
    if holder is None or holder not in _WRITES or holder.value is not value:
        return None
    require_contact_plan_graph_write_v3(holder.write)
    if key != holder.key:
        raise AuthorityUnavailable('Contact Plan3 seal cannot authorize another graph type or key')
    return value


def contact_plan_graph_cell_ref_v3(write,db,*,revision,event_digest,scope_key,read_versions,epochs):
    holder = require_contact_plan_graph_write_v3(write)
    prepared = holder.prepared
    if (db is not prepared.db or _BOUND.get() is not prepared or prepared.phase != 'publishing'
            or not db.in_transaction or revision != 1 or event_digest != prepared.event_digest
            or scope_key != (*prepared.namespace.as_tuple,prepared.frame.envelope.identity.activity_id,prepared.operation_id)
            or tuple(read_versions) != prepared.frame.snapshot.versions or tuple(epochs) != ()):
        raise AuthorityUnavailable('Contact Plan3 sealed graph member lost actual final CAS identity')
    with runtime_storage_quantum_v3(db) as meter:
        prepared.require_current(meter=meter)
        return prepared.cells[holder.name].publish_in_transaction(prepared,meter)


class PreparedContactPlanPhysicalV3:
    def __init__(self,issuer,parent,runtime,frame,request,readers,scope,owner,guard,metadata,epoch,plan,expression,proof):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        from ..domains.d08.contact_plan_v3 import ContactExpressionPlanProvenanceV3,contact_plan_keys_v3,PROVENANCE,ELIGIBILITY
        from ..domains.d08.contact_plan_v2 import PLAN
        from ..domains.d01.production_operations_v1 import plain_v1
        if issuer is not _ISSUER or type(proof) is not ContactExpressionPlanProvenanceV3:
            raise AuthorityUnavailable('Contact Plan3 physical factory requires its exact actual proof')
        require_actual_background_attachment_owner_v3(parent,db=parent.db)
        if (parent.kind!='followup_child' or parent.graph is not runtime.graph or parent.db.in_transaction is False
                or scope.operation!='write' or scope is parent.read_scope or frame.envelope.identity.phase!='adopt_contact_expression_plan_v2'
                or scope.namespace!=parent.namespace or frame.owner_guard!=guard or owner.principal!=parent.owner.principal
                or (metadata,epoch)!=parent.graph_stamp or parent.operation.closed):
            raise AuthorityUnavailable('Contact Plan3 cannot borrow READ or another actual child WRITE')
        self.parent,self.runtime,self.db,self.frame,self.request,self.readers = parent,runtime,parent.db,frame,request,readers
        self.scope,self.owner,self.guard,self.metadata,self.epoch = scope,owner,guard,metadata,epoch
        self.operation,self.handle,self.namespace = parent.operation,runtime_storage_v3(parent.db),scope.namespace
        self.operation_id = frame.envelope.identity.operation_id
        self.request_digest = None
        attempt = self.db.execute('SELECT request_digest,attempt_id,permit_json FROM graph_owner_domain_attempts_v3 '
            'WHERE bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,self.operation_id)).fetchone()
        if attempt is None or attempt[1]!=scope.operation_id:
            raise AuthorityUnavailable('Contact Plan3 physical writer lacks its actual durable Owner attempt')
        from ..authority_service.v2_contract import to_wire
        self.request_digest,self.attempt_id,self.permit_digest = attempt[0],attempt[1],canonical_digest(to_wire(scope.permit))
        self.plan,self.expression,self.proof = plan,expression,proof
        self.phase,self.closed,self.cells,self.writes = 'preparing',False,{},()
        self.stream_ref = 'contact-plan-stream:'+canonical_digest((self.namespace,self.operation_id,self.request_digest))
        self.source_selection_digest = canonical_digest(tuple((row.ref,row.revision,row.valid)for row in proof.historical_reads))
        self.readset_digest = None
        self.readset_stream = CanonicalValueStreamV3([[v.key.token,v.revision]for v in frame.snapshot.versions])
        self.names,self.index = [],0
        self.event_digest,self.bundle,self.stage,self.original_payload,self.original_digest = None,None,None,None,None
        self.process_lease,self.external_originals = None,()
        self.followup,self.fence_context,self.finish_id,self.finish_digest = None,None,None,None
        self.current_policy,self.result = readers.current_contact_policy,None
        self.expected_graph_keys = contact_plan_keys_v3(plan)
        self.graph_values = {'fact':plain_v1(plan),'provenance':plain_v1(proof)}
        self.phase = 'readset_hash'
        _PREPARED.add(self)
        _BINDINGS[self] = self.identity_v3()
    def identity_v3(self):
        return (self.parent,self.runtime,self.db,self.frame,self.request,self.readers,self.scope,self.owner,self.guard,
            self.metadata,self.epoch,self.operation,self.handle,self.namespace,self.operation_id,self.request_digest,
            self.attempt_id,self.permit_digest,self.plan,self.expression,self.proof,self.stream_ref,self.source_selection_digest)
    def require_current(self,*,meter):
        require_contact_plan_physical_v3(self)
        self.operation.handle.require_current(meter)
        if self.runtime.graph._v2_graph_stamp(self.namespace)!=(self.metadata,self.epoch):
            raise AuthorityUnavailable('Contact Plan3 actual WRITE Graph stamp changed between quanta')
        return self


    def begin_graph_hashes(self):
        from ..domains.d08.contact_plan_v3 import ContactExpressionPlanEligibilityV3
        from ..runtime_contracts import VersionedRef
        fact,provenance,eligibility = self.expected_graph_keys
        for name,key in (('provenance',provenance),('fact',fact)):
            self.cells[name] = ContactPlanCellStreamV3(self,name,self.graph_values[name],
                {'table':'graph_atoms','token':key.token,'revision':1},key.token)
        self.names,self.index,self.phase = ['provenance','fact'],0,'graph_hashes'
    def assemble_eligibility(self):
        from ..domains.d08.contact_plan_v3 import ContactExpressionPlanEligibilityV3
        from ..runtime_contracts import VersionedRef
        from ..domains.d01.production_operations_v1 import plain_v1
        fact,provenance,eligibility = self.expected_graph_keys
        self.provenance_digest = self.cells['provenance'].raw_sha
        current = ContactExpressionPlanEligibilityV3(self.namespace,VersionedRef(fact.token,1),VersionedRef(provenance.token,1),
            self.provenance_digest,self.operation_id,self.proof.activation_generation,self.proof.graph_incarnation,self.proof.current_reads)
        self.graph_values['eligibility'] = plain_v1(current)
        self.cells['eligibility'] = ContactPlanCellStreamV3(self,'eligibility',self.graph_values['eligibility'],
            {'table':'graph_atoms','token':eligibility.token,'revision':1},eligibility.token)
        self.names.append('eligibility')
    def assemble_bundle(self):
        from ..runtime_contracts import DomainBundle,DomainProposal,DependencySet,_canonical_value
        from ..graph_types import AtomKey
        from ..domains.d08.contact_plan_v3 import PROPOSAL_SCHEMA,PROPOSAL_HASH
        from .source_correction_read_v3 import _heap
        fact,provenance,_eligibility = self.expected_graph_keys
        dependencies = tuple(sorted({fact,provenance,*(AtomKey.from_token(row.ref) for row in self.proof.current_reads)},key=lambda key:key.token))
        self.writes = tuple(SealedContactPlanGraphWriteV3(_ISSUER,self,key,self.graph_values[name],
            () if name!='eligibility' else dependencies,name).take_write_v3()
            for name,key in zip(('fact','provenance','eligibility'),self.expected_graph_keys))
        dependency_set = DependencySet(current_invalidation=tuple(version for version in self.frame.snapshot.versions
            if version.key in set(dependencies)-set(self.expected_graph_keys)),
            historical_provenance=tuple(version for version in self.frame.snapshot.versions
                if version.key.type_name=='memory.source' and version.revision>0))
        proposal = DomainProposal('d08',PROPOSAL_SCHEMA,PROPOSAL_HASH,self.frame.envelope,self.writes,dependency_set,(),())
        self.bundle = DomainBundle(self.frame.envelope,(proposal,),(),(),(),(),(self.operation_id,),(),())
        self.operation.retain(_heap(self.graph_values)*3+65536)
        self.bundle_value = {'$type':DomainBundle.__module__+'.'+DomainBundle.__qualname__,
            **{field.name:_canonical_value(getattr(self.bundle,field.name),set()) for field in fields(self.bundle)
                if field.name not in {'product_advance','root_adoption'}}}
        self.bundle_stream = CanonicalValueStreamV3(self.bundle_value)
        self.phase = 'bundle_hash'
    def assemble_originals(self):
        from ..runtime_contracts import CommitReceipt,canonical_serialize,_canonical_value
        from ..graph_types import GraphVersion
        from ..contracts import Event,Scope
        from ..domains.d01.production_operations_v1 import current_stage_payload_v1,plain_v1
        from .contact_plan_adoption_v3 import LOGICAL_KIND
        self.bundle_digest = self.bundle_stream.hash.hexdigest()
        self.event = Event(Scope(*self.namespace.as_tuple,self.frame.envelope.identity.activity_id),self.operation_id,
            self.frame.now_utc,'domain_bundle',{'bundle_digest':self.bundle_digest})
        self.event_digest = self.event.digest
        seq = self.db.execute('SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?',self.namespace.as_tuple).fetchone()
        self.expected_sequence = (seq[0] if seq is not None else 0)+1
        self.predicted_receipt = CommitReceipt('committed',self.operation_id,self.bundle_digest,
            self.frame.envelope.identity.activity_id,self.frame.envelope.identity.effect_id,self.expected_sequence,
            self.frame.snapshot.versions,tuple(GraphVersion(key,1) for key in self.expected_graph_keys),
            (NamespaceEpoch(*self.namespace.as_tuple,self.epoch.revision+1),),(),())
        self.receipt_stream = CanonicalValueStreamV3(_canonical_value(self.predicted_receipt,set()))
        self.phase = 'receipt_hash'
    def assemble_payload_cells(self):
        from ..graph_types import AtomKey
        from ..domains.d01.production_operations_v1 import current_stage_payload_v1,plain_v1
        from .contact_plan_adoption_v3 import LOGICAL_KIND
        receipt_digest = self.receipt_stream.hash.hexdigest()
        inventory = {}
        reads = {row.ref:row for row in self.proof.historical_reads}
        for query in self.proof.query_coverage:
            inventory[query.type_id] = [plain_v1(reads[version.key.token]) for version in query.row_versions]
        from .contact_initial_plan_source_v3 import require_initial_contact_source_work_v3
        initial=require_initial_contact_source_work_v3(self.parent.contact_initial_component)
        business_terms=initial.business_deadline_terms
        if business_terms['deadline_utc']!=self.plan.valid_until_utc:
            raise AuthorityUnavailable('Contact Plan3 business deadline differs from its actual immutable standing terms')
        self.plan_payload = {'schema':LOGICAL_KIND,'plan':plain_v1(self.plan),'expression':plain_v1(self.expression),
            'birth_bundle':self.bundle_value,'business_deadline':business_terms,
            'proof':plain_v1(self.proof),'producing_operation_id':self.operation_id,'receipt_digest':receipt_digest,
            'policy_ref':self.request.contact_policy_ref,'opportunity_ref':self.request.opportunity_ref,
            'route_ref':self.request.target_route_ref,'current_inventories':inventory}
        self.domain_payload = current_stage_payload_v1(self.frame,'d08','adopt_contact_expression_plan_v2',self.request,
            writes=self.writes,provenance={'schema':LOGICAL_KIND,'contact_plan':plain_v1(self.plan),
                'expression':plain_v1(self.expression),'proof':plain_v1(self.proof),'business_deadline':business_terms})
        self.cells['plan_original'] = ContactPlanCellStreamV3(self,'plan_original',self.plan_payload,
            {'table':'graph_contact_expression_plan_originals_v3','key':[*self.namespace.as_tuple,self.plan.contact_id]},
            self.expected_graph_keys[0].token)
        from .contact_initial_plan_source_v3 import require_initial_contact_source_work_v3
        initial=require_initial_contact_source_work_v3(self.parent.contact_initial_component)
        material=initial.source_material
        if material is None or set(material.source_records)!={row.ref for row in self.proof.historical_reads if AtomKey.from_token(row.ref).type_name=='memory.source'}:
            raise AuthorityUnavailable('Plan3 purpose metadata requires its complete actual initial protected Source closure')
        self.source_metadata = {'schema':'d10.contact-plan-source-selection.v3','namespace':plain_v1(self.namespace),
            'contact_id':self.plan.contact_id,'producing_operation_id':self.operation_id,'plan':plain_v1(self.plan),
            'business_deadline':business_terms,
            'proof':{'schema':self.proof.schema,'historical_reads':[{'ref':row.ref,'revision':row.revision,'valid':row.valid}
                for row in self.proof.historical_reads],'current_reads':[{'ref':row.ref,'revision':row.revision,'valid':row.valid}
                for row in self.proof.current_reads]},
            'historical_sources':[plain_v1(row) for row in self.proof.historical_reads if AtomKey.from_token(row.ref).type_name=='memory.source'],
            'source_refs':sorted(row.ref for row in self.proof.historical_reads if AtomKey.from_token(row.ref).type_name=='memory.source'),
            'source_purposes':[{'ref':ref,'purposes':sorted(material.purposes[ref])}for ref in sorted(material.purposes)]}
        self.cells['source_selection'] = ContactPlanCellStreamV3(self,'source_selection',self.source_metadata,
            {'table':'graph_contact_expression_plan_originals_v3','key':[*self.namespace.as_tuple,self.plan.contact_id],
                'field':'source_selection_cell_id'},self.expected_graph_keys[0].token)
        self.cells['domain_original'] = ContactPlanCellStreamV3(self,'domain_original',self.domain_payload,
            {'table':'graph_domain_production_originals_v3','key':[*self.namespace.as_tuple,self.operation_id]},
            self.expected_graph_keys[0].token)
        self.names,self.index,self.phase = ['plan_original','source_selection','domain_original'],0,'original_hashes'
    def advance(self,meter):
        self.require_current(meter=meter)
        if self.phase=='readset_hash':
            self.readset_stream.read_fragment(meter)
            if self.readset_stream.complete:
                self.readset_digest = self.readset_stream.hash.hexdigest()
                self.readset_stream = None
                self.begin_graph_hashes()
            return
        if self.phase in {'graph_hashes','original_hashes'}:
            cell = self.cells[self.names[self.index]]
            cell.advance(meter)
            if cell.phase=='hash_complete':
                self.index += 1
                if self.phase=='graph_hashes' and self.index==2:
                    self.assemble_eligibility()
                if self.index==len(self.names):
                    if self.phase=='graph_hashes':
                        self.assemble_bundle()
                    else:
                        self.names,self.index,self.phase = list(self.cells),0,'cell_write'
            return
        if self.phase=='bundle_hash':
            self.bundle_stream.read_fragment(meter)
            if self.bundle_stream.complete:
                self.assemble_originals()
            return
        if self.phase=='receipt_hash':
            self.receipt_stream.read_fragment(meter)
            if self.receipt_stream.complete:
                self.assemble_payload_cells()
            return
        if self.phase=='cell_write':
            cell = self.cells[self.names[self.index]]
            cell.advance(meter)
            if cell.complete:
                self.index += 1
                if self.index==len(self.names):
                    self.phase = 'sealed'
            return
        raise AuthorityUnavailable('Contact Plan3 WRITE stream phase is not registered')
    def release_payload_v3(self):
        self.closed = True
        for holder in tuple(_WRITES):
            if holder.prepared is self:
                _WRITES.discard(holder)
                _VALUES.pop(id(holder.value),None)
        self.cells.clear()
        self.writes,self.bundle,self.stage,self.original_payload = (),None,None,None
        self.graph_values,self.plan_payload,self.domain_payload = {},None,None
        _PREPARED.discard(self)
        _BINDINGS.pop(self,None)

def require_contact_plan_physical_v3(prepared):
    if (type(prepared) is not PreparedContactPlanPhysicalV3 or prepared not in _PREPARED or prepared.closed
            or _BINDINGS.get(prepared) != prepared.identity_v3()):
        raise AuthorityUnavailable('Actual Contact Plan3 physical preparation required')
    from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
    require_actual_background_attachment_owner_v3(prepared.parent,db=prepared.db)
    prepared.runtime._current()
    if (prepared.operation is not prepared.parent.operation or prepared.operation.closed or prepared.handle is not runtime_storage_v3(prepared.db)
            or _operation(prepared.handle) is not prepared.operation):
        raise AuthorityUnavailable('Contact Plan3 changed its actual retained operation/selected Graph')
    return prepared


@contextmanager
def bind_contact_plan_physical_v3(prepared):
    require_contact_plan_physical_v3(prepared)
    token = _BOUND.set(prepared)
    try:
        yield prepared
    finally:
        _BOUND.reset(token)


def contact_plan_bundle_digest_v3(bundle):
    from ..runtime_contracts import DomainBundle,_canonical_value
    if type(bundle) is not DomainBundle or len(bundle.proposals)!=1:
        return None
    writes = bundle.proposals[0].typed_writes
    if len(writes)!=3 or not all(issued_contact_plan_graph_write_v3(write) for write in writes):
        return None
    prepared = require_contact_plan_graph_write_v3(writes[0]).prepared
    if any(require_contact_plan_graph_write_v3(write).prepared is not prepared for write in writes):
        raise AuthorityUnavailable('Contact Plan3 bundle mixed actual WRITE preparations')
    if prepared.phase not in {'cell_write','sealed','publishing','committed'}:
        raise AuthorityUnavailable('Contact Plan3 bundle has not completed its actual typed canonical EOF')
    value = {'$type':DomainBundle.__module__+'.'+DomainBundle.__qualname__,
        **{field.name:_canonical_value(getattr(bundle,field.name),set()) for field in fields(bundle)
            if field.name not in {'product_advance','root_adoption'}}}
    if value != prepared.bundle_value or bundle.product_advance is not None or bundle.root_adoption is not None:
        raise AuthorityUnavailable('Contact Plan3 bundle changed its complete original typed payload')
    return prepared.bundle_digest


def contact_plan_provenance_digest_v3(proof):
    prepared = _BOUND.get()
    if prepared is None or prepared.proof is not proof or not hasattr(prepared,'provenance_digest'):
        return None
    require_contact_plan_physical_v3(prepared)
    return prepared.provenance_digest


def require_contact_plan_commit_v3(witness,graph,db,bundle,v2_write):
    from .domain_production_commit_v1 import _ACTIVE,_ProductionCommitWitnessV1
    from .contact_plan_preparation_v2 import prepare_contact_plan_in_transaction_v2
    from .d01_production_operations_v1 import CurrentDomainReadV1
    prepared = require_contact_plan_physical_v3(witness.stage)
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or _BOUND.get() is not prepared or prepared.phase!='publishing' or db is not prepared.db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or witness.runtime is not prepared.runtime or graph is not prepared.runtime.graph
            or witness.scope is not prepared.scope or witness.frame is not prepared.frame
            or witness.owner != prepared.owner or witness.guard != prepared.guard or bundle is not prepared.bundle
            or witness.request != prepared.request or witness.operation.operation_kind!='adopt_contact_expression_plan_v2'
            or v2_write[:2]!=(prepared.metadata,prepared.epoch)):
        raise AuthorityUnavailable('Contact Plan3 actual W01 witness/WRITE/EOF identity differs')
    CurrentDomainReadV1(prepared.frame).check(db)
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    prepared.readers.current_contact_policy = prepared.runtime._active_current_contact_policy_v1
    plan,expression = prepare_contact_plan_in_transaction_v2(db,frame=prepared.frame,request=prepared.request,
        installed_readers=prepared.readers,installed_bundle=assembly.admin_bundle,issuer=prepared.readers.issuer)
    if (plan,expression)!=(prepared.plan,prepared.expression):
        raise AuthorityUnavailable('Contact Plan3 current semantic Source/policy/Root qualification changed')
    actual = db.execute('SELECT request_digest,attempt_id,permit_json,receipt_json FROM graph_owner_domain_attempts_v3 '
        'WHERE bot=? AND persona=? AND operation_id=?',(*prepared.namespace.as_tuple,prepared.operation_id)).fetchone()
    from ..authority_service.v2_contract import to_wire
    from ..contracts import canonical_json
    if actual!=(prepared.request_digest,prepared.attempt_id,canonical_json(to_wire(prepared.scope.permit)),None):
        raise AuthorityUnavailable('Contact Plan3 actual original durable WRITE attempt differs')
    if contact_plan_bundle_digest_v3(bundle)!=prepared.bundle_digest or any(not cell.complete for cell in prepared.cells.values()):
        raise AuthorityUnavailable('Contact Plan3 complete canonical/physical EOF has not sealed')
    return witness


def publish_contact_plan_in_transaction_v3(prepared):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE
    from .domain_production_registry_v1 import installed_operation_v1
    from .domain_production_originals_v1 import _receipt_wire
    from .contact_plan_adoption_v3 import record_contact_plan_physical_after_cas_v3
    from .domain_followup_consumer_v1 import validate_followup_command_in_transaction_v1,finish_followup_command_in_transaction_v1
    from ..authority_service.v2_contract import to_wire
    from ..contracts import canonical_json
    prepared = require_contact_plan_physical_v3(prepared)
    if prepared.phase!='sealed' or not prepared.db.in_transaction:
        raise AuthorityUnavailable('Contact Plan3 cannot publish unsealed or outside its actual final CAS')
    runtime,graph,db = prepared.runtime,prepared.runtime.graph,prepared.db
    _frame,resolution = validate_followup_command_in_transaction_v1(prepared.followup,graph,db,
        prepared.scope,prepared.owner,prepared.frame.now_utc)
    witness = _ProductionCommitWitnessV1(runtime,graph,prepared.scope,prepared.frame,prepared,
        installed_operation_v1('adopt_contact_expression_plan_v2'),prepared.request,prepared.owner,prepared.guard,
        prepared.bundle,prepared.external_originals)
    _ACTIVE[id(witness)] = witness
    prepared.phase = 'publishing'
    try:
        with bind_contact_plan_physical_v3(prepared):
            receipt = graph._commit_domain_bundle_fenced(prepared.bundle,prepared.process_lease,in_transaction=True,
                v2_write=(prepared.metadata,prepared.epoch,prepared.finish_id,prepared.finish_digest,
                    canonical_json(to_wire(prepared.scope.permit))),now_utc=prepared.frame.now_utc,
                domain_production_issuance_v1=witness)
            if receipt!=prepared.predicted_receipt:
                raise AuthorityUnavailable('Contact Plan3 actual COMMIT differs from its prehashed immutable birth bytes')
            digest,original = record_contact_plan_physical_after_cas_v3(db,prepared=prepared,receipt=receipt)
    finally:
        _ACTIVE.pop(id(witness),None)
    result = {'schema':'sylanne.domain-production-receipt.v1','domain':'d08',
        'operation_kind':'adopt_contact_expression_plan_v2','operation_id':prepared.operation_id,
        'activity_id':receipt.activity_id,'original_ref':original.original_ref,'original_digest':original.original_digest,
        'receipt':_receipt_wire(receipt),'receipt_digest':prepared.receipt_stream.hash.hexdigest(),
        'job_states':[],'coverage':'complete','missing_inputs':[],'continuation_ref':None,'outbox':[],
        'produced_originals':[{'kind':'d10.contact_plan.v2','original_ref':prepared.plan.contact_id,'original_digest':digest}]}
    result['followup_disposition'] = finish_followup_command_in_transaction_v1(prepared.followup,graph,db,resolution,result)
    changed = db.execute('UPDATE graph_owner_domain_attempts_v3 SET receipt_json=? WHERE bot=? AND persona=? '
        'AND operation_id=? AND attempt_id=? AND receipt_json IS NULL',
        (canonical_json(result),*prepared.namespace.as_tuple,prepared.operation_id,prepared.attempt_id))
    if changed.rowcount!=1:
        raise AuthorityUnavailable('Contact Plan3 actual durable Owner receipt raced')
    prepared.result = result
    return result


def advance_contact_plan_write_v3(graph,work):
    from ..graph_worker import GraphStorageStepV3
    from .domain_followup_consumer_v1 import _ACTIVE as active_followups,_observe_owner
    from .domain_background_read_v3 import bind_background_reads_v3
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    from .first_ingress_v2 import trusted_upper
    parent = work.state
    prepared = require_contact_plan_physical_v3(parent.contact_plan_write)
    port,store = graph._GraphCoordinator__content_fence_v2,parent.store
    with bind_runtime_storage_operation_v3(parent.operation,parent.db):
        if port.validate_fence(prepared.scope)!=prepared.scope.permit:
            raise AuthorityUnavailable('Contact Plan3 original WRITE fence is no longer active')
        guard,owner = _observe_owner(graph,parent.authority,prepared.scope)
        if (guard,owner)!=(prepared.guard,prepared.owner):
            raise AuthorityUnavailable('Contact Plan3 current Owner changed during streamed WRITE')
        now = trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
        if now>=min(prepared.frame.envelope.deadline_utc,parent.operation.deadline_utc):
            raise AuthorityUnavailable('Contact Plan3 original retained WRITE deadline expired')
        active_followups[id(prepared.followup)] = prepared.followup
        prepared.runtime._active_background_followup_v1 = prepared.followup
        try:
            from .contact_initial_plan_source_v3 import bind_initial_contact_fresh_write_v3
            with (bind_background_reads_v3(parent,db=parent.db),bind_initial_contact_fresh_write_v3(prepared.runtime,
                    authority=parent.authority,operation_kind='adopt_contact_expression_plan_v2',request=prepared.request,
                    operation_id=prepared.operation_id,request_digest=prepared.request_digest,scope=prepared.scope,guard=guard,owner=owner),
                    prepared.fence_context(prepared.scope,guard,owner)):
                with store._lock,runtime_storage_quantum_v3(parent.db) as meter:
                    parent.db.execute('BEGIN IMMEDIATE')
                    try:
                        prepared.require_current(meter=meter)
                        if prepared.phase=='sealed':
                            publish_contact_plan_in_transaction_v3(prepared)
                        else:
                            prepared.advance(meter)
                        persist_contact_plan_stream_in_transaction_v3(prepared,meter)
                        persist_contact_plan_cell_cursors_in_transaction_v3(prepared,meter)
                        parent.db.commit()
                    except BaseException:
                        parent.db.rollback()
                        raise
            if prepared.result is None:
                return GraphStorageStepV3('progress')
            prepared.phase = 'committed'
            port.finish_fence(prepared.scope,request_id=prepared.finish_id,request_digest=prepared.finish_digest)
            parent.graph_stamp = graph._v2_graph_stamp(parent.namespace)
            parent.contact_plan_result,parent.complete = prepared.result,True
            parent.phase = 'contact_plan_complete'
            return GraphStorageStepV3('complete',parent.result)
        finally:
            active_followups.pop(id(prepared.followup),None)
            prepared.runtime._active_background_followup_v1 = None


def finish_contact_plan_write_v3(parent,error):
    prepared = getattr(parent,'contact_plan_write',None)
    if prepared is None:
        return
    require_contact_plan_physical_v3(prepared)
    if prepared.process_lease is not None:
        prepared.runtime.graph.release_authority_lease(prepared.runtime._bootstrap,prepared.process_lease)
        prepared.process_lease = None
    prepared.release_payload_v3()
    parent.contact_plan_write = None


def persist_contact_plan_stream_in_transaction_v3(prepared,meter):
    require_contact_plan_physical_v3(prepared)
    db = prepared.db
    if not db.in_transaction:
        raise AuthorityUnavailable('Contact staged stream persistence requires its actual WRITE quantum')
    from .c09_contact_plan_prefix_history_v3 import TABLE as PREFIX_HISTORY
    db=prepared.db
    present=meter.read_fixed_row(db,'sqlite_master',('name',),"type='table' AND name=?",(PREFIX_HISTORY,))
    if present is not None:
        history=meter.read_fixed_row(db,PREFIX_HISTORY,('original_cell_id','disposition'),
            'operation_id=? ORDER BY capture_scope_digest,old_storage_instance,original_cell_id',
            (prepared.frame.envelope.identity.operation_id,))
        if history is not None:
            raise ValueError('Contact old-instance prefix is non-executable history; original unknown inspection required')
    install_contact_plan_stream_schema_v3(db)
    from ..graph_types import AtomKey
    descriptor = {'schema':'d10.contact-plan-stream-descriptor.v3','namespace':prepared.namespace,
        'contact_id':prepared.plan.contact_id,'original_now_utc':prepared.frame.now_utc,
        'original_deadline_utc':prepared.frame.envelope.deadline_utc,'phase':prepared.phase,
        'cells':{name:{'cell_id':cell.cell_id,'byte_count':cell.byte_count,'payload_sha256':cell.raw_sha,
            'phase':cell.phase,'next_ordinal':cell.ordinal,'next_offset':cell.offset,
            'origin':getattr(cell,'origin',None),'origin_digest':getattr(cell,'origin_digest',None),
            'owner_ref':cell.owner_ref,'locator':cell.locator}for name,cell in prepared.cells.items()},
        'bundle_digest':getattr(prepared,'bundle_digest',None),'event_digest':prepared.event_digest,
        'source_closure':[{'ref':row.ref,'revision':row.revision,'valid':row.valid}
            for row in prepared.proof.historical_reads if AtomKey.from_token(row.ref).type_name=='memory.source']}
    wire = canonical_serialize(descriptor)
    identity = (*prepared.namespace.as_tuple,prepared.operation_id,prepared.request_digest,prepared.attempt_id,
        prepared.permit_digest,prepared.metadata.graph_revision,prepared.epoch.revision,prepared.source_selection_digest)
    prior = db.execute('SELECT * FROM '+STREAM_TABLE+' WHERE bot=? AND persona=? AND operation_id=?',identity[:3]).fetchone()
    phase = 'committed' if prepared.result is not None else 'sealed' if prepared.phase=='sealed' else 'preparing'
    if prior is None:
        meter.charge_write(len(wire.encode())+512)
        db.execute('INSERT INTO '+STREAM_TABLE+' VALUES('+','.join('?'for _ in range(11))+')',(*identity,wire,phase))
    else:
        old = json.loads(prior[9])
        if (prior[:9]!=identity or old['original_now_utc']!=prepared.frame.now_utc
                or old['original_deadline_utc']!=prepared.frame.envelope.deadline_utc
                or prior[10] in ('committed','aborted')):
            raise AuthorityUnavailable('Contact staged WRITE cannot replace its original durable stream identity/deadline')
        meter.charge_read(len(prior[9].encode())+256)
        meter.charge_write(len(wire.encode())+256)
        db.execute('UPDATE '+STREAM_TABLE+' SET descriptor_json=?,phase=? WHERE bot=? AND persona=? AND operation_id=?',
            (wire,phase,*identity[:3]))


def validate_contact_plan_stream_row_v3(columns,row):
    expected = ('bot','persona','operation_id','request_digest','attempt_id','permit_digest','graph_revision',
        'graph_epoch','selection_digest','descriptor_json','phase')
    if tuple(columns)!=expected or len(row)!=11 or row[10] not in ('preparing','sealed','committed','aborted'):
        raise AuthorityUnavailable('Contact Plan3 exact staged stream record shape differs')
    value = json.loads(row[9])
    names = {'schema','namespace','contact_id','original_now_utc','original_deadline_utc','phase','cells','bundle_digest','event_digest','source_closure'}
    if (type(value) is not dict or set(value)!=names or value['schema']!='d10.contact-plan-stream-descriptor.v3'
            or value['namespace'].get('bot_id')!=row[0] or value['namespace'].get('persona_id')!=row[1]
            or value['original_now_utc']>=value['original_deadline_utc'] or canonical_serialize(value)!=row[9]
            or type(value['cells']) is not dict or not set(value['cells'])<=
                {'fact','provenance','eligibility','plan_original','source_selection','domain_original'}):
        raise AuthorityUnavailable('Contact Plan3 original staged descriptor identity/deadline differs')
    from ..graph_types import AtomKey
    closure=value['source_closure']
    if (type(closure)is not list or not closure or len(closure)>256
            or len({row['ref']for row in closure})!=len(closure)):
        raise AuthorityUnavailable('Contact staged stream has no exact bounded immutable Source closure')
    row_namespace=(row[0],row[1])
    for row in closure:
        if (type(row)is not dict or set(row)!={'ref','revision','valid'} or row['revision']<1 or row['valid']is not True
                or AtomKey.from_token(row['ref']).type_name!='memory.source'
                or (AtomKey.from_token(row['ref']).owner.bot,AtomKey.from_token(row['ref']).owner.persona)!=(row_namespace[0],row_namespace[1])):
            raise AuthorityUnavailable('Contact staged Source closure original is invalid')
    for name,cell in value['cells'].items():
        if (set(cell)!={'cell_id','byte_count','payload_sha256','phase','next_ordinal','next_offset',
                'origin','origin_digest','owner_ref','locator'}
                or cell['phase'] not in ('hash','hash_complete','write','verify','sealed')
                or type(cell['next_ordinal']) is not int or cell['next_ordinal']<0
                or type(cell['next_offset']) is not int or cell['next_offset']<0):
            raise AuthorityUnavailable('Contact Plan3 staged physical cursor differs')
    return value


def persist_contact_plan_cell_cursors_in_transaction_v3(prepared,meter):
    require_contact_plan_physical_v3(prepared)
    if not prepared.db.in_transaction:
        raise AuthorityUnavailable('Contact physical cursors require actual same-WRITE SQL quantum')
    for name,cell in prepared.cells.items():
        if cell.cell_id is None:
            continue
        ordinal,offset,root,prefix_sha = cell.write_cursor
        locator={'schema':'d10.contact-plan-cell-locator.v3','stream_ref':prepared.stream_ref,'name':name,
            'namespace':prepared.namespace.as_tuple,'operation_id':prepared.operation_id,'owner_ref':cell.owner_ref}
        verified=(cell.count,cell.byte_count,cell.root,cell.raw_sha) if cell.complete else (
            cell.ordinal,cell.offset,cell.verify_root,cell.verify_hash.hexdigest()) if cell.phase=='verify' else (
            0,0,canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell.cell_id)),sha256().hexdigest())
        phase='committed' if prepared.result is not None else 'sealed' if cell.complete else 'staging'
        content=(cell.cell_id,prepared.stream_ref,canonical_serialize(locator),'canonical-json.ascii.v1',
            prepared.operation_id,cell.owner_ref,phase,ordinal,offset,root,prefix_sha,
            canonical_serialize({'schema':'d10.contact-plan-cell-source-cursor.v3','name':name,
                'payload_sha256':cell.raw_sha,'origin_digest':cell.origin_digest}),cell.byte_count,*verified,1)
        prior=prepared.db.execute('SELECT * FROM segmented_cell_writes_v1 WHERE cell_id=?',(cell.cell_id,)).fetchone()
        meter.charge_read(0 if prior is None else sum(len(str(v).encode())for v in prior))
        if prior is None:
            meter.charge_write(sum(len(str(v).encode())for v in content)+256)
            prepared.db.execute('INSERT INTO segmented_cell_writes_v1 VALUES('+','.join('?'for _ in content)+')',content)
        else:
            if prior[:6]!=content[:6] or prior[12]!=content[12] or prior[6] in ('committed','aborted'):
                raise AuthorityUnavailable('Contact immutable original physical cursor identity/terminal changed')
            values=(*content[6:17],prior[17]+1,cell.cell_id)
            meter.charge_write(sum(len(str(v).encode())for v in values)+256)
            prepared.db.execute('UPDATE segmented_cell_writes_v1 SET phase=?,next_ordinal=?,next_byte_offset=?,prefix_root=?,prefix_sha256=?,'
                'source_cursor_json=?,expected_total_bytes=?,verify_next_ordinal=?,verify_next_byte_offset=?,verify_prefix_root=?,'
                'verify_prefix_sha256=?,cursor_revision=? WHERE cell_id=?',values)
