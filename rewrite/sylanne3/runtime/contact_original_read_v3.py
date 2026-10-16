"""Fixed Contact original read seams; actual V3 Work owns bodies and their EOF."""
from ..authority_service.contact_background_graph_v3 import contact_authority_work_v3, require_contact_source_db_v3
from .contact_host_source_v3 import contact_host_work_for_db_v3
from .contact_domain_source_v3 import contact_domain_work_for_db_v3
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3


def contact_original_point_v3(db, *, table, columns, key_columns, key, legacy_reader):
    from .contact_cost_metadata_v3 import contact_cost_original_point_v3
    accounting,row = contact_cost_original_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if accounting:
        return row
    from .contact_domain_source_work_v3 import contact_domain_original_point_v3
    domain,row = contact_domain_original_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if domain:
        return row
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .contact_host_source_v3 import contact_host_work_for_db_v3
    work = contact_domain_work_for_db_v3(db) or contact_host_work_for_db_v3(db) or contact_authority_work_v3(db)
    if work is not None:
        require_contact_source_db_v3(db)
        if table in {'graph_atoms','graph_history'}:
            atom = AtomKey.from_token(key[0])
            if atom.type_name == 'memory.source' and atom.token not in work.source_material.source_records:
                raise AuthorityUnavailable('Contact body is outside its actual purpose/audience-qualified Source material')
    if columns == ('1',):
        row = _producer_original_point_v3(db,table=table,columns=('epoch_revision',),key_columns=key_columns,key=key,
            legacy_reader=lambda: None if legacy_reader() is None else (1,))
        return None if row is None else (1,)
    return _producer_original_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key,
        legacy_reader=legacy_reader)


def contact_current_inventory_v3(db, *, namespace, kind):
    work = contact_domain_work_for_db_v3(db) or contact_host_work_for_db_v3(db) or contact_authority_work_v3(db)
    if work is None:
        return None
    require_contact_source_db_v3(db)
    from .contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
    if namespace != work.namespace or kind not in CONTACT_CURRENT_TYPES:
        raise AuthorityUnavailable('Contact inventory is outside its exact registered current family')
    rows = []
    for token, head in sorted(work.heads.items()):
        if AtomKey.from_token(token).type_name != kind:
            continue
        if len(rows) == 128:
            raise AuthorityUnavailable('Contact current inventory exceeds its original complete bound')
        row = contact_original_point_v3(db,table='graph_atoms',columns=('revision','value','valid'),
            key_columns=('token','bot','persona'),key=(token,*namespace.as_tuple),
            legacy_reader=lambda:None)
        rows.append((token,*row))
    return rows


def contact_dependency_rows_v3(db, *, dependent_token):
    work = contact_domain_work_for_db_v3(db) or contact_host_work_for_db_v3(db) or contact_authority_work_v3(db)
    if work is None:
        return None
    require_contact_source_db_v3(db)
    from .contact_host_stage_work_v3 import ContactHostStageReadWorkV3
    from .contact_domain_source_work_v3 import ContactDomainSourceReadV3
    if type(work) in {ContactHostStageReadWorkV3,ContactDomainSourceReadV3}:
        from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
        request = ('graph_dependencies',('dependency_token','dependency_revision'),('dependent_token',),(dependent_token,),'dependency_token')
        task = work.attachments.get(request)
        if task is None:
            _require_contact_attachment_v3(work,request)
        with runtime_storage_quantum_v3(db) as meter:
            work.require_current(meter=meter)
            return task.require_row_v3(work,meter)
    from .natural_producer_qualification_v1 import _producer_original_many_v3
    return _producer_original_many_v3(db,table='graph_dependencies',columns=('dependency_token','dependency_revision'),
        key_columns=('dependent_token',),key=(dependent_token,),order_column='dependency_token',legacy_reader=lambda:None)


def contact_original_durable_connection_v3(db, row):
    work = contact_domain_work_for_db_v3(db) or contact_host_work_for_db_v3(db) or contact_authority_work_v3(db)
    if work is None:
        return False
    require_contact_source_db_v3(db)
    from .contact_plan_adoption_v2 import TABLE
    actual = contact_original_point_v3(db,table=TABLE,
        columns=('bot','persona','contact_id','payload_json','payload_digest','signature'),
        key_columns=('bot','persona','contact_id'),key=row[:3],legacy_reader=lambda:None)
    if actual != row or row[4] != work.contact_locator.digest:
        raise AuthorityUnavailable('Contact durable Plan differs from its independently selected readonly SourceDB EOF')
    return True


def contact_historical_inventory_v3(db, *, namespace, epoch, refs, kinds):
    work = contact_domain_work_for_db_v3(db) or contact_host_work_for_db_v3(db) or contact_authority_work_v3(db)
    if work is None:
        return None
    require_contact_source_db_v3(db)
    from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
    request = ('contact_historical_inventory',namespace.as_tuple,epoch,tuple(refs),tuple(kinds))
    reader = work.attachments.get(request)
    if reader is None:
        if work.complete:
            raise AuthorityUnavailable('Contact historical inventory was not prepared to whole metadata EOF')
        _require_contact_attachment_v3(work,request)
    rows = []
    for token,revision,valid in reader.require_rows_v3(work):
        value = contact_original_point_v3(db,table='graph_history',columns=('value','valid'),
            key_columns=('token','revision'),key=(token,revision),legacy_reader=lambda:None)
        if value is None or value[1] != valid:
            raise AuthorityUnavailable('Contact historical current selected member changed after metadata EOF')
        rows.append((token,revision,value[0],valid))
    return rows


class ContactHistoricalInventoryReadV3:
    def __init__(self,work,request):
        self.owner,self.request = work,request
        _,namespace,self.epoch,self.refs,self.kinds = request
        if ((contact_domain_work_for_db_v3(work.db) or contact_host_work_for_db_v3(work.db) or contact_authority_work_v3(work.db)) is not work or namespace != work.namespace.as_tuple
                or len(self.refs) > 1024 or len(self.kinds) > 64 or type(self.epoch) is not int):
            raise AuthorityUnavailable('Contact historical inventory fixed scope differs')
        work.contact_locator.require_v3(work)
        TABLE = work.contact_locator.original_table
        from .contact_plan_adoption_v3 import TABLE as PLAN3
        if TABLE==PLAN3:
            payload = contact_plan_physical_payload_v3(work.db,work.namespace,work.contact_selector.contact_id)
        else:
            plan_request = (TABLE,('bot','persona','contact_id','payload_json','payload_digest','signature'),
                ('bot','persona','contact_id'),(*work.namespace.as_tuple,work.contact_selector.contact_id))
            original = work.attachments.get(plan_request)
            if original is None or not original.complete:
                raise AuthorityUnavailable('Contact history needs its actual signed Plan full-column EOF')
            payload = original.json_columns['payload_json'].require_v3(work)
        expected_refs = tuple(read['ref'] for read in payload['proof']['historical_reads'])
        expected_kinds = tuple(sorted({query['type_id'] for query in payload['proof']['query_coverage']}))
        expected_epochs = {query['epoch']['revision'] for query in payload['proof']['query_coverage']}
        if self.refs != expected_refs or self.kinds != expected_kinds or expected_epochs != {self.epoch}:
            raise AuthorityUnavailable('Contact history scope differs from its actual immutable Plan provenance')
        self.after = ''
        self.rows = []
        self.complete = False
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        work = self.owner
        work.require_current(meter=meter)
        source = (' FROM graph_history h JOIN graph_events e ON '
            '(h.event_bot,h.event_persona,h.event_session,h.event_id)=(e.bot,e.persona,e.session,e.event_id) '
            'WHERE e.bot=? AND e.persona=? AND e.epoch_revision<=? AND h.token>?')
        params = (*work.namespace.as_tuple,self.epoch,self.after)
        meter.require_available(8192)
        sql = 'SELECT MIN(h.token)' + source
        meter.charge_encode(len(sql)+sum(len(str(value)) for value in params))
        token = work.db.execute(sql,params).fetchone()[0]
        meter.charge_read(8 if token is None else len(token.encode('utf-8'))+8)
        if token is None:
            self.complete = True
            return
        self.after = token
        if token not in self.refs and AtomKey.from_token(token).type_name not in self.kinds:
            return
        if len(self.rows) == 1024:
            raise AuthorityUnavailable('Contact historical full inventory exceeds its original bound')
        revision = work.db.execute('SELECT MAX(h.revision) FROM graph_history h JOIN graph_events e ON '
            '(h.event_bot,h.event_persona,h.event_session,h.event_id)=(e.bot,e.persona,e.session,e.event_id) '
            'WHERE e.bot=? AND e.persona=? AND e.epoch_revision<=? AND h.token=?',
            (*work.namespace.as_tuple,self.epoch,token)).fetchone()[0]
        meter.charge_read(8)
        actual = _runtime_bounded_fixed_row_v3(work.db,meter,'graph_history',('token','revision','valid'),
            'token=? AND revision=?',(token,revision))
        if actual is None:
            raise AuthorityUnavailable('Contact historical metadata disappeared inside its current Source snapshot')
        work.operation.retain(len(token.encode('utf-8'))*4+256)
        self.rows.append(actual)
        self.after = token
    def require_rows_v3(self,work):
        if not self.complete or work is not self.owner or work.attachments.get(self.request) is not self:
            raise AuthorityUnavailable('Contact historical negative inventory lacks actual same-Work EOF')
        work._actual()
        return tuple(self.rows)


def read_contact_budget_grant_v3(db, issuer, lease_id, *, version=None):
    from ..authority_service.current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from .contact_host_source_v3 import contact_host_work_for_db_v3
    domain = contact_domain_work_for_db_v3(db)
    host = contact_host_work_for_db_v3(db)
    work = domain or host or _authority_attachment_owner_v3(db)
    if work is None or domain is None and host is None and work.controller.kind != 'contact' and getattr(work,'contact_prepared_locator',None) is None:
        return False, None
    require_contact_source_db_v3(db)
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db) as meter:
        lease = meter.read_fixed_row(db,'runtime_budget_leases',('bot_id','persona_id'),'lease_id=?',(lease_id,))
        current = meter.read_fixed_row(db,'runtime_budget_grants',('version','status'),
            'lease_id=? AND version=(SELECT MAX(version) FROM runtime_budget_grants WHERE lease_id=?)',(lease_id,lease_id))
    if lease != work.namespace.as_tuple or current is None or version is None and current[1] != 'active':
        raise AuthorityUnavailable('Contact actual finite parent grant namespace/current state differs')
    selected = current[0] if version is None else version
    row = contact_original_point_v3(db,table='runtime_budget_grants',columns=('grant_json','signature'),
        key_columns=('lease_id','version'),key=(lease_id,selected),legacy_reader=lambda:None)
    if row is None:
        raise AuthorityUnavailable('Contact signed parent grant original absent')
    issuer._signer.verify('budget-grant.v1',row[0],row[1])
    from .issuers import _decode_grant
    grant = _decode_grant(row[0])
    if (grant.lease_id,grant.version) != (lease_id,selected):
        raise AuthorityUnavailable('Contact signed original parent identity differs')
    if domain is not None and (grant.lease_id != domain.contact_locator.plan_metadata['parent_budget_lease_id']
            or grant.version != domain.contact_locator.plan_metadata['budget_grant_version']
            or canonical_digest(grant) != domain.contact_locator.plan_metadata['budget_grant_digest']):
        raise AuthorityUnavailable('Contact domain cannot substitute the original signed parent grant')
    return True, (grant,row[1])


class ContactPayloadCommitmentEOFV3:
    def __init__(self,work,request):
        from .contact_host_source_v3 import contact_host_work_for_db_v3
        if (contact_domain_work_for_db_v3(work.db) or contact_host_work_for_db_v3(work.db) or contact_authority_work_v3(work.db)) is not work:
            raise AuthorityUnavailable('Contact payload commitment requires its actual same installed Work')
        self.owner,self.request = work,request
        _,self.ref,self.revision,self.historical = request
        if NamespaceId.from_key(AtomKey.from_token(self.ref)) != work.namespace or self.revision<1 or type(self.historical) is not bool:
            raise AuthorityUnavailable('Contact payload commitment crossed its exact namespace/revision')
        if (self.ref,self.revision) not in {(ref,revision) for ref,revision,_ in work.contact_locator.historical_read_metadata}:
            raise AuthorityUnavailable('Contact metadata EOF is outside its actual signed Plan read closure')
        self.cell,self.row,self.complete = None,None,False
    def advance(self,meter):
        from ..runtime_storage_v3 import RuntimeCellReadV3,_runtime_bounded_fixed_row_v3
        work = self.owner
        work.require_current(meter=meter)
        table = 'graph_history' if self.historical else 'graph_atoms'
        columns = ('revision','valid','value_cell_id')
        where,key = ('token=? AND revision=?',(self.ref,self.revision)) if self.historical else (
            'token=? AND bot=? AND persona=?',(self.ref,*work.namespace.as_tuple))
        current = _runtime_bounded_fixed_row_v3(work.db,meter,table,columns,where,key)
        if current is None or current[0]!=self.revision:
            raise AuthorityUnavailable('Contact physical payload lost its actual exact revision')
        if self.row is None:
            self.row = current
            self.cell = RuntimeCellReadV3(work.operation.handle,current[2],
                erasure_owner_ref=self.ref if self.historical else None,meter=meter)
            return
        if current != self.row:
            raise AuthorityUnavailable('Contact physical payload changed during same-Work EOF')
        fragment = self.cell.read_fragment(meter=meter)
        if fragment is not None:
            return
        digest = self.cell.finish(meter=meter)
        self.commitment = (self.cell.header[0],self.cell.header[3],digest)
        self.complete = True
    def require_for_v3(self,work):
        if not self.complete or work is not self.owner or work.attachments.get(self.request) is not self:
            raise AuthorityUnavailable('Contact physical payload lacks its actual same-Work full EOF')
        work._actual()
        return self.commitment


def contact_payload_commitment_v3(db,ref,revision,*,historical=False):
    from .contact_host_source_v3 import contact_host_work_for_db_v3
    from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
    work = contact_domain_work_for_db_v3(db) or contact_host_work_for_db_v3(db) or contact_authority_work_v3(db)
    if work is None:
        raise AuthorityUnavailable('Contact Plan3 cannot read raw payloads outside actual V3 Work')
    request = ('contact_payload_commitment',ref,revision,historical)
    task = work.attachments.get(request)
    if task is None:
        _require_contact_attachment_v3(work,request)
    return task.require_for_v3(work)


def contact_historical_metadata_inventory_v3(db,*,namespace,epoch,refs,kinds):
    from .contact_host_source_v3 import contact_host_work_for_db_v3
    from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
    work = contact_domain_work_for_db_v3(db) or contact_host_work_for_db_v3(db) or contact_authority_work_v3(db)
    if work is None:
        raise AuthorityUnavailable('Contact Plan3 history requires its actual V3 Work')
    request = ('contact_historical_inventory',namespace.as_tuple,epoch,tuple(refs),tuple(kinds))
    reader = work.attachments.get(request)
    if reader is None:
        _require_contact_attachment_v3(work,request)
    return reader.require_rows_v3(work)


def _require_contact_attachment_v3(work,request):
    from .contact_domain_source_work_v3 import ContactDomainSourceReadV3
    if type(work) is ContactDomainSourceReadV3:
        from .domain_background_read_v3 import BackgroundReadNeededV3
        if work.parent.sealed:
            raise AuthorityUnavailable('Contact WRITE cannot add a new original to its prepared READ set')
        raise BackgroundReadNeededV3(('contact_domain_attachment',work.selector.contact_id,work.selector.phase,request))
    from ..authority_service.current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
    raise AuthorityGraphAttachmentRequiredV3(request)


class ContactPlanPhysicalPayloadReadV3:
    def __init__(self,work,request):
        from .contact_plan_adoption_v3 import TABLE,COLUMNS,contact_plan_logical_descriptor_v3,SIGN_KIND
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
        self.owner,self.request = work,request
        _,namespace,contact_id = request
        if ((contact_domain_work_for_db_v3(work.db) or contact_host_work_for_db_v3(work.db) or contact_authority_work_v3(work.db)) is not work
                or namespace!=work.namespace.as_tuple or contact_id!=work.contact_selector.contact_id
                or work.source_material is None):
            raise AuthorityUnavailable('Contact Plan3 protected original requires its actual Source-qualified Work')
        require_contact_source_db_v3(work.db)
        work.contact_locator.require_v3(work)
        with runtime_storage_quantum_v3(work.db) as meter:
            work.require_current(meter=meter)
            self.row = _runtime_bounded_fixed_row_v3(work.db,meter,TABLE,COLUMNS,
                'bot=? AND persona=? AND contact_id=?',(*namespace,contact_id))
            if self.row is None or self.row[8]!=work.contact_locator.digest:
                raise AuthorityUnavailable('Contact Plan3 protected cell differs from its actual signed metadata locator')
            work.contact_issuer._signer.verify(SIGN_KIND,canonical_serialize(contact_plan_logical_descriptor_v3(self.row)),self.row[13])
        self.original = DispatchOriginalJSONReadV3(work,table=TABLE,column='payload_cell_id',
            key_columns=('bot','persona','contact_id'),key=(*namespace,contact_id),cell_id=self.row[4])
        if (self.original.cell.header[0],self.original.cell.header[3],self.original.cell.header[5])!=(self.row[5],self.row[6],self.row[7]):
            raise AuthorityUnavailable('Contact Plan3 protected payload exact physical descriptor differs')
        self.complete = False
        self.phase,self.domain_original,self.receipt_original,self.reads_original = 'plan',None,None,None
    def advance(self,meter):
        self.owner.require_current(meter=meter)
        require_contact_source_db_v3(self.owner.db)
        from .domain_production_originals_v1 import PHYSICAL_TABLE
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
        work = self.owner
        if self.phase=='plan':
            if self.original.advance(meter):
                if (self.original.sha256,self.original.byte_count)!=(self.row[8],self.row[6]):
                    raise AuthorityUnavailable('Contact Plan3 complete protected canonical EOF differs')
                self.domain_row = _runtime_bounded_fixed_row_v3(work.db,meter,PHYSICAL_TABLE,
                    ('domain','operation_kind','request_digest','original_digest','original_payload_cell_id',
                        'prepared_digest','bundle_digest','receipt_digest'),
                    'bot=? AND persona=? AND operation_id=?',(*work.namespace.as_tuple,self.row[3]))
                if self.domain_row is None or self.domain_row[:2]!=('d08','adopt_contact_expression_plan_v2'):
                    raise AuthorityUnavailable('Contact Plan3 actual physical adoption original is absent')
                self.domain_original = DispatchOriginalJSONReadV3(work,table=PHYSICAL_TABLE,column='original_payload_cell_id',
                    key_columns=('bot','persona','operation_id'),key=(*work.namespace.as_tuple,self.row[3]),cell_id=self.domain_row[4])
                self.phase = 'domain'
            return False
        if self.phase=='domain':
            if self.domain_original.advance(meter):
                if self.domain_original.sha256!=self.domain_row[3]:
                    raise AuthorityUnavailable('Contact Plan3 actual complete physical adoption EOF differs')
                self.receipt_original = DispatchOriginalJSONReadV3(work,table=PHYSICAL_TABLE,column='receipt_json',
                    key_columns=('bot','persona','operation_id'),key=(*work.namespace.as_tuple,self.row[3]))
                self.phase = 'receipt'
            return False
        if self.phase=='receipt':
            if self.receipt_original.advance(meter):
                self.reads_original = DispatchOriginalJSONReadV3(work,table=PHYSICAL_TABLE,column='read_versions_json',
                    key_columns=('bot','persona','operation_id'),key=(*work.namespace.as_tuple,self.row[3]))
                self.phase = 'reads'
            return False
        if self.phase=='reads':
            if self.reads_original.advance(meter):
                self.complete = True
            return self.complete
        raise AuthorityUnavailable('Contact Plan3 original reader has no other phase')
    def require_row_v3(self,work,meter):
        from .contact_plan_adoption_v3 import TABLE,COLUMNS
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        if (work is not self.owner or not self.complete or work.attachments.get(self.request) is not self
                or _runtime_bounded_fixed_row_v3(work.db,meter,TABLE,COLUMNS,
                    'bot=? AND persona=? AND contact_id=?',self.row[:3])!=self.row):
            raise AuthorityUnavailable('Contact Plan3 protected body lost its actual same-Work durable physical original')
        require_contact_source_db_v3(work.db)
        work.contact_locator.require_v3(work)
        return self.original.require_v3(work)


def contact_plan_physical_payload_v3(db,namespace,contact_id):
    work = contact_domain_work_for_db_v3(db) or contact_host_work_for_db_v3(db) or contact_authority_work_v3(db)
    if work is None or work.namespace!=namespace:
        raise AuthorityUnavailable('Contact Plan3 physical payload needs its actual current Source Work')
    require_contact_source_db_v3(db)
    request = ('contact_plan_physical_payload',namespace.as_tuple,contact_id)
    task = work.attachments.get(request)
    if task is None or not task.complete:
        _require_contact_attachment_v3(work,request)
    with runtime_storage_quantum_v3(db) as meter:
        work.require_current(meter=meter)
        return task.require_row_v3(work,meter)


def contact_plan_physical_adoption_v3(db,namespace,contact_id):
    from .domain_production_originals_v1 import _receipt
    from ..graph_types import GraphVersion
    from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
    contact_plan_physical_payload_v3(db,namespace,contact_id)
    work = contact_domain_work_for_db_v3(db) or contact_host_work_for_db_v3(db) or contact_authority_work_v3(db)
    task = work.attachments[('contact_plan_physical_payload',namespace.as_tuple,contact_id)]
    raw,reads_wire = task.domain_original.require_v3(work),task.reads_original.require_v3(work)
    receipt = _receipt(task.receipt_original.require_v3(work))
    reads = tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in reads_wire)
    if (receipt.operation_id!=task.row[3] or receipt.read_versions!=reads or receipt.operation_digest!=task.domain_row[6]
            or canonical_digest(receipt)!=task.row[12] or task.row[12]!=task.domain_row[7]
            or raw['namespace']!={'bot_id':namespace.bot_id,'persona_id':namespace.persona_id}
            or raw['identity']['operation_id']!=task.row[3]):
        raise AuthorityUnavailable('Contact Plan3 physical adoption full receipt/namespace/readset identity differs')
    with runtime_storage_quantum_v3(db) as meter:
        work.require_current(meter=meter)
        bundle = _runtime_bounded_fixed_row_v3(db,meter,'graph_bundle_operations',
            ('digest','activity_id','effect_id','commit_seq'),'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,task.row[3]))
        if bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
            raise AuthorityUnavailable('Contact Plan3 actual durable W01 bundle is absent or differs')
    return {'domain':'d08','operation_kind':'adopt_contact_expression_plan_v2','request_digest':task.domain_row[2],
        'original_digest':task.domain_row[3],'payload':raw,'read_versions':reads,'receipt':receipt}
