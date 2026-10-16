"""Actual Contact Authority Work over selected V3 Source cells and full EOF originals."""
from dataclasses import dataclass
import json
from weakref import WeakKeyDictionary

from .contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from ..runtime.c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3

_LOCATORS = WeakKeyDictionary()
_SELECTORS = WeakKeyDictionary()
_BACKGROUND_WORKS = WeakKeyDictionary()


def _locator_metadata_digest_v3(locator):
    return canonical_digest((tuple(sorted(locator.values.items())),locator.plan_metadata,
        tuple(sorted(locator.versions.items())),locator.protected_history,locator.historical_read_metadata,locator.original_table,locator.original_sign_kind,locator.source_purposes))


@dataclass(frozen=True, slots=True)
class ContactBackgroundSelectorV3:
    namespace: NamespaceId
    contact_id: str
    operation_id: str
    request_digest: str
    policy_id: str
    dedupe_key: str

    def __post_init__(self):
        from .contract import identifier
        if type(self.namespace) is not NamespaceId:
            raise ValueError('Contact selector requires its exact namespace type')
        for name in ('contact_id','operation_id','policy_id','dedupe_key'):
            identifier(getattr(self,name),name)
        if (not self.contact_id.startswith('contact:') or len(self.request_digest) != 64
                or any(c not in '0123456789abcdef' for c in self.request_digest)):
            raise ValueError('Contact selector exact original identity differs')


def contact_authority_work_v3(db):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work = _authority_attachment_owner_v3(db)
    if work is None:
        return None
    if type(getattr(work,'contact_selector',None)) is ContactBackgroundSelectorV3:
        require_contact_background_work_v3(work)
    else:
        from .contact_model_work_v3 import require_model_contact_work_v3
        require_model_contact_work_v3(work)
    return work


class ContactPlanLocatorEOFV3:
    def __init__(self,work):
        self.work = work
        self.origin_scope = work.scope
        self.phase = 'metadata'
        self.offset = 0
        self.fragment = b''
        self.fragment_offset = 0
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.scalar = bytearray()
        self.values = {}
        self.plan_nodes = {}
        self.plan_metadata = None
        self.plan_scalar = bytearray()
        self.versions = {}
        self.historical_source_versions = {}
        self.purpose_rows = {}
        self.complete = False
        self.metadata = None
        self.digest = None
        self.reserved = 0
        self.physical_cell,self.physical_row = None,None
    def _reserve(self,extra=0):
        from ..runtime.source_correction_read_v3 import _heap
        size = _heap((self.values,self.plan_nodes,self.plan_scalar,self.versions,self.historical_source_versions,self.scalar,self.fragment)) + extra + 65536
        if size > self.reserved:
            self.work.operation.retain(size-self.reserved)
            self.reserved = size
    def _selected(self,path):
        allowed = {'contact_id','audience_id','parent_budget_lease_id','policy_original_ref',
            'policy_original_digest','policy_version','valid_until_utc','budget_grant_version','budget_grant_digest'}
        return (len(path)==3 and path[0]=='source_purposes' and path[2]=='ref'
            or len(path)==4 and path[0]=='source_purposes' and path[2]=='purposes'
            or path == ('proof','schema') or len(path)==2 and path[0]=='plan' and path[1] in allowed
            or path in {('plan','source_ref','ref'),('plan','namespace','bot_id'),('plan','namespace','persona_id')}
            or len(path)==4 and path[:2]==('plan','qualified_read_versions') and path[3] in {'key','revision'}
            or len(path)==4 and path[0]=='proof' and path[1] in {'historical_reads','current_reads'} and path[3] in {'ref','revision','valid'})
    def _emit(self,event):
        # The Plan DTO has locators, scalar limits and digests; it carries no expression text.
        if event.path and event.path[0] == 'plan':
            path = event.path[1:]
            if event.kind in {'object_start','array_start'}:
                value = {} if event.kind == 'object_start' else []
                self.plan_nodes[path] = value
                if not path:
                    self.plan_metadata = value
                else:
                    parent = self.plan_nodes[path[:-1]]
                    if type(parent) is list:
                        parent.append(value)
                    else:
                        parent[path[-1]] = value
                self._reserve()
            elif event.kind == 'scalar_start':
                self.plan_scalar = bytearray()
            elif event.kind == 'scalar_chunk':
                self._reserve(len(event.raw)*4+1024)
                self.plan_scalar.extend(event.raw)
            elif event.kind == 'scalar_end':
                value = json.loads(self.plan_scalar)
                self.plan_scalar = bytearray()
                parent = self.plan_nodes[path[:-1]]
                if type(parent) is list:
                    parent.append(value)
                else:
                    parent[path[-1]] = value
                self._reserve()
        if not self._selected(event.path):
            return
        if event.kind == 'scalar_start':
            self.scalar = bytearray()
        elif event.kind == 'scalar_chunk':
            self._reserve(len(event.raw)*4+1024)
            self.scalar.extend(event.raw)
        elif event.kind == 'scalar_end':
            value = json.loads(self.scalar)
            self.scalar = bytearray()
            if event.path[0]=='source_purposes':
                row=self.purpose_rows.setdefault(event.path[1],{'purposes':{}})
                if event.path[2]=='ref':row['ref']=value
                else:row['purposes'][event.path[3]]=value
            elif len(event.path)==4 and event.path[:2]==('plan','qualified_read_versions'):
                self.versions.setdefault(event.path[2],{})[event.path[3]] = value
            elif len(event.path)==4 and event.path[0]=='proof' and event.path[1] in {'historical_reads','current_reads'}:
                self.historical_source_versions.setdefault((event.path[1],event.path[2]),{})[event.path[3]] = value
            else:
                self.values[event.path] = value
            self._reserve()
    def advance(self,meter):
        from ..runtime.contact_plan_adoption_v2 import TABLE,SIGN_KIND
        work = self.work
        work.require_current(meter=meter)
        key = (*work.namespace.as_tuple,work.contact_selector.contact_id)
        if self.phase == 'metadata':
            from ..runtime.contact_plan_adoption_v3 import TABLE as TABLE3,SIGN_KIND as SIGN_KIND3
            exists3 = work.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE3,)).fetchone()
            meter.charge_read(8)
            from ..runtime.contact_plan_adoption_v3 import COLUMNS,contact_plan_logical_descriptor_v3
            row3 = None if exists3 is None else _runtime_bounded_fixed_row_v3(work.db,meter,TABLE3,COLUMNS,
                'bot=? AND persona=? AND contact_id=?',key)
            self.original_table = TABLE3 if row3 is not None else TABLE
            self.original_sign_kind = SIGN_KIND3 if row3 is not None else SIGN_KIND
            TABLE = self.original_table
            if row3 is not None:
                descriptor = contact_plan_logical_descriptor_v3(row3)
                work.contact_issuer._signer.verify(SIGN_KIND3,canonical_serialize(descriptor),row3[13])
                from ..runtime_storage_v3 import RuntimeCellReadV3
                self.physical_row = row3
                self.metadata = (row3[8],row3[13])
                self.physical_cell = RuntimeCellReadV3(work.operation.handle,row3[9],meter=meter)
                if (self.physical_cell.header[0],self.physical_cell.header[3],self.physical_cell.header[5])!=(
                        'canonical-json.ascii.v1',row3[10],row3[11]):
                    raise AuthorityUnavailable('Contact Plan3 signed Source metadata cell descriptor differs')
                self.total = row3[10]
            else:
                self.metadata = _runtime_bounded_fixed_row_v3(work.db,meter,TABLE,('payload_digest','signature'),
                    'bot=? AND persona=? AND contact_id=?',key)
                if self.metadata is None:
                    raise AuthorityUnavailable('Contact actual immutable Plan locator absent')
                self.total = work.db.execute(f'SELECT length(CAST(payload_json AS BLOB)) FROM {TABLE} WHERE bot=? AND persona=? AND contact_id=?',key).fetchone()[0]
                meter.charge_read(8)
            self.phase = 'body'
            return
        TABLE,SIGN_KIND = self.original_table,self.original_sign_kind
        if self.phase == 'body':
            if self.fragment_offset < len(self.fragment):
                end = min(self.fragment_offset+1024,len(self.fragment))
                self.parser.feed(self.fragment[self.fragment_offset:end],self._emit)
                self.fragment_offset = end
                return
            if self.offset == self.total:
                self.phase = 'eof'
                return
            if self.physical_cell is not None:
                fragment = self.physical_cell.read_fragment(meter=meter)
                total,kind = self.total,'text'
            else:
                fragment, total, kind = read_legacy_sql_cell_fragment_v2(work.db,table=TABLE,column='payload_json',
                    where='bot=? AND persona=? AND contact_id=?',parameters=key,start=self.offset,
                    length=min(16384,self.total-self.offset),meter=meter)
            if total != self.total or kind != 'text':
                raise AuthorityUnavailable('Contact locator actual Source column kind/length changed')
            if fragment:
                self._reserve(len(fragment)+1024)
                self.fragment = fragment
                self.fragment_offset = 0
                self.offset += len(fragment)
                return
            self.phase = 'eof'
            return
        from ..runtime.contact_plan_adoption_v3 import COLUMNS
        result = self.parser.finish()
        if self.physical_cell is not None:
            digest = self.physical_cell.finish(meter=meter)
            if (result.sha256,result.byte_count,digest)!=(self.physical_row[11],self.physical_row[10],self.physical_row[11]):
                raise AuthorityUnavailable('Contact Plan3 signed metadata canonical/physical EOF differs')
            actual = _runtime_bounded_fixed_row_v3(work.db,meter,TABLE,COLUMNS,
                'bot=? AND persona=? AND contact_id=?',key)
            if actual!=self.physical_row:
                raise AuthorityUnavailable('Contact Plan3 physical original changed while reading metadata')
        else:
            if result.sha256 != self.metadata[0]:
                raise AuthorityUnavailable('Contact locator whole canonical EOF SHA differs')
            work.contact_issuer._signer.verify(SIGN_KIND,
                canonical_serialize((work.namespace,work.contact_selector.contact_id,result.sha256)),self.metadata[1])
        ns = NamespaceId(self.values[('plan','namespace','bot_id')],self.values[('plan','namespace','persona_id')])
        policy = work.contact_policy
        from ..runtime.contact_host_stage_work_v3 import ContactHostStageReadWorkV3
        from ..runtime.contact_domain_source_work_v3 import ContactDomainSourceReadV3
        from ..runtime.contact_background_plan_metadata_v3 import (ContactBackgroundPlanMetadataWorkV3,
            require_contact_background_plan_metadata_work_v3)
        background_metadata=type(work)is ContactBackgroundPlanMetadataWorkV3
        if background_metadata:require_contact_background_plan_metadata_work_v3(work)
        domain_metadata = type(work) is ContactDomainSourceReadV3
        if domain_metadata:
            from ..runtime.contact_domain_source_v3 import require_contact_domain_work_v3
            require_contact_domain_work_v3(work)
        host_metadata = type(work) is ContactHostStageReadWorkV3
        if host_metadata:
            from ..runtime.contact_host_source_v3 import require_contact_host_work_v3
            require_contact_host_work_v3(work)
        if (ns != work.namespace or self.values[('plan','contact_id')] != work.request.contact_id
                or not (host_metadata or domain_metadata or background_metadata) and (self.values[('plan','policy_original_ref')] != policy.original_ref
                    or self.values[('plan','policy_original_digest')] != policy.digest)
                or len(self.versions) > 1024):
            raise AuthorityUnavailable('Contact signed Plan locator/current standing policy scope differs')
        self.root = self.values[('plan','source_ref','ref')]
        self.audience = self.values[('plan','audience_id')]
        roots = []
        for item in self.versions.values():
            if set(item) != {'key','revision'}:
                raise AuthorityUnavailable('Contact qualified locator revision fields differ')
            atom = AtomKey.from_token(item['key'])
            if NamespaceId.from_key(atom) != ns:
                raise AuthorityUnavailable('Contact signed qualified Source locator crossed namespace')
            if atom.type_name == 'memory.source' and item['revision'] > 0:
                roots.append(atom.token)
        # Full Plan2 provenance carries historical value_json. Every actual Source body
        # parsed by the later full original reader needs today's exact rights/version.
        protected_history = {}
        for item in self.historical_source_versions.values():
            if set(item) != {'ref','revision','valid'}:
                raise AuthorityUnavailable('Contact signed historical Source metadata is incomplete')
            atom = AtomKey.from_token(item['ref'])
            if NamespaceId.from_key(atom) != ns:
                raise AuthorityUnavailable('Contact historical Plan body locator crossed namespace')
            if (self.values.get(('proof','schema')) != 'd08.contact_expression_plan_provenance.v3'
                    and atom.type_name == 'memory.source' and item['revision'] > 0):
                if not item['valid']:
                    raise AuthorityUnavailable('Contact Plan2 embeds an invalid historical Source body; protected metadata-only producer required')
                protected_history[atom.token] = item['revision']
                roots.append(atom.token)
        prepared_locator = getattr(work,'contact_prepared_locator',None)
        if prepared_locator is not None:
            prepared_locator.require_v3(work)
            for ref,revision in prepared_locator.frozen_metadata.sources:
                if ref in protected_history and protected_history[ref] != revision:
                    raise AuthorityUnavailable('Contact Plan and nested frozen protected Source revisions differ')
                protected_history[ref] = revision
                roots.append(ref)
        self.historical_read_metadata = tuple(sorted((item['ref'],item['revision'],item['valid'])
            for item in self.historical_source_versions.values()))
        self.protected_history = tuple(sorted(protected_history.items()))
        self.roots = tuple(sorted(set(roots)))
        if self.root not in self.roots or not self.audience or len(self.roots) > 256:
            raise AuthorityUnavailable('Contact signed Plan source family is incomplete or exceeds its existing bound')
        if self.physical_row is not None:
            if len(self.purpose_rows)!=len(self.roots):
                raise AuthorityUnavailable('Contact Plan3 signed per-Source purpose metadata lacks complete root coverage')
            purposes={}
            for index,row in sorted(self.purpose_rows.items()):
                if set(row)!={'ref','purposes'} or row['ref']in purposes or row['ref']not in self.roots:
                    raise AuthorityUnavailable('Contact Plan3 signed Source purposes have another exact metadata ref')
                values=tuple(value for _,value in sorted(row['purposes'].items()))
                if not values or values!=tuple(sorted(set(values))) or not set(values)<={'expression','context'}:
                    raise AuthorityUnavailable('Contact Plan3 Source purpose group differs from its fixed two-use contract')
                purposes[row['ref']]=values
            self.source_purposes=purposes
        else:
            self.source_purposes=None
        self.digest = self.metadata[0]
        self.complete = True
        self.fragment = b''
        self.parser = None
        _LOCATORS[self] = (work,work.request,work.operation,self.origin_scope,self.metadata,self.digest,self.root,self.audience,self.roots,_locator_metadata_digest_v3(self))
        from .current_authority_graph_read_v3 import _track_authority_capability_v3
        from ..runtime.contact_host_source_v3 import track_contact_host_metadata_v3
        from ..runtime.contact_domain_source_v3 import track_contact_domain_metadata_v3
        from ..runtime.contact_background_plan_metadata_v3 import track_contact_background_plan_metadata_v3
        if not (track_contact_host_metadata_v3(work,_LOCATORS,self) or track_contact_domain_metadata_v3(work,_LOCATORS,self)
                or track_contact_background_plan_metadata_v3(work,_LOCATORS,self)):
            _track_authority_capability_v3(work,_LOCATORS,self)
    def require_v3(self,work):
        if (not self.complete or _LOCATORS.get(self) != (work,work.request,work.operation,self.origin_scope,
                self.metadata,self.digest,self.root,self.audience,self.roots,
                _locator_metadata_digest_v3(self)) or work.contact_locator is not self):
            raise AuthorityUnavailable('Contact locator lost its actual complete EOF/Work/SourceDB origin')
        work._actual()
        return self


class ContactAuthoritySourceSelectionV3:
    def __init__(self,work,locator):
        locator.require_v3(work)
        self.work = work
        self.locator = locator
        for item in locator.versions.values():
            current = work.heads.get(item['key'])
            if (current is not None if item['revision'] == 0 else
                    current is None or current[0] != item['revision'] or not current[1]):
                raise AuthorityUnavailable('Contact current Source/rights/Owner/policy locator changed before body decode')
        for ref,revision in locator.protected_history:
            current = work.heads.get(ref)
            if current is None or current[0] != revision or not current[1]:
                raise AuthorityUnavailable('Contact historical Source body has no current exact version/rights to decode')
        self.root,self.audience,self.roots = locator.root,locator.audience,locator.roots
        from ..runtime.contact_source_purposes_v3 import contact_plan_source_purpose_groups_v3
        self.purpose_groups=contact_plan_source_purpose_groups_v3(work,locator,self.roots)
        self.purpose = 'expression'
        self.maximum_ancestors = 256
        self.attention = None
        _SELECTORS[self] = (work,locator,work.contact_policy,work.operation,work.scope,self.root,self.audience,self.roots,self.purpose_groups)
        from .current_authority_graph_read_v3 import _track_authority_capability_v3
        _track_authority_capability_v3(work,_SELECTORS,self)
    def require_v3(self,work):
        if _SELECTORS.get(self) != (work,self.locator,work.contact_policy,work.operation,work.scope,
                self.root,self.audience,self.roots,self.purpose_groups) or work.source_selection is not self:
            raise AuthorityUnavailable('Contact Source selection differs from its actual signed Plan/policy/Work')
        self.locator.require_v3(work)
        return self


def begin_contact_authority_graph_read_v3(service, *, credential, subject, permit, selector, policy, location):
    from .contact_model_result_service_v2 import InstalledContactModelResultServiceV2
    from .current_authority_graph_read_v3 import (
        require_authority_graph_read_controller_v3,AuthorityGraphReadWorkV3,_ISSUER,_AuthorityCatalogueReadV3)
    if type(service) is not InstalledContactModelResultServiceV2 or type(selector) is not ContactBackgroundSelectorV3:
        raise AuthorityUnavailable('Contact requires its exact installed result service and finite selector')
    controller = require_authority_graph_read_controller_v3(service)
    if (controller.kind != 'contact' or controller.service is not service or controller.location is not service._location
            or policy is None or policy.namespace != selector.namespace or policy.policy.policy_id != selector.policy_id
            or policy.installation_id != service._installation_id):
        raise AuthorityUnavailable('Contact actual Controller/current policy installation differs')
    work = AuthorityGraphReadWorkV3(_ISSUER,controller,credential=credential,subject=subject,permit=permit,
        namespace=selector.namespace,request=selector,deadline_utc=policy.policy.window_end)
    work.contact_policy = policy
    work.contact_selector = selector
    work.contact_issuer = service._issuer
    work.contact_location = location
    work.contact_locator = ContactPlanLocatorEOFV3(work)
    work.now_utc = service._clock()
    work.parent_original_id = selector.operation_id
    work.catalogue_reader = _AuthorityCatalogueReadV3(work)
    work.phase = 'contact_locator'
    _BACKGROUND_WORKS[work] = (service,controller,service._location,service._issuer,policy,selector,
        work.operation,work.scope,permit,credential,subject)
    from .current_authority_graph_read_v3 import _track_authority_capability_v3
    _track_authority_capability_v3(work,_BACKGROUND_WORKS,work)
    return work


def require_contact_background_work_v3(work):
    from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
    from .contact_model_result_service_v2 import InstalledContactModelResultServiceV2
    if type(work) is not AuthorityGraphReadWorkV3:
        raise AuthorityUnavailable('Contact background requires its actual independent Authority Work')
    work._actual()
    saved = _BACKGROUND_WORKS.get(work)
    if saved is None:
        raise AuthorityUnavailable('Contact background Work has no actual installed producer registry')
    service,controller,location,issuer,policy,selector,operation,scope,permit,credential,subject = saved
    controller.require_installed_v3()
    if (type(service) is not InstalledContactModelResultServiceV2 or type(selector) is not ContactBackgroundSelectorV3
            or work.service is not service or work.controller is not controller or controller.kind != 'contact'
            or controller.service is not service or controller.location is not location
            or service._location is not location or service._issuer is not issuer or work.contact_issuer is not issuer
            or work.contact_policy is not policy or work.contact_selector is not selector
            or work.operation is not operation or work.scope is not scope or work.permit is not permit
            or work.credential is not credential or work.subject != subject or work.namespace != selector.namespace
            or permit.operation not in {'read','write'} or policy.namespace != selector.namespace
            or policy.policy.policy_id != selector.policy_id or policy.installation_id != service._installation_id):
        raise AuthorityUnavailable('Contact background original service/selector/permit/retention tuple changed')
    return saved


def advance_contact_authority_material_v3(work,meter):
    from .current_authority_graph_read_v3 import (
        _AuthoritySourceMaterialReadV3,_DEADLINES)
    if work.phase == 'contact_locator':
        work.contact_locator.advance(meter)
        if work.contact_locator.complete:
            deadline = min(work.deadline_utc,work.contact_locator.values[('plan','valid_until_utc')])
            if getattr(work,'contact_prepared_locator',None) is not None:
                if work.contact_prepared_locator.values[('plan_original_digest',)] != work.contact_locator.digest:
                    raise AuthorityUnavailable('Contact prepared birth Plan differs from its full signed locator EOF')
            if not work.service._clock() < deadline:
                raise AuthorityUnavailable('Contact actual signed Plan/policy original deadline expired')
            work.deadline_utc = float(deadline)
            work.operation.deadline_utc = float(deadline)
            work.deadline_original = work.contact_locator
            _DEADLINES[work] = (work.operation,work.deadline_utc,work.deadline_original)
            work.phase = 'catalogue'
        return
    if work.phase == 'contact_source':
        if work.source_reader is None:
            from ..runtime.contact_continuation_v1 import contact_continuation_projection_source_reader_v1
            handled,metadata_reader=contact_continuation_projection_source_reader_v1(work)
            if handled:work.source_reader=metadata_reader
            else:
                work.source_selection = ContactAuthoritySourceSelectionV3(work,work.contact_locator)
                work.source_reader = _AuthoritySourceMaterialReadV3(work,work.source_selection)
        work.source_reader.advance_v3(meter)
        if work.source_reader.complete:
            work.source_material = work.source_reader.proof
            work.phase = 'validate'
        return
    raise AuthorityUnavailable('Unregistered Contact Authority material phase')


def require_contact_source_db_v3(db):
    from ..runtime.contact_domain_source_v3 import contact_domain_work_for_db_v3
    domain = contact_domain_work_for_db_v3(db)
    if domain is not None:
        domain.require_current_v3()
        domain.contact_locator.require_v3(domain)
        if not domain.complete or domain.source_material is None or domain.scope is not domain.parent.read_scope:
            raise AuthorityUnavailable('Contact domain protected Source lacks its exact actual current material EOF')
        if domain.parent.sealed:
            from ..runtime.contact_domain_source_v3 import require_contact_domain_fresh_write_v3
            require_contact_domain_fresh_write_v3(domain,db)
        return domain
    from ..runtime.contact_host_source_v3 import contact_host_work_for_db_v3
    host = contact_host_work_for_db_v3(db)
    if host is not None:
        host.require_current_v3()
        host.contact_locator.require_v3(host)
        if host.source_material is None or host.operation.handle is None or host.scope is None:
            raise AuthorityUnavailable("Contact Host SourceDB lacks its actual Scope/current material EOF")
        return host
    work = contact_authority_work_v3(db)
    if work is None:
        return None
    work.controller.require_installed_v3()
    work.contact_locator.require_v3(work)
    work.controller.location.require_graph_snapshot_v1(db,work.contact_location,graph_db_path=work.controller.location._graph_db_path)
    if (work.source_material is None or work.source_material.selection is not work.source_selection
            or work.operation.handle is not work.handle or work.db is not db):
        raise AuthorityUnavailable('Contact actual SourceDB proof/material/original retention differs')
    return work
