"""Independent Contact model/result Work identity and fixed metadata parentage."""
from dataclasses import dataclass
from weakref import WeakKeyDictionary
from .contract import AuthorityUnavailable
from ..runtime_contracts import NamespaceId

_PAIRS = WeakKeyDictionary()
_CONTACT_WORKS = WeakKeyDictionary()
_POLICIES = WeakKeyDictionary()
_PREPARED_METADATA = WeakKeyDictionary()

@dataclass(frozen=True,slots=True)
class ModelContactReadSelectorV3:
    namespace: NamespaceId
    contact_id: str
    phase: str
    job_id: str
    prepared_ref: str
    prepared_digest: str
    role: str
    read_attempt_id: str | None
    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or self.phase not in {'contact_generation','contact_review'}
                or self.role not in {'model','result'} or not self.contact_id.startswith('contact:')
                or self.prepared_ref != self.job_id or len(self.prepared_digest) != 64
                or (self.read_attempt_id is None) != (self.role == 'model')):
            raise AuthorityUnavailable('Contact independent model/result selector original differs')


def install_contact_work_pair_v3(model,result):
    from .v2_model_egress_service import AuthorityV2ModelEgressService
    from .contact_model_result_service_v2 import InstalledContactModelResultServiceV2
    from .current_authority_graph_read_v3 import require_authority_graph_read_controller_v3
    if (type(model) is not AuthorityV2ModelEgressService or type(result) is not InstalledContactModelResultServiceV2
            or model._store is not result._store or model._fences is not result._fences
            or model._graph_verifier._path != result._path or model._source_location is not result._location
            or model._graph_verifier._issuer is not result._issuer
            or model._graph_verifier._contact_policy_service is not result._policy):
        raise AuthorityUnavailable('Contact actual installed model/result/policy/Source tuple differs')
    from .current_authority_graph_read_v3 import install_authority_graph_read_controller_v3
    install_authority_graph_read_controller_v3(model._graph_verifier,service=model,source_location=result._location)
    controller = require_authority_graph_read_controller_v3(model._graph_verifier)
    reader = require_authority_graph_read_controller_v3(result)
    if controller.kind != 'model' or reader.kind != 'contact' or controller.control is not reader.control:
        raise AuthorityUnavailable('Contact actual independent Work controllers differ')
    previous = _PAIRS.get(model)
    pair = (result,model._graph_verifier,controller,reader,result._policy,result._location,result._issuer)
    if previous is not None and previous != pair:
        raise AuthorityUnavailable('Contact installed service pairing cannot be replaced')
    _PAIRS[model] = pair


def contact_pair_for_model_v3(model):
    pair = _PAIRS.get(model)
    if pair is None:
        raise AuthorityUnavailable('Contact actual installed model/result pairing is absent')
    result,verifier,controller,reader,policy,location,issuer = pair
    controller.require_installed_v3()
    reader.require_installed_v3()
    if (model._graph_verifier is not verifier or result._policy is not policy or result._location is not location
            or result._issuer is not issuer or model._fences is not result._fences or model._store is not result._store):
        raise AuthorityUnavailable('Contact actual installed pair changed')
    return pair


def register_contact_work_v3(work, *, model, selector, intent):
    from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
    from .v2_model_egress_contract import ModelEgressIntentV1,ModelEgressDraftV1
    if type(work) is not AuthorityGraphReadWorkV3 or type(selector) is not ModelContactReadSelectorV3:
        raise AuthorityUnavailable('Contact requires an actual independent typed Authority Work')
    work._actual()
    pair = contact_pair_for_model_v3(model)
    result,verifier,controller,reader,policy,location,issuer = pair
    if (type(intent) not in {ModelEgressIntentV1,ModelEgressDraftV1} or selector.namespace != work.namespace
            or selector.job_id != intent.job_id or selector.prepared_digest != intent.binding_digest
            or selector.role == 'model' and (work.controller is not controller or work.service is not model
                or work.permit.operation != 'model_egress' or work.permit.operation_id != intent.operation_id
                or work.subject != intent.subject or work.permit.pinned_anchor.authority_id != intent.authority_id)
            or selector.role == 'result' and (work.controller is not reader or work.service is not result
                or work.permit.operation != 'read' or work.permit.operation_id != selector.read_attempt_id)):
        raise AuthorityUnavailable('Contact original permit/intent/job cannot borrow another Work phase')
    work.contact_selector,work.contact_intent,work.contact_issuer = selector,intent,issuer
    work.contact_policy_service = policy
    _CONTACT_WORKS[work] = (pair,selector,intent,work.operation,work.scope,work.permit)
    from .current_authority_graph_read_v3 import _track_authority_capability_v3
    _track_authority_capability_v3(work,_CONTACT_WORKS,work)
    return work


def require_model_contact_work_v3(work):
    from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
    if type(work) is not AuthorityGraphReadWorkV3:
        raise AuthorityUnavailable('Contact cannot borrow a generic caller context')
    work._actual()
    saved = _CONTACT_WORKS.get(work)
    if saved is None or saved[1:] != (work.contact_selector,work.contact_intent,work.operation,work.scope,work.permit):
        raise AuthorityUnavailable('Contact actual model/result Work lost its installed original identity')
    pair,selector,intent,operation,scope,permit = saved
    pair[2].require_installed_v3()
    pair[3].require_installed_v3()
    return saved


class ContactFrozenMetadataEOFV3:
    """Decode only canonical nested selectors, discarding every protected scalar."""
    def __init__(self,work):
        from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.work = work
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.started = self.finished = self.escape = False
        self.unicode = None
        self.scalar = bytearray()
        self.fields = {}
        self.sources = {}
        self.result = None
    def feed_outer_v3(self,raw):
        decoded = bytearray()
        for byte in raw:
            if not self.started:
                if byte != 34:
                    raise AuthorityUnavailable('Contact frozen metadata must originate in the actual JSON string')
                self.started = True
                continue
            if self.finished:
                raise AuthorityUnavailable('Contact frozen string metadata has trailing scalar bytes')
            if self.unicode is not None:
                self.unicode.append(byte)
                if len(self.unicode) == 4:
                    value = int(self.unicode.decode('ascii'),16)
                    if value > 127:
                        raise AuthorityUnavailable('Contact frozen original must preserve its canonical ASCII JSON codec')
                    decoded.append(value)
                    self.unicode = None
                continue
            if self.escape:
                self.escape = False
                if byte == 117:
                    self.unicode = bytearray()
                else:
                    decoded.append({34:34,92:92,47:47,98:8,102:12,110:10,114:13,116:9}[byte])
                continue
            if byte == 92:
                self.escape = True
            elif byte == 34:
                self.finished = True
            else:
                decoded.append(byte)
        if decoded:
            self.parser.feed(bytes(decoded),self._emit)
    def _selected(self,path):
        return (path[:3] == ('input','adopted_plan','source_ref') and len(path) == 4 and path[-1] in {'ref','version'}
            or path[:3] == ('input','adopted_plan','qualified_read_versions') and len(path) == 5 and path[-1] in {'key','revision'}
            or path[:3] == ('input','expression_plan','units') and len(path) == 7
                and path[4] == 'source_refs' and path[-1] in {'ref','version'})
    def _emit(self,event):
        if not self._selected(event.path):
            return
        if event.kind == 'scalar_start':
            self.scalar = bytearray()
        elif event.kind == 'scalar_chunk':
            self.work.operation.retain(len(event.raw)*4+512)
            self.scalar.extend(event.raw)
        elif event.kind == 'scalar_end':
            import json
            value = json.loads(self.scalar)
            self.fields.setdefault(event.path[:-1],{})[event.path[-1]] = value
            self.scalar = bytearray()
    def finish_v3(self):
        from ..graph_types import AtomKey
        if not self.finished or self.escape or self.unicode is not None:
            raise AuthorityUnavailable('Contact nested frozen selector has no complete string EOF')
        self.result = self.parser.finish()
        for fields in self.fields.values():
            if set(fields) not in ({'ref','version'},{'key','revision'}):
                raise AuthorityUnavailable('Contact nested protected Source locator is incomplete')
            ref = fields.get('ref',fields.get('key'))
            revision = fields.get('version',fields.get('revision'))
            key = AtomKey.from_token(ref)
            if NamespaceId.from_key(key) != self.work.namespace:
                raise AuthorityUnavailable('Contact nested frozen Source escaped its exact namespace')
            if key.type_name == 'memory.source' and revision > 0:
                if ref in self.sources and self.sources[ref] != revision:
                    raise AuthorityUnavailable('Contact frozen original has inconsistent protected Source revisions')
                self.sources[ref] = revision
        self.sources = tuple(sorted(self.sources.items()))
        self.fields = {}
        self.parser = None
        return self.result


class ContactPreparedLocatorEOFV3:
    """Authenticate prepared whole bytes while retaining no frozen/request body."""
    def __init__(self,work,*,model,intent,role,read_attempt_id=None):
        from .contact_background_graph_v3 import ContactPlanLocatorEOFV3
        self.work,self.model,self.intent,self.role,self.read_attempt_id = work,model,intent,role,read_attempt_id
        self.reader = ContactPlanLocatorEOFV3(work)
        self.reader._selected = self._selected
        self.frozen_metadata = ContactFrozenMetadataEOFV3(work)
        original_emit = self.reader._emit
        def metadata_emit(event):
            if event.path == ('frozen_json',) and event.kind == 'scalar_chunk':
                self.frozen_metadata.feed_outer_v3(event.raw)
            else:
                original_emit(event)
        self.reader._emit = metadata_emit
        self.complete = False
        self.selector = None
    def _selected(self,path):
        allowed = {'contact_id','phase','job_id','installation_id','prepare_operation_id','acquire_operation_id',
            'call_id','plan_original_digest','frozen_digest','quote_id','quote_version','quote_digest','reservation_digest'}
        return len(path)==1 and path[0] in allowed or path in {('namespace','bot_id'),('namespace','persona_id')}
    def advance(self,meter):
        from ..runtime.contact_paid_original_v2 import TABLE,SIGN_KIND
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from ..runtime.c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
        from ..runtime_contracts import canonical_serialize
        work,r = self.work,self.reader
        work.require_current(meter=meter)
        key = (*work.namespace.as_tuple,'prepared',self.intent.job_id)
        where = 'bot=? AND persona=? AND kind=? AND original_ref=?'
        if r.phase == 'metadata':
            r.metadata = _runtime_bounded_fixed_row_v3(work.db,meter,TABLE,('payload_digest','signature'),where,key)
            if r.metadata is None:
                raise AuthorityUnavailable('Contact actual prepared metadata original absent')
            r.total = work.db.execute('SELECT length(CAST(payload_json AS BLOB)) FROM '+TABLE+' WHERE '+where,key).fetchone()[0]
            meter.charge_read(8)
            r.phase = 'body'
            return
        if r.phase == 'body':
            if r.fragment_offset < len(r.fragment):
                end = min(r.fragment_offset+1024,len(r.fragment))
                r.parser.feed(r.fragment[r.fragment_offset:end],r._emit)
                r.fragment_offset = end
                return
            if r.offset == r.total:
                r.phase = 'eof'
                return
            fragment,total,kind = read_legacy_sql_cell_fragment_v2(work.db,table=TABLE,column='payload_json',
                where=where,parameters=key,start=r.offset,length=min(16384,r.total-r.offset),meter=meter)
            if total != r.total or kind != 'text' or not fragment:
                raise AuthorityUnavailable('Contact actual prepared whole-column metadata EOF changed')
            r._reserve(len(fragment)+1024)
            r.fragment,r.fragment_offset = fragment,0
            r.offset += len(fragment)
            return
        result = r.parser.finish()
        frozen_result = self.frozen_metadata.finish_v3()
        if frozen_result.sha256 != r.values[('frozen_digest',)]:
            raise AuthorityUnavailable('Contact nested frozen whole canonical birth EOF differs')
        if result.sha256 != r.metadata[0] or result.sha256 != self.intent.binding_digest:
            raise AuthorityUnavailable('Contact prepared canonical birth SHA differs from original model intent')
        pair = contact_pair_for_model_v3(self.model)
        pair[6]._signer.verify(SIGN_KIND,canonical_serialize((work.namespace,'prepared',self.intent.job_id,result.sha256)),r.metadata[1])
        v = r.values
        ns = NamespaceId(v[('namespace','bot_id')],v[('namespace','persona_id')])
        if (ns != work.namespace or v[('job_id',)] != self.intent.job_id or v[('call_id',)] != self.intent.call_id
                or v[('acquire_operation_id',)] != self.intent.acquire_operation_id
                or v[('installation_id',)] != pair[0]._installation_id):
            raise AuthorityUnavailable('Contact prepared original parentage escapes actual installed intent/job')
        self.selector = ModelContactReadSelectorV3(ns,v[('contact_id',)],v[('phase',)],self.intent.job_id,
            self.intent.job_id,result.sha256,self.role,self.read_attempt_id)
        register_contact_work_v3(work,model=self.model,selector=self.selector,intent=self.intent)
        work.contact_prepared_locator = self
        self.metadata,self.values,self.digest = r.metadata,dict(v),result.sha256
        self.complete = True
        _PREPARED_METADATA[self] = (work,self.model,self.intent,self.role,self.read_attempt_id,self.metadata,
            self.digest,tuple(sorted(self.values.items())),self.frozen_metadata.result,self.frozen_metadata.sources)
        from .current_authority_graph_read_v3 import _track_authority_capability_v3
        _track_authority_capability_v3(work,_PREPARED_METADATA,self)
        r.fragment = b''
        r.parser = None
    def require_v3(self,work):
        require_model_contact_work_v3(work)
        if (not self.complete or work.contact_prepared_locator is not self or self.work is not work
                or _PREPARED_METADATA.get(self) != (work,self.model,self.intent,self.role,self.read_attempt_id,self.metadata,
                    self.digest,tuple(sorted(self.values.items())),self.frozen_metadata.result,self.frozen_metadata.sources)):
            raise AuthorityUnavailable('Contact prepared locator lacks its actual complete metadata EOF')
        return self


def prepare_contact_policy_metadata_v3(work,meter):
    import json
    from ..graph_types import AtomKey
    from ..runtime.contact_original_read_v3 import contact_original_point_v3
    require_model_contact_work_v3(work)
    locator = work.contact_locator.require_v3(work)
    matched = []
    for row in locator.versions.values():
        key = AtomKey.from_token(row['key'])
        if key.type_name != 'd10.contact_policy.v1' or row['revision'] < 1:
            continue
        original = contact_original_point_v3(work.db,table='graph_atoms',columns=('revision','value','valid'),
            key_columns=('token',),key=(key.token,),legacy_reader=lambda:None)
        if original is None or (original[0],original[2]) != (row['revision'],1):
            raise AuthorityUnavailable('Contact actual current mirrored policy metadata differs')
        value = json.loads(original[1])
        if value['approval_ref'] == locator.values[('plan','policy_original_ref')]:
            matched.append(value)
    if len(matched) != 1:
        raise AuthorityUnavailable('Contact signed Plan has no exact current policy locator')
    work.contact_policy_metadata = matched[0]
    work.phase = 'contact_owner_observation'


def observe_contact_current_policy_v3(work):
    from .owner_location_read_v3 import (observe_owner_location_for_contact_v3,
        require_owner_location_observation_current_for_contact_v3)
    from .current_authority_graph_read_v3 import _DEADLINES,_track_authority_capability_v3
    pair,selector,intent,operation,scope,permit = require_model_contact_work_v3(work)
    if work.db.in_transaction or work.phase not in {'contact_owner_observation','validate'}:
        raise AuthorityUnavailable('Contact policy/Owner observation must be outside its Graph quantum')
    policy_service = pair[4]
    work.contact_location = pair[5].observe_business_for_fence_v1(credential=work.credential,subject=work.subject,permit=permit)
    observed = observe_owner_location_for_contact_v3(policy_service.owner_service,work)
    with policy_service.fences._frozen() as (db,deletion,execution,_):
        anchor = policy_service.fences._current_locked(db,deletion,execution)
        policy_service.fences.fences.validate_fence_locked(db,permit,subject=work.subject,current_anchor=anchor)
        require_owner_location_observation_current_for_contact_v3(policy_service.owner_service,work,observed,db)
        head = policy_service._current_owner(db,observed,permit)
        value = policy_service._head(db,work.contact_policy_metadata['policy_id'])
        now = policy_service._clock()
        locator = work.contact_locator
        if (value is None or value.action != 'issue' or value.namespace != selector.namespace
                or value.authority_id != permit.authority_id or value.installation_id != pair[0]._installation_id
                or value.original_ref != locator.values[('plan','policy_original_ref')]
                or value.digest != locator.values[('plan','policy_original_digest')]
                or value.policy.version != locator.values[('plan','policy_version')]
                or value.owner_head_digest != head.guard.authorization_head
                or value.owner_authorization_revision != head.guard.authorization_revision
                or value.owner_principal_epoch != policy_service._principal_epoch(db,head)
                or not value.policy.window_start <= now < value.policy.window_end):
            raise AuthorityUnavailable('Contact current standing policy/principal/window differs from signed Plan')
    policy_service.fences.validate_fence(credential=work.credential,subject=work.subject,permit=permit)
    previous = _POLICIES.get(work)
    if previous is not None and previous[1] != value:
        raise AuthorityUnavailable('Contact same-Work standing policy changed after Source preparation')
    work.contact_policy = value
    _POLICIES[work] = (policy_service,value,selector,operation,scope,permit,work.contact_locator.digest)
    _track_authority_capability_v3(work,_POLICIES,work)
    deadline = min(work.deadline_utc,value.policy.window_end,work.contact_locator.values[('plan','valid_until_utc')])
    work.deadline_utc = work.operation.deadline_utc = float(deadline)
    work.deadline_original = work.contact_locator
    _DEADLINES[work] = (work.operation,work.deadline_utc,work.deadline_original)
    if not policy_service._clock() < deadline:
        raise AuthorityUnavailable('Contact original model/result/Plan/policy deadline intersection expired')
    if work.phase == 'contact_owner_observation':
        work.phase = 'contact_source'
    return value


def require_contact_policy_observation_for_plan_v3(db,service,plan):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work = _authority_attachment_owner_v3(db)
    if work is None:
        return None
    require_model_contact_work_v3(work)
    actual = _POLICIES.get(work)
    if (actual is None or actual != (service,work.contact_policy,work.contact_selector,work.operation,work.scope,
            work.permit,work.contact_locator.digest) or service is not work.contact_policy_service
            or plan.namespace != work.namespace or plan.policy_original_ref != actual[1].original_ref
            or plan.policy_original_digest != actual[1].digest or plan.policy_version != actual[1].policy.version):
        raise AuthorityUnavailable('Contact semantic policy check lacks its actual same-Work current observation')
    return actual[1]


def begin_contact_result_work_v3(result, *, credential, permit, request, intent, location):
    from .current_authority_graph_read_v3 import (AuthorityGraphReadWorkV3,_ISSUER,
        require_authority_graph_read_controller_v3,_AuthorityCatalogueReadV3,_DEADLINES)
    from datetime import datetime
    matches = [model for model,pair in _PAIRS.items() if pair[0] is result]
    if len(matches) != 1 or permit.operation != 'read' or permit.operation_id != request.read_attempt_id:
        raise AuthorityUnavailable('Contact result requires its independent exact installed read Work')
    model = matches[0]
    pair = contact_pair_for_model_v3(model)
    work = AuthorityGraphReadWorkV3(_ISSUER,pair[3],credential=credential,subject=result._read_subject,
        permit=permit,namespace=request.namespace,request=request,deadline_utc=None)
    try:
        with work.quantum_v3() as meter:
            row = meter.read_fixed_row(work.db,'runtime_jobs',('bot_id','persona_id','deadline_utc','work_kind'),
                'job_id=?',(request.job_id,))
            if row is None or row[:2] != request.namespace.as_tuple or row[3] != request.phase:
                raise AuthorityUnavailable('Contact result original job/deadline metadata differs')
        deadline = datetime.fromisoformat(row[2].replace('Z','+00:00')).timestamp()
        work.deadline_utc = work.operation.deadline_utc = float(deadline)
        work.deadline_original = (request.job_id,row)
        _DEADLINES[work] = (work.operation,work.deadline_utc,work.deadline_original)
        work._check_permission_v3()
        work.contact_location = location
        work.now_utc = result._clock()
        work.catalogue_reader = _AuthorityCatalogueReadV3(work)
        work.contact_prepared_reader = ContactPreparedLocatorEOFV3(work,model=model,intent=intent,
            role='result',read_attempt_id=request.read_attempt_id)
        work.phase = 'contact_prepared_locator'
        return work
    except BaseException:
        work.release_v3()
        raise


def read_contact_model_work_current_v3(work,read):
    from .current_authority_graph_read_v3 import read_authority_graph_current_v3
    result = read_authority_graph_current_v3(work,read)
    if getattr(work,'contact_prepared_locator',None) is None:
        return result
    require_model_contact_work_v3(work)
    observe_contact_current_policy_v3(work)
    if read_authority_graph_current_v3(work,read) != result:
        raise AuthorityUnavailable('Contact actual same-Work current model input changed across Owner/policy observation')
    return result
