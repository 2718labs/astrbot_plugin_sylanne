"""Independent D04 Authority ordinary-role metadata and current Source ALL."""
from contextlib import contextmanager
from weakref import WeakKeyDictionary
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner, owner_grant_key
from .contract import AuthorityUnavailable

_READERS = WeakKeyDictionary()
_OWNERS = WeakKeyDictionary()
_QUALIFIED = WeakKeyDictionary()
_ACTIVE_OWNERS = WeakKeyDictionary()
_KEY = object()


class InstalledD04AuthoritySourceReaderV3:
    def __init__(self,*,owner_storage,bundle,issuer,model_service,result_service):
        from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
        from .v2_model_egress_service import AuthorityV2ModelEgressService
        from .d04_appraisal_result_service_v3 import AuthorityD04AppraisalResultServiceV3
        from ..host.authority_profile import AdminInstallationBundle
        from ..runtime.issuers import D11BudgetJobIssuer
        if (type(owner_storage) is not InstalledD12OwnerStorageAdmissionServiceV1
                or type(bundle) is not AdminInstallationBundle or type(issuer) is not D11BudgetJobIssuer
                or type(model_service) is not AuthorityV2ModelEgressService
                or type(result_service) is not AuthorityD04AppraisalResultServiceV3
                or model_service._fences is not owner_storage.fences
                or result_service._fences is not owner_storage.fences
                or model_service._graph_verifier._issuer is not issuer or result_service._issuer is not issuer
                or owner_storage.namespace_id != bundle.installation_policy.namespace
                or owner_storage.graph_path != model_service._graph_verifier._path
                or owner_storage.graph_path != result_service._path):
            raise AuthorityUnavailable('D04 Authority Source requires actual same-package Graph/Owner/model/result installation')
        self.owner_storage,self.bundle,self.issuer = owner_storage,bundle,issuer
        self.model_service,self.result_service = model_service,result_service
        _READERS[self] = (owner_storage,bundle,issuer,model_service,result_service)

    def require_installed_v3(self,work):
        if _READERS.get(self) != (self.owner_storage,self.bundle,self.issuer,self.model_service,self.result_service):
            raise AuthorityUnavailable('D04 actual installed Authority reader changed')
        verifier = work.controller.verifier
        expected = self.model_service._graph_verifier if work.controller.kind == 'model' else self.result_service
        if (work.controller.kind not in {'model','d04_result'} or verifier is not expected
                or verifier._d04_source_reader_v3 is not self or work.owner_model_work_kind != 'd04.appraisal'
                or work.namespace != self.bundle.installation_policy.namespace
                or work.controller.control is not self.owner_storage.control
                or work.controller.fences is not self.owner_storage.fences):
            raise AuthorityUnavailable('D04 Authority source reader crossed its actual consumer/Owner/Scope')
        work._actual()
        return self


class _AuthorityD04OrdinaryOwnerV3:
    def __init__(self,key,work,reader,owner_entry):
        if key is not _KEY:
            raise TypeError('D04 Authority origin adapter has no public issuer')
        reader.require_installed_v3(work)
        self.work,self.reader,self.owner_entry = work,reader,owner_entry
        self.namespace,self.db,self.operation = work.namespace,work.db,work.operation
        self.origin_signer = reader.issuer._signer
        self.origin_columns,self.origin_support_readsets,self.origin_history = [],{},{}
        self.authority_epochs = tuple(work.graph_stamp[1:])
        self.namespace_reader = self
        _OWNERS[self] = (work,reader,owner_entry,self.operation,work.permit,work.selection_digest)
        _ACTIVE_OWNERS[work] = self
    @property
    def atoms(self):
        require_authority_d04_origin_owner_v3(self)
        return tuple(self.work.members.values())
    @property
    def sources(self):
        return self.work.sources
    @property
    def heads(self):
        return self.work.heads
    @contextmanager
    def quantum_v3(self):
        require_authority_d04_origin_owner_v3(self)
        with self.work.quantum_v3() as meter:
            yield meter


def authority_d04_origin_owner_v3(value):
    return type(value) is _AuthorityD04OrdinaryOwnerV3 and value in _OWNERS


def require_authority_d04_origin_owner_v3(value):
    if type(value) is not _AuthorityD04OrdinaryOwnerV3:
        raise AuthorityUnavailable('actual D04 Authority origin Work required')
    work,reader,entry = value.work,value.reader,value.owner_entry
    reader.require_installed_v3(work)
    if (_OWNERS.get(value) != (work,reader,entry,work.operation,work.permit,work.selection_digest)
            or work.namespace_reader is None or not work.namespace_reader.graph_eof):
        raise AuthorityUnavailable('D04 Authority ordinary metadata lost its actual complete namespace EOF')
    return value


def require_d04_authority_owner_header_v3(proof):
    work = proof.request
    reader = work.controller.verifier._d04_source_reader_v3
    reader.require_installed_v3(work)
    if (proof.owner_service is not reader.owner_storage or proof.bundle is not reader.bundle
            or proof.retained_operation is not work.operation or proof.original_permit != work.permit
            or proof.namespace != work.namespace or proof.controller is not work.controller
            or proof.service is not work.service):
        raise AuthorityUnavailable('D04 Authority Owner header crossed its actual registered service')
    return proof


def prepare_authority_d04_ordinary_readout_v3(work):
    """Runs before frozen appraisal/request Body originals can be prepared."""
    from .current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
    from .owner_location_read_v3 import prepare_owner_location_for_model_graph_work_v3
    from ..runtime.d01_ordinary_origin_read_v3 import _column,_fixed,read_current_ordinary_origins_v3
    from ..runtime.d04_ordinary_readout_v3 import (
        _qualify_d04_role_support_metadata_v3,d04_role_manifest_wire_v3,validate_d04_role_manifest_wire_v3)
    from ..domains.d01 import PersonaDomain
    require_actual_authority_graph_attachment_owner_v3(work)
    reader = work.controller.verifier._d04_source_reader_v3
    reader.require_installed_v3(work)
    if work in _QUALIFIED:
        return _QUALIFIED[work]
    if work.db.in_transaction or work.phase != 'validate':
        raise AuthorityUnavailable('D04 independent ordinary Source must precede its final Graph transaction')
    entry = prepare_owner_location_for_model_graph_work_v3(work,
        installed_reader=reader,owner_service=reader.owner_storage)
    owner = _AuthorityD04OrdinaryOwnerV3(_KEY,work,reader,entry)
    ns,intent = work.namespace,work.request
    original_header = _fixed(owner,'graph_d04_originals_v3',('payload_digest',),
        'bot=? AND persona=? AND kind=? AND original_ref=?',(*ns.as_tuple,'appraisal',intent.job_id))
    if original_header != (intent.binding_digest,):
        raise AuthorityUnavailable('D04 Authority selected appraisal original digest changed')
    metadata = _column(owner,'graph_d04_originals_v3','payload_json',
        ('bot','persona','kind','original_ref'),(*ns.as_tuple,'appraisal',intent.job_id),'d04_prepared')
    if metadata.semantic_digest != intent.binding_digest:
        raise AuthorityUnavailable('D04 actual immutable appraisal canonical EOF differs from model binding')
    raw = metadata.metadata
    manifest = raw.get('role_support_manifest')
    validate_d04_role_manifest_wire_v3(manifest,ns)
    if (raw['namespace'] != {'bot_id':ns.bot_id,'persona_id':ns.persona_id}
            or raw['job_id'] != intent.job_id or raw['call_id'] != intent.call_id
            or raw['purpose'] != 'expression' or raw['audience'] != manifest['audience']):
        raise AuthorityUnavailable('D04 Authority original role support is outside its actual selected model use')
    _qualify_actual_d04_event_sources_v3(owner,raw,intent)
    activation_key = AtomKey(Owner('persona',*ns.as_tuple),'d01.persona_activation.v1','current')
    aheader = work.heads.get(activation_key.token)
    if aheader is None or not aheader[1]:
        raise AuthorityUnavailable('D04 Authority current activation Head absent')
    activation = _column(owner,'graph_atoms','value',('token',),(activation_key.token,),
        'activation',cell_id=aheader[2])
    grant_key = owner_grant_key(*ns.as_tuple)
    gheader = work.heads.get(grant_key.token)
    if gheader is None or not gheader[1]:
        raise AuthorityUnavailable('D04 Authority current Owner grant Head absent')
    grant = _column(owner,'graph_atoms','value',('token',),(grant_key.token,),
        'activation',cell_id=gheader[2])
    control_snapshot = GraphSnapshot((
        GraphAtom(activation_key,aheader[0],activation.metadata,True),
        GraphAtom(grant_key,gheader[0],grant.metadata,True)),(NamespaceEpoch(*ns.as_tuple,work.graph_stamp[0]),))
    control = PersonaDomain.resolve_active_role_control_v3(control_snapshot,
        namespace=ns,current_guard=entry.head.guard)
    head,origins = read_current_ordinary_origins_v3(owner,control)
    pheader = work.heads.get(head.plan_ref.key.token)
    if pheader is None or pheader[:2] != (head.plan_ref.revision,True):
        raise AuthorityUnavailable('D04 Authority actual current plan Head differs from reconstructed lineage')
    qualified = _qualify_d04_role_support_metadata_v3(owner,head,origins,
        purpose='expression',audience=tuple(raw['audience']))
    if d04_role_manifest_wire_v3(qualified) != manifest:
        raise AuthorityUnavailable('D04 Authority independently reconstructed role support differs from frozen manifest')
    _QUALIFIED[work] = (owner,qualified,intent.binding_digest)
    return _QUALIFIED[work]


def require_authority_d04_ordinary_readout_v3(db,intent,original):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from ..runtime.d04_ordinary_readout_v3 import (
        d04_role_manifest_wire_v3,require_current_d04_role_manifest_heads_v3)
    work = _authority_attachment_owner_v3(db)
    if work is None:
        raise AuthorityUnavailable('D04 current content needs its actual independent Authority Source Work')
    found = _QUALIFIED.get(work)
    if found is None:
        raise AuthorityUnavailable('D04 Authority ordinary source qualification did not complete')
    owner,manifest,digest = found
    require_authority_d04_origin_owner_v3(owner)
    if (work.request != intent or digest != intent.binding_digest or original.digest != digest
            or original.role_support_manifest != d04_role_manifest_wire_v3(manifest)):
        raise AuthorityUnavailable('D04 current original differs from independent Authority readout')
    require_current_d04_role_manifest_heads_v3(db,work.namespace,original.role_support_manifest)
    return manifest


def release_authority_d04_ordinary_readout_v3(work):
    found = _QUALIFIED.pop(work,None)
    owner = _ACTIVE_OWNERS.pop(work,None)
    if owner is not None:
        _OWNERS.pop(owner,None)
        owner.origin_columns.clear()
        owner.origin_support_readsets.clear()
        owner.origin_history.clear()


def _qualify_actual_d04_event_sources_v3(owner,metadata,intent):
    """Independent event group, separate from ordinary role support."""
    from ..memory_types import source_key,access_key,validate_access
    from ..domains.d06 import source_correction_head_key
    ns = owner.namespace
    rows = metadata['read_rows']
    originals = {item['ref']:item for item in rows}
    if len(originals) != len(rows) or not 1 <= len(intent.source_refs) <= 4:
        raise AuthorityUnavailable('D04 Authority event source original summary differs')
    accesses = dict(intent.access_revisions)
    source_versions = dict(intent.source_revisions)
    if set(source_versions) != set(intent.source_refs) or set(accesses) != set(intent.source_refs):
        raise AuthorityUnavailable('D04 Authority model event source tuple differs')
    atoms = {a.key.token:a for a in owner.atoms}
    active,done = set(),set()
    def visit(ref):
        if ref in active or len(active)+len(done) >= 256:
            raise AuthorityUnavailable('D04 Authority event source ancestry is cyclic or exceeds its bound')
        if ref in done:return
        key = AtomKey.from_token(ref)
        witness = owner.sources.get(ref)
        old = originals.get(ref)
        ak,ck = access_key(*ns.as_tuple,key.owner.subject),source_correction_head_key(ns,key.owner.subject)
        access = atoms.get(ak.token)
        old_access = originals.get(ak.token)
        if (key != source_key(*ns.as_tuple,key.owner.subject or '') or witness is None or not witness.valid
                or old is None or not old['valid'] or old['revision'] != witness.revision
                or access is None or not access.valid or old_access is None
                or old_access['revision'] != access.revision or not old_access['valid']
                or ck.token in owner.heads):
            raise AuthorityUnavailable('D04 Authority actual event source/access/correction original changed')
        raw = witness.metadata
        validate_access(access.value)
        if (raw['source_id'] != key.owner.subject or access.value['source_id'] != raw['source_id']
                or access.value['status'] != 'active' or 'expression' not in raw['purposes']
                or 'expression' not in access.value['purposes']
                or not set(metadata['audience']) <= set(raw['audiences'])
                or not set(metadata['audience']) <= set(access.value['audiences'])):
            raise AuthorityUnavailable('D04 Authority actual event source lacks current expression/audience rights')
        active.add(ref)
        for parent in raw['parent_source_ids']:
            visit(source_key(*ns.as_tuple,parent).token)
        active.remove(ref);done.add(ref)
    for source_id in intent.source_refs:
        ref = source_key(*ns.as_tuple,source_id).token
        visit(ref)
        source = owner.sources[ref]
        access = atoms[access_key(*ns.as_tuple,source_id).token]
        if (source.revision != source_versions[source_id] or access.revision != accesses[source_id]):
            raise AuthorityUnavailable('D04 Authority event source differs from actual model intent')
    return tuple(sorted(done))
