"""Private current SQL reader for actual Contact P2, independent of W01.

The frame below is explicitly a read-only provider input view, not a rewritten
CommandEnvelope or a pre-E/E+1 projection. It exists only in its concrete active
GraphWorker reverse transaction and carries the full current negative inventory.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import json

from ..authority_service.contact_p2_contract_v1 import ContactP2PolicyCapsuleV1
from ..authority_service.reverse_handoff import require_exact_reverse_handoff_identity, require_exact_authority_snapshot
from ..authority_service.v2_contract import canonical_digest as authority_digest
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, owner_grant_key
from ..runtime_contracts import QueryEpoch, canonical_digest
from .contact_batch_current_v3 import require_current_contact_batch_v3
from .contact_p2_birth_v1 import read_contact_p2_birth_v1
from .contact_qualification_evidence_v3 import CONTACT_FINAL_QUERY_TYPES_V3
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .domain_production_contracts_v1 import ProductionOperationLimitsV1, ProductionQueryCoverageV1

_ACTIVE = {}


@dataclass(frozen=True, slots=True)
class _ContactP2AuthorityReadViewV1:
    namespace: object
    purpose: str
    audience: tuple


@dataclass(frozen=True, slots=True)
class _ContactP2VersionReadViewV1:
    query_epochs: tuple
    access_epoch: int
    delete_epoch: int


@dataclass(frozen=True, slots=True)
class _ContactP2EnvelopeReadViewV1:
    authority: _ContactP2AuthorityReadViewV1
    version_guard: _ContactP2VersionReadViewV1
    deadline_utc: float


@dataclass(frozen=True, slots=True)
class _ContactP2FrameReadViewV1:
    envelope: _ContactP2EnvelopeReadViewV1
    snapshot: GraphSnapshot
    now_utc: float
    query_coverage: tuple
    limits: ProductionOperationLimitsV1


class ContactP2CurrentReadV1:
    def __init__(self, *, graph, db, scope, context, binding, claimed, owner_witness,
            authority_snapshot, capsule, now_utc, prepared_inventory=None):
        self.graph,self.db,self.scope = graph,db,scope
        self.context,self.binding,self.claimed = context,binding,claimed
        self.owner_witness,self.authority_snapshot,self.capsule = owner_witness,authority_snapshot,capsule
        self.now_utc = now_utc
        self.prepared_inventory = prepared_inventory
        if prepared_inventory is not None:
            prepared_inventory.operation.retain(ProductionOperationLimitsV1().max_graph_heads*96+1024)
        self._source_versions_v3 = {}
        self.birth = read_contact_p2_birth_v1(db,namespace=scope.namespace,operation_id=binding.operation_id,
            prepared_original=None if prepared_inventory is None else prepared_inventory.contact_birth)
        self.batch,self.batch_proof,_ = require_current_contact_batch_v3(db,namespace=scope.namespace,
            batch_ref=self.birth.batch_ref,operation_id=binding.operation_id,
            generation=scope.generation,graph_incarnation=binding.graph_incarnation)
        self._materialize()

    def _require(self, db):
        from ..graph_coordinator import GraphCoordinator
        from ..graph_store import ProductionGraphStore
        from ..runtime_contracts import FenceScope
        if (type(self.graph) is not GraphCoordinator or type(self.graph._GraphCoordinator__store) is not ProductionGraphStore
                or _ACTIVE.get(id(self)) is not self or db is not self.db
                or db is not self.graph._GraphCoordinator__store._db or not db.in_transaction
                or not self.graph._GraphCoordinator__store._lock._is_owned()
                or type(self.scope) is not FenceScope or self.scope.operation != 'dispatch'
                or self.scope.permit != self.context.permit
                or type(self.capsule) is not ContactP2PolicyCapsuleV1):
            raise ValueError('Contact P2 private reader lost its actual reverse SQL scope')
        require_exact_reverse_handoff_identity(self.scope.authority_namespace,self.context,self.binding,self.claimed)
        require_exact_authority_snapshot(self.context,self.owner_witness,self.authority_snapshot)
        c = self.capsule
        if ((c.context_digest,c.binding_digest,c.claimed_receipt_digest,c.owner_witness_digest,c.authority_snapshot_digest)
                != tuple(authority_digest(v) for v in (self.context,self.binding,self.claimed,self.owner_witness,self.authority_snapshot))
                or c.namespace != self.scope.namespace or c.installation_id != self.owner_witness.guard.installation_id
                or c.graph_incarnation != self.binding.graph_incarnation
                or c.admission_ref != self.binding.origin.admission_ref
                or c.batch_ref != self.birth.batch_ref
                or c.policy_original.original_ref != self.batch_proof.qualification.check_versions.owner_policy_ref
                or c.policy_original.digest != self.batch_proof.qualification.check_versions.owner_policy_digest):
            raise ValueError('Contact P2 capsule and actual whole batch identity differ')
        stamp,epoch = self.graph._v2_graph_stamp(self.scope.namespace)
        if (epoch != self.scope.graph_epoch or stamp.graph_revision != self.scope.graph_revision
                or stamp.requirements.graph_incarnation != c.graph_incarnation
                or stamp.requirements.activation_generation != self.scope.generation
                or not self.graph._accounting_anchor_covers(stamp.requirements,self.scope.pinned_anchor)):
            raise ValueError('Contact P2 actual current Graph stamp changed')

    def _materialize(self):
        if self.prepared_inventory is not None:
            proof=self.prepared_inventory
            proof.require_for(self.context,self.binding,self.claimed,self.db,authority_snapshot=self.authority_snapshot)
            ns=self.scope.namespace;limits=ProductionOperationLimitsV1();pages=[]
            for kind in CONTACT_FINAL_QUERY_TYPES_V3:
                atoms=proof.atoms_for(self.db,ns,proof.query,(kind,),valid_only=False)
                if len(atoms)>limits.max_query_rows:
                    raise MissingProductionOriginalV1('complete_current_contact_p2_inventory:'+kind)
                versions=tuple(GraphVersion(atom.key,atom.revision)for atom in atoms)
                pages.append(ProductionQueryCoverageV1(QueryEpoch(ns,'namespace',self.scope.graph_epoch.revision),
                    kind,versions,True,None))
            rights=proof.authority_epochs
            if rights!=(self.birth.admission.admission.access_epoch,self.birth.admission.admission.delete_epoch):
                raise ValueError('Contact P2 actual Source access/deletion barrier changed')
            self.frame=_ContactP2FrameReadViewV1(_ContactP2EnvelopeReadViewV1(
                _ContactP2AuthorityReadViewV1(ns,'expression',(self.batch.content.audience_id,)),
                _ContactP2VersionReadViewV1((proof.query,),*rights),self.birth.qualification.deadline_utc),
                proof.projection,self.now_utc,tuple(pages),limits)
            return
        ns,db = self.scope.namespace,self.db
        limits = ProductionOperationLimitsV1()
        atoms = {}
        def load(key):
            if key in atoms:return
            if len(atoms)>=limits.max_graph_heads:
                raise MissingProductionOriginalV1('bounded_complete_contact_p2_heads')
            row = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?',
                (key.token,*ns.as_tuple)).fetchone()
            atoms[key] = GraphAtom(key,row[0],json.loads(row[1]),bool(row[2])) if row else GraphAtom(key,0,{},False)
        pages=[]
        for kind in CONTACT_FINAL_QUERY_TYPES_V3:
            rows = db.execute('SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? '
                'ORDER BY token LIMIT ?',(*ns.as_tuple,kind,limits.max_query_rows+1)).fetchall()
            if len(rows)>limits.max_query_rows:
                raise MissingProductionOriginalV1('complete_current_contact_p2_inventory:'+kind)
            versions=tuple(GraphVersion(AtomKey.from_token(token),rev) for token,rev in rows)
            for version in versions:load(version.key)
            pages.append(ProductionQueryCoverageV1(QueryEpoch(ns,'namespace',self.scope.graph_epoch.revision),
                kind,versions,True,None))
        for row in self.birth.qualification.members:load(AtomKey.from_token(row.ref))
        load(owner_grant_key(*ns.as_tuple))
        rights = db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',ns.as_tuple).fetchone()
        if rights != (self.birth.admission.admission.access_epoch,self.birth.admission.admission.delete_epoch):
            raise ValueError('Contact P2 actual Source access/deletion barrier changed')
        query = QueryEpoch(ns,'all',self.scope.graph_epoch.revision)
        self.frame = _ContactP2FrameReadViewV1(_ContactP2EnvelopeReadViewV1(
            _ContactP2AuthorityReadViewV1(ns,'expression',(self.batch.content.audience_id,)),
            _ContactP2VersionReadViewV1((query,),*rights),self.birth.qualification.deadline_utc),
            GraphSnapshot(tuple(sorted(atoms.values(),key=lambda a:a.key.token)),(self.scope.graph_epoch,)),
            self.now_utc,tuple(pages),limits)

    def check(self, db):
        self._require(db)
        ns = self.scope.namespace
        if db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',ns.as_tuple).fetchone() != (
                self.frame.envelope.version_guard.access_epoch,self.frame.envelope.version_guard.delete_epoch):
            raise ValueError('Contact P2 current Source rights changed')
        for atom in self.frame.snapshot.atoms:
            if self.head(db,atom.key) != atom:
                raise ValueError('Contact P2 actual current head changed')
        grant = self.head(db,owner_grant_key(*ns.as_tuple),required=True)
        guard = self.owner_witness.guard
        if (grant.value['authority_id'] != guard.authority_id
                or grant.value['installation_id'] != guard.installation_id
                or grant.value['grant_id'] != self.owner_witness.grant_id
                or grant.value['issue_operation_id'] != self.owner_witness.issue_operation_id
                or grant.value['activation_generation'] != self.scope.generation
                or grant.value['graph_incarnation'] != self.binding.graph_incarnation
                or 'sha256:'+canonical_digest(grant.value) != self.owner_witness.grant_digest):
            raise ValueError('Contact P2 current Owner Graph grant differs from independent Core')
        return self.frame.snapshot

    def head(self, db, key, *, required=False):
        self._require(db)
        if type(key) is str:key=AtomKey.from_token(key)
        if self.prepared_inventory is not None:
            proof=self.prepared_inventory
            if key.type_name=='memory.source':
                source=proof.source_metadata(db,self.scope.namespace,proof.query,key,require_grant=False)
                self._source_versions_v3[source.key]=source.revision
                return source
            atom=proof.projection.get(key)
            if atom is None:atom=GraphAtom(key,0,{},False)
            if required and (not atom.valid or atom.revision<1):
                raise MissingProductionOriginalV1('current_required_head:'+key.token)
            return atom
        return CurrentDomainReadV1.head(self,db,key,required=required)

    def complete_inventory(self, db, type_name):
        self._require(db)
        if self.prepared_inventory is not None:
            proof=self.prepared_inventory
            return proof.atoms_for(db,self.scope.namespace,proof.query,(type_name,),valid_only=False)
        return CurrentDomainReadV1.complete_inventory(self,db,type_name)

    def source_family(self, db, roots, **kwargs):
        self._require(db)
        if self.prepared_inventory is not None:
            purpose=kwargs.get('purpose') or self.frame.envelope.authority.purpose
            audience=kwargs.get('audience')
            audiences=(audience,)if audience is not None else self.frame.envelope.authority.audience
            records=self.prepared_inventory.source_family(db,roots,purpose=purpose,audiences=audiences,
                allow_corrected=kwargs.get('allow_corrected',False),max_roots=self.frame.limits.max_source_roots,
                max_heads=self.frame.limits.max_graph_heads)
            for source in records.values():
                self._source_versions_v3[source.key]=source.revision
            return records
        return CurrentDomainReadV1.source_family(self,db,roots,**kwargs)

    def source_read_versions_v3(self,db):
        self._require(db)
        self.prepared_inventory.operation.retain(len(self._source_versions_v3)*512+256)
        return tuple(GraphVersion(key,self._source_versions_v3[key])for key in sorted(self._source_versions_v3,key=lambda key:key.token))


@contextmanager
def current_contact_p2_read_v1(**actual):
    value = ContactP2CurrentReadV1(**actual)
    _ACTIVE[id(value)] = value
    try:
        value.check(value.db)
        value.source_family(value.db,value.birth.qualification.expression_roots,
            purpose='expression',audience=value.batch.content.audience_id)
        yield value
    finally:
        _ACTIVE.pop(id(value),None)


def require_current_contact_p2_read_v1(value, db):
    if type(value) is not ContactP2CurrentReadV1:
        raise ValueError('actual independent Contact P2 current SQL reader required')
    value.check(db)
    return value
