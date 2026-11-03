"""Selected C02 originals for one real Natural P2 SourceALL Work."""
import hmac
from hashlib import sha256
from types import MappingProxyType
from weakref import WeakKeyDictionary,WeakSet

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion,NamespaceEpoch
from ..memory_types import source_key,access_key
from ..runtime_contracts import CommitReceipt,canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3

_ISSUER=object()
_READERS=WeakSet()
_ISSUED=WeakKeyDictionary()
_OWNER_COLUMNS=("operation_id","request_digest","grant_id","grant_digest","graph_incarnation",
    "graph_access_epoch","graph_epoch","graph_receipt_digest")
_INGRESS_COLUMNS=("source_ref","platform_ref","conversation_ref","sender_ref","message_id",
    "visibility","content_fingerprint","learned_at","bundle_digest")


def _barrier(owner):
    from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3
    from .natural_dispatch_p2_read_v1 import require_natural_p2_source_all_v1
    if type(owner)is not _DispatchInventoryReadV3 or owner.family!="natural_reply":
        raise AuthorityUnavailable("exact Natural P2 SourceALL owner required")
    return require_natural_p2_source_all_v1(owner,owner.db)


def _require_open(owner,c02_operation_id,source_ref):
    from ..graph_worker import GraphStorageWorkV3
    from .natural_dispatch_p2_read_v1 import _NaturalP2ReadV1
    barrier=_barrier(owner)
    barrier.require_c02_selection_v1(c02_operation_id,source_ref)
    work=owner.work
    if (type(work)is not GraphStorageWorkV3 or work.state is not owner
            or work.operation is not owner.operation or work.kind!="dispatch_inventory_prepare_v3"
            or work.terminal or work._finish_called
            or type(owner.natural_task)is not _NaturalP2ReadV1
            or owner.natural_task.phase!="c02_originals"):
        raise AuthorityUnavailable("C02 original columns require their actual open Natural P2 stage")
    return barrier


class _NaturalP2C02OriginalReadV1:
    def __init__(self,token,owner,*,c02_operation_id,source_ref):
        if token is not _ISSUER:raise AuthorityUnavailable("actual P2 C02 original factory required")
        self.owner=owner
        self.barrier=_require_open(owner,c02_operation_id,source_ref)
        self.c02_operation_id,self.source_ref=c02_operation_id,source_ref
        self.namespace,self.db=owner.namespace,owner.db
        key=AtomKey.from_token(source_ref)
        if key!=source_key(*self.namespace.as_tuple,key.owner.subject or ""):
            raise AuthorityUnavailable("selected C02 Source is not canonical in this namespace")
        self.source_id=key.owner.subject
        from .first_ingress_v2 import ingress_ids
        from .issuers import d06_first_ingress_c02_quote_id
        self.ingress_operation_id=ingress_ids(self.source_id)[2]
        self.cost_operation_id="c02-cost-"+canonical_digest({"namespace":list(self.namespace.as_tuple),
            "operation_id":c02_operation_id})[:48]
        self.arrival_operation_id="d03-arrival-"+canonical_digest({"namespace":list(self.namespace.as_tuple),
            "source_ref":self.source_id})[:40]
        self.quote_id=d06_first_ingress_c02_quote_id(self.namespace,c02_operation_id)
        self.issuer=owner.graph._GraphCoordinator__d02_issuer
        self.phase="headers";self.position=0;self.columns={};self.column=None
        self.headers={};self.points={};self.result=None;self.complete=False
        self.quote_hmac=None;self.quote_signature=self.quote=self.receipt=self.ingress_identity=None
        ns=self.namespace.as_tuple;where="bot=? AND persona=? AND operation_id=?"
        self.header_specs=[
            ("business","graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),where,(*ns,c02_operation_id)),
            ("archive","graph_first_ingress_c02_committed_seals_v2",("schema","bundle_digest"),where,(*ns,c02_operation_id)),
            ("cost","graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),where,(*ns,self.cost_operation_id)),
            ("cost_attempt","graph_c02_cost_attempts_v1",("state",),where,(*ns,c02_operation_id)),
            ("quote_signature","runtime_resource_quotes",("signature",),"quote_id=? AND version=?",(self.quote_id,1)),
            ("ingress","graph_first_ingress_identity_v1",_INGRESS_COLUMNS,where,(*ns,self.ingress_operation_id)),
            ("observed","ingress_first_observations",("content_fingerprint","learned_at","bundle_digest"),where,(*ns,self.ingress_operation_id)),
            ("ingress_bundle","graph_bundle_operations",("digest",),where,(*ns,self.ingress_operation_id)),
            ("arrival","graph_d03_arrival_issuance_v2",("source_ref","bundle_digest"),where,(*ns,self.arrival_operation_id)),
            ("arrival_bundle","graph_bundle_operations",("digest",),where,(*ns,self.arrival_operation_id)),
            ("owner","graph_owner_issue_operations_v1",_OWNER_COLUMNS,"bot=? AND persona=?",ns),
        ]
        owner.operation.retain(65536+len(self.header_specs)*1024)
        _READERS.add(self)

    def _point(self,meter,table,columns,where,key):
        return _runtime_bounded_fixed_row_v3(self.db,meter,table,columns,where,key)

    def _start_columns(self,meter):
        row=self.headers["business"];ns=self.namespace.as_tuple;op=self.c02_operation_id
        where="bot=? AND persona=? AND operation_id=?"
        self.points[("graph_bundle_operations",("digest","activity_id"),where,(*ns,op))]=row[:2]
        self.points[("graph_bundle_operations",("digest",),where,(*ns,op))]=row[:1]
        self.points[("graph_first_ingress_c02_committed_seals_v2",("bundle_digest",),where,(*ns,op))]=self.headers["archive"][1:]
        self.points[("graph_bundle_operations",("operation_id",),where,(*ns,self.cost_operation_id))]=(self.cost_operation_id,)
        if (self.headers["archive"]!=("sylanne.first-ingress-c02-candidate.v2",row[0])
                or self.headers["cost_attempt"]!=("committed",)
                or self.headers["arrival"]!=(self.source_id,self.headers["arrival_bundle"][0])):
            raise AuthorityUnavailable("selected C02/cost/arrival original scalar linkage differs")
        eventkey=(*ns,row[1],op)
        event=self._point(meter,"graph_events",("epoch_revision",),
            "bot=? AND persona=? AND session=? AND event_id=?",eventkey)
        if event is None:raise AuthorityUnavailable("actual C02 producing event is absent")
        self.event_epoch=event[0]
        self.quote_signature=self.headers["quote_signature"][0]
        self.quote_hmac=hmac.new(self.issuer._signer._Signer__key,b"resource-quote.v1\n",sha256)
        key=(*ns,op);pk=("bot","persona","operation_id")
        self.column_specs=(
            ("evidence","graph_first_ingress_c02_committed_seals_v2","evidence_json",pk,key),
            ("archive_quote","graph_first_ingress_c02_committed_seals_v2","quote_json",pk,key),
            ("business","graph_bundle_operations","receipt_json",pk,key),
            ("cost","graph_bundle_operations","receipt_json",pk,(*ns,self.cost_operation_id)),
            ("event_reads","graph_events","reads",("bot","persona","session","event_id"),eventkey),
            ("event_writes","graph_events","revisions",("bot","persona","session","event_id"),eventkey),
            ("signed_quote","runtime_resource_quotes","quote_json",("quote_id","version"),(self.quote_id,1)),
            ("ingress_identity","graph_first_ingress_identity_v1","identity_json",pk,(*ns,self.ingress_operation_id)),
            ("ingress_intent","graph_first_ingress_intents_v2","identity_json",pk,(*ns,self.ingress_operation_id)),
            ("owner_proof","graph_owner_issue_operations_v1","proof_json",("bot","persona"),ns),
        )
        self.position=0;self.phase="columns"

    def _prepare_dependencies(self):
        from .issuers import ResourceQuote
        if not hmac.compare_digest(self.quote_hmac.hexdigest(),self.quote_signature):
            raise AuthorityUnavailable("actual original C02 resource quote signature differs")
        signed,archived=self.columns["signed_quote"],self.columns["archive_quote"]
        if (signed.sha256,signed.byte_count)!=(archived.sha256,archived.byte_count):
            raise AuthorityUnavailable("C02 archive quote differs from actual signed complete EOF")
        value=signed.require_v3(self.owner)
        value["outbox_refs"]=tuple(value["outbox_refs"])
        value["d02_settlement_refs"]=tuple(value["d02_settlement_refs"])
        self.quote=ResourceQuote(**value)
        if(self.quote.quote_id,self.quote.version)!=(self.quote_id,1):
            raise AuthorityUnavailable("actual signed C02 quote identity differs")
        evidence=self.columns["evidence"].require_v3(self.owner)
        if evidence["source_ref"]!=self.source_id:
            raise AuthorityUnavailable("C02 evidence differs from actual selected Source")
        business=self.columns["business"].require_v3(self.owner)
        row=self.headers["business"]
        reads=tuple(GraphVersion(AtomKey.from_token(token),revision)
            for token,revision in self.columns["event_reads"].require_v3(self.owner))
        writes=tuple(GraphVersion(AtomKey.from_token(token),revision)
            for token,revision in self.columns["event_writes"].require_v3(self.owner))
        self.receipt=CommitReceipt("committed",self.c02_operation_id,*row,reads,writes,
            (NamespaceEpoch(*self.namespace.as_tuple,self.event_epoch),),tuple(business["ledger_refs"]),
            tuple(business["outbox_refs"]))
        identity=self.columns["ingress_identity"].require_v3(self.owner)
        intent=self.columns["ingress_intent"].require_v3(self.owner)
        original=self.headers["ingress"]
        if (type(identity)is not dict or set(identity)!={"schema","namespace","operation_id","source_ref",
                "platform_ref","conversation_ref","sender_ref","message_id","visibility","lineage"}
                or identity["schema"]!="sylanne3.ingress.identity.v1"
                or identity["namespace"]!=list(self.namespace.as_tuple)
                or identity["operation_id"]!=self.ingress_operation_id
                or tuple(identity[name]for name in ("source_ref","platform_ref","conversation_ref","sender_ref",
                    "message_id","visibility"))!=original[:6]
                or identity["source_ref"]!=self.source_id
                or self.headers["observed"]!=original[6:9]
                or self.headers["ingress_bundle"]!=(original[8],)
                or type(intent)is not dict or intent.get("fingerprint")!=original[6]):
            raise AuthorityUnavailable("actual committed ingress identity differs from its immutable originals")
        self.ingress_identity=identity
        cost=self.columns["cost"].require_v3(self.owner)
        ns=self.namespace.as_tuple;op=self.c02_operation_id
        access=access_key(*ns,self.source_id)
        self.dependency_specs=[
            ("settled","runtime_budget_operations",("operation_id",),
                "bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",(*ns,op)),
            ("reservation","runtime_budget_reservations",("state",),"lease_id=? AND operation_id=?",
                (self.quote.parent_budget_lease_ref,op)),
            ("dependency","graph_dependencies",("dependency_revision",),"dependent_token=? AND dependency_token=?",
                (access.token,self.source_ref)),
            ("cost_atom","graph_atoms",("token",),"token=? AND valid=1",(cost["cost_ref"],)),
            ("ingress_first","graph_first_ingress_identity_v1",("operation_id","conversation_ref","visibility"),
                "bot=? AND persona=? AND source_ref=? ORDER BY operation_id",(*ns,self.source_id)),
        ]
        for index,version in enumerate(writes):
            if version.key.type_name in {"memory.episode.v1","memory.subjective_trace.v2"}:
                self.dependency_specs.append(("episode:"+str(index),"graph_atoms",("revision","valid"),
                    "token=?",(version.key.token,)))
        self.position=0;self.phase="dependencies"

    def advance(self,meter):
        if self not in _READERS:raise AuthorityUnavailable("actual P2 C02 original reader required")
        if self.complete:return True
        if _require_open(self.owner,self.c02_operation_id,self.source_ref)is not self.barrier:
            raise AuthorityUnavailable("P2 C02 original SourceALL barrier changed")
        if self.phase=="headers":
            if self.position==len(self.header_specs):self.phase="columns_setup";return False
            name,table,columns,where,key=self.header_specs[self.position]
            value=self._point(meter,table,columns,where,key)
            if value is None:raise AuthorityUnavailable("selected Natural P2 original header absent: "+name)
            self.owner.operation.retain(1024+sum(len(v)*4 for v in value if type(v)is str))
            self.headers[name]=value;self.points[(table,columns,where,key)]=value
            self.position+=1
        elif self.phase=="columns_setup":self._start_columns(meter)
        elif self.phase=="columns":
            if self.position==len(self.column_specs):self.phase="quote";return False
            if self.column is None:
                _,table,column,key_columns,key=self.column_specs[self.position]
                self.column=DispatchOriginalJSONReadV3(self.owner,table=table,column=column,key_columns=key_columns,key=key)
                return False
            name=self.column_specs[self.position][0];before=self.column.offset
            done=self.column.advance(meter)
            if name=="signed_quote"and self.column.offset>before:self.quote_hmac.update(self.column.fragment)
            if done:self.columns[name]=self.column;self.column=None;self.position+=1
        elif self.phase=="quote":self._prepare_dependencies()
        elif self.phase=="dependencies":
            if self.position==len(self.dependency_specs):
                first=self.headers["ingress_first"]
                if first[0]!=self.ingress_operation_id:
                    raise AuthorityUnavailable("selected ingress route differs from canonical original operation")
                self.ingress_second_spec=("graph_first_ingress_identity_v1",("operation_id","conversation_ref","visibility"),
                    "bot=? AND persona=? AND source_ref=? AND operation_id>? ORDER BY operation_id",
                    (*self.namespace.as_tuple,self.source_id,first[0]))
                self.phase="ingress_second";return False
            name,table,columns,where,key=self.dependency_specs[self.position]
            value=self._point(meter,table,columns,where,key)
            if value is None:raise AuthorityUnavailable("selected Natural P2 original dependency absent: "+name)
            self.headers[name]=value;self.points[(table,columns,where,key)]=value;self.position+=1
        elif self.phase=="ingress_second":
            value=self._point(meter,*self.ingress_second_spec)
            if value is not None:raise AuthorityUnavailable("selected Source ingress route is ambiguous")
            self.points[self.ingress_second_spec]=None
            self.result=PreparedNaturalP2C02OriginalsV1(_ISSUER,self);self.complete=True;self.phase="complete"
        else:raise AuthorityUnavailable("actual P2 C02 original stage differs")
        return self.complete


class PreparedNaturalP2C02OriginalsV1:
    """Cached historical originals, never permission to start a new Body read."""
    def __init__(self,token,reader):
        if token is not _ISSUER or reader not in _READERS or reader.phase!="ingress_second":
            raise AuthorityUnavailable("actual completed P2 C02 original issuer required")
        self.owner,self.barrier=reader.owner,reader.barrier
        self.c02_operation_id,self.source_ref=reader.c02_operation_id,reader.source_ref
        self.issuer,self.quote_id,self.quote,self.quote_signature=reader.issuer,reader.quote_id,reader.quote,reader.quote_signature
        self.columns=MappingProxyType(dict(reader.columns));self.points=MappingProxyType(dict(reader.points))
        self.business,self.archive,self.event_epoch=reader.headers["business"],reader.headers["archive"],reader.event_epoch
        self.owner_header=reader.headers["owner"]
        self.receipt=reader.receipt;self._ingress_identity=reader.ingress_identity
        self.ingress_operation_id,self.cost_operation_id,self.arrival_operation_id=(
            reader.ingress_operation_id,reader.cost_operation_id,reader.arrival_operation_id)
        self.ingress_source_id=reader.source_id
        self.owner.operation.retain(4096+256*len(self.columns)+256*len(self.points))
        _ISSUED[self]=self._identity()

    def _identity(self):
        return(self.owner,self.barrier,self.c02_operation_id,self.source_ref,self.issuer,self.quote_id,self.quote,
            self.quote_signature,self.columns,self.points,self.business,self.archive,self.event_epoch,self.owner_header,
            self.receipt,self._ingress_identity,self.ingress_operation_id,self.cost_operation_id,self.arrival_operation_id,
            tuple((name,column.sha256,column.byte_count)for name,column in self.columns.items()))

    def require_owner_v1(self):
        if self not in _ISSUED or _ISSUED[self]!=self._identity()or self.owner.operation.closed:
            raise AuthorityUnavailable("actual retained P2 C02 original issuer changed")
        if _barrier(self.owner)is not self.barrier:
            raise AuthorityUnavailable("cached C02 originals belong to another actual SourceALL Work")
        self.barrier.require_c02_selection_v1(self.c02_operation_id,self.source_ref)
        return self

    def require_inventory_v1(self,inventory,db,*,c02_operation_id=None,source_ref=None):
        from .dispatch_current_inventory_v3 import PreparedCurrentDispatchInventoryV3
        if(type(inventory)is not PreparedCurrentDispatchInventoryV3 or inventory.family!="natural_reply"
                or inventory.natural_c02_originals is not self or db is not self.owner.db
                or inventory.operation is not self.owner.operation or inventory.scope is not self.owner.fence.scope
                or inventory.graph is not self.owner.graph or inventory.namespace!=self.owner.namespace):
            raise AuthorityUnavailable("actual Natural P2 inventory C02 original attachment required")
        self.require_owner_v1()
        if ((c02_operation_id is not None and c02_operation_id!=self.c02_operation_id)
                or (source_ref is not None and source_ref!=self.source_ref)):
            raise AuthorityUnavailable("C02 original selector differs from actual P2 metadata")
        inventory.require_current(db,inventory.namespace,inventory.query)
        return self

    def value_v3(self,name):
        self.require_owner_v1()
        return self.columns[name].require_v3(self.owner)

    def committed_receipt_v1(self):
        self.require_owner_v1()
        return self.receipt

    def read_point_v1(self,table,columns,where,key):
        self.require_owner_v1();descriptor=(table,tuple(columns),where,tuple(key))
        if descriptor not in self.points:
            raise AuthorityUnavailable("point is outside the actual selected C02 original profile")
        with runtime_storage_quantum_v3(self.owner.db)as meter:
            value=_runtime_bounded_fixed_row_v3(self.owner.db,meter,*descriptor)
        if value!=self.points[descriptor]:
            raise AuthorityUnavailable("selected C02 original fixed point changed")
        return value

    def require_quote_for_v3(self,issuer,db,quote_id,version):
        self.require_owner_v1()
        if issuer is not self.issuer or db is not self.owner.db or(quote_id,version)!=(self.quote_id,1):
            raise AuthorityUnavailable("signed C02 quote crossed actual issuer/PK/Work")
        signature=self.read_point_v1("runtime_resource_quotes",("signature",),"quote_id=? AND version=?",(quote_id,version))
        if signature!=(self.quote_signature,):raise AuthorityUnavailable("signed C02 quote signature changed")
        return self.quote

    def require_archive_quote_v3(self):
        self.require_owner_v1();signed,archived=self.columns["signed_quote"],self.columns["archive_quote"]
        if(signed.sha256,signed.byte_count)!=(archived.sha256,archived.byte_count):
            raise AuthorityUnavailable("C02 archive and actual signed quote EOF differ")

    def ingress_identity_v1(self,db,namespace,source_ref):
        self.require_owner_v1()
        if db is not self.owner.db or namespace!=self.owner.namespace or source_ref!=self.source_ref:
            raise AuthorityUnavailable("ingress original crossed selected C02 Source")
        return dict(self._ingress_identity)

    def release_payload_v3(self):
        _ISSUED.pop(self,None)
        self.owner=self.barrier=self.columns=self.points=self.quote=self.receipt=self._ingress_identity=None


def begin_natural_p2_c02_originals_v1(owner,*,c02_operation_id,source_ref):
    return _NaturalP2C02OriginalReadV1(_ISSUER,owner,c02_operation_id=c02_operation_id,source_ref=source_ref)


def require_prepared_natural_p2_c02_originals_v1(inventory,db,*,c02_operation_id=None,source_ref=None):
    from .dispatch_current_inventory_v3 import PreparedCurrentDispatchInventoryV3
    if type(inventory)is not PreparedCurrentDispatchInventoryV3 or inventory.family!="natural_reply":
        raise AuthorityUnavailable("actual Natural P2 inventory required for C02 originals")
    result=inventory.natural_c02_originals
    if type(result)is not PreparedNaturalP2C02OriginalsV1:
        raise AuthorityUnavailable("actual completed Natural P2 C02 originals absent")
    return result.require_inventory_v1(inventory,db,c02_operation_id=c02_operation_id,source_ref=source_ref)
