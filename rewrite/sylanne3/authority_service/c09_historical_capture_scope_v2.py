"""Pre-issue historical capture anchors bound to actual signed storage lineage."""
from __future__ import annotations
from dataclasses import dataclass
from .contract import AuthorityUnavailable
from ..runtime.c09_paged_capture_contract_v2 import (
    C09CaptureScopeV2,C09FrozenRoleSourceV2,GraphErasureRebaseCertificateV2,
    c09_paged_value_from_wire_v2)

_ANCHOR=object()


@dataclass(frozen=True,slots=True,init=False)
class VerifiedHistoricalCaptureScopeV2:
    _issuer: object
    _session: object
    _pair: object
    scope: C09CaptureScopeV2
    source: C09FrozenRoleSourceV2
    certificate: GraphErasureRebaseCertificateV2
    prepared_digest: str

    def __init__(self,token,session,pair,scope,source,certificate,prepared_digest):
        if token is not _ANCHOR:
            raise AuthorityUnavailable("actual signed historical capture anchor required")
        for name,value in (("_issuer",token),("_session",session),("_pair",pair),
                ("scope",scope),("source",source),("certificate",certificate),("prepared_digest",prepared_digest)):
            object.__setattr__(self,name,value)

    def require_current(self):
        if self._issuer is not _ANCHOR:
            raise AuthorityUnavailable("historical capture anchor issuer differs")
        current=_read(self._session,self.scope.scope_digest)
        if current!=(self._pair,self.scope,self.source,self.certificate,self.prepared_digest):
            raise AuthorityUnavailable("actual historical capture anchor changed")
        return self


def _read(session,historical_scope_digest):
    from .c09_role_capture_pair_v2 import InstalledC09RolePairV2
    from .c09_paged_recovery_facts_v2 import mint_installed_recovery_facts_resolver_v2,_BoundedReadConnectionV2,_read_one
    from .c09_prepared_storage_v2 import _build_original,read_selected_prepared_v2
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    session.require_current()
    producer=session._control._role_pairs.get("graph")
    pair=None if producer is None else producer.pair
    if type(pair) is not InstalledC09RolePairV2:
        raise AuthorityUnavailable("actual registered Graph pair required for historical capture")
    pair.require_current()
    facts=mint_installed_recovery_facts_resolver_v2(session,pair)
    facts.require_complete(scope_digest=session.scope.scope_digest,facts_pin_digest=facts._completion.pin_digest)
    meter=current_c09_sql_meter_v2()
    lineage=_read_one(facts._db,"SELECT generation,operation_id,prepared_digest FROM c09_recovery_history_scopes_v2 WHERE scope_digest=? AND historical_scope_digest=?",(session.scope.scope_digest,historical_scope_digest),meter)
    if lineage is None or not 1<=lineage[0]<session.scope.maintenance_generation:
        raise AuthorityUnavailable("historical capture scope is outside actual authenticated selected lineage")
    control=session._control.maintenance.control
    with control._db() as db:
        metadata=_read_one(db,"SELECT new_manifest_digest,prepared_digest FROM c09_storage_operations_v2 WHERE installation_id=? AND operation_id=? AND generation=?",(session.scope.installation_id,lineage[1],lineage[0]),meter)
        if metadata is None or metadata[1]!=lineage[2]:
            raise AuthorityUnavailable("historical capture generation does not have its actual V2 operation")
        manifest=control._read_manifest(db,metadata[0])
        prepared=read_selected_prepared_v2(control,db,manifest)
        if prepared is None or prepared["prepared_digest"]!=lineage[2]:
            raise AuthorityUnavailable("historical capture PREPARED signed original differs")
        bounded=_BoundedReadConnectionV2(db,meter)
        scope=c09_paged_value_from_wire_v2(_build_original(control,bounded,lineage[1],"capture_scope_v2"),C09CaptureScopeV2)
        issue=_build_original(control,bounded,lineage[1],"graph_issued_v2",prepared["graph_issue_original_digest"])
        header=_build_original(control,bounded,lineage[1],"capture_role_complete_v2_graph",prepared["four_role_complete_original_digests"]["graph"])
    certificate=c09_paged_value_from_wire_v2(issue["certificate"],GraphErasureRebaseCertificateV2)
    source=c09_paged_value_from_wire_v2(header["source_original"],C09FrozenRoleSourceV2)
    if (scope.scope_digest!=historical_scope_digest or certificate.candidate.scope!=scope
            or certificate.candidate.source!=source or header["scope_digest"]!=historical_scope_digest
            or scope.maintenance_generation!=lineage[0]
            or (scope.authority_id,scope.installation_id,scope.authority_namespace,scope.graph_namespace)!=
               (session.scope.authority_id,session.scope.installation_id,session.scope.authority_namespace,session.scope.graph_namespace)
            or issue["issue_digest"]!=manifest["graph_issue_digest"]
            or certificate.certificate_digest!=manifest["certificate_digest"]):
        raise AuthorityUnavailable("historical capture actual namespace/source/signed directory anchors differ")
    session.require_current();pair.require_current()
    return pair,scope,source,certificate,lineage[2]


def require_historical_capture_scope_v2(session,historical_scope_digest):
    pair,scope,source,certificate,prepared_digest=_read(session,historical_scope_digest)
    return VerifiedHistoricalCaptureScopeV2(_ANCHOR,session,pair,scope,source,certificate,prepared_digest)
