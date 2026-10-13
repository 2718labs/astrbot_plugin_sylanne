"""Private current installed resource selection for paged C09 Source plans.

This view conveys location identity only. Owner proof, Source access, actual
Core pending and content/delete fences remain separate required protocols.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from .contract import AuthorityUnavailable
from ..runtime_contracts import NamespaceId, canonical_digest

_ISSUER = object()


@dataclass(frozen=True, slots=True, init=False)
class SelectedSourcePlanLocationV2:
    _issuer: object
    _control: object
    _namespace: NamespaceId
    source_location_digest: str
    selected_storage_generation: int
    selected_manifest_digest: str
    selected_pointer_version: int

    def __init__(self, token, control, namespace, current, commitment):
        if token is not _ISSUER:
            raise AuthorityUnavailable("actual installed Source-plan location required")
        for name, value in (("_issuer",token),("_control",control),("_namespace",namespace),
                ("source_location_digest",commitment),("selected_storage_generation",current.storage_generation),
                ("selected_manifest_digest",current.manifest_digest),("selected_pointer_version",current.pointer_version)):
            object.__setattr__(self,name,value)

    def require_current(self):
        if self._issuer is not _ISSUER:
            raise AuthorityUnavailable("Source-plan location issuer differs")
        current, commitment = _observe(self._control, self._namespace)
        if ((current.storage_generation,current.manifest_digest,current.pointer_version,commitment) !=
                (self.selected_storage_generation,self.selected_manifest_digest,self.selected_pointer_version,self.source_location_digest)):
            raise AuthorityUnavailable("Source-plan selected installation resources changed")
        return self


def _observe(control, namespace):
    from .c09_paged_capture_control_v2 import InstalledC09PagedCaptureControlV2
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    if type(control) is not InstalledC09PagedCaptureControlV2:
        raise AuthorityUnavailable("actual installed protected Source-plan location issuer required")
    control._registered()
    m=control.maintenance
    qualifier=m.current_source_location
    if (type(namespace) is not NamespaceId or namespace!=m.namespace_id
            or qualifier.namespace_id!=namespace or qualifier.namespace!=m.closure.namespace
            or qualifier.installation_id!=m.control.installation_id
            or qualifier.core is not m.core or qualifier._control is not m.control):
        raise AuthorityUnavailable("Source-plan location crosses actual installed namespace qualifier")
    meter=current_c09_sql_meter_v2()
    current=m.control.read_verified_current_storage_v2(meter=meter,verify_files=False)
    members=current.manifest["members"]
    graph_member=next(member for member in members if member["role"]=="graph")
    core_member=next(member for member in members if member["role"]=="core")
    if (Path(core_member["resolved_path"]).resolve(strict=True)!=m.core.path.resolve(strict=True)
            or Path(graph_member["resolved_path"]).resolve(strict=True)!=qualifier._graph_db_path):
        raise AuthorityUnavailable("Source-plan qualifier does not hold the actual selected stores")
    for member in members:
        m.control.verify_member_v1(member,prepared=False)
    with m.core._tx() as db:
        row=m.core._row(db,m.closure.namespace)
        anchor=m.core._anchor(db,m.closure.namespace,row)
    with m.graph._lock:
        raw=m.graph._db.execute("SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",namespace.as_tuple).fetchone()
        if raw is None:
            raise AuthorityUnavailable("actual Source-plan Graph recovery metadata absent")
        from ..graph_store import GraphStore
        requirements=GraphStore._decode_recovery(raw,namespace).requirements
    if (requirements.namespace!=namespace or requirements.authority_namespace!=m.closure.namespace
            or requirements.authority_id!=m.control.authority_id
            or requirements.activation_generation!=anchor.activation_generation):
        raise AuthorityUnavailable("Source-plan current Core and Graph installation identities differ")
    commitment=canonical_digest(("sylanne3.c09.selected-source-plan-location.v2",
        m.control.authority_id,m.control.installation_id,namespace,m.closure.namespace,
        current.storage_generation,current.manifest_digest,current.pointer_version,
        tuple((member["role"],member["resolved_path"],member["device"],member["file_id"]) for member in members),
        requirements.graph_incarnation,anchor.activation_generation,anchor.deletion_journal_id))
    return current,commitment


def current_source_plan_selection_v2(control, namespace):
    current, commitment=_observe(control,namespace)
    return SelectedSourcePlanLocationV2(_ISSUER,control,namespace,current,commitment)
