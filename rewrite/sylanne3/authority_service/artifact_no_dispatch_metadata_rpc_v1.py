"""Exact actual installed Artifact financial metadata RPC registration."""
from .contract import AuthorityUnavailable
from .artifact_no_dispatch_metadata_contract_v1 import (
    ModelNoDispatchMetadataRequestV1,ModelNoDispatchMetadataGrantV1,from_wire_v1,to_wire_v1)
METHODS=frozenset({"artifact_no_dispatch_metadata_issue_v1","artifact_no_dispatch_metadata_validate_v1",
    "artifact_no_dispatch_metadata_cancel_v1"})


def dispatch_artifact_no_dispatch_metadata_v1(server,method,command,*,credential,profile_id,manifest_digest):
    expected={"namespace","request"} if method=="artifact_no_dispatch_metadata_issue_v1" else {"namespace","grant"}
    if method=="artifact_no_dispatch_metadata_cancel_v1":expected|={"prepared","prepared_signature"}
    if method not in METHODS or type(command) is not dict or set(command)!=expected:
        raise AuthorityUnavailable("exact financial metadata command required")
    namespace=command["namespace"]
    server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    installed=server._installations_v2[(credential.certificate_sha256,profile_id)]
    service=server._artifact_no_dispatch_metadata_services_v1.get((namespace,installed.installation_id))
    if service is None:raise AuthorityUnavailable("actual installed Artifact financial metadata service unavailable")
    subject="mtls:sha256:"+credential.certificate_sha256
    if method=="artifact_no_dispatch_metadata_issue_v1":
        request=from_wire_v1(command["request"],ModelNoDispatchMetadataRequestV1)
        grant=service.issue_v1(credential=credential,subject=subject,request=request)
        return {"grant":None if grant is None else to_wire_v1(grant)}
    grant=from_wire_v1(command["grant"],ModelNoDispatchMetadataGrantV1)
    if method=="artifact_no_dispatch_metadata_validate_v1":
        return {"grant":to_wire_v1(service.validate_v1(credential=credential,subject=subject,grant=grant))}
    from dataclasses import asdict
    original=service.read_cancellation_v1(credential=credential,subject=subject,grant=grant,
        prepared_wire=command["prepared"],prepared_signature=command["prepared_signature"])
    return {"original":None if original is None else asdict(original),"grant_digest":grant.digest}
