"""Current target Owner location through actual released C09 storage lineage."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path

from ..runtime.c09_graph_originals_read_v4 import read_graph_rebase_certificate_v1
from ..runtime.lifecycle_operations_v1 import digest
from ..runtime_contracts import canonical_serialize
from ..runtime.restore_anchor import RestoreAnchor
from .contract import AuthorityUnavailable
from .c09_close_apply_v1 import InstalledC09CloseApplyV1
from .c09_storage_control_v1 import C09StorageControlV1


@dataclass(frozen=True, slots=True)
class D12C09TargetContinuationV1:
    authority_namespace: str
    installation_id: str
    transfer_id: str
    source_graph_incarnation: str
    current_graph_incarnation: str
    activation_generation: int
    revocation_epoch: int
    storage_generation: int
    manifest_digest: str
    release_digest: str
    certificate_chain: tuple[tuple[str, str, str], ...]
    original_ref: str
    original_digest: str


class InstalledD12C09TargetContinuationReaderV1:
    def __init__(self, *, control, close_apply):
        if (type(control) is not C09StorageControlV1 or type(close_apply) is not InstalledC09CloseApplyV1
                or close_apply.control is not control or control._applied_reader is not close_apply):
            raise TypeError("actual current C09 control and installed applied reader required")
        self.control, self.close_apply = control, close_apply

    def require_current_target_continuation_v1(self, *, graph_db, history, metadata):
        """Read only installed originals; caller already holds Core and Graph read txs."""
        namespace = self.close_apply.graph_application.namespace
        if not graph_db.in_transaction or metadata.requirements.namespace != namespace:
            raise AuthorityUnavailable("target C09 location requires the current graph read transaction")
        context = self.control.read_verified_current_storage_v1()
        if (context.stage != "RELEASED" or context.prepared_original is None
                or self.control.installation_id != history.plan.target_installation_id
                or self.control.authority_id != metadata.requirements.authority_id):
            raise AuthorityUnavailable("target C09 location is not the current released installation")
        # This is the actual twelve-surface/closed/ACK/scoped-applied reader. A
        # signed PREPARED/RELEASED dictionary alone cannot qualify the new graph.
        release = self.close_apply.read_storage_applied_original_v1(context=context)
        operation_id = context.prepared_original["operation_id"]
        application = self.close_apply.graph_application
        latest = application._certificate_locked(graph_db, context, operation_id)
        member = next(item for item in context.manifest["members"] if item["role"] == "graph")
        path = graph_db.execute("PRAGMA database_list").fetchone()
        if (path is None or Path(path[2]).resolve() != Path(member["resolved_path"])
                or latest.new_incarnation != metadata.requirements.graph_incarnation
                or latest.certificate_digest != context.manifest["certificate_digest"]):
            raise AuthorityUnavailable("current target C09 graph/certificate differs")
        origin = history.target_recovery.new_graph_incarnation
        by_digest = {}
        for (op,) in graph_db.execute("SELECT operation_id FROM graph_c09_rebase_certificates_v1 WHERE bot=? AND persona=?",
                                     namespace.as_tuple):
            certificate = read_graph_rebase_certificate_v1(graph_db, namespace, op)
            if certificate is None or certificate.certificate_digest in by_digest:
                raise AuthorityUnavailable("C09 target certificate ancestry is ambiguous")
            by_digest[certificate.certificate_digest] = certificate
        chain, seen, current = [], set(), latest
        while True:
            if current.certificate_digest in seen:
                raise AuthorityUnavailable("C09 target certificate ancestry cycles")
            seen.add(current.certificate_digest)
            chain.append(current)
            if current.old_incarnation == origin:
                break
            older = by_digest.get(current.prior_certificate_digest)
            if older is None or older.new_incarnation != current.old_incarnation:
                raise AuthorityUnavailable("C09 current target does not descend from the activated import")
            current = older
        previous_incarnation = origin
        previous_epoch = history.target_recovery.current_requirements.revocation_epoch
        generation = history.target_permit.generation
        commitments = []
        with self.control._db() as control_db:
            self.control._current(control_db)
            for certificate in reversed(chain):
                row = control_db.execute("SELECT prepared_original_json,prepared_digest FROM c09_storage_operations_v1 "
                    "WHERE operation_id=?", (certificate.operation_id,)).fetchone()
                if row is None:
                    raise AuthorityUnavailable("C09 target continuation PREPARED original is absent")
                prepared = json.loads(row[0])
                self.control.verify_original_v1(prepared, "prepared_digest")
                before, after = RestoreAnchor(**prepared["old_core_anchor_original"]), RestoreAnchor(**prepared["new_core_anchor_original"])
                event = self.control.read_operation_event_v1(certificate.operation_id, "RELEASED")
                released = event["details"]["release_original"]
                self.control.verify_original_v1(released, "release_digest")
                if (prepared["prepared_digest"] != row[1]
                        or prepared["namespace"] != history.plan.namespace
                        or prepared["installation_id"] != history.plan.target_installation_id
                        or canonical_serialize(prepared["graph_certificate_original"]) != canonical_serialize(asdict(certificate))
                        or certificate.old_incarnation != previous_incarnation
                        or before.namespace != history.plan.namespace or after.namespace != history.plan.namespace
                        or before.authority_id != metadata.requirements.authority_id or after.authority_id != before.authority_id
                        or before.activation_generation != generation or after.activation_generation != generation
                        or before.revocation_epoch != previous_epoch or after.revocation_epoch != previous_epoch + 1
                        or released["manifest_digest"] != prepared["new_manifest_digest"]
                        or released["operation_id"] != certificate.operation_id or released["state"] != "applied"):
                    raise AuthorityUnavailable("C09 target continuation signed lineage differs")
                commitments.append((certificate.certificate_digest, prepared["prepared_digest"], released["release_digest"]))
                previous_incarnation, previous_epoch = certificate.new_incarnation, after.revocation_epoch
        if (metadata.requirements.activation_generation != generation
                or metadata.requirements.revocation_epoch != previous_epoch):
            raise AuthorityUnavailable("target metadata does not match released C09 continuation")
        context.require_current("business")
        material = dict(authority_namespace=history.plan.namespace, installation_id=history.plan.target_installation_id,
            transfer_id=history.plan.transfer_id, source_graph_incarnation=origin,
            current_graph_incarnation=previous_incarnation, activation_generation=generation,
            revocation_epoch=previous_epoch, storage_generation=context.storage_generation,
            manifest_digest=context.manifest_digest, release_digest=release["release_digest"],
            certificate_chain=tuple(commitments))
        material["original_ref"] = "d12c09location:" + digest(material)[7:]
        material["original_digest"] = digest(material)
        return D12C09TargetContinuationV1(**material)


__all__ = ("D12C09TargetContinuationV1", "InstalledD12C09TargetContinuationReaderV1")
