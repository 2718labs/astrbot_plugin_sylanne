"""Current source disclosure candidate for a specific expression audience.

The caller must supply a full, fenced graph snapshot and re-read at use time.
This projection does not change D06 access or grant permission to send.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import NamespaceId


@dataclass(frozen=True, slots=True)
class SourceDisclosureCandidateV1:
    status: str
    source_ref: str
    audience_scope: str
    purpose: str
    read_versions: tuple[GraphVersion, ...]
    graph_epoch: int | None


def qualify_source_disclosure_v1(
    snapshot: GraphSnapshot, source_ref: str, *, namespace: NamespaceId,
    audience_scope: str, purpose: str = "expression",
) -> SourceDisclosureCandidateV1:
    """Both immutable source scope and current D06 access must cover audience."""
    if (type(snapshot) is not GraphSnapshot or type(namespace) is not NamespaceId
            or type(source_ref) is not str or not source_ref
            or type(audience_scope) is not str or not audience_scope
            or type(purpose) is not str or not purpose):
        raise TypeError("typed source, audience, namespace and snapshot required")
    epoch = snapshot.epochs[0] if len(snapshot.epochs) == 1 else None
    graph_epoch = epoch.revision if epoch is not None else None
    def result(status: str, reads: tuple[GraphVersion, ...] = ()):
        return SourceDisclosureCandidateV1(
            status, source_ref, audience_scope, purpose, reads, graph_epoch)
    if (epoch is None or (epoch.bot, epoch.persona) != namespace.as_tuple
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)):
        return result("unavailable")
    try:
        key = AtomKey.from_token(source_ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
            return result("unavailable")
        source_atom = snapshot.get(key)
        access_atom = snapshot.get(access_key(
            *namespace.as_tuple, key.owner.subject or ""))
        if (source_atom is None or access_atom is None
                or not source_atom.valid or not access_atom.valid
                or source_atom.revision < 1 or access_atom.revision < 1):
            return result("unavailable")
        source = SourceRecord.from_dict(source_atom.value)
        validate_access(access_atom.value)
        if (source.source_id != key.owner.subject
                or access_atom.value["source_id"] != source.source_id):
            return result("unavailable")
        reads = (GraphVersion(source_atom.key, source_atom.revision),
                 GraphVersion(access_atom.key, access_atom.revision))
        if (access_atom.value["status"] != "active"
                or audience_scope not in source.audiences
                or audience_scope not in access_atom.value["audiences"]
                or purpose not in source.purposes
                or purpose not in access_atom.value["purposes"]):
            return result("restricted", reads)
        return result("eligible", reads)
    except (TypeError, ValueError, KeyError):
        return result("unavailable")


__all__ = ["SourceDisclosureCandidateV1", "qualify_source_disclosure_v1"]
