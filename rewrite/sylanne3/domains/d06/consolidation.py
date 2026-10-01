"""D06 evidence closure for cross-domain consolidation candidates.

Stances are supplied by a semantic owner. This module groups eligible source
families and freezes their graph proofs; it neither decides a belief nor writes
personality, relationship, or autobiography state.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, NamespaceEpoch
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import NamespaceId
from . import source_correction_head_key


@dataclass(frozen=True, slots=True)
class ConsolidationInput:
    source_ref: str
    stance: str

    def __post_init__(self) -> None:
        if self.stance not in {"support", "counterexample"}:
            raise ValueError("consolidation stance must be support or counterexample")
        AtomKey.from_token(self.source_ref)


@dataclass(frozen=True, slots=True)
class ConsolidationFamily:
    provenance_root: str
    support_refs: tuple[str, ...]
    counterexample_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PreparedConsolidation:
    namespace: NamespaceId
    hypothesis_ref: str
    families: tuple[ConsolidationFamily, ...]
    declared_independent_refs: tuple[str, ...]
    independence_unverified_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch
    access_epoch: int
    deletion_epoch: int
    status: str = "candidate_hold"

    def assert_current_for_adoption(
        self, snapshot: GraphSnapshot, *, access_epoch: int, deletion_epoch: int,
    ) -> None:
        """Reject stale material before W01 attempts a cross-domain commit.

        W01 must authenticate this snapshot and atomically validate the same
        read set, epochs, and source/deletion barrier at its actual commit.
        """
        if (not isinstance(snapshot, GraphSnapshot)
                or snapshot.epochs != (self.epoch,)
                or access_epoch != self.access_epoch
                or deletion_epoch != self.deletion_epoch):
            raise ValueError("consolidation snapshot or access barrier is stale")
        for version in self.read_versions:
            atom = snapshot.get(version.key)
            if atom is None or atom.revision != version.revision:
                raise ValueError("consolidation source proof is stale or incomplete")
            if version.revision > 0 and not atom.valid:
                raise ValueError("consolidation source proof is invalid")
            if version.revision == 0 and atom.valid:
                raise ValueError("consolidation correction absence proof changed")


def prepare_consolidation_candidate(
    snapshot: GraphSnapshot, *, namespace: NamespaceId,
    hypothesis_ref: str, inputs: tuple[ConsolidationInput, ...],
    audience: str, access_epoch: int, deletion_epoch: int,
) -> PreparedConsolidation:
    """Group source-backed support and counterexamples under a frozen read set."""
    if (not isinstance(snapshot, GraphSnapshot) or type(namespace) is not NamespaceId
            or len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona)
            != namespace.as_tuple
            or any(NamespaceId.from_key(atom.key) != namespace for atom in snapshot.atoms)
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)):
        raise ValueError("consolidation needs one coherent namespace snapshot")
    if (type(hypothesis_ref) is not str or not hypothesis_ref.strip()
            or type(audience) is not str or not audience
            or type(access_epoch) is not int or access_epoch < 0
            or type(deletion_epoch) is not int or deletion_epoch < 0
            or type(inputs) is not tuple or not inputs or len(inputs) > 128
            or any(type(item) is not ConsolidationInput for item in inputs)):
        raise ValueError("consolidation scope, inputs, or barrier is invalid")
    if len({(item.source_ref, item.stance) for item in inputs}) != len(inputs):
        raise ValueError("duplicate consolidation input")

    proofs: dict[AtomKey, GraphVersion] = {}
    families: dict[str, dict[str, set[str]]] = {}
    parsed: dict[str, SourceRecord] = {}

    def source_record(source_id: str) -> SourceRecord:
        token = source_key(*namespace.as_tuple, source_id).token
        prior = parsed.get(token)
        if prior is not None:
            return prior
        key = source_key(*namespace.as_tuple, source_id)
        access = access_key(*namespace.as_tuple, source_id)
        head = source_correction_head_key(namespace, source_id)
        source_atom, access_atom, head_atom = (snapshot.get(item) for item in (key, access, head))
        if (source_atom is None or access_atom is None or head_atom is None
                or source_atom.revision < 1 or access_atom.revision < 1
                or not source_atom.valid or not access_atom.valid):
            raise ValueError("consolidation source closure is incomplete")
        if head_atom.revision != 0 or head_atom.valid:
            raise ValueError("consolidation source is corrected")
        record = SourceRecord.from_dict(source_atom.value)
        validate_access(access_atom.value)
        if record.source_id != source_id or access_atom.value["source_id"] != source_id:
            raise ValueError("consolidation source identity differs")
        if (access_atom.value["status"] != "active"
                or audience not in record.audiences
                or audience not in access_atom.value["audiences"]
                or "consolidation" not in record.purposes
                or "consolidation" not in access_atom.value["purposes"]):
            raise PermissionError("consolidation source or ancestor is unavailable")
        parsed[token] = record
        proofs[key] = GraphVersion(key, source_atom.revision)
        proofs[access] = GraphVersion(access, access_atom.revision)
        proofs[head] = GraphVersion(head, 0)
        return record

    for item in inputs:
        key = AtomKey.from_token(item.source_ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject):
            raise ValueError("consolidation input is not a same-namespace source")
        pending = [key.owner.subject]
        seen: set[str] = set()
        while pending:
            source_id = pending.pop()
            if source_id in seen:
                continue
            seen.add(source_id)
            if len(seen) > 4096:
                raise ValueError("consolidation source ancestry exceeds bound")
            record = source_record(source_id)
            pending.extend(record.parent_source_ids)
        record = parsed[item.source_ref]
        group = families.setdefault(record.provenance_root,
                                    {"support": set(), "counterexample": set()})
        group[item.stance].add(item.source_ref)

    grouped = tuple(
        ConsolidationFamily(root, tuple(sorted(group["support"])),
                            tuple(sorted(group["counterexample"])))
        for root, group in sorted(families.items())
    )
    declared_independent = tuple(sorted(
        min(ref for ref in (*group["support"], *group["counterexample"])
            if parsed[ref].independence == "independent")
        for group in families.values()
        if any(parsed[ref].independence == "independent"
               for ref in (*group["support"], *group["counterexample"]))
    ))
    unverified = tuple(sorted(
        ref for group in families.values()
        for ref in (*group["support"], *group["counterexample"])
        if parsed[ref].independence == "unknown"
    ))
    return PreparedConsolidation(
        namespace, hypothesis_ref, grouped, declared_independent, unverified,
        tuple(proofs[key] for key in sorted(proofs, key=lambda item: item.token)),
        snapshot.epochs[0], access_epoch, deletion_epoch,
    )


__all__ = ["ConsolidationInput", "ConsolidationFamily", "PreparedConsolidation",
           "prepare_consolidation_candidate"]
