"""C03/D07 selection metadata from the exact private installed retrieval."""
from dataclasses import dataclass
from ..domains.d01.production_operations_v1 import stage_result_v1
from ..domains.d06 import CandidateSet, SelectionTicket
from ..domains.d07 import D07DomainProvider
from ..graph_types import AtomKey, GraphVersion, NamespaceEpoch
from ..runtime_contracts import NamespaceId, canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .d06_ingress_c03_read_v1 import (
    OPERATION, SelectIngressRecallSeedRequestV1, require_ingress_c03_read_v1,
)
from .foreground_cycle_v1 import foreground_cycle_from_wire_v1, require_current_foreground_responsibility_v1
from .jobs import get_job
from .d11_types import job_graph_write
from .domain_production_originals_v1 import read_adopted_domain_operation_v1


def ingress_c03_selection_operation_id_v1(namespace, c02_operation_id):
    return "ingress-c03-select:" + canonical_digest((namespace, c02_operation_id, OPERATION))[:48]


def ingress_c04_child_activity_id_v1(namespace, c02_operation_id):
    return "ingress-c04-activity:" + canonical_digest((namespace, c02_operation_id, OPERATION))[:48]


@dataclass(frozen=True, slots=True)
class C03DirectSelectionOriginalV1:
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    c02_operation_id: str
    cycle_job_ref: str
    cue_source_ref: str
    need_ref: str
    need_digest: str
    routing_adoption_ref: str
    routing_adoption_digest: str
    query_digest: str
    query_epoch: NamespaceEpoch
    access_epoch: int
    delete_epoch: int
    accepted_round: int
    candidate_set: CandidateSet
    candidate_set_digest: str
    source_family_read_versions: tuple[GraphVersion, ...]
    selected_source_ref: str | None
    selected_source_revision: int | None
    selected_source_digest: str | None
    selection_ticket: SelectionTicket | None
    selection_ticket_digest: str | None
    child_activity_id: str
    responsibility_ref: str
    responsibility_digest: str
    cancel_generation: int
    purpose: str
    audience: tuple[str, ...]
    required_checks: tuple[str, ...]
    missing_items: tuple[str, ...]
    candidate_count: int
    node_count: int
    page_count: int
    elapsed_seconds: float
    search_stop_reason: str
    search_cursor: str | None
    schema: str = "d06.ingress-c03-direct-selection.v1"

    def __post_init__(self):
        if (self.schema != "d06.ingress-c03-direct-selection.v1"
                or type(self.namespace) is not NamespaceId or type(self.query_epoch) is not NamespaceEpoch
                or (self.query_epoch.bot, self.query_epoch.persona) != self.namespace.as_tuple
                or type(self.accepted_round) is not int or not 1 <= self.accepted_round <= 4
                or type(self.candidate_set) is not CandidateSet
                or canonical_digest(self.candidate_set) != self.candidate_set_digest
                or self.child_activity_id != ingress_c04_child_activity_id_v1(self.namespace, self.c02_operation_id)):
            raise ValueError("C03 selection requires its actual finite namespace/query/candidate original")
        cycle = AtomKey.from_token(self.cycle_job_ref)
        if cycle.type_name != "runtime.job" or NamespaceId.from_key(cycle) != self.namespace:
            raise ValueError("C03 selection crossed its original parent cycle")
        for name in ("manifest_digest", "need_digest", "routing_adoption_digest", "query_digest",
                "candidate_set_digest", "responsibility_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("C03 selection original commitment differs")
        if (len(self.candidate_set.items) > 64 or len(self.source_family_read_versions) > 512
                or not 0 <= self.candidate_count <= 64 or not 0 <= self.node_count <= 128
                or not 0 <= self.page_count <= 4
                or self.search_stop_reason not in {"complete", "round_budget", "candidate_budget", "node_budget", "no_progress"}
                or self.search_stop_reason == "complete" and (self.search_cursor is not None or self.candidate_set.coverage != "complete")):
            raise ValueError("C03 selection exceeds the installed finite structural query budget")
        selected = (self.selected_source_ref, self.selected_source_revision, self.selected_source_digest,
            self.selection_ticket, self.selection_ticket_digest)
        if self.selected_source_ref is None:
            if any(value is not None for value in selected):
                raise ValueError("C03 no-candidate metadata cannot invent a selection")
        else:
            key = AtomKey.from_token(self.selected_source_ref)
            if (key.type_name != "memory.source" or NamespaceId.from_key(key) != self.namespace
                    or self.selected_source_ref == self.cue_source_ref
                    or type(self.selected_source_revision) is not int or self.selected_source_revision < 1
                    or type(self.selection_ticket) is not SelectionTicket
                    or self.selection_ticket.activity_id != self.child_activity_id
                    or self.selection_ticket.candidate_set_id != self.candidate_set.candidate_set_id
                    or canonical_digest(self.selection_ticket) != self.selection_ticket_digest
                    or len(self.selection_ticket.selected_candidate_ids) != 1):
                raise ValueError("C03 direct seed lacks its actual historical member/selection ticket")
            item = next((item for item in self.candidate_set.items
                if item.candidate_id == self.selection_ticket.selected_candidate_ids[0]), None)
            if item is None or item.content_ref != self.selected_source_ref:
                raise ValueError("C03 direct seed is not a member of the actual retrieved set")


@dataclass(frozen=True, slots=True)
class InstalledIngressC03ReadersV1:
    graph: object
    issued: object
    scope: object
    search: object
    execution_reader: object

    @property
    def issuer(self):
        return self.execution_reader.d11_issuer

    @property
    def installed_bundle(self):
        return self.execution_reader.bundle


def read_plan_ingress_c03_selection_v1(db, *, namespace, request, readers):
    handle = require_ingress_c03_read_v1(readers.search, readers.graph, readers.issued, readers.scope, request)
    need = handle.need
    keys = tuple(version.key for version in handle.closure_versions) + (
        AtomKey.from_token(request.job_ref), AtomKey.from_token(need.focus_ref), AtomKey.from_token(need.attention_ticket_ref))
    return production_read_plan_v1((), tuple(sorted(set(keys), key=lambda key: key.token)),
        (request.source_ref,), (handle.routing["adoption_operation_id"],))


def stage_ingress_c03_selection_v1(db, *, frame, request, installed_readers):
    readers = installed_readers
    if type(readers) is not InstalledIngressC03ReadersV1 or type(request) is not SelectIngressRecallSeedRequestV1:
        raise TypeError("C03 selection requires its actual installed private readers")
    handle = require_ingress_c03_read_v1(readers.search, readers.graph, readers.issued, readers.scope, request)
    ns = frame.envelope.authority.namespace
    if (frame.snapshot.epochs != (handle.query_epoch,)
            or (frame.envelope.version_guard.access_epoch, frame.envelope.version_guard.delete_epoch)
                != (handle.access_epoch, handle.delete_epoch)
            or frame.envelope.identity.operation_id != ingress_c03_selection_operation_id_v1(ns, request.c02_operation_id)):
        raise ValueError("C03 selection cannot relabel stale evidence with the current epoch")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    cycle = get_job(db, AtomKey.from_token(request.job_ref).name)
    continuation = foreground_cycle_from_wire_v1(cycle.continuation)
    if (cycle.phase != "running" or cycle.cancel_epoch or cycle.lease_holder != frame.envelope.authority.actor
            or continuation.c02_operation_id != request.c02_operation_id or continuation.source_ref != request.source_ref
            or read.head(db, request.job_ref, required=True).value != job_graph_write(cycle).value):
        raise MissingProductionOriginalV1("actual_running_self_c03_parent")
    responsibility = require_current_foreground_responsibility_v1(db, namespace=ns, job=cycle,
        installed_bundle=readers.installed_bundle, issuer=readers.issuer, owner_guard=frame.owner_guard,
        purpose=frame.envelope.authority.purpose, audiences=frame.envelope.authority.audience, now_utc=frame.now_utc)
    if responsibility is None or responsibility.digest != handle.need.responsibility_digest:
        raise MissingProductionOriginalV1("actual_current_c03_responsibility")
    for version in handle.closure_versions:
        if read.head(db, version.key).revision != version.revision:
            raise ValueError("C03 actual Source/access/correction closure changed before selection")
    candidates = handle.outcome.candidates
    eligible = tuple(item.candidate_id for item in candidates.items
        if item.content_ref != request.source_ref and AtomKey.from_token(item.content_ref).type_name == "memory.source"
        and frame.envelope.authority.purpose in item.allowed_purposes)
    ticket, selected, revision, digest = None, None, None, None
    if eligible:
        # Every considered historical member, not a caller-supplied extra locator.
        roots = tuple(dict.fromkeys(item.content_ref for item in candidates.items if item.candidate_id in eligible))
        read.source_family(db, roots, purpose=frame.envelope.authority.purpose)
        focus = read.head(db, handle.need.focus_ref, required=True)
        handoff = D07DomainProvider.select_bounded_recollection(
            activity_id=ingress_c04_child_activity_id_v1(ns, request.c02_operation_id),
            focus_epoch=focus.value["focus_epoch"], candidates=candidates,
            purpose=frame.envelope.authority.purpose, eligible_candidate_ids=eligible)
        ticket = handoff.selection_ticket
        chosen = next(item for item in candidates.items if item.candidate_id == ticket.selected_candidate_ids[0])
        atom = read.head(db, chosen.content_ref, required=True)
        selected, revision, digest = atom.key.token, atom.revision, canonical_digest(atom.value)
    original = C03DirectSelectionOriginalV1(ns, readers.installed_bundle.installation_policy.installation_id,
        readers.installed_bundle.installation_policy.manifest_digest, request.c02_operation_id, request.job_ref,
        request.source_ref, handle.routing["need_ref"], request.need_digest,
        handle.routing["adoption_operation_id"], handle.routing_digest, canonical_digest(handle.plans),
        handle.query_epoch, handle.access_epoch, handle.delete_epoch, len(handle.outcome.batches),
        candidates, canonical_digest(candidates), handle.closure_versions, selected, revision, digest,
        ticket, None if ticket is None else canonical_digest(ticket),
        ingress_c04_child_activity_id_v1(ns, request.c02_operation_id),
        handle.need.responsibility_ref, responsibility.digest, cycle.cancel_epoch,
        frame.envelope.authority.purpose, frame.envelope.authority.audience,
        handle.need.required_checks, handle.need.missing_items,
        sum(batch.candidate_count for batch in handle.outcome.batches),
        sum(batch.node_count for batch in handle.outcome.batches),
        sum(batch.page_count for batch in handle.outcome.batches), handle.elapsed_seconds,
        handle.search_stop_reason, handle.search_cursor)
    coverage = "partial" if candidates.coverage != "complete" else "complete"
    return stage_result_v1(frame, "d06", OPERATION, request, provenance={"selection": original},
        coverage=coverage, missing=original.missing_items,
        continuation=candidates.continuation)


def read_adopted_ingress_c03_selection_v1(db, *, namespace, c02_operation_id):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    original = read_adopted_domain_operation_v1(db, namespace,
        ingress_c03_selection_operation_id_v1(namespace, c02_operation_id))
    if original is None:
        return None
    if original["domain"] != "d06" or original["operation_kind"] != OPERATION:
        raise ValueError("C03 selection locator belongs to another immutable producer")
    value = decode_typed_production_value_v1(original["payload"]["provenance"]["selection"], C03DirectSelectionOriginalV1)
    receipt = original["receipt"]
    if (value.namespace != namespace or value.c02_operation_id != c02_operation_id
            or len(receipt.invalidated_epochs) != 1 or receipt.invalidated_epochs[0].revision != value.query_epoch.revision + 1
            or original["payload"]["writes"]):
        raise ValueError("C03 own metadata CAS bridge lacks its exact query-before/commit-after proof")
    return value, original, {"query_epoch": value.query_epoch.revision,
        "commit_after_epoch": receipt.invalidated_epochs[0].revision, "metadata_receipt_digest": canonical_digest(receipt)}
