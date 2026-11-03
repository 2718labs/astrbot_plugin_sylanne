"""Named generic outbound metadata after shared SourceALL; grants no execution permission."""
from __future__ import annotations
from dataclasses import dataclass
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.v2_contract import ExecutionBindingV2, MutationReceiptV2
from ..authority_service.observation_refinement_contract_v3 import (
    PlatformObservationRefinementReceiptV3,observation_platform_observation_v3)
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d08.execution import _decode
from ..domains.d08.commitment_communication_v1 import (
    USE_TYPE, USE_TYPES, CommitmentTermsCommunicationIntentV2, decode_communication_scope_v1, decode_communication_use_v1,
    scope_route_source_v1, communication_scope_request_v1, CommitmentCommunicationIntentV1, CommitmentPromiseUseV1,
    RegisterCurrentCommitmentCommunicationInputRequestV1, decode_commitment_communication_v1)
from .d08_commitment_scope_read_v1 import _ScopeJSONColumnV1

_ISSUED = WeakKeyDictionary()


@dataclass(frozen=True, slots=True)
class NamedCommitmentOutboundLocatorV1:
    source_refs: tuple[str, ...]
    audience: tuple[str, ...]
    scene_ref: str
    account_ref: str
    binding_digest: str


def begin_named_commitment_outbound_locator_metadata_v1(reader):
    from .natural_outbound_receipt_adoption_read_v3 import NaturalOutboundReceiptAdoptionReadV3
    from .first_ingress_v2 import scene_ref_for_conversation
    from .current_commitment_lifecycle_source_v3 import CommitmentLifecycleOriginalReadV3
    if type(reader) not in (NaturalOutboundReceiptAdoptionReadV3,CommitmentLifecycleOriginalReadV3) or reader.family != "commitment_literal":
        raise AuthorityUnavailable("named outbound locator belongs only to its actual receipt-adoption READ Work")
    observed = reader.observed
    if type(observed) not in (MutationReceiptV2,PlatformObservationRefinementReceiptV3) or observed.durable_state != "committed":
        raise AuthorityUnavailable("named outbound locator requires the actual committed Core observation")
    binding = observation_platform_observation_v3(observed).binding
    if type(binding) is not ExecutionBindingV2:
        raise AuthorityUnavailable("named outbound locator requires the actual admitted generic binding")
    origin = binding.origin; candidate = reader.candidate_metadata
    if (origin.operation_id != reader.final_operation_id
            or candidate.get("schema") != "sylanne.d11.dispatch_candidate.v1"
            or candidate.get("status") != "source_qualified"
            or type(candidate.get("source_refs")) is not list or not 1<=len(candidate["source_refs"])<=32):
        raise AuthorityUnavailable("named outbound locator changed its actual generic candidate/Core origin")
    refs = tuple(candidate["source_refs"])
    for ref in refs:
        key = AtomKey.from_token(ref)
        if NamespaceId.from_key(key) != reader.namespace or key.type_name != "memory.source":
            raise AuthorityUnavailable("named outbound Source locator crossed namespace/type")
    return NamedCommitmentOutboundLocatorV1(refs, (origin.destination_ref,),
        scene_ref_for_conversation(reader.namespace, origin.account_ref, origin.destination_ref),
        origin.account_ref, canonical_digest(binding))


class NamedCommitmentOutboundReceiptMetadataV1:
    def __init__(self, reader):
        from .natural_outbound_receipt_adoption_read_v3 import NaturalOutboundReceiptAdoptionReadV3
        from .current_commitment_lifecycle_source_v3 import CommitmentLifecycleOriginalReadV3
        if type(reader) not in (NaturalOutboundReceiptAdoptionReadV3,CommitmentLifecycleOriginalReadV3) or reader.family != "commitment_literal" or not reader.qualified:
            raise AuthorityUnavailable("named literal/Scope/Use bytes require actual shared ALLcontext+expression EOF first")
        self.reader = reader; self.owner = reader
        self.db, self.namespace, self.operation = reader.db, reader.namespace, reader.operation
        self.operation_id = reader.final_operation_id; self.locator = begin_named_commitment_outbound_locator_metadata_v1(reader)
        self.columns = {}; self.current = None; self.queue = []; self.complete = False; self.result = None
        self.metadata = self.event_epoch = self.use = self.scope = self.owner_metadata = None
        self.phase = "bundle"; self.terms_dependencies=None
        _ISSUED[self] = (reader, reader.operation, reader.observed, self.locator)
        reader.operation.retain(65536)

    def _actual(self, meter=None):
        if (_ISSUED.get(self) != (self.reader, self.reader.operation, self.reader.observed, self.locator)
                or self.operation.closed or not self.reader.qualified):
            raise AuthorityUnavailable("named outbound original stream lost its same-Work SourceALL qualification")
        self.reader.require_current_v3(meter)

    def _begin(self, tag, *, table, column, keys, key, cell_id=None):
        self.current = (tag, _ScopeJSONColumnV1(self.reader, table=table, column=column,
            key_columns=keys, key=key, cell_id=cell_id))

    def value(self, tag): return self.columns[tag].require_v3(self.reader)

    def _history(self, meter, tag, ref, revision, *, event_id=None):
        key = AtomKey.from_token(ref)
        row = meter.read_fixed_row(self.db, "graph_history",
            ("value_cell_id", "valid", "event_bot", "event_persona", "event_session", "event_id"),
            "token=? AND revision=?", (ref, revision))
        if (NamespaceId.from_key(key) != self.namespace or row is None or row[1] != 1
                or row[2:4] != self.namespace.as_tuple or event_id is not None and row[5] != event_id):
            raise AuthorityUnavailable("named outbound historical Scope/Use/member lost its actual committed origin")
        self._begin(tag, table="graph_history", column="value", keys=("token", "revision"), key=(ref, revision), cell_id=row[0])

    def advance(self, meter):
        self._actual(meter)
        if self.complete: return True
        if self.current is not None:
            tag, column = self.current
            if column.advance(meter): self.columns[tag] = column; self.current = None
            return False
        reader = self.reader; namespace = self.namespace
        if self.phase == "bundle":
            self.metadata = meter.read_fixed_row(self.db, "graph_bundle_operations", ("activity_id", "effect_id"),
                "bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, self.operation_id))
            origin = observation_platform_observation_v3(reader.observed).binding.origin
            if self.metadata != (origin.activity_id, origin.effect_id):
                raise AuthorityUnavailable("named observation does not belong to the actual generic final activity/effect")
            self._begin("bundle", table="graph_bundle_operations", column="receipt_json", keys=("bot", "persona", "operation_id"),
                key=(*namespace.as_tuple, self.operation_id)); self.phase = "event"; return False
        if self.phase == "event":
            self.candidate = self.value("bundle").get("dispatch_candidate")
            if self.candidate != reader.candidate_metadata:
                raise AuthorityUnavailable("named observation metadata candidate changed before its complete original read")
            row = meter.read_fixed_row(self.db, "graph_events", ("epoch_revision",),
                "bot=? AND persona=? AND session=? AND event_id=?", (*namespace.as_tuple, self.metadata[0], self.operation_id))
            if row is None or row[0] != self.candidate["graph_epoch"]:
                raise AuthorityUnavailable("named observation actual final event epoch differs")
            self.event_epoch = row[0]; self.queue = ["revisions", "reads"]; self.phase = "event_columns"; return False
        if self.phase == "event_columns":
            if self.queue:
                tag = self.queue.pop(0)
                self._begin(tag, table="graph_events", column=tag, keys=("bot", "persona", "session", "event_id"),
                    key=(*namespace.as_tuple, self.metadata[0], self.operation_id)); return False
            uses = tuple((ref, revision) for ref, revision in self.value("revisions") if AtomKey.from_token(ref).type_name in USE_TYPES)
            if len(uses) != 1 or uses[0][1] != 1:
                raise AuthorityUnavailable("named observation requires its one actual same-final PromiseUse")
            self.use_ref = uses[0][0]
            self.queue = [tuple(row) for row in self.candidate["refs"]] + [uses[0]]
            self.phase = "members"; return False
        if self.phase == "members":
            if self.queue:
                ref, revision = self.queue.pop(0)
                if [ref, revision] not in self.value("revisions"):
                    raise AuthorityUnavailable("named observed member is outside actual final write footprint")
                self._history(meter, (ref, revision), ref, revision, event_id=self.operation_id); return False
            self.use = decode_communication_use_v1(self.value((self.use_ref, 1)))
            self._history(meter, "scope", self.use.scope.key.token, self.use.scope.revision)
            self.phase = "scope"; return False
        if self.phase == "scope":
            self.scope = decode_communication_scope_v1(self.value("scope"))
            if (self.scope.source_refs != self.locator.source_refs or self.scope.conversation_ref != self.locator.audience[0]
                    or self.scope.scene_ref != self.locator.scene_ref or self.scope.platform_ref != self.locator.account_ref):
                raise AuthorityUnavailable("named actual outbound recipient/scene/complete Source roots changed")
            self._history(meter, "commitment", self.use.commitment.key.token, self.use.commitment.revision)
            if type(self.scope) is CommitmentTermsCommunicationIntentV2:
                from .current_commitment_fulfillment_source_v3 import TermsCommunicationDependenciesReadV3
                self.terms_dependencies=TermsCommunicationDependenciesReadV3(self);self.phase="terms_dependencies"
            else:self.phase="owner_original"
            return False
        if self.phase=="terms_dependencies":
            if self.terms_dependencies.advance_v3(meter):self.phase="owner_original"
            return False
        if self.phase == "owner_original":
            from .d08_commitment_scope_read_v1 import read_commitment_approval_original_header_v1
            self.owner_metadata=read_commitment_approval_original_header_v1(self.db,meter,namespace,self.scope)
            self._begin("owner_original", table="graph_domain_production_originals_v1", column="original_payload_json",
                keys=("bot", "persona", "operation_id"), key=(*namespace.as_tuple, self.scope.approval_operation_id), cell_id=None)
            self.phase = "verify"; return False
        if self.phase == "verify":
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            from .domain_production_contracts_v1 import ProductionOwnerGuardV1
            from .d08_commitment_communication_v1 import recover_commitment_dispatch_candidate_in_transaction_v1
            original = self.value("owner_original")
            expected_request=communication_scope_request_v1(self.scope)
            request = decode_typed_production_value_v1(original["request"],type(expected_request))
            guard = decode_typed_production_value_v1(original["owner_guard"], ProductionOwnerGuardV1)
            if (canonical_digest(original) != self.owner_metadata[3]
                    or canonical_digest(plain_v1(request)) != self.owner_metadata[2] or guard != self.scope.owner_guard
                    or original["identity"]["operation_id"] != self.scope.approval_operation_id
                    or request != expected_request
                    or [write["value"] for write in original["writes"] if write["key"] == self.use.scope.key.token] != [self.value("scope")]):
                raise AuthorityUnavailable("named historical approval does not match the actual Scope/Use original")
            self.result = recover_commitment_dispatch_candidate_in_transaction_v1(self.db, namespace,
                self.operation_id, prepared_history=self)
            platform = observation_platform_observation_v3(reader.observed)
            if (self.result is None or platform.binding.action_intent_digest.removeprefix("sha256:") != canonical_digest(
                    _decode("d08.action_intent.v1", self.value(tuple(self.candidate["refs"][0]))))
                    or platform.binding.origin.payload_digest.removeprefix("sha256:") != self.result.evidence.payload_digest
                    or platform.binding.origin.effect_id != self.result.evidence.effect_id):
                raise AuthorityUnavailable("named actual Core observation differs from its historical approved final payload/effect")
            self.complete = True; return True
        raise AuthorityUnavailable("unregistered named receipt metadata phase")

    def row_v1(self): return (*self.metadata, None)
    def receipt_v1(self): return self.value("bundle")
    def event_v1(self): return (self.value("revisions"), self.event_epoch, self.value("reads"))
    def history_v1(self, ref, revision):
        if ref == self.use.scope.key.token: return self.value("scope")
        if ref == self.use.commitment.key.token: return self.value("commitment")
        return self.value((ref, revision))

    def release_v1(self):
        if self.terms_dependencies is not None:
            self.terms_dependencies.release_v1();self.terms_dependencies=None
        _ISSUED.pop(self, None)
        for column in self.columns.values(): column._frozen_value = None
        self.columns = {}; self.current = self.scope = self.use = self.result = None


def begin_named_commitment_outbound_receipt_metadata_v1(reader):
    return NamedCommitmentOutboundReceiptMetadataV1(reader)
