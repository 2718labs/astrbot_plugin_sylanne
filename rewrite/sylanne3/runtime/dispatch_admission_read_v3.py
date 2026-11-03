"""Exact admission columns owned by the actual retained P2 inventory Work."""
from dataclasses import asdict
from weakref import WeakKeyDictionary, WeakSet

from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import _canonical_value, canonical_digest
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .owner_material_source_storage_v3 import CanonicalValueStreamV3

_ISSUER = object()
_ISSUED = WeakKeyDictionary()
_VERIFIED_READERS = WeakSet()
_COLUMNS = ("operation_id", "effect_id", "admission_digest", "graph_revision", "graph_epoch", "receipt_digest")


class DispatchAdmissionReadV3:
    def __init__(self, owner):
        from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3
        if type(owner) is _DispatchInventoryReadV3:
            ref=owner.binding.origin.admission_ref
        else:
            from .natural_dispatch_initial_read_v1 import _NaturalInitialReadV1
            from .natural_outbound_receipt_adoption_read_v3 import NaturalOutboundReceiptAdoptionReadV3
            from .artifact_outbound_receipt_adoption_read_v3 import ArtifactOutboundReceiptAdoptionReadV3
            if type(owner) is _NaturalInitialReadV1:
                owner.require_actual_v1()
            elif type(owner) in(NaturalOutboundReceiptAdoptionReadV3,ArtifactOutboundReceiptAdoptionReadV3):
                owner.require_current_v3()
                if not owner.qualified:
                    raise AuthorityUnavailable("outbound admission requires its actual complete SourceALL")
            else:
                raise AuthorityUnavailable("actual dispatch, Natural initial or named outbound receipt owner required")
            ref=owner.admission_ref
        self.owner, self.ref = owner, ref
        self.header = self.admission = self.request = self.result = None
        self.typed_admission = self.typed_request = self.stream = None
        self.phase = "header"

    def advance(self, meter):
        owner = self.owner
        if self.phase == "header":
            self.header = meter.read_fixed_row(owner.db, "graph_dispatch_admissions", _COLUMNS,
                "bot=? AND persona=? AND admission_ref=?", (*owner.namespace.as_tuple, self.ref))
            if self.header is None:
                raise AuthorityUnavailable("actual durable dispatch admission is absent")
            self.admission = DispatchOriginalJSONReadV3(owner, table="graph_dispatch_admissions",
                column="admission_json", key_columns=("bot", "persona", "admission_ref"), key=(*owner.namespace.as_tuple, self.ref))
            self.phase = "admission"
        elif self.phase == "admission":
            if self.admission.advance(meter):
                self.request = DispatchOriginalJSONReadV3(owner, table="graph_dispatch_admissions",
                    column="request_json", key_columns=("bot", "persona", "admission_ref"), key=(*owner.namespace.as_tuple, self.ref))
                self.phase = "request"
        elif self.phase == "request":
            if self.request.advance(meter):
                self.phase = "typed"
        elif self.phase == "typed":
            from .dispatch_admission import _admission_value_from_parsed_v3, _request_from_parsed_v3, namespace_of
            # Reserve the detached typed values and one active primitive stream;
            # no complete encoded JSON output is allocated in this phase.
            owner.operation.retain((self.admission.byte_count + self.request.byte_count) * 8 + 65536)
            self.typed_admission = _admission_value_from_parsed_v3(self.admission.require_v3(owner))
            self.typed_request = _request_from_parsed_v3(self.request.require_v3(owner))
            value = self.typed_admission
            if ((value.operation_id, value.effect_id) != self.header[:2]
                    or namespace_of(value) != owner.namespace or value.admission_ref != self.ref):
                raise AuthorityUnavailable("stored dispatch admission identity differs")
            self.stream = CanonicalValueStreamV3(asdict(value))
            self.phase = "admission_digest"
        elif self.phase == "admission_digest":
            self.stream.read_fragment(meter)
            if self.stream.complete:
                if self.stream.hash.hexdigest() != self.header[2]:
                    raise AuthorityUnavailable("actual full dispatch admission digest differs")
                self.stream = None
                self.phase = "request_stored_start"
        elif self.phase == "request_stored_start":
            self.stream = CanonicalValueStreamV3(asdict(self.typed_request))
            self.phase = "request_stored_digest"
        elif self.phase == "request_stored_digest":
            self.stream.read_fragment(meter)
            if self.stream.complete:
                if (self.stream.hash.hexdigest(), self.stream.offset) != (self.request.sha256, self.request.byte_count):
                    raise AuthorityUnavailable("actual original dispatch request canonical bytes differ")
                self.stream = None
                self.phase = "request_digest_start"
        elif self.phase == "request_digest_start":
            self.stream = CanonicalValueStreamV3(_canonical_value(self.typed_request, set()))
            self.phase = "request_digest"
        elif self.phase == "request_digest":
            self.stream.read_fragment(meter)
            if self.stream.complete:
                if self.stream.hash.hexdigest() != self.typed_admission.request_digest:
                    raise AuthorityUnavailable("actual original dispatch request digest differs")
                self.stream = None
                self.phase = "verified"
                _VERIFIED_READERS.add(self)
        elif self.phase == "verified":
            self.result = PreparedDispatchAdmissionV3(_ISSUER, self)
            from .dispatch_current_inventory_v3 import _DispatchInventoryReadV3
            receipt=self.result.receipt_v3()
            actual_request=self.result.request_v3()
            if type(owner)is _DispatchInventoryReadV3:
                if receipt != owner.admission or actual_request != owner.request:
                    self.result.release_payload_v3()
                    raise AuthorityUnavailable("actual full-EOF dispatch admission or request changed")
            else:
                from .natural_dispatch_initial_read_v1 import _NaturalInitialReadV1
                from .dispatch_admission import namespace_of
                from .natural_outbound_receipt_adoption_read_v3 import NaturalOutboundReceiptAdoptionReadV3
                if type(owner) is _NaturalInitialReadV1:
                    owner.require_actual_v1()
                elif type(owner) is NaturalOutboundReceiptAdoptionReadV3:
                    owner.require_current_v3()
                    if not owner.qualified:
                        self.result.release_payload_v3()
                        raise AuthorityUnavailable("outbound admission lost its actual SourceALL")
                else:
                    self.result.release_payload_v3()
                    raise AuthorityUnavailable("actual independent Natural initial or named receipt admission owner required")
                value=receipt.admission
                if (namespace_of(value)!=owner.namespace or value.admission_ref!=owner.admission_ref
                        or (value.operation_id,value.activity_id,value.effect_id)!=(
                            owner.selected_operation_id,owner.selected_activity_id,owner.selected_effect_id)
                        or (actual_request.operation_id,actual_request.activity_id,actual_request.effect_id)!=(
                            owner.selected_operation_id,owner.selected_activity_id,owner.selected_effect_id)):
                    self.result.release_payload_v3()
                    raise AuthorityUnavailable("actual full-EOF initial admission selection differs")
            _VERIFIED_READERS.discard(self)
            self.typed_admission = self.typed_request = None
            self.phase = "complete"
        return self.phase == "complete"


def _receipt_from_verified_original_v3(reader):
    """Construct only from the same reader's completed three canonical streams.

    The public receipt constructor keeps its full validation. Here the actual
    admission digest was already measured to EOF across reserved quanta; only
    the small receipt envelope is encoded again, never the complete admission.
    """
    from .dispatch_admission import DispatchAdmissionReceiptV1, _digest, _version
    if type(reader) is not DispatchAdmissionReadV3 or reader not in _VERIFIED_READERS or reader.phase != "verified":
        raise AuthorityUnavailable("actual verified admission reader required")
    admission, request = reader.typed_admission, reader.typed_request
    if (request.namespace != admission.namespace
            or (request.activity_id, request.effect_id, request.attempt_id, request.operation_id,
                request.dispatch_generation, request.segment_index, request.payload_digest) !=
               (admission.activity_id, admission.effect_id, admission.attempt_id, admission.operation_id,
                admission.dispatch_generation, admission.segment_index, admission.payload_digest)):
        raise AuthorityUnavailable("actual original dispatch request and admission differ")
    revision, epoch, digest = reader.header[3:]
    _version(revision, "graph_revision")
    _version(epoch, "graph_epoch")
    _digest(digest, "receipt_digest")
    if digest != canonical_digest({"admission_digest": reader.header[2],
            "graph_revision": revision, "graph_epoch": epoch}):
        raise AuthorityUnavailable("admission receipt digest differs")
    receipt = object.__new__(DispatchAdmissionReceiptV1)
    for name, value in (("admission", admission), ("graph_revision", revision),
                        ("graph_epoch", epoch), ("receipt_digest", digest)):
        object.__setattr__(receipt, name, value)
    return receipt


class PreparedDispatchAdmissionV3:
    """Historical original evidence; grants neither a permit nor sender power."""
    def __init__(self, issuer, reader):
        if issuer is not _ISSUER or reader not in _VERIFIED_READERS:
            raise AuthorityUnavailable("actual complete dispatch admission columns required")
        self.owner, self.ref, self.header = reader.owner, reader.ref, reader.header
        self.admission, self.request = reader.admission, reader.request
        self._receipt = _receipt_from_verified_original_v3(reader)
        self._request = reader.typed_request
        _ISSUED[self] = (self.owner, self.ref, self.header, self.admission, self.request, self._receipt, self._request)

    def _actual(self):
        if (_ISSUED.get(self) != (self.owner, self.ref, self.header, self.admission, self.request, self._receipt, self._request)
                or self.owner.operation.closed):
            raise AuthorityUnavailable("dispatch admission original retention changed")
        row = self.owner.db.execute("SELECT operation_id,effect_id,admission_digest,graph_revision,graph_epoch,receipt_digest "
            "FROM graph_dispatch_admissions WHERE bot=? AND persona=? AND admission_ref=?", (*self.owner.namespace.as_tuple, self.ref)).fetchone()
        if row != self.header:
            raise AuthorityUnavailable("dispatch admission scalar identity changed")
        return self

    def receipt_v3(self):
        self._actual()
        return self._receipt

    def request_v3(self):
        self._actual()
        return self._request

    def release_payload_v3(self):
        _ISSUED.pop(self, None)
        self.admission = self.request = self._receipt = self._request = None


def require_prepared_dispatch_admission_v3(value, db, namespace, admission_ref):
    if type(value) is not PreparedDispatchAdmissionV3:
        raise AuthorityUnavailable("actual private dispatch admission columns required")
    value._actual()
    if value.owner.db is not db or value.owner.namespace != namespace or value.ref != admission_ref:
        raise AuthorityUnavailable("dispatch admission original crossed its selected namespace or identity")
    return value
