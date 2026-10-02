"""Closed Contact V3 finished-fence observation; decoding grants no authority."""
from dataclasses import dataclass
import re

from .contract import identifier
from .v2_contract import FencePermitV2,canonical_digest,from_wire,to_wire
from ..runtime.restore_anchor import RestoreAnchor

SCHEMA='d08.contact-fence-finished-original.v3'


@dataclass(frozen=True,slots=True)
class ContactFenceFinishedOriginalV3:
    permit: FencePermitV2
    permit_commitment: str
    finish_request_id: str
    finish_request_digest: str
    current_anchor: RestoreAnchor
    state: str='finished'
    schema: str=SCHEMA

    def __post_init__(self):
        if (self.schema != SCHEMA or self.state != 'finished'
                or type(self.permit) is not FencePermitV2 or self.permit.operation != 'write'
                or not re.fullmatch(r'owner-domain-[0-9a-f]{48}',self.permit.operation_id)
                or self.permit_commitment != canonical_digest(self.permit)
                or type(self.current_anchor) is not RestoreAnchor
                or self.current_anchor != self.permit.pinned_anchor
                or self.current_anchor.activation_generation != self.permit.generation
                or type(self.finish_request_digest) is not str
                or not re.fullmatch(r'sha256:[0-9a-f]{64}',self.finish_request_digest)):
            raise ValueError('Contact finished original is not its closed actual permit/anchor')
        identifier(self.finish_request_id,'finish_request_id')


def contact_finished_to_wire_v3(value):
    if type(value) is not ContactFenceFinishedOriginalV3:
        raise ValueError('typed Contact finished original required')
    from dataclasses import asdict
    return {'schema':value.schema,'state':value.state,'permit':to_wire(value.permit),
        'permit_commitment':value.permit_commitment,'finish_request_id':value.finish_request_id,
        'finish_request_digest':value.finish_request_digest,'current_anchor':asdict(value.current_anchor)}


def contact_finished_from_wire_v3(raw):
    if type(raw) is not dict or set(raw)!=set(ContactFenceFinishedOriginalV3.__dataclass_fields__):
        raise ValueError('Contact finished original fields differ')
    value=ContactFenceFinishedOriginalV3(**{**raw,'permit':from_wire(raw['permit']),
        'current_anchor':RestoreAnchor(**raw['current_anchor'])})
    if contact_finished_to_wire_v3(value)!=raw:
        raise ValueError('Contact finished original wire differs')
    return value
