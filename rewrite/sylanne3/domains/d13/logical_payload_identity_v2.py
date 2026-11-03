"""Stable D13 payload identity algebra over actual verified committed rows."""
import json
from dataclasses import replace
from ...authority_service.contract import AuthorityUnavailable
from ...authority_service.d13_cache_use_contract_v2 import payload_identity_v2
from ...runtime_contracts import VersionedRef, canonical_digest
from .derived_block_metadata_v2 import DerivedBlockMetadataV2, derived_block_metadata_key_v2


def initial_logical_payload_identity_v2(metadata, *, metadata_ref, initial_metadata,
        initial_history, producer_attempt, event):
    """No authority is conferred. Callers verify physical capture and committed receipt.

    history=(rev,valid,cell,bot,persona,session,eventid), attempt=(digest,pre_epoch),
    event=(digest,revisions_json,epoch). Physical capture IDs never change the key.
    """
    if (type(metadata) is not DerivedBlockMetadataV2 or type(metadata_ref) is not VersionedRef
            or initial_metadata != replace(metadata, status='standby')
            or derived_block_metadata_key_v2(metadata).token != metadata_ref.ref
            or type(initial_history) is not tuple or len(initial_history) != 7
            or initial_history[:2] != (1, 1) or initial_history[3:5] != metadata.namespace.as_tuple
            or initial_history[5] != 'd13-derived-cache-v6'
            or not initial_history[6].startswith('d13-paid-derived-complete:')
            or type(producer_attempt) is not tuple or len(producer_attempt) != 2
            or type(event) is not tuple or len(event) != 3):
        raise AuthorityUnavailable('D13 logical identity requires exact verified initial committed producer rows')
    request_digest, before_epoch = producer_attempt
    event_digest, revisions, epoch = event
    if (any(type(value) is not str or len(value) != 64
            or any(char not in '0123456789abcdef' for char in value)
            for value in (request_digest, event_digest))
            or type(before_epoch) is not int or before_epoch < 0 or epoch != before_epoch + 1
            or [metadata_ref.ref, 1] not in json.loads(revisions)):
        raise AuthorityUnavailable('D13 logical identity lost its exact committed event/request/epoch')
    origin = canonical_digest(('d13.logical-payload-origin.v2', metadata.namespace,
        metadata.block_ref, metadata.payload_digest, initial_history[6], request_digest, event_digest, epoch))
    return payload_identity_v2((metadata.block_ref, metadata.payload_digest, origin, metadata_ref.version))
