"""Finite structural inventory of Contact Owner originals, without erasure rights.

Authentication is owned by read_contact_owner_invocation_v3 with the installed
issuer. No decoded row or accepted receipt proves completed physical disposal.
"""
from dataclasses import asdict
import json

from ..runtime_contracts import NamespaceId, canonical_serialize
from .contact_owner_invocation_v3 import (
    TABLE, ContactOwnerInvocationOriginalV3, require_contact_owner_invocation_schema_v3,
)

COLUMNS = ('bot', 'persona', 'operation_id', 'request_digest', 'payload_json', 'payload_digest', 'signature')
MAX_PAYLOAD_BYTES = 1024 * 1024


def validate_contact_owner_inventory_row_v3(columns, row):
    if tuple(columns) != COLUMNS or len(row) != len(COLUMNS):
        raise ValueError('C09 Contact Owner invocation inventory columns differ')
    bot, persona, operation, request, encoded, committed, signature = row
    if type(encoded) is not str or len(encoded.encode('utf-8')) > MAX_PAYLOAD_BYTES:
        raise ValueError('C09 complete Contact Owner invocation exceeds payload bound; HOLD')
    value = ContactOwnerInvocationOriginalV3(encoded)
    raw = json.loads(encoded)
    if (raw['namespace'] != asdict(NamespaceId(bot, persona)) or raw['operation_id'] != operation
            or raw['request_digest'] != request or value.digest != committed
            or canonical_serialize(raw) != encoded or type(signature) is not str or not signature):
        raise ValueError('C09 Contact Owner invocation exact row differs')
    return value
