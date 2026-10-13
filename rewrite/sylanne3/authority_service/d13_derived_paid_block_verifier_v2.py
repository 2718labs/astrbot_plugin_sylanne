"""New installed v6 derived-block paid verifier; legacy V1 semantics remain exact."""
import json

from ..graph_types import AtomKey, Owner
from ..runtime_contracts import canonical_digest
from ..domains.d13.derived_block_metadata_v2 import METADATA_TYPE, decode_derived_block_metadata_v2
from ..runtime.d11_derived_cache_payload_v1 import read_derived_payload_v1
from ..runtime.d13_current_collection_v6 import read_current_d13_collection_v6, _snapshot
from .d13_paid_block_verifier_v1 import InstalledD13PaidBlockVerifierV1

class InstalledD13DerivedPaidBlockVerifierV2(InstalledD13PaidBlockVerifierV1):
    def __init__(self, db, *, installation, resource_issuer, budget_issuer, namespace, scene_ref,
            conversation_ref, now_utc, activation_generation, authority_store=None, max_slots=256,
            _authority_collection=None):
        super().__init__(db, installation=installation, resource_issuer=resource_issuer,
            budget_issuer=budget_issuer, authority_store=authority_store, max_slots=64)
        self._authority_collection = _authority_collection
        if _authority_collection is None:
            self._collection = read_current_d13_collection_v6(db, namespace, scene_ref, conversation_ref, now_utc,
                expected_activation_generation=activation_generation, max_slots=max_slots)
        else:
            from ..runtime.d13_current_collection_v6 import PreparedAuthorityD13CollectionV6
            from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
            work,cap=_authority_collection
            if type(work)is not AuthorityGraphReadWorkV3 or type(cap)is not PreparedAuthorityD13CollectionV6 or work.db is not db:
                raise ValueError('actual same-Work current paid collection cap required')
            self._collection=cap.require_current_v6(work)
            window=self._collection.window
            if (window.namespace!=namespace or AtomKey.from_token(window.scene_ref.ref).owner.subject!=scene_ref
                    or window.conversation_ref!=conversation_ref or window.trusted_utc!=now_utc
                    or window.activation_epoch!=activation_generation or self._collection.max_slots!=max_slots):
                raise ValueError('actual paid collection cap crossed its original namespace/scene/time/activation')
        self._snapshot = _snapshot(db, namespace)

    def for_current_read_v2(self, now_utc):
        window=self._collection.window
        return InstalledD13DerivedPaidBlockVerifierV2(self._db,installation=self._installation,
            resource_issuer=self._resource,budget_issuer=self._budget,namespace=window.namespace,
            scene_ref=AtomKey.from_token(window.scene_ref.ref).owner.subject,conversation_ref=window.conversation_ref,
            now_utc=now_utc,activation_generation=window.activation_epoch,authority_store=self._authority,
            max_slots=self._collection.max_slots,_authority_collection=self._authority_collection)

    def _current_window(self, window):
        if _snapshot(self._db,window.namespace) != self._snapshot:
            raise ValueError('derived paid verifier crossed its actual current Graph snapshot')
        return self._collection.window

    def _stored_block(self, candidate, window, original, evidence, settlement):
        key = AtomKey(Owner('persona',*window.namespace.as_tuple),METADATA_TYPE,candidate.block_ref)
        from .current_authority_graph_read_v3 import read_bound_authority_graph_attachment_v3
        handled,row=read_bound_authority_graph_attachment_v3(self._db,table='graph_atoms',columns=('value','valid'),
            key_columns=('token',),key=(key.token,))
        if not handled:
            row = self._db.execute('SELECT value,valid FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
        if row is None or row[1]!=1:
            return None
        metadata = decode_derived_block_metadata_v2(json.loads(row[0]))
        if (metadata.namespace != window.namespace or metadata.block_ref != candidate.block_ref
                or metadata.scene_ref != window.scene_ref or metadata.audience_ref != window.audience_ref
                or metadata.conversation_ref != window.conversation_ref
                or metadata.status not in {'standby','active'}
                or metadata.paid_original_operation_id != original.binding.original_operation_id
                or metadata.paid_original_digest != original.original_digest
                or metadata.paid_evidence_digest != evidence.evidence_digest
                or metadata.paid_settlement_digest != canonical_digest(settlement)
                or metadata.expires_at_utc != min(candidate.expires_at_utc,original.binding.expires_at_utc,
                    *(turn.trusted_utc+72*3600 for turn in candidate.turns))):
            return None
        return read_derived_payload_v1(self._db,metadata,now_utc=window.trusted_utc)


def build_installed_d13_derived_paid_block_verifier_v2(db, **kwargs):
    return InstalledD13DerivedPaidBlockVerifierV2(db,**kwargs)
