"""Closed Natural locator metadata codec; no Source or full-original issuer."""
from ..authority_service.contract import AuthorityUnavailable
# The fixed profile retains only the declared locator subtree. All other
# receipt bytes still enter the canonical parser and whole-original SHA.
_FIELD_V1 = "natural_dispatch_read_locator"
_REF_KEYS_V1 = frozenset({"ref", "version"})
_PART_KEYS_V1 = frozenset({"kind", "ref", "dependencies", "audience_ref", "access_ref", "expires_at_utc"})
_META_KEYS_V1 = frozenset({
    "schema", "profile_version", "namespace", "operation_id", "activity_id", "effect_id",
    "admission_ref", "original_utc_deadline", "bundle_digest", "admission_digest",
    "admission_receipt_digest", "candidate_digest", "request_digest", "graph_receipt_commitment",
    "graph_incarnation", "graph_revision", "graph_epoch", "generation_seal_digest",
    "review_seal_digest", "scoped_proof_digest", "authorization_original_digest", "source_originals",
    "final_job", "recipe",
})
_RECIPE_KEYS_V1 = frozenset({
    "schema", "kind", "namespace", "variant", "generation_parent_original_id",
    "generation_original_operation_id", "generation_job_id", "generation_c02_operation_id",
    "generation_original_header", "commitments", "committed_selection", "admission", "action",
    "batch", "semantic_child", "plan", "frozen_at_utc", "expires_at_utc", "question",
    "stable_history", "history_selection", "recent_history", "detail_history", "stable_turns",
    "source_groups", "expected_scoped_d06_projection", "required_producer_joins",
})
_NAMESPACE_KEYS_V1 = frozenset({"bot_id", "persona_id"})
_OBJECT_FIELDS_V1 = {
    (): frozenset({"schema", "profile_version", "metadata", "metadata_byte_count", "metadata_sha256"}),
    ("metadata",): _META_KEYS_V1,
    ("metadata", "namespace"): _NAMESPACE_KEYS_V1,
    ("metadata", "final_job"): frozenset({"job_ref", "job_id", "operation_id", "activity_id", "effect_id",
        "bot_id", "persona_id", "snapshot_ref", "phase", "work_kind", "deadline_utc", "budget_ref",
        "resource_ref", "fence", "cancel_epoch"}),
    ("metadata", "source_originals", "*"): frozenset({"ref", "version", "cell_id", "byte_count", "sha256", "producer_operation_id"}),
    ("metadata", "recipe"): _RECIPE_KEYS_V1,
}
_RV1 = ("metadata", "recipe")
_OBJECT_FIELDS_V1.update({
    _RV1+("namespace",): _NAMESPACE_KEYS_V1,
    _RV1+("generation_original_header",): frozenset({"graph_epoch", "access_epoch", "deletion_epoch", "worker_fence", "state"}),
    _RV1+("commitments",): frozenset({"frozen_input_digest", "qualified_units_digest", "model_request_digest",
        "stable_prefix_digest", "semantic_projection_digest", "original_graph_guard_digest",
        "generation_terminal_receipt_digest", "generation_terminal_output_digest", "generation_typed_request_digest",
        "candidate_digest", "admission_receipt_digest", "request_digest"}),
    _RV1+("committed_selection",): frozenset({"operation_id", "activity_id", "effect_id", "attempt_id",
        "admission_ref", "candidate_writes", "admission_graph_revision", "graph_epoch", "graph_incarnation",
        "original_utc_deadline", "clock_policy_ref", "clock_policy_digest", "bundle_source_refs",
        "access_epoch", "delete_epoch", "query_epoch"}),
    _RV1+("admission",): frozenset({"schema", "purpose", "audience", "account_ref", "destination_ref", "scene_ref", "action_ref", "segment_index"}),
    _RV1+("action",): frozenset({"identity", "action_id", "action_kind", "target_ref", "purpose", "source_refs"}),
    _RV1+("action", "identity"): frozenset({"activity_id", "effect_id", "attempt_id", "phase", "operation_id", "canonical_input_digest"}),
    _RV1+("batch",): frozenset({"schema", "scene_id", "audience_id", "source_ref", "valid_until", "cancellation_epoch",
        "batch_digest", "segment_id", "payload_digest", "segment_position", "segment_count", "paid_review"}),
    _RV1+("batch", "paid_review"): frozenset({"generation_original_operation_id", "generation_call_id",
        "generation_model_call_request_digest", "generation_terminal_receipt_digest", "generation_output_digest",
        "generation_reservation_operation_id", "review_original_operation_id", "review_call_id",
        "review_model_call_request_digest", "review_terminal_receipt_digest", "review_output_digest",
        "review_reservation_operation_id", "parent_budget_lease_id", "review_policy_version",
        "current_graph_guard_digest", "receipt_digest"}),
    _RV1+("semantic_child",): frozenset({"selected_index", "root_operation_id", "root_effect_id", "plan_ref", "generation_output_digest", "roster"}),
    _RV1+("semantic_child", "roster", "*"): frozenset({"operation_id", "effect_id", "segment_id", "position", "payload_digest"}),
    _RV1+("plan",): frozenset({"namespace", "plan_ref", "scene_ref", "audience_ref", "scene_id", "audience_id",
        "valid_until_utc", "final_activity_id", "final_operation_id", "final_effect_id", "promise_grants", "units"}),
    _RV1+("plan", "namespace"): _NAMESPACE_KEYS_V1,
    _RV1+("plan", "units", "*"): frozenset({"basis_id", "kind", "d06_claim_kind", "source_refs", "access_refs",
        "correction_refs", "audience_ref", "purpose", "expires_at_utc", "qualification_ref", "qualification_digest"}),
    _RV1+("question",): _PART_KEYS_V1,
    _RV1+("stable_history", "*"): _PART_KEYS_V1,
    _RV1+("history_selection",): frozenset({"schema", "window_digest", "order_watermark", "coverage", "gaps",
        "source_dependencies", "scene_ref", "audience_ref", "conversation_ref", "expires_at_utc", "access_epoch",
        "deletion_epoch", "activation_generation", "raw_turn_refs", "selected_slice_digest", "policy_ref", "policy_digest",
        "block_ref", "block_refs", "page_cursors", "collection_snapshot_commitment"}),
    _RV1+("recent_history", "*"): frozenset({"sequence", "source_ref", "access_ref", "raw_ref", "audience_ref",
        "conversation_ref", "trusted_utc", "completion_ref"}),
    _RV1+("detail_history", "*"): frozenset({"sequence", "source_ref", "expires_at_utc"}),
    _RV1+("stable_turns", "*"): frozenset({"block_index", "sequence", "block_ref"}),
    _RV1+("source_groups", "*"): frozenset({"group", "index", "purpose", "audience", "source_versions", "source_walk_profile"}),
    _RV1+("expected_scoped_d06_projection",): frozenset({"source_roots", "versions"}),
})
for _path_v1 in (
    ("committed_selection", "candidate_writes", "*"), ("batch", "source_ref"),
    ("semantic_child", "plan_ref"), ("plan", "plan_ref"), ("plan", "scene_ref"), ("plan", "audience_ref"),
    ("plan", "promise_grants", "*"),
    *(("plan", "units", "*", name, "*") for name in ("source_refs", "access_refs", "correction_refs")),
    ("plan", "units", "*", "qualification_ref"),
    *(("question", name) for name in ("ref", "audience_ref", "access_ref")), ("question", "dependencies", "*"),
    *(("stable_history", "*", name) for name in ("ref", "audience_ref", "access_ref")), ("stable_history", "*", "dependencies", "*"),
    *(("history_selection", name) for name in ("scene_ref", "audience_ref", "block_ref")),
    *(("history_selection", name, "*") for name in ("source_dependencies", "raw_turn_refs", "block_refs")),
    *(("recent_history", "*", name) for name in ("source_ref", "access_ref", "raw_ref", "audience_ref", "completion_ref")),
    ("detail_history", "*", "source_ref"), ("stable_turns", "*", "block_ref"),
    ("source_groups", "*", "source_versions", "*"), ("expected_scoped_d06_projection", "versions", "*"),
):
    _OBJECT_FIELDS_V1[_RV1+_path_v1] = _REF_KEYS_V1
del _path_v1

_ARRAY_PATHS_V1 = frozenset({
    ("metadata", "source_originals"),
    *(_RV1+path for path in (
        ("committed_selection", "candidate_writes"), ("committed_selection", "bundle_source_refs"),
        ("admission", "audience"), ("action", "source_refs"), ("semantic_child", "roster"),
        ("plan", "promise_grants"), ("plan", "units"),
        *(("plan", "units", "*", name) for name in ("source_refs", "access_refs", "correction_refs")),
        ("question", "dependencies"), ("stable_history",), ("stable_history", "*", "dependencies"),
        *(("history_selection", name) for name in
          ("coverage", "gaps", "source_dependencies", "raw_turn_refs", "block_refs", "page_cursors")),
        *(("history_selection", name, "*") for name in ("coverage", "gaps", "page_cursors")),
        ("recent_history",), ("detail_history",), ("stable_turns",), ("source_groups",),
        ("source_groups", "*", "audience"), ("source_groups", "*", "source_versions"),
        ("expected_scoped_d06_projection", "source_roots"), ("expected_scoped_d06_projection", "versions"),
        ("required_producer_joins",),
    )),
})

from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2, _CanonicalJSONValueBuilderV3
from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2, legacy_cell_read_transaction_v2
class NaturalDispatchLocatorMetadataColumnV1(_CanonicalJSONValueBuilderV3):
    def __init__(self, owner, operation_id):
        # Codec only. The outer initial/P2 factory owns its exact Work and
        # private metadata proof; this reader grants no Body/Source permission.
        self.operation_id = operation_id
        self.owner, self.db, self.operation = owner, owner.db, owner.operation
        from .dispatch_current_inventory_v3 import _FrozenObjectV3, _FrozenArrayV3
        self._initialize_json_value_v3(incremental_retention=True,
            frozen_object_type=_FrozenObjectV3, frozen_array_type=_FrozenArrayV3)
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.offset = self.fragment_offset = 0
        self.total = None
        self.complete = False
        self._reserve(65536)

    def _emit(self, event):
        if not event.path:
            if event.kind == "object_start" or event.kind == "object_end":
                return super()._emit(event)
            raise AuthorityUnavailable("Natural committed receipt must be its actual canonical object")
        if event.path[0] != _FIELD_V1:
            return
        if event.path == (_FIELD_V1,) and event.kind == "key":
            return super()._emit(event)
        path = event.path[1:]
        pattern = tuple("*" if type(v) is int else v for v in path)
        if event.kind == "object_start" and pattern not in _OBJECT_FIELDS_V1:
            raise AuthorityUnavailable("Natural locator contains an undeclared metadata object")
        if event.kind == "array_start" and pattern not in _ARRAY_PATHS_V1:
            raise AuthorityUnavailable("Natural locator contains an undeclared metadata array")
        if event.kind == "key":
            allowed = _OBJECT_FIELDS_V1.get(pattern[:-1])
            if allowed is None or event.key not in allowed:
                raise AuthorityUnavailable("Natural locator contains an undeclared metadata field")
        # Keep the real outer root so the selected subtree cannot masquerade as
        # a standalone/full receipt original. This class publishes only its own
        # private metadata EOF proof, never a DispatchOriginalJSONReadV3 record.
        return super()._emit(event)

    def advance(self, meter):
        if self.complete:
            return True
        if self.fragment_offset < len(self.fragment):
            end = min(self.fragment_offset + 1024, len(self.fragment))
            self._reserve(65536)
            self.parser.feed(self.fragment[self.fragment_offset:end], self._emit)
            self.fragment_offset = end
            return False
        key = (*self.owner.namespace.as_tuple, self.operation_id)
        with legacy_cell_read_transaction_v2(self.db):
            if self.total is None:
                meter.charge_read(8)
                row = self.db.execute("SELECT length(CAST(receipt_json AS BLOB)) "
                    "FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?", key).fetchone()
                if row is None:
                    raise AuthorityUnavailable("actual Natural receipt metadata original is absent")
                self.total = row[0]
            if self.offset < self.total:
                chunk, total, kind = read_legacy_sql_cell_fragment_v2(
                    self.db, table="graph_bundle_operations", column="receipt_json",
                    where="bot=? AND persona=? AND operation_id=?", parameters=key,
                    start=self.offset, length=min(16384, self.total-self.offset), meter=meter)
                if total != self.total or kind != "text":
                    raise AuthorityUnavailable("Natural receipt metadata original kind or length changed")
                self.offset += len(chunk)
                self.fragment, self.fragment_offset = chunk, 0
                return False
        parsed = self.parser.finish()
        if parsed.byte_count != self.total:
            raise AuthorityUnavailable("Natural receipt metadata did not reach complete original EOF")
        from .dispatch_current_inventory_v3 import _detach_value_v3
        self.operation.retain(self._detached_container_bytes + 1024)
        raw = _detach_value_v3(self.value)
        if type(raw) is not dict or set(raw) != {_FIELD_V1}:
            raise AuthorityUnavailable("Natural receipt has no supported producer-issued locator")
        self.sha256, self.byte_count = parsed.sha256, parsed.byte_count
        self.raw = raw[_FIELD_V1]
        self.complete = True
        self.nodes = {}; self.value = self.parser = None
        self.scalar = bytearray(); self.fragment = b""
        return True

