"""Streaming ordinary-persona origin projections; data, never permissions.

The actual consumer Work supplies a fixed profile, real storage fragments and
its existing memory/quantum accounting. Full canonical EOF and subtree hashes
cover omitted claims. No PersonaPlan/GraphAtom or claim readout is fabricated.
"""
from __future__ import annotations
import codecs
from hashlib import sha256
import json
import re
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2


class _CanonicalRangeHashV3:
    def __init__(self, ensure_ascii):
        self.hash = sha256()
        self.decoder = None if ensure_ascii else codecs.getincrementaldecoder("utf8")("strict")
    def update(self, raw, meter):
        if self.decoder is None:
            encoded = raw
        else:
            text = self.decoder.decode(raw)
            parts = []
            for char in text:
                cp = ord(char)
                if cp < 127:
                    parts.append(char)
                elif cp <= 65535:
                    parts.append("\\u" + format(cp, "04x"))
                else:
                    cp -= 65536
                    parts.append("\\u" + format(55296 + (cp >> 10), "04x")
                        + "\\u" + format(56320 + (cp & 1023), "04x"))
            encoded = "".join(parts).encode("ascii")
        meter.charge_encode(len(encoded))
        self.hash.update(encoded)
    def finish(self):
        if self.decoder is not None and self.decoder.decode(b"", final=True):
            raise ValueError("ordinary origin range ended in a partial UTF8 scalar")
        return self.hash.hexdigest()


class OrdinaryOriginMetadataStreamV3(C09CanonicalJSONStreamV2):
    """Closed projections plus exact whole-value/range commitments.

    Profile selection is not authorization. Only an actual issuing Work may
    bind the resulting metadata to its independently verified original rows,
    signatures, Owner/currentness and subsequent Source ALL.
    """
    _SINGLE_EVENT_READOUT_D07_PROFILES = {
        'single_event_readout_d07_adopted_v4':'adopted',
        'single_event_readout_d07_prepared_v4':'prepared',
        'single_event_readout_d07_semantic_question_v4':'semantic_question',
        'single_event_readout_d07_single_event_review_attention_v1_v4':'single_event_review_attention_v1',
        'single_event_readout_d07_request_v4':'request',
        'single_event_readout_d07_call_v4':'call',
        'single_event_readout_d07_paid_cost_v4':'paid_cost',
        'single_event_readout_d07_body_cost_v4':'body_cost',
        'single_event_readout_d07_execution_v4':'execution',
        'single_event_readout_d07_result_v4':'result',
        'single_event_readout_d07_single_event_review_adoption_v1_v4':'single_event_review_adoption_v1',
    }
    _PROFILES = frozenset({"plan", "revision", "adoption", "proposal", "activation",
        "initial_receipt", "resources", "trial", "counter", "general_intent", "general_start", "growth", "c02", "interpretation", "d04_prepared",
        "single_event_policy", "single_event_input", "single_event_adoption", "single_event_review",
        "single_event_counter_metadata","single_event_interpretation_body","single_event_review_operation",
        "single_event_review_adoption_original_v1",
        "single_event_readout_case_metadata_v4","single_event_readout_registration_metadata_v4",
        "ordinary_cumulative_policy", "ordinary_continuity_assessment", "ordinary_deep_adoption",
        "ordinary_deep_anchor", "ordinary_basis_locator", "ordinary_basis_body", "ordinary_cumulative_producer",
        "ordinary_unchanged_producer", "ordinary_dedicated_member", "ordinary_dedicated_producer_v3",
        "ordinary_d07_adopted", "ordinary_d07_prepared", "ordinary_d07_question",
        "full_persona_writer_producer_metadata_v1", "full_persona_writer_signed_metadata_v1",
        "full_persona_writer_life_metadata_v1"}) | frozenset(_SINGLE_EVENT_READOUT_D07_PROFILES)
    _PLAN_FIELDS = frozenset({"plan_id", "namespace", "version", "authored", "blocks"})
    _BLOCK_FIELDS = frozenset({"block_id", "kind", "plasticity"})
    _ADOPTION_FIELDS = frozenset({"schema", "namespace", "identity", "authority", "owner_guard",
        "now_utc", "coverage", "missing_inputs", "continuation_ref", "request", "read_versions",
        "observed_originals", "provenance", "writes"})
    _PROVENANCE_FIELDS = frozenset({"candidate", "originals", "growth", "general_growth_intent",
        "trial_start_originals", "trial_originals", "general_growth", "single_event_adoption", "single_event_review"})
    _AUTHORITY_FIELDS = frozenset({"actor", "issuer_domain", "namespace", "purpose", "audience", "activation_generation"})

    def __init__(self, *, profile, ensure_ascii, reserve):
        if profile not in self._PROFILES:
            raise ValueError("unregistered ordinary origin metadata profile")
        super().__init__(ensure_ascii=ensure_ascii)
        self.profile, self.codec_ascii, self.reserve = profile, ensure_ascii, reserve
        self.nodes, self.metadata, self.fields = {}, None, {}
        self.scalar = bytearray()
        self.active_hashes, self.commitments, self.ranges = {}, {}, {}
        self.wire_offset, self.fragment_base, self.hash_cursor = 0, 0, 0
        self.fragment = b""
        self.meter = None
        self.eof = False
        self.claim_protocols = {}
        self._claim_scan = {}
        self.method_policy_claims, self._method_policy_scan = {}, {}

    def _append_decoded_codepoint(self, codepoint):
        state = self._string
        if state is not None and state['mode'] == 'value':
            path = state['path']
            if path and path[-1] in {'claim', 'replacement_claim'}:
                from .d01_ordinary_dedicated_origin_v3 import (
                    new_method_policy_metadata_scan_v3, feed_method_policy_metadata_v3)
                scan = self._method_policy_scan.get(path)
                if scan is None:
                    scan = new_method_policy_metadata_scan_v3()
                    self._method_policy_scan[path] = scan
                feed_method_policy_metadata_v3(scan, chr(codepoint))
                markers = ('d01.semantic-identity-revision.v3',
                    'd01.conditioned-capability-revision.v1',
                    'd01.conditioned-strategy-revision.v1', 'd01.method-policy.v1')
                tail = self._claim_scan.get(path, '') + chr(codepoint)
                for marker in markers:
                    if marker in tail:
                        self.claim_protocols[path] = marker
                unknown = re.search(r'"schema"\s*:\s*"([^"\\]+)"', tail)
                if unknown is not None and unknown.group(1) not in markers:
                    self.claim_protocols[path] = "unregistered:" + unknown.group(1)
                self._claim_scan[path] = tail[-256:]
        return super()._append_decoded_codepoint(codepoint)

    def _retains(self, path):
        if self.profile == 'ordinary_dedicated_producer_v3':
            from .d01_ordinary_dedicated_origin_v3 import ordinary_dedicated_metadata_retains_path_v3
            return ordinary_dedicated_metadata_retains_path_v3(path)
        if self.profile in {"single_event_readout_case_metadata_v4","single_event_readout_registration_metadata_v4"}:
            from .d01_single_event_readout_v4 import single_event_readout_metadata_retains_path_v4
            return single_event_readout_metadata_retains_path_v4(self.profile,path)
        if self.profile in self._SINGLE_EVENT_READOUT_D07_PROFILES:
            from .d07_single_event_review_v1 import single_event_review_historical_metadata_retains_path_v1
            return single_event_review_historical_metadata_retains_path_v1(self._SINGLE_EVENT_READOUT_D07_PROFILES[self.profile],path)
        if self.profile=="single_event_review_adoption_original_v1":
            from .single_event_review_target_v1 import single_event_review_adoption_retains_path_v1
            return single_event_review_adoption_retains_path_v1(path)
        if self.profile in {"full_persona_writer_producer_metadata_v1","full_persona_writer_signed_metadata_v1",
                "full_persona_writer_life_metadata_v1"}:
            from .current_full_persona_writer_v1 import full_persona_writer_metadata_retains_path_v1
            return full_persona_writer_metadata_retains_path_v1(self.profile,path)
        if self.profile.startswith("ordinary_"):
            from .d01_ordinary_cumulative_growth_v1 import ordinary_cumulative_metadata_retains_path_v1
            selected = ordinary_cumulative_metadata_retains_path_v1(self.profile, path)
            if selected is not None: return selected
        if not path:
            return True
        if self.profile == "d04_prepared":
            if path[0] == "read_rows":
                return len(path)<3 or path[2] in {"ref","revision","valid"}
            return path[0] in {"schema","namespace","operation_id","job_id","call_id","audience","purpose","role_support_manifest"}
        if self.profile == "single_event_counter_metadata":
            return path[0] in {"schema","interpretation_id","question_key","source_refs","stance","evidence_status","current"}
        if self.profile == "single_event_review_operation":
            if path[0] in {"schema","namespace","identity","coverage","now_utc"}:return True
            return path[0]=="provenance" and (len(path)==1 or path[1] in {"single_event_adoption","single_event_review"})
        if self.profile == "interpretation":
            return path[0] in {"source_refs", "current"}
        if self.profile == "c02":
            return path[0] == "envelope" and (len(path) == 1 or path[1] in {"deadline_utc", "parent_budget_lease_ref"})
        # Never retain a claim, a replacement claim, or value-rule prose while
        # discovering origin. Their complete original bytes are hashed below.
        if "values" in path or path[-1] in {"claim", "replacement_claim"}:
            return False
        if "blocks" in path:
            i = path.index("blocks")
            if len(path) > i + 2:
                return path[i + 2] in self._BLOCK_FIELDS
        if self.profile == "plan":
            return path[0] in self._PLAN_FIELDS
        if self.profile == "adoption":
            if path[0] not in self._ADOPTION_FIELDS:
                return False
            if path[0] == "authority" and len(path) > 1:
                return path[1] in self._AUTHORITY_FIELDS
            if path[0] == "provenance" and len(path) > 1:
                return path[1] in self._PROVENANCE_FIELDS
        return True

    def _commits(self, path):
        if self.profile == 'ordinary_dedicated_producer_v3':
            from .d01_ordinary_dedicated_origin_v3 import ordinary_dedicated_metadata_commits_path_v3
            return ordinary_dedicated_metadata_commits_path_v3(path)
        if self.profile in {"single_event_readout_case_metadata_v4","single_event_readout_registration_metadata_v4"}:
            from .d01_single_event_readout_v4 import single_event_readout_metadata_commits_path_v4
            return single_event_readout_metadata_commits_path_v4(self.profile,path)
        if self.profile in self._SINGLE_EVENT_READOUT_D07_PROFILES:
            return not path
        if self.profile=="single_event_review_adoption_original_v1":
            from .single_event_review_target_v1 import single_event_review_adoption_commits_path_v1
            return single_event_review_adoption_commits_path_v1(path)
        if self.profile in {"full_persona_writer_producer_metadata_v1","full_persona_writer_signed_metadata_v1",
                "full_persona_writer_life_metadata_v1"}:
            from .current_full_persona_writer_v1 import full_persona_writer_metadata_commits_path_v1
            return full_persona_writer_metadata_commits_path_v1(self.profile,path)
        if self.profile.startswith("ordinary_"):
            from .d01_ordinary_cumulative_growth_v1 import ordinary_cumulative_metadata_commits_path_v1
            selected = ordinary_cumulative_metadata_commits_path_v1(self.profile, path)
            if selected is not None and (selected or not path or path[-1] in {"claim", "replacement_claim", "values"}):
                return selected or not path or path[-1] in {"claim", "replacement_claim", "values"}
        if not path or path[-1] in {"claim", "replacement_claim", "values"}:
            return True
        if self.profile != "adoption":
            return False
        if path == ("writes",):
            return True
        if len(path) == 3 and path[0] == "writes" and path[2] == "value":
            return True
        prefix = ("provenance", "candidate")
        general = ("provenance", "growth", "candidate")
        for base in (prefix, general):
            if path == base + ("revision",) or path == base + ("typed_writes",):
                return True
            if path[:len(base) + 1] == base + ("typed_writes",) and len(path) == len(base) + 3 and path[-1] == "value":
                return True
        return path in {("provenance", "general_growth_intent"),
            ("provenance", "general_growth", "general_growth_intent")}

    def _hash_to(self, end):
        if end <= self.hash_cursor:
            return
        if not self.fragment_base <= self.hash_cursor <= end <= self.fragment_base + len(self.fragment):
            raise ValueError("ordinary origin parser range left its actual current fragment")
        raw = self.fragment[self.hash_cursor - self.fragment_base:end - self.fragment_base]
        self.reserve(len(raw) * 12 + 65536)
        for state in self.active_hashes.values():
            state.update(raw, self.meter)
        self.hash_cursor = end

    def _put(self, path, value):
        if not path:
            self.metadata = value
        else:
            parent = self.nodes[path[:-1]]
            if type(parent) is list:
                parent.append(value)
            else:
                parent[path[-1]] = value

    def _event(self, event):
        path, kind = event.path, event.kind
        if kind in {"object_start", "array_start", "scalar_start"} and self._commits(path):
            self._hash_to(event.start_offset)
            self.active_hashes[path] = _CanonicalRangeHashV3(self.codec_ascii)
            self.ranges[path] = [event.start_offset, None]
        self._hash_to(event.end_offset)
        if kind in {"object_end", "array_end", "scalar_end"} and path in self.active_hashes:
            self.commitments[path] = self.active_hashes.pop(path).finish()
            self.ranges[path][1] = event.end_offset
        if kind == "scalar_end" and path and path[-1] in {"claim", "replacement_claim"}:
            self.claim_protocols.setdefault(path, None)
            self._claim_scan.pop(path, None)
            from .d01_ordinary_dedicated_origin_v3 import finish_method_policy_metadata_v3
            self.method_policy_claims[path] = finish_method_policy_metadata_v3(
                self._method_policy_scan.pop(path, None))
        if kind == "key":
            self.fields.setdefault(path[:-1], set()).add(event.key)
        if not self._retains(path):
            return
        if kind in {"object_start", "array_start"}:
            value = {} if kind == "object_start" else []
            self.nodes[path] = value
            self._put(path, value)
        elif kind == "scalar_start":
            self.scalar.clear()
        elif kind == "scalar_chunk":
            self.reserve(len(self.scalar) + len(event.raw) * 12 + 65536)
            self.scalar.extend(event.raw)
        elif kind == "scalar_end":
            self._put(path, json.loads(self.scalar))
            self.scalar.clear()
        elif kind in {"object_end", "array_end"}:
            self.nodes.pop(path, None)

    def advance_fragment_v3(self, raw, meter):
        if self.eof:
            raise ValueError("ordinary origin metadata already reached EOF")
        self.fragment, self.fragment_base, self.hash_cursor, self.meter = raw, self.wire_offset, self.wire_offset, meter
        progress = super().feed(raw, self._event)
        self._hash_to(self.fragment_base + len(raw))
        self.wire_offset += len(raw)
        self.fragment, self.meter = b"", None
        return progress

    def finish_metadata_v3(self):
        parsed = super().finish()
        if self.active_hashes or () not in self.commitments or self.scalar:
            raise ValueError("ordinary origin metadata has no complete canonical EOF")
        self.eof = True
        return self.metadata, self.commitments, self.ranges, self.fields, parsed
