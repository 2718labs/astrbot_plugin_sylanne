"""Actual Natural W01 locator originals; selection metadata grants no access."""
from dataclasses import asdict
from hashlib import sha256
import json
from weakref import WeakSet

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..memory_types import source_key, access_key
from ..runtime_contracts import canonical_serialize
from .natural_dispatch_read_locator_v1 import extract_natural_dispatch_read_locator_recipe_v1

SCHEMA = "sylanne.natural_dispatch_read_locator.v1"
_TOKEN = object()
_INPUTS = WeakSet()
_LOCATORS = WeakSet()


def _full(coordinator, db, namespace):
    from .current_graph_full_read_v3 import (
        CURRENT_DISPATCH_FAMILY_V3, SOURCE_METADATA_FAMILY_V3,
        require_bound_graph_full_read_proof_for_db_v3,
    )
    return require_bound_graph_full_read_proof_for_db_v3(
        db, namespace, required_families=frozenset({
            CURRENT_DISPATCH_FAMILY_V3, SOURCE_METADATA_FAMILY_V3,
        }))


def _frame(coordinator, db, scope, parent):
    from .natural_producer_qualification_v1 import _natural_frame
    frame = _natural_frame(db, scope.namespace)
    if (frame.graph is not coordinator or frame.scope is not scope
            or frame.origin != "host" or frame.phase != "frozen"
            or frame.parent_original_id != parent or scope.operation != "write"):
        raise AuthorityUnavailable("locator requires its actual Natural W01 producer frame")
    return frame


class _NaturalLocatorInputsV1:
    def __init__(self, token, *, coordinator, db, scope, generation, review,
                 frozen, scoped, scoped_digest, paid, final, same_batch_prepared):
        from .current_graph_full_read_v3 import PreparedCurrentGraphFullReadV3
        from .natural_reply_job_v2 import natural_semantic_original_version_v3
        if token is not _TOKEN:
            raise AuthorityUnavailable("actual verified Natural producer required")
        store = coordinator._GraphCoordinator__store
        if store._db is not db or not store._lock._is_owned() or not db.in_transaction:
            raise AuthorityUnavailable("locator input capture lost its actual Graph transaction")
        self.frame = _frame(coordinator, db, scope, generation.parent_original_id)
        full = _full(coordinator, db, scope.namespace)
        if type(full) is not PreparedCurrentGraphFullReadV3:
            raise AuthorityUnavailable("locator input capture requires actual pre-write FULL originals")
        full.require_current(coordinator, db, scope.namespace,
            required_families=full.prepared_families)
        # The caller is the successful paid-current verifier, after its actual
        # installed history rebuild or same-batch original verification. The
        # latter deliberately returns frozen_original, preserving own suffixes.
        from ..model_broker.natural_reply import FrozenNaturalReplyRequestV2
        if type(generation.frozen) is FrozenNaturalReplyRequestV2:
            original = generation.frozen
            if (original.input.stable_history or frozen.input.stable_history
                    or frozen.input.question != original.input.question
                    or frozen.input.plan != original.input.plan
                    or frozen.installation != original.installation):
                raise AuthorityUnavailable("V2 locator lacks its actual ingress-only original lineage")
        elif frozen is not generation.frozen and frozen != generation.frozen:
            raise AuthorityUnavailable("verified current history does not bind the original frozen input")
        self.version = natural_semantic_original_version_v3(generation, review)
        self.coordinator, self.db, self.scope = coordinator, db, scope
        self.full, self.before_stamp = full, full.graph_stamp
        self.generation, self.review, self.scoped = generation, review, scoped
        self.scoped_digest, self.paid, self.full_final = scoped_digest, paid, final
        self.same_batch_prepared = same_batch_prepared
        self.selected = self.selected_index = self.roster = self.roster_key = None
        self.roster_revision = None
        self.used = False
        _INPUTS.add(self)

    def select_final_v1(self, coordinator, scope, full_final, semantic_output, index):
        from ..domains.d09.natural_reply import select_natural_final_segment_v3
        if (self not in _INPUTS or self.used or coordinator is not self.coordinator
                or scope is not self.scope or full_final is not self.full_final
                or self.selected is not None):
            raise AuthorityUnavailable("Natural locator selection crossed its verified producer")
        _frame(coordinator, self.db, scope, self.generation.parent_original_id)
        if self.version is None:
            if semantic_output is not None or index != 0:
                raise AuthorityUnavailable("legacy Natural locator requires its exact one output")
            selected = full_final
        else:
            if semantic_output != self.paid.generation_output:
                raise AuthorityUnavailable("Natural semantic selection lost actual paid complete output")
            selected = select_natural_final_segment_v3(
                full_final, plan=self.generation.frozen.input.plan,
                generation_output=semantic_output, segment_index=index)
        self.selected, self.selected_index = selected, index
        return selected

    def bind_roster_v1(self, coordinator, scope, *, head, roster_write, roster_original):
        from ..domains.d09.natural_disposition_v1 import natural_disposition_from_wire_v1
        from ..authority_service.natural_disposition_maintenance_v1 import NaturalDispositionCoreOriginalV1
        if (self not in _INPUTS or self.used or coordinator is not self.coordinator
                or scope is not self.scope or self.selected is None or self.version is None):
            raise AuthorityUnavailable("actual selected semantic producer required for roster binding")
        if roster_write is not None:
            if (head is not None or self.selected_index != 0
                    or type(roster_original) is not NaturalDispositionCoreOriginalV1
                    or roster_original.kind != "roster_prepared"
                    or roster_original.authority_namespace != scope.authority_namespace
                    or roster_original.parent_original_id != self.generation.parent_original_id):
                raise AuthorityUnavailable("first semantic locator has no actual Core roster original")
            value = natural_disposition_from_wire_v1(roster_write.value)
            if (value.birth_original_ref != roster_original.original_ref
                    or value.to_wire() != roster_original.payload["expected_next_value"]):
                raise AuthorityUnavailable("actual first roster differs from its Core producer original")
            self.roster_key, self.roster_revision = roster_write.key, 1
        else:
            if head is None:
                raise AuthorityUnavailable("later semantic locator lacks its actual adopted roster")
            self.roster_key, self.roster_revision, value = head
        if (value.namespace != scope.namespace
                or value.parent_original_id != self.generation.parent_original_id
                or value.generation_original_operation_id != self.generation.seal.original_operation_id
                or value.review_original_operation_id != self.review.seal.original_operation_id
                or value.whole_output_digest != self.generation.terminal_output_digest):
            raise AuthorityUnavailable("actual roster crossed the paid generation/review original")
        child = value.children[self.selected_index]
        material = self.selected.material
        if ((child.index, child.operation_id, child.effect_id, child.segment_id, child.payload_digest)
                != (self.selected_index, material.final_operation_id, material.final_effect_id,
                    material.segment.segment_id, material.payload_digest)):
            raise AuthorityUnavailable("actual roster does not contain this selected paid child")
        self.roster = value


def _capture_verified_natural_locator_inputs_v1(**inputs):
    return _NaturalLocatorInputsV1(_TOKEN, **inputs)


def _source_originals(coordinator, db, full, recipe):
    """Qualify real metadata EOFs per original purpose, without reading text."""
    from ..domains.d06 import source_correction_head_key
    from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
    namespace = full.namespace
    projection, _query = full.require_current(coordinator, db, namespace,
        required_families=full.prepared_families)
    profiles = {
        "dispatch_context_32": ("context", 32),
        "dispatch_expression_32": ("expression", 32),
        "producer_expression_256": ("expression", 256),
        "material_expression_256": ("expression", 256),
    }
    cache = {}
    for group in recipe["source_groups"]:
        profile = profiles.get(group["source_walk_profile"])
        if profile is None or group["purpose"] != profile[0]:
            raise AuthorityUnavailable("unknown actual Natural locator purpose profile")
        expected = {row["ref"]: row["version"] for row in group["source_versions"]}
        active, done = set(), set()
        pending = [(ref, False) for ref in expected]
        while pending:
            ref, leaving = pending.pop()
            if leaving:
                active.remove(ref)
                done.add(ref)
                continue
            if ref in active:
                raise AuthorityUnavailable("Natural locator Source ancestry is cyclic")
            if ref in done:
                continue
            if len(active) + len(done) >= profile[1]:
                raise AuthorityUnavailable("Natural locator Source family exceeds its original profile")
            key = AtomKey.from_token(ref)
            if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
                raise AuthorityUnavailable("Natural locator Source crosses its namespace")
            if ref not in cache:
                witness = full.source_metadata(coordinator, db, namespace, key)
                cache[ref] = witness
            witness = cache[ref]
            if ref in expected and witness.revision != expected[ref]:
                raise AuthorityUnavailable("Natural locator selected Source version changed")
            access = projection.get(access_key(*namespace.as_tuple, key.owner.subject))
            correction = projection.get(source_correction_head_key(namespace, key.owner.subject))
            record = None
            for audience in group["audience"]:
                record = _qualify_source_rights_values_v3(namespace, ref, witness, access,
                    correction, audience=audience, purpose=group["purpose"], metadata_only=True)
                if record is None:
                    raise AuthorityUnavailable("Natural locator Source/ancestor lacks its actual purpose rights")
            if record is None:
                raise AuthorityUnavailable("Natural locator group has no actual audience")
            active.add(ref)
            pending.append((ref, True))
            pending.extend((source_key(*namespace.as_tuple, parent).token, False)
                           for parent in record.parent_source_ids)
    full.require_current(coordinator, db, namespace, required_families=full.prepared_families)
    return [{"ref": ref, "version": witness.revision, "cell_id": witness.cell_id,
             "byte_count": witness.header[3], "sha256": witness.payload_sha256,
             "producer_operation_id": witness.header[2]}
            for ref, witness in sorted(cache.items())]


def _final_job_metadata(db, bundle, runtime, admission, request):
    from datetime import datetime
    from .d11_types import runtime_job_key
    from .jobs import PersistentJob
    from .natural_final_issuer_v2 import NaturalFinalD11RuntimeV2
    if (type(runtime) is not NaturalFinalD11RuntimeV2
            or runtime.status != "admitted_runtime_hold_graph_final_claim"
            or len(runtime.runtime_admission.jobs) != 1
            or bundle.persistent_job_refs != (runtime.job_ref,)):
        raise AuthorityUnavailable("Natural locator requires its actual unique D11 final job")
    admitted = runtime.runtime_admission.jobs[0]
    job = admitted.job
    identity = bundle.envelope.identity
    namespace = bundle.envelope.authority.namespace
    if (type(job) is not PersistentJob or admitted.graph_job_ref != runtime.job_ref
            or runtime_job_key(job.bot_id,job.persona_id,job.activity_id,job.job_id).token != runtime.job_ref
            or (job.bot_id,job.persona_id,job.operation_id,job.activity_id,job.effect_id)
                != (*namespace.as_tuple,identity.operation_id,identity.activity_id,identity.effect_id)
            or job.work_kind != "message" or job.phase != "waiting" or job.fence != 0
            or job.budget_ref != admission.admission.budget_parent_lease_ref
            or request.operation_id != job.operation_id or request.effect_id != job.effect_id):
        raise AuthorityUnavailable("Natural locator final job crossed its successful admission identity")
    columns = ("job_id","operation_id","activity_id","effect_id","bot_id","persona_id",
               "snapshot_ref","phase","work_kind","deadline_utc","budget_ref","resource_ref",
               "fence","cancel_epoch","lease_holder","lease_expires_utc")
    row = db.execute("SELECT "+",".join(columns)+" FROM runtime_jobs WHERE job_id=?",
                     (job.job_id,)).fetchone()
    if row is None or tuple(row) != tuple(getattr(job,name) for name in columns):
        raise AuthorityUnavailable("Natural locator final job scalar head differs from actual D11 admission")
    if (datetime.fromisoformat(admission.admission.utc_deadline.replace("Z","+00:00")).timestamp()
            > datetime.fromisoformat(job.deadline_utc.replace("Z","+00:00")).timestamp()):
        raise AuthorityUnavailable("Natural locator admission exceeds its actual final job deadline")
    return {"job_ref":runtime.job_ref, **{name:getattr(job,name) for name in columns
                                        if name not in ("lease_holder","lease_expires_utc")}}


class _NaturalDispatchReadLocatorWitnessV1:
    def __init__(self, token, *, inputs, coordinator, db, bundle, evidence,
                 graph_receipt, authorization_original, admission, request, runtime):
        from .current_graph_full_read_v3 import PreparedCurrentGraphFullWriteViewV3
        from .natural_final_authorization_original_v3 import _NaturalFinalAuthorizationWitnessV3
        if (token is not _TOKEN or type(inputs) is not _NaturalLocatorInputsV1
                or inputs not in _INPUTS or inputs.used or inputs.coordinator is not coordinator
                or inputs.db is not db or inputs.selected is None
                or type(authorization_original) is not _NaturalFinalAuthorizationWitnessV3):
            raise AuthorityUnavailable("actual selected Natural producer/auth originals required")
        scope = inputs.scope
        _frame(coordinator, db, scope, inputs.generation.parent_original_id)
        full = _full(coordinator, db, scope.namespace)
        if (type(full) is not PreparedCurrentGraphFullWriteViewV3 or full.base is not inputs.full
                or full.facts.before_stamp != inputs.before_stamp
                or full.graph_stamp[1] != graph_receipt.epoch):
            raise AuthorityUnavailable("Natural locator requires its actual same-Work Store writer delta")
        actual = authorization_original.locator_commitments_v1(
            coordinator, db, bundle, evidence, graph_receipt, scope, admission, request)
        material = inputs.selected.material
        if ((material.final_activity_id, material.final_operation_id, material.final_effect_id)
                != (bundle.envelope.identity.activity_id, bundle.envelope.identity.operation_id,
                    bundle.envelope.identity.effect_id)):
            raise AuthorityUnavailable("Natural locator selected child differs from the actual committed bundle")
        recipe = extract_natural_dispatch_read_locator_recipe_v1(inputs.generation,
            evidence=evidence, admission=admission, bundle=bundle, graph_receipt=graph_receipt)
        if recipe["semantic_child"] is not None:
            if inputs.roster is None:
                raise AuthorityUnavailable("semantic locator has no actual adopted/prepared roster producer")
            child = recipe["semantic_child"]
            if child["selected_index"] != inputs.selected_index:
                raise AuthorityUnavailable("Natural locator selected roster index differs")
            rows = [{"operation_id": value.operation_id, "effect_id": value.effect_id,
                     "segment_id": value.segment_id, "position": value.index,
                     "payload_digest": value.payload_digest} for value in inputs.roster.children]
            if rows != child["roster"]:
                raise AuthorityUnavailable("Natural locator complete roster metadata differs")
            row = db.execute("SELECT revision,valid,value FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
                (*scope.namespace.as_tuple, inputs.roster_key.token)).fetchone()
            if row is None or row[:2] != (inputs.roster_revision, 1) or json.loads(row[2]) != inputs.roster.to_wire():
                raise AuthorityUnavailable("Natural locator roster lost its actual current Store write")
        sources = _source_originals(coordinator, db, full, recipe)
        final_job = _final_job_metadata(db,bundle,runtime,admission,request)
        payload = {
            "schema": SCHEMA, "profile_version": 1,
            "namespace": asdict(scope.namespace),
            "operation_id": bundle.envelope.identity.operation_id,
            "activity_id": bundle.envelope.identity.activity_id,
            "effect_id": bundle.envelope.identity.effect_id,
            "admission_ref": admission.admission.admission_ref,
            "original_utc_deadline": admission.admission.utc_deadline,
            **actual,
            "graph_incarnation": full.graph_stamp[0].requirements.graph_incarnation,
            "graph_revision": scope.graph_revision + 1,
            "graph_epoch": graph_receipt.epoch.revision,
            "generation_seal_digest": inputs.paid.request.generation_content_request.original_seal_digest,
            "review_seal_digest": inputs.paid.request.review_original_seal_digest,
            "scoped_proof_digest": inputs.scoped_digest,
            "authorization_original_digest": authorization_original.digest,
            "source_originals": sources,
            "final_job": final_job,
            "recipe": recipe,
        }
        from .source_correction_read_v3 import _heap
        full.operation.retain(_heap(payload) * 4 + 65536)
        self.raw = canonical_serialize(payload)
        self.metadata_sha256 = sha256(self.raw.encode("ascii")).hexdigest()
        self.metadata_byte_count = len(self.raw)
        self.coordinator, self.db, self.scope, self.full = coordinator, db, scope, full
        self.bundle, self.evidence, self.graph_receipt = bundle, evidence, graph_receipt
        self.authorization_original, self.admission, self.request = authorization_original, admission, request
        self.used = False
        inputs.used = True
        _INPUTS.discard(inputs)
        _LOCATORS.add(self)

    def consume_for(self, coordinator, db, bundle, evidence, graph_receipt,
                    v2_write, admission, request, authorization_original, authorization_record):
        if (self not in _LOCATORS or self.used or self.coordinator is not coordinator
                or self.db is not db or not db.in_transaction or self.bundle is not bundle
                or self.evidence is not evidence or self.graph_receipt is not graph_receipt
                or self.admission != admission or self.request != request
                or authorization_original is not self.authorization_original
                or not authorization_original.used
                or authorization_record["original_digest"] != authorization_original.digest
                or v2_write is None or v2_write[0].graph_revision != self.scope.graph_revision
                or v2_write[1] != self.scope.graph_epoch):
            raise AuthorityUnavailable("Natural locator witness crossed its actual one-shot W01 commit")
        self.full.require_current(coordinator, db, self.scope.namespace,
            required_families=self.full.prepared_families)
        result = {"schema": SCHEMA, "profile_version": 1,
                  "metadata": json.loads(self.raw),
                  "metadata_byte_count": self.metadata_byte_count,
                  "metadata_sha256": self.metadata_sha256}
        self.used = True
        _LOCATORS.discard(self)
        return result


def _capture_natural_dispatch_read_locator_v1(**inputs):
    return _NaturalDispatchReadLocatorWitnessV1(_TOKEN, **inputs)
