"""Pinned read-only Graph facts for Authority model-egress admission.

Even a complete graph binding is not an Authority model fence or an executable
provider admission. The callable remains HOLD until those independent gates.
"""

from __future__ import annotations

from .current_authority_graph_read_v3 import (read_authority_current_point_v3 as _authority_point_v3,
    authority_current_json_v3 as _authority_json_v3,authority_current_json_matches_v3 as _authority_json_matches_v3,
    authority_current_versions_v3 as _authority_versions_v3,authority_reply_attention_versions_v3,
    require_authority_c02_bundle_envelope_v3)

from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sqlite3
from typing import Callable

from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2, from_wire
from .v2_model_egress_contract import ModelEgressIntentV1, ModelEgressDraftV1
from .current_d04_baseline_graph_proof import committed_baseline_current
from ..contracts import canonical_json
from ..graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner,
)
from ..graph_store import GraphStore
from ..domains.d06 import source_correction_head_key
from ..domains.d07 import attention_ticket_key
from ..domains.d07.qualified_attention_read import (
    read_qualified_focus_attention_ticket,
)
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
    build_first_ingress_encoding_payload,
)
from ..runtime.budget import get_budget_lease, require_budget_family_admissible
from ..runtime.c02_bundle_codec import c02_bundle_from_wire
from ..runtime.d11_types import RuntimeOutboxValue, job_graph_write, runtime_job_key, runtime_outbox_key
from ..runtime.encoding_call_binding import (
    CommittedEncodingBaselineV1, binding_to_json, load_binding,
)
from ..runtime.first_ingress_v2 import ingress_ids
from ..runtime.issuers import D11BudgetJobIssuer
from ..runtime.jobs import get_job
from ..runtime.reply_model_job import (
    read_current_reply_model_inputs_v1, read_saved_reply_job_v1,
    reply_binding_digest_v1, reply_envelope_from_wire_v1,
    reply_request_wire_v1, source_key_from_ref,
)
from ..runtime.restore_anchor import RestoreAnchor
from ..model_broker.reply_language import (
    REPLY_TEMPLATE_DIGEST, issue_reply_request_v1,
)
from ..runtime_contracts import (
    NamespaceId, QueryEpoch, SnapshotRequirementsV2, SourceQualification,
    VersionGuard, VersionedRef,
    canonical_digest, canonical_serialize,
)


def _canonical(value: str):
    result = _authority_json_v3(value)
    if not _authority_json_matches_v3(value,result,legacy_serializer=canonical_json):
        raise ValueError("noncanonical persisted JSON")
    return result


class PinnedCurrentModelEgressGraphVerifier:
    """Check original business facts in one pinned, read-only SQLite snapshot.

    ``graph_facts_current`` verifies the original job, source/access, and
    budget. ``complete_graph_current`` additionally checks the one durable
    model request in the same read snapshot. Neither method validates
    the new Authority fence or the administrator's live provider configuration.
    These are admission checks, not a result-read proof: they receive no
    consumer Owner principal/session or read purpose/audience, do not compare
    the current Owner graph grant, and require the original job to be running,
    its outbox pending and its budget reserved. They cannot authorize release
    of a completed provider body after a terminal receipt.
    """

    def __init__(self, graph_db_path: str | Path, *,
                 d11_issuer: D11BudgetJobIssuer,
                 trusted_now_utc: Callable[[], float],
                 trusted_paired_clock: Callable[[], tuple[float, str]] | None = None,
                 natural_history_verifier=None, artifact_draft_bundle=None):
        path = Path(graph_db_path)
        if not path.is_absolute():
            raise ValueError("graph database path must be administrator-pinned and absolute")
        if type(d11_issuer) is not D11BudgetJobIssuer or not callable(trusted_now_utc):
            raise TypeError("pinned D11 issuer and trusted clock are required")
        self._path = path.resolve(strict=True)
        if not self._path.is_file():
            raise ValueError("pinned graph database is not a file")
        self._issuer = d11_issuer
        self._clock = trusted_now_utc
        self._paired_clock = trusted_paired_clock
        self._natural_history = natural_history_verifier
        self._contact_policy_service = None
        self._internal_life_reader_v2 = None
        self._life_numeric_reader_v1 = None
        if artifact_draft_bundle is not None:
            from ..host.authority_profile import AdminInstallationBundle
            if type(artifact_draft_bundle) is not AdminInstallationBundle:
                raise TypeError("artifact draft verifier requires its actual installed bundle")
        self._artifact_draft_bundle = artifact_draft_bundle
        self._artifact_model_reader_v3 = None
        self._d13_paid_reader_v3 = None
        self._owner_stop_reply_service_v1 = None

    def install_owner_stop_reply_service_v1(self, service):
        from .owner_stop_reply_v1 import InstalledOwnerStopReplyServiceV1
        if (type(service) is not InstalledOwnerStopReplyServiceV1
                or self._owner_stop_reply_service_v1 is not None
                or service.issuer is not self._issuer
                or service.status_service._source_graphs[service.installation_id] != self._path):
            raise ValueError("model reply barrier needs the actual same-Graph/Core installed service")
        self._owner_stop_reply_service_v1 = service

    def read_current_relationship_model_workflow_v2(self, intent, request):
        """Read the actual signed Relationship C3 kind from this installed Graph."""
        from ..host.model_workflows_v5 import AdminModelWorkflowsV5
        from ..host.model_workflows_v6 import AdminModelWorkflowsV6
        from ..host.model_workflows_v7 import AdminModelWorkflowsV7
        from ..runtime.d07_execution_v1 import D07RelationshipPreparedV2
        from ..model_broker.broker import ModelCallRequest
        from .d07_current_execution_v1 import read_current_d07_execution_graph_v1
        from .contract import AuthorityUnavailable
        bundle = self._artifact_draft_bundle
        if (bundle is None or type(bundle.model_workflows) not in {AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7}
                or bundle.model_workflows.d07_relationship_cognition is None
                or type(request) is not ModelCallRequest):
            raise AuthorityUnavailable("actual installed named Relationship C3 workflow unavailable")
        path = self._path
        if self._owner_stop_reply_service_v1 is not None:
            _, storage, _ = self._owner_stop_reply_service_v1._storage()
            path = Path(storage["graph_path"])
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("BEGIN")
            prepared, _, _ = read_current_d07_execution_graph_v1(db, intent, self._issuer, self._clock(),
                allow_unsealed_prepare=True, installed_bundle=bundle)
            if (type(prepared) is not D07RelationshipPreparedV2 or prepared.digest != intent.binding_digest
                    or request.digest != intent.request_digest or prepared.call_id != intent.call_id):
                raise AuthorityUnavailable("named Relationship C3 differs from its actual signed prepared kind")
        return bundle.model_workflows.d07_relationship_cognition

    def read_current_named_d07_model_workflow_v3(self,intent,request,*,source_material):
        """Consume the retained actual Source Work, never reopen protected Graph JSON."""
        from ..host.model_workflows_v5 import AdminModelWorkflowsV5
        from ..host.model_workflows_v6 import AdminModelWorkflowsV6
        from ..host.model_workflows_v7 import AdminModelWorkflowsV7
        from ..host.model_workflows_v8 import AdminModelWorkflowsV8
        from ..host.model_workflows_v9 import AdminModelWorkflowsV9
        from ..runtime.d07_execution_v1 import (D07PreparedExecutionV1,D07RelationshipPreparedV2,
            D07IngressRecallPreparedV1,D07ReflectionPreparedV3)
        from ..runtime.d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
        from ..runtime.d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
        from ..model_broker.broker import ModelCallRequest
        from .d07_authority_model_source_read_v3 import PreparedD07AuthoritySourceMaterialV3
        from .contract import AuthorityUnavailable
        bundle=self._artifact_draft_bundle
        if (bundle is None or type(bundle.model_workflows)not in {AdminModelWorkflowsV5,AdminModelWorkflowsV6,
                AdminModelWorkflowsV7,AdminModelWorkflowsV8, AdminModelWorkflowsV9}or type(request)is not ModelCallRequest
                or type(source_material)is not PreparedD07AuthoritySourceMaterialV3):
            raise AuthorityUnavailable("named D07 workflow requires its actual retained qualified Source material")
        work=source_material.work
        if (work.controller.verifier is not self or work.request is not intent or source_material.reader.bundle is not bundle
                or source_material.reader.model_source_phase!="model_policy"):
            raise AuthorityUnavailable("named D07 policy crossed its actual verifier/intent/installed Source Work")
        from ..runtime.artifact_phase_observation_execution_v1 import D07ArtifactObservationPreparedV3
        prepared,job,frozen,actual_request,basis=source_material.require_for_observer_v3(work)
        if type(prepared)is D07RelationshipPreparedV2:
            workflow=bundle.model_workflows.d07_relationship_cognition
        elif type(prepared)is D07MethodGrowthPreparedV2 and type(bundle.model_workflows)in{
                AdminModelWorkflowsV6,AdminModelWorkflowsV7,AdminModelWorkflowsV8, AdminModelWorkflowsV9}:
            workflow=bundle.model_workflows.growth_cognition
        elif type(prepared)is D07ArtifactObservationPreparedV3:
            from ..host.model_workflows_v9 import is_installed_artifact_observation_cognition_slot_v1
            workflow=bundle.model_workflows.artifact_observation_cognition if type(bundle.model_workflows)is AdminModelWorkflowsV9 else None
            if not is_installed_artifact_observation_cognition_slot_v1(bundle,workflow):
                raise AuthorityUnavailable("Artifact observation lost its exact installed V9 workflow slot")
            if basis.kind!="artifact_observation_self":
                raise AuthorityUnavailable("Artifact workflow requires its dedicated actual qualified parentage")
        elif type(prepared)is D07GeneralGrowthPreparedV1 and type(bundle.model_workflows) in (AdminModelWorkflowsV8, AdminModelWorkflowsV9):
            workflow=bundle.model_workflows.general_growth_cognition
        elif type(prepared)in {D07PreparedExecutionV1,D07IngressRecallPreparedV1,D07ReflectionPreparedV3}:
            workflow=bundle.model_workflows.d07_cognition
        else:
            raise AuthorityUnavailable("actual D07 prepared variant has no installed workflow slot")
        if (workflow is None or prepared.digest!=intent.binding_digest or actual_request.digest!=request.digest
                or request.digest!=intent.request_digest or prepared.call_id!=intent.call_id or job.job_id!=intent.job_id
                or (workflow.provider_id,workflow.model_id,workflow.provider_config_ref,workflow.provider_config_digest,
                    workflow.max_output_tokens)!=(frozen.installation.provider_id,frozen.installation.model_id,
                    frozen.installation.provider_config_ref,frozen.installation.provider_config_digest,
                    frozen.installation.max_output_tokens)or workflow.purpose!=prepared.purpose):
            raise AuthorityUnavailable("named D07 policy differs from its actual signed kind/provider/source purpose")
        return workflow

    def observe_current_reply_scope_for_model_v1(self, intent, *, model_service=None,
            credential=None, subject=None, holder=None, expected_anchor=None, permit=None):
        """Derive only existing original parentage before the final Core tx."""
        from .contract import AuthorityUnavailable
        from ..runtime.foreground_cycle_v1 import WORK_KIND
        if type(intent) not in {ModelEgressDraftV1, ModelEgressIntentV1}:
            raise TypeError("actual typed model intent required for reply barrier scope")
        bundle = self._artifact_draft_bundle
        configured = bundle is not None and WORK_KIND in bundle.installation_policy.root_grant.allowed_work_kinds
        service = self._owner_stop_reply_service_v1
        path = self._path
        def read_parent(db):
            job = get_job(db, intent.job_id)
            namespace = NamespaceId(job.bot_id, job.persona_id)
            kind = job.work_kind
            relationship_prepared = None
            if kind == "d07.concern":
                if observation is not None and not observation.legacy:
                    from .model_reply_parentage_v3 import require_d07_parentage_v3
                    relationship_prepared = require_d07_parentage_v3(db,intent=intent,issuer=self._issuer)
                    if relationship_prepared is None or relationship_prepared.schema not in {
                            "d07.relationship-prepared.v2","d07.method-growth-prepared.v2","d07.artifact-observation-prepared.v3"}:
                        return None
                else:
                    from ..runtime.d07_execution_v1 import D07RelationshipPreparedV2, read_prepared_d07_execution_v1
                    from ..runtime.d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
                    relationship_prepared = read_prepared_d07_execution_v1(db, self._issuer, namespace, intent.job_id)
                    from ..runtime.artifact_phase_observation_execution_v1 import D07ArtifactObservationPreparedV3
                    if type(relationship_prepared) not in {D07RelationshipPreparedV2, D07MethodGrowthPreparedV2,D07ArtifactObservationPreparedV3}:
                        return None
                    if relationship_prepared.call_id != intent.call_id or relationship_prepared.digest != intent.binding_digest:
                        raise AuthorityUnavailable("model barrier Relationship C3 signed identity differs")
            if kind not in {"artifact_draft_v1", "natural_generation", "natural_review", "d04.appraisal", "d07.recall_need", "d07.concern"}:
                return None
            if not configured:
                if kind in {"artifact_draft_v1", "d07.recall_need", "d07.concern"}:
                    raise AuthorityUnavailable("auxiliary model has no actual installed foreground reply scope")
                return None
            if service is None or namespace != bundle.installation_policy.namespace:
                raise AuthorityUnavailable("foreground model admission lacks its actual Core reply barrier service/namespace")
            if kind == "artifact_draft_v1":
                from ..runtime.d11_life_preparation_v1 import TABLE, _read
                from ..runtime.d11_artifact_draft_model_v1 import (
                    decode_artifact_draft_original_v1, decode_artifact_draft_original_v2)
                from .model_reply_scope_observation_v3 import model_reply_scope_rows_v3
                refs = model_reply_scope_rows_v3(db, kind='life_c4_call_original', parameters=(intent.call_id,),
                    legacy_reader=lambda: db.execute("SELECT kind,original_ref FROM " + TABLE +
                        " WHERE bot=? AND persona=? AND kind IN ('c4_prepared','c4_phase_prepared') "
                        "AND json_extract(payload_json,'$.call_id')=? LIMIT 2",
                        (*namespace.as_tuple, intent.call_id)).fetchall())
                if len(refs) != 1:
                    raise AuthorityUnavailable("model barrier lacks its unique signed C4 parent")
                original_kind, original_ref = refs[0]
                row = _read(db, issuer=self._issuer, namespace=namespace, kind=original_kind, ref=original_ref)
                if row is None: raise AuthorityUnavailable("actual signed C4 parent is absent")
                prepared = (decode_artifact_draft_original_v2(original_kind, row[0])
                    if original_kind == "c4_phase_prepared" else decode_artifact_draft_original_v1(original_kind, row[0]))
                if (prepared.call_id, prepared.job_id, prepared.digest) != (intent.call_id,intent.job_id,intent.binding_digest):
                    raise AuthorityUnavailable("actual signed C4 parent changed the model call identity")
                task = prepared.selector.task if original_kind == "c4_phase_prepared" else prepared.selector
                c02_operation_id = task.c02_operation_id
            elif kind == "d07.recall_need":
                if observation is not None and not observation.legacy:
                    from .model_reply_parentage_v3 import require_d07_parentage_v3
                    prepared = require_d07_parentage_v3(db,intent=intent,issuer=self._issuer)
                    if prepared is None or prepared.schema!="d07.ingress-recall-prepared.v1":
                        raise AuthorityUnavailable("model barrier lacks its exact signed Self C3 parent")
                else:
                    from ..runtime.d07_execution_v1 import D07IngressRecallPreparedV1, read_prepared_d07_execution_v1
                    prepared = read_prepared_d07_execution_v1(db, self._issuer, namespace, intent.job_id)
                    if (type(prepared) is not D07IngressRecallPreparedV1
                            or prepared.call_id != intent.call_id or prepared.digest != intent.binding_digest):
                        raise AuthorityUnavailable("model barrier lacks its exact signed Self C3 parent")
                c02_operation_id = prepared.c02_operation_id
            elif kind == "d07.concern":
                if observation is not None and not observation.legacy:
                    from ..runtime.foreground_call_plan_v1 import require_current_named_c3_parentage_v3
                    _,cycle,_ = require_current_named_c3_parentage_v3(db,namespace=namespace,
                        parentage=relationship_prepared,issuer=self._issuer)
                else:
                    from ..runtime.foreground_call_plan_v1 import require_current_named_c3_cycle_v2
                    _, cycle, _ = require_current_named_c3_cycle_v2(db, namespace=namespace,
                        prepared=relationship_prepared, issuer=self._issuer)
                c02_operation_id = cycle.c02_operation_id
            elif kind in {"natural_generation", "natural_review"}:
                from ..runtime.foreground_cycle_v1 import _read_reply_natural_metadata_v1
                stage = "generation" if kind == "natural_generation" else "review"
                table = "graph_natural_generation_preparations_v2" if stage == "generation" else "graph_natural_review_preparations_v2"
                from .model_reply_scope_observation_v3 import model_reply_scope_point_v3
                from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
                locator = model_reply_scope_point_v3(db, table=table,
                    columns=('parent_original_id', 'original_operation_id', 'job_id'),
                    key_columns=('job_id',), key=(intent.job_id,),
                    legacy_reader=lambda: db.execute(
                        "SELECT parent_original_id,original_operation_id,job_id FROM " + table +
                        " WHERE bot=? AND persona=? AND job_id=? LIMIT 2",
                        (*namespace.as_tuple, intent.job_id)).fetchone())
                rows = [] if locator is None else [locator]
                if locator is not None:
                    ids_for_parent = natural_job_ids_v2(namespace, locator[0], stage)
                    if (locator[2], locator[1], intent.call_id) != (
                            ids_for_parent[0], ids_for_parent[1], ids_for_parent[3]):
                        raise AuthorityUnavailable("model barrier natural locator changed its actual job/origin/call")
                if len(rows) != 1:
                    raise AuthorityUnavailable("model barrier lacks its unique sealed natural parent")
                c02_operation_id = rows[0][0]
                metadata = _read_reply_natural_metadata_v1(db, namespace, c02_operation_id, stage)
                if metadata is None or metadata[0].call_id != intent.call_id:
                    raise AuthorityUnavailable("model barrier natural parent is not its actual adopted seal")
            else:
                if observation is not None and not observation.legacy:
                    from .model_reply_parentage_v3 import require_appraisal_parent_v3
                    return require_appraisal_parent_v3(db,intent=intent,job=job,issuer=self._issuer)
                from ..runtime.d04_appraisal_driver_v3 import read_current_d04_appraisal_original_v3
                from ..runtime.d04_product_pipeline_v3 import ids
                from ..runtime.foreground_cycle_v1 import foreground_cycle_from_wire_v1
                from .model_reply_scope_observation_v3 import model_reply_scope_rows_v3
                parent_rows = model_reply_scope_rows_v3(db, kind='foreground_parents', parameters=(),
                    legacy_reader=lambda: db.execute("SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
                        "AND work_kind=? ORDER BY job_id LIMIT 129", (*namespace.as_tuple, WORK_KIND)).fetchall())
                rows = [(get_job(db, row[0]).continuation,) for row in parent_rows]
                if len(rows) > 128:
                    raise AuthorityUnavailable("model barrier foreground parent inventory exceeds its finite bound")
                parents = [foreground_cycle_from_wire_v1(row[0]).c02_operation_id for row in rows]
                matches = [parent for parent in parents if ids(namespace, parent)["call"] == intent.call_id]
                if len(matches) != 1:
                    raise AuthorityUnavailable("model barrier lacks its actual appraisal cycle parent")
                c02_operation_id = matches[0]
                original = read_current_d04_appraisal_original_v3(db, namespace, ids(namespace, c02_operation_id)["job"])
                if original is None or original.call_id != intent.call_id:
                    raise AuthorityUnavailable("model barrier appraisal original is absent")
            return c02_operation_id
        observation = None
        if model_service is not None:
            from .model_reply_scope_observation_v3 import observe_authority_model_reply_scope_v3
            observation = observe_authority_model_reply_scope_v3(
                self, model_service=model_service, credential=credential, subject=subject,
                holder=holder, intent=intent, expected_anchor=expected_anchor, permit=permit)
        if observation is not None and not observation.legacy:
            kind=observation.job_metadata[2]
            scoped_kinds={"artifact_draft_v1","natural_generation","natural_review","d04.appraisal","d07.recall_need","d07.concern"}
            if kind not in scoped_kinds:
                return None
            if not configured and kind in {"natural_generation","natural_review","d04.appraisal"}:
                return None
            if kind=="d07.concern":
                from .model_reply_parentage_v3 import require_d07_parentage_v3
                classified=observation.evaluate_v3(
                    lambda db:require_d07_parentage_v3(db,intent=intent,issuer=self._issuer))
                if classified is None or classified.schema not in {
                        "d07.relationship-prepared.v2","d07.method-growth-prepared.v2","d07.artifact-observation-prepared.v3"}:
                    return None
            if not configured:
                raise AuthorityUnavailable("auxiliary model has no actual installed foreground reply scope")
            service=observation.require_reply_service_v3()
            c02_operation_id = observation.evaluate_v3(read_parent)
        else:
            if service is not None:
                _,storage,_=service._storage()
                path=Path(storage["graph_path"])
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("BEGIN")
                c02_operation_id = read_parent(db)
        if c02_operation_id is None:
            return None
        return service.observe_actual_reply_scope_v1(c02_operation_id=c02_operation_id)

    def install_contact_policy_service_v1(self, service):
        from .d10_contact_policy_service_v1 import InstalledD10ContactPolicyServiceV1
        if type(service) is not InstalledD10ContactPolicyServiceV1 or self._contact_policy_service is not None:
            raise ValueError("actual contact policy service must be installed exactly once")
        self._contact_policy_service = service

    def install_d13_paid_reader_v3(self,reader):
        from .d13_authority_model_source_v3 import InstalledD13AuthorityModelReaderV3
        if (type(reader)is not InstalledD13AuthorityModelReaderV3 or self._d13_paid_reader_v3 is not None
                or reader.issuer is not self._issuer or reader.bundle is not self._artifact_draft_bundle
                or reader.owner_storage.graph_path!=self._path
                or reader.model_service._graph_verifier is not self
                or reader.worker_service._graph._d13_paid_reader_v3 is not None):
            raise ValueError("D13 Source reader requires its actual installed same-Graph model/result services")
        self._d13_paid_reader_v3=reader
        reader.worker_service._graph._d13_paid_reader_v3=reader

    def install_artifact_model_reader_v3(self,reader):
        from .artifact_model_graph_v3 import InstalledArtifactDraftModelGraphReaderV3
        if(type(reader)is not InstalledArtifactDraftModelGraphReaderV3 or self._artifact_model_reader_v3 is not None
                or reader.issuer is not self._issuer or reader.owner_storage.graph_path!=self._path
                or reader.bundle is not self._artifact_draft_bundle or reader.model_service._graph_verifier is not self):
            raise ValueError('Artifact model reader requires its actual installed same-Graph model service')
        self._artifact_model_reader_v3=reader

    def install_internal_life_reader_v2(self, reader):
        from .internal_life_model_graph_v2 import InstalledInternalLifeModelGraphReaderV2
        if (type(reader) is not InstalledInternalLifeModelGraphReaderV2
                or self._internal_life_reader_v2 is not None
                or reader.readers.issuer is not self._issuer
                or reader.owner_storage.graph_path != self._path):
            raise ValueError("actual same-Graph Life V2 reader must be installed exactly once")
        self._internal_life_reader_v2 = reader

    def install_life_numeric_reader_v1(self, reader):
        from .current_life_numeric_v1 import InstalledLifeNumericModelGraphReaderV1
        if (type(reader) is not InstalledLifeNumericModelGraphReaderV1
                or self._life_numeric_reader_v1 is not None
                or reader.readers.issuer is not self._issuer
                or reader.owner_storage.graph_path != self._path):
            raise ValueError("actual same-Graph numeric Life reader must be installed exactly once")
        self._life_numeric_reader_v1 = reader

    def __call__(self, intent: ModelEgressIntentV1) -> bool:
        # A graph row alone cannot authenticate the live Authority model fence
        # or the administrator-bound provider and executable token ceiling.
        return False

    def graph_facts_current(self, intent: ModelEgressIntentV1) -> bool:
        return self._current(intent, include_binding=False)

    def complete_graph_current(self, intent: ModelEgressIntentV1, *,
                               source_location=None, location_observation=None,
                               model_service=None, credential=None, subject=None, permit=None,
                               d07_source_material=None) -> bool:
        if d07_source_material is not None:
            from .d07_authority_model_source_read_v3 import PreparedD07AuthoritySourceMaterialV3
            if type(d07_source_material) is not PreparedD07AuthoritySourceMaterialV3:
                raise TypeError("D07 model policy requires its actual qualified Source material")
            work=d07_source_material.work
            reader=d07_source_material.reader
            if (reader.model_source_phase!="model_policy" or work.controller.verifier is not self
                    or work.controller.service is not model_service or work.request is not intent
                    or work.credential is not credential or work.subject!=subject or work.permit is not permit
                    or work.controller.location is not source_location
                    or reader.location_observation is not location_observation):
                raise AuthorityUnavailable("D07 policy Graph check crossed its actual retained model Source Work")
            d07_source_material.require_for_observer_v3(work)
            return True
        return self._current(intent, include_binding=True,
                             source_location=source_location, location_observation=location_observation,
                             model_service=model_service, credential=credential, subject=subject, permit=permit)

    def _current(self, intent: ModelEgressIntentV1, *, include_binding: bool,
                 source_location=None, location_observation=None,
                 model_service=None, credential=None, subject=None, permit=None) -> bool:
        if type(intent) is not ModelEgressIntentV1:
            return False
        try:
            if (source_location is None) != (location_observation is None):
                return False
            if source_location is not None:
                from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
                if (not include_binding
                        or type(source_location) is not InstalledCurrentSourceLocationQualifierV1):
                    return False
            if include_binding:
                if self._paired_clock is None:
                    return False
                reading = self._paired_clock()
                if type(reading) is not tuple or len(reading) != 2:
                    return False
                now, clock_epoch = reading
                if type(clock_epoch) is not str or not clock_epoch:
                    return False
            else:
                now, clock_epoch = self._clock(), None
            if type(now) not in (float, int) or not math.isfinite(now):
                return False
            from .current_authority_graph_read_v3 import (require_authority_graph_read_controller_v3,
                begin_authority_model_graph_read_work_v3,read_authority_graph_current_v3,finish_authority_graph_read_work_v3)
            controller=require_authority_graph_read_controller_v3(self)
            if controller.fences.core._runtime_storage_v3 is not None:
                if model_service is not controller.service or permit is None:return False
                work=begin_authority_model_graph_read_work_v3(self,model_service=model_service,credential=credential,
                    subject=subject,permit=permit,intent=intent,now_utc=now)
                try:
                    from .contact_model_work_v3 import read_contact_model_work_current_v3
                    return read_contact_model_work_current_v3(work,lambda db:self._current_graph_in_db_v3(db,intent,
                        now,clock_epoch,include_binding=include_binding,source_location=source_location,
                        location_observation=location_observation))
                finally:finish_authority_graph_read_work_v3(work)
            # UTC upper bound and epoch must come from one trusted sample.
            # The persisted monotonic deadline is only request identity.
            with closing(sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                from contextlib import ExitStack
                from ..runtime.natural_producer_qualification_v1 import (
                    natural_model_parent_original_v1, authority_natural_producer_context_v1)
                db.execute("BEGIN")
                try:
                    natural_parent = natural_model_parent_original_v1(db, intent=intent)
                finally:
                    db.execute("ROLLBACK")
                with ExitStack() as producer_context:
                    if natural_parent is not None:
                        producer_context.enter_context(authority_natural_producer_context_v1(
                            db, fences=(None if model_service is None else model_service._fences),
                            credential=credential, subject=subject, permit=permit,
                            namespace=natural_parent[0], parent_original_id=natural_parent[1],
                            model_service=model_service, model_intent=intent))
                    db.execute("BEGIN")
                    try:
                        return self._current_graph_in_db_v3(db,intent,now,clock_epoch,include_binding=include_binding,
                            source_location=source_location,location_observation=location_observation)
                    finally:
                        db.execute("ROLLBACK")
        except Exception:
            return False

    def _current_graph_in_db_v3(self,db,intent,now,clock_epoch,*,include_binding,source_location,location_observation):
        if source_location is not None:
            source_location.require_graph_snapshot_v1(
                db, location_observation, graph_db_path=self._path)
        from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
        actual_work = _authority_attachment_owner_v3(db)
        if actual_work is not None and actual_work.owner_model_work_kind == "d06.encode_internal_life_content":
            from .internal_life_model_source_read_v3 import require_internal_life_model_body_v3
            require_internal_life_model_body_v3(db, self._internal_life_reader_v2, intent)
        if actual_work is not None and actual_work.owner_model_work_kind=="artifact_draft_v1":
            if self._artifact_model_reader_v3 is None:return False
            body=self._artifact_model_reader_v3.read(db,intent,now,allow_unsealed_prepare=not include_binding)
            fresh_now,fresh_epoch=self._paired_clock() if include_binding else (self._clock(),clock_epoch)
            return fresh_epoch==clock_epoch and now<=fresh_now<body.deadline_utc
        job = get_job(db, intent.job_id)
        if (location_observation is not None
                and NamespaceId(job.bot_id, job.persona_id)
                    != location_observation.namespace_id):
            return False
        if job.work_kind == "artifact_draft_v1":
            if self._artifact_draft_bundle is None:
                return False
            selector_wire = job.continuation.get("selector")
            if (type(selector_wire) is dict
                    and selector_wire.get("schema") == "d11.artifact-draft-phase-selector.v2"):
                from ..host.authority_profile import AdminArtifactDraftPolicyV3, is_installed_artifact_draft_phase_slot_v2
                from ..host.artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4
                from ..model_broker.artifact_draft_v1 import (
                    ArtifactDraftPhaseSelectorV2, ArtifactDraftInputV2, ArtifactDraftInputV3, TEMPLATE_VERSION_V2,
                    artifact_draft_from_wire_v2, artifact_draft_input_from_wire_v2, artifact_draft_model_ids_v2,
                )
                from ..runtime.d11_life_preparation_v1 import _read
                from ..runtime.d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
                if (job.continuation.get("schema") != "d11.artifact-draft-phase-model-job.v2"
                        or type(self._artifact_draft_bundle.artifact_draft) not in {AdminArtifactDraftPolicyV3, AdminArtifactDraftPairedPolicyV4}):
                    return False
                selector = artifact_draft_from_wire_v2(selector_wire, ArtifactDraftPhaseSelectorV2)
                phase = self._artifact_draft_bundle.artifact_draft.phase_model_workflow
                if (not is_installed_artifact_draft_phase_slot_v2(self._artifact_draft_bundle, phase)
                        or phase.template_version != TEMPLATE_VERSION_V2):
                    return False
                ids = artifact_draft_model_ids_v2(selector)
                original = _read(db, issuer=self._issuer, namespace=selector.task.namespace,
                    kind="c4_phase_frozen", ref=ids["frozen"])
                root_original = _read(db, issuer=self._issuer, namespace=selector.task.namespace,
                    kind="draft_root_capability", ref=selector.task.root_registration_ref)
                if original is None or root_original is None:
                    return False
                frozen = artifact_draft_input_from_wire_v2(original[0])
                root = draft_from_wire_v1(root_original[0], DraftRootCapabilityV1)
                if (type(frozen) not in {ArtifactDraftInputV2, ArtifactDraftInputV3} or frozen.selector != selector
                        or type(root) is not DraftRootCapabilityV1
                        or root.registration_ref != selector.task.root_registration_ref
                        or root.source_ref != frozen.task_source_ref):
                    return False
                try:
                    from .d11_artifact_draft_model_v1 import read_current_artifact_draft_prepared_v2
                    from ..runtime.d11_artifact_draft_model_v1 import ArtifactDraftModelPreparedV2
                except ImportError:
                    return False
                prepared, current_job, verified_frozen = read_current_artifact_draft_prepared_v2(
                    db, intent, self._issuer, float(now), installed_bundle=self._artifact_draft_bundle,
                    allow_unsealed_prepare=not include_binding)
                if (type(prepared) is not ArtifactDraftModelPreparedV2 or current_job != job
                        or type(verified_frozen) not in {ArtifactDraftInputV2, ArtifactDraftInputV3} or verified_frozen != frozen):
                    return False
            else:
                from .d11_artifact_draft_model_v1 import read_current_artifact_draft_model_graph_v1
                prepared, _, _ = read_current_artifact_draft_model_graph_v1(db, intent, self._issuer, float(now),
                    installed_bundle=self._artifact_draft_bundle, allow_unsealed_prepare=not include_binding)
            if include_binding:
                fresh_now, fresh_epoch = self._paired_clock()
                if fresh_epoch != clock_epoch:
                    return False
            else:
                fresh_now = self._clock()
            return (type(fresh_now) in (int, float) and math.isfinite(fresh_now)
                and now <= fresh_now < datetime.fromisoformat(prepared.deadline_utc.replace("Z", "+00:00")).timestamp())
        if job.work_kind == "d06.encode_internal_life_content":
            if self._internal_life_reader_v2 is None:
                return False
            current = self._internal_life_reader_v2.read(db, intent, float(now))
            if include_binding:
                from ..runtime.internal_life_content_worker_v2 import read_life_worker_original_v2
                from .v2_model_egress_wire import to_wire
                call = read_life_worker_original_v2(db, namespace=current.prepared.namespace,
                    issuer=self._issuer, kind="call", job_id=job.job_id)
                if call is None or call["intent"] != to_wire(intent):
                    return False
            return True
        if job.work_kind == "d06.encode_internal_life_numeric":
            if self._life_numeric_reader_v1 is None:
                return False
            current = self._life_numeric_reader_v1.read(db, intent, float(now))
            if include_binding:
                from ..runtime.d11_life_preparation_v1 import _read
                from .v2_model_egress_wire import to_wire
                call = _read(db, namespace=current.prepared.namespace,
                    issuer=self._issuer, kind="numeric_call_v1", ref=job.job_id)
                if call is None or call[0]["intent"] != to_wire(intent):
                    return False
                fresh_reading = self._paired_clock()
                if (type(fresh_reading) is not tuple or len(fresh_reading) != 2
                        or fresh_reading[1] != clock_epoch):
                    return False
                fresh_now = fresh_reading[0]
            else:
                fresh_now = self._clock()
            # Source/Owner qualification can itself consume the remaining
            # lifetime. Recheck the same clock against verified originals;
            # never issue a new deadline or reuse the entry sample here.
            return (type(fresh_now) in (float, int) and math.isfinite(fresh_now)
                    and now <= fresh_now < current.valid_until_utc)
        if job.work_kind == "reply":
            return self._check_reply(
                db, intent, float(now), clock_epoch,
                include_binding=include_binding)
        if job.work_kind == "context_reply":
            return self._check_context_reply(
                db, intent, float(now),
                include_binding=include_binding)
        if job.work_kind == "natural_generation":
            return self._check_natural_stage(
                db, intent, float(now),
                stage="generation",
                include_binding=include_binding)
        if job.work_kind in {"contact_generation", "contact_review"}:
            from .contact_model_graph_v1 import read_current_contact_model_graph_v1
            if job.job_id.startswith("contact-model-job-v2:"):
                from .contact_model_graph_v2 import read_current_contact_model_graph_v2 as read_current_contact_model_graph_v1
            if self._contact_policy_service is None:
                return False
            read_current_contact_model_graph_v1(db, intent, self._issuer, float(now),
                allow_unsealed_prepare=not include_binding,
                contact_policy_service=self._contact_policy_service)
            return True
        if job.work_kind == "natural_review":
            return self._check_natural_stage(
                db, intent, float(now),
                stage="review",
                include_binding=include_binding)
        if job.work_kind == "d04.appraisal":
            from .current_d04_appraisal_v3 import read_current_d04_appraisal_graph_v3
            read_current_d04_appraisal_graph_v3(db, intent, self._issuer, float(now),
                allow_unsealed_prepare=not include_binding)
            return True
        if job.work_kind in {"d07.concern", "d07.reflection", "d07.simulation", "d07.recall_need"}:
            from .d07_current_execution_v1 import read_current_d07_execution_graph_v1
            prepared, current_job, _ = read_current_d07_execution_graph_v1(db, intent, self._issuer, float(now),
                allow_unsealed_prepare=not include_binding, installed_bundle=self._artifact_draft_bundle)
            if job.work_kind == "d07.recall_need":
                if include_binding:
                    fresh_now, fresh_epoch = self._paired_clock()
                    if fresh_epoch != clock_epoch:
                        return False
                else:
                    fresh_now = self._clock()
                return (type(fresh_now) in (int, float) and math.isfinite(fresh_now)
                    and now <= fresh_now < min(
                        datetime.fromisoformat(current_job.deadline_utc.replace("Z", "+00:00")).timestamp(),
                        datetime.fromisoformat(current_job.lease_expires_utc.replace("Z", "+00:00")).timestamp()))
            return True
        if job.work_kind == "d13.precompress.paid.v1":
            return self._check_d13_paid(
                db, intent, float(now),
                include_binding=include_binding)
        return (self._check(db, intent, float(now))
                and (not include_binding or self._check_binding(
                    db, intent, float(now), clock_epoch)))

    def _check_d13_paid(self, db: sqlite3.Connection,
                        intent: ModelEgressIntentV1, now: float, *,
                        include_binding: bool) -> bool:
        from .current_d13_paid_model_graph import read_current_d13_paid_model_graph
        current = read_current_d13_paid_model_graph(
            db, intent, self._issuer, now)
        binding = current.original.binding
        if (intent.operation_id != binding.original_operation_id
                or intent.acquire_operation_id != binding.original_operation_id
                or intent.binding_digest != binding.binding_digest
                or intent.call_id != binding.call_id):
            return False
        if not include_binding:
            return True
        # The immutable D13 paid original is not allowed to attest its own
        # request digest.  Admission requires W01's durable request copy.
        from ..model_broker.d13_precompression import (
            D13PrecompressionInstallationV1,
            d13_model_request_shape_valid_v1,
            freeze_d13_precompression_request_v1,
        )
        from .current_d13_paid_model_graph import _plan, _window, _canonical
        from .d13_authority_model_source_v3 import require_d13_current_frozen_v3
        frozen = require_d13_current_frozen_v3(db,current)
        actual_frozen=frozen is not None
        if frozen is None:
            frozen_data = _canonical(current.original.frozen_json)
            frozen = freeze_d13_precompression_request_v1(
                _window(frozen_data["window"]), _plan(frozen_data["plan"]),
                D13PrecompressionInstallationV1(**frozen_data["installation"]),
            )
        request = current.request
        guard = request.envelope.version_guard
        read_versions = {item.key.token: item.revision
                         for item in guard.read_versions}
        required = {ref.ref: ref.version for ref in (
            frozen.plan.scene_ref, frozen.plan.audience_ref,
            *frozen.plan.source_dependencies)}
        if (len(read_versions) != len(guard.read_versions)
                or not all(read_versions.get(ref) == version
                           for ref, version in required.items())
                or (guard.access_epoch, guard.delete_epoch) != (
                    intent.access_epoch, intent.delete_epoch)
                or any(item.namespace != current.original.namespace
                       or item.revision > intent.graph_epoch
                       for item in guard.query_epochs)):
            return False
        for token, revision in read_versions.items():
            if actual_frozen:
                from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
                head=_authority_attachment_owner_v3(db).heads.get(token)
                row=None if head is None else tuple(head[:2])
            else:
                row = _authority_point_v3(db,table='graph_atoms',columns=('revision', 'valid'),key_columns=('token',),key=tuple((token,)),legacy_reader=lambda: db.execute(
                    "SELECT revision,valid FROM graph_atoms WHERE token=?",
                    (token,),
                ).fetchone())
            if row != ((revision, 1) if revision else None):
                return False
        return ((actual_frozen or d13_model_request_shape_valid_v1(request, frozen))
                and request.digest == intent.request_digest
                and request.call_id == binding.call_id
                and request.identity.operation_id == binding.original_operation_id
                and request.identity.phase == "d13.precompress"
                and request.envelope.authority.issuer_domain == "d13"
                and request.envelope.authority.actor == intent.subject
                and request.envelope.authority.worker_fence == current.job.fence
                and request.envelope.authority.activation_generation ==
                    intent.authority_activation_generation
                and request.envelope.authority.namespace == current.original.namespace
                and request.envelope.authority.audience == (
                    current.window.conversation_ref,)
                and request.envelope.parent_budget_lease_ref == current.job.budget_ref
                and now < request.envelope.deadline_utc
                and request.envelope.deadline_utc <= min(
                    datetime.fromisoformat(current.job.deadline_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    datetime.fromisoformat(current.job.lease_expires_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    binding.expires_at_utc))

    @staticmethod
    def _reply_snapshot(db: sqlite3.Connection, namespace: NamespaceId,
                        source_ref: str, graph_epoch: int,
                        now: float):
        """Independently rebuild D07's full source closure in one graph read.

        The graph's saved guard is compared only after this read. It never
        supplies the source list, ancestry, access decisions or correction
        head absence used here.
        """
        from .current_authority_graph_read_v3 import require_authority_current_reply_attention_v3
        actual=require_authority_current_reply_attention_v3(db,namespace,source_ref=source_ref,now_utc=now,
            epoch=NamespaceEpoch(*namespace.as_tuple,graph_epoch))
        if actual is not None:return actual
        source_id = source_key_from_ref(source_ref, namespace)
        ingress = db.execute(
            "SELECT conversation_ref FROM graph_first_ingress_identity_v1 "
            "WHERE bot=? AND persona=? AND source_ref=?",
            namespace.as_tuple + (source_id,),
        ).fetchall()
        if len(ingress) != 1:
            raise ValueError("reply source has no unique original audience")
        focus_key = AtomKey(Owner("persona", *namespace.as_tuple),
                            "d07.focus.v1", namespace.persona_id)
        atoms = {}

        def load(key: AtomKey) -> GraphAtom:
            if key not in atoms:
                row = db.execute(
                    "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                    (key.token,),
                ).fetchone()
                atoms[key] = (GraphAtom(key, row[0], _canonical(row[1]), bool(row[2]))
                              if row else GraphAtom(key, 0, {}, False))
            return atoms[key]

        focus = load(focus_key)
        if not focus.valid:
            raise ValueError("reply focus absent")
        ticket_ref = focus.value["primary_ticket_ref"]
        ticket_key = AtomKey.from_token(ticket_ref)
        if ticket_key != attention_ticket_key(namespace, ticket_key.name):
            raise ValueError("reply ticket crosses namespace")
        ticket = load(ticket_key)
        pending = list(ticket.value["source_refs"])
        if not pending or len(pending) > 256:
            raise ValueError("reply ticket source roots invalid")
        seen = set()
        while pending:
            ref = pending.pop()
            if ref in seen:
                continue
            if len(seen) >= 256:
                raise ValueError("reply source closure exceeds bound")
            key = AtomKey.from_token(ref)
            if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
                raise ValueError("reply source crosses namespace")
            seen.add(ref)
            atom = load(key)
            load(access_key(*namespace.as_tuple, key.owner.subject))
            load(source_correction_head_key(namespace, key.owner.subject))
            record = SourceRecord.from_dict(atom.value)
            pending.extend(source_key(*namespace.as_tuple, parent).token
                           for parent in record.parent_source_ids)
        snapshot = GraphSnapshot(tuple(atoms.values()),
                                 (NamespaceEpoch(*namespace.as_tuple, graph_epoch),))
        qualified = read_qualified_focus_attention_ticket(
            snapshot, namespace, now=now, audience=ingress[0][0],
            purpose="expression")
        if (qualified is None
                or set(authority_reply_attention_versions_v3(snapshot)) != set(qualified.read_versions)):
            raise ValueError("reply D07 source closure is not qualified")
        return snapshot, qualified.attention

    def _check_reply(self, db: sqlite3.Connection, intent: ModelEgressIntentV1,
                     now: float, clock_epoch: str | None, *,
                     include_binding: bool) -> bool:
        """Read the original C02, D07, worker and request in one graph snapshot."""
        job = get_job(db, intent.job_id)
        namespace = NamespaceId(job.bot_id, job.persona_id)
        ns = namespace.as_tuple
        recovery = _authority_point_v3(db,table='graph_recovery_metadata_v2',columns=('schema', 'requirements_json', 'graph_revision'),key_columns=('bot', 'persona'),key=tuple(ns),legacy_reader=lambda: db.execute(
            "SELECT schema,requirements_json,graph_revision FROM "
            "graph_recovery_metadata_v2 WHERE bot=? AND persona=?", ns).fetchone())
        epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns).fetchone()
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns).fetchone()
        if (recovery is None or recovery[0] != "sylanne3.authority.v2"
                or recovery[2] != intent.graph_revision
                or epoch != (intent.graph_epoch,)
                or epochs != (intent.access_epoch, intent.delete_epoch)):
            return False
        requirements_data = _canonical(recovery[1])
        if (type(requirements_data) is not dict
                or requirements_data.get("namespace") != asdict(namespace)):
            return False
        requirements = SnapshotRequirementsV2(**{
            **requirements_data, "namespace": namespace})
        if (requirements.authority_id != intent.authority_id
                or requirements.authority_namespace != intent.namespace
                or requirements.activation_generation !=
                   intent.authority_activation_generation
                or requirements.revocation_epoch != intent.authority_revocation_epoch
                or requirements.deletion_seq != intent.authority_deletion_seq
                or requirements.execution_seq != intent.authority_execution_seq):
            return False
        if (job.work_kind != "reply" or job.effect_id is not None
                or job.phase != "running" or job.fence != intent.worker_fence
                or job.cancel_epoch != 0 or job.lease_holder != intent.subject
                or job.result_ref is not None or job.lease_expires_utc is None
                or not now < min(
                    datetime.fromisoformat(job.deadline_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    datetime.fromisoformat(job.lease_expires_utc.replace(
                        "Z", "+00:00")).timestamp())):
            return False
        from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
        actual_work=_authority_attachment_owner_v3(db)
        if actual_work is None:
            prep_rows = db.execute(
                "SELECT c02_operation_id,source_ref,c02_receipt_digest,source_id,"
                "source_revision,access_revision,attention_ticket_id,focus_revision,"
                "audience,state,acquire_operation_id,actor,worker_fence,call_id,"
                "model_request_digest,binding_digest,envelope_json,request_json "
                "FROM graph_post_c02_reply_model_preparations_v1 "
                "WHERE bot=? AND persona=? AND job_id=?", ns + (job.job_id,)).fetchall()
        else:
            locators=db.execute('SELECT c02_operation_id,source_ref FROM graph_post_c02_reply_model_preparations_v1 '
                'WHERE bot=? AND persona=? AND job_id=? LIMIT 2',ns+(job.job_id,)).fetchall()
            if len(locators)!=1:return False
            point=_authority_point_v3(db,table='graph_post_c02_reply_model_preparations_v1',
                columns=('c02_operation_id', 'source_ref', 'c02_receipt_digest', 'source_id', 'source_revision', 'access_revision', 'attention_ticket_id', 'focus_revision', 'audience', 'state', 'acquire_operation_id', 'actor', 'worker_fence', 'call_id', 'model_request_digest', 'binding_digest', 'envelope_json', 'request_json'),key_columns=('bot','persona','c02_operation_id','source_ref'),
                key=ns+tuple(locators[0]),legacy_reader=lambda:None)
            prep_rows=[]if point is None else[point]
        if len(prep_rows) != 1:
            return False
        row = prep_rows[0]
        c02_operation_id, source_ref = row[:2]
        snapshot, attention = self._reply_snapshot(
            db, namespace, source_ref, intent.graph_epoch, now)
        c02 = _authority_point_v3(db,table='graph_bundle_operations',columns=('digest', 'activity_id', 'effect_id', 'commit_seq', 'receipt_json'),key_columns=('bot', 'persona', 'operation_id'),key=tuple(ns + (c02_operation_id,)),legacy_reader=lambda: db.execute(
            "SELECT digest,activity_id,effect_id,commit_seq,receipt_json "
            "FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
            ns + (c02_operation_id,)).fetchone())
        if c02 is None:
            return False
        event = _authority_point_v3(db,table='graph_events',columns=('reads', 'revisions', 'epoch_revision'),key_columns=('bot', 'persona', 'session', 'event_id'),key=tuple(ns + (c02[1], c02_operation_id)),legacy_reader=lambda: db.execute(
            "SELECT reads,revisions,epoch_revision FROM graph_events "
            "WHERE bot=? AND persona=? AND session=? AND event_id=?",
            ns + (c02[1], c02_operation_id)).fetchone())
        if event is None:
            return False
        from ..runtime_contracts import CommitReceipt
        detail = _canonical(c02[4])
        c02_receipt = CommitReceipt(
            "committed", c02_operation_id, c02[0], c02[1], c02[2], c02[3],
            _authority_versions_v3(event[0]), _authority_versions_v3(event[1]),
            (NamespaceEpoch(*ns, event[2]),), tuple(detail["ledger_refs"]),
            tuple(detail["outbox_refs"]))
        inputs = read_current_reply_model_inputs_v1(
            db, self._issuer.resource_issuer, namespace, c02_receipt,
            source_ref, snapshot, attention)
        saved = read_saved_reply_job_v1(
            db, self._issuer.resource_issuer, namespace,
            c02_operation_id, source_ref)
        if saved is None or saved.job != job:
            return False
        quote = saved.quote
        acquire = _authority_point_v3(db,table='graph_post_c02_reply_model_acquires_v1',columns=('state', 'request_digest', 'attempt_id', 'anchor_json', 'graph_revision', 'graph_epoch'),key_columns=('bot', 'persona', 'acquire_operation_id', 'original_operation_id'),key=tuple(ns + (row[10], job.operation_id)),legacy_reader=lambda: db.execute(
            "SELECT state,request_digest,attempt_id,anchor_json,"
            "graph_revision,graph_epoch "
            "FROM graph_post_c02_reply_model_acquires_v1 "
            "WHERE bot=? AND persona=? AND acquire_operation_id=? "
            "AND original_operation_id=?",
            ns + (row[10], job.operation_id)).fetchone())
        if (row[2:10] != (
                canonical_digest(asdict(c02_receipt)),
                inputs.source.source.source_id, inputs.source.source_revision,
                inputs.source.access_revision, attention.ticket.ticket_id,
                attention.focus_version.revision, inputs.conversation_ref,
                "acquired")
                or row[11:13] != (intent.subject, intent.worker_fence)
                or row[10] != intent.operation_id
                or acquire is None or acquire[0] != "committed"
                or intent.source_refs != (inputs.source.source.source_id,)
                or intent.source_revisions != ((row[3], row[4]),)
                or intent.access_revisions != ((row[3], row[5]),)):
            return False
        acquired_anchor = RestoreAnchor(**_canonical(acquire[3]))
        job_key = runtime_job_key(*ns, job.activity_id, job.job_id)
        job_atom = _authority_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=tuple((job_key.token,)),legacy_reader=lambda: db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (job_key.token,)).fetchone())
        acquire_event = _authority_point_v3(db,table='graph_events',columns=('digest', 'reads', 'revisions', 'epoch_revision'),key_columns=('bot', 'persona', 'session', 'event_id'),key=tuple(ns + (job.activity_id, row[10])),legacy_reader=lambda: db.execute(
            "SELECT digest,reads,revisions,epoch_revision FROM graph_events "
            "WHERE bot=? AND persona=? AND session=? AND event_id=?",
            ns + (job.activity_id, row[10])).fetchone())
        if (not acquire[1] or not acquire[2]
                or acquired_anchor.authority_id != intent.authority_id
                or acquired_anchor.namespace != intent.namespace
                or acquired_anchor.activation_generation !=
                   intent.authority_activation_generation
                or acquired_anchor.revocation_epoch != intent.authority_revocation_epoch
                or acquired_anchor.deletion_seq != intent.authority_deletion_seq
                or acquired_anchor.execution_seq != intent.authority_execution_seq
                or acquire[4] >= intent.graph_revision
                or acquire[5] >= intent.graph_epoch
                or acquire_event is None
                or job_atom is None or job_atom[2] != 1
                or _canonical(job_atom[1]) != job_graph_write(job).value
                or job_atom[0] != saved.graph_job_revision
                or GraphVersion(job_key, job_atom[0]) not in
                   _authority_versions_v3(acquire_event[2])
                or acquire_event[3] != acquire[5] + 1
                or acquire_event[3] > intent.graph_epoch):
            return False
        grant = self._issuer.current_budget_grant(db, job.budget_ref)
        lease = get_budget_lease(db, job.budget_ref)
        require_budget_family_admissible(db, job.budget_ref)
        reservation = _authority_point_v3(db,table='runtime_budget_reservations',columns=('digest', 'ceiling_json', 'state'),key_columns=('lease_id', 'operation_id'),key=tuple((job.budget_ref, job.operation_id)),legacy_reader=lambda: db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (job.budget_ref, job.operation_id)).fetchone())
        ceiling = dict(intent.budget_ceiling)
        if (now >= quote.valid_until_utc or now >= grant.valid_until_utc
                or lease.state != "active" or (reservation is None or reservation[0]!=intent.budget_reservation_digest
                    or reservation[2]!='reserved' or not _authority_json_matches_v3(reservation[1],ceiling,legacy_serializer=canonical_json))
                or intent.budget_lease_id != job.budget_ref
                or intent.budget_reservation_operation_id != job.operation_id
                or saved.reservation_digest != intent.budget_reservation_digest
                or quote.ceiling != ceiling
                or quote.graph_job_ref != runtime_job_key(*ns, job.activity_id,
                                                          job.job_id).token
                or quote.effect_id is not None
                or quote.snapshot_ref != job.snapshot_ref
                or quote.resource_ref != job.resource_ref
                or job.work_kind not in grant.allowed_work_kinds
                or any(amount > grant.max_ceiling.get(key, 0)
                       for key, amount in ceiling.items())
                or any(lease.reserved.get(key, 0) < amount
                       for key, amount in ceiling.items())):
            return False
        if not include_binding:
            return True
        if (row[13] != intent.call_id or row[14] != intent.request_digest
                or row[15] != intent.binding_digest
                or row[16] is None or row[17] is None):
            return False
        envelope = reply_envelope_from_wire_v1(row[16])
        frozen = _canonical(row[17])
        c02_envelope=require_authority_c02_bundle_envelope_v3(db,namespace,c02_operation_id)
        if c02_envelope is None:
            archive = db.execute(
                "SELECT bundle_json FROM graph_first_ingress_c02_committed_seals_v2 "
                "WHERE bot=? AND persona=? AND operation_id=?",
                ns + (c02_operation_id,)).fetchone()
            c02_envelope=None if archive is None else c02_bundle_from_wire(archive[0]).envelope

        guard = envelope.version_guard
        guard_versions = db.execute(
            "SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
            "AND ref='current' AND kind IN ('scheme','operator','policy')",
            ns).fetchall()
        if (type(frozen) is not dict
                or frozen.get("envelope") != _canonical(canonical_serialize(asdict(envelope)))
                or c02_envelope is None
                or envelope.source_qualification !=
                   c02_envelope.source_qualification
                or guard.read_versions != authority_reply_attention_versions_v3(inputs.graph_snapshot)
                or guard.query_epochs != (QueryEpoch(namespace, "all", acquire[5]),)
                or (guard.access_epoch, guard.delete_epoch) != epochs
                or guard.source_grant_refs
                or guard.focus_lease_versions != (
                    VersionedRef(attention.ticket_version.key.token,
                                 attention.ticket_version.revision),)
                or guard.resource_lease_versions != (
                    VersionedRef(quote.quote_id, quote.version),)
                or dict(guard_versions) != {
                    "scheme": guard.scheme_version,
                    "operator": guard.operator_version,
                    "policy": guard.policy_version}
                or frozen.get("call_id") != intent.call_id
                or frozen.get("provider_id") != intent.provider_id
                or frozen.get("model_id") != intent.model_id
                or frozen.get("max_output_tokens") != intent.max_output_tokens
                or frozen.get("prompt_template_digest") != REPLY_TEMPLATE_DIGEST):
            return False
        request = issue_reply_request_v1(
            envelope, inputs.source, provider_id=frozen["provider_id"],
            model_id=frozen["model_id"],
            required_capabilities=frozenset(frozen["required_capabilities"]),
            privacy_tier=frozen["privacy_tier"],
            timeout_seconds=frozen["timeout_seconds"],
            max_output_tokens=frozen["max_output_tokens"])
        if (not _authority_json_matches_v3(row[17],reply_request_wire_v1(envelope,request),legacy_serializer=canonical_serialize)
                or request.digest != intent.request_digest
                or request.call_id != intent.call_id
                or reply_binding_digest_v1(job, inputs, row[10],
                                           request.call_id, request.digest)
                   != intent.binding_digest
                or envelope.identity.operation_id != row[10]
                or envelope.identity.activity_id != job.activity_id
                or envelope.identity.phase != "post_c02_reply_model"
                or envelope.authority.actor != intent.subject
                or envelope.authority.issuer_domain != "d11"
                or envelope.authority.worker_fence != intent.worker_fence
                or envelope.authority.namespace != namespace
                or envelope.authority.audience != (inputs.conversation_ref,)
                or envelope.authority.activation_generation !=
                   intent.authority_activation_generation
                or envelope.parent_budget_lease_ref != job.budget_ref
                or envelope.deadline_utc != min(
                    datetime.fromisoformat(job.deadline_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    datetime.fromisoformat(job.lease_expires_utc.replace(
                        "Z", "+00:00")).timestamp())
                or not now < envelope.deadline_utc):
            return False
        return True

    def _check_context_reply(self, db: sqlite3.Connection,
                             intent: ModelEgressIntentV1, now: float, *,
                             include_binding: bool) -> bool:
        """Reopen the original V2 call and its current D06/D07/budget read set."""
        from ..runtime.context_reply_job_v2 import (
            read_original_context_reply_call_binding_v2,
            read_original_context_reply_preparation_v2,
        )
        from .current_context_reply_source_verifier import (
            read_current_context_reply_sources_v1,
        )

        job = get_job(db, intent.job_id)
        namespace = NamespaceId(job.bot_id, job.persona_id)
        ns = namespace.as_tuple
        rows = db.execute(
            "SELECT c02_operation_id,source_ref FROM "
            "graph_context_reply_preparations_v2 WHERE bot=? AND persona=? "
            "AND job_id=?", ns + (job.job_id,),
        ).fetchall()
        if len(rows) != 1:
            return False
        c02_operation_id, source_ref = rows[0]
        saved = read_original_context_reply_preparation_v2(
            db, namespace, c02_operation_id, source_ref)
        if saved is None or saved.state != "acquired":
            return False
        seal, frozen = saved.seal, saved.frozen_request
        binding = read_original_context_reply_call_binding_v2(db, saved)
        if binding is None:
            return False
        request = binding.model_call_request
        c02_envelope=require_authority_c02_bundle_envelope_v3(db,namespace,c02_operation_id)
        if c02_envelope is None:
            archive = db.execute(
                "SELECT bundle_json FROM graph_first_ingress_c02_committed_seals_v2 "
                "WHERE bot=? AND persona=? AND operation_id=?",
                ns + (c02_operation_id,),
            ).fetchone()
            c02_envelope=None if archive is None else c02_bundle_from_wire(archive[0]).envelope

        original_source_id = AtomKey.from_token(source_ref).owner.subject
        ingress = db.execute(
            "SELECT conversation_ref FROM graph_first_ingress_identity_v1 "
            "WHERE bot=? AND persona=? AND source_ref=?",
            ns + (original_source_id,),
        ).fetchall()
        if (c02_envelope is None or len(ingress) != 1
                or c02_envelope
                   .source_qualification.source_refs != (source_ref,)
                or ingress[0][0] != frozen.input.conversation_ref
                or frozen.input.audience_ref.ref != ingress[0][0]):
            return False
        recovery = _authority_point_v3(db,table='graph_recovery_metadata_v2',columns=('schema', 'requirements_json', 'graph_revision'),key_columns=('bot', 'persona'),key=tuple(ns),legacy_reader=lambda: db.execute(
            "SELECT schema,requirements_json,graph_revision FROM "
            "graph_recovery_metadata_v2 WHERE bot=? AND persona=?", ns,
        ).fetchone())
        epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns,
        ).fetchone()
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns,
        ).fetchone()
        if (recovery is None or recovery[0] != "sylanne3.authority.v2"
                or recovery[2] != intent.graph_revision
                or epoch != (intent.graph_epoch,)
                or epochs != (intent.access_epoch, intent.delete_epoch)):
            return False
        requirement_data = _canonical(recovery[1])
        requirements = SnapshotRequirementsV2(**{
            **requirement_data, "namespace": namespace})
        if (requirement_data.get("namespace") != asdict(namespace)
                or requirements.authority_id != intent.authority_id
                or requirements.authority_namespace != intent.namespace
                or requirements.activation_generation !=
                   intent.authority_activation_generation
                or requirements.revocation_epoch != intent.authority_revocation_epoch
                or requirements.deletion_seq != intent.authority_deletion_seq
                or requirements.execution_seq != intent.authority_execution_seq
                or frozen.input.activation_generation !=
                   requirements.activation_generation):
            return False
        if (job.work_kind != "context_reply" or job.phase != "running"
                or job.effect_id is not None or job.cancel_epoch != 0
                or job.result_ref is not None or job.fence != intent.worker_fence
                or job.fence != binding.worker_fence
                or job.lease_holder != intent.subject
                or job.operation_id != seal.original_operation_id
                or job.lease_expires_utc is None
                or not now < min(
                    datetime.fromisoformat(job.deadline_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    datetime.fromisoformat(job.lease_expires_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    frozen.input.expires_at_utc)):
            return False
        snapshot, attention = self._reply_snapshot(
            db, namespace, source_ref, intent.graph_epoch, now)
        sources = read_current_context_reply_sources_v1(
            db, frozen, now_utc=now)
        if (sources is None
                or set(authority_reply_attention_versions_v3(snapshot)) != set(saved.read_versions)
                or not set(sources.read_versions) <= set(authority_reply_attention_versions_v3(snapshot))
                or set(part.ref.ref for part in frozen.input.evidence)
                   != set(attention.ticket.source_refs)
                or source_ref not in attention.ticket.source_refs
                or (saved.access_epoch, saved.delete_epoch) != epochs):
            return False
        original = snapshot.get(AtomKey.from_token(source_ref))
        if (original is None or not original.valid
                or frozen.input.question.text !=
                   SourceRecord.from_dict(original.value).text):
            return False
        source_versions = []
        access_versions = []
        for part in frozen.input.evidence:
            atom = snapshot.get(AtomKey.from_token(part.ref.ref))
            record = SourceRecord.from_dict(atom.value)
            if part.access_ref is None:
                return False
            source_versions.append((record.source_id, part.ref.version))
            access_versions.append((record.source_id, part.access_ref.version))
        if (intent.source_refs != tuple(source_id for source_id, _ in source_versions)
                or intent.source_revisions != tuple(source_versions)
                or intent.access_revisions != tuple(access_versions)):
            return False
        acquire = _authority_point_v3(db,table='graph_context_reply_acquires_v2',columns=('state', 'request_digest', 'anchor_json', 'graph_revision', 'graph_epoch'),key_columns=('bot', 'persona', 'acquire_operation_id'),key=tuple(ns + (seal.acquire_operation_id,)),legacy_reader=lambda: db.execute(
            "SELECT state,request_digest,anchor_json,graph_revision,graph_epoch "
            "FROM graph_context_reply_acquires_v2 WHERE bot=? AND persona=? "
            "AND acquire_operation_id=?", ns + (seal.acquire_operation_id,),
        ).fetchone())
        job_key = runtime_job_key(*ns, job.activity_id, job.job_id)
        job_atom = _authority_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=tuple((job_key.token,)),legacy_reader=lambda: db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (job_key.token,),
        ).fetchone())
        if (acquire is None or acquire[0] != "committed"
                or not acquire[1] or not acquire[2]
                or acquire[3] >= intent.graph_revision
                or acquire[4] >= intent.graph_epoch
                or job_atom is None or job_atom[2] != 1
                or _canonical(job_atom[1]) != job_graph_write(job).value):
            return False
        acquire_event = _authority_point_v3(db,table='graph_events',columns=('revisions', 'epoch_revision'),key_columns=('bot', 'persona', 'session', 'event_id'),key=tuple(ns + (job.activity_id, seal.acquire_operation_id)),legacy_reader=lambda: db.execute(
            "SELECT revisions,epoch_revision FROM graph_events "
            "WHERE bot=? AND persona=? AND session=? AND event_id=?",
            ns + (job.activity_id, seal.acquire_operation_id),
        ).fetchone())
        if (acquire_event is None
                or GraphVersion(job_key, job_atom[0]) not in
                   _authority_versions_v3(acquire_event[0])
                or acquire_event[1] != acquire[4] + 1
                or acquire_event[1] > intent.graph_epoch):
            return False
        anchor = RestoreAnchor(**_canonical(acquire[2]))
        if (anchor.authority_id != intent.authority_id
                or anchor.namespace != intent.namespace
                or anchor.activation_generation !=
                   intent.authority_activation_generation
                or anchor.revocation_epoch != intent.authority_revocation_epoch
                or anchor.deletion_seq != intent.authority_deletion_seq
                or anchor.execution_seq != intent.authority_execution_seq):
            return False
        grant = self._issuer.current_budget_grant(db, job.budget_ref)
        lease = get_budget_lease(db, job.budget_ref)
        require_budget_family_admissible(db, job.budget_ref)
        quote_id = "context-reply-quote:" + seal.job_id.split(":")[-1]
        quote = self._issuer.resource_issuer.original_signed_quote(
            db, quote_id, 1)
        ceiling = dict(intent.budget_ceiling)
        reservation = _authority_point_v3(db,table='runtime_budget_reservations',columns=('digest', 'ceiling_json', 'state'),key_columns=('lease_id', 'operation_id'),key=tuple((job.budget_ref, job.operation_id)),legacy_reader=lambda: db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (job.budget_ref, job.operation_id),
        ).fetchone())
        if (now >= quote.valid_until_utc or now >= grant.valid_until_utc
                or lease.state != "active" or (reservation is None or reservation[0]!=intent.budget_reservation_digest
                    or reservation[2]!='reserved' or not _authority_json_matches_v3(reservation[1],ceiling,legacy_serializer=canonical_json))
                or intent.budget_lease_id != job.budget_ref
                or intent.budget_reservation_operation_id != job.operation_id
                or quote.ceiling != ceiling or quote.work_kind != "context_reply"
                or quote.graph_job_ref != job_key.token
                or quote.effect_id is not None
                or quote.snapshot_ref != job.snapshot_ref
                or quote.resource_ref != job.resource_ref
                or job.work_kind not in grant.allowed_work_kinds
                or ceiling.get("output_tokens", 0) < intent.max_output_tokens
                or any(amount > grant.max_ceiling.get(key, 0)
                       or lease.reserved.get(key, 0) < amount
                       for key, amount in ceiling.items())):
            return False
        # The original typed call is part of both the proposed intent and
        # final dispatch check. A graph-only preflight cannot accept a draft
        # with somebody else's call identity.
        guard = request.envelope.version_guard
        guard_versions = db.execute(
            "SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
            "AND ref='current' AND kind IN ('scheme','operator','policy')",
            ns,
        ).fetchall()
        if (intent.operation_id != seal.acquire_operation_id
                or intent.acquire_operation_id != seal.acquire_operation_id
                or intent.call_id != seal.call_id
                or intent.request_digest != binding.model_call_request_digest
                or intent.binding_digest != canonical_digest({
                    "original_seal_digest": canonical_digest(asdict(seal)),
                    "model_call_request_digest": request.digest,
                    "worker_fence": job.fence,
                })
                or intent.provider_id != request.provider_id
                or intent.model_id != request.model_id
                or intent.provider_config_digest != seal.provider_config_digest
                or intent.max_output_tokens != request.max_output_tokens
                or request.identity.phase != "context_reply"
                or request.identity.operation_id != seal.acquire_operation_id
                or request.envelope.authority.actor != intent.subject
                or request.envelope.authority.issuer_domain != "d11"
                or request.envelope.authority.worker_fence != job.fence
                or request.envelope.authority.namespace != namespace
                or request.envelope.authority.audience != (
                    frozen.input.conversation_ref,)
                or request.envelope.authority.purpose != "proposal"
                or request.envelope.parent_budget_lease_ref != job.budget_ref
                or guard.read_versions != saved.read_versions + (
                    GraphVersion(job_key, job_atom[0]),)
                or guard.query_epochs != (QueryEpoch(
                    namespace, saved.query_epoch.scope_ref,
                    intent.graph_epoch),)
                or (guard.access_epoch, guard.delete_epoch) != epochs
                or guard.source_grant_refs or guard.focus_lease_versions
                or guard.resource_lease_versions
                or dict(guard_versions) != {
                    "scheme": guard.scheme_version,
                    "operator": guard.operator_version,
                    "policy": guard.policy_version}
                or not now < request.envelope.deadline_utc):
            return False
        return True

    def _check_natural_stage(self, db: sqlite3.Connection,
                             intent: ModelEgressIntentV1, now: float, *,
                             stage: str, include_binding: bool) -> bool:
        """Reopen one sealed natural stage, private scope and current grant."""
        from ..runtime.natural_generation_issue_v2 import (
            read_original_scoped_query_proof_v2,
        )
        from ..runtime.natural_reply_job_v2 import (
            read_original_call_binding, read_original_preparation,
        )
        from ..runtime.natural_scoped_query_proof_v2 import (
            assert_natural_scoped_query_current_v2,
        )

        job = get_job(db, intent.job_id)
        namespace = NamespaceId(job.bot_id, job.persona_id)
        ns = namespace.as_tuple
        if stage not in {"generation", "review"}:
            return False
        table = ("graph_natural_generation_preparations_v2" if
                 stage == "generation" else "graph_natural_review_preparations_v2")
        rows = db.execute(
            f"SELECT parent_original_id FROM {table} "
            "WHERE bot=? AND persona=? AND job_id=?", ns + (job.job_id,),
        ).fetchall()
        if len(rows) != 1:
            return False
        saved = read_original_preparation(db, namespace, rows[0][0], stage)
        if saved is None or saved.state != "acquired":
            return False
        generation = (saved if stage == "generation" else
                      read_original_preparation(
                          db, namespace, rows[0][0], "generation"))
        if generation is None or (stage == "review" and
                                  generation.state != "terminal"):
            return False
        seal, frozen = saved.seal, generation.frozen
        from ..model_broker.natural_reply_history_v4 import FrozenNaturalReplyRequestV4
        from ..model_broker.natural_reply_history_v6 import FrozenNaturalReplyRequestV6
        from ..model_broker.natural_reply_history_v7 import FrozenNaturalReplyRequestV7
        if type(frozen) is FrozenNaturalReplyRequestV7:
            from .d13_natural_frame_verifier_v7 import InstalledAuthorityD13NaturalFrameVerifierV7
            if (type(self._natural_history) is not InstalledAuthorityD13NaturalFrameVerifierV7
                    or self._natural_history.current_v7(db,frozen=frozen,
                        parent_original_id=generation.seal.c02_operation_id,now_utc=now) is None):
                return False
        elif type(frozen) is FrozenNaturalReplyRequestV6:
            from .d13_natural_frame_verifier_v6 import InstalledAuthorityD13NaturalFrameVerifierV6
            if (type(self._natural_history) is not InstalledAuthorityD13NaturalFrameVerifierV6
                    or self._natural_history.current_v6(db,frozen=frozen,
                        parent_original_id=generation.seal.c02_operation_id,now_utc=now) is None):
                return False
        elif type(frozen) is FrozenNaturalReplyRequestV4:
            from .d13_natural_frame_verifier_v1 import InstalledAuthorityD13NaturalFrameVerifierV1
            if (type(self._natural_history) is not InstalledAuthorityD13NaturalFrameVerifierV1
                    or self._natural_history.current_v4(db, frozen=frozen,
                        parent_original_id=generation.seal.c02_operation_id, now_utc=now) is None):
                return False
        binding = read_original_call_binding(db, saved)
        if binding is None:
            return False
        request = binding.request
        proof = read_original_scoped_query_proof_v2(db, generation)
        from ..runtime.natural_scoped_query_proof_v2 import assert_current_natural_producer_scope_v1
        producer_reads = assert_current_natural_producer_scope_v1(db, proof, frozen, now_utc=now)
        if producer_reads:
            from ..domains.d08.natural_plan import decode_natural_plan_v2
            plan = frozen.input.plan
            head = _authority_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=tuple((plan.plan_ref.ref,)),legacy_reader=lambda: db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                              (plan.plan_ref.ref,)).fetchone())
            if head is None or head[0] != plan.plan_ref.version or head[2] != 1:
                return False
            adopted = decode_natural_plan_v2(_authority_json_v3(head[1]))
            if (adopted.c02_operation_id != generation.seal.c02_operation_id
                    or adopted.qualified_units_digest != canonical_digest(plan.units)
                    or any(row not in adopted.qualified_read_versions for row in producer_reads)):
                return False
        recovery = _authority_point_v3(db,table='graph_recovery_metadata_v2',columns=('schema', 'requirements_json', 'graph_revision'),key_columns=('bot', 'persona'),key=tuple(ns),legacy_reader=lambda: db.execute(
            "SELECT schema,requirements_json,graph_revision FROM "
            "graph_recovery_metadata_v2 WHERE bot=? AND persona=?", ns,
        ).fetchone())
        epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns,
        ).fetchone()
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns,
        ).fetchone()
        if (recovery is None or recovery[0] != "sylanne3.authority.v2"
                or recovery[2] < intent.graph_revision
                or epoch is None or epoch[0] < intent.graph_epoch
                or epochs != (intent.access_epoch, intent.delete_epoch)
                or epochs != (saved.access_epoch, saved.deletion_epoch)):
            return False
        requirement_data = _canonical(recovery[1])
        requirements = SnapshotRequirementsV2(**{
            **requirement_data, "namespace": namespace})
        if (requirement_data.get("namespace") != asdict(namespace)
                or (requirements.authority_id,
                    requirements.authority_namespace,
                    requirements.activation_generation,
                    requirements.revocation_epoch,
                    requirements.deletion_seq,
                    requirements.execution_seq) !=
                   (intent.authority_id, intent.namespace,
                    intent.authority_activation_generation,
                    intent.authority_revocation_epoch,
                    intent.authority_deletion_seq,
                    intent.authority_execution_seq)):
            return False
        if (job.work_kind != "natural_" + stage or job.phase != "running"
                or job.effect_id is not None or job.cancel_epoch != 0
                or job.result_ref is not None or job.fence != intent.worker_fence
                or job.fence != binding.worker_fence
                or job.lease_holder != intent.subject
                or job.operation_id != seal.original_operation_id
                or job.lease_expires_utc is None
                or not now < min(
                    datetime.fromisoformat(job.deadline_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    datetime.fromisoformat(job.lease_expires_utc.replace(
                        "Z", "+00:00")).timestamp(),
                    frozen.input.expires_at_utc,
                    frozen.input.plan.valid_until_utc)):
            return False
        job_key = runtime_job_key(*ns, job.activity_id, job.job_id)
        job_atom = _authority_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=tuple((job_key.token,)),legacy_reader=lambda: db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (job_key.token,),
        ).fetchone())
        if (job_atom is None or job_atom[2] != 1 or job_atom[0] != 2
                or _canonical(job_atom[1]) != job_graph_write(job).value):
            return False
        if (intent.operation_id != seal.acquire_operation_id
                or intent.acquire_operation_id != seal.acquire_operation_id
                or intent.call_id != seal.call_id
                or intent.job_id != seal.job_id
                or intent.request_digest != binding.typed_request_digest
                or intent.binding_digest != canonical_digest({
                    "original_seal_digest": canonical_digest(asdict(seal)),
                    "model_call_request_digest": request.digest,
                    "worker_fence": job.fence,
                })
                or intent.provider_id != request.provider_id
                or intent.model_id != request.model_id
                or intent.provider_config_digest != seal.provider_config_digest
                or intent.max_output_tokens != request.max_output_tokens
                or request.identity.phase != "natural_" + stage
                or request.identity.operation_id != seal.acquire_operation_id
                or request.call_id != seal.call_id
                or request.envelope.authority.actor != intent.subject
                or request.envelope.authority.issuer_domain != "d11"
                or request.envelope.authority.worker_fence != job.fence
                or request.envelope.authority.namespace != namespace
                or request.envelope.authority.audience != (
                    frozen.input.plan.audience_id,)
                or request.envelope.authority.purpose != "proposal"
                or request.envelope.parent_budget_lease_ref != job.budget_ref):
            return False
        guard = request.envelope.version_guard
        guard_versions = db.execute(
            "SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
            "AND ref='current' AND kind IN ('scheme','operator','policy')",
            ns,
        ).fetchall()
        if (tuple(item.scope_ref for item in guard.query_epochs) != (
                "all", "d03.role_binding", "d05.boundary")
                or any(item.namespace != namespace
                       or not saved.graph_epoch < item.revision <= intent.graph_epoch
                       for item in guard.query_epochs)
                or (guard.access_epoch, guard.delete_epoch) != epochs
                or dict(guard_versions) != {
                    "scheme": guard.scheme_version,
                    "operator": guard.operator_version,
                    "policy": guard.policy_version}
                or guard.source_grant_refs
                or not now < request.envelope.deadline_utc):
            return False
        read_versions = {row.key.token: row.revision
                         for row in guard.read_versions}
        if (len(read_versions) != len(guard.read_versions)
                or read_versions.get(job_key.token) != job_atom[0]
                or any(read_versions.get(item.token) != item.revision
                       for item in (*proof.account_matches, *proof.role_matches,
                                    *proof.boundary_matches, *proof.d06_closure))):
            return False
        if any(read_versions.get(row.key.token) != row.revision for row in producer_reads):
            return False
        for token, revision in read_versions.items():
            row = _authority_point_v3(db,table='graph_atoms',columns=('revision',),key_columns=('token',),key=tuple((token,)),legacy_reader=lambda: db.execute(
                "SELECT revision FROM graph_atoms WHERE token=?", (token,),
            ).fetchone())
            if (row[0] if row else 0) != revision:
                return False
        source = _authority_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=tuple((generation.seal.source_ref,)),legacy_reader=lambda: db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (generation.seal.source_ref,),
        ).fetchone())
        source_id = AtomKey.from_token(generation.seal.source_ref).owner.subject
        access = _authority_point_v3(db,table='graph_atoms',columns=('revision', 'valid'),key_columns=('token',),key=tuple((access_key(*ns, source_id).token,)),legacy_reader=lambda: db.execute(
            "SELECT revision,valid FROM graph_atoms WHERE token=?",
            (access_key(*ns, source_id).token,),
        ).fetchone())
        if (source is None or source[2] != 1 or access is None or access[1] != 1
                or intent.source_refs != (source_id,)
                or intent.source_revisions != ((source_id, source[0]),)
                or intent.access_revisions != ((source_id, access[0]),)):
            return False
        quote_ref = job.operator_versions["resource_quote"]
        quote_id, quote_version = quote_ref.rsplit(":", 1)
        quote = self._issuer.resource_issuer.original_signed_quote(
            db, quote_id, int(quote_version))
        grant = self._issuer.current_budget_grant(db, job.budget_ref)
        lease = get_budget_lease(db, job.budget_ref)
        require_budget_family_admissible(db, job.budget_ref)
        ceiling = dict(intent.budget_ceiling)
        reservation = _authority_point_v3(db,table='runtime_budget_reservations',columns=('digest', 'ceiling_json', 'state'),key_columns=('lease_id', 'operation_id'),key=tuple((job.budget_ref, seal.reservation_operation_id)),legacy_reader=lambda: db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (job.budget_ref, seal.reservation_operation_id),
        ).fetchone())
        if (now >= quote.valid_until_utc or now >= grant.valid_until_utc
                or lease.state != "active" or (reservation is None or reservation[0]!=intent.budget_reservation_digest
                    or reservation[2]!='reserved' or not _authority_json_matches_v3(reservation[1],ceiling,legacy_serializer=canonical_json))
                or intent.budget_lease_id != job.budget_ref
                or intent.budget_reservation_operation_id !=
                   seal.reservation_operation_id
                or quote.ceiling != ceiling or quote.work_kind !=
                   "natural_" + stage
                or quote.operation_id != seal.reservation_operation_id
                or quote.graph_job_ref != job_key.token
                or quote.effect_id is not None
                or quote.snapshot_ref != job.snapshot_ref
                or quote.resource_ref != job.resource_ref
                or job.work_kind not in grant.allowed_work_kinds
                or ceiling.get("output_tokens", 0) < intent.max_output_tokens
                or any(amount > grant.max_ceiling.get(key, 0)
                       or lease.reserved.get(key, 0) < amount
                       for key, amount in ceiling.items())):
            return False
        return True

    def _check_binding(self, db: sqlite3.Connection, intent: ModelEgressIntentV1,
                       now: float, clock_epoch: str) -> bool:
        job = get_job(db, intent.job_id)
        namespace = NamespaceId(job.bot_id, job.persona_id)
        binding = load_binding(db, namespace, intent.job_id)
        if binding is None:
            return False
        frozen = binding.request
        if frozen.get("schema") not in {
                "sylanne.first-ingress-encoding-call.v2",
                "sylanne.first-ingress-encoding-call.v3"}:
            return False
        acquire = db.execute(
            "SELECT i.acquire_operation_id,i.job_id,i.original_operation_id,"
            "i.actor,i.encoding_binding_json,r.job_json "
            "FROM graph_job_acquire_intents_v2 AS i "
            "JOIN graph_job_acquire_receipts_v2 AS r ON "
            "r.bot=i.bot AND r.persona=i.persona "
            "AND r.acquire_operation_id=i.acquire_operation_id "
            "WHERE i.bot=? AND i.persona=? AND i.job_id=?",
            namespace.as_tuple + (job.job_id,),
        ).fetchall()
        if (len(acquire) != 1 or acquire[0][1:4] != (
                job.job_id, job.operation_id, job.lease_holder)
                or acquire[0][4] != binding_to_json(binding)
                or _canonical(acquire[0][5]) != asdict(job)):
            return False
        acquire_operation_id = acquire[0][0]
        source_id = intent.source_refs[0]
        source_token = source_key(*namespace.as_tuple, source_id).token
        source_row = _authority_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=tuple((source_token,)),legacy_reader=lambda: db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (source_token,),
        ).fetchone())
        if source_row is None or source_row[2] != 1:
            return False
        source = SourceRecord.from_dict(_canonical(source_row[1]))
        access_key_value = access_key(*namespace.as_tuple, source_id)
        access_row = _authority_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=tuple((access_key_value.token,)),legacy_reader=lambda: db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (access_key_value.token,),
        ).fetchone())
        if (access_row is None or access_row[2] != 1
                or access_row[0] != binding.access_revision):
            return False
        access = _canonical(access_row[1])
        validate_access(access)
        if access["status"] != "active" or access["source_id"] != source_id:
            return False
        from ..model_broker.first_ingress_encoding import ENCODING_TEMPLATE_VERSIONS
        payload, template_digest = build_first_ingress_encoding_payload(source,template_version=frozen["prompt_template_version"])
        envelope = frozen["envelope"]
        request_authority = envelope["authority"]
        purpose = request_authority["purpose"]
        audience = request_authority["audience"]
        request_deadline = envelope["deadline_utc"]
        if (type(purpose) is not str or type(audience) is not list
                or not audience or any(type(item) is not str for item in audience)
                or type(request_deadline) not in (int, float)
                or not now < request_deadline
                <= min(datetime.fromisoformat(job.deadline_utc.replace(
                    "Z", "+00:00")).timestamp(),
                       datetime.fromisoformat(job.lease_expires_utc.replace(
                           "Z", "+00:00")).timestamp())
                or purpose not in source.purposes
                or purpose not in access["purposes"]
                or not set(audience).issubset(source.audiences)
                or not set(audience).issubset(access["audiences"])):
            return False
        # Only the identically named reservation dimension is a proof for
        # max_completion_tokens. cpu_ms or currency cannot be converted here.
        output_token_limit = dict(intent.budget_ceiling).get("output_tokens")
        if (type(output_token_limit) is not int
                or output_token_limit < intent.max_output_tokens):
            return False
        versions = db.execute(
            "SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
            "AND kind IN ('scheme','operator','policy') AND ref='current'",
            namespace.as_tuple,
        ).fetchall()
        if len(versions) != 3 or len({kind for kind, _ in versions}) != 3:
            return False
        current = dict(versions)
        provisions = db.execute(
            "SELECT receipt_json FROM graph_namespace_provisioning_v2 "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchall()
        if len(provisions) != 1:
            return False
        catalogue = _canonical(provisions[0][0]).get("catalogue_hash")
        baseline_version = ()
        if frozen["schema"] == "sylanne.first-ingress-encoding-call.v3":
            baseline = CommittedEncodingBaselineV1(**frozen["baseline"])
            acquire_stamp = _authority_point_v3(db,table='graph_job_acquire_intents_v2',columns=('graph_revision', 'graph_epoch'),key_columns=('bot', 'persona', 'acquire_operation_id'),key=tuple(namespace.as_tuple + (acquire_operation_id,)),legacy_reader=lambda: db.execute(
                "SELECT graph_revision,graph_epoch FROM "
                "graph_job_acquire_intents_v2 WHERE bot=? AND persona=? "
                "AND acquire_operation_id=?",
                namespace.as_tuple + (acquire_operation_id,),
            ).fetchone())
            if acquire_stamp is None:
                return False
            recovery = _authority_point_v3(db,table='graph_recovery_metadata_v2',columns=('requirements_json', 'graph_revision'),key_columns=('bot', 'persona'),key=tuple(namespace.as_tuple),legacy_reader=lambda: db.execute(
                "SELECT requirements_json,graph_revision FROM "
                "graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone())
            epoch = db.execute(
                "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                namespace.as_tuple,
            ).fetchone()
            if recovery is None or epoch is None:
                return False
            requirements_data = _canonical(recovery[0])
            requirements = SnapshotRequirementsV2(**{
                **requirements_data, "namespace": namespace})
            if not committed_baseline_current(
                    db, namespace=namespace, baseline=baseline,
                    source_id=source_id, requirements=requirements,
                    current_graph_revision=recovery[1],
                    current_graph_epoch=epoch[0],
                    acquire_graph_revision=acquire_stamp[0],
                    acquire_graph_epoch=acquire_stamp[1],
                    issuer=self._issuer):
                return False
            baseline_version = (
                GraphVersion(AtomKey.from_token(baseline.baseline_ref),
                             baseline.baseline_revision),)
        expected_guard = VersionGuard(
            (GraphVersion(source_key(*namespace.as_tuple, source_id), source_row[0]),
             GraphVersion(access_key_value, access_row[0])) + baseline_version, (),
            intent.access_epoch, intent.delete_epoch, catalogue,
            current["scheme"], current["operator"], current["policy"],
            (), (), (),
        )
        original = _authority_point_v3(db,table='runtime_ingress_issuance',columns=('source_qualification_json', 'policy_json'),key_columns=('bot', 'persona', 'operation_id'),key=tuple(namespace.as_tuple + (job.operation_id,)),legacy_reader=lambda: db.execute(
            "SELECT source_qualification_json,policy_json "
            "FROM runtime_ingress_issuance "
            "WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (job.operation_id,),
        ).fetchone())
        if original is None or original[0] is None:
            return False
        issue_policy = _canonical(original[1])
        qualification_data = _canonical(original[0])
        qualification_data["source_refs"] = tuple(qualification_data["source_refs"])
        qualification = SourceQualification(**qualification_data)
        if (not _authority_json_matches_v3(original[0],asdict(qualification),legacy_serializer=canonical_serialize)
                or qualification.source_refs != (source_token,)
                or envelope["version_guard"]
                != _authority_json_v3(canonical_serialize(expected_guard))
                or envelope["source_qualification"]
                != _authority_json_v3(canonical_serialize(qualification))):
            return False
        return (
            binding.call_id == intent.call_id
            and binding.model_request_digest == intent.request_digest
            and binding.source_id == source_id
            and binding.source_revision == intent.source_revisions[0][1] == source_row[0]
            and binding.access_revision == intent.access_revisions[0][1]
            and binding.budget_lease_id == intent.budget_lease_id
            and binding.budget_reservation_operation_id == intent.budget_reservation_operation_id
            and frozen["job_id"] == job.job_id
            and frozen["acquire_operation_id"] == acquire_operation_id
            and frozen["original_operation_id"] == job.operation_id
            and frozen["budget_reservation_operation_id"] == job.operation_id
            and frozen["budget_lease_id"] == job.budget_ref
            and frozen["work_kind"] == job.work_kind
            and frozen["worker_fence"] == job.fence
            and frozen["worker_lease_expires_utc"] == job.lease_expires_utc
            and frozen["clock_epoch"] == clock_epoch
            and frozen["provider_id"] == intent.provider_id
            and frozen["model_id"] == intent.model_id
            and frozen["provider_config_digest"] == intent.provider_config_digest
            and frozen["max_output_tokens"] == intent.max_output_tokens
            and frozen["prompt_template_version"] in ENCODING_TEMPLATE_VERSIONS
            and frozen["prompt_template_digest"] == template_digest
            and frozen["payload"] == payload
            and envelope["identity"]["operation_id"] == acquire_operation_id
            and envelope["identity"]["phase"] == "encode"
            and envelope["identity"]["activity_id"] == job.activity_id
            and envelope["schema"] == "sylanne.runtime.v1"
            and envelope["authority"]["actor"] == intent.subject
            and envelope["authority"]["issuer_domain"] == "d11"
            and envelope["authority"]["worker_fence"] == intent.worker_fence
            and envelope["authority"]["activation_generation"]
            == intent.authority_activation_generation
            and envelope["authority"]["namespace"] == _authority_json_v3(canonical_serialize(namespace))
            and envelope["source_qualification"]["source_refs"] == [source_token]
            and envelope["input_refs"] == [source_token]
            and envelope["parent_budget_lease_ref"] == intent.budget_lease_id
            and request_deadline == min(
                datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp(),
                datetime.fromisoformat(job.lease_expires_utc.replace("Z", "+00:00")).timestamp())
            and envelope["character_interval_ref"] == issue_policy["character_interval_ref"]
        )

    def _check(self, db: sqlite3.Connection, intent: ModelEgressIntentV1,
               now: float) -> bool:
        job = get_job(db, intent.job_id)
        namespace = NamespaceId(job.bot_id, job.persona_id)
        ns = namespace.as_tuple
        recovery = _authority_point_v3(db,table='graph_recovery_metadata_v2',columns=('schema', 'requirements_json', 'graph_revision'),key_columns=('bot', 'persona'),key=tuple(ns),legacy_reader=lambda: db.execute(
            "SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
            "WHERE bot=? AND persona=?", ns).fetchone())
        epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns).fetchone()
        access_epoch = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns).fetchone()
        if (recovery is None or recovery[0] != "sylanne3.authority.v2"
                or recovery[2] != intent.graph_revision
                or epoch != (intent.graph_epoch,)
                or access_epoch != (intent.access_epoch, intent.delete_epoch)):
            return False
        requirements_data = _canonical(recovery[1])
        if (type(requirements_data) is not dict
                or requirements_data.get("namespace") != asdict(namespace)):
            return False
        requirements = SnapshotRequirementsV2(**{
            **requirements_data, "namespace": namespace})
        if (requirements.authority_id != intent.authority_id
                or requirements.authority_namespace != intent.namespace
                or requirements.activation_generation
                != intent.authority_activation_generation
                or requirements.revocation_epoch != intent.authority_revocation_epoch
                or requirements.deletion_seq != intent.authority_deletion_seq
                or requirements.execution_seq != intent.authority_execution_seq):
            return False
        if ((job.bot_id, job.persona_id) != ns or job.work_kind != "d06.encode_source"
                or job.effect_id is not None or job.phase != "running"
                or job.fence != intent.worker_fence or job.cancel_epoch != 0
                or job.lease_holder != intent.subject or job.result_ref is not None
                or job.lease_expires_utc is None
                or datetime.fromisoformat(job.lease_expires_utc.replace(
                    "Z", "+00:00")).timestamp() <= now
                or datetime.fromisoformat(job.deadline_utc.replace(
                    "Z", "+00:00")).timestamp() <= now):
            return False
        job_key = runtime_job_key(*ns, job.activity_id, job.job_id)
        job_atom = _authority_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=tuple((job_key.token,)),legacy_reader=lambda: db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (job_key.token,)).fetchone())
        if (job_atom is None or job_atom[2] != 1
                or _canonical(job_atom[1]) != job_graph_write(job).value):
            return False
        receipt = _authority_point_v3(db,table='graph_bundle_operations',columns=('activity_id', 'effect_id', 'receipt_json'),key_columns=('bot', 'persona', 'operation_id'),key=tuple(ns + (job.operation_id,)),legacy_reader=lambda: db.execute(
            "SELECT activity_id,effect_id,receipt_json FROM graph_bundle_operations "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (job.operation_id,)).fetchone())
        if receipt is None or receipt[:2] != (job.activity_id, None):
            return False
        receipt_data = _canonical(receipt[2])
        outbox_rows = db.execute(
            "SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
            "AND owner_kind='activity' AND subject=? AND type_name='runtime.outbox'",
            ns + (job.activity_id,)).fetchall()
        matches = [row for row in outbox_rows if _canonical(row[2]).get("job_id") == job.job_id]
        if len(matches) != 1:
            return False
        outbox_row = matches[0]
        outbox = RuntimeOutboxValue(**_canonical(outbox_row[2]))
        expected = ingress_ids(outbox.payload_ref)
        outbox_key = runtime_outbox_key(*ns, job.activity_id, outbox.outbox_id)
        dependency = _authority_point_v3(db,table='graph_dependencies',columns=('dependency_revision',),key_columns=('dependent_token', 'dependency_token'),key=tuple((outbox_key.token, job_key.token)),legacy_reader=lambda: db.execute(
            "SELECT dependency_revision FROM graph_dependencies WHERE dependent_token=? "
            "AND dependency_token=?", (outbox_key.token, job_key.token)).fetchone())
        if (outbox_row[0] != outbox_key.token or outbox_row[3] != 1
                or expected[1:5] != (job.activity_id, job.operation_id,
                                     job.job_id, outbox.outbox_id)
                or outbox.job_id != job.job_id or outbox.job_ref != job_key.token
                or outbox.idempotency_key != expected[5]
                or outbox.phase != "pending" or outbox.dispatch_generation != 1
                or (outbox.bot_id, outbox.persona_id, outbox.activity_id,
                    outbox.operation_id, outbox.effect_id) != (
                    *ns, job.activity_id, job.operation_id, None)
                or dependency != (job_atom[0],)
                or outbox_key.token not in receipt_data.get("outbox_refs", ())
                or job_key.token not in receipt_data.get("ledger_refs", ())):
            return False
        source_ref = outbox.payload_ref
        if intent.source_refs != (source_ref,):
            return False
        source_key_value = source_key(*ns, source_ref)
        access_key_value = access_key(*ns, source_ref)
        source_row = _authority_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=tuple((source_key_value.token,)),legacy_reader=lambda: db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (source_key_value.token,)).fetchone())
        access_row = _authority_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=tuple((access_key_value.token,)),legacy_reader=lambda: db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (access_key_value.token,)).fetchone())
        if (source_row is None or access_row is None
                or source_row[2] != 1 or access_row[2] != 1
                or intent.source_revisions != ((source_ref, source_row[0]),)
                or intent.access_revisions != ((source_ref, access_row[0]),)):
            return False
        source = SourceRecord.from_dict(_canonical(source_row[1]))
        access = _canonical(access_row[1])
        validate_access(access)
        source_dependency = _authority_point_v3(db,table='graph_dependencies',columns=('dependency_revision',),key_columns=('dependent_token', 'dependency_token'),key=tuple((access_key_value.token,
                                       source_key_value.token)),legacy_reader=lambda: db.execute(
            "SELECT dependency_revision FROM graph_dependencies WHERE dependent_token=? "
            "AND dependency_token=?", (access_key_value.token,
                                       source_key_value.token)).fetchone())
        if (source.source_id != source_ref or access["source_id"] != source_ref
                or access["status"] != "active"
                or "consolidation" not in source.purposes
                or "consolidation" not in access["purposes"]
                or not set(access["audiences"]).issubset(source.audiences)
                or source_dependency != (source_row[0],)):
            return False
        quote_ref = job.operator_versions.get("resource_quote")
        if type(quote_ref) is not str or ":" not in quote_ref:
            return False
        quote_id, version_text = quote_ref.rsplit(":", 1)
        quote = self._issuer.resource_issuer._load_quote(db, quote_id, int(version_text))
        grant = self._issuer.current_budget_grant(db, job.budget_ref)
        lease = get_budget_lease(db, job.budget_ref)
        # A sibling or descendant may already have spent beyond its original
        # ceiling. The family debt marker is read in this same graph snapshot;
        # a still-reserved local job is not permission for a new model dispatch.
        require_budget_family_admissible(db, job.budget_ref)
        reservation = _authority_point_v3(db,table='runtime_budget_reservations',columns=('digest', 'ceiling_json', 'state'),key_columns=('lease_id', 'operation_id'),key=tuple((job.budget_ref, job.operation_id)),legacy_reader=lambda: db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (job.budget_ref, job.operation_id)).fetchone())
        ceiling = dict(intent.budget_ceiling)
        if (now >= quote.valid_until_utc or now >= grant.valid_until_utc
                or lease.state != "active" or reservation is None
                or (reservation is None or reservation[0]!=intent.budget_reservation_digest
                    or reservation[2]!='reserved' or not _authority_json_matches_v3(reservation[1],ceiling,legacy_serializer=canonical_json))
                or intent.budget_lease_id != job.budget_ref
                or intent.budget_reservation_operation_id != job.operation_id
                or quote.ceiling != ceiling or quote.graph_job_ref != job_key.token
                or quote.outbox_refs != (outbox_key.token,)
                or quote.effect_id is not None
                or quote.snapshot_ref != job.snapshot_ref
                or quote.resource_ref != job.resource_ref
                or job.deadline_utc != datetime.fromtimestamp(
                    quote.deadline_utc, timezone.utc).isoformat().replace("+00:00", "Z")
                or (quote.bot_id, quote.persona_id, quote.activity_id,
                    quote.operation_id, quote.work_kind,
                    quote.parent_budget_lease_ref) != (
                    *ns, job.activity_id, job.operation_id, job.work_kind, job.budget_ref)
                or (grant.bot_id, grant.persona_id, grant.lease_id) != (
                    *ns, job.budget_ref)
                or (lease.bot_id, lease.persona_id) != ns
                or job.work_kind not in grant.allowed_work_kinds
                or any(amount > grant.max_ceiling.get(key, 0)
                       for key, amount in ceiling.items())
                or any(lease.reserved.get(key, 0) < amount
                       for key, amount in ceiling.items())):
            return False
        acquire = db.execute(
            "SELECT i.job_id,i.original_operation_id,i.actor,r.job_json,r.permit_json,"
            "r.post_graph_revision,r.post_graph_epoch "
            "FROM graph_job_acquire_receipts_v2 AS r "
            "JOIN graph_job_acquire_intents_v2 AS i ON "
            "i.bot=r.bot AND i.persona=r.persona "
            "AND i.acquire_operation_id=r.acquire_operation_id "
            "WHERE r.bot=? AND r.persona=? AND i.job_id=?",
            ns + (job.job_id,)).fetchall()
        if (len(acquire) != 1 or acquire[0][:3] != (
                job.job_id, job.operation_id, job.lease_holder)
                or _canonical(acquire[0][3]) != asdict(job)):
            return False
        permit = from_wire(_canonical(acquire[0][4]))
        if (type(permit) is not FencePermitV2 or permit.operation != "write"
                or permit.authority_id != intent.authority_id
                or permit.namespace != intent.namespace
                or acquire[0][5] > intent.graph_revision
                or acquire[0][6] > intent.graph_epoch):
            return False
        return True


__all__ = ["PinnedCurrentModelEgressGraphVerifier"]
