"""Manifest-pinned semantic profile and its explicit Owner-installed reader.

A package supplies engineering examples and exact template shares, not Owner
consent. Only the immutable, signed adoption original can activate a profile.
No missing member receives an inferred or equal share.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, replace
import hashlib
import json
import math
from pathlib import Path
import re

from ..domains.d04.affect import MeaningFacet
from ..domains.d04.mapping_asset_v2 import (
    DirectionFixtureV2, MappingRuleV2, SemanticMappingAssetV2,
    load_mapping_asset_v2, seal_mapping_asset_v2, verify_direction_fixtures_v2,
)
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .installed_package import _safe_file, verify_installed_backend_runtime_v1
from .installed_d04_root_resources import _object

PROFILE_PATH = "resources/catalogue/d04-semantic-mapping-profile.v3.json"
PROFILE_SHA256 = "7a1843875913dc0e9e3a813dc898cb26ab2d0438906cdf20a078d35e2796c41e"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PROFILE_FIELDS = frozenset(("schema", "profile_id", "profile_version", "calibration_status",
    "role_binding", "root_preset_id", "root_preset_version", "root_preset_digest", "allocation_policy_id",
    "allocation_policy_version", "template_shares", "mapping_template", "content_digest"))


def decode_semantic_mapping_asset_v3(raw):
    if type(raw) is not dict or set(raw) != set(SemanticMappingAssetV2.__dataclass_fields__):
        raise ValueError("D04 semantic mapping asset fields differ")
    fixtures = []
    for item in raw["fixtures"]:
        facet = {**item["facet"]}
        facet["source_refs"] = tuple(facet["source_refs"])
        facet["unknown_fields"] = tuple(facet["unknown_fields"])
        fixtures.append(DirectionFixtureV2(**{**item, "facet": MeaningFacet(**facet),
            "signaled_mechanisms": tuple(item["signaled_mechanisms"]),
            "expected_positive_mechanisms": tuple(item["expected_positive_mechanisms"])}))
    asset = SemanticMappingAssetV2(**{**raw,
        **{name: tuple(raw[name]) for name in ("persona_versions", "basis", "allowed_realities",
                                             "allowed_interpretation_levels")},
        "fixtures": tuple(fixtures),
        "rules": tuple(MappingRuleV2(**{**item, "layer_gains": tuple(item["layer_gains"]),
            "required_known_fields": tuple(item["required_known_fields"])}) for item in raw["rules"])})
    load_mapping_asset_v2(asset)
    if json.loads(canonical_serialize(asdict(asset))) != raw:
        raise ValueError("D04 semantic mapping codec differs")
    return asset


@dataclass(frozen=True, slots=True)
class InstalledD04SemanticProfileV3:
    manifest_sha256: str
    file_sha256: str
    profile_json: str
    profile_digest: str

    @property
    def raw(self):
        return json.loads(self.profile_json)

    def bind(self, *, role_ref: str, persona_version: str) -> SemanticMappingAssetV2:
        template = decode_semantic_mapping_asset_v3(self.raw["mapping_template"])
        return seal_mapping_asset_v2(replace(template, role_ref=role_ref,
                                             persona_versions=(persona_version,)))


def decode_semantic_profile_v3(content: bytes, manifest_sha256: str) -> InstalledD04SemanticProfileV3:
    """Validate bytes only. This decoder grants neither installation nor adoption."""
    raw = _object(content, "D04 semantic profile")
    if (set(raw) != _PROFILE_FIELDS
            or raw["schema"] != "d04.packaged-semantic-profile.v3"
            or raw["calibration_status"] != "engineering_unvalidated_owner_selection_required"
            or raw["role_binding"] != "exact_current_d01_activation_and_plan_version"
            or canonical_serialize(raw).encode("utf-8") != content
            or raw["content_digest"] != canonical_digest({k: v for k, v in raw.items() if k != "content_digest"})):
        raise ValueError("D04 packaged semantic profile schema or digest differs")
    for key in ("profile_id", "profile_version", "root_preset_id", "root_preset_version",
                "allocation_policy_id", "allocation_policy_version"):
        if type(raw[key]) is not str or not raw[key]:
            raise ValueError("D04 semantic profile identity is absent")
    if type(raw["root_preset_digest"]) is not str or _SHA.fullmatch(raw["root_preset_digest"]) is None:
        raise ValueError("D04 profile root preset digest is absent")
    shares = raw["template_shares"]
    if (type(shares) is not list or not shares
            or any(type(row) is not list or len(row) != 2 or type(row[0]) is not str or not row[0]
                   or type(row[1]) not in (int, float) or not math.isfinite(row[1])
                   or not 0 < row[1] <= 1 for row in shares)
            or len({row[0] for row in shares}) != len(shares)
            or math.fsum(row[1] for row in shares) > 1):
        raise ValueError("D04 profile requires explicit bounded unique template shares")
    asset = decode_semantic_mapping_asset_v3(raw["mapping_template"])
    if (asset.role_ref != "$current_d01_activation"
            or asset.persona_versions != ("$current_d01_plan_version",)
            or asset.asset_id != raw["profile_id"]):
        raise ValueError("D04 profile requires explicit current-role template binding")
    verify_direction_fixtures_v2(asset)
    return InstalledD04SemanticProfileV3(manifest_sha256, hashlib.sha256(content).hexdigest(),
        content.decode("utf-8"), raw["content_digest"])


def semantic_profile_manifest_binding_v3(content: bytes) -> dict:
    """Exact public package-builder binding; does not confer trust."""
    profile = decode_semantic_profile_v3(content, "0" * 64)
    return {"path": PROFILE_PATH, "sha256": profile.file_sha256, "bytes": len(content),
        "profile_id": profile.raw["profile_id"], "profile_version": profile.raw["profile_version"],
        "profile_digest": profile.profile_digest,
        "status": "engineering_unvalidated_owner_selection_required"}


def load_installed_d04_semantic_profile_v3(package_root, trusted_manifest_sha256, *,
                                          available_cpu_features=None):
    if type(trusted_manifest_sha256) is not str or _SHA.fullmatch(trusted_manifest_sha256) is None:
        raise ValueError("D04 semantic profile requires an externally pinned manifest")
    original = Path(package_root)
    if original.is_symlink() or bool(getattr(original, "is_junction", lambda: False)()):
        raise ValueError("D04 installed package root is linked")
    root = original.resolve(strict=True)
    verified = verify_installed_backend_runtime_v1(root, trusted_manifest_sha256,
        available_cpu_features=available_cpu_features)
    if (not verified.verified or verified.manifest_digest != trusted_manifest_sha256
            or verified.runtime_scope not in {"formal-alpha1", "backend-production-acceptance", "backend-local-alpha2-acceptance"}):
        raise ValueError("D04 semantic profile requires verified installed runtime bytes")
    manifest_path, path = _safe_file(root, "release-manifest.json"), _safe_file(root, PROFILE_PATH)
    if manifest_path is None or path is None:
        raise ValueError("D04 semantic profile or manifest path is absent or unsafe")
    manifest_bytes, content = manifest_path.read_bytes(), path.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != trusted_manifest_sha256:
        raise ValueError("D04 manifest changed after verification")
    manifest = _object(manifest_bytes, "installed manifest")
    profile = decode_semantic_profile_v3(content, trusted_manifest_sha256)
    if profile.file_sha256 != PROFILE_SHA256:
        raise ValueError("D04 packaged engineering profile differs from registered bytes")
    binding = semantic_profile_manifest_binding_v3(content)
    if manifest.get("semantic_mapping_profile") != binding:
        raise ValueError("D04 semantic profile manifest binding differs")
    rows = manifest.get("files")
    matches = [row for row in rows if type(row) is dict and row.get("path") == PROFILE_PATH] if type(rows) is list else []
    if (len(matches) != 1 or any(matches[0].get(k) != binding[k] for k in ("path", "sha256", "bytes"))):
        raise ValueError("D04 semantic profile is not exactly manifest-listed")
    from .installed_d04_root_resources import load_installed_d04_root_preset_v3
    preset = load_installed_d04_root_preset_v3(root, trusted_manifest_sha256,
        available_cpu_features=available_cpu_features)
    if preset.digest != profile.raw["root_preset_digest"]:
        raise ValueError("D04 semantic profile and installed root preset differ")
    return profile


class InstalledD04SemanticMappingReaderV3:
    """Composition-owned port, bound to a real Graph and actual Authority fence."""

    def __init__(self, graph, package_root, trusted_manifest_sha256, *, available_cpu_features=None,
                 historical_compatibility=None):
        from ..graph_coordinator import GraphCoordinator
        from ..graph_store import ProductionGraphStore
        from ..runtime.issuers import D11BudgetGrantIssuer
        if (type(graph) is not GraphCoordinator
                or not isinstance(graph._GraphCoordinator__store, ProductionGraphStore)
                or not isinstance(graph._GraphCoordinator__d11_issuer, D11BudgetGrantIssuer)
                or graph._GraphCoordinator__content_fence_v2 is None):
            raise ValueError("D04 installed mapping needs the production graph and signed D11 issuer")
        candidate_root = Path(package_root)
        if candidate_root.is_symlink() or bool(getattr(candidate_root, "is_junction", lambda: False)()):
            raise ValueError("D04 installed package root is linked")
        root = candidate_root.resolve(strict=True)
        if Path(__file__).resolve(strict=True) != root / "rewrite/sylanne3/host/installed_d04_semantic_mapping_v3.py":
            raise ValueError("loaded D04 semantic reader differs from installed package code")
        self.graph = graph
        self.package_root = root
        self.manifest_sha256 = trusted_manifest_sha256
        self.available_cpu_features = available_cpu_features
        if historical_compatibility is not None:
            from .installed_d04_historical_compatibility_v1 import InstalledHistoricalD04CompatibilityV1
            if (type(historical_compatibility) is not InstalledHistoricalD04CompatibilityV1
                    or historical_compatibility.current_manifest_sha256 != trusted_manifest_sha256
                    or historical_compatibility.installation_id != graph._GraphCoordinator__content_fence_v2.installation_grant.installation_id):
                raise ValueError("D04 historical resource compatibility differs from installed reader")
            historical_compatibility.require_current_selection_v1()
        self._historical_compatibility = historical_compatibility
        self._fence = ContextVar("d04_semantic_mapping_fence", default=None)
        self._selection_owner = ContextVar("d04_semantic_selection_owner", default=None)
        self._location = ContextVar("d04_semantic_current_owner_location", default=None)
        self._numeric_bridge = ContextVar("d04_semantic_readonly_numeric_bridge", default=None)

    def profile(self):
        return load_installed_d04_semantic_profile_v3(self.package_root, self.manifest_sha256,
            available_cpu_features=self.available_cpu_features)

    @contextmanager
    def current_fence(self, scope):
        """Enter before BEGIN. Neither a supplied guard nor an DTO is authority."""
        graph = self.graph
        db, port = graph._GraphCoordinator__store._db, graph._GraphCoordinator__content_fence_v2
        if db.in_transaction or self._fence.get() is not None:
            raise ValueError("D04 mapping fence must be entered before the graph transaction")
        if (port.installation_grant.manifest_digest != self.manifest_sha256
                or scope.operation not in {"read", "write"} or port.validate_fence(scope) != scope.permit):
            raise ValueError("D04 mapping actual Authority fence is unavailable")
        self._observe_historical_process()
        from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
        observed = port.get_current_background_owner_authority_for_fence_v1(namespace=scope.namespace,
            authority_namespace=scope.authority_namespace, permit=scope.permit)
        if (type(observed) is not tuple or len(observed) != 2
                or type(observed[0]) is not D12CurrentOwnerAuthorityV1 or observed[1] != scope.permit
                or observed[0].guard.namespace != scope.namespace
                or observed[0].guard.authority_id != scope.permit.authority_id
                or observed[0].guard.pending_revoke_operation_id is not None):
            raise ValueError("D04 current Owner guard is unavailable or revoking")
        current = observed[0]
        profile = self._profile_for_current_owner(scope, current, port.installation_grant)
        marker = self._fence.set((scope, current.guard, profile))
        location_marker = self._location.set(current)
        try:
            yield self
            if db.in_transaction:
                raise ValueError("D04 mapping fence exited with an open graph transaction")
            if port.get_current_background_owner_authority_for_fence_v1(namespace=scope.namespace,
                    authority_namespace=scope.authority_namespace, permit=scope.permit) != observed:
                raise ValueError("D04 current Owner location changed after graph read")
            self._observe_historical_process()
        finally:
            self._location.reset(location_marker)
            self._fence.reset(marker)

    def _profile_for_current_owner(self, scope, current, installation_grant):
        graph, db = self.graph, self.graph._GraphCoordinator__store._db
        target = current.target_admission
        if (target is None and current.guard.installation_id != installation_grant.installation_id
                or target is not None and (target.target_installation_id != installation_grant.installation_id
                    or target.target_holder != scope.permit.holder or target.activation_generation != scope.permit.generation
                    or target.source_installation_id != current.guard.installation_id)):
            raise ValueError("D04 current Owner location differs from actual installation")
        # Durable selection survives a session expiry, but never revocation
        # of the actual accepting Owner/paired credential. Resolve identity
        # outside the business lock, just like the ordinary Owner fence path.
        from ..runtime.d04_semantic_installation_original_v3 import TABLE, SIGN_KIND
        from ..runtime.d11_role_clock_installation_v1 import TABLE as CLOCK_TABLE, SIGN_KIND as CLOCK_SIGN_KIND
        from ..runtime.domain_background_read_v3 import read_bound_background_role_clock_selections_v3
        background,selections=read_bound_background_role_clock_selections_v3(db,self,scope)
        for table, kind in ((TABLE, SIGN_KIND), (CLOCK_TABLE, CLOCK_SIGN_KIND)):
            if background:
                actual=next(original for name,sign_kind,original in selections if name==table and sign_kind==kind)
                if actual is None or self._selection_owner.get() is not None:continue
                raw,_original_digest=actual
            else:
                with graph._GraphCoordinator__store._lock:
                    row = db.execute(f"SELECT original_json,original_digest,signature FROM {table} "
                        "WHERE bot=? AND persona=? ORDER BY revision DESC LIMIT 1", scope.namespace.as_tuple).fetchone()
                if row is None or self._selection_owner.get() is not None:continue
                graph._GraphCoordinator__d11_issuer._signer.verify(kind,row[0],row[2])
                raw=json.loads(row[0])
                if canonical_digest(raw)!=row[1] or raw.get('namespace')!=asdict(scope.namespace):
                    raise ValueError('D04 accepting Owner original identity differs')
            original_manifest = self._qualified_original_manifest(scope.namespace, raw)
            source_ref = (None if target is None else "d04-semantic-installation:" + canonical_digest(
                (scope.namespace, target.source_installation_id, original_manifest)))
            if target is not None and raw.get("installation_ref") == source_ref:
                if (raw.get("owner_guard") != asdict(target.source_owner_guard)
                        or raw["owner"]["principal"] != asdict(target.principal)):
                    raise ValueError("D04 migrated accepting Owner differs from actual target admission")
            else:
                paired = graph._current_owner_principal(raw["owner"]["actor_id"], scope.namespace)
                if asdict(paired) != raw["owner"]["principal"]:
                    raise ValueError("D04 accepting Owner pairing was revoked or replaced")
        # Verify package once outside SQL locks, then replay exact pinned bytes in
        # each read; paths and bytes can change between those two points.
        return self.profile()

    @contextmanager
    def current_numeric_fence(self, scope, *, numeric_port, bridge):
        """Read-only two-head reconstruction under the actual installed gate.

        The ordinary Graph fence remains strict. Only this independently
        authenticated numeric bridge may retain Graph's before requirements
        while its real write permit pins the after-claim/terminal journal head.
        """
        from ..runtime.c04_authority_port_v3 import InstalledC04AuthorityPortV3
        from ..authority_service.d04_numeric_claim_bridge_v3 import D04NumericAdoptionBridgeV3
        from ..runtime_contracts import FenceScope
        graph, store = self.graph, self.graph._GraphCoordinator__store
        db = store._db
        if (type(numeric_port) is not InstalledC04AuthorityPortV3
                or type(bridge) is not D04NumericAdoptionBridgeV3 or type(scope) is not FenceScope
                or graph._GraphCoordinator__c04_authority_port_v3 is not numeric_port
                or graph._GraphCoordinator__d04_semantic_mapping_reader is not self
                or db.in_transaction or self._fence.get() is not None or self._numeric_bridge.get() is not None
                or self._selection_owner.get() is not None):
            raise ValueError("D04 numeric read needs its registered installed gate before SQL")
        grant = numeric_port._grant
        ordinary_grant = graph._GraphCoordinator__content_fence_v2.installation_grant
        if ((grant.authority_id, grant.installation_id, grant.administrator_holder, grant.manifest_digest) !=
                (ordinary_grant.authority_id, ordinary_grant.installation_id,
                 ordinary_grant.administrator_holder, self.manifest_sha256)
                or ordinary_grant.manifest_digest != self.manifest_sha256
                or grant.manifest_digest != bridge.binding.native_manifest_sha256
                or scope.namespace != bridge.binding.namespace
                or scope.authority_namespace != bridge.binding.authority_namespace
                or scope.generation != bridge.binding.activation_generation or scope.operation != "write"
                or scope.graph_revision != bridge.before_graph_revision
                or scope.permit != bridge.permit or scope.pinned_anchor != bridge.after_anchor
                or scope.permit.subject != "d04-numeric:" + grant.installation_id
                or scope.permit.holder != grant.administrator_holder):
            raise ValueError("D04 numeric bridge and current installation scope differ")
        observed = numeric_port.numeric_validate_gate(bridge.binding, bridge)
        if type(observed) is not D04NumericAdoptionBridgeV3 or observed != bridge:
            raise ValueError("D04 numeric semantic gate is not independently current")
        self._observe_historical_process()
        current = observed.owner_authority
        if (current.guard.namespace != scope.namespace or current.guard.authority_id != grant.authority_id
                or current.guard.pending_revoke_operation_id is not None):
            raise ValueError("D04 numeric current Owner is unavailable or revoking")
        profile = self._profile_for_current_owner(scope, current, grant)
        before_changes = db.total_changes
        marker = self._fence.set((scope, current.guard, profile))
        location_marker = self._location.set(current)
        bridge_marker = self._numeric_bridge.set(observed)
        try:
            yield self
            if db.in_transaction or db.total_changes != before_changes:
                raise ValueError("D04 numeric semantic reconstruction must remain read-only and close SQL")
            with store._lock:
                metadata, epoch = graph._v2_graph_stamp(scope.namespace)
                if (metadata.graph_revision != scope.graph_revision or epoch != scope.graph_epoch
                        or canonical_serialize(asdict(metadata.requirements)) != bridge.before_requirements_json):
                    raise ValueError("D04 numeric Graph changed during semantic reconstruction")
            if numeric_port.numeric_validate_gate(bridge.binding, bridge) != observed:
                raise ValueError("D04 numeric semantic gate changed after reconstruction")
            self._observe_historical_process()
        finally:
            self._numeric_bridge.reset(bridge_marker)
            self._location.reset(location_marker)
            self._fence.reset(marker)

    @contextmanager
    def current_owner_selection_fence(self, scope, authority, lease):
        """Only a genuine signed current Owner may replace an obsolete selection."""
        graph = self.graph
        binding = graph._GraphCoordinator__owner_leases.get(lease)
        proof = graph._GraphCoordinator__owner_session_proofs.get(lease)
        if binding is None or proof is None or "workbench.activate" not in binding.capabilities:
            raise ValueError("D04 Owner selection requires its genuine signed process lease")
        graph._owner_binding_in_fence(authority, scope, binding.principal, binding,
            owner_session_proof=proof)
        marker = self._selection_owner.set(binding.principal)
        try:
            with self.current_fence(scope):
                yield self
        finally:
            self._selection_owner.reset(marker)

    def _current(self, db, namespace):
        graph, context = self.graph, self._fence.get()
        store = graph._GraphCoordinator__store
        if (context is None or db is not store._db or not db.in_transaction
                or not store._lock._is_owned() or context[0].namespace != namespace):
            raise ValueError("D04 mapping reader lacks the actual current fenced graph transaction")
        self._require_historical_selection()
        # File validation is local only; no Authority/network call while SQL held.
        if self.profile() != context[2]:
            raise ValueError("D04 installed semantic profile changed under fence")
        self._require_current_location(db, namespace, context[0])
        return context

    def _require_historical_selection(self):
        if self._historical_compatibility is not None:
            self._historical_compatibility.require_current_selection_v1()

    def _observe_historical_process(self):
        if self._historical_compatibility is not None:
            self._historical_compatibility.observe_current_process_v1()

    def _qualified_original_manifest(self, namespace, body):
        manifest = body.get("manifest_sha256")
        if manifest == self.manifest_sha256:
            return manifest
        historical = self._historical_compatibility
        if historical is None or historical.namespace != namespace:
            raise ValueError("D04 historical original has no registered resource qualification")
        historical.require_original_manifest_v1(manifest)
        return manifest

    def qualified_original_manifest_sha256(self, db, namespace, body):
        self._current(db, namespace)
        return self._qualified_original_manifest(namespace, body)

    def _require_current_location(self, db, namespace, scope):
        """Reconcile an independently observed admission with this Graph snapshot."""
        from ..graph_store import GraphStore
        from ..graph_types import owner_grant_key
        from ..runtime.graph_migration_snapshot_v1 import _read_import_receipt_locked
        from ..runtime.lifecycle_operations_v1 import digest
        current = self._location.get()
        if current is None:
            raise ValueError("D04 current independent Owner location is absent")
        row = db.execute("SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
            "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
        metadata = GraphStore._decode_recovery(row, namespace)
        epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
        bridge = self._numeric_bridge.get()
        business_anchor = scope.pinned_anchor
        if bridge is not None:
            if (metadata is None or bridge.permit != scope.permit or bridge.after_anchor != scope.pinned_anchor
                    or bridge.owner_authority != current or bridge.before_graph_revision != metadata.graph_revision
                    or canonical_serialize(asdict(metadata.requirements)) != bridge.before_requirements_json):
                raise ValueError("D04 numeric semantic before/after bindings differ")
            business_anchor = bridge.before_anchor
        if (metadata is None or metadata.graph_revision != scope.graph_revision or epoch != (scope.graph_epoch.revision,)
                or metadata.requirements.activation_generation != scope.generation
                or metadata.requirements.authority_namespace != scope.authority_namespace
                or scope.permit.pinned_anchor != scope.pinned_anchor
                or not self.graph._anchor_matches(metadata.requirements, business_anchor)):
            raise ValueError("D04 mapping current graph and actual fence differ")
        target = current.target_admission
        if target is None:
            from ..runtime.d04_owner_storage_binding_v1 import require_d04_source_storage_binding_v1
            require_d04_source_storage_binding_v1(db, namespace=namespace, metadata=metadata,
                scope=scope, observed=current,
                installation_id=self.graph._GraphCoordinator__content_fence_v2.installation_grant.installation_id,
                business_anchor=business_anchor)
            return
        req = metadata.requirements
        grant_key = owner_grant_key(*namespace.as_tuple)
        from ..runtime.domain_background_read_v3 import background_graph_head_v3,background_json_loads_v3
        grant=background_graph_head_v3(db,namespace,grant_key)
        imported = _read_import_receipt_locked(db, namespace, target.transfer_id)
        if (target.namespace != namespace or target.authority_namespace != req.authority_namespace
                or target.target_installation_id != self.graph._GraphCoordinator__content_fence_v2.installation_grant.installation_id
                or target.target_holder != scope.permit.holder or target.activation_generation != req.activation_generation
                or target.revocation_epoch != req.revocation_epoch or target.graph_incarnation != req.graph_incarnation
                or target.source_owner_guard != current.guard or target.source_grant_ref != grant_key.token
                or grant is None or grant[0] != target.source_grant_revision or grant[2] != 1
                or digest(background_json_loads_v3(grant[1])) != target.source_grant_digest
                or background_json_loads_v3(grant[1])["principal"] != asdict(target.principal)
                or imported is None or imported.graph_commit_digest != target.target_import_digest
                or imported.snapshot_digest != target.source_snapshot_digest
                or imported.target_activation_generation != target.activation_generation
                or target.storage_continuation_ref is None and imported.target_graph_incarnation != req.graph_incarnation
                or metadata.graph_revision < imported.target_graph_revision):
            raise ValueError("D04 mapping source original and actual imported target location differ")

    def qualified_original_installation_ref(self, db, namespace, body):
        self._current(db, namespace)
        original_manifest = self._qualified_original_manifest(namespace, body)
        current_installation = self.graph._GraphCoordinator__content_fence_v2.installation_grant.installation_id
        allowed = {current_installation}
        target = self._location.get().target_admission
        if target is not None:
            allowed.add(target.source_installation_id)
        refs = {"d04-semantic-installation:" + canonical_digest((namespace, installation, original_manifest))
            for installation in allowed}
        if body.get("installation_ref") not in refs:
            raise ValueError("D04 semantic original installation has no current qualified location")
        return body["installation_ref"]

    def __call__(self, db, namespace):
        from ..runtime.d04_semantic_installation_original_v3 import read_current_semantic_mapping_v3
        return read_current_semantic_mapping_v3(self, db, namespace)

    def current_role_condition(self, db, namespace):
        from ..domains.d04.drive_allocation import RoleCondition
        installed = self(db, namespace)
        return RoleCondition(installed.asset.role_ref, installed.asset.persona_versions[0],
                             installed.asset.condition_version, installed.asset.policy_version)

    def current_role_clock_identity(self, db, namespace):
        from ..runtime.d11_role_clock_installation_v1 import read_current_role_clock_installation_v1
        current = read_current_role_clock_installation_v1(self, db, namespace)
        return current.mapping_id, current.version

    def adopt_current(self, authority, lease, *, operation_id, profile_digest, expected_revision=0):
        from ..runtime.d04_semantic_installation_original_v3 import adopt_current_d04_semantic_mapping_v3
        return adopt_current_d04_semantic_mapping_v3(self, authority, lease,
            operation_id=operation_id, profile_digest=profile_digest, expected_revision=expected_revision)

    def register_current_role_clock(self, authority, lease, **request):
        from ..runtime.d11_role_clock_installation_v1 import register_current_role_clock_v1
        return register_current_role_clock_v1(self, authority, lease, **request)
