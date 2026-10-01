"""Independently signed provider cache purge/read through a pinned adapter.

The adapter is an administrator-installed program, not a caller command. Its
provider signing key must be pinned separately. No Graph absence, HTTP success
or local file removal is accepted as evidence about provider-owned caches.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import canonical, digest
from .linux_installation_security_v1 import opened_installed_file_v1, read_installed_bytes_v1


class InstalledProviderCacheDispositionV1:
    def __init__(self, *, provider_id, executable=None, executable_sha256=None,
                 public_key_path=None, public_key_sha256=None, provider_config_digests=()):
        self.provider_id = provider_id
        self.executable, self.executable_sha256 = executable, executable_sha256
        self.public_key_path, self.public_key_sha256 = public_key_path, public_key_sha256
        if (type(provider_config_digests) not in {tuple, list}
                or tuple(provider_config_digests) != tuple(sorted(set(provider_config_digests)))
                or any(type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value)
                    for value in provider_config_digests)):
            raise AuthorityUnavailable("provider cache exact historical configuration coverage required")
        self.provider_config_digests = tuple(provider_config_digests)
        if not isinstance(provider_id, str) or not provider_id:
            raise AuthorityUnavailable("installed provider cache identity required")
        if executable is not None:
            self._key()
            with opened_installed_file_v1(executable) as fd:
                if hashlib.file_digest(os.fdopen(os.dup(fd), "rb"), "sha256").hexdigest() != executable_sha256:
                    raise AuthorityUnavailable("provider cache executable pin differs")

    def require_historical_provider_scopes_v2(self, scopes):
        if (type(scopes) is not tuple or scopes != tuple(sorted(set(scopes)))
                or any(provider != self.provider_id or configuration not in self.provider_config_digests
                    for provider, configuration in scopes)):
            raise AuthorityUnavailable("provider cache historical configuration/account scope is unresolved")
        self._key()

    def _key(self):
        if self.executable is None or self.public_key_path is None:
            raise AuthorityUnavailable("provider cache purge/read adapter is not installed for " + self.provider_id)
        value = read_installed_bytes_v1(self.public_key_path, limit=32)
        if len(value) != 32 or hashlib.sha256(value).hexdigest() != self.public_key_sha256:
            raise AuthorityUnavailable("provider cache verification key pin differs")
        return value

    def _request(self, operation_id, control, action, receipt_id=None):
        context = control.read_verified_current_storage_v1()
        context.require_current("maintenance")
        if context.stage not in {"SWITCHED", "CLEANED"} or context.prepared_original["operation_id"] != operation_id:
            raise AuthorityUnavailable("provider cache operation is not current")
        inventory = control.read_build_original_v1(operation_id=operation_id, kind="provider_scope_inventory")
        if inventory is None:
            raise AuthorityUnavailable("provider cache complete frozen historical inventory absent")
        details = inventory["details"]
        if (set(details) != {"schema", "namespace", "installation_id", "provider_config_scopes", "source_row_commitments"}
                or details["schema"] != "sylanne3.c09.historical-provider-scopes.v2"
                or (details["namespace"], details["installation_id"]) != (context.prepared_original["namespace"], control.installation_id)):
            raise AuthorityUnavailable("provider cache historical inventory scope differs")
        scopes = tuple(tuple(item) for item in details["provider_config_scopes"])
        if scopes:
            self.require_historical_provider_scopes_v2(scopes)
        body = {"schema": "sylanne3.c09.provider-cache-request.v2" if scopes else "sylanne3.c09.provider-cache-request.v1", "action": action,
            "provider_id": self.provider_id, "installation_id": control.installation_id,
            "authority_id": control.authority_id, "namespace": context.prepared_original["namespace"],
            "operation_id": operation_id, "manifest_digest": context.manifest_digest,
            "scope": "installation_namespace_all_prompt_caches", "receipt_id": receipt_id}
        if scopes:
            body.update(scope="installation_namespace_exact_provider_config_prompt_caches",
                provider_config_scopes=scopes, scope_inventory_digest=inventory["original_digest"])
        return context, {**body, "request_digest": digest(body)}

    def _call(self, request):
        key = self._key()
        with opened_installed_file_v1(self.executable) as fd:
            with os.fdopen(os.dup(fd), "rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != self.executable_sha256:
                    raise AuthorityUnavailable("provider cache executable changed")
            # Keep the verified file descriptor open across exec; pathname
            # substitution cannot change which installed executable is run.
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
                result = subprocess.run([f"/proc/self/fd/{fd}"], input=canonical(request).encode(),
                    stdout=output, stderr=error, timeout=60, pass_fds=(fd,),
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, cwd="/")
                if result.returncode != 0 or output.tell() > 1048576:
                    raise AuthorityUnavailable("provider cache adapter failed or exceeded response limit")
                output.seek(0)
                raw = output.read(1048577)
        try:
            envelope = json.loads(raw)
            if set(envelope) != {"payload", "signature"}:
                raise ValueError("provider envelope fields differ")
            payload = envelope["payload"]
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            v2 = request["schema"] == "sylanne3.c09.provider-cache-request.v2"
            schema = "sylanne3.c09.provider-cache-original.v2" if v2 else "sylanne3.c09.provider-cache-original.v1"
            Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(envelope["signature"], validate=True),
                schema.encode() + b"\0" + canonical(payload).encode())
            expected_fields = {"schema", "request_digest", "provider_id", "receipt_id", "state", "scope"}
            if v2:
                expected_fields |= {"provider_config_scopes", "scope_inventory_digest"}
            if (set(payload) != expected_fields
                    or payload["schema"] != schema
                    or payload["request_digest"] != request["request_digest"]
                    or payload["provider_id"] != self.provider_id
                    or payload["scope"] != request["scope"] or payload["state"] != "absent"
                    or not isinstance(payload["receipt_id"], str) or not payload["receipt_id"]
                    or request["receipt_id"] is not None and payload["receipt_id"] != request["receipt_id"]):
                raise ValueError("provider cache scope or result differs")
            if v2 and (payload["provider_config_scopes"] != json.loads(canonical(request["provider_config_scopes"]))
                    or payload["scope_inventory_digest"] != request["scope_inventory_digest"]):
                raise ValueError("provider cache did not attest every exact historical configuration scope")
        except Exception as exc:
            raise AuthorityUnavailable("provider cache signed original is invalid") from exc
        return envelope

    def clean_installed_surface_v1(self, *, operation_id, storage_reader):
        control = storage_reader
        context, request = self._request(operation_id, control, "purge")
        plan = control.read_build_original_v1(operation_id=operation_id, kind="purge_model_prompt_caches")
        if plan is None:
            plan = control.record_cleanup_plan_v1(operation_id=operation_id, surface="model_prompt_caches",
                details={"provider_id": self.provider_id, "request": request,
                         "adapter_sha256": self.executable_sha256, "public_key_sha256": self.public_key_sha256})
        elif plan["details"]["request"] != request:
            raise AuthorityUnavailable("provider cache cleanup replay changed")
        original = self._call(request)
        _, read_request = self._request(operation_id, control, "read", original["payload"]["receipt_id"])
        reread = self._call(read_request)
        return control.sign_original_v1("sylanne3.c09.surface-evidence.v1", {
            "schema": "sylanne3.c09.surface-evidence.v1", "installation_id": control.installation_id,
            "issuer_id": control.authority_id, "operation_id": operation_id, "surface": "model_prompt_caches",
            "manifest_digest": context.manifest_digest, "action": "purged", "plan_digest": plan["original_digest"],
            "before_observations": [original], "after_observations": [{key: reread["payload"][key]
                for key in ("provider_id", "receipt_id", "state", "scope", *(
                    ("provider_config_scopes", "scope_inventory_digest") if "provider_config_scopes" in read_request else ()))}]},
            "evidence_digest")

    def reread_installed_surface_v1(self, *, operation_id, storage_reader, original):
        storage_reader.verify_original_v1(original, "evidence_digest")
        after = original["after_observations"]
        context, request = self._request(operation_id, storage_reader, "read", after[0]["receipt_id"])
        plan = storage_reader.read_build_original_v1(operation_id=operation_id, kind="purge_model_prompt_caches")
        if (original["operation_id"] != operation_id or original["manifest_digest"] != context.manifest_digest
                or original["surface"] != "model_prompt_caches" or plan is None
                or plan["original_digest"] != original["plan_digest"]):
            raise AuthorityUnavailable("provider cache current original changed")
        current = self._call(request)["payload"]
        expected = [{key: current[key] for key in ("provider_id", "receipt_id", "state", "scope", *(
            ("provider_config_scopes", "scope_inventory_digest") if "provider_config_scopes" in request else ()))}]
        if after != expected:
            raise AuthorityUnavailable("provider cache independent observation changed")
        return {"evidence_digest": original["evidence_digest"], "after_observations": after}
