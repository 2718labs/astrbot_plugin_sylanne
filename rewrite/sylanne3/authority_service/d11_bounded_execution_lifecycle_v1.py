"""Actual D11 once-claim/terminal lifecycle on the installed mixed journal.

Only fixed installed family classes supply their closed codecs and prepared
reader. Sources, algorithms, budget state and admission remain owned by their
existing authorities; this layer shares the actual append and recovery logic.
"""
from contextlib import contextmanager
from dataclasses import fields
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import sqlite3
from .contract import AuthorityUnavailable, JournalHead
from .independent_append_guard_v3 import independent_append_core_guard_v3
from ..runtime.d11_offline_originals_v1 import _utc
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1


class InstalledD11BoundedExecutionLifecycleV1:
    def _now(self):
        value = self._clock()
        if type(value) not in {float, int} or not math.isfinite(value):
            raise AuthorityUnavailable("trusted finite UTC sample required")
        return float(value)


    @staticmethod
    def _utc_text(value):
        return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


    def _sign(self, material):
        return hmac.new(self._key, canonical_serialize(plain_v1(material)).encode(), hashlib.sha256).hexdigest()


    def _payload(self, kind, **values):
        material = {**values, "schema": kind.__dataclass_fields__["schema"].default}
        return kind(**values, signature=self._sign(material))


    def _verify_payload(self, payload):
        material = {f.name: getattr(payload, f.name) for f in fields(payload) if f.name != "signature"}
        if not hmac.compare_digest(payload.signature, self._sign(material)):
            raise AuthorityUnavailable("offline signed original authentication failed")


    @contextmanager
    def _frozen(self):
        with self.fences._frozen() as value:
            yield value


    def _current(self, db, deletion, execution):
        anchor = self.fences._current_locked(db, deletion, execution)
        if anchor.authority_id != self.bridge.core._id(db):
            raise AuthorityUnavailable("offline current Authority differs")
        return anchor, self.bridge.core._row(db, self.bridge.namespace)[0]


    def _gate(self, db, binding, phase):
        row = self.bridge.fences._row(db, self._gate_id(binding, phase))
        if row is None:
            raise AuthorityUnavailable("offline actual gate absent")
        permit = self.bridge.fences._permit(row)
        if (permit.namespace != binding.authority_namespace or permit.subject != self._subject
                or permit.generation != binding.activation_generation or row[10] is not None
                or permit.operation != ("write" if phase == "claim" else "accounting")):
            raise AuthorityUnavailable("offline actual gate identity differs")
        return permit, row


    def _owner_current(self, db, binding, prepared, observed):
        from ..graph_types import owner_grant_key
        head = self.owner_tickets.current_migration_head_in_tx(db, authority_namespace=self.bridge.namespace)
        guard = json.loads(prepared.owner_guard_json)
        if (head is None or head.state != "active" or head.guard != observed.guard
                or head.guard.namespace != binding.namespace or head.guard.authority_id != binding.authority_id
                or head.guard.pending_revoke_operation_id is not None
                or head.guard.minimum_revocation_epoch
                or head.guard.minimum_revocation_revision >= head.guard.authorization_revision
                or head.grant_digest.removeprefix("sha256:") != binding.owner_grant_digest
                or head.grant_revision != binding.owner_grant_revision
                or binding.owner_grant_ref != owner_grant_key(*self.namespace.as_tuple).token
                or guard["owner_head_digest"] != head.guard.authorization_head.removeprefix("sha256:")):
            raise AuthorityUnavailable("offline accepting Owner changed before claim")


    @staticmethod
    def _prepared_anchor(prepared, anchor):
        raw = json.loads(prepared.requirements_json)
        expected = {"authority_id": anchor.authority_id, "authority_namespace": anchor.namespace,
                    "activation_generation": anchor.activation_generation,
                    **{k: getattr(anchor, k) for k in ("revocation_epoch", "deletion_journal_id",
                        "deletion_seq", "deletion_digest", "execution_journal_id", "execution_seq", "execution_digest")}}
        if any(raw.get(key) != value for key, value in expected.items()):
            raise AuthorityUnavailable("offline frozen Graph differs from current preclaim heads")


    def _advance_core(self, db, binding, row, before):
        current = self.bridge.core._head(self.bridge.core._row(db, self.bridge.namespace), "execution")
        after = JournalHead(self.bridge.journal.journal_id, row[0], row[6])
        if current != before or row[0] != before.seq + 1 or row[5] != before.digest:
            raise AuthorityUnavailable("offline Core reconciliation is not the exact next append")
        db.execute("UPDATE authority_namespaces SET execution_seq=?,execution_digest=?,anchor_nonce=? WHERE namespace=?",
            (after.seq, after.digest, self.bridge.core._new_nonce(), self.bridge.namespace))
        phase = "claim" if row[1] == self._execution_mutation_id(binding, "claim") else "terminal"
        self.bridge.core._event(db, self.bridge.namespace, self._event_prefix + phase,
            binding.activation_generation, (binding.digest, row[1], row[2], after.digest))
        return after


    def _finish_gate(self, db, binding, permit, row):
        self.bridge.fences.finish_fence_locked(db, permit, subject=self._subject,
            current_anchor=permit.pinned_anchor, request_id=permit.operation_id + ":consumed",
            request_digest="sha256:" + canonical_digest((binding.digest, row[1], row[6])))


    def _continuation(self, db, binding, claim):
        anchor = self.bridge.core._anchor(db, self.bridge.namespace,
            self.bridge.core._row(db, self.bridge.namespace))
        return self.bridge.fences.begin_fence_locked(db, subject=self._subject,
            holder=self.bridge.core._row(db, self.bridge.namespace)[0],
            operation="accounting", current_anchor=anchor,
            operation_id=self._gate_id(binding, "terminal"),
            command_digest="sha256:" + canonical_digest((binding.digest, claim.claim_digest)))


    def _recover_committed_append(self, binding):
        """Reconcile only an exact journal-ahead original, never rerun work."""
        with self._frozen() as (db, deletion, execution, _):
            _, claim, terminal, claim_row, terminal_row = self._read_execution_rows(
                self.bridge.journal, binding)
            if claim is None:
                return None
            self._verify_payload(claim.payload)
            if terminal is not None:
                self._verify_payload(terminal.payload)
            row = terminal_row or claim_row
            current = self.bridge.core._head(self.bridge.core._row(db, self.bridge.namespace), "execution")
            if current != execution:
                before = JournalHead(self.bridge.journal.journal_id, row[0] - 1, row[5])
                if current != before or execution != JournalHead(self.bridge.journal.journal_id, row[0], row[6]):
                    raise AuthorityUnavailable("offline recovery cannot skip unrelated journal progress")
                self.bridge._require_v2_mode_locked(db)
                self.bridge._check_deletion_locked(db, deletion)
                phase = "terminal" if terminal is not None else "claim"
                gate, stored = self._gate(db, binding, phase)
                anchor = self.bridge.core._anchor(db, self.bridge.namespace,
                    self.bridge.core._row(db, self.bridge.namespace))
                if stored[6] != "active" or gate.pinned_anchor != anchor:
                    raise AuthorityUnavailable("offline journal-ahead recovery lacks its original live gate")
                self.bridge.fences.validate_fence_locked(db, gate, subject=self._subject, current_anchor=anchor)
                if phase == "terminal" and gate.command_digest != "sha256:" + canonical_digest((binding.digest, claim.claim_digest)):
                    raise AuthorityUnavailable("offline recovery continuation differs from original claim")
                self._finish_gate(db, binding, gate, row)
                self._advance_core(db, binding, row, before)
                if terminal is None:
                    return self._continuation(db, binding, claim)
            if terminal is not None:
                return None
            gate, stored = self._gate(db, binding, "terminal")
            anchor = self.bridge.core._anchor(db, self.bridge.namespace,
                self.bridge.core._row(db, self.bridge.namespace))
            if (stored[6] != "active" or gate.pinned_anchor != anchor
                    or gate.command_digest != "sha256:" + canonical_digest((binding.digest, claim.claim_digest))):
                raise AuthorityUnavailable("unresolved offline claim lacks its actual continuation")
            self.bridge.fences.validate_fence_locked(db, gate, subject=self._subject, current_anchor=anchor)
            return gate


    def _close_unclaimed_gate(self, binding):
        """Close only this verified never-appended preflight; ambiguity stays HOLD."""
        try:
            with self._frozen() as (db, deletion, execution, _):
                _, claim, _, _, _ = self._read_execution_rows(self.bridge.journal, binding)
                if claim is not None:
                    return
                stored = self.bridge.fences._row(db, self._gate_id(binding, "claim"))
                if stored is None or stored[6] != "active":
                    return
                gate, _ = self._gate(db, binding, "claim")
                current, _ = self._current(db, deletion, execution)
                self.bridge.fences.validate_fence_locked(db, gate, subject=self._subject, current_anchor=current)
                self.bridge.fences.finish_fence_locked(db, gate, subject=self._subject, current_anchor=current,
                    request_id=gate.operation_id + ":unappended",
                    request_digest="sha256:" + canonical_digest((binding.digest, "unappended")))
        except Exception:
            # A durable or uncertain claim must not become an unexecuted refund.
            return


    def _claim(self, binding):
        from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
        with self._frozen() as (db, deletion, execution, _):
            anchor, holder = self._current(db, deletion, execution)
            if anchor.activation_generation != binding.activation_generation:
                raise AuthorityUnavailable("offline generation changed")
            permit = self.bridge.fences.begin_fence_locked(db, subject=self._subject, holder=holder,
                operation="write", current_anchor=anchor, operation_id=self._gate_id(binding, "claim"))
        prepared = self._prepared(binding)
        owner, returned = self.owner_service.get_current_background_owner_authority_for_fence_v1(
            credential=self.credential, subject=self._subject, permit=permit)
        if returned != permit:
            raise AuthorityUnavailable("offline Owner qualification changed its real permit")
        with independent_append_core_guard_v3(self.bridge) as (db, deletion):
            with self.bridge.journal.freeze_writes():
                before = self.bridge.journal.verified_head()
                current, holder = self._current(db, deletion, before)
                self.bridge.fences.validate_fence_locked(db, permit, subject=self._subject, current_anchor=current)
                self._owner_current(db, binding, prepared, owner)
                self._prepared_anchor(prepared, current)
                require_lifecycle_admission_in_tx_v1(db, self.bridge.namespace, action=self._first_claim_action)
                now = self._now()
                if now >= min(_utc(binding.deadline_utc).timestamp(), _utc(binding.job_lease_expires_utc).timestamp()):
                    raise AuthorityUnavailable("offline deadline/worker expired before durable claim")
                payload = self._payload(self._claim_payload_type,
                    binding_digest=binding.digest, prepared_digest=prepared.digest,
                    execution_id=binding.execution_id, claim_id=self._execution_mutation_id(binding, "claim"),
                    claim_sequence=before.seq + 1, executor_installation_id=self.installation_id,
                    executor_incarnation=self._executor, claimed_at_utc=self._utc_text(now))
                row = self._append_execution_row(self.bridge.journal,
                    binding=binding, payload=payload, before_head=before)
            # Journal is committed first. The real preclaim gate is consumed
            # and its accounting continuation is created in the same Core tx.
            with self.bridge.journal.freeze_writes():
                actual, claim, _, _, _ = self._read_execution_rows(self.bridge.journal, binding)
                if actual != JournalHead(self.bridge.journal.journal_id, row[0], row[6]):
                    raise AuthorityUnavailable("offline claim journal changed before reconciliation")
                self._finish_gate(db, binding, permit, row)
                self._advance_core(db, binding, row, before)
                continuation = self._continuation(db, binding, claim)
        return prepared, claim, continuation


    def _terminal(self, binding, claim, continuation, payload):
        from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
        with independent_append_core_guard_v3(self.bridge) as (db, deletion):
            with self.bridge.journal.freeze_writes():
                before, actual_claim, old, _, _ = self._read_execution_rows(self.bridge.journal, binding)
                if actual_claim != claim or old is not None:
                    raise AuthorityUnavailable("offline terminal does not own the unresolved claim")
                current, _ = self._current(db, deletion, before)
                gate, gate_row = self._gate(db, binding, "terminal")
                if (gate != continuation or gate_row[6] != "active"
                        or gate.command_digest != "sha256:" + canonical_digest((binding.digest, claim.claim_digest))):
                    raise AuthorityUnavailable("offline actual postclaim continuation differs")
                self.bridge.fences.validate_fence_locked(db, gate, subject=self._subject, current_anchor=current)
                require_lifecycle_admission_in_tx_v1(db, self.bridge.namespace, action="accounting", original_claimed=True)
                row = self._append_execution_row(self.bridge.journal,
                    binding=binding, payload=payload, before_head=before)
            with self.bridge.journal.freeze_writes():
                actual = self.bridge.journal.verified_head()
                if actual != JournalHead(self.bridge.journal.journal_id, row[0], row[6]):
                    raise AuthorityUnavailable("offline terminal journal changed before reconciliation")
                self._finish_gate(db, binding, continuation, row)
                self._advance_core(db, binding, row, before)

