"""Actual Core observation of a Contact prospective birth or final successor.

No Core table or permission is issued. The private Source-qualified Work reads
current originals; the caller stores this observation in its real Graph CAS.
"""
from dataclasses import asdict
import json
import hmac

from .contract import AuthorityUnavailable
from .contact_prospective_contract_v1 import (ContactProspectiveSelectorV1,
    ContactProspectiveObservationV1, MAX_INPUT_BYTES, MAX_OBSERVATION_BYTES,
    contact_prospective_to_wire_v1, contact_prospective_from_wire_v1)
from .v2_contract import FencePermitV2, to_wire as authority_wire, from_wire as authority_unwire, canonical_digest as authority_digest
from ..runtime_contracts import canonical_digest, canonical_serialize


class InstalledContactProspectiveObserverV1:
    def __init__(self, *, result_service, execution, bundle):
        from .contact_model_result_service_v2 import InstalledContactModelResultServiceV2
        from .v2_execution_bridge import AuthorityV2ExecutionBridge
        from ..host.authority_profile import AdminInstallationBundle
        if (type(result_service) is not InstalledContactModelResultServiceV2
                or type(execution) is not AuthorityV2ExecutionBridge
                or type(bundle) is not AdminInstallationBundle
                or execution.core is not result_service._fences.core
                or execution.fences is not result_service._fences.fences
                or execution.namespace != result_service._fences.namespace
                or bundle.installation_policy.namespace != result_service._policy.namespace
                or bundle.installation_policy.authority_namespace != execution.namespace
                or bundle.installation_policy.installation_id != result_service._installation_id
                or bundle.installation_policy.administrator_holder != result_service._holder):
            raise AuthorityUnavailable('Contact prospective requires its actual paired installed services')
        self.reader, self.execution, self.bundle = result_service, execution, bundle
        self.policy = result_service._policy
        self.fences, self.core = result_service._fences, result_service._fences.core
        self.namespace, self.installation_id = execution.namespace, result_service._installation_id
        self.subject, self.holder = result_service._read_subject, result_service._holder

    def _owner_policy(self, work):
        from .owner_location_read_v3 import (observe_owner_location_for_contact_v3,
            require_owner_location_observation_current_for_contact_v3)
        observed = observe_owner_location_for_contact_v3(self.policy.owner_service, work)
        with self.fences._frozen() as (db, deletion, execution, _):
            anchor = self.fences._current_locked(db, deletion, execution)
            self.fences.fences.validate_fence_locked(db, work.permit,
                subject=work.subject, current_anchor=anchor)
            require_owner_location_observation_current_for_contact_v3(self.policy.owner_service, work, observed, db)
            head = self.policy._current_owner(db, observed, work.permit)
            policy = self.policy._head(db, work.contact_selector.policy_id)
            now = self.reader._clock()
            if (policy is None or policy.action != 'issue' or policy.authority_id != work.permit.authority_id
                    or policy.namespace != work.namespace or policy.installation_id != self.installation_id
                    or policy.owner_head_digest != head.guard.authorization_head
                    or policy.owner_authorization_revision != head.guard.authorization_revision
                    or policy.owner_principal_epoch != self.policy._principal_epoch(db, head)
                    or not policy.policy.window_start <= now < policy.policy.window_end):
                raise AuthorityUnavailable('Contact prospective current Owner/standing policy differs')
        if policy != work.contact_policy:
            raise AuthorityUnavailable('Contact prospective original standing policy changed')
        return observed

    def _inputs(self, db, work, selected):
        from ..runtime.contact_original_read_v3 import contact_original_point_v3
        from ..runtime.contact_plan_adoption_v2 import read_adopted_contact_plan_v2
        from ..runtime.contact_background_inputs_v1 import read_contact_background_inputs_v1
        from ..runtime.contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
        from ..runtime.contact_prospective_v1 import (PrepareCurrentContactProspectiveRequestV1,
            contact_prospective_command_digest_v1, contact_prospective_attempt_id_v1,
            read_contact_prospective_original_v1)
        from ..runtime.domain_production_originals_v1 import _receipt, read_adopted_domain_operation_v1
        from ..runtime.joint_contact_preparation_v1 import read_current_joint_contact_preparation_v1
        from .contact_background_graph_v3 import require_contact_source_db_v3
        require_contact_source_db_v3(db)
        event = contact_original_point_v3(db, table='graph_domain_production_outbox_v1',
            columns=('causal_operation_id', 'receiver_domain', 'event_kind', 'original_ref', 'original_digest', 'state'),
            key_columns=('bot', 'persona', 'dedupe_key'),
            key=(*selected.namespace.as_tuple, selected.causal_dedupe_key), legacy_reader=lambda: None)
        if (event is None or event[1:3] != ('d10', 'qualified_joint_contact_requires_prospective_v1')
                or event[5] not in {'pending', 'waiting', 'completed'}
                or selected.causal_dedupe_key != canonical_digest((selected.namespace, event[0], event[1], event[2]))):
            raise AuthorityUnavailable('Contact prospective requires its actual Joint preparation event')
        preparation = read_current_joint_contact_preparation_v1(db, namespace=selected.namespace,
            original_ref=event[3], issuer=self.reader._issuer)
        causal = read_adopted_domain_operation_v1(db, selected.namespace, event[0])
        if (preparation.digest != event[4] or preparation.producer_operation_id != event[0]
                or preparation.request.contact_id != selected.contact_id
                or preparation.owner_acl_actor != work.contact_policy.owner_actor_id
                or causal is None or (causal['domain'], causal['operation_kind']) !=
                   ('d10', 'input:register_joint_contact_preparation_v1')
                or causal['receipt'].status != 'committed' or causal['receipt'].operation_id != event[0]):
            raise AuthorityUnavailable('Contact prospective Joint preparation lost its actual Owner/producer receipt')
        joint_origin = (preparation.original_ref, preparation.digest, preparation.producer_operation_id,
            canonical_digest(causal['receipt']))
        plan, _, _, _ = read_adopted_contact_plan_v2(db, namespace=selected.namespace,
            contact_id=selected.contact_id, issuer=self.reader._issuer)
        root = self.reader._issuer.current_budget_grant(db, plan.parent_budget_lease_id)
        if root != self.bundle.installation_policy.root_grant:
            raise AuthorityUnavailable('Contact prospective cannot replace its originally installed root grant')
        birth_digest = contact_prospective_command_digest_v1(selected.namespace,
            work.contact_policy.owner_actor_id, PrepareCurrentContactProspectiveRequestV1(selected.contact_id),
            selected.birth_operation_id, plan.activity_id, plan.audience_id, root.lease_id)
        if birth_digest != selected.birth_request_digest:
            raise AuthorityUnavailable('Contact prospective business selector differs from its actual command')
        final_digest = canonical_digest(('sylanne.domain-production-command.v1', selected.namespace,
            work.contact_policy.owner_actor_id, 'prepare_contact_dispatch_v3',
            PrepareCurrentContactDispatchRequestV3(selected.contact_id, 0), selected.final_operation_id,
            plan.activity_id, plan.audience_id, root.lease_id))
        columns = ('request_digest', 'attempt_id', 'anchor_json', 'graph_revision', 'graph_epoch',
            'permit_json', 'receipt_json')
        attempts = []
        for operation_id, request_digest in ((selected.birth_operation_id, birth_digest),
                                             (selected.final_operation_id, final_digest)):
            row = contact_original_point_v3(db, table='graph_owner_domain_attempts_v3', columns=columns,
                key_columns=('bot', 'persona', 'operation_id'),
                key=(*selected.namespace.as_tuple, operation_id), legacy_reader=lambda: None)
            if row is not None and row[1] == work.permit.operation_id:
                attempts.append((operation_id, request_digest, row))
        if len(attempts) != 1:
            raise AuthorityUnavailable('Contact prospective lacks its one actual current WRITE attempt')
        operation_id, request_digest, attempt = attempts[0]
        if (attempt[0] != request_digest or attempt[5] is None or attempt[6] is not None
                or authority_unwire(json.loads(attempt[5])) != work.permit
                or json.loads(attempt[2]) != asdict(work.permit.pinned_anchor)):
            raise AuthorityUnavailable('Contact prospective attempt/permit/anchor original differs')
        prior = None
        birth_limit = None
        if operation_id == selected.birth_operation_id:
            expected_attempt = contact_prospective_attempt_id_v1(selected.namespace,
                selected.birth_operation_id, birth_digest)
            if read_contact_prospective_original_v1(db, self.reader._issuer, selected.namespace, selected.contact_id) is not None:
                raise AuthorityUnavailable('Contact prospective birth already exists; use its fixed successor')
            if attempt[1] != expected_attempt:
                raise AuthorityUnavailable('Contact prospective birth attempt is not its installed once identity')
        else:
            original = read_contact_prospective_original_v1(db, self.reader._issuer,
                selected.namespace, selected.contact_id)
            if original is None:
                raise AuthorityUnavailable('Contact final successor has no actual saved prospective birth')
            birth = json.loads(original.payload_json)
            if (birth['namespace'] != asdict(selected.namespace) or birth['contact_id'] != selected.contact_id
                    or birth['birth_operation_id'] != selected.birth_operation_id
                    or birth['birth_request_digest'] != birth_digest
                    or birth['final_operation_id'] != selected.final_operation_id
                    or birth['effect_id'] != selected.effect_id):
                raise AuthorityUnavailable('Contact final successor differs from its immutable prospective birth')
            prior = contact_prospective_from_wire_v1(birth['observation'], ContactProspectiveObservationV1)
            prior_wire = contact_prospective_to_wire_v1(prior)
            if not hmac.compare_digest(prior.signature, self.policy._sign(
                    {name: value for name, value in prior_wire.items() if name != 'signature'})):
                raise AuthorityUnavailable('Contact prospective saved Core observation signature differs')
            receipt = _receipt(birth['receipt'])
            if (prior.selector != selected or prior.observed_operation_id != selected.birth_operation_id
                    or receipt.status != 'committed' or receipt.operation_id != selected.birth_operation_id
                    or (prior.joint_preparation_ref, prior.joint_preparation_digest, prior.joint_preparation_operation_id,
                        prior.joint_preparation_receipt_digest) != joint_origin):
                raise AuthorityUnavailable('Contact final successor cannot create or rewrite its original birth')
            saved_quote, saved_reservation = birth['quote'], birth['reservation']
            quote = self.reader._issuer._d02.original_signed_quote(db, saved_quote['id'], saved_quote['version'])
            quote_status = contact_original_point_v3(db, table='runtime_resource_quotes', columns=('status',),
                key_columns=('quote_id', 'version'), key=(quote.quote_id, quote.version), legacy_reader=lambda: None)
            reservation = contact_original_point_v3(db, table='runtime_budget_reservations',
                columns=('digest', 'ceiling_json', 'state'), key_columns=('lease_id', 'operation_id'),
                key=(root.lease_id, selected.final_operation_id), legacy_reader=lambda: None)
            if (quote_status != ('active',) or reservation is None or reservation[2] != 'reserved'
                    or (quote.bot_id, quote.persona_id) != selected.namespace.as_tuple
                    or quote.activity_id != plan.activity_id or quote.operation_id != selected.final_operation_id
                    or quote.effect_id != selected.effect_id or quote.parent_budget_lease_ref != root.lease_id
                    or canonical_digest(quote) != saved_quote['digest']
                    or (saved_quote['operation_id'], saved_quote['effect_id'], saved_quote['lease_ref']) !=
                       (selected.final_operation_id, selected.effect_id, root.lease_id)
                    or (saved_reservation['lease_ref'], saved_reservation['operation_id'], saved_reservation['digest']) !=
                       (root.lease_id, selected.final_operation_id, reservation[0])
                    or saved_reservation['ceiling'] != dict(quote.ceiling)
                    or json.loads(reservation[1]) != dict(quote.ceiling)):
                raise AuthorityUnavailable('Contact final successor changed its actual original quote/reservation')
            birth_limit = min(prior.deadline_utc, birth['deadline_utc'], quote.deadline_utc, quote.valid_until_utc)
            if not self.reader._clock() < birth_limit:
                raise AuthorityUnavailable('Contact original prospective budget deadline expired')
        final = contact_original_point_v3(db, table='graph_bundle_operations', columns=('digest',),
            key_columns=('bot', 'persona', 'operation_id'),
            key=(*selected.namespace.as_tuple, selected.final_operation_id), legacy_reader=lambda: None)
        if final is not None:
            raise AuthorityUnavailable('Committed Contact final must use its original recovery path')
        terms, results, plan, content = read_contact_background_inputs_v1(db,
            namespace=selected.namespace, contact_id=selected.contact_id,
            operation_id=selected.final_operation_id, request_digest=final_digest,
            dedupe_key=preparation.request.qualified_contact_dedupe_key, issuer=self.reader._issuer,
            now=self.reader._clock(), owner_actor=work.contact_policy.owner_actor_id)
        if ((plan.policy_original_ref, plan.policy_original_digest, plan.policy_version) !=
                (work.contact_policy.original_ref, work.contact_policy.digest, work.contact_policy.policy.version)
                or content.segments[0].segment.effect_id != selected.effect_id
                or attempt[3:5] != (terms['graph_revision'], terms['graph_epoch'])):
            raise AuthorityUnavailable('Contact prospective current Plan/policy/effect/attempt stamp differs')
        if ((preparation.contact_plan_ref, preparation.contact_plan_revision, preparation.contact_plan_original_digest,
                preparation.reviewed_content_digest, preparation.contact_causal_original_ref,
                preparation.contact_causal_original_digest, preparation.parent_budget_lease_ref,
                preparation.parent_grant_id, preparation.parent_grant_version, preparation.parent_grant_digest,
                preparation.absolute_deadline_utc, preparation.source_refs, preparation.purpose, preparation.audience,
                preparation.request.prepare_contact_operation_id) !=
                (terms['plan_ref'], terms['plan_revision'], terms['plan_original_digest'],
                 terms['reviewed_content_digest'], terms['causal_original_ref'], terms['causal_original_digest'],
                 terms['budget_lease_ref'], terms['grant_id'], terms['grant_version'], terms['grant_digest'],
                 terms['deadline_utc'], tuple(terms['source_refs']), 'expression', (plan.audience_id,),
                 terms['causal_operation_id'])):
            raise AuthorityUnavailable('Contact prospective changed its original Joint preparation business tuple')
        if prior is not None:
            birth_terms = json.loads(prior.inputs_json)
            stable_fields = set(terms) - {'graph_revision', 'graph_epoch'}
            if any(terms[name] != birth_terms[name] for name in stable_fields):
                raise AuthorityUnavailable('Contact prospective successor changed original business inputs')
        # Return terminal metadata only. Core checks the authenticated original
        # observation digest without materializing provider output a second time.
        terminals = tuple((result.request, result.terminal_receipt, result.observation.digest) for result in results)
        return terms, terminals, operation_id, request_digest, attempt[1], (
            terms['deadline_utc'] if prior is None else birth_limit), joint_origin

    def capture(self, *, credential, subject, permit, selector):
        from .contact_background_graph_v3 import ContactBackgroundSelectorV3, begin_contact_authority_graph_read_v3
        from .current_authority_graph_read_v3 import read_authority_graph_current_v3, finish_authority_graph_read_work_v3
        from .d12_target_owner_admission_v1 import current_owner_authority_to_wire_v1
        from .owner_location_read_v3 import require_owner_location_observation_current_for_contact_v3
        if (type(selector) is not ContactProspectiveSelectorV1 or type(permit) is not FencePermitV2
                or permit.operation != 'write' or subject != self.subject or permit.subject != subject
                or permit.holder != self.holder or permit.namespace != self.namespace
                or selector.namespace != self.bundle.installation_policy.namespace):
            raise AuthorityUnavailable('Contact prospective needs its actual installed separate WRITE call')
        self.core._require(credential, 'write', self.namespace, self.holder)
        self.fences.validate_fence(credential=credential, subject=subject, permit=permit)
        with self.fences._frozen() as (db, deletion, execution, _):
            anchor = self.fences._current_locked(db, deletion, execution)
            self.fences.fences.validate_fence_locked(db, permit, subject=subject, current_anchor=anchor)
            policy = self.policy._head(db, selector.policy_id)
            if (policy is None or policy.action != 'issue' or policy.namespace != selector.namespace
                    or not policy.policy.window_start <= self.reader._clock() < policy.policy.window_end):
                raise AuthorityUnavailable('Contact prospective signed standing-policy selector is unavailable')
        location = self.reader._location.observe_business_for_fence_v1(
            credential=credential, subject=subject, permit=permit)
        selected = ContactBackgroundSelectorV3(selector.namespace, selector.contact_id,
            selector.birth_operation_id, selector.birth_request_digest, selector.policy_id, selector.causal_dedupe_key)
        work = begin_contact_authority_graph_read_v3(self.reader, credential=credential, subject=subject,
            permit=permit, selector=selected, policy=policy, location=location)
        try:
            observed = self._owner_policy(work)
            first = read_authority_graph_current_v3(work, lambda db: self._inputs(db, work, selector))
            terms, terminals, operation_id, request_digest, attempt_id, original_deadline, joint_origin = first
            for request, terminal, observation_digest in terminals:
                _, actual, _ = self.reader._read_original(request, permit.pinned_anchor, content=False)
                if actual != terminal or actual.observation_digest != observation_digest:
                    raise AuthorityUnavailable('Contact prospective paid model terminal differs from real Core evidence')
            effect = self.execution.read_current_effect(credential=credential, subject=subject, effect_id=selector.effect_id)
            snapshot = self.execution.read_current_effect_snapshot_for_write_fence(
                credential=credential, subject=subject, permit=permit)
            if (effect.state != 'absent' or snapshot.coverage != 'complete'
                    or snapshot.anchor != permit.pinned_anchor
                    or (effect.execution_head_seq, effect.execution_head_digest) !=
                       (snapshot.execution_head_seq, snapshot.execution_head_digest)):
                raise AuthorityUnavailable('Contact prospective future effect is not independently absent')
            if read_authority_graph_current_v3(work, lambda db: self._inputs(db, work, selector)) != first:
                raise AuthorityUnavailable('Contact prospective actual source and original inputs changed')
            after = self._owner_policy(work)
            if after != observed:
                raise AuthorityUnavailable('Contact prospective Owner changed across its actual observation')
            authority = {**current_owner_authority_to_wire_v1(observed), 'permit': authority_wire(permit)}
            with self.fences._frozen() as (db, deletion, execution, _):
                anchor = self.fences._current_locked(db, deletion, execution)
                self.fences.fences.validate_fence_locked(db, permit, subject=subject, current_anchor=anchor)
                require_owner_location_observation_current_for_contact_v3(self.policy.owner_service, work, observed, db)
                self.reader._location.require_current_in_tx_v1(db, location)
                head = self.policy._current_owner(db, observed, permit)
                now = self.reader._clock()
                deadline = min(terms['deadline_utc'], policy.policy.window_end, original_deadline)
                if (self.policy._head(db, selector.policy_id) != policy
                        or policy.owner_principal_epoch != self.policy._principal_epoch(db, head)
                        or anchor != snapshot.anchor or not now < deadline):
                    raise AuthorityUnavailable('Contact prospective originals changed before its signed observation')
                from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
                input_size = c09_canonical_json_size_v3(terms, ascii=True, exact=True)
                if input_size > MAX_INPUT_BYTES:
                    raise AuthorityUnavailable('Contact prospective input metadata exceeds its fixed bound')
                work.operation.retain(input_size * 2 + 8192)
                inputs_json = canonical_serialize(terms)
                material = dict(selector=contact_prospective_to_wire_v1(selector),
                    authority_id=permit.authority_id, authority_namespace=self.namespace,
                    installation_id=self.installation_id, subject=subject,
                    observed_operation_id=operation_id, observed_request_digest=request_digest,
                    attempt_id=attempt_id, permit_digest=authority_digest(permit).removeprefix('sha256:'),
                    anchor_digest=canonical_digest(asdict(anchor)), selection_digest=work.selection_digest,
                    joint_preparation_ref=joint_origin[0], joint_preparation_digest=joint_origin[1],
                    joint_preparation_operation_id=joint_origin[2], joint_preparation_receipt_digest=joint_origin[3],
                    owner_authority_digest=canonical_digest(authority), owner_actor=policy.owner_actor_id,
                    owner_head_digest=policy.owner_head_digest, owner_revision=policy.owner_authorization_revision,
                    principal_epoch=policy.owner_principal_epoch, policy_original_ref=policy.original_ref,
                    policy_original_digest=policy.digest, policy_window_id=policy.window_id,
                    policy_version=policy.policy.version, inputs_json=inputs_json,
                    current_effect=authority_wire(effect), effect_snapshot=authority_wire(snapshot),
                    observed_at_utc=float(now), deadline_utc=float(deadline),
                    schema='authority.contact-prospective-observation.v1')
                encoded_size = c09_canonical_json_size_v3(material, ascii=True, exact=True)
                if encoded_size + 256 > MAX_OBSERVATION_BYTES:
                    raise AuthorityUnavailable('Contact prospective bodyless observation exceeds its fixed wire bound')
                # Existing Work pays for the ASCII canonical text, UTF-8 signing
                # bytes and returned encoding. This is its original shared pool.
                work.operation.retain(encoded_size * 3 + 8192)
                material['observation_ref'] = 'contact-prospective-observation:' + canonical_digest(material)
                material['signature'] = self.policy._sign(material)
                observation = contact_prospective_from_wire_v1(material, ContactProspectiveObservationV1)
            self.fences.validate_fence(credential=credential, subject=subject, permit=permit)
            return observation, authority
        finally:
            finish_authority_graph_read_work_v3(work)
