# D12 installed lifecycle integration receipt — 2026-09-30

This is a source/integration receipt, not a production deployment, whole-backend acceptance, or release claim. No live model calls, platform sends, production installation, credentials, push, or release occurred.

## Implemented and locally accepted

- `runtime/d12_installed_services_v1.py` installs a concrete W01 callback adapter. Command admission uses `GraphCoordinator._owner_domain_write_v3`: real process lease, signed Owner session, current graph grant, Authority fence, replay identity, and final Graph CAS. The lifecycle callback uses the transaction already owned by W01; it does not nest `BEGIN`.
- `cancel_job` writes the actual runtime cancellation epoch/fence and its `runtime.job` graph projection in the same business transaction. Unknown expenses are not settled or zeroed. The result distinguishes cancellation from a draining worker. Unsupported lifecycle/domain controls report an installed prerequisite before opening an Owner write attempt.
- The administrator-only relocation manifest registry resolves opaque manifest/target references. V1 supports complete-namespace, same-Authority relocation and no implicit loss. It verifies current source epochs, actual closed table inventory, catalogue/schema, current target reservation, and original plan. Browser data never supplies a `MigrationPlanV2`, file path, current authority proof, or successful receipt.
- The concrete local transfer factory uses actual `AuthorityV2MigrationService`, source verifier, target recovery verifier, target graph import, and execution/model reconciliation. Source and target management identities are separate. The order is freeze → source snapshot → source revocation → target preparation → real import/recovery → target activation.
- Accepted execution is registered in Authority before freeze. Subsequent progress originals live in Authority, not the frozen source Graph. This preserves the exact source snapshot during status refresh, unknown-response recovery, and replay. A lost committed activation ACK is resolved from the original transfer; no second transfer or blind rollback is issued.
- The actual final target activation Core transaction rechecks its original target lease, current pairing, holder, generation, incarnation, and transfer binding. This uses the caller's existing Core transaction without new locks, RPC, or `BEGIN`. The lease becomes `active` in that same transaction; its initial reservation expiry is historical after activation.
- A separate `D12TargetOwnerAdmissionV1` preserves the source immutable Owner grant/proof and unchanged Authority Owner head. It binds the actual activated/import receipts to the target installation, holder, generation, revocation epoch, and graph incarnation. A separately administrator-paired target key and freshly signed target Owner session are required. Source private keys and sessions are never copied.
- The current target Owner can obtain a real target Graph lease/query through that admission. Target and source grant JSON remain byte-identical. Target exact-operation status access is authorized through the admission's same-principal migration chain, not the old source session.
- Background target authority is a distinct installed-peer/current-fence read. It requires an existing admission created by a real signed target login, current actor/key registration and credential epoch, unchanged Owner head, and current target Graph/import. It does not use or extend a browser session. Browser logout ends signed workbench access; actual key/pairing/Owner or namespace revocation blocks background access.
- `read_backend_operation` has an explicit operation-only W09 admission path. It is never a fallback from failed content authentication. Existing local signed-login username/cookie binding, independent Authority status authentication, Origin, and CSRF are retained. The temporary session grants only `workbench.operation_status` and is pinned to one `backend_operation_ref`.

## Exact RuntimeContext integration

On the existing installed coordinator and bootstrap, before exposing W09:

```python
backend = install_d12_services_v1(
    coordinator, bootstrap=bootstrap,
    transfer_port=administrator_paired_transfer_port_or_none,
    operation_status_port=installed_status_port_or_none,
    domain_controls=registered_domain_controls,
    lifecycle_control_port=installed_lifecycle_control_port_or_none,
)
```

The factory returns `WorkbenchLifecyclePortV1`. It creates `InstalledD12OperationStatusPortV1` against the same paired V2 port when one is not supplied. `None` transfer pairing means a truthful `installed_transfer_pairing_unavailable` prerequisite; ordinary installed job control remains usable.

Pass exactly that object as `backend_operation_port` to `AsyncGraphWorkbenchService`/`GraphWorkbenchIssuer`, and `backend.operation_status_port` as the new `operation_status_port` argument of `BoundOwnerSessions`. It must not be replaced by a request-created port. The installed target workbench grant resolver must use the current target generation, rather than a hardcoded source generation 1.

`prepare_transfer` additionally exposes a fenced `d12.transfer_preview.v1` projection containing the exact `d12.transfer_expected_epochs.v1` CAS fields and server-selected target lease reference. The original remains the public typed operation original.

## Authority construction and routes

### Original operation status

```python
status = InstalledD12OperationStatusServiceV1(
    fences=current_namespace_fence_service,
    owner_tickets=same_core_owner_ticket_store,
    source_graph_db=administrator_pinned_source_graph_path,
    namespace_id=namespace_id,
    installation_id=source_installation_id,
    migration=actual_namespace_migration_service,
)
```

Installer only: `status.install_schema(administrator_credential)`.

At every daemon composition: `install_d12_operation_status_service_v1(server, status)`.

`AuthorityServer._v2_command` dispatches `dispatch_d12_operation_status_v1(server, method, credential, profile_id, manifest_digest, command)` before other branches; a non-`None` return is the response. Supported methods are `d12_register_operation_v1`, `d12_resolve_operation_v1`, and `d12_read_operation_v1`. The dispatcher verifies the actual installed mTLS peer/profile/manifest/namespace and session identity. It does not accept paths or plan/receipt bodies.

### Target Owner admission

```python
target_owner = InstalledD12TargetOwnerAdmissionServiceV1(
    migration=actual_namespace_migration_service,
    owner_tickets=same_core_owner_ticket_store,
    target_graph_db=administrator_pinned_target_graph_path,
    namespace_id=namespace_id,
    target_installation_id=target_installation_id,
    target_holder=target_holder,
    policy_ref=administrator_target_owner_policy_ref,
    policy_digest=administrator_target_owner_policy_digest,
    operation_status_service=status,
)
```

Installer only: `target_owner.install_schema(administrator_credential)`.

At daemon composition: `install_d12_target_owner_service_v1(server, target_owner)`. The source status service must already be installed. This adds the explicit target-principal exact-status route; no arbitrary cross-installation alias is created.

`dispatch_d12_target_owner_v1(...)` supports `d12_current_owner_authority_for_fence_v1` and `d12_current_background_owner_authority_for_fence_v1`. It returns an unchanged source Owner guard plus an optional, independently reread typed admission and the exact permit. Source installations explicitly retain the ordinary existing guard route. A configured target admission failure never falls back to source admission.

Host forwarding helpers are in `host/d12_target_owner_port_v1.py`. Shared GraphCoordinator/port integration is owned by the backend integrator. The Graph binding adds an optional typed `target_admission`; all original grant/proof integrity, source permissions, purpose, audience, and Owner-head checks remain. Only location comparisons can use the current independently verified admission. `BoundOwnerSessions._view_matches` accepts this explicit qualified target alternative.

### Administrator target reservations and local transfer factory

`InstalledD12TargetRegistryV1(pairing_registry=actual_InstalledMigrationPairingRegistry, target_leases=typed_tuple, utc_clock=trusted_UTC_clock)` owns actual Core reservations. Installation invokes `install_schema` and `register` with administrator credentials; reopening must re-read original rows, not register them again.

Each `D12TargetLeaseOriginalV1` contains: opaque `lease_ref`, `target_ref`; Authority namespace and typed Graph namespace; target installation and holder; fixed target graph incarnation and administrator absolute graph path; exact schema/catalogue digests; UTC reservation expiry; installed policy ref/digest. The graph path is never exposed as a browser upload/download destination. Registration independently verifies an isolated empty target schema and inventory.

`install_d12_isolated_target_schema_v1(graph_db, registry, schema_fence_port, holder)` is installer-only. It uses the current installed constructors to build the full schema, then closes the schema-only coordinator. It never copies source DDL, issues a target content lease, or uses a legacy core.

`InstalledD12TransferManifestV1` contains the opaque manifest reference, source identities/holder, target reference, exactly `("namespace:bot/persona",)`-style full namespace selection, source schema/catalogue digests, and installed policy ref/digest. Loss coverage is empty for this complete relocation version.

`install_local_d12_transfer_port_v1` requires the actual source Graph and recovery capability, source path, real migration service, these manifests and target registry, separately authorized source/target management credentials and subjects, and optional actual model ledger. It constructs the real import/reconciliation/final lease gate. This local factory does not invent remote peers, target credentials, or a transport across process boundaries. Separate-process/remote deployment must supply the corresponding explicitly paired management transport; otherwise it remains HOLD.

## New Core tables and C09 obligations

1. `authority_d12_operation_originals_v1`
   - Columns: `authority_namespace`, `operation_id`, `original_ref` (PK), `original_json`, `actor`, `session_request_json`, `owner_head`, `plan_json`, `source_original_ref`
   - No bearer token or private key is saved. `session_request_json` is the public login identity selector. Plan and originals are content-free metadata but still namespace-owned and grant/epoch-bound
   - Validate originals with `decode_original`, exact row identity, canonical plan digest, original migration plan, and Owner head before preserving an unaffected namespace. Affected namespace rows must be retired/removed with their D12 graph originals; do not let an old snapshot, grant, or status record grant current admission after C09
2. `authority_d12_target_leases_v1`
   - Columns: `lease_ref` (PK), `record_json`, `state` (`reserved` or `active`), `transfer_id` (nullable before claim)
   - Decode only `D12TargetLeaseOriginalV1`; namespace comes from its typed record. Check exact configured registration, actual pairing, and transfer relationship. A revoked/expired/rebased reservation is not automatically renewed. Target paths are managed storage surfaces, not harmless text whose referenced data may be skipped
3. `authority_d12_target_owner_admissions_v1`
   - Columns: `authority_namespace`, `target_installation_id`, `original_ref` (PK), `original_digest`, `original_json`
   - Decode only `D12TargetOwnerAdmissionV1`, recompute digest, verify row identity and actual transfer/import/Owner-head lineage. Its generation/incarnation and key/actor epoch are current-admission dependencies. It cannot be copied into a new C09 cohort and treated as current merely because it is content-free

Administrator-only actions: `d12_operation_install`, `d12_target_install`, `d12_target_register`, `d12_target_owner_install`. Installed peer action: `d12_operation_status`. Current target Owner/background reads still authenticate through existing `read`/`write` fence actions and independently current identity checks; no generic administrator action is exposed to the browser.

## Acceptance and unverified boundaries

Executed with `PYTHONPATH=rewrite ../../venv/bin/python -m pytest -q` on:

- `rewrite/tests/alpha1/d12/test_installed_lifecycle_services_v1.py`
- `rewrite/tests/alpha1/d12/test_lifecycle_status_transport_v1.py`
- `rewrite/tests/alpha1/d12/test_workbench_http_transport.py`
- `rewrite/tests/alpha1/d12/test_workbench_service.py`
- `rewrite/tests/alpha1/d12/test_owner_session_resolver.py`

Result: **51 passed**, including target key/session/Graph admission, lost activation ACK, unchanged grant bytes, exact target status, logout distinction, and key-revocation denial. Final verification is rerun after subsequent integration changes. These are local isolated real-store/crypto checks; the W09 routing test is explicitly a transport-boundary test, not a real TLS/browser installation.

Ruff F821/F822/F823 passed for the changed D12/runtime/Host/Authority/workbench modules. New modules are also syntax-compiled; final verification follows subsequent integration changes.

Still distinct/not claimed complete:

- Remote/independent-process migration management transport and daemon/administrator configuration assembly, target C09 four-path current-pointer bootstrap, and full target autonomous product workflow. The integrator owns those shared interfaces
- A later C09 rebase after migration must derive fresh location admission from the actual RELEASED continuation lineage plus original migration/Owner provenance. Exact old migration generation/incarnation must not be accepted as a shortcut
- Maintenance upgrade/quiesce/qualified backup/shadow migration/activate/rollback executor. The existing Linux CLI is fresh-install-only and cannot be presented as an upgrade executor. Maintenance package verification now uses the central backend runtime qualifier and truthfully distinguishes formal vs backend-production-acceptance; this does not itself implement the executor
- General backup/share/import artifact producers, richer support exports, and general isolated experiments remain dependent on their real installed producers. Full database bytes are never relabeled as a redacted support archive
- Pause/disable/retire/uninstall and arbitrary domain configuration require actual registered lifecycle/domain controls. They are not implemented as UI flags or advertised as complete because a method name exists

## 04:50 UTC follow-on: whole-Host control, post-C09 target qualification

The earlier remaining-boundary list is superseded only for the concrete items
below. General role configuration/disable/retire/uninstall and maintenance
upgrade/rollback are still distinct unfinished producers.

### Independent whole-Host service assembly

```python
supervisor = InstalledD12SystemdSupervisorV1(config=D12SystemdSupervisorConfigV1(
    unit_name=administrator_exact_host_service,
    systemctl_path=administrator_exact_systemctl_path,
    unit_fragment_path=administrator_exact_unit_fragment,
    unit_fragment_sha256=administrator_pinned_unit_sha256,
    control_group=administrator_exact_cgroup,
    timeout_seconds=60,
))
lifecycle = InstalledD12InstallationLifecycleV1(
    status_service=actual_same_core_d12_status_service,
    control=actual_current_C09StorageControlV1,
    supervisor=supervisor,
    package_root=administrator_exact_current_package_root,
    expected_manifest_digest=administrator_pinned_manifest_sha256,
    peer_certificate_sha256=installed_host_peer_sha256,
    peer_profile_id=installed_host_profile_id,
    model_store=actual_same_core_model_ledger,
    drain_timeout_seconds=300,
)
```

The package pin above is the central qualifier's **bare** 64-digit SHA256.
The control service requires an explicitly single-Owner namespace cohort; it
cannot authorize stopping unrelated roles through one role's Owner command.
Installer calls `lifecycle.install_schema(administrator_credential)` once.
Reopening installs `install_d12_installation_lifecycle_v1(server, lifecycle)`;
after the daemon is fully assembled, call `resume_pending_operations_v1()`.
Before closing Core/journals, call `lifecycle.close()` and let the original bounded
supervisor action finish. It does not delete live fences to make shutdown pass.

The dispatcher is
`dispatch_d12_installation_lifecycle_v1(server, method, credential, profile_id,
manifest_digest, command)`. Nonmatching methods return `None`.

- `d12_installation_control_v1`: actions `inspect`, `submit`, `status`,
  `continue`, and `resume`. Every action has actual installed
  `namespace`/mTLS peer/profile/manifest binding and a current signed Owner
  actor/session request/token. `submit` names one exact previously registered
  control original; `status`/`continue` names one operation; `resume` names the
  exact pause operation plus a fresh operation UUID4 and expected lifecycle epoch
- `d12_lifecycle_host_bootstrap_v1`: exact installed peer/profile plus
  `operation_id`, `expected_epoch`, `process_id`, `invocation_id`,
  `catalogue_hash`, `ready_domains`. PID/birth/systemd MainPID+cgroup+InvocationID,
  actual native mapped inode, qualified package, current Graph and retained
  ledger constraints are independently re-read. These JSON fields alone never
  establish readiness
- Existing `d12_read_operation_v1` and `d12_resolve_operation_v1` remain exact
  status-only routes. Registration still requires a real content fence, so it
  must occur before the head closes ordinary admissions

The management/status/bootstrap methods must not depend on the stopped old
Host's C09 peer-process gate. They have their own narrow installed/session or
bootstrap checks above. All ordinary content methods retain their C09 gate.
Wrap ordinary RPC execution in the matching service's `rpc_activity_v1()` so
the final stop stage observes actual outstanding handlers; do not count these
independent management/status/bootstrap calls as business RPCs.

Core policy actions are `d12_lifecycle_install` (administrator only),
`d12_lifecycle_control` and `d12_lifecycle_bootstrap` (exact installed peer).
Do not grant either latter action to an arbitrary browser request identity.
The independent paired CLI/console must remain available when W09 stops; the
ordinary W09 page alone cannot resume itself.

### Shared admission hooks

`require_lifecycle_admission_in_tx_v1(db, namespace, *, action,
original_claimed=False, bootstrap=False, expected_epoch=None)` belongs in the
**existing Core transaction** that grants a new Graph/job/model/dispatch/handoff
claim. A persisted already-claimed lookup by the owning subsystem may pass
`original_claimed=True` for `terminal`, `accounting`, or `original_inspection`.
A prepared row alone is not a claim. Do not derive this boolean from RPC JSON.
Only `host_bootstrap`, `recovery_read`, and `recovery_accounting` may use explicit
`bootstrap=True` while `resuming`. A lifecycle status read grants no work.

`require_lifecycle_exclusion_in_tx_v1(db, namespace, *, operation)` rejects a
non-active lifecycle for competing C09, migration, upgrade, and revoke. The
respective command must also establish its actual independent current state;
this helper is an exclusion, not a grant.

Phases are `active → quiescing → drained → paused → resuming → active`, with
immutable `stop_intent`, `start_intent`, and `ready` intermediate receipts.
The business activation generation does not change. `start_intent` recovery
never issues a second start: it waits for the original actual new bootstrap.
An unresolved start or missing native readiness remains pending confirmation.
An administrator needs the original supervisor invocation evidence to resolve
an ambiguous not-started/started outcome; no retry guesses success.

### Four lifecycle Core schemas and C09

Exact columns are centralized in `authority_service/d12_c09_core_rows_v1.py`:

- `authority_d12_lifecycle_heads_v1`: namespace, installation_id, state, epoch,
  operation_id, head_digest, current_receipt_ref
- `authority_d12_lifecycle_operations_v1`: namespace, operation_id,
  request_digest, action, source_original_ref, source_original_json, intent_json,
  actor, session_request_json, owner_head, storage_json, initial_supervisor_json,
  initial_process_json, current_stage, current_receipt_ref, hold_code
- `authority_d12_lifecycle_receipts_v1`: namespace, operation_id, stage,
  original_ref, original_digest, original_json
- `authority_d12_lifecycle_bootstraps_v1`: namespace, epoch, operation_id,
  peer_certificate_sha256, peer_profile_id, process_json, invocation_id,
  manifest_digest, graph_head_digest, constraint_digest, original_ref,
  original_digest

C09 validates every typed row, including unaffected namespaces, before copying.
Affected operation/receipt/bootstrap originals are retired with consumed
commitments. Affected active heads receive a fresh lifecycle epoch under the
actual C09 transition; nonactive heads forbid a competing C09. Retired Graph
source operation references are also consumed, so old copied originals cannot
be re-registered in the new cohort.

A target signed-admission original may additionally carry
`source_lifecycle_head_digest`, `source_lifecycle_epoch`, and
`target_lifecycle_epoch`. Once actual activated transfer, imported/current
Graph, unchanged source Owner head and fresh target key/session are verified in
one Core transaction, an active source lifecycle head can CAS to the target at
epoch+1. The original commits the prior head. Unrelated, paused or unfinished
heads cannot be adopted; no configured head means no lifecycle feature is
invented. Future signed rereads preserve the original relocation commitment.

For a target after C09, construct
`InstalledD12C09TargetContinuationReaderV1(control=actual_control,
close_apply=actual_InstalledC09CloseApplyV1)` and inject it as
`storage_continuation_reader` into target Owner service. The control must have
that same actual applied reader installed. It validates current RELEASED and
applied proofs, actual selected Graph and full protected certificate ancestry
back to the activated import. This is implemented, but a complete released-C09
plus target-login acceptance has not yet been run here.

### W09 read/control contract

`read_installation_lifecycle` takes empty input, Owner audience, and purpose
`audit` or `workbench_view`. Actual signed current Owner needs both
`workbench.read` and `workbench.control`. A ready projection is exactly:

```json
{"schema":"d12.installation_lifecycle_view.v1","scope":"whole_host",
 "installation_id":"<current installed identity>","state":"active",
 "lifecycle_epoch":0,"head_digest":"sha256:<digest>","operation_id":null}
```

The browser submits `configure_or_control` with a stable operation UUID4 and:

```json
{"object_ref":"installation:<current installed identity>","control":"pause",
 "test_intent":null,"config_diff":{"schema":"d12.installation_control.v1",
 "scope":"whole_host","expected_lifecycle_epoch":0,"prior_pause_operation_id":null}}
```

Backend independently requires both current control and maintain capabilities.
No process action occurs in the W01 SQL transaction. The accepted original is
registered with Authority before quiescing begins. Exact operation replay reads
current independent status rather than trying an old-epoch Graph command.
`result.effective_version` is lifecycle epoch; `domain_receipt_refs` contains
actual stage originals. `coverage` `stage:paused` plus completed is the actual
stop outcome; running/pending confirmation must remain visibly unfinished.

### Follow-on executed acceptance

At 04:50 UTC the previous five focused files plus
`test_installation_lifecycle_v1.py` passed: **52 passed in 8.76s**.
The new permanent test uses actual signed Owner/Graph/Core/both journals/signed
four-file pointer and real subprocess birth/retirement. It checks in-flight RPC
drain, new-admission denials, claimed accounting allowance, pause completion,
unchanged business generation, exact changed-request refusal, one-start resume
replay, unqualified native/bootstrap HOLD, logout denial, and all installed D12
Core row codecs. Its systemd boundary is explicitly a local-process fixture;
it is not a privileged installed systemd or real native Host acceptance.

The canonical target schema constructor is
`runtime/d12_installed_graph_schema_v1.py`; fresh production source and isolated
target both call the same actual constructors. No source sqlite_master SQL is
copied. The separate D04 actual authored-root/coupling transfer acceptance also
passed after this repair; that result is reported by its owning workstream.

## C11 compatible package replacement decision (implementation still pending)

The accepted bounded lane is a separately versioned
`compatible_package_switch`. Existing V1's mandatory `migrate_shadow` cannot be
satisfied by calling the current Graph a shadow or inventing a mapping receipt.
Its Host Graph-backed orchestrator does not survive a real whole-Host stop.

The required V2 sequence is independent Authority/supervisor accepted original
(Owner/request/old+new manifests/compatibility plan), staged verified bytes,
shared lifecycle/C09/migration exclusion, actual drain+old cgroup retirement,
consistent managed recovery backup, independent full compatibility proof,
durable switch intent, atomic root-owned package-pointer switch outside SQL,
fresh bootstrap-only Host, actual qualified Python/native ABI2+thirteen-domain
composition/current-storage reread, then activation receipt and admission release.
If replacing Authority itself, a separate supervisor must own restart and
continuation. The killed process cannot finish its own operation.

Compatibility must cover exact four-file pointer/cohort, schemas/catalogue/type
authorities, journal formats/hash semantics/decoders, Owner and installation
identities, active resource/policy/numerical assets, and every current/unknown
historical original. Equal `schema_version` is insufficient. This lane cannot
mutate business data or schema. Incompatible changes remain HOLD pending a
separate real shadow migration and qualified storage/location transition.

Backups use actual SQLite backup/checkpoint/WAL semantics and carry Graph
revision/incarnation, Core identity, both journal IDs/seq/digests, Owner,
deletion/unknown/budget constraints, managed file paths/lengths/hashes, creation
operation and restore qualification. They are protected C09-inventoried recovery
artifacts, never redacted support exports and never permission to restore old
independent journals. Any post-backup terminal remains current truth.

Filesystem selection and Core cannot commit atomically together. Persist the
old/desired pointer intent, switch outside SQL, reread the actual pointer and
loaded process manifest, then append the observed receipt. A third pointer,
unknown process, or ambiguous start stays HOLD; it does not authorize another
start or blind rollback. Advance independent package/lifecycle epoch, preserving
business generation and immutable Owner grant for this compatible same-location
lane. Retired manifest/process identities must lose admission.

Package rollback first retires the candidate, independently qualifies the last
supported alpha package against **current** four files and current journal
heads, then selects and starts a fresh bootstrap-only process. It never rewinds
Core/deletion/execution. After new business writes, rollback remains possible
only if the old package truly reads all resulting current data. Restoring a
business snapshot needs separate replay/inverse mapping preserving every later
event/tombstone/permission/unknown effect; otherwise stay stopped for repair.
Retired v1/v2 core is never reactivated.

Receipts distinguish `prepared`, `stopped`, `backup_ready`,
`compatible_no_data_migration`, `package_switched`, `bootstrap_ready`, `active`,
`rollback_complete`, and `unknown`, bound to exact operation/lifecycle epoch,
old/new package hashes, current storage/Owner/journal heads, old/new birth and
invocation, compatibility/backup proofs and prior-stage commitment. Accepted
bounded maintenance may outlive a browser session; new activation still denies
current Owner/key/namespace revocation, and exact status requires fresh current
signed authentication. No V2 implementation or deployment is claimed here.

### 07:43 UTC: metered root execution and maintenance acceptance checkpoint

The dedicated authored-root Authority service, contracts and journal discriminator are now in `authority_service/d04_root_execution_{contract,journal,bridge,service,rpc}_v3.py`. Root and joint work share the actual independent namespace journal and exclusion, but their bindings, mutation IDs, signatures, artifact codecs and recovery services remain distinct. Root claim admission independently rereads the actual reserved Owner preparation after acquiring its exclusive permit. Journal commit precedes Core gate consumption/head reconciliation. A measured failure retains actual thread CPU; a completed measurement without retainable artifact has an explicit cost-only closure and cannot authorize adoption.

The paired Host now uses a separate freshly authenticated mTLS channel for each numeric/root high-level RPC. It reads a real server-issued installation grant and compares every stable identity field. A first-claim ACK loss remains inspection-only. Technical append/terminal retries keep the original binding and claim. Bounded restoration keeps the existing 64 KiB frame profile, transfers at most 32 MiB in 24 KiB raw pieces, and renews real pairing between frames before the server's fixed 30-second session lifetime expires. Every piece rechecks actual current source/Owner/storage qualification; no server body cache or fake renewed grant is used.

Actual installed root acceptance on snapshot `snapshot-0736` (manifest `85135e1c20e94ffe1c7b334c588acb1433f389411ce58c03c375ee090b60c83d`) passed **2 tests in 83.62 seconds**. The positive case used an explicitly signed local 60,000 ms CPU allowance, then proved one real native execution, a durable measured terminal, current qualified cold read, native-forbidden execution/adoption replay, one transaction for head + actual cost + six root writes, and independent finish/repeated finish. The 900 ms case retained the actual bounded failure expense, denied adoption, settled the overrun historically, and replayed without another charge. No production budget default was increased. Log: `../../verification/d04-root-cpu-0736.log`. Public W09 root routing is integrated separately by the Graph owner; this result does not itself attest a privileged deployment.

The same-principal lifecycle key continuation acceptance passed **1 test in 4.13 seconds**. It revoked/re-enrolled the real current key/actor, denied the old session, permitted a fresh signed same-principal session to read the exact original pause without rewriting its initiating bytes, and recorded the new key request in a new resume operation. The actual process started once. This case deliberately remains unqualified-native bootstrap-only; it is not a positive deployed Host readiness claim.

C11 V2 now has typed compatible-package intent and receipt contracts in `d12_package_maintenance_contract_v2.py`, and concrete acceptance/current-status/pre-stop supervisor reads in `d12_package_maintenance_authority_v2.py` and `d12_package_maintenance_rpc_v2.py` (compile/F821 only at this checkpoint). Acceptance reads the protected registered code/configuration cohorts and actual current signed Owner/Graph under an exclusive permit, then atomically persists the immutable acceptance and closes lifecycle admission. It performs no OS stop/copy/switch and does not launch the V1 Host-only pause worker. The exact single-Owner namespace cohort is required. The separate protected supervisor owns both-process retirement, coherent backup, candidate compatibility, package/configuration selection CAS and restart. Its actual journal/readiness integration and final activation are still required; the typed intent is not an authorization substitute or a completed maintenance receipt.

### 08:58 UTC follow-on: real bootstrap, source storage continuation and managed backups

The actual pinned Host lifecycle acceptance passed (1 test, 20.15 s;
`verification/d12-actual-bootstrap-0757.log`). It starts a new real subprocess,
loads the selected native ABI2 and thirteen-domain catalogue, uses actual paired
mTLS bootstrap, proves ready-to-active CAS and exact bootstrap replay, rejects a
wrong invocation, then admits a normal signed Owner fence. The subprocess
supervisor is an explicit test boundary; this is not privileged systemd
installation acceptance.

`InstalledD12OwnerStorageAdmissionServiceV1` now derives same-installation
Owner location from actual signed C09 PREPARED/RELEASED/applied originals and the
current Graph certificate ancestry while keeping the rev1 grant and Owner proof
unchanged. Current storage/Core qualification occurs before Graph BEGIN and is
repeated after closing that snapshot. Graph, mapping and topology integration
is compiled; the full four-store RELEASED plus fresh source Owner acceptance
remains a separate required check.

The compatible-package lane now has a fixed `read_supervisor_backup_source`
paired read. It authenticates the accepted operation/current Owner, closes new
admission through the real lifecycle head, checks zero live fences/pending
mutations, authenticates actual journal/history originals, and reads all four
logical row/DDL inventories under the actual ordered writer locks. SQL snapshots
are sequential, with short Core checks before/after Graph reads. The response
is capped at 48 KiB and includes the concrete historical manifest inventory.
It cannot stop a process, copy storage, change selection or confer restore
permission.

`InstalledD12ManagedBackupV2` consumes that independently signed supervisor
observation only after both actual fixed units retire and the genuine C09 OS
lease is reacquired. It verifies the protected selected configuration, instance
lock path, C09 control identity and pinned managed directory, uses SQLite backup
including committed WAL, and requires exact logical equality to the qualified
source. Complete same-operation files can be independently recovered after an
ACK loss; changed/incomplete/unregistered files HOLD and are never overwritten.
All resulting snapshots have `restore_authorized=False`.

`InstalledD12ManagedBackupCleanupV2` implements the separately versioned
revoke-then-destroy disposition. Every registered backup execution row, prior
redacted frame, model unit obligation and immutable budget receipt must be
covered by the current actual sanitized C09 recovery inventory before a durable
pending-destruction plan is recorded. Only then are exact registered bytes
unlinked, parent directories fsynced and actual absence reread. Content-free
registration/coverage/destruction originals remain. No current journal is
restored or rewound, and unknown managed files keep cleanup held.

Two permanent component tests passed (1.18 s): real SQLite ACK recovery rejects
a later terminal without overwrite; actual budget ledger coverage rejects lost
unknown occupancy, removed immutable receipts and erased overrun expense.
The protected supervisor, candidate compatibility producer, startup/bootstrap
and complete maintenance activation are still required integration work.
Until those concrete producers are ready, acceptance remains HOLD before the
live installation is changed to quiescing.

## 10:37 UTC follow-on: actual package forward and pre-switch abort

The earlier 08:58 integration gaps above are superseded by these concrete
results. The permanent `integration/test_d12_package_process_v2.py` exercises
production Owner/Core/journal/Graph, mTLS, supervisor signatures, SQLite backup,
candidate decoder, package-selection CAS, process birth/retirement, actual
native loading, thirteen-domain readiness and admission receipts. Its explicitly
isolated boundary remaps root-owned locations and systemd to private test paths
and real subprocess groups. This is not privileged Linux deployment acceptance.
It performs no external model/provider/platform call.

- Forward compatible switch passed: **1 case, 71.01 s**; external log
  `verification/c11-process-forward-1035.log`, fixture/package pair
  `build/c11-whole-1034`. Source manifest
  `9650d72f596321bf8eec3e01cced4551a877f77127ba6c0ddc430d8596458437`,
  candidate manifest
  `b0423fafbed18573962a90ffb109a45d5cf5adb89472125e4e2ea64bcdd46f59`.
  The registered candidate changes documentation, with the actual complete
  runtime AST, semantic resources and native interpretation remaining compatible.
  The chain reached signed `active`, then a fresh external executor returned the
  exact original receipt without another pointer revision or process start.
- An independently built, genuinely different Python AST candidate was rejected
  before switching. The pre-switch abort case passed: **1 case, 67.78 s**;
  `verification/c11-process-abort-1032.log`, `build/c11-whole-1025/actual-abort`.
  Both old units retired; the actual current-data abort source was qualified;
  fresh old-package Authority and native/thirteen-domain Host bootstraps returned
  admission to active with selection revision/package epoch still zero. A fresh
  executor replay returned the same final receipt without another start.
- The failed-candidate post-switch rollback case is a separate required run and
  was started after those results. Neither forward nor abort establishes it.

The first actual source projection exposed a strict codec mismatch: its original
hash includes the typed `NamespaceId`, while the decoder had flattened it before
recomputing the hash. The decoder now preserves the original typed material;
a focused tamper-negative roundtrip plus the two existing managed-backup
components passed together (**3 cases, 1.20 s**). Actual WAL-aware candidate
verification also demonstrated that SQLite read-only connections change SHM
read marks. DB/WAL/journal fingerprints and complete logical roots remain exact;
SHM checks retain path, device/inode and bounded valid size, excluding only its
mutable read-mark bytes/mtime, with the held lease and both stopped units rechecked.

Fresh signed source Owner admission after actual C09 RELEASED now joins all
three real transitions: signed storage rebase, exact closed mutation/journal
receipt, and actual scoped-applied Core event plus Graph ACK. It preserves the
immutable rev1 Owner grant. The retained real four-store fixture passed ordinary
survivor read and access-revoke write (`verification/c09-owner-after-release-1032.log`).
A new full release run and repeated-C09 ancestry remain distinct acceptance
boundaries; another erasure must join its exact pending/accepted originals rather
than relax epoch equality.

W09 provides explicit `read_package_maintenance`, `accept_package_switch` and
exact-operation `read_package_operation` actions through the same concrete paired
port. Accepted status distinguishes `awaiting_privileged_executor` from actual
active readiness. Existing W09 regression tests passed 49/6.66 s; two dedicated
HTTP status-authentication boundary tests passed 2/1.14 s. The original V1 shadow
migration lane remains unavailable without an actual shadow executor; this V2
lane does not claim arbitrary schema or interpretation-changing upgrades.

### 10:41 UTC completion of the current-data rollback acceptance

The permanent failed-candidate rollback case passed **1/188.54 s** on the same
`build/c11-whole-1034` pair (`verification/c11-process-rollback-1037.log`). The
candidate actually opened the current Core and rotated its process-session
bootstrap original, then exited before listening. The external executor kept
business admission closed, retired that invocation, independently qualified the
current four stores offline, produced a new rollback backup, qualified the old
package against that current data, and switched to selection revision/package
epoch 2. Fresh Authority and native/thirteen-domain Host originals preceded
`rollback_complete`. The test reread the immutable activation over a fresh mTLS
channel and replayed a new external executor with no additional start, selection
revision, or activation row. No old database or journal snapshot was restored.

The abort case was also repeated on this latest package family with an explicit
activation-RPC replay: **1/59.81 s**, `verification/c11-process-abort-1041.log`.
Thus forward, pre-switch abort and failed-candidate current-data rollback each
have actual process acceptance, subject to the explicit isolated OS boundary.
