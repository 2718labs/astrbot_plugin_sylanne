# D04 Owner semantic installation V3

Implementation contract, 2026-09-30. This document is not an acceptance result or an Owner selection.

## Installed asset and explicit first use

`resources/catalogue/d04-semantic-mapping-profile.v3.json` is an engineering, psychologically unvalidated profile. The release manifest must contain its exact `semantic_mapping_profile` binding and file row. The profile also pins the authored-root preset digest, so a reused preset ID/version cannot replace its blocks or mathematical assets.

The profile contains eight source-labelled authored direction examples, the complete 24-axis basis, eight explicit `anticipated_impact` rules with `(0.125, 0.0625, 0.03125)` gains, family L1 cap `2.0`, and these exact template shares:

- `feeling.initial.v3`: `0.5`
- `feeling.initial.secondary.v3`: `0.25`
- `mood.initial.v3`: `0.25`

The Workbench must show the actual profile and its engineering-unvalidated status before the Owner selects it. It must not silently initialize the mapping, choose a rate, infer missing block shares, or treat a digest submission as authority. Missing/repeated templates, extra roots, invalid members, unsynchronized cursors, unsupported old checkpoints, changed D01 role, revoked Owner pairing and changed installed bytes all hold.

## Composition API

Create `InstalledD04SemanticMappingReaderV3(graph, package_root, manifest_sha256)` only from the installed package's own code. Register it as the coordinator's private `__d04_semantic_mapping_reader`. Provision `install_d04_semantic_installation_schema_v3(db)` in the existing business database. The function also provisions the D11 clock originals and the durable Owner operation attempts.

For an ordinary current product transaction:

1. Obtain the actual Authority read/write permit and `FenceScope`
2. Enter `with reader.current_fence(scope)` before SQL `BEGIN`
3. Hold the existing GraphStore lock and transaction while invoking `reader(db, namespace)`, `reader.current_role_condition(db, namespace)` and `reader.current_role_clock_identity(db, namespace)`
4. Finish the actual Authority fence outside the business lock

The reader returns `InstalledD04SemanticMappingV3`. It derives exact current role scope and member refs from real graph rows, verifies each root's signed D11 freeze and immutable root/history provenance, and replays the latest signed semantic acceptance. Neither request DTOs nor canonical digest agreement creates this authority.

## Owner commands

`adopt_current_d04_semantic_mapping_v3(authority, lease, operation_id, profile_digest, expected_revision)` requires the actual signed current Owner session and `workbench.activate`. The command derives the bound asset and all actual member shares, writes a signed immutable acceptance, and advances Graph recovery metadata in the same fenced transaction. Its UUID operation is replayable; another payload under the same UUID conflicts. A current Owner can explicitly reselect an obsolete acceptance, but an ordinary product read cannot bypass its revoked accepting Owner.

`register_current_d11_role_clock_v1(authority, lease, **request)` requires these explicit fields:

- `operation_id`: canonical UUID4
- `expected_version`: exact nonnegative integer, `0` for first registration
- `character_origin`, `rate`: exact decimal strings; rate must be positive
- `wall_origin_utc`, `valid_from_utc`, `valid_until_utc`: explicit timestamp strings with timezone

The character origin must equal every actual current checkpoint cursor. The independently read installed wall clock must fall inside validity, and the wall origin cannot be in the future. A replacement must agree with the previous registered clock at its origin. The operation uses `issue_clock_mapping` and writes a signed immutable original; bare clock rows never satisfy the installed reader.

Durable attempt IDs retain the original Graph/Authority pin across a lost begin acknowledgement. A committed result retained in the same SQLite transaction permits finishing an interrupted original fence; replay never creates a second acceptance or budget effect.

## Permanent acceptance

`rewrite/tests/alpha1/integration/test_d04_owner_semantic_initialization_v3.py` exercises real signed Owner/mTLS/D01 initialization, the real D04 draft and budget producers, installed ABI2 root adoption, explicit semantic/clock adoption, exact replay, immutable storage, changed assets/member validity/clock policy, fresh GraphStore reopening and actual Owner-key revocation. It needs `SYLANNE_D04_INSTALLED_ROOT` and imports runtime code from that extracted package's `rewrite` directory. It does not seed an adopted root or fabricate an Owner guard.

The complementary `test_d04_owner_root_initialization_v3.py` checks preservation of an existing D09 draft and the real parent/child budget split. Passing these tests alone does not establish paid appraisal, complete family drive, full/LOO numeric advance, cross-platform delivery or psychological calibration.

### Executed evidence (2026-09-30 04:22 UTC)

The permanent `test_true_owner_root_mapping_clock_and_rejection_boundaries` passed against extracted installed runtime code, with the real local Authority/Owner path and actual native ABI2, in 29.37 seconds. ZIP SHA-256: `b0820e4fdaf0e0461888964ff67b9ec57869cf27edc85940909adca007bc8091`; manifest SHA-256: `0bff5c813b2f4090f560eaeb19d918ed9d8bd17a017bd2ec6391e687b8f4430d`.

This proves that exact development-candidate snapshot's root/mapping/clock path and the negative/reopen checks named above. It is not a final delivery pin, a topology lifecycle acceptance, a paid appraisal/drive/full-LOO advance result, or a formal release. Subsequent source changes need a fresh package and the applicable permanent acceptance again.

### Unified permanent acceptance (2026-09-30 04:31 UTC snapshot)

Both permanent integration files passed together: **3 passed in 76.13 seconds**. This snapshot includes exact attempt-ID CAS hardening and the independent topology verifier's historical-draft and Owner/event/permit replay checks. It covers the existing-D09 preservation/budget/root path and the real 48-edge topology adoption plus its negative cases, in addition to root/mapping/clock initialization and reopen/revocation checks.

- ZIP SHA-256: `28e769e1edae278100fb0a9330e15a141099e4efaa441144a371652af18efdf1`
- Manifest SHA-256: `f6f3325dc76bd987d8b5ce101ca8d8319707dcc3ef7a1dfb44be49f4dd9686c4`

The positively migrated-target topology path and appraisal→drive→full/LOO numeric advance remain separate acceptance responsibilities; they are not established by these three passing cases. This remains a development candidate, not the final release artifact.

## Installed appraisal/drive continuation and W09 route acceptance

The semantic asset's bound `role_ref` is the verified D01 `ActiveRoleQualification.head_id` (the plan ID/version), as required by the family-drive compiler. The immutable acceptance separately retains the complete activation, plan and Owner graph rows; an activation atom token is not substituted for this head identity.

`commit_post_c02_semantic_drive_v3` admits only an actual paid, adopted appraisal under the registered installed reader. The current D11 grant and durable lease must agree with the namespace, lease, currency and explicit semantic work kind. The installed dose policy is bound into the exact replay request. The semantic original also retains the full canonical dose policy, exact signed budget-grant JSON/signature, and a D11 `d11.installed-d04-semantic-dose-policy.v3` signature binding those facts to the package manifest, installed mapping acceptance, appraisal acceptance and mapping original. Caller JSON or a self-consistent digest does not supply any of this authority.

Immutable sourced drives carry historical provenance through same-transaction `graph_dependency_edges` rows rather than invalidating graph dependencies. Complete CAS reads are retained. The joint numeric collector must still independently qualify current D06 source/access/correction heads and audience/purpose; historical drive existence is insufficient.

The permanent `test_d04_installed_semantic_drive_v3.py` now composes the existing genuine Owner fixture through its explicit `continue_to_ingress=True` seam. The known-impact branch uses actual W09 registered command handlers for all seven initialization actions with a genuinely signed `BoundOwnerSessions` login and CSRF. It checks exact operation/phase receipts, current profile revision fields, wrong-scope denial and logout invalidation. The same root then continues through actual C02 and the installed appraisal/drive path. Only the local model provider HTTP response is controlled; no live paid provider is called. `after_drive` is available for later native full/LOO acceptance without constructing another root.

### Executed unknown-impact evidence (2026-09-30 05:11 UTC)

`test_installed_owner_c02_appraisal_semantic_drive[unknown-impact-holds]` passed in 36.32 seconds against snapshot-0509. ZIP SHA-256: `5383e9366e8adf6af0f044f4a10bdab56e15408e06d0eba70fdf6b9fdc063d80`; manifest SHA-256: `643830c179f27f43f58275d873b550a4469f7b8f68ae83140581040eb68c343b`. This run verified the actual paid/appraisal original, zero drive and semantic acceptance writes, durable refusal, exact request remaining held, finished Authority permit, and a subsequent independently fenced current mapping read.

This result does not cover the newly added signed dose-policy payload or the full successful W09/drive branch; those await the next fresh installed package run. The failed intermediate runs exposed and drove repairs for preserved multi-domain D07 policy reads, the bound D01 head identity, immutable-drive dependency handling, actual Workbench receipt wire digests and root replay. They are not acceptance passes.

### Executed W09 and semantic-drive evidence (2026-09-30 05:24 UTC)

Both permanent `test_installed_owner_c02_appraisal_semantic_drive` branches passed against fresh extracted snapshot-0522: **2 passed, 1 warning in 76.82 seconds**. The warning is AstrBot's Python `audioop` deprecation. ZIP SHA-256: `596ce08686069933e9e0013d2129ebdeedf5d71d5d396156d502c7b9eec9a1b4`; manifest SHA-256: `a13b4b9cbb064f408c19f6e3e467191bed15e5459d2a887fa7053204cd61be19`.

The successful branch exercised the actual AstrBot-registered W09 command handlers, `BoundOwnerSessions`, `GraphWorker`, current Owner grant resolver, CSRF transport, all seven initialization commands, exact root replay without another budget effect, and current profile reads. Wrong namespace scope and the actual logged-out Owner session were rejected. That same root proceeded through real C02, the installed controlled-provider appraisal path and durable model-cost original, appraisal adoption, explicit eight-mechanism mapping, all three numeric-drive writes with `0.5/0.25/0.25` shares, retained historical provenance, authentic signed policy/grant evidence, exact drive replay and altered-policy request conflict. The unknown-impact branch additionally confirmed no numeric drive, durable refusal, finished original Authority permit, exact repeat remaining held and a new fenced read succeeding.

The reproducible command is the two-case integration file with `SYLANNE_D04_INSTALLED_ROOT` pointing at snapshot-0522 and that package's `rewrite` directory first on `PYTHONPATH`. The local verification log is `verification/d04-drive-0522.log` under the task's Sylanne workspace.

**Remaining boundary:** This acceptance does not execute full/leave-one-family-out numerical integration or prove the initial authored-root ABI2 CPU reservation/actual settlement path. That root-accounting gap was identified during integration and remains a separate production repair. The optional `after_drive` hook now requests the genuine initial signed `d04.joint_numeric_cpu.v3` work-kind grant and an explicit test ceiling of 60000 `cpu_ms`; its native consumer acceptance belongs to the next test, not this result.

## Qualified ordinary migration of mapping and role clock

An ordinary mapping fence now obtains `D12CurrentOwnerAuthorityV1` from the independently configured background Owner authority port before SQL and checks the same current observation after SQL. On a target, the reader separately matches the actual current target admission with the Graph recovery stamp/epoch/anchor, unchanged source Owner grant and principal, imported snapshot/receipt, target generation/incarnation and any storage continuation. The live D01 role and complete member/predecessor inputs are still independently replayed.

A source installation's immutable mapping/clock originals may be used at the verified target only under this current admission and the same verified package manifest/profile bytes. Their source guard and acceptance actor remain historical evidence. The current target principal/key/actor are reauthenticated by the actual target service; no source actor is newly paired or promoted. Same-installation reads keep the accepting-principal check. This is not a package-upgrade or numeric two-head-journal bridge exemption.

### Executed migration evidence (2026-09-30 05:43 UTC)

Fresh snapshot-0536 ZIP SHA-256: `993a1d1b1d11bfb9b4dfe28ad6a9846487eecdfb4769d1481d81c7a11f95a8df`; manifest SHA-256: `9ca30d540f0d69ec2e4cbe9aebd4f7d2baaef2fbc002c822e71185c21bea76a8`.

- The source semantic initialization test, including database reopening and actual Owner-key revocation, passed on this pin
- The extended existing topology migration test reused its real D12 freeze/revoke/import/activate path and freshly signed target Owner. It verified unchanged mapping/clock JSON, digest and signature bytes at the target; ordinary background reads after browser logout; and rejection after actual target-key revocation
- That target case and both W09/drive cases then passed together: **3 passed, 1 warning in 116.04 seconds** (`verification/d04-mapping-migration-0541.log`)
- The permanent public `AffectProvider.propose_sourced_numeric_drive`/validator regression passed separately after replacing invalidating dependencies with explicit checkpoint/source/access current reads and historical provenance

The initial failed target attempt in the earlier log was a missing local transport protocol method in the test composition, not an admitted unqualified target. The subsequent run uses direct calls to the actual Core fence and target Owner services. No target Owner admission or migration original was fabricated, and source/target schema and original-byte checks were retained.

## Separate read-only numeric journal bridge

`reader.current_numeric_fence(scope, numeric_port=..., bridge=...)` is a separate installed-port context for the final pre-adoption semantic/evidence reconstruction. It requires the coordinator's actual registered `InstalledC04AuthorityPortV3`, the same installed reader, and an actual independently revalidated `D04NumericAdoptionBridgeV3` on entry and exit. The genuine permit and scope retain the after-claim/terminal anchor. Only within this context does the business Graph match the bridge's exact `before_requirements_json`, revision/epoch and before anchor. Ordinary `current_fence` comparisons remain unchanged.

The context admits a read-only Graph transaction and requires it to be closed before exit; the connection's change counter and Graph stamp must remain unchanged. It reuses the same signed mapping/clock, current Owner and current source/target location checks. Callers must roll back their read, exit and revalidate the gate before opening the separate final CAS transaction. The method is compiled/F821–F823 checked; its live full/LOO and cold-recovery coverage belongs to the separate joint acceptance run.

The reusable permanent fixture accepts `role_clock_rate` as an explicit decimal string, defaulting to its existing `"1"`. A caller may select `"0.001"` through the genuine Owner HTTP clock command for a positive contraction-bound numerical case. This does not change production clock defaults, validators, mathematical guards or interval evidence.
