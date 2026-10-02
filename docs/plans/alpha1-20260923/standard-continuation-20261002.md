# Alpha1 backend development checkpoint — 2026-10-02

This checkpoint continues `2718labs/astrbot_plugin_sylanne` from
`1e2ae78d2a1423a6d94fa4d57c0606dd1656ea7d`. It preserves the current backend source,
permanent software fixtures and post-S57 repairs on the independent development
branch `codex/standard-continuation-20261002`. It is **not a release or completed
D01–D13 backend acceptance**. Existing branches and history are retained.

Read this document before the older status sections in `CLOUD_CONTINUATION.md`.
The older sections describe their own snapshots, not this source checkpoint.
Read `AGENTS.md`, `docs/plans/alpha1-20260923/architecture-gate.md`, `task_plan.md`,
`local-continuation-20261001.md`, and the applicable module contracts before work.
Current task-specific instructions take precedence over historical model assignments.

## Scope and unchanged gates

The implementation target remains the complete D01–D13 backend, Authority fee
accounting, recovery and deletion, native kernel, and a Linux AstrBot ZIP. Build
and installed acceptance must use one coherent source/manifest/native snapshot.
No complete backend, current populated recovery/deletion chain, or real Linux
AstrBot installation is certified by this checkpoint.

Do not reset or clean existing work. Do not automatically open a PR, merge or
release. Preserve mathematical rules, CPU evidence, original deadlines, identity,
lease/fence, admission, SQL originals, and genuine Authority ACK requirements.
Generic freeze/current readers remain strict. `GraphReceipt.committed` alone is
not durable COMMIT. Production code must not substitute caller flags, fabricated
receipts, dictionary placeholders or filtered unresolved inventories for evidence.

The retained permanent runtime fixtures use isolated synthetic data and finite
MockTransport. No real user platform or billable provider was used for these
results. Further execution must respect the task's actual permission and budget.
Do not enable sending before installed integration acceptance.

## Last fixed package and source relationship

The last fixed test package was S57, named
`astrbot_plugin_sylanne-3.0.0-alpha1-linux-x86_64-glibc-alpha1-test-snapshot.zip`.
It is not attached to this Git checkpoint and must not be treated as containing
the current source changes below.

| S57 item | Exact value |
|---|---|
| ZIP bytes | 5,039,610 |
| ZIP SHA256 | `8b979b86f6b46eeea3dc79b4924fcf33a1fab9a0b63ac31c0296798b4234ab16` |
| Manifest SHA256 | `6bb76741d27518599340e7e7d8dd2a69621c2e12643a4a5a872738088c58c7a3` |
| Engineering inventory | 2092 rows; canonical SHA256 `5843e64e7253508a9d8849b175effdd196bc4309bb61da583e6e7055be429eb7` |
| Native library SHA256 | `b4a1d1e6236bd7d0f9ba8b45f940a4175e0dadbc406b032c26161b4adfb84be4` |
| Native platform | Linux x86_64, GLIBC >= 2.35 |

All 995 product payload files were byte-identical to S56. ZIP CRC, 969 Python
syntax files, eight installed product imports, and full inventory hashes passed.
These are mechanical checks, not backend acceptance. The S57 permanent fixture
static import then failed with exit 86 on a legitimate implicit
`rewrite.host_tests.alpha1` namespace; C09 business execution did not start.
The frozen package and its failure were retained. No S58 was built or run.

W09 remains unchanged:

| File | Bytes | SHA256 |
|---|---:|---|
| `resources/workbench/index.html` | 689111 | `3e296089fc19e4df3ede0d4a05b19567e574311ee8b41de2ff907593e77258ca` |
| `resources/workbench/workbench-manifest.json` | 334 | `9485b21712fc2c4a0197d5015ad7a4c0457e3a8fd7a979688db73adad8cecd17` |

## Actual behavioral results

| Chain and snapshot | Actual result | Limit |
|---|---|---|
| D04 S55 run02 | FAIL, pytest 932.67 s, exit 1 | First 1355 steps/3 chunks adopted. Successor planned 12569 steps/25 chunks, completed 4608/9 with CPU 374492477249 ns. All completed costs settled with Authority ACK. Next prepare refused the original 600 s deadline. No successor adoption or D06 read. |
| Numeric Life S54 | FAIL, 16.05 s | Initial prefixed UUID fixture was invalid; numeric scope not reached. Fixture repaired in S55. |
| Numeric Life S55 | FAIL, 68.36 s | Absence check used mandatory `get_job`; repaired with two held-SQL checks in S56. |
| Numeric Life S56 | FAIL, 83.08 s | Actual before-original checks passed. Internal numeric-context process grant omitted required D07 domain. Paid numeric/native interval not reached. Current source repair has static checks only. |
| D09/D13 S56 | 24 D09 PASS; first installed D13 FAIL, 16.70 s | Six completed synthetic inbound events retained distinct arrivals and original binding evidence. Fixture omitted real D13 provider registration. No D13 paid job/call; expiry node not run. Current conditional fixture repair has static checks only. |
| C09 S52, historical exact input | One positive PASS, 48.10 s; nine refusals PASS, 380.15 s | Authenticated absent execution and file invariance only. Does not establish populated Life/Contact recovery or disposal. |

Old D06/offline PASS and the earlier 1614-file syntax check do not establish
current whole-package acceptance. Recorded installed runs checked actual import
provenance and before/after product/source/native pins.

A later read-only D04 SQLite observer changed SHM mtime. Its initial before-state
was not persisted and was not reconstructed. This observation is separate from
the actual failed run and unchanged installed payload. The original database
was closed; a complete file cohort was copied and measured in its own invariance
window. Further recovery/deletion evidence must preserve complete cohorts and
record actual before/open/read/close file state.

## Current repairs and unverified work

Paths in this section are relative to `rewrite/` unless otherwise stated.

1. `sylanne3/runtime/domain_production_runtime_v1.py` grants D03/D06/D07/D11 only
   for `prepare_internal_life_numeric_context`; generic guards remain unchanged.
   Syntax, Graph-first import and the eight numeric-operation domain audit passed.
   SHA256: `5a4d4c241bd9d0a3353beae25dbaa5b4ce729df6299f6706fd159e0b34cfb4cb`.
   No installed behavior rerun.
2. D09 now requires `binding_evidence: GraphAtom`, authenticates both the original
   binding event and the current arrival, and retains version/CAS checks. D13
   request expiry uses the minimum of actual job deadline, worker lease expiry
   and binding expiry, with exact SQL recheck at seal. Actor, lease holder/fence,
   mTLS identity, budget and Core admission are retained. The installed fixture
   `tests/alpha1/runtime/test_post_c02_reply_assembly_v2.py` conditionally registers
   the existing real D13 provider when paid precompression is enabled.
   Fixture SHA256: `e82cd89d90d891320b9cbd6fbf5ba2ed76bf5d0b5858da09ab065d0ba2300b2b`.
   Its registration repair was compiled/imported but not rerun.
3. `tests/alpha1/integration/test_c09_daemon_factual_process_v2.py` accepts the
   exact authenticated implicit test namespace. Corrected guard static import
   passed once; no subsequent pytest/runtime. Fixture SHA256:
   `718ba8d79e1e30a2f97c129b5c93cb634e903590abd0ac290779cc3484e5e2be`.
   The retained six-process prepare/switch/release/build/dispose/factual fixture
   includes populated inventory, signed cold configuration, provider purge,
   full file-phase snapshots, genuine fork Host retirement/exit evidence and
   original Authority retirement. Its complete installed behavior remains unrun.
4. Finished Contact reading has a private signed readonly-use contract, Authority
   RPC, Host mTLS port, GCP entrant and permanent installed fixture. It checks
   signed invocation, original valid/unrevoked session, finished permit and exact
   finish ID/digest/ACK, durable D11 original, new actual read permit and current
   same-principal Owner. It allows only same-Authority-boot use with current
   purpose/permissions intersection; original deadline is retained. It issues no
   new fee, business write or send right. Ten syntax files, seven source imports
   and selected diff checks passed; no installed behavior run. Composition with
   the Owner console beyond the callable GCP entrant and Host port is unverified.
5. `sylanne3/host/contact_dispatch_driver_v3.py` and
   `sylanne3/runtime/contact_dispatch_host_v3.py` retain the single sender scaffold,
   runtime entry and permanent negative fixture. **Current P2 qualification is
   unconditionally HOLD before P0/accounting/sending.** Five syntax files and
   three source imports passed. Positive accepted/unknown/failure/timeout and
   post-handoff cancellation behavior remains unfinished and unverified.
6. `native/src/v2.rs` has an ordinary, finite, all-coordinate bitwise stationary
   exit; cancellation control flow is unchanged. Source SHA256:
   `c078f78277e27ba4384cbc9e0e73d90db8700d625785f48575c606a7b7418f8c`.
   Thirty-eight exact differential cases and nine existing Rust checks passed
   under the reviewed ABI/floating-environment premises. Existing local min/max
   `nsz` flags remain in old and new IR. This does not prove the D04 full-series
   deadline. No further performance implementation followed the failed long run.

The current runtime entry SHA256 is
`09c53cfb17dafce8bbcf6f858cf6bfe389e49d63d5953fd8d877278f98de972f`
for `sylanne3/runtime_context.py`. The shared final Contact fixture SHA256 is
`ad888504cde18933ee13571f87f1d6ea4bfa73e8c778332b48eb998b82c928e5`
for `tests/alpha1/integration/test_installed_contact_final_v3.py`.

## Contact contracts still needed

The agreed implementation direction for P2 is a private finite-lifetime progress
witness derived from real durable claim/receipt and actual Authority state. This
is a design direction; the required witness is not installed by this checkpoint.
Keep the existing D08 write-stage contract intact. Bind original admission anchor,
current anchor, immutable final D11/whole-parent, action/effect/attempt/payload and
the entire Authority footprint. Independently authenticate every necessary current
provider and the complete unresolved inventory. Permit only the exact own claim
after each inventory item is authenticated; do not remove other unresolved items.
Any relevant state change invalidates the witness and requires a fresh read.

Private installed Contact projection must preserve original permit R/E and real
database/lock/closed-stage witnesses. Authenticate E, provisional E+1 and receipt-
hook E+1 separately. Keep finite provider read closures, actual own-claim SQL,
true proactive identity, verified policy and full D10 SQL/window/claim issuance.
Do not broaden the generic readers or bypass qualification rechecks.

Later segments stay HOLD until actual D11/Authority/PlatformObservation immutable
prefix evidence reaches D08 and P0/P2. Accepted/unknown platform status is not
delivered, completed or resolved. Parent grants remain immutable; fresh-segment
eligibility independently binds manifest/prerequisites/action/effect/attempt/payload
and distinguishes the first action ID from communication parent ID. Authority
reboot continuity and shared-session exclusivity/quiescence need explicit contracts;
unknown peer state stays HOLD.

## Resume with a coherent installed snapshot

Fetch and verify this development branch and commit before continuing. Inspect
current dependencies and fixture guards; do not infer behavior from source imports.
Build the native library from `rewrite/native/Cargo.toml` and `Cargo.lock` on the
intended Linux target. Authority dependencies are in `requirements-authority.txt`.
Use `rewrite/tools/build_plugin_package.py` and its existing snapshot/candidate
qualification rules; a registry catalogue is not acceptance evidence. Keep builds,
runtime data, certificates, logs and evidence outside Git. Never mark a candidate
formal to bypass qualification.

After authorized implementation, freeze one coherent source/native/manifest set,
check the package and install it outside the source tree. Use
`SYLANNE_D04_INSTALLED_ROOT=<actual-installed-root>` and prove imports come from
that installed payload. Serial affected permanent nodes include:

- `rewrite/tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_original_paid_native_interval_and_trace`
- `rewrite/tests/alpha1/integration/test_installed_d13_paid_v1.py::test_installed_d13_paid_standby_current_cold_and_no_charge_replay`
- `rewrite/tests/alpha1/integration/test_installed_d13_paid_v1.py::test_installed_d13_paid_expired_original_never_calls_provider`
- `rewrite/tests/alpha1/integration/test_c09_daemon_factual_process_v2.py::test_public_daemon_cold_factual_v2`
- `rewrite/tests/alpha1/integration/test_installed_contact_final_recovery_v3.py::test_installed_contact3_finished_fresh_owner_session_readonly_exact_no_effects`

For D04, require a substantiated improvement before repeating
`rewrite/tests/alpha1/integration/test_d04_installed_series_v1.py::test_installed_multichunk_series_cold_adoption_and_successor_d06_read`.
Do not relax the deadline, CPU or mathematical checks. Sender acceptance requires
the missing P2 contract and installed closure first. Adoption, full populated C09
recovery/deletion, sender/D13 and real Linux AstrBot/systemd installation remain
delivery gates. Final ZIP must identify its commit, manifest, actual verification
results and every unverified boundary.

This transfer itself runs no new build, pytest, native test, platform or model call.
Raw private continuation notes, runtime databases, generated keys, full logs and
binary packages are intentionally excluded from this public source checkpoint.
The source-transfer diff check reports one existing extra blank line at EOF in
`rewrite/sylanne3/runtime/contact_final_action_v3.py`; its source bytes were retained.
