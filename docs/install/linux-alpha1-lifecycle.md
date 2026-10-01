# Linux alpha1 installation and independent Host recovery

The fresh installer now accepts `sylanne3.linux-install-request.v2`. It creates a new installation only; it does not overwrite an existing or interrupted installation, upgrade packages, erase data, enable systemd units, or make model/platform calls.

## Explicit configuration

Print the complete template first:

    python scripts/alpha1/install_linux.py --template > request.json

The printed template is intentionally **not installable**: UID/GID, all spending ceilings, numeric iteration/time limits and expiry must be selected explicitly. Replace every `FILL_*` value. Zero semantic dose limits mean no allowed dose; they are not a calibrated neutral personality. Review all eight mechanisms and each fast/residual/slow bound before selecting nonzero values.

- `budget_limits` is the total root lease; `budget_max_ceiling` bounds each quoted operation
- `budget_valid_until_utc` is an explicitly chosen future UTC Unix timestamp in seconds, not an ISO date string; `currency` is an ISO-style uppercase code
- `model_quote` and `local_quote` are independent limits; each is checked against both root limits
- `cpu_ms` bounds measured full/LOO joint work; the current root-adoption contract separately uses `thread_cpu_ms`
- `d04_joint_numeric` explicitly supplies version 3, positive `cpu_ceiling_ms`, at most 256 `max_iterations`, finite positive binary64 `tolerance` no greater than 1, and at most 3600 `job_lifetime_seconds`
- `d04_semantic_drive` explicitly bounds the registered mapping/basis and all mechanism doses/family shares; these bounds do not adopt a mapping or replace Owner selection
- `host_lifecycle.supervisor` pins the actual AstrBot unit, canonical root-owned systemctl/fragment paths, fragment SHA256 and cgroup. Obtain these from the real service, not an example guess. The same unit must be used by C09 and lifecycle control
- Model configuration is read from the administrator-selected local file solely to bind its canonical digest. Do not paste provider secrets into a shared request or upload the file
- The current Linux composition supports one cache-disposition provider. Its `provider_cache.provider_id` must match every configured model workflow, including paid precompression. Multiple providers are rejected until complete adapter coverage is implemented. An absent pinned purge/read adapter cannot establish provider-cache erasure; this remains a maintenance blocker, not an empty-cache assumption

Optional D13 precompression policies and protected signed full-wire counter configuration are explicit objects or null. A missing counter retains raw/unverified selection; the installer never fabricates token counts or potential cache savings. For a fresh D13 wire policy, set its `installation` field to the explicit marker `$current_installation`; the installer binds it to the newly created installation and actual chosen provider/model/configuration digest/output limit. All prices, policy fingerprints, public key and capacities remain your explicit inputs. The external counter must independently produce matching signed evidence. `d13_paid_precompression` requires the corresponding real installed workflow and approved budget; null does not advertise it as active.

The corresponding D13 work kind is included only when its policy is explicitly configured. Deterministic precompression requires an explicit `d13_compute_units` allowance in both root limits. Paid precompression requires independent positive input/model-token and output-token bounds, within both the root budget and selected main-model quote. The installer does not increase any supplied limit to make an optional policy pass.

Use externally supplied package and manifest hashes to plan:

    python scripts/alpha1/install_linux.py --package alpha1.zip --package-sha256 <sha256> --manifest-sha256 <sha256> --request request.json

The default is plan-only; `--plan` also selects it explicitly. Planning verifies the pinned archive, its actual installed assets and the full generated policy in temporary storage before any system directories are created. `--install` is a separate consequential administrator action that creates local credentials and protected directories. Review the plan and operating environment before running it. Installing/enabling the generated systemd unit is another explicit administrator action. Keep Owner private keys local. Existing data requires a qualified migration; never delete an old store to force a fresh install.

## Pause and resume

Whole-Host pause is distinct from a role-only logical pause. It stops the actual AstrBot service cgroup, which also removes W09. Resumption therefore uses the running independent Authority, not a button served by the stopped Host.

The independent client is:

    python scripts/alpha1/authority_linux_control.py --profile <installed-profile> <action> < input.json

It never reopens Authority databases. Input is bounded JSON via stdin, not credentials in process arguments. Actions:

1. `challenge`: `{ "request": <canonical registered Owner login request> }`. Output contains the real challenge and `signing_payload_base64`
2. Sign the decoded payload locally with the registered Owner Ed25519 key. `accept`: `{ "challenge": <same challenge>, "signature_base64": <64-byte signature in Base64> }`. Output includes the current session token; protect it and do not include it in support logs
3. `inspect`: current `owner_actor_id`, canonical `owner_session_request`, and `owner_session_token`. Output is the actual lifecycle head, including its epoch and operation
4. `status` / `continue`: the same current Owner fields plus the exact original `operation_id`. Continue resumes the existing durable operation; it does not allocate a new start
5. `resume`: the same current Owner fields plus `pause_operation_id`, a stable new UUID4 `operation_id`, and `expected_lifecycle_epoch` copied from actual inspection. Preserve that operation ID for every retry
6. `logout`: `{ "request": <same current request>, "token": <session token> }`

Do not infer paused/active from request acceptance. Completion requires the corresponding independent original stage. Unknown remote outcomes, costs and reservations remain recorded during pause. The business generation and immutable Owner grant are not rewritten for a compatible same-installation pause/resume.

A resumed Host is bootstrap-only until its actual PID birth/systemd invocation, externally pinned package, mapped ABI2 library, complete thirteen-domain catalogue, current four-file selection and retained execution constraints are independently verified. Ordinary Graph work remains closed. A timeout means inspect the same original; never blindly issue another process start.

## Validation boundary

Local acceptance uses real typed Owner/Core/Graph/journal and subprocess evidence, with a clearly identified systemd command fixture where applicable. This is not a claim of a privileged systemd deployment, real production AstrBot service, live model calls or platform sends. Package replacement/rollback is a separate qualified maintenance contract; the fresh installer is not an upgrade implementation.

### Fixed cohort startup and privileged package executor

A fresh installation now stages an independent bootstrap at
`/opt/sylanne/bootstrap`. The AstrBot plugin link points to its fixed Host shim;
the Authority unit invokes `bootstrap/authority_entry.py`. Both resolve the same
protected `/etc/sylanne/maintenance/selection.json`, rather than following a
mutable code-directory symlink. The selected Authority deployment/assets stay
root-private; the Host reads only its public profile. TLS and D02/D11/C04 keys
remain in their original credential directory.

The initial selection is signed only after the real initial C09 four-file seal.
Registered candidate packages do not become historical active versions merely
because they appear in the registry. A compatible switch must preserve fixed
bootstrap loader surfaces and all non-package identity/configuration fields.

`authority_linux_control.py first-owner-issue` accepts bounded stdin JSON with
`ticket`, `operation`, `grant_value`, `owner_session_request`, and
`owner_session_token`. Use the original administrator-paired creation and the
`sylanne-owner-console` signed session. Authority retains the bearer, registers
and reserves the exact claim, calls the installed live Host over pinned reverse
mTLS for the existing pending-grant Graph transaction, and independently
finalizes the proof. A lost acknowledgement must be retried with those same
original identities. An already-finalized retry returns its original receipt;
it does not issue another grant. A missing current Host, revoked session or
changed process/storage/cohort is HOLD. Ordinary W09 login still requires the
resulting real Owner view.

Review the immutable grant before issuing it. If the intended installation
includes Body policy configuration and C04 internal work, the selected Owner
capabilities must explicitly include `d02.body_policy.install`,
`c04.cpu_policy.install`, and `c04.internal_work.prepare`. Internal recall and
source use also need the corresponding `consolidation` and `context` purposes
and the actual allowed conversation audiences, in addition to the selected
workbench and expression purposes. These are separate from D11 work kinds and
spending limits. Do not copy a permissive audience list or add purposes to an
already-issued grant: choose the intended scope before issuance, or use the
qualified Owner grant-change path. A missing permission must remain denied.

The backend exposes the `c04_cpu_policy`, `c04_prepare`, `c04_advance`, and
`d07_cognition_budget` workbench operations. Their presence does not imply that
the retained W09 frontend already provides every corresponding control, nor
that a policy or child budget has been installed. Inspect the actual original
receipt and preserve its operation identity for retries.

Package acceptance and privileged execution are separate explicit steps. An
accepted switch reports `awaiting_privileged_executor`; closed admission may
already be `quiescing`. The fixed root executor receives only the original
operation UUID, never a caller-selected path, command, backup or readiness DTO:

```
python /opt/sylanne/bootstrap/maintenance_entry.py --operation ORIGINAL_UUID
```

Installed-file preflight is not evidence that this executor is running. Actual
retirement, coherent four-store backup, candidate compatibility, selection CAS,
new Authority and Host readiness and activation each require independent real
observations. Resume an interrupted executor with the same UUID. After a
successful active switch, a later rollback requires a new signed compatible
switch against the current data. It must never restore old Core/deletion/
execution journals over newer effects, cost or revocation history.

Implementation status: the fixed installer/bootstrap and first-Owner route are
implemented; the complete privileged package executor chain is still undergoing
integration. Do not infer whole-machine installation or upgrade acceptance from
component tests or source compilation.
