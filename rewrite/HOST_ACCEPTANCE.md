# Root cutover and host slice acceptance — 2026-09-22

Status: locally verified engineering slice. The complete heavyweight Sylanne 3.0 product is still under implementation. These are working-tree changes; no commit, push, release, marketplace update or live bot installation was performed.

## Product direction and cutover

The user explicitly required the old interfaces and core to retire, then clarified that the target is a heavyweight character system rather than a small emotional plugin. The root `main.py` is now the sole entry and imports `.rewrite.sylanne3`. There is no secondary `rewrite/main.py` entry or runtime fallback into the previous core.

Tracked legacy runtime, its tests and scripts, old UI/frontends, checked-in old distributable archives, widget and release workflow were removed after checking their baseline state. User data and ignored files were not deleted. The old implementation remains in Git history at `Embodiment-2.5.1`. README, metadata, configuration schema, contribution guidance and CI now refer to the new implementation.

The full target and next stages are recorded in [the heavyweight system architecture](../docs/architecture/embodiment-3-system.md). The present two-dimensional model, narrow appraisal vocabulary, single-owner engine transaction and fixed response templates are engineering fixtures, not the final product model.

## Executed evidence

Local platform: Windows x86_64, CPython 3.13.14, Rust/Cargo 1.97.0, Ruff 0.16.8. AstrBot 4.28.1 was installed in the isolated `D:\bun\tmp\codex\sylanne3-host` environment.

| Check | Result |
| --- | --- |
| Native formatting, check, tests and release build | PASS; 2 Rust tests |
| Python core/application suite | PASS; 67 tests |
| Core and root-entry compilation | PASS |
| AST legacy import boundary | PASS |
| Exact AstrBot 4.28.1 SDK gate and compilation | PASS |
| Root namespace / command / controlled host suite | PASS; 9 tests |
| Ruff on `main.py rewrite` with the retained rule set | PASS |
| Git whitespace check | PASS |
| Before/after verification source manifests | No drift in either successful receipt |

Core command and receipt:

```powershell
& 'C:\Users\pidan\AppData\Roaming\uv\python\cpython-3.13.14-windows-x86_64-none\python.exe' rewrite/tools/verify.py
```

`artifacts/verification-20260922T031457.661662Z.json` and sibling `.log` contain commands, outputs and source hashes. This final run includes the finalized host-verifier source in the core manifest; the earlier successful core run preceded that tooling edit.

Host command and receipt:

```powershell
& 'D:\bun\tmp\codex\sylanne3-host\Scripts\python.exe' rewrite/tools/verify_host.py
```

`artifacts/host-verification-20260922T031049.710520Z.json` and sibling `.log` contain the actual SDK path, pinned version, outputs and source hashes. Source SDK methods execute with controlled provider, conversation/persona and platform implementations; this is not a full plugin-manager or live-platform test.

The release DLL SHA256 remains `6531a11f0322686864316232c2223c5415ca12ed89aba97dbd6e1c949cb36414`. The generated binary is ignored and has not been distributed.

## Review findings resolved

- Cancellation during final engine commit now joins the transaction before propagating and cannot fall through to sending; single and repeated cancellation have real SQLite regressions.
- Stable ingress ownership prevents replaying an old message as new evidence after a persona/conversation change. Shared-ledger CAS admission suppresses duplicate claims and returns busy for another active message to the same state owner.
- Startup/unload races join resource creation and close resources rather than publishing an application after termination. Delivery rechecks ownership immediately before send.
- Root promotion exposed a stale package re-export and a verifier path assumption. Both were corrected before the successful root SDK and combined core receipts.
- SDK test asynchronous file access was corrected before the final Ruff/SDK evidence.

## Limits and manual checks

Full plugin discovery/reload in a running AstrBot instance, external provider behavior, messaging-platform delivery, Linux execution and remote GitHub Actions have not been exercised here. CI now builds the native library in each job that uses it, but its Windows/Linux matrix still needs an actual remote run.

For a controlled manual host trial, follow [HOST_TESTING.md](HOST_TESTING.md): compile for the target platform, load the repository root, start disabled, enable explicitly, use an existing selected conversation/persona, send `/sylanne3 <message>`, then exercise an in-flight owner switch, duplicate host message and unload. No old configuration or database migration is implemented.

The 256-record fixture limit and conservative crash-stranded claims are unsuitable as a final long-running retention/recovery policy. A stranded claim blocks that destination until explicit recovery; unknown deliveries are never automatically resent. The one-second episode is a modeling assumption using the normalized host timestamp. No psychological accuracy, natural-dialogue quality, full sparse graph execution, cross-owner transaction support or complete 3.0 readiness is claimed.
