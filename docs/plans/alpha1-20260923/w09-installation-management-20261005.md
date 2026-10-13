# W09 installation management and 2718lab 0.25 local integration

This local integration preserves the Numeric, Contact, C09 and D04 acceptance
holds. It is not an alpha1 production release or permission to call a model or
sender. The backend source is the local continuation worktree at 00049ab3,
including its recorded uncommitted Numeric fixes.

The four management POST routes are independent of D12 `/commands`. A current
Dashboard user and signed Owner identity share one in-memory CSRF store.
Every management call resolves the installed mTLS peer and rechecks a separate
finite installation grant in Authority. The three explicit permissions are
installation.logs.read, installation.settings.read, and
installation.settings.enabled.write. D12 retains current Graph Owner reads.

Authority owns the enabled singleton, CAS revision, idempotent operation
receipts and fixed-code audit events in the existing Core database. Startup
reads this actual setting before starting the engine. Disabled runtime still
exposes authenticated management; it does not start the Graph engine or
recovery schedulers. `enabled` applies on next restart and has no pause/resume
meaning. The profile comes from the installed binding and is read-only.

The common Owner identity layer retains the original signed challenge,
one-shot acceptance, current credential/session checks, Dashboard binding,
Secure/HttpOnly/Strict cookie and exact origin. `/session` keeps its existing
four-field identity/CSRF response. No actor or Graph capability is fabricated.
The D12 adapter proves an actor and Graph grant on each read and separately
retains its exact-operation status proof after a Graph freeze.

The new four tables and append-only event triggers are registered with cold
schema verification and C09's closed Core table inventory. Management may be
available when runtime is disabled, but must still enter the current C09
maintenance/storage admission boundary. This registration does not pass C09.

The explicit source/build seam is workbench-src/prototype-v6/singlefile.
Only the final same-origin HTML and its verified resource manifest are served.
Protected GLB/logo bytes retain the incoming v24 visual baseline. Offline
builds, source tests, installed runtime and local browser validation each have
separate receipts.
