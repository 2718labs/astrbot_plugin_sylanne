# Phase 5a: controlled host integration

This milestone supplies the repository's sole root entry point. The user explicitly required retirement of the old interfaces and core; no parallel legacy runtime remains. It is still a development slice, not product acceptance. Routine implementation is delegated to Sol, environment work to Luna; architecture and acceptance remain in the main task. The full heavyweight product architecture is defined in `../docs/architecture/embodiment-3-system.md`.

## Authority and semantic boundary

The host supplies exact bot, persona and conversation/participant ownership, a stable message identifier, source text and a finite observed interval. Missing ownership fails closed. A language model may propose only an appraisal enum and a verbatim evidence excerpt. It cannot assign scope, time, identifiers, coefficients, arbitrary state or a reply.

The strict JSON gate rejects duplicate/unknown fields, unbounded output, malformed types and evidence absent from the source. `abstain` has no evidence and causes no reaction/action update. Evidence matching establishes provenance only; it does not prove the appraisal correct.

For this integration fixture only, support/pressure/neutral map to drives `(6, 0)`, `(-6, 0)`, `(0, 0)`. These are uncalibrated test operators, not the final emotional ontology. Host messages use a documented one-second appraisal episode ending at the source timestamp. The episode is an integration assumption, not an inferred psychological duration. Computation refinement never advances that timestamp.

Replies are deterministic templates selected from the committed action expression. No second free-form model call can bypass the authoritative state. Natural conversation, semantic calibration and expression quality require later milestones.

## Ingress and lifecycle

Admission is immediate and bounded, with one in-flight request per exact scope. A durable ingress claim precedes the provider call. The host intake scope contains the bot/platform, chat and participant but is independent of the current persona/conversation. The state scope additionally contains the resolved persona and conversation. Replaying an old message after switching persona or creating a new conversation therefore conflicts with its original ownership instead of assigning its evidence to a new owner. The same message ID and envelope are never automatically proposed or sent again, including after restart; different content under that ID conflicts. Cross-instance claims use full read-set CAS.

Provider timeouts, parsing failure and abstention cannot write reaction state. Cancellation and shutdown own and join pending database work, including the engine's final commit. A cancelled commit may leave a durable pending action, but must finish before resource closure and must not send. Shutdown closes admission, cancels/joins active handlers, then closes workers and storage. Delivery still records pending/sending/delivered/failed/unknown separately from state commitment. The host transport re-resolves ownership immediately before sending; a changed owner prevents that send. The host provides no transaction spanning its configuration and platform transmission, so this is a checkpoint, not a claim of atomicity with concurrent host configuration changes.

A crash can strand an ingress claim or delivery intent. A claimed row also blocks new messages for that same state owner in the shared ingress ledger. This slice intentionally offers inspection rather than automatic replay or guessed lease expiry; a recovery policy must distinguish known failure from unknown acceptance before it can resend or unblock. Callers must consistently map the same destination owner to the same ingress scope; the host adapter supplies that mapping. The bounded 256-event fixture is not a production retention policy.

## Acceptance boundary

Compile and test the core plus strict gate, restart deduplication, cancellation, capacity and isolation. Verify namespace-relative loading and command invocation against a pinned actual AstrBot distribution with controlled provider/platform inputs. Report the exact SDK version, and distinguish SDK execution from a running bot connected to a real model or messaging platform.
