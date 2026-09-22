# AstrBot 4.28.1 host verification

The host suite executes the root `main.py` entry point against an installed AstrBot 4.28.1 distribution. It uses AstrBot's actual `Star`, command registration/filter, `Context`, `Provider`, `LLMResponse`, message event and message-chain classes. Conversation/persona managers, provider output and platform transmission are controlled local implementations exposed through those SDK interfaces: they make no network request, do not start AstrBot, and do not read bot or provider credentials.

Run the verifier with the interpreter that contains the pinned SDK:

```powershell
& 'D:\bun\tmp\codex\sylanne3-host\Scripts\python.exe' rewrite\tools\verify_host.py
```

The script rejects any AstrBot distribution version other than 4.28.1, compiles the root adapter and rewrite runtime first, then runs `rewrite/host_tests` from a fresh temporary working directory. It puts the repository root and `rewrite` source root on the child `PYTHONPATH`, loads the entry point with the package-qualified namespace `data.plugins.sylanne3_acceptance.main`, and never imports the retired plugin entry point under a top-level fallback name.

Each run writes a JSON receipt and complete stdout/stderr log under `rewrite/artifacts`. The receipt records the exact Python executable, SDK version and installed source path, commands, exits, output, duration, and SHA256 manifests before and after the run. The manifest includes the root entry point/config metadata and the rewrite runtime, native source, host tests, verifier and this document.

The controlled checks cover default-disabled behavior, actual `/sylanne3` command filtering, preservation of multiword input, one real local SQLite/native/provider path, invalid model output, bot/sender/persona/conversation isolation, restart deduplication, replay after an owner switch, a new message under a new owner, ownership revalidation before send, in-flight unload, and unload concurrent with resource initialization.

This is source-based SDK acceptance. It does not prove AstrBot's complete plugin discovery/reload workflow, a running bot, an external model provider, or delivery through a real messaging platform. `AstrBotMessage.timestamp` is the normalized timestamp exposed by the host object; the test does not prove it came unchanged from an upstream platform.

For a manual host trial, build `rewrite/native` on the target platform first, install the repository root as the plugin, and confirm the plugin remains inert with `enabled: false`. Set `enabled: true` only in a controlled AstrBot 4.28.1 instance with an existing selected conversation and effective persona, then invoke `/sylanne3 <message>`. Switch persona or conversation while a deliberately delayed provider request is in flight and confirm no reply is sent; replay the same host message ID and confirm the provider is not called again. A missing conversation/persona must fail closed. A process crash can leave an ingress claim or delivery intent whose acceptance is unknown; inspect that state and do not delete or automatically replay it.
