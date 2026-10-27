# Live Token Factory verification - October 28, 2026

An actual `npm run demo:live` execution completed successfully against
`https://api.tokenfactory.nebius.com/v1`. The private API key was supplied only
through the child process environment; it is not part of this evidence or the
repository. No private headers or credential-setting command are shown.

```text
Authenticated model count: 30
Selected NVIDIA model: nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B
Streaming through NebiusGuard:

Blocking cloud-metadata SSRF calls stops attackers from harvesting sensitive
instance credentials and other internal data that could be used for further
compromise. It also prevents the gateway from being leveraged as a pivot point
to bypass network security controls.

Provider: nebius-token-factory
Audit chain valid: true
Audit events: 2
```

Line wrapping and the hyphen in the captured answer are normalized for readability.
The model ID, catalog count, provider, audit result and event count are exact.

This confirms one authenticated catalog read and streamed completion through the
gateway. It is not a model-quality evaluation, comparative benchmark, claim of
particular GPU hardware, or evidence of latency/cost savings. Deterministic
security cases and automated tests are separate from this provider smoke test.
