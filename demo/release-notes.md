# NebiusGuard verified demo bundle

- One authenticated Nebius Token Factory stream verified with `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`; [non-secret evidence](https://github.com/sidsri14/nebiusguard/blob/main/docs/live-verification-2026-10-28.md).
- 29 passing automated tests; Node20/22/24 Windows/Linux CI passes on the hardened implementation.
- Narrated 2:44.465 H.264/AAC demo at 1440x900, with 40 burned-in caption cues. Actual captured provider evidence and synthetic security cases are labeled separately.
- Reproducible media scripts, evidence and QA record are included in `demo/`.
- Prototype limits remain explicit: static URL checks do not enforce DNS/redirect policy, secret detection is pattern-specific, and cache/audit storage is in memory.

MP4 SHA-256: `80b777b589c0473f2c4fcdaee123ea98d43307b283c1be16a98fcdc58a680a04`.

This release makes no model-accuracy, latency, cost-saving, production-deployment or award claim.
