# 🛡️ NebiusGuard: Streaming Security Gateway for NVIDIA Models on Nebius Token Factory

> **Target Competition**: Nebius × NVIDIA Global AI Hackathon ($50,000+ Prize Pool on Devpost)  
> **Target Track**: Coding & Agentic Engineering / Apps & Agents  
> **Model selection**: discovers the live catalog and selects an available `nvidia/*` model
> **Endpoint**: Nebius Token Factory (`https://api.tokenfactory.nebius.com/v1`)
> **Status**: tested live-client and streaming implementation; a private API key is required for provider verification

---

## ⚡ Executive Summary

Autonomous agents powered by open NVIDIA models can access critical systems through tool calling: databases, shell environments, web search, and payment rails. Direct inference without deterministic boundaries exposes applications to:
1. **SSRF & Metadata Theft**: Adversarial prompts coaxing models to fetch AWS/GCP/Nebius internal metadata (`169.254.169.254`).
2. **Command & Path Traversal Injection**: Malicious arguments executing shell commands or traversing directories (`../../etc/passwd`).
3. **Runaway GPU Spend & Buffer Bloat**: Models generating hundreds of un-needed tokens after client disconnects or during runaway recursion loops.
4. **Credential Exfiltration in SSE Streams**: Accidental emission of API keys or secrets in streaming token deltas.

**`NebiusGuard`** is a zero-dependency streaming gateway between agent orchestrators and Nebius Token Factory. It performs prompt inspection before a request, validates tool boundaries, filters streamed deltas, aborts a live upstream stream when a credential pattern appears, and records a hash-linked audit trail.

---

## 🏛️ Architecture & Core Components

```mermaid
flowchart LR
    A[Agent Client / Orchestrator] -->|Prompt / Query| B[NebiusGuard Proxy]
    B -->|Check Exact/Prefix Cache| C{Cache Hit?}
    C -->|Yes (<0.1ms)| A
    C -->|No| D[Prompt Sanitizer & Injection Guard]
    D -->|Blocked| E[Drop & Audit Log]
    D -->|Approved| F[Nebius Token Factory API]
    F -->|NVIDIA model SSE stream| G[Streaming Token Filter]
    G -->|Detect Leak / Abort| H[Fast-Cancel GPU Inference]
    G -->|Sanitized Stream| A
    F -->|Tool Call Emitted| I[Tool Boundary Firewall]
    I -->|SSRF / Traversal / Command Check| J{Compliant?}
    J -->|Yes| K[Execute Tool Safely]
    J -->|No| L[Fail-Closed Rejection & Chain Hash]
```

### 1. In-Flight Tool Boundary Firewall
- Validates tool names against a strict whitelist.
- Blocks SSRF targets: `169.254.169.254`, `metadata.google.internal`, private RFC1918 CIDRs (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`), loopbacks (`127.0.0.1`, `localhost`).
- Detects path traversals (`../`, `..\`) and shell injection metacharacters (`;`, `&&`, `||`, `` ` ``, `$()`).

### 2. Streaming Token Sanitizer
- Intercepts Server-Sent Events (SSE) token by token.
- Prevents credential emission (`sk-...`, `AKIA...`, `ghp_...`, `nebius-...`).
- Aborts the active Token Factory request when a credential pattern appears in streamed deltas.

### 3. Sub-Millisecond Exact Prompt Cache
- SHA-256 keyed LRU prompt cache with configurable TTL.
- Eliminates redundant inference calls for static agent prompts.

### 4. Cryptographic Tamper-Evident Audit Chain
- Every approval, rejection, and circuit breaker trip is linked in an append-only SHA-256 hash chain (`prevHash -> hash`).
- Verifiable in real-time via `guard.verifyAuditChain()`.

---

## 🚀 Quickstart and verification

```bash
# Run unit and integration-style tests with an injected HTTP transport
npm test

# Run the deterministic offline boundary demonstration
npm run demo
```

The offline demo never claims a provider call. It is useful for reviewing prompt, tool, stream, cache, circuit-breaker, and audit behavior without credentials.

### Live Token Factory proof

Create a Token Factory API key in the official console, keep it out of chat and Git, and export it only in your shell:

```bash
export NEBIUS_API_KEY="..."
# Optional: copy an exact NVIDIA model ID from your live catalog.
export NEBIUS_MODEL="nvidia/Nemotron-3_5-Lightning"
npm run demo:live
```

PowerShell:

```powershell
$env:NEBIUS_API_KEY = "..."
# Optional: $env:NEBIUS_MODEL = "exact nvidia/* model ID from the catalog"
npm run demo:live
```

`demo:live` first calls `/models`, refuses a requested model that is absent from the account's catalog, then streams one bounded completion through the real gateway. The output records the selected model, provider path, audit-event count, and audit-chain verification without printing the key.

### Evidence boundary

- Tests prove request construction, bearer authentication, live response validation, SSE parsing across transport chunks, upstream abort behavior, bounded response sizes, caching, and audit-chain integrity.
- A passing test is not evidence that this checkout made a real paid/provider request.
- Do not describe the provider path as live-verified until `npm run demo:live` succeeds with the account owner's private key and the model/usage evidence is captured without secrets.
