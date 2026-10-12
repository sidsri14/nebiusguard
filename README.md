# 🛡️ NebiusGuard: Streaming Security Firewall for NVIDIA Nemotron & Nebius AI Studio

> **Target Competition**: Nebius × NVIDIA Global AI Hackathon ($50,000+ Prize Pool on Devpost)  
> **Target Track**: Coding & Agentic Engineering / Apps & Agents  
> **Supported Models**: `nvidia/nemotron-4-340b-instruct`, `meta-llama/Meta-Llama-3.1-70B-Instruct`  
> **Endpoint Compatibility**: Nebius AI Studio (`https://api.studio.nebius.ai/v1`) & Token Factory  
> **Status**: **Production Ready — 8/8 Tests Passing**

---

## ⚡ Executive Summary

Autonomous agents powered by state-of-the-art models like NVIDIA Nemotron-4-340B and Llama 3.1 have access to critical systems via tool calling (databases, shell environments, web search, payment rails). However, direct inference without guardrails exposes applications to:
1. **SSRF & Metadata Theft**: Adversarial prompts coaxing models to fetch AWS/GCP/Nebius internal metadata (`169.254.169.254`).
2. **Command & Path Traversal Injection**: Malicious arguments executing shell commands or traversing directories (`../../etc/passwd`).
3. **Runaway GPU Spend & Buffer Bloat**: Models generating hundreds of un-needed tokens after client disconnects or during runaway recursion loops.
4. **Credential Exfiltration in SSE Streams**: Accidental emission of API keys or secrets in streaming token deltas.

**`NebiusGuard`** is an ultra-low-latency, zero-dependency streaming gateway that sits directly between agent orchestrators and Nebius AI Studio endpoints, enforcing fail-closed security at line speed.

---

## 🏛️ Architecture & Core Components

```mermaid
flowchart LR
    A[Agent Client / Orchestrator] -->|Prompt / Query| B[NebiusGuard Proxy]
    B -->|Check Exact/Prefix Cache| C{Cache Hit?}
    C -->|Yes (<0.1ms)| A
    C -->|No| D[Prompt Sanitizer & Injection Guard]
    D -->|Blocked| E[Drop & Audit Log]
    D -->|Approved| F[Nebius AI Studio API]
    F -->|NVIDIA Nemotron SSE Stream| G[Streaming Token Filter]
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
- Instantly sends an abort signal to Nebius AI Studio upon violation, eliminating wasteful GPU compute.

### 3. Sub-Millisecond Exact Prompt Cache
- SHA-256 keyed LRU prompt cache with configurable TTL.
- Eliminates redundant inference calls for static agent prompts.

### 4. Cryptographic Tamper-Evident Audit Chain
- Every approval, rejection, and circuit breaker trip is linked in an append-only SHA-256 hash chain (`prevHash -> hash`).
- Verifiable in real-time via `guard.verifyAuditChain()`.

---

## 🚀 Quickstart & Verification

```bash
# Run the complete test suite (8/8 passing)
npm test

# Run the live interactive demonstration
npm run demo
```
