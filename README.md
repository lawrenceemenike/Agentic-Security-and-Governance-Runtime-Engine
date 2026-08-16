# Agentic Security & Governance Runtime Engine (`agentic-gov`)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)

An enterprise-grade, standalone open-source library providing sub-5ms deterministic AI governance, cryptographic zero-trust inter-agent security, state-bound human checkpoints, causal Merkle-DAG decision ledgers, and automated EU AI Act Annex IV / GDPR Art 17 compliance artifact generation.

---

## Key Architecture & Features

1. **Cryptographic Identity & Zero-Trust A2A (`core/identity.py`, `core/types.py`)**:
   - Ed25519 payload signatures & JCS (RFC 8785) canonical JSON envelope verification ($< 1.0\text{ ms}$).
   - Time-ordered UUIDv7 identifiers (pure Python native bit-shifting implementation).
   - Dual-tier replay protection (in-memory sliding TTL LRU store + Redis adapter interface).
2. **Defense-in-Depth Security Pipeline (`security/`)**:
   - Layer 1 Regex Ingress Filter ($p95 < 2.0\text{ ms}$).
   - Layer 2 Semantic Similarity (`all-MiniLM-L6-v2`, cosine threshold $\ge 0.85$).
   - Layer 3 LLM Judge (Gemma 2B via Ollama with 2.0s circuit breaker).
   - Structural Tool Intent Parser `(Action, Target, Scope)` and shell command blocklist.
   - PII/Secret output sanitizer (`[REDACTED_*]`) and untrusted RAG XML isolation (`<untrusted_context>`).
3. **Dynamic Trust Scoring & Isolation (`core/trust.py`)**:
   - Stateful score tracking (100 baseline, score decay on security events, incremental recovery).
   - Autonomous agent quarantine at score $\le 20.0$.
4. **Cascading Failure Circuit Breakers & PSI Drift (`governance/circuit_breakers.py`)**:
   - Tool execution timeouts ($5000\text{ ms}$ fail-closed fallback) and inter-agent loop ceiling ($N \le 10$).
   - Population Stability Index ($\text{PSI} \ge 0.20$) detection triggering auto-downgrade to `SHADOW_MODE`.
5. **Themis State-Bound Checkpoints (`governance/themis.py`)**:
   - Pause high-risk actions to `PENDING_HUMAN` over `paused_state_hash`.
   - Ed25519 human reviewer signature validation; state mutation aborts execution.
   - Anti-rubber-stamping telemetry ($< 3000\text{ ms}$ dwell time detection).
6. **Atlas Merkle-DAG Ledger & GDPR Erasure (`ledger/`)**:
   - Multi-parent causal DAG structure with JCS canonical hashing.
   - Immutable policy version commitments (`rule_id @ rule_version_hash`).
   - GDPR Art 17 cryptographic salt destruction (preserves Merkle integrity while deleting data).
   - RFC 3161 timestamp authority anchoring.
7. **5-Layer Composite Explainability & EU AI Act Exporter (`telemetry/`)**:
   - Standardized 5-Layer Explainability payload assembly (DG, MG, SI, CM, AE).
   - CLI command: `agentic-gov export-audit-package --trace-id <UUIDv7> --format annex-iv`.
   - Async PostgreSQL non-blocking queue (`<0.5ms` enqueue, graceful drain on shutdown) & OpenTelemetry trace propagation.

---

## Quickstart & Installation

```bash
pip install agentic-security-governance-runtime
```

### Basic Usage

```python
from agentic_gov.middleware import GovernanceRuntime

runtime = GovernanceRuntime()
agent_id, keypair = runtime.register_agent(name="SearchAgent")

# Intercept prompt ingress
is_safe, receipt, clean_prompt = runtime.inspect_input("Summarize user request")
if not is_safe:
    print(f"Blocked: {receipt.reason}")

# Validate tool execution
is_tool_safe, receipt = runtime.validate_tool(
    agent_id=agent_id,
    tool_name="SearxNGTool",
    query="query text"
)
```

---

## License

Licensed under the Apache License, Version 2.0.
