# Agentic Security & Governance Runtime Engine

**A deterministic runtime control layer for autonomous AI agents.**

[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-research%20%2F%20open%20source-orange.svg)](#project-status)

Agentic systems are increasingly capable of making decisions, calling tools, accessing data, communicating with other agents, and initiating downstream actions.

The problem is no longer only whether an AI model produces a safe response.

The problem is:

> **What happens when an autonomous agent attempts to take an action?**

The **Agentic Security & Governance Runtime Engine (`agentic-gov`)** provides a runtime control boundary between an agent's intent and its ability to execute.

It combines **security enforcement, governance controls, risk evaluation, human oversight, runtime isolation, and auditability** into a single execution layer.

```text
                    AUTONOMOUS AI AGENT
                           │
                           │ intent / request
                           ▼
                 ┌──────────────────────┐
                 │   RUNTIME CONTROL    │
                 │       LAYER          │
                 └──────────┬───────────┘
                            │
             ┌──────────────┼──────────────┐
             │              │              │
             ▼              ▼              ▼
          SECURITY       GOVERNANCE      TRUST
          CONTROLS        POLICIES       SCORE
             │              │              │
             └──────────────┼──────────────┘
                            │
                    ┌───────▼───────┐
                    │ HUMAN REVIEW  │
                    │  IF REQUIRED  │
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │   EXECUTE OR   │
                    │     BLOCK      │
                    └───────┬───────┘
                            │
                            ▼
                    ┌───────────────┐
                    │ AUDIT / TRACE │
                    └───────────────┘
```

## Why this exists

Traditional application security controls were generally designed around software with relatively predictable execution paths.

Agentic systems introduce another layer:

```text
Model
  ↓
Reasoning
  ↓
Tool selection
  ↓
Identity
  ↓
Permissions
  ↓
Data access
  ↓
External action
  ↓
Downstream consequences
```

An agent may be authorized to perform a legitimate task while still possessing more functionality, permissions, autonomy, or execution freedom than that task requires.

This creates a control problem that sits between the **AI model** and the **systems the AI can influence**.

The runtime engine is designed around that boundary.

### Core principle

> **The model can determine what it wants to do. The runtime determines what it is allowed to do.**

This distinction allows probabilistic AI systems to operate inside deterministic security and governance boundaries.

---

# What the Runtime Controls

The engine is designed around six core control domains.

| Domain              | Purpose                                                  |
| ------------------- | -------------------------------------------------------- |
| **Identity**        | Establish trusted agent and human identities             |
| **Security**        | Detect and block unsafe prompts, tool calls and outputs  |
| **Governance**      | Apply runtime policies and risk controls                 |
| **Human Oversight** | Pause high-risk actions for state-bound approval         |
| **Resilience**      | Detect loops, excessive consumption and behavioral drift |
| **Auditability**    | Preserve causal, versioned evidence of decisions         |

---

# Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    AGENTIC APPLICATION                       │
│                                                             │
│   Agent → Model → Reasoning → Tool / API / Data Access      │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              AGENTIC-GOV RUNTIME CONTROL LAYER              │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌─────────────────┐ │
│  │   Identity   │ → │   Security   │ → │   Governance    │ │
│  └──────────────┘   └──────────────┘   └─────────────────┘ │
│          │                  │                    │           │
│          ▼                  ▼                    ▼           │
│  Signed Identity      Threat / Input       Policy / Risk    │
│  Replay Protection    Tool Validation      Enforcement      │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌─────────────────┐ │
│  │    Trust     │ → │  Checkpoint  │ → │  Circuit Breaker│ │
│  └──────────────┘   └──────────────┘   └─────────────────┘ │
│                                                             │
│          │                  │                    │           │
│          └──────────────────┼────────────────────┘           │
│                             ▼                               │
│                    EXECUTE / BLOCK                           │
│                             │                               │
│                             ▼                               │
│                    ┌────────────────┐                       │
│                    │ Causal Ledger  │                       │
│                    └────────────────┘                       │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
                  Enterprise systems / tools
```

---

# Core Capabilities

## 01 — Cryptographic Agent Identity

Agents are assigned cryptographic identities and can exchange signed, canonicalized payloads.

Current implementation includes:

* Ed25519 payload signatures
* JCS / RFC 8785 canonical JSON
* UUIDv7 identifiers
* Replay protection
* In-memory sliding TTL LRU protection
* Redis adapter interface

The objective is to establish a verifiable identity and message integrity boundary for agent-to-agent communication.

---

## 02 — Runtime Security Enforcement

The security pipeline evaluates agent interactions before execution.

Current controls include:

### Input protection

* Regex-based ingress filtering
* Semantic similarity detection
* LLM-based security judging
* Untrusted-context isolation
* Prompt inspection

### Tool security

* Structural tool-intent parsing
* Action / Target / Scope extraction
* Tool validation
* Shell-command blocklists

### Output protection

* PII detection
* Secret detection
* Output sanitization
* Redaction controls

The security layer is designed as defense-in-depth rather than relying on a single detection mechanism.

---

# 03 — Runtime Governance

Security alone is not sufficient for autonomous systems.

The governance layer introduces controls over **what an agent is permitted to do, under what conditions, and with what level of autonomy.**

Examples include:

* Runtime policy enforcement
* Risk-based execution controls
* Agent trust scoring
* Autonomous quarantine
* Human approval checkpoints
* Policy version commitments
* Runtime state validation
* Behavioral drift detection

The goal is to move governance from a static policy document into an **enforceable runtime mechanism**.

---

# 04 — Dynamic Trust & Agent Isolation

Agents maintain a stateful trust score.

Security and behavioral events can reduce the agent's trust score, while controlled recovery allows the score to improve over time.

Agents reaching the configured quarantine threshold can automatically transition into an isolated state.

```text
             Agent starts
                  │
                  ▼
             Trust = 100
                  │
        ┌─────────┴─────────┐
        │                   │
   Safe behavior       Security event
        │                   │
        ▼                   ▼
   Recover slowly       Trust decreases
                            │
                            ▼
                     Trust ≤ threshold
                            │
                            ▼
                       QUARANTINE
```

This provides a mechanism for treating trust as a **runtime state**, rather than a static property of an agent.

---

# 05 — Human-in-the-Loop Governance

High-risk actions can be paused before execution.

The runtime creates a state-bound checkpoint containing the state required for the approval decision.

Human reviewers authenticate their approval using cryptographic signatures.

If the underlying state changes after approval, execution is aborted rather than allowing the original approval to be reused against a different state.

The implementation also includes telemetry intended to identify potential rubber-stamping behavior.

```text
Agent action
     │
     ▼
Risk evaluation
     │
     ├──────── Low risk ────────→ Execute
     │
     ▼
 High risk
     │
     ▼
PENDING_HUMAN
     │
     ▼
Human review
     │
     ├── Reject ────────────────→ Block
     │
     └── Approve
            │
            ▼
     State validation
            │
       ┌────┴────┐
       │         │
   unchanged   changed
       │         │
       ▼         ▼
    Execute    Abort
```

---

# 06 — Resilience & Runtime Circuit Breakers

Autonomous systems can fail through cascading behavior even without a traditional security compromise.

The runtime therefore includes controls for:

* Tool execution timeouts
* Fail-closed execution
* Inter-agent loop ceilings
* Behavioral drift detection
* Population Stability Index monitoring
* Automatic downgrade to `SHADOW_MODE`

These controls are designed to prevent abnormal agent behavior from propagating indefinitely through connected systems.

---

# 07 — Causal Decision Ledger

Every important runtime decision should be explainable after the fact.

The engine uses a multi-parent Merkle-DAG structure to preserve causal relationships between events.

The ledger records information such as:

* Agent identity
* Runtime events
* Security decisions
* Governance decisions
* Policy versions
* Human approvals
* Execution outcomes
* Causal relationships

Policy versions can be committed using identifiers such as:

```text
rule_id @ rule_version_hash
```

The implementation also supports RFC 3161 timestamp authority anchoring.

---

# 08 — Privacy & Cryptographic Erasure

The runtime includes a mechanism for GDPR Article 17-oriented data erasure while maintaining the integrity of the surrounding audit structure.

Cryptographic salt destruction can make protected data unrecoverable while preserving the structural integrity of the Merkle ledger.

This is intended to address a difficult requirement in immutable audit systems:

> **How do you preserve evidence integrity without making personal data permanently undeletable?**

---

# 09 — Explainability & Compliance Evidence

Runtime events can be assembled into structured explainability and audit payloads.

The current implementation includes a five-layer explainability model covering:

* Data Governance
* Model Governance
* Security & Integrity
* Compliance
* Agent Execution

The engine also provides a CLI workflow for generating audit packages:

```bash
agentic-gov export-audit-package \
    --trace-id <UUIDv7> \
    --format annex-iv
```

This creates a bridge between runtime activity and downstream governance/compliance processes.

---

# 10 — Observability

The runtime is designed to integrate with operational observability infrastructure.

Current capabilities include:

* OpenTelemetry trace propagation
* Asynchronous PostgreSQL persistence
* Non-blocking event enqueueing
* Graceful queue draining during shutdown
* Trace-level correlation

The objective is to make governance and security events observable alongside the application's existing operational telemetry.

---

# Example

```python
from agentic_gov.middleware import GovernanceRuntime

runtime = GovernanceRuntime()

agent_id, keypair = runtime.register_agent(
    name="SearchAgent"
)

# Inspect incoming prompt
is_safe, receipt, clean_prompt = runtime.inspect_input(
    "Summarize the latest regulatory filing"
)

if not is_safe:
    print(f"Blocked: {receipt.reason}")

# Validate a tool invocation
is_tool_safe, receipt = runtime.validate_tool(
    agent_id=agent_id,
    tool_name="SearxNGTool",
    query="latest regulatory filing"
)

if not is_tool_safe:
    print(f"Tool call blocked: {receipt.reason}")
```

The application remains responsible for the actual agent implementation.

`agentic-gov` provides the runtime control layer around that implementation.

---

# Security Model

The project is based on a simple architectural assumption:

> **An AI model should not be treated as the final authority over enterprise actions.**

The runtime therefore separates:

### Intent

What the agent wants to do.

### Authorization

What the agent is permitted to do.

### Enforcement

Whether the requested action is allowed to execute.

### Oversight

Whether human approval is required.

### Evidence

What happened, why it happened, which policy was applied, and what the final outcome was.

This separation is particularly important for agents with access to:

* Enterprise data
* External APIs
* Databases
* File systems
* MCP servers
* Other AI agents
* Financial or operational systems

---

# Governance Model

The engine is designed to support governance controls across the agent lifecycle:

```text
DISCOVER
   ↓
IDENTIFY
   ↓
ASSESS
   ↓
AUTHORIZE
   ↓
MONITOR
   ↓
ENFORCE
   ↓
REVIEW
   ↓
AUDIT
   ↓
IMPROVE
```

This is intentionally different from treating governance as a static compliance document.

The objective is **policy → runtime decision → evidence**.

---

# Relationship to Existing Frameworks

The runtime is designed as an implementation layer that can sit beneath organizational governance frameworks rather than replacing them.

Potential control mappings include:

* NIST AI RMF
* ISO/IEC 42001
* EU AI Act
* GDPR
* OWASP GenAI Security
* OWASP Agentic Security
* MITRE ATLAS

Framework mappings should be treated as implementation guidance rather than claims of formal compliance or certification.

---

# Project Status

This project is an **open-source engineering and research project** exploring runtime security and governance for autonomous AI systems.

It is not currently positioned as a certified compliance product.

Performance characteristics, security guarantees and compliance mappings should be independently validated before production deployment in high-risk environments.

Future work includes:

* Expanded policy-as-code capabilities
* Formal threat modeling
* Larger adversarial test suites
* Agent framework integrations
* MCP integrations
* Policy evaluation benchmarks
* Runtime performance benchmarks
* False-positive / false-negative measurement
* Distributed deployment patterns
* Key management integrations
* Additional regulatory control mappings

---

# Roadmap

### Phase 1 — Runtime Foundation

* [x] Agent identity
* [x] Signed messages
* [x] Replay protection
* [x] Runtime security inspection
* [x] Tool validation
* [x] Trust scoring
* [x] Runtime quarantine

### Phase 2 — Governance

* [x] Human checkpoints
* [x] Policy version commitments
* [x] Circuit breakers
* [x] Behavioral drift detection
* [x] Audit ledger
* [x] Explainability payloads

### Phase 3 — Evidence & Integration

* [x] OpenTelemetry propagation
* [x] Audit package generation
* [x] GDPR-oriented cryptographic erasure
* [x] EU AI Act-oriented evidence export
* [ ] Formal benchmark suite
* [ ] Adversarial evaluation suite
* [ ] Agent framework integrations
* [ ] MCP integration

### Phase 4 — Production Hardening

* [ ] Distributed runtime deployment
* [ ] Production key management
* [ ] High-availability persistence
* [ ] Performance benchmarking
* [ ] Security assessment
* [ ] Formal threat model
* [ ] Expanded policy engine

---

# Who Is This For?

`agentic-gov` is intended for engineers and researchers building autonomous AI systems where runtime behavior requires stronger controls.

Potential use cases include:

* Enterprise AI agents
* Multi-agent systems
* AI copilots with tool access
* Regulated AI applications
* Autonomous research systems
* Financial AI systems
* Healthcare AI systems
* Government / sovereign AI environments
* AI platforms requiring runtime governance

---

# Design Philosophy

The project is built around five principles:

### 1. Least Privilege

Agents should receive only the capabilities required for the task.

### 2. Deterministic Enforcement

Critical security and governance decisions should not depend solely on probabilistic model behavior.

### 3. Human Accountability

High-impact autonomous actions should have an explicit mechanism for human intervention where required.

### 4. Evidence by Default

Important decisions should generate traceable evidence rather than relying on retrospective reconstruction.

### 5. Fail Closed

When critical security or governance controls cannot establish that an action is safe and authorized, the default should be to prevent execution.

---

# Contributing

Contributions are welcome.

Areas where contributions are particularly valuable:

* New runtime security controls
* Policy engine development
* Agent framework adapters
* MCP integrations
* Adversarial test cases
* Governance control mappings
* Performance benchmarks
* Threat modeling
* Documentation
* Compliance evidence formats

Please open an issue before major architectural changes.

---

# License

Licensed under the **Apache License 2.0**.

---

## Disclaimer

This project is provided for research, engineering and educational purposes.

It should not be interpreted as a guarantee of security, regulatory compliance, or certification against any referenced framework or regulation.

Organizations should independently validate controls against their own threat models, regulatory obligations, infrastructure and risk requirements.
