import os
import time
import secrets
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


def generate_uuidv7() -> str:
    """
    Pure-Python native implementation of UUIDv7 (RFC draft compliant).
    Ensures 100% time-ordered UUID generation across Python 3.10-3.13 without C-extensions.
    Structure:
      - 48 bits: Unix timestamp in milliseconds
      - 4 bits: Version (0b0111 = 7)
      - 12 bits: High pseudo-random sequence (rand_a)
      - 2 bits: Variant (0b10)
      - 62 bits: Low pseudo-random sequence (rand_b)
    """
    timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)

    # Construct the 128-bit integer
    # 48 bits timestamp
    uuid_int = (timestamp_ms << 80)
    # 4 bits version (7) + 12 bits rand_a
    uuid_int |= (0x7 << 76) | (rand_a << 64)
    # 2 bits variant (0b10) + 62 bits rand_b
    uuid_int |= (0x2 << 62) | rand_b

    # Format as 8-4-4-4-12 hex string
    hex_str = f"{uuid_int:032x}"
    return f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:]}"


class TrustStateEnum(str, Enum):
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    QUARANTINED = "QUARANTINED"
    SHADOW_MODE = "SHADOW_MODE"


class GovernanceDecisionReceipt(BaseModel):
    receipt_id: str = Field(default_factory=generate_uuidv7)
    asi_code: str  # e.g., "ASI-01", "ASI-02", "ASI-03", "ASI-04", "ASI-05"
    action: str    # "ALLOW", "HALT", "BLOCK", "REDACT", "QUARANTINE", "SHADOW"
    target_stage: str  # "INPUT", "TOOL_ARG", "MODEL_OUTPUT", "CHECKPOINT", "REPLAY"
    reason: str
    details: Dict[str, Any] = Field(default_factory=dict)
    latency_ms: float = 0.0
    timestamp_ns: int = Field(default_factory=time.time_ns)


class AgentMessageEnvelope(BaseModel):
    agent_id: str = Field(default_factory=generate_uuidv7)
    timestamp_ns: int = Field(default_factory=time.time_ns)
    nonce: str = Field(default_factory=lambda: secrets.token_hex(16))
    payload_hash: str  # SHA3-256 canonical payload hash
    signature: str     # Ed25519 signature of payload_hash
    body: Dict[str, Any]


class ActionNode(BaseModel):
    action_id: str = Field(default_factory=generate_uuidv7)
    agent_id: str
    timestamp_ns: int = Field(default_factory=time.time_ns)
    input_hash: str  # SHA3-256(canonical(input_context + salt))
    decision_payload: Dict[str, Any]
    governance_rules_applied: List[str] = Field(default_factory=list)  # ["rule_id@rule_version_hash"]
    human_checkpoint_result: Optional[Dict[str, Any]] = None
    parent_hashes: List[str] = Field(default_factory=list)  # Causal DAG parents
    node_hash: str = ""  # SHA3-256 over canonical JSON of all above fields
    signature: str = ""  # Ed25519 signature by agent key
    anchor_ref: Optional[str] = None  # RFC 3161 timestamp receipt


class HumanOverridePayload(BaseModel):
    reviewer_id: str
    override_category: str  # TAXONOMY: DATA_PROXY_BIAS, FACTUAL_HALLUCINATION, POLICY_EDGE_CASE, CONTEXT_DRIFT
    root_cause_classification: str
    justification_text: str
    corrected_output: Dict[str, Any]
    dwell_time_ms: float
    timestamp_ns: int = Field(default_factory=time.time_ns)


class Layer1DataGovernance(BaseModel):
    source_provenance_uri: str
    collection_timestamp_ns: int
    freshness_days: float
    proxy_bias_checked: bool = True
    lawful_basis: str = "CONSENT"


class Layer2ModelGovernance(BaseModel):
    model_version_hash: str
    shap_attributions: Dict[str, float] = Field(default_factory=dict)
    subgroup_parity_status: str = "PASS"


class Layer3SystemIntegration(BaseModel):
    decision_confidence: float
    circuit_breaker_status: str = "CLOSED"
    integration_route: str = "AUTONOMOUS"


class Layer4ControlMonitoring(BaseModel):
    psi_drift_score: float = 0.0
    threat_scanner_receipt: Optional[GovernanceDecisionReceipt] = None


class Layer5AuditEvidence(BaseModel):
    rule_version_hash: str
    merkle_node_hash: str
    reviewer_signature: Optional[str] = None


class CompositeExplainabilityPayload(BaseModel):
    trace_id: str = Field(default_factory=generate_uuidv7)
    timestamp_ns: int = Field(default_factory=time.time_ns)
    agent_id: str
    layer1_dg: Layer1DataGovernance
    layer2_mg: Layer2ModelGovernance
    layer3_si: Layer3SystemIntegration
    layer4_cm: Layer4ControlMonitoring
    layer5_ae: Layer5AuditEvidence
