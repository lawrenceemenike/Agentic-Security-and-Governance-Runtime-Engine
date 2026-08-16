import time
import logging
from typing import Dict, Any, Optional, List, Tuple, Set

from agentic_gov.core.types import (
    GovernanceDecisionReceipt,
    AgentMessageEnvelope,
    ActionNode,
    TrustStateEnum,
    Layer1DataGovernance,
    Layer2ModelGovernance,
    Layer3SystemIntegration,
    Layer4ControlMonitoring,
    Layer5AuditEvidence,
    CompositeExplainabilityPayload
)
from agentic_gov.core.identity import (
    AgentIdentity,
    AgentIdentityRegistry,
    NonceReplayStore,
    sign_envelope,
    verify_envelope
)
from agentic_gov.core.trust import AgentTrustEngine
from agentic_gov.security.interceptor import DefenseInDepthInterceptor
from agentic_gov.security.tool_gate import ToolIntentGate
from agentic_gov.security.sanitization import OutputSanitizer
from agentic_gov.governance.circuit_breakers import (
    LoopCeilingBreaker,
    DependencyTimeoutBreaker,
    PSIDriftInterceptor
)
from agentic_gov.governance.policy import (
    PolicyRegistry,
    PurposeLimitationGate,
    DataFreshnessAttestor
)
from agentic_gov.governance.themis import ThemisCheckpointEngine, CheckpointStatus
from agentic_gov.ledger.atlas import AtlasMerkleDAG
from agentic_gov.ledger.privacy import EphemeralSaltStore
from agentic_gov.ledger.anchor import RFC3161TimestampAnchor
from agentic_gov.telemetry.composite import CompositeExplainabilityBuilder
from agentic_gov.telemetry.storage import AsyncTelemetrySink
from agentic_gov.telemetry.otel import OTelTracePropagator

logger = logging.getLogger(__name__)


class GovernanceRuntime:
    """
    Unified Agentic Governance & Security Interceptor Engine.
    Hooks into agent frameworks (LangGraph, AutoGen, CrewAI, raw async loops) to enforce
    sub-5ms deterministic security scanning, stateful trust scoring, state-bound checkpoints,
    Merkle-DAG decision logging, and compliance explainability.
    """

    def __init__(
        self,
        allowed_tools: Optional[Set[str]] = None,
        db_dsn: Optional[str] = None,
        enable_layer2: bool = True,
        enable_layer3: bool = False
    ):
        # 1. Identity & Replay Store
        self.registry = AgentIdentityRegistry()
        self.nonce_store = NonceReplayStore()

        # 2. Security Pipeline
        self.interceptor = DefenseInDepthInterceptor(enable_layer2=enable_layer2, enable_layer3=enable_layer3)
        self.tool_gate = ToolIntentGate(allowed_tools=allowed_tools)
        self.sanitizer = OutputSanitizer()

        # 3. Trust & Circuit Breakers
        self.trust_engine = AgentTrustEngine()
        self.loop_breaker = LoopCeilingBreaker(max_turns=10)
        self.tool_breaker = DependencyTimeoutBreaker(timeout_ms=5000.0)
        self.psi_interceptor = PSIDriftInterceptor(psi_threshold=0.20)

        # 4. Governance & Policy
        self.policy_registry = PolicyRegistry()
        self.purpose_gate = PurposeLimitationGate()
        self.freshness_attestor = DataFreshnessAttestor(max_freshness_days=30.0)
        self.themis = ThemisCheckpointEngine()

        # 5. Ledger & Privacy
        self.atlas = AtlasMerkleDAG()
        self.salt_store = EphemeralSaltStore()
        self.anchor = RFC3161TimestampAnchor()

        # 6. Telemetry & OTel
        self.composite_builder = CompositeExplainabilityBuilder()
        self.telemetry_sink = AsyncTelemetrySink(db_dsn=db_dsn)
        self.otel = OTelTracePropagator()

    def register_agent(
        self,
        name: str = "Agent",
        roles: Optional[List[str]] = None,
        permissions: Optional[Set[str]] = None
    ) -> Tuple[str, AgentIdentity]:
        """Registers a new agent identity in the runtime."""
        identity = AgentIdentity()
        self.registry.register_agent(
            agent_id=identity.agent_id,
            public_key=identity.public_key,
            roles=roles,
            permissions=permissions
        )
        logger.info(f"[RUNTIME] Registered agent '{name}' with Agent ID '{identity.agent_id}'")
        return identity.agent_id, identity

    def inspect_input(self, payload: str, stage: str = "INPUT") -> Tuple[bool, Optional[GovernanceDecisionReceipt], str]:
        """
        Intercepts ingress prompt across Layer 1-3 injection scanners (< 5ms overhead).
        """
        return self.interceptor.inspect_input(payload, stage=stage)

    def validate_tool(
        self,
        agent_id: str,
        tool_name: str,
        query: str
    ) -> Tuple[bool, Optional[GovernanceDecisionReceipt]]:
        """
        Validates agent tool dispatch against trust score, allowlist, argument constraints,
        and dependency circuit breaker state.
        """
        # Check trust score quarantine
        if not self.trust_engine.can_dispatch_tools(agent_id):
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-01",
                action="BLOCK",
                target_stage="TOOL_GATE",
                reason=f"Agent '{agent_id}' is in state {self.trust_engine.get_state(agent_id)} and cannot execute tools.",
                details={"agent_id": agent_id, "state": self.trust_engine.get_state(agent_id)}
            )
            return False, receipt

        # Check dependency breaker state
        if not self.tool_breaker.can_dispatch(tool_name):
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-02",
                action="FALLBACK",
                target_stage="TOOL_GATE",
                reason=f"Circuit breaker for tool '{tool_name}' is OPEN. Directed to manual review fallback.",
                details={"tool_name": tool_name}
            )
            return False, receipt

        # Perform structural tool gate check
        is_safe, receipt = self.tool_gate.validate_tool_call(tool_name, query)
        if not is_safe and receipt:
            # Apply trust penalty on violation
            penalty_type = "UNAUTHORIZED_TOOL_ATTEMPT" if receipt.asi_code == "ASI-01" else "REGEX_TRIGGER_LAYER1"
            self.trust_engine.apply_penalty(agent_id, penalty_type)

        return is_safe, receipt

    def sanitize_output(self, text: str) -> Tuple[str, Optional[GovernanceDecisionReceipt]]:
        """Redacts PII and secrets from model output text."""
        return self.sanitizer.sanitize_output(text)

    def record_decision_node(
        self,
        agent_identity: AgentIdentity,
        input_payload: Dict[str, Any],
        decision_payload: Dict[str, Any],
        rules_applied: List[str],
        parent_hashes: Optional[List[str]] = None,
        human_checkpoint_result: Optional[Dict[str, Any]] = None
    ) -> ActionNode:
        """
        Constructs and records an ActionNode in the Atlas Merkle-DAG decision ledger.
        """
        payload_id = f"tx_{time.time_ns()}"
        salt_hex, salted_hash = self.salt_store.generate_and_store_salt(payload_id, input_payload)

        node = self.atlas.create_action_node(
            agent_identity=agent_identity,
            input_payload=input_payload,
            decision_payload=decision_payload,
            governance_rules_applied=rules_applied,
            salt=salt_hex,
            parent_hashes=parent_hashes,
            human_checkpoint_result=human_checkpoint_result
        )

        # Record telemetry
        self.telemetry_sink.enqueue_event("MERKLE_NODE", node.model_dump())
        return node
