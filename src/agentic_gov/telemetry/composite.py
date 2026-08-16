import time
import logging
from typing import Dict, Any, Optional

from agentic_gov.core.types import (
    CompositeExplainabilityPayload,
    Layer1DataGovernance,
    Layer2ModelGovernance,
    Layer3SystemIntegration,
    Layer4ControlMonitoring,
    Layer5AuditEvidence,
    GovernanceDecisionReceipt,
    generate_uuidv7
)

logger = logging.getLogger(__name__)


class CompositeExplainabilityBuilder:
    """
    5-Layer Composite Explainability Payload Assembler (SI-2 & AE-1).
    Synthesizes Data Governance, Model Governance, System Integration, Control & Monitoring,
    and Audit Evidence telemetry into a standardized regulatory explainability record in < 5.0ms.
    """

    def assemble(
        self,
        agent_id: str,
        layer1_dg: Layer1DataGovernance,
        layer2_mg: Layer2ModelGovernance,
        layer3_si: Layer3SystemIntegration,
        layer4_cm: Layer4ControlMonitoring,
        layer5_ae: Layer5AuditEvidence,
        trace_id: Optional[str] = None
    ) -> CompositeExplainabilityPayload:
        start_time = time.perf_counter()

        payload = CompositeExplainabilityPayload(
            trace_id=trace_id or generate_uuidv7(),
            timestamp_ns=time.time_ns(),
            agent_id=agent_id,
            layer1_dg=layer1_dg,
            layer2_mg=layer2_mg,
            layer3_si=layer3_si,
            layer4_cm=layer4_cm,
            layer5_ae=layer5_ae
        )

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        logger.debug(f"[EXPLAINABILITY_ASSEMBLED] Assembled 5-Layer payload for trace '{payload.trace_id}' in {latency_ms:.2f}ms")
        return payload
