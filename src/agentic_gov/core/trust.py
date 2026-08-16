import time
import logging
from typing import Dict, Any, Optional, List, Tuple

from agentic_gov.core.types import TrustStateEnum, GovernanceDecisionReceipt

logger = logging.getLogger(__name__)


class AgentTrustEngine:
    """
    Stateful Agent Trust Scoring & Autonomous Quarantine Engine (OWASP SI-3).
    Tracks real-time trust score decay, incremental recovery over sliding windows,
    and triggers autonomous isolation when score drops below critical threshold (20.0).
    """

    PENALTIES = {
        "SCHEMA_VALIDATION_FAILURE": 10.0,
        "REGEX_TRIGGER_LAYER1": 25.0,
        "UNAUTHORIZED_TOOL_ATTEMPT": 50.0,
        "SIGNATURE_FAILURE": 100.0,
        "TIMED_OUT": 15.0,
    }

    def __init__(self, quarantine_threshold: float = 20.0, recovery_rate: float = 1.0):
        self.quarantine_threshold = quarantine_threshold
        self.recovery_rate = recovery_rate
        # agent_id -> trust_score (float)
        self._scores: Dict[str, float] = {}
        # agent_id -> TrustStateEnum
        self._states: Dict[str, TrustStateEnum] = {}
        # agent_id -> list of violation history
        self._history: Dict[str, List[Dict[str, Any]]] = {}

    def get_score(self, agent_id: str) -> float:
        if agent_id not in self._scores:
            self._scores[agent_id] = 100.0
            self._states[agent_id] = TrustStateEnum.ACTIVE
            self._history[agent_id] = []
        return self._scores[agent_id]

    def get_state(self, agent_id: str) -> TrustStateEnum:
        self.get_score(agent_id)  # Ensure initialized
        return self._states[agent_id]

    def set_state(self, agent_id: str, new_state: TrustStateEnum):
        self._states[agent_id] = new_state

    def apply_penalty(self, agent_id: str, violation_type: str, details: Optional[Dict[str, Any]] = None) -> Tuple[float, TrustStateEnum, Optional[GovernanceDecisionReceipt]]:
        """
        Applies deterministic penalty to agent trust score.
        Trips circuit breaker to QUARANTINED if score <= quarantine_threshold (20.0).
        """
        current_score = self.get_score(agent_id)
        penalty = self.PENALTIES.get(violation_type, 15.0)

        new_score = max(0.0, current_score - penalty)
        self._scores[agent_id] = new_score

        history_entry = {
            "timestamp_ns": time.time_ns(),
            "event": "PENALTY",
            "violation_type": violation_type,
            "penalty": penalty,
            "old_score": current_score,
            "new_score": new_score,
            "details": details or {}
        }
        self._history[agent_id].append(history_entry)

        receipt = None
        if new_score <= self.quarantine_threshold and self._states[agent_id] != TrustStateEnum.QUARANTINED:
            self._states[agent_id] = TrustStateEnum.QUARANTINED
            logger.error(f"[QUARANTINE_TRIGGERED] Agent '{agent_id}' trust score dropped to {new_score:.1f} (<= {self.quarantine_threshold}). Autonomous isolation enforced.")
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-03",
                action="QUARANTINE",
                target_stage="TRUST_ENGINE",
                reason=f"Agent '{agent_id}' trust score degraded to {new_score:.1f} <= threshold {self.quarantine_threshold}",
                details={"agent_id": agent_id, "score": new_score, "last_violation": violation_type}
            )

        return new_score, self._states[agent_id], receipt

    def record_successful_turn(self, agent_id: str) -> float:
        """
        Incrementally recovers score (+1.0 per successful turn) up to maximum 100.0.
        Does not automatically un-quarantine an agent.
        """
        current_score = self.get_score(agent_id)
        if self._states[agent_id] == TrustStateEnum.QUARANTINED:
            return current_score  # No score recovery while quarantined

        new_score = min(100.0, current_score + self.recovery_rate)
        self._scores[agent_id] = new_score

        if new_score >= 80.0 and self._states[agent_id] == TrustStateEnum.DEGRADED:
            self._states[agent_id] = TrustStateEnum.ACTIVE

        return new_score

    def can_dispatch_tools(self, agent_id: str) -> bool:
        """Returns False if agent is QUARANTINED or SHADOW_MODE."""
        state = self.get_state(agent_id)
        return state in (TrustStateEnum.ACTIVE, TrustStateEnum.DEGRADED)
