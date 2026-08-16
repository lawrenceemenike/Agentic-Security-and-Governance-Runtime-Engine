import time
import math
import logging
from enum import Enum
from typing import Dict, List, Tuple, Optional, Any
import numpy as np

from agentic_gov.core.types import GovernanceDecisionReceipt, TrustStateEnum

logger = logging.getLogger(__name__)


class BreakerState(str, Enum):
    CLOSED = "CLOSED"  # Normal operation
    OPEN = "OPEN"      # Tripped, failing closed
    HALF_OPEN = "HALF_OPEN"


class LoopCeilingBreaker:
    """
    Execution Loop Ceiling Monitor (SI-3).
    Enforces hard maximum ceiling (default N <= 10 turns) to prevent infinite inter-agent recursion.
    """

    def __init__(self, max_turns: int = 10):
        self.max_turns = max_turns
        # session_id -> turn count
        self._turn_counts: Dict[str, int] = {}

    def increment_and_check(self, session_id: str) -> Tuple[bool, int, Optional[GovernanceDecisionReceipt]]:
        """
        Increments turn count for session_id.
        Returns (is_allowed, current_turns, receipt).
        """
        current_turns = self._turn_counts.get(session_id, 0) + 1
        self._turn_counts[session_id] = current_turns

        if current_turns > self.max_turns:
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-03",
                action="HALT",
                target_stage="LOOP_CEILING",
                reason=f"Execution loop ceiling exceeded: {current_turns} turns > max allowed {self.max_turns}",
                details={"session_id": session_id, "turns": current_turns, "max_turns": self.max_turns}
            )
            logger.error(f"[LOOP_CEILING_TRIPPED] Session '{session_id}' exceeded max turn ceiling ({current_turns} > {self.max_turns}).")
            return False, current_turns, receipt

        return True, current_turns, None

    def reset(self, session_id: str):
        self._turn_counts.pop(session_id, None)


class DependencyTimeoutBreaker:
    """
    Dependency & Tool Timeout Circuit Breaker (Fail-Closed).
    Enforces tool execution timeout (default 5000 ms).
    Trips breaker to OPEN after failure_threshold (default 3) consecutive failures,
    routing requests to manual review fallback queue.
    """

    def __init__(self, timeout_ms: float = 5000.0, failure_threshold: int = 3, recovery_time_s: float = 30.0):
        self.timeout_ms = timeout_ms
        self.failure_threshold = failure_threshold
        self.recovery_time_s = recovery_time_s

        # tool_name -> state
        self._states: Dict[str, BreakerState] = {}
        # tool_name -> consecutive failures
        self._failures: Dict[str, int] = {}
        # tool_name -> timestamp of trip
        self._trip_times: Dict[str, float] = {}

    def get_state(self, tool_name: str) -> BreakerState:
        state = self._states.get(tool_name, BreakerState.CLOSED)
        if state == BreakerState.OPEN:
            trip_time = self._trip_times.get(tool_name, 0.0)
            if time.time() - trip_time > self.recovery_time_s:
                self._states[tool_name] = BreakerState.HALF_OPEN
                return BreakerState.HALF_OPEN
        return state

    def record_success(self, tool_name: str):
        self._failures[tool_name] = 0
        self._states[tool_name] = BreakerState.CLOSED

    def record_failure_or_timeout(self, tool_name: str, is_timeout: bool = True) -> GovernanceDecisionReceipt:
        consecutive = self._failures.get(tool_name, 0) + 1
        self._failures[tool_name] = consecutive

        receipt = GovernanceDecisionReceipt(
            asi_code="ASI-02",
            action="FALLBACK",
            target_stage="TOOL_TIMEOUT",
            reason=f"Tool '{tool_name}' {'timed out (> ' + str(self.timeout_ms) + 'ms)' if is_timeout else 'failed'}. Consecutive failures: {consecutive}",
            details={"tool_name": tool_name, "consecutive_failures": consecutive}
        )

        if consecutive >= self.failure_threshold:
            self._states[tool_name] = BreakerState.OPEN
            self._trip_times[tool_name] = time.time()
            logger.error(f"[CIRCUIT_BREAKER_OPEN] Dependency circuit breaker OPEN for tool '{tool_name}' ({consecutive} consecutive failures). Route directed to manual review fallback.")

        return receipt

    def can_dispatch(self, tool_name: str) -> bool:
        return self.get_state(tool_name) != BreakerState.OPEN


class PSIDriftInterceptor:
    """
    Population Stability Index (PSI) Real-Time Feature Drift Detector (CM-5).
    Computes PSI between baseline feature distribution and sliding operational window.
    If PSI >= 0.20, triggers alert and downgrades agent to SHADOW_MODE.
    """

    def __init__(self, psi_threshold: float = 0.20, num_bins: int = 10):
        self.psi_threshold = psi_threshold
        self.num_bins = num_bins

    def calculate_psi(self, baseline: List[float], target: List[float]) -> float:
        """
        Calculates Population Stability Index (PSI) across numeric features.
        PSI = sum((P_i - Q_i) * ln(P_i / Q_i))
        """
        if not baseline or not target:
            return 0.0

        base_arr = np.array(baseline, dtype=float)
        target_arr = np.array(target, dtype=float)

        # Create bin boundaries based on baseline quantiles
        percentiles = np.linspace(0, 100, self.num_bins + 1)
        bin_edges = np.percentile(base_arr, percentiles)
        bin_edges[0] -= 1e-5
        bin_edges[-1] += 1e-5

        # Compute histograms
        base_counts, _ = np.histogram(base_arr, bins=bin_edges)
        target_counts, _ = np.histogram(target_arr, bins=bin_edges)

        # Convert to proportions with smoothing epsilon to prevent division by zero
        eps = 1e-4
        P = (base_counts + eps) / (len(base_arr) + eps * self.num_bins)
        Q = (target_counts + eps) / (len(target_arr) + eps * self.num_bins)

        psi_val = np.sum((P - Q) * np.log(P / Q))
        return float(psi_val)

    def evaluate_drift(
        self,
        agent_id: str,
        baseline_features: List[float],
        current_features: List[float]
    ) -> Tuple[bool, float, Optional[GovernanceDecisionReceipt]]:
        """
        Evaluates PSI score for agent.
        Returns (is_drifted, psi_score, receipt).
        If psi_score >= 0.20, triggers SHADOW_MODE downgrade receipt.
        """
        psi_score = self.calculate_psi(baseline_features, current_features)
        is_drifted = psi_score >= self.psi_threshold

        receipt = None
        if is_drifted:
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-03",
                action="SHADOW",
                target_stage="PSI_DRIFT_INTERCEPTOR",
                reason=f"Feature distribution drift PSI ({psi_score:.4f}) >= threshold ({self.psi_threshold}). Agent downgraded to SHADOW_MODE.",
                details={"agent_id": agent_id, "psi_score": round(psi_score, 4), "threshold": self.psi_threshold}
            )
            logger.warning(f"[PSI_DRIFT_DETECTED] Agent '{agent_id}' feature drift PSI={psi_score:.4f} >= {self.psi_threshold}. Downgrading to SHADOW_MODE.")

        return is_drifted, psi_score, receipt
