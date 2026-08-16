import pytest
from agentic_gov.core.trust import AgentTrustEngine
from agentic_gov.core.types import TrustStateEnum
from agentic_gov.governance.circuit_breakers import (
    LoopCeilingBreaker,
    DependencyTimeoutBreaker,
    PSIDriftInterceptor,
    BreakerState
)


def test_trust_score_decay_and_quarantine():
    engine = AgentTrustEngine(quarantine_threshold=20.0)
    agent_id = "agent_test_01"

    assert engine.get_score(agent_id) == 100.0
    assert engine.get_state(agent_id) == TrustStateEnum.ACTIVE

    # Apply penalties
    score, state, receipt = engine.apply_penalty(agent_id, "REGEX_TRIGGER_LAYER1")
    assert score == 75.0
    assert state == TrustStateEnum.ACTIVE
    assert receipt is None

    # Apply heavy penalty
    score, state, receipt = engine.apply_penalty(agent_id, "UNAUTHORIZED_TOOL_ATTEMPT")
    assert score == 25.0
    assert state == TrustStateEnum.ACTIVE

    # Apply penalty causing quarantine (score <= 20.0)
    score, state, receipt = engine.apply_penalty(agent_id, "SCHEMA_VALIDATION_FAILURE")
    assert score == 15.0
    assert state == TrustStateEnum.QUARANTINED
    assert receipt is not None
    assert receipt.action == "QUARANTINE"

    # Verify tool dispatch revoked
    assert engine.can_dispatch_tools(agent_id) is False


def test_trust_score_incremental_recovery():
    engine = AgentTrustEngine()
    agent_id = "agent_test_02"

    engine.apply_penalty(agent_id, "REGEX_TRIGGER_LAYER1")  # 75.0
    score = engine.record_successful_turn(agent_id)
    assert score == 76.0


def test_loop_ceiling_breaker():
    breaker = LoopCeilingBreaker(max_turns=3)
    session_id = "sess_100"

    assert breaker.increment_and_check(session_id)[0] is True  # 1
    assert breaker.increment_and_check(session_id)[0] is True  # 2
    assert breaker.increment_and_check(session_id)[0] is True  # 3

    # 4th turn exceeds ceiling of 3
    is_allowed, turns, receipt = breaker.increment_and_check(session_id)
    assert is_allowed is False
    assert turns == 4
    assert receipt is not None
    assert receipt.action == "HALT"


def test_dependency_timeout_circuit_breaker():
    breaker = DependencyTimeoutBreaker(failure_threshold=3)
    tool_name = "UnstableAPITool"

    assert breaker.can_dispatch(tool_name) is True

    breaker.record_failure_or_timeout(tool_name)
    breaker.record_failure_or_timeout(tool_name)
    assert breaker.can_dispatch(tool_name) is True

    # 3rd failure trips breaker to OPEN
    breaker.record_failure_or_timeout(tool_name)
    assert breaker.get_state(tool_name) == BreakerState.OPEN
    assert breaker.can_dispatch(tool_name) is False


def test_psi_drift_interceptor():
    interceptor = PSIDriftInterceptor(psi_threshold=0.20)
    agent_id = "ml_agent_01"

    # Baseline distribution
    import numpy as np
    np.random.seed(42)
    baseline = list(np.random.normal(loc=50.0, scale=10.0, size=1000))
    # Similar target distribution from same generator (no drift)
    similar_target = list(np.random.normal(loc=50.1, scale=10.0, size=1000))

    is_drifted, psi, receipt = interceptor.evaluate_drift(agent_id, baseline, similar_target)
    assert is_drifted is False
    assert psi < 0.20
    assert receipt is None

    # Heavily shifted distribution (significant drift)
    drifted_target = list(np.random.normal(loc=80.0, scale=15.0, size=1000))
    is_drifted, psi, receipt = interceptor.evaluate_drift(agent_id, baseline, drifted_target)
    assert is_drifted is True
    assert psi >= 0.20
    assert receipt is not None
    assert receipt.action == "SHADOW"
