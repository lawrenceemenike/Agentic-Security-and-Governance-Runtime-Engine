import time
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from agentic_gov.governance.themis import (
    ThemisCheckpointEngine,
    CheckpointStatus,
    OVERRIDE_TAXONOMY
)
from agentic_gov.core.types import HumanOverridePayload


def test_themis_state_bound_approval_workflow():
    engine = ThemisCheckpointEngine(min_inspection_dwell_ms=10.0)

    # Register reviewer key
    reviewer_key = ed25519.Ed25519PrivateKey.generate()
    reviewer_pub = reviewer_key.public_key()
    reviewer_id = "rev_alice"
    engine.register_reviewer(reviewer_id, reviewer_pub)

    # Initial execution state
    execution_state = {"action": "TRANSFER_FUNDS", "amount": 50000, "account": "ACC_9912"}
    ckpt_id, paused_state_hash = engine.create_checkpoint("sess_01", execution_state)

    # Sign the paused_state_hash
    signature = reviewer_key.sign(paused_state_hash.encode('utf-8')).hex()

    time.sleep(0.02)  # Ensure dwell time > 10ms

    # Submit approval with identical execution state
    status, receipt, metadata = engine.submit_approval(ckpt_id, reviewer_id, execution_state, signature)
    assert status == CheckpointStatus.APPROVED
    assert receipt.action == "ALLOW"
    assert metadata["suspected_rubber_stamp"] is False


def test_state_hash_divergence_aborts():
    engine = ThemisCheckpointEngine()
    reviewer_key = ed25519.Ed25519PrivateKey.generate()
    reviewer_id = "rev_bob"
    engine.register_reviewer(reviewer_id, reviewer_key.public_key())

    execution_state = {"action": "UPDATE_POLICY", "scope": "READ_ONLY"}
    ckpt_id, paused_state_hash = engine.create_checkpoint("sess_02", execution_state)

    signature = reviewer_key.sign(paused_state_hash.encode('utf-8')).hex()

    # Mutate execution state during pause (state drift)
    mutated_state = {"action": "UPDATE_POLICY", "scope": "ADMIN_FULL_ACCESS"}

    # Approval attempt must FAIL CLOSED to ABORTED
    status, receipt, metadata = engine.submit_approval(ckpt_id, reviewer_id, mutated_state, signature)
    assert status == CheckpointStatus.ABORTED
    assert receipt.action == "HALT"
    assert "State drift detected" in receipt.reason


def test_rubber_stamping_velocity_detection():
    engine = ThemisCheckpointEngine(min_inspection_dwell_ms=3000.0)
    reviewer_key = ed25519.Ed25519PrivateKey.generate()
    reviewer_id = "rev_charlie"
    engine.register_reviewer(reviewer_id, reviewer_key.public_key())

    execution_state = {"action": "DEPLOY_MODEL", "version": "v1.2"}
    ckpt_id, paused_state_hash = engine.create_checkpoint("sess_03", execution_state)

    signature = reviewer_key.sign(paused_state_hash.encode('utf-8')).hex()

    # Submit immediately (< 3000ms dwell time)
    status, receipt, metadata = engine.submit_approval(ckpt_id, reviewer_id, execution_state, signature)
    assert status == CheckpointStatus.APPROVED
    assert metadata["suspected_rubber_stamp"] is True
    assert receipt.details["suspected_rubber_stamp"] is True


def test_structured_human_override():
    engine = ThemisCheckpointEngine()
    execution_state = {"action": "LOAN_APPROVAL", "user_id": "U123"}
    ckpt_id, _ = engine.create_checkpoint("sess_04", execution_state)

    override = HumanOverridePayload(
        reviewer_id="rev_diana",
        override_category="FACTUAL_HALLUCINATION",
        root_cause_classification="Model misread income field",
        justification_text="Verified tax return documents manually.",
        corrected_output={"decision": "REJECTED"},
        dwell_time_ms=12000.0
    )

    receipt = engine.submit_override(ckpt_id, override)
    assert receipt.action == "OVERRIDE"
    assert receipt.details["category"] == "FACTUAL_HALLUCINATION"
