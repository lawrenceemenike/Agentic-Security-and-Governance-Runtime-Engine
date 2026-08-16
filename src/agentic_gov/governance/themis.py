import time
import json
import hashlib
import logging
from enum import Enum
from typing import Dict, Any, Tuple, Optional, List
from cryptography.hazmat.primitives.asymmetric import ed25519

from agentic_gov.core.types import (
    HumanOverridePayload,
    GovernanceDecisionReceipt,
    generate_uuidv7
)

logger = logging.getLogger(__name__)


class CheckpointStatus(str, Enum):
    IDLE = "IDLE"
    PENDING_HUMAN = "PENDING_HUMAN"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    ABORTED = "ABORTED"  # State hash mismatch during pause


OVERRIDE_TAXONOMY = {
    "DATA_PROXY_BIAS",
    "FACTUAL_HALLUCINATION",
    "POLICY_EDGE_CASE",
    "CONTEXT_DRIFT"
}


class ThemisCheckpointEngine:
    """
    Themis State-Bound Cryptographic Human Checkpoint Engine (OWASP SI-4 & CM-1).
    Binds human approvals to exact paused execution state snapshots (paused_state_hash),
    traps state drift, detects fast rubber-stamping (< 3000ms dwell time),
    and enforces structured override taxonomies.
    """

    def __init__(
        self,
        min_inspection_dwell_ms: float = 3000.0,
        authorized_reviewer_keys: Optional[Dict[str, ed25519.Ed25519PublicKey]] = None
    ):
        self.min_inspection_dwell_ms = min_inspection_dwell_ms
        self.authorized_reviewer_keys = authorized_reviewer_keys or {}

        # checkpoint_id -> pending state metadata
        self._pending_checkpoints: Dict[str, Dict[str, Any]] = {}
        # reviewer_id -> stats
        self._reviewer_stats: Dict[str, Dict[str, Any]] = {}

    def register_reviewer(self, reviewer_id: str, public_key: ed25519.Ed25519PublicKey):
        self.authorized_reviewer_keys[reviewer_id] = public_key

    def compute_state_hash(self, execution_state: Dict[str, Any]) -> str:
        """Computes canonical SHA3-256 hash of current execution state."""
        canonical_bytes = json.dumps(execution_state, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha3_256(canonical_bytes).hexdigest()

    def create_checkpoint(self, session_id: str, execution_state: Dict[str, Any]) -> Tuple[str, str]:
        """
        Transitions workflow to PENDING_HUMAN and captures paused_state_hash.
        Returns (checkpoint_id, paused_state_hash).
        """
        checkpoint_id = generate_uuidv7()
        paused_state_hash = self.compute_state_hash(execution_state)

        self._pending_checkpoints[checkpoint_id] = {
            "session_id": session_id,
            "paused_state_hash": paused_state_hash,
            "paused_at_ns": time.time_ns(),
            "presentation_timestamp_ms": time.time() * 1000.0,
            "status": CheckpointStatus.PENDING_HUMAN,
            "execution_state_snapshot": json.loads(json.dumps(execution_state))
        }

        logger.info(f"[THEMIS_HALT] Session '{session_id}' paused to PENDING_HUMAN. Checkpoint: '{checkpoint_id}', State Hash: '{paused_state_hash[:12]}...'")
        return checkpoint_id, paused_state_hash

    def submit_approval(
        self,
        checkpoint_id: str,
        reviewer_id: str,
        current_execution_state: Dict[str, Any],
        signature_hex: str
    ) -> Tuple[CheckpointStatus, Optional[GovernanceDecisionReceipt], Dict[str, Any]]:
        """
        Validates human signature over paused_state_hash.
        Verifies state hash continuity (fails closed to ABORTED if state mutated during pause).
        Enforces rubber-stamping velocity detection (< 3000ms).
        """
        start_time = time.perf_counter()
        if checkpoint_id not in self._pending_checkpoints:
            raise KeyError(f"Checkpoint '{checkpoint_id}' not found or already resolved.")

        ckpt = self._pending_checkpoints[checkpoint_id]

        # 1. State Continuity Check (State-Bound Halting)
        current_hash = self.compute_state_hash(current_execution_state)
        if current_hash != ckpt["paused_state_hash"]:
            ckpt["status"] = CheckpointStatus.ABORTED
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-04",
                action="HALT",
                target_stage="CHECKPOINT",
                reason=f"State drift detected! Execution state mutated during pause. Expected hash {ckpt['paused_state_hash'][:12]}, got {current_hash[:12]}.",
                details={"checkpoint_id": checkpoint_id, "status": "ABORTED"}
            )
            logger.error(f"[THEMIS_FAIL_CLOSED] Checkpoint '{checkpoint_id}' ABORTED due to state hash divergence.")
            return CheckpointStatus.ABORTED, receipt, {}

        # 2. Reviewer Identity Verification
        if reviewer_id not in self.authorized_reviewer_keys:
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-01",
                action="HALT",
                target_stage="CHECKPOINT",
                reason=f"Reviewer '{reviewer_id}' is not authorized to sign checkpoints.",
                details={"reviewer_id": reviewer_id}
            )
            return CheckpointStatus.REJECTED, receipt, {}

        # 3. Ed25519 Signature Verification over paused_state_hash
        pub_key = self.authorized_reviewer_keys[reviewer_id]
        sig_bytes = bytes.fromhex(signature_hex)
        hash_bytes = ckpt["paused_state_hash"].encode('utf-8')

        try:
            pub_key.verify(sig_bytes, hash_bytes)
        except Exception:
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-01",
                action="HALT",
                target_stage="CHECKPOINT",
                reason="Invalid Ed25519 signature submitted for paused_state_hash.",
                details={"reviewer_id": reviewer_id, "checkpoint_id": checkpoint_id}
            )
            return CheckpointStatus.REJECTED, receipt, {}

        # 4. Anti-Rubber-Stamping Inspection Velocity Monitor
        now_ms = time.time() * 1000.0
        dwell_time_ms = now_ms - ckpt["presentation_timestamp_ms"]
        suspected_rubber_stamp = dwell_time_ms < self.min_inspection_dwell_ms

        # Update reviewer stats
        stats = self._reviewer_stats.setdefault(reviewer_id, {"total_reviews": 0, "overrides": 0, "rubber_stamps": 0})
        stats["total_reviews"] += 1
        if suspected_rubber_stamp:
            stats["rubber_stamps"] += 1
            logger.warning(f"[SUSPECTED_RUBBER_STAMP] Reviewer '{reviewer_id}' completed inspection in {dwell_time_ms:.0f}ms (< {self.min_inspection_dwell_ms}ms threshold).")

        ckpt["status"] = CheckpointStatus.APPROVED
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        receipt = GovernanceDecisionReceipt(
            asi_code="ASI-04",
            action="ALLOW",
            target_stage="CHECKPOINT",
            reason="Human approval verified successfully over paused_state_hash.",
            details={
                "checkpoint_id": checkpoint_id,
                "reviewer_id": reviewer_id,
                "dwell_time_ms": round(dwell_time_ms, 2),
                "suspected_rubber_stamp": suspected_rubber_stamp
            },
            latency_ms=latency_ms
        )

        return CheckpointStatus.APPROVED, receipt, {"dwell_time_ms": dwell_time_ms, "suspected_rubber_stamp": suspected_rubber_stamp}

    def submit_override(self, checkpoint_id: str, override: HumanOverridePayload) -> GovernanceDecisionReceipt:
        """
        Processes structured human override. Enforces taxonomy validation.
        """
        if checkpoint_id not in self._pending_checkpoints:
            raise KeyError(f"Checkpoint '{checkpoint_id}' not found.")

        if override.override_category not in OVERRIDE_TAXONOMY:
            raise ValueError(f"Invalid override category '{override.override_category}'. Must be one of {OVERRIDE_TAXONOMY}")

        ckpt = self._pending_checkpoints[checkpoint_id]
        ckpt["status"] = CheckpointStatus.REJECTED

        # Track override stat
        stats = self._reviewer_stats.setdefault(override.reviewer_id, {"total_reviews": 0, "overrides": 0, "rubber_stamps": 0})
        stats["total_reviews"] += 1
        stats["overrides"] += 1

        receipt = GovernanceDecisionReceipt(
            asi_code="ASI-04",
            action="OVERRIDE",
            target_stage="CHECKPOINT",
            reason=f"Human override applied under category '{override.override_category}'",
            details={
                "checkpoint_id": checkpoint_id,
                "reviewer_id": override.reviewer_id,
                "category": override.override_category,
                "justification": override.justification_text,
                "dwell_time_ms": override.dwell_time_ms
            }
        )

        logger.info(f"[HUMAN_OVERRIDE] Checkpoint '{checkpoint_id}' overridden by '{override.reviewer_id}'. Category: '{override.override_category}'")
        return receipt
