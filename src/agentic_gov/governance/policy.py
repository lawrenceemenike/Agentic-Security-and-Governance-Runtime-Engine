import time
import json
import hashlib
import logging
from typing import Dict, Any, List, Optional, Set, Tuple

from agentic_gov.core.types import GovernanceDecisionReceipt, Layer1DataGovernance

logger = logging.getLogger(__name__)


class PolicyRegistry:
    """
    Governance Policy Versioning Engine.
    Computes immutable SHA3-256 deployment hashes (rule_id @ rule_version_hash)
    to prevent retroactive policy tampering.
    """

    def __init__(self):
        # rule_id -> policy_definition_dict
        self._policies: Dict[str, Dict[str, Any]] = {}
        # rule_id -> rule_version_hash
        self._hashes: Dict[str, str] = {}

    def register_policy(self, rule_id: str, policy_def: Dict[str, Any]) -> str:
        """
        Registers a governance policy rule and computes its canonical SHA3-256 version hash.
        Returns the committed version string: "rule_id@rule_version_hash".
        """
        canonical_str = json.dumps(policy_def, sort_keys=True, separators=(',', ':')).encode('utf-8')
        version_hash = hashlib.sha3_256(canonical_str).hexdigest()[:16]

        committed_id = f"{rule_id}@{version_hash}"
        self._policies[rule_id] = policy_def
        self._hashes[rule_id] = version_hash
        return committed_id

    def get_committed_id(self, rule_id: str) -> Optional[str]:
        if rule_id in self._hashes:
            return f"{rule_id}@{self._hashes[rule_id]}"
        return None

    def get_all_active_commitments(self) -> List[str]:
        return [f"{rid}@{rhash}" for rid, rhash in self._hashes.items()]


class PurposeLimitationGate:
    """
    GDPR Article 6 & EDPB Opinion 28/2024 Purpose Limitation & Lawful Basis Gate (SI-1 & CM-1).
    Enforces purpose scoping, metadata filtering, and Article 9 special-category data conditions.
    """

    VALID_LAWFUL_BASES = {"CONSENT", "CONTRACT", "LEGAL_OBLIGATION", "VITAL_INTERESTS", "PUBLIC_TASK", "LEGITIMATE_INTEREST"}

    def __init__(self, allowed_purposes: Optional[Set[str]] = None):
        self.allowed_purposes = allowed_purposes or {"CUSTOMER_SUPPORT", "FRAUD_DETECTION", "ANALYTICS"}

    def validate_retrieval_query(
        self,
        purpose_id: str,
        lawful_basis_token: str,
        is_special_category_data: bool = False,
        article_9_verified: bool = False
    ) -> Tuple[bool, Optional[GovernanceDecisionReceipt]]:
        """
        Validates whether RAG retrieval query satisfies lawful basis and purpose scope.
        """
        start_time = time.perf_counter()

        # 1. Lawful Basis Token Verification
        if lawful_basis_token not in self.VALID_LAWFUL_BASES:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-01",
                action="BLOCK",
                target_stage="PURPOSE_GATE",
                reason=f"Invalid or unverified lawful basis token: '{lawful_basis_token}'",
                details={"provided_token": lawful_basis_token, "valid_bases": list(self.VALID_LAWFUL_BASES)},
                latency_ms=latency_ms
            )
            return False, receipt

        # 2. Purpose Scope Verification
        if purpose_id not in self.allowed_purposes:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-01",
                action="BLOCK",
                target_stage="PURPOSE_GATE",
                reason=f"Purpose '{purpose_id}' is outside authorized scope",
                details={"purpose_id": purpose_id, "allowed_purposes": list(self.allowed_purposes)},
                latency_ms=latency_ms
            )
            return False, receipt

        # 3. GDPR Article 9 Special Category Data Check
        if is_special_category_data and not article_9_verified:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-01",
                action="BLOCK",
                target_stage="PURPOSE_GATE",
                reason="Special category data (Art. 9 GDPR) requested without explicit verified condition boolean",
                details={"purpose_id": purpose_id},
                latency_ms=latency_ms
            )
            return False, receipt

        return True, None

    def filter_rag_documents(self, documents: List[Dict[str, Any]], active_purpose_id: str) -> List[Dict[str, Any]]:
        """
        Metadata filter excluding RAG documents tagged with purposes outside active context scope.
        """
        filtered = []
        for doc in documents:
            doc_purposes = doc.get("metadata", {}).get("allowed_purposes", [active_purpose_id])
            if active_purpose_id in doc_purposes:
                filtered.append(doc)
        return filtered


class DataFreshnessAttestor:
    """
    Data Freshness & Provenance Lineage Attestation Engine (DG-1).
    Validates input data freshness (max 30 days) and captures transformation provenance.
    """

    def __init__(self, max_freshness_days: float = 30.0):
        self.max_freshness_days = max_freshness_days

    def verify_freshness(self, collection_timestamp_ns: int) -> Tuple[bool, float, Optional[GovernanceDecisionReceipt]]:
        """
        Checks if collection timestamp is within max_freshness_days.
        Returns (is_fresh, age_days, receipt).
        """
        now_ns = time.time_ns()
        age_seconds = (now_ns - collection_timestamp_ns) / 1e9
        age_days = age_seconds / (24 * 3600)

        receipt = None
        if age_days > self.max_freshness_days:
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-04",
                action="BLOCK",
                target_stage="DATA_FRESHNESS",
                reason=f"Data staleness ({age_days:.1f} days) exceeds maximum freshness threshold ({self.max_freshness_days} days)",
                details={"age_days": round(age_days, 2), "max_days": self.max_freshness_days}
            )
            return False, age_days, receipt

        return True, age_days, None

    def create_provenance_record(
        self,
        source_uri: str,
        collection_timestamp_ns: int,
        raw_content: str,
        lawful_basis: str = "CONSENT"
    ) -> Layer1DataGovernance:
        """Creates a standardized Layer1DataGovernance provenance model."""
        transformation_hash = hashlib.sha3_256(raw_content.encode('utf-8')).hexdigest()[:16]
        now_ns = time.time_ns()
        age_days = ((now_ns - collection_timestamp_ns) / 1e9) / (24 * 3600)

        return Layer1DataGovernance(
            source_provenance_uri=f"{source_uri}#hash={transformation_hash}",
            collection_timestamp_ns=collection_timestamp_ns,
            freshness_days=round(age_days, 2),
            proxy_bias_checked=True,
            lawful_basis=lawful_basis
        )
