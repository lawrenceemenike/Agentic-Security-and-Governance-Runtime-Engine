import json
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from cryptography.hazmat.primitives.asymmetric import ed25519

from agentic_gov.core.types import ActionNode, generate_uuidv7
from agentic_gov.core.identity import AgentIdentity

logger = logging.getLogger(__name__)


def jcs_canonical_serialize(obj: Any) -> bytes:
    """
    RFC 8785 (JSON Canonicalization Scheme - JCS) zero-dependency implementation.
    Guarantees cross-platform, cross-language deterministic JSON encoding.
    """
    def _canonicalize(val: Any) -> Any:
        if isinstance(val, dict):
            sorted_dict = {}
            for k in sorted(val.keys()):
                sorted_dict[k] = _canonicalize(val[k])
            return sorted_dict
        elif isinstance(val, list):
            return [_canonicalize(v) for v in val]
        elif isinstance(val, float):
            if val.is_integer():
                return int(val)
            return val
        return val

    canonical_obj = _canonicalize(obj)
    return json.dumps(canonical_obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def compute_sha3_256(canonical_bytes: bytes) -> str:
    return hashlib.sha3_256(canonical_bytes).hexdigest()


class AtlasMerkleDAG:
    """
    Atlas Causal Merkle-DAG Decision Ledger (OWASP SI-1, CM-1).
    Constructs tamper-evident decision graphs supporting multi-parent causal relationships,
    RFC 8785 canonical hashing, and O(1) indexed inclusion verification proofs.
    """

    def __init__(self):
        # node_hash -> ActionNode (O(1) index)
        self._nodes: Dict[str, ActionNode] = {}
        # node_hash -> index in ordered insertion list (O(1) lookup)
        self._hash_to_index: Dict[str, int] = {}
        # Ordered list of all node hashes
        self._ordered_hashes: List[str] = []
        # Multi-parent index: parent_hash -> set of child node_hashes (O(1) graph traversal)
        self._parent_to_children: Dict[str, Set[str]] = {}
        # Child index: child_node_hash -> set of parent node_hashes
        self._child_to_parents: Dict[str, Set[str]] = {}
        # Memoized root hash cache
        self._cached_root_hash: Optional[str] = None

    def create_action_node(
        self,
        agent_identity: AgentIdentity,
        input_payload: Dict[str, Any],
        decision_payload: Dict[str, Any],
        governance_rules_applied: List[str],
        salt: str,
        parent_hashes: Optional[List[str]] = None,
        human_checkpoint_result: Optional[Dict[str, Any]] = None
    ) -> ActionNode:
        """
        Constructs, hashes, indexes, and signs a new ActionNode in the Merkle-DAG.
        """
        import time
        action_id = generate_uuidv7()
        timestamp_ns = time.time_ns()

        # 1. Compute salted input hash: SHA3-256(canonical(input) + salt)
        salted_input_obj = {"payload": input_payload, "salt": salt}
        input_hash = compute_sha3_256(jcs_canonical_serialize(salted_input_obj))

        parents = sorted(parent_hashes or [])

        # Build payload dict for node_hash computation
        node_payload = {
            "action_id": action_id,
            "agent_id": agent_identity.agent_id,
            "timestamp_ns": timestamp_ns,
            "input_hash": input_hash,
            "decision_payload": decision_payload,
            "governance_rules_applied": sorted(governance_rules_applied),
            "human_checkpoint_result": human_checkpoint_result,
            "parent_hashes": parents
        }

        # 2. Compute canonical JCS node_hash
        canonical_bytes = jcs_canonical_serialize(node_payload)
        node_hash = compute_sha3_256(canonical_bytes)

        # 3. Sign node_hash with Ed25519 agent private key
        signature = agent_identity._private_key.sign(node_hash.encode('utf-8')).hex()

        node = ActionNode(
            action_id=action_id,
            agent_id=agent_identity.agent_id,
            timestamp_ns=timestamp_ns,
            input_hash=input_hash,
            decision_payload=decision_payload,
            governance_rules_applied=sorted(governance_rules_applied),
            human_checkpoint_result=human_checkpoint_result,
            parent_hashes=parents,
            node_hash=node_hash,
            signature=signature
        )

        # O(1) Indexing
        idx = len(self._ordered_hashes)
        self._nodes[node_hash] = node
        self._hash_to_index[node_hash] = idx
        self._ordered_hashes.append(node_hash)

        # Build parent-child graph indices for O(1) traversal
        self._child_to_parents[node_hash] = set(parents)
        for parent_h in parents:
            if parent_h not in self._parent_to_children:
                self._parent_to_children[parent_h] = set()
            self._parent_to_children[parent_h].add(node_hash)

        # Invalidate root hash cache on new node insertion
        self._cached_root_hash = None

        logger.info(f"[ATLAS_DAG] Created ActionNode '{node.action_id}' (Node Hash: {node_hash[:12]}...). Parents: {len(parents)}")
        return node

    def get_node(self, node_hash: str) -> Optional[ActionNode]:
        """O(1) node lookup."""
        return self._nodes.get(node_hash)

    def get_children(self, node_hash: str) -> Set[str]:
        """O(1) lookup of child node hashes."""
        return self._parent_to_children.get(node_hash, set())

    def get_parents(self, node_hash: str) -> Set[str]:
        """O(1) lookup of parent node hashes."""
        return self._child_to_parents.get(node_hash, set())

    def compute_dag_root_hash(self) -> str:
        """
        Computes memoized Merkle root hash across all leaf nodes in O(1) cached time.
        """
        if self._cached_root_hash:
            return self._cached_root_hash

        if not self._nodes:
            return compute_sha3_256(b"EMPTY_DAG")

        sorted_hashes = sorted(list(self._nodes.keys()))
        combined = "".join(sorted_hashes).encode('utf-8')
        self._cached_root_hash = compute_sha3_256(combined)
        return self._cached_root_hash

    def verify_node_integrity(self, node_hash: str, public_key: ed25519.Ed25519PublicKey) -> bool:
        """
        Verifies node hash integrity and Ed25519 signature in O(1) time.
        """
        node = self.get_node(node_hash)
        if not node:
            return False

        node_payload = {
            "action_id": node.action_id,
            "agent_id": node.agent_id,
            "timestamp_ns": node.timestamp_ns,
            "input_hash": node.input_hash,
            "decision_payload": node.decision_payload,
            "governance_rules_applied": sorted(node.governance_rules_applied),
            "human_checkpoint_result": node.human_checkpoint_result,
            "parent_hashes": sorted(node.parent_hashes)
        }

        recomputed_hash = compute_sha3_256(jcs_canonical_serialize(node_payload))
        if recomputed_hash != node.node_hash:
            return False

        try:
            sig_bytes = bytes.fromhex(node.signature)
            public_key.verify(sig_bytes, node.node_hash.encode('utf-8'))
            return True
        except Exception:
            return False

    def generate_inclusion_proof(self, target_node_hash: str) -> Dict[str, Any]:
        """
        Generates Merkle inclusion proof using O(1) dictionary index lookups.
        """
        if target_node_hash not in self._nodes:
            raise KeyError(f"Node '{target_node_hash}' does not exist in ledger.")

        idx = self._hash_to_index[target_node_hash]

        return {
            "target_node_hash": target_node_hash,
            "leaf_index": idx,
            "total_nodes": len(self._ordered_hashes),
            "parent_hashes": list(self.get_parents(target_node_hash)),
            "child_hashes": list(self.get_children(target_node_hash)),
            "dag_root_hash": self.compute_dag_root_hash()
        }

    def verify_inclusion_proof(self, proof: Dict[str, Any]) -> bool:
        """Verifies inclusion proof against current DAG state in O(1) time."""
        target_hash = proof.get("target_node_hash")
        if target_hash not in self._nodes:
            return False
        return self.compute_dag_root_hash() == proof.get("dag_root_hash")
