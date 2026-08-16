import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from agentic_gov.core.identity import AgentIdentity
from agentic_gov.ledger.atlas import (
    AtlasMerkleDAG,
    jcs_canonical_serialize,
    compute_sha3_256
)
from agentic_gov.ledger.privacy import EphemeralSaltStore
from agentic_gov.ledger.anchor import RFC3161TimestampAnchor


def test_jcs_canonical_serialization_consistency():
    obj1 = {"b": 2, "a": 1, "c": [3, 2, 1]}
    obj2 = {"a": 1, "c": [3, 2, 1], "b": 2}

    bytes1 = jcs_canonical_serialize(obj1)
    bytes2 = jcs_canonical_serialize(obj2)

    assert bytes1 == bytes2
    assert compute_sha3_256(bytes1) == compute_sha3_256(bytes2)


def test_merkle_dag_multi_parent_construction_and_verification():
    dag = AtlasMerkleDAG()
    agent_identity = AgentIdentity()

    # Create root node 1
    node1 = dag.create_action_node(
        agent_identity=agent_identity,
        input_payload={"prompt": "Task A"},
        decision_payload={"result": "Done A"},
        governance_rules_applied=["rule1@v1"],
        salt="salt_1"
    )

    # Create root node 2
    node2 = dag.create_action_node(
        agent_identity=agent_identity,
        input_payload={"prompt": "Task B"},
        decision_payload={"result": "Done B"},
        governance_rules_applied=["rule1@v1"],
        salt="salt_2"
    )

    # Create multi-parent child node (parents: node1.node_hash, node2.node_hash)
    child_node = dag.create_action_node(
        agent_identity=agent_identity,
        input_payload={"prompt": "Merge A and B"},
        decision_payload={"result": "Merged"},
        governance_rules_applied=["rule1@v1", "rule2@v1"],
        salt="salt_3",
        parent_hashes=[node1.node_hash, node2.node_hash]
    )

    assert len(child_node.parent_hashes) == 2
    assert node1.node_hash in child_node.parent_hashes
    assert node2.node_hash in child_node.parent_hashes

    # Verify node integrity & Ed25519 signature
    assert dag.verify_node_integrity(child_node.node_hash, agent_identity.public_key) is True


def test_inclusion_proof_generation_and_verification():
    dag = AtlasMerkleDAG()
    agent_identity = AgentIdentity()

    node = dag.create_action_node(
        agent_identity=agent_identity,
        input_payload={"test": "data"},
        decision_payload={"status": "OK"},
        governance_rules_applied=["rule_security@v1"],
        salt="test_salt"
    )

    proof = dag.generate_inclusion_proof(node.node_hash)
    assert proof["target_node_hash"] == node.node_hash
    assert dag.verify_inclusion_proof(proof) is True


def test_gdpr_article_17_salt_destruction():
    salt_store = EphemeralSaltStore()
    payload_id = "user_tx_9921"
    sensitive_payload = {"ssn": "000-12-3456", "name": "John Doe"}

    salt_hex, salted_hash = salt_store.generate_and_store_salt(payload_id, sensitive_payload)

    assert salt_store.is_erased(payload_id) is False
    assert len(salt_hex) == 64

    # Execute GDPR Article 17 Erasure Request
    erased = salt_store.execute_gdpr_article_17_erasure(payload_id)
    assert erased is True
    assert salt_store.is_erased(payload_id) is True
    assert salt_store.get_salt(payload_id) is None


def test_rfc3161_timestamp_anchoring():
    anchor = RFC3161TimestampAnchor()
    dag_root_hash = compute_sha3_256(b"SAMPLE_DAG_ROOT_HASH")

    receipt = anchor.anchor_root_hash(dag_root_hash)
    assert receipt.root_hash == dag_root_hash
    assert anchor.verify_anchor_receipt(receipt, dag_root_hash) is True

    # Tampered root hash fails verification
    assert anchor.verify_anchor_receipt(receipt, "TAMPERED_ROOT_HASH") is False
