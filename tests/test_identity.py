import time
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from agentic_gov.core.types import generate_uuidv7, AgentMessageEnvelope
from agentic_gov.core.identity import (
    AgentIdentity,
    AgentIdentityRegistry,
    NonceReplayStore,
    sign_envelope,
    verify_envelope,
    SignatureVerificationError
)


def test_uuidv7_generation():
    uuid1 = generate_uuidv7()
    time.sleep(0.002)
    uuid2 = generate_uuidv7()

    assert len(uuid1) == 36
    assert uuid1.count('-') == 4
    # Time-ordering check
    assert uuid1 < uuid2


def test_agent_identity_repr_protection():
    identity = AgentIdentity()
    repr_str = repr(identity)
    str_str = str(identity)

    assert "[PRIVATE KEY REDACTED]" in repr_str
    assert "[PRIVATE KEY REDACTED]" in str_str
    assert identity.agent_id in repr_str


def test_envelope_signing_and_verification_latency():
    identity = AgentIdentity()
    registry = AgentIdentityRegistry()
    registry.register_agent(identity.agent_id, identity.public_key)
    nonce_store = NonceReplayStore()

    body = {"action": "query_database", "target": "financial_records", "scope": "read"}
    envelope = sign_envelope(identity, body)

    # Verification must execute in < 1.0ms
    is_valid, latency_ms = verify_envelope(envelope, registry, nonce_store)
    assert is_valid is True
    assert latency_ms < 1.0


def test_replay_attack_trapping():
    identity = AgentIdentity()
    registry = AgentIdentityRegistry()
    registry.register_agent(identity.agent_id, identity.public_key)
    nonce_store = NonceReplayStore()

    body = {"data": "test"}
    envelope = sign_envelope(identity, body)

    # First verification passes
    is_valid, _ = verify_envelope(envelope, registry, nonce_store)
    assert is_valid is True

    # Replayed verification raises SignatureVerificationError
    with pytest.raises(SignatureVerificationError, match="Replay attack trapped"):
        verify_envelope(envelope, registry, nonce_store)


def test_expired_timestamp_rejection():
    identity = AgentIdentity()
    registry = AgentIdentityRegistry()
    registry.register_agent(identity.agent_id, identity.public_key)
    nonce_store = NonceReplayStore()

    body = {"data": "test"}
    envelope = sign_envelope(identity, body)
    # Simulate timestamp 10 seconds in the past
    envelope.timestamp_ns = time.time_ns() - int(10 * 1e9)

    with pytest.raises(SignatureVerificationError, match="Timestamp drift"):
        verify_envelope(envelope, registry, nonce_store)


def test_tampered_payload_rejection():
    identity = AgentIdentity()
    registry = AgentIdentityRegistry()
    registry.register_agent(identity.agent_id, identity.public_key)
    nonce_store = NonceReplayStore()

    body = {"amount": 100}
    envelope = sign_envelope(identity, body)
    
    # Tamper with the body
    envelope.body["amount"] = 1000000

    with pytest.raises(SignatureVerificationError, match="Payload hash mismatch"):
        verify_envelope(envelope, registry, nonce_store)


def test_key_rotation_grace_period():
    identity = AgentIdentity()
    registry = AgentIdentityRegistry(grace_period_seconds=2.0)
    registry.register_agent(identity.agent_id, identity.public_key)
    nonce_store = NonceReplayStore()

    old_envelope = sign_envelope(identity, {"msg": "before rotation"})

    # Rotate to new key
    new_key = ed25519.Ed25519PrivateKey.generate()
    new_identity = AgentIdentity(agent_id=identity.agent_id, private_key=new_key)
    registry.rotate_key(identity.agent_id, new_identity.public_key)

    # Verification of old envelope still succeeds during grace period
    is_valid, _ = verify_envelope(old_envelope, registry, nonce_store)
    assert is_valid is True

    # Verification of new envelope succeeds
    new_envelope = sign_envelope(new_identity, {"msg": "after rotation"})
    is_valid, _ = verify_envelope(new_envelope, registry, nonce_store)
    assert is_valid is True
