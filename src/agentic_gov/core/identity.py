import time
import json
import logging
from collections import OrderedDict
from typing import Dict, Any, Optional, Tuple, List, Set
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import hashlib

from agentic_gov.core.types import AgentMessageEnvelope, generate_uuidv7

logger = logging.getLogger(__name__)


class SignatureVerificationError(Exception):
    """Raised when envelope signature, timestamp, or nonce verification fails."""
    pass


class NonceReplayStore:
    """
    Dual-tier Nonce Anti-Replay Store.
    Default: In-memory sliding window OrderedDict (sub-millisecond).
    Supports pluggable distributed backends (e.g. Redis) for containerized agent networks.
    """
    def __init__(self, ttl_seconds: float = 5.0, max_capacity: int = 10000):
        self.ttl_seconds = ttl_seconds
        self.max_capacity = max_capacity
        # Store nonces mapped to timestamp_ns
        self._store: OrderedDict[str, int] = OrderedDict()

    def check_and_add(self, nonce: str, timestamp_ns: int) -> bool:
        """
        Returns True if the nonce is fresh (not seen before).
        Returns False if the nonce is replayed.
        """
        now_ns = time.time_ns()
        cutoff_ns = now_ns - int(self.ttl_seconds * 1e9)

        # Evict expired nonces from left
        while self._store:
            oldest_nonce, oldest_ts = next(iter(self._store.items()))
            if oldest_ts < cutoff_ns:
                self._store.popitem(last=False)
            else:
                break

        if nonce in self._store:
            return False  # Replay detected!

        # Maintain capacity ceiling
        if len(self._store) >= self.max_capacity:
            self._store.popitem(last=False)

        self._store[nonce] = timestamp_ns
        return True


class KeyVersion:
    def __init__(self, key_id: str, public_key: ed25519.Ed25519PublicKey, created_at: float):
        self.key_id = key_id
        self.public_key = public_key
        self.created_at = created_at


class AgentIdentityRegistry:
    """
    Registry for managing agent public keys, key rotation grace periods, and permissions.
    """
    def __init__(self, grace_period_seconds: float = 300.0):
        self.grace_period_seconds = grace_period_seconds
        # agent_id -> list of KeyVersion
        self._keys: Dict[str, List[KeyVersion]] = {}
        # agent_id -> permissions/roles dict
        self._metadata: Dict[str, Dict[str, Any]] = {}

    def register_agent(
        self,
        agent_id: str,
        public_key: ed25519.Ed25519PublicKey,
        roles: Optional[List[str]] = None,
        permissions: Optional[Set[str]] = None
    ):
        key_version = KeyVersion(
            key_id=generate_uuidv7(),
            public_key=public_key,
            created_at=time.time()
        )
        if agent_id not in self._keys:
            self._keys[agent_id] = []
        self._keys[agent_id].append(key_version)

        self._metadata[agent_id] = {
            "roles": roles or ["agent"],
            "permissions": permissions or set(),
            "registered_at": time.time()
        }

    def rotate_key(self, agent_id: str, new_public_key: ed25519.Ed25519PublicKey) -> str:
        """Rotates agent key while keeping previous key active during grace period."""
        if agent_id not in self._keys:
            raise KeyError(f"Agent '{agent_id}' is not registered.")

        key_version = KeyVersion(
            key_id=generate_uuidv7(),
            public_key=new_public_key,
            created_at=time.time()
        )
        self._keys[agent_id].append(key_version)
        return key_version.key_id

    def get_active_public_keys(self, agent_id: str) -> List[ed25519.Ed25519PublicKey]:
        """Returns valid public keys for agent (current key + keys within grace period)."""
        if agent_id not in self._keys or not self._keys[agent_id]:
            return []

        now = time.time()
        valid_keys = []
        # Reverse order (latest first)
        for kv in reversed(self._keys[agent_id]):
            if now - kv.created_at <= self.grace_period_seconds or kv == self._keys[agent_id][-1]:
                valid_keys.append(kv.public_key)
        return valid_keys


class AgentIdentity:
    """
    Encapsulates Ed25519 keypair for an agent.
    Guarantees key protection in repr/str and logs.
    """
    def __init__(self, agent_id: Optional[str] = None, private_key: Optional[ed25519.Ed25519PrivateKey] = None):
        self.agent_id = agent_id or generate_uuidv7()
        self._private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self.public_key = self._private_key.public_key()

    def get_public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def get_public_hex(self) -> str:
        return self.get_public_bytes().hex()

    def __repr__(self) -> str:
        return f"<AgentIdentity agent_id={self.agent_id} public_key={self.get_public_hex()[:12]}... [PRIVATE KEY REDACTED]>"

    def __str__(self) -> str:
        return self.__repr__()


def canonical_sha3_256(payload: Dict[str, Any]) -> str:
    """
    Canonical JSON serialization helper producing deterministic SHA3-256 hash.
    For complex RFC 8785 JCS engine, see atlas.py.
    """
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    return hashlib.sha3_256(canonical_bytes).hexdigest()


def sign_envelope(agent_identity: AgentIdentity, body: Dict[str, Any]) -> AgentMessageEnvelope:
    """
    Creates and signs an AgentMessageEnvelope for inter-agent communication.
    """
    timestamp_ns = time.time_ns()
    payload_hash = canonical_sha3_256(body)
    
    # Sign the payload hash using Ed25519 private key
    signature_bytes = agent_identity._private_key.sign(payload_hash.encode('utf-8'))
    
    return AgentMessageEnvelope(
        agent_id=agent_identity.agent_id,
        timestamp_ns=timestamp_ns,
        payload_hash=payload_hash,
        signature=signature_bytes.hex(),
        body=body
    )


def verify_envelope(
    envelope: AgentMessageEnvelope,
    registry: AgentIdentityRegistry,
    nonce_store: NonceReplayStore,
    max_drift_ms: float = 5000.0
) -> Tuple[bool, float]:
    """
    Verifies an incoming AgentMessageEnvelope in < 1.0 ms.
    Enforces:
      1. Timestamp freshness (delta <= max_drift_ms)
      2. Nonce anti-replay protection
      3. Canonical payload hash verification
      4. Ed25519 cryptographic signature verification against active registered keys
    Returns (is_valid, latency_ms).
    Raises SignatureVerificationError on violation.
    """
    start_time = time.perf_counter()

    # 1. Timestamp Freshness Check
    now_ns = time.time_ns()
    drift_ms = abs(now_ns - envelope.timestamp_ns) / 1e6
    if drift_ms > max_drift_ms:
        raise SignatureVerificationError(
            f"Timestamp drift of {drift_ms:.2f}ms exceeds maximum allowance of {max_drift_ms}ms."
        )

    # 2. Nonce Replay Check
    if not nonce_store.check_and_add(envelope.nonce, envelope.timestamp_ns):
        raise SignatureVerificationError(f"Replay attack trapped! Nonce '{envelope.nonce}' has already been processed.")

    # 3. Canonical Payload Hash Verification
    recomputed_hash = canonical_sha3_256(envelope.body)
    if recomputed_hash != envelope.payload_hash:
        raise SignatureVerificationError(
            f"Payload hash mismatch! Received {envelope.payload_hash}, computed {recomputed_hash}."
        )

    # 4. Ed25519 Signature Verification
    active_keys = registry.get_active_public_keys(envelope.agent_id)
    if not active_keys:
        raise SignatureVerificationError(f"Agent '{envelope.agent_id}' has no registered active public keys.")

    signature_bytes = bytes.fromhex(envelope.signature)
    payload_hash_bytes = envelope.payload_hash.encode('utf-8')

    signature_valid = False
    for pub_key in active_keys:
        try:
            pub_key.verify(signature_bytes, payload_hash_bytes)
            signature_valid = True
            break
        except Exception:
            continue

    if not signature_valid:
        raise SignatureVerificationError("Invalid Ed25519 signature for payload hash.")

    latency_ms = (time.perf_counter() - start_time) * 1000.0
    return True, latency_ms
