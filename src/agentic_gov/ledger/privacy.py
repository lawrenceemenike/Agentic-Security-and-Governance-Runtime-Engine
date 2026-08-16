import secrets
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)


class EphemeralSaltStore:
    """
    GDPR Article 17 Cryptographic Salt Destruction Interface (SI-1 & Privacy).
    Isolates cryptographic salts into an independent keystore (separated from main ledger database).
    When an erasure request is executed, salt destruction renders salted hashes irreversibly unlinkable
    while preserving Merkle-DAG node hash structural continuity.
    """

    def __init__(self):
        # payload_id -> salt_hex
        self._salts: Dict[str, str] = {}
        # payload_id -> operational_data
        self._operational_store: Dict[str, Dict[str, Any]] = {}

    def generate_and_store_salt(self, payload_id: str, payload_data: Dict[str, Any]) -> Tuple[str, str]:
        """
        Generates a 32-byte hex salt, stores it in the isolated salt store,
        and computes the salted SHA3-256 hash.
        Returns (salt_hex, salted_hash).
        """
        salt_bytes = secrets.token_bytes(32)
        salt_hex = salt_bytes.hex()

        self._salts[payload_id] = salt_hex
        self._operational_store[payload_id] = payload_data

        # Compute SHA3-256(payload_json || salt)
        import json
        payload_str = json.dumps(payload_data, sort_keys=True)
        salted_bytes = payload_str.encode('utf-8') + salt_bytes
        salted_hash = hashlib.sha3_256(salted_bytes).hexdigest()

        return salt_hex, salted_hash

    def get_salt(self, payload_id: str) -> Optional[str]:
        return self._salts.get(payload_id)

    def execute_gdpr_article_17_erasure(self, payload_id: str) -> bool:
        """
        Executes right-to-be-forgotten erasure request.
        Destroys salt and primary operational record.
        Returns True if erasure succeeded.
        """
        salt_existed = payload_id in self._salts
        self._salts.pop(payload_id, None)
        self._operational_store.pop(payload_id, None)

        if salt_existed:
            logger.info(f"[GDPR_ART17_ERASURE] Cryptographic salt for payload '{payload_id}' permanently destroyed. Ledger hash remains structurally intact but underlying data is cryptographically unrecoverable.")
            return True
        return False

    def is_erased(self, payload_id: str) -> bool:
        return payload_id not in self._salts
