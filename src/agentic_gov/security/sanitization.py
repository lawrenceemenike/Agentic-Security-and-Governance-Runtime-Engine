import re
import time
import logging
from typing import Tuple, Optional, List

from agentic_gov.core.types import GovernanceDecisionReceipt

logger = logging.getLogger(__name__)

# --- Regex Patterns for PII & Secrets ---
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
IPV4_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
IPV6_PATTERN = re.compile(r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b', re.IGNORECASE)
API_KEY_PATTERN = re.compile(r'\b(sk-[a-zA-Z0-9]{20,}|bearer\s+[a-zA-Z0-9_\-\.]{20,}|AKIA[0-9A-Z]{16})\b', re.IGNORECASE)


class OutputSanitizer:
    """
    Output Sanitizer & Context Isolator (OWASP ASI-04 & ASI-05).
    Redacts secrets and PII from post-model outputs and wraps RAG/external web context in XML delimiters.
    """

    def sanitize_output(self, text: str) -> Tuple[str, Optional[GovernanceDecisionReceipt]]:
        """
        Scans model output text for emails, IPs, and API keys.
        Redacts them into [REDACTED_*] tokens and returns (sanitized_text, receipt).
        """
        start_time = time.perf_counter()
        if not text:
            return "", None

        redacted = text
        violations: List[str] = []

        if EMAIL_PATTERN.search(redacted):
            redacted = EMAIL_PATTERN.sub('[REDACTED_EMAIL]', redacted)
            violations.append("PII_EMAIL")

        if IPV4_PATTERN.search(redacted):
            redacted = IPV4_PATTERN.sub('[REDACTED_IP]', redacted)
            violations.append("PII_IPV4")

        if IPV6_PATTERN.search(redacted):
            redacted = IPV6_PATTERN.sub('[REDACTED_IP]', redacted)
            violations.append("PII_IPV6")

        if API_KEY_PATTERN.search(redacted):
            redacted = API_KEY_PATTERN.sub('[REDACTED_API_KEY]', redacted)
            violations.append("API_KEY_SECRET")

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        receipt = None
        if violations:
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-04",
                action="REDACT",
                target_stage="MODEL_OUTPUT",
                reason="Sensitive information or API secrets redacted from output text",
                details={"violation_types": violations},
                latency_ms=latency_ms
            )

        return redacted, receipt

    def wrap_untrusted_context(self, content: str) -> str:
        """
        ASI-05 Mitigation: Wraps untrusted external context in strict <untrusted_context> XML boundaries
        after stripping dangerous HTML tags.
        """
        if not content:
            return "<untrusted_context>\n</untrusted_context>"
        clean = re.sub(r'</?(script|iframe|object|embed|style)[^>]*>', '', content, flags=re.IGNORECASE)
        return f"<untrusted_context>\n{clean.strip()}\n</untrusted_context>"
