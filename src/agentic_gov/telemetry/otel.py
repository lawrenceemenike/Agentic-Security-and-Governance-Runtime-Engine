import logging
from typing import Dict, Any, Optional, Tuple

try:
    from opentelemetry import trace
    OPENTELEMETRY_AVAILABLE = True
except ImportError:
    OPENTELEMETRY_AVAILABLE = False

from agentic_gov.core.types import generate_uuidv7

logger = logging.getLogger(__name__)


class OTelTracePropagator:
    """
    OpenTelemetry Context & Span Propagator (SI-2).
    Injects and extracts trace_id and parent_span_id across inter-agent message envelopes.
    Provides graceful zero-crash fallback if OpenTelemetry libraries are not installed.
    """

    def __init__(self, service_name: str = "agentic-gov"):
        self.service_name = service_name
        self.tracer = None
        if OPENTELEMETRY_AVAILABLE:
            try:
                self.tracer = trace.get_tracer(service_name)
            except Exception as e:
                logger.warning(f"Failed to initialize OpenTelemetry tracer: {e}")

    def inject_trace_headers(self, headers: Dict[str, Any], trace_id: Optional[str] = None, span_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Injects trace_id and parent_span_id into message headers dictionary.
        """
        active_trace_id = trace_id or generate_uuidv7()
        active_span_id = span_id or generate_uuidv7()[:16]

        if OPENTELEMETRY_AVAILABLE and self.tracer:
            try:
                current_span = trace.get_current_span()
                ctx = current_span.get_span_context()
                if ctx.is_valid:
                    active_trace_id = f"{ctx.trace_id:032x}"
                    active_span_id = f"{ctx.span_id:016x}"
            except Exception:
                pass

        headers["trace_id"] = active_trace_id
        headers["parent_span_id"] = active_span_id
        headers["service_name"] = self.service_name
        return headers

    def extract_trace_context(self, headers: Dict[str, Any]) -> Tuple[str, str]:
        """
        Extracts (trace_id, parent_span_id) from message headers.
        """
        trace_id = str(headers.get("trace_id") or generate_uuidv7())
        parent_span_id = str(headers.get("parent_span_id") or generate_uuidv7()[:16])
        return trace_id, parent_span_id
