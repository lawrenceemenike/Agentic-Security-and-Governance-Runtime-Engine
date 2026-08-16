import re
import time
import logging
from typing import Tuple, Optional, Set, Dict, Any

from agentic_gov.core.types import GovernanceDecisionReceipt

logger = logging.getLogger(__name__)

# --- Patterns for Shell Operators, Binaries & Tags ---
SHELL_OPERATORS_PATTERN = re.compile(r'(\||&&|;|`|\$(?:\(|\{)|>|<|\bexec\b|\beval\b)', re.IGNORECASE)
EXEC_PATHS_PATTERN = re.compile(r'(/etc/passwd|c:\\windows|cmd\.exe|powershell|/bin/sh|/bin/bash)', re.IGNORECASE)
HTML_DANGEROUS_TAGS_PATTERN = re.compile(r'<\s*(script|iframe|object|embed|style)\b[^>]*>', re.IGNORECASE)


class ToolIntentGate:
    """
    Structural Intent Parser & Allowlist Gate (OWASP ASI-01 & ASI-02).
    Decomposes tool calls into (Action, Target, Scope) tuples, enforces tool allowlists,
    argument string bounds (1 <= len <= 200), and blocks shell execution vectors.
    """

    def __init__(self, allowed_tools: Optional[Set[str]] = None, max_arg_length: int = 200):
        self.allowed_tools = allowed_tools or {"SearxNG Scraped Search Tool", "SearxNGTool", "PythonInterpreterTool"}
        self.max_arg_length = max_arg_length

    def decompose_intent(self, tool_name: str, args: Dict[str, Any]) -> Tuple[str, str, str]:
        """
        Decomposes tool call into (Action, Target, Scope).
        """
        action = tool_name
        target = str(args.get("target") or args.get("query") or args.get("path") or "default_target")
        scope = str(args.get("scope") or "execute")
        return action, target, scope

    def validate_tool_call(
        self,
        tool_name: str,
        query: str,
        additional_args: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[GovernanceDecisionReceipt]]:
        """
        Validates proposed tool invocation against allowlist and argument constraints.
        Returns (is_safe, receipt).
        """
        start_time = time.perf_counter()

        # 1. Tool Allowlist Check (ASI-01)
        if tool_name not in self.allowed_tools:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-01",
                action="BLOCK",
                target_stage="TOOL_ARG",
                reason=f"Unauthorized tool execution attempt: '{tool_name}'",
                details={"tool_name": tool_name, "allowed_tools": list(self.allowed_tools)},
                latency_ms=latency_ms
            )
            return False, receipt

        # 2. Argument Length Checks (ASI-02)
        if not query or len(query.strip()) == 0:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-02",
                action="BLOCK",
                target_stage="TOOL_ARG",
                reason="Query argument string cannot be empty",
                latency_ms=latency_ms
            )
            return False, receipt

        if len(query) > self.max_arg_length:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-02",
                action="BLOCK",
                target_stage="TOOL_ARG",
                reason=f"Query string length ({len(query)}) exceeds maximum limit of {self.max_arg_length} chars",
                details={"query_length": len(query), "limit": self.max_arg_length},
                latency_ms=latency_ms
            )
            return False, receipt

        # 3. Shell Operators & Injection Traps (ASI-02)
        if SHELL_OPERATORS_PATTERN.search(query):
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-02",
                action="BLOCK",
                target_stage="TOOL_ARG",
                reason="Query contains prohibited shell operators (| && ; ` $)",
                latency_ms=latency_ms
            )
            return False, receipt

        # 4. Executable Paths & Script Tags (ASI-02)
        if EXEC_PATHS_PATTERN.search(query) or HTML_DANGEROUS_TAGS_PATTERN.search(query):
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            receipt = GovernanceDecisionReceipt(
                asi_code="ASI-02",
                action="BLOCK",
                target_stage="TOOL_ARG",
                reason="Query contains executable file paths or HTML script tags",
                latency_ms=latency_ms
            )
            return False, receipt

        return True, None
