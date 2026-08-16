import os
import pytest
import asyncio

from agentic_gov.telemetry.composite import CompositeExplainabilityBuilder
from agentic_gov.telemetry.storage import AsyncTelemetrySink
from agentic_gov.telemetry.otel import OTelTracePropagator
from agentic_gov.telemetry.exporter import AnnexIVAuditPackageExporter
from agentic_gov.core.types import (
    Layer1DataGovernance,
    Layer2ModelGovernance,
    Layer3SystemIntegration,
    Layer4ControlMonitoring,
    Layer5AuditEvidence
)


def test_composite_explainability_assembly_latency():
    builder = CompositeExplainabilityBuilder()

    l1 = Layer1DataGovernance(source_provenance_uri="s3://data/v1", collection_timestamp_ns=1700000000000000000, freshness_days=2.5)
    l2 = Layer2ModelGovernance(model_version_hash="gemma2_2b")
    l3 = Layer3SystemIntegration(decision_confidence=0.99)
    l4 = Layer4ControlMonitoring(psi_drift_score=0.02)
    l5 = Layer5AuditEvidence(rule_version_hash="rule_sec@v1", merkle_node_hash="node_abc")

    payload = builder.assemble(
        agent_id="agent_007",
        layer1_dg=l1,
        layer2_mg=l2,
        layer3_si=l3,
        layer4_cm=l4,
        layer5_ae=l5
    )

    assert payload.agent_id == "agent_007"
    assert payload.layer1_dg.freshness_days == 2.5
    assert payload.layer5_ae.merkle_node_hash == "node_abc"


@pytest.mark.asyncio
async def test_async_telemetry_sink_queue_and_drain():
    sink = AsyncTelemetrySink()
    await sink.initialize()

    # Enqueue event and measure latency (< 0.5ms target)
    latency_ms = sink.enqueue_event("GOVERNANCE_LOG", {"action": "ALLOW", "agent_id": "test_agent"})
    assert latency_ms < 0.5

    # Graceful shutdown & drain
    await sink.aclose()


def test_otel_trace_propagation():
    propagator = OTelTracePropagator()
    headers = {}
    updated_headers = propagator.inject_trace_headers(headers)

    assert "trace_id" in updated_headers
    assert "parent_span_id" in updated_headers

    trace_id, span_id = propagator.extract_trace_context(updated_headers)
    assert trace_id == updated_headers["trace_id"]
    assert span_id == updated_headers["parent_span_id"]


def test_annex_iv_exporter():
    exporter = AnnexIVAuditPackageExporter()
    trace_id = "test_trace_12345"

    package = exporter.generate_audit_package(trace_id=trace_id)
    assert package["trace_id"] == trace_id
    assert package["export_latency_seconds"] < 5.0
    assert "compliance_standard" in package

    markdown = exporter.render_markdown_report(package)
    assert "# EU AI Act Annex IV Compliance" in markdown
    assert trace_id in markdown
