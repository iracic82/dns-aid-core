"""Tests for OTEL telemetry integration."""

from __future__ import annotations

from unittest.mock import patch

from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.models import InvocationSignal, InvocationStatus
from dns_aid.sdk.telemetry.otel import TelemetryManager


def _make_signal() -> InvocationSignal:
    return InvocationSignal(
        agent_fqdn="_network._mcp._agents.example.com",
        agent_endpoint="https://mcp.example.com:443",
        protocol="mcp",
        method="tools/call",
        invocation_latency_ms=150.0,
        status=InvocationStatus.SUCCESS,
        cost_units=0.5,
    )


class TestTelemetryManager:
    def setup_method(self) -> None:
        TelemetryManager.reset()

    def test_singleton(self) -> None:
        """Test get_or_create returns same instance."""
        config = SDKConfig(otel_enabled=False)
        mgr1 = TelemetryManager.get_or_create(config)
        mgr2 = TelemetryManager.get_or_create(config)
        assert mgr1 is mgr2

    def test_reset(self) -> None:
        """Test reset clears singleton."""
        config = SDKConfig(otel_enabled=False)
        mgr1 = TelemetryManager.get_or_create(config)
        TelemetryManager.reset()
        mgr2 = TelemetryManager.get_or_create(config)
        assert mgr1 is not mgr2

    def test_disabled_noop(self) -> None:
        """Test that disabled OTEL is a no-op."""
        config = SDKConfig(otel_enabled=False)
        mgr = TelemetryManager.get_or_create(config)
        assert mgr.is_available is False
        # Should not raise
        mgr.record_signal(_make_signal())

    def test_otel_not_installed_noop(self) -> None:
        """Test graceful fallback when opentelemetry is not installed."""
        config = SDKConfig(otel_enabled=True, otel_export_format="console")

        with patch("dns_aid.sdk.telemetry.otel._otel_available", False):
            mgr = TelemetryManager(config)
            mgr._initialize()
            assert mgr.is_available is False
            # Should not raise
            mgr.record_signal(_make_signal())

    def test_record_signal_when_available(self) -> None:
        """Test recording a signal when OTEL is available (console exporter)."""
        from dns_aid.sdk.telemetry.otel import _otel_available

        if not _otel_available:
            # Skip if OTEL not installed in test environment
            return

        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        mgr = TelemetryManager.get_or_create(config)

        signal = _make_signal()
        # Should not raise
        mgr.record_signal(signal)

    def test_record_error_signal(self) -> None:
        """Test recording an error signal."""
        from dns_aid.sdk.telemetry.otel import _otel_available

        if not _otel_available:
            return

        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        mgr = TelemetryManager.get_or_create(config)

        signal = InvocationSignal(
            agent_fqdn="_network._mcp._agents.example.com",
            agent_endpoint="https://mcp.example.com:443",
            protocol="mcp",
            invocation_latency_ms=5000.0,
            status=InvocationStatus.TIMEOUT,
            error_type="TimeoutError",
            error_message="Connection timed out",
        )
        mgr.record_signal(signal)
