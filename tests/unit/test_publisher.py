"""Tests for DNS-AID publisher."""

import pytest

from dns_aid.backends.mock import MockBackend
from dns_aid.core.models import Protocol
from dns_aid.core.publisher import publish, unpublish


class TestPublish:
    """Tests for publish function."""

    @pytest.mark.asyncio
    async def test_publish_basic(self, mock_backend: MockBackend):
        """Test basic agent publishing."""
        result = await publish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            endpoint="chat.example.com",
            backend=mock_backend,
        )

        assert result.success is True
        assert result.agent.name == "chat"
        assert result.agent.fqdn == "_chat._a2a._agents.example.com"
        assert len(result.records_created) == 2  # SVCB + TXT

    @pytest.mark.asyncio
    async def test_publish_with_capabilities(self, mock_backend: MockBackend):
        """Test publishing with capabilities."""
        result = await publish(
            name="network",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["ipam", "dns", "vpn"],
            backend=mock_backend,
        )

        assert result.success is True
        assert result.agent.capabilities == ["ipam", "dns", "vpn"]

        # Check TXT record was created with capabilities
        txt_values = mock_backend.get_txt_record("example.com", "_network._mcp._agents")
        assert txt_values is not None
        assert "capabilities=ipam,dns,vpn" in txt_values

    @pytest.mark.asyncio
    async def test_publish_creates_svcb_record(self, mock_backend: MockBackend):
        """Test that SVCB record is created correctly."""
        await publish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            endpoint="chat.example.com",
            port=8443,
            backend=mock_backend,
        )

        svcb = mock_backend.get_svcb_record("example.com", "_chat._a2a._agents")

        assert svcb is not None
        assert svcb["target"] == "chat.example.com."
        assert svcb["params"]["alpn"] == "a2a"
        assert svcb["params"]["port"] == "8443"

    @pytest.mark.asyncio
    async def test_publish_with_protocol_enum(self, mock_backend: MockBackend):
        """Test publishing with Protocol enum."""
        result = await publish(
            name="agent",
            domain="example.com",
            protocol=Protocol.MCP,
            endpoint="mcp.example.com",
            backend=mock_backend,
        )

        assert result.success is True
        assert result.agent.protocol == Protocol.MCP

    @pytest.mark.asyncio
    async def test_publish_invalid_zone(self, mock_backend: MockBackend):
        """Test publishing to non-existent zone."""
        # Configure mock to only accept specific zones
        mock_backend._zones = {"allowed.com"}

        result = await publish(
            name="chat",
            domain="notallowed.com",
            protocol="a2a",
            endpoint="chat.notallowed.com",
            backend=mock_backend,
        )

        assert result.success is False
        assert "does not exist" in result.message

    @pytest.mark.asyncio
    async def test_publish_custom_ttl(self, mock_backend: MockBackend):
        """Test publishing with custom TTL."""
        result = await publish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            endpoint="chat.example.com",
            ttl=300,
            backend=mock_backend,
        )

        assert result.success is True
        assert result.agent.ttl == 300

        svcb = mock_backend.get_svcb_record("example.com", "_chat._a2a._agents")
        assert svcb["ttl"] == 300


class TestUnpublish:
    """Tests for unpublish function."""

    @pytest.mark.asyncio
    async def test_unpublish_existing(self, mock_backend: MockBackend):
        """Test unpublishing an existing agent."""
        # First publish
        await publish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            endpoint="chat.example.com",
            backend=mock_backend,
        )

        # Verify records exist
        assert mock_backend.get_svcb_record("example.com", "_chat._a2a._agents") is not None

        # Unpublish
        result = await unpublish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            backend=mock_backend,
        )

        assert result is True
        assert mock_backend.get_svcb_record("example.com", "_chat._a2a._agents") is None

    @pytest.mark.asyncio
    async def test_unpublish_nonexistent(self, mock_backend: MockBackend):
        """Test unpublishing non-existent agent returns False."""
        result = await unpublish(
            name="nonexistent",
            domain="example.com",
            protocol="a2a",
            backend=mock_backend,
        )

        assert result is False
