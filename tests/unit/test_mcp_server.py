"""
Unit tests for MCP server tools.

Tests the MCP tool functions using the mock backend.
"""


class TestMCPServerImport:
    """Test MCP server can be imported and has correct tools."""

    def test_server_import(self):
        """Test MCP server imports successfully."""
        from dns_aid.mcp.server import mcp

        assert mcp is not None
        assert mcp.name == "DNS-AID"

    def test_tools_registered(self):
        """Test all expected tools are registered."""
        from dns_aid.mcp.server import mcp

        tools = list(mcp._tool_manager._tools.keys())

        expected_tools = [
            "publish_agent_to_dns",
            "discover_agents_via_dns",
            "verify_agent_dns",
            "list_published_agents",
            "delete_agent_from_dns",
        ]

        for tool in expected_tools:
            assert tool in tools, f"Tool {tool} not registered"


class TestPublishAgentTool:
    """Test the publish_agent_to_dns tool."""

    def test_publish_with_mock_backend(self):
        """Test publishing agent with mock backend."""
        from dns_aid.mcp.server import publish_agent_to_dns

        result = publish_agent_to_dns(
            name="test-agent",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            port=443,
            capabilities=["test", "demo"],
            backend="mock",
        )

        assert result["success"] is True
        assert result["fqdn"] == "_test-agent._mcp._agents.example.com"
        assert result["endpoint_url"] == "https://mcp.example.com:443"
        assert len(result["records_created"]) == 2

    def test_publish_default_endpoint(self):
        """Test publishing with default endpoint."""
        from dns_aid.mcp.server import publish_agent_to_dns

        result = publish_agent_to_dns(
            name="chat",
            domain="test.com",
            protocol="a2a",
            backend="mock",
        )

        assert result["success"] is True
        assert result["endpoint_url"] == "https://a2a.test.com:443"


class TestDiscoverAgentsTool:
    """Test the discover_agents_via_dns tool."""

    def test_discover_no_agents(self):
        """Test discovery when no agents exist."""
        from unittest.mock import AsyncMock, patch

        from dns_aid.core.models import DiscoveryResult
        from dns_aid.mcp.server import discover_agents_via_dns

        # Mock the discover function to avoid real DNS queries
        mock_result = DiscoveryResult(
            query="_index._agents.nonexistent.com",
            domain="nonexistent.com",
            agents=[],
            dnssec_validated=False,
            cached=False,
            query_time_ms=1.0,
        )
        with patch("dns_aid.core.discoverer.discover", new=AsyncMock(return_value=mock_result)):
            result = discover_agents_via_dns(
                domain="nonexistent.com",
            )

        assert result["domain"] == "nonexistent.com"
        assert result["count"] == 0
        assert result["agents"] == []

    def test_discover_returns_dict(self):
        """Test discovery returns proper structure."""
        from unittest.mock import AsyncMock, patch

        from dns_aid.core.models import DiscoveryResult
        from dns_aid.mcp.server import discover_agents_via_dns

        # Mock the discover function to avoid real DNS queries
        mock_result = DiscoveryResult(
            query="_index._mcp._agents.example.com",
            domain="example.com",
            agents=[],
            dnssec_validated=False,
            cached=False,
            query_time_ms=1.0,
        )
        with patch("dns_aid.core.discoverer.discover", new=AsyncMock(return_value=mock_result)):
            result = discover_agents_via_dns(
                domain="example.com",
                protocol="mcp",
            )

        assert "domain" in result
        assert "query" in result
        assert "agents" in result
        assert "count" in result
        assert "query_time_ms" in result


class TestVerifyAgentTool:
    """Test the verify_agent_dns tool."""

    def test_verify_nonexistent_agent(self):
        """Test verifying a nonexistent agent."""
        from dns_aid.mcp.server import verify_agent_dns

        result = verify_agent_dns(fqdn="_nonexistent._mcp._agents.example.com")

        assert result["fqdn"] == "_nonexistent._mcp._agents.example.com"
        assert result["record_exists"] is False
        assert "security_score" in result
        assert "security_rating" in result

    def test_verify_returns_all_fields(self):
        """Test verify returns all expected fields."""
        from dns_aid.mcp.server import verify_agent_dns

        result = verify_agent_dns(fqdn="_test._mcp._agents.example.com")

        expected_fields = [
            "fqdn",
            "record_exists",
            "svcb_valid",
            "dnssec_valid",
            "dane_valid",
            "endpoint_reachable",
            "endpoint_latency_ms",
            "security_score",
            "security_rating",
        ]

        for field in expected_fields:
            assert field in result, f"Field {field} missing from result"


class TestListAgentsTool:
    """Test the list_published_agents tool."""

    def test_list_with_mock_backend(self):
        """Test listing agents with mock backend."""
        from dns_aid.mcp.server import list_published_agents

        result = list_published_agents(
            domain="example.com",
            backend="mock",
        )

        assert result["domain"] == "example.com"
        assert "records" in result
        assert "count" in result
        assert isinstance(result["records"], list)

    def test_list_returns_structure(self):
        """Test list returns proper structure."""
        from dns_aid.mcp.server import list_published_agents

        result = list_published_agents(
            domain="test.com",
            backend="mock",
        )

        assert isinstance(result, dict)
        assert result["domain"] == "test.com"


class TestDeleteAgentTool:
    """Test the delete_agent_from_dns tool."""

    def test_delete_with_mock_backend(self):
        """Test deleting agent with mock backend."""
        from dns_aid.mcp.server import (
            delete_agent_from_dns,
            publish_agent_to_dns,
        )

        # First publish
        publish_agent_to_dns(
            name="to-delete",
            domain="example.com",
            protocol="mcp",
            backend="mock",
        )

        # Then delete
        result = delete_agent_from_dns(
            name="to-delete",
            domain="example.com",
            protocol="mcp",
            backend="mock",
        )

        assert result["fqdn"] == "_to-delete._mcp._agents.example.com"
        assert "success" in result
        assert "message" in result

    def test_delete_nonexistent(self):
        """Test deleting nonexistent agent."""
        from dns_aid.mcp.server import delete_agent_from_dns

        result = delete_agent_from_dns(
            name="does-not-exist",
            domain="example.com",
            protocol="mcp",
            backend="mock",
        )

        assert result["success"] is False
        assert "No records found" in result["message"]
