"""
DNS-AID MCP Server.

Provides MCP tools for AI agents to publish and discover other agents via DNS.
Uses the DNS-AID protocol (IETF draft-mozleywilliams-dnsop-bandaid-02).

Usage:
    # Run with stdio transport (default for MCP)
    python -m dns_aid.mcp.server

    # Run with HTTP transport
    python -m dns_aid.mcp.server --transport http --port 8000

    # Or use the CLI
    dns-aid-mcp

Security Notes:
    - HTTP transport binds to 127.0.0.1 by default (use --host to override)
    - All inputs are validated before processing
    - For production HTTP deployment, use a reverse proxy (nginx, traefik)
"""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Literal

from mcp.server.fastmcp import FastMCP

from dns_aid.utils.validation import (
    ValidationError,
    validate_agent_name,
    validate_backend,
    validate_capabilities,
    validate_domain,
    validate_endpoint,
    validate_fqdn,
    validate_port,
    validate_protocol,
    validate_ttl,
    validate_version,
)

# Track server start time for uptime
_start_time = time.time()

# Shared thread pool for async operations (avoids creating pool per call)
_executor: ThreadPoolExecutor | None = None


def _get_executor() -> ThreadPoolExecutor:
    """Get or create shared thread pool executor."""
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns-aid-")
    return _executor


# Initialize MCP server
mcp = FastMCP(
    "DNS-AID",
    json_response=True,
    instructions="""DNS-AID enables AI agents to discover and connect to other agents using DNS.

Use these tools to:
- Publish your agent to DNS so others can discover it
- Discover other agents at a domain
- Verify that an agent's DNS records are properly configured
- List all agents published at a domain

DNS-AID uses SVCB records (RFC 9460) with the naming convention:
_{agent-name}._{protocol}._agents.{domain}

Example: _chat._mcp._agents.example.com""",
)


def _run_async(coro):
    """
    Run async coroutine in sync context.

    Uses a shared thread pool executor for better performance
    instead of creating a new pool per call.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None:
        # We're in an async context, use the shared thread pool
        executor = _get_executor()
        future = executor.submit(asyncio.run, coro)
        return future.result(timeout=30)  # 30 second timeout
    else:
        return asyncio.run(coro)


def _format_validation_error(e: ValidationError) -> dict:
    """Format validation error for API response."""
    return {
        "success": False,
        "error": "validation_error",
        "field": e.field,
        "message": e.message,
        "value": e.value,
    }


@mcp.tool()
def publish_agent_to_dns(
    name: str,
    domain: str,
    protocol: Literal["mcp", "a2a"] = "mcp",
    endpoint: str | None = None,
    port: int = 443,
    capabilities: list[str] | None = None,
    version: str = "1.0.0",
    ttl: int = 3600,
    backend: Literal["route53", "mock"] = "route53",
    update_index: bool = True,
) -> dict:
    """
    Publish an AI agent to DNS using DNS-AID protocol.

    Creates SVCB and TXT records that allow other agents to discover this agent.
    The agent will be discoverable at: _{name}._{protocol}._agents.{domain}

    By default, also updates the domain's index record (_index._agents.{domain})
    to include this agent for efficient discovery.

    Args:
        name: Agent identifier (e.g., "chat", "network-specialist", "data-cleaner").
              Must be lowercase with hyphens only.
        domain: Domain to publish under (must have DNS control via Route53 or other backend).
        protocol: Communication protocol - "mcp" for Model Context Protocol or "a2a" for Agent-to-Agent.
        endpoint: Hostname where agent is reachable. Defaults to {protocol}.{domain}.
        port: Port number where agent listens (default: 443).
        capabilities: List of agent capabilities (e.g., ["chat", "code-review", "data-analysis"]).
        version: Agent version string (default: "1.0.0").
        ttl: DNS record TTL in seconds (default: 3600).
        backend: DNS backend to use - "route53" for AWS Route53 or "mock" for testing.
        update_index: Whether to update the domain's agent index record (default: True).

    Returns:
        dict with:
        - success: Whether publication succeeded
        - fqdn: The fully qualified domain name for the agent record
        - endpoint_url: The URL where the agent can be reached
        - records_created: List of DNS records that were created
        - index_updated: Whether the index record was updated
        - message: Status message
    """
    # Validate all inputs
    try:
        name = validate_agent_name(name)
        domain = validate_domain(domain)
        protocol = validate_protocol(protocol)
        port = validate_port(port)
        capabilities = validate_capabilities(capabilities)
        version = validate_version(version)
        ttl = validate_ttl(ttl)
        backend = validate_backend(backend)

        if endpoint:
            endpoint = validate_endpoint(endpoint)
        else:
            endpoint = f"{protocol}.{domain}"

    except ValidationError as e:
        return _format_validation_error(e)

    from dns_aid.backends.base import DNSBackend
    from dns_aid.backends.mock import MockBackend
    from dns_aid.backends.route53 import Route53Backend
    from dns_aid.core.publisher import publish

    # Get backend
    dns_backend: DNSBackend
    if backend == "route53":
        dns_backend = Route53Backend()
    else:
        dns_backend = MockBackend()

    async def _publish():
        return await publish(
            name=name,
            domain=domain,
            protocol=protocol,
            endpoint=endpoint,
            port=port,
            capabilities=capabilities,
            version=version,
            ttl=ttl,
            backend=dns_backend,
        )

    try:
        result = _run_async(_publish())

        index_updated = False
        index_message = None

        # Update index if requested and publish succeeded
        if result.success and update_index:
            from dns_aid.core.indexer import IndexEntry
            from dns_aid.core.indexer import update_index as do_update_index

            async def _update_index():
                return await do_update_index(
                    domain=domain,
                    backend=dns_backend,
                    add=[IndexEntry(name=name, protocol=protocol)],
                    ttl=ttl,
                )

            try:
                index_result = _run_async(_update_index())
                index_updated = index_result.success
                if index_result.success:
                    action = "Created" if index_result.created else "Updated"
                    index_message = f"{action} index with {len(index_result.entries)} agent(s)"
                else:
                    index_message = index_result.message
            except Exception as e:
                index_message = f"Index update failed: {e}"

        return {
            "success": result.success,
            "fqdn": result.agent.fqdn if result.agent else None,
            "endpoint_url": result.agent.endpoint_url if result.agent else None,
            "records_created": result.records_created,
            "index_updated": index_updated,
            "index_message": index_message,
            "message": result.message,
        }
    except Exception as e:
        return {
            "success": False,
            "error": "publish_error",
            "message": str(e),
        }


@mcp.tool()
def discover_agents_via_dns(
    domain: str,
    protocol: Literal["mcp", "a2a"] | None = None,
    name: str | None = None,
) -> dict:
    """
    Discover AI agents at a domain using DNS-AID protocol.

    Queries DNS for SVCB records and returns agent endpoints. Use this to find
    agents that have been published to a domain.

    Args:
        domain: Domain to search for agents (e.g., "example.com", "salesforce.com").
        protocol: Filter by protocol - "mcp" or "a2a". If None, discovers all protocols.
        name: Filter by agent name (e.g., "chat", "network"). If None, discovers all agents.

    Returns:
        dict with:
        - domain: The domain that was queried
        - query: The DNS query that was made
        - agents: List of discovered agents, each with:
            - name: Agent identifier
            - protocol: Communication protocol
            - endpoint: Full URL to reach the agent
            - capabilities: List of agent capabilities
        - count: Number of agents found
        - query_time_ms: Query latency in milliseconds
    """
    # Validate inputs
    try:
        domain = validate_domain(domain)
        if protocol:
            protocol = validate_protocol(protocol)
        if name:
            name = validate_agent_name(name)
    except ValidationError as e:
        return _format_validation_error(e)

    from dns_aid.core.discoverer import discover

    async def _discover():
        return await discover(
            domain=domain,
            protocol=protocol,
            name=name,
        )

    try:
        result = _run_async(_discover())

        return {
            "domain": result.domain,
            "query": result.query,
            "agents": [
                {
                    "name": agent.name,
                    "protocol": agent.protocol.value,
                    "endpoint": agent.endpoint_url,
                    "capabilities": agent.capabilities,
                    "fqdn": agent.fqdn,
                }
                for agent in result.agents
            ],
            "count": result.count,
            "query_time_ms": result.query_time_ms,
        }
    except Exception as e:
        return {
            "success": False,
            "error": "discover_error",
            "message": str(e),
        }


@mcp.tool()
def verify_agent_dns(fqdn: str) -> dict:
    """
    Verify DNS-AID records for an agent.

    Checks DNS record existence, SVCB validity, DNSSEC validation, DANE/TLSA
    configuration, and endpoint reachability. Returns a security score.

    Args:
        fqdn: Fully qualified domain name of the agent record.
              Format: _{agent-name}._{protocol}._agents.{domain}
              Example: "_chat._mcp._agents.example.com"

    Returns:
        dict with:
        - fqdn: The FQDN that was verified
        - record_exists: Whether the DNS record exists
        - svcb_valid: Whether the SVCB record is properly formatted
        - dnssec_valid: Whether DNSSEC validation passed (None if not checked)
        - dane_valid: Whether DANE/TLSA is configured (None if not checked)
        - endpoint_reachable: Whether the endpoint responds
        - endpoint_latency_ms: Response latency if reachable
        - security_score: Score from 0-100
        - security_rating: Human-readable rating (Excellent, Good, Fair, Poor)
    """
    # Validate inputs
    try:
        fqdn = validate_fqdn(fqdn)
    except ValidationError as e:
        return _format_validation_error(e)

    from dns_aid.core.validator import verify

    async def _verify():
        return await verify(fqdn)

    try:
        result = _run_async(_verify())

        return {
            "fqdn": result.fqdn,
            "record_exists": result.record_exists,
            "svcb_valid": result.svcb_valid,
            "dnssec_valid": result.dnssec_valid,
            "dane_valid": result.dane_valid,
            "endpoint_reachable": result.endpoint_reachable,
            "endpoint_latency_ms": result.endpoint_latency_ms,
            "security_score": result.security_score,
            "security_rating": result.security_rating,
        }
    except Exception as e:
        return {
            "success": False,
            "error": "verify_error",
            "message": str(e),
        }


@mcp.tool()
def list_published_agents(
    domain: str,
    backend: Literal["route53", "mock"] = "route53",
) -> dict:
    """
    List all agents published at a domain via DNS-AID.

    Queries the DNS backend for all _agents.* records in the specified zone.

    Args:
        domain: Domain to list agents from (e.g., "example.com").
        backend: DNS backend to use - "route53" for AWS Route53 or "mock" for testing.

    Returns:
        dict with:
        - domain: The domain that was queried
        - records: List of DNS-AID records found, each with:
            - fqdn: Full record name
            - type: Record type (SVCB, TXT)
            - ttl: Time-to-live
            - value: Record value
        - count: Number of records found
    """
    # Validate inputs
    try:
        domain = validate_domain(domain)
        backend = validate_backend(backend)
    except ValidationError as e:
        return _format_validation_error(e)

    from dns_aid.backends.base import DNSBackend
    from dns_aid.backends.mock import MockBackend
    from dns_aid.backends.route53 import Route53Backend

    # Get backend
    dns_backend: DNSBackend
    if backend == "route53":
        dns_backend = Route53Backend()
    else:
        dns_backend = MockBackend()

    async def _list():
        records = []
        async for record in dns_backend.list_records(domain, name_pattern="_agents"):
            records.append(record)
        return records

    try:
        records = _run_async(_list())

        formatted_records = []
        for record in records:
            value = record.get("values", [])
            if isinstance(value, list):
                value = value[0] if value else ""
            formatted_records.append(
                {
                    "fqdn": record["fqdn"],
                    "type": record["type"],
                    "ttl": record["ttl"],
                    "value": str(value)[:100] + "..." if len(str(value)) > 100 else str(value),
                }
            )

        return {
            "domain": domain,
            "records": formatted_records,
            "count": len(formatted_records),
        }
    except Exception as e:
        return {
            "success": False,
            "error": "list_error",
            "message": str(e),
        }


@mcp.tool()
def delete_agent_from_dns(
    name: str,
    domain: str,
    protocol: Literal["mcp", "a2a"] = "mcp",
    backend: Literal["route53", "mock"] = "route53",
    update_index: bool = True,
) -> dict:
    """
    Delete an agent from DNS.

    Removes SVCB and TXT records for the specified agent.
    By default, also removes the agent from the domain's index record.

    Args:
        name: Agent identifier to delete.
        domain: Domain where agent is published.
        protocol: Protocol the agent was published with.
        backend: DNS backend to use.
        update_index: Whether to remove agent from domain's index record (default: True).

    Returns:
        dict with:
        - success: Whether deletion succeeded
        - fqdn: The FQDN that was deleted
        - index_updated: Whether the index record was updated
        - message: Status message
    """
    # Validate inputs
    try:
        name = validate_agent_name(name)
        domain = validate_domain(domain)
        protocol = validate_protocol(protocol)
        backend = validate_backend(backend)
    except ValidationError as e:
        return _format_validation_error(e)

    from dns_aid.backends.base import DNSBackend
    from dns_aid.backends.mock import MockBackend
    from dns_aid.backends.route53 import Route53Backend
    from dns_aid.core.publisher import unpublish

    # Get backend
    dns_backend: DNSBackend
    if backend == "route53":
        dns_backend = Route53Backend()
    else:
        dns_backend = MockBackend()

    async def _unpublish():
        return await unpublish(
            name=name,
            domain=domain,
            protocol=protocol,
            backend=dns_backend,
        )

    try:
        result = _run_async(_unpublish())
        fqdn = f"_{name}._{protocol}._agents.{domain}"

        index_updated = False
        index_message = None

        # Update index if requested and delete succeeded
        if result and update_index:
            from dns_aid.core.indexer import IndexEntry
            from dns_aid.core.indexer import update_index as do_update_index

            async def _update_index():
                return await do_update_index(
                    domain=domain,
                    backend=dns_backend,
                    remove=[IndexEntry(name=name, protocol=protocol)],
                )

            try:
                index_result = _run_async(_update_index())
                index_updated = index_result.success
                if index_result.success:
                    index_message = f"Updated index: {len(index_result.entries)} agent(s) remaining"
                else:
                    index_message = index_result.message
            except Exception as e:
                index_message = f"Index update failed: {e}"

        return {
            "success": result,
            "fqdn": fqdn,
            "index_updated": index_updated,
            "index_message": index_message,
            "message": "Agent deleted successfully" if result else "No records found to delete",
        }
    except Exception as e:
        return {
            "success": False,
            "error": "delete_error",
            "message": str(e),
        }


@mcp.tool()
def list_agent_index(
    domain: str,
    backend: Literal["route53", "mock"] = "route53",
) -> dict:
    """
    List agents in a domain's index record.

    Reads the _index._agents.{domain} TXT record and returns all indexed agents.
    This is useful for seeing what agents are published at a domain.

    Args:
        domain: Domain to list index from.
        backend: DNS backend to use.

    Returns:
        dict with:
        - domain: The domain queried
        - agents: List of indexed agents with name and protocol
        - count: Number of agents in the index
        - index_exists: Whether an index record was found
    """
    # Validate inputs
    try:
        domain = validate_domain(domain)
        backend = validate_backend(backend)
    except ValidationError as e:
        return _format_validation_error(e)

    from dns_aid.backends.base import DNSBackend
    from dns_aid.backends.mock import MockBackend
    from dns_aid.backends.route53 import Route53Backend
    from dns_aid.core.indexer import read_index

    # Get backend
    dns_backend: DNSBackend
    if backend == "route53":
        dns_backend = Route53Backend()
    else:
        dns_backend = MockBackend()

    async def _read_index():
        return await read_index(domain, dns_backend)

    try:
        entries = _run_async(_read_index())

        return {
            "domain": domain,
            "agents": [
                {
                    "name": entry.name,
                    "protocol": entry.protocol,
                    "fqdn": f"_{entry.name}._{entry.protocol}._agents.{domain}",
                }
                for entry in entries
            ],
            "count": len(entries),
            "index_exists": len(entries) > 0,
        }
    except Exception as e:
        return {
            "success": False,
            "error": "list_index_error",
            "message": str(e),
        }


@mcp.tool()
def sync_agent_index(
    domain: str,
    backend: Literal["route53", "mock"] = "route53",
    ttl: int = 3600,
) -> dict:
    """
    Sync domain's agent index with actual DNS records.

    Scans DNS for all _agents.* SVCB records and updates the index
    to reflect what's actually published.

    Args:
        domain: Domain to sync index for.
        backend: DNS backend to use.
        ttl: TTL for the index record.

    Returns:
        dict with:
        - success: Whether sync succeeded
        - domain: The domain synced
        - agents: List of agents now in the index
        - count: Number of agents found
        - created: Whether the index was newly created
        - message: Status message
    """
    # Validate inputs
    try:
        domain = validate_domain(domain)
        backend = validate_backend(backend)
        ttl = validate_ttl(ttl)
    except ValidationError as e:
        return _format_validation_error(e)

    from dns_aid.backends.base import DNSBackend
    from dns_aid.backends.mock import MockBackend
    from dns_aid.backends.route53 import Route53Backend
    from dns_aid.core.indexer import sync_index

    # Get backend
    dns_backend: DNSBackend
    if backend == "route53":
        dns_backend = Route53Backend()
    else:
        dns_backend = MockBackend()

    async def _sync_index():
        return await sync_index(domain, dns_backend, ttl=ttl)

    try:
        result = _run_async(_sync_index())

        return {
            "success": result.success,
            "domain": domain,
            "agents": [
                {
                    "name": entry.name,
                    "protocol": entry.protocol,
                }
                for entry in result.entries
            ],
            "count": len(result.entries),
            "created": result.created,
            "message": result.message,
        }
    except Exception as e:
        return {
            "success": False,
            "error": "sync_index_error",
            "message": str(e),
        }


# =============================================================================
# HEALTH ENDPOINTS (for HTTP transport)
# =============================================================================

try:
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response

    @mcp.custom_route(path="/health", methods=["GET"])
    async def health_check(request: Request) -> Response:
        """
        Health check endpoint for load balancers and monitoring.
        Returns server status and version information.
        """
        from dns_aid import __version__

        uptime = time.time() - _start_time

        return JSONResponse(
            {
                "status": "healthy",
                "service": "dns-aid-mcp",
                "version": __version__,
                "uptime_seconds": round(uptime, 2),
                "tools": [
                    "publish_agent_to_dns",
                    "discover_agents_via_dns",
                    "verify_agent_dns",
                    "list_published_agents",
                    "delete_agent_from_dns",
                    "list_agent_index",
                    "sync_agent_index",
                ],
            }
        )

    @mcp.custom_route(path="/ready", methods=["GET"])
    async def readiness_check(request: Request) -> Response:
        """
        Readiness check endpoint for Kubernetes and orchestrators.
        Verifies the server can handle requests.
        """
        # Test that we can import core modules
        try:
            from dns_aid.backends.mock import MockBackend  # noqa: F401
            from dns_aid.core.discoverer import discover  # noqa: F401
            from dns_aid.core.publisher import publish  # noqa: F401

            return JSONResponse(
                {
                    "ready": True,
                    "checks": {
                        "publisher": "ok",
                        "discoverer": "ok",
                        "mock_backend": "ok",
                    },
                }
            )
        except ImportError as e:
            return JSONResponse(
                {
                    "ready": False,
                    "error": str(e),
                },
                status_code=503,
            )

    @mcp.custom_route(path="/", methods=["GET"])
    async def root_info(request: Request) -> Response:
        """
        Root endpoint with API information.
        """
        from dns_aid import __version__

        return JSONResponse(
            {
                "service": "DNS-AID MCP Server",
                "version": __version__,
                "description": "DNS-based Agent Identification and Discovery",
                "endpoints": {
                    "/mcp": "MCP protocol endpoint (POST)",
                    "/health": "Health check (GET)",
                    "/ready": "Readiness check (GET)",
                },
                "documentation": "https://github.com/iracic82/dns-aid",
                "specification": "IETF draft-mozleywilliams-dnsop-bandaid-02",
            }
        )

except ImportError:
    # Starlette not available (stdio-only mode)
    pass


def _cleanup():
    """Cleanup resources on shutdown."""
    global _executor
    if _executor is not None:
        _executor.shutdown(wait=False)
        _executor = None


def main():
    """Run the MCP server."""
    import atexit
    import sys

    # Register cleanup handler
    atexit.register(_cleanup)

    transport = "stdio"
    # Security: Default to localhost for HTTP transport
    host = "127.0.0.1"
    port = 8000

    # Simple argument parsing
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--transport":
            transport = args[i + 1]
            i += 2
        elif args[i] == "--port":
            port = int(args[i + 1])
            i += 2
        elif args[i] == "--host":
            host = args[i + 1]
            i += 2
        elif args[i] in ("--help", "-h"):
            print("""DNS-AID MCP Server

Usage: dns-aid-mcp [OPTIONS]

Options:
  --transport <TYPE>   Transport type: stdio (default) or http
  --host <HOST>        Host to bind to (default: 127.0.0.1, http only)
  --port <PORT>        Port to listen on (default: 8000, http only)
  --help, -h           Show this help message

Examples:
  dns-aid-mcp                           # Run with stdio transport
  dns-aid-mcp --transport http          # Run HTTP server on localhost:8000
  dns-aid-mcp --transport http --port 9000  # Run HTTP server on port 9000
  dns-aid-mcp --transport http --host 0.0.0.0  # Bind to all interfaces (use with caution)

HTTP Endpoints:
  /mcp      MCP protocol endpoint
  /health   Health check
  /ready    Readiness check

Security Notes:
  - HTTP transport binds to 127.0.0.1 by default for security
  - For production deployment, use a reverse proxy (nginx, traefik)
  - Use --host 0.0.0.0 only in containerized environments with proper network isolation
""")
            return
        else:
            i += 1

    if transport == "http":
        import uvicorn

        # Security warning for binding to all interfaces
        if host == "0.0.0.0":  # nosec B104 - This is a security check, not a bind
            print("WARNING: Binding to 0.0.0.0 exposes this server to all network interfaces.")
            print("         Ensure proper network isolation or use a reverse proxy.")
            print()

        print(f"Starting DNS-AID MCP server on http://{host}:{port}")
        print(f"  MCP endpoint: http://{host}:{port}/mcp")
        print(f"  Health check: http://{host}:{port}/health")
        print(f"  Ready check:  http://{host}:{port}/ready")
        print()
        uvicorn.run(
            mcp.streamable_http_app(),
            host=host,
            port=port,
            log_level="info",
        )
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
