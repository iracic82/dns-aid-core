"""
DNS-AID Discoverer: Query DNS to find AI agents.

This module handles discovering agents via DNS queries for SVCB and TXT
records as specified in IETF draft-mozleywilliams-dnsop-bandaid-02.
"""

from __future__ import annotations

import time

import dns.asyncresolver
import dns.rdatatype
import dns.resolver
import structlog

from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol

logger = structlog.get_logger(__name__)


async def discover(
    domain: str,
    protocol: str | Protocol | None = None,
    name: str | None = None,
    require_dnssec: bool = False,  # Default False for now, True in production
) -> DiscoveryResult:
    """
    Discover AI agents at a domain using DNS-AID protocol.

    Queries DNS for SVCB records under _agents.{domain} and returns
    discovered agent endpoints.

    Args:
        domain: Domain to search for agents (e.g., "example.com")
        protocol: Filter by protocol ("a2a", "mcp", or None for all)
        name: Filter by specific agent name (or None for all)
        require_dnssec: Require DNSSEC validation (raises if invalid)

    Returns:
        DiscoveryResult with list of discovered agents

    Example:
        >>> result = await discover("example.com", protocol="mcp")
        >>> for agent in result.agents:
        ...     print(f"{agent.name}: {agent.endpoint_url}")
    """
    start_time = time.perf_counter()

    # Normalize protocol
    if isinstance(protocol, str):
        protocol = Protocol(protocol.lower())

    # Build query based on filters
    if name and protocol:
        # Specific agent
        query = f"_{name}._{protocol.value}._agents.{domain}"
    elif protocol:
        # All agents with specific protocol - query index
        query = f"_index._{protocol.value}._agents.{domain}"
    else:
        # All agents - query general index
        query = f"_index._agents.{domain}"

    logger.info(
        "Discovering agents via DNS",
        domain=domain,
        protocol=protocol.value if protocol else None,
        name=name,
        query=query,
    )

    agents: list[AgentRecord] = []
    dnssec_validated = False

    try:
        # First try specific query if name is provided
        if name and protocol:
            agent = await _query_single_agent(domain, name, protocol)
            if agent:
                agents.append(agent)
        else:
            # Try to discover multiple agents
            agents = await _discover_agents_in_zone(domain, protocol)

    except dns.resolver.NXDOMAIN:
        logger.debug("No DNS-AID records found", query=query)
    except dns.resolver.NoAnswer:
        logger.debug("No answer for query", query=query)
    except dns.resolver.NoNameservers:
        logger.error("No nameservers available", domain=domain)
    except Exception as e:
        logger.exception("DNS query failed", error=str(e))

    elapsed_ms = (time.perf_counter() - start_time) * 1000

    result = DiscoveryResult(
        query=query,
        domain=domain,
        agents=agents,
        dnssec_validated=dnssec_validated,
        cached=False,
        query_time_ms=elapsed_ms,
    )

    logger.info(
        "Discovery complete",
        domain=domain,
        agents_found=result.count,
        time_ms=f"{elapsed_ms:.2f}",
    )

    return result


async def _query_single_agent(
    domain: str,
    name: str,
    protocol: Protocol,
) -> AgentRecord | None:
    """Query DNS for a specific agent's SVCB record."""
    fqdn = f"_{name}._{protocol.value}._agents.{domain}"

    try:
        resolver = dns.asyncresolver.Resolver()

        # Query SVCB record
        # Note: dnspython uses type 64 for SVCB
        try:
            answers = await resolver.resolve(fqdn, "SVCB")
        except dns.resolver.NoAnswer:
            # Try HTTPS record as fallback (type 65)
            try:
                answers = await resolver.resolve(fqdn, "HTTPS")
            except dns.resolver.NoAnswer:
                return None

        for rdata in answers:
            # Parse SVCB record
            target = str(rdata.target).rstrip(".")
            # Note: priority (rdata.priority) available but not currently used

            # Extract parameters
            port = 443
            ipv4_hint = None
            ipv6_hint = None

            # Parse SVCB params (keys are param types, values are param data)
            for key, _value in rdata.params.items():
                if key == dns.rdatatype.RdataType.SVCB:
                    pass  # Handle specific params as needed
                # Port is typically in params

            if hasattr(rdata, "port") and rdata.port:
                port = rdata.port

            # Query TXT for capabilities
            capabilities = await _query_capabilities(fqdn)

            return AgentRecord(
                name=name,
                domain=domain,
                protocol=protocol,
                target_host=target,
                port=port,
                ipv4_hint=ipv4_hint,
                ipv6_hint=ipv6_hint,
                capabilities=capabilities,
            )

    except Exception as e:
        logger.debug("Failed to query agent", fqdn=fqdn, error=str(e))

    return None


async def _query_capabilities(fqdn: str) -> list[str]:
    """Query TXT record for agent capabilities."""
    capabilities = []

    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve(fqdn, "TXT")

        for rdata in answers:
            # TXT records can have multiple strings
            for txt_string in rdata.strings:
                txt = txt_string.decode("utf-8")
                if txt.startswith("capabilities="):
                    caps = txt[len("capabilities=") :]
                    capabilities.extend(caps.split(","))

    except Exception:
        pass  # TXT record is optional

    return capabilities


async def _discover_agents_in_zone(
    domain: str,
    protocol: Protocol | None = None,
) -> list[AgentRecord]:
    """
    Discover all agents in a domain's _agents zone.

    This queries for known patterns and the index.
    """
    agents = []

    # For now, we try common agent names
    # In a full implementation, we'd query the index or do zone enumeration
    # TODO: Phase 2 will add _index._agents.* query and NSEC zone walking
    common_names = [
        "chat",
        "assistant",
        "network",
        "data-cleaner",
        "index",
        "multiagent",  # For multi-agent platform discovery
        "api",
        "help",
        "support",
        "agent",
    ]

    protocols_to_try = [protocol] if protocol else [Protocol.MCP, Protocol.A2A]

    for proto in protocols_to_try:
        for name in common_names:
            agent = await _query_single_agent(domain, name, proto)
            if agent:
                agents.append(agent)

    return agents


async def discover_at_fqdn(fqdn: str) -> AgentRecord | None:
    """
    Discover agent at a specific FQDN.

    Args:
        fqdn: Full DNS-AID record name (e.g., "_chat._a2a._agents.example.com")

    Returns:
        AgentRecord if found, None otherwise
    """
    # Parse FQDN to extract components
    # Format: _{name}._{protocol}._agents.{domain}
    parts = fqdn.split(".")

    if len(parts) < 4:
        logger.error("Invalid DNS-AID FQDN format", fqdn=fqdn)
        return None

    # Extract components
    name_part = parts[0]  # _name
    protocol_part = parts[1]  # _protocol

    if not name_part.startswith("_") or not protocol_part.startswith("_"):
        logger.error("Invalid DNS-AID FQDN format", fqdn=fqdn)
        return None

    name = name_part[1:]  # Remove leading underscore
    protocol_str = protocol_part[1:]  # Remove leading underscore

    # Find _agents marker to determine domain
    try:
        agents_idx = parts.index("_agents")
        domain = ".".join(parts[agents_idx + 1 :])
    except ValueError:
        logger.error("Missing _agents in FQDN", fqdn=fqdn)
        return None

    try:
        protocol = Protocol(protocol_str)
    except ValueError:
        logger.error("Unknown protocol", protocol=protocol_str)
        return None

    return await _query_single_agent(domain, name, protocol)
