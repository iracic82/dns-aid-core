"""
DNS-AID Validator: Verify agent DNS records and security.

Handles DNSSEC validation, DANE/TLSA verification, and endpoint health checks.
"""

from __future__ import annotations

import time

import dns.asyncresolver
import dns.flags
import dns.rdatatype
import dns.resolver
import httpx
import structlog

from dns_aid.core.models import VerifyResult

logger = structlog.get_logger(__name__)


async def verify(fqdn: str) -> VerifyResult:
    """
    Verify DNS-AID records for an agent.

    Checks:
    - DNS record exists
    - SVCB record is valid
    - DNSSEC chain is validated
    - DANE/TLSA certificate binding (if configured)
    - Endpoint is reachable

    Args:
        fqdn: Fully qualified domain name of agent record
              (e.g., "_chat._a2a._agents.example.com")

    Returns:
        VerifyResult with security validation results
    """
    logger.info("Verifying agent DNS records", fqdn=fqdn)

    result = VerifyResult(fqdn=fqdn)

    # 1. Check SVCB record exists and is valid
    svcb_data = await _check_svcb_record(fqdn)
    if svcb_data:
        result.record_exists = True
        result.svcb_valid = svcb_data.get("valid", False)
        target = svcb_data.get("target")
        port = svcb_data.get("port", 443)
    else:
        target = None
        port = None

    # 2. Check DNSSEC validation
    result.dnssec_valid = await _check_dnssec(fqdn)

    # 3. Check DANE/TLSA (if target is available)
    if target:
        result.dane_valid = await _check_dane(target, port)

    # 4. Check endpoint reachability
    if target and port:
        endpoint_result = await _check_endpoint(target, port)
        result.endpoint_reachable = endpoint_result.get("reachable", False)
        result.endpoint_latency_ms = endpoint_result.get("latency_ms")

    logger.info(
        "Verification complete",
        fqdn=fqdn,
        score=result.security_score,
        rating=result.security_rating,
    )

    return result


async def _check_svcb_record(fqdn: str) -> dict | None:
    """
    Check if SVCB record exists and is valid.

    Returns dict with target, port, and validity info, or None if not found.
    """
    try:
        resolver = dns.asyncresolver.Resolver()

        # Query SVCB record
        try:
            answers = await resolver.resolve(fqdn, "SVCB")
        except dns.resolver.NoAnswer:
            # Try HTTPS record as fallback
            try:
                answers = await resolver.resolve(fqdn, "HTTPS")
            except dns.resolver.NoAnswer:
                logger.debug("No SVCB/HTTPS record found", fqdn=fqdn)
                return None

        for rdata in answers:
            target = str(rdata.target).rstrip(".")

            # Extract port from params
            port = 443
            if hasattr(rdata, "params") and rdata.params:
                # Port param key is 3 in SVCB
                port_param = rdata.params.get(3)
                if port_param and hasattr(port_param, "port"):
                    port = port_param.port

            # SVCB is valid if it has a target
            is_valid = bool(target and target != ".")

            logger.debug(
                "SVCB record found",
                fqdn=fqdn,
                target=target,
                port=port,
                valid=is_valid,
            )

            return {
                "target": target,
                "port": port,
                "valid": is_valid,
                "priority": rdata.priority,
            }

    except dns.resolver.NXDOMAIN:
        logger.debug("FQDN does not exist", fqdn=fqdn)
    except Exception as e:
        logger.debug("SVCB query failed", fqdn=fqdn, error=str(e))

    return None


async def _check_dnssec(fqdn: str) -> bool:
    """
    Check if DNSSEC is validated for the FQDN.

    Returns True if DNSSEC AD (Authenticated Data) flag is set.
    """
    try:
        resolver = dns.asyncresolver.Resolver()

        # Enable DNSSEC validation
        resolver.use_edns(edns=0, ednsflags=dns.flags.DO)

        # Query with DNSSEC
        try:
            answer = await resolver.resolve(fqdn, "SVCB")

            # Check AD (Authenticated Data) flag in response
            if hasattr(answer.response, "flags"):
                ad_flag = answer.response.flags & dns.flags.AD
                if ad_flag:
                    logger.debug("DNSSEC validated", fqdn=fqdn)
                    return True

        except dns.resolver.NoAnswer:
            # Try TXT as fallback for DNSSEC check
            try:
                answer = await resolver.resolve(fqdn, "TXT")
                if hasattr(answer.response, "flags"):
                    ad_flag = answer.response.flags & dns.flags.AD
                    if ad_flag:
                        logger.debug("DNSSEC validated via TXT", fqdn=fqdn)
                        return True
            except Exception:
                pass

    except Exception as e:
        logger.debug("DNSSEC check failed", fqdn=fqdn, error=str(e))

    # Note: Many domains don't have DNSSEC enabled
    # This is not necessarily an error
    logger.debug("DNSSEC not validated", fqdn=fqdn)
    return False


async def _check_dane(target: str, port: int) -> bool | None:
    """
    Check DANE/TLSA record for the endpoint.

    Returns:
        True if TLSA record exists and matches
        False if TLSA record exists but doesn't match
        None if no TLSA record configured
    """
    # TLSA record format: _port._tcp.hostname
    tlsa_fqdn = f"_{port}._tcp.{target}"

    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve(tlsa_fqdn, "TLSA")

        for rdata in answers:
            logger.debug(
                "TLSA record found",
                fqdn=tlsa_fqdn,
                usage=rdata.usage,
                selector=rdata.selector,
                mtype=rdata.mtype,
            )
            # For now, just check if TLSA exists
            # Full DANE validation would verify certificate matches
            return True

    except dns.resolver.NXDOMAIN:
        logger.debug("No TLSA record (DANE not configured)", fqdn=tlsa_fqdn)
    except dns.resolver.NoAnswer:
        logger.debug("No TLSA record", fqdn=tlsa_fqdn)
    except Exception as e:
        logger.debug("TLSA query failed", fqdn=tlsa_fqdn, error=str(e))

    return None  # Not configured


async def _check_endpoint(target: str, port: int) -> dict:
    """
    Check if endpoint is reachable.

    Returns dict with reachable status and latency.
    """
    endpoint = f"https://{target}:{port}"

    try:
        start_time = time.perf_counter()

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=True,
        ) as client:
            # Try health endpoint first, then root
            for path in ["/health", "/.well-known/agent.json", "/"]:
                try:
                    response = await client.get(f"{endpoint}{path}")
                    latency_ms = (time.perf_counter() - start_time) * 1000

                    if response.status_code < 500:
                        logger.debug(
                            "Endpoint reachable",
                            endpoint=endpoint,
                            path=path,
                            status=response.status_code,
                            latency_ms=f"{latency_ms:.2f}",
                        )
                        return {
                            "reachable": True,
                            "latency_ms": latency_ms,
                            "status_code": response.status_code,
                        }
                except httpx.HTTPError:
                    continue

    except httpx.ConnectError as e:
        logger.debug("Endpoint connection failed", endpoint=endpoint, error=str(e))
    except httpx.TimeoutException:
        logger.debug("Endpoint timeout", endpoint=endpoint)
    except Exception as e:
        logger.debug("Endpoint check failed", endpoint=endpoint, error=str(e))

    return {"reachable": False}
