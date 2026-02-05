"""
Database-backed signal store.

Persists InvocationSignal objects to the invocation_signals table
using the existing DatabaseManager infrastructure.
"""

from __future__ import annotations

from datetime import datetime

import structlog
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from dns_aid.directory.models import Agent, InvocationSignalRecord
from dns_aid.sdk.models import AgentScorecard, InvocationSignal, InvocationStatus
from dns_aid.sdk.signals.collector import _compute_scorecard

logger = structlog.get_logger(__name__)


class SignalStore:
    """
    Async database store for invocation signals.

    Uses the existing DatabaseManager session pattern for consistency
    with the rest of the directory infrastructure.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def save(self, signal: InvocationSignal) -> InvocationSignalRecord:
        """Persist a single signal to the database."""
        record = InvocationSignalRecord(
            id=str(signal.id),
            agent_fqdn=signal.agent_fqdn,
            agent_endpoint=signal.agent_endpoint,
            protocol=signal.protocol,
            method=signal.method,
            timestamp=signal.timestamp,
            discovery_latency_ms=signal.discovery_latency_ms,
            invocation_latency_ms=signal.invocation_latency_ms,
            total_latency_ms=signal.total_latency_ms,
            ttfb_ms=signal.ttfb_ms,
            status=signal.status.value,
            error_type=signal.error_type,
            error_message=signal.error_message,
            http_status_code=signal.http_status_code,
            cost_units=signal.cost_units,
            cost_currency=signal.cost_currency,
            response_size_bytes=signal.response_size_bytes,
            dnssec_validated=signal.dnssec_validated,
            tls_version=signal.tls_version,
            caller_id=signal.caller_id,
        )
        self.session.add(record)
        await self.session.flush()
        return record

    async def save_batch(self, signals: list[InvocationSignal]) -> int:
        """Persist multiple signals in a single flush. Returns count saved."""
        for signal in signals:
            record = InvocationSignalRecord(
                id=str(signal.id),
                agent_fqdn=signal.agent_fqdn,
                agent_endpoint=signal.agent_endpoint,
                protocol=signal.protocol,
                method=signal.method,
                timestamp=signal.timestamp,
                discovery_latency_ms=signal.discovery_latency_ms,
                invocation_latency_ms=signal.invocation_latency_ms,
                total_latency_ms=signal.total_latency_ms,
                ttfb_ms=signal.ttfb_ms,
                status=signal.status.value,
                error_type=signal.error_type,
                error_message=signal.error_message,
                http_status_code=signal.http_status_code,
                cost_units=signal.cost_units,
                cost_currency=signal.cost_currency,
                response_size_bytes=signal.response_size_bytes,
                dnssec_validated=signal.dnssec_validated,
                tls_version=signal.tls_version,
                caller_id=signal.caller_id,
            )
            self.session.add(record)
        await self.session.flush()
        return len(signals)

    async def get(self, signal_id: str) -> InvocationSignalRecord | None:
        """Retrieve a single signal by ID."""
        result = await self.session.execute(
            select(InvocationSignalRecord).where(InvocationSignalRecord.id == signal_id)
        )
        return result.scalar_one_or_none()

    async def list_signals(
        self,
        *,
        agent_fqdn: str | None = None,
        protocol: str | None = None,
        status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[InvocationSignalRecord]:
        """List signals with optional filters."""
        query = select(InvocationSignalRecord).order_by(InvocationSignalRecord.timestamp.desc())

        if agent_fqdn:
            query = query.where(InvocationSignalRecord.agent_fqdn == agent_fqdn)
        if protocol:
            query = query.where(InvocationSignalRecord.protocol == protocol)
        if status:
            query = query.where(InvocationSignalRecord.status == status)
        if since:
            query = query.where(InvocationSignalRecord.timestamp >= since)
        if until:
            query = query.where(InvocationSignalRecord.timestamp <= until)

        query = query.limit(limit).offset(offset)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def count_signals(
        self,
        *,
        agent_fqdn: str | None = None,
        status: str | None = None,
    ) -> int:
        """Count signals with optional filters."""
        query = select(func.count(InvocationSignalRecord.id))
        if agent_fqdn:
            query = query.where(InvocationSignalRecord.agent_fqdn == agent_fqdn)
        if status:
            query = query.where(InvocationSignalRecord.status == status)
        result = await self.session.execute(query)
        return result.scalar_one()

    async def scorecard(self, agent_fqdn: str) -> AgentScorecard:
        """Compute an aggregated scorecard for a single agent from the DB."""
        records = await self.list_signals(agent_fqdn=agent_fqdn, limit=10000)
        signals = [_record_to_signal(r) for r in records]
        return _compute_scorecard(agent_fqdn, signals)

    async def update_agent_scores(self, agent_fqdn: str) -> None:
        """
        Roll up signal data into the agents table scores.

        Updates popularity_score and trust_score based on invocation telemetry.
        """
        total = await self.count_signals(agent_fqdn=agent_fqdn)
        success_count = await self.count_signals(agent_fqdn=agent_fqdn, status="success")

        # Popularity: logarithmic scale of invocation count (0-100)
        import math

        popularity = min(100, int(math.log2(total + 1) * 10)) if total > 0 else 0

        # Trust: weighted success rate (0-100)
        success_rate = (success_count / total * 100) if total > 0 else 0
        trust = int(success_rate) if total >= 5 else 0  # Require minimum sample size

        await self.session.execute(
            update(Agent)
            .where(Agent.fqdn == agent_fqdn)
            .values(popularity_score=popularity, trust_score=trust)
        )
        await self.session.flush()

        logger.info(
            "Updated agent scores",
            agent_fqdn=agent_fqdn,
            total_signals=total,
            popularity_score=popularity,
            trust_score=trust,
        )


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware (UTC). SQLite returns naive datetimes."""
    if dt.tzinfo is None:
        from datetime import UTC

        return dt.replace(tzinfo=UTC)
    return dt


def _record_to_signal(record: InvocationSignalRecord) -> InvocationSignal:
    """Convert a DB record back to an InvocationSignal for scorecard computation."""
    import uuid as _uuid

    return InvocationSignal(
        id=_uuid.UUID(record.id),
        timestamp=_ensure_utc(record.timestamp),
        agent_fqdn=record.agent_fqdn,
        agent_endpoint=record.agent_endpoint,
        protocol=record.protocol,
        method=record.method,
        discovery_latency_ms=record.discovery_latency_ms or 0.0,
        invocation_latency_ms=record.invocation_latency_ms,
        total_latency_ms=record.total_latency_ms or 0.0,
        ttfb_ms=record.ttfb_ms,
        status=InvocationStatus(record.status),
        error_type=record.error_type,
        error_message=record.error_message,
        http_status_code=record.http_status_code,
        cost_units=record.cost_units,
        cost_currency=record.cost_currency,
        response_size_bytes=record.response_size_bytes,
        dnssec_validated=record.dnssec_validated or False,
        tls_version=record.tls_version,
        caller_id=record.caller_id,
    )
