"""
Telemetry repository — DB queries for the telemetry API.

Follows the same pattern as dns_aid.directory.repository.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from dns_aid.directory.models import InvocationSignalRecord
from dns_aid.sdk.signals.store import SignalStore

logger = structlog.get_logger(__name__)


class TelemetryRepository:
    """Repository for telemetry queries — extends SignalStore with analytics."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self._store = SignalStore(session)

    @property
    def store(self) -> SignalStore:
        return self._store

    async def get_signal(self, signal_id: str) -> InvocationSignalRecord | None:
        return await self._store.get(signal_id)

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
    ) -> tuple[list[InvocationSignalRecord], int]:
        """List signals with count for pagination."""
        signals = await self._store.list_signals(
            agent_fqdn=agent_fqdn,
            protocol=protocol,
            status=status,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
        )
        total = await self._store.count_signals(
            agent_fqdn=agent_fqdn,
            status=status,
        )
        return signals, total

    async def get_scorecard(self, agent_fqdn: str):  # noqa: ANN201
        """Get scorecard for a single agent."""
        return await self._store.scorecard(agent_fqdn)

    async def get_rankings(self, limit: int = 50) -> list[dict]:
        """Get agent rankings by composite score (computed from signals)."""
        # Get distinct agents with signals
        result = await self.session.execute(
            select(InvocationSignalRecord.agent_fqdn).distinct().limit(limit)
        )
        fqdns = list(result.scalars().all())

        rankings: list[dict] = []
        for fqdn in fqdns:
            sc = await self._store.scorecard(fqdn)
            rankings.append(
                {
                    "agent_fqdn": fqdn,
                    "composite_score": sc.composite_score,
                    "success_rate": sc.success_rate,
                    "avg_latency_ms": sc.avg_latency_ms,
                    "total_invocations": sc.total_invocations,
                    "total_cost_units": sc.total_cost_units,
                }
            )

        # Sort by composite score descending
        rankings.sort(key=lambda r: float(r["composite_score"]), reverse=True)
        return rankings

    async def get_global_stats(self) -> dict:
        """Get global telemetry statistics."""
        now = datetime.now(UTC)
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)

        total = await self._store.count_signals()
        error_count = await self._store.count_signals(status="error")
        timeout_count = await self._store.count_signals(status="timeout")

        # Distinct agents
        result = await self.session.execute(
            select(func.count(distinct(InvocationSignalRecord.agent_fqdn)))
        )
        total_agents = result.scalar_one()

        # Average latency
        result = await self.session.execute(
            select(func.avg(InvocationSignalRecord.invocation_latency_ms))
        )
        avg_latency = result.scalar_one() or 0.0

        # Total cost
        result = await self.session.execute(select(func.sum(InvocationSignalRecord.cost_units)))
        total_cost = result.scalar_one() or 0.0

        # Signals in last 24h
        result = await self.session.execute(
            select(func.count(InvocationSignalRecord.id)).where(
                InvocationSignalRecord.timestamp >= last_24h
            )
        )
        signals_24h = result.scalar_one()

        # Signals in last 7d
        result = await self.session.execute(
            select(func.count(InvocationSignalRecord.id)).where(
                InvocationSignalRecord.timestamp >= last_7d
            )
        )
        signals_7d = result.scalar_one()

        error_rate = ((error_count + timeout_count) / total * 100) if total > 0 else 0.0

        return {
            "total_invocations": total,
            "total_agents_invoked": total_agents,
            "avg_latency_ms": round(avg_latency, 2),
            "error_rate": round(error_rate, 2),
            "total_cost_units": round(total_cost, 4),
            "signals_last_24h": signals_24h,
            "signals_last_7d": signals_7d,
        }

    async def export_signals(
        self,
        *,
        agent_fqdn: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 10000,
    ) -> list[InvocationSignalRecord]:
        """Export signals for external consumption (JSON/CSV)."""
        return await self._store.list_signals(
            agent_fqdn=agent_fqdn,
            since=since,
            until=until,
            limit=limit,
        )
