"""Core DNS-AID functionality: models, publisher, discoverer, validator."""

from dns_aid.core.a2a_card import (
    A2AAgentCard,
    A2AAuthentication,
    A2AProvider,
    A2ASkill,
    fetch_agent_card,
    fetch_agent_card_from_domain,
)
from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol, PublishResult

__all__ = [
    "A2AAgentCard",
    "A2AAuthentication",
    "A2AProvider",
    "A2ASkill",
    "AgentRecord",
    "DiscoveryResult",
    "Protocol",
    "PublishResult",
    "fetch_agent_card",
    "fetch_agent_card_from_domain",
]
