"""Shared builder for a miner's own harness diagnostics.

The HTTP route lives on the signed-in ``/me`` console. This module stays
separate from ``retrieval.py``: that one is documented as public, unauthed
reads, and this is the opposite.

The failure this exists for: a submission fails scoring and its owner learns
only the coarse class. Agent ``5fdadd33`` burned four validator leases in 82-108
seconds each, every one reporting a bare ``scoring_error``. The harness's own
output -- already bounded and redacted by the scorer -- named the cause the
entire time and reached nobody.

``validator_tickets`` is a mutable per-agent/version/validator row, not an
attempt ledger. Reissue restamps ``issued_at`` while retaining the prior
failure fields, so a tail must be labelled with the ``attempt_count`` that
produced it and marked stale when that no longer matches the current lease.

Miners refer to agents by the eight-character prefix the dashboard, Discord and
every incident note print (``5fdadd33``), so the loader accepts either a full
UUID or a unique prefix of at least :data:`AGENT_PREFIX_MIN_LENGTH` characters.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from ditto.api_models.miner_logs import (
    MinerHarnessLogAttempt,
    MinerHarnessLogsResponse,
)
from ditto.db.models import Agent, TicketStatus, ValidatorTicket

AGENT_PREFIX_MIN_LENGTH = 8
"""Shortest agent id prefix the loader resolves.

Eight hex characters is 32 bits: plenty to be unique within one miner's
agents, and exactly what the dashboard and ``ditto status`` already display.
"""


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def ticket_log_is_stale(ticket: ValidatorTicket) -> bool:
    """True when the stored tail or failure belongs to a superseded lease."""
    if (
        ticket.container_log_tail is not None
        and ticket.container_log_tail_attempt is not None
    ):
        return ticket.container_log_tail_attempt != ticket.attempt_count
    if ticket.failed_at is None:
        return False
    return _aware(ticket.failed_at) < _aware(ticket.issued_at)


def attempt_from_ticket(ticket: ValidatorTicket) -> MinerHarnessLogAttempt:
    return MinerHarnessLogAttempt(
        validator_hotkey=ticket.validator_hotkey,
        bench_version=ticket.bench_version,
        status=ticket.status.value
        if isinstance(ticket.status, TicketStatus)
        else str(ticket.status),
        attempt_count=ticket.attempt_count,
        issued_at=ticket.issued_at,
        deadline=ticket.deadline,
        failed_at=ticket.failed_at,
        failure_reason=ticket.failure_reason,
        failure_detail=ticket.failure_detail,
        container_log_tail=ticket.container_log_tail,
        log_tail_attempt=ticket.container_log_tail_attempt,
        stale=ticket_log_is_stale(ticket),
    )


async def resolve_owned_agent(
    session: AsyncSession,
    *,
    hotkey: str,
    agent_ref: str,
) -> Agent | None:
    """Resolve a full agent UUID or a unique short prefix owned by ``hotkey``.

    Returns ``None`` for an unknown id, another miner's id, a prefix shorter
    than :data:`AGENT_PREFIX_MIN_LENGTH`, and an ambiguous prefix alike.
    """
    ref = agent_ref.strip().lower()
    try:
        agent_id: UUID | None = UUID(ref)
    except ValueError:
        agent_id = None
    if agent_id is not None:
        return (
            await session.execute(
                select(Agent).where(
                    Agent.agent_id == agent_id,
                    Agent.miner_hotkey == hotkey,
                )
            )
        ).scalar_one_or_none()
    if len(ref) < AGENT_PREFIX_MIN_LENGTH:
        return None
    matches = (
        (
            await session.execute(
                select(Agent)
                .where(cast(Agent.agent_id, String).like(f"{ref}%"))
                .limit(2)
            )
        )
        .scalars()
        .all()
    )
    # A prefix that names two agents names neither.
    if len(matches) != 1:
        return None
    return matches[0]


async def load_owned_agent_logs(
    session: AsyncSession,
    *,
    hotkey: str,
    agent_ref: str,
    bench_version: int | None = None,
    since_hours: int | None = None,
    now: datetime | None = None,
) -> MinerHarnessLogsResponse | None:
    """Return diagnostics for ``agent_ref`` when ``hotkey`` owns it.

    A miss covers both "no such agent" and "someone else's agent" without
    distinguishing them. The signed-in session already identified the caller;
    this still must not confirm that another miner's agent id exists.

    ``bench_version`` narrows to one benchmark era; ``since_hours`` keeps only
    tickets issued within that window, which is what a miner iterating on one
    failure actually wants to read.
    """
    agent = await resolve_owned_agent(session, hotkey=hotkey, agent_ref=agent_ref)
    if agent is None:
        return None
    query = select(ValidatorTicket).where(ValidatorTicket.agent_id == agent.agent_id)
    if bench_version is not None:
        query = query.where(ValidatorTicket.bench_version == bench_version)
    if since_hours is not None:
        cutoff = (now or datetime.now(UTC)) - timedelta(minutes=since_hours)
        query = query.where(ValidatorTicket.issued_at >= cutoff)
    tickets = (
        (await session.execute(query.order_by(ValidatorTicket.issued_at.desc())))
        .scalars()
        .all()
    )
    return MinerHarnessLogsResponse(
        agent_id=agent.agent_id,
        miner_hotkey=agent.miner_hotkey,
        agent_status=str(agent.status),
        attempts=[attempt_from_ticket(ticket) for ticket in tickets],
    )
