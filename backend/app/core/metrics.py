from collections import defaultdict
from threading import Lock

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AccessFinding, ApprovalRequest, Incident, TelemetryAlert
from app.db.session import get_db
from app.governance.service import verify_audit_chain

router = APIRouter(tags=["metrics"])


class MetricsRegistry:
    """Lightweight in-memory Prometheus metrics collector."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._request_counts: dict[tuple[str, str, str], int] = defaultdict(int)
        self._latency_sum_ms: dict[tuple[str, str], float] = defaultdict(float)

    def record_http_request(
        self,
        *,
        method: str,
        path: str,
        status_code: int,
        duration_ms: float,
    ) -> None:
        """Record an HTTP request counter and cumulative latency."""
        status_class = f"{status_code // 100}xx"
        clean_path = path.split("?")[0]
        with self._lock:
            self._request_counts[(method.upper(), clean_path, status_class)] += 1
            self._latency_sum_ms[(method.upper(), clean_path)] += duration_ms

    def snapshot(self) -> tuple[dict[tuple[str, str, str], int], dict[tuple[str, str], float]]:
        """Return a consistent copy of HTTP counters and latency sums."""
        with self._lock:
            return dict(self._request_counts), dict(self._latency_sum_ms)


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_prometheus_text(
    registry: MetricsRegistry,
    *,
    pending_approvals: int,
    firing_alerts: int,
    open_incidents: int,
    open_access_findings: int,
    audit_chain_valid: bool,
) -> str:
    """Format collected metrics and operational DB gauges in Prometheus text format."""
    counts, latency_sums = registry.snapshot()
    lines: list[str] = [
        "# HELP ai_it_admin_http_requests_total Total HTTP requests handled by status class.",
        "# TYPE ai_it_admin_http_requests_total counter",
    ]
    for (method, path, status_class), val in sorted(counts.items()):
        lines.append(
            "ai_it_admin_http_requests_total{"
            f'method="{_escape_label(method)}",'
            f'path="{_escape_label(path)}",'
            f'status_class="{_escape_label(status_class)}"'
            f"}} {val}"
        )

    lines.extend(
        [
            "# HELP ai_it_admin_http_request_duration_ms_sum HTTP request duration sum in ms.",
            "# TYPE ai_it_admin_http_request_duration_ms_sum counter",
        ]
    )
    for (method, path), total_ms in sorted(latency_sums.items()):
        lines.append(
            "ai_it_admin_http_request_duration_ms_sum{"
            f'method="{_escape_label(method)}",'
            f'path="{_escape_label(path)}"'
            f"}} {total_ms:.3f}"
        )

    lines.extend(
        [
            "# HELP ai_it_admin_pending_approvals Pending human-in-the-loop approval requests.",
            "# TYPE ai_it_admin_pending_approvals gauge",
            f"ai_it_admin_pending_approvals {pending_approvals}",
            "# HELP ai_it_admin_firing_alerts Currently firing telemetry alerts.",
            "# TYPE ai_it_admin_firing_alerts gauge",
            f"ai_it_admin_firing_alerts {firing_alerts}",
            "# HELP ai_it_admin_open_incidents Open or non-resolved incidents.",
            "# TYPE ai_it_admin_open_incidents gauge",
            f"ai_it_admin_open_incidents {open_incidents}",
            "# HELP ai_it_admin_open_access_findings Open or pending access audit findings.",
            "# TYPE ai_it_admin_open_access_findings gauge",
            f"ai_it_admin_open_access_findings {open_access_findings}",
            "# HELP ai_it_admin_audit_chain_valid Audit hash chain integrity (1=valid, 0=invalid).",
            "# TYPE ai_it_admin_audit_chain_valid gauge",
            f"ai_it_admin_audit_chain_valid {1 if audit_chain_valid else 0}",
        ]
    )
    return "\n".join(lines) + "\n"


@router.get("/metrics")
async def get_prometheus_metrics(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Expose Prometheus exposition metrics and live IT operations gauges."""
    registry = getattr(request.app.state, "metrics", None)
    if not isinstance(registry, MetricsRegistry):
        registry = MetricsRegistry()

    pending_approvals = int(
        (
            await db.execute(
                select(func.count(ApprovalRequest.id)).where(ApprovalRequest.status == "pending")
            )
        ).scalar_one()
        or 0
    )
    firing_alerts = int(
        (
            await db.execute(
                select(func.count(TelemetryAlert.id)).where(TelemetryAlert.status == "firing")
            )
        ).scalar_one()
        or 0
    )
    open_incidents = int(
        (
            await db.execute(
                select(func.count(Incident.id)).where(Incident.status != "resolved")
            )
        ).scalar_one()
        or 0
    )
    open_findings = int(
        (
            await db.execute(
                select(func.count(AccessFinding.id)).where(
                    AccessFinding.status.in_(["open", "pending_approval"])
                )
            )
        ).scalar_one()
        or 0
    )
    chain_status = await verify_audit_chain(db)

    body = render_prometheus_text(
        registry,
        pending_approvals=pending_approvals,
        firing_alerts=firing_alerts,
        open_incidents=open_incidents,
        open_access_findings=open_findings,
        audit_chain_valid=chain_status.valid,
    )
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")
