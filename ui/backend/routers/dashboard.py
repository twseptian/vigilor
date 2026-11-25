"""routers/dashboard.py — Global dashboard stats and charts data."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select, distinct, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.dependencies import get_current_user
from backend.models.finding import Finding
from backend.models.scan import Scan
from backend.models.user import User

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


class DashboardStats(BaseModel):
    active_scans: int
    queued_scans: int
    total_scans: int
    open_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    informational_findings: int
    scans_this_week: int
    total_targets: int


class SeverityBreakdown(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    informational: int


@router.get("/stats", response_model=DashboardStats)
async def dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> DashboardStats:
    running = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == "running")
    )
    queued = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.status == "queued")
    )
    total = await db.execute(select(func.count()).select_from(Scan))
    open_f = await db.execute(
        select(func.count()).select_from(Finding).where(
            Finding.status.notin_(["Resolved", "Closed", "NA"])
        )
    )
    # Per-severity counts (all findings, regardless of status)
    sev_result = await db.execute(
        select(Finding.severity, func.count().label("cnt"))
        .group_by(Finding.severity)
    )
    sev_counts: dict[str, int] = {r.severity.lower(): r.cnt for r in sev_result}

    week_ago = datetime.utcnow() - timedelta(days=7)
    week_scans = await db.execute(
        select(func.count()).select_from(Scan).where(Scan.created_at >= week_ago)
    )
    targets = await db.execute(
        select(func.count(distinct(Scan.target_url))).select_from(Scan)
    )
    return DashboardStats(
        active_scans=running.scalar_one(),
        queued_scans=queued.scalar_one(),
        total_scans=total.scalar_one(),
        open_findings=open_f.scalar_one(),
        critical_findings=sev_counts.get("critical", 0),
        high_findings=sev_counts.get("high", 0),
        medium_findings=sev_counts.get("medium", 0),
        low_findings=sev_counts.get("low", 0),
        informational_findings=sev_counts.get("informational", 0),
        scans_this_week=week_scans.scalar_one(),
        total_targets=targets.scalar_one(),
    )


@router.get("/severity-breakdown", response_model=SeverityBreakdown)
async def severity_breakdown(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SeverityBreakdown:
    result = await db.execute(
        select(Finding.severity, func.count().label("cnt"))
        .where(Finding.status.notin_(["Closed", "NA"]))
        .group_by(Finding.severity)
    )
    counts: dict[str, int] = {row.severity.lower(): row.cnt for row in result}
    return SeverityBreakdown(
        critical=counts.get("critical", 0),
        high=counts.get("high", 0),
        medium=counts.get("medium", 0),
        low=counts.get("low", 0),
        informational=counts.get("informational", 0),
    )


@router.get("/most-vulnerable-targets", response_model=list[dict])
async def most_vulnerable_targets(
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Targets ordered by critical+high finding count (live from Finding table)."""
    from sqlalchemy import case as sa_case

    def _sev_sum(sev: str):
        return func.sum(sa_case((Finding.severity == sev, 1), else_=0))

    result = await db.execute(
        select(
            Scan.target_url,
            _sev_sum("Critical").label("critical"),
            _sev_sum("High").label("high"),
            _sev_sum("Medium").label("medium"),
            _sev_sum("Low").label("low"),
            _sev_sum("Informational").label("info"),
        )
        .join(Finding, Finding.scan_id == Scan.id)
        .group_by(Scan.target_url)
        .order_by(
            _sev_sum("Critical").desc(),
            _sev_sum("High").desc(),
        )
        .limit(limit)
    )
    out = []
    for row in result:
        total = (row.critical or 0) + (row.high or 0) + (row.medium or 0) + (row.low or 0) + (row.info or 0)
        if total > 0:
            out.append({
                "target_url": row.target_url,
                "critical": row.critical or 0,
                "high": row.high or 0,
                "medium": row.medium or 0,
                "low": row.low or 0,
                "info": row.info or 0,
            })
    return out


@router.get("/top-vulnerabilities", response_model=list[dict])
async def top_vulnerabilities(
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Most frequent vulnerability titles across all findings."""
    result = await db.execute(
        select(
            Finding.title,
            Finding.severity,
            func.count().label("cnt"),
        )
        .where(Finding.status.notin_(["Closed", "NA"]))
        .group_by(Finding.title, Finding.severity)
        .order_by(func.count().desc())
        .limit(limit)
    )
    return [{"title": r.title, "severity": r.severity, "count": r.cnt} for r in result]


def _last_12_months() -> list[str]:
    """Return list of 'YYYY-MM' strings for the past 12 months (oldest first)."""
    now = datetime.utcnow()
    months = []
    for i in range(11, -1, -1):
        d = now - timedelta(days=i * 30)
        months.append(d.strftime("%Y-%m"))
    return months


@router.get("/vuln-trend", response_model=list[dict])
async def vuln_trend(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Monthly count of open High and Medium findings for the past 12 months."""
    cutoff = datetime.utcnow() - timedelta(days=365)
    result = await db.execute(
        select(
            func.to_char(Finding.created_at, "YYYY-MM").label("month"),
            Finding.severity,
            func.count().label("cnt"),
        )
        .where(
            Finding.created_at >= cutoff,
            Finding.severity.in_(["Critical", "High", "Medium"]),
            Finding.status.notin_(["Closed", "NA"]),
        )
        .group_by(text("month"), Finding.severity)
        .order_by(text("month"))
    )
    # Build a complete month scaffold
    monthly: dict[str, dict] = {m: {"month": m, "high": 0, "medium": 0} for m in _last_12_months()}
    for row in result:
        if row.month in monthly:
            if row.severity in ("Critical", "High"):
                monthly[row.month]["high"] += row.cnt
            elif row.severity == "Medium":
                monthly[row.month]["medium"] = row.cnt
    return list(monthly.values())


@router.get("/vuln-per-target", response_model=list[dict])
async def vuln_per_target(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Monthly average High/Medium findings per distinct target."""
    cutoff = datetime.utcnow() - timedelta(days=365)

    # Findings per month per severity
    finding_rows = await db.execute(
        select(
            func.to_char(Finding.created_at, "YYYY-MM").label("month"),
            Finding.severity,
            func.count().label("cnt"),
        )
        .where(
            Finding.created_at >= cutoff,
            Finding.severity.in_(["Critical", "High", "Medium"]),
            Finding.status.notin_(["Closed", "NA"]),
        )
        .group_by(text("month"), Finding.severity)
    )

    # Distinct targets per month (via scans)
    target_rows = await db.execute(
        select(
            func.to_char(Scan.created_at, "YYYY-MM").label("month"),
            func.count(distinct(Scan.target_url)).label("targets"),
        )
        .where(Scan.created_at >= cutoff)
        .group_by(text("month"))
    )
    target_map: dict[str, int] = {r.month: r.targets for r in target_rows}

    monthly: dict[str, dict] = {m: {"month": m, "high": 0.0, "medium": 0.0} for m in _last_12_months()}
    raw: dict[str, dict] = {}
    for row in finding_rows:
        if row.month not in raw:
            raw[row.month] = {"high": 0, "medium": 0}
        if row.severity in ("Critical", "High"):
            raw[row.month]["high"] += row.cnt
        elif row.severity == "Medium":
            raw[row.month]["medium"] = row.cnt

    for month, counts in raw.items():
        if month in monthly:
            t = max(target_map.get(month, 1), 1)
            monthly[month]["high"] = round(counts["high"] / t, 2)
            monthly[month]["medium"] = round(counts["medium"] / t, 2)

    return list(monthly.values())


@router.get("/remediation-trend", response_model=list[dict])
async def remediation_trend(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Monthly count of remediated High/Medium findings and avg days (approximated)."""
    cutoff = datetime.utcnow() - timedelta(days=365)
    result = await db.execute(
        select(
            func.to_char(Finding.created_at, "YYYY-MM").label("month"),
            Finding.severity,
            func.count().label("cnt"),
        )
        .where(
            Finding.created_at >= cutoff,
            Finding.status == "Resolved",
            Finding.severity.in_(["Critical", "High", "Medium"]),
        )
        .group_by(text("month"), Finding.severity)
        .order_by(text("month"))
    )
    monthly: dict[str, dict] = {
        m: {"month": m, "avg_days": 0, "high_fixed": 0, "medium_fixed": 0}
        for m in _last_12_months()
    }
    for row in result:
        if row.month in monthly:
            if row.severity in ("Critical", "High"):
                monthly[row.month]["high_fixed"] += row.cnt
            elif row.severity == "Medium":
                monthly[row.month]["medium_fixed"] = row.cnt
    return list(monthly.values())


@router.get("/findings-status", response_model=list[dict])
async def findings_status_distribution(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Count of findings grouped by status."""
    result = await db.execute(
        select(Finding.status, func.count().label("cnt")).group_by(Finding.status)
    )
    counts: dict[str, int] = {r.status: r.cnt for r in result}
    order = ["Open", "Partially Resolved", "Risk Accepted", "Resolved", "Closed", "NA"]
    return [{"status": s, "count": counts.get(s, 0)} for s in order]


@router.get("/scan-status", response_model=list[dict])
async def scan_status_distribution(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Count of scans grouped by status."""
    result = await db.execute(
        select(Scan.status, func.count().label("cnt")).group_by(Scan.status)
    )
    counts: dict[str, int] = {r.status: r.cnt for r in result}
    order = ["queued", "running", "completed", "failed", "cancelled"]
    return [{"status": s, "count": counts.get(s, 0)} for s in order]


@router.get("/recent-scans", response_model=list[dict])
async def recent_scans(
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(limit)
    )
    out = []
    for s in result.scalars().all():
        out.append({
            "id": s.id,
            "target_url": s.target_url,
            "status": s.status,
            "phase": s.phase,
            "findings_critical": s.findings_critical,
            "findings_high": s.findings_high,
            "findings_medium": s.findings_medium,
            "findings_low": s.findings_low,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        })
    return out


# ---------------------------------------------------------------------------
# OWASP Top 10 distribution
# ---------------------------------------------------------------------------

_OWASP_CATEGORIES: list[tuple[str, str]] = [
    ("A01", "Broken Access Control"),
    ("A02", "Cryptographic Failures"),
    ("A03", "Injection"),
    ("A04", "Insecure Design"),
    ("A05", "Security Misconfiguration"),
    ("A06", "Vulnerable and Outdated Components"),
    ("A07", "Identification and Authentication Failures"),
    ("A08", "Software and Data Integrity Failures"),
    ("A09", "Security Logging and Monitoring Failures"),
    ("A10", "Server-Side Request Forgery"),
]


@router.get("/owasp-distribution", response_model=list[dict])
async def owasp_distribution(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Count of findings grouped by OWASP Top 10 category."""
    result = await db.execute(
        select(Finding.owasp_category, func.count().label("cnt"))
        .where(
            Finding.status.notin_(["Closed", "NA"]),
            Finding.owasp_category.isnot(None),
        )
        .group_by(Finding.owasp_category)
    )
    # Build a raw map: prefix (e.g. "A01") -> count
    raw: dict[str, int] = {}
    for row in result:
        if row.owasp_category:
            for code, _ in _OWASP_CATEGORIES:
                if code in row.owasp_category:
                    raw[code] = raw.get(code, 0) + row.cnt
                    break
    return [
        {"category": code, "name": name, "count": raw.get(code, 0)}
        for code, name in _OWASP_CATEGORIES
    ]


# ---------------------------------------------------------------------------
# CVSS score distribution
# ---------------------------------------------------------------------------

_CVSS_BUCKETS: list[tuple[str, float, float]] = [
    ("0–3.9 (Low)", 0.0, 3.9),
    ("4.0–6.9 (Medium)", 4.0, 6.9),
    ("7.0–8.9 (High)", 7.0, 8.9),
    ("9.0–10.0 (Critical)", 9.0, 10.0),
]


@router.get("/cvss-distribution", response_model=list[dict])
async def cvss_distribution(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Count of findings bucketed by CVSS score range."""
    result = await db.execute(
        select(Finding.cvss_score)
        .where(
            Finding.cvss_score.isnot(None),
            Finding.status.notin_(["Closed", "NA"]),
        )
    )
    scores = [row[0] for row in result if row[0] is not None]
    counts: dict[str, int] = {label: 0 for label, *_ in _CVSS_BUCKETS}
    for score in scores:
        for label, lo, hi in _CVSS_BUCKETS:
            if lo <= score <= hi:
                counts[label] += 1
                break
    return [{"range": label, "count": counts[label]} for label, *_ in _CVSS_BUCKETS]


# ---------------------------------------------------------------------------
# SLA compliance
# ---------------------------------------------------------------------------

_SLA_RULES: list[tuple[str, int]] = [
    ("Critical", 7),
    ("High", 30),
    ("Medium", 90),
    ("Low", 180),
]


@router.get("/sla-compliance", response_model=list[dict])
async def sla_compliance(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """SLA compliance per severity — within_sla vs overdue open findings."""
    result = await db.execute(
        select(Finding.severity, Finding.created_at)
        .where(Finding.status.notin_(["Resolved", "Closed", "NA"]))
    )
    rows = result.all()
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    # accumulate per severity
    buckets: dict[str, dict[str, int]] = {
        sev: {"within_sla": 0, "overdue": 0}
        for sev, _ in _SLA_RULES
    }
    sla_map: dict[str, int] = {sev: days for sev, days in _SLA_RULES}

    for row in rows:
        sev = row.severity
        if sev not in buckets:
            continue
        threshold = sla_map[sev]
        age_days = (now - row.created_at).days if row.created_at else 0
        if age_days <= threshold:
            buckets[sev]["within_sla"] += 1
        else:
            buckets[sev]["overdue"] += 1

    return [
        {
            "severity": sev,
            "within_sla": buckets[sev]["within_sla"],
            "overdue": buckets[sev]["overdue"],
            "threshold_days": days,
        }
        for sev, days in _SLA_RULES
    ]


# ---------------------------------------------------------------------------
# Vulnerability ageing
# ---------------------------------------------------------------------------

_AGE_BUCKETS: list[tuple[str, int, int]] = [
    ("0–20d",   0,   20),
    ("21–40d",  21,  40),
    ("41–60d",  41,  60),
    ("61–80d",  61,  80),
    ("81–100d", 81, 100),
    (">100d",  101, 9999),
]

@router.get("/vulnerability-ageing", response_model=list[dict])
async def vulnerability_ageing(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Open findings bucketed by age (days since created_at), split by severity."""
    result = await db.execute(
        select(Finding.severity, Finding.created_at)
        .where(Finding.status.notin_(["Resolved", "Closed", "NA"]))
    )
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    data: dict[str, dict] = {
        label: {"label": label, "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for label, *_ in _AGE_BUCKETS
    }
    for row in result.all():
        age = int((now - row.created_at).total_seconds() // 86400) if row.created_at else 0
        for label, lo, hi in _AGE_BUCKETS:
            if lo <= age <= hi:
                data[label][row.severity] = data[label].get(row.severity, 0) + 1
                break
    return list(data.values())


# ---------------------------------------------------------------------------
# Vulnerability recurrence
# ---------------------------------------------------------------------------

@router.get("/vuln-recurrence", response_model=list[dict])
async def vuln_recurrence(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Vulnerability titles that recur across 2+ distinct scans (top 10)."""
    result = await db.execute(
        select(
            Finding.title,
            Finding.severity,
            func.count(distinct(Finding.scan_id)).label("scan_count"),
            func.count().label("total_count"),
        )
        .where(Finding.status.notin_(["Closed", "NA"]))
        .group_by(Finding.title, Finding.severity)
        .having(func.count(distinct(Finding.scan_id)) >= 2)
        .order_by(func.count(distinct(Finding.scan_id)).desc())
        .limit(10)
    )
    return [
        {
            "title": row.title,
            "severity": row.severity,
            "scan_count": row.scan_count,
            "total_count": row.total_count,
        }
        for row in result
    ]


# ---------------------------------------------------------------------------
# Recent activity
# ---------------------------------------------------------------------------

def _age_label(created_at: datetime) -> str:
    """Return a human-readable relative time string for created_at."""
    delta = datetime.now(timezone.utc).replace(tzinfo=None) - created_at
    total_seconds = int(delta.total_seconds())
    if total_seconds < 60:
        return "just now"
    if total_seconds < 3600:
        minutes = total_seconds // 60
        return f"{minutes}m ago"
    if total_seconds < 86400:
        hours = total_seconds // 3600
        return f"{hours}h ago"
    days = total_seconds // 86400
    if days < 30:
        return f"{days}d ago"
    weeks = days // 7
    if days < 60:
        return f"{weeks}w ago"
    months = days // 30
    return f"{months}mo ago"


@router.get("/recent-activity", response_model=list[dict])
async def recent_activity(
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Last N scans with enriched metadata (hostname, findings summary, age label)."""
    from urllib.parse import urlparse

    result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(limit)
    )
    out = []
    for s in result.scalars().all():
        # Extract hostname from target_url
        try:
            parsed = urlparse(s.target_url or "")
            hostname = parsed.hostname or s.target_url or ""
        except Exception:
            hostname = s.target_url or ""

        critical = s.findings_critical or 0
        high = s.findings_high or 0
        medium = s.findings_medium or 0
        low = s.findings_low or 0
        total_findings = critical + high + medium + low

        age = _age_label(s.created_at) if s.created_at else "unknown"

        out.append({
            "id": s.id,
            "hostname": hostname,
            "target_url": s.target_url,
            "status": s.status,
            "total_findings": total_findings,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "age_label": age,
        })
    return out
