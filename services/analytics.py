from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def validate_date_range(start_date: Optional[str], end_date: Optional[str]) -> Tuple[Optional[datetime], Optional[datetime], Optional[str]]:
    if not start_date and not end_date:
        return None, None, None
    start_dt = parse_date(start_date) if start_date else None
    end_dt = parse_date(end_date) if end_date else None
    if not start_dt and start_date:
        return None, None, "Invalid start date."
    if not end_dt and end_date:
        return None, None, "Invalid end date."
    if start_dt and end_dt and start_dt > end_dt:
        return None, None, "Start date cannot be after the end date."
    if end_dt and start_dt is None:
        start_dt = end_dt - timedelta(days=30)
    if start_dt and end_dt is None:
        end_dt = start_dt + timedelta(days=30)
    if start_dt and end_dt and (end_dt - start_dt).days < 0:
        return None, None, "Date range invalid."
    return start_dt, end_dt, None


def safe_percent_change(current: float, previous: float) -> Optional[float]:
    if previous in (None, 0):
        return None
    return round(((float(current) - float(previous)) / abs(float(previous))) * 100, 2)


def format_currency(value: Optional[float]) -> str:
    if value is None:
        return "$0.00"
    return f"${value:,.2f}"
