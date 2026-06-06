"""
ShieldIQ Enterprise — Audit Trail API Routes
──────────────────────────────────────────────
GET /audit/history  — user/partner scan history
GET /audit/summary  — admin aggregate summary
GET /audit/patterns — pattern intelligence (admin)
GET /audit/report   — generate intelligence report (admin)

No message content in any response.
"""

import os
import logging
from fastapi import APIRouter, Request, HTTPException, Query

from enterprise.audit_store import get_user_history, get_admin_summary, get_user_activities, get_platform_metrics
from enterprise.pattern_store import get_pattern_stats
from enterprise.report_generator import generate_report

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/audit", tags=["Audit Trail"])

ADMIN_KEY = os.environ.get("ADMIN_SECRET_KEY", "shieldiq_admin_2026")


@router.get("/history", summary="Scan history (metadata only)")
async def get_history(
    request: Request,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    days: int = Query(default=30, ge=1, le=365)
):
    """Returns scan history — timestamps and verdicts only. No message content."""
    api_key_id = getattr(request.state, "api_key_id", None)
    result = get_user_history(api_key_id=api_key_id, limit=limit, offset=offset, days=days)
    return result


@router.get("/summary", summary="Admin — aggregate summary")
async def get_summary(
    days: int = Query(default=30, ge=1, le=365),
    admin_key: str = Query(default="")
):
    """Admin only. Returns aggregate statistics across all scans."""
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_admin_summary(days=days)


@router.get("/patterns", summary="Admin — pattern intelligence")
async def get_patterns(
    days: int = Query(default=30, ge=1, le=365),
    admin_key: str = Query(default="")
):
    """Admin only. Returns aggregate pattern statistics — the data moat view."""
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_pattern_stats(days=days)


@router.get("/report", summary="Admin — intelligence report")
async def get_report(
    days: int = Query(default=30, ge=1, le=365),
    admin_key: str = Query(default="")
):
    """Admin only. Generates an executive intelligence report for download."""
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    return generate_report(days=days)


@router.get("/activities", summary="Admin — recent user activities")
async def get_activities(
    limit: int = Query(default=50, ge=1, le=500),
    admin_key: str = Query(default="")
):
    """Admin only. Returns recent user activities (signup, login, logout, etc.)."""
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_user_activities(limit=limit)


@router.get("/metrics", summary="Admin — recent platform usage metrics")
async def get_metrics(
    limit: int = Query(default=50, ge=1, le=500),
    admin_key: str = Query(default="")
):
    """Admin only. Returns recent platform usage metrics (requests, latency, client ip)."""
    if not ADMIN_KEY or admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access required")
    return get_platform_metrics(limit=limit)
