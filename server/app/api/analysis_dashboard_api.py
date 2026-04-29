from __future__ import annotations

import sqlite3

from server.app.analysis.dashboard import build_analysis_dashboard_payload
from server.app.api.analysis_dashboard_contracts import AnalysisDashboardQuery
from server.app.api.authz_policy import authorize_request


def _enforce_authorization(role: str, endpoint: str, method: str) -> None:
    allowed, reason = authorize_request(role, endpoint, method)
    if not allowed:
        raise PermissionError(reason)


def get_analysis_dashboard(
    query: AnalysisDashboardQuery,
    role: str,
    connection: sqlite3.Connection,
) -> dict[str, object]:
    _enforce_authorization(role, "/api/analysis/dashboard", "GET")
    return build_analysis_dashboard_payload(
        connection=connection,
        start_at=query.startAt,
        end_at=query.endAt,
        bucket_grain=query.bucketGrain,
    )
