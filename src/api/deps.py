from __future__ import annotations

import hmac

from fastapi import HTTPException, Request

from src.config import get_settings


async def require_api_key(http: Request) -> None:
    expected = get_settings().security.api_key
    if not expected:
        return
    provided = http.headers.get("x-api-key", "")
    if not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


async def enforce_rate_limit(http: Request) -> None:
    limiter = getattr(http.app.state, "rate_limiter", None)
    if limiter is None:
        return
    key = http.headers.get("x-api-key") or (
        http.client.host if http.client else "unknown"
    )
    if not limiter.allow(key):
        raise HTTPException(
            status_code=429,
            detail="rate limit exceeded",
            headers={"Retry-After": "1"},
        )
