from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from src.api import deps


def _request(headers: dict[str, str]):
    return SimpleNamespace(headers=headers)


def _settings(api_key: str):
    return SimpleNamespace(security=SimpleNamespace(api_key=api_key))


async def test_auth_disabled_when_no_key(monkeypatch):
    monkeypatch.setattr(deps, "get_settings", lambda: _settings(""))
    await deps.require_api_key(_request({}))


async def test_auth_rejects_missing_or_wrong_key(monkeypatch):
    monkeypatch.setattr(deps, "get_settings", lambda: _settings("secret"))
    with pytest.raises(HTTPException) as exc:
        await deps.require_api_key(_request({}))
    assert exc.value.status_code == 401

    with pytest.raises(HTTPException):
        await deps.require_api_key(_request({"x-api-key": "wrong"}))


async def test_auth_accepts_correct_key(monkeypatch):
    monkeypatch.setattr(deps, "get_settings", lambda: _settings("secret"))
    await deps.require_api_key(_request({"x-api-key": "secret"}))
