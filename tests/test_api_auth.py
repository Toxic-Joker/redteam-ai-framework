"""API_KEY is empty by default (doesn't break an existing deployment), but

as soon as it's set, every /api/* route must require it - directly tied to
the security audit of the framework itself (docs/HISTORY.md, section 20).
"""
import pytest
from httpx import ASGITransport, AsyncClient

from core.config import get_settings
from main import app


@pytest.mark.asyncio
async def test_api_open_when_api_key_unset(monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "")
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.get("/api/missions")
            assert r.status_code == 200


@pytest.mark.asyncio
async def test_api_rejects_missing_or_wrong_key_when_set(monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "s3cr3t")
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.get("/api/missions")
            assert r.status_code == 401

            r = await client.get("/api/missions", headers={"X-API-Key": "wrong"})
            assert r.status_code == 401


@pytest.mark.asyncio
async def test_api_accepts_correct_header_key(monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "s3cr3t")
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.get("/api/missions", headers={"X-API-Key": "s3cr3t"})
            assert r.status_code == 200


@pytest.mark.asyncio
async def test_api_accepts_correct_query_param_key(monkeypatch):
    # Fallback for the direct <a href> download link (see
    # api/dependencies.py): a plain navigation can't set a custom
    # header.
    monkeypatch.setattr(get_settings(), "api_key", "s3cr3t")
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.get("/api/missions?api_key=s3cr3t")
            assert r.status_code == 200


@pytest.mark.asyncio
async def test_health_and_dashboard_never_require_api_key(monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "s3cr3t")
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            assert (await client.get("/health")).status_code == 200
            assert (await client.get("/")).status_code == 200
