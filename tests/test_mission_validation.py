"""target_host must never reach a tool's argv as a bare CLI flag.

Direct regression test for the argument-injection finding against
tools/nmap_tool.py and tools/dalfox_tool.py (docs/HISTORY.md, section 27):
the Pydantic validator rejects it before a mission is even created, so
every tool downstream is covered by one check.
"""
import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from api.routes.missions import MissionCreateRequest
from main import app


def test_mission_create_request_rejects_target_host_starting_with_dash():
    with pytest.raises(ValidationError):
        MissionCreateRequest(
            mission_name="t", operator="op", target_host="-oN/app/pwned", authorization_ref="AUTH-1"
        )


def test_mission_create_request_accepts_ordinary_target_host():
    req = MissionCreateRequest(
        mission_name="t", operator="op", target_host="gta-it.com", authorization_ref="AUTH-1"
    )
    assert req.target_host == "gta-it.com"


@pytest.mark.asyncio
async def test_create_mission_endpoint_rejects_target_host_starting_with_dash():
    # End-to-end: the validator fires before the route handler body runs
    # (store write, background task), so this never touches either.
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.post(
                "/api/missions",
                json={
                    "mission_name": "t",
                    "operator": "op",
                    "target_host": "--script=http-slowloris-check",
                    "authorization_ref": "AUTH-1",
                },
            )
            assert r.status_code == 422
