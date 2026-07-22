"""Black-box HTTP integration tests for the Python admin API. Drives the
real server purely over HTTP; see conftest.py for server bootstrap +
cleanup."""
from __future__ import annotations

import base64
import json

import httpx

from conftest import insert_verified_admin, unique_email


def test_health(client: httpx.Client):
    resp = client.get("/api/health")
    assert resp.status_code == 200


def test_not_found(client: httpx.Client):
    resp = client.get("/api/does-not-exist")
    assert resp.status_code == 404
    assert resp.json()["status"] == 0


def test_admin_login_validation(client: httpx.Client):
    resp = client.post("/api/admin/auth/login", json={})
    assert resp.status_code == 422
    body = resp.json()
    assert body["status"] == 0
    errors = body["data"]["errors"]
    assert isinstance(errors, dict) and len(errors) > 0


def test_admin_login_wrong_password(client: httpx.Client):
    email = unique_email("adminwrongpw")
    insert_verified_admin("CorrectHorseBattery1!", email)
    resp = client.post("/api/admin/auth/login", json={"email": email, "password": "WrongPassword1!"})
    assert resp.status_code != 200
    assert resp.json()["status"] == 0


def test_authenticated_admin_flow(client: httpx.Client):
    password = "CorrectHorseBattery1!"
    email = unique_email("adminverified")
    insert_verified_admin(password, email)

    # Login
    resp = client.post("/api/admin/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    parsed = resp.json()
    assert parsed["status"] == 1
    assert any(c == "next_session_token" for c in resp.cookies)

    # Users list with base64 `filter` query param per the pagination contract
    # (multiSelect column -> array of string values, same shape express_admin's
    # buildFilter.ts expects). Unfiltered baseline first, then a filter on an
    # email substring that only matches this test's own admin account, to
    # assert the filter actually narrows the result set (not just accepted).
    resp = client.get("/api/admin/users", params={"page": 1, "limit": 100})
    assert resp.status_code == 200, resp.text
    baseline_total = resp.json()["data"]["pagination"]["total"]
    assert baseline_total >= 1

    filter_b64 = base64.b64encode(json.dumps({"email": [email]}).encode()).decode()
    resp = client.get("/api/admin/users", params={"filter": filter_b64, "page": 1, "limit": 10})
    assert resp.status_code == 200, resp.text
    parsed = resp.json()
    assert parsed["status"] == 1
    assert "list" in parsed["data"]
    assert "pagination" in parsed["data"]
    pagination = parsed["data"]["pagination"]
    assert set(pagination.keys()) >= {"page", "limit", "total", "pages", "count"}
    # NOTE: the admin account itself has role ADMIN, not USER, so filtering
    # the users (role=USER) list by its email must return zero rows -- this
    # proves the filter is actually applied to the query, not ignored.
    assert pagination["total"] == 0
    assert parsed["data"]["list"] == []
    assert pagination["total"] < baseline_total

    # Logout
    resp = client.post("/api/auth/logout")
    assert resp.status_code == 200
    assert resp.json()["status"] == 1

    # Session must now be rejected
    resp = client.get("/api/auth/session")
    assert resp.status_code == 401


def test_admin_login_rate_limit(client: httpx.Client):
    email = unique_email("adminratelimit")
    last_resp = None
    for _ in range(11):
        last_resp = client.post("/api/admin/auth/login", json={"email": email, "password": "WhateverWrong1!"})
    assert last_resp.status_code == 429
    assert last_resp.headers.get("Retry-After")
