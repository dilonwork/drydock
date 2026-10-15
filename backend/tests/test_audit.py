"""Audit log tests: mutations are recorded, reads are not, admin-only access."""
import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="drydock-audit-test-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["CELERY_EAGER"] = "1"

import pytest
from fastapi.testclient import TestClient

from app import main
from app.db import init_db, session_scope
from app.main import app
from app.models import AuditLog, Session, User


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main, "keyscan", lambda address, port: "fake-host-key-line")
    init_db()
    _clear_db()
    with TestClient(app) as c:
        yield c
    _clear_db()


def _clear_db():
    with session_scope() as s:
        for m in (AuditLog, Session, User):
            s.query(m).delete()


def _setup(c, username="admin", password="adminpass123"):
    r = c.post("/api/auth/setup",
               json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def _login(c, username, password):
    r = c.post("/api/auth/login",
               json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _entries(action=None):
    with session_scope() as s:
        q = s.query(AuditLog)
        if action:
            q = q.filter_by(action=action)
        rows = q.order_by(AuditLog.ts).all()
        return [{"action": e.action, "username": e.username,
                 "user_id": e.user_id, "resource_type": e.resource_type,
                 "resource_id": e.resource_id, "detail": e.detail}
                for e in rows]


def test_setup_and_login_recorded(client):
    _setup(client)
    got = _entries()
    assert [e["action"] for e in got] == ["auth.setup"]
    assert got[0]["username"] == "admin"
    assert got[0]["resource_type"] == "user"

    _login(client, "admin", "adminpass123")
    got = _entries("auth.login")
    assert len(got) == 1 and got[0]["username"] == "admin"


def test_failed_login_recorded_without_user_id(client):
    _setup(client)
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": "wrongpass"})
    assert r.status_code == 401
    got = _entries("auth.login_failed")
    assert len(got) == 1
    assert got[0]["username"] == "admin"
    assert got[0]["user_id"] is None
    # unknown username is recorded too, without leaking existence
    r = client.post("/api/auth/login",
                    json={"username": "ghost", "password": "whatever123"})
    assert r.status_code == 401
    got = _entries("auth.login_failed")
    assert [e["username"] for e in got] == ["admin", "ghost"]


def test_logout_recorded(client):
    token = _setup(client)["token"]
    r = client.post("/api/auth/logout", headers=_auth(token))
    assert r.status_code == 200
    got = _entries("auth.logout")
    assert len(got) == 1 and got[0]["username"] == "admin"


def test_user_lifecycle_recorded(client):
    token = _setup(client)["token"]
    h = _auth(token)
    r = client.post("/api/users", headers=h,
                    json={"username": "op1", "password": "oppass123",
                          "role": "operator"})
    assert r.status_code == 200
    uid = r.json()["id"]

    client.patch(f"/api/users/{uid}", headers=h, json={"role": "viewer"})
    client.patch(f"/api/users/{uid}", headers=h,
                 json={"password": "newpass123"})
    client.delete(f"/api/users/{uid}", headers=h)

    actions = [e["action"] for e in _entries()]
    assert actions == ["auth.setup", "user.create", "user.role_change",
                       "user.password_reset", "user.delete"]
    # username is the actor (admin); the deleted account's name is in detail
    # (denormalized, survives deletion)
    deleted = _entries("user.delete")[0]
    assert deleted["username"] == "admin"
    assert "'op1'" in deleted["detail"]
    assert "viewer" in _entries("user.role_change")[0]["detail"]


def test_host_and_job_recorded(client):
    token = _setup(client)["token"]
    h = _auth(token)
    r = client.post("/api/hosts", headers=h,
                    json={"name": "h1", "address": "127.0.0.1", "port": 22,
                          "username": "root", "private_key": "FAKE"})
    hid = r.json()["id"]
    jid = client.post("/api/jobs", headers=h,
                      json={"host_ids": [hid]}).json()["job_id"]

    created = _entries("host.create")[0]
    assert created["resource_id"] == hid and "h1" in created["detail"]
    job = _entries("job.create")[0]
    assert job["resource_id"] == jid and job["username"] == "admin"


def test_reads_are_not_logged(client):
    token = _setup(client)["token"]
    h = _auth(token)
    client.get("/api/hosts", headers=h)
    client.get("/api/jobs", headers=h)
    client.get("/api/auth/me", headers=h)
    assert [e["action"] for e in _entries()] == ["auth.setup"]


def test_audit_endpoint_admin_only(client):
    token = _setup(client)["token"]
    admin_h = _auth(token)
    # create operator + viewer
    client.post("/api/users", headers=admin_h,
                json={"username": "op", "password": "oppass123",
                      "role": "operator"})
    client.post("/api/users", headers=admin_h,
                json={"username": "vw", "password": "vwpass123",
                      "role": "viewer"})
    op_h = _auth(_login(client, "op", "oppass123"))
    vw_h = _auth(_login(client, "vw", "vwpass123"))

    # no token -> 401
    assert client.get("/api/audit").status_code == 401
    # operator / viewer -> 403
    assert client.get("/api/audit", headers=op_h).status_code == 403
    assert client.get("/api/audit", headers=vw_h).status_code == 403
    # admin sees newest-first entries with total
    body = client.get("/api/audit", headers=admin_h).json()
    assert body["total"] >= 1
    actions = [e["action"] for e in body["entries"]]
    assert "auth.setup" in actions
    # action prefix filter
    body = client.get("/api/audit", headers=admin_h,
                      params={"action": "auth."}).json()
    assert body["entries"] and all(
        e["action"].startswith("auth.") for e in body["entries"])
    # limit respected
    body = client.get("/api/audit", headers=admin_h,
                      params={"limit": 1}).json()
    assert len(body["entries"]) == 1
