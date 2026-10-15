"""Audit log: who did what, when.

Every state-changing API call records one row: the acting user (username is
denormalized so entries survive account deletion), the action, the affected
resource, and a short human-readable detail. Reads are never logged.

Recording is best-effort: an audit write failure is logged as a warning and
never breaks the API call it describes.
"""
import logging
import time
import uuid

from .db import session_scope
from .models import AuditLog

log = logging.getLogger("drydock.audit")


def record(user, action, resource_type=None, resource_id=None, detail=None,
           username=None, session=None):
    """Append one audit row. ``user`` may be None (e.g. failed login).

    Pass the endpoint's open ``session`` when called inside its transaction
    so the audit row commits atomically with the change (and so SQLite's
    single-writer lock is not contended). Without a session, a short-lived
    one is opened and failures are logged as warnings instead of raised.
    """
    entry = AuditLog(
        id=uuid.uuid4().hex[:16],
        ts=time.time(),
        user_id=user.id if user is not None else None,
        username=username or (user.username if user is not None else "?"),
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=detail,
    )
    if session is not None:
        session.add(entry)
        return
    try:
        with session_scope() as s:
            s.add(entry)
    except Exception as e:
        log.warning("audit record failed for %s: %s", action, e)


def public_entry(e: AuditLog) -> dict:
    return {"id": e.id, "ts": e.ts, "username": e.username,
            "action": e.action, "resource_type": e.resource_type,
            "resource_id": e.resource_id, "detail": e.detail}
