from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.db import SessionLocal
from app.models import ResponseAction


def expire_actions() -> int:
    changed = 0
    with SessionLocal() as db:
        rows = db.scalars(
            select(ResponseAction).where(ResponseAction.state.in_(["approved", "pending_approval"]))
        ).all()
        now = datetime.now(timezone.utc)
        for row in rows:
            created_at = row.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            if created_at + timedelta(seconds=row.ttl_seconds) < now:
                row.state = "expired"
                changed += 1
        db.commit()
    return changed


def run() -> None:
    while True:
        expire_actions()
        time.sleep(10)


if __name__ == "__main__":
    run()
