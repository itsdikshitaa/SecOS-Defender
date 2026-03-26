from __future__ import annotations

import asyncio
from collections import deque
from typing import Any

from fastapi import WebSocket

from app.config import get_settings


class BroadcastHub:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._history: deque[dict[str, Any]] = deque(maxlen=get_settings().websocket_backlog)
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)
            for item in self._history:
                await websocket.send_json(item)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(websocket)

    async def broadcast(self, event_type: str, payload: Any) -> None:
        message = {"event": event_type, "payload": payload}
        async with self._lock:
            self._history.append(message)
            stale: list[WebSocket] = []
            for websocket in self._connections:
                try:
                    await websocket.send_json(message)
                except Exception:
                    stale.append(websocket)
            for websocket in stale:
                self._connections.discard(websocket)


hub = BroadcastHub()
