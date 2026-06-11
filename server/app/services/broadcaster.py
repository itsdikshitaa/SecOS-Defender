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
                try:
                    await websocket.send_json(item)
                except Exception:
                    break

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(websocket)

    async def broadcast(self, event_type: str, payload: Any) -> None:

        message = {"event": event_type, "payload": payload}
        stale: list[WebSocket] = []
        async with self._lock:
            self._history.append(message)
            connections = list(self._connections)

        async def _send(ws: WebSocket) -> None:
            try:
                await ws.send_json(message)
            except Exception:
                stale.append(ws)

        if connections:
            await asyncio.gather(*[_send(ws) for ws in connections], return_exceptions=True)

        async with self._lock:
            for ws in stale:
                self._connections.discard(ws)


hub = BroadcastHub()
