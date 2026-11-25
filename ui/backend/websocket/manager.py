"""websocket/manager.py — ConnectionManager for per-scan WebSocket broadcasting."""
from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    """Manages active WebSocket connections grouped by scan_id."""

    def __init__(self) -> None:
        self._connections: dict[str, list[WebSocket]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def connect(self, scan_id: str, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections[scan_id].append(ws)

    async def disconnect(self, scan_id: str, ws: WebSocket) -> None:
        async with self._lock:
            conns = self._connections.get(scan_id, [])
            if ws in conns:
                conns.remove(ws)
            if not conns:
                self._connections.pop(scan_id, None)

    async def broadcast(self, scan_id: str, message: dict[str, Any]) -> None:
        """Send a JSON message to all listeners on this scan_id."""
        payload = json.dumps(message)
        async with self._lock:
            conns = list(self._connections.get(scan_id, []))
        dead: list[WebSocket] = []
        for ws in conns:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(scan_id, ws)

    async def send_log(self, scan_id: str, level: str, phase: str, message: str) -> None:
        await self.broadcast(scan_id, {
            "type": "log",
            "level": level,
            "phase": phase,
            "message": message,
        })

    async def send_phase_change(self, scan_id: str, phase: str, detail: str = "") -> None:
        await self.broadcast(scan_id, {
            "type": "phase_change",
            "phase": phase,
            "detail": detail,
        })

    async def send_finding(self, scan_id: str, finding: dict[str, Any]) -> None:
        await self.broadcast(scan_id, {"type": "finding_found", "finding": finding})

    async def send_progress(self, scan_id: str, stats: dict[str, Any]) -> None:
        await self.broadcast(scan_id, {"type": "progress", "stats": stats})

    async def send_complete(self, scan_id: str, status: str, summary: dict[str, Any]) -> None:
        await self.broadcast(scan_id, {"type": "scan_complete", "status": status, "summary": summary})

    async def send_error(self, scan_id: str, message: str) -> None:
        await self.broadcast(scan_id, {"type": "scan_error", "message": message})


# Singleton used across the app
manager = ConnectionManager()
