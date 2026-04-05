"""websocket/router.py — WS /ws/scans/{scan_id}/progress endpoint."""
from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.websocket.manager import manager

router = APIRouter()


@router.websocket("/ws/scans/{scan_id}/progress")
async def scan_progress(scan_id: str, ws: WebSocket) -> None:
    """
    WebSocket endpoint — client subscribes to real-time scan events.

    Messages sent to client (JSON):
      {"type": "log",          "level": "INFO", "phase": "recon", "message": "..."}
      {"type": "phase_change", "phase": "exploit", "detail": "testing 3/8"}
      {"type": "finding_found","finding": {...}}
      {"type": "scan_complete","status": "completed", "summary": {...}}
      {"type": "scan_error",   "message": "..."}
      {"type": "ping"}
    """
    await manager.connect(scan_id, ws)
    try:
        while True:
            # Keep connection alive; client can send "ping"
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text('{"type":"ping"}')
    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(scan_id, ws)
