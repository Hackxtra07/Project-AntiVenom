from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader
import json
import asyncio
from typing import List
from database.manager import DBManager
from config import BASE_DIR
from datetime import datetime

app = FastAPI(title="AntiVenom Alpha Dashboard")
db = DBManager()

@app.get("/api/hosts")
async def get_hosts():
    return db.get_hosts()

@app.post("/api/host/isolate")
async def toggle_isolation(request: Request, uuid_str: str, enabled: bool):
    db.set_isolation(uuid_str, enabled)
    
    # Trigger functional isolation in the engine
    if hasattr(request.app.state, 'system'):
        request.app.state.system.network_ids.isolate_host(enabled)
    
    # Broadcast the command for synchronization
    await broadcast_alert({
        "message": f"COMMAND: Host Isolation {'ACTIVATED' if enabled else 'DEACTIVATED'}",
        "severity": "CRITICAL" if enabled else "INFO",
        "timestamp": datetime.now().isoformat(),
        "is_command": True,
        "command": "ISOLATE",
        "target_uuid": uuid_str,
        "enabled": enabled
    })
    return {"status": "success", "uuid": uuid_str, "isolated": enabled}

# WebSocket connections
active_connections: List[WebSocket] = []

# Templates
templates = Environment(loader=FileSystemLoader(str(BASE_DIR / "ui" / "templates")))

from core.optimizer import SystemOptimizer

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    template = templates.get_template("index.html")
    # Get initial alerts
    alerts = db.get_alerts(limit=50)
    return template.render(alerts=alerts)

@app.post("/api/optimize")
async def trigger_optimization():
    res1 = SystemOptimizer.cleanup_temp_directories()
    res2 = SystemOptimizer.flush_dns()
    return {"cleanup": res1, "dns_flushed": res2}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            # Keep alive and receive any client messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)

async def broadcast_alert(alert: dict):
    for connection in active_connections:
        try:
            await connection.send_json(alert)
        except:
            pass
