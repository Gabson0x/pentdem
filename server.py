from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import uuid
import json
import asyncio
from typing import Dict, Any
from pipeline import pipeline

app = FastAPI(title="AI Pentesting Daemon v2.0")

tasks: Dict[str, Dict[str, Any]] = {}
websockets: Dict[str, list] = {}


class PentestRequest(BaseModel):
    target: str
    mode: str = "full"
    platform: str = "hackerone"
    engine: str = "agent"  # agent, pipeline, or hybrid
    options: dict = {}


class PentestResponse(BaseModel):
    task_id: str
    status: str


class TaskStatus(BaseModel):
    task_id: str
    status: str
    progress: float = 0.0
    results: dict = None


@app.post("/scan", response_model=PentestResponse)
async def start_scan(request: PentestRequest):
    task_id = str(uuid.uuid4())
    tasks[task_id] = {
        "status": "queued",
        "progress": 0.0,
        "target": request.target,
        "mode": request.mode,
        "platform": request.platform,
        "stages": {},
        "results": None,
    }
    asyncio.create_task(_run_pipeline(task_id, request))
    return PentestResponse(task_id=task_id, status="queued")


async def _run_pipeline(task_id: str, request: PentestRequest):
    try:
        tasks[task_id]["status"] = "running"

        def progress_callback(event):
            tasks[task_id]["progress"] = event["progress"]
            tasks[task_id]["stages"][event["stage"]] = event["status"]
            _broadcast(task_id, event)
            if event.get("data"):
                tasks[task_id].setdefault("stage_data", {})[event["stage"]] = event["data"]

        pipeline.on_progress(progress_callback)

        results = await pipeline.run(
            target=request.target,
            mode=request.mode,
            platform=request.platform,
            engine=request.engine,
        )

        tasks[task_id]["status"] = "completed"
        tasks[task_id]["progress"] = 1.0
        tasks[task_id]["results"] = results

        _broadcast(task_id, {"stage": "complete", "status": "completed", "progress": 1.0})

    except Exception as e:
        tasks[task_id]["status"] = "failed"
        tasks[task_id]["results"] = {"error": str(e)}
        _broadcast(task_id, {"stage": "error", "status": "failed", "progress": -1, "error": str(e)})


@app.websocket("/ws/{task_id}")
async def websocket_endpoint(websocket: WebSocket, task_id: str):
    await websocket.accept()
    if task_id not in websockets:
        websockets[task_id] = []
    websockets[task_id].append(websocket)

    try:
        # Send current state immediately
        if task_id in tasks:
            await websocket.send_json({
                "stage": "init",
                "status": tasks[task_id].get("status", "unknown"),
                "progress": tasks[task_id].get("progress", 0.0),
            })

        # Keep connection alive
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({"type": "ping"})
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    finally:
        if task_id in websockets:
            websockets[task_id] = [ws for ws in websockets[task_id] if ws != websocket]
            if not websockets[task_id]:
                del websockets[task_id]


def _broadcast(task_id: str, event: dict):
    if task_id not in websockets:
        return
    dead = []
    for ws in websockets[task_id]:
        try:
            asyncio.create_task(ws.send_json(event))
        except Exception:
            dead.append(ws)
    if dead:
        websockets[task_id] = [ws for ws in websockets[task_id] if ws not in dead]


@app.get("/status/{task_id}")
async def get_status(task_id: str):
    if task_id not in tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    return tasks[task_id]


@app.get("/results/{task_id}")
async def get_results(task_id: str):
    if task_id not in tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    t = tasks[task_id]
    if t["status"] != "completed":
        return {"task_id": task_id, "status": t["status"], "results": None}
    return {"task_id": task_id, "status": "completed", "results": t.get("results")}


@app.get("/health")
async def health():
    return {"status": "healthy", "tasks": len(tasks), "active_connections": sum(len(ws) for ws in websockets.values())}


@app.get("/models")
async def list_models():
    from models import model_client
    return {"models": model_client.get_available_models()}
