"""HTTP and WebSocket surface.

REST for anything a script or another tool would want; a WebSocket for the
dashboard, which needs a push stream rather than a polling loop.
"""

from __future__ import annotations

import asyncio
import queue
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm

from .config import Config
from .engine import Engine
from .auth import get_current_user, get_current_user_ws, verify_password, create_access_token, FAKE_USERS_DB

WEB_DIR = Path(__file__).resolve().parent.parent / "web"


def create_app(cfg: Config | None = None) -> FastAPI:
    cfg = cfg or Config.load()
    engine = Engine(cfg)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        engine.start()
        yield
        engine.stop()

    app = FastAPI(title="OSentinel AI", version="1.0.0", lifespan=lifespan,
                  description="Host intrusion detection and autonomous response.")
    app.state.engine = engine

    # ------------------------------------------------------------ dashboard

    @app.get("/", include_in_schema=False)
    def dashboard():
        index = WEB_DIR / "index.html"
        if not index.exists():
            return JSONResponse({"error": "dashboard not found", "expected": str(index)}, 500)
        return FileResponse(index)

    # ----------------------------------------------------------------- rest
    
    @app.post("/api/token")
    def login(form_data: OAuth2PasswordRequestForm = Depends()):
        user = FAKE_USERS_DB.get(form_data.username)
        if not user or not verify_password(form_data.password, user["hashed_password"]):
            raise HTTPException(status_code=400, detail="Incorrect username or password")
        access_token = create_access_token(data={"sub": user["username"]})
        return {"access_token": access_token, "token_type": "bearer"}

    @app.get("/api/snapshot")
    def snapshot(current_user: dict = Depends(get_current_user)):
        return engine.snapshot()

    @app.get("/api/posture")
    def posture(current_user: dict = Depends(get_current_user)):
        return engine.posture()

    @app.get("/api/status")
    def status(current_user: dict = Depends(get_current_user)):
        return engine.status()

    @app.get("/api/events")
    def events(limit: int = 200, category: str | None = None, current_user: dict = Depends(get_current_user)):
        return engine.store.recent_events(min(limit, 1000), category)

    @app.get("/api/detections")
    def detections(limit: int = 200, current_user: dict = Depends(get_current_user)):
        return engine.store.recent_detections(min(limit, 1000))

    @app.get("/api/incidents")
    def incidents(current_user: dict = Depends(get_current_user)):
        return [i.to_dict() for i in engine.correlator.open_incidents()]

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: str, current_user: dict = Depends(get_current_user)):
        for inc in engine.correlator.open_incidents():
            if inc.id == incident_id:
                return inc.to_dict()
        raise HTTPException(404, "incident not found")

    @app.post("/api/incidents/{incident_id}/triage")
    def triage(incident_id: str, current_user: dict = Depends(get_current_user)):
        for inc in engine.correlator.open_incidents():
            if inc.id == incident_id:
                inc.narrative = engine.triage.summarise(inc)
                engine.store.upsert_incident(inc)
                return inc.to_dict()
        raise HTTPException(404, "incident not found")

    @app.post("/api/incidents/{incident_id}/close")
    def close(incident_id: str, current_user: dict = Depends(get_current_user)):
        for inc in engine.correlator.open_incidents():
            if inc.id == incident_id:
                # Record this before mutating: closing an incident nobody acted
                # on is the operator telling us the rule was not worth the
                # interrupt, and that is the only honest false-positive signal
                # this system gets.
                engine.assistant.note_incident_closed(inc)
                inc.state = "closed"
                inc.score = 0.0
                engine.store.upsert_incident(inc)
                return inc.to_dict()
        raise HTTPException(404, "incident not found")

    @app.post("/api/respond/{action}/{target}")
    def respond(action: str, target: str, current_user: dict = Depends(get_current_user)):
        """Operator-initiated containment. Honours the same guards as autonomy."""
        r = engine.responder
        if action == "suspend" and target.isdigit():
            result = r.suspend(int(target))
        elif action == "terminate" and target.isdigit():
            result = r.terminate(int(target))
        elif action == "quarantine":
            result = r.quarantine(target)
        else:
            raise HTTPException(400, "unsupported action or target")
        return result.to_dict()

    @app.get("/api/processes")
    def processes(current_user: dict = Depends(get_current_user)):
        return engine.procs.tree()

    @app.get("/api/rules")
    def rules(current_user: dict = Depends(get_current_user)):
        return {"loaded": engine.rules.describe(), "errors": engine.rules.errors}

    @app.get("/api/metrics/{name}")
    def metric(name: str, minutes: int = 30, current_user: dict = Depends(get_current_user)):
        import time
        return engine.store.metric_series(name, time.time() - minutes * 60)

    # ------------------------------------------------------------ assistant

    @app.post("/api/assistant/chat")
    def assistant_chat(payload: dict = Body(...), current_user: dict = Depends(get_current_user)):
        question = str(payload.get("message", "")).strip()
        if not question:
            raise HTTPException(400, "message is required")
        if len(question) > 4000:
            raise HTTPException(400, "message too long")
        session = str(payload.get("session") or "console")[:64]
        result = engine.assistant.ask(session, question)
        if "error" in result:
            raise HTTPException(400, result["error"])
        return result

    @app.post("/api/assistant/feedback")
    def assistant_feedback(payload: dict = Body(...), current_user: dict = Depends(get_current_user)):
        return engine.assistant.feedback(
            helpful=bool(payload.get("helpful")),
            rule_ids=payload.get("rule_ids") or None)

    @app.post("/api/assistant/reset")
    def assistant_reset(payload: dict = Body(default={}), current_user: dict = Depends(get_current_user)):
        engine.assistant.reset(str(payload.get("session") or "console")[:64])
        return {"ok": True}

    @app.get("/api/assistant/status")
    def assistant_status(current_user: dict = Depends(get_current_user)):
        return engine.assistant.status()

    @app.get("/api/assistant/suggestions")
    def assistant_suggestions(current_user: dict = Depends(get_current_user)):
        return {"suggestions": engine.assistant.suggestions()}

    @app.post("/api/classifier/train")
    def classifier_train(payload: dict = Body(default={}), current_user: dict = Depends(get_current_user)):
        use_llm = bool(payload.get("use_llm", True))
        try:
            return engine.train_classifier(use_llm=use_llm)
        except Exception as exc:
            raise HTTPException(500, f"training failed: {type(exc).__name__}: {exc}")

    @app.get("/api/classifier/status")
    def classifier_status(current_user: dict = Depends(get_current_user)):
        return engine.classifier.status()

    @app.post("/api/classifier/predict")
    def classifier_predict(payload: dict = Body(...), current_user: dict = Depends(get_current_user)):
        cmd = str(payload.get("command", "")).strip()
        if not cmd:
            raise HTTPException(400, "command is required")
        pred = engine.classifier.predict(cmd)
        if pred is None:
            raise HTTPException(503, "classifier not trained yet")
        return pred

    @app.get("/api/playbooks")
    def playbook_index(technique: str | None = None, current_user: dict = Depends(get_current_user)):
        from .playbooks import PLAYBOOKS, GENERAL
        if technique:
            pb = PLAYBOOKS.get(technique.upper())
            if not pb:
                raise HTTPException(404, "no playbook for that technique")
            return pb.to_dict()
        return {"playbooks": [pb.to_dict() for pb in PLAYBOOKS.values()],
                "general": GENERAL}

    @app.get("/api/health")
    def health(current_user: dict = Depends(get_current_user)):
        return {"ok": True, "queue_depth": engine.queue.qsize(),
                "dropped": engine.dropped, "processed": engine.processed}

    # ------------------------------------------------------------ websocket

    @app.websocket("/ws")
    async def stream(ws: WebSocket):
        await ws.accept()
        
        # Expect the first message to be authentication
        try:
            auth_msg = await ws.receive_json()
            if auth_msg.get("type") != "auth":
                await ws.close(code=1008, reason="Authentication expected")
                return
            
            token = auth_msg.get("token")
            user = await get_current_user_ws(token)
            if not user:
                await ws.close(code=1008, reason="Invalid token")
                return
        except Exception:
            await ws.close(code=1008, reason="Authentication failed")
            return
            
        sub = engine.subscribe()
        loop = asyncio.get_running_loop()
        try:
            await ws.send_json({"type": "snapshot", "data": engine.snapshot()})
            while True:
                try:
                    msg = await loop.run_in_executor(None, sub.get, True, 20.0)
                except queue.Empty:
                    await ws.send_json({"type": "heartbeat"})
                    continue
                await ws.send_json(msg)
        except (WebSocketDisconnect, RuntimeError, ConnectionError):
            pass
        finally:
            engine.unsubscribe(sub)

    return app
