from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from scenario import engine
import copilot
import ml_service
import live_agent
from routes.phishing import router as phishing_router
from routes.url_analyzer import router as url_analyzer_router
from routes.pkg_sentinel import router as pkg_sentinel_router

app = FastAPI(title="RAKSHA API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(phishing_router)
app.include_router(url_analyzer_router)
app.include_router(pkg_sentinel_router)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/state")
def get_state():
    """Full live scenario state -- the dashboard polls this."""
    return engine.state()


@app.post("/api/reset")
def reset_scenario():
    engine.reset()
    return {"status": "reset"}


class ApprovalRequest(BaseModel):
    action_id: str
    approved: bool


@app.post("/api/soar/decision")
def soar_decision(req: ApprovalRequest):
    action = engine.approve_action(req.action_id, req.approved)
    if not action:
        raise HTTPException(status_code=404, detail="No pending action with that id")
    return {"status": "recorded", "action_id": req.action_id, "approved": req.approved}


class CopilotQuery(BaseModel):
    query: str


@app.post("/api/copilot/query")
def copilot_query(req: CopilotQuery):
    answer = copilot.answer_query(engine, req.query)
    return {"query": req.query, "answer": answer}


@app.get("/api/incident-report")
def incident_report():
    return copilot.generate_incident_report(engine)


@app.get("/api/ml/metrics")
def ml_metrics():
    """Real model performance on the real NSL-KDD test set -- see ml/train_anomaly_model.py."""
    return ml_service.get_metrics()


@app.get("/api/ml/sample-prediction")
def ml_sample_prediction():
    """Runs the trained model on a random real held-out record and returns the verdict."""
    return ml_service.get_random_prediction()


@app.post("/api/live/start")
def live_start():
    """Starts real, read-only monitoring of THIS machine's processes/connections/CPU."""
    live_agent.agent.start()
    return {"status": "started"}


@app.post("/api/live/stop")
def live_stop():
    live_agent.agent.stop()
    return {"status": "stopped"}


@app.get("/api/live/state")
def live_state():
    return live_agent.agent.state()