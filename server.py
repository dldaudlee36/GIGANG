"""
FastAPI Backend Server
Serves the modern HTML5/JS Web Dashboard and provides REST API endpoints for SecOps & AI automation.
"""
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
ROOT_DIR = Path(__file__).resolve().parent
sys.path.append(str(ROOT_DIR))

from src.engine.ai_agent import AISecOpsAgent
from src.collector.watcher import emit_mock_attack_logs

app = FastAPI(
    title="Security Correlation & Zero Trust SOAR API",
    description="API for multi-source log correlation, Zero Trust verification, and AI SOAR automation",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ai_agent = AISecOpsAgent()
DATA_FILE = ROOT_DIR / "data" / "mock_incidents.json"
remediation_state = {}

def load_incidents():
    if DATA_FILE.exists():
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

# Request Models
class CopilotRequest(BaseModel):
    incident_id: str
    question: str

class SoarExecuteRequest(BaseModel):
    incident_id: str
    action_index: int
    command: str

# API Endpoints
@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "Security Correlation Backend"}

@app.get("/api/incidents")
def get_incidents():
    incidents = load_incidents()
    # Merge remediation state
    for inc in incidents:
        inc_id = inc.get("incident_id")
        playbook = inc.get("ai_analysis", {}).get("recommended_playbook", [])
        for idx, item in enumerate(playbook):
            key = f"{inc_id}_{idx}"
            if key in remediation_state:
                item["status"] = remediation_state[key]
    return incidents

@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    incidents = load_incidents()
    for inc in incidents:
        if inc.get("incident_id") == incident_id:
            return inc
    raise HTTPException(status_code=404, detail="Incident not found")

@app.post("/api/soar/execute")
def execute_soar_action(req: SoarExecuteRequest):
    key = f"{req.incident_id}_{req.action_index}"
    remediation_state[key] = "EXECUTED"
    return {
        "status": "success",
        "incident_id": req.incident_id,
        "action_index": req.action_index,
        "command": req.command,
        "message": f"Successfully executed SOAR mitigation command: {req.command}"
    }

@app.post("/api/ai/copilot")
def copilot_query(req: CopilotRequest):
    incidents = load_incidents()
    target_inc = next((inc for inc in incidents if inc.get("incident_id") == req.incident_id), None)
    if not target_inc:
        raise HTTPException(status_code=404, detail="Incident context not found")
    
    answer = ai_agent.answer_copilot_query(target_inc, req.question)
    return {
        "incident_id": req.incident_id,
        "question": req.question,
        "answer": answer
    }

@app.post("/api/logs/simulate")
def trigger_attack_simulation():
    raw_logs_dir = ROOT_DIR / "data" / "raw_logs"
    emit_mock_attack_logs(str(raw_logs_dir))
    return {"status": "success", "message": "Mock attack log stream emitted successfully"}

# Mount Static Web Dashboard
WEB_DIR = ROOT_DIR / "web"
if not WEB_DIR.exists():
    WEB_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("[*] Security Correlation & Zero Trust Web Server starting...")
    print("[*] Dashboard URL: http://localhost:8000")
    print("[*] API Docs: http://localhost:8000/docs")
    print("="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
