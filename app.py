from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Security, APIRouter
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import os
import io
import json
import pandas as pd
import random
import uuid
import time
from datetime import datetime
from typing import List, Dict, Any

# Reuse existing inference utilities
from inference import load_artifacts, predict, predict_csv, predict_zeek_log

# LangGraph and Agent imports
from graph.builder import GraphBuilder
from graph.runtime import GraphRuntime
from cyber_surakshya.platform.state import create_initial_state, PlatformStateModel
from cyber_surakshya.platform.schemas.security_event import SecurityEvent, NetworkEndpoint
from cyber_surakshya.platform.enums.event_source import EventSource
from cyber_surakshya.platform.enums.event_type import EventType
from cyber_surakshya.platform.enums.severity import Severity
from cyber_surakshya.platform.risk.score import RiskScore
from cyber_surakshya.platform.identifiers.correlation import CorrelationContext, generate_event_id, generate_correlation_id, generate_trace_id
from cyber_surakshya.platform.audit.metadata import AuditMetadata
from cyber_surakshya.platform.schemas.alert import Alert, AlertStatus
from cyber_surakshya.platform.enums.detection_status import DetectionStatus
from cyber_surakshya.platform.schemas.detection_result import DetectionResult
from cyber_surakshya.platform.risk.score import severity_from_risk_score

from adapters.detection.ids_adapter import IDSDetectionAdapter
from agents.detection.detection_agent import DetectionAgent
from ai_engine.deterministic import DeterministicRuleEngine
from agents.analysis.analysis_agent import AnalysisAgent

class HybridDetectionAdapter(IDSDetectionAdapter):
    def detect(self, flow_data: dict):
        if "_SIMULATED_ATTACK_NAME" in flow_data:
            attack_name = flow_data.pop("_SIMULATED_ATTACK_NAME")
            
            if "DDoS" in attack_name: pred = "DDOS"
            elif "BruteForce" in attack_name: pred = "BRUTEFORCE"
            elif "PortScan" in attack_name: pred = "PORTSCAN"
            else: pred = attack_name.upper()
            
            conf = 0.98
            status = DetectionStatus.DETECTED
            risk_score = self._risk_score_for(status, conf)
            
            return DetectionResult(
                event_id=generate_event_id(),
                correlation_id=generate_correlation_id(),
                trace_id=generate_trace_id(),
                status=status,
                severity=severity_from_risk_score(risk_score.value),
                risk_score=risk_score,
                model_name="SimulatedIDS",
                model_version="1.0",
                predicted_label=pred,
                confidence=conf,
                probabilities={pred: conf, "BENIGN": 1-conf},
                is_anomaly=True,
                benign_label="BENIGN",
                feature_snapshot=self._numeric_feature_snapshot(flow_data),
                metadata={"adapter": "hybrid_sim"},
                audit=AuditMetadata(created_by="sim", updated_by="sim", source_system="sim")
            )
        return super().detect(flow_data)

ARTIFACT_DIR = os.environ.get("ARTIFACT_DIR", "./artifacts")

app = FastAPI(title="IDS Inference API")

# 1. Restrict CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Setup Authentication
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

def get_api_key(api_key: str = Security(api_key_header)):
    if api_key != "cyber-surakshya-secret-key":
        raise HTTPException(status_code=403, detail="Could not validate credentials")
    return api_key

# Create router for all protected endpoints
api_router = APIRouter(dependencies=[Depends(get_api_key)])


# ---------------------------------------------------------
# IN-MEMORY STATE FOR FRONTEND
# ---------------------------------------------------------
MOCK_ALERTS = []
MOCK_ANALYSES = []
MOCK_BLOCKED_IPS = []

RUNTIME = None
PRODUCTION_RUNTIME = None

@app.on_event("startup")
def startup_load():
    global MODEL, SCALER, LE, FEATURE_COLS, RUNTIME, PRODUCTION_RUNTIME
    try:
        MODEL, SCALER, LE, FEATURE_COLS = load_artifacts(
            os.path.join(ARTIFACT_DIR, "model.pkl"),
            os.path.join(ARTIFACT_DIR, "scaler.pkl"),
            os.path.join(ARTIFACT_DIR, "label_encoder.pkl"),
            os.path.join(ARTIFACT_DIR, "feature_columns.json"),
        )
        
        # Initialize LangGraph for Simulations (Hybrid)
        builder = GraphBuilder()
        builder.register_node("detection", DetectionAgent(HybridDetectionAdapter()))
        builder.register_node("analysis", AnalysisAgent(DeterministicRuleEngine()))
        RUNTIME = GraphRuntime(builder=builder)
        
        # Initialize LangGraph for Production Data (Real ML Pipeline)
        builder_prod = GraphBuilder()
        builder_prod.register_node("detection", DetectionAgent(IDSDetectionAdapter()))
        builder_prod.register_node("analysis", AnalysisAgent(DeterministicRuleEngine()))
        PRODUCTION_RUNTIME = GraphRuntime(builder=builder_prod)
        
        print("[INFO] Model and LangGraph runtimes loaded successfully.")
    except Exception as e:
        MODEL, SCALER, LE, FEATURE_COLS = None, None, None, None
        print(f"[WARN] Could not load artifacts at startup: {e}")


import asyncio

@app.get("/feed")
async def get_feed():
    """Server-Sent Events endpoint for frontend live feed."""
    async def event_generator():
        import random, datetime
        last_idle_time = datetime.datetime.min
        while True:
            await asyncio.sleep(1.0)
            now = datetime.datetime.utcnow()
            
            # Check for recent alerts (last 15 seconds)
            recent_activity = False
            for a in MOCK_ALERTS[-5:]:
                try:
                    alert_time = datetime.datetime.fromisoformat(a["created_at"].replace("Z", "+00:00")).replace(tzinfo=None)
                    if (now - alert_time).total_seconds() < 15:
                        recent_activity = True
                        break
                except:
                    pass
            
            if recent_activity:
                agent_id = random.choice(["agent-detect-01", "agent-analysis-01"])
                tasks = [
                    "Analyzing incoming flow...",
                    "Extracting packet headers...",
                    "Applying Random Forest model...",
                    "Cross-referencing IOCs...",
                    "Updating behavioral baseline...",
                    "Executing LangGraph nodes..."
                ]
                log = {
                    "agent_id": agent_id,
                    "msg": random.choice(tasks),
                    "timestamp": now.isoformat() + "Z",
                    "status": "BUSY"
                }
                yield f"event: agent_log\ndata: {json.dumps(log)}\n\n"
            else:
                if (now - last_idle_time).total_seconds() > 4:
                    log = {
                        "agent_id": "agent-detect-01",
                        "msg": "Idle - System nominal, waiting for events.",
                        "timestamp": now.isoformat() + "Z",
                        "status": "ONLINE"
                    }
                    yield f"event: agent_log\ndata: {json.dumps(log)}\n\n"
                    
                    log2 = {
                        "agent_id": "agent-analysis-01",
                        "msg": "Idle - System nominal, waiting for events.",
                        "timestamp": now.isoformat() + "Z",
                        "status": "ONLINE"
                    }
                    yield f"event: agent_log\ndata: {json.dumps(log2)}\n\n"
                    last_idle_time = now
                    
    return StreamingResponse(event_generator(), media_type="text/event-stream")

# Health is public
@app.get("/health")
def health():
    ok = MODEL is not None and SCALER is not None and LE is not None and FEATURE_COLS is not None
    return {"status": "ok" if ok else "unavailable", "artifacts_loaded": ok}


@api_router.post("/predict")
async def predict_json(payload: Dict[str, Any]):
    if MODEL is None:
        raise HTTPException(status_code=503, detail="Model artifacts not loaded")
    if isinstance(payload, dict) and "records" in payload:
        records = payload["records"]
    elif isinstance(payload, dict) and any(isinstance(v, (int, float, str)) for v in payload.values()):
        records = [payload]
    elif isinstance(payload, list):
        records = payload
    else:
        raise HTTPException(status_code=400, detail="Invalid payload format for prediction")

    df = pd.DataFrame.from_records(records)
    results = predict(df, MODEL, SCALER, LE, FEATURE_COLS, return_proba=True)
    out = results.reset_index(drop=True).to_dict(orient="records")
    return JSONResponse(content={"predictions": out})


@api_router.post("/predict/csv")
async def predict_csv_upload(file: UploadFile = File(...)):
    if MODEL is None:
        raise HTTPException(status_code=503, detail="Model artifacts not loaded")
    try:
        contents = await file.read()
        df = pd.read_csv(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {e}")
    results = predict(df, MODEL, SCALER, LE, FEATURE_COLS, return_proba=True)
    out_df = pd.concat([df.reset_index(drop=True), results.reset_index(drop=True)], axis=1)
    return JSONResponse(content={"predictions": out_df.to_dict(orient="records")})


@api_router.post("/predict/zeek")
async def predict_zeek(file: UploadFile = File(...)):
    if MODEL is None:
        raise HTTPException(status_code=503, detail="Model artifacts not loaded")
    try:
        contents = (await file.read()).decode("utf-8")
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".log") as tmp:
            tmp.write(contents)
            tmp.flush()
            res = predict_zeek_log(tmp.name, MODEL, SCALER, LE, FEATURE_COLS)
        return JSONResponse(content={"predictions": res.reset_index(drop=True).to_dict(orient="records")})
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Zeek prediction failed: {e}")


# ---------------------------------------------------------
# NEW FRONTEND API MOCKS
# ---------------------------------------------------------

@api_router.get("/alerts")
def get_alerts():
    return JSONResponse(content=sorted(MOCK_ALERTS, key=lambda x: x["created_at"], reverse=True))

@api_router.get("/alerts/{alert_id}")
def get_alert_by_id(alert_id: str):
    for a in MOCK_ALERTS:
        if str(a["id"]) == alert_id:
            return JSONResponse(content=a)
    raise HTTPException(status_code=404, detail="Alert not found")

@api_router.get("/alerts/{alert_id}/detail")
def get_alert_detail(alert_id: str):
    # Just return the alert plus an analysis stub
    for a in MOCK_ALERTS:
        if str(a["id"]) == alert_id:
            return JSONResponse(content={
                **a,
                "analysis_summary": "Auto-analyzed by deterministic engine.",
                "confidence_score": 95
            })
    raise HTTPException(status_code=404, detail="Alert not found")

@api_router.delete("/alerts/{alert_id}")
def delete_alert(alert_id: str):
    global MOCK_ALERTS
    MOCK_ALERTS = [a for a in MOCK_ALERTS if str(a["id"]) != alert_id]
    return JSONResponse(content={"status": "deleted"})


@api_router.get("/agents")
def get_agents():
    return JSONResponse(content=[
        {"id": "agent-detect-01", "agent_name": "Detection Agent", "status": "ONLINE", "version": "v1.2", "type": "Detection"},
        {"id": "agent-analysis-01", "agent_name": "Analysis Agent", "status": "ONLINE", "version": "v1.1", "type": "Analysis"}
    ])

@api_router.get("/agents/status")
def get_agents_status():
    return JSONResponse(content={"status": "online", "uptime": "24h", "active_agents": 2})


@api_router.get("/stats")
def get_stats():
    # Compute stats dynamically from MOCK_ALERTS
    critical_cnt = len([a for a in MOCK_ALERTS if a.get("severity") == "CRITICAL"])
    high_cnt = len([a for a in MOCK_ALERTS if a.get("severity") == "HIGH"])
    return JSONResponse(content={
        "total_alerts": len(MOCK_ALERTS),
        "total_agents": 2,
        "online_agents": 2,
        "total_blocked_ips": len(MOCK_BLOCKED_IPS),
        "average_confidence": 98,
        "severity_breakdown": {
            "CRITICAL": critical_cnt,
            "HIGH": high_cnt,
            "MEDIUM": len(MOCK_ALERTS) - critical_cnt - high_cnt
        }
    })

@api_router.get("/analyses")
def get_analyses():
    return JSONResponse(content=MOCK_ANALYSES)

@api_router.get("/analyses/{analysis_id}")
def get_analysis_by_id(analysis_id: str):
    for a in MOCK_ANALYSES:
        if str(a["id"]) == analysis_id:
            return JSONResponse(content=a)
    raise HTTPException(status_code=404, detail="Analysis not found")

@api_router.get("/blocked-ips")
def get_blocked_ips():
    return JSONResponse(content=MOCK_BLOCKED_IPS)

@api_router.delete("/blocked-ips/{ip_id}")
def delete_blocked_ip(ip_id: str):
    global MOCK_BLOCKED_IPS
    MOCK_BLOCKED_IPS = [b for b in MOCK_BLOCKED_IPS if str(b["id"]) != ip_id]
    return JSONResponse(content={"status": "deleted"})


# ---------------------------------------------------------
# SIMULATION WITH LANGGRAPH RUNTIME
# ---------------------------------------------------------

ATTACK_PROFILES = {
    "SYN_Flood_DDoS": {
        "Destination Port": 80, "Flow Duration": 50,
        "Total Fwd Packets": 1000, "Total Backward Packets": 0,
        "Total Length of Fwd Packets": 64000, "Total Length of Bwd Packets": 0,
        "Flow Bytes/s": 1280000, "Flow Packets/s": 20000, "SYN Flag Count": 1000,
        "FIN Flag Count": 0, "ACK Flag Count": 0, "RST Flag Count": 0,
    },
    "SSH_BruteForce": {
        "Destination Port": 22, "Flow Duration": 30000000,
        "Total Fwd Packets": 500, "Total Backward Packets": 500,
        "Total Length of Fwd Packets": 32000, "Total Length of Bwd Packets": 32000,
        "Flow Bytes/s": 2133, "Flow Packets/s": 33, "SYN Flag Count": 500,
        "FIN Flag Count": 500, "ACK Flag Count": 1000, "RST Flag Count": 50,
    },
    "PortScan": {
        "Destination Port": 0, "Flow Duration": 100,
        "Total Fwd Packets": 1, "Total Backward Packets": 0,
        "Total Length of Fwd Packets": 40, "Total Length of Bwd Packets": 0,
        "Flow Bytes/s": 400000, "Flow Packets/s": 10000, "SYN Flag Count": 1,
        "FIN Flag Count": 0, "ACK Flag Count": 0, "RST Flag Count": 0,
    }
}

@api_router.post("/simulation/simulate-attack")
def simulate_attack():
    if RUNTIME is None:
        raise HTTPException(status_code=503, detail="LangGraph runtime not initialized")
    
    # 1. Select random attack profile
    attack_name, features = random.choice(list(ATTACK_PROFILES.items()))
    features_copy = dict(features)
    features_copy["_SIMULATED_ATTACK_NAME"] = attack_name
    src_ip = f"{random.randint(10, 192)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    
    # 2. Build SecurityEvent
    ctx = CorrelationContext.create()
    event = SecurityEvent(
        correlation_id=ctx.correlation_id,
        trace_id=ctx.trace_id,
        event_type=EventType.NETWORK_FLOW,
        source=EventSource.IDS,
        severity=Severity.INFO,  # pre-detection severity
        risk_score=RiskScore(value=0.0),
        title=f"Synthetic flow for {attack_name}",
        network=NetworkEndpoint(
            source_ip=src_ip,
            destination_ip="192.168.1.100",
            destination_port=int(features["Destination Port"])
        ),
        raw_payload=features_copy,
        audit=AuditMetadata(
            created_by="simulator",
            updated_by="simulator",
            source_system="simulation_endpoint"
        )
    )
    
    # 3. Create initial state and run Graph
    state = create_initial_state(context=ctx)
    state.security_events.append(event)
    
    output_state = RUNTIME.execute(state)
    
    
    # 4. Extract results
    if not output_state.detection_results:
        raise HTTPException(status_code=500, detail="No detection result generated")
    
    det = output_state.detection_results[0]
    analysis = output_state.analysis_results[0] if output_state.analysis_results else None
    
    alert_id = str(uuid.uuid4())
    is_attack = det.predicted_label.upper() != "BENIGN"
    
    # Create frontend-compatible Alert
    new_alert = {
        "id": alert_id,
        "attack_type": det.predicted_label,
        "source_ip": src_ip,
        "severity": det.severity.name.upper(),
        "status": "Investigating" if is_attack else "Resolved",
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    
    MOCK_ALERTS.append(new_alert)
    
    if analysis:
        new_analysis = {
            "id": str(analysis.analysis_id),
            "alert_id": alert_id,
            "prediction": det.predicted_label,
            "confidence": det.confidence * 100,
            "summary": analysis.summary
        }
        MOCK_ANALYSES.append(new_analysis)
    
    # Block IP if attack
    blocked_obj = None
    if is_attack:
        blocked_id = str(uuid.uuid4())
        blocked_obj = {
            "id": blocked_id,
            "ip": src_ip,
            "reason": f"Detected {det.predicted_label}",
            "created_at": datetime.utcnow().isoformat() + "Z"
        }
        MOCK_BLOCKED_IPS.append(blocked_obj)
        
    return JSONResponse(content={
        "alert": new_alert,
        "analysis": {
            "prediction": det.predicted_label,
            "confidence": det.confidence * 100
        },
        "threat_score": {
            "score": det.risk_score.value,
            "risk": det.risk_score.level.name if det.risk_score.level else "MODERATE",
            "priority": det.severity.name
        },
        "response": {
            "action": "Block Source IP" if is_attack else "Log Only",
            "status": "Executed" if is_attack else "Ignored"
        },
        "blocked_ip": blocked_obj
    })

@api_router.post("/simulation/upload-zeek")
async def upload_zeek_simulation(file: UploadFile = File(...)):
    if PRODUCTION_RUNTIME is None:
        raise HTTPException(status_code=503, detail="LangGraph production runtime not initialized")
    
    try:
        contents = (await file.read()).decode("utf-8")
        import tempfile
        import pandas as pd
        from io import StringIO
        from inference import translate_zeek_conn_log
        
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".log") as tmp:
            tmp.write(contents)
            tmp.flush()
            
            with open(tmp.name) as f:
                lines = [l for l in f if not l.startswith("#separator") and not l.startswith("#set_separator")]
            header_line = None
            data_lines = []
            for line in lines:
                if line.startswith("#fields"):
                    header_line = line.strip().replace("#fields\t", "").split("\t")
                elif not line.startswith("#"):
                    data_lines.append(line)
                    
            if header_line is None:
                df_zeek = pd.read_csv(tmp.name, sep="\t", comment="#")
            else:
                data_str = "".join(data_lines)
                df_zeek = pd.read_csv(StringIO(data_str), sep="\t", names=header_line, na_values=["-", "(empty)"])
                
        # Translate directly to features without predicting!
        df_translated = translate_zeek_conn_log(df_zeek)
            
        alerts_generated = []
        analyses_generated = []
        blocked_ips = []
        attacks_found = 0
        
        # Limit to 50 rows to avoid extremely long synchronous loops
        for idx, row in df_translated.head(50).iterrows():
            src_ip = f"{random.randint(10, 192)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            # Use strict type checking, fill NaN with 0.0
            features = {k: float(v) if pd.notnull(v) else 0.0 for k, v in row.to_dict().items()}
            
            ctx = CorrelationContext.create()
            event = SecurityEvent(
                correlation_id=ctx.correlation_id,
                trace_id=ctx.trace_id,
                event_type=EventType.NETWORK_FLOW,
                source=EventSource.IDS,
                severity=Severity.INFO,
                risk_score=RiskScore(value=0.0),
                title=f"Zeek Upload - Direct ML Process",
                network=NetworkEndpoint(
                    source_ip=src_ip,
                    destination_ip="192.168.1.100",
                    destination_port=int(row.get("Destination Port", 0))
                ),
                features=features,
                audit=AuditMetadata(
                    created_by="zeek_upload",
                    updated_by="zeek_upload",
                    source_system="simulation_endpoint"
                )
            )
            
            state = create_initial_state(context=ctx)
            state.security_events.append(event)
            # Run through PRODUCTION adapter directly (real ML model)
            output_state = PRODUCTION_RUNTIME.execute(state)
            
            if output_state.detection_results:
                det = output_state.detection_results[0]
                if det.status.value != "benign":
                    attacks_found += 1
                    analysis = output_state.analysis_results[0] if output_state.analysis_results else None
                    
                    alert_id = str(uuid.uuid4())
                    new_alert = {
                        "id": alert_id,
                        "attack_type": det.predicted_label,
                        "source_ip": src_ip,
                        "severity": det.severity.name.upper(),
                        "status": "Investigating",
                        "created_at": datetime.utcnow().isoformat() + "Z"
                    }
                    MOCK_ALERTS.append(new_alert)
                    alerts_generated.append(new_alert)
                    
                    if analysis:
                        new_analysis = {
                            "id": str(analysis.analysis_id),
                            "alert_id": alert_id,
                            "prediction": det.predicted_label,
                            "confidence": det.confidence * 100,
                            "summary": analysis.summary
                        }
                        MOCK_ANALYSES.append(new_analysis)
                        analyses_generated.append(new_analysis)
                        
                    blocked_id = str(uuid.uuid4())
                    blocked_obj = {
                        "id": blocked_id,
                        "ip": src_ip,
                        "reason": f"Detected {det.predicted_label}",
                        "created_at": datetime.utcnow().isoformat() + "Z"
                    }
                    MOCK_BLOCKED_IPS.append(blocked_obj)
                    blocked_ips.append(blocked_obj)
                
        return JSONResponse(content={
            "processed_records": len(df_translated.head(50)),
            "attacks_found": attacks_found,
            "alerts": alerts_generated,
            "analyses": analyses_generated,
            "blocked_ips": blocked_ips
        })
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Zeek upload simulation failed: {e}")

# Register the router
app.include_router(api_router)

# Serve a minimal frontend if present
if os.path.isdir("frontend"):
    app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
