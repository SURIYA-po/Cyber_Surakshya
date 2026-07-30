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
import asyncio
from datetime import datetime
from typing import List, Dict, Any

# Reuse existing inference utilities & artifacts container
import inference
from inference import IDSArtifacts, load_artifacts, predict, predict_csv, predict_zeek_log, resolve_model_path

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
from agents.decision.decision_agent import DecisionAgent
from agents.decision.deterministic import DeterministicDecisionEngine

ARTIFACT_DIR = os.path.abspath(
    os.environ.get("ARTIFACT_DIR", os.path.join(os.path.dirname(__file__), "artifacts"))
)

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

ARTIFACTS = None
MODEL = None
SCALER = None
LE = None
FEATURE_COLS = None

RUNTIME = None
PRODUCTION_RUNTIME = None

def ensure_runtime():
    """Ensure LangGraph runtime & ML adapters are created, registered, and injected."""
    global ARTIFACTS, MODEL, SCALER, LE, FEATURE_COLS, RUNTIME, PRODUCTION_RUNTIME
    if RUNTIME is None:
        try:
            model_path = resolve_model_path(ARTIFACT_DIR)
            scaler_path = os.path.join(ARTIFACT_DIR, "scaler.pkl")
            le_path = os.path.join(ARTIFACT_DIR, "label_encoder.pkl")
            feat_path = os.path.join(ARTIFACT_DIR, "feature_columns.json")
            iforest_path = os.path.join(ARTIFACT_DIR, "iforest.pkl")
            ae_path = os.path.join(ARTIFACT_DIR, "autoencoder.pkl")
            thresholds_path = os.path.join(ARTIFACT_DIR, "anomaly_thresholds.json")

            print(f"[INFO] Using model artifact: {model_path}")

            ARTIFACTS = IDSArtifacts(
                model_path=model_path,
                scaler_path=scaler_path,
                le_path=le_path,
                feat_path=feat_path,
                iforest_path=iforest_path,
                ae_path=ae_path,
                thresholds_path=thresholds_path,
            )
            MODEL = ARTIFACTS.model
            SCALER = ARTIFACTS.scaler
            LE = ARTIFACTS.le
            FEATURE_COLS = ARTIFACTS.feature_cols
            
            # Real ML Adapter (using trained models or fallback container)
            adapter = IDSDetectionAdapter(artifacts=ARTIFACTS)
            
            # Initialize LangGraph Pipeline (Detection -> Analysis -> Decision)
            builder = GraphBuilder()
            builder.register_node("detection", DetectionAgent(adapter))
            builder.register_node("analysis", AnalysisAgent(DeterministicRuleEngine()))
            builder.register_node("decision", DecisionAgent(DeterministicDecisionEngine()))
            
            RUNTIME = GraphRuntime(builder=builder)
            PRODUCTION_RUNTIME = RUNTIME
            print("[INFO] Model artifacts & LangGraph ML runtime created and registered successfully.")
        except Exception as e:
            print(f"[ERROR] Could not initialize GraphRuntime: {e}")
    return RUNTIME

# Initialize runtime immediately upon module load
ensure_runtime()

@app.on_event("startup")
def startup_load():
    ensure_runtime()


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
                    "Applying VotingEnsemble / Random Forest model...",
                    "Evaluating anomaly layer (Isolation Forest + Autoencoder)...",
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
    ok = RUNTIME is not None
    return {"status": "ok" if ok else "unavailable", "artifacts_loaded": ok}


@api_router.post("/predict")
async def predict_json(payload: Dict[str, Any]):
    ensure_runtime()
    if ARTIFACTS is None and MODEL is None:
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
    arts = ARTIFACTS or (MODEL, SCALER, LE, FEATURE_COLS)
    results = predict(df, arts, return_proba=True)
    out = results.reset_index(drop=True).to_dict(orient="records")
    return JSONResponse(content={"predictions": out})


@api_router.post("/predict/csv")
async def predict_csv_upload(file: UploadFile = File(...)):
    ensure_runtime()
    if ARTIFACTS is None and MODEL is None:
        raise HTTPException(status_code=503, detail="Model artifacts not loaded")
    try:
        contents = await file.read()
        df = pd.read_csv(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {e}")
    arts = ARTIFACTS or (MODEL, SCALER, LE, FEATURE_COLS)
    results = predict(df, arts, return_proba=True)
    out_df = pd.concat([df.reset_index(drop=True), results.reset_index(drop=True)], axis=1)
    return JSONResponse(content={"predictions": out_df.to_dict(orient="records")})


@api_router.post("/predict/zeek")
async def predict_zeek(file: UploadFile = File(...)):
    ensure_runtime()
    if ARTIFACTS is None and MODEL is None:
        raise HTTPException(status_code=503, detail="Model artifacts not loaded")
    try:
        contents = (await file.read()).decode("utf-8")
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".log") as tmp:
            tmp.write(contents)
            tmp.flush()
            arts = ARTIFACTS or (MODEL, SCALER, LE, FEATURE_COLS)
            res = predict_zeek_log(tmp.name, output_path=None, artifacts=arts)
        return JSONResponse(content={"predictions": res.reset_index(drop=True).to_dict(orient="records")})
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Zeek prediction failed: {e}")


# ---------------------------------------------------------
# FRONTEND DASHBOARD APIS
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
    for a in MOCK_ALERTS:
        if str(a["id"]) == alert_id:
            return JSONResponse(content={
                **a,
                "analysis_summary": "Auto-analyzed by deterministic rule engine & dual-layer IDS.",
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
            "MEDIUM": max(0, len(MOCK_ALERTS) - critical_cnt - high_cnt)
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
# REAL ML SIMULATION WITH LANGGRAPH RUNTIME
# ---------------------------------------------------------

# Realistic 52-feature flow profiles based on CICIDS2017 dataset
ATTACK_PROFILES = {
    "SYN_Flood_DDoS": {
        "Destination Port": 80, "Flow Duration": 50,
        "Total Fwd Packets": 5000, "Total Length of Fwd Packets": 320000,
        "Fwd Packet Length Max": 64, "Fwd Packet Length Min": 64,
        "Fwd Packet Length Mean": 64, "Fwd Packet Length Std": 0,
        "Bwd Packet Length Max": 0, "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 0, "Bwd Packet Length Std": 0,
        "Flow Bytes/s": 6400000, "Flow Packets/s": 100000,
        "Flow IAT Mean": 0.01, "Flow IAT Std": 0.005,
        "Flow IAT Max": 0.02, "Flow IAT Min": 0.001,
        "Fwd IAT Total": 50, "Fwd IAT Mean": 0.01,
        "Fwd IAT Std": 0.005, "Fwd IAT Max": 0.02,
        "Fwd IAT Min": 0.001, "Bwd IAT Total": 0,
        "Bwd IAT Mean": 0, "Bwd IAT Std": 0,
        "Bwd IAT Max": 0, "Bwd IAT Min": 0,
        "Fwd Header Length": 320000, "Bwd Header Length": 0,
        "Fwd Packets/s": 100000, "Bwd Packets/s": 0,
        "Min Packet Length": 64, "Max Packet Length": 64,
        "Packet Length Mean": 64, "Packet Length Std": 0,
        "Packet Length Variance": 0, "FIN Flag Count": 0,
        "SYN Flag Count": 5000, "RST Flag Count": 0,
        "PSH Flag Count": 0, "ACK Flag Count": 0,
        "URG Flag Count": 0, "Average Packet Size": 64,
        "Subflow Fwd Bytes": 320000, "Init_Win_bytes_forward": 65535,
        "Init_Win_bytes_backward": 0, "act_data_pkt_fwd": 0,
        "min_seg_size_forward": 64, "Active Mean": 0.01,
        "Active Max": 0.02, "Active Min": 0.001,
        "Idle Mean": 0, "Idle Max": 0, "Idle Min": 0,
    },
    "SSH_BruteForce": {
        "Destination Port": 22, "Flow Duration": 30000000,
        "Total Fwd Packets": 1000, "Total Length of Fwd Packets": 64000,
        "Fwd Packet Length Max": 128, "Fwd Packet Length Min": 40,
        "Fwd Packet Length Mean": 64, "Fwd Packet Length Std": 12,
        "Bwd Packet Length Max": 128, "Bwd Packet Length Min": 40,
        "Bwd Packet Length Mean": 64, "Bwd Packet Length Std": 12,
        "Flow Bytes/s": 2133, "Flow Packets/s": 33,
        "SYN Flag Count": 1000, "FIN Flag Count": 1000,
        "ACK Flag Count": 2000, "RST Flag Count": 100,
        "Average Packet Size": 64, "Init_Win_bytes_forward": 14600,
        "Init_Win_bytes_backward": 14600,
    },
    "PortScan": {
        "Destination Port": 0, "Flow Duration": 100,
        "Total Fwd Packets": 1, "Total Length of Fwd Packets": 40,
        "Fwd Packet Length Max": 40, "Fwd Packet Length Min": 40,
        "Fwd Packet Length Mean": 40, "Fwd Packet Length Std": 0,
        "Flow Bytes/s": 400000, "Flow Packets/s": 10000,
        "SYN Flag Count": 1, "FIN Flag Count": 0,
        "ACK Flag Count": 0, "PSH Flag Count": 0,
        "Average Packet Size": 40, "Init_Win_bytes_forward": 1024,
    },
    "DoS_Hulk": {
        "Destination Port": 80, "Flow Duration": 100000,
        "Total Fwd Packets": 500, "Total Length of Fwd Packets": 750000,
        "Fwd Packet Length Max": 1500, "Fwd Packet Length Min": 64,
        "Fwd Packet Length Mean": 1500, "Fwd Packet Length Std": 100,
        "Flow Bytes/s": 7500000, "Flow Packets/s": 5000,
        "SYN Flag Count": 0, "FIN Flag Count": 0,
        "ACK Flag Count": 500, "PSH Flag Count": 500,
        "Average Packet Size": 1500, "Init_Win_bytes_forward": 65535,
    },
    "Botnet_C2": {
        "Destination Port": 6667, "Flow Duration": 3600000000,
        "Total Fwd Packets": 10, "Total Length of Fwd Packets": 640,
        "Flow Bytes/s": 10, "Flow Packets/s": 0.003,
        "SYN Flag Count": 1, "FIN Flag Count": 0,
        "ACK Flag Count": 10, "PSH Flag Count": 8,
        "Average Packet Size": 64, "Init_Win_bytes_forward": 8192,
    },
    "Normal_HTTP_GET": {
        "Destination Port": 80, "Flow Duration": 500000,
        "Total Fwd Packets": 5, "Total Length of Fwd Packets": 2000,
        "Flow Bytes/s": 20000, "Flow Packets/s": 18,
        "SYN Flag Count": 1, "FIN Flag Count": 1,
        "ACK Flag Count": 8, "PSH Flag Count": 2,
        "Average Packet Size": 400, "Init_Win_bytes_forward": 65535,
    }
}

@api_router.post("/simulation/simulate-attack")
def simulate_attack():
    runtime = ensure_runtime()
    if runtime is None:
        raise HTTPException(status_code=503, detail="LangGraph runtime not initialized")
    
    # 1. Select random flow profile
    attack_name, features = random.choice(list(ATTACK_PROFILES.items()))
    features_copy = dict(features)
    src_ip = f"{random.randint(10, 192)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    
    # 2. Build SecurityEvent with real numeric flow features
    ctx = CorrelationContext.create()
    event = SecurityEvent(
        correlation_id=ctx.correlation_id,
        trace_id=ctx.trace_id,
        event_type=EventType.NETWORK_FLOW,
        source=EventSource.IDS,
        severity=Severity.INFO,
        risk_score=RiskScore(value=0.0),
        title=f"Network flow simulation: {attack_name}",
        network=NetworkEndpoint(
            source_ip=src_ip,
            destination_ip="192.168.1.100",
            destination_port=int(features_copy.get("Destination Port", 80))
        ),
        raw_payload=features_copy,
        features={k: float(v) for k, v in features_copy.items() if isinstance(v, (int, float))},
        audit=AuditMetadata(
            created_by="simulator",
            updated_by="simulator",
            source_system="simulation_endpoint"
        )
    )
    
    # 3. Create initial state and run real ML Pipeline via LangGraph
    state = create_initial_state(context=ctx)
    state.security_events.append(event)
    
    output_state = runtime.execute(state)
    
    # 4. Extract real ML detection & analysis results
    if not output_state.detection_results:
        raise HTTPException(status_code=500, detail="No detection result generated by ML pipeline")
    
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
            "confidence": round(det.confidence * 100, 2),
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
            "reason": f"Detected {det.predicted_label} (Confidence: {round(det.confidence * 100, 1)}%)",
            "created_at": datetime.utcnow().isoformat() + "Z"
        }
        MOCK_BLOCKED_IPS.append(blocked_obj)
        
    return JSONResponse(content={
        "alert": new_alert,
        "analysis": {
            "prediction": det.predicted_label,
            "confidence": round(det.confidence * 100, 2)
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
    runtime = ensure_runtime()
    if runtime is None:
        raise HTTPException(status_code=503, detail="LangGraph production runtime not initialized")
    
    try:
        contents = (await file.read()).decode("utf-8")
        import tempfile
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
            output_state = runtime.execute(state)
            
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
                            "confidence": round(det.confidence * 100, 2),
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
